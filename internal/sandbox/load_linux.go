package sandbox

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/samyfodil/laboon/internal/rewrite"
)

type image struct {
	dyn    bool   // position-independent (ET_DYN): it may load at any bias
	bias   uint64 // address of ELF vaddr 0
	entry  uint64
	phdr   uint64
	phnum  uint64
	interp string // PT_INTERP, if any
	lo, hi uint64 // page-aligned span: all PT_LOAD segments and the trampolines
	prots  []run  // final protections

	// Until mapImage installs it: the file, its loadable segments, the
	// rewritten byte ranges within them and the trampoline code.
	file    *progFile
	segs    []segment
	patches []patch
	tramp   uint64
	code    []byte

	sites        []uint64 // sorted
	fast, strays int
}

type run struct {
	lo, hi uint64
	prot   int
}

// segment is a PT_LOAD: filesz bytes at file offset off map at addr.
type segment struct {
	addr, off, filesz, memsz uint64
}

// patch is a rewritten range of a segment, whose bytes are in the file view.
type patch struct {
	addr uint64
	b    []byte
}

// progFile is a program opened for exec. It is read once: the ELF parse and
// the rewriting use its view, the whole file mapped copy-on-write, so
// rewriting patches it in place; the guest maps the file itself (mapImage).
type progFile struct {
	f    *os.File
	id   rewrite.FileID
	size int64
	data []byte // the view, once mapped
}

func (g *dguest) openProgram(src execSrc) (*progFile, error) {
	f := src.f
	if f != nil {
		if src.own {
			defer f.Close() // a reopened O_PATH handle; the dup below owns it now
		}
		df, e := dupFile(f)
		if e != 0 {
			return nil, lxErr(e)
		}
		f = df
	} else {
		rp, e := g.resolve(src.gp, true)
		if e != 0 {
			return nil, lxErr(e)
		}
		if f, e = g.openFile(rp); e != 0 {
			return nil, lxErr(e)
		}
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		f.Close()
		return nil, unix.EACCES
	}
	return &progFile{f: f, id: statIdentity(&st), size: st.Size}, nil
}

// view maps the file for reading and patching, once.
func (pf *progFile) view() ([]byte, error) {
	if pf.data == nil && pf.size > 0 {
		data, err := unix.Mmap(int(pf.f.Fd()), 0, int(pf.size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
		if err != nil {
			return nil, err
		}
		pf.data = data
	}
	return pf.data, nil
}

func statIdentity(st *unix.Stat_t) rewrite.FileID {
	return rewrite.FileID{Dev: st.Dev, Ino: st.Ino, Size: st.Size, Mtime: st.Mtim.Nano(), Ctime: st.Ctim.Nano(), Unlinked: st.Nlink == 0}
}

// identity returns the identity of the file code was mapped from, if any.
func (src *codeSource) identity() (rewrite.FileID, bool) {
	var st unix.Stat_t
	if src == nil || src.fd < 0 || unix.Fstat(src.fd, &st) != nil {
		return rewrite.FileID{}, false
	}
	return statIdentity(&st), true
}

func (pf *progFile) close() {
	if pf.data != nil {
		unix.Munmap(pf.data)
	}
	pf.f.Close()
}

// errTruncated is a program file that shrank while it was being read.
var errTruncated = errors.New("program file changed while loading")

// loadELF prepares an image from an ELF file, rewriting its code. dynBias
// is where an ET_DYN image with an interpreter is placed; one with none -- an
// interpreter, or a program that loads itself -- goes where the fresh address
// space under mm places a mapping first, the top of its mmap area, as Linux's
// load_elf_binary maps it. An image carrying the window note (a nested stub)
// is instead placed at a free high window chosen here, so its private window
// clears this level's guests. On success the image owns pf. An image the
// sandbox prepared before is reused, moved to its place.
func (g *dguest) loadELF(pf *progFile, dynBias uint64, mm mmapLayout) (*image, error) {
	bias := dynBias
	data, err := pf.view()
	if err != nil {
		return nil, err
	}
	if wantsWindow(data) {
		w, err := g.claimWindow()
		if err != nil {
			return nil, err
		}
		bias = w
	}
	key := preparedKey{pf.id}
	img := g.run.prepared(key)
	if img == nil {
		var err error
		if img, err = g.prepareELF(pf, bias); err != nil {
			return nil, err
		}
		g.run.keepPrepared(key, img)
	}
	if img.dyn && img.interp == "" && !wantsWindow(data) {
		g.mp.mu.Lock()
		lo, ok := g.mp.placeFresh(mm, img.hi-img.lo)
		g.mp.mu.Unlock()
		if !ok {
			return nil, errors.New("no room for the image")
		}
		bias = lo + (img.bias - img.lo)
	}
	img = img.instance(pf, bias)
	g.mp.mu.Lock()
	g.reserve(img.tramp, trampSize)
	g.mp.sites.addList(img.sites)
	g.mp.fast += img.fast
	g.mp.strays += img.strays
	g.mp.mu.Unlock()
	return img, nil
}

// The window-placement note (stub/zig/stub.zig lc_window_note): an image that
// carries it in a PT_NOTE segment asks to be loaded in a private high window
// rather than at the exe bias. A nested laboon's stub carries it; the loader
// honors it so nesting composes to any depth. It is a declared property of the
// image, not a recognition of specific bytes.
var windowNoteName = []byte("laboon\x00")

const windowNoteType = 1

// wantsWindow reports whether the ELF in data is a nested stub to place in a
// high window: an ET_DYN without PT_INTERP carrying the window note.
func wantsWindow(data []byte) bool {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || f.Type != elf.ET_DYN {
		return false
	}
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_INTERP:
			return false
		case elf.PT_NOTE:
			if p.Filesz == 0 || p.Filesz > 1<<16 {
				continue
			}
			nb := make([]byte, p.Filesz)
			if _, err := p.ReadAt(nb, 0); err == nil && hasWindowNote(nb) {
				return true
			}
		}
	}
	return false
}

func hasWindowNote(nb []byte) bool {
	for len(nb) >= 12 {
		namesz := le32(nb[0:])
		descsz := le32(nb[4:])
		ntype := le32(nb[8:])
		next := 12 + align4(namesz) + align4(descsz)
		if next > uint32(len(nb)) || 12+namesz > uint32(len(nb)) {
			return false
		}
		if ntype == windowNoteType && int(namesz) == len(windowNoteName) &&
			bytes.Equal(nb[12:12+namesz], windowNoteName) {
			return true
		}
		nb = nb[next:]
	}
	return false
}

func align4(n uint32) uint32 { return (n + 3) &^ 3 }

// stubWinTop is the first (highest) window the loader tries for a nested stub
// -- the primary window -- stepping down by stubWinSize to stubWinFloor, kept
// above the band a randomized x86-64 program loads in (ELF_ET_DYN_BASE plus
// 2^28 pages, and room for the image; arm64's band lies above the windows).
// An ancestor's window is already mapped, so its candidate is rejected and the
// next is tried: no depth cap but address space.
const (
	stubWinTop   = 0x6c0000000000
	stubWinFloor = 0x580000000000
)

// claimWindow finds a free high window in the stub's process for a nested
// stub and returns its base. It probes the code base and the channel base of
// each candidate -- the regions a collision would hit -- in the child via the
// stub, since only a real mapping proves an ancestor's window taken.
func (g *dguest) claimWindow() (uint64, error) {
	for w := uint64(stubWinTop); w >= stubWinFloor; w -= stubWinSize {
		free := g.windowFreeAt(w)
		if free {
			return w, nil
		}
	}
	return 0, errors.New("no free window for a nested stub")
}

func (g *dguest) windowFreeAt(w uint64) bool {
	for _, off := range [...]uint64{0, 0x1000000000} { // image base, channel base
		a := w + off
		r := g.host(unix.SYS_MMAP, a, pageSize, unix.PROT_NONE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED_NOREPLACE, ^uint64(0), 0)
		if uint64(r) != a {
			if r >= 0 {
				g.host(unix.SYS_MUNMAP, uint64(r), pageSize)
			}
			return false
		}
		g.host(unix.SYS_MUNMAP, a, pageSize)
	}
	return true
}

// prepareELF parses and rewrites the ELF image in pf's view.
func (g *dguest) prepareELF(pf *progFile, dynBias uint64) (img *image, err error) {
	// The view is the file itself: one truncated underfoot faults, which
	// fails this load instead of the supervisor.
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if r := recover(); r != nil {
			img, err = nil, errTruncated
		}
	}()
	data := pf.data
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if f.Machine != elfMachine {
		return nil, fmt.Errorf("not a %s executable", platform)
	}
	img = &image{phnum: uint64(len(f.Progs))}
	switch f.Type {
	case elf.ET_EXEC:
	case elf.ET_DYN:
		img.dyn, img.bias = true, dynBias
	default:
		return nil, errors.New("not an executable")
	}
	img.entry = img.bias + f.Entry
	img.lo = ^uint64(0)
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_INTERP:
			if p.Off+p.Filesz > uint64(len(data)) || p.Filesz == 0 {
				return nil, errors.New("bad PT_INTERP")
			}
			img.interp = string(bytes.TrimRight(data[p.Off:p.Off+p.Filesz], "\x00"))
		case elf.PT_PHDR:
			img.phdr = img.bias + p.Vaddr
		case elf.PT_LOAD:
			img.lo = min(img.lo, img.bias+p.Vaddr&^(pageSize-1))
			img.hi = max(img.hi, alignUp(img.bias+p.Vaddr+p.Memsz))
			if img.phdr == 0 && p.Off == 0 {
				img.phdr = img.bias + p.Vaddr + phoff(data)
			}
		}
	}
	if img.hi == 0 {
		return nil, errors.New("no loadable segments")
	}
	if img.hi > stubLo && img.lo < stubHi {
		return nil, errors.New("image overlaps the stub")
	}
	// Trampolines sit directly below the image, or above it when it starts
	// too low (Go links linux/arm64 binaries at 0x10000), within branch
	// range of its code.
	switch {
	case img.lo >= trampSize+minAddr:
		img.lo -= trampSize
		img.tramp = img.lo
	case img.hi+trampSize-img.lo <= trampReach:
		img.tramp = img.hi
		img.hi += trampSize
	default:
		return nil, errors.New("no room for trampolines near the image")
	}
	w := g.newRewriter(img.tramp, trampSize)
	var plan imagePlan
	if !g.cfg.NoRewrite {
		plan = g.imagePlan(pf, f)
	}
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if p.Off+p.Filesz > uint64(len(data)) || p.Filesz > p.Memsz {
			return nil, errors.New("segment outside file")
		}
		addr := img.bias + p.Vaddr
		img.segs = append(img.segs, segment{addr: addr, off: p.Off, filesz: p.Filesz, memsz: p.Memsz})
		prot := 0
		if p.Flags&elf.PF_R != 0 {
			prot |= unix.PROT_READ
		}
		if p.Flags&elf.PF_W != 0 {
			prot |= unix.PROT_WRITE
		}
		if p.Flags&elf.PF_X != 0 {
			prot |= unix.PROT_EXEC
			if prot&unix.PROT_WRITE != 0 {
				return nil, errors.New("writable and executable segment refused (W^X)")
			}
			if !g.cfg.NoRewrite {
				seg := data[p.Off : p.Off+p.Filesz]
				n := len(w.Patched().Sites)
				g.rewriteSegment(w, plan, p, seg, addr)
				img.patches = appendPatches(img.patches, w.Patched().Sites[n:], seg, addr)
			}
		}
		img.prots = append(img.prots, run{addr &^ (pageSize - 1), alignUp(addr + p.Memsz), prot})
	}
	res := w.Patched()
	img.sites = slices.Sorted(slices.Values(res.Sites))
	img.fast, img.strays = res.Fast, len(res.Stray)
	img.code = w.Trampolines()
	img.prots = append(img.prots, run{img.tramp, img.tramp + trampSize, unix.PROT_READ | unix.PROT_EXEC})
	return img, nil
}

// siteSpan bounds the bytes rewriting a site may change on either side of
// it: on x86-64 the run stolen before the syscall, or the cave it jumps
// through, and the syscall; on arm64 the svc word.
const siteSpan = rewrite.SiteSpan

// appendPatches adds the byte ranges of seg (loaded at addr) that the sites
// rewritten in it may have changed, merging neighbours.
func appendPatches(ps []patch, sites []uint64, seg []byte, addr uint64) []patch {
	end := addr + uint64(len(seg))
	for _, s := range sites {
		lo, hi := max(s, addr+siteSpan)-siteSpan, min(s+siteSpan, end)
		if n := len(ps); n > 0 {
			last := &ps[n-1]
			if la := last.addr + uint64(len(last.b)); lo <= la+64 && lo >= last.addr {
				last.b = seg[last.addr-addr : max(la, hi)-addr]
				continue
			}
		}
		ps = append(ps, patch{lo, seg[lo-addr : hi-addr]})
	}
	return ps
}

// mapImage installs a prepared image in the stub. Segments map the file
// itself, copy-on-write, as the kernel's loader does, so only the pages the
// guest touches are read and only rewritten ones are copied.
func (g *dguest) mapImage(img *image, replace bool) error {
	defer img.release()
	// At initial load the target must be empty (NOREPLACE catches a clash);
	// for execve the address space is being replaced, so FIXED clobbers any
	// residue the vma teardown did not reach.
	fixed := uint64(unix.MAP_FIXED_NOREPLACE)
	if replace {
		fixed = unix.MAP_FIXED
	}
	r := g.host(unix.SYS_MMAP, img.lo, img.hi-img.lo, unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|fixed, ^uint64(0), 0)
	if uint64(r) != img.lo {
		return errors.New("cannot map image at its address")
	}
	if err := g.mapSegments(img); err != nil {
		return err
	}
	if err := g.writeMem(img.tramp, img.code); err != nil {
		return err
	}
	// Gaps between segments stay inaccessible.
	if r := g.host(unix.SYS_MPROTECT, img.lo, img.hi-img.lo, unix.PROT_NONE); r < 0 {
		return errors.New("cannot protect image")
	}
	for _, p := range img.prots {
		if r := g.host(unix.SYS_MPROTECT, p.lo, p.hi-p.lo, uint64(p.prot)); r != 0 {
			return errors.New("cannot protect segment")
		}
	}
	return nil
}

func (g *dguest) mapSegments(img *image) (err error) {
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if r := recover(); r != nil {
			err = errTruncated
		}
	}()
	sfd := -1
	if e := lxErrno(0); len(img.segs) > 0 {
		if sfd, e = g.passFd(hostFd(img.file.f)); e != 0 {
			sfd = -1
		}
	}
	for _, s := range img.segs {
		if s.filesz == 0 {
			continue
		}
		lo, end := s.addr&^(pageSize-1), s.addr+s.filesz
		mapped := sfd >= 0 && s.addr%pageSize == s.off%pageSize &&
			uint64(g.host(unix.SYS_MMAP, lo, alignUp(end)-lo, unix.PROT_READ|unix.PROT_WRITE,
				unix.MAP_PRIVATE|unix.MAP_FIXED, uint64(sfd), s.off&^(pageSize-1))) == lo
		if !mapped {
			data, err := img.file.view()
			if err != nil {
				return err
			}
			if err := g.writeMem(s.addr, data[s.off:s.off+s.filesz]); err != nil {
				return err
			}
			continue
		}
		// The file's bytes past the segment share its last page. With bss
		// there, the rest of the page reads as zero, as the kernel's loader
		// leaves it: ld.so's early allocator takes it as zeroed memory.
		if s.memsz > s.filesz && end%pageSize != 0 {
			if err := g.writeMem(end, make([]byte, alignUp(end)-end)); err != nil {
				return err
			}
		}
	}
	if sfd >= 0 {
		g.host(unix.SYS_CLOSE, uint64(sfd))
	}
	return g.writePatches(img.patches)
}

// writePatches writes rewritten ranges into the guest, many per syscall.
func (g *dguest) writePatches(ps []patch) error {
	const batch = 512
	local := make([]unix.Iovec, 0, batch)
	remote := make([]unix.RemoteIovec, 0, batch)
	for len(ps) > 0 {
		n := min(len(ps), batch)
		local, remote = local[:0], remote[:0]
		want := 0
		for _, p := range ps[:n] {
			local = append(local, unix.Iovec{Base: &p.b[0], Len: uint64(len(p.b))})
			remote = append(remote, unix.RemoteIovec{Base: uintptr(p.addr), Len: len(p.b)})
			want += len(p.b)
		}
		got, err := unix.ProcessVMWritev(int(g.mp.pid.Load()), local, remote, 0)
		if err != nil {
			return err
		}
		if got != want {
			// A partial write: finish one range at a time.
			for _, p := range ps[:n] {
				if err := g.writeMem(p.addr, p.b); err != nil {
					return err
				}
			}
		}
		ps = ps[n:]
	}
	return nil
}

// instance returns a copy of a prepared image to map from pf.
// instance is the image loaded from pf at bias: a position-independent one
// moves there whole, its trampolines with it (their guest addresses are all
// relative to the code), so a prepared image serves every load of its file.
func (img *image) instance(pf *progFile, bias uint64) *image {
	c := *img
	c.file = pf
	if !c.dyn || bias == c.bias {
		return &c
	}
	d := bias - c.bias
	c.bias, c.entry, c.phdr, c.lo, c.hi, c.tramp = bias, c.entry+d, c.phdr+d, c.lo+d, c.hi+d, c.tramp+d
	c.prots = slices.Clone(c.prots)
	for i := range c.prots {
		c.prots[i].lo += d
		c.prots[i].hi += d
	}
	c.segs = slices.Clone(c.segs)
	for i := range c.segs {
		c.segs[i].addr += d
	}
	c.patches = slices.Clone(c.patches)
	for i := range c.patches {
		c.patches[i].addr += d
	}
	c.sites = slices.Clone(c.sites)
	for i := range c.sites {
		c.sites[i] += d
	}
	return &c
}

// release drops the image's file once it is mapped (or abandoned).
func (img *image) release() {
	if img.file != nil {
		img.file.close()
	}
	img.file, img.segs, img.patches, img.code = nil, nil, nil, nil
}

func phoff(data []byte) uint64 {
	// e_phoff lives at byte 32 of an ELF64 header.
	return le64(data[32:])
}

// preparedKey names a prepared image: its file.
type preparedKey struct {
	id rewrite.FileID
}

// maxPrepared bounds the images a sandbox keeps prepared.
const maxPrepared = 256

// prepared returns the image prepared from key's file before, or nil.
func (s *runInfo) prepared(k preparedKey) *image {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.images[k]
}

// keepPrepared remembers img, just prepared, for later loads of its file.
// The kept copy owns its rewritten bytes; the file is not kept.
func (s *runInfo) keepPrepared(k preparedKey, img *image) {
	if s == nil {
		return
	}
	c := *img
	c.file = nil
	c.patches = make([]patch, len(img.patches))
	for i, p := range img.patches {
		c.patches[i] = patch{p.addr, bytes.Clone(p.b)}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.images == nil || len(s.images) >= maxPrepared {
		s.images = map[preparedKey]*image{}
	}
	s.images[k] = &c
}
