//go:build windows

package sandbox

import (
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The stub owns guest memory (stub/windows/mem.zig) and asks the supervisor
// only for file contents: lcMapFill fills private anonymous memory from a
// file, lcMapSection makes a section for a shared mapping and duplicates it
// into the stub. An executable private mapping is filled with its code
// rewritten: lcCodeSize sizes the trampolines, which the stub then places in
// branch range, and lcMapCode writes both.
const (
	lcMapFill    = 0x4c430020 // (fd, off, len, addr) -> 0
	lcMapSection = 0x4c430021 // (fd or -1, off, len, prot) -> section handle in the stub (0 when no byte of the file is past off), key in args[0], section size in args[1]
	lcCodeSize   = 0x4c430023 // (fd, off, len, addr) -> trampoline bytes
	lcMapCode    = 0x4c430024 // (fd, off, len, addr, n) -> 0, the n trampoline areas (base, size) in the slot scratch
	lcIdregs     = 0x4c430035 // () -> the guest's ID_AA64ISAR0/1/2 in args[0..2] (arm64)

	brkMax = 1 << 30 // the brk reservation after the image
	// brkGap is left free between the image and its brk area: the arm64 stub
	// puts a resume page there, in branch range of the image's code.
	brkGap = allocGran
)

// mapFile returns the open file a file mapping of guest fd reads.
func (g *wguest) mapFile(dg *dguest, fd uint64) (*dfile, lxErrno) {
	d, ok := dg.ft.get(int(fd))
	if !ok || d.fx.opath {
		return nil, lxEBADF
	}
	if d.fx.hasFlags && d.fx.oflags&lxOAccmod == lxOWronly {
		return nil, lxEACCES
	}
	if d.vf != nil { // a non-host regular file (in-memory, user-defined, network)
		return d, 0
	}
	if d.f == nil {
		return nil, lxEBADF
	}
	if d.isDir || d.pipe != nil || !d.isRegular() {
		return nil, lxENODEV
	}
	return d, 0
}

func (g *wguest) mapFill(dg *dguest, fd, off, n, addr uint64) int64 {
	d, e := g.mapFile(dg, fd)
	if e != 0 {
		return sErr(e)
	}
	buf := make([]byte, min(n, 1<<20))
	for done := uint64(0); done < n; {
		k, err := d.readAt(buf[:min(uint64(len(buf)), n-done)], int64(off+done))
		if k > 0 {
			if g.sp.writeMem(addr+done, buf[:k]) != nil {
				return sErr(lxEFAULT)
			}
			done += uint64(k)
		}
		if err == io.EOF || k == 0 {
			break // the rest stays zero, as past EOF on Linux
		}
		if err != nil {
			return sErr(osErrno(err))
		}
	}
	return 0
}

// mapSection makes the section of a shared mapping: of guest fd's file, or
// (fd = -1) of n bytes of anonymous memory. The reply's args[0] is the key
// shared futexes on it are matched by, args[1] the section's size: a file
// mapping may run past the end of the file, and the stub reserves the part
// the section does not hold. With nothing of the file past off there is no
// section, and the reply is 0.
func (g *wguest) mapSection(dg *dguest, fd, off, n, prot uint64) int64 {
	var sec windows.Handle
	var key, size uint64
	var err error
	if fd == ^uint64(0) {
		sec, err = windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE, uint32(n>>32), uint32(n), nil)
		key, size = sectionKeys.Add(1), n
	} else {
		d, e := g.mapFile(dg, fd)
		if e != 0 {
			return sErr(e)
		}
		if d.vf != nil {
			// A non-host file (in-memory, user-defined, network): the guest never
			// touches the real backing. A writable shared mapping maps the one
			// per-vnode backing (sharedback.go) through a file-backed section, so
			// every mapping and fork child is coherent and its stores are written
			// back to the file; its views and the supervisor's reads of the file
			// share the page cache. A read-only mapping maps an anonymous snapshot
			// the supervisor fills (no stores to track). An executable mapping is
			// rewritten elsewhere, so refuse it here.
			if prot&lxProtExec != 0 {
				return sErr(lxENODEV)
			}
			end := off + n
			if prot&lxProtWrite != 0 {
				sb, e := dg.sharedBackingWindows(d)
				if e != 0 {
					return sErr(e)
				}
				// A file-backed section may run past the end of the file, which
				// grows the backing file; write-back still covers only the file's
				// logical size, so the tail is not written to the backend.
				sec, err = windows.CreateFileMapping(windows.Handle(sb.f.Fd()), nil, windows.PAGE_READWRITE, uint32(end>>32), uint32(end), nil)
				key, size = sb.key, end
			} else {
				if sec, err = windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE, uint32(end>>32), uint32(end), nil); err == nil {
					err = g.fillSection(sec, d, off, n)
				}
				key, size = sectionKeys.Add(1), end
			}
		} else {
			page := uint32(windows.PAGE_READONLY)
			if prot&lxProtWrite != 0 {
				if !d.writable() {
					return sErr(lxEACCES)
				}
				page = windows.PAGE_READWRITE
			}
			// The section reaches only as far into the file as the view does:
			// one spanning the whole of a large sparse file is beyond the kernel
			// (.NET maps slices of a 2 TiB memfd), and one longer than the file
			// would grow it.
			var fi windows.ByHandleFileInformation
			if err = windows.GetFileInformationByHandle(windows.Handle(d.f.Fd()), &fi); err != nil {
				return sErr(osErrno(err))
			}
			end := min(off+n, uint64(fi.FileSizeHigh)<<32|uint64(fi.FileSizeLow))
			sec, err = windows.CreateFileMapping(windows.Handle(d.f.Fd()), nil, page, uint32(end>>32), uint32(end), nil)
			if err == windows.ERROR_FILE_INVALID { // an empty file
				dg.ch.page.args[0], dg.ch.page.args[1] = 0, 0
				return 0
			}
			if err == nil {
				if size, err = sectionSize(sec); err == nil && size <= off {
					windows.CloseHandle(sec)
					dg.ch.page.args[0], dg.ch.page.args[1] = 0, size
					return 0
				}
				if err != nil {
					windows.CloseHandle(sec)
				}
			}
			key = futexFileKey(windows.Handle(d.f.Fd()))
			if prot&lxProtExec != 0 {
				dg.codeKey(key) // its writes reach the stubs' shadows of its pages
			}
		}
	}
	if err != nil {
		return sErr(osErrno(err))
	}
	dg.ch.page.args[0], dg.ch.page.args[1] = key, size
	var h windows.Handle
	// Inheritable, so a fork child can map what survives a partial munmap.
	err = windows.DuplicateHandle(windows.CurrentProcess(), sec, g.sp.proc, &h, 0, true,
		windows.DUPLICATE_SAME_ACCESS|windows.DUPLICATE_CLOSE_SOURCE)
	if err != nil {
		windows.CloseHandle(sec)
		return sErr(osErrno(err))
	}
	return int64(h)
}

// sharedBackingWindows returns the one host object every writable MAP_SHARED
// mapping of d's vnode maps: a temp file holding the whole content, filled from
// the file. A file-backed section over it is coherent across opens and fork
// children, and sharedback.go writes its stores back to the file. Windows cannot
// unlink an open file, so the path is kept and removed on release. Every mapping
// of the vnode uses the same shared-futex key.
func (dg *dguest) sharedBackingWindows(d *dfile) (*shBacking, lxErrno) {
	fs := dg.dfs
	id := d.vn.ID()
	fs.shMu.Lock()
	defer fs.shMu.Unlock()
	if sb := fs.shared[id]; sb != nil {
		return sb, 0
	}
	a, err := d.vn.Stat()
	if err != nil {
		return nil, osErrno(err)
	}
	tf, err := os.CreateTemp("", "lc-shmem")
	if err != nil {
		return nil, osErrno(err)
	}
	if a.Size > 0 {
		if err := tf.Truncate(a.Size); err != nil {
			tf.Close()
			os.Remove(tf.Name())
			return nil, osErrno(err)
		}
		if err := fillFrom(tf, d.vf, a.Size); err != nil {
			tf.Close()
			os.Remove(tf.Name())
			return nil, osErrno(err)
		}
	}
	sb := &shBacking{f: tf, vf: d.vf, size: a.Size, eof: a.Size, path: tf.Name(), key: sectionKeys.Add(1)}
	fs.putBacking(id, sb)
	return sb, 0
}

var procNtQuerySection = modNtdll.NewProc("NtQuerySection")

// sectionSize returns the size of section sec.
func sectionSize(sec windows.Handle) (uint64, error) {
	var info struct { // SECTION_BASIC_INFORMATION
		base  uintptr
		attrs uint32
		size  int64
	}
	if st, _, _ := procNtQuerySection.Call(uintptr(sec), 0, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 0); st != 0 {
		return 0, ntErr("query section", st)
	}
	return uint64(info.size), nil
}

// fillSection fills the anonymous section sec, at the mapping's own offsets, from
// the file through its ReadAt — the supervisor's copy into the section the guest
// will map, so an in-memory or network file maps like a host file. Bytes past the
// content stay zero, as the pagefile-backed section is zero to begin with.
func (g *wguest) fillSection(sec windows.Handle, d *dfile, off, n uint64) error {
	base, err := windows.MapViewOfFile(sec, windows.FILE_MAP_WRITE, 0, 0, uintptr(off+n))
	if err != nil {
		return err
	}
	defer windows.UnmapViewOfFile(base)
	view := unsafe.Slice((*byte)(unsafe.Pointer(base)), off+n)
	for done := uint64(0); done < n; {
		k, e := d.readAt(view[off+done:off+n], int64(off+done))
		if k > 0 {
			done += uint64(k)
		}
		if e == io.EOF || k == 0 {
			break
		}
		if e != nil {
			return e
		}
	}
	return nil
}

// codeImage is the ELF behind d for rewriting: the host file, or a non-host
// file (in-memory, user-defined, network) read whole through its ReaderAt. A
// host file keeps its identity so the plan cache finds it again; a non-host
// file has none and is analyzed by its content instead.
func (g *wguest) codeImage(d *dfile) (imageSrc, error) {
	if d.f != nil {
		return imageSrc{f: d.f}, nil
	}
	b, err := io.ReadAll(io.NewSectionReader(d.vf, 0, 1<<62))
	if err != nil {
		return imageSrc{}, err
	}
	return imageSrc{data: b}, nil
}

// codeFill reads [off, off+n) of guest fd's file and rewrites the parts the
// file's executable segments cover, as mapped at addr with its trampolines in
// areas. It returns the bytes, each area's contents and where traps were
// left; with no area, every site traps. The bytes flow through the supervisor
// (d.readAt), so a non-host file's code is rewritten and mapped like a host
// file's without the stub ever touching the backing.
func (g *wguest) codeFill(dg *dguest, fd, off, n, addr uint64, areas []trampArea) ([]byte, [][]byte, []uint64, lxErrno) {
	d, e := g.mapFile(dg, fd)
	if e != 0 {
		return nil, nil, nil, e
	}
	buf := make([]byte, n)
	k, err := d.readAt(buf, int64(off))
	if err != nil && err != io.EOF {
		return nil, nil, nil, osErrno(err)
	}
	clear(buf[k:])
	if g.cfg.NoRewrite {
		return buf, nil, nil, 0
	}
	src, serr := g.codeImage(d)
	if serr != nil {
		return nil, nil, nil, osErrno(serr)
	}
	f, err := elf.NewFile(src.reader())
	if err != nil || f.Machine != elfMachine {
		return nil, nil, nil, lxEACCES // code that is not ours to rewrite
	}
	rw, err := g.newRewriter(src)
	if err != nil {
		return nil, nil, nil, lxEACCES
	}
	if areas == nil {
		areas = rw.sizingAreas(addr, n)
	}
	rw.place(areas)
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		lo, hi := max(p.Off, off), min(p.Off+p.Filesz, off+n)
		if lo >= hi {
			continue
		}
		rw.segment(buf[lo-off:hi-off], addr+lo-off, p.Vaddr+lo-p.Off)
	}
	tr, err := rw.finish(addr, addr+n)
	if err != nil {
		g.tracef("[lc] code at %#x: %v\n", addr, err)
		return nil, nil, nil, lxEACCES
	}
	return buf, tr, rw.traps(), 0
}

// codeSize is the room the trampolines of a code mapping need: in each of
// its areas, of which there may be one on either side of it.
func (g *wguest) codeSize(dg *dguest, fd, off, n, addr uint64) int64 {
	_, tr, _, e := g.codeFill(dg, fd, off, n, addr, nil)
	if e != 0 {
		return sErr(e)
	}
	var need int
	for _, t := range tr {
		need += len(t)
	}
	return int64(need)
}

func (g *wguest) mapCode(dg *dguest, fd, off, n, addr, count uint64) int64 {
	sc := dg.scratch()
	if count > uint64(len(sc)/16) {
		return sErr(lxEINVAL)
	}
	areas := make([]trampArea, count)
	for i := range areas {
		areas[i] = trampArea{binary.LittleEndian.Uint64(sc[16*i:]), binary.LittleEndian.Uint64(sc[16*i+8:])}
	}
	buf, tr, traps, e := g.codeFill(dg, fd, off, n, addr, areas)
	if e != 0 {
		return sErr(e)
	}
	for i, a := range areas {
		if uint64(len(tr[i])) > a.size {
			return sErr(lxENOMEM)
		}
	}
	ranges := [][2]uint64{{addr, addr + n}}
	for _, a := range areas {
		ranges = append(ranges, [2]uint64{a.base, a.base + a.size})
	}
	g.traps.set(ranges, traps)
	if g.sp.writeMem(addr, buf) != nil {
		return sErr(lxEFAULT)
	}
	for i, a := range areas {
		if g.sp.writeMem(a.base, tr[i]) != nil {
			return sErr(lxEFAULT)
		}
	}
	g.sp.flushCode(addr, n)
	g.st.addCode(addr, addr+n)
	for _, a := range areas {
		g.sp.flushCode(a.base, a.size)
		g.st.addCode(a.base, a.base+a.size)
	}
	return 0
}
