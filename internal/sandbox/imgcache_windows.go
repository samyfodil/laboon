//go:build windows

package sandbox

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/samyfodil/laboon/internal/rewrite"
	winstub "github.com/samyfodil/laboon/stub/windows"
	"golang.org/x/sys/windows"
)

// A rewritten image is kept on disk, and later loads map its read-only part
// (the trampolines and every segment below the first writable one) into the
// stub as a view of that file instead of reading, rewriting and copying it
// again; only the writable segments are copied. The view is shared by every
// process that runs the image and kept by a fork child, as the stub's own
// shared mappings are.
//
// Images live in the img subdirectory of the rewrite cache's directory
// (NewCache), so a cache in memory only keeps none, and only images of
// stable files (imageSrc.stable) are kept: a binary a guest builds and runs
// would add one each run. The directory is bounded (imgStore). An entry is
// keyed by the file's identity, the stub, its entry points and the build of
// the supervisor that rewrote it, since the trampolines are that build's
// code; a rebuilt supervisor's entries replace the old ones as they go
// unused. A position-independent image is stored at the bias it was first
// loaded at and moved to each load's (wimage.relocate): its trampolines
// address the guest only relative to the code.

type imgView struct {
	sec  windows.Handle
	size uint64 // bytes from the image's lo mapped from the file
}

type imgMeta struct {
	Entry, Phdr, Phnum, Lo, Hi, Base uint64
	Interp                           string
	View, Tail                       uint64
	Prots                            [][3]uint64
	Segs                             [][5]uint64
	Traps                            []uint64
}

// buildKey names what a prepared image depends on besides its file: the
// stub, this supervisor's build and the entry format. A supervisor with no
// build ID (linked with -buildid=) is named by its executable's identity.
var buildKey = sync.OnceValue(func() []byte {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	f, err := os.Open(exe)
	if err != nil {
		return nil
	}
	defer f.Close()
	s := sha256.Sum256(winstub.Binary)
	b := binary.LittleEndian.AppendUint64(s[:8], imgCacheVersion)
	if id := goBuildID(f); id != "" {
		return append(b, id...)
	}
	id, ok := fileIdentity(f)
	if !ok {
		return nil
	}
	return append(b, idBytes(id)...)
})

// imgCacheVersion changes when what an entry holds does.
const imgCacheVersion = 2

func idBytes(id rewrite.FileID) []byte {
	b := binary.LittleEndian.AppendUint64(nil, id.Dev)
	b = binary.LittleEndian.AppendUint64(b, id.Ino)
	b = binary.LittleEndian.AppendUint64(b, uint64(id.Size))
	b = binary.LittleEndian.AppendUint64(b, uint64(id.Mtime))
	return binary.LittleEndian.AppendUint64(b, uint64(id.Ctime))
}

// imgEntryOf is the store and entry name for src, or nil when it has none.
func (g *wguest) imgEntryOf(src imageSrc) (*imgStore, string) {
	if !src.stable || !src.hasID || src.id.Unlinked || testNoImgCache || g.cache.Dir() == "" {
		return nil, ""
	}
	key := buildKey()
	if key == nil {
		return nil, ""
	}
	b := append([]byte(guestArch), key...)
	b = append(b, idBytes(src.id)...)
	for _, v := range []uint64{g.entry, g.exitEntry} {
		b = binary.LittleEndian.AppendUint64(b, v)
	}
	if g.cfg.NoRewrite {
		b = append(b, 'n')
	}
	if strictRewrite {
		b = append(b, 's')
	}
	h := sha256.Sum256(b)
	return newImgStore(filepath.Join(g.cache.Dir(), "img"), maxImgFiles, maxImgBytes), hex.EncodeToString(h[:16])
}

// cachedImage returns the image stored as name, with its view, or nil.
func cachedImage(st *imgStore, name string) *wimage {
	path := st.path(name)
	mb, err := os.ReadFile(path + imgMetaExt)
	if err != nil {
		return nil
	}
	var m imgMeta
	if json.Unmarshal(mb, &m) != nil || m.View == 0 || m.Lo+m.View > m.Hi || m.Tail > m.Hi-m.Lo-m.View {
		return nil
	}
	fp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}
	h, err := windows.CreateFile(fp, windows.GENERIC_READ|windows.GENERIC_EXECUTE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)
	tail := make([]byte, m.Tail)
	if m.Tail > 0 {
		var n uint32
		ov := windows.Overlapped{Offset: uint32(m.View), OffsetHigh: uint32(m.View >> 32)}
		if windows.ReadFile(h, tail, &n, &ov) != nil || uint64(n) != m.Tail {
			return nil
		}
	}
	sec, err := windows.CreateFileMapping(h, nil, windows.PAGE_EXECUTE_READ, uint32(m.View>>32), uint32(m.View), nil)
	if err != nil {
		return nil
	}
	img := &wimage{entry: m.Entry, phdr: m.Phdr, phnum: m.Phnum, lo: m.Lo, hi: m.Hi, base: m.Base, interp: m.Interp,
		bytes: tail, view: &imgView{sec: sec, size: m.View}, traps: m.Traps}
	for _, p := range m.Prots {
		img.prots = append(img.prots, wrun{p[0], p[1], uint32(p[2])})
	}
	for _, s := range m.Segs {
		img.segs = append(img.segs, mapEnt{s[0], s[1], s[2], s[3], s[4]})
	}
	st.used(name)
	return img
}

// saveImage stores img as name, prepared by loadELF with its trampolines at
// its lo and no read-only segment past view, so later loads can map it. A
// failure only costs those loads the work.
func saveImage(st *imgStore, name string, img *wimage, view uint64) {
	if st == nil || view == 0 || view > img.hi-img.lo {
		return
	}
	tail := img.bytes[view:]
	for len(tail) > 0 && tail[len(tail)-1] == 0 {
		tail = tail[:len(tail)-1]
	}
	m := imgMeta{Entry: img.entry, Phdr: img.phdr, Phnum: img.phnum, Lo: img.lo, Hi: img.hi, Base: img.base,
		Interp: img.interp, View: view, Tail: uint64(len(tail)), Traps: img.traps}
	for _, p := range img.prots {
		m.Prots = append(m.Prots, [3]uint64{p.lo, p.hi, uint64(p.prot)})
	}
	for _, s := range img.segs {
		m.Segs = append(m.Segs, [5]uint64{s.lo, s.hi, s.off, s.aux, s.attr})
	}
	mb, err := json.Marshal(m)
	if err != nil {
		return
	}
	size := int64(view) + int64(len(tail)) + int64(len(mb))
	if !st.fits(size) {
		return
	}
	if err := os.MkdirAll(st.dir, 0o700); err != nil {
		return
	}
	// The data first, the metadata last: an entry is only used whole.
	path := st.path(name)
	if writeImgAtomic(path, img.bytes[:view], tail) != nil {
		return
	}
	if writeImgAtomic(path+imgMetaExt, mb, nil) != nil {
		return
	}
	st.saved(name)
}

var (
	modNtdll                      = windows.NewLazySystemDLL("ntdll.dll")
	procNtAllocateVirtualMemoryEx = modNtdll.NewProc("NtAllocateVirtualMemoryEx")
	procNtFreeVirtualMemory       = modNtdll.NewProc("NtFreeVirtualMemory")
	procNtMapViewOfSectionEx      = modNtdll.NewProc("NtMapViewOfSectionEx")
)

// testNoImgCache makes every load rewrite and copy its image.
var testNoImgCache bool

const (
	memReservePlaceholder  = 0x40000
	memReplacePlaceholder  = 0x4000
	memPreservePlaceholder = 0x2
)

// mapImageView installs img's view and copies its writable tail: the range
// is reserved as a placeholder, split at the view's end and both parts
// replaced.
func (g *wguest) mapImageView(img *wimage) error {
	defer windows.CloseHandle(img.view.sec)
	proc := uintptr(g.sp.proc)
	lo, mid, hi := img.lo, img.lo+img.view.size, img.hi
	base, size := uintptr(lo), uintptr(hi-lo)
	if st, _, _ := procNtAllocateVirtualMemoryEx.Call(proc, uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&size)),
		windows.MEM_RESERVE|memReservePlaceholder, windows.PAGE_NOACCESS, 0, 0); st != 0 {
		return ntErr("reserve image", st)
	}
	if mid < hi {
		base, size = uintptr(lo), uintptr(mid-lo)
		if st, _, _ := procNtFreeVirtualMemory.Call(proc, uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&size)),
			windows.MEM_RELEASE|memPreservePlaceholder); st != 0 {
			return ntErr("split image", st)
		}
	}
	base, size = uintptr(lo), uintptr(mid-lo)
	var off int64
	if st, _, _ := procNtMapViewOfSectionEx.Call(uintptr(img.view.sec), proc, uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&off)), uintptr(unsafe.Pointer(&size)), memReplacePlaceholder, windows.PAGE_EXECUTE_READ, 0, 0); st != 0 {
		return ntErr("map image", st)
	}
	if mid < hi {
		base, size = uintptr(mid), uintptr(hi-mid)
		if st, _, _ := procNtAllocateVirtualMemoryEx.Call(proc, uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&size)),
			windows.MEM_RESERVE|windows.MEM_COMMIT|memReplacePlaceholder, windows.PAGE_READWRITE, 0, 0); st != 0 {
			return ntErr("image data", st)
		}
		if err := g.sp.writeMem(mid, img.bytes); err != nil {
			return err
		}
		if err := g.sp.protect(mid, hi-mid, windows.PAGE_NOACCESS); err != nil {
			return err
		}
	}
	if err := g.sp.flushCode(lo, mid-lo); err != nil {
		return err
	}
	if err := g.sp.protect(lo, mid-lo, windows.PAGE_NOACCESS); err != nil {
		return err
	}
	for _, r := range img.prots {
		if err := g.sp.protect(r.lo, r.hi-r.lo, r.prot); err != nil {
			return err
		}
	}
	return nil
}

func ntErr(what string, st uintptr) error {
	return &os.SyscallError{Syscall: what, Err: windows.NTStatus(st)}
}
