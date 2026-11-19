//go:build windows

package hostfs

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/samyfodil/laboon/core"
)

// The Windows HostFS. NTFS has no POSIX modes, owners, FIFOs or usable
// symlinks, so a side table keyed by (volume serial, file id) holds each
// object's Linux mode, type bits included. A Linux symlink is a regular file
// whose content is the target, typed S_IFLNK in the table; the overlay
// resolves it, never NTFS. The table follows renames and hard links, as the
// file id does. The lower layer's entries come from <root>.lcmeta, written
// when the rootfs is built; an entry-less lower file is 0755, an upper one
// gets its mode when the guest creates it.
//
// Guest names NTFS cannot hold are escaped (winfs.go) and unescaped on
// readdir.
//
// Directories we create are case-sensitive (FILE_CASE_SENSITIVE_INFORMATION,
// inherited by subdirectories). On a layer without the flag each lookup checks
// the exact on-disk name of its last component; the overlay resolves a path
// one component at a time, so every component gets checked.

type fileKey struct {
	vol uint32
	id  uint64
}

// winMeta is the side table, shared by every Run in the process: file ids are
// unique per volume and NTFS bumps an id's sequence number on reuse.
var winMeta struct {
	mu     sync.Mutex
	m      map[fileKey]uint32
	own    map[fileKey][2]uint32 // lower files' owners, when not root
	loaded map[string]bool       // lower roots whose .lcmeta is in m
}

func metaGet(k fileKey) (uint32, bool) {
	winMeta.mu.Lock()
	defer winMeta.mu.Unlock()
	m, ok := winMeta.m[k]
	return m, ok
}

func metaSet(k fileKey, mode uint32) {
	winMeta.mu.Lock()
	defer winMeta.mu.Unlock()
	if winMeta.m == nil {
		winMeta.m = map[fileKey]uint32{}
	}
	winMeta.m[k] = mode
}

func metaDel(k fileKey) {
	winMeta.mu.Lock()
	defer winMeta.mu.Unlock()
	delete(winMeta.m, k)
}

type WinFS struct {
	rootAbs, upperAbs, workAbs string
	lowerExact, upperExact     bool // the layer is case-insensitive: check exact names
}

// HostONonblock is the host open flag for a non-blocking open; Windows files
// have none.
const HostONonblock = 0

// FifoRendezvous is false: Windows has no real FIFOs (a named-pipe node is
// metadata only), so a FIFO open goes straight to the backend with no
// reader/writer rendezvous.
const FifoRendezvous = false

func NewHostFS(rootAbs, upperAbs, workAbs string) HostFS {
	fs := &WinFS{rootAbs: rootAbs, upperAbs: upperAbs, workAbs: workAbs}
	for _, d := range []string{upperAbs, workAbs} {
		if d != "" && !SetCaseSensitive(d) {
			fs.upperExact = true
		}
	}
	if rootAbs != "" {
		fs.lowerExact = !CaseSensitive(rootAbs)
		loadLowerMeta(rootAbs)
	}
	return fs
}

// NewRawHostFS is an uncached host backend confined to root (see the linux note).
func NewRawHostFS(root string) HostFS { return &WinFS{rootAbs: root} }

const fileFlagsReparseBackup = windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_REPARSE_POINT

var extPath = ExtPath

func openAttr(p string, access uint32) (windows.Handle, error) {
	return windows.CreateFile(extPath(p), access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, fileFlagsReparseBackup, 0)
}

// loadLowerMeta reads <root>.lcmeta (winfs.go): each entry's mode, and
// its owner when it is not root's.
func loadLowerMeta(root string) {
	winMeta.mu.Lock()
	done := winMeta.loaded[root]
	if winMeta.loaded == nil {
		winMeta.loaded = map[string]bool{}
	}
	winMeta.loaded[root] = true
	winMeta.mu.Unlock()
	if done {
		return
	}
	f, err := os.Open(root + MetaSuffix)
	if err != nil {
		return
	}
	defer f.Close()
	rk, _, err := keyOf(root)
	if err != nil {
		return
	}
	cache := lowerMetaCache(root, f, rk)
	ents, ok := readMetaCache(cache)
	if !ok {
		ents = scanLowerMeta(root, f)
		writeMetaCache(cache, ents)
	}
	for _, e := range ents {
		k := fileKey{rk.vol, e.id}
		metaSet(k, e.mode)
		if e.uid != 0 || e.gid != 0 {
			winMeta.mu.Lock()
			if winMeta.own == nil {
				winMeta.own = map[fileKey][2]uint32{}
			}
			winMeta.own[k] = [2]uint32{e.uid, e.gid}
			winMeta.mu.Unlock()
		}
	}
}

// metaEnt is one lower file's stored metadata, by its file id.
type metaEnt struct {
	id             uint64
	mode, uid, gid uint32
}

// scanLowerMeta resolves the .lcmeta entries to file ids. One directory
// listing per directory gives every entry's file id, far cheaper than
// opening each file.
func scanLowerMeta(root string, f *os.File) []metaEnt {
	var out []metaEnt
	dirs := map[string]map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		e, ok := ParseEntry(sc.Text())
		if !ok {
			continue
		}
		dir, name := path.Split("/" + e.Path)
		ids, ok := dirs[dir]
		if !ok {
			ids = dirIDs(HostPath(root, dir))
			dirs[dir] = ids
		}
		if id, ok := ids[EscapeName(name)]; ok {
			out = append(out, metaEnt{id, e.Mode, e.Uid, e.Gid})
		}
	}
	return out
}

// lowerMetaCache names the file that keeps a lower layer's resolved
// metadata between runs, in the user cache directory: keyed by the root's
// volume and file id and the .lcmeta file's size and time, so an extracted
// image is resolved once. "" when there is no cache directory.
func lowerMetaCache(root string, f *os.File, rk fileKey) string {
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	h := sha256.Sum256(fmt.Appendf(nil, "lcmeta-1 %s %d %d %d %d", root, rk.vol, rk.id, fi.Size(), fi.ModTime().UnixNano()))
	return filepath.Join(d, "laboon", "meta", hex.EncodeToString(h[:16]))
}

func readMetaCache(name string) ([]metaEnt, bool) {
	if name == "" {
		return nil, false
	}
	b, err := os.ReadFile(name)
	if err != nil || len(b)%20 != 0 {
		return nil, false
	}
	out := make([]metaEnt, 0, len(b)/20)
	for ; len(b) > 0; b = b[20:] {
		out = append(out, metaEnt{binary.LittleEndian.Uint64(b), binary.LittleEndian.Uint32(b[8:]), binary.LittleEndian.Uint32(b[12:]), binary.LittleEndian.Uint32(b[16:])})
	}
	return out, true
}

// writeMetaCache stores ents; a failure only costs a scan next time.
func writeMetaCache(name string, ents []metaEnt) {
	if name == "" || os.MkdirAll(filepath.Dir(name), 0o700) != nil {
		return
	}
	b := make([]byte, 0, 20*len(ents))
	for _, e := range ents {
		b = binary.LittleEndian.AppendUint64(b, e.id)
		b = binary.LittleEndian.AppendUint32(b, e.mode)
		b = binary.LittleEndian.AppendUint32(b, e.uid)
		b = binary.LittleEndian.AppendUint32(b, e.gid)
	}
	f, err := os.CreateTemp(filepath.Dir(name), ".meta-*")
	if err != nil {
		return
	}
	_, werr := f.Write(b)
	if f.Close() != nil || werr != nil || os.Rename(f.Name(), name) != nil {
		os.Remove(f.Name())
	}
}

// dirIDs maps the names in host directory dir to their file ids.
func dirIDs(dir string) map[string]uint64 {
	ids := map[string]uint64{}
	h, err := openAttr(dir, windows.FILE_LIST_DIRECTORY|windows.SYNCHRONIZE)
	if err != nil {
		return ids
	}
	defer windows.CloseHandle(h)
	buf := make([]byte, 64<<10)
	class := uint32(windows.FileIdBothDirectoryRestartInfo)
	for windows.GetFileInformationByHandleEx(h, class, &buf[0], uint32(len(buf))) == nil {
		class = windows.FileIdBothDirectoryInfo
		// FILE_ID_BOTH_DIR_INFO: NextEntryOffset at 0, FileNameLength at 60,
		// FileId at 96, FileName at 104.
		for off := 0; off+104 <= len(buf); {
			e := buf[off:]
			n := int(binary.LittleEndian.Uint32(e[60:]))
			if 104+n > len(e) {
				break
			}
			name := make([]uint16, n/2)
			for i := range name {
				name[i] = binary.LittleEndian.Uint16(e[104+2*i:])
			}
			ids[windows.UTF16ToString(name)] = binary.LittleEndian.Uint64(e[96:])
			next := int(binary.LittleEndian.Uint32(e))
			if next == 0 {
				break
			}
			off += next
		}
	}
	return ids
}

func keyOf(p string) (fileKey, *windows.ByHandleFileInformation, error) {
	h, err := openAttr(p, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return fileKey{}, nil, &os.PathError{Op: "lstat", Path: p, Err: err}
	}
	defer windows.CloseHandle(h)
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return fileKey{}, nil, &os.PathError{Op: "lstat", Path: p, Err: err}
	}
	return handleKey(&fi), &fi, nil
}

func handleKey(fi *windows.ByHandleFileInformation) fileKey {
	return fileKey{fi.VolumeSerialNumber, uint64(fi.FileIndexHigh)<<32 | uint64(fi.FileIndexLow)}
}

func filetimeTs(t windows.Filetime) syscall.Timespec {
	return syscall.NsecToTimespec(t.Nanoseconds())
}

// byHandleStat is a host file's HostStat from its handle information and the
// side table.
func byHandleStat(fi *windows.ByHandleFileInformation) HostStat {
	k := handleKey(fi)
	st := HostStat{
		dev: uint64(k.vol), ino: k.id,
		nlink: fi.NumberOfLinks, size: int64(fi.FileSizeHigh)<<32 | int64(fi.FileSizeLow),
		blksize: 4096,
		atime:   filetimeTs(fi.LastAccessTime), mtime: filetimeTs(fi.LastWriteTime),
		ctime: filetimeTs(fi.LastWriteTime), btime: filetimeTs(fi.CreationTime),
	}
	st.blocks = (st.size + 511) / 512
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		st.mode = lxSIFDIR | 0o755
	} else {
		st.mode = lxSIFREG | 0o755
	}
	if m, ok := metaGet(k); ok {
		st.mode = m
	}
	return st
}

// winInfo is the os.FileInfo of an hLstat; Sys is its *HostStat.
type winInfo struct {
	name string
	st   HostStat
}

func (w *winInfo) Name() string       { return w.name }
func (w *winInfo) Size() int64        { return w.st.size }
func (w *winInfo) ModTime() time.Time { return time.Unix(w.st.mtime.Sec, w.st.mtime.Nsec) }
func (w *winInfo) IsDir() bool        { return w.st.mode&lxSIFMT == lxSIFDIR }
func (w *winInfo) Sys() any           { return &w.st }

func (w *winInfo) Mode() os.FileMode {
	m := os.FileMode(w.st.mode & 0o777)
	switch w.st.mode & lxSIFMT {
	case lxSIFDIR:
		m |= os.ModeDir
	case lxSIFLNK:
		m |= os.ModeSymlink
	case lxSIFIFO:
		m |= os.ModeNamedPipe
	case lxSIFSCK:
		m |= os.ModeSocket
	case lxSIFCHR:
		m |= os.ModeDevice | os.ModeCharDevice
	case lxSIFBLK:
		m |= os.ModeDevice
	}
	if w.st.mode&0o4000 != 0 {
		m |= os.ModeSetuid
	}
	if w.st.mode&0o2000 != 0 {
		m |= os.ModeSetgid
	}
	if w.st.mode&0o1000 != 0 {
		m |= os.ModeSticky
	}
	return m
}

// StatOf is fi's HostStat when fi describes a host file.
func StatOf(fi os.FileInfo) (HostStat, bool) {
	if st, ok := fi.Sys().(*HostStat); ok {
		return *st, true
	}
	return HostStat{}, false
}

// FileStat is the os.FileInfo of the open file f.
func FileStat(f *os.File) (os.FileInfo, error) {
	h := windows.Handle(f.Fd())
	name := UnescapeName(filepath.Base(f.Name()))
	switch t, _ := windows.GetFileType(h); t {
	case windows.FILE_TYPE_PIPE:
		return &winInfo{name: name, st: HostStat{mode: lxSIFIFO | 0o600, nlink: 1, blksize: 4096, ino: uint64(h)}}, nil
	case windows.FILE_TYPE_CHAR:
		if f.Name() == "pipe:" {
			return &winInfo{name: name, st: HostStat{mode: lxSIFIFO | 0o600, nlink: 1, blksize: 4096, ino: uint64(h)}}, nil
		}
		if strings.HasPrefix(f.Name(), "socket:") {
			return &winInfo{name: name, st: HostStat{mode: lxSIFSCK | 0o777, nlink: 1, blksize: 4096, ino: uint64(h)}}, nil
		}
		return &winInfo{name: name, st: HostStat{mode: lxSIFCHR | 0o620, nlink: 1, blksize: 4096, ino: uint64(h)}}, nil
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return nil, &os.PathError{Op: "fstat", Path: f.Name(), Err: err}
	}
	return &winInfo{name: name, st: byHandleStat(&fi)}, nil
}

func FstatOf(f *os.File) (HostStat, error) {
	fi, err := FileStat(f)
	if err != nil {
		return HostStat{}, err
	}
	return *fi.Sys().(*HostStat), nil
}

// ---- names -------------------------------------------------------------------

// HostPath is the host path of resolved guest path gp under root.
func HostPath(root, gp string) string {
	var b strings.Builder
	b.WriteString(root)
	for _, c := range strings.Split(gp, "/") {
		if c == "" {
			continue
		}
		b.WriteByte('\\')
		b.WriteString(EscapeName(c))
	}
	if b.Len() == len(root) && !strings.HasSuffix(root, `\`) {
		return root
	}
	return b.String()
}

func (fs *WinFS) exact(p string) bool {
	switch {
	case fs.rootAbs != "" && strings.HasPrefix(p, fs.rootAbs+`\`):
		if !fs.lowerExact {
			return true
		}
	case fs.upperExact:
	default:
		return true
	}
	var fd windows.Win32finddata
	h, err := windows.FindFirstFile(extPath(p), &fd)
	if err != nil {
		return true // the operation itself reports the error
	}
	windows.FindClose(h)
	return windows.UTF16ToString(fd.FileName[:]) == filepath.Base(p)
}

func notExist(op, p string) error {
	return &os.PathError{Op: op, Path: p, Err: windows.ERROR_FILE_NOT_FOUND}
}

// ---- HostFS ----------------------------------------------------------------------

func (fs *WinFS) hOpen(p string, flag int, perm os.FileMode) (*os.File, error) {
	if !fs.exact(p) {
		return nil, notExist("open", p)
	}
	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_WRONLY:
		access = windows.GENERIC_WRITE
	case os.O_RDWR:
		access = windows.GENERIC_READ | windows.GENERIC_WRITE
	default:
		access = windows.GENERIC_READ
	}
	if flag&os.O_APPEND != 0 && access&windows.GENERIC_WRITE != 0 {
		// Append-only access: every write lands at the end, as with O_APPEND.
		access &^= windows.GENERIC_WRITE
		access |= windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.READ_CONTROL | windows.SYNCHRONIZE
	}
	access |= windows.FILE_READ_ATTRIBUTES | windows.FILE_WRITE_ATTRIBUTES
	var disp uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		disp = windows.CREATE_NEW
	case flag&(os.O_CREATE|os.O_TRUNC) == os.O_CREATE|os.O_TRUNC:
		disp = windows.CREATE_ALWAYS
	case flag&os.O_CREATE != 0:
		disp = windows.OPEN_ALWAYS
	case flag&os.O_TRUNC != 0:
		disp = windows.TRUNCATE_EXISTING
	default:
		disp = windows.OPEN_EXISTING
	}
	h, err := windows.CreateFile(extPath(p), access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, disp, fileFlagsReparseBackup, 0)
	if err == windows.ERROR_ACCESS_DENIED && access&windows.FILE_WRITE_ATTRIBUTES != 0 {
		access &^= windows.FILE_WRITE_ATTRIBUTES
		h, err = windows.CreateFile(extPath(p), access,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, disp, fileFlagsReparseBackup, 0)
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: p, Err: lxELOOP}
	}
	if disp == windows.CREATE_NEW {
		metaSet(handleKey(&fi), lxSIFREG|uint32(perm.Perm()))
	}
	return os.NewFile(uintptr(h), p), nil
}

func (fs *WinFS) hLstat(p string) (os.FileInfo, error) {
	if !fs.exact(p) {
		return nil, notExist("lstat", p)
	}
	_, fi, err := keyOf(p)
	if err != nil {
		return nil, err
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, &os.PathError{Op: "lstat", Path: p, Err: lxELOOP}
	}
	return &winInfo{name: UnescapeName(filepath.Base(p)), st: byHandleStat(fi)}, nil
}

func (fs *WinFS) hReadlink(p string) (string, error) {
	fi, err := fs.hLstat(p)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return "", &os.PathError{Op: "readlink", Path: p, Err: lxEINVAL}
	}
	b, err := os.ReadFile(p)
	return string(b), err
}

func (fs *WinFS) hMkdir(p string, perm uint32) error {
	if err := windows.CreateDirectory(extPath(p), nil); err != nil {
		return &os.PathError{Op: "mkdir", Path: p, Err: err}
	}
	if k, _, err := keyOf(p); err == nil {
		metaSet(k, lxSIFDIR|perm&0o7777)
	}
	return nil
}

// mkTyped creates p as a regular file holding data, typed mode in the table.
func (fs *WinFS) mkTyped(p string, mode uint32, data []byte) error {
	f, err := fs.hOpen(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	fi, serr := FileStat(f)
	f.Close()
	if werr == nil {
		werr = serr
	}
	if werr != nil {
		os.Remove(p)
		return werr
	}
	st := fi.Sys().(*HostStat)
	metaSet(fileKey{uint32(st.dev), st.ino}, mode)
	return nil
}

func (fs *WinFS) hSymlink(target, p string) error {
	return fs.mkTyped(p, lxSIFLNK|0o777, []byte(target))
}

func (fs *WinFS) hMkfifo(p string, perm uint32) error {
	return fs.mkTyped(p, lxSIFIFO|perm&0o7777, nil)
}

func (fs *WinFS) hMksock(p string, perm uint32) error {
	return fs.mkTyped(p, lxSIFSCK|perm&0o7777, nil)
}

type fileRenameInfoEx struct {
	flags      uint32
	root       windows.Handle
	nameLength uint32
	name       [1]uint16
}

const (
	fileRenameInfoExClass  = 22 // FileRenameInfoEx
	renameReplaceIfExists  = 0x1
	renamePosixSemantics   = 0x2
	renameIgnoreReadonly   = 0x40
	fileDispositionInfoEx  = 21 // FileDispositionInfoEx
	dispositionDelete      = 0x1
	dispositionPosix       = 0x2
	dispositionIgnoreRdonl = 0x10
)

// renameHandle renames the open file h to to, replacing it if it exists, with
// POSIX semantics: open handles to the replaced file stay valid.
func renameHandle(h windows.Handle, to string) error {
	name, err := windows.UTF16FromString(`\??\` + to)
	if err != nil {
		return err
	}
	name = name[:len(name)-1]
	buf := make([]byte, int(unsafe.Offsetof(fileRenameInfoEx{}.name))+2*len(name)+2)
	ri := (*fileRenameInfoEx)(unsafe.Pointer(&buf[0]))
	ri.flags = renameReplaceIfExists | renamePosixSemantics | renameIgnoreReadonly
	ri.nameLength = uint32(2 * len(name))
	copy(unsafe.Slice(&ri.name[0], len(name)), name)
	return windows.SetFileInformationByHandle(h, fileRenameInfoExClass, &buf[0], uint32(len(buf)))
}

func (fs *WinFS) hRename(from, to string, exchange bool) error {
	if exchange {
		tmp := filepath.Join(fs.workAbs, "xchg-"+strconv.FormatUint(hostSeq.Add(1), 10))
		if err := fs.hRename(from, tmp, false); err != nil {
			return err
		}
		if err := fs.hRename(to, from, false); err != nil {
			fs.hRename(tmp, from, false)
			return err
		}
		return fs.hRename(tmp, to, false)
	}
	h, err := windows.CreateFile(extPath(from), windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, fileFlagsReparseBackup, 0)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	defer windows.CloseHandle(h)
	err = renameHandle(h, to)
	if err == windows.ERROR_ACCESS_DENIED {
		// A directory cannot replace one; Linux allows it over an empty one.
		if t, terr := fs.hLstat(to); terr == nil && t.IsDir() {
			if rerr := windows.RemoveDirectory(extPath(to)); rerr != nil {
				return &os.LinkError{Op: "rename", Old: from, New: to, Err: rerr}
			}
			err = renameHandle(h, to)
		}
	}
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}

func (fs *WinFS) hUnlink(p string, dir bool) error {
	k, fi, err := keyOf(p)
	if err != nil {
		return err
	}
	isDir := fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if dir != isDir {
		if dir {
			return &os.PathError{Op: "rmdir", Path: p, Err: lxENOTDIR}
		}
		return &os.PathError{Op: "unlink", Path: p, Err: lxEISDIR}
	}
	if dir {
		err = windows.RemoveDirectory(extPath(p))
	} else {
		err = deletePosix(p)
	}
	if err != nil {
		return &os.PathError{Op: "unlink", Path: p, Err: err}
	}
	if fi.NumberOfLinks <= 1 {
		metaDel(k)
	}
	return nil
}

// deletePosix unlinks p with POSIX semantics: the name goes at once even while
// the file is open.
func deletePosix(p string) error {
	h, err := windows.CreateFile(extPath(p), windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, fileFlagsReparseBackup, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	flags := uint32(dispositionDelete | dispositionPosix | dispositionIgnoreRdonl)
	if err := windows.SetFileInformationByHandle(h, fileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)), 4); err != nil {
		return windows.DeleteFile(extPath(p))
	}
	return nil
}

func (fs *WinFS) hChmod(p string, mode uint32) error {
	k, fi, err := keyOf(p)
	if err != nil {
		return err
	}
	st := byHandleStat(fi)
	metaSet(k, st.mode&lxSIFMT|mode&0o7777)
	return nil
}

func setTimes(h windows.Handle, atime, mtime syscall.Timespec) error {
	a := windows.NsecToFiletime(syscall.TimespecToNsec(atime))
	m := windows.NsecToFiletime(syscall.TimespecToNsec(mtime))
	return windows.SetFileTime(h, nil, &a, &m)
}

func (fs *WinFS) hUtimes(p string, atime, mtime syscall.Timespec) error {
	h, err := openAttr(p, windows.FILE_WRITE_ATTRIBUTES)
	if err != nil {
		return &os.PathError{Op: "utimes", Path: p, Err: err}
	}
	defer windows.CloseHandle(h)
	return setTimes(h, atime, mtime)
}

// FutimesOf sets the open file f's times, through its path when the handle
// lacks FILE_WRITE_ATTRIBUTES.
func FutimesOf(f *os.File, atime, mtime syscall.Timespec) error {
	if setTimes(windows.Handle(f.Fd()), atime, mtime) == nil {
		return nil
	}
	h, err := openAttr(f.Name(), windows.FILE_WRITE_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return setTimes(h, atime, mtime)
}

func (fs *WinFS) hLink(from, to string) error {
	if err := windows.CreateHardLink(extPath(to), extPath(from), 0); err != nil {
		return &os.LinkError{Op: "link", Old: from, New: to, Err: err}
	}
	return nil
}

func (fs *WinFS) hClone(from, to string) error { return errors.ErrUnsupported }

func (fs *WinFS) hCloneFile(f *os.File, to string) error {
	out, err := fs.hOpen(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, io.NewSectionReader(f, 0, 1<<62))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

func (fs *WinFS) hTruncate(p string, n int64) error {
	f, err := fs.hOpen(p, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(n)
}

func (fs *WinFS) hStatfs(dir string) (core.StatFS, error) {
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(extPath(dir+`\`), &avail, &total, &free); err != nil {
		return core.StatFS{}, &os.PathError{Op: "statfs", Path: dir, Err: err}
	}
	k, _, _ := keyOf(dir)
	return core.StatFS{
		Bsize: 4096, Blocks: total / 4096, Bfree: free / 4096, Bavail: avail / 4096,
		Files: 1 << 32, Ffree: 1 << 31, Fsid: [2]uint32{k.vol, 0},
	}, nil
}

// FstatfsOf is the statfs of the filesystem holding the open file f.
func FstatfsOf(f *os.File) (core.StatFS, error) {
	return (&WinFS{}).hStatfs(filepath.Dir(f.Name()))
}

func (fs *WinFS) hReadDir(p string) ([]os.FileInfo, error) {
	d, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return nil, err
	}
	out := make([]os.FileInfo, 0, len(names))
	for _, n := range names {
		if fi, err := fs.hLstat(p + `\` + n); err == nil {
			out = append(out, fi)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// FchmodOf sets the open file f's permission bits in the side table.
func FchmodOf(f *os.File, mode uint32) error {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &fi); err != nil {
		return err
	}
	st := byHandleStat(&fi)
	metaSet(handleKey(&fi), st.mode&lxSIFMT|mode&0o7777)
	return nil
}

// AnonFile makes an unnamed host file in dir (named with prefix only while it
// is being made).
func AnonFile(dir, prefix string) (*os.File, error) {
	p := filepath.Join(dir, prefix+strconv.FormatUint(hostSeq.Add(1), 10))
	f, err := (&WinFS{}).hOpen(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := deletePosix(p); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// modeless reports whether the host keeps no permission bits for f's object:
// a socket, pipe or console, which fstat describes from the description.
func Modeless(f *os.File) bool {
	t, _ := windows.GetFileType(windows.Handle(f.Fd()))
	return t != windows.FILE_TYPE_DISK
}

// LowerOwners returns the lower layer's non-root owners from the shared sidecar,
// keyed by [volume, file id], for a consumer that seeds them into its own table.
func LowerOwners() map[[2]uint64][2]uint32 {
	winMeta.mu.Lock()
	defer winMeta.mu.Unlock()
	out := make(map[[2]uint64][2]uint32, len(winMeta.own))
	for k, o := range winMeta.own {
		out[[2]uint64{uint64(k.vol), k.id}] = o
	}
	return out
}
