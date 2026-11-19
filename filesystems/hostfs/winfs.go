package hostfs

// This file holds the conventions of a Linux root filesystem kept on NTFS,
// shared by the image extractor (oci) and the Windows host backend
// (hostfs_windows.go), which reads it:
//
//   - Guest names NTFS cannot hold (\ : * ? " < > |, control characters, a
//     trailing dot or space, DOS device names) are escaped into the
//     private-use range U+F000+c, as Cygwin and WSL1 do.
//   - POSIX metadata NTFS has no place for (the mode with its file type, and
//     the owner) lives in <root>.lcmeta, one Entry per line. A Linux symlink
//     is a regular file holding its target, typed S_IFLNK there.
//   - Directories are made case-sensitive where the volume allows it
//     (winfs_windows.go).
//
// The logic is pure and compiles on every platform so oci (cross-platform) can
// name MetaSuffix; it is exercised only on Windows.

import (
	"fmt"
	"strconv"
	"strings"
)

const escBase = 0xf000

// MetaSuffix names a rootfs's metadata file: <root>.lcmeta.
const MetaSuffix = ".lcmeta"

func escapeRune(r rune) bool {
	return r < 0x20 || strings.ContainsRune(`\:*?"<>|`, r)
}

func dosDevice(n string) bool {
	base := strings.ToUpper(n)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	return len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9'
}

// EscapeName is the host name of guest name n.
func EscapeName(n string) string {
	if n == "." || n == ".." {
		return n
	}
	var b strings.Builder
	rs := []rune(n)
	for i, r := range rs {
		last := i == len(rs)-1
		if escapeRune(r) || last && (r == '.' || r == ' ') || i == 0 && dosDevice(n) {
			b.WriteRune(escBase + r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// UnescapeName is the guest name of host name n.
func UnescapeName(n string) string {
	if !strings.ContainsFunc(n, func(r rune) bool { return r >= escBase && r < escBase+0x100 }) {
		return n
	}
	var b strings.Builder
	for _, r := range n {
		if r >= escBase && r < escBase+0x100 {
			r -= escBase
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Entry is one line of a .lcmeta file: "<octal mode>[,uid,gid] <path>",
// the mode with its S_IFMT bits and the path relative to the root, in guest
// names. An entry without an owner is root's.
type Entry struct {
	Mode     uint32
	Uid, Gid uint32
	Path     string
}

// String formats e as its line, without the newline. A path holding a
// newline cannot be written; Valid reports that.
func (e Entry) String() string {
	if e.Uid == 0 && e.Gid == 0 {
		return fmt.Sprintf("%o %s", e.Mode, e.Path)
	}
	return fmt.Sprintf("%o,%d,%d %s", e.Mode, e.Uid, e.Gid, e.Path)
}

// Valid reports whether e can be written as a line.
func (e Entry) Valid() bool { return e.Path != "" && !strings.ContainsAny(e.Path, "\n\r") }

// ParseEntry parses one line of a .lcmeta file.
func ParseEntry(line string) (Entry, bool) {
	head, rel, ok := strings.Cut(line, " ")
	if !ok || rel == "" {
		return Entry{}, false
	}
	f := strings.Split(head, ",")
	if len(f) != 1 && len(f) != 3 {
		return Entry{}, false
	}
	m, err := strconv.ParseUint(f[0], 8, 32)
	if err != nil {
		return Entry{}, false
	}
	e := Entry{Mode: uint32(m), Path: rel}
	if len(f) == 3 {
		u, err1 := strconv.ParseUint(f[1], 10, 32)
		g, err2 := strconv.ParseUint(f[2], 10, 32)
		if err1 != nil || err2 != nil {
			return Entry{}, false
		}
		e.Uid, e.Gid = uint32(u), uint32(g)
	}
	return e, true
}
