package winfs

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// FILE_INFORMATION_CLASS FileCaseSensitiveInformation and its flag.
const (
	fileCaseSensitiveInfo = 71
	caseSensitiveDir      = 1
)

// ExtPath is p as a Win32 path without the MAX_PATH limit.
func ExtPath(p string) *uint16 {
	if len(p) >= 2 && p[1] == ':' {
		p = `\\?\` + p
	}
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		u, _ = windows.UTF16PtrFromString(`\\?\invalid`)
	}
	return u
}

func openDir(dir string, access uint32) (windows.Handle, error) {
	return windows.CreateFile(ExtPath(dir), access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

// CaseSensitive reports whether lookups in dir are case-sensitive.
func CaseSensitive(dir string) bool {
	h, err := openDir(dir, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var flags uint32
	var iosb windows.IO_STATUS_BLOCK
	if windows.NtQueryInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&flags)), 4, fileCaseSensitiveInfo) != nil {
		return false
	}
	return flags&caseSensitiveDir != 0
}

// SetCaseSensitive makes dir case-sensitive; directories created in it later
// inherit the flag. It reports whether the volume allowed it.
func SetCaseSensitive(dir string) bool {
	h, err := openDir(dir, windows.FILE_WRITE_ATTRIBUTES|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	flags := uint32(caseSensitiveDir)
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&flags)), 4, fileCaseSensitiveInfo) == nil
}
