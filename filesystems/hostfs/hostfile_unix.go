//go:build darwin || linux

package hostfs

import "os"

// FstatOf is the HostStat of the open file f.
func FstatOf(f *os.File) (HostStat, error) {
	fi, err := f.Stat()
	if err != nil {
		return HostStat{}, err
	}
	st, _ := StatOf(fi)
	return st, nil
}

// FileStat is the os.FileInfo of the open file f, which StatOf understands.
func FileStat(f *os.File) (os.FileInfo, error) { return f.Stat() }

// FchmodOf sets the open file f's permission bits.
func FchmodOf(f *os.File, mode uint32) error { return f.Chmod(os.FileMode(mode)) }

// AnonFile makes an unnamed host file in dir (named with prefix only while it is
// being made).
func AnonFile(dir, prefix string) (*os.File, error) {
	f, err := os.CreateTemp(dir, prefix)
	if err != nil {
		return nil, err
	}
	os.Remove(f.Name())
	return f, nil
}

// Modeless reports whether the host keeps no permission bits for an object: on
// unix never (a socket and a pipe have inodes of their own).
func Modeless(*os.File) bool { return false }
