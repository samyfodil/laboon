//go:build windows

package hostfs

import "os"

func hostFd(f *os.File) int { return int(f.Fd()) }
