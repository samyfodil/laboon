//go:build ignore

// mmapguest is the Go form of testdata/mmapguest.c: a guest program for the
// writable MAP_SHARED test of a non-host file. It checks cross-open coherence,
// that a mapping store is visible to read() with no msync, and that a write() is
// visible through the mapping; it prints MMAP-OK and the supervisor then checks
// the stores reached the composed filesystem. Go so it cross-compiles with no C
// toolchain, for the host-arch build path of the test.
package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
)

func die(code int, msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(code)
}

func main() {
	fd1, err := syscall.Open("/data/f", syscall.O_RDWR, 0)
	if err != nil {
		die(1, "open1: "+err.Error())
	}
	fd2, err := syscall.Open("/data/f", syscall.O_RDWR, 0) // an independent open
	if err != nil {
		die(1, "open2: "+err.Error())
	}
	p1, err := syscall.Mmap(fd1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		die(2, "mmap1: "+err.Error())
	}
	p2, err := syscall.Mmap(fd2, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		die(2, "mmap2: "+err.Error())
	}

	// Cross-open coherence: a store through one mapping is seen by the other.
	copy(p1, "SHARED-WRITTEN")
	if !bytes.Equal(p2[:14], []byte("SHARED-WRITTEN")) {
		die(3, fmt.Sprintf("incoherent: %q", p2[:14]))
	}

	// The store is visible to a plain read() with no msync.
	buf := make([]byte, 14)
	if _, err := syscall.Pread(fd2, buf, 0); err != nil {
		die(4, "pread: "+err.Error())
	}
	if !bytes.Equal(buf, []byte("SHARED-WRITTEN")) {
		die(4, fmt.Sprintf("read stale: %q", buf))
	}

	// A write() is visible through the mapping.
	if _, err := syscall.Pwrite(fd2, []byte("WROTE"), 100); err != nil {
		die(5, "pwrite: "+err.Error())
	}
	if !bytes.Equal(p1[100:105], []byte("WROTE")) {
		die(5, fmt.Sprintf("mmap stale: %q", p1[100:105]))
	}

	fmt.Println("MMAP-OK")
}
