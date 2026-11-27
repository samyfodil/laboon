//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// heldReader hands out data, then holds every Read until release is closed,
// as a terminal or connection with nothing more typed yet does.
type heldReader struct {
	mu       sync.Mutex
	data     []byte
	given    int
	inRead   int
	released chan struct{}
}

func (r *heldReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	if r.given < len(r.data) {
		n := copy(p, r.data[r.given:])
		r.given += n
		r.mu.Unlock()
		return n, nil
	}
	r.inRead++
	r.mu.Unlock()
	<-r.released
	r.mu.Lock()
	r.inRead--
	r.mu.Unlock()
	return 0, io.EOF
}

// TestStdinReaderNotOutlived: a stdin reader that is not a file is read only
// as far as the guest reads it. When Run returns, nothing is reading it, the
// copier is gone and its pipe closed, and the bytes the guest did not read
// are still the caller's.
func TestStdinReaderNotOutlived(t *testing.T) {
	root, prog := guestRoot(t, "stdinsome")
	run := func(want int, stdin io.Reader) string {
		var o bytes.Buffer
		code, err := Run(context.Background(), prog, Config{RootFS: HostRoot(root), Args: []string{"stdinsome", strconv.Itoa(want)}, Stdin: stdin, Stdout: &o, Stderr: &o})
		if err != nil || code != 0 {
			t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
		}
		return o.String()
	}
	run(0, nil)
	pipes := hostPipes()
	for _, want := range []int{0, 5} {
		r := &heldReader{data: []byte("hello, world"), released: make(chan struct{})}
		out := run(want, r)
		if exp := "read " + strconv.Itoa(want) + ": " + "hello, world"[:want] + "\n"; out != exp {
			t.Errorf("guest reading %d: %q, want %q", want, out, exp)
		}
		r.mu.Lock()
		given, inRead := r.given, r.inRead
		r.mu.Unlock()
		if given != want || inRead != 0 {
			t.Errorf("guest reading %d: the reader gave %d bytes and has %d Reads outstanding", want, given, inRead)
		}
		if n := hostPipes(); n != pipes {
			t.Errorf("guest reading %d: %d pipe fds after the run, %d before", want, n, pipes)
		}
		buf := make([]byte, 1<<20)
		if s := string(buf[:runtime.Stack(buf, true)]); strings.Contains(s, "stdinFeed).copy") {
			t.Errorf("guest reading %d: the stdin copier outlived the run", want)
		}
		close(r.released)
	}
}

// hostPipes counts this process's open pipe fds.
func hostPipes() int {
	n := 0
	for fd := 0; fd < 4096; fd++ {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFIFO {
			n++
		}
	}
	return n
}
