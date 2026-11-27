//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
// as far as the guest reads it, whether it reads fd 0 with read(2), after an
// fstat as stdio does, through getchar, or with readv. When Run returns,
// nothing is reading it, the copier is gone and its pipe closed, and the
// bytes the guest did not read are still the caller's.
func TestStdinReaderNotOutlived(t *testing.T) {
	type guest struct {
		name string
		args []string
		out  string
		take int // bytes the guest reads from fd 0
	}
	cases := []guest{
		{"stdinsome", []string{"0"}, "read 0: \n", 0},
		{"stdinsome", []string{"5"}, "read 5: hello\n", 5},
		{"stdinstdio", []string{"fstat"}, "fstat 5: hello\n", 5},
		{"stdinstdio", []string{"readv"}, "readv 5: hello\n", 5},
		// stdio reads a buffer's worth, all the reader has before it holds.
		{"stdinstdio", []string{"getc"}, "getc 5: hello\n", 12},
	}
	roots := map[string][2]string{}
	run := func(c guest, stdin io.Reader) string {
		rp, ok := roots[c.name]
		if !ok {
			root, prog := guestRoot(t, c.name)
			rp = [2]string{root, prog}
			roots[c.name] = rp
		}
		var o bytes.Buffer
		code, err := Run(context.Background(), rp[1], Config{RootFS: HostRoot(rp[0]), Args: append([]string{c.name}, c.args...), Stdin: stdin, Stdout: &o, Stderr: &o})
		if err != nil || code != 0 {
			t.Fatalf("%s %v: code=%d err=%v\n%s", c.name, c.args, code, err, o.String())
		}
		return o.String()
	}
	run(cases[0], nil)
	pipes := hostPipes()
	for _, c := range cases {
		r := &heldReader{data: []byte("hello, world"), released: make(chan struct{})}
		if out := run(c, r); out != c.out {
			t.Errorf("%s %v: %q, want %q", c.name, c.args, out, c.out)
		}
		r.mu.Lock()
		given, inRead := r.given, r.inRead
		r.mu.Unlock()
		if given != c.take || inRead != 0 {
			t.Errorf("%s %v: the reader gave %d bytes, want %d, and has %d Reads outstanding", c.name, c.args, given, c.take, inRead)
		}
		if n := hostPipes(); n != pipes {
			t.Errorf("%s %v: %d pipe fds after the run, %d before", c.name, c.args, n, pipes)
		}
		buf := make([]byte, 1<<20)
		if s := string(buf[:runtime.Stack(buf, true)]); strings.Contains(s, "stdinFeed).copy") {
			t.Errorf("%s %v: the stdin copier outlived the run", c.name, c.args)
		}
		close(r.released)
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// readPipe is a guest read of the feed's pipe: it asks, waits, and is done.
func readPipe(t *testing.T, f *stdinFeed, n int) string {
	t.Helper()
	got := make(chan string, 1)
	go func() {
		f.want(n)
		buf := make([]byte, n)
		m, _ := f.in.Read(buf)
		f.done(n)
		got <- string(buf[:m])
	}()
	select {
	case s := <-got:
		return s
	case <-time.After(10 * time.Second):
		t.Fatalf("a read of %d bytes got nothing", n)
		return ""
	}
}

// TestStdinFeedServesEveryWaiter: two reads wait on stdin at once and the
// first takes all the pipe holds. The feed Reads again for the other, and
// only then: never while what it copied is still unread.
func TestStdinFeedServesEveryWaiter(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	chunks := make(chan string)
	var ahead atomic.Bool
	f := newStdinFeed(readerFunc(func(p []byte) (int, error) {
		if n, err := pipeHeld(pr); err != nil || n > 0 {
			ahead.Store(true)
		}
		s, ok := <-chunks
		if !ok {
			return 0, io.EOF
		}
		return copy(p, s), nil
	}), pr, pw)
	defer func() { // the copier may be in a Read: end it, and the feed with it
		close(chunks)
		f.stop()
		<-f.exited
	}()
	f.want(100) // a second read, still waiting when the first returns
	chunks <- "hello"
	if s := readPipe(t, f, 100); s != "hello" {
		t.Fatalf("first read got %q", s)
	}
	go func() { chunks <- "world" }()
	if s := readPipe(t, f, 100); s != "world" {
		t.Fatalf("second read got %q", s)
	}
	f.done(100)
	if ahead.Load() {
		t.Error("the feed read its reader while the pipe still held what it had copied")
	}
}

// TestStdinFeedRetriesEmptyRead: a Read that returns nothing and no error
// leaves the waiting read asking, as io.Reader allows.
func TestStdinFeedRetriesEmptyRead(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	reads := 0
	f := newStdinFeed(readerFunc(func(p []byte) (int, error) {
		reads++
		if reads == 1 {
			return 0, nil
		}
		return copy(p, "hello"), nil
	}), pr, pw)
	defer func() {
		f.stop()
		<-f.exited
	}()
	if s := readPipe(t, f, 5); s != "hello" {
		t.Fatalf("read got %q", s)
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
