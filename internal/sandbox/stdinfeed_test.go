//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"io"
	"os"
	"runtime"
	"strconv"
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
	defer f.stop()
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
	defer f.stop()
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
