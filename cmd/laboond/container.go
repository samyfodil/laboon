package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/samyfodil/laboon"
)

// container is one Docker container, run as a laboon sandbox.
type container struct {
	id      string
	name    string
	image   string
	cmd     []string
	entry   []string
	env     []string
	workdir string
	user    string
	tty     bool
	created time.Time

	mu       sync.Mutex
	started  bool
	exited   bool
	exitCode int
	proc     *laboon.Process

	attachMu sync.Mutex // serializes frames onto attachConn
	attachW  net.Conn   // the hijacked attach connection, nil until attach
	attached chan struct{}

	done chan struct{} // closed when the run finishes
}

func newContainer(id string) *container {
	return &container{id: id, created: time.Now(), attached: make(chan struct{}), done: make(chan struct{})}
}

func (c *container) running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started && !c.exited
}

func (c *container) status() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.exited:
		return "exited"
	case c.started:
		return "running"
	default:
		return "created"
	}
}

func newID() string {
	var b [32]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// run starts the container as a laboon image run, streaming stdout/stderr to the
// attached connection (if any), and records the exit code.
func (c *container) run(allowNet bool) {
	defer close(c.done)
	opts := []laboon.Option{laboon.WithStdout(c.frame(1)), laboon.WithStderr(c.frame(2)), laboon.WithCache(plans)}
	if len(c.cmd) > 0 {
		opts = append(opts, laboon.WithArgs(c.cmd...))
	}
	if len(c.entry) > 0 {
		opts = append(opts, laboon.WithEntrypoint(c.entry...))
	}
	if len(c.env) > 0 {
		opts = append(opts, laboon.WithEnv(c.env...))
	}
	if c.workdir != "" {
		opts = append(opts, laboon.WithDir(c.workdir))
	}
	if c.user != "" {
		opts = append(opts, laboon.WithUser(c.user))
	}
	if allowNet {
		opts = append(opts, laboon.WithNet())
	}
	code, err := laboon.RunImage(context.Background(), c.image, opts...)
	c.mu.Lock()
	c.exited = true
	if err != nil && code == 0 {
		code = 1
	}
	c.exitCode = code
	c.mu.Unlock()
	c.closeAttach()
}

// frame returns a writer that wraps each write in a Docker stdcopy frame for the
// given stream (1 stdout, 2 stderr) on the attached connection, or discards it
// when nothing is attached.
func (c *container) frame(stream byte) io.Writer { return &frameWriter{c: c, stream: stream} }

type frameWriter struct {
	c      *container
	stream byte
}

func (f *frameWriter) Write(p []byte) (int, error) {
	f.c.attachMu.Lock()
	defer f.c.attachMu.Unlock()
	w := f.c.attachW
	if w == nil {
		return len(p), nil // not attached: discard, as docker run without -a does
	}
	if f.c.tty {
		return w.Write(p) // a TTY stream is not framed
	}
	var hdr [8]byte
	hdr[0] = f.stream
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(p)))
	if _, err := w.Write(hdr[:]); err != nil {
		return 0, err
	}
	return w.Write(p)
}

func (c *container) closeAttach() {
	c.attachMu.Lock()
	defer c.attachMu.Unlock()
	if c.attachW != nil {
		c.attachW.Close()
		c.attachW = nil
	}
}

// plans keeps rewrite plans in the user cache directory, shared by every run
// in this process and by later processes.
var plans = planCache()

func planCache() *laboon.Cache {
	d, err := os.UserCacheDir()
	if err != nil {
		return laboon.NewCache("")
	}
	// Windows kept prepared images here, unbounded, before they moved
	// into the plan cache.
	os.RemoveAll(filepath.Join(d, "laboon", "img"))
	return laboon.NewCache(filepath.Join(d, "laboon", "plans"))
}
