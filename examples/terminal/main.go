//go:build darwin || linux

// terminal starts a confined interactive shell over a host directory, mounted
// read-only, driven through laboon's WithTerminal interface: every process runs
// in the laboon sandbox, so nothing it does can modify the directory or reach
// the rest of the host.
//
//	go run ./examples/terminal <dir> [image]
//
// The Terminal here is the local console; an app would pass its own transport
// instead — a net.Conn, a websocket adapter — and laboon would drive a confined
// shell against it the same way, without the app ever touching a pty.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/samyfodil/laboon"
	"github.com/samyfodil/laboon/filesystems/hostfs"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// console is a Terminal backed by the local tty: laboon reads keystrokes from
// os.Stdin, writes the program's output to os.Stdout, and is told the window
// size through Resizes.
type console struct{ sz chan laboon.WinSize }

func (c *console) Read(p []byte) (int, error)     { return os.Stdin.Read(p) }
func (c *console) Write(p []byte) (int, error)    { return os.Stdout.Write(p) }
func (c *console) Close() error                   { return nil }
func (c *console) Resizes() <-chan laboon.WinSize { return c.sz }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: terminal <dir> [image]")
		os.Exit(2)
	}
	dir, err := filepath.Abs(os.Args[1])
	if err != nil {
		fail(err)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		fail(fmt.Errorf("%s is not a directory", dir))
	}
	image := "alpine:3.20"
	if len(os.Args) > 2 {
		image = os.Args[2]
	}

	fmt.Printf("\x1b[1mlaboon · confined terminal\x1b[0m\r\n")
	fmt.Printf("  %s  →  /work  (read-only)\r\n", dir)
	fmt.Printf("  image %s · sandboxed · exit to leave\r\n\r\n", image)

	// Raw mode so keystrokes reach the guest's pty one at a time (the guest's own
	// line discipline does the editing); skipped when stdin is not a tty, so a
	// scripted/piped run still works.
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if st, err := term.MakeRaw(int(os.Stdin.Fd())); err == nil {
			defer term.Restore(int(os.Stdin.Fd()), st)
		}
	}

	c := &console{sz: make(chan laboon.WinSize, 1)}
	pushSize(c.sz)
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			pushSize(c.sz)
		}
	}()

	code, err := laboon.RunImage(context.Background(), image,
		laboon.WithMount("/work", laboon.ReadOnly(hostfs.Dir(dir))),
		laboon.WithDir("/work"),
		laboon.WithEnvVar("TERM", os.Getenv("TERM")),
		laboon.WithArgs("/bin/sh"),
		laboon.WithTerminal(c),
	)
	signal.Stop(winch)
	close(c.sz)
	if err != nil {
		fail(err)
	}
	os.Exit(code)
}

func pushSize(sz chan laboon.WinSize) {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return
	}
	select {
	case sz <- laboon.WinSize{Rows: ws.Row, Cols: ws.Col}:
	default:
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "terminal:", err)
	os.Exit(1)
}
