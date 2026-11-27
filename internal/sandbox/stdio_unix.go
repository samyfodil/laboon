//go:build linux || darwin

package sandbox

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// stdio gives the guest real files for its standard fds, so that it can
// close, dup and redirect them like any other (a shell's background job
// reopens fd 0 on /dev/null). A writer or reader that is not a file is
// joined to the guest through a pipe and a copier. A missing reader, and a
// missing or io.Discard writer, is /dev/null: the stub reads and writes its
// own fd for those, so discarded output never reaches the supervisor.
type stdio struct {
	files [3]*os.File
	own   []*os.File // ours to close once the guest is gone
	pumps []pump     // the output copiers
	wg    sync.WaitGroup
	feed  *stdinFeed // the copier of a stdin reader that is not a file

	term   Terminal // set for WithTerminal: the guest runs on a pty bridged to it
	master *os.File
	slave  *os.File
}

// pump copies the guest's output from r, a pipe's read end, to w.
type pump struct {
	r *os.File
	w io.Writer
}

func newStdio(cfg Config) (*stdio, error) {
	if cfg.Terminal != nil {
		return newTerminalStdio(cfg.Terminal)
	}
	s := &stdio{}
	switch r := cfg.Stdin.(type) {
	case *os.File:
		s.files[0] = r
	case nil:
		f, err := os.Open(os.DevNull)
		if err != nil {
			return nil, err
		}
		s.files[0] = f
		s.own = append(s.own, f)
	default:
		pr, pw, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		s.feed = newStdinFeed(r, pr, pw)
		s.files[0] = pr
		s.own = append(s.own, pr)
	}
	for i, w := range []io.Writer{cfg.Stdout, cfg.Stderr} {
		fd := i + 1
		if f, ok := w.(*os.File); ok {
			s.files[fd] = f
			continue
		}
		if discarded(w) {
			f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			if err != nil {
				s.finish()
				return nil, err
			}
			s.files[fd] = f
			s.own = append(s.own, f)
			continue
		}
		if fd == 2 && sameWriter(cfg.Stdout, cfg.Stderr) {
			// One pipe keeps the order of the two streams.
			s.files[2] = s.files[1]
			continue
		}
		pr, pw, err := os.Pipe()
		if err != nil {
			s.finish()
			return nil, err
		}
		s.files[fd] = pw
		s.own = append(s.own, pw)
		s.pumps = append(s.pumps, pump{pr, w})
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			io.Copy(w, pr)
		}()
	}
	return s, nil
}

// finish closes our ends of the pipes and copies out the guest's output. It
// runs once the guest is gone, every stub and every serve loop with it, so no
// one writes to the pipes any more and what they hold is all the output
// there is: the copiers are stopped (a write end someone still holds would
// keep them from seeing end of file) and the pipes drained.
func (s *stdio) finish() {
	if s.term != nil {
		s.master.Close() // the guest-output copier sees EOF; the input copier's write fails
		s.term.Close()   // unblocks the input copier if it waits on Read, and tells the far side
		s.wg.Wait()
		for _, f := range s.own {
			f.Close()
		}
		return
	}
	for _, f := range s.own {
		f.Close()
	}
	if s.feed != nil {
		s.feed.stop()
	}
	for _, p := range s.pumps {
		p.r.SetReadDeadline(time.Now())
	}
	s.wg.Wait()
	buf := make([]byte, 32<<10)
	for _, p := range s.pumps {
		p.r.SetReadDeadline(time.Time{})
		if rc, err := p.r.SyscallConn(); err == nil {
			for {
				n := 0
				rc.Read(func(fd uintptr) bool {
					n, _ = unix.Read(int(fd), buf)
					return true
				})
				if n <= 0 {
					break
				}
				p.w.Write(buf[:n])
			}
		}
		p.r.Close()
	}
}

// newTerminalStdio puts the guest on a pty and bridges it to t: the guest's
// three standard fds are the slave (so it is a terminal), and copiers move bytes
// each way between the master and t, applying any window sizes t reports.
func newTerminalStdio(t Terminal) (*stdio, error) {
	master, slavePath, e := hostPtyOpen()
	if e != 0 {
		return nil, fmt.Errorf("laboon: open pty: errno %d", int(e))
	}
	slave, err := os.OpenFile(slavePath, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, err
	}
	s := &stdio{files: [3]*os.File{slave, slave, slave}, own: []*os.File{slave}, term: t, master: master, slave: slave}
	s.wg.Add(1)
	go func() { defer s.wg.Done(); io.Copy(t, master) }() // the guest's output -> the Terminal
	go io.Copy(master, t)                                 // the Terminal's input -> the guest
	return s, nil
}

// serveResize applies the window sizes the Terminal reports to the guest's pty
// and delivers SIGWINCH to the guest's controlling-terminal foreground group —
// the host pty would send it to its own (host) foreground group, not the
// guest's. Called once the guest is running so fs can resolve the group; a no-op
// unless WithTerminal was used with a Resizer.
func (fs *dfs) serveResize(s *stdio) {
	if s == nil || s.term == nil || s.master == nil || s.slave == nil {
		return
	}
	r, ok := s.term.(Resizer)
	if !ok {
		return
	}
	slaveFd := int(s.slave.Fd())
	resizes := r.Resizes()
	go func() {
		for {
			var ws WinSize
			select {
			case <-fs.done:
				return
			case w, ok := <-resizes:
				if !ok {
					return
				}
				ws = w
			}
			unix.IoctlSetWinsize(int(s.master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: ws.Rows, Col: ws.Cols})
			pgrp := 1 // the guest's init session group, when none is set for job control
			if ctl := fs.cttyOf(slaveFd); ctl != nil && ctl.pgrp > 0 {
				pgrp = int(ctl.pgrp)
			}
			fs.signalPgrp(pgrp, sigWINCH)
		}
	}()
}
