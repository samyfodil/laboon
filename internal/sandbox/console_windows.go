//go:build windows

package sandbox

import (
	"os"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The host console as the guest's terminal. When the run's stdio is a
// Windows console, the supervisor puts it in raw VT mode (no line input, no
// echo, no Ctrl+C processing, VT sequences both ways, UTF-8) and runs the
// Linux line discipline itself: the guest sees /dev/pts/N with termios, job
// control and the console's window size, and a resize raises SIGWINCH. The
// console's modes are restored when the run ends.

var procReadConsoleInputW = modKernel32.NewProc("ReadConsoleInputW")

const (
	inputRecordSize        = 20
	keyEvent               = 1
	windowBufferSizeEvent  = 4
	consoleInputBatch      = 64
	cpUTF8                 = 65001
	consoleInputModeCooked = windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT
)

type console struct {
	in, out           windows.Handle // in is 0 when stdin is not the console
	ownOut            bool           // out was opened here (CONOUT$)
	inMode, outMode   uint32
	inCP, outCP       uint32
	quit              windows.Handle
	done              chan struct{}
	wmu               sync.Mutex // orders echo and output on the console
	hi                uint16     // a high surrogate waiting for its pair
	closeOnce         sync.Once
	setIn, setOut, cp bool
}

// attachConsole makes the stdio fds of pid 1 that are a console one terminal,
// /dev/pts/0, controlled by session 1 with group 1 in the foreground.
func (fs *dfs) attachConsole(g *dguest) {
	var files [3]*os.File
	isCon := [3]bool{}
	found := false
	for i, v := range []any{g.cfg.Stdin, g.cfg.Stdout, g.cfg.Stderr} {
		if f, ok := v.(*os.File); ok && f != nil && hostIsTTY(f) {
			files[i], isCon[i], found = f, true, true
		}
	}
	if !found {
		return
	}
	c := &console{done: make(chan struct{})}
	if isCon[0] {
		c.in = windows.Handle(files[0].Fd())
	}
	switch {
	case isCon[1]:
		c.out = windows.Handle(files[1].Fd())
	case isCon[2]:
		c.out = windows.Handle(files[2].Fd())
	default:
		p, err := windows.UTF16PtrFromString("CONOUT$")
		if err != nil {
			return
		}
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			return
		}
		c.out, c.ownOut = h, true
	}
	c.setup()

	d := fs.term.newDev(fs, &ttyHub{n: g.netState()}, -1)
	d.con = c
	d.sid, d.pgrp = 1, 1
	d.slaves, d.slaveSeen = 1, true
	d.ld.t.iflag |= lxIUTF8
	d.ld.ws = c.size()
	f, e := hostless(d.name())
	if e != 0 {
		c.close()
		return
	}
	df := &dfile{f: f, gp: d.name(), stub: -1, tty: true, pty: &ptmx{dev: d}}
	df.fx.oflags, df.fx.hasFlags = lxORdwr, true
	for i, on := range isCon {
		if on {
			g.ft.installAt(i, df)
		}
	}
	if c.in != 0 {
		ev, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			close(c.done)
			return
		}
		c.quit = ev
		go c.pump(d)
	} else {
		close(c.done)
	}
}

// setup switches the console to raw VT mode, remembering what to restore.
func (c *console) setup() {
	if c.in != 0 && windows.GetConsoleMode(c.in, &c.inMode) == nil {
		m := c.inMode&^consoleInputModeCooked | windows.ENABLE_VIRTUAL_TERMINAL_INPUT | windows.ENABLE_WINDOW_INPUT
		c.setIn = windows.SetConsoleMode(c.in, m) == nil
	}
	if windows.GetConsoleMode(c.out, &c.outMode) == nil {
		m := c.outMode | windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING | windows.DISABLE_NEWLINE_AUTO_RETURN
		c.setOut = windows.SetConsoleMode(c.out, m) == nil
	}
	var err error
	if c.inCP, err = windows.GetConsoleCP(); err == nil {
		if c.outCP, err = windows.GetConsoleOutputCP(); err == nil {
			windows.SetConsoleCP(cpUTF8)
			windows.SetConsoleOutputCP(cpUTF8)
			c.cp = true
		}
	}
}

func (c *console) close() {
	c.closeOnce.Do(func() {
		if c.quit != 0 {
			windows.SetEvent(c.quit)
		}
		<-c.done
		if c.quit != 0 {
			windows.CloseHandle(c.quit)
		}
		if c.setIn {
			windows.SetConsoleMode(c.in, c.inMode)
		}
		if c.setOut {
			windows.SetConsoleMode(c.out, c.outMode)
		}
		if c.cp {
			windows.SetConsoleCP(c.inCP)
			windows.SetConsoleOutputCP(c.outCP)
		}
		if c.ownOut {
			windows.CloseHandle(c.out)
		}
	})
}

// size is the console window's size as a struct winsize.
func (c *console) size() [4]uint16 {
	var info windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(c.out, &info) != nil {
		return [4]uint16{24, 80, 0, 0}
	}
	w := info.Window
	return [4]uint16{uint16(w.Bottom - w.Top + 1), uint16(w.Right - w.Left + 1), 0, 0}
}

// pump reads console input records: key presses become terminal input (VT
// sequences included), a buffer size change a new window size.
func (c *console) pump(d *ttyDev) {
	defer close(c.done)
	recs := make([]byte, inputRecordSize*consoleInputBatch)
	for {
		ev, err := windows.WaitForMultipleObjects([]windows.Handle{c.quit, c.in}, false, windows.INFINITE)
		if err != nil || ev != windows.WAIT_OBJECT_0+1 {
			return
		}
		var n uint32
		if r, _, _ := procReadConsoleInputW.Call(uintptr(c.in), uintptr(unsafe.Pointer(&recs[0])), consoleInputBatch, uintptr(unsafe.Pointer(&n))); r == 0 {
			return
		}
		var in []byte
		resized := false
		for i := range int(n) {
			rec := recs[inputRecordSize*i:]
			switch le16(rec) {
			case keyEvent:
				down, rep, ch := le32(rec[4:]) != 0, le16(rec[8:]), le16(rec[14:])
				if !down || ch == 0 {
					continue
				}
				r := rune(ch)
				switch {
				case utf16.IsSurrogate(r) && ch < 0xdc00:
					c.hi = ch
					continue
				case utf16.IsSurrogate(r):
					r = utf16.DecodeRune(rune(c.hi), r)
					c.hi = 0
				}
				enc := utf8.AppendRune(nil, r)
				for range max(rep, 1) {
					in = append(in, enc...)
				}
			case windowBufferSizeEvent:
				resized = true
			}
		}
		if resized {
			d.setWinsize(c.size())
		}
		if len(in) > 0 {
			c.input(d, in)
		}
	}
}

// input runs typed bytes through the line discipline, writes their echo and
// raises the signals they generate.
func (c *console) input(d *ttyDev, in []byte) {
	c.wmu.Lock()
	d.mu.Lock()
	if !d.ld.canon() {
		in = in[:min(len(in), d.ld.room())]
	}
	sigs := d.ld.receive(in)
	out := d.ld.takeOut(len(d.ld.out))
	fg := d.pgrp
	d.touch()
	d.mu.Unlock()
	c.writeOut(out)
	c.wmu.Unlock()
	for _, s := range sigs {
		d.fs.signalPgrp(fg, s)
	}
}

// write is a guest write to the console: output processing, then the
// console.
func (c *console) write(d *ttyDev, b []byte) lxErrno {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	d.mu.Lock()
	d.ld.output(b)
	out := d.ld.takeOut(len(d.ld.out))
	d.mu.Unlock()
	return c.writeOut(out)
}

// flush writes output held back by a stop (TCOOFF, ^S) once restarted.
func (c *console) flush(d *ttyDev) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	d.mu.Lock()
	out := d.ld.takeOut(len(d.ld.out))
	d.mu.Unlock()
	c.writeOut(out)
}

func (c *console) writeOut(b []byte) lxErrno {
	for len(b) > 0 {
		var n uint32
		if err := windows.WriteFile(c.out, b, &n, nil); err != nil {
			return osErrno(err)
		}
		b = b[n:]
	}
	return 0
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
