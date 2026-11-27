//go:build darwin || linux || windows

package sandbox

import "io"

// WinSize is a terminal window size in character cells.
type WinSize struct{ Rows, Cols uint16 }

// Terminal is the host side of a confined terminal, passed with WithTerminal.
// laboon runs the program on a pseudo-terminal and bridges it to the Terminal:
// it reads the program's input (keystrokes) from Read, writes the program's
// output to Write, and Closes it when the program exits; if Read returns an
// error (the far side went away) laboon ends the run. Any io.ReadWriteCloser
// works — a net.Conn, a websocket adapter, a pair of pipes — so an app wires a
// confined shell to its own transport without touching a pty itself. A Terminal
// that also implements Resizer is told the window size. Close must make a
// Read in progress return: laboon's input copier is blocked in one when the
// program exits, and it is gone only once that Read returns.
type Terminal interface {
	io.ReadWriteCloser
}

// Resizer is an optional Terminal whose Resizes channel reports window-size
// changes; laboon applies each to the program's pty. laboon receives from it
// only while the program runs, so a sender must not block once Run returns:
// buffer the channel and send without waiting, or stop sending.
type Resizer interface {
	Resizes() <-chan WinSize
}
