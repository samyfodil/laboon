//go:build darwin || linux || windows

package sandbox

import (
	"fmt"
	"runtime/debug"
)

// handlerPanic is the error a run ends with when serving one of its guest's
// calls panicked: the run is torn down and the embedding program goes on.
type handlerPanic struct {
	Value any
	Stack []byte
}

func (p *handlerPanic) Error() string {
	return fmt.Sprintf("sandbox: a syscall handler panicked: %v\n%s", p.Value, p.Stack)
}

// contain, deferred by a serve loop, turns a panic in it into the run's
// failure: the run's first panic is kept for Run to return, the call's err is
// set to it, and every stub of the run is killed so the other serve loops end.
// The kill runs apart from the panicking goroutine, which may have unwound
// holding a lock the kill takes.
func (fs *dfs) contain(err *error) {
	v := recover()
	if v == nil {
		return
	}
	p := &handlerPanic{Value: v, Stack: debug.Stack()}
	fs.fault.CompareAndSwap(nil, p)
	*err = p
	if fs.abort != nil {
		fs.abort()
	}
	go fs.killAll()
}

// faulted is the run's first handler panic, nil if none.
func (fs *dfs) faulted() error {
	if p := fs.fault.Load(); p != nil {
		return p
	}
	return nil
}
