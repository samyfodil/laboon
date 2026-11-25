package sandbox

import (
	"errors"
	"sync"
	"testing"
)

// A panic in a serve loop becomes the run's error, and the run's stubs are
// killed so its other serve loops end.
func TestContainPanic(t *testing.T) {
	fs := &dfs{}
	fs.cond = sync.NewCond(&fs.mu)
	aborted := false
	fs.abort = func() { aborted = true }
	err := func() (err error) {
		defer fs.contain(&err)
		panic("boom")
	}()
	var p *handlerPanic
	if !errors.As(err, &p) || p.Value != "boom" {
		t.Fatalf("err = %v", err)
	}
	if !aborted || fs.faulted() != err {
		t.Fatalf("aborted %v, faulted %v", aborted, fs.faulted())
	}
}
