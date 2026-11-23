package sandbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestEpollEventKeepsData checks that a ready event reports the data its
// registration had when the wait took it, even when the fd is deleted before
// the event is copied out: Go's netpoller dereferences that data.
func TestEpollEventKeepsData(t *testing.T) {
	ep := &epoll{interest: map[int]epollReg{5: {d: &dfile{}, events: unix.EPOLLIN, data: 0xabcdef, id: 1}}}
	evs := ep.collect([]unix.EpollEvent{{Events: unix.EPOLLIN, Fd: 5, Pad: 1}}, 8)
	delete(ep.interest, 5)
	b := encodeEvents(evs)
	if len(b) != epollEventSize {
		t.Fatalf("encoded %d bytes, want %d", len(b), epollEventSize)
	}
	if got := le64(b[epollEventSize-8:]); got != 0xabcdef {
		t.Fatalf("data %#x, want 0xabcdef", got)
	}
}
