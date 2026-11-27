package sandbox

import (
	"bytes"
	"context"
	"testing"

	"golang.org/x/sys/unix"
)

// TestEpollWake runs testdata/epollwake.c: a thread's blocking epoll_waits
// end on a timeout, another thread's write, an fd ready already or a signal,
// across the epolls it waits on and after they close (the thread's wait
// epoll, waitEpoll).
func TestEpollWake(t *testing.T) {
	root, bin := guestRoot(t, "epollwake")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{Args: []string{"epollwake"}, Stdout: &out, Stderr: &out, RootFS: HostRoot(root)})
	if err != nil || code != 0 {
		t.Fatalf("code %d (testdata/epollwake.c line) err %v\n%s", code, err, out.String())
	}
}

// TestEpollEventKeepsData checks that a ready event reports the data its
// registration had when the wait took it, even when the fd is deleted before
// the event is copied out: Go's netpoller dereferences that data.
func TestEpollEventKeepsData(t *testing.T) {
	ep := &epoll{interest: map[int]epollReg{5: {d: &dfile{}, events: unix.EPOLLIN, data: 0xabcdef, id: 1, wfd: -1, xfd: -1}}}
	evs := ep.collect([]unix.EpollEvent{{Events: unix.EPOLLIN, Fd: 5, Pad: 1}}, 8, &epScratch{fold: map[int]int{}})
	delete(ep.interest, 5)
	b := encodeEvents(nil, evs)
	if len(b) != epollEventSize {
		t.Fatalf("encoded %d bytes, want %d", len(b), epollEventSize)
	}
	if got := le64(b[epollEventSize-8:]); got != 0xabcdef {
		t.Fatalf("data %#x, want 0xabcdef", got)
	}
}

// TestEpollCollectFolds checks that the host events of a registration on two
// host fds fold into one guest event, in the order the fds first came up, and
// that an edge-triggered event past maxevents waits for the next call, also
// when the scratch is reused.
func TestEpollCollectFolds(t *testing.T) {
	ep := &epoll{interest: map[int]epollReg{
		3: {d: &dfile{}, events: unix.EPOLLIN | unix.EPOLLOUT, data: 3, id: 1, wfd: 9, xfd: -1},
		4: {d: &dfile{}, events: unix.EPOLLIN, data: 4, id: 2, wfd: -1, xfd: -1},
		5: {d: &dfile{}, events: unix.EPOLLIN | unix.EPOLLET, data: 5, id: 3, wfd: -1, xfd: -1},
	}}
	hev := []unix.EpollEvent{
		{Events: unix.EPOLLIN, Fd: 3, Pad: 1},
		{Events: unix.EPOLLIN, Fd: 4, Pad: 2},
		{Events: unix.EPOLLOUT, Fd: 3, Pad: 1},
		{Events: unix.EPOLLIN, Fd: 5, Pad: 3},
		{Events: unix.EPOLLIN, Fd: 4, Pad: 7}, // a dropped registration's
	}
	s := &epScratch{fold: map[int]int{}}
	for range 2 {
		ep.pending = nil
		evs := ep.collect(hev, 2, s)
		if len(evs) != 2 || evs[0].gfd != 3 || evs[0].ev != unix.EPOLLIN|unix.EPOLLOUT || evs[1].gfd != 4 || evs[1].ev != unix.EPOLLIN {
			t.Fatalf("collected %+v", evs)
		}
		if len(ep.pending) != 1 || ep.pending[0].gfd != 5 || ep.pending[0].data != 5 {
			t.Fatalf("pending %+v", ep.pending)
		}
	}
}
