//go:build linux

package sandbox

import "os"

func (g *dguest) pipeFiles() (*os.File, *os.File, pipeIO, error) {
	r, w, err := hostPipe(lxPipeDefSize)
	return r, w, nil, err
}

func (g *dguest) pollNote() pollNote { return pollNote{} }

func ringOf(*dfile) (pipeIO, bool) { return nil, false }

func ringPollState(*dfile) (pollState, bool) { return pollState{}, false }

func ringFds(*dfile) (rfd, wfd int, ok bool) { return 0, 0, false }

func ringQueued(*dfile) (int, bool) { return 0, false }
