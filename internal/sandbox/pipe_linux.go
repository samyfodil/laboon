//go:build darwin || linux

package sandbox

import "os"

func (g *dguest) pipeFiles() (*os.File, *os.File, pipeIO, error) {
	r, w, err := hostPipe(lxPipeDefSize)
	return r, w, nil, err
}

func (g *dguest) pollNote() pollNote { return pollNote{} }
