//go:build linux

package sandbox

import (
	"os"

	"github.com/samyfodil/laboon/core"
)

// Code in shared memory needs no supervisor here: Linux runs shared memory
// as it is, its syscalls trapped (codereg.go).

func (sr *sigRun) codeStop(p *sigProc) {}

func (sr *sigRun) codeGo(p *sigProc, cont func()) { cont() }

func (g *dguest) codeFile(fi os.FileInfo) {}

func (g *dguest) modified(d *dfile) { g.notifyFd(d, inModify) }

func (g *dguest) fileModified(core.File) {}
