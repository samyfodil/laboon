//go:build darwin || windows

package sandbox

import (
	"os"

	"github.com/samyfodil/laboon/core"
)

// O_PATH (and executing a descriptor whose name is gone) is a Linux feature;
// elsewhere an O_PATH fd stays path-based and a descriptor exec uses d.f.
func pinPathFD(core.Node) *os.File { return nil }

func reopenReadable(*os.File) (*os.File, lxErrno)  { return nil, lxEACCES }
func reopenMode(*os.File, int) (*os.File, lxErrno) { return nil, lxEACCES }

func pinExeFD(*os.File) *os.File { return nil }
