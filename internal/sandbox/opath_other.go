//go:build darwin || windows

package sandbox

import (
	"os"

	"github.com/samyfodil/laboon/core"
)

// The host has no O_PATH: an O_PATH fd of a regular file holds it open for
// reading instead (pinOpen), and other objects stay path-based.
func pinPathFD(core.Node) *os.File { return nil }

func reopenReadable(*os.File) (*os.File, lxErrno)  { return nil, lxEACCES }
func reopenMode(*os.File, int) (*os.File, lxErrno) { return nil, lxEACCES }
