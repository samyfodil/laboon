//go:build darwin || linux

package hostfs

import (
	"path/filepath"
	"testing"
)

func TestJoinClean(t *testing.T) {
	for _, root := range []string{"/", "/a", "/a/b", "/a/", "a", "", "/a/./b", "/a//b", "/a/../b"} {
		for _, gp := range []string{"", "x", "x/y", "x/", "./x", "x/../y", "/x", "..", "x//y", "."} {
			if got, want := joinClean(root, gp), filepath.Join(root, gp); got != want {
				t.Errorf("joinClean(%q, %q) = %q, want %q", root, gp, got, want)
			}
		}
	}
}
