//go:build !linux

package sandbox

import "testing"

// fileOffsetBins is the staged static guest (guestBin).
func fileOffsetBins(t *testing.T) map[string]string {
	return map[string]string{"static": guestBin(t, "fileoffset")}
}
