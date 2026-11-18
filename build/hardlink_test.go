//go:build linux

package build

import (
	"context"
	"strings"
	"testing"

	"github.com/samyfodil/laboon/oci"
)

// TestBuildHardlinkAcrossSteps proves a hardlink made in one RUN step survives
// into the next step's root: step 1 links /a and /b, step 2 asserts both still
// report a link count of 2. Before ApplyTo recreated hardlinks, the fold into
// the next step's root copied them independently and step 2 saw a count of 1.
func TestBuildHardlinkAcrossSteps(t *testing.T) {
	ctx := context.Background()
	if _, err := oci.Pull(ctx, "alpine:3.20", oci.Options{}); err != nil {
		t.Skipf("base image unavailable: %v", err)
	}
	df := `FROM alpine:3.20
RUN echo shared > /a && ln /a /b
RUN test "$(stat -c %h /a)" = 2 && test "$(stat -c %h /b)" = 2
`
	if _, err := Build(ctx, strings.NewReader(df), Options{Tag: "laboon-hl:1"}); err != nil {
		t.Fatalf("build (step 2 checks the hardlink survived the fold into root): %v", err)
	}
}

// TestBuildOwnerAcrossSteps proves a non-root owner set in one RUN step is seen
// by the next: step 1 chowns a file to 1000:1000, step 2 asserts it. The owner a
// host file cannot hold rides in the root's sidecar, which the next step's
// sandbox hydrates into its inode table. Without that, step 2 saw root (0:0).
func TestBuildOwnerAcrossSteps(t *testing.T) {
	ctx := context.Background()
	if _, err := oci.Pull(ctx, "alpine:3.20", oci.Options{}); err != nil {
		t.Skipf("base image unavailable: %v", err)
	}
	df := `FROM alpine:3.20
RUN echo x > /owned && chown 1000:1000 /owned
RUN test "$(stat -c %u:%g /owned)" = 1000:1000
`
	if _, err := Build(ctx, strings.NewReader(df), Options{Tag: "laboon-own:1"}); err != nil {
		t.Fatalf("build (step 2 checks the owner survived the fold into root): %v", err)
	}
}
