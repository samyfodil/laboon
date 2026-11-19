// Demonstrates forwarding the host's X server into laboon: a GUI program runs
// confined in the sandbox but draws on the host's display. hostfs.Dir binds the
// host's X socket directory into the guest and forwards an AF_UNIX connect under
// it to the host socket there, so the guest's X client reaches the host's X
// server; DISPLAY tells the client which socket to use. This is the composition
// a one-line helper would otherwise hide.
//
//	go run ./examples/x11            # runs jess/xeyes
//	go run ./examples/x11 <image>    # any image with an X client as its entrypoint
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/samyfodil/laboon"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

func main() {
	display := os.Getenv("DISPLAY")
	if display == "" {
		fail(fmt.Errorf("no DISPLAY set — run this under an X session"))
	}
	image := "jess/xeyes"
	if len(os.Args) > 1 {
		image = os.Args[1]
	}

	fmt.Printf("running %s confined in laboon, on the host X server (close the window to exit)\n", image)
	code, err := laboon.RunImage(context.Background(), image,
		laboon.WithMount("/tmp/.X11-unix", hostfs.Dir("/tmp/.X11-unix")),
		laboon.WithEnvVar("DISPLAY", display),
		laboon.WithStderr(os.Stderr),
	)
	if err != nil {
		fail(err)
	}
	os.Exit(code)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "x11:", err)
	os.Exit(1)
}
