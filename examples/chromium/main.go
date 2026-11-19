// Demonstrates running headless Chromium confined in laboon: it renders a page
// to a PNG through the sandbox — no browser on the host, no GPU, no VM. The
// screenshot is written to a read-write bind, so it lands on the host.
//
//	go run ./examples/chromium [out.png]
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/samyfodil/laboon"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

func main() {
	out := "chromium.png"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		fail(err)
	}
	dir, name := filepath.Split(abs)

	fmt.Printf("rendering a page with headless Chromium, confined in laboon → %s\n", abs)
	code, err := laboon.RunImage(context.Background(), "zenika/alpine-chrome",
		laboon.WithMount("/out", hostfs.Dir(dir)),
		laboon.WithArgs("--headless", "--no-sandbox", "--disable-gpu",
			"--virtual-time-budget=6000", "--window-size=1024,768",
			"--screenshot=/out/"+name,
			`data:text/html,<h1>rendered in laboon</h1>`),
		laboon.WithStderr(os.Stderr),
	)
	if err != nil {
		fail(err)
	}
	if code != 0 {
		fmt.Fprintf(os.Stderr, "chromium exited %d\n", code)
		os.Exit(code)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		fail(fmt.Errorf("no screenshot written: %w", err))
	}
	fmt.Printf("wrote %s (%d bytes) — headless Chromium rendered through the sandbox\n", abs, fi.Size())
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "chromium:", err)
	os.Exit(1)
}
