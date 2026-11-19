package e2b

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samyfodil/laboon"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// DesktopImage is a prebuilt XFCE image, so the desktop boots without installing
// a desktop at runtime. Point Desktop.Image at any XFCE image (including an
// E2B-style one); the script installs only small capture tools it's missing.
const DesktopImage = "accetto/ubuntu-vnc-xfce-g3:latest"

// Desktop is an E2B-Desktop-style GUI sandbox: a full XFCE desktop on a virtual
// framebuffer (Xvfb), with no VM, that you can screenshot and drive with mouse
// and keyboard actions. It mirrors e2b-desktop's Sandbox (screenshot,
// left_click, write, press, ...).
type Desktop struct {
	Image         string // base image (DesktopImage if empty)
	Width, Height int    // framebuffer size (default 1280x800)
	BootSeconds   int    // seconds to wait for the session to settle (default 25)
}

// Action is one input event applied before the screenshot, like E2B Desktop's
// computer-use primitives. Build them with LeftClick, TypeText, PressKey, etc.
type Action struct {
	Kind string
	X, Y int
	Text string
	N    int
}

func LeftClick(x, y int) Action   { return Action{Kind: "click", X: x, Y: y} }
func DoubleClick(x, y int) Action { return Action{Kind: "doubleclick", X: x, Y: y} }
func MoveMouse(x, y int) Action   { return Action{Kind: "move", X: x, Y: y} }
func TypeText(text string) Action { return Action{Kind: "type", Text: text} }
func PressKey(key string) Action  { return Action{Kind: "key", Text: key} }
func Wait(seconds int) Action     { return Action{Kind: "sleep", N: seconds} }

// NewDesktop returns a desktop sandbox with sensible defaults.
func NewDesktop() *Desktop {
	return &Desktop{Image: DesktopImage, Width: 1280, Height: 800, BootSeconds: 25}
}

// Screenshot boots the desktop and returns a PNG of the root window, like E2B
// Desktop's screenshot().
func (d *Desktop) Screenshot(ctx context.Context) ([]byte, error) {
	return d.Run(ctx, nil)
}

// Run boots the desktop, applies actions (via xdotool), then returns a PNG.
func (d *Desktop) Run(ctx context.Context, actions []Action) ([]byte, error) {
	img := d.Image
	if img == "" {
		img = DesktopImage
	}
	w, h, boot := d.Width, d.Height, d.BootSeconds
	if w == 0 {
		w = 1280
	}
	if h == 0 {
		h = 800
	}
	if boot == 0 {
		boot = 25
	}

	out, err := memTempDir("e2b-desktop-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(out)

	code, rerr := laboon.RunImage(ctx, img,
		laboon.WithEntrypoint("bash", "-c", desktopScript(w, h, boot, actions)),
		laboon.WithMount("/out", hostfs.Dir(out)),
		laboon.WithNet(),
		laboon.WithUser("root"),      // prebuilt desktop images often default to a non-root user
		laboon.WithStderr(os.Stderr), // apt / session progress for the caller
	)
	if rerr != nil {
		return nil, rerr
	}
	png, err := os.ReadFile(filepath.Join(out, "shot.png"))
	if err != nil {
		return nil, fmt.Errorf("no screenshot (desktop exited %d): %w", code, err)
	}
	return png, nil
}

func desktopScript(w, h, boot int, actions []Action) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString("export DEBIAN_FRONTEND=noninteractive DISPLAY=:1\n")
	b.WriteString("if ! command -v xfce4-session >/dev/null 2>&1 || ! command -v Xvfb >/dev/null 2>&1 || ! command -v import >/dev/null 2>&1 || ! command -v xdotool >/dev/null 2>&1; then apt-get update -qq >&2; apt-get install -y -qq xfce4 xvfb imagemagick dbus-x11 x11-utils xdotool >&2; fi\n")
	fmt.Fprintf(&b, "Xvfb :1 -screen 0 %dx%dx24 >/dev/null 2>&1 &\n", w, h)
	b.WriteString("sleep 3\n")
	b.WriteString("dbus-launch --exit-with-session xfce4-session >/dev/null 2>&1 &\n")
	fmt.Fprintf(&b, "sleep %d\n", boot)
	b.WriteString("set +e\n") // an input action must not abort the screenshot
	for _, a := range actions {
		switch a.Kind {
		case "click":
			fmt.Fprintf(&b, "xdotool mousemove %d %d click 1\n", a.X, a.Y)
		case "doubleclick":
			fmt.Fprintf(&b, "xdotool mousemove %d %d click --repeat 2 1\n", a.X, a.Y)
		case "move":
			fmt.Fprintf(&b, "xdotool mousemove %d %d\n", a.X, a.Y)
		case "type":
			fmt.Fprintf(&b, "xdotool type -- %s\n", shquote(a.Text))
		case "key":
			fmt.Fprintf(&b, "xdotool key -- %s\n", shquote(a.Text))
		case "sleep":
			fmt.Fprintf(&b, "sleep %d\n", a.N)
		}
	}
	b.WriteString("import -window root /out/shot.png\n")
	return b.String()
}

func shquote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// memTempDir makes a temp dir on an in-memory filesystem when one is available
// (/dev/shm), so ephemeral captures like screenshots never touch the disk.
func memTempDir(prefix string) (string, error) {
	if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() {
		if d, err := os.MkdirTemp("/dev/shm", prefix); err == nil {
			return d, nil
		}
	}
	return os.MkdirTemp("", prefix)
}
