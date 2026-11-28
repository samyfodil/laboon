//go:build ignore

// architecture-svg writes docs/assets/architecture-light.svg and
// architecture-dark.svg, the README's animated diagram of how laboon runs a
// program. The README picks one by the reader's GitHub theme. Run it from the
// repository root:
//
//	go run scripts/architecture-svg.go
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	width, height = 800, 684
	dur           = "9.0"
	begin         = "0.4"
)

var palettes = map[string]string{
	"light": "--card: #ffffff; --stroke: #d8dee4; --text: #1f2328; --muted: #59636e; --pill: #f6f8fa; --pillstroke: #d1d9e0; " +
		"--line: #8c959f; --mod1: #eef6ff; --mod2: #f3f0ff; --modstroke: #9ec5fe; --green: #1a7f37; --amber: #bf8700; " +
		"--blue: #0969da; --violet: #8250df; --red: #cf222e; --dot: #0969da;",
	"dark": "--card: #151b23; --stroke: #3d444d; --text: #f0f6fc; --muted: #9198a1; --pill: #0d1117; --pillstroke: #3d444d; " +
		"--line: #656c76; --mod1: #0f2138; --mod2: #1d1736; --modstroke: #1f6feb; --green: #3fb950; --amber: #d29922; " +
		"--blue: #4493f8; --violet: #ab7df8; --red: #f85149; --dot: #79c0ff;",
}

const style = `text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif; fill: var(--text); }
.mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace; }
.tag { font-size: 10.5px; font-weight: 600; letter-spacing: 1.2px; }
.title { font-size: 17px; font-weight: 600; }
.sub { font-size: 13px; fill: var(--muted); }
.small { font-size: 11.5px; fill: var(--muted); }
.chip { font-size: 11px; fill: var(--text); }
.procname { font-size: 14px; font-weight: 600; fill: var(--blue); }
.card { fill: var(--card); stroke: var(--stroke); stroke-width: 1; }
.pill { fill: var(--pill); stroke: var(--pillstroke); stroke-width: 1; }
.labelpill { fill: var(--card); stroke: var(--stroke); stroke-width: 1; }
.module { fill: url(#module); stroke: var(--modstroke); stroke-width: 1.2; }
.wire { stroke: var(--line); stroke-width: 1.5; fill: none; }
.head { stroke: var(--line); stroke-width: 1.8; fill: none; stroke-linecap: round; stroke-linejoin: round; }
.miss { stroke: var(--red); stroke-width: 1.5; fill: none; stroke-dasharray: 4 4; opacity: 0.55; }
.misshead { stroke: var(--red); stroke-width: 1.8; fill: none; stroke-linecap: round; stroke-linejoin: round; opacity: 0.7; }
.badge { stroke-width: 1; fill-opacity: 0.12; }
.badgetext { font-size: 11px; font-weight: 600; }
.badgetext.green { fill: var(--green); } .badgetext.amber { fill: var(--amber); } .badgetext.blue { fill: var(--blue); }
.badgetext.violet { fill: var(--violet); } .badgetext.red { fill: var(--red); }
.tag.green { fill: var(--green); } .tag.amber { fill: var(--amber); } .tag.blue { fill: var(--blue); } .tag.violet { fill: var(--violet); } .tag.red { fill: var(--red); }
.glow { fill-opacity: 0.22; stroke-width: 1.5; }
.glowcard { fill-opacity: 0.09; stroke-width: 1.8; }
.dot { fill: var(--dot); }
.reddot { fill: var(--red); }
.mod1 { stop-color: var(--mod1); } .mod2 { stop-color: var(--mod2); }
</style>`

const desc = "An unmodified Linux program or container is loaded into one host process, with no VM and no second kernel. " +
	"Its machine code runs as is on the host CPU; only its syscall instructions are rewritten, without a disassembler, to trap into a small stub in the same address space. " +
	"The stub keeps thread control, signal trampolines and the stdio fast path, and forwards every other call over a shared-memory channel to the supervisor, " +
	"which emulates the Linux ABI and owns all file and network I/O through one confined vfs Namespace, then replies so the program resumes. " +
	"A syscall the rewriter missed reaches the host sandbox (seccomp on Linux, Seatbelt on macOS, AppContainer on Windows), which kills the guest."

type svg struct{ lines []string }

func (s *svg) o(format string, a ...any) { s.lines = append(s.lines, fmt.Sprintf(format, a...)) }

// num prints a coordinate in its shortest form.
func num(x float64) string { return strconv.FormatFloat(x, 'f', -1, 64) }

// textWidth estimates a label's width at the given font size.
func textWidth(s string, mono bool, size float64) float64 {
	k := 0.57
	if mono {
		k = 0.61
	}
	return float64(len([]rune(s))) * size * k
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func (s *svg) text(x, y float64, t, class, anchor string) {
	s.o(`<text x="%.1f" y="%.1f" class="%s" text-anchor="%s">%s</text>`, x, y, class, anchor, esc(t))
}

func (s *svg) card(x, y, w, h int, class string, rx int) {
	s.o(`<rect x="%d" y="%d" width="%d" height="%d" rx="%d" class="%s"/>`, x, y, w, h, rx, class)
}

func (s *svg) badge(right float64, y int, label, color string) {
	w := textWidth(label, false, 11) + 20
	x := right - w
	s.o(`<rect x="%.1f" y="%d" width="%.1f" height="22" rx="11" class="badge" style="fill:var(--%s);stroke:var(--%s)"/>`, x, y, w, color, color)
	s.text(x+w/2, float64(y+15), label, "badgetext "+color, "middle")
}

func (s *svg) chip(x float64, y int, label string, mono bool) float64 {
	w := textWidth(label, mono, 11) + 18
	s.o(`<rect x="%.1f" y="%d" width="%.1f" height="24" rx="6" class="pill"/>`, x, y, w)
	class := "chip"
	if mono {
		class = "chip mono"
	}
	s.text(x+w/2, float64(y+16), label, class, "middle")
	return w
}

// opacity shows an element over [a, b] of the loop, fading in and out.
func opacity(a, b float64) string {
	const fade = 0.012
	ts := []float64{0, max(a-fade, 0), a, b, min(b+fade, 1), 1}
	vs := []string{"0", "0", "1", "1", "0", "0"}
	var keys []string
	for _, t := range ts {
		keys = append(keys, fmt.Sprintf("%.3f", t))
	}
	return fmt.Sprintf(`<animate attributeName="opacity" values="%s" keyTimes="%s" dur="%ss" begin="%ss" repeatCount="indefinite"/>`,
		strings.Join(vs, ";"), strings.Join(keys, ";"), dur, begin)
}

// dot moves a dot along path over [a, b] of the loop.
func (s *svg) dot(path string, a, b float64, class string) {
	s.o(`<circle r="4.5" class="%s" opacity="0">`, class)
	s.o(`  <animateMotion path="%s" keyPoints="0;0;1;1" keyTimes="0;%.3f;%.3f;1" calcMode="linear" dur="%ss" begin="%ss" repeatCount="indefinite"/>`, path, a, b, dur, begin)
	s.o("  %s", opacity(a, b+0.005))
	s.o("</circle>")
}

// glow lights a chip (rx 6) or a whole card over [a, b] of the loop.
func (s *svg) glow(x float64, y int, w float64, h int, a, b float64, color string, rx int) {
	class := "glow"
	if rx > 6 {
		class = "glowcard"
	}
	s.o(`<rect x="%.1f" y="%d" width="%.1f" height="%d" rx="%d" class="%s" style="fill:var(--%s);stroke:var(--%s)" opacity="0">`, x, y, w, h, rx, class, color, color)
	s.o("  %s", opacity(a, b))
	s.o("</rect>")
}

func (s *svg) path(d, class string) { s.o(`<path d="%s" class="%s"/>`, d, class) }

// head draws an arrowhead at (x, y) pointing in dir.
func (s *svg) head(x, y float64, dir, class string) {
	const k = 5
	var d string
	switch dir {
	case "down":
		d = fmt.Sprintf("M%s,%s L%s,%s L%s,%s", num(x-k), num(y-k), num(x), num(y), num(x+k), num(y-k))
	case "up":
		d = fmt.Sprintf("M%s,%s L%s,%s L%s,%s", num(x-k), num(y+k), num(x), num(y), num(x+k), num(y+k))
	case "right":
		d = fmt.Sprintf("M%s,%s L%s,%s L%s,%s", num(x-k), num(y-k), num(x), num(y), num(x-k), num(y+k))
	default:
		d = fmt.Sprintf("M%s,%s L%s,%s L%s,%s", num(x+k), num(y-k), num(x), num(y), num(x+k), num(y+k))
	}
	s.path(d, class)
}

func (s *svg) labelPill(cx float64, cy int, t string) {
	w := textWidth(t, false, 11) + 22
	s.o(`<rect x="%.1f" y="%d" width="%.1f" height="22" rx="11" class="labelpill"/>`, cx-w/2, cy-11, w)
	s.text(cx, float64(cy+4), t, "small", "middle")
}

type span struct{ x, w float64 }

func draw(theme string) string {
	s := &svg{}
	s.o(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-labelledby="title desc">`, width, height, width, height)
	s.o(`<title id="title">How laboon runs a Linux program</title>`)
	s.o(`<desc id="desc">%s</desc>`, desc)
	s.o("<style>\nsvg { %s }\n%s", palettes[theme], style)
	s.o(`<defs><linearGradient id="module" x1="0" y1="0" x2="1" y2="1"><stop offset="0" class="mod1"/><stop offset="1" class="mod2"/></linearGradient></defs>`)

	// The programs.
	s.card(110, 14, 580, 76, "card", 12)
	s.text(400, 37, "GUEST", "tag green", "middle")
	s.text(400, 59, "Unmodified Linux programs and containers", "title", "middle")
	s.text(400, 78, "static or dynamic ELF · whole OCI images · glibc or musl · amd64 or arm64", "sub", "middle")

	// The host process.
	s.card(20, 140, 760, 372, "module", 16)
	s.text(760, 168, "laboon: one host process", "procname mono", "end")
	s.text(760, 186, "no VM, no second kernel", "small", "end")

	const (
		gx, gy, gw, gh = 40, 196, 320, 148  // guest code
		sx, sy, sw, sh = 40, 366, 320, 128  // stub
		px, py, pw, ph = 440, 196, 320, 298 // supervisor
	)

	s.path(fmt.Sprintf("M210,90 L210,%d", gy), "wire")
	s.head(210, gy, "down", "head")
	s.labelPill(210, 117, "loaded, syscall sites rewritten")

	s.card(gx, gy, gw, gh, "card", 12)
	s.text(gx+18, gy+25, "GUEST CODE", "tag green", "start")
	s.badge(gx+gw-14, gy+11, "native speed", "green")
	s.text(gx+18, gy+50, "Runs as is on the host CPU", "title", "start")
	s.text(gx+18, gy+71, "Every instruction executes untouched except", "small", "start")
	s.text(gx+18, gy+87, "syscall sites, found without a disassembler.", "small", "start")
	chips := map[string]span{}
	cx := float64(gx + 16)
	for _, t := range []string{"mov", "add", "ldr", "bl", "syscall", "cmp"} {
		w := s.chip(cx, gy+104, t, true)
		chips[t] = span{cx, w}
		cx += w + 6
	}

	s.card(sx, sy, sw, sh, "card", 12)
	s.text(sx+18, sy+25, "STUB", "tag amber", "start")
	s.text(sx+18, sy+50, "In the guest's address space", "title", "start")
	for i, row := range [][]string{{"clone", "futex", "signal trampolines"}, {"thread exit", "stdio fast path"}} {
		cx = float64(sx + 16)
		for _, t := range row {
			cx += s.chip(cx, sy+62+30*i, t, false) + 6
		}
	}

	s.card(px, py, pw, ph, "card", 12)
	s.text(px+18, py+25, "SUPERVISOR", "tag blue", "start")
	s.text(px+18, py+50, "The Linux ABI, emulated", "title", "start")
	s.text(px+18, py+71, "Owns all file and network I/O.", "small", "start")
	type at struct {
		x float64
		y int
		w float64
	}
	sup := map[string]at{}
	y := py + 86
	for _, row := range [][]string{
		{"vfs Namespace", "overlay", "tmpfs"},
		{"/proc", "/sys", "/dev", "cgroups", "mounts"},
		{"sockets", "egress allowlist", "epoll"},
		{"pipes", "ptys", "signals", "SysV IPC"},
		{"fork", "exec", "ptrace", "timers", "inotify"},
		{"users", "capabilities", "namespaces"},
	} {
		cx = float64(px + 16)
		for _, t := range row {
			w := s.chip(cx, y, t, strings.HasPrefix(t, "/"))
			sup[t] = at{cx, y, w}
			cx += w + 6
		}
		y += 30
	}

	// The channel between the stub and the supervisor.
	const ry, ry2 = sy + 40, sy + 84
	s.path(fmt.Sprintf("M%d,%d L%d,%d", sx+sw, ry, px, ry), "wire")
	s.head(px, ry, "right", "head")
	s.path(fmt.Sprintf("M%d,%d L%d,%d", px, ry2, sx+sw, ry2), "wire")
	s.head(sx+sw, ry2, "left", "head")
	s.text(400, ry-8, "request", "small", "middle")
	s.text(400, ry2+18, "reply", "small", "middle")
	s.text(400, (ry+ry2)/2.0+4, "shared", "small", "middle")
	s.text(400, (ry+ry2)/2.0+18, "memory", "small", "middle")

	// The trap between the syscall chip and the stub.
	sc := chips["syscall"]
	tx := sc.x + sc.w/2
	s.path(fmt.Sprintf("M%.1f,%d L%.1f,%d", tx, gy+128, tx, sy), "wire")
	s.head(tx, sy, "down", "head")
	s.head(tx, gy+128, "up", "head")
	s.text(tx+10, gy+gh+16, "trap · resume", "small", "start")

	// The backstop.
	const bx, by, bw, bh = 110, 540, 580, 82
	s.card(bx, by, bw, bh, "card", 12)
	s.text(400, by+24, "HOST BACKSTOP", "tag red", "middle")
	s.text(400, by+47, "seccomp · Seatbelt · AppContainer", "title", "middle")
	s.text(400, by+67, "a syscall the rewriter missed kills the guest: ErrKilled", "sub", "middle")
	miss := fmt.Sprintf("M%d,%d L30,%d L30,%d L%d,%d", gx, gy+116, gy+116, by+41, bx, by+41)
	s.path(miss, "miss")
	s.head(bx, by+41, "right", "misshead")
	s.text(400, height-34, "Hosts: Linux, macOS and Windows, on amd64 and arm64.", "small", "middle")
	s.text(400, height-17, "A guest runs on a host of its own architecture; an Apple Silicon Mac also runs x86-64 guests through Rosetta.", "small", "middle")

	// The animation: a program starts and its code runs natively until a
	// syscall traps to the stub, which forwards it to the supervisor; the
	// reply resumes it. Then a syscall the rewriter missed goes to the
	// backstop, which kills the guest.
	s.dot(fmt.Sprintf("M210,90 L210,%d", gy), 0.00, 0.05, "dot")
	t := 0.06
	for _, n := range []string{"mov", "add", "ldr", "bl"} {
		c := chips[n]
		s.glow(c.x, gy+104, c.w, 24, t, t+0.03, "green", 6)
		t += 0.035
	}
	s.glow(sc.x, gy+104, sc.w, 24, t, 0.30, "amber", 6)
	s.dot(fmt.Sprintf("M%.1f,%d L%.1f,%d", tx, gy+128, tx, sy), t+0.01, t+0.06, "dot")
	s.glow(sx, sy, sw, sh, t+0.06, t+0.10, "amber", 12)
	s.dot(fmt.Sprintf("M%d,%d L%d,%d", sx+sw, ry, px, ry), 0.31, 0.37, "dot")
	v := sup["vfs Namespace"]
	s.glow(v.x, v.y, v.w, 24, 0.37, 0.45, "blue", 6)
	v = sup["/proc"]
	s.glow(v.x, v.y, v.w, 24, 0.39, 0.45, "blue", 6)
	s.dot(fmt.Sprintf("M%d,%d L%d,%d", px, ry2, sx+sw, ry2), 0.45, 0.51, "dot")
	s.dot(fmt.Sprintf("M%.1f,%d L%.1f,%d", tx, sy, tx, gy+128), 0.52, 0.57, "dot")
	c := chips["cmp"]
	s.glow(c.x, gy+104, c.w, 24, 0.57, 0.62, "green", 6)

	s.glow(sc.x, gy+104, sc.w, 24, 0.68, 0.74, "red", 6)
	s.dot(miss, 0.70, 0.84, "reddot")
	s.glow(bx, by, bw, bh, 0.84, 0.97, "red", 12)
	s.glow(gx, gy, gw, gh, 0.86, 0.97, "red", 12)

	s.o("</svg>")
	return strings.Join(s.lines, "\n") + "\n"
}

func main() {
	for _, theme := range []string{"light", "dark"} {
		name := "docs/assets/architecture-" + theme + ".svg"
		if err := os.WriteFile(name, []byte(draw(theme)), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
