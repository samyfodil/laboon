package laboon

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// stdioRoot is the root the stdio tests run busybox in: the host's own on
// Linux, LC_TEST_ROOT on macOS and LC_WIN_ROOTFS on Windows.
func stdioRoot(t testing.TB) string {
	t.Helper()
	root := "/"
	switch runtime.GOOS {
	case "darwin":
		root = os.Getenv("LC_TEST_ROOT")
	case "windows":
		root = os.Getenv("LC_WIN_ROOTFS")
	}
	if root == "" {
		t.Skip("no guest root (LC_TEST_ROOT on macOS, LC_WIN_ROOTFS on Windows)")
	}
	if _, err := os.Stat(filepath.Join(root, "bin", "busybox")); err != nil {
		t.Skip("no /bin/busybox in the guest root")
	}
	return root
}

// sh runs a busybox shell command in the stdio root. Other applets are run
// as "busybox name": a root may have no links for them.
func sh(t testing.TB, cmd string, opts ...Option) int {
	t.Helper()
	root := stdioRoot(t)
	code, err := Run(context.Background(), "/bin/busybox", append([]Option{WithMount("/", hostfs.Dir(root)), WithArgs("sh", "-c", cmd)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestStdioCapture(t *testing.T) {
	var out, errw bytes.Buffer
	code := sh(t, "busybox cat; echo out; echo err >&2", WithStdin(strings.NewReader("in\n")), WithStdout(&out), WithStderr(&errw))
	if code != 0 || out.String() != "in\nout\n" || errw.String() != "err\n" {
		t.Fatalf("code %d, stdout %q, stderr %q", code, out.String(), errw.String())
	}
}

func TestStdioDiscardPipeline(t *testing.T) {
	if code := sh(t, "echo hi; echo err >&2; echo x | busybox cat", WithDiscardStdio()); code != 0 {
		t.Fatalf("code %d", code)
	}
}

func TestStdioDiscardFullCount(t *testing.T) {
	var errw bytes.Buffer
	code := sh(t, "busybox dd if=/dev/zero bs=4k count=1000", WithDiscardStdin(), WithDiscardStdout(), WithStderr(&errw))
	if code != 0 || !strings.Contains(errw.String(), "1000+0 records out") {
		t.Fatalf("code %d, stderr %q", code, errw.String())
	}
}

// A later option for a stream overrides an earlier one for it alone.
func TestStdioOptionOrder(t *testing.T) {
	var out bytes.Buffer
	code := sh(t, "echo out; echo err >&2; busybox cat; echo rc=$?", WithStdin(strings.NewReader("in\n")), WithDiscardStdio(), WithStdout(&out))
	if code != 0 || out.String() != "out\nrc=0\n" {
		t.Fatalf("code %d, stdout %q", code, out.String())
	}
}

// A file put on a discarded fd gets what is written there.
func TestStdioDup2OntoDiscarded(t *testing.T) {
	var errw bytes.Buffer
	code := sh(t, "exec 3>/tmp/o; exec 1>&3; echo data; busybox cat /tmp/o >&2", WithDiscardStdout(), WithStderr(&errw))
	if code != 0 || errw.String() != "data\n" {
		t.Fatalf("code %d, stderr %q", code, errw.String())
	}
}

// stdiocheck returns the root and the path in it of testdata/stdiocheck.c:
// built here on Linux, /stdiocheck.elf in the root elsewhere.
func stdiocheck(t testing.TB) (root, prog string) {
	t.Helper()
	root = stdioRoot(t)
	if runtime.GOOS != "linux" {
		if _, err := os.Stat(filepath.Join(root, "stdiocheck.elf")); err != nil {
			t.Skip("no /stdiocheck.elf in the guest root (testdata/stdiocheck.c)")
		}
		return root, "/stdiocheck.elf"
	}
	prog = filepath.Join(t.TempDir(), "stdiocheck")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", prog, "testdata/stdiocheck.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	return root, prog
}

// The guest's view of discarded stdio: fstat, poll, full write counts, EOF,
// dup2 of a file onto it and back, threads, fork and exec. stdiocheck's exit
// status is the source line of the first failed check.
func TestStdioDiscardGuestView(t *testing.T) {
	root, prog := stdiocheck(t)
	code, err := Run(context.Background(), prog, WithMount("/", hostfs.Dir(root)), WithDiscardStdio())
	if err != nil || code != 0 {
		t.Fatalf("code %d (testdata/stdiocheck.c line), err %v", code, err)
	}
}

type countWriter struct{ n int64 }

func (w *countWriter) Write(b []byte) (int, error) {
	w.n += int64(len(b))
	return len(b), nil
}

var stdioSinks = []struct {
	name string
	w    func() io.Writer
}{
	{"capture", func() io.Writer { return &countWriter{} }},
	{"discard", func() io.Writer { return io.Discard }},
}

// BenchmarkStdioWrite has stdiocheck write 4 KiB 25600 times (100 MiB) to
// stdout, copied out to a writer or discarded in the stub.
func BenchmarkStdioWrite(b *testing.B) {
	root, prog := stdiocheck(b)
	benchStdio(b, func(w io.Writer) (int, error) {
		return Run(context.Background(), prog, WithMount("/", hostfs.Dir(root)), WithArgs("write", "25600"), WithStdout(w))
	})
}

// BenchmarkStdioDD is the same through dd, which also reads /dev/zero.
func BenchmarkStdioDD(b *testing.B) {
	benchStdio(b, func(w io.Writer) (int, error) {
		return sh(b, "busybox dd if=/dev/zero bs=4k count=25600 2>/dev/null", WithStdout(w)), nil
	})
}

func benchStdio(b *testing.B, run func(io.Writer) (int, error)) {
	const size = 25600 * 4096
	for _, sink := range stdioSinks {
		b.Run(sink.name, func(b *testing.B) {
			b.SetBytes(size)
			for range b.N {
				w := sink.w()
				if code, err := run(w); err != nil || code != 0 {
					b.Fatalf("code %d, err %v", code, err)
				}
				if c, ok := w.(*countWriter); ok && c.n != size {
					b.Fatalf("captured %d bytes", c.n)
				}
			}
		})
	}
}
