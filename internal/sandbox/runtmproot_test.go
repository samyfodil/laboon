package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestRunTmpNotAdopted: what someone put in TMPDIR under the per-process
// name a supervisor once used, a directory or a symlink to one, is never
// taken for a run's temp directory, and the run's own is gone once it ends.
func TestRunTmpNotAdopted(t *testing.T) {
	root, prog := guestRoot(t, "hello")
	for _, kind := range []string{"dir", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			if runtime.GOOS == "windows" {
				t.Setenv("TMP", tmp)
			}
			planted := filepath.Join(tmp, "lc-run-"+strconv.Itoa(os.Getpid()))
			target := planted
			if kind == "symlink" {
				target = t.TempDir()
				if err := os.Symlink(target, planted); err != nil {
					if runtime.GOOS == "windows" {
						t.Skipf("symlink: %v", err)
					}
					t.Fatal(err)
				}
			} else if err := os.Mkdir(planted, 0o777); err != nil {
				t.Fatal(err)
			}
			var during []string
			var modes []os.FileMode
			out := writerFunc(func(p []byte) (int, error) {
				if during == nil {
					during = runDirs(t, tmp)
					for _, d := range during {
						if fi, err := os.Lstat(filepath.Join(tmp, d)); err == nil {
							modes = append(modes, fi.Mode())
						}
					}
				}
				return len(p), nil
			})
			code, err := Run(context.Background(), prog, Config{RootFS: HostRoot(root), Args: []string{"hello"}, Stdout: out, Stderr: out})
			if err != nil || code != 7 {
				t.Fatalf("code=%d err=%v", code, err)
			}
			if len(during) != 1 || len(modes) != 1 {
				t.Fatalf("run directories while the guest ran: %v %v", during, modes)
			}
			if !modes[0].IsDir() || runtime.GOOS != "windows" && modes[0].Perm() != 0o700 {
				t.Errorf("run directory %s: mode %v", during[0], modes[0])
			}
			if ents, err := os.ReadDir(target); err != nil || len(ents) != 0 {
				t.Errorf("the planted %s holds %d entries (err %v)", kind, len(ents), err)
			}
			if left := runDirs(t, tmp); len(left) != 0 {
				t.Errorf("run directories left after the run: %v", left)
			}
		})
	}
}

// runDirs lists this process's run directories in dir.
func runDirs(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	ds := []string{}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), runTmpPrefix()) {
			ds = append(ds, e.Name())
		}
	}
	return ds
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
