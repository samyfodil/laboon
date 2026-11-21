package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/oci"
)

// nodeImage is node:22-alpine, pinned to its multi-arch index.
const nodeImage = "node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a"

// nodeRoot is nodeImage's rootfs, pulled once into the tests' own cache.
func nodeRoot(t *testing.T) string {
	t.Helper()
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	img, err := oci.Pull(context.Background(), nodeImage, oci.Options{CacheDir: filepath.Join(cache, "laboon-test", "images")})
	if err != nil {
		t.Fatal(err)
	}
	return img.Root
}

// nodeOpt is a directory holding the Node test files, mounted at /opt: the
// smoke suite, the readline check and ptyrun.
func nodeOpt(t *testing.T) Mount {
	t.Helper()
	dir := t.TempDir()
	for _, n := range []string{"node-smoke.js", "readline.js"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "node", n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyGuest(t, filepath.Join(dir, "ptyrun"), "ptyrun")
	return Mount{Guest: "/opt", FS: hostfs.Dir(dir)}
}

// TestNode: Node starts, runs JIT code, and
// passes the smoke suite (crypto, fs, timers, workers, child processes, http
// on loopback, an outbound fetch through the egress allowlist) and readline
// on a terminal.
func TestNode(t *testing.T) {
	root, opt := nodeRoot(t), nodeOpt(t)
	node := "/usr/local/bin/node"
	smoke := []string{"node", "/opt/node-smoke.js"}
	if os.Getenv("LC_NET_OFFLINE") != "" {
		smoke = append(smoke, "--offline")
	}
	egress := func(c *Config) { c.Net, c.AllowDomains = true, []string{"example.com"} }
	cases := []struct {
		name string
		mod  func(*Config)
		prog string
		args []string
		want []string
	}{
		{"version", nil, node, []string{"node", "--version"}, []string{"v22."}},
		{"eval", nil, node, []string{"node", "-e", "console.log(1+1)"}, []string{"2\n"}},
		{"smoke", egress, node, smoke, []string{"PASS jit.loop", "PASS worker_threads", "PASS child.spawn.node", "PASS http.loopback", "ALL PASS"}},
		{"readline", nil, "/opt/ptyrun", []string{"ptyrun", "laboon", "node", "/opt/readline.js"}, []string{"tty true true", "name? ", "hello laboon"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errb := runCfg(t, root, func(cfg *Config) {
				cfg.Env = []string{"PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
				cfg.Mounts = []Mount{opt}
				if c.mod != nil {
					c.mod(cfg)
				}
			}, c.prog, c.args...)
			if code != 0 {
				t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errb)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("stdout lacks %q:\n%s\nstderr:\n%s", w, out, errb)
				}
			}
			if testing.Verbose() {
				t.Logf("%s", out)
			}
		})
	}
}

// TestNodeStartup times node -e 0, warm.
func TestNodeStartup(t *testing.T) {
	root := nodeRoot(t)
	runIn(t, root, "/usr/local/bin/node", "node", "-e", "0")
	var ds []time.Duration
	for range 7 {
		t0 := time.Now()
		if code, _, errb := runIn(t, root, "/usr/local/bin/node", "node", "-e", "0"); code != 0 {
			t.Fatalf("exit %d: %s", code, errb)
		}
		ds = append(ds, time.Since(t0))
	}
	slices.Sort(ds)
	t.Logf("node -e 0: min %v, median %v, max %v", ds[0].Round(time.Millisecond), ds[len(ds)/2].Round(time.Millisecond), ds[len(ds)-1].Round(time.Millisecond))
}
