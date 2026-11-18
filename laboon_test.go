package laboon

import (
	"bytes"
	"context"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/samyfodil/laboon/internal/oci"
	"github.com/samyfodil/laboon/internal/rewrite"
	"github.com/samyfodil/laboon/internal/sandbox"
)

func TestOptionsApply(t *testing.T) {
	var in bytes.Buffer
	var out, errw, tr bytes.Buffer
	c := rewrite.DefaultCache()
	o := newOptions([]Option{
		WithStdin(&in), WithStdout(&out), WithStderr(&errw),
		WithDir("/work"), WithRoot("/rootfs"), WithTrace(&tr),
		WithRejectRWX(), WithMaxMemory(1 << 30),
		WithNet(), WithAllowDomains("a.com"), WithAllowDomains("b.com"),
		WithAllowCIDRs("10.0.0.0/8"), WithAllowPorts(443, 80),
		WithCache(c), WithNoRewrite(),
		WithPull(), WithImageCacheDir("/cache"), WithMaxImageSize(1 << 20),
		WithPlatform("linux/arm64"),
	})
	want := sandbox.Config{
		Stdin: &in, Stdout: &out, Stderr: &errw, Trace: &tr,
		RootFS: sandbox.HostRoot("/rootfs"), Dir: "/work", Cache: c, NoRewrite: true, RejectRWX: true,
		Net: true, AllowDomains: []string{"a.com", "b.com"}, AllowCIDRs: []string{"10.0.0.0/8"},
		AllowPorts: []int{443, 80}, MaxBytes: 1 << 30,
	}
	if !reflect.DeepEqual(o.cfg, want) {
		t.Fatalf("cfg = %+v\nwant %+v", o.cfg, want)
	}
	if o.pull != (oci.Options{CacheDir: "/cache", MaxSize: 1 << 20, Refresh: true}) || o.platform != "linux/arm64" {
		t.Fatalf("pull = %+v, platform %q", o.pull, o.platform)
	}
	o = newOptions([]Option{WithStdio(&in, &out, &errw)})
	if o.cfg.Stdin != &in || o.cfg.Stdout != &out || o.cfg.Stderr != &errw {
		t.Fatal("WithStdio did not set the three streams")
	}
}

func TestDiscardOptions(t *testing.T) {
	var in bytes.Buffer
	var out bytes.Buffer
	o := newOptions([]Option{WithStdin(&in), WithDiscardStdio(), WithStdout(&out)})
	if o.cfg.Stdin != nil || o.cfg.Stdout != &out || o.cfg.Stderr != io.Discard {
		t.Fatalf("stdin %v stdout %v stderr %v: want discard, the buffer, discard", o.cfg.Stdin, o.cfg.Stdout, o.cfg.Stderr)
	}
	o = newOptions([]Option{WithStdio(&in, &out, &out), WithDiscardStdin(), WithDiscardStderr()})
	if o.cfg.Stdin != nil || o.cfg.Stdout != &out || o.cfg.Stderr != io.Discard {
		t.Fatal("per-stream discard options")
	}
	o = newOptions([]Option{WithDiscardStdout(), WithStdout(nil)})
	if o.cfg.Stdout != nil {
		t.Fatal("WithStdout after WithDiscardStdout")
	}
}

func TestDefaults(t *testing.T) {
	o := newOptions(nil)
	if !reflect.DeepEqual(o.cfg, sandbox.Config{}) {
		t.Fatalf("cfg = %+v, want zero (no stdio, RWX allowed)", o.cfg)
	}
	prog, cfg, err := programConfig("/bin/true", o)
	if err != nil || prog != "/bin/true" || !reflect.DeepEqual(cfg.Args, []string{"/bin/true"}) {
		t.Fatalf("prog %q args %q", prog, cfg.Args)
	}
	if !reflect.DeepEqual(cfg.Env, defaultEnv) {
		t.Fatalf("env = %q", cfg.Env)
	}
}

func TestProgramArgsAndEnv(t *testing.T) {
	_, cfg, _ := programConfig("/bin/busybox", newOptions([]Option{
		WithArgs("sh", "-c", "echo"), WithEnvVar("HOME", "/root"), WithEnvVar("X", "1"),
	}))
	if !reflect.DeepEqual(cfg.Args, []string{"/bin/busybox", "sh", "-c", "echo"}) {
		t.Fatalf("args = %q", cfg.Args)
	}
	if want := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/root", "X=1"}; !reflect.DeepEqual(cfg.Env, want) {
		t.Fatalf("env = %q, want %q", cfg.Env, want)
	}
	if defaultEnv[1] != "HOME=/" {
		t.Fatal("WithEnvVar changed the default environment")
	}
	_, cfg, _ = programConfig("/p", newOptions([]Option{WithEnv("A=1"), WithEnvVar("B", "2")}))
	if !reflect.DeepEqual(cfg.Env, []string{"A=1", "B=2"}) {
		t.Fatalf("env = %q", cfg.Env)
	}
}

func TestImageConfig(t *testing.T) {
	img := &oci.Image{Ref: "x", Root: "/img", Config: oci.Config{
		Entrypoint: []string{"/entry", "--flag"},
		Cmd:        []string{"serve"},
		Env:        []string{"PATH=/bin"},
		WorkingDir: "/app",
	}}
	for _, tc := range []struct {
		name string
		opts []Option
		args []string
		env  []string
		dir  string
	}{
		{"image defaults", nil, []string{"/entry", "--flag", "serve"}, []string{"PATH=/bin", "HOME=/"}, "/app"},
		{"args replace cmd", []Option{WithArgs("run", "-v")}, []string{"/entry", "--flag", "run", "-v"}, []string{"PATH=/bin", "HOME=/"}, "/app"},
		{"empty args drop cmd", []Option{WithArgs()}, []string{"/entry", "--flag"}, []string{"PATH=/bin", "HOME=/"}, "/app"},
		{"dir and env var", []Option{WithDir("/tmp"), WithEnvVar("PATH", "/usr/bin")}, []string{"/entry", "--flag", "serve"}, []string{"PATH=/usr/bin", "HOME=/"}, "/tmp"},
		{"env replaces image env", []Option{WithEnv("A=1")}, []string{"/entry", "--flag", "serve"}, []string{"A=1"}, "/app"},
		{"entrypoint drops cmd", []Option{WithEntrypoint("/bin/sh")}, []string{"/bin/sh"}, []string{"PATH=/bin", "HOME=/"}, "/app"},
		{"entrypoint and args", []Option{WithArgs("-c", "id"), WithEntrypoint("/bin/sh")}, []string{"/bin/sh", "-c", "id"}, []string{"PATH=/bin", "HOME=/"}, "/app"},
		{"cleared entrypoint", []Option{WithEntrypoint(), WithArgs("ls")}, []string{"ls"}, []string{"PATH=/bin", "HOME=/"}, "/app"},
	} {
		cfg, err := imageConfig(img, newOptions(tc.opts))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		root, _ := sandbox.HostRootPath(cfg.RootFS)
		if root != "/img" || cfg.Dir != tc.dir || !reflect.DeepEqual(cfg.Args, tc.args) || !reflect.DeepEqual(cfg.Env, tc.env) {
			t.Fatalf("%s: root %q dir %q args %q env %q", tc.name, root, cfg.Dir, cfg.Args, cfg.Env)
		}
	}
	if !reflect.DeepEqual(img.Config.Env, []string{"PATH=/bin"}) {
		t.Fatalf("image env modified: %q", img.Config.Env)
	}

	home := &oci.Image{Root: "/img", Config: oci.Config{Cmd: []string{"sh"}, Env: []string{"HOME=/root"}}}
	if cfg, err := imageConfig(home, newOptions(nil)); err != nil || !reflect.DeepEqual(cfg.Env, []string{"HOME=/root"}) {
		t.Fatalf("env %q err %v: the image's HOME should stay", cfg.Env, err)
	}
	if _, err := imageConfig(&oci.Image{Ref: "empty"}, newOptions(nil)); err == nil || !strings.Contains(err.Error(), "no entrypoint or command") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunRejectsEntrypoint(t *testing.T) {
	if _, err := Run(context.Background(), "/bin/true", WithEntrypoint("/bin/sh")); err == nil || !strings.Contains(err.Error(), "WithEntrypoint") {
		t.Fatalf("Run: err = %v", err)
	}
	if _, err := Start(context.Background(), "/bin/true", WithEntrypoint()); err == nil {
		t.Fatal("Start accepted WithEntrypoint")
	}
}

func TestRunImageRejectsRoot(t *testing.T) {
	_, err := RunImage(context.Background(), "alpine:3.20", WithRoot(os.TempDir()))
	if err == nil || !strings.Contains(err.Error(), "WithRoot") {
		t.Fatalf("err = %v", err)
	}
}

func TestBadPlatform(t *testing.T) {
	_, err := RunImage(context.Background(), "alpine:3.20", WithPlatform("arm64"))
	if err == nil || !strings.Contains(err.Error(), "bad platform") {
		t.Fatalf("err = %v", err)
	}
}

func TestErrKilled(t *testing.T) {
	if ErrKilled != sandbox.ErrKilled {
		t.Fatal("ErrKilled is not sandbox.ErrKilled")
	}
}
