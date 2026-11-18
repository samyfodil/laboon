// Package laboon runs Linux programs in a sandbox, embedded in a Go program:
// a binary from a host path or root directory with Run, or a container from an
// OCI image with RunImage.
//
// The guest runs in a stub process whose syscalls are rewritten to trap into
// this process, which serves them; a syscall the rewriter missed reaches the
// host's backstop (seccomp on Linux, Seatbelt on macOS, the instrumentation
// callback on Windows), which kills the guest (ErrKilled).
//
// A run is configured with options. Without any, the guest has no standard
// streams (input is empty, output is discarded), the environment
// PATH=/usr/local/bin:/usr/bin:/bin and HOME=/, no network, no memory cap,
// and writable+executable memory allowed (WithRejectRWX refuses it).
//
// The sandbox and oci packages are the lower layer this one is built on.
package laboon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/samyfodil/laboon/oci"
	"github.com/samyfodil/laboon/internal/sandbox"
)

// ErrKilled reports that the backstop killed the guest for a syscall the
// rewriter missed.
var ErrKilled = sandbox.ErrKilled

var defaultEnv = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/"}

// Run runs program and returns its exit status. The program is a host path,
// or a path inside WithRoot's directory. A guest killed by a signal exits
// with 128 plus the signal number; cancelling ctx kills it.
func Run(ctx context.Context, program string, opts ...Option) (int, error) {
	prog, cfg, err := programConfig(program, newOptions(opts))
	if err != nil {
		return 0, err
	}
	return sandbox.Run(ctx, prog, cfg)
}

// RunImage runs a container from the OCI image ref (e.g. alpine:3.20) and
// returns its exit status. The image is pulled unless an earlier pull is
// cached (see WithPull). As with docker run, WithArgs replaces the image's
// CMD, its ENTRYPOINT stays unless WithEntrypoint replaces it, and its
// environment and working directory apply.
func RunImage(ctx context.Context, ref string, opts ...Option) (int, error) {
	prog, cfg, err := imageRun(ctx, ref, newOptions(opts))
	if err != nil {
		return 0, err
	}
	return sandbox.Run(ctx, prog, cfg)
}

// A Process is a run started by Start or StartImage.
type Process struct {
	cancel  context.CancelFunc
	control *sandbox.Control
	done    chan struct{}
	code    int
	err     error
}

// Start starts program as Run does and returns without waiting for it.
func Start(ctx context.Context, program string, opts ...Option) (*Process, error) {
	prog, cfg, err := programConfig(program, newOptions(opts))
	if err != nil {
		return nil, err
	}
	return start(ctx, prog, cfg), nil
}

// StartImage pulls ref as RunImage does, then starts the container and
// returns without waiting for it. Errors pulling or reading the image are
// returned here.
func StartImage(ctx context.Context, ref string, opts ...Option) (*Process, error) {
	prog, cfg, err := imageRun(ctx, ref, newOptions(opts))
	if err != nil {
		return nil, err
	}
	return start(ctx, prog, cfg), nil
}

func start(ctx context.Context, prog string, cfg sandbox.Config) *Process {
	ctx, cancel := context.WithCancel(ctx)
	ctrl := &sandbox.Control{}
	cfg.Control = ctrl
	p := &Process{cancel: cancel, control: ctrl, done: make(chan struct{})}
	go func() {
		defer cancel()
		p.code, p.err = sandbox.Run(ctx, prog, cfg)
		close(p.done)
	}()
	return p
}

// Wait waits for the process to exit and returns what Run would.
func (p *Process) Wait() (int, error) {
	<-p.done
	return p.code, p.err
}

// Kill kills the process and everything it started. Wait still reports how
// it ended.
func (p *Process) Kill() {
	p.cancel()
}

// Pid is the host process id of the running guest's leader, for logging and
// observability. It is 0 before the guest has started, after it has ended, or
// on a host that does not expose it (Windows). It is a host pid, not the
// guest's own pid 1.
func (p *Process) Pid() int {
	return p.control.Pid()
}

// Signal sends sig to the guest's init process (pid 1) as a signal it can
// handle, so SIGTERM asks the guest to shut down where Kill forces it. It
// returns an error before the guest starts, after it has exited, or for a
// signal the guest's Linux ABI has no number for. A zero signal reports only
// whether the guest is still running.
func (p *Process) Signal(sig os.Signal) error {
	return p.control.Signal(sig)
}

func programConfig(program string, o *options) (string, sandbox.Config, error) {
	if o.entrySet {
		return "", sandbox.Config{}, errors.New("WithEntrypoint applies to an image")
	}
	cfg := o.cfg
	cfg.Args = append([]string{program}, o.args...)
	cfg.Env = o.environ(defaultEnv)
	if o.userSet {
		root, _ := sandbox.HostRootPath(cfg.RootFS)
		if root == "" {
			root = "/"
		}
		user, err := resolveUser(root, o.user)
		if err != nil {
			return "", sandbox.Config{}, err
		}
		cfg.User = user
	}
	return program, cfg, nil
}

func imageRun(ctx context.Context, ref string, o *options) (string, sandbox.Config, error) {
	if o.cfg.RootFS != nil {
		return "", sandbox.Config{}, errors.New("WithRoot does not apply to an image")
	}
	pull := o.pull
	if o.platform != "" {
		arch, ok := strings.CutPrefix(o.platform, "linux/")
		if !ok {
			return "", sandbox.Config{}, fmt.Errorf("bad platform %q: want linux/amd64 or linux/arm64", o.platform)
		}
		pull.Arch = arch
	}
	img, err := oci.Pull(ctx, ref, pull)
	if err != nil {
		return "", sandbox.Config{}, err
	}
	cfg, err := imageConfig(img, o)
	if err != nil {
		return "", sandbox.Config{}, err
	}
	prog, err := oci.LookPath(img.Root, cfg.Args[0], cfg.Env)
	if err != nil {
		return "", sandbox.Config{}, err
	}
	return prog, cfg, nil
}

// imageConfig composes the run of img: its root, ENTRYPOINT followed by CMD
// or by WithArgs (WithEntrypoint replaces both ENTRYPOINT and CMD), its
// environment with HOME=/ unless it sets HOME, and its working directory
// unless WithDir sets one.
func imageConfig(img *oci.Image, o *options) (sandbox.Config, error) {
	cfg := o.cfg
	cfg.RootFS = sandbox.HostRoot(img.Root)
	if cfg.Dir == "" {
		cfg.Dir = img.Config.WorkingDir
	}
	entry, cmd := img.Config.Entrypoint, img.Config.Cmd
	if o.entrySet {
		entry, cmd = o.entry, nil
	}
	if o.argsSet {
		cmd = o.args
	}
	cfg.Args = append(append([]string{}, entry...), cmd...)
	if len(cfg.Args) == 0 {
		return sandbox.Config{}, fmt.Errorf("%s has no entrypoint or command", img.Ref)
	}
	base := img.Config.Env
	if !hasEnv(base, "HOME") {
		base = append(append([]string{}, base...), "HOME=/")
	}
	cfg.Env = o.environ(base)
	spec := img.Config.User
	if o.userSet {
		spec = o.user // --user overrides the image's USER
	}
	user, err := resolveUser(img.Root, spec)
	if err != nil {
		return sandbox.Config{}, err
	}
	cfg.User = user
	return cfg, nil
}

func hasEnv(env []string, key string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, key+"=") {
			return true
		}
	}
	return false
}
