// Package e2b is a small, E2B-style sandbox SDK built on laboon: disposable
// code sandboxes and a GUI (XFCE) desktop sandbox, with no VM, no daemon, and no
// cloud. It mirrors the shape of e2b.dev's Sandbox and Desktop APIs on top of
// laboon.RunImage.
package e2b

import (
	"bytes"
	"context"
	"os"
	"path/filepath"

	"github.com/samyfodil/laboon"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// DefaultImage has python3 and a shell, like E2B's default code sandbox.
const DefaultImage = "python:3.12-slim"

// Sandbox is a disposable code sandbox. Where E2B keeps one long-lived VM, each
// call here runs in its own fresh laboon sandbox (per-call isolation); a host
// directory mounted at /workspace gives the filesystem continuity E2B gets from
// the VM, so files written in one call are visible to the next.
type Sandbox struct {
	Image        string          // OCI image to run (DefaultImage if empty)
	Workdir      string          // host dir mounted at /workspace; a temp dir if empty
	Net          bool            // allow networking (pip install, fetches, ...)
	Extra        []laboon.Option // options applied to every run
	ownedWorkdir bool
}

// Execution is the result of running code or a command.
type Execution struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// New returns a sandbox for image (DefaultImage if empty), networking on.
func New(image string) *Sandbox {
	if image == "" {
		image = DefaultImage
	}
	return &Sandbox{Image: image, Net: true}
}

func (s *Sandbox) workdir() (string, error) {
	if s.Workdir != "" {
		return s.Workdir, os.MkdirAll(s.Workdir, 0o755)
	}
	d, err := os.MkdirTemp("", "e2b-sandbox-")
	if err != nil {
		return "", err
	}
	s.Workdir, s.ownedWorkdir = d, true
	return d, nil
}

// RunCommand runs name with args in the sandbox and captures its output, like
// E2B's sandbox.commands.run. The guest's cwd is /workspace.
func (s *Sandbox) RunCommand(ctx context.Context, name string, args ...string) (*Execution, error) {
	wd, err := s.workdir()
	if err != nil {
		return nil, err
	}
	var out, errb bytes.Buffer
	opts := []laboon.Option{
		laboon.WithArgs(append([]string{name}, args...)...),
		laboon.WithStdout(&out),
		laboon.WithStderr(&errb),
		laboon.WithMount("/workspace", hostfs.Dir(wd)),
		laboon.WithDir("/workspace"),
	}
	if s.Net {
		opts = append(opts, laboon.WithNet())
	}
	opts = append(opts, s.Extra...)
	code, err := laboon.RunImage(ctx, s.Image, opts...)
	if err != nil {
		return nil, err
	}
	return &Execution{Stdout: out.String(), Stderr: errb.String(), ExitCode: code}, nil
}

// RunCode runs a snippet of Python, like E2B's sandbox.run_code.
func (s *Sandbox) RunCode(ctx context.Context, code string) (*Execution, error) {
	return s.RunCommand(ctx, "python3", "-c", code)
}

// WriteFile writes data to name under /workspace, like E2B's sandbox.files.write.
func (s *Sandbox) WriteFile(name string, data []byte) error {
	wd, err := s.workdir()
	if err != nil {
		return err
	}
	p := filepath.Join(wd, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

// ReadFile reads name from /workspace, like E2B's sandbox.files.read.
func (s *Sandbox) ReadFile(name string) ([]byte, error) {
	wd, err := s.workdir()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(wd, name))
}

// Close removes the sandbox's work dir if it was auto-created, like E2B's kill.
func (s *Sandbox) Close() error {
	if s.ownedWorkdir && s.Workdir != "" {
		return os.RemoveAll(s.Workdir)
	}
	return nil
}
