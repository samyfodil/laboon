package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/samyfodil/laboon"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

const defaultStateRoot = "/run/laboon-runtime"

// specOptions maps an OCI bundle to the laboon run: the program is the first
// process arg, resolved inside the bundle's rootfs, with its env, working
// directory, user and bind mounts.
func specOptions(s *Spec, rootfs string, stdin io.Reader, stdout, stderr io.Writer) (string, []laboon.Option) {
	prog, opts := procOptions(s.Process, rootfs, stdin, stdout, stderr)
	for _, m := range s.Mounts {
		if m.Type == "bind" && m.Source != "" {
			opts = append(opts, laboon.WithMount(m.Destination, hostfs.Dir(m.Source)))
		}
	}
	return prog, opts
}

// plans keeps rewrite plans in the user cache directory, so each container
// process starts without re-analyzing the binaries the last one ran.
var plans = planCache()

func planCache() *laboon.Cache {
	d, err := os.UserCacheDir()
	if err != nil {
		return laboon.NewCache("")
	}
	return laboon.NewCache(filepath.Join(d, "laboon", "plans"))
}

// procOptions maps an OCI process (the bundle's or an exec's) to a laboon run on
// rootfs: program resolved on PATH, plus args, env, cwd, user and stdio.
func procOptions(p *Process, rootfs string, stdin io.Reader, stdout, stderr io.Writer) (string, []laboon.Option) {
	prog := lookPath(rootfs, p.Args[0], p.Env)
	opts := []laboon.Option{
		laboon.WithMount("/", hostfs.Dir(rootfs)),
		laboon.WithArgs(p.Args[1:]...),
		laboon.WithStdio(stdin, stdout, stderr),
		laboon.WithCache(plans),
	}
	if len(p.Env) > 0 {
		opts = append(opts, laboon.WithEnv(p.Env...))
	}
	if p.Cwd != "" {
		opts = append(opts, laboon.WithDir(p.Cwd))
	}
	if u := p.User; u.UID != 0 || u.GID != 0 {
		opts = append(opts, laboon.WithUser(fmt.Sprintf("%d:%d", u.UID, u.GID)))
	}
	return prog, opts
}

// lookPath resolves the program the container runs to a guest-absolute path. An
// absolute or slash-bearing name is taken as is; a bare name is searched on the
// container's PATH inside the rootfs, as an engine's exec would, so args like
// ["echo", ...] (not ["/bin/echo", ...]) run.
func lookPath(rootfs, name string, env []string) string {
	if strings.Contains(name, "/") {
		return name
	}
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			path = v
			break
		}
	}
	for _, dir := range strings.Split(path, ":") {
		if dir == "" {
			continue
		}
		cand := filepath.Join(dir, name)
		if fi, err := os.Stat(filepath.Join(rootfs, cand)); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return cand
		}
	}
	return name // not found; laboon reports ENOENT
}

// cmdRun runs a bundle to completion and returns its exit status, as `runc run`
// does: create plus start plus wait in one call.
func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	bundle := fs.String("bundle", ".", "path to the OCI bundle")
	fs.String("pid-file", "", "write the container pid here (accepted)")
	fs.String("console-socket", "", "console socket (accepted)")
	fs.Bool("detach", false, "detach (accepted)")
	fs.Bool("no-pivot", false, "")
	fs.Bool("no-new-keyring", false, "")
	fs.Int("preserve-fds", 0, "")
	fs.Parse(args)

	s, rootfs, err := loadSpec(*bundle)
	if err != nil {
		die(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	prog, opts := specOptions(s, rootfs, os.Stdin, os.Stdout, os.Stderr)
	code, err := laboon.Run(ctx, prog, opts...)
	plans.Sync()
	if err != nil {
		die(err)
	}
	return code
}
