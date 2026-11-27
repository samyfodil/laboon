// Command laboon runs a Linux program in the sandbox, either from a host
// directory or from an OCI image. It is a thin front end to package laboon:
// each flag is one of its options.
//
//	laboon [-root dir] program [args...]
//	laboon -image ref [command [args...]]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"

	"github.com/samyfodil/laboon"
	"github.com/samyfodil/laboon/build"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// version is the released version, set by the linker at build time (see the
// release workflow); "dev" for an ordinary `go build`.
var version = "dev"

// buildCmd implements `laboon build`: run a Dockerfile and write an image.
func buildCmd(args []string) {
	fs := flag.NewFlagSet("laboon build", flag.ExitOnError)
	tag := fs.String("t", "laboon-build:latest", "name:tag for the built image")
	file := fs.String("f", "", "Dockerfile to use (default <context>/Dockerfile)")
	out := fs.String("o", "image.tar", "write the image here as a docker-load tarball")
	platform := fs.String("platform", "", "image platform, linux/amd64 or linux/arm64 (default: the host's)")
	target := fs.String("target", "", "build only up to this named stage (default: the last stage)")
	net := fs.Bool("net", false, "allow RUN steps to use the network")
	var buildArgs mountList
	fs.Var(&buildArgs, "build-arg", "set a build-time ARG as NAME=VALUE (repeatable)")
	noCache := fs.Bool("no-cache", false, "do not reuse cached layers from previous builds")
	cacheDir := fs.String("cache", "", "build layer cache directory (default: <user cache>/laboon/build)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: laboon build [-t name:tag] [-f Dockerfile] [-o image.tar] [--platform P] [--target stage] [--net] [--build-arg NAME=VALUE] [--no-cache] [context]")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	ctxDir := fs.Arg(0)
	if ctxDir == "" {
		ctxDir = "."
	}
	df := *file
	if df == "" {
		df = filepath.Join(ctxDir, "Dockerfile")
	}
	f, err := os.Open(df)
	if err != nil {
		fmt.Fprintln(os.Stderr, "laboon build:", err)
		os.Exit(1)
	}
	defer f.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var cache build.Cache
	if !*noCache {
		dir := *cacheDir
		if dir == "" {
			base, err := os.UserCacheDir()
			if err != nil {
				base = os.TempDir()
			}
			dir = filepath.Join(base, "laboon", "build")
		}
		if c, err := build.NewDirCache(dir); err != nil {
			fmt.Fprintln(os.Stderr, "laboon build: cache:", err)
		} else {
			cache = c
		}
	}
	bargs := map[string]string{}
	for _, kv := range buildArgs {
		k, v, _ := strings.Cut(kv, "=")
		bargs[k] = v
	}
	plans := planCache()
	h, err := build.Build(ctx, f, build.Options{
		Context: ctxDir, Tag: *tag, Platform: *platform, Output: *out, Target: *target, Net: *net,
		Store: true, BuildArgs: bargs, Cache: cache, Plans: plans, Stdout: os.Stderr, Stderr: os.Stderr,
	})
	plans.Sync()
	if err != nil {
		fmt.Fprintln(os.Stderr, "laboon build:", err)
		os.Exit(1)
	}
	fmt.Printf("built %s\n%s\nrun it: laboon -image %s\nwrote %s (docker load -i %s)\n", *tag, h, *tag, *out, *out)
}

// mountList collects repeated -mount/-v flags.
type mountList []string

func (m *mountList) String() string { return strings.Join(*m, ",") }
func (m *mountList) Set(s string) error {
	*m = append(*m, s)
	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "build" {
		buildCmd(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println("laboon", version)
		return
	}
	root := flag.String("root", "", "directory the guest sees as / (read-only); the program path is inside it")
	image := flag.String("image", "", "OCI image to run, e.g. alpine:3.20; arguments replace its CMD")
	entrypoint := flag.String("entrypoint", "", "with -image: replace the image's ENTRYPOINT and drop its CMD, as docker run --entrypoint (empty clears it)")
	pull := flag.Bool("pull", false, "with -image: check the registry for a newer image")
	platform := flag.String("platform", "", "with -image: the image's platform, linux/amd64 or linux/arm64 (default: the host's architecture)")
	trace := flag.Bool("trace", false, "log guest syscalls to stderr")
	rejectRWX := flag.Bool("reject-rwx", false, "refuse writable+executable memory (W^X); JIT engines like V8 need it allowed")
	maxMem := flag.String("mem", "", "cap guest address space, e.g. 256M, 1G (0 = unlimited)")
	net := flag.Bool("net", false, "enable networking (proxy guest sockets to host); without it the guest has loopback only")
	noNet := flag.Bool("no-net", false, "no network at all, not even loopback (without -net)")
	runtime := flag.String("runtime", "standalone", "where to run: standalone (in-process, no daemon), laboon (a laboon daemon over ConnectRPC), or docker (a Docker API endpoint)")
	x11 := flag.Bool("x11", false, "sugar for -mount /tmp/.X11-unix:/tmp/.X11-unix and passing DISPLAY, so GUI programs display on the host X server")
	user := flag.String("user", "", "run as this user (uid, uid:gid, name or name:group), overriding the image's USER, as docker --user")
	flag.StringVar(user, "u", "", "alias for -user")
	var mounts mountList
	flag.Var(&mounts, "mount", "bind a host path into the guest as HOST:GUEST (repeatable); GUEST=/ is the rootfs (-root), others are socket binds")
	flag.Var(&mounts, "v", "alias for -mount")
	var envVars mountList
	flag.Var(&envVars, "env", "set a guest environment variable as KEY=VALUE (repeatable), on top of the image's environment")
	flag.Var(&envVars, "e", "alias for -env")
	allowDomains := flag.String("allow-domains", "", "with -net: comma-separated egress allowlist; the sandbox resolves only these domains (and subdomains) and lets the guest connect only to the addresses it resolved")
	allowCIDRs := flag.String("allow-cidrs", "", "with -net: comma-separated CIDR networks the guest may also connect to directly")
	allowPorts := flag.String("allow-ports", "", "with -net: comma-separated destination ports the guest may connect to (others refused)")
	noRewrite := flag.Bool("no-rewrite", false, "skip syscall rewriting (seccomp should kill the guest)")
	quiet := flag.Bool("q", false, "discard the guest's stdout and stderr")
	discardOut := flag.Bool("discard-stdout", false, "discard the guest's stdout")
	discardErr := flag.Bool("discard-stderr", false, "discard the guest's stderr")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] program [args...]\n       %s -image ref [command [args...]]\n", os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	switch *runtime {
	case "standalone":
		// in-process, the rest of main
	case "docker", "laboon":
		fail(fmt.Errorf("-runtime %s submits the run to a daemon, not yet wired in this build; run laboond (it serves the Docker API) and point a docker client at it", *runtime))
	default:
		fail(fmt.Errorf("unknown -runtime %q: want standalone, laboon or docker", *runtime))
	}
	if pf := os.Getenv("LABOON_CPUPROFILE"); pf != "" {
		if f, err := os.Create(pf); err != nil {
			fmt.Fprintln(os.Stderr, "laboon: cpuprofile:", err)
		} else {
			pprof.StartCPUProfile(f) // stopped before os.Exit, which skips defers
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	plans := planCache()
	opts := []laboon.Option{
		laboon.WithStdio(os.Stdin, os.Stdout, os.Stderr),
		laboon.WithCache(plans),
		laboon.WithAllowDomains(splitList(*allowDomains)...),
		laboon.WithAllowCIDRs(splitList(*allowCIDRs)...),
	}
	for _, p := range splitList(*allowPorts) {
		n, err := strconv.Atoi(p)
		if err != nil {
			fail(fmt.Errorf("bad -allow-ports value %q: %w", p, err))
		}
		opts = append(opts, laboon.WithAllowPorts(n))
	}
	if *maxMem != "" {
		n, err := parseSize(*maxMem)
		if err != nil {
			fail(err)
		}
		opts = append(opts, laboon.WithMaxMemory(n))
	}
	for _, m := range mounts {
		host, guest, ok := strings.Cut(m, ":")
		if !ok || host == "" || guest == "" {
			fail(fmt.Errorf("bad -mount %q: want HOST:GUEST", m))
		}
		opts = append(opts, laboon.WithMount(guest, hostfs.Dir(host)))
	}
	for _, kv := range envVars {
		key, val, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			fail(fmt.Errorf("bad -env %q: want KEY=VALUE", kv))
		}
		opts = append(opts, laboon.WithEnvVar(key, val))
	}
	if *x11 {
		opts = append(opts, laboon.WithMount("/tmp/.X11-unix", hostfs.Dir("/tmp/.X11-unix")))
		if d := os.Getenv("DISPLAY"); d != "" {
			opts = append(opts, laboon.WithEnvVar("DISPLAY", d))
		}
	}
	for _, f := range []struct {
		on  bool
		opt laboon.Option
	}{
		{*root != "", laboon.WithMount("/", hostfs.Dir(*root))},
		{*pull, laboon.WithPull()},
		{*platform != "", laboon.WithPlatform(*platform)},
		{*trace, laboon.WithTrace(os.Stderr)},
		{*rejectRWX, laboon.WithRejectRWX()},
		{*net, laboon.WithNet()},
		{*noNet, laboon.WithNoNet()},
		{*user != "", laboon.WithUser(*user)},
		{*noRewrite, laboon.WithNoRewrite()},
		{flagSet("entrypoint"), entrypointOpt(*entrypoint)},
		{*quiet || *discardOut, laboon.WithDiscardStdout()},
		{*quiet || *discardErr, laboon.WithDiscardStderr()},
	} {
		if f.on {
			opts = append(opts, f.opt)
		}
	}

	var code int
	var err error
	if *image != "" {
		if flag.NArg() > 0 {
			opts = append(opts, laboon.WithArgs(flag.Args()...))
		}
		code, err = laboon.RunImage(ctx, *image, opts...)
	} else {
		if flag.NArg() < 1 {
			flag.Usage()
			os.Exit(2)
		}
		code, err = laboon.Run(ctx, flag.Arg(0), append(opts, laboon.WithArgs(flag.Args()[1:]...))...)
	}
	if os.Getenv("LABOON_CPUPROFILE") != "" {
		pprof.StopCPUProfile() // flush before any error exit, so a signal-stopped run still profiles
	}
	plans.Sync()
	if err != nil {
		fail(err)
	}
	os.Exit(code)
}

// planCache keeps rewrite plans in the user cache directory, so a later run
// starts without re-analyzing the same binaries.
func planCache() *laboon.Cache {
	d, err := os.UserCacheDir()
	if err != nil {
		return laboon.NewCache("")
	}
	return laboon.NewCache(filepath.Join(d, "laboon", "plans"))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "laboon:", err)
	os.Exit(125)
}

// parseSize parses a byte size with an optional K/M/G suffix.
func parseSize(s string) (uint64, error) {
	mult := uint64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		mult, s = 1<<10, s[:len(s)-1]
	case 'M', 'm':
		mult, s = 1<<20, s[:len(s)-1]
	case 'G', 'g':
		mult, s = 1<<30, s[:len(s)-1]
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad -mem size %q", s)
	}
	return n * mult, nil
}

// splitList parses a comma-separated flag value into trimmed, non-empty items.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// flagSet reports whether flag name was given, even as an empty value.
func flagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

// entrypointOpt is -entrypoint's option: one program, or none when empty.
func entrypointOpt(e string) laboon.Option {
	if e == "" {
		return laboon.WithEntrypoint()
	}
	return laboon.WithEntrypoint(e)
}
