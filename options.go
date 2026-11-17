package laboon

import (
	"io"
	"os"
	"strings"

	"github.com/samyfodil/laboon/internal/oci"
	"github.com/samyfodil/laboon/internal/rewrite"
	"github.com/samyfodil/laboon/internal/sandbox"
)

// An Option configures a run.
type Option func(*options)

type options struct {
	cfg      sandbox.Config
	args     []string
	argsSet  bool
	entry    []string // replaces the image's ENTRYPOINT when entrySet
	entrySet bool
	env      []string // replaces the default or image environment when envSet
	envSet   bool
	envVars  []string // KEY=VALUE set on top of the environment
	user     string   // overrides the image's USER when userSet
	userSet  bool
	pull     oci.Options
	platform string
}

func newOptions(opts []Option) *options {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// WithArgs sets the arguments after the program, as on the command line. In
// Run the guest's argv is the program followed by args. In RunImage they
// replace the image's CMD and the ENTRYPOINT stays, as with docker run.
func WithArgs(args ...string) Option {
	return func(o *options) { o.args, o.argsSet = args, true }
}

// WithEntrypoint replaces an image's ENTRYPOINT, as docker run --entrypoint
// does: the image's CMD is dropped, so the guest runs entrypoint followed by
// WithArgs. With no arguments it clears the ENTRYPOINT. It applies to
// RunImage and StartImage only.
func WithEntrypoint(entrypoint ...string) Option {
	return func(o *options) { o.entry, o.entrySet = entrypoint, true }
}

// WithEnv replaces the guest's base environment: by default
// PATH=/usr/local/bin:/usr/bin:/bin and HOME=/, or for an image its own
// environment plus HOME=/.
func WithEnv(env ...string) Option {
	return func(o *options) { o.env, o.envSet = env, true }
}

// WithEnvVar sets one variable on top of the base environment, replacing any
// earlier value of key.
func WithEnvVar(key, value string) Option {
	return func(o *options) { o.envVars = append(o.envVars, key+"="+value) }
}

// WithStdin sets the guest's standard input. Nil, the default, is empty, as
// with WithDiscardStdin.
func WithStdin(r io.Reader) Option {
	return func(o *options) { o.cfg.Stdin = r }
}

// WithStdout sets the guest's standard output. Nil, the default, discards it,
// as with WithDiscardStdout.
func WithStdout(w io.Writer) Option {
	return func(o *options) { o.cfg.Stdout = w }
}

// WithStderr sets the guest's standard error. Nil, the default, discards it,
// as with WithDiscardStderr.
func WithStderr(w io.Writer) Option {
	return func(o *options) { o.cfg.Stderr = w }
}

// WithStdio sets all three standard streams.
func WithStdio(in io.Reader, out, err io.Writer) Option {
	return func(o *options) { o.cfg.Stdin, o.cfg.Stdout, o.cfg.Stderr = in, out, err }
}

// WithDiscardStdin gives the guest a standard input that is the null device:
// every read is at end of file. The stub answers it without the supervisor.
func WithDiscardStdin() Option {
	return func(o *options) { o.cfg.Stdin = nil }
}

// WithDiscardStdout makes the guest's standard output the null device: a
// write of n bytes returns n from the stub, without the supervisor.
// io.Discard as the writer does the same.
func WithDiscardStdout() Option {
	return func(o *options) { o.cfg.Stdout = io.Discard }
}

// WithDiscardStderr is WithDiscardStdout for standard error.
func WithDiscardStderr() Option {
	return func(o *options) { o.cfg.Stderr = io.Discard }
}

// WithDiscardStdio discards all three standard streams. A later option for
// one stream overrides it for that stream.
func WithDiscardStdio() Option {
	return func(o *options) { o.cfg.Stdin, o.cfg.Stdout, o.cfg.Stderr = nil, io.Discard, io.Discard }
}

// WithDir sets the guest's initial working directory ("/" by default, or the
// image's WorkingDir).
func WithDir(dir string) Option {
	return func(o *options) { o.cfg.Dir = dir }
}

// WithRoot gives Run a host directory the guest sees as "/", read-only; the
// program path is then inside it. Without it the program is a host path and the
// guest has no filesystem. RunImage uses the image's root instead. It is sugar
// for WithMount(dir, "/").
func WithRoot(dir string) Option {
	return WithMount(dir, "/")
}

// WithTrace logs one line per guest syscall to w.
func WithTrace(w io.Writer) Option {
	return func(o *options) { o.cfg.Trace = w }
}

// WithRejectRWX refuses writable+executable guest memory with EACCES (W^X).
// By default it is allowed, as JIT engines like V8 need.
func WithRejectRWX() Option {
	return func(o *options) { o.cfg.RejectRWX = true }
}

// WithMaxMemory caps the guest's memory in bytes (0, the default, is
// unlimited): on Linux the address space its mappings take, which the
// supervisor counts; on Windows the memory the run's stub processes commit,
// which their job object holds to it. macOS does not enforce it yet.
func WithMaxMemory(bytes uint64) Option {
	return func(o *options) { o.cfg.MaxBytes = bytes }
}

// WithNet enables networking: guest sockets are proxied to host sockets.
// Without it the guest has loopback only, as Linux has with no network.
func WithNet() Option {
	return func(o *options) { o.cfg.Net = true }
}

// WithNoNet takes loopback away too: without WithNet, the guest can make no
// INET socket at all.
func WithNoNet() Option {
	return func(o *options) { o.cfg.NoNet = true }
}

// WithMount binds a host path into the guest at guest, as docker's -v does.
// Binding at the guest root ("/") sets the rootfs (what WithRoot is sugar for).
// A host directory is bound read-write and confined to its subtree, so the
// guest reads and writes it at guest; an AF_UNIX connect at or under guest also
// reaches the host socket at host (e.g. an X server), whether or not the bind
// exposes it as a file.
func WithMount(host, guest string) Option {
	return func(o *options) {
		if strings.TrimRight(guest, "/") == "" {
			o.cfg.Root = host
			return
		}
		o.cfg.Mounts = append(o.cfg.Mounts, sandbox.Mount{Host: host, Guest: guest})
	}
}

// WithMountReadOnly binds a host directory into the guest at guest, read-only:
// the guest reads the subtree but cannot create, delete, rename or modify
// anything in it (EROFS), so it is safe to expose a directory a confined
// program must not change.
func WithMountReadOnly(host, guest string) Option {
	return func(o *options) {
		o.cfg.Mounts = append(o.cfg.Mounts, sandbox.Mount{Host: host, Guest: guest, ReadOnly: true})
	}
}

// WithFS mounts fs, a FileSystem, at the guest path guest. It is the general form
// of WithMount: where WithMount binds a host directory, WithFS mounts any backend
// — NewMemFS for in-memory storage, NewDirFS for a host tree, Overlay for a
// union, any of them wrapped with ReadOnly or HardenFS, or a FileSystem you
// implement yourself. Mounting over an existing path shadows it.
func WithFS(guest string, fs FileSystem) Option {
	return func(o *options) {
		o.cfg.Mounts = append(o.cfg.Mounts, sandbox.Mount{Guest: guest, FS: fs})
	}
}

// Terminal and WinSize are re-exported so a caller using WithTerminal need not
// import the sandbox package.
type (
	Terminal = sandbox.Terminal
	WinSize  = sandbox.WinSize
)

// WithTerminal runs the program on a pseudo-terminal and bridges it to t: laboon
// reads t for the program's input and writes the program's output to t, so a
// confined interactive shell (or any program) is driven through t — a net.Conn,
// a websocket adapter, a pair of pipes. It overrides WithStdio. A t that also
// implements the Resizer interface is told the window size.
func WithTerminal(t sandbox.Terminal) Option {
	return func(o *options) { o.cfg.Terminal = t }
}

// Device and DeviceKind are re-exported from the sandbox package so a caller
// using WithDevice need not import it.
type (
	Device     = sandbox.Device
	DeviceKind = sandbox.DeviceKind
)

// DeviceSerial is a byte-stream device backed by a host socketpair.
const DeviceSerial = sandbox.DeviceSerial

// WithDevice attaches a character device to the guest at d.Path (under /dev),
// backed by the host for a direct channel with no network. After the run
// starts, d.Host() is the supervisor's end. A *Device serves one run.
func WithDevice(d *sandbox.Device) Option {
	return func(o *options) { o.cfg.Devices = append(o.cfg.Devices, d) }
}

// WithUser runs the first process as this user, overriding the image's USER,
// as docker's --user does. The spec is a name, uid, uid:gid or name:group,
// resolved against the rootfs's /etc/passwd and /etc/group.
func WithUser(spec string) Option {
	return func(o *options) { o.user, o.userSet = spec, true }
}

// WithX11 is sugar for binding /tmp/.X11-unix and passing the host's DISPLAY,
// so a GUI program displays on the host's X server.
func WithX11() Option {
	return func(o *options) {
		WithMount("/tmp/.X11-unix", "/tmp/.X11-unix")(o)
		if d := os.Getenv("DISPLAY"); d != "" {
			o.envVars = append(o.envVars, "DISPLAY="+d)
		}
	}
}

// WithAllowDomains restricts egress (with WithNet) to these domains and their
// subdomains: the sandbox answers the guest's DNS and lets it connect only to
// addresses it resolved.
func WithAllowDomains(domains ...string) Option {
	return func(o *options) { o.cfg.AllowDomains = append(o.cfg.AllowDomains, domains...) }
}

// WithAllowCIDRs lets the guest (with WithNet) also connect directly to
// addresses in these networks.
func WithAllowCIDRs(cidrs ...string) Option {
	return func(o *options) { o.cfg.AllowCIDRs = append(o.cfg.AllowCIDRs, cidrs...) }
}

// WithAllowPorts restricts outbound connections (with WithNet) to these
// destination ports.
func WithAllowPorts(ports ...int) Option {
	return func(o *options) { o.cfg.AllowPorts = append(o.cfg.AllowPorts, ports...) }
}

// WithPull has RunImage check the registry for a newer image; otherwise an
// image pulled before is used offline, as docker run does.
func WithPull() Option {
	return func(o *options) { o.pull.Refresh = true }
}

// WithPlatform picks the image's platform, "linux/amd64" or "linux/arm64";
// the default is the host's architecture.
func WithPlatform(platform string) Option {
	return func(o *options) { o.platform = platform }
}

// WithImageCacheDir sets where images are unpacked (the user cache directory
// by default).
func WithImageCacheDir(dir string) Option {
	return func(o *options) { o.pull.CacheDir = dir }
}

// WithMaxImageSize caps an image's unpacked size in bytes (0 is 16 GiB).
func WithMaxImageSize(bytes uint64) Option {
	return func(o *options) { o.pull.MaxSize = int64(bytes) }
}

// WithCache memoizes syscall rewriting in c instead of the process-wide
// default cache.
func WithCache(c *Cache) Option {
	return func(o *options) { o.cfg.Cache = c }
}

// Cache memoizes syscall rewriting across runs; re-exported so a caller using
// WithCache need not import an internal package.
type Cache = rewrite.Cache

// DefaultCache is the process-wide rewrite cache that WithCache replaces.
func DefaultCache() *Cache { return rewrite.DefaultCache() }

// WithNoRewrite skips syscall rewriting, so the guest's syscalls reach the
// backstop, which kills it (ErrKilled). It exists to demonstrate the backstop.
func WithNoRewrite() Option {
	return func(o *options) { o.cfg.NoRewrite = true }
}

// environ is base with o's environment options applied.
func (o *options) environ(base []string) []string {
	env := base
	if o.envSet {
		env = o.env
	}
	env = append([]string(nil), env...)
	for _, kv := range o.envVars {
		env = setEnv(env, kv)
	}
	return env
}

// setEnv sets kv ("KEY=VALUE") in env, replacing the first entry for KEY.
func setEnv(env []string, kv string) []string {
	key, _, _ := strings.Cut(kv, "=")
	for i, e := range env {
		if k, _, _ := strings.Cut(e, "="); k == key {
			env[i] = kv
			return env
		}
	}
	return append(env, kv)
}
