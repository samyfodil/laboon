// Package sandbox runs a Linux program in a stub process whose syscalls are
// rewritten to trap into this supervisor. The public surface (Config, Run,
// ErrKilled) is cross-platform; the backend is per-OS (Linux today, macOS in
// progress — see AGENTS.md), selected by build tag.
package sandbox

import (
	"errors"
	"io"
	"sync"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/internal/rewrite"
)

// ErrKilled reports that the kernel killed the stub because the backstop
// denied a guest syscall. On Linux the seccomp backstop traps an unrewritten
// syscall and the supervisor services it, so this fires only for one it
// genuinely rejects (a wrong-architecture call, or the stub's own
// out-of-policy call); on macOS the Seatbelt allowlist denies.
var ErrKilled = errors.New("guest killed by the syscall backstop: rejected syscall")

// errNoBackstop refuses NoRewrite on a host with no syscall backstop to
// mediate the guest's raw syscalls (windows/arm64).
var errNoBackstop = errors.New("syscall rewriting cannot be turned off on this host: it has no syscall backstop")

var defaultCache = sync.OnceValue(rewrite.DefaultCache)

// discarded reports whether w is a standard output stream that goes to the
// null device.
func discarded(w io.Writer) bool {
	return w == nil || w == io.Discard
}

// Config describes one run.
type Config struct {
	Args []string // argv; Args[0] is the program name seen by the guest
	Env  []string
	// The guest's standard streams. An *os.File is handed to the guest
	// as is, and any other reader or writer is joined to it through a pipe
	// that the supervisor copies. A nil Stdin, and a nil or io.Discard
	// Stdout or Stderr, is the null device, which the stub serves itself.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Terminal, if set, runs the program on a pseudo-terminal bridged to it
	// (see WithTerminal); it overrides Stdin, Stdout and Stderr.
	Terminal Terminal
	// Trace, if set, receives one line per guest syscall.
	Trace io.Writer
	// RootFS is the guest's root filesystem ("/"), any core.FileSystem: a host
	// directory (HostRoot, or a public hostfs.Dir mounted at "/"), an in-memory tree (NewMemFS), a
	// union, a read-only or hardened wrapper, a network-backed or custom backend.
	// Without it the program path is a host path and the guest's / is an empty,
	// run-private writable tree holding only that program, read-only at its path.
	// The root is always a FileSystem, so the sandbox takes no host path for it;
	// the parts that still need a real host directory (a host image's writable
	// upper, the darwin exec resolver) recover it from a HostRoot with HostRootPath.
	RootFS core.FileSystem
	// Dir is the guest's initial working directory ("/" if empty).
	Dir string
	// Upper, if set with a host-directory RootFS, is a writable overlay layer kept after the run
	// instead of an ephemeral one: every change the guest makes to the
	// read-only Root lands here (new and modified files, and whiteouts for
	// deletions), so it is the filesystem diff of the run. An image builder
	// captures each build step's layer this way.
	Upper string
	// User, if set, is the credentials the first process runs as (an image's
	// USER). Nil runs as root with full capabilities.
	User *UserID
	// Mounts bind host paths into the guest. A mount whose Host is a directory
	// is a read-write bind of that directory at Guest, confined to the subtree
	// (as docker's -v does). A guest AF_UNIX connect under Guest also reaches
	// the host socket at the matching Host path, so a program reaches a host
	// service (an X server, a message bus) whether or not the bind exposes the
	// socket as a file.
	Mounts []Mount
	// Devices attach character devices to the guest, backed by the host, for a
	// direct host-guest channel with no network. Each appears under /dev.
	Devices []*Device
	// Cache memoizes rewriting by code content. Nil uses
	// rewrite.DefaultCache, shared by all runs in this process.
	Cache *rewrite.Cache
	// NoRewrite skips syscall rewriting, so every guest syscall is a raw one
	// that reaches the host's backstop: on Linux and macOS it is served
	// through the trap, as a rewritten site is; on windows/amd64 the
	// instrumentation-callback backstop kills the guest (ErrKilled); and
	// windows/arm64, which has no backstop, refuses to run (errNoBackstop).
	NoRewrite bool
	// RejectRWX refuses writable+executable guest memory: a mapping or
	// protection change asking for both fails with EACCES (W^X). Without it
	// JIT engines like V8 can map RWX code; the syscall backstop holds
	// either way.
	RejectRWX bool
	// Net enables networking: guest sockets are proxied to host sockets.
	// Without it the guest has loopback only, as Linux has with no network:
	// sockets on 127.0.0.1 and ::1 reach each other inside the run, and
	// nothing reaches the host or resolves through it.
	Net bool
	// NoNet takes loopback away too: without Net, no INET socket can be made.
	NoNet bool
	// AllowDomains, if non-empty, restricts egress: the supervisor answers
	// the guest's DNS itself and resolves only these domains (and their
	// subdomains), refusing all others, and lets the guest connect only to
	// addresses it resolved through us. A name that resolves to a private or
	// link-local/metadata address does not become reachable: those need an
	// explicit AllowCIDRs. Empty means the supervisor still answers DNS but
	// permits every domain and connection. The loopback is never the host's:
	// the guest's is its own, as a network namespace's lo is.
	AllowDomains []string
	// AllowCIDRs, if non-empty, additionally lets the guest connect to any
	// address in these networks (CIDR notation), even one it did not resolve
	// through us. It widens the IP allowlist alongside AllowDomains.
	AllowCIDRs []string
	// AllowPorts, if non-empty, restricts outbound connections to these
	// destination ports; any other port is refused. It applies on its own or
	// together with the domain/CIDR rules.
	AllowPorts []int
	// MaxBytes caps the guest's memory (0 = unlimited): its processes'
	// mapped address space together on Linux and macOS, its stubs' committed
	// memory on Windows (the job's limit).
	MaxBytes uint64
	// Control, if set, receives a handle to the running guest: its host leader
	// pid and a way to signal its init process (Control.Pid / Control.Signal),
	// valid while the run is live.
	Control *Control
}

// UserID is the credentials the first process runs as: uid, primary gid and
// supplementary groups, as an image's USER resolves to.
type UserID struct {
	Uid, Gid uint32
	Groups   []uint32
}

// Mount places a FileSystem into the guest's namespace at Guest. FS is any
// core.FileSystem the caller composed: hostfs.Dir for a confined host-directory
// bind (read-write, with AF_UNIX socket forwarding to the host), an in-memory
// store, a union, a hardened or read-only wrapper, or a custom backend. The
// public WithMount builds it.
type Mount struct {
	Guest string
	FS    core.FileSystem
}
