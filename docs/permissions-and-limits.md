# Permissions and limits

laboon is confined by default; every capability below is an explicit opt-in.

## Networking

Networking is off by default: the guest has loopback only, like
`docker --network none`. `WithNet()` enables egress through supervisor-proxied
host sockets. Add `WithAllowDomains`, `WithAllowCIDRs`, and `WithAllowPorts` to
bound access; enabling networking alone does not create a restrictive allowlist.
Domain rules include subdomains, CIDRs add directly reachable addresses, and
port rules restrict destination ports.

`WithNoNet()` removes loopback too when `WithNet` is absent. The current Windows
exception is that guest `AF_INET` sockets require `WithNet`, even for loopback.

## Filesystem

Without a root (`WithRoot`, or `WithMount` at `/`), the guest's `/` is an empty,
run-private writable tree holding only the program, read-only at its host path;
nothing else of the host is visible. A `tmpfs` the guest mounts is a fresh
private tree wherever it is mounted.

`WithMount(host, guest)` exposes a host directory read-write, confined to that
subtree; `WithMountReadOnly(host, guest)` exposes it read-only (create, modify,
delete and rename all fail with `EROFS`). A mount can also expose host Unix
sockets beneath it, so a mount is an explicit grant of access.

## Memory

Writable-plus-executable guest memory is allowed by default for JITs such as V8;
`WithRejectRWX()` refuses it. There is no default memory cap. `WithMaxMemory`
limits mapped address space on Linux and macOS, and stub-process committed
memory on Windows. The cap covers all of the run's processes together.

These controls and their semantics are documented in
[../options.go](../options.go) and
[../internal/sandbox/config.go](../internal/sandbox/config.go).
