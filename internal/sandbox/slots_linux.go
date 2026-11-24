package sandbox

// maxSlots is the slot index space: PID_MAX_LIMIT, as many threads as Linux
// can ever have (MAX_SLOTS in stub/zig/stub.zig). Nothing is allocated for a
// slot until a thread uses it: the shared regions are memfd pages, and the
// private stacks are mapped a chunk at a time (stacks_linux.go).
const maxSlots = 1 << 22
