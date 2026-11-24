package sandbox

// maxSlots is the slot index space: PID_MAX_LIMIT, as many threads as Linux
// can ever have (MAX_SLOTS in stub/macos/chan.zig). Nothing is allocated for
// a slot until a thread uses it: the shared regions are a sparse file, and
// the stub's per-slot tables are zero-fill memory.
const maxSlots = 1 << 22
