package sandbox

// maxSlots is the slot index space: PID_MAX_LIMIT, as many threads as Linux
// can ever have (MAX_SLOTS in stub/windows/stub.zig). Nothing is allocated
// for a slot until a thread uses it: the shared region is a section per chunk
// of slots, made as the chunk comes into use (chanmap_windows.go), and each
// stub keeps its own per-slot state in chunks it allocates as it uses them
// (stub/windows/blocks.zig).
const maxSlots = 1 << 22
