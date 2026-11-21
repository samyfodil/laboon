// Linked into m5dlopen so that it is a dynamic executable (zig links a
// program with no shared library statically): it names what to dlopen.
const char *m5b_target(void) { return "libm5.so"; }
