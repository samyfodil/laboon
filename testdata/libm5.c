// A shared library for the M5 dynamic-linking tests: plain calls, a
// constructor, thread-local storage and a call back into libc.
#include <stdio.h>
#include <string.h>

int m5_inited;
static __thread int tls_counter = 40;

__attribute__((constructor)) static void m5_init(void) { m5_inited = 7; }

int m5_add(int a, int b) { return a + b; }

int m5_tls(void) { return ++tls_counter; }

int m5_fmt(char *buf, int n, int v) { return snprintf(buf, n, "v=%d len=%zu", v, strlen("libm5")); }
