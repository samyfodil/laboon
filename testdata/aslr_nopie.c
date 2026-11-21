// build: -static -no-pie -fno-pie
// aslr built position-dependent: its code stays at the link address while its
// stack and heap move.
#include "aslr.c"
