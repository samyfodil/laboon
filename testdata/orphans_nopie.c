// build: -static -no-pie -fno-pie
// orphans built position-dependent, which Darwin runs under the HVF stub.
#include "orphans.c"
