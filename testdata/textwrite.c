// Writes its own text: makes the page of a function writable (and still
// executable: main may run there too), writes a byte of it back unchanged,
// then writes raw getpid code (a syscall instruction) over a padding
// function, drops the write and calls both. A program's text, however it was
// loaded, can be written once the program asks, and a syscall written there
// is the guest's, served as any other.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

__attribute__((noinline)) int seven(void) { return 7; }

__attribute__((noinline, aligned(64))) long pad(void) {
	__asm__ volatile(".rept 32\n nop\n .endr");
	return -1;
}

#if defined(__x86_64__)
static const uint8_t getpid_code[] = {0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0xc3}; // mov $39,%eax; syscall; ret
#elif defined(__aarch64__)
static const uint32_t getpid_code[] = {0xd2801588, 0xd4000001, 0xd65f03c0}; // mov x8,#172; svc #0; ret
#endif

static int writable(void *fn, int on) {
	long pg = sysconf(_SC_PAGESIZE);
	uintptr_t a = (uintptr_t)fn & ~(uintptr_t)(pg - 1);
	return mprotect((void *)a, 2 * pg, PROT_READ | PROT_EXEC | (on ? PROT_WRITE : 0));
}

int main(void) {
	volatile uint8_t *p = (volatile uint8_t *)(uintptr_t)seven;
	if (writable((void *)seven, 1) != 0) {
		perror("mprotect rwx");
		return 1;
	}
	*p = *p;
	if (writable((void *)seven, 0) != 0) {
		perror("mprotect rx");
		return 1;
	}
	if (writable((void *)pad, 1) != 0) {
		perror("mprotect rwx pad");
		return 1;
	}
	memcpy((void *)(uintptr_t)pad, getpid_code, sizeof(getpid_code));
	if (writable((void *)pad, 0) != 0) {
		perror("mprotect rx pad");
		return 1;
	}
	__builtin___clear_cache((char *)(uintptr_t)pad, (char *)(uintptr_t)pad + sizeof(getpid_code));
	long got = pad();
	printf("text written, seven()=%d, written getpid %s\n", seven(), got == getpid() ? "ok" : "wrong");
	return 0;
}
