// Code that writes a syscall into the page it runs from, then runs it: a
// routine in an anonymous read-write-execute page stores the syscall
// instruction into a getpid sequence further on in its own page and returns,
// and the program calls that sequence. The written syscall is the guest's,
// served as any other.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__x86_64__)
// movw $0x050f, 0x40(%rdi); ret
static const uint8_t store[] = {0x66, 0xc7, 0x47, 0x40, 0x0f, 0x05, 0xc3};
// at 0x3b: mov $39, %eax; (0x40: nop; nop, to become syscall); ret
static const uint8_t seq[] = {0xb8, 39, 0, 0, 0, 0x90, 0x90, 0xc3};
#define SEQ 0x3b
#elif defined(__aarch64__)
// movz w9, #1; movk w9, #0xd400, lsl #16; str w9, [x0, #0x40]; ret
static const uint32_t store[] = {0x52800029, 0x72ba8009, 0xb9004009, 0xd65f03c0};
// at 0x3c: mov x8, #172; (0x40: nop, to become svc #0); ret
static const uint32_t seq[] = {0xd2801588, 0xd503201f, 0xd65f03c0};
#define SEQ 0x3c
#endif

int main(void) {
	uint8_t *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	memcpy(page, store, sizeof(store));
	memcpy(page + SEQ, seq, sizeof(seq));
	__builtin___clear_cache((char *)page, (char *)page + 4096);
	for (int i = 0; i < 3; i++) {
		((void (*)(void *))page)(page);
		__builtin___clear_cache((char *)page, (char *)page + 4096);
		long got = ((long (*)(void))(page + SEQ))();
		if (got != getpid()) {
			printf("written getpid returned %ld, not %d\n", got, getpid());
			return 1;
		}
	}
	puts("own syscall ok");
	return 0;
}
