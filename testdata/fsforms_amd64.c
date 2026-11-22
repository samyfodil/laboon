// %fs-relative instruction forms beyond plain loads and stores, each run a few
// times on two threads: push, pop, call and jmp through %fs memory, a 16-bit
// immediate store whose operand-size prefix follows the %fs override (as rustc
// emits it), and an adc, which the stub does not emulate but sends to an
// island. The last two run with rax at a canary, which nothing executed on the
// way through may touch. Prints "fsforms ok" per thread.
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint64_t fs_push(long off);
void fs_pop(long off, uint64_t v);
uint64_t fs_call(long off);
uint64_t fs_jmp(long off);
void fs_movw(long off, volatile unsigned char *rax);
void fs_adc(long off, volatile unsigned char *rax);
uint64_t fs_ret7(void);
uint64_t fs_jt(void);

__asm__(
	".text\n"
	".globl fs_push\n fs_push:\n .byte 0x64,0xff,0x37\n pop %rax\n ret\n"         // push qword fs:[rdi]
	".globl fs_pop\n fs_pop:\n push %rsi\n .byte 0x64,0x8f,0x07\n ret\n"          // pop qword fs:[rdi]
	".globl fs_call\n fs_call:\n .byte 0x64,0xff,0x17\n ret\n"                     // call qword fs:[rdi]
	".globl fs_jmp\n fs_jmp:\n .byte 0x64,0xff,0x27\n"                             // jmp qword fs:[rdi]
	".globl fs_movw\n fs_movw:\n mov %rsi, %rax\n .byte 0x64,0x66,0xc7,0x07,0x34,0x12\n ret\n" // mov word fs:[rdi], 0x1234
	".globl fs_adc\n fs_adc:\n mov %rsi, %rax\n clc\n .byte 0x64,0x48,0x11,0x47,0x00\n ret\n" // adc fs:[rdi], rax
	".globl fs_ret7\n fs_ret7:\n mov $7, %eax\n ret\n"
	".globl fs_jt\n fs_jt:\n mov $9, %eax\n ret\n");

static __thread uint64_t tv[4];

static int check(const char *who) {
	int fails = 0;
	uint64_t tp;
	__asm__ volatile("mov %%fs:0, %0" : "=r"(tp));
	long off = (long)((uintptr_t)&tv[0] - tp);
	static volatile unsigned char canary[512];
	volatile unsigned char *c = canary + 256;
	c -= (uintptr_t)c & 0xff;
	c += 0x5a; // rax's low byte, al, is not zero
	for (int round = 0; round < 3; round++) {
		tv[0] = 0x1111222233334444ull + round;
		if (fs_push(off) != tv[0]) { printf("%s FAIL push round %d\n", who, round); fails++; }
		fs_pop(off + 8, 0x5555666677778888ull + round);
		if (tv[1] != 0x5555666677778888ull + round) { printf("%s FAIL pop round %d\n", who, round); fails++; }
		tv[2] = (uint64_t)(uintptr_t)fs_ret7;
		if (fs_call(off + 16) != 7) { printf("%s FAIL call round %d\n", who, round); fails++; }
		tv[3] = (uint64_t)(uintptr_t)fs_jt;
		if (fs_jmp(off + 24) != 9) { printf("%s FAIL jmp round %d\n", who, round); fails++; }
		tv[0] = 0xaaaaaaaaaaaaaaaaull;
		memset((void *)canary, 0, sizeof canary);
		fs_movw(off, c);
		if (tv[0] != 0xaaaaaaaaaaaa1234ull) { printf("%s FAIL movw round %d: %llx\n", who, round, (unsigned long long)tv[0]); fails++; }
		for (size_t i = 0; i < sizeof canary; i++) {
			if (canary[i]) { printf("%s FAIL movw round %d: canary[%zu]=%u\n", who, round, i, canary[i]); fails++; break; }
		}
		tv[1] = 1000 + round;
		fs_adc(off + 8, c);
		if (tv[1] != 1000 + round + (uint64_t)(uintptr_t)c) { printf("%s FAIL adc round %d\n", who, round); fails++; }
		for (size_t i = 0; i < sizeof canary; i++) {
			if (canary[i]) { printf("%s FAIL adc round %d: canary[%zu]=%u\n", who, round, i, canary[i]); fails++; break; }
		}
	}
	if (!fails) printf("fsforms ok\n");
	return fails;
}

static void *thread(void *arg) {
	(void)arg;
	return (void *)(intptr_t)check("thread");
}

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);
	int fails = check("main");
	pthread_t t;
	void *r;
	if (pthread_create(&t, NULL, thread, NULL) != 0 || pthread_join(t, &r) != 0) return 2;
	return fails + (int)(intptr_t)r ? 1 : 0;
}
