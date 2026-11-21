// Guest faults, and the x18/system-register paths of the Windows arm64 stub.
//   fault segv  load from address 0 (on arm64 with a junk x18 live): SIGSEGV
//   fault ill   an undefined instruction (udf #1, ud0): SIGILL
//   fault x18   arm64: a junk x18 survives a svc and a trapped mrs
//               midr_el1; prints the CTR_EL0 the guest reads
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
	const char *m = argc > 1 ? argv[1] : "";
#ifdef __aarch64__
	if (!strcmp(m, "segv"))
		__asm__ volatile("mov x18, %0\n ldr x0, [%1]" ::"r"(0xdeadbeef0badf00dUL), "r"(0UL) : "x18", "x0", "memory");
	if (!strcmp(m, "ill"))
		__asm__ volatile(".inst 0x00000001");
#else
	if (!strcmp(m, "segv"))
		return *(volatile int *)0;
	if (!strcmp(m, "ill"))
		__asm__ volatile(".byte 0x0f, 0xff, 0xc0"); // ud0 eax, eax
#endif
#ifdef __aarch64__
	if (!strcmp(m, "x18")) {
		unsigned long junk = 0x1122334455667788UL, a, b, midr, ctr;
		register unsigned long nr __asm__("x8") = 172; // getpid
		__asm__ volatile(
			"mov x18, %[j]\n"
			"svc #0\n"
			"mov %[a], x18\n"
			"mrs %[m], midr_el1\n"
			"mov %[b], x18\n"
			"mrs %[c], ctr_el0\n"
			"mov x18, xzr\n"
			: [a] "=&r"(a), [b] "=&r"(b), [m] "=&r"(midr), [c] "=&r"(ctr)
			: [j] "r"(junk), "r"(nr)
			: "x0", "x18", "memory");
		printf("%s %lx\n", a == junk && b == junk ? "x18 ok" : "x18 BAD", ctr);
		return 0;
	}
#endif
	return 2;
}
