// idregs: the AArch64 feature ID registers the guest reads with mrs are
// served and consistent with AT_HWCAP — never claiming a feature the host
// lacks. On Linux the kernel emulates these reads; laboon emulates them on
// macOS and Windows arm64, where they otherwise trap. Not aarch64: a no-op.
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/auxv.h>

static int fails;
#define CHECK(c, ...) \
	do { \
		if (!(c)) { \
			fails++; \
			printf("FAIL %d: ", __LINE__); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} \
	} while (0)

#if defined(__aarch64__)
static sigjmp_buf illJmp;
static void onIll(int s) { (void)s; siglongjmp(illJmp, 1); }

// rd reads system register reg (an mrs), or reports it trapped.
#define rd(reg, out) \
	({ \
		int ok = !sigsetjmp(illJmp, 1); \
		if (ok) \
			__asm__ volatile("mrs %0, " reg : "=r"(out)); \
		ok; \
	})

#define F(v, lo) (((v) >> (lo)) & 0xf)

// want: if the host advertises hwbit in HWCAP, the ISAR field must be set,
// and never the other way (no feature the host lacks).
#define BOTH(name, set, hwbit) \
	CHECK(!!(set) == !!(hwbit), "%s: isar %d hwcap %d", name, !!(set), !!(hwbit))
// safe: the ISAR field may be set only if the host advertises hwbit.
#define SAFE(name, set, hwbit) \
	CHECK(!(set) || (hwbit), "%s: claimed but no hwcap", name)

int main(void) {
	struct sigaction sa = {0}, old;
	sa.sa_handler = onIll;
	sigaction(SIGILL, &sa, &old);

	unsigned long hc = getauxval(AT_HWCAP), hc2 = getauxval(AT_HWCAP2);
	unsigned long isar0 = 0, isar1 = 0, isar2 = 0, mpidr = 0, revidr = 0;
	CHECK(rd("id_aa64isar0_el1", isar0), "id_aa64isar0_el1 trapped");
	CHECK(rd("id_aa64isar1_el1", isar1), "id_aa64isar1_el1 trapped");
	CHECK(rd("id_aa64isar2_el1", isar2), "id_aa64isar2_el1 trapped");
	CHECK(rd("mpidr_el1", mpidr), "mpidr_el1 trapped");
	CHECK(rd("revidr_el1", revidr), "revidr_el1 trapped");
	sigaction(SIGILL, &old, NULL);

	// ISAR0.
	BOTH("aes", F(isar0, 4) >= 1, hc & (1 << 3));
	BOTH("pmull", F(isar0, 4) >= 2, hc & (1 << 4));
	BOTH("sha1", F(isar0, 8), hc & (1 << 5));
	BOTH("sha2", F(isar0, 12) >= 1, hc & (1 << 6));
	BOTH("sha512", F(isar0, 12) >= 2, hc & (1 << 21));
	BOTH("crc32", F(isar0, 16), hc & (1 << 7));
	BOTH("lse", F(isar0, 20), hc & (1 << 8));
	BOTH("rdm", F(isar0, 28), hc & (1 << 12));
	BOTH("sha3", F(isar0, 32), hc & (1 << 17));
	BOTH("dp", F(isar0, 44), hc & (1 << 20));
	// ISAR1.
	BOTH("jscvt", F(isar1, 12), hc & (1 << 13));
	BOTH("fcma", F(isar1, 16), hc & (1 << 14));
	BOTH("lrcpc", F(isar1, 20) >= 1, hc & (1 << 15));
	BOTH("i8mm", F(isar1, 52), hc2 & (1 << 13));
	BOTH("bf16", F(isar1, 44), hc2 & (1 << 14));
	BOTH("sm3", F(isar0, 36), hc & (1 << 18));
	BOTH("sm4", F(isar0, 40), hc & (1 << 19));
	SAFE("isar1 ptrauth-apa", F(isar1, 4), hc & (1UL << 30));

	CHECK(mpidr == 0x80000000, "mpidr %#lx, want 0x80000000", mpidr);
	CHECK(revidr == 0, "revidr %#lx, want 0", revidr);

	printf("idregs fails=%d\n", fails);
	return fails != 0;
}
#else
int main(void) {
	printf("idregs fails=%d\n", fails);
	return 0;
}
#endif
