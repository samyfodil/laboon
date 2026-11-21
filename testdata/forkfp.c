// A fork child resumes with the forking thread's FP/SIMD state: every vector
// register (with AVX's upper halves where the CPU has AVX) and the FP control
// word, through a
// rewritten syscall site and (x86) a stray one the rewriter left to seccomp,
// which the stub serves inside a signal handler. With argv[1] "sites" only
// the rewritten site: a host that kills a stray syscall (Windows) has none to
// serve.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define NV 16
#define VB 32
static uint8_t in[NV * VB] __attribute__((aligned(32))), out[NV * VB] __attribute__((aligned(32)));
static uint32_t csr_in = 0x7f80 | 0x6000, csr_out; // all masked, round toward zero

// hidden_sys+2 is a syscall instruction inside a mov: a stray encoding.
__asm__(".text\n.globl hidden_sys\nhidden_sys:\n.byte 0x66, 0xb8, 0x0f, 0x05\nret\n");
void hidden_sys(void);

#define LOADV                                                                     \
    "vmovdqu 0(%[i]), %%ymm0\n vmovdqu 32(%[i]), %%ymm1\n vmovdqu 64(%[i]), %%ymm2\n" \
    "vmovdqu 96(%[i]), %%ymm3\n vmovdqu 128(%[i]), %%ymm4\n vmovdqu 160(%[i]), %%ymm5\n" \
    "vmovdqu 192(%[i]), %%ymm6\n vmovdqu 224(%[i]), %%ymm7\n vmovdqu 256(%[i]), %%ymm8\n" \
    "vmovdqu 288(%[i]), %%ymm9\n vmovdqu 320(%[i]), %%ymm10\n vmovdqu 352(%[i]), %%ymm11\n" \
    "vmovdqu 384(%[i]), %%ymm12\n vmovdqu 416(%[i]), %%ymm13\n vmovdqu 448(%[i]), %%ymm14\n" \
    "vmovdqu 480(%[i]), %%ymm15\n ldmxcsr (%[ci])\n"
#define STOREV                                                                    \
    "vmovdqu %%ymm0, 0(%[o])\n vmovdqu %%ymm1, 32(%[o])\n vmovdqu %%ymm2, 64(%[o])\n" \
    "vmovdqu %%ymm3, 96(%[o])\n vmovdqu %%ymm4, 128(%[o])\n vmovdqu %%ymm5, 160(%[o])\n" \
    "vmovdqu %%ymm6, 192(%[o])\n vmovdqu %%ymm7, 224(%[o])\n vmovdqu %%ymm8, 256(%[o])\n" \
    "vmovdqu %%ymm9, 288(%[o])\n vmovdqu %%ymm10, 320(%[o])\n vmovdqu %%ymm11, 352(%[o])\n" \
    "vmovdqu %%ymm12, 384(%[o])\n vmovdqu %%ymm13, 416(%[o])\n vmovdqu %%ymm14, 448(%[o])\n" \
    "vmovdqu %%ymm15, 480(%[o])\n stmxcsr (%[co])\n"
#define LOADX                                                                     \
    "movdqu 0(%[i]), %%xmm0\n movdqu 16(%[i]), %%xmm1\n movdqu 32(%[i]), %%xmm2\n"   \
    "movdqu 48(%[i]), %%xmm3\n movdqu 64(%[i]), %%xmm4\n movdqu 80(%[i]), %%xmm5\n"  \
    "movdqu 96(%[i]), %%xmm6\n movdqu 112(%[i]), %%xmm7\n movdqu 128(%[i]), %%xmm8\n" \
    "movdqu 144(%[i]), %%xmm9\n movdqu 160(%[i]), %%xmm10\n movdqu 176(%[i]), %%xmm11\n" \
    "movdqu 192(%[i]), %%xmm12\n movdqu 208(%[i]), %%xmm13\n movdqu 224(%[i]), %%xmm14\n" \
    "movdqu 240(%[i]), %%xmm15\n ldmxcsr (%[ci])\n"
#define STOREX                                                                    \
    "movdqu %%xmm0, 0(%[o])\n movdqu %%xmm1, 16(%[o])\n movdqu %%xmm2, 32(%[o])\n"   \
    "movdqu %%xmm3, 48(%[o])\n movdqu %%xmm4, 64(%[o])\n movdqu %%xmm5, 80(%[o])\n"  \
    "movdqu %%xmm6, 96(%[o])\n movdqu %%xmm7, 112(%[o])\n movdqu %%xmm8, 128(%[o])\n" \
    "movdqu %%xmm9, 144(%[o])\n movdqu %%xmm10, 160(%[o])\n movdqu %%xmm11, 176(%[o])\n" \
    "movdqu %%xmm12, 192(%[o])\n movdqu %%xmm13, 208(%[o])\n movdqu %%xmm14, 224(%[o])\n" \
    "movdqu %%xmm15, 240(%[o])\n stmxcsr (%[co])\n"
#define CLOBBER "rcx", "r11", "memory", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", \
    "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"

static int avx;
static long nbytes = NV * VB;

static long fork_site(int stray) {
    long r = 57; // fork
    void (*h)(void) = (void (*)(void))((char *)hidden_sys + 2);
    if (!avx) {
        if (stray)
            __asm__ volatile(LOADX "call *%[h]\n" STOREX
                             : "+a"(r)
                             : [i] "r"(in), [o] "r"(out), [ci] "r"(&csr_in), [co] "r"(&csr_out), [h] "r"(h)
                             : CLOBBER);
        else
            __asm__ volatile(LOADX "syscall\n" STOREX
                             : "+a"(r)
                             : [i] "r"(in), [o] "r"(out), [ci] "r"(&csr_in), [co] "r"(&csr_out)
                             : CLOBBER);
        return r;
    }
    if (stray) {
        __asm__ volatile(LOADV "call *%[h]\n" STOREV
                         : "+a"(r)
                         : [i] "r"(in), [o] "r"(out), [ci] "r"(&csr_in), [co] "r"(&csr_out), [h] "r"(h)
                         : CLOBBER);
    } else {
        __asm__ volatile(LOADV "syscall\n" STOREV
                         : "+a"(r)
                         : [i] "r"(in), [o] "r"(out), [ci] "r"(&csr_in), [co] "r"(&csr_out)
                         : CLOBBER);
    }
    return r;
}
#define CSR_MASK 0xffc0 // the control bits; the flags may differ
#elif defined(__aarch64__)
#define NV 32
#define VB 16
static uint8_t in[NV * VB] __attribute__((aligned(16))), out[NV * VB] __attribute__((aligned(16)));
static uint64_t csr_in = 3 << 22, csr_out; // FPCR.RMode: round toward zero

static long fork_site(int stray) {
    (void)stray;
    register long x8 __asm__("x8") = 220; // clone
    register long x0 __asm__("x0") = 17;  // SIGCHLD
    register long x1 __asm__("x1") = 0;
    __asm__ volatile(
        "ldp q0, q1, [%[i], #0]\n ldp q2, q3, [%[i], #32]\n ldp q4, q5, [%[i], #64]\n ldp q6, q7, [%[i], #96]\n"
        "ldp q8, q9, [%[i], #128]\n ldp q10, q11, [%[i], #160]\n ldp q12, q13, [%[i], #192]\n ldp q14, q15, [%[i], #224]\n"
        "ldp q16, q17, [%[i], #256]\n ldp q18, q19, [%[i], #288]\n ldp q20, q21, [%[i], #320]\n ldp q22, q23, [%[i], #352]\n"
        "ldp q24, q25, [%[i], #384]\n ldp q26, q27, [%[i], #416]\n ldp q28, q29, [%[i], #448]\n ldp q30, q31, [%[i], #480]\n"
        "ldr x9, [%[ci]]\n msr fpcr, x9\n"
        "svc #0\n"
        "stp q0, q1, [%[o], #0]\n stp q2, q3, [%[o], #32]\n stp q4, q5, [%[o], #64]\n stp q6, q7, [%[o], #96]\n"
        "stp q8, q9, [%[o], #128]\n stp q10, q11, [%[o], #160]\n stp q12, q13, [%[o], #192]\n stp q14, q15, [%[o], #224]\n"
        "stp q16, q17, [%[o], #256]\n stp q18, q19, [%[o], #288]\n stp q20, q21, [%[o], #320]\n stp q22, q23, [%[o], #352]\n"
        "stp q24, q25, [%[o], #384]\n stp q26, q27, [%[o], #416]\n stp q28, q29, [%[o], #448]\n stp q30, q31, [%[o], #480]\n"
        "mrs x9, fpcr\n str x9, [%[co]]\n"
        : "+r"(x0)
        : "r"(x8), "r"(x1), [i] "r"(in), [o] "r"(out), [ci] "r"(&csr_in), [co] "r"(&csr_out)
        : "x9", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13",
          "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28",
          "v29", "v30", "v31");
    return x0;
}
#define CSR_MASK (~0ull)
static long nbytes = NV * VB;
#endif

static int same(void) {
    return memcmp(in, out, nbytes) == 0 && ((csr_in ^ csr_out) & CSR_MASK) == 0;
}

int main(int argc, char **argv) {
    int strays = !(argc > 1 && strcmp(argv[1], "sites") == 0);
#if defined(__x86_64__)
    __builtin_cpu_init();
    avx = __builtin_cpu_supports("avx");
    if (!avx) nbytes = NV * 16;
#endif
    for (int stray = 0; stray < 2; stray++) {
#if !defined(__x86_64__)
        if (stray) break;
#endif
        if (stray && !strays) break;
        for (int i = 0; i < (int)sizeof in; i++) in[i] = (uint8_t)(i * 7 + 13 + stray);
        memset(out, 0, sizeof out);
        long pid = fork_site(stray);
        if (pid < 0) {
            printf("fork failed: %ld\n", pid);
            return 1;
        }
        if (pid == 0) _exit(same() ? 0 : 1);
        if (!same()) {
            printf("parent lost FP state (stray=%d)\n", stray);
            return 1;
        }
        int st;
        if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            printf("child lost FP state (stray=%d): %#x\n", stray, st);
            return 1;
        }
    }
    printf("forkfp ok\n");
    return 0;
}
