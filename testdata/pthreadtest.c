// libc: musl
// A real musl pthread workload: create worker threads, have them contend on a
// mutex to bump a shared counter, then join them and check the total. This
// exercises clone(CLONE_VM...), set_tid_address, futex (mutex + join), and the
// single-thread exit path end to end -- the real libc threading path, not a
// hand-rolled clone. Then a semaphore handshake: every post of a burst wakes a
// waiter, as a GC's start semaphore needs (a lost wake hangs it). Built static
// for aarch64-linux-musl with zig cc.
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>

#define THREADS 4
#define ITERS 50000

#define WAITERS 8
#define ROUNDS 200

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long counter;
static sem_t go, back;

static void *waiter(void *arg) {
    for (int r = 0; r < ROUNDS; r++) {
        sem_wait(&go);
        sem_post(&back);
    }
    return arg;
}

static void *worker(void *arg) {
    long id = (long)arg;
    for (int i = 0; i < ITERS; i++) {
        pthread_mutex_lock(&mu);
        counter++;
        pthread_mutex_unlock(&mu);
    }
    return (void *)(id + 100);
}

int main(void) {
    pthread_t t[THREADS];
    for (long i = 0; i < THREADS; i++) {
        if (pthread_create(&t[i], NULL, worker, (void *)i) != 0) {
            printf("create %ld failed\n", i);
            return 1;
        }
    }
    long sum = 0;
    for (long i = 0; i < THREADS; i++) {
        void *r = NULL;
        pthread_join(t[i], &r);
        sum += (long)r;
    }
    long want = (long)THREADS * ITERS;
    long wantsum = 0;
    for (long i = 0; i < THREADS; i++) wantsum += i + 100;

    sem_init(&go, 0, 0);
    sem_init(&back, 0, 0);
    pthread_t w[WAITERS];
    for (int i = 0; i < WAITERS; i++) pthread_create(&w[i], NULL, waiter, NULL);
    int rounds = 0;
    for (; rounds < ROUNDS; rounds++) {
        for (int i = 0; i < WAITERS; i++) sem_post(&go);
        for (int i = 0; i < WAITERS; i++) sem_wait(&back);
    }
    for (int i = 0; i < WAITERS; i++) pthread_join(w[i], NULL);

    int ok = counter == want && sum == wantsum && rounds == ROUNDS;
    printf("counter=%ld want=%ld join_sum=%ld want=%ld sem_rounds=%d %s\n",
           counter, want, sum, wantsum, rounds, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
