// Links libm5.so at load time: relocations, its constructor, TLS from the
// main thread and a second thread, and libc calls that reach syscalls in
// ld-musl.
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

extern int m5_inited;
int m5_add(int, int);
int m5_tls(void);
int m5_fmt(char *, int, int);

static void *worker(void *arg) {
	(void)arg;
	return (void *)(long)m5_tls(); // a fresh thread sees the initial TLS value
}

int main(void) {
	char buf[64];
	int fails = 0;
	if (m5_inited != 7) printf("FAIL constructor %d\n", m5_inited), fails++;
	if (m5_add(2, 3) != 5) printf("FAIL add\n"), fails++;
	int a = m5_tls(), b = m5_tls();
	if (a != 41 || b != 42) printf("FAIL tls %d %d\n", a, b), fails++;
	pthread_t t;
	void *r;
	if (pthread_create(&t, 0, worker, 0) || pthread_join(t, &r) || (long)r != 41) printf("FAIL thread tls %ld\n", (long)r), fails++;
	m5_fmt(buf, sizeof buf, 9);
	printf("%s pid>0:%d\n", buf, getpid() > 0);
	printf(fails ? "m5dyn FAIL\n" : "m5dyn OK\n");
	return fails;
}
