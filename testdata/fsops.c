// libc: musl
// Filesystem and misc syscalls a guest expects; each failed check prints a
// FAIL line, and the last line is "done fails=N". Runs with / as the root.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;

#define CHECK(c)                                                                  \
	do {                                                                          \
		if (!(c)) {                                                               \
			printf("FAIL %s:%d %s (errno %d)\n", __func__, __LINE__, #c, errno); \
			fails++;                                                              \
		}                                                                         \
	} while (0)

static char dir[64];

static char *p(const char *name) {
	static char buf[4][128];
	static int i;
	char *b = buf[i++ % 4];
	snprintf(b, 128, "%s/%s", dir, name);
	return b;
}

static void writeFile(const char *path, const char *s) {
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	write(fd, s, strlen(s));
	close(fd);
}

static void excl(void) {
	int fd = open(p("e"), O_WRONLY | O_CREAT | O_EXCL, 0100644);
	CHECK(fd >= 0);
	close(fd);
	CHECK(open(p("e"), O_WRONLY | O_CREAT | O_EXCL, 0644) < 0 && errno == EEXIST);
	CHECK(open("/etc/passwd", O_WRONLY | O_CREAT | O_EXCL, 0644) < 0 && errno == EEXIST);
}

static void modes(void) {
	struct stat st;
	umask(022);
	CHECK(umask(027) == 022);
	int fd = open(p("m"), O_WRONLY | O_CREAT, 0666);
	CHECK(fstat(fd, &st) == 0 && (st.st_mode & 0777) == 0640);
	CHECK(fchmod(fd, 0604) == 0);
	CHECK(stat(p("m"), &st) == 0 && (st.st_mode & 07777) == 0604);
	close(fd);
	umask(022);
	CHECK(chmod(p("m"), 04755) == 0);
	CHECK(stat(p("m"), &st) == 0 && (st.st_mode & 07777) == 04755);
	CHECK(fchmodat(AT_FDCWD, p("m"), 0, 0) == 0);
	CHECK(stat(p("m"), &st) == 0 && (st.st_mode & 07777) == 0);
	fd = open(p("m"), O_RDWR); // root ignores permission bits
	CHECK(fd >= 0);
	close(fd);
	CHECK(chmod("/etc/passwd", 0600) == 0);
	CHECK(stat("/etc/passwd", &st) == 0 && (st.st_mode & 0777) == 0600);
	CHECK(chmod(p("nonexistent"), 0600) < 0 && errno == ENOENT);
}

static void owners(void) {
	struct stat st;
	writeFile(p("o"), "x");
	CHECK(chown(p("o"), 123, 456) == 0);
	CHECK(stat(p("o"), &st) == 0 && st.st_uid == 123 && st.st_gid == 456);
	CHECK(chown(p("o"), -1, 7) == 0);
	CHECK(stat(p("o"), &st) == 0 && st.st_uid == 123 && st.st_gid == 7);
	int fd = open(p("o"), O_RDONLY);
	CHECK(fchown(fd, 0, 0) == 0);
	CHECK(fstat(fd, &st) == 0 && st.st_uid == 0 && st.st_gid == 0);
	close(fd);
	CHECK(symlink("o", p("ol")) == 0);
	CHECK(lchown(p("ol"), 5, 5) == 0);
	CHECK(lstat(p("ol"), &st) == 0 && st.st_uid == 5);
	CHECK(stat(p("ol"), &st) == 0 && st.st_uid == 0);
}

static void times_(void) {
	struct stat st;
	writeFile(p("t"), "x");
	struct timespec ts[2] = {{1000, 5}, {2000, 7}};
	CHECK(utimensat(AT_FDCWD, p("t"), ts, 0) == 0);
	CHECK(stat(p("t"), &st) == 0 && st.st_atim.tv_sec == 1000 && st.st_mtim.tv_sec == 2000 && st.st_mtim.tv_nsec == 7);
	struct timespec omit[2] = {{0, UTIME_OMIT}, {3000, 0}};
	CHECK(utimensat(AT_FDCWD, p("t"), omit, 0) == 0);
	CHECK(stat(p("t"), &st) == 0 && st.st_atim.tv_sec == 1000 && st.st_mtim.tv_sec == 3000);
	struct timeval tv[2] = {{4000, 0}, {5000, 0}};
	CHECK(utimes(p("t"), tv) == 0);
	CHECK(stat(p("t"), &st) == 0 && st.st_mtim.tv_sec == 5000);
	int fd = open(p("t"), O_RDONLY);
	CHECK(futimens(fd, NULL) == 0);
	CHECK(fstat(fd, &st) == 0 && st.st_mtim.tv_sec > 1600000000);
	close(fd);
	CHECK(utimensat(AT_FDCWD, "/etc/hostname", ts, 0) == 0 || errno == ENOENT);
	CHECK(utimensat(AT_FDCWD, p("nonexistent"), ts, 0) < 0 && errno == ENOENT);
}

static void links(void) {
	struct stat st;
	char buf[64] = {0};
	CHECK(symlink("target", p("l")) == 0);
	CHECK(readlink(p("l"), buf, sizeof buf) == 6 && memcmp(buf, "target", 6) == 0);
	CHECK(lstat(p("l"), &st) == 0 && S_ISLNK(st.st_mode));
	CHECK(symlink("x", p("l")) < 0 && errno == EEXIST);
	CHECK(symlink("x", "/etc/passwd") < 0 && errno == EEXIST);
	int d = open(dir, O_RDONLY | O_DIRECTORY);
	CHECK(symlinkat("/etc/passwd", d, "l2") == 0);
	CHECK(stat(p("l2"), &st) == 0 && S_ISREG(st.st_mode));
	close(d);
	writeFile(p("h"), "hard");
	CHECK(link(p("h"), p("h2")) == 0);
	CHECK(stat(p("h2"), &st) == 0 && st.st_size == 4 && st.st_nlink == 2);
	// A new symlink into the image, followed through further ones.
	CHECK(symlink("/usr", p("usr")) == 0);
	CHECK(symlink("usr/bin", p("bin")) == 0);
	int fd = open(p("bin/env"), O_RDONLY);
	CHECK(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode));
	close(fd);
	CHECK(access(p("usr/bin/env"), X_OK) == 0);
}

static void nodes(void) {
	struct stat st;
	CHECK(mkfifo(p("ff"), 0644) == 0);
	CHECK(stat(p("ff"), &st) == 0 && S_ISFIFO(st.st_mode));
	CHECK(mknod(p("reg"), S_IFREG | 0600, 0) == 0);
	CHECK(stat(p("reg"), &st) == 0 && S_ISREG(st.st_mode));
	CHECK(mknod(p("reg"), S_IFREG | 0600, 0) < 0 && errno == EEXIST);
	// A socket inode needs no privilege; nothing listens on it.
	CHECK(mknod(p("sock"), S_IFSOCK | 0600, 0) == 0);
	CHECK(stat(p("sock"), &st) == 0 && S_ISSOCK(st.st_mode));
	CHECK(mknod(p("sock"), S_IFSOCK | 0600, 0) < 0 && errno == EEXIST);
	CHECK(mknod(p("dir"), S_IFDIR | 0700, 0) < 0 && errno == EPERM);
	struct sockaddr_un ua = {.sun_family = AF_UNIX};
	strncpy(ua.sun_path, p("sock"), sizeof ua.sun_path - 1);
	int us = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(connect(us, (struct sockaddr *)&ua, sizeof ua) < 0 && errno == ECONNREFUSED);
	close(us);
	pid_t c = fork();
	if (c == 0) {
		int fd = open(p("ff"), O_WRONLY);
		write(fd, "fifo", 4);
		_exit(0);
	}
	char buf[8] = {0};
	int fd = open(p("ff"), O_RDONLY);
	CHECK(fd >= 0 && read(fd, buf, sizeof buf) == 4 && memcmp(buf, "fifo", 4) == 0);
	close(fd);
	waitpid(c, 0, 0);
}

static void locks(void) {
	writeFile(p("k"), "lock");
	int a = open(p("k"), O_RDWR), b = open(p("k"), O_RDWR);
	CHECK(flock(a, LOCK_EX) == 0);
	CHECK(flock(b, LOCK_EX | LOCK_NB) < 0 && errno == EWOULDBLOCK);
	CHECK(flock(a, LOCK_UN) == 0);
	CHECK(flock(b, LOCK_SH | LOCK_NB) == 0);
	flock(b, LOCK_UN);
	struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
	CHECK(fcntl(a, F_SETLK, &fl) == 0);
	pid_t c = fork();
	if (c == 0) {
		int fd = open(p("k"), O_RDWR);
		struct flock w = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
		int busy = fcntl(fd, F_SETLK, &w) < 0 && (errno == EAGAIN || errno == EACCES);
		struct flock q = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
		int seen = fcntl(fd, F_GETLK, &q) == 0 && q.l_type == F_WRLCK;
		struct flock o = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 1, .l_len = 1};
		int other = fcntl(fd, F_SETLK, &o) == 0;
		_exit(busy && seen && other ? 0 : 1);
	}
	int ws;
	CHECK(waitpid(c, &ws, 0) == c && WIFEXITED(ws) && WEXITSTATUS(ws) == 0);
	fl.l_type = F_UNLCK;
	CHECK(fcntl(a, F_SETLK, &fl) == 0);
	close(a);
	close(b);
}

static void vectors(void) {
	writeFile(p("v"), "hello world");
	int fd = open(p("v"), O_RDONLY);
	char x[6] = {0}, y[6] = {0};
	struct iovec iov[2] = {{x, 5}, {y, 6}};
	CHECK(readv(fd, iov, 2) == 11 && memcmp(x, "hello", 5) == 0 && memcmp(y, " world", 6) == 0);
	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	CHECK(preadv(fd, iov, 1, 6) == 5 && memcmp(x, "world", 5) == 0);
	close(fd);
	fd = open(p("v"), O_WRONLY);
	struct iovec w[2] = {{"ab", 2}, {"cd", 2}};
	CHECK(pwritev(fd, w, 2, 1) == 4);
	CHECK(pwrite(fd, "Z", 1, 0) == 1);
	CHECK(fdatasync(fd) == 0 && fsync(fd) == 0);
	close(fd);
	char buf[16] = {0};
	fd = open(p("v"), O_RDONLY);
	CHECK(read(fd, buf, sizeof buf) == 11 && memcmp(buf, "Zabcd world", 11) == 0);
	close(fd);
}

static double since(struct timespec *a) {
	struct timespec b;
	clock_gettime(CLOCK_MONOTONIC, &b);
	return (b.tv_sec - a->tv_sec) + (b.tv_nsec - a->tv_nsec) / 1e9;
}

static void sleeps(void) {
	struct timespec t0, d = {0, 50000000};
	clock_gettime(CLOCK_MONOTONIC, &t0);
	CHECK(nanosleep(&d, NULL) == 0);
	CHECK(since(&t0) >= 0.049);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &d, NULL) == 0);
	CHECK(since(&t0) >= 0.049);
	struct timespec abs;
	clock_gettime(CLOCK_MONOTONIC, &abs);
	t0 = abs;
	abs.tv_nsec += 50000000;
	if (abs.tv_nsec >= 1000000000) abs.tv_sec++, abs.tv_nsec -= 1000000000;
	CHECK(clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &abs, NULL) == 0);
	CHECK(since(&t0) >= 0.049);
	CHECK(usleep(1000) == 0);
}

static void selects(void) {
	int p[2];
	pipe(p);
	fd_set r, w;
	FD_ZERO(&r);
	FD_SET(p[0], &r);
	struct timeval tv = {0, 0};
	CHECK(select(p[0] + 1, &r, NULL, NULL, &tv) == 0 && !FD_ISSET(p[0], &r));
	write(p[1], "x", 1);
	FD_SET(p[0], &r);
	FD_ZERO(&w);
	FD_SET(p[1], &w);
	tv.tv_sec = 1;
	CHECK(select(p[1] + 1, &r, &w, NULL, &tv) == 2 && FD_ISSET(p[0], &r) && FD_ISSET(p[1], &w));
	FD_ZERO(&r);
	FD_SET(p[0], &r);
	struct timespec ts = {1, 0};
	CHECK(pselect(p[0] + 1, &r, NULL, NULL, &ts, NULL) == 1 && FD_ISSET(p[0], &r));
	struct timespec t0;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	tv.tv_sec = 0, tv.tv_usec = 50000;
	CHECK(select(0, NULL, NULL, NULL, &tv) == 0 && since(&t0) >= 0.049);
	close(p[1]);
	FD_ZERO(&r);
	FD_SET(p[1], &r);
	CHECK(select(p[1] + 1, &r, NULL, NULL, &tv) == -1 && errno == EBADF);
	close(p[0]);
}

static void session(void) {
	pid_t c = fork();
	if (c == 0) {
		pid_t s = setsid();
		_exit(s == getpid() && getsid(0) == getpid() && getpgrp() == getpid() && setsid() < 0 ? 0 : 1);
	}
	int ws;
	CHECK(waitpid(c, &ws, 0) == c && WIFEXITED(ws) && WEXITSTATUS(ws) == 0);
	CHECK(getsid(0) > 0);
}

static void misc(void) {
#ifdef SYS_time
	time_t t = 0;
	CHECK(syscall(SYS_time, &t) > 1600000000 && t > 1600000000);
#endif
	struct sysinfo si;
	CHECK(sysinfo(&si) == 0 && si.totalram > 0 && si.mem_unit > 0 && si.procs > 0);
	gid_t gs[256];
	CHECK(getgroups(256, gs) >= 0);
	CHECK(getgroups(0, NULL) >= 0);
	CHECK(syscall(SYS_membarrier, 0, 0, 0) >= 0);
	struct itimerval it = {{0, 0}, {10, 0}}, old;
	CHECK(setitimer(ITIMER_REAL, &it, NULL) == 0);
	CHECK(getitimer(ITIMER_REAL, &old) == 0 && old.it_value.tv_sec >= 9);
	memset(&it, 0, sizeof it);
	CHECK(setitimer(ITIMER_REAL, &it, NULL) == 0);
}

static void copies(void) {
	writeFile(p("src"), "0123456789");
	int in = open(p("src"), O_RDONLY), out = open(p("dst"), O_WRONLY | O_CREAT | O_TRUNC, 0644);
	off_t off = 2;
	CHECK(sendfile(out, in, &off, 5) == 5 && off == 7);
	CHECK(sendfile(out, in, NULL, 3) == 3);
	close(out);
	char buf[16] = {0};
	int r = open(p("dst"), O_RDONLY);
	CHECK(read(r, buf, sizeof buf) == 8 && memcmp(buf, "23456012", 8) == 0);
	close(r);
	out = open(p("cfr"), O_WRONLY | O_CREAT | O_TRUNC, 0644);
	loff_t io = 0;
	CHECK(copy_file_range(in, &io, out, NULL, 10, 0) == 10);
	close(out);
	int pf[2];
	pipe(pf);
	lseek(in, 0, SEEK_SET);
	CHECK(splice(in, NULL, pf[1], NULL, 4, 0) == 4);
	memset(buf, 0, sizeof buf);
	CHECK(read(pf[0], buf, 4) == 4 && memcmp(buf, "0123", 4) == 0);
	close(pf[0]);
	close(pf[1]);
	close(in);
}

static void memory(void) {
	char *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	m[0] = 'q';
	char *n = mremap(m, 4096, 8 * 4096, MREMAP_MAYMOVE);
	CHECK(n != MAP_FAILED && n[0] == 'q');
	if (n != MAP_FAILED) {
		n[8 * 4096 - 1] = 1;
		munmap(n, 8 * 4096);
	}

	int fd = open(p("shm"), O_RDWR | O_CREAT | O_TRUNC, 0600);
	CHECK(ftruncate(fd, 4096) == 0);
	char *s = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(s != MAP_FAILED);
	if (s == MAP_FAILED) return;
	memcpy(s, "shared", 6);
	char buf[8] = {0};
	CHECK(pread(fd, buf, 6, 0) == 6 && memcmp(buf, "shared", 6) == 0);
	pid_t c = fork();
	if (c == 0) {
		memcpy(s, "child!", 6);
		_exit(0);
	}
	waitpid(c, 0, 0);
	CHECK(memcmp(s, "child!", 6) == 0);
	CHECK(msync(s, 4096, MS_SYNC) == 0);
	munmap(s, 4096);
	close(fd);

	// A process-shared semaphore in shared anonymous memory: the post
	// comes from another process.
	sem_t *sem = mmap(0, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	CHECK(sem != MAP_FAILED && sem_init(sem, 1, 0) == 0);
	c = fork();
	if (c == 0) {
		usleep(50000);
		sem_post(sem);
		_exit(0);
	}
	struct timespec dl;
	clock_gettime(CLOCK_REALTIME, &dl);
	dl.tv_sec += 5;
	CHECK(sem_timedwait(sem, &dl) == 0);
	waitpid(c, 0, 0);
}

static void fdctl(void) {
	int pf[2];
	pipe(pf);
	int on = 1;
	CHECK(ioctl(pf[0], FIONBIO, &on) == 0);
	char c;
	CHECK(read(pf[0], &c, 1) < 0 && errno == EAGAIN);
	CHECK((fcntl(pf[0], F_GETFL) & O_NONBLOCK) != 0);
	CHECK(ioctl(pf[0], FIOCLEX) == 0 && (fcntl(pf[0], F_GETFD) & FD_CLOEXEC));
	CHECK(ioctl(pf[0], FIONCLEX) == 0 && !(fcntl(pf[0], F_GETFD) & FD_CLOEXEC));
	write(pf[1], "ab", 2);
	int n = 0;
	CHECK(ioctl(pf[0], FIONREAD, &n) == 0 && n == 2);
	int hi = dup2(pf[0], 40);
	CHECK(hi == 40);
	CHECK(syscall(SYS_close_range, 40, ~0U, 0) == 0);
	CHECK(fcntl(40, F_GETFD) < 0 && errno == EBADF);
	CHECK(syscall(SYS_close_range, pf[0], pf[0], 4 /* CLOSE_RANGE_CLOEXEC */) == 0);
	CHECK(fcntl(pf[0], F_GETFD) & FD_CLOEXEC);
	close(pf[0]);
	close(pf[1]);
	CHECK(close(-1) < 0 && errno == EBADF);

	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) == 0);
	CHECK(recv(sv[0], &c, 1, 0) < 0 && errno == EAGAIN);
	on = 0;
	CHECK(ioctl(sv[0], FIONBIO, &on) == 0 && fcntl(sv[1], F_SETFL, O_NONBLOCK) == 0);
	char big[4096] = {0};
	long sent = 0;
	for (int i = 0; i < 10000; i++) {
		ssize_t k = send(sv[1], big, sizeof big, 0);
		if (k < 0) break;
		sent += k;
	}
	CHECK(errno == EAGAIN && sent > 0);
	CHECK(write(sv[1], big, sizeof big) < 0 && errno == EAGAIN);
	CHECK(read(sv[0], big, sizeof big) == sizeof big);
	close(sv[0]);
	close(sv[1]);
}

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);
	snprintf(dir, sizeof dir, "/tmp/fsops.%d", getpid());
	mkdir(dir, 0755);
	excl();
	modes();
	owners();
	times_();
	links();
	nodes();
	locks();
	vectors();
	sleeps();
	selects();
	session();
	misc();
	copies();
	memory();
	fdctl();
	printf("done fails=%d\n", fails);
	return 0;
}
