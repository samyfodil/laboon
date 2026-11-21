// File-offset and append semantics of open regular files: separate and shared
// descriptions, O_APPEND (open, F_SETFL, pwrite), files unlinked or replaced
// while open, vectored I/O, /proc fdinfo, SEEK_CUR locks, stdio redirection, and
// (when /lowerfile exists) a lower-layer file copied up by an append. Each failed
// check prints a FAIL line; the last line is "done fails=N". argv[1] overrides the
// working directory.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;

#define CHECK(c)                                                                  \
	do {                                                                          \
		if (!(c)) {                                                               \
			printf("FAIL %s:%d %s (errno %d)\n", __func__, __LINE__, #c, errno); \
			fails++;                                                              \
		}                                                                         \
	} while (0)

static char dir[128];

static char *p(const char *name) {
	static char buf[4][192];
	static int i;
	char *b = buf[i++ % 4];
	snprintf(b, 192, "%s/%s", dir, name);
	return b;
}

static int body(const char *path, char *out, int max) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	int n = read(fd, out, max - 1);
	close(fd);
	if (n >= 0) out[n] = 0;
	return n;
}

static void put(const char *path, const char *s) {
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0 && write(fd, s, strlen(s)) == (ssize_t)strlen(s));
	close(fd);
}

// Two descriptions of one file, both O_APPEND: every write lands at the real end.
static void append_two_opens(void) {
	char b[64];
	put(p("ap2"), "");
	int a = open(p("ap2"), O_WRONLY | O_APPEND);
	int c = open(p("ap2"), O_WRONLY | O_APPEND);
	CHECK(a >= 0 && c >= 0);
	CHECK(write(a, "a1", 2) == 2);
	CHECK(write(c, "c1", 2) == 2);
	CHECK(write(a, "a2", 2) == 2);
	CHECK(write(c, "c2", 2) == 2);
	CHECK(lseek(a, 0, SEEK_CUR) == 6 && lseek(c, 0, SEEK_CUR) == 8);
	close(a);
	close(c);
	CHECK(body(p("ap2"), b, sizeof b) == 8 && strcmp(b, "a1c1a2c2") == 0);
}

// A plain description overwrites at its own offset; an O_APPEND one still
// appends past whatever the other wrote.
static void append_vs_plain(void) {
	char b[64];
	put(p("apm"), "0123");
	int w = open(p("apm"), O_RDWR);
	int ap = open(p("apm"), O_WRONLY | O_APPEND);
	CHECK(write(w, "XY", 2) == 2);
	CHECK(write(ap, "zz", 2) == 2);
	CHECK(lseek(w, 0, SEEK_CUR) == 2);
	CHECK(write(w, "Q", 1) == 1);
	close(w);
	close(ap);
	CHECK(body(p("apm"), b, sizeof b) == 6 && strcmp(b, "XYQ3zz") == 0);
}

// F_SETFL toggles O_APPEND on a live description; pwrite on an O_APPEND fd
// appends regardless of its offset argument, as on Linux.
static void setfl_append(void) {
	char b[64];
	int fd = open(p("sfl"), O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(write(fd, "abc", 3) == 3);
	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	CHECK(fcntl(fd, F_SETFL, O_APPEND) == 0 && (fcntl(fd, F_GETFL) & O_APPEND));
	CHECK(write(fd, "d", 1) == 1);
	CHECK(lseek(fd, 0, SEEK_CUR) == 4);
	CHECK(pwrite(fd, "e", 1, 0) == 1);
	CHECK(fcntl(fd, F_SETFL, 0) == 0 && !(fcntl(fd, F_GETFL) & O_APPEND));
	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	CHECK(write(fd, "Z", 1) == 1);
	CHECK(pwrite(fd, "Y", 1, 1) == 1);
	close(fd);
	CHECK(body(p("sfl"), b, sizeof b) == 5 && strcmp(b, "ZYcde") == 0);
}

// An unlinked file keeps its content, size and offset through its fd.
static void unlinked_open(void) {
	char b[64];
	int fd = open(p("unl"), O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(write(fd, "hello", 5) == 5);
	CHECK(unlink(p("unl")) == 0);
	struct stat st;
	CHECK(fstat(fd, &st) == 0 && st.st_size == 5);
	CHECK(lseek(fd, 0, SEEK_END) == 5);
	CHECK(write(fd, "!!", 2) == 2);
	CHECK(fstat(fd, &st) == 0 && st.st_size == 7);
	memset(b, 0, sizeof b);
	CHECK(pread(fd, b, sizeof b, 0) == 7 && strcmp(b, "hello!!") == 0);
	int ap = fcntl(fd, F_DUPFD, 0);
	CHECK(fcntl(ap, F_SETFL, O_APPEND) == 0 && write(ap, "?", 1) == 1);
	CHECK(fstat(fd, &st) == 0 && st.st_size == 8);
	close(ap);
	close(fd);
}

// A name replaced by rename while the old file is open: the fd still sees the
// old object's size, identity and bytes.
static void replaced_open(void) {
	char b[64];
	put(p("old"), "oldbody");
	put(p("new"), "nb");
	int fd = open(p("old"), O_RDWR);
	struct stat before, after;
	CHECK(fstat(fd, &before) == 0);
	CHECK(rename(p("new"), p("old")) == 0);
	CHECK(fstat(fd, &after) == 0 && after.st_ino == before.st_ino && after.st_size == 7);
	CHECK(lseek(fd, 0, SEEK_END) == 7);
	CHECK(write(fd, "+", 1) == 1);
	memset(b, 0, sizeof b);
	CHECK(pread(fd, b, sizeof b, 0) == 8 && strcmp(b, "oldbody+") == 0);
	CHECK(body(p("old"), b, sizeof b) == 2 && strcmp(b, "nb") == 0);
	close(fd);
}

// readv/writev advance the offset by the bytes moved.
static void vectors(void) {
	char x[3], y[4], z[2];
	int fd = open(p("vec"), O_RDWR | O_CREAT | O_TRUNC, 0644);
	struct iovec w[3] = {{"abc", 3}, {"defg", 4}, {"hi", 2}};
	CHECK(writev(fd, w, 3) == 9 && lseek(fd, 0, SEEK_CUR) == 9);
	CHECK(lseek(fd, 1, SEEK_SET) == 1);
	struct iovec r[3] = {{x, 3}, {y, 4}, {z, 2}};
	CHECK(readv(fd, r, 3) == 8 && lseek(fd, 0, SEEK_CUR) == 9);
	CHECK(memcmp(x, "bcd", 3) == 0 && memcmp(y, "efgh", 4) == 0 && z[0] == 'i');
	CHECK(readv(fd, r, 3) == 0);
	close(fd);
}

// dup and fork share one description's offset.
static void shared_offset(void) {
	int fd = open(p("shr"), O_RDWR | O_CREAT | O_TRUNC, 0644);
	int d = dup(fd);
	CHECK(write(fd, "1234", 4) == 4 && lseek(d, 0, SEEK_CUR) == 4);
	pid_t c = fork();
	if (c == 0) {
		_exit(write(d, "56", 2) == 2 ? 0 : 1);
	}
	int s;
	CHECK(waitpid(c, &s, 0) == c && WIFEXITED(s) && WEXITSTATUS(s) == 0);
	CHECK(lseek(fd, 0, SEEK_CUR) == 6);
	close(d);
	close(fd);
}

// Appends from two processes, through one shared description and through each
// process's own, lose nothing.
static void append_procs(void) {
	struct stat st;
	int shared = open(p("apf"), O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
	CHECK(shared >= 0);
	pid_t c = fork();
	if (c == 0) {
		int own = open(p("apf"), O_WRONLY | O_APPEND);
		for (int i = 0; i < 200; i++) {
			if (write(i & 1 ? own : shared, "c", 1) != 1) _exit(1);
		}
		_exit(0);
	}
	int own = open(p("apf"), O_WRONLY | O_APPEND);
	CHECK(own >= 0);
	for (int i = 0; i < 200; i++) {
		CHECK(write(i & 1 ? own : shared, "p", 1) == 1);
	}
	int s;
	CHECK(waitpid(c, &s, 0) == c && WIFEXITED(s) && WEXITSTATUS(s) == 0);
	CHECK(stat(p("apf"), &st) == 0 && st.st_size == 400);
	close(own);
	close(shared);
}

// /proc/self/fdinfo reports the description's offset.
static void fdinfo(void) {
	int fd = open(p("fdi"), O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(write(fd, "0123456789", 10) == 10 && lseek(fd, 7, SEEK_SET) == 7);
	char path[64], b[512];
	snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fd);
	CHECK(body(path, b, sizeof b) > 0 && strstr(b, "pos:\t7\n") != NULL);
	close(fd);
}

// A SEEK_CUR lock is placed relative to the description's offset.
static void seekcur_lock(void) {
	int fd = open(p("lck"), O_RDWR | O_CREAT | O_TRUNC, 0644);
	int other = open(p("lck"), O_RDWR);
	CHECK(ftruncate(fd, 64) == 0 && lseek(fd, 10, SEEK_SET) == 10);
	struct flock l = {.l_type = F_WRLCK, .l_whence = SEEK_CUR, .l_start = 0, .l_len = 5};
	CHECK(fcntl(fd, F_OFD_SETLK, &l) == 0);
	struct flock q = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 64};
	CHECK(fcntl(other, F_OFD_GETLK, &q) == 0 && q.l_type == F_WRLCK && q.l_start == 10 && q.l_len == 5);
	close(other);
	close(fd);
}

// A file the guest opens and dup2s onto stdout takes writes at its offset.
static void dup2_stdout(void) {
	char b[64];
	int saved = dup(1);
	int fd = open(p("so"), O_WRONLY | O_CREAT | O_TRUNC, 0644);
	CHECK(write(fd, "pre-", 4) == 4);
	CHECK(dup2(fd, 1) == 1);
	CHECK(write(1, "out", 3) == 3);
	fflush(stdout);
	CHECK(dup2(saved, 1) == 1);
	CHECK(lseek(fd, 0, SEEK_CUR) == 7);
	close(fd);
	close(saved);
	CHECK(body(p("so"), b, sizeof b) == 7 && strcmp(b, "pre-out") == 0);
}

// A lower-layer file read through one fd and appended through another: the
// append copies it up and lands after the lower content.
static void lower_append(void) {
	char b[64];
	if (access("/lowerfile", F_OK) != 0) return;
	int r = open("/lowerfile", O_RDONLY);
	CHECK(r >= 0 && read(r, b, 2) == 2 && lseek(r, 0, SEEK_CUR) == 2);
	int w = open("/lowerfile", O_WRONLY | O_APPEND);
	CHECK(w >= 0 && write(w, "+", 1) == 1 && lseek(w, 0, SEEK_CUR) == 6);
	close(w);
	close(r);
	CHECK(body("/lowerfile", b, sizeof b) == 6 && strcmp(b, "lower+") == 0);
}

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc > 1) {
		snprintf(dir, sizeof dir, "%s", argv[1]);
	} else {
		snprintf(dir, sizeof dir, "/tmp/fileoffset.%d", getpid());
	}
	mkdir(dir, 0755);
	append_two_opens();
	append_vs_plain();
	setfl_append();
	unlinked_open();
	replaced_open();
	vectors();
	shared_offset();
	append_procs();
	fdinfo();
	seekcur_lock();
	dup2_stdout();
	lower_append();
	printf("done fails=%d\n", fails);
	return 0;
}
