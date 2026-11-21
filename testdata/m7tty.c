// libc: musl
// M7 terminal tests, driven through guest ptys the way script(1) and expect
// drive a terminal: a pty pair and its line discipline, a termios round trip,
// isatty/ttyname/TIOCGWINSZ and SIGWINCH, background reads and writes
// (SIGTTIN, SIGTTOU), waitpid WUNTRACED/WCONTINUED, an interactive busybox sh
// with line editing and job control, and vi and less. One case per argv[1];
// each prints "<case> OK" on success. Every case also passes natively on
// Linux.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...)                                                          \
	do {                                                                   \
		if (!(c)) {                                                    \
			printf("FAIL %s:%d: %s: ", __FILE__, __LINE__, #c);   \
			printf(__VA_ARGS__);                                   \
			printf(" (errno %d)\n", errno);                        \
			fflush(stdout);                                        \
			fails++;                                               \
		}                                                              \
	} while (0)
#define MUST(c)                                                                \
	do {                                                                   \
		if (!(c)) {                                                    \
			printf("FAIL %s:%d: %s (errno %d)\n", __FILE__, __LINE__, #c, errno); \
			exit(1);                                               \
		}                                                              \
	} while (0)

static char *self;

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void msleep(int ms)
{
	struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
	while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
		;
}

static int readall(int fd, char *buf, int n, int ms)
{
	int got = 0;
	while (got < n) {
		struct pollfd p = {fd, POLLIN, 0};
		if (poll(&p, 1, ms) <= 0)
			break;
		int r = read(fd, buf + got, n - got);
		if (r <= 0)
			break;
		got += r;
	}
	buf[got] = 0;
	return got;
}

// ---- a pty session: the driver side of script/expect --------------------------

struct sess {
	int m;
	pid_t pid;
	char buf[1 << 16];
	int len, mark; // output collected; the search starts at mark
	int eof;
};

// spawn runs argv on a new pty as a session leader with the slave as its
// controlling terminal and stdio, as login_tty does.
static void spawn(struct sess *s, int rows, int cols, char **argv, char **envp)
{
	memset(s, 0, sizeof *s);
	s->m = posix_openpt(O_RDWR | O_NOCTTY);
	MUST(s->m >= 0);
	MUST(grantpt(s->m) == 0 && unlockpt(s->m) == 0);
	struct winsize ws = {.ws_row = rows, .ws_col = cols};
	MUST(ioctl(s->m, TIOCSWINSZ, &ws) == 0);
	char *name = ptsname(s->m);
	MUST(name);
	char slave[64];
	snprintf(slave, sizeof slave, "%s", name);
	s->pid = fork();
	MUST(s->pid >= 0);
	if (s->pid == 0) {
		close(s->m);
		MUST(setsid() == getpid());
		int fd = open(slave, O_RDWR);
		MUST(fd >= 0);
		MUST(ioctl(fd, TIOCSCTTY, 0) == 0);
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		if (fd > 2)
			close(fd);
		execve(argv[0], argv, envp);
		printf("exec %s: %s\n", argv[0], strerror(errno));
		_exit(127);
	}
}

static void pump(struct sess *s, int ms)
{
	struct pollfd p = {s->m, POLLIN, 0};
	if (s->eof || poll(&p, 1, ms) <= 0)
		return;
	if (s->len >= (int)sizeof s->buf - 1) {
		int drop = s->mark;
		memmove(s->buf, s->buf + drop, s->len - drop);
		s->len -= drop;
		s->mark = 0;
	}
	int r = read(s->m, s->buf + s->len, sizeof s->buf - 1 - s->len);
	if (r <= 0) {
		s->eof = 1;
		return;
	}
	s->len += r;
	s->buf[s->len] = 0;
}

static void dump(struct sess *s)
{
	printf("--- transcript (from mark) ---\n");
	for (char *c = s->buf + s->mark; c < s->buf + s->len; c++) {
		if (*c == '\r')
			printf("\\r");
		else if (*c == '\n')
			printf("\\n\n");
		else if ((unsigned char)*c < 0x20 || *c == 0x7f)
			printf("\\x%02x", (unsigned char)*c);
		else
			putchar(*c);
	}
	printf("\n--- end ---\n");
}

// expect waits until want shows up in the output after the mark, then moves
// the mark past it.
static int expect(struct sess *s, const char *want, int ms)
{
	double end = now_ms() + ms;
	for (;;) {
		char *hit = memmem(s->buf + s->mark, s->len - s->mark, want, strlen(want));
		if (hit) {
			s->mark = hit - s->buf + strlen(want);
			return 1;
		}
		double left = end - now_ms();
		if (left <= 0 || s->eof) {
			printf("FAIL: expected %s\n", want);
			dump(s);
			fails++;
			return 0;
		}
		pump(s, left > 100 ? 100 : (int)left + 1);
	}
}

static void send(struct sess *s, const char *str)
{
	MUST(write(s->m, str, strlen(str)) == (ssize_t)strlen(str));
}

// finish reads to end of output (EIO once the slave side is all closed) and
// reaps the child.
static int finish(struct sess *s, int ms)
{
	double end = now_ms() + ms;
	while (!s->eof && now_ms() < end)
		pump(s, 100);
	int st;
	for (;;) {
		pid_t r = waitpid(s->pid, &st, WNOHANG);
		if (r == s->pid)
			break;
		if (now_ms() > end) {
			printf("FAIL: child still running\n");
			dump(s);
			kill(s->pid, SIGKILL);
			waitpid(s->pid, &st, 0);
			fails++;
			break;
		}
		msleep(20);
	}
	close(s->m);
	return st;
}

static char *env_sh[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "TERM=vt100", "PS1=P1> ", 0};

// ---- cases ----------------------------------------------------------------------

// A pty pair with the line discipline between: canonical input, echo, ONLCR,
// raw mode, the ptmx ioctls, the slave's stat, window size across the pair,
// epoll and FIONREAD, nonblocking reads, TIOCGPTPEER and hangup.
static int t_pty(void)
{
	int m = posix_openpt(O_RDWR | O_NOCTTY);
	MUST(m >= 0);
	CHECK(isatty(m), "master isatty");
	int n = -1;
	CHECK(ioctl(m, TIOCGPTN, &n) == 0 && n >= 0, "TIOCGPTN");
	char name[64];
	snprintf(name, sizeof name, "/dev/pts/%d", n);
	int lk = -1;
	CHECK(ioctl(m, TIOCGPTLCK, &lk) == 0 && lk == 1, "locked at open: %d", lk);
	CHECK(open(name, O_RDWR | O_NOCTTY) < 0 && errno == EIO, "open of a locked slave");
	CHECK(grantpt(m) == 0 && unlockpt(m) == 0, "grantpt/unlockpt");
	CHECK(strcmp(ptsname(m), name) == 0, "ptsname %s vs %s", ptsname(m), name);
	int s = open(name, O_RDWR | O_NOCTTY);
	MUST(s >= 0);
	CHECK(isatty(s), "slave isatty");
	struct stat st, fst;
	CHECK(stat(name, &st) == 0 && S_ISCHR(st.st_mode) && major(st.st_rdev) == 136 && minor(st.st_rdev) == (unsigned)n,
	      "stat %s mode %o rdev %d,%d", name, st.st_mode, major(st.st_rdev), minor(st.st_rdev));
	CHECK(fstat(s, &fst) == 0 && fst.st_ino == st.st_ino && fst.st_dev == st.st_dev, "fstat matches stat");
	CHECK(stat("/dev/ptmx", &st) == 0 && S_ISCHR(st.st_mode) && major(st.st_rdev) == 5 && minor(st.st_rdev) == 2,
	      "/dev/ptmx rdev %d,%d", major(st.st_rdev), minor(st.st_rdev));

	struct termios t;
	CHECK(tcgetattr(s, &t) == 0, "tcgetattr slave");
	CHECK((t.c_lflag & (ICANON | ECHO | ISIG)) == (ICANON | ECHO | ISIG) && (t.c_oflag & ONLCR) && (t.c_iflag & ICRNL),
	      "default termios i%o o%o l%o", t.c_iflag, t.c_oflag, t.c_lflag);
	CHECK(write(m, "hello\n", 6) == 6, "write master");
	char buf[256];
	int r = read(s, buf, sizeof buf);
	CHECK(r == 6 && memcmp(buf, "hello\n", 6) == 0, "slave read %d", r);
	r = readall(m, buf, 7, 500);
	CHECK(r == 7 && memcmp(buf, "hello\r\n", 7) == 0, "master echo %d [%s]", r, buf);

	// Line editing in the discipline: erase and kill.
	write(m, "abX\177c\r", 6);
	r = read(s, buf, sizeof buf);
	CHECK(r == 4 && memcmp(buf, "abc\n", 4) == 0, "erase %d", r);
	readall(m, buf, sizeof buf - 1, 100);
	write(m, "zzz\025ok\r", 7);
	r = read(s, buf, sizeof buf);
	CHECK(r == 3 && memcmp(buf, "ok\n", 3) == 0, "kill %d", r);
	readall(m, buf, sizeof buf - 1, 100);
	// VEOF: a line without newline, then end of file.
	write(m, "ab\004\004", 4);
	r = read(s, buf, sizeof buf);
	CHECK(r == 2 && memcmp(buf, "ab", 2) == 0, "eof line %d", r);
	r = read(s, buf, sizeof buf);
	CHECK(r == 0, "eof %d", r);
	readall(m, buf, sizeof buf - 1, 100);

	CHECK(write(s, "out\n", 4) == 4, "write slave");
	r = readall(m, buf, 5, 500);
	CHECK(r == 5 && memcmp(buf, "out\r\n", 5) == 0, "master read %d [%s]", r, buf);

	cfmakeraw(&t);
	CHECK(tcsetattr(s, TCSANOW, &t) == 0, "raw");
	write(m, "x\ry", 3);
	r = readall(s, buf, 3, 500);
	CHECK(r == 3 && memcmp(buf, "x\ry", 3) == 0, "raw read %d", r);
	CHECK(readall(m, buf, 1, 100) == 0, "raw has no echo");

	struct winsize ws = {.ws_row = 24, .ws_col = 80}, wr = {0};
	CHECK(ioctl(m, TIOCSWINSZ, &ws) == 0 && ioctl(s, TIOCGWINSZ, &wr) == 0 && wr.ws_row == 24 && wr.ws_col == 80,
	      "winsize %dx%d", wr.ws_row, wr.ws_col);

	int ep = epoll_create1(0);
	struct epoll_event ev = {.events = EPOLLIN, .data.u32 = 7}, out;
	CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, m, &ev) == 0, "epoll_ctl master");
	CHECK(epoll_wait(ep, &out, 1, 50) == 0, "master idle");
	write(s, "abc", 3);
	CHECK(epoll_wait(ep, &out, 1, 1000) == 1 && out.data.u32 == 7, "master readable");
	readall(m, buf, 3, 200);
	write(m, "pq", 2);
	msleep(50);
	int q = -1;
	CHECK(ioctl(s, FIONREAD, &q) == 0 && q == 2, "FIONREAD %d", q);
	readall(s, buf, 2, 200);

	fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
	CHECK(read(s, buf, 1) < 0 && errno == EAGAIN, "nonblocking slave read");

	int s2 = ioctl(m, TIOCGPTPEER, O_RDWR | O_NOCTTY);
	CHECK(s2 >= 0 && isatty(s2), "TIOCGPTPEER");
	CHECK(ioctl(s, TIOCGPTN, &n) < 0 && errno == ENOTTY, "TIOCGPTN on slave");

	close(s);
	close(s2);
	struct pollfd pf = {m, POLLIN, 0};
	CHECK(poll(&pf, 1, 1000) == 1 && (pf.revents & POLLHUP), "master POLLHUP %#x", pf.revents);
	r = read(m, buf, 1);
	CHECK(r < 0 && errno == EIO, "master after hangup %d", r);
	close(m);
	int p[2];
	pipe(p);
	CHECK(!isatty(p[0]) && errno == ENOTTY, "pipe isatty");
	return fails == 0;
}

// termtest: every termios bit flipped and read back, c_cc, speeds, termios2,
// window size, FIONREAD, drain/flush/flow, the process group ids. Runs under
// a pty as its controlling terminal (see t_termios).
struct termios2x {
	tcflag_t c_iflag, c_oflag, c_cflag, c_lflag;
	cc_t c_line, c_cc[19];
	speed_t c_ispeed, c_ospeed;
};
#define TCGETS2X _IOR('T', 0x2A, struct termios2x)
#define TCSETS2X _IOW('T', 0x2B, struct termios2x)
#define BOTHERX 010000

static void flip(const char *name, tcflag_t *w, tcflag_t bit, struct termios *base)
{
	struct termios t = *base, r;
	tcflag_t *tw = (tcflag_t *)((char *)&t + ((char *)w - (char *)base));
	*tw ^= bit;
	if (tcsetattr(0, TCSANOW, &t)) {
		printf("%s %#o: set errno %d\n", name, bit, errno);
		fails++;
		return;
	}
	tcgetattr(0, &r);
	tcflag_t got = *(tcflag_t *)((char *)&r + ((char *)w - (char *)base));
	if ((got & bit) != (*tw & bit))
		printf("%s %#o: did not stick\n", name, bit), fails++;
	tcsetattr(0, TCSANOW, base);
}

static int termtest(void)
{
	struct termios o, t;
	if (!isatty(0) || !isatty(1)) {
		printf("not a tty\n");
		return 0;
	}
	if (tcgetattr(0, &o)) {
		printf("tcgetattr errno %d\n", errno);
		return 0;
	}
	tcflag_t ibits[] = {IGNBRK, BRKINT, IGNPAR, PARMRK, INPCK, ISTRIP, INLCR, IGNCR, ICRNL, IXON, IXANY, IXOFF, IMAXBEL, IUTF8};
	tcflag_t obits[] = {OPOST, ONLCR, OCRNL, ONOCR, ONLRET, OFILL, OFDEL, NL1, CR1, CR2, CR3, TAB1, TAB2, TAB3, BS1, VT1, FF1};
	tcflag_t cbits[] = {CSTOPB, PARODD, HUPCL, CLOCAL};
	tcflag_t lbits[] = {ISIG, ICANON, ECHO, ECHOE, ECHOK, ECHONL, NOFLSH, TOSTOP, ECHOCTL, ECHOPRT, ECHOKE, IEXTEN};
	for (unsigned i = 0; i < sizeof ibits / sizeof *ibits; i++)
		flip("iflag", &o.c_iflag, ibits[i], &o);
	for (unsigned i = 0; i < sizeof obits / sizeof *obits; i++) {
		tcflag_t b = obits[i];
		struct termios x = o, r;
		tcflag_t mask = (b & CRDLY) ? CRDLY : (b & TABDLY) ? TABDLY : b;
		x.c_oflag = (x.c_oflag & ~mask) | b;
		tcsetattr(0, TCSANOW, &x);
		tcgetattr(0, &r);
		if ((r.c_oflag & mask) != b)
			printf("oflag %#o: got %#o\n", b, r.c_oflag & mask), fails++;
	}
	tcsetattr(0, TCSANOW, &o);
	for (unsigned i = 0; i < sizeof cbits / sizeof *cbits; i++) {
		struct termios x = o, r;
		tcflag_t mask = (cbits[i] & CSIZE) ? CSIZE : cbits[i];
		x.c_cflag = (x.c_cflag & ~mask) | (cbits[i] ^ (o.c_cflag & mask & ~CSIZE));
		if (mask == CSIZE)
			x.c_cflag = (x.c_cflag & ~CSIZE) | cbits[i];
		tcsetattr(0, TCSANOW, &x);
		tcgetattr(0, &r);
		if ((r.c_cflag & mask) != (x.c_cflag & mask))
			printf("cflag %#o: got %#o\n", cbits[i], r.c_cflag & mask), fails++;
	}
	tcsetattr(0, TCSANOW, &o);
	// A Linux pty forces CS8 and CREAD and refuses PARENB.
	t = o;
	t.c_cflag = (t.c_cflag & ~(CSIZE | CREAD)) | CS7 | PARENB;
	tcsetattr(0, TCSANOW, &t);
	tcgetattr(0, &t);
	if ((t.c_cflag & (CSIZE | CREAD | PARENB)) != (CS8 | CREAD))
		printf("pty cflag: got %#o\n", t.c_cflag & (CSIZE | CREAD | PARENB)), fails++;
	tcsetattr(0, TCSANOW, &o);
	for (unsigned i = 0; i < sizeof lbits / sizeof *lbits; i++)
		flip("lflag", &o.c_lflag, lbits[i], &o);
	int ccs[] = {VINTR, VQUIT, VERASE, VKILL, VEOF, VTIME, VMIN, VSTART, VSTOP, VSUSP, VEOL, VREPRINT, VDISCARD, VWERASE, VLNEXT, VEOL2};
	for (unsigned i = 0; i < sizeof ccs / sizeof *ccs; i++) {
		struct termios x = o, r;
		x.c_cc[ccs[i]] = 7 + i;
		tcsetattr(0, TCSANOW, &x);
		tcgetattr(0, &r);
		if (r.c_cc[ccs[i]] != 7 + i)
			printf("c_cc[%d]: got %d\n", ccs[i], r.c_cc[ccs[i]]), fails++;
		x.c_cc[ccs[i]] = 0;
		tcsetattr(0, TCSANOW, &x);
		tcgetattr(0, &r);
		if (r.c_cc[ccs[i]] != 0)
			printf("c_cc[%d] disable: got %d\n", ccs[i], r.c_cc[ccs[i]]), fails++;
	}
	tcsetattr(0, TCSANOW, &o);
	t = o;
	cfsetspeed(&t, B38400);
	tcsetattr(0, TCSANOW, &t);
	tcgetattr(0, &t);
	if (cfgetospeed(&t) != B38400)
		printf("speed: got %#o\n", cfgetospeed(&t)), fails++;
	cfsetspeed(&t, B115200);
	tcsetattr(0, TCSANOW, &t);
	tcgetattr(0, &t);
	if (cfgetospeed(&t) != B115200)
		printf("speed 115200: got %#o\n", cfgetospeed(&t)), fails++;
	struct termios2x t2;
	if (ioctl(0, TCGETS2X, &t2))
		printf("TCGETS2 errno %d\n", errno), fails++;
	t2.c_cflag = (t2.c_cflag & ~CBAUD) | BOTHERX;
	t2.c_ispeed = t2.c_ospeed = 31250;
	if (ioctl(0, TCSETS2X, &t2) || ioctl(0, TCGETS2X, &t2) || t2.c_ospeed != 31250 || (t2.c_cflag & CBAUD) != BOTHERX)
		printf("termios2 custom speed: %u cflag %#o errno %d\n", t2.c_ospeed, t2.c_cflag & CBAUD, errno), fails++;
	tcsetattr(0, TCSAFLUSH, &o);
	struct winsize ws = {.ws_row = 33, .ws_col = 99}, wr;
	if (ioctl(1, TIOCSWINSZ, &ws) || ioctl(1, TIOCGWINSZ, &wr) || wr.ws_row != 33 || wr.ws_col != 99)
		printf("winsize: %d x %d\n", wr.ws_row, wr.ws_col), fails++;
	int n = -1;
	if (ioctl(0, FIONREAD, &n) || n != 0)
		printf("FIONREAD %d errno %d\n", n, errno), fails++;
	if (tcdrain(1) || tcflush(0, TCIFLUSH) || tcflow(1, TCOON))
		printf("drain/flush/flow errno %d\n", errno), fails++;
	pid_t pg = tcgetpgrp(0);
	if (pg != getpgrp())
		printf("tcgetpgrp %d errno %d\n", pg, errno), fails++;
	pid_t sid = -1;
	if (ioctl(0, TIOCGSID, &sid) || sid != getsid(0))
		printf("TIOCGSID %d errno %d\n", sid, errno), fails++;
	if (tcsetpgrp(0, pg))
		printf("tcsetpgrp errno %d\n", errno), fails++;
	if (tcsetpgrp(0, 999999) == 0 || errno != ESRCH)
		printf("tcsetpgrp of no group: errno %d\n", errno), fails++;
	printf("termtest: %s (%d)\n", fails ? "FAIL" : "ok", fails);
	return fails == 0;
}

static int t_termios(void)
{
	struct sess s;
	char *argv[] = {self, "termtest", 0};
	spawn(&s, 24, 80, argv, env_sh);
	expect(&s, "termtest: ok", 20000);
	int st = finish(&s, 5000);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "status %#x", st);
	return fails == 0;
}

// ttyinfo runs on a pty: isatty, ttyname, the window size, /dev/tty, the
// session and group ids, and SIGWINCH when the master resizes the pair.
static volatile sig_atomic_t winched;
static void on_winch(int s) { winched = 1; }

static int ttyinfo(void)
{
	char want[64];
	snprintf(want, sizeof want, "/dev/pts/%s", getenv("PTN") ? getenv("PTN") : "?");
	CHECK(isatty(0) && isatty(1) && isatty(2), "isatty");
	char *tn = ttyname(0);
	CHECK(tn && strcmp(tn, want) == 0, "ttyname %s, want %s", tn ? tn : "(null)", want);
	char link[64] = {0};
	readlink("/proc/self/fd/0", link, sizeof link - 1);
	CHECK(strcmp(link, want) == 0, "fd link %s", link);
	struct winsize ws;
	CHECK(ioctl(0, TIOCGWINSZ, &ws) == 0 && ws.ws_row == 30 && ws.ws_col == 100, "winsize %dx%d", ws.ws_row, ws.ws_col);
	int t = open("/dev/tty", O_RDWR);
	CHECK(t >= 0 && isatty(t), "open /dev/tty");
	struct stat st;
	CHECK(fstat(t, &st) == 0 && S_ISCHR(st.st_mode) && major(st.st_rdev) == 5 && minor(st.st_rdev) == 0,
	      "/dev/tty rdev %d,%d", major(st.st_rdev), minor(st.st_rdev));
	CHECK(write(t, "via-dev-tty\n", 12) == 12, "write /dev/tty");
	CHECK(getsid(0) == getpid() && tcgetpgrp(0) == getpgrp(), "sid %d pgrp %d fg %d", getsid(0), getpgrp(), tcgetpgrp(0));
	signal(SIGWINCH, on_winch);
	printf("resize-me\n");
	fflush(stdout);
	for (int i = 0; i < 200 && !winched; i++)
		msleep(25);
	CHECK(winched, "SIGWINCH");
	CHECK(ioctl(0, TIOCGWINSZ, &ws) == 0 && ws.ws_row == 40 && ws.ws_col == 120, "new winsize %dx%d", ws.ws_row, ws.ws_col);
	// A process that is not a session leader cannot take a terminal; a new
	// session has none (/dev/tty is ENXIO).
	pid_t p = fork();
	if (p == 0) {
		setsid();
		int fd = open("/dev/tty", O_RDWR);
		_exit(fd < 0 && errno == ENXIO ? 0 : 1);
	}
	int status;
	waitpid(p, &status, 0);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "new session has no tty");
	printf("ttyinfo: %s\n", fails ? "FAIL" : "done");
	return fails == 0;
}

static int t_tty(void)
{
	struct sess s;
	char *argv[] = {self, "ttyinfo", 0};
	int m = posix_openpt(O_RDWR | O_NOCTTY);
	int n = -1;
	ioctl(m, TIOCGPTN, &n);
	close(m); // the next pty gets the same index
	char ptn[32];
	snprintf(ptn, sizeof ptn, "PTN=%d", n);
	char *envp[] = {ptn, 0};
	spawn(&s, 30, 100, argv, envp);
	expect(&s, "via-dev-tty\r\n", 20000);
	expect(&s, "resize-me", 20000);
	struct winsize ws = {.ws_row = 40, .ws_col = 120};
	CHECK(ioctl(s.m, TIOCSWINSZ, &ws) == 0, "resize");
	expect(&s, "ttyinfo: done", 20000);
	int st = finish(&s, 5000);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "status %#x", st);
	return fails == 0;
}

// jobs runs on a pty as a shell would: a background group's read stops it
// with SIGTTIN, its write with SIGTTOU under TOSTOP; brought to the
// foreground it continues and reads; with SIGTTIN ignored the read is EIO.
static int jobs(void)
{
	signal(SIGTTOU, SIG_IGN); // as a shell does, to tcsetpgrp from the background
	pid_t me = getpgrp();
	int st;

	pid_t c = fork();
	MUST(c >= 0);
	if (c == 0) {
		setpgid(0, 0);
		signal(SIGTTOU, SIG_DFL);
		char b[64];
		int r = read(0, b, sizeof b);
		if (r > 0 && strncmp(b, "data", 4) == 0)
			_exit(7);
		_exit(1);
	}
	setpgid(c, c);
	MUST(waitpid(c, &st, WUNTRACED) == c);
	CHECK(WIFSTOPPED(st) && WSTOPSIG(st) == SIGTTIN, "background read: status %#x", st);
	CHECK(tcsetpgrp(0, c) == 0, "tcsetpgrp child");
	kill(c, SIGCONT);
	MUST(waitpid(c, &st, WCONTINUED) == c);
	CHECK(WIFCONTINUED(st), "continued: status %#x", st);
	printf("send-data\n");
	fflush(stdout);
	MUST(waitpid(c, &st, 0) == c);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 7, "foreground read: status %#x", st);
	CHECK(tcsetpgrp(0, me) == 0, "tcsetpgrp back");

	// TOSTOP: a background write stops with SIGTTOU.
	struct termios t, o;
	tcgetattr(0, &o);
	t = o;
	t.c_lflag |= TOSTOP;
	tcsetattr(0, TCSANOW, &t);
	c = fork();
	if (c == 0) {
		setpgid(0, 0);
		signal(SIGTTOU, SIG_DFL);
		write(1, "bg-write\n", 9);
		_exit(0);
	}
	setpgid(c, c);
	MUST(waitpid(c, &st, WUNTRACED) == c);
	CHECK(WIFSTOPPED(st) && WSTOPSIG(st) == SIGTTOU, "TOSTOP write: status %#x", st);
	kill(c, SIGKILL);
	waitpid(c, &st, 0);
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "killed while stopped: %#x", st);
	tcsetattr(0, TCSANOW, &o);

	// Ignored SIGTTIN: the background read fails with EIO.
	c = fork();
	if (c == 0) {
		setpgid(0, 0);
		signal(SIGTTIN, SIG_IGN);
		char b[8];
		int r = read(0, b, sizeof b);
		_exit(r < 0 && errno == EIO ? 0 : 1);
	}
	setpgid(c, c);
	MUST(waitpid(c, &st, WUNTRACED) == c);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "ignored SIGTTIN: status %#x", st);
	printf("jobs: %s\n", fails ? "FAIL" : "done");
	return fails == 0;
}

static int t_ttin(void)
{
	struct sess s;
	char *argv[] = {self, "jobs", 0};
	spawn(&s, 24, 80, argv, env_sh);
	if (expect(&s, "send-data", 20000))
		send(&s, "data\n");
	expect(&s, "jobs: done", 20000);
	int st = finish(&s, 5000);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "status %#x", st);
	return fails == 0;
}

// waitpid WUNTRACED/WCONTINUED around SIGSTOP, SIGTSTP and SIGCONT; a
// stopped child makes no progress.
static int t_wait(void)
{
	volatile long *ctr = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	MUST(ctr != MAP_FAILED);
	pid_t c = fork();
	MUST(c >= 0);
	if (c == 0) {
		setpgid(0, 0); // a group with a parent outside it: not orphaned, so SIGTSTP stops
		for (;;) {
			(*ctr)++;
			msleep(2);
		}
	}
	setpgid(c, c);
	int st;
	msleep(100);
	CHECK(waitpid(c, &st, WNOHANG | WUNTRACED) == 0, "running child");
	kill(c, SIGSTOP);
	MUST(waitpid(c, &st, WUNTRACED) == c);
	CHECK(WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP, "SIGSTOP status %#x", st);
	CHECK(waitpid(c, &st, WNOHANG | WUNTRACED) == 0, "stop reported once");
	long a = *ctr;
	msleep(300);
	long b = *ctr;
	CHECK(a == b, "stopped child ran: %ld -> %ld", a, b);
	kill(c, SIGCONT);
	MUST(waitpid(c, &st, WCONTINUED) == c);
	CHECK(WIFCONTINUED(st), "SIGCONT status %#x", st);
	msleep(200);
	CHECK(*ctr > b, "continued child does not run");
	kill(c, SIGTSTP);
	MUST(waitpid(c, &st, WUNTRACED) == c);
	CHECK(WIFSTOPPED(st) && WSTOPSIG(st) == SIGTSTP, "SIGTSTP status %#x", st);
	siginfo_t si = {0};
	kill(c, SIGCONT);
	MUST(waitid(P_PID, c, &si, WCONTINUED) == 0);
	CHECK(si.si_code == CLD_CONTINUED && si.si_pid == c, "waitid continued code %d", si.si_code);
	kill(c, SIGTERM);
	MUST(waitpid(c, &st, 0) == c);
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM, "end status %#x", st);
	return fails == 0;
}

// An interactive busybox sh on a pty: prompt, line editing, a command, ^C
// interrupting sleep, ^Z stopping it, jobs/bg/fg, exit.
static int t_sh(void)
{
	struct sess s;
	char *argv[] = {"/bin/sh", "-i", 0};
	spawn(&s, 24, 80, argv, env_sh);
	if (!expect(&s, "P1> ", 20000))
		goto out;
	send(&s, "echo $((6*7))x\r");
	expect(&s, "42x\r\n", 10000);
	expect(&s, "P1> ", 10000);
	send(&s, "echo ab_\177c\r");
	expect(&s, "abc\r\n", 10000);
	expect(&s, "P1> ", 10000);
	send(&s, "echo XY\033[DQ\r");
	expect(&s, "XQY\r\n", 10000);
	expect(&s, "P1> ", 10000);

	send(&s, "sleep 30\r");
	msleep(1500);
	send(&s, "\003");
	expect(&s, "P1> ", 10000);
	send(&s, "echo rc=$?\r");
	expect(&s, "rc=130", 10000);
	expect(&s, "P1> ", 10000);

	send(&s, "sleep 30\r");
	msleep(1500);
	send(&s, "\032");
	expect(&s, "Stopped", 10000);
	expect(&s, "P1> ", 10000);
	send(&s, "jobs\r");
	expect(&s, "sleep 30", 10000);
	expect(&s, "P1> ", 10000);
	send(&s, "bg\r");
	expect(&s, "P1> ", 10000);
	send(&s, "jobs\r");
	expect(&s, "Running", 10000);
	expect(&s, "P1> ", 10000);
	send(&s, "fg\r");
	expect(&s, "sleep 30", 10000);
	msleep(500);
	send(&s, "\003");
	expect(&s, "P1> ", 10000);
	send(&s, "echo rc2=$?\r");
	expect(&s, "rc2=130", 10000);
	expect(&s, "P1> ", 10000);
	send(&s, "exit\r");
out:;
	int st = finish(&s, 10000);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "sh status %#x", st);
	return fails == 0;
}

// vi edits a file through the pty; less pages one and quits.
static int t_vi(void)
{
	struct sess s;
	unlink("/tmp/m7vi.txt");
	char *argv[] = {"/usr/bin/vi", "/tmp/m7vi.txt", 0};
	spawn(&s, 24, 80, argv, env_sh);
	expect(&s, "~", 20000);
	msleep(300);
	send(&s, "ihello from vi");
	expect(&s, "hello from vi", 10000);
	send(&s, "\033");
	msleep(500);
	send(&s, ":wq\r");
	int st = finish(&s, 15000);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "vi status %#x", st);
	char buf[64] = {0};
	int fd = open("/tmp/m7vi.txt", O_RDONLY);
	CHECK(fd >= 0 && read(fd, buf, sizeof buf - 1) > 0 && strcmp(buf, "hello from vi\n") == 0, "file [%s]", buf);
	return fails == 0;
}

static int t_less(void)
{
	struct sess s;
	char *argv[] = {"/usr/bin/less", "/etc/passwd", 0};
	spawn(&s, 24, 80, argv, env_sh);
	expect(&s, "root:x:0:0", 20000);
	msleep(300);
	send(&s, "q");
	int st = finish(&s, 15000);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "less status %#x", st);
	return fails == 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, 0, _IONBF, 0);
	static char exe[256];
	self = argv[0];
	if (readlink("/proc/self/exe", exe, sizeof exe - 1) > 0)
		self = exe;
	if (argc < 2)
		return 2;
	const char *c = argv[1];
	if (!strcmp(c, "termtest"))
		return !termtest();
	if (!strcmp(c, "ttyinfo"))
		return !ttyinfo();
	if (!strcmp(c, "jobs"))
		return !jobs();
	if (!strcmp(c, "winch")) { // the console test: report a resize
		signal(SIGWINCH, on_winch);
		printf("waiting-winch\n");
		for (int i = 0; i < 800 && !winched; i++)
			msleep(25);
		struct winsize ws = {0};
		ioctl(0, TIOCGWINSZ, &ws);
		printf("%s %d %d\n", winched ? "got-winch" : "no-winch", ws.ws_row, ws.ws_col);
		return !winched;
	}
	struct {
		const char *name;
		int (*fn)(void);
	} cases[] = {
		{"pty", t_pty}, {"termios", t_termios}, {"tty", t_tty}, {"ttin", t_ttin},
		{"wait", t_wait}, {"sh", t_sh}, {"vi", t_vi}, {"less", t_less},
	};
	for (unsigned i = 0; i < sizeof cases / sizeof *cases; i++) {
		if (strcmp(c, cases[i].name))
			continue;
		int ok = cases[i].fn();
		printf("%s %s\n", c, ok && !fails ? "OK" : "FAILED");
		return !(ok && !fails);
	}
	return 2;
}
