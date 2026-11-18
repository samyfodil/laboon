// mmapguest: guest programs for the writable MAP_SHARED tests of a non-host
// file, selected by argv[1] (default "coherence"). Built -static-pie so it needs
// no dynamic loader and runs on the rewriter backend (a non-PIE ET_EXEC forces
// the hypervisor backend on arm64 macOS, which copies file mappings into VM RAM
// instead of sharing them). Output is via write(2) and the program ends with
// _exit(2): a static-PIE glibc binary's normal exit cleanup faults under
// laboon's rewriter (the gate runs musl binaries), which would discard buffered
// stdout and mask the result.
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static void say(const char *s) { write(1, s, strlen(s)); }

// coherence: cross-open coherence, a mapping store visible to read() with no
// msync, a write() visible through the mapping, then an msync write-back.
static int coherence(void) {
	int fd1 = open("/data/f", O_RDWR);
	int fd2 = open("/data/f", O_RDWR); // an independent open
	if (fd1 < 0 || fd2 < 0) {
		say("OPEN-FAIL\n");
		return 1;
	}
	char *p1 = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
	char *p2 = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
	if (p1 == MAP_FAILED || p2 == MAP_FAILED) {
		say("MMAP-FAIL\n");
		return 2;
	}
	memcpy(p1, "SHARED-WRITTEN", 14);
	if (memcmp(p2, "SHARED-WRITTEN", 14) != 0) {
		say("INCOHERENT\n");
		return 3;
	}
	char buf[14];
	if (pread(fd2, buf, 14, 0) != 14 || memcmp(buf, "SHARED-WRITTEN", 14) != 0) {
		say("READ-STALE\n");
		return 4;
	}
	if (pwrite(fd2, "WROTE", 5, 100) != 5 || memcmp(p1 + 100, "WROTE", 5) != 0) {
		say("MMAP-STALE\n");
		return 5;
	}
	if (msync(p1, 4096, MS_SYNC) != 0) {
		say("MSYNC-FAIL\n");
		return 6;
	}
	say("MMAP-OK\n");
	return 0;
}

// mapWriteUnmap maps the file shared, writes s at 0, and unmaps it (the last
// unmap writes the backing back and releases it).
static int mapWriteUnmap(const char *s) {
	int fd = open("/data/f", O_RDWR);
	if (fd < 0) {
		return -1;
	}
	char *p = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		close(fd);
		return -1;
	}
	memcpy(p, s, strlen(s));
	int r = munmap(p, 4096);
	close(fd);
	return r;
}

// reevict maps, writes and unmaps twice: each unmap writes the backing back and
// evicts it, so the second mapping builds a fresh backing. The supervisor sees
// two write-backs and the file ends with the second store.
static int reevict(void) {
	if (mapWriteUnmap("FIRST-STORE") != 0 || mapWriteUnmap("SECOND-STORE") != 0) {
		say("REEVICT-FAIL\n");
		return 1;
	}
	say("MMAP-OK\n");
	return 0;
}

// forkshare: a MAP_SHARED mapping stays coherent across fork and its backing
// survives while a child maps it. The parent writes and forks; the child sees it
// and writes back; the parent sees the child's store, then both unmap.
static int forkshare(void) {
	int fd = open("/data/f", O_RDWR);
	if (fd < 0) {
		say("OPEN-FAIL\n");
		return 1;
	}
	char *p = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		say("MMAP-FAIL\n");
		return 2;
	}
	memcpy(p, "PARENT", 6);
	pid_t pid = fork();
	if (pid < 0) {
		say("FORK-FAIL\n");
		return 3;
	}
	if (pid == 0) {
		if (memcmp(p, "PARENT", 6) != 0) {
			_exit(10);
		}
		memcpy(p + 100, "CHILD", 5);
		_exit(0);
	}
	int st;
	waitpid(pid, &st, 0);
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		say("CHILD-FAIL\n");
		return 4;
	}
	if (memcmp(p + 100, "CHILD", 5) != 0) {
		say("PARENT-STALE\n");
		return 5;
	}
	munmap(p, 4096);
	say("MMAP-OK\n");
	return 0;
}

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "coherence";
	if (strcmp(mode, "reevict") == 0) {
		_exit(reevict());
	}
	if (strcmp(mode, "fork") == 0) {
		_exit(forkshare());
	}
	_exit(coherence());
}
