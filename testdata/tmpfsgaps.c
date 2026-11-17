#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

// Exercise the fd operations a real tmpfs supports, reporting which ones the
// in-memory backend serves and which fail. Always returns 0 after printing, so
// the harness captures the full picture rather than stopping at the first fail.
static void rep(const char *op, int ok) {
	if (ok) printf("  %-16s OK\n", op);
	else printf("  %-16s FAIL errno=%d (%s)\n", op, errno, strerror(errno));
}

int main(void) {
	unshare(CLONE_NEWUSER | CLONE_NEWNS);
	mkdir("/mnt/t", 0755);
	if (mount("none", "/mnt/t", "tmpfs", 0, "") != 0) { perror("mount"); return 1; }

	int fd = open("/mnt/t/f", O_CREAT | O_RDWR, 0644);
	if (fd < 0) { perror("open"); return 2; }
	if (write(fd, "hello world data", 16) != 16) { perror("write"); return 3; }

	rep("fsync", fsync(fd) == 0);
	rep("fdatasync", fdatasync(fd) == 0);
	rep("fallocate", fallocate(fd, 0, 0, 4096) == 0);

	struct statfs sfs;
	rep("fstatfs", fstatfs(fd, &sfs) == 0);

	char *pp = mmap(NULL, 16, PROT_READ, MAP_PRIVATE, fd, 0);
	rep("mmap-private", pp != MAP_FAILED && memcmp(pp, "hello", 5) == 0);
	if (pp != MAP_FAILED) munmap(pp, 16);

	char *ps = mmap(NULL, 16, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	rep("mmap-shared", ps != MAP_FAILED);
	if (ps != MAP_FAILED) munmap(ps, 16);

	char *pe = mmap(NULL, 16, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	rep("mmap-exec", pe != MAP_FAILED);
	if (pe != MAP_FAILED) munmap(pe, 16);

	int nul = open("/dev/null", O_WRONLY);
	off_t off = 0;
	rep("sendfile", sendfile(nul, fd, &off, 16) == 16);
	close(nul);

	// /dev/shm as its own tmpfs with a MAP_SHARED segment: the postgres/chromium
	// shared-memory pattern a container runtime sets up.
	mkdir("/dev/shm", 01777);
	if (mount("none", "/dev/shm", "tmpfs", 0, "") == 0) {
		int sh = open("/dev/shm/seg", O_CREAT | O_RDWR, 0644);
		if (sh >= 0 && ftruncate(sh, 4096) == 0) {
			void *seg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, sh, 0);
			rep("devshm-shared", seg != MAP_FAILED);
			if (seg != MAP_FAILED) munmap(seg, 4096);
		}
		if (sh >= 0) close(sh);
	}

	// unlinked-but-open file: the anonymous temp pattern (mkstemp + unlink).
	unlink("/mnt/t/f");
	struct stat st;
	rep("fstat-unlinked", fstat(fd, &st) == 0 && S_ISREG(st.st_mode));
	rep("ftrunc-unlinked", ftruncate(fd, 8) == 0);
	char rb[16] = {0};
	rep("read-unlinked", lseek(fd, 0, SEEK_SET) == 0 && read(fd, rb, 8) == 8);
	close(fd);

	printf("TMPFSGAPS-DONE\n");
	return 0;
}
