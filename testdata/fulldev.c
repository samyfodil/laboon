#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
// mknod a /dev/full-style char device (rdev 1:7) in a tmpfs. laboon backs it
// with the host /dev/zero (rdev 1:5), so a naive fstat of the open fd reports
// the backing device's 1:5; it must report the guest device's own 1:7. Prints
// FULLDEV-OK.
int main(void) {
	mkdir("/t", 0755);
	if (mount("none", "/t", "tmpfs", 0, NULL) != 0) { perror("mount"); return 1; }
	if (mknod("/t/full", S_IFCHR | 0666, makedev(1, 7)) != 0) { perror("mknod"); return 2; }
	int fd = open("/t/full", O_RDONLY);
	if (fd < 0) { perror("open"); return 3; }
	struct stat fs;
	if (fstat(fd, &fs) != 0) { perror("fstat"); return 4; }
	if (!S_ISCHR(fs.st_mode) || fs.st_rdev != makedev(1, 7)) {
		fprintf(stderr, "fstat rdev=%lu:%lu, want 1:7 (not the host backing device's)\n",
			(unsigned long)major(fs.st_rdev), (unsigned long)minor(fs.st_rdev));
		return 5;
	}
	printf("FULLDEV-OK\n");
	return 0;
}
