// ownerck: a guest (root) chowns a file to 1000:1000, then checks that stat()
// and fstat() agree and both report the chowned owner. Covers an overlay lower
// file (which copies up, so the override is stored under the upper inode while
// the path resolves to the lower identity) and an in-memory (tmpfs) mount whose
// owner lives on the node. Prints OWNER-OK.
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static int check(const char *p) {
	if (chown(p, 1000, 1000) != 0) {
		perror("chown");
		return 1;
	}
	struct stat ps, fs;
	if (stat(p, &ps) != 0) {
		perror("stat");
		return 2;
	}
	int fd = open(p, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 3;
	}
	if (fstat(fd, &fs) != 0) {
		perror("fstat");
		close(fd);
		return 4;
	}
	close(fd);
	if (ps.st_uid != 1000 || ps.st_gid != 1000) {
		fprintf(stderr, "%s stat uid/gid=%d/%d want 1000/1000\n", p, ps.st_uid, ps.st_gid);
		return 5;
	}
	if (fs.st_uid != 1000 || fs.st_gid != 1000) {
		fprintf(stderr, "%s fstat uid/gid=%d/%d want 1000/1000\n", p, fs.st_uid, fs.st_gid);
		return 6;
	}
	if (ps.st_uid != fs.st_uid || ps.st_gid != fs.st_gid) {
		fprintf(stderr, "%s stat(%d/%d) vs fstat(%d/%d) owner disagree\n",
			p, ps.st_uid, ps.st_gid, fs.st_uid, fs.st_gid);
		return 7;
	}
	return 0;
}

int main(void) {
	if (check("/f") != 0)
		return 1;
	if (check("/data/mf") != 0)
		return 2;
	printf("OWNER-OK\n");
	return 0;
}
