#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    struct stat st;
    if (stat("/dev/shm", &st) != 0) { perror("stat"); return 1; }
    if (!S_ISDIR(st.st_mode) || (st.st_mode & 07777) != 01777) {
        printf("mode %o\n", st.st_mode);
        return 2;
    }
    int fd = open("/dev/shm/x", O_CREAT | O_RDWR, 0600);
    if (fd < 0 || write(fd, "ok", 2) != 2) { perror("create"); return 3; }
    close(fd);
    puts("OK");
    return 0;
}
