// statls PATH...: prints "PATH uid gid mode" (mode in octal, type bits
// included) for each path, from lstat.
#include <stdio.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        struct stat st;
        if (lstat(argv[i], &st) != 0) {
            printf("%s missing\n", argv[i]);
            continue;
        }
        printf("%s %u %u %o\n", argv[i], st.st_uid, st.st_gid, st.st_mode);
    }
    return 0;
}
