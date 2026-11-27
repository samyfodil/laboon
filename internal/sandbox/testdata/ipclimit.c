// System V IPC limits: every per-namespace limit IPC_INFO and
// /proc/sys/kernel report is the one enforced, exhausting it fails with
// Linux's errno, and removing an object makes room again. Prints one line per
// check and "ALL OK" at the end.
#define _GNU_SOURCE
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int fails;
#define CHECK(c, ...) do { if (c) { printf("ok   "); } else { printf("FAIL "); fails++; } printf(__VA_ARGS__); printf("\n"); } while (0)

union semun { int val; struct semid_ds *buf; unsigned short *array; struct seminfo *__buf; };

static unsigned long sysctl1(const char *name) {
    char path[64], buf[128];
    snprintf(path, sizeof path, "/proc/sys/kernel/%s", name);
    FILE *f = fopen(path, "r");
    if (!f || !fgets(buf, sizeof buf, f)) return 0;
    fclose(f);
    return strtoul(buf, NULL, 10);
}

static int ids[32001];

static void t_shm(void) {
    struct shminfo si;
    int r = shmctl(0, IPC_INFO, (struct shmid_ds *)&si);
    CHECK(r >= 0 && si.shmmni == 4096, "IPC_INFO shmmni %lu", si.shmmni);
    CHECK(si.shmmax == sysctl1("shmmax") && si.shmall == sysctl1("shmall") && si.shmmni == sysctl1("shmmni"),
          "shm sysctls match IPC_INFO: shmmax %lu shmall %lu", si.shmmax, si.shmall);
    long page = sysconf(_SC_PAGESIZE);

    errno = 0;
    CHECK(shmget(IPC_PRIVATE, si.shmmax + 1, IPC_CREAT | 0600) < 0 && errno == EINVAL, "size over SHMMAX: EINVAL (%d)", errno);

    int n = 0;
    while (n <= (int)si.shmmni && (ids[n] = shmget(IPC_PRIVATE, 1, IPC_CREAT | 0600)) >= 0) n++;
    int e = errno;
    CHECK(n == (int)si.shmmni && e == ENOSPC, "SHMMNI: %d segments then ENOSPC (%d)", n, e);
    struct shm_info inf;
    r = shmctl(0, SHM_INFO, (struct shmid_ds *)&inf);
    CHECK(r >= 0 && inf.used_ids == n && inf.shm_tot == (unsigned long)n, "SHM_INFO used_ids %d shm_tot %lu", inf.used_ids, inf.shm_tot);
    shmctl(ids[0], IPC_RMID, NULL);
    ids[0] = shmget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    CHECK(ids[0] >= 0, "a removed segment makes room");
    for (int i = 0; i < n; i++) shmctl(ids[i], IPC_RMID, NULL);

    unsigned long all = si.shmall * page;
    if (all > si.shmmax) all = si.shmmax;
    int big = shmget(IPC_PRIVATE, all, IPC_CREAT | 0600);
    unsigned long left = si.shmall - (all + page - 1) / page;
    int fill = left ? shmget(IPC_PRIVATE, left * page, IPC_CREAT | 0600) : -1;
    errno = 0;
    int over = shmget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    e = errno;
    CHECK(big >= 0 && (left == 0 || fill >= 0) && over < 0 && e == ENOSPC, "SHMALL %lu pages then ENOSPC (%d)", si.shmall, e);
    shmctl(big, IPC_RMID, NULL);
    int again = shmget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    CHECK(again >= 0, "removing a segment returns its pages");
    shmctl(again, IPC_RMID, NULL);
    if (fill >= 0) shmctl(fill, IPC_RMID, NULL);
    r = shmctl(0, SHM_INFO, (struct shmid_ds *)&inf);
    CHECK(r >= 0 && inf.used_ids == 0 && inf.shm_tot == 0, "all segments gone: used_ids %d shm_tot %lu", inf.used_ids, inf.shm_tot);
}

static void t_sem(void) {
    struct seminfo si;
    union semun a = {.__buf = &si};
    int r = semctl(0, 0, IPC_INFO, a);
    CHECK(r >= 0 && si.semmni == 32000 && si.semmsl == 32000, "IPC_INFO semmni %d semmsl %d semmns %d", si.semmni, si.semmsl, si.semmns);
    FILE *f = fopen("/proc/sys/kernel/sem", "r");
    int msl = 0, mns = 0, opm = 0, mni = 0;
    if (f) { if (fscanf(f, "%d %d %d %d", &msl, &mns, &opm, &mni) != 4) msl = 0; fclose(f); }
    CHECK(msl == si.semmsl && mns == si.semmns && opm == si.semopm && mni == si.semmni, "/proc/sys/kernel/sem matches IPC_INFO");

    errno = 0;
    CHECK(semget(IPC_PRIVATE, si.semmsl + 1, IPC_CREAT | 0600) < 0 && errno == EINVAL, "nsems over SEMMSL: EINVAL (%d)", errno);

    int n = 0;
    while (n <= si.semmni && (ids[n] = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600)) >= 0) n++;
    int e = errno;
    CHECK(n == si.semmni && e == ENOSPC, "SEMMNI: %d sets then ENOSPC (%d)", n, e);
    semctl(ids[0], 0, IPC_RMID);
    ids[0] = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    CHECK(ids[0] >= 0, "a removed set makes room");
    for (int i = 0; i < n; i++) semctl(ids[i], 0, IPC_RMID);

    int used = 0;
    n = 0;
    while (used + si.semmsl <= si.semmns && (ids[n] = semget(IPC_PRIVATE, si.semmsl, IPC_CREAT | 0600)) >= 0) {
        used += si.semmsl;
        n++;
    }
    int rest = si.semmns - used;
    if (rest > 0) ids[n++] = semget(IPC_PRIVATE, rest, IPC_CREAT | 0600);
    struct seminfo now;
    a.__buf = &now;
    semctl(0, 0, SEM_INFO, a);
    errno = 0;
    int over = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    e = errno;
    CHECK(ids[n - 1] >= 0 && now.semaem == si.semmns && now.semusz == n && over < 0 && e == ENOSPC,
          "SEMMNS: %d semaphores in %d sets then ENOSPC (%d)", now.semaem, now.semusz, e);
    semctl(ids[0], 0, IPC_RMID);
    ids[0] = semget(IPC_PRIVATE, si.semmsl, IPC_CREAT | 0600);
    CHECK(ids[0] >= 0, "a removed set returns its semaphores");
    for (int i = 0; i < n; i++) semctl(ids[i], 0, IPC_RMID);
    semctl(0, 0, SEM_INFO, a);
    CHECK(now.semusz == 0 && now.semaem == 0, "all sets gone");
}

struct big { long type; char text[8192]; };
static struct big m = {.type = 1};

static void t_msg(void) {
    struct msginfo mi;
    int r = msgctl(0, IPC_INFO, (struct msqid_ds *)&mi);
    CHECK(r >= 0 && mi.msgmni == 32000 && mi.msgmnb == 16384 && mi.msgmax == 8192, "IPC_INFO msgmni %d msgmnb %d msgmax %d", mi.msgmni, mi.msgmnb, mi.msgmax);
    CHECK(mi.msgmni == (int)sysctl1("msgmni") && mi.msgmnb == (int)sysctl1("msgmnb") && mi.msgmax == (int)sysctl1("msgmax"), "msg sysctls match IPC_INFO");

    errno = 0;
    CHECK(msgsnd(0, &m, mi.msgmax + 1, 0) < 0 && errno == EINVAL, "message over MSGMAX: EINVAL (%d)", errno);

    int n = 0;
    while (n <= mi.msgmni && (ids[n] = msgget(IPC_PRIVATE, IPC_CREAT | 0600)) >= 0) n++;
    int e = errno;
    CHECK(n == mi.msgmni && e == ENOSPC, "MSGMNI: %d queues then ENOSPC (%d)", n, e);
    msgctl(ids[0], IPC_RMID, NULL);
    ids[0] = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    CHECK(ids[0] >= 0, "a removed queue makes room");

    int full = msgsnd(ids[0], &m, mi.msgmax, IPC_NOWAIT) | msgsnd(ids[0], &m, mi.msgmax, IPC_NOWAIT);
    errno = 0;
    CHECK(full == 0 && msgsnd(ids[0], &m, 1, IPC_NOWAIT) < 0 && errno == EAGAIN, "MSGMNB: a full queue is EAGAIN (%d)", errno);

    int q = 1, sent = 0;
    while (q < n && (r = msgsnd(ids[q], &m, mi.msgmax, IPC_NOWAIT)) == 0) {
        sent++;
        if (sent % 2 == 0) q++;
    }
    e = errno;
    struct msginfo now;
    msgctl(0, MSG_INFO, (struct msqid_ds *)&now);
    long pool = (long)mi.msgpool * 1024, held = now.msgtql + 48L * now.msgmap; // 48: laboon's charge per message
    CHECK(r < 0 && e == ENOMEM && held > pool - mi.msgmax - 48 && held <= pool && now.msgpool == n,
          "message pool %d KiB: %d messages queued then ENOMEM (%d)", mi.msgpool, now.msgmap, e);
    struct big got;
    CHECK(msgrcv(ids[1], &got, sizeof got.text, 0, IPC_NOWAIT) == mi.msgmax && msgsnd(ids[n - 1], &m, mi.msgmax, IPC_NOWAIT) == 0,
          "a received message returns its bytes to the pool");
    msgctl(ids[2], IPC_RMID, NULL);
    CHECK(msgsnd(ids[n - 1], &m, mi.msgmax, IPC_NOWAIT) == 0, "a removed queue returns its bytes to the pool");
    for (int i = 0; i < n; i++) msgctl(ids[i], IPC_RMID, NULL);
    msgctl(0, MSG_INFO, (struct msqid_ds *)&now);
    CHECK(now.msgpool == 0 && now.msgmap == 0 && now.msgtql == 0, "all queues gone");
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    t_shm();
    t_sem();
    t_msg();
    if (fails) {
        printf("%d FAILED\n", fails);
        return 1;
    }
    printf("ALL OK\n");
    return 0;
}
