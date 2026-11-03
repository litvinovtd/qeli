#define _GNU_SOURCE
/* Test-only Linux fsync barrier. Use only with audit_status_writer.py in a private lab. */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static _Atomic int first_seen, final_seen;
static void path(char *out, const char *name) {
    const char *root = getenv("QELI_STATUS_FIXTURE");
    if (!root || snprintf(out, PATH_MAX, "%s/%s", root, name) >= PATH_MAX) _exit(180);
}
static void hold(const char *stage) {
    char ready[PATH_MAX], release[PATH_MAX], name[40], thread[16] = {0};
    snprintf(name, sizeof(name), "%s-ready", stage); path(ready, name);
    snprintf(name, sizeof(name), "%s-release", stage); path(release, name);
    pthread_getname_np(pthread_self(), thread, sizeof(thread));
    int fd = open(ready, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) _exit(181);
    if (dprintf(fd, "pid=%ld tid=%ld thread=%s\n", (long)getpid(), syscall(SYS_gettid), thread) < 0 || close(fd)) _exit(182);
    struct timespec start, now, tick = {0, 10000000};
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (access(release, F_OK)) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > 45) _exit(183);
        nanosleep(&tick, NULL);
    }
}
int fsync(int fd) {
    int (*next)(int) = dlsym(RTLD_NEXT, "fsync");
    if (!next) _exit(184);
    if (!getenv("QELI_STATUS_FIXTURE")) return next(fd);
    char link[64], target[PATH_MAX], body[16384];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t size = readlink(link, target, sizeof(target) - 1);
    if (size < 0) return next(fd);
    target[size] = 0;
    if (!strstr(target, "/.status.json.qeli-tmp-")) return next(fd);
    int source = open(target, O_RDONLY | O_CLOEXEC);
    if (source < 0) return next(fd);
    size = read(source, body, sizeof(body) - 1); close(source);
    if (size < 0) return next(fd);
    body[size] = 0;
    const char *stage = NULL;
    if (!atomic_exchange(&first_seen, 1)) stage = "first";
    else if ((strstr(body, "\"state\":\"failed\"") || strstr(body, "\"state\":\"stopped\"")) && !atomic_exchange(&final_seen, 1)) stage = "final";
    if (stage) {
        hold(stage);
        const char *fault = getenv("QELI_STATUS_FAULT");
        if (fault && !strcmp(stage, fault)) { errno = EIO; return -1; }
    }
    return next(fd);
}
