#define _GNU_SOURCE
/* Test-only x86_64 Linux fault injection; never preload into installed services.
 * Fail pump fcntl or the second thread creation only after the fixture post_up.
 * Build: cc -shared -fPIC -Wall -Wextra -Werror -o pump.so this.c -ldl -pthread
 */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static _Atomic long starter;
static _Atomic int creations;
static _Atomic int fired;

static void path(char *out, const char *name) {
    const char *root = getenv("QELI_PUMP_FIXTURE");
    if (!root || snprintf(out, PATH_MAX, "%s/%s", root, name) >= PATH_MAX) _exit(180);
}
static int enabled(void) {
    if (!getenv("QELI_PUMP_FIXTURE")) return 0;
    char file[PATH_MAX];
    path(file, "post-up");
    if (access(file, F_OK) != 0) return 0;
    path(file, "fault-enabled");
    return access(file, F_OK) == 0;
}
static void hold(void) {
    char ready[PATH_MAX], release[PATH_MAX], thread[16] = {0};
    path(ready, "pump-ready"); path(release, "pump-release");
    pthread_getname_np(pthread_self(), thread, sizeof(thread));
    int fd = open(ready, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) _exit(181);
    if (dprintf(fd, "pid=%ld tid=%ld thread=%s failure=%s\n", (long)getpid(),
                syscall(SYS_gettid), thread, getenv("QELI_PUMP_FAILURE")) < 0 || close(fd) != 0) _exit(182);
    struct timespec start, now, tick = {0, 10000000};
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (access(release, F_OK) != 0) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > 60) _exit(183);
        nanosleep(&tick, NULL);
    }
}
static int intercept(int fd, int command) {
    if (command != F_GETFL || !enabled()) return 0;
    int saved = errno;
    struct ifreq link = {0};
    int is_tun = ioctl(fd, TUNGETIFF, &link) == 0 && strcmp(link.ifr_name, "qnt0") == 0;
    errno = saved;
    if (!is_tun) return 0;
    const char *kind = getenv("QELI_PUMP_FAILURE");
    if (!kind) return 0;
    if (strcmp(kind, "fcntl") == 0 && !atomic_exchange(&fired, 1)) {
        hold(); errno = EIO; return 1;
    }
    if (strcmp(kind, "writer") == 0) {
        long absent = 0;
        atomic_compare_exchange_strong(&starter, &absent, syscall(SYS_gettid));
    }
    return 0;
}
/* Only actual argument kinds are read. In particular F_GETFL carries no vararg. */
static int dispatch(const char *symbol, int fd, int command, va_list args) {
    int (*next)(int, int, ...) = dlsym(RTLD_NEXT, symbol);
    if (!next) _exit(184);
    if (intercept(fd, command)) return -1;
    switch (command) {
    case F_GETFD: case F_GETFL: case F_GETOWN: case F_GETSIG:
    case F_GETLEASE: case F_GETPIPE_SZ: case F_GET_SEALS:
        return next(fd, command);
    case F_DUPFD: case F_DUPFD_CLOEXEC: case F_SETFD: case F_SETFL:
    case F_SETOWN: case F_SETSIG: case F_SETLEASE: case F_SETPIPE_SZ: case F_ADD_SEALS:
        return next(fd, command, va_arg(args, int));
    default:
        return next(fd, command, va_arg(args, void *));
    }
}
int fcntl(int fd, int command, ...) {
    va_list args; va_start(args, command);
    int result = dispatch("fcntl", fd, command, args);
    va_end(args); return result;
}
int fcntl64(int fd, int command, ...) {
    va_list args; va_start(args, command);
    int result = dispatch("fcntl64", fd, command, args);
    va_end(args); return result;
}
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*entry)(void *), void *argument) {
    int (*next)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = dlsym(RTLD_NEXT, "pthread_create");
    if (!next) _exit(185);
    if (enabled() && atomic_load(&starter) == syscall(SYS_gettid) &&
        atomic_fetch_add(&creations, 1) == 1 && !atomic_exchange(&fired, 1)) {
        hold(); return EAGAIN;
    }
    return next(thread, attr, entry, argument);
}
