// Test-only: delay one matching operation in the explicitly selected test process.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <time.h>
static _Atomic int injected;
static int selected(const char *mode) {
    const char *pid = getenv("QELI_AUDIT_PID");
    const char *wanted = getenv("QELI_AUDIT_IO_MODE");
    return pid && (pid_t)strtol(pid, NULL, 10) == getpid() && wanted && !strcmp(mode, wanted);
}
static void delay(const char *path) {
    const char *marker = getenv("QELI_AUDIT_MARKER");
    if (!marker || atomic_exchange(&injected, 1)) return;
    int fd = syscall(SYS_openat, AT_FDCWD, marker, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
    if (fd >= 0) { syscall(SYS_write, fd, path, strlen(path)); syscall(SYS_close, fd); }
    struct timespec rest = {2, 0};
    while (nanosleep(&rest, &rest) != 0) {}
}
static int fd_path(int fd, char *buf, size_t capacity) {
    char link[64]; snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, buf, capacity - 1);
    if (n < 0) return 0;
    buf[n] = 0; return 1;
}
ssize_t read(int fd, void *buf, size_t count) {
    ssize_t (*real)(int, void *, size_t) = dlsym(RTLD_NEXT, "read");
    char path[4096];
    if (count && selected("backup-read") && fd_path(fd, path, sizeof(path)) && !strcmp(path, "/etc/qeli/server.ini")) delay(path);
    return real(fd, buf, count);
}
ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t (*real)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    char path[4096];
    if (count && selected("hook-write") && fd_path(fd, path, sizeof(path)) && !strncmp(path, "/tmp/qeli-hook-", 15)) delay(path);
    return real(fd, buf, count);
}
int unlink(const char *path) {
    int (*real)(const char *) = dlsym(RTLD_NEXT, "unlink");
    if (selected("hook-unlink") && !strncmp(path, "/tmp/qeli-hook-", 15)) delay(path);
    return real(path);
}
int unlinkat(int fd, const char *path, int flags) {
    int (*real)(int, const char *, int) = dlsym(RTLD_NEXT, "unlinkat");
    if (selected("hook-unlink") && !strncmp(path, "/tmp/qeli-hook-", 15)) delay(path);
    return real(fd, path, flags);
}
