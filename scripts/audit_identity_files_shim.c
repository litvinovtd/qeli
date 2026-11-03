#define _GNU_SOURCE
/* Test-only TOFU fsync failure; preload only into the isolated audit client. */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int fsync(int fd) {
    int (*next)(int) = dlsym(RTLD_NEXT, "fsync");
    if (!next) _exit(181);
    const char *root = getenv("QELI_IDENTITY_FIXTURE");
    if (!root) return next(fd);
    char link[64], target[PATH_MAX], marker[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t size = readlink(link, target, sizeof(target) - 1);
    if (size < 0) return next(fd);
    target[size] = 0;
    const char *base = strrchr(target, '/');
    if (!base || (strcmp(base, "/known_hosts") && !strstr(base, "/.known_hosts.qeli-tmp-"))) return next(fd);
    if (snprintf(marker, sizeof(marker), "%s/tofu-fsync-failed", root) >= PATH_MAX) _exit(182);
    int mark = open(marker, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (mark < 0 || close(mark)) _exit(183);
    errno = EIO; return -1;
}
