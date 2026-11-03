#define _GNU_SOURCE
/* Test-only held TOFU fsync, gated by a path inside an isolated audit client. */
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
    const char *root = getenv("QELI_TOFU_FIXTURE");
    if (!root) return next(fd);
    char link[64], target[PATH_MAX], marker[PATH_MAX], release[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t size = readlink(link, target, sizeof(target) - 1);
    if (size < 0) return next(fd);
    target[size] = 0;
    const char *base = strrchr(target, '/');
    if (!base || !strstr(base, "/.known_hosts.qeli-tmp-")) return next(fd);
    if (snprintf(marker, sizeof(marker), "%s/tofu-entered", root) >= PATH_MAX ||
        snprintf(release, sizeof(release), "%s/release-tofu", root) >= PATH_MAX) _exit(182);
    int mark = open(marker, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (mark < 0 || write(mark, "1", 1) != 1 || close(mark)) _exit(183);
    unsigned int tries = 0;
    while (access(release, F_OK)) { if (++tries > 1500) _exit(184); usleep(10000); }
    const char *fail = getenv("QELI_TOFU_FAIL");
    if (fail && !strcmp(fail, "1")) {errno = EIO; return -1;}
    return next(fd);
}
