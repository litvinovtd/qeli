#define _GNU_SOURCE
/* Test-only x86_64 Linux fault injection. Never preload into installed services.
 * Make the original, exclusively created Qeli queue persistent before SIGKILL.
 * Build: cc -shared -fPIC -Wall -Wextra -Werror -o persist.so this.c -ldl
 */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int ioctl(int fd, unsigned long request, ...) {
    int (*next_ioctl)(int, unsigned long, ...) = dlsym(RTLD_NEXT, "ioctl");
    if (!next_ioctl) _exit(185);
    va_list args;
    va_start(args, request);
    unsigned long arg = va_arg(args, unsigned long);
    va_end(args);
    int result = next_ioctl(fd, request, arg);
    int saved_errno = errno;
    const char *name = getenv("QELI_TEST_PERSIST_NAME");
    if (result == 0 && request == TUNSETIFF && name) {
        const struct ifreq *ifr = (const struct ifreq *)arg;
        if ((ifr->ifr_flags & IFF_TUN_EXCL) &&
            strncmp(ifr->ifr_name, name, IFNAMSIZ) == 0) {
            const char *path = getenv("QELI_TEST_PERSIST_MARKER");
            if (!path || next_ioctl(fd, TUNSETPERSIST, 1UL) != 0) _exit(186);
            int marker = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (marker < 0) _exit(187);
            if (dprintf(marker, "%ld %s\n", (long)getpid(), name) < 0 ||
                fsync(marker) != 0 || close(marker) != 0) _exit(188);
        }
    }
    errno = saved_errno;
    return result;
}
