/* sotOs v2-real-vfs gate · dynamic PIE. (1) calls vfs_probe() from a .so
 * resolved through a symlink; (2) exercises openat/fstat/read/lseek/mmap on
 * a real sysroot file; (3) getdents64 over /usr/lib. Prints gate markers. */
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <string.h>

extern int vfs_probe(void);

static void say(const char *s) { write(1, s, strlen(s)); }

int main(void) {
    /* 1 · symlink-resolved .so */
    if (vfs_probe() == 0x5A) say("[real-vfs] symlink-so OK\n");
    else                     say("[real-vfs] symlink-so FAIL\n");

    /* 2 · openat/fstat/read/lseek/mmap on a real file (crt1.o always present) */
    int fd = openat(AT_FDCWD, "/usr/lib/crt1.o", O_RDONLY);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size > 0) say("[real-vfs] fstat OK\n");
        char b0, b1;
        read(fd, &b0, 1);
        lseek(fd, 0, SEEK_SET);
        read(fd, &b1, 1);
        if (b0 == 0x7f && b1 == 0x7f) say("[real-vfs] read+lseek OK\n");  /* ELF magic */
        void *m = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (m != MAP_FAILED && ((unsigned char *)m)[0] == 0x7f) say("[real-vfs] mmap OK\n");
        close(fd);
    } else say("[real-vfs] openat FAIL\n");

    /* 3 · getdents64 over /usr/lib (must list libvfsprobe.so.1) */
    int dfd = openat(AT_FDCWD, "/usr/lib", O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        char buf[4096];
        long n = syscall(217 /*getdents64*/, dfd, buf, sizeof(buf));  /* SYS_getdents64 */
        int found = 0;
        for (long o = 0; o < n; ) {
            struct { unsigned long ino, off; unsigned short rl; unsigned char ty; char name[]; } *d =
                (void *)(buf + o);
            if (strstr(d->name, "libvfsprobe")) found = 1;
            o += d->rl;
        }
        say(found ? "[real-vfs] getdents OK\n" : "[real-vfs] getdents FAIL\n");
        close(dfd);
    }
    return 0;
}
