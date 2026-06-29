/*
 * sotOs · LUCAS · PR 6 · POSIX-surface syscall test fixture.
 *
 * REAL runtime validation of the LUCAS POSIX surface arc (PRs 1-5):
 *   PR 1  unlink(87)              · delete a file, assert it's gone
 *   PR 3  readv(19) / writev(20)  · scatter-gather round-trip
 *   PR 4  safe_noop[] / madvise   · madvise(0,0,0) returns 0 (noop)
 *   PR 5  console/FS boundary     · write(1,...) to stdout must NOT
 *                                    count as a filesystem mutation.
 *
 * The expected operator-visible markers in the serial log are:
 *   [syscall-test] alive
 *   [vfs] unlink /tmp/sc.tmp           (from lucas_sys_unlink, PR 1)
 *   [syscall-test] iov OK              (writev/readv round-trip OK)
 *   [syscall-test] ALL PASS            (smoke gate SYSCALL·all-pass)
 *
 * Source-level C view (see syscall_test.S for the actual asm):
 *
 *   int main(void) {
 *       int fail = 0;
 *       write(1, "[syscall-test] alive\n", 21);   // PR 5 stdout path
 *
 *       int fd = open("/tmp/sc.tmp", O_CREAT|O_WRONLY|O_TRUNC, 0644);
 *       if (fd < 0) fail = 1;
 *       else { if (write(fd, "hello", 5) != 5) fail = 1; close(fd); }
 *
 *       // PR 3 · writev/readv scatter-gather round-trip
 *       int iofd = open("/tmp/sc.iov", O_CREAT|O_RDWR|O_TRUNC, 0644);
 *       if (iofd < 0) fail = 1;
 *       else {
 *           struct iovec wv[2] = {{"foo",3},{"bar",3}};
 *           char buf[6]; struct iovec rv[2] = {{buf,3},{buf+3,3}};
 *           if (writev(iofd, wv, 2) != 6) fail = 1;
 *           lseek(iofd, 0, SEEK_SET);
 *           if (readv(iofd, rv, 2) != 6) fail = 1;
 *           close(iofd); unlink("/tmp/sc.iov");
 *           if (!fail) write(1, "[syscall-test] iov OK\n", 22);
 *       }
 *
 *       // PR 1 · unlink + assert the file is gone
 *       if (unlink("/tmp/sc.tmp") < 0) fail = 1;
 *       int re = open("/tmp/sc.tmp", O_RDONLY);
 *       if (re >= 0) { close(re); fail = 1; }   // must be ENOENT
 *
 *       // PR 4 · madvise is a safe-noop · must return 0
 *       if (madvise(0, 0, 0) != 0) fail = 1;
 *
 *       if (!fail) write(1, "[syscall-test] ALL PASS\n", 24);
 *       else       write(2, "[syscall-test] FAIL\n", 20);
 *       _exit(0);
 *   }
 *
 * As with the rest of the test fixtures in this tree, the load-bearing
 * source ships as syscall_test.S (hand-derived asm · no libc · static
 * ELF · committed binary).  This .c file is kept in tree for
 * documentation and the plan's Step 6.4 reference.
 */
