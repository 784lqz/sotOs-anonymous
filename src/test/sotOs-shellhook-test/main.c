/*
 * sotOs · LUCAS · PR 10 · shell-hook test fixture.
 *
 * Exercises the execve argv rewrite path in lucas:
 *   1. fork() (sysno=57)
 *   2. child execve("/bin/sh", {"sh", NULL}, NULL)
 *   3. parent wait4(-1, NULL, 0, NULL)
 *
 * The expected operator-visible markers in the serial log are:
 *   [shellhook-test] before execve
 *   [lucas] shellhook · injected 2 rc files into execve of /bin/sh
 *   [BASHRC-MARKER] /etc/bashrc sourced by shellhook
 *   [BASHRC-MARKER] /root/.bashrc sourced by shellhook
 *
 * Source-level C view (see shellhook_test.S for the actual asm):
 *
 *   int main(void) {
 *       write(1, "[shellhook-test] before execve\n", 31);
 *       pid_t pid = fork();
 *       if (pid == 0) {
 *           const char *argv[] = { "sh", NULL };
 *           execve("/bin/sh", argv, NULL);
 *           write(2, "[shellhook-test] execve returned (FAIL)\n", 40);
 *           _exit(1);
 *       }
 *       wait4(-1, NULL, 0, NULL);
 *       write(1, "[shellhook-test] parent reaped\n", 31);
 *       _exit(0);
 *   }
 *
 * As with the rest of the test fixtures in this tree, the load-bearing
 * source ships as shellhook_test.S (hand-derived asm · no libc · static
 * ELF · committed binary).  This .c file is kept in tree for documentation
 * and the plan's Step 10.4 reference.
 */
