/*
 * sotOs · procd PR 6 · fork test fixture.
 *
 * Exercises the OP_FORK + OP_EXIT + OP_WAIT shadow-announce path:
 *   1. fork() · expect [orch] procd fork announced
 *   2. child exit_group(42) · expect [procd] exit slot=
 *   3. parent wait() · expect [procd] EV_SIGCHLD + [procd] wait reaped
 *
 * Built as a static no-libc Linux ELF so it can be embedded in orch's
 * CPIO (same pattern as src/test/lucas_fork_test).
 *
 * Source-level C view:
 *
 *   int main(void) {
 *       pid_t pid = fork();
 *       if (pid == 0) {
 *           write(1, "[fork-test] child\n", 18);
 *           _exit(42);
 *       }
 *       int status = 0;
 *       pid_t r = wait(&status);
 *       const char *msg = "[fork-test] parent reaped child\n";
 *       write(1, msg, 32);
 *       _exit(WEXITSTATUS(status) == 42 ? 0 : 1);
 *   }
 *
 * The actual translation unit ships as fork_test.S so we don't pull
 * in libc at this layer.  The .S is hand-derived from this C source
 * and committed-as-binary so the cross-compile build doesn't need a
 * host gcc.  See fork_test.S for the assembly + the Makefile.fixture
 * for the rebuild recipe.
 */

/* This .c file is documentation-only · the load-bearing source is
 * fork_test.S in the same directory.  We keep this file in tree so
 * the plan's Step 6.8 reference resolves and future maintainers see
 * the C-level intent. */
