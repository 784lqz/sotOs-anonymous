/*
 * sotOs · procd PR 9 · process-group test fixture.
 *
 * Exercises the OP_SETSID + OP_SETPGID + OP_GETPGID shadow-announce
 * path against procd.  The actual translation unit ships as pg_test.S
 * so we don't pull in libc at this layer.  The .S is hand-derived from
 * this C source and committed-as-binary so the cross-compile build
 * doesn't need a host gcc.  See pg_test.S for the assembly + the
 * Makefile.fixture for the rebuild recipe.
 *
 * Source-level C view (logical · the fixture is fork-then-child-runs
 * so that procd's setsid EPERM-on-pgrp-leader rule doesn't fire on a
 * fresh slot · see pg_test.S header for the explanation):
 *
 *   int main(void) {
 *       pid_t pid = fork();
 *       if (pid == 0) {
 *           pid_t before = getpgrp();
 *           pid_t sid    = setsid();
 *           pid_t pgid   = getpgid(0);
 *           int ok = (sid > 0 && pgid == sid);
 *           printf("[pg-test] before_pgrp=%d sid=%d pgid=%d ok=%d\n",
 *                  (int)before, (int)sid, (int)pgid, ok);
 *           _exit(ok ? 0 : 1);
 *       }
 *       int status = 0;
 *       wait(&status);
 *       _exit(0);
 *   }
 *
 * The exit-code path captures the loop integrity (setsid returned a
 * positive sid + getpgid(0) returned the same value), and the stdout
 * line carries the operator-visible evidence for scripts/smoke-procd.sh.
 */

/* This .c file is documentation-only · the load-bearing source is
 * pg_test.S in the same directory.  We keep this file in tree so the
 * plan's Step 9.5 reference resolves and future maintainers see the
 * C-level intent.  Same pattern as src/test/sotOs-procd-fork-test. */
