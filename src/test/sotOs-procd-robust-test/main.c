/*
 * sotOs · procd PR 13 · robust_list test fixture.
 *
 * Exercises the OP_SET_ROBUST shadow-announce + the kernel-side
 * robust_list walk on thread exit (FUTEX_OWNER_DIED + futex wake).
 * The actual translation unit ships as robust_test.S so the
 * cross-compile doesn't need libc · pthread mutex robust semantics
 * depend on glibc/musl runtime support that we don't have in the
 * static-no-libc fixture.  Scope reduction per the PR 13 plan note:
 *
 *   "If the robust-test is too brittle (pthread mutex robust semantics
 *    depend on glibc/musl support that may not exist in your fixture),
 *    take a scope reduction · just verify [procd] set_robust tid=N fires
 *    when pthread initializes its robust list."
 *
 * Source-level C view (logical · the .S fixture lowers this to raw
 * syscalls so we don't need pthread.h or libc):
 *
 *   #include <pthread.h>
 *   #include <linux/futex.h>
 *
 *   static pthread_mutex_t m;
 *   static int dummy_robust_head[3];
 *
 *   static void *killer(void *unused) {
 *       struct robust_list_head head = {
 *           .list = NULL, .futex_offset = 0, .list_op_pending = NULL,
 *       };
 *       syscall(SYS_set_robust_list, &head, sizeof(head));
 *       pthread_mutex_lock(&m);
 *       return NULL;  // die without unlocking
 *   }
 *
 *   int main(void) {
 *       struct robust_list_head head = {0};
 *       syscall(SYS_set_robust_list, &head, sizeof(head));
 *
 *       pthread_mutexattr_t a;
 *       pthread_mutexattr_init(&a);
 *       pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST);
 *       pthread_mutex_init(&m, &a);
 *
 *       pthread_t t;
 *       pthread_create(&t, NULL, killer, NULL);
 *       pthread_join(t, NULL);
 *
 *       int rc = pthread_mutex_lock(&m);
 *       int ok = (rc == EOWNERDEAD);
 *       printf("[robust-test] second_lock rc=%d ok=%d\n", rc, ok);
 *       return ok ? 0 : 1;
 *   }
 *
 * The .S equivalent (robust_test.S) just exercises the set_robust_list
 * syscall path: main calls it, then clone()s one worker that ALSO
 * calls it, then both exit.  The smoke-visible evidence is two
 * `[procd] set_robust tid=N head=0x...` lines · the operator-visible
 * PASS line "[robust-test] set_robust announced" confirms the fixture
 * ran end-to-end.
 *
 * Operator-visible evidence on stdout:
 *   [procd] set_robust tid=0 head=0x...
 *   [robust-test] set_robust announced
 */

/* This .c file is documentation-only · the load-bearing source is
 * robust_test.S in the same directory.  We keep this file in tree so
 * future maintainers see the C-level intent.  Same pattern as
 * sotOs-procd-fork-test, sotOs-procd-pg-test, sotOs-procd-cond-test. */
