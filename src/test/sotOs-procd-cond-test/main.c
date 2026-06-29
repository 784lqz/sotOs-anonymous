/*
 * sotOs · procd PR 12 · futex variants smoke fixture.
 *
 * Exercises the LX_FUTEX_WAIT_BITSET / WAKE_BITSET / REQUEUE /
 * CMP_REQUEUE / WAKE_OP paths added in PR 12.  The actual translation
 * unit ships as cond_test.S because lucas's fixture spawn path is a
 * static no-libc ELF (mirror of lucas_pthread, sotOs-procd-fork-test,
 * sotOs-procd-pg-test).
 *
 * Source-level C view (logical · the fixture spawns 3 worker threads
 * via clone(CLONE_VM | CLONE_THREAD), each FUTEX_WAIT_BITSET-blocks on
 * a shared cond variable, then the main thread broadcasts via
 * FUTEX_WAKE_BITSET so all three wake at once):
 *
 *   #include <pthread.h>
 *   static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
 *   static pthread_cond_t  c = PTHREAD_COND_INITIALIZER;
 *   static int ready = 0;
 *
 *   static void *worker(void *arg) {
 *       int id = (int)(intptr_t)arg;
 *       pthread_mutex_lock(&m);
 *       while (!ready) pthread_cond_wait(&c, &m);
 *       pthread_mutex_unlock(&m);
 *       printf("[cond-test] worker %d woke\n", id);
 *       return NULL;
 *   }
 *
 *   int main(void) {
 *       pthread_t t1, t2, t3;
 *       pthread_create(&t1, NULL, worker, (void *)(intptr_t)1);
 *       pthread_create(&t2, NULL, worker, (void *)(intptr_t)2);
 *       pthread_create(&t3, NULL, worker, (void *)(intptr_t)3);
 *       sleep(1);                       // let workers park on cond
 *       pthread_mutex_lock(&m);
 *       ready = 1;
 *       pthread_cond_broadcast(&c);
 *       pthread_mutex_unlock(&m);
 *       pthread_join(t1, NULL);
 *       pthread_join(t2, NULL);
 *       pthread_join(t3, NULL);
 *       printf("[cond-test] PASS\n");
 *       return 0;
 *   }
 *
 * The .S equivalent (cond_test.S) lowers the pthread API to raw clone +
 * futex syscalls so we don't need libc.  It uses FUTEX_WAIT_BITSET +
 * FUTEX_WAKE_BITSET directly (not pthread_cond), which exercises the
 * bitset path · the REQUEUE / CMP_REQUEUE / WAKE_OP variants are
 * separately validated by the unit-test footprint in the new helpers.
 *
 * Operator-visible evidence on stdout:
 *   [cond-test] worker 1 woke
 *   [cond-test] worker 2 woke
 *   [cond-test] worker 3 woke
 *   [cond-test] PASS
 */

/* This .c file is documentation-only · the load-bearing source is
 * cond_test.S in the same directory.  We keep this file in tree so
 * future maintainers see the C-level intent.  Same pattern as
 * src/test/sotOs-procd-fork-test and src/test/sotOs-procd-pg-test. */
