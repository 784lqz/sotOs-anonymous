/*
 * sotOs · ANOMALY · PR 7 · weighted-score test fixture.
 *
 * Deterministic regression proof for the Spec B weighted suspicion
 * scoring engine (anomaly PRs 1-5).  Runs as a sotbox at boot and
 * drives the monitor's per-pid score across BOTH tier thresholds
 * (T1=20, T2=40) with a fixed raw-syscall sequence:
 *
 *   cred recon  open("/honey-aws-creds")  +15  → score 15 (under T1)
 *   5 writes    write(doc_fd, "x", 1) x5  +5   → score 20 (crosses T1)
 *   6 unlinks   /tmp/st_b0..b5 burst       +42 → score 62 (crosses T2)
 *
 * The unlink burst escalates super-linearly: the i-th unlink in a
 * consecutive run adds min(2*i, 12), so 2+4+6+8+10+12 = 42.  Tier 2
 * (T2=40) is crossed at the 4th unlink (20+2+4+6+8 = 40).
 *
 * Expected operator-visible markers in the serial log:
 *   [anomaly-test] alive
 *   [lucas] cred-access · pid=N path=/honey-aws-creds   (stage 1)
 *   [anomaly] pid=N reply-driven promote Tier 0 → 1    (stage 2 · T1)
 *   [functor] pid=N transition F_1 → F_2 ...            (stage 3 · T2)
 *   [anomaly-test] ALL PASS                            (smoke gate)
 *
 * The tier transitions are asserted by the SMOKE GATES against the
 * monitor's serial output (a sotbox can't reliably read its own tier).
 * This fixture only proves the syscall sequence ran to completion
 * without faulting.
 *
 * Source-level C view (see anomaly_test.S for the actual asm):
 *
 *   int main(void) {
 *       int fail = 0;
 *       write(1, "[anomaly-test] alive\n", 22);
 *
 *       // stage 0 · create six burst files + open the doc fd while
 *       //           still Tier 0 (open-with-write is gated at Tier 1).
 *       const char *bp[6] = { "/tmp/st_b0","/tmp/st_b1","/tmp/st_b2",
 *                             "/tmp/st_b3","/tmp/st_b4","/tmp/st_b5" };
 *       for (int i = 0; i < 6; i++) {
 *           int f = open(bp[i], O_CREAT|O_WRONLY, 0644);
 *           if (f < 0) fail = 1; else close(f);
 *       }
 *       int doc = open("/tmp/st_doc.bin", O_CREAT|O_WRONLY|O_TRUNC, 0644);
 *       if (doc < 0) fail = 1;
 *
 *       // stage 1 · cred recon · +15 → score 15 (under T1=20)
 *       int c = open("/honey-aws-creds", O_RDONLY);
 *       if (c < 0) fail = 1; else close(c);
 *
 *       // stage 2 · five writes · +1 each → score 20 (crosses T1)
 *       if (doc >= 0) {
 *           for (int i = 0; i < 5; i++)
 *               if (write(doc, "x", 1) != 1) fail = 1;
 *           close(doc);
 *       }
 *
 *       // stage 3 · six-unlink burst → crosses T2=40
 *       for (int i = 0; i < 6; i++)
 *           if (unlink(bp[i]) < 0) fail = 1;
 *
 *       if (!fail) write(1, "[anomaly-test] ALL PASS\n", 25);
 *       else       write(2, "[anomaly-test] FAIL\n", 21);
 *       _exit(0);
 *   }
 *
 * As with the rest of the test fixtures in this tree, the load-bearing
 * source ships as anomaly_test.S (hand-derived asm · no libc · static
 * ELF · committed binary).  This .c file is kept in tree for
 * documentation and the plan's Step 7.2 reference.
 */
