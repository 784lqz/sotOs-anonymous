/*
 * sotOs · γ · Stage 7 demo · C-static fixture.
 *
 * Exercises the F_persistence path end-to-end via raw Linux syscalls
 * (no libc).  A Tier-2 sotbox spawned by orch writes to 4 sensitive
 * paths in sequence:
 *
 *   /etc/crontab                          (cron-driven backdoor)
 *   /root/.bashrc                         (env-var backdoor)
 *   /etc/systemd/system/backdoor.service  (unit file)
 *   /etc/systemd/system/backdoor.timer    (timer unit)
 *
 * On each open()/write() lucas's path_matcher fires, sets
 * pending_sotfs_hint |= SOTFS_HINT_FUNCTOR_PERSISTENCE, prints
 * `[lucas] persistence install · path=N (openat)`, and emits an
 * AUDIT record (kind = 0xc0 SOTGUARD_KIND_PERSISTENCE_INSTALL).
 * sotfs then sets inode.functor_persistence=1 on each inode and
 * the change persists via the WAL → virtio-blk → replay chain.
 *
 * Expected operator-visible markers in the serial log:
 *   [stage7-c] alive · running F_persistence install demo
 *   [stage7-c] crontab written · /etc/crontab
 *   [stage7-c] bashrc appended · /root/.bashrc
 *   [stage7-c] service written · /etc/systemd/system/backdoor.service
 *   [stage7-c] timer written · /etc/systemd/system/backdoor.timer
 *   [stage7-c] === STAGE 7 complete · operator: simreboot + verify ===
 *   [lucas] persistence install · path=N (openat)                 (×4)
 *   [lucas] AUDIT kind=0xc0 SOTGUARD_KIND_PERSISTENCE_INSTALL    (×4)
 *
 * Source-level C view (see stage7_demo.S for the actual asm):
 *
 *   int main(void) {
 *       write(2, "[stage7-c] alive · ...\n", ...);
 *
 *       int fd = open("/etc/crontab", O_CREAT|O_WRONLY|O_TRUNC, 0644);
 *       write(fd, "* * * * * /bin/sh -c 'curl ...'\n", ...);
 *       close(fd);
 *       write(2, "[stage7-c] crontab written ...\n", ...);
 *
 *       fd = open("/root/.bashrc", O_CREAT|O_WRONLY|O_APPEND, 0644);
 *       write(fd, "\nexport BACKDOOR=/usr/local/evil\n", ...);
 *       close(fd);
 *       write(2, "[stage7-c] bashrc appended ...\n", ...);
 *
 *       fd = open("/etc/systemd/system/backdoor.service",
 *                 O_CREAT|O_WRONLY|O_TRUNC, 0644);
 *       write(fd, "[Unit]\nDescription=Backdoor\n...\n", ...);
 *       close(fd);
 *       write(2, "[stage7-c] service written ...\n", ...);
 *
 *       fd = open("/etc/systemd/system/backdoor.timer",
 *                 O_CREAT|O_WRONLY|O_TRUNC, 0644);
 *       write(fd, "[Unit]\nDescription=Backdoor tick\n...\n", ...);
 *       close(fd);
 *       write(2, "[stage7-c] timer written ...\n", ...);
 *
 *       write(2, "[stage7-c] === STAGE 7 complete ...\n", ...);
 *       _exit(0);
 *   }
 *
 * As with the rest of the test fixtures in this tree, the load-bearing
 * source ships as stage7_demo.S (hand-derived asm · no libc · static
 * ELF · committed binary).  This .c file is kept in tree for
 * documentation and a quick C-level reference.
 *
 * Why C-static and not Python (simulated_attacker.py)?
 *   The python312 stdlib zip is not populated in the install image
 *   ("Could not find platform independent libraries"), so the Python
 *   path can't drive the demo today.  This fixture provides a
 *   non-Python end-to-end path until the stdlib bundle lands.
 */
