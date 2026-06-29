#ifndef SOTFS_SELFTEST_H
#define SOTFS_SELFTEST_H

/*
 * sotfs_selftest() · callable but NOT called anywhere in Phase 1.
 *
 * Phase 2 wires this in when sotFS is mounted as a LUCAS VFS backend.
 * The function is stack-hungry (~70 KiB for sotfs_graph_t g) and must
 * NOT be called from any hot path or small-stack context.
 */
void sotfs_selftest(void);

#endif /* SOTFS_SELFTEST_H */
