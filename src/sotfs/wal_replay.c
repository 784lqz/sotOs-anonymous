/* sotOs · sotfs · WAL replay dispatcher · scans v2 records, dispatches
 * by kind to per-subsystem handlers.  PR 5 lands the file-only path
 * (sotfs's own FS kinds).  PR 6 extends the dispatcher to call the
 * per-subsystem replay scanners for the three non-FS kinds that have
 * live writer hooks today (PROCD_MUT, ANOMALY_EV, SOTNET_SYNTH);
 * CHECKPOINT replays land in PR 8 alongside the throttling write.
 *
 * Option B (per the PR 6 plan): ALL replay handlers run inside orch's
 * address space (the only ELF linked against sotos-sotfs).  Their
 * source lives in src/sotfs/ as replay_<subsys>.c so they have direct
 * access to the same storage_read helper sotfs_wal_replay_files uses.
 *
 * Boot-time call site: src/lucas/backends_sotfs.c lazy_init() (which
 * runs in orch's address space because lucas is statically linked
 * into the orch executable).  The dispatcher emits one line per
 * subsystem so a single boot's serial log surfaces all four replay
 * counts side-by-side.
 */
#include <stdio.h>
#include <sotfs/wal.h>
#include <sotfs/graph.h>
#include <sotguard/event.h>

/* α · PR 9 · audit-event bridge · weak-stub override lives in
 * src/orch/main.c.  Declared as `extern` so the C front-end accepts
 * the call even though the weak no-op stub is defined in wal.c. */
extern void sotfs_wal_audit_emit(uint16_t kind, uint64_t arg0);

/* PR 6 · per-subsystem replay handlers · defined in replay_procd.c /
 * replay_anomaly.c / replay_sotnet.c.  Returns count of records
 * successfully applied.  Negative return on init/IO failure would be
 * surfaced as `=0` in the boot log · we treat any non-positive return
 * as "no records applied" since the replays themselves print their
 * own diagnostic lines. */
extern int procd_wal_replay(void);
extern int anomaly_wal_replay(void);
extern int sotnet_wal_replay(void);

int sotfs_wal_replay_apply(sotfs_graph_t *g) {
    int files = sotfs_wal_replay_files(g);
    printf("[sotfs] WAL replay apply · files=%d\n", files);

    /* PR 6 · per-subsystem replays · all run in orch's address space.
     * Order: procd → anomaly → sotnet.  Independent scans · each one
     * walks the WAL from offset 0 in isolation.  This is O(N·K) for K
     * subsystems but the WAL region is bounded at 4 MiB and the per-
     * subsystem scans only memcmp-and-skip on non-matching kinds, so
     * total cost is dominated by virtio-blk sector reads (cached after
     * first pass).  PR 8+ will collapse into a single multi-handler
     * walk if profiling shows hotness. */
    int procd_n    = procd_wal_replay();
    int anomaly_n = anomaly_wal_replay();
    int sotnet_n   = sotnet_wal_replay();

    if (procd_n    < 0) procd_n    = 0;
    if (anomaly_n < 0) anomaly_n = 0;
    if (sotnet_n   < 0) sotnet_n   = 0;

    printf("[sotfs] WAL replay apply · procd=%d anomaly=%d sotnet=%d\n",
           procd_n, anomaly_n, sotnet_n);
    int total = files + procd_n + anomaly_n + sotnet_n;
    /* α · PR 9 · audit event · arg0 = total records applied across all
     * subsystems · operator sees a single REPLAY_DONE marker per cold
     * boot (and again per simreboot Phase 5). */
    sotfs_wal_audit_emit(SOTGUARD_KIND_WAL_REPLAY_DONE, (uint64_t)total);
    return total;
}
