/* sotOs · sotfs · procd_mut WAL replay + snapshot (procd-authoritative-GC).
 *
 * Two halves, both running inside orch's address space (the only place with
 * direct sotos-sotfs linkage · PR 6 design "Option B"):
 *
 * 1. procd_wal_replay() — WAL → table.  Scans the WAL for PROCD_MUT frames.
 *    The MUTATION step is INTENTIONALLY a no-op: it gates on g_procd_shm_base
 *    (the hot-path reader base, kept 0 by design — see src/orch/main.c) and
 *    orch's cross-mapping is read-only anyway, so orch cannot write procd's
 *    table.  More importantly, restoring a prior boot's proc_t records into a
 *    freshly-rebuilt table would be WRONG (those procs no longer exist).  So
 *    the procd_mut records are a forward-only DURABLE AUDIT TRAIL, not a
 *    restore source; replay scans + counts them (skipped_no_shm) for the boot
 *    log but does not apply.  Restoring authoritative state across reboot is a
 *    separate future arc (it needs procd-side replay or an orch→procd boot
 *    IPC, since orch's mapping is RO).
 *
 * 2. procd_wal_snapshot() — table → WAL.  Reads procd's live authoritative
 *    table via orch's dedicated RO view (g_procd_shm_ro) and writes a
 *    procd_mut record per live proc.  This is the WRITE side of the audit
 *    trail, invoked at WAL-init (boot snapshot) and at poweroff (final state);
 *    the per-event continuous mirror lives in orch_procd_drain.  procd's own
 *    blocking g_wal_attached path stays 0 (retired · the synchronous
 *    SOTFS_OP_WAL_LOG IPC would deadlock orch · see src/procd/main.c).
 */
#include <stdio.h>
#include <string.h>
#include <sotfs/wal.h>
#include <sotfs/crc64.h>
#include <sotfs/layout.h>
#include <sotguard/event.h>
#include <procd/proc.h>
#include <procd/shm.h>

/* α · PR 9 · audit-event bridge · weak-stub override lives in
 * src/orch/main.c.  Declared as `extern` so the C front-end accepts
 * the call even though the weak no-op stub is defined in wal.c. */
extern void sotfs_wal_audit_emit(uint16_t kind, uint64_t arg0);

/* g_procd_shm_base lives in orch's procd_client.c · kept 0 BY DESIGN (it
 * gates the latency-critical lucas/fork hot-path readers · enabling it puts a
 * 256-slot seqlock scan on every syscall · see src/orch/main.c).  Replay's
 * mutation step therefore never fires — procd_mut records are a forward audit
 * trail, not a restore source (see file header). */
extern void *g_procd_shm_base;

static proc_t *procd_shm_proc_at(uint32_t slot) {
    if (g_procd_shm_base == NULL) return NULL;
    procd_shm_header_t *hdr = (procd_shm_header_t *)g_procd_shm_base;
    if (slot == 0 || slot >= hdr->table_n) return NULL;
    return (proc_t *)((uint8_t *)g_procd_shm_base + hdr->table_ofs +
                      sizeof(proc_t) * slot);
}

int procd_wal_replay(void) {
    uint64_t off = SOTFS_WAL_OFFSET;
    const uint64_t cap = SOTFS_WAL_OFFSET + SOTFS_WAL_REGION_BYTES;
    uint32_t applied = 0;
    uint32_t scanned = 0;
    uint32_t skipped_torn = 0;
    uint32_t skipped_no_shm = 0;

    while (off + sizeof(sotfs_wal_v2_header_t) <= cap) {
        sotfs_wal_v2_header_t hdr;
        if (sotfs_storage_read(off, &hdr, sizeof(hdr)) < 0) break;
        if (hdr.seq == 0 || hdr.len < sizeof(hdr)) break;
        if (off + hdr.len > cap) break;
        if (hdr.kind != SOTFS_WAL_KIND_PROCD_MUT) { off += hdr.len; continue; }

        scanned++;
        sotfs_wal_payload_procd_mut_t p;
        if (hdr.len - sizeof(hdr) != sizeof(p)) { off += hdr.len; continue; }
        if (sotfs_storage_read(off + sizeof(hdr), &p, sizeof(p)) < 0) {
            off += hdr.len; continue;
        }
        if (sotfs_crc64(&p, sizeof(p)) != hdr.crc64) {
            skipped_torn++;
            sotfs_wal_audit_emit(SOTGUARD_KIND_WAL_TORN_RECORD, hdr.seq);
            off += hdr.len;
            continue;
        }

        proc_t *slot = procd_shm_proc_at(p.slot);
        if (slot == NULL) {
            /* EXPECTED · g_procd_shm_base is 0 by design (hot-path latency
             * protection), so this mutation step never fires.  procd_mut
             * records are a forward audit trail, not a restore source —
             * re-applying a prior boot's procs into a freshly-rebuilt table
             * would be incorrect.  Counted so the boot log shows the records
             * were seen.  See file header. */
            skipped_no_shm++;
            off += hdr.len;
            continue;
        }

        /* Last-write-wins seqlock mutation · mirrors PR 4's writer
         * which builds the payload from these same fields. */
        procd_seqlock_begin(slot);
        slot->synthetic_pid     = p.synthetic_pid;
        slot->ppid         = p.ppid;
        slot->pgid         = p.pgid;
        slot->sid          = p.sid;
        slot->tier         = (proc_tier_t)p.tier;
        slot->functor_fs   = p.functor_fs;
        slot->functor_net  = p.functor_net;
        slot->functor_proc = p.functor_proc;
        slot->state        = (proc_state_t)p.state;
        slot->pledge_mask  = p.pledge_mask;
        procd_seqlock_end(slot);
        applied++;
        off += hdr.len;
    }

    printf("[procd] WAL replay · %u applied · %u scanned · %u torn · %u no-shm\n",
           applied, scanned, skipped_torn, skipped_no_shm);
    return (int)applied;
}

/* procd-authoritative-GC · durable snapshot of procd's authoritative proc
 * table into the WAL.  The symmetric counterpart to the replay scan above:
 * replay is WAL→table, this is table→WAL.  Runs once at WAL-replay time
 * (orch's address space · WAL backend ready · g_procd_shm_base live).
 *
 * This is how procd's proc_t state reaches the WAL now that the blocking
 * procd→orch SOTFS_OP_WAL_LOG writer is retired (procd's g_wal_attached
 * stays 0 · see src/procd/main.c).  orch reads procd's RO-mapped table and
 * writes the records itself, in-process, with no IPC.  procd publishes its
 * boot-time PROC_BORN events before the WAL backend is up, so a drain-time
 * mirror would miss them; snapshotting at WAL-init captures the live table
 * regardless of event timing. */
/* orch's dedicated RO view of procd's SHM (set by orch BOOTSTRAP · main.c).
 * Distinct from g_procd_shm_base above, which gates the hot-path lucas/fork
 * readers and stays 0 by design.  The snapshot reads the live table through
 * this RO mapping without touching the latency-critical path. */
extern void *g_procd_shm_ro;

int procd_wal_snapshot(void) {
    if (g_procd_shm_ro == NULL) return 0;
    procd_shm_header_t *hdr = (procd_shm_header_t *)g_procd_shm_ro;
    if (hdr->magic != PROCD_SHM_MAGIC) return 0;
    uint32_t n = hdr->table_n;
    if (n > PROCD_MAX_PROCS) n = PROCD_MAX_PROCS;

    uint32_t wrote = 0;
    for (uint32_t slot = 1; slot < n; ++slot) {
        proc_t *p = (proc_t *)((uint8_t *)g_procd_shm_ro + hdr->table_ofs +
                               sizeof(proc_t) * slot);

        /* seqlock read · snapshot the proc_t between two even, equal version
         * reads so a concurrent procd mutation cannot tear the record. */
        proc_t snap;
        int ok = 0;
        for (int tries = 0; tries < 8; ++tries) {
            uint64_t v1 = p->version;
            if (v1 & 1ull) continue;            /* writer mid-update */
            memcpy(&snap, p, sizeof(snap));
            uint64_t v2 = p->version;
            if (v1 == v2) { ok = 1; break; }
        }
        if (!ok || snap.state == PROC_STATE_FREE) continue;

        sotfs_wal_payload_procd_mut_t rec;
        memset(&rec, 0, sizeof(rec));
        rec.slot         = snap.slot;
        rec.synthetic_pid     = snap.synthetic_pid;
        rec.ppid         = snap.ppid;
        rec.pgid         = snap.pgid;
        rec.sid          = snap.sid;
        rec.tier         = (uint16_t)snap.tier;
        rec.functor_fs   = snap.functor_fs;
        rec.functor_net  = snap.functor_net;
        rec.functor_proc = snap.functor_proc;
        rec.state        = (uint8_t)snap.state;
        rec.pledge_mask  = snap.pledge_mask;
        if (sotfs_wal_log_procd_mut(&rec) == 0) wrote++;
    }
    printf("[procd] WAL snapshot · %u proc_t record(s) durably logged\n", wrote);
    return (int)wrote;
}
