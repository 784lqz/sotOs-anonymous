/* sotOs · sotfs · WAL replay-applies for ANOMALY_EV records (PR 6).
 *
 * Walks the WAL region scanning for SOTFS_WAL_KIND_ANOMALY_EV frames
 * and copies each into the in-orch historical events buffer.  These
 * are events that fired in some PRIOR boot · they should NOT be
 * re-emitted to the live sotguard ring (that would double-count
 * current state) and they do NOT trigger any anomaly rule eval at
 * replay time.  The buffer is a passive archive sized to 256 entries;
 * older entries past the cap are dropped (FIFO).
 *
 * The history is exposed via anomaly_replay_history_count() and
 * anomaly_replay_history_get() so future PRs can extend the
 * `anomaly-log` sotShell query to render historical alongside live
 * events.  Today the data lives in the buffer for future readout.
 *
 * Runs inside orch's address space (Option B · all replays in-orch).
 */
#include <stdio.h>
#include <string.h>
#include <sotfs/wal.h>
#include <sotfs/crc64.h>
#include <sotfs/layout.h>
#include <sotguard/event.h>

/* α · PR 9 · audit-event bridge · weak-stub override lives in
 * src/orch/main.c.  Declared as `extern` so the C front-end accepts
 * the call even though the weak no-op stub is defined in wal.c. */
extern void sotfs_wal_audit_emit(uint16_t kind, uint64_t arg0);

#define ANOMALY_REPLAY_HISTORY_MAX 256

static sotfs_wal_payload_anomaly_ev_t g_history[ANOMALY_REPLAY_HISTORY_MAX];
static uint32_t g_history_count = 0;

int anomaly_wal_replay(void) {
    uint64_t off = SOTFS_WAL_OFFSET;
    const uint64_t cap = SOTFS_WAL_OFFSET + SOTFS_WAL_REGION_BYTES;
    uint32_t restored = 0;
    uint32_t skipped_torn = 0;
    uint32_t skipped_full = 0;

    /* PR 6 · scanner is invoked once per cold boot from
     * sotfs_wal_replay_apply.  We reset the buffer on entry so a
     * second replay (e.g. from a future simreboot path) gets a clean
     * historical view rather than appending duplicate entries. */
    g_history_count = 0;

    while (off + sizeof(sotfs_wal_v2_header_t) <= cap) {
        sotfs_wal_v2_header_t hdr;
        if (sotfs_storage_read(off, &hdr, sizeof(hdr)) < 0) break;
        if (hdr.seq == 0 || hdr.len < sizeof(hdr)) break;
        if (off + hdr.len > cap) break;
        if (hdr.kind != SOTFS_WAL_KIND_ANOMALY_EV) { off += hdr.len; continue; }

        sotfs_wal_payload_anomaly_ev_t p;
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

        if (g_history_count < ANOMALY_REPLAY_HISTORY_MAX) {
            g_history[g_history_count++] = p;
            restored++;
        } else {
            skipped_full++;
        }
        off += hdr.len;
    }

    printf("[anomaly] WAL replay · %u events restored · %u torn · %u dropped(full)\n",
           restored, skipped_torn, skipped_full);
    return (int)restored;
}

/* PR 6 · history accessors.  A follow-up PR will wire these into
 * ORCH_OP_QUERY_ANOMALY_LOG so sotShell renders pre-reboot events. */
uint32_t anomaly_replay_history_count(void) { return g_history_count; }

const sotfs_wal_payload_anomaly_ev_t *anomaly_replay_history_get(uint32_t i) {
    if (i >= g_history_count) return (const sotfs_wal_payload_anomaly_ev_t *)0;
    return &g_history[i];
}
