/* sotOs · sotfs · WAL replay-applies for SOTNET_SYNTH records (PR 6).
 *
 * Walks the WAL region scanning for SOTFS_WAL_KIND_SOTNET_SYNTH
 * frames and bumps the in-orch synth counter table for each one
 * (total redirects, total bytes, per-pid redirects).  The per-pid
 * bump is only applied when src_slot falls inside the bounded
 * 1..ORCH_STATUS_MAX_ENTRIES range · the synth_replay_bump helper
 * mirrors the same clamp synth_redirect_emit uses for live calls.
 *
 * We do NOT re-issue the orch ORCH_OP_SYNTH_REDIRECT IPC to net-
 * synth · those would queue scripted-response_profile responses in net-
 * synth that have nothing to do with the current sotbox stream.
 * Replay is silent counter restoration, no side effects on the
 * live deception loop.
 *
 * Runs inside orch's address space (Option B · all replays in-orch).
 * synth.c is compiled into orch directly (see src/orch/CMakeLists.txt)
 * so the bump call is a direct local function reference.
 */
#include <stdio.h>
#include <string.h>
#include <sotfs/wal.h>
#include <sotfs/crc64.h>
#include <sotfs/layout.h>
#include <sotguard/event.h>
#include <sotnet/synth.h>

/* α · PR 9 · audit-event bridge · weak-stub override lives in
 * src/orch/main.c.  Declared as `extern` so the C front-end accepts
 * the call even though the weak no-op stub is defined in wal.c. */
extern void sotfs_wal_audit_emit(uint16_t kind, uint64_t arg0);

int sotnet_wal_replay(void) {
    uint64_t off = SOTFS_WAL_OFFSET;
    const uint64_t cap = SOTFS_WAL_OFFSET + SOTFS_WAL_REGION_BYTES;
    uint32_t restored = 0;
    uint32_t skipped_torn = 0;

    while (off + sizeof(sotfs_wal_v2_header_t) <= cap) {
        sotfs_wal_v2_header_t hdr;
        if (sotfs_storage_read(off, &hdr, sizeof(hdr)) < 0) break;
        if (hdr.seq == 0 || hdr.len < sizeof(hdr)) break;
        if (off + hdr.len > cap) break;
        if (hdr.kind != SOTFS_WAL_KIND_SOTNET_SYNTH) { off += hdr.len; continue; }

        sotfs_wal_payload_sotnet_synth_t p;
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

        synth_replay_bump(p.src_slot, p.bytes_redirected);
        restored++;
        off += hdr.len;
    }

    printf("[sotnet] WAL replay · %u synth entries restored · %u torn\n",
           restored, skipped_torn);
    return (int)restored;
}
