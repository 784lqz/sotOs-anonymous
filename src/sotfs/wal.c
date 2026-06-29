/*
 * sotOs · sotFS-γ Phase 1 · Write-Ahead Log + storage abstraction.
 *
 * Every DPO rewrite that commits emits a sotfs_wal_record_t serialized
 * to the storage backend.  Phase 1 backend is RAM; Phase 2 is virtio-blk.
 * The record format is stable across phases · once Phase 2 lands,
 * existing logs replay correctly on reboot.
 *
 * Log layout (v2): linear, append-only inside the WAL region
 * [SOTFS_WAL_OFFSET, SOTFS_WAL_OFFSET + SOTFS_WAL_REGION_BYTES).  Each
 * frame is a 24 B outer header (sotfs_wal_v2_header_t · seq + kind +
 * len + crc64) followed by a payload of `len - sizeof(header)` bytes.
 * The iterator walks forward by hdr.len; EOF is the first slot where
 * hdr.seq == 0 (the zeroed/unwritten anomaly) or hdr.len underflows.
 */
#include <sotfs/wal.h>
#include <sotfs/graph.h>
#include <sotfs/rewrite.h>
#include <sotfs/layout.h>
#include <sotfs/crc64.h>
#include <sotguard/event.h>
#include <stdio.h>
#include <string.h>
#include <sotos/string.h>

/* α · PR 9 · v0.26.0 · audit-event bridge.  Defined as a weak no-op
 * stub here so sotos-sotfs links cleanly without orch headers; the
 * real implementation lives in src/orch/main.c where it routes the
 * (kind, arg0) pair into the in-orch anomaly-log ring (the same
 * ring sotShell's `anomaly-log` reads).  Same pattern as
 * sotfs_graph_curvature_anomaly_notify in src/sotfs/graph_curvature.c. */
void sotfs_wal_audit_emit(uint16_t kind, uint64_t arg0) __attribute__((weak));
void sotfs_wal_audit_emit(uint16_t kind, uint64_t arg0)
{
    (void)kind; (void)arg0;  /* default no-op stub */
}

static sotfs_storage_t g_storage;
static uint64_t        g_wal_cursor;   /* write cursor · next record goes here (absolute backend offset) */
static uint64_t        g_wal_seq = 1;  /* v2 outer header seq counter · 0 reserved as end-of-log anomaly */
static int             g_initialised;

/* PR 8 · CHECKPOINT throttling.  Every SOTFS_WAL_CHECKPOINT_INTERVAL
 * records (any kind, including CHECKPOINT itself), the shared append
 * paths emit a periodic CHECKPOINT record so operators can locate
 * epoch boundaries in the WAL hex dump.  The in_checkpoint flag
 * prevents recursion if sotfs_wal_log_checkpoint re-enters the
 * payload writer that triggered it. */
#define SOTFS_WAL_CHECKPOINT_INTERVAL 4096u
static uint32_t g_records_since_checkpoint = 0;
static int      g_in_checkpoint = 0;

static void wal_maybe_checkpoint(void) {
    if (g_in_checkpoint) return;
    g_records_since_checkpoint++;
    if (g_records_since_checkpoint < SOTFS_WAL_CHECKPOINT_INTERVAL) return;
    g_records_since_checkpoint = 0;
    sotfs_wal_payload_checkpoint_t ck;
    memset(&ck, 0, sizeof(ck));
    ck.epoch_seq        = g_wal_seq;
    ck.simreboot_count  = 0;     /* periodic · not simreboot-driven */
    ck.shutdown_reason  = 0;
    ck.total_records    = g_wal_seq;
    g_in_checkpoint = 1;
    sotfs_wal_log_checkpoint(&ck);
    g_in_checkpoint = 0;
}

/* Public getter · PR 3-4 writer hooks use this rather than the file-static. */
uint64_t sotfs_wal_cursor(void) { return g_wal_cursor; }
/* libsot · the WAL record sequence counter (== total records appended + 1) ·
 * read by `sotctl wal` for the deception-timeline status. */
uint64_t sotfs_wal_seq(void) { return g_wal_seq; }

/* PR 6 · raw storage read helper · exposed so per-subsystem replay
 * scanners (replay_procd.c / replay_anomaly.c / replay_sotnet.c) can
 * walk the WAL region without each duplicating the storage-vtable
 * indirection.  Returns 0 on success, negative on backend error /
 * pre-init.  -22 = EINVAL (not initialised / null ops); -19 = ENODEV
 * (no read_block in vtable).  read_block returns the byte count or
 * negative on IO error · we collapse the success case to 0 to match
 * the simpler "either it all worked or it didn't" contract the
 * replays need. */
int sotfs_storage_read(uint64_t off, void *buf, uint32_t len) {
    if (!g_initialised || buf == NULL || len == 0) return -22;
    if (g_storage.ops == NULL || g_storage.ops->read_block == NULL) return -19;
    int rc = g_storage.ops->read_block(g_storage.backend_state, off, buf, len);
    if (rc < 0) return rc;
    if ((uint32_t)rc != len) return -5; /* EIO · short read */
    return 0;
}

static uint64_t rdtsc_now(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

void sotfs_wal_init(sotfs_storage_t *storage) {
    g_storage    = *storage;
    g_wal_cursor = SOTFS_WAL_OFFSET;   /* L11-γ · WAL lives at [SOTFS_WAL_OFFSET, +SOTFS_WAL_REGION_BYTES); see include/sotfs/layout.h */
    g_wal_seq    = 1;
    g_initialised = 1;
    printf("[wal] init · backend capacity=%lu bytes · WAL offset=%u (stdlib region in [0..%u))\n",
           (unsigned long)g_storage.ops->capacity_bytes(g_storage.backend_state),
           SOTFS_WAL_OFFSET, SOTFS_WAL_OFFSET);
}

int sotfs_wal_append(const sotfs_wal_record_t *rec) {
    if (!g_initialised) return -22;
    uint64_t cap = g_storage.ops->capacity_bytes(g_storage.backend_state);

    /* v2 framing · prepend a 24 B outer header carrying seq + kind + len + crc64.
     * Stamp seq with g_wal_seq but DO NOT bump until after the cap check + writes
     * succeed · prevents burning sequence numbers on failed appends. */
    sotfs_wal_v2_header_t hdr;
    hdr.seq   = g_wal_seq;
    hdr.kind  = (uint32_t)rec->kind;
    hdr.len   = (uint32_t)(sizeof(hdr) + sizeof(*rec));
    hdr.crc64 = sotfs_crc64(rec, sizeof(*rec));

    if (g_wal_cursor + hdr.len > cap) {
        printf("[wal] capacity exhausted · offset=%lu len=%u cap=%lu\n",
               (unsigned long)g_wal_cursor, hdr.len, (unsigned long)cap);
        /* α · PR 9 · audit event · operator triages WAL exhaustion
         * from anomaly-log.  arg0 = current cursor so the operator
         * sees the wrap point. */
        sotfs_wal_audit_emit(SOTGUARD_KIND_WAL_FULL_DROP, g_wal_cursor);
        return -28;
    }

    int rc = g_storage.ops->write_block(g_storage.backend_state,
                                         g_wal_cursor, &hdr, sizeof(hdr));
    if (rc < 0) return rc;
    rc = g_storage.ops->write_block(g_storage.backend_state,
                                     g_wal_cursor + sizeof(hdr),
                                     rec, sizeof(*rec));
    if (rc < 0) return rc;
    g_wal_cursor += hdr.len;
    g_wal_seq++;
    /* PR 8 · periodic CHECKPOINT throttle · in_checkpoint guard
     * prevents recursion when the CHECKPOINT itself is being written. */
    wal_maybe_checkpoint();
    return 0;
}

/* δ-1: replay is not idempotent · dup tx_ids may produce -EEXIST · ignored */
static int apply_record(sotfs_graph_t *g, const sotfs_wal_record_t *rec) {
    switch (rec->kind) {
    case SOTFS_WAL_KIND_CREATE_FILE:
        return sotfs_rewrite_create_file(g, rec->parent_id, rec->name, rec->mode);
    case SOTFS_WAL_KIND_MKDIR:
        return sotfs_rewrite_mkdir(g, rec->parent_id, rec->name, rec->mode);
    case SOTFS_WAL_KIND_UNLINK:
        return sotfs_rewrite_unlink(g, rec->parent_id, rec->name);
    case SOTFS_WAL_KIND_RMDIR:
        return sotfs_rewrite_rmdir(g, rec->parent_id, rec->name);
    case SOTFS_WAL_KIND_RENAME:
        return sotfs_rewrite_rename(g, rec->parent_id, rec->name,
                                       rec->new_parent_id, rec->name2);
    case SOTFS_WAL_KIND_WRITE:
        /* If the record carries a path (rec->name set), resolve the inode
         * by path · inode IDs are NOT stable across replay (the demo installs
         * run after replay in lazy_init, shifting allocation), so a write
         * keyed only on target_id lands on the wrong/absent inode and the
         * file replays empty.  Path resolution is stable like INSTALL.
         * Legacy writes with no name fall back to target_id. */
        if (rec->name[0] != '\0') {
            int fid = sotfs_resolve_path(g, rec->name);
            if (fid == 0) return -2; /* ENOENT · create_file record precedes it */
            return sotfs_file_write(g, fid, rec->offset, rec->blob, rec->blob_len);
        }
        return sotfs_file_write(g, rec->target_id, rec->offset,
                                   rec->blob, rec->blob_len);
    case SOTFS_WAL_KIND_INSTALL: {
        /* Install = create + write atomically.  Path stored in rec->name is
         * a full path under root (Phase 1 · /<leaf>).  Strip leading '/'. */
        const char *leaf = (rec->name[0] == '/') ? rec->name + 1 : rec->name;
        (void)sotfs_rewrite_create_file(g, g->root_id, leaf, 0644);
        int file_id = sotfs_resolve_path(g, rec->name);
        if (file_id == 0) return -2; /* ENOENT */
        return sotfs_file_write(g, file_id, 0, rec->blob, rec->blob_len);
    }
    default:
        return -22; /* EINVAL · unknown kind */
    }
}

/* PR 5 · file-only WAL replay handler.  Was sotfs_wal_replay() pre-PR-5;
 * the top-level dispatcher sotfs_wal_replay_apply() (in wal_replay.c)
 * now calls this for the FS kinds and (in PR 6) will route non-FS kinds
 * to per-subsystem replays.  Behaviour for FS kinds is identical to the
 * pre-PR-5 function: scan v2 frames, CRC-validate FS records, apply
 * via the local apply_record() switch, skip non-FS kinds, count torn
 * records, advance g_wal_cursor + g_wal_seq past the last good slot. */
int sotfs_wal_replay_files(sotfs_graph_t *g) {
    if (!g_initialised) return -22;
    uint64_t off = SOTFS_WAL_OFFSET;   /* L11-γ · WAL region starts at SOTFS_WAL_OFFSET (see include/sotfs/layout.h) */
    const uint64_t cap = SOTFS_WAL_OFFSET + SOTFS_WAL_REGION_BYTES;
    uint32_t applied = 0;
    uint32_t torn = 0;
    uint64_t last_seq = 0;

    while (off + sizeof(sotfs_wal_v2_header_t) <= cap) {
        sotfs_wal_v2_header_t hdr;
        int rc = g_storage.ops->read_block(g_storage.backend_state,
                                             off, &hdr, sizeof(hdr));
        if (rc < 0) break;
        if (hdr.seq == 0 || hdr.len < sizeof(hdr)) break;  /* end of WAL · zeroed/unwritten slot */
        if (off + hdr.len > cap) break;

        /* α · skip non-FS kinds · PR 6 routes them to per-subsystem replays. */
        if (hdr.kind >= SOTFS_WAL_KIND_PROCD_MUT) {
            off += hdr.len;
            last_seq = hdr.seq;
            continue;
        }

        /* FS record · read payload and CRC-validate. */
        if (hdr.len - sizeof(hdr) == sizeof(sotfs_wal_record_t)) {
            sotfs_wal_record_t rec;
            rc = g_storage.ops->read_block(g_storage.backend_state,
                                            off + sizeof(hdr),
                                            &rec, sizeof(rec));
            if (rc >= 0 && sotfs_crc64(&rec, sizeof(rec)) == hdr.crc64) {
                int ar = apply_record(g, &rec);
                if (ar >= 0) applied++;
            } else {
                printf("[wal] CRC mismatch · skip torn record · off=%lu seq=%lu kind=0x%x\n",
                       (unsigned long)off, (unsigned long)hdr.seq, hdr.kind);
                torn++;
                /* α · PR 9 · audit event · arg0 = seq of the torn frame
                 * so the operator can correlate against the WAL hex dump. */
                sotfs_wal_audit_emit(SOTGUARD_KIND_WAL_TORN_RECORD, hdr.seq);
            }
        }
        off += hdr.len;
        last_seq = hdr.seq;
    }

    /* Position the write cursor past the last good record · future
     * appends overwrite the partial / zeroed tail. */
    g_wal_cursor = off;
    if (last_seq >= g_wal_seq) g_wal_seq = last_seq + 1;

    printf("[wal] replay applied %u records · torn %u · last_seq=%lu cursor=%lu\n",
           applied, torn, (unsigned long)last_seq, (unsigned long)g_wal_cursor);
    return (int)applied;
}

void sotfs_wal_flush(void) {
    if (g_initialised) g_storage.ops->flush(g_storage.backend_state);
}

/* sotfs_wal_kind_t → short name (for the replay export). */
static const char *wal_kind_name(uint32_t kind) {
    switch (kind) {
    case SOTFS_WAL_KIND_CREATE_FILE: return "CREATE";
    case SOTFS_WAL_KIND_MKDIR:       return "MKDIR";
    case SOTFS_WAL_KIND_UNLINK:      return "UNLINK";
    case SOTFS_WAL_KIND_RMDIR:       return "RMDIR";
    case SOTFS_WAL_KIND_RENAME:      return "RENAME";
    case SOTFS_WAL_KIND_WRITE:       return "WRITE";
    case SOTFS_WAL_KIND_INSTALL:     return "INSTALL";
    case SOTFS_WAL_KIND_PROCD_MUT:   return "PROCD_MUT";
    case SOTFS_WAL_KIND_ANOMALY_EV:  return "ANOMALY";
    case SOTFS_WAL_KIND_SOTNET_SYNTH:return "SYNTH_NET";
    case SOTFS_WAL_KIND_CHECKPOINT:  return "CHECKPOINT";
    default:                         return "OTHER";
    }
}

/* `sotctl replay-export` · the PER-RECORD WAL reader (the deception-replay
 * timeline · was status-only).  Walks the on-disk v2 frames the replays walk and
 * FORMATS each record as a text line into `buf` (instead of applying it), so the
 * operator can export the attacker's recorded create/rename/write/synth-net/
 * anomaly timeline.  Returns bytes written; max_records bounds the output. */
int sotfs_wal_export(char *buf, int cap, int max_records) {
    if (!buf || cap < 64) return 0;
    int pos = 0;
    if (!g_initialised) {
        pos = snprintf(buf, (size_t)cap, "[sotctl] REPLAY · WAL not initialised\n");
        return pos > 0 ? pos : 0;
    }
    pos += snprintf(buf + pos, (size_t)(cap - pos),
                    "[sotctl] REPLAY · deception timeline (WAL · oldest→newest)\n");
    uint64_t off = SOTFS_WAL_OFFSET;
    const uint64_t end = SOTFS_WAL_OFFSET + SOTFS_WAL_REGION_BYTES;
    int n = 0;
    while (off + sizeof(sotfs_wal_v2_header_t) <= end &&
           n < max_records && pos < cap - 96) {
        sotfs_wal_v2_header_t hdr;
        if (g_storage.ops->read_block(g_storage.backend_state, off, &hdr, sizeof(hdr)) < 0) break;
        if (hdr.seq == 0 || hdr.len < sizeof(hdr) || off + hdr.len > end) break;
        const char *kn = wal_kind_name(hdr.kind);
        if (hdr.kind < SOTFS_WAL_KIND_PROCD_MUT &&
            hdr.len - sizeof(hdr) == sizeof(sotfs_wal_record_t)) {
            sotfs_wal_record_t rec;
            if (g_storage.ops->read_block(g_storage.backend_state,
                                          off + sizeof(hdr), &rec, sizeof(rec)) >= 0) {
                rec.name[SOTFS_WAL_NAME_BYTES - 1] = '\0';
                rec.name2[SOTFS_WAL_NAME_BYTES - 1] = '\0';
                pos += snprintf(buf + pos, (size_t)(cap - pos),
                                "[sotctl]   seq=%-4lu %-10s %s%s%s\n",
                                (unsigned long)hdr.seq, kn, rec.name,
                                rec.name2[0] ? " -> " : "", rec.name2);
            }
        } else {
            pos += snprintf(buf + pos, (size_t)(cap - pos),
                            "[sotctl]   seq=%-4lu %-10s\n", (unsigned long)hdr.seq, kn);
        }
        off += hdr.len;
        n++;
    }
    pos += snprintf(buf + pos, (size_t)(cap - pos),
                    "[sotctl]   (%d record(s) · replayable deception timeline)\n", n);
    return pos;
}

/* PR 8 · scan the WAL region forward and return the absolute storage
 * offset of the LAST CHECKPOINT record.  Walks the same v2 frames the
 * replays do · stops at the first zero/short slot (end-of-log
 * anomaly).  Returns SOTFS_WAL_OFFSET if no CHECKPOINT exists yet
 * (callers should treat that as "scan from the start").
 *
 * NOTE on replay narrowing: PR 6's per-subsystem replays scan from
 * SOTFS_WAL_OFFSET unconditionally.  Narrowing them to start at the
 * value returned by this helper would bound replay time, BUT requires
 * the invariant that CHECKPOINT is written AFTER all subsystem state
 * ≤ epoch_seq is durable.  PR 8 KEEPS the full-scan behaviour and
 * provides this helper for OPERATIONAL inspection only · a future PR
 * can wire the narrowing once the durability invariant is enforced.
 */
uint64_t sotfs_wal_find_last_checkpoint(void) {
    if (!g_initialised) return SOTFS_WAL_OFFSET;
    uint64_t off = SOTFS_WAL_OFFSET;
    const uint64_t cap = SOTFS_WAL_OFFSET + SOTFS_WAL_REGION_BYTES;
    uint64_t last_ck = SOTFS_WAL_OFFSET;
    while (off + sizeof(sotfs_wal_v2_header_t) <= cap) {
        sotfs_wal_v2_header_t hdr;
        if (sotfs_storage_read(off, &hdr, sizeof(hdr)) < 0) break;
        if (hdr.seq == 0 || hdr.len < sizeof(hdr)) break;
        if (off + hdr.len > cap) break;
        if (hdr.kind == SOTFS_WAL_KIND_CHECKPOINT) last_ck = off;
        off += hdr.len;
    }
    return last_ck;
}

/* --- per-kind emitters --- */

static void prep_header(sotfs_wal_record_t *rec, uint16_t kind, uint64_t tx) {
    memset(rec, 0, sizeof(*rec));
    rec->magic     = SOTFS_WAL_MAGIC;
    rec->length    = sizeof(*rec);
    rec->tx_id     = tx;
    rec->timestamp = rdtsc_now();
    rec->kind      = kind;
}

void sotfs_wal_log_create_file(uint64_t tx, int parent, const char *name, uint32_t mode) {
    sotfs_wal_record_t r;
    prep_header(&r, SOTFS_WAL_KIND_CREATE_FILE, tx);
    r.parent_id = parent;
    r.mode      = mode;
    sotos_strlcpy(r.name, name, SOTFS_WAL_NAME_BYTES);
    r.blob_len  = (uint32_t)strnlen(r.name, SOTFS_WAL_NAME_BYTES);
    sotfs_wal_append(&r);
    printf("[wal] tx=%lu kind=create_file parent=%d name=%s mode=%o\n",
           (unsigned long)tx, parent, r.name, mode);
}

void sotfs_wal_log_mkdir(uint64_t tx, int parent, const char *name, uint32_t mode) {
    sotfs_wal_record_t r;
    prep_header(&r, SOTFS_WAL_KIND_MKDIR, tx);
    r.parent_id = parent;
    r.mode      = mode;
    sotos_strlcpy(r.name, name, SOTFS_WAL_NAME_BYTES);
    sotfs_wal_append(&r);
    printf("[wal] tx=%lu kind=mkdir parent=%d name=%s mode=%o\n",
           (unsigned long)tx, parent, r.name, mode);
}

void sotfs_wal_log_unlink(uint64_t tx, int parent, const char *name) {
    sotfs_wal_record_t r;
    prep_header(&r, SOTFS_WAL_KIND_UNLINK, tx);
    r.parent_id = parent;
    sotos_strlcpy(r.name, name, SOTFS_WAL_NAME_BYTES);
    sotfs_wal_append(&r);
    printf("[wal] tx=%lu kind=unlink parent=%d name=%s\n",
           (unsigned long)tx, parent, r.name);
}

void sotfs_wal_log_rmdir(uint64_t tx, int parent, const char *name) {
    sotfs_wal_record_t r;
    prep_header(&r, SOTFS_WAL_KIND_RMDIR, tx);
    r.parent_id = parent;
    sotos_strlcpy(r.name, name, SOTFS_WAL_NAME_BYTES);
    sotfs_wal_append(&r);
    printf("[wal] tx=%lu kind=rmdir parent=%d name=%s\n",
           (unsigned long)tx, parent, r.name);
}

void sotfs_wal_log_rename(uint64_t tx, int p_src, const char *old_name,
                            int p_dst, const char *new_name) {
    sotfs_wal_record_t r;
    prep_header(&r, SOTFS_WAL_KIND_RENAME, tx);
    r.parent_id     = p_src;
    r.new_parent_id = p_dst;
    sotos_strlcpy(r.name,  old_name, SOTFS_WAL_NAME_BYTES);
    sotos_strlcpy(r.name2, new_name, SOTFS_WAL_NAME_BYTES);
    sotfs_wal_append(&r);
    printf("[wal] tx=%lu kind=rename %d:%s -> %d:%s\n",
           (unsigned long)tx, p_src, r.name, p_dst, r.name2);
}

void sotfs_wal_log_write(uint64_t tx, int file_id, uint32_t offset,
                          const void *buf, uint32_t len) {
    sotfs_wal_record_t r;
    prep_header(&r, SOTFS_WAL_KIND_WRITE, tx);
    r.target_id = file_id;
    r.offset    = offset;
    uint32_t n = len > SOTFS_WAL_MAX_BLOB ? SOTFS_WAL_MAX_BLOB : len;
    r.blob_len  = n;
    memcpy(r.blob, buf, n);
    sotfs_wal_append(&r);
    printf("[wal] tx=%lu kind=write inode=%d off=%u len=%u\n",
           (unsigned long)tx, file_id, offset, len);
}

/* Path-keyed write · replay resolves the inode by path (stable across
 * reboots) instead of target_id (which is not).  Used by sotnano's
 * chunked save so edited files survive simreboot. */
void sotfs_wal_log_write_path(uint64_t tx, const char *path, uint32_t offset,
                              const void *buf, uint32_t len) {
    sotfs_wal_record_t r;
    prep_header(&r, SOTFS_WAL_KIND_WRITE, tx);
    r.target_id = 0;
    r.offset    = offset;
    if (path) {
        size_t pl = strlen(path);
        if (pl >= SOTFS_WAL_NAME_BYTES) pl = SOTFS_WAL_NAME_BYTES - 1;
        memcpy(r.name, path, pl);
        r.name[pl] = '\0';
    }
    uint32_t n = len > SOTFS_WAL_MAX_BLOB ? SOTFS_WAL_MAX_BLOB : len;
    r.blob_len  = n;
    memcpy(r.blob, buf, n);
    sotfs_wal_append(&r);
    printf("[wal] tx=%lu kind=write path=%s off=%u len=%u\n",
           (unsigned long)tx, path ? path : "?", offset, len);
}

void sotfs_wal_log_install(uint64_t tx, const char *path,
                          const void *content, uint32_t len) {
    sotfs_wal_record_t r;
    prep_header(&r, SOTFS_WAL_KIND_INSTALL, tx);
    sotos_strlcpy(r.name, path, SOTFS_WAL_NAME_BYTES);
    uint32_t n = len > SOTFS_WAL_MAX_BLOB ? SOTFS_WAL_MAX_BLOB : len;
    r.blob_len = n;
    memcpy(r.blob, content, n);
    sotfs_wal_append(&r);
    printf("[wal] tx=%lu kind=install path=%s len=%u\n",
           (unsigned long)tx, path, len);
}

/* α · per-subsystem WAL writers (PR 1 declared prototypes · PR 3 lands
 * the implementations).  Each builds a v2 outer header for the payload
 * type, CRC-stamps the payload, and appends the frame to the storage
 * backend at g_wal_cursor.  Pre-init mutations are rejected with
 * -EINVAL so the writer is safe to call from any subsystem (PR 4 wires
 * the actual cross-process IPC).
 *
 * Cap check matches sotfs_wal_append's discipline · seq is bumped only
 * after both writes succeed so failed appends don't burn sequence
 * numbers.  Returns:
 *    0       · committed
 *   -EINVAL  · null payload or pre-init
 *   -ENOSPC  · WAL region full
 *   negative · storage backend IO error
 */
static int sotfs_wal_log_payload(uint32_t kind, const void *p, uint32_t len) {
    if (!g_initialised) return -22;
    if (p == NULL || len == 0) return -22;
    uint64_t cap = SOTFS_WAL_OFFSET + SOTFS_WAL_REGION_BYTES;

    sotfs_wal_v2_header_t hdr;
    hdr.seq   = g_wal_seq;
    hdr.kind  = kind;
    hdr.len   = (uint32_t)(sizeof(hdr) + len);
    hdr.crc64 = sotfs_crc64(p, len);

    if (g_wal_cursor + hdr.len > cap) {
        printf("[wal] capacity exhausted · offset=%lu len=%u cap=%lu kind=0x%x\n",
               (unsigned long)g_wal_cursor, hdr.len, (unsigned long)cap, kind);
        /* α · PR 9 · same audit event as the FS-record path · operator
         * sees the wrap regardless of which writer hit the cap first. */
        sotfs_wal_audit_emit(SOTGUARD_KIND_WAL_FULL_DROP, g_wal_cursor);
        return -28; /* ENOSPC */
    }

    int rc = g_storage.ops->write_block(g_storage.backend_state,
                                          g_wal_cursor, &hdr, sizeof(hdr));
    if (rc < 0) return rc;
    rc = g_storage.ops->write_block(g_storage.backend_state,
                                      g_wal_cursor + sizeof(hdr), p, len);
    if (rc < 0) return rc;
    g_wal_cursor += hdr.len;
    g_wal_seq++;
    /* PR 8 · periodic CHECKPOINT throttle · shared with the FS path.
     * The g_in_checkpoint flag in wal_maybe_checkpoint prevents the
     * CHECKPOINT-driven append from recursively triggering another
     * CHECKPOINT.  Counter includes CHECKPOINT records themselves so
     * the cadence is exactly 1 per 4096 frames. */
    wal_maybe_checkpoint();
    return 0;
}

int sotfs_wal_log_procd_mut(const sotfs_wal_payload_procd_mut_t *p) {
    int rc = sotfs_wal_log_payload(SOTFS_WAL_KIND_PROCD_MUT, p, sizeof(*p));
    if (rc == 0) {
        printf("[wal] kind=procd_mut slot=%u synthetic_pid=%u tier=%u "
               "state=%u pledge=0x%llx\n",
               p->slot, p->synthetic_pid, (unsigned)p->tier,
               (unsigned)p->state, (unsigned long long)p->pledge_mask);
    }
    return rc;
}

int sotfs_wal_log_anomaly_ev(const sotfs_wal_payload_anomaly_ev_t *p) {
    int rc = sotfs_wal_log_payload(SOTFS_WAL_KIND_ANOMALY_EV, p, sizeof(*p));
    if (rc == 0) {
        printf("[wal] kind=anomaly_ev pid=%u kind=%u arg0=%u arg1=%u\n",
               p->pid, (unsigned)p->kind, p->arg0, p->arg1);
    }
    return rc;
}

int sotfs_wal_log_sotnet_synth(const sotfs_wal_payload_sotnet_synth_t *p) {
    int rc = sotfs_wal_log_payload(SOTFS_WAL_KIND_SOTNET_SYNTH, p, sizeof(*p));
    if (rc == 0) {
        printf("[wal] kind=sotnet_synth src_slot=%u dst_ip=0x%x:%u bytes=%u\n",
               p->src_slot, p->dst_ip_be,
               (unsigned)p->dst_port_be, p->bytes_redirected);
    }
    return rc;
}

int sotfs_wal_log_checkpoint(const sotfs_wal_payload_checkpoint_t *p) {
    int rc = sotfs_wal_log_payload(SOTFS_WAL_KIND_CHECKPOINT, p, sizeof(*p));
    if (rc == 0) {
        printf("[wal] kind=checkpoint epoch_seq=%lu simreboot_count=%u "
               "shutdown_reason=%u total_records=%lu\n",
               (unsigned long)p->epoch_seq, p->simreboot_count,
               p->shutdown_reason, (unsigned long)p->total_records);
    }
    return rc;
}
