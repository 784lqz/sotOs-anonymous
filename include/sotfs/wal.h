#ifndef SOTFS_WAL_H
#define SOTFS_WAL_H

#include <stdint.h>
#include <stddef.h>
#include <sotfs/graph.h>

#define SOTFS_WAL_MAGIC          0xDF50FA01u   /* "sotFS WAL v1" */
#define SOTFS_WAL_NAME_BYTES     128 /* 32 -> 64 -> 128 · match SOTFS_MAX_NAME so create/
                                      * rename/unlink WAL records carry full leaf names
                                      * (apt list filenames up to ~100 chars) un-truncated. */
#define SOTFS_WAL_MAX_BLOB       512

#define SOTFS_WAL_VERSION 2u  /* was 1 · α adds non-fs kinds */

/* v2 outer header · prepended to every record on disk.
 * Existing v1 records had no CRC and no separate header · v2 wraps
 * the old layout for FS records and uses new payload structs for
 * non-FS kinds.
 */
typedef struct {
    uint64_t seq;
    uint32_t kind;     /* sotfs_wal_kind_t */
    uint32_t len;      /* total bytes incl. this header */
    uint64_t crc64;    /* of payload bytes only */
} sotfs_wal_v2_header_t;

_Static_assert(sizeof(sotfs_wal_v2_header_t) == 24,
               "wal v2 header must be 24 B");

/* Record kinds · one per DPO rewrite. */
typedef enum {
    SOTFS_WAL_KIND_NONE        = 0,
    SOTFS_WAL_KIND_CREATE_FILE = 1,
    SOTFS_WAL_KIND_MKDIR       = 2,
    SOTFS_WAL_KIND_UNLINK      = 3,
    SOTFS_WAL_KIND_RMDIR       = 4,
    SOTFS_WAL_KIND_RENAME      = 5,
    SOTFS_WAL_KIND_WRITE       = 6,
    SOTFS_WAL_KIND_INSTALL       = 7,    /* sotFS-ζ canary installing */

    /* α · v2 non-FS kinds */
    SOTFS_WAL_KIND_PROCD_MUT      = 0x10,
    SOTFS_WAL_KIND_ANOMALY_EV    = 0x20,
    SOTFS_WAL_KIND_SOTNET_SYNTH = 0x30,
    SOTFS_WAL_KIND_CHECKPOINT     = 0xF0,
} sotfs_wal_kind_t;

typedef struct sotfs_wal_record {
    uint32_t magic;          /* SOTFS_WAL_MAGIC · validates the record */
    uint32_t length;         /* total record size including this header */
    uint64_t tx_id;          /* STO transaction id from sto_local */
    uint64_t timestamp;      /* rdtsc snapshot · debugging + ordering */
    uint16_t kind;           /* sotfs_wal_kind_t */
    uint16_t reserved;
    int32_t  parent_id;      /* for create / mkdir / unlink / rmdir / rename src */
    int32_t  target_id;      /* for write · file inode */
    int32_t  new_parent_id;  /* for rename · destination dir */
    uint32_t mode;           /* for create / mkdir */
    uint32_t offset;         /* for write */
    uint32_t blob_len;       /* bytes in blob[] · NAME for create/mkdir/etc., DATA for write/install */
    char     name[SOTFS_WAL_NAME_BYTES];     /* primary name */
    char     name2[SOTFS_WAL_NAME_BYTES];    /* secondary · for rename */
    uint8_t  blob[SOTFS_WAL_MAX_BLOB];       /* file content for write/install */
} sotfs_wal_record_t;

/* α · non-FS payloads.  Each goes inside a v2 record body following
 * the sotfs_wal_v2_header_t.  Total record bytes on disk =
 * sizeof(header) + sizeof(payload). */

typedef struct {
    uint32_t slot;
    uint32_t synthetic_pid;
    uint32_t ppid;
    uint32_t pgid;
    uint32_t sid;
    uint16_t tier;
    uint16_t functor_fs;
    uint16_t functor_net;
    uint16_t functor_proc;
    uint8_t  state;
    uint8_t  _pad[7];
    uint64_t pledge_mask;
} sotfs_wal_payload_procd_mut_t;

typedef struct {
    uint64_t timestamp;
    uint32_t pid;
    uint16_t kind;
    uint16_t _pad;
    uint32_t arg0;
    uint32_t arg1;
} sotfs_wal_payload_anomaly_ev_t;

typedef struct {
    uint32_t src_slot;
    uint32_t dst_ip_be;
    uint16_t dst_port_be;
    uint16_t _pad;
    uint32_t bytes_redirected;
} sotfs_wal_payload_sotnet_synth_t;

typedef struct {
    uint64_t epoch_seq;
    uint32_t simreboot_count;
    uint32_t shutdown_reason;
    uint64_t total_records;
} sotfs_wal_payload_checkpoint_t;

/* Budget asserts · sizes reflect actual C alignment.
 * procd_mut has uint64_t pledge_mask at end · struct align = 8, fields = 44,
 * trailing pad → 48.  anomaly_ev leads with uint64_t timestamp · struct
 * align = 8, no trailing pad needed (24 already a multiple of 8) · 24.
 * Plan-written numbers (32 / 16) ignored alignment · actuals are 48 / 24. */
_Static_assert(sizeof(sotfs_wal_payload_procd_mut_t)      == 48, "procd_mut");
_Static_assert(sizeof(sotfs_wal_payload_anomaly_ev_t)    == 24, "anomaly_ev");
_Static_assert(sizeof(sotfs_wal_payload_sotnet_synth_t) == 16, "sotnet_synth");
_Static_assert(sizeof(sotfs_wal_payload_checkpoint_t)     == 24, "checkpoint");

/* Storage backend · phase-agnostic interface · Phase 2 swaps virtio-blk. */
typedef struct sotfs_storage_ops {
    int  (*write_block)(void *backend, uint64_t offset, const void *buf, size_t len);
    int  (*read_block) (void *backend, uint64_t offset,       void *buf, size_t len);
    int  (*flush)      (void *backend);
    uint64_t (*capacity_bytes)(void *backend);
} sotfs_storage_ops_t;

typedef struct sotfs_storage {
    const sotfs_storage_ops_t *ops;
    void                      *backend_state;
} sotfs_storage_t;

/* RAM-backed storage constructor · Phase 1. */
sotfs_storage_t sotfs_storage_ram(void);

/* WAL operations · public API. */
void  sotfs_wal_init(sotfs_storage_t *storage);
int   sotfs_wal_append(const sotfs_wal_record_t *rec);
/* PR 5 · file-only replay handler (renamed from sotfs_wal_replay).
 * Public so the dispatcher in wal_replay.c can call it.  Returns the
 * count of FS records successfully applied. */
int   sotfs_wal_replay_files(sotfs_graph_t *g);
/* PR 5 · top-level WAL replay dispatcher.  Cold boot calls this.  For
 * PR 5 it only dispatches the file kinds (via sotfs_wal_replay_files);
 * PR 6 will add per-subsystem replays for the non-FS kinds. */
int   sotfs_wal_replay_apply(sotfs_graph_t *g);
void  sotfs_wal_flush(void);

/* α · v2 write cursor · used by per-subsystem writers (PR 3-4). */
uint64_t sotfs_wal_cursor(void);
uint64_t sotfs_wal_seq(void);    /* libsot · record seq counter (sotctl wal) */
/* libsot · sotctl replay-export · format up to max_records on-disk WAL records as
 * text into buf (the deception-replay timeline).  Returns bytes written. */
int sotfs_wal_export(char *buf, int cap, int max_records);

/* PR 8 · scan WAL forward and return offset of LAST CHECKPOINT record.
 * Returns SOTFS_WAL_OFFSET if no CHECKPOINT exists yet.  Used for
 * operational inspection · the per-subsystem replays in PR 6 keep
 * their full-scan behaviour for correctness (CHECKPOINT-bounded
 * replay is a future optimisation pending the durability invariant). */
uint64_t sotfs_wal_find_last_checkpoint(void);

/* PR 6 · raw storage read helper · per-subsystem replays (procd,
 * anomaly, sotnet) walk the WAL region using this thin wrapper around
 * the storage vtable's read_block.  Returns 0 on success, negative
 * errno on backend failure or pre-init.  Bytes copied are guaranteed
 * to be exactly `len` when the return is 0.  Used by replay_procd.c /
 * replay_anomaly.c / replay_sotnet.c in src/sotfs/. */
int sotfs_storage_read(uint64_t off, void *buf, uint32_t len);

/* Convenience emitters · one per kind.  Each builds a record and
 * calls sotfs_wal_append. */
void  sotfs_wal_log_create_file(uint64_t tx, int parent, const char *name, uint32_t mode);
void  sotfs_wal_log_mkdir      (uint64_t tx, int parent, const char *name, uint32_t mode);
void  sotfs_wal_log_unlink     (uint64_t tx, int parent, const char *name);
void  sotfs_wal_log_rmdir      (uint64_t tx, int parent, const char *name);
void  sotfs_wal_log_rename     (uint64_t tx, int p_src,  const char *old_name,
                                              int p_dst,  const char *new_name);
void  sotfs_wal_log_write      (uint64_t tx, int file_id, uint32_t offset,
                                  const void *buf, uint32_t len);
void  sotfs_wal_log_write_path (uint64_t tx, const char *path, uint32_t offset,
                                  const void *buf, uint32_t len);
void  sotfs_wal_log_install      (uint64_t tx, const char *path,
                                  const void *content, uint32_t len);

/* α · per-subsystem writers.  Each computes the v2 header + CRC, writes
 * to virtio-blk synchronously, returns 0 on commit, -1 on full / IO. */
int sotfs_wal_log_procd_mut    (const sotfs_wal_payload_procd_mut_t    *p);
int sotfs_wal_log_anomaly_ev  (const sotfs_wal_payload_anomaly_ev_t  *p);
int sotfs_wal_log_sotnet_synth(const sotfs_wal_payload_sotnet_synth_t *p);
int sotfs_wal_log_checkpoint   (const sotfs_wal_payload_checkpoint_t   *p);

#endif /* SOTFS_WAL_H */
