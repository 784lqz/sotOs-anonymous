#ifndef SOTFS_WAL_IPC_H
#define SOTFS_WAL_IPC_H

/*
 * sotOs · sotFS · cross-process WAL writer IPC.
 *
 * sotfs is NOT a separate process · the storage backend + WAL writer
 * live as a static library (sotos-sotfs) linked into the orch ELF.
 * Path D siblings (procd, anomaly, net-synth) run as separate
 * processes and CANNOT call sotfs_wal_log_* directly.  To let them
 * append to the same WAL we add an orch listen-EP op (SOTFS_OP_WAL_LOG)
 * that orch dispatches to the local sotfs_wal_log_* function based on
 * the payload kind carried in MR(1).
 *
 * Wire format on the EP:
 *   MR(0) = SOTFS_OP_WAL_LOG (label is op, MRs carry payload)
 *   MR(1) = kind (uint32 cast · SOTFS_WAL_KIND_* from <sotfs/wal.h>)
 *   MR(2..N) = payload bytes packed as uint64_t MRs · each payload
 *              type fits in <= 7 MRs (= 56 bytes):
 *                procd_mut     = 48 B = 6 MRs
 *                anomaly_ev   = 24 B = 3 MRs
 *                sotnet_synth= 16 B = 2 MRs
 *                checkpoint    = 24 B = 3 MRs
 *
 * Reply:
 *   MR(0) = rc  (0 on commit, negative errno on full / IO error)
 *
 * The op label uses 0x90 to stay clear of ORCH_OP_* (1..25 range).
 *
 * Callers · each subsystem owns its own g_wal_attached gate:
 *   procd    · src/procd/main.c           · 0 until argv slot is verified
 *   anomaly · src/anomaly/main.c        · 0 until argv slot is verified
 *   orch     · src/orch/main.c            · 0 until BOOTSTRAP returns;
 *                                            in-process WAL calls bypass IPC.
 */

#define SOTFS_OP_WAL_LOG  0x90

/* γ · PR 3 · per-op hint bits read by the sotfs write/create handler.
 * Producer (lucas, PR 4) sets bits before the VFS op; consumer (sotfs
 * backend) inspects req->hint after the inode is resolved/allocated and
 * stamps inode->functor_persistence accordingly.  Hints are advisory ·
 * silently ignored on unknown bits to keep ABI forward-compatible.
 *
 * The hint is plumbed via lucas_state_t.pending_sotfs_hint (set by the
 * caller right before issuing the op, cleared by the backend after it
 * applies).  There is no separate sotfs_request_t in the current
 * codebase — VFS dispatch is via direct vfs_ops_t function pointers. */
#define SOTFS_HINT_FUNCTOR_PERSISTENCE  (1u << 0)

/* α · PR 4 · per-subsystem WAL writer gate.  Each process that mirrors
 * mutations to the WAL owns its own definition of this symbol (orch:
 * src/orch/main.c, procd: src/procd/main.c, anomaly: src/anomaly/main.c).
 * Set to 1 after the subsystem confirms its WAL transport is wired
 * (BOOTSTRAP for orch, argv slot != 0 for procd / anomaly).  Producer
 * call sites gate on `if (g_wal_attached)` so a missing transport
 * silently no-ops · no rebuild required to toggle. */
extern int g_wal_attached;

#endif /* SOTFS_WAL_IPC_H */
