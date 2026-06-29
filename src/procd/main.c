/* sotOs · procd · process server.
 *
 * Path D process spawned by root. Owns the authoritative composition
 * of every sotOs process (TCB+CSpace+VSpace+tier+functor) and acts as
 * the policy gate for tier/functor mutations from Anomaly.
 *
 * argv[0] = "sotOs-procd"
 * argv[1] = procd listen EP slot in procd's CSpace
 * argv[2] = (optional) PR 4 · notification slot in procd's CSpace; if
 *           present, procd seL4_Signals on it after publishing each
 *           event so subscribers (orch first) can wake up + drain.
 * argv[4] = (optional) procd-authoritative-GC · RW vaddr of the 1 MiB SHM
 *           that root cross-mapped into procd's vspace (and RO into orch).
 *           When present procd initializes the shared frames (visible RO to
 *           orch) instead of the private .bss buffer.
 *
 * PR 5 · CROSSING-OF-RUBICON · the idle Yield loop is replaced by a real
 * IPC dispatcher.  Requests arrive packed in MRs (MR(0)=op, MR(1..)=op-
 * specific payload).  For OP_SPAWN today we accept caller_slot in MR(1),
 * initial_tier in MR(2), and the pledge mask split across MR(3) (lo32)
 * and MR(4) (hi32).  Cross-vspace SHM scratch passing is deferred to
 * PR 6+ when ops need bigger payloads.
 *
 * Spec: procd-process-server-design
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sel4/sel4.h>
#include <procd/proto.h>
#include <procd/proc.h>
#include <procd/shm.h>
#include <procd/events.h>
#include <procd/functor.h>
#include <sotfs/wal.h>      /* PR 3 · sotfs_wal_payload_procd_mut_t */
#include <sotfs/wal_ipc.h>  /* PR 4 · SOTFS_OP_WAL_LOG wire op */

/* PR 3 · WAL writer attach flag · referenced by procd_wal_log_p in
 * include/procd/wal_log_helper.h.  Stays 0 until PR 4's IPC stub
 * verifies a non-zero g_sotfs_wal_ep slot from argv[3]; after that
 * point procd_wal_log_p starts mirroring every proc_t mutation into
 * the sotfs WAL via SOTFS_OP_WAL_LOG. */
int g_wal_attached = 0;

/* α · PR 4 · sotfs WAL EP cap in procd's CSpace.  Minted by root from
 * orch's listen EP (unbadged · op label routes the call).  The IPC
 * stub below seL4_Calls this slot with SOTFS_OP_WAL_LOG and packs the
 * 48-byte procd_mut payload into MR(2..7).  0 until argv[3] arrives. */
seL4_CPtr g_sotfs_wal_ep = 0;

/* α · PR 4 · cross-process WAL writer IPC client.  Sends the procd_mut
 * payload to orch over the WAL EP and returns the orch-side rc.  Payload
 * is 48 B = 6 MRs (matches sotfs_wal_payload_procd_mut_t alignment).
 *
 * On the wire:
 *   call info · label = SOTFS_OP_WAL_LOG, length = 8 words
 *   MR(0) = op label echo (some seL4 configs put label in MR(0) too · safe to set)
 *   MR(1) = kind = SOTFS_WAL_KIND_PROCD_MUT
 *   MR(2..7) = 48 B payload packed as 6 uint64_t MRs
 *
 * Reply · MR(0) = rc.  Errors propagate up unchanged so the caller can
 * decide whether to surface them; procd_wal_log_p discards rc with
 * (void) because the inline helper is best-effort. */
int sotfs_wal_log_procd_mut(const sotfs_wal_payload_procd_mut_t *p) {
    if (g_sotfs_wal_ep == 0) return -38; /* -ENOSYS · WAL EP not wired */
    if (p == NULL) return -22;            /* -EINVAL */

    /* Pack the 48-byte payload into 6 MRs (MR(2..7)).  The struct is
     * uint64_t-aligned (pledge_mask trailing) so a direct cast is sound.
     * Compile-time sanity check guards future field reordering. */
    _Static_assert(sizeof(sotfs_wal_payload_procd_mut_t) == 48,
                   "procd_mut must remain 48 B for 6-MR packing");
    const uint64_t *src = (const uint64_t *)p;
    seL4_SetMR(0, (seL4_Word)SOTFS_OP_WAL_LOG);
    seL4_SetMR(1, (seL4_Word)SOTFS_WAL_KIND_PROCD_MUT);
    for (int i = 0; i < 6; i++) {
        seL4_SetMR(2 + i, (seL4_Word)src[i]);
    }
    seL4_MessageInfo_t info = seL4_MessageInfo_new(SOTFS_OP_WAL_LOG,
                                                    0, 0, 8);
    (void)seL4_Call(g_sotfs_wal_ep, info);
    return (int)seL4_GetMR(0);
}

extern void *procd_shm_init(void *shm_base);
extern procd_reply_t procd_handle_spawn      (const procd_request_t *req);
extern procd_reply_t procd_handle_fork       (const procd_request_t *req);
extern procd_reply_t procd_handle_exit       (const procd_request_t *req);
extern procd_reply_t procd_handle_wait       (const procd_request_t *req);
extern procd_reply_t procd_handle_exec       (const procd_request_t *req);
extern procd_reply_t procd_handle_clone      (const procd_request_t *req);
extern procd_reply_t procd_handle_thread_exit(const procd_request_t *req);
extern procd_reply_t procd_handle_set_robust (const procd_request_t *req);
extern procd_reply_t procd_handle_setsid     (const procd_request_t *req);
extern procd_reply_t procd_handle_setpgid    (const procd_request_t *req,
                                               uint32_t target_pid,
                                               uint32_t new_pgid);
extern procd_reply_t procd_handle_getpgid    (const procd_request_t *req,
                                               uint32_t target_pid);
/* PR 10 · badge-gated tier mutation + functor rebind.  Both ops carry
 * the caller badge as their first argument so the handler can verify
 * the anomaly's badged-EP origin before mutating proc_t under the
 * seqlock.  Any other badge / unbadged caller is rejected with -EPERM
 * and a PROCD_EV_BADGE_REJECT audit event. */
extern procd_reply_t procd_handle_set_tier   (seL4_Word badge,
                                               const procd_request_t *req,
                                               uint32_t new_tier_arg);
extern procd_reply_t procd_handle_rebind_functor(seL4_Word badge,
                                                  const procd_request_t *req,
                                                  uint32_t new_fs,
                                                  uint32_t new_net,
                                                  uint32_t new_proc);
/* ABI v2 · post-spawn cow_session + comm update.  comm_present==0 leaves
 * comm unchanged (cow_session-only path · e.g. SSH login); 1 sets comm too
 * (execve path). */
extern procd_reply_t procd_handle_set_session(const procd_request_t *req,
                                               uint32_t comm_present);

int main(int argc, char *argv[]) {
    seL4_CPtr listen_ep = (argc > 1) ? (seL4_CPtr)atol(argv[1]) : 0;
    seL4_CPtr ev_ntf    = (argc > 2) ? (seL4_CPtr)atol(argv[2]) : 0;
    /* α · PR 4 · WAL EP slot (orch listen, unbadged copy minted by root).
     * The cap is captured for diagnostics only.
     *
     * IMPORTANT · g_wal_attached stays 0 PERMANENTLY by design (not deferred).
     * A synchronous seL4_Call from a procd handler back into orch's listen EP
     * would deadlock: every procd lifecycle handler is itself invoked via
     * seL4_Call from orch/lucas, so orch is blocked waiting for procd's reply
     * at that moment and NOT in seL4_Recv.  The procd→orch WAL IPC could never
     * complete.  The procd-authoritative-GC arc RETIRED this path entirely:
     * procd's proc_t state reaches the WAL from ORCH's side instead — orch
     * reads procd's RO-mapped table (g_procd_shm_ro) and writes procd_mut
     * records in-process (boot + poweroff snapshots in sotfs/replay_procd.c,
     * and a per-event continuous mirror in orch_procd_drain).  No procd→orch
     * call, no deadlock.  procd just publishes events to the SHM ring; orch
     * does the durable logging. */
    seL4_CPtr wal_ep    = (argc > 3) ? (seL4_CPtr)atol(argv[3]) : 0;
    /* procd-authoritative-GC · argv[4] = RW vaddr of the 1 MiB SHM that root
     * cross-mapped into our vspace (and RO into orch).  NULL/absent → fall
     * back to the private .bss buffer (NTF-only legacy mode). */
    void *shm_base      = (argc > 4) ? (void *)(uintptr_t)atol(argv[4]) : (void *)0;

    if (wal_ep != 0) {
        g_sotfs_wal_ep = wal_ep;
        /* RETIRED by design · the blocking procd→orch WAL IPC would deadlock
         * (see comment above).  WAL durability of proc_t now comes from orch's
         * side via g_procd_shm_ro · this gate stays 0 permanently. */
        g_wal_attached = 0;
        printf("[procd] WAL EP captured · wal_ep=%lu (g_wal_attached=0 · WAL written by orch · blocking path retired)\n",
               (unsigned long)wal_ep);
    } else {
        printf("[procd] WAL writer disabled · no wal_ep in argv[3]\n");
    }

    printf("[procd] alive · ep=%lu ntf=%lu wal_ep=%lu\n",
           (unsigned long)listen_ep, (unsigned long)ev_ntf,
           (unsigned long)wal_ep);
    printf("[procd] abi v%u · sizeof(proc_t)=%zu thread_t=%zu req=%zu reply=%zu event=%zu\n",
           (unsigned)PROCD_ABI_VERSION,
           sizeof(proc_t), sizeof(thread_t),
           sizeof(procd_request_t), sizeof(procd_reply_t),
           sizeof(procd_event_t));

    /* PR 3 · bring up the SHM region + slot tables in our own address
     * space.  The region is a static .bss buffer for now; PR 4 keeps
     * it that way (NTF-only fallback per the plan).  PR 5 promotes it
     * to a frame-backed mapping shared RO with subscribers as part of
     * the OP_SPAWN migration. */
    void *shm = procd_shm_init(shm_base);
    procd_shm_header_t *h = (procd_shm_header_t *)shm;
    printf("[procd] shm ready · base=%p magic=0x%lx abi=%u table_n=%u\n",
           shm, (unsigned long)h->magic, h->abi_version, h->table_n);

    /* PR 4 smoke marker: publish one event so subscribers can verify
     * the channel.  Today we only have the NTF half wired into orch
     * (NTF-only fallback); the actual ring drain on the orch side
     * lands in PR 5 once SHM is mapped cross-vspace. */
    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_PROC_BORN, 0, 0xC0FFEE);
        printf("[procd] event channel marker published · kind=0x10 slot=0 extra=0xC0FFEE\n");
        if (ev_ntf) {
            seL4_Signal(ev_ntf);
            printf("[procd] signaled subscriber NTF · slot=%lu\n",
                   (unsigned long)ev_ntf);
        }
    } else {
        printf("[procd] event ring unavailable · marker not published\n");
    }

    /* PR 5 · enter the IPC dispatcher.  Without a valid listen EP we
     * fall back to the PR 4 idle loop so a broken Phase 1 mint doesn't
     * lock procd out of debugging.  In normal boots listen_ep is the
     * EP that orch calls into via the procd_listen_ep_slot delegated
     * through BOOTSTRAP. */
    if (listen_ep == 0) {
        printf("[procd] no listen EP · idling\n");
        while (1) seL4_Yield();
    }

    printf("[procd] dispatcher entering · listen_ep=%lu\n",
           (unsigned long)listen_ep);

    while (1) {
        seL4_Word badge = 0;
        seL4_MessageInfo_t info = seL4_Recv(listen_ep, &badge);
        (void)info;
        seL4_Word op = seL4_GetMR(0);

        procd_request_t req;
        memset(&req, 0, sizeof(req));
        req.op           = (uint32_t)op;
        req.caller_slot  = (uint32_t)seL4_GetMR(1);

        /* MR unpack · per-op layout.  Future ops with bigger payloads
         * use the SHM scratch region (lands once cross-vspace SHM is
         * mapped · PR 7+). */
        if (op == PROCD_OP_SPAWN) {
            req.spawn.initial_tier   = (uint32_t)seL4_GetMR(2);
            uint64_t pl_lo           = (uint64_t)seL4_GetMR(3);
            uint64_t pl_hi           = (uint64_t)seL4_GetMR(4);
            req.spawn.initial_pledge = (pl_hi << 32) | (pl_lo & 0xFFFFFFFFull);
            /* ABI v2 · comm[16] packed in MR5,MR6.  memcpy out of two words
             * so we don't assume host endianness in the field layout. */
            uint64_t c_lo            = (uint64_t)seL4_GetMR(5);
            uint64_t c_hi            = (uint64_t)seL4_GetMR(6);
            memcpy(req.spawn.comm,     &c_lo, 8);
            memcpy(req.spawn.comm + 8, &c_hi, 8);
            req.spawn.comm[15] = '\0';
        } else if (op == PROCD_OP_SET_SESSION) {
            /* ABI v2 · post-spawn cow_session + comm update.
             * MR(1) reused as target_slot (caller_slot above already holds it). */
            req.set_session.target_slot = (uint32_t)seL4_GetMR(1);
            req.set_session.cow_session = (uint32_t)seL4_GetMR(2);
            uint64_t c_lo               = (uint64_t)seL4_GetMR(3);
            uint64_t c_hi               = (uint64_t)seL4_GetMR(4);
            memcpy(req.set_session.comm,     &c_lo, 8);
            memcpy(req.set_session.comm + 8, &c_hi, 8);
            req.set_session.comm[15] = '\0';
            /* MR(5) = comm_present · stashed in op-local; passed to handler below. */
        } else if (op == PROCD_OP_FORK) {
            /* No extra payload · MR(1) (caller_slot) is the parent slot. */
        } else if (op == PROCD_OP_EXIT) {
            req.exit.exit_status = (int32_t)seL4_GetMR(2);
        } else if (op == PROCD_OP_WAIT) {
            req.wait.which   = (int32_t)seL4_GetMR(2);
            req.wait.options = (int32_t)seL4_GetMR(3);
        } else if (op == PROCD_OP_EXEC) {
            /* No extra payload · MR(1) (caller_slot) identifies the
             * sotbox whose image was just replaced.  PR 10+ may add
             * a new-tier / new-functor flag here. */
        } else if (op == PROCD_OP_CLONE) {
            /* PR 8 · thread-path clone.  We carry the minimal payload
             * that procd needs to record the thread_t entry (flags +
             * tls + child_tid_ptr); the remaining clone fields
             * (child_stack, parent_tid, start_func) are lucas-side
             * mechanics and stay out of the announce wire for now. */
            req.clone.flags         = (uint64_t)seL4_GetMR(2);
            req.clone.tls           = (uint64_t)seL4_GetMR(3);
            req.clone.child_tid_ptr = (uint64_t)seL4_GetMR(4);
        } else if (op == PROCD_OP_THREAD_EXIT) {
            /* PR 8 · thread exit · MR(2) is the procd-assigned synthetic_tid
             * from the matching OP_CLONE reply. */
            req.thread_exit.tid     = (uint32_t)seL4_GetMR(2);
        } else if (op == PROCD_OP_SET_ROBUST) {
            /* PR 13 · per-thread robust_list_head registration.
             * MR(2) = procd-assigned tid (0 = main thread anomaly).
             * MR(3) = user vaddr of the robust_list_head struct. */
            req.set_robust.tid         = (uint32_t)seL4_GetMR(2);
            req.set_robust.robust_head = (uint64_t)seL4_GetMR(3);
        }

        procd_reply_t rep = { .result = -38 /* -ENOSYS */,
                               .out_slot = 0,
                               .out_extra = 0 };

        switch (op) {
            case PROCD_OP_SPAWN:
                rep = procd_handle_spawn(&req);
                /* If we just published PROC_BORN, signal the subscriber
                 * NTF so orch's main loop wakes up + drains the ring on
                 * its next pass (in PR 4-style NTF-only mode the wake
                 * is enough · PR 5 leaves the SHM-drain branch dormant
                 * since SHM is not yet cross-mapped, see plan). */
                if (rep.result >= 0 && ev_ntf) {
                    seL4_Signal(ev_ntf);
                }
                break;
            case PROCD_OP_FORK:
                rep = procd_handle_fork(&req);
                /* Same NTF-wake invariant as SPAWN · a fork publishes
                 * PROC_BORN so subscribers want to drain the ring. */
                if (rep.result >= 0 && ev_ntf) {
                    seL4_Signal(ev_ntf);
                }
                break;
            case PROCD_OP_EXIT:
                rep = procd_handle_exit(&req);
                /* Exit publishes PROC_EXITED + SIGCHLD; both want wake. */
                if (rep.result >= 0 && ev_ntf) {
                    seL4_Signal(ev_ntf);
                }
                break;
            case PROCD_OP_WAIT:
                rep = procd_handle_wait(&req);
                /* PROC_REAPED is published when a zombie was found. */
                if (rep.result > 0 && ev_ntf) {
                    seL4_Signal(ev_ntf);
                }
                break;
            case PROCD_OP_EXEC:
                rep = procd_handle_exec(&req);
                /* Publishes PROCD_EV_EXEC_OK · wake subscribers. */
                if (rep.result >= 0 && ev_ntf) {
                    seL4_Signal(ev_ntf);
                }
                break;
            case PROCD_OP_CLONE:
                rep = procd_handle_clone(&req);
                /* On success publishes PROCD_EV_THREAD_BORN; on the
                 * -ENOSYS rejection path publishes CLONE_FLAG_ENOSYS —
                 * both want a wake so observers see the event without
                 * waiting for the next op. */
                if (ev_ntf) {
                    seL4_Signal(ev_ntf);
                }
                break;
            case PROCD_OP_THREAD_EXIT:
                rep = procd_handle_thread_exit(&req);
                /* Publishes PROCD_EV_THREAD_EXITED on success · wake
                 * subscribers so the audit cursor advances quickly. */
                if (rep.result >= 0 && ev_ntf) {
                    seL4_Signal(ev_ntf);
                }
                break;
            /* PR 13 · OP_SET_ROBUST · per-thread robust_list_head
             * registration.  No event published (audit-only mutation
             * of thread_t.robust_list_head) · subscribers don't need a
             * wake on every pthread init. */
            case PROCD_OP_SET_ROBUST:
                rep = procd_handle_set_robust(&req);
                break;
            /* PR 9 · OP_SETSID / OP_SETPGID / OP_GETPGID · pure proc_t
             * accounting (no seL4 mechanics).  Necessary precondition for
             * shell job control and Wine basics.  MR(2)/MR(3) reads happen
             * inside the case bodies so the per-op unpack above doesn't
             * have to learn about these payloads · the dispatcher's MR
             * window is still live at this point because seL4_Reply hasn't
             * fired yet. */
            case PROCD_OP_SETSID:
                rep = procd_handle_setsid(&req);
                /* No event published for setsid in PR 9 · the audit cursor
                 * doesn't need a wake for pure accounting changes.  PR 10+
                 * may add PROCD_EV_SETSID once anomaly needs to observe
                 * session-leader transitions. */
                break;
            case PROCD_OP_SETPGID: {
                uint32_t target_pid = (uint32_t)seL4_GetMR(2);
                uint32_t new_pgid   = (uint32_t)seL4_GetMR(3);
                rep = procd_handle_setpgid(&req, target_pid, new_pgid);
                break;
            }
            case PROCD_OP_GETPGID: {
                uint32_t target_pid = (uint32_t)seL4_GetMR(2);
                rep = procd_handle_getpgid(&req, target_pid);
                break;
            }
            /* PR 10 · OP_SET_TIER · badge-gated authoritative tier mutation.
             * MR(2) = new tier (0..3).  Caller badge (read from seL4_Recv
             * above) is BADGE_ANOMALY_OP_SET_TIER (0xA009) when the
             * anomaly's badged procd EP is used; the handler rejects
             * everything else with -EPERM.  Publishes EV_TIER_CHANGED +
             * EV_FUNCTOR_REBOUND on success · wake subscribers so the
             * cross-vspace SHM readers (PR 14+) observe the new tier
             * promptly. */
            case PROCD_OP_SET_TIER: {
                uint32_t new_tier = (uint32_t)seL4_GetMR(2);
                rep = procd_handle_set_tier(badge, &req, new_tier);
                if (rep.result >= 0 && ev_ntf) {
                    seL4_Signal(ev_ntf);
                }
                break;
            }
            /* PR 10 · OP_REBIND_FUNCTOR · same badge contract as SET_TIER but
             * mutates functor_fs/functor_net/functor_proc directly without
             * touching the tier number.  Publishes EV_FUNCTOR_REBOUND only. */
            case PROCD_OP_REBIND_FUNCTOR: {
                uint32_t fs   = (uint32_t)seL4_GetMR(2);
                uint32_t net  = (uint32_t)seL4_GetMR(3);
                uint32_t proc = (uint32_t)seL4_GetMR(4);
                rep = procd_handle_rebind_functor(badge, &req, fs, net, proc);
                if (rep.result >= 0 && ev_ntf) {
                    seL4_Signal(ev_ntf);
                }
                break;
            }
            /* ABI v2 · OP_SET_SESSION · post-spawn cow_session + comm update.
             * MR(5) carries comm_present (the dispatcher's MR window is still
             * live · seL4_Reply hasn't fired yet). */
            case PROCD_OP_SET_SESSION: {
                uint32_t comm_present = (uint32_t)seL4_GetMR(5);
                rep = procd_handle_set_session(&req, comm_present);
                break;
            }
            default:
                printf("[procd] unknown op=0x%lx caller=%u\n",
                       (unsigned long)op, req.caller_slot);
                break;
        }

        seL4_SetMR(0, (seL4_Word)rep.result);
        seL4_SetMR(1, (seL4_Word)rep.out_slot);
        seL4_SetMR(2, (seL4_Word)rep.out_extra);
        seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 3));
    }
    return 0;
}
