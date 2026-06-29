/* sotOs · lucas-orchestrator IPC protocol.
 *
 * Root sends BOOTSTRAP once at startup with cap-delegation info.
 * Root (until L4 · later: sotShell or clients) sends SPAWN to create
 * a sotBox from an ELF.  sotBoxes send themselves FORK / EXECVE /
 * WAIT4 via their fault EP and the orchestrator handles them in the
 * fault loop (in-band; see fault_loop.c).
 *
 * This header carries the OUT-OF-BAND orchestrator API.
 */

#ifndef SOTOS_ORCH_PROTO_H
#define SOTOS_ORCH_PROTO_H

#include <stdint.h>
#include <sotnet/sotnet.h>

#define ORCH_OP_BOOTSTRAP     1
#define ORCH_OP_SPAWN         2
#define ORCH_OP_SHUTDOWN      3
#define ORCH_OP_QUERY_STATUS  4
/* L4-T3: spawn a native (non-Linux) seL4 process from orch's CPIO.
 * Payload: orch_spawn_msg_t (same struct as SPAWN · only binname used).
 * Orch mints its listen EP into the child's CSpace (child reads it via
 * argv[1] per the sotos_spawn_child convention). */
#define ORCH_OP_SPAWN_NATIVE  5

/* A2 / L4-Phase-B: runtime tier promotion.
 * MR(0) = pid (synthetic_pid, i.e. slot+1), MR(1) = tier (0/1/2).
 * Returns label=0 on success, label=1 (pid out of range),
 * label=2 (pid not found). */
#define ORCH_OP_PROMOTE_TIER  6

/* A3-Phase-B: anomaly event from orch → external anomaly process.
 * MR(0) = pid       (sotbox synthetic_pid)
 * MR(1) = event_kind (1 = ANOMALY_EV_WRITE)
 * MR(2) = arg        (bytes written or similar)
 */
#define ORCH_OP_ANOMALY_EVENT 7

/* Anomaly event kinds (used in MR(1) of ORCH_OP_ANOMALY_EVENT). */
#define ANOMALY_EV_WRITE            1
#define ANOMALY_EV_OPERATOR_PROMOTE 2
#define ANOMALY_EV_PLEDGE_VIOLATION 3
#define ANOMALY_EV_NET_PRECOMMIT    4  /* sotNet-δ Phase 2 · per-tx pre-commit hook */
#define ANOMALY_EV_CURVATURE        5  /* sotFS-θ rule fires · curvature anomaly */
#define ANOMALY_EV_DNS_HIT          6  /* sotNet-ε Phase 2 · canary-domain lookup hit
                                         *  MR(0) = pid             (0 = system / bootstrap)
                                         *  MR(1) = ANOMALY_EV_DNS_HIT
                                         *  MR(2) = ip_be            (synth A record, network byte order)
                                         *  MR(3..9) = domain[0..55] (null-padded ASCII · up to 56 bytes
                                         *                            packed 8 bytes per word, MR(3)=bytes 0..7) */
#define ANOMALY_EV_TCP_OPEN         7  /* sotNet-δ-2 · TCP connection open (audit + auto-promote)
                                         *  MR(0) = pid              (originating sotbox synthetic_pid · 0 = passive/unattributed)
                                         *  MR(1) = ANOMALY_EV_TCP_OPEN
                                         *  MR(2) = remote_ip_be     (peer IP, network byte order)
                                         *  MR(3) = (remote_port_be << 16) | local_port_be (packed ports) */
#define ANOMALY_EV_MSYSCALL         8  /* OBSD-ε · syscall RIP-origin check (msyscall/pinsyscalls).
                                         * Fired by lucas_handle_one_fault when the syscall site
                                         * (rip - 2) is outside the legitimate ELF .text range ·
                                         * STAR Tier-2 auto-promote (shellcode deception).
                                         *  MR(0) = pid    (sotbox synthetic_pid)
                                         *  MR(1) = ANOMALY_EV_MSYSCALL
                                         *  MR(2) = rip    (syscall site address)
                                         *  MR(3) = sysno  (attempted syscall number) */

/* Spec B · weighted-suspicion signals (sync-origin · ride a lucas Call).
 * For these kinds the anomaly reply carries the authoritative target
 * tier in MR(0) (0/1/2); the caller (lucas) applies it via lucas_set_tier.
 * Values 16+ stay below sotguard/event.h's reserved 0x70 band. */
#define ANOMALY_EV_CRED_ACCESS     16  /* MR(2) = cred path category (0 = generic) */
#define ANOMALY_EV_UNLINK          17  /* MR(2) = bit0: unlinked path was cred/canary */
#define ANOMALY_EV_EXEC            18  /* MR(2) = 0 (reserved) */

/* procd PR 15 · audit-trail bridge.  procd publishes events through its
 * SHM ring; orch drains them and re-emits the load-bearing ones into the
 * unified anomaly-log so the operator sees a single timeline.  We do NOT
 * map one-to-one to PROCD_EV_* · only the events that matter to a human
 * operator triaging an incident get a dedicated kind.  Everything else
 * collapses to ANOMALY_EV_PROCD_OTHER with the original kind in arg1
 * (so curious operators can still decode rare events from the dump). */
#define ANOMALY_EV_PROCD_PROC_BORN        9   /* arg0=slot (synthetic_pid · same field) */
#define ANOMALY_EV_PROCD_PROC_EXITED     10   /* arg0=slot · arg1=exit_code */
#define ANOMALY_EV_PROCD_TIER_CHANGED    11   /* arg0=slot · arg1=new_tier */
#define ANOMALY_EV_PROCD_FUNCTOR_REBOUND 12   /* arg0=slot · arg1=functor_id */
#define ANOMALY_EV_PROCD_SYNTH_FORK    13   /* arg0=child_slot · arg1=parent_slot */
#define ANOMALY_EV_PROCD_DENIED_TIER3    14   /* arg0=slot · arg1=op */
#define ANOMALY_EV_PROCD_OTHER           15   /* arg0=slot · arg1=PROCD_EV_* kind
                                                 *   catch-all for thread lifecycle,
                                                 *   exec_ok, sigchld, errors, etc. */

typedef struct orch_promote_msg {
    int pid;     /* sotBox synthetic_pid */
    int tier;    /* 0/1/2 */
} orch_promote_msg_t;

#define ORCH_STATUS_MAX_ENTRIES 8

typedef struct orch_status_entry {
    int      slot_index;       /* -1 = unused slot · -2 = zombie marker */
    int      synthetic_pid;
    int      exit_code;
    int      state;            /* sotbox_state_t value */
    int      tier;             /* 0 / 1 / 2 (per spec) */
    int      silenced_write_count;  /* L6: writes silenced in Tier 1 */
    int      canary_read_count;      /* L8: Tier 2 canary-file reads */
    uint32_t pledge_violations;     /* obsd-δ: pledge violation count */
    uint32_t anomaly_triggers;     /* A3: anomaly rules fired on this sotbox */
    uint32_t synth_redirects;     /* STAR Tier-2: per-pid synth redirect count */
    uint32_t curvature_alerts;      /* STAR pillar 4 · Forman-Ricci curvature alerts */
    uint32_t display_pid;          /* OBSD-ζ · sotbox-visible getpid result */
    char     name[12];         /* program name (trimmed · was 16, -4 for anomaly field) */
} orch_status_entry_t;        /* 7*4 + 4 + 4 + 4 + 4 + 4 + 12 = 60 bytes */

typedef struct orch_status_reply {
    uint32_t entry_count;
    uint32_t pad0;
    orch_status_entry_t entries[ORCH_STATUS_MAX_ENTRIES];
} orch_status_reply_t;        /* 8 + 8*60 = 488 bytes = 61 words */

#define ORCH_MAX_DELEGATED_UNTYPEDS  32

/* Sent by root in MR(0..N) as the payload of an ORCH_OP_BOOTSTRAP message.
 * T3 populates the fields with real untyped descriptors from root's
 * bootinfo. */
typedef struct orch_bootstrap_info {
    uint32_t  untyped_count;
    uint32_t  pad0;
    uint64_t  cnode_slot_first;
    uint64_t  ut_size_bits[ORCH_MAX_DELEGATED_UNTYPEDS];
    uint64_t  ut_paddr    [ORCH_MAX_DELEGATED_UNTYPEDS];
    uint64_t  ut_is_device[ORCH_MAX_DELEGATED_UNTYPEDS];
    /* sotFS-β-Phase-B · STO server endpoint in orch's CSpace, 0 if not delegated */
    uint64_t  sto_ep_slot;
    /* virtio-blk Phase 2b · x86 IO_Port cap in orch's CSpace, 0 if not delegated.
     * TODO: tighten to sub-range 0xCF8-0xCFF + virtio device ports once BAR0 is known. */
    uint64_t  io_port_slot;
    /* Path D · EP that orch sends anomaly events on (badged BADGE_ORCH_ANOMALY_EVENT=0xA004).
     * 0 if anomaly was not pre-spawned by root (A3-Phase-B disabled). */
    uint64_t  anomaly_event_ep_slot;
    /* sotNet-γ Phase 3-A · Path D · EP that orch/synth.c sends SYNTH_REDIRECT events on.
     * 0 if sotOs-net-synth was not pre-spawned by root (Phase 3-A disabled). */
    uint64_t  synth_event_ep_slot;
    /* procd PR 4 · notification cap that procd Signals after publishing
     * to the event ring.  Orch seL4_Polls on this on every main-loop
     * pass and drains the ring (when SHM cross-mapping lands in PR 5).
     * 0 if procd was not pre-spawned by root or the NTF mint failed. */
    uint64_t  procd_event_ntf_slot;
    /* procd PR 4/5 · base vaddr of procd's 1 MiB SHM region mapped RO
     * into orch's vspace.  0 until PR 5 ships the cross-vspace mapping;
     * orch treats 0 as "drain disabled · NTF-only mode". */
    uint64_t  procd_shm_base;
    /* sotNet γ-3-γ-1 · 1 if root mapped the orch<->responder byte channel
     * (SPSC rings live at BYTEPIPE_C2P_VADDR / BYTEPIPE_P2C_VADDR · see
     * include/sotnet/bytepipe.h).  0 = disabled · both sides fall back to the
     * message-register path. */
    uint64_t  bytepipe_ready;
    /* procd PR 5 · CROSSING-OF-RUBICON · listen-EP cap in orch's CSpace
     * that orch seL4_Calls on to send OP_SPAWN (and PR 6+ OP_FORK / EXIT /
     * EXEC / ... ) to procd.  Minted by root from procd_listen_ep_obj
     * after the orch process exists.  0 if procd was not pre-spawned by
     * root or the mint failed · orch_procd_spawn short-circuits in that
     * case so the legacy orch sotbox_init path remains the source of
     * truth. */
    uint64_t  procd_listen_ep_slot;
    /* procd PR 10 · BADGED listen-EP cap in orch's CSpace with badge
     * BADGE_ANOMALY_OP_SET_TIER (0xA009) · used by lucas_set_tier() to
     * dual-write tier mutations to procd.  Distinct from
     * procd_listen_ep_slot (unbadged) because OP_SET_TIER / OP_REBIND_FUNCTOR
     * are badge-gated · the unbadged cap can't drive them.  0 if procd
     * was not pre-spawned or the badged mint failed · lucas_set_tier
     * still flips writes_silenced/is_isolated (demo invariant); procd just doesn't
     * accumulate the authoritative tier history in that case. */
    uint64_t  procd_set_tier_ep_slot;
    /* β · PR 5 · sotinit listen-EP cap in orch's CSpace.  Minted by root
     * from sotinit_listen_ep_obj after orch is spawned · orch forwards
     * the same slot to sotShell on ORCH_OP_SPAWN_NATIVE so the operator
     * can drive `systemctl list/status/start/stop` directly against
     * sotinit's operator-query IPC loop.  0 if sotinit was not
     * pre-spawned by root or the mint failed · sotShell prints
     * "sotinit EP not available" and the systemctl command short-
     * circuits.  Unbadged because sotinit accepts the wire protocol
     * verb (MR(0)) without per-caller authentication in PR 5 · badge
     * gating arrives once cron/lucas join as additional callers. */
    uint64_t  sotinit_listen_ep_slot;
    /* β · PR 9 · sotcron listen-EP cap in orch's CSpace.  Minted by root
     * from sotcron_listen_ep_obj after orch is spawned · orch forwards
     * the same slot to sotShell on ORCH_OP_SPAWN_NATIVE so the operator
     * can drive `cron list` / `cron now <timer>` directly against
     * sotcron's non-blocking IPC drain (PR 9).  0 if sotcron was not
     * pre-spawned by root or the mint failed · sotShell prints
     * "sotcron EP not available" and the cmd_cron command short-
     * circuits.  Badged with BADGE_SOTCRON_OPERATOR when forwarded into
     * sotShell so sotcron's drain can distinguish "real message arrived"
     * from "no message pending" via the badge register (the kernel
     * zeroes badge on doNBRecvFailedTransfer). */
    uint64_t  sotcron_listen_ep_slot;
    /* L12-alpha · native Wayland compositor listen EP cap in orch's CSpace.
     * Root mints this from the Path-D `sotOs-wl-compositor` process listen EP.
     * L12-beta will route connect(AF_UNIX, "/run/user/1000/wayland-0") to this
     * slot. 0 means compositor unavailable and AF_UNIX wayland-0 must fail. */
    uint64_t  wayland_listen_ep_slot;
    /* L13-A1 · compositor page-directory (PML4) cap in orch's CSpace.
     * Root mints wayland_proc.pd.cptr into orch immediately after the
     * wayland_listen_ep_slot mint (same condition: wayland_configured).
     * Orch uses this cap as the target vspace root for sel4utils_map_page
     * calls that install shared SHM frames into the compositor address space
     * (L13-A2 shm_pool).  0 if compositor was not pre-spawned or mint failed
     * → L13 SHM disabled. */
    uint64_t  wayland_pd_slot;
    /* N2-T · inbound framed transport · 1 if root mapped the SECOND (inbound)
     * byte-pipe ring pair (SPSC rings live at BYTEPIPE_IN_C2P_VADDR /
     * BYTEPIPE_IN_P2C_VADDR · see include/sotnet/bytepipe.h).  0 = inbound
     * disabled.  Appended as the LAST field (no layout/word-index change to any
     * existing EP-slot field · root serializes word-by-word). */
    uint64_t  bytepipe2_ready;
    /* L14a-A1 · shadow compositor listen EP cap in orch's CSpace.
     * Root mints the wayland-canary process's listen EP into orch so a later
     * task can route flagged-hostile clients to the shadow (away from the
     * honest compositor).  0 if shadow was not pre-spawned or mint failed
     * → L14a deception routing disabled. */
    uint64_t  wayland_canary_ep_slot;
    /* SSH canary shell (Phase B) · 1 if root mapped the THIRD (shell) byte-pipe
     * ring pair (SPSC rings at BYTEPIPE_SHELL_IN_VADDR / BYTEPIPE_SHELL_OUT_VADDR ·
     * see include/sotnet/bytepipe.h).  0 = SSH busybox shell disabled (Phase A
     * CHANNEL_DATA echo fallback).  Appended as the LAST field (no layout/word-
     * index change to any existing field · root serializes word-by-word). */
    uint64_t  bytepipe3_ready;
    /* IRQ-driven virtio-net RX · Notification cap (orch CSpace) that the kernel
     * Signals when the virtio-net IOAPIC IRQ (GSI 11, PCI INTA) fires.  orch
     * blocks/polls on it to wake on RX instead of busy-polling.  0 = root failed
     * to claim the IRQ → orch falls back to the legacy busy-poll. */
    uint64_t  virtio_net_irq_ntf_slot;
    /* IRQ-driven virtio-net RX · IRQHandler cap (orch CSpace) · orch calls
     * seL4_IRQHandler_Ack on it after servicing RX to re-arm the (level) IRQ.
     * 0 = not delegated. */
    uint64_t  virtio_net_irq_handler_slot;
    /* IRQ-driven RX for the SECOND virtio-net (the lwIP egress NIC, GSI 10 / PCI
     * INTA on QEMU i440fx).  Same shape as the δ NIC pair above: a badged
     * Notification orch waits on + the IRQHandler it Acks to re-arm.  0 = not
     * delegated → lwIP egress falls back to busy-poll. */
    uint64_t  lwip_net_irq_ntf_slot;
    uint64_t  lwip_net_irq_handler_slot;
    /* PIT (i8254 ch0) IRQHandler, bound to the SAME notification as the lwIP RX
     * IRQ above.  Gives the egress pump a periodic tick so it wakes (and runs
     * raw_poll → complete_tx) even when no RX IRQ arrives — breaks the TX-
     * completion deadlock that stalls a pure blocking-Wait at one TX-ring fill.
     * 0 = not delegated (pump stays busy-poll). */
    uint64_t  lwip_pit_irq_handler_slot;
} orch_bootstrap_info_t;

/* L3b-T6: ORCH_OP_SPAWN payload carrying binary name + argv.
 *
 * Layout:
 *   binname[64]          — null-padded CPIO filename of the ELF to spawn
 *   argc (uint32_t)      — number of argv strings (not including NULL terminator)
 *   profile (uint32_t)   — lucas_profile_t: 0=ALPINE (default) 1=UBUNTU
 *   initial_tier (uint32_t) — L6: 0=Tier0 pass-through, 1=Tier1 silenced mode
 *   trusted (uint32_t)   — SP1: 1 = operator-trusted; monitor never promotes
 *                          (occupies the former `pad1` reserved slot)
 *   pledge (uint64_t)   — obsd-δ: pledge template; 0 = use default (PLEDGE_ALL)
 *   argv_pool[368]      — sequential null-terminated argv strings
 *
 * Total = 64 + 16 + 8 + 368 = 456 bytes = 57 seL4 words.  `trusted` reused
 * the `pad1` alignment slot (the four u32 fields keep `pledge` 8-byte
 * aligned), so SP1 PR2 added the field at no size cost.
 */
#define ORCH_SPAWN_BINNAME_BYTES  64
#define ORCH_SPAWN_ARGV_BYTES     368   /* reduced by 8 to accommodate pledge field */

typedef struct orch_spawn_msg {
    char     binname[ORCH_SPAWN_BINNAME_BYTES];
    uint32_t argc;
    uint32_t profile;       /* lucas_profile_t · 0=ALPINE 1=UBUNTU */
    uint32_t initial_tier;  /* L6: 0=Tier0 1=Tier1 Silenced Mode */
    uint32_t trusted;       /* SP1 · 1 = operator-trusted · monitor never promotes
                             * (reuses the former pad1 alignment slot) */
    uint64_t pledge;        /* obsd-δ: pledge template; 0 = default (PLEDGE_ALL) */
    char     argv_pool[ORCH_SPAWN_ARGV_BYTES];  /* sequential null-terminated strings */
} orch_spawn_msg_t;  /* total = 64 + 16 + 8 + 368 = 456 bytes = 57 words */
_Static_assert(sizeof(orch_spawn_msg_t) == 456,
               "orch_spawn_msg_t must be 456 bytes (57 seL4 words) · SP1 PR2's `trusted` reused the pad1 slot");

/* sotNet-ζ · query active network flows from sotShell.
 * Orch replies with an orch_net_flows_reply_t packed into MRs. */
#define ORCH_OP_QUERY_NET_FLOWS 9

typedef struct orch_net_flows_reply {
    uint32_t flow_count;
    uint32_t pad0;
    sotnet_flow_entry_t flows[SOTNET_MAX_FLOWS];
} orch_net_flows_reply_t;

/* L4-Phase-D · operator-side VFS commands (sotShell → orch).
 * MR layout for each op is described inline below. */
#define ORCH_OP_SOTFS_LS    10
#define ORCH_OP_SOTFS_CAT   11
#define ORCH_OP_SOTFS_INSTALL 12
#define ORCH_OP_SOTFS_MKDIR 13
#define ORCH_OP_SOTFS_RM    14

/* sotNet-γ Phase 3-A · synth server event from orch → sotOs-net-synth.
 * Fired by synth_record_redirect() when a Tier 2 sotbox calls sendto.
 * MR(0) = pid          (sotbox synthetic_pid)
 * MR(1) = dst_ip_be    (destination IP, network byte order)
 * MR(2) = dst_port_be  (destination port, network byte order)
 * MR(3) = len          (payload length in bytes)
 */
#define ORCH_OP_SYNTH_REDIRECT 15

/* One directory entry returned by ORCH_OP_SOTFS_LS. */
typedef struct orch_sotfs_dirent {
    char     name[32];
    uint32_t size;
    uint8_t  kind;   /* 1=file, 2=dir */
    uint8_t  pad[3];
} orch_sotfs_dirent_t;

/* Reply struct for ORCH_OP_SOTFS_LS (up to 16 entries per call · ~81 seL4 MR
 * words, within the 120-word IPC limit).  Raised from 8 so the merged operator
 * '/' shows a believable Linux top-level (etc,bin,usr,lib,tmp,dev,var,…). */
#define ORCH_SOTFS_LS_MAX_ENTRIES 16
typedef struct orch_sotfs_ls_reply {
    uint32_t entry_count;
    uint32_t pad0;
    orch_sotfs_dirent_t entries[ORCH_SOTFS_LS_MAX_ENTRIES];
} orch_sotfs_ls_reply_t;

/* Reply struct for ORCH_OP_SOTFS_CAT (up to 512 bytes of file content). */
#define ORCH_SOTFS_CAT_MAX_BYTES 512
typedef struct orch_sotfs_cat_reply {
    int32_t  rc;          /* 0=ok, negative=error */
    uint32_t data_len;
    uint8_t  data[ORCH_SOTFS_CAT_MAX_BYTES];
} orch_sotfs_cat_reply_t;

/* Request structs (path packed as null-terminated string in a fixed buf). */
#define ORCH_SOTFS_PATH_MAX 128
typedef struct orch_sotfs_path_req {
    char path[ORCH_SOTFS_PATH_MAX];
} orch_sotfs_path_req_t;

/* INSTALL request: path + content packed. */
#define ORCH_SOTFS_INSTALL_CONTENT_MAX 256
typedef struct orch_sotfs_install_req {
    char path[ORCH_SOTFS_PATH_MAX];
    uint32_t content_len;
    uint32_t pad0;
    char content[ORCH_SOTFS_INSTALL_CONTENT_MAX];
} orch_sotfs_install_req_t;

/* sotnano · chunked offset I/O (op codes 26/27). */
#define ORCH_OP_SOTFS_WRITE_AT 26
#define ORCH_OP_SOTFS_READ_AT  27

/* A2 · rwbinstore · install (copy) a binary into the writable on-disk store.
 * src = a binstore name (bare) or a sotfs path ('/'-prefixed); dest = the
 * rwbinstore entry name to write/replace. op id 16 is taken (DNS_LIST) → 28. */
#define ORCH_OP_RWBIN_INSTALL 28
typedef struct orch_rwbin_install_req {
    char src[64];
    char dest[64];
} orch_rwbin_install_req_t;

/* Performance benchmarks · spawn a bench harness (sotOs-bench_<name>) with a
 * copy of orch's STO endpoint minted in as its argv[1] session cap. */
#define ORCH_OP_SPAWN_BENCH 29
typedef struct orch_bench_req {
    char name[32];   /* harness suffix · "baseline" → sotOs-bench_baseline */
} orch_bench_req_t;

/* Clean poweroff · persist state (WAL checkpoint + flush · like simreboot
 * Phase 1) then power off the QEMU VM via the ACPI PM1a S5 port.  No payload. */
#define ORCH_OP_POWEROFF 30

/* sotNet-γ-3-ε · operator installs a per-destination synth response_profile at runtime.
 * sotShell `synth-install <a.b.c.d> <port> <response_profile>` → orch → synth.
 * MR(0) = dst_ip_be   (destination IP, network byte order)
 * MR(1) = dst_port_be (destination port, network byte order)
 * MR(2) = response_profile_kind (response_profile_kind_t · see include/net-synth/response_profiles.h)
 */
#define ORCH_OP_SYNTH_INSTALL 31

/* N2-T · inbound framed transport · drive the inbound byte-pipe (in_c2p) from
 * an external request and read the synth's reply (in_p2c).  Opcodes 1-34 are
 * all taken; 35 is the next free value. */
#define ORCH_OP_SYNTH_INBOUND 35
void orch_inbound_push(uint16_t conn_id, uint16_t local_port, const uint8_t *data, uint32_t len);

#define ORCH_SOTFS_WRITE_AT_CHUNK 256
typedef struct {
    char     path[ORCH_SOTFS_PATH_MAX];   /* 128 */
    uint32_t offset;
    uint32_t len;
    uint8_t  truncate;                     /* 1 on first chunk → reset file to 0 */
    uint8_t  _pad[7];                      /* pad struct to a multiple of 8 bytes */
    uint8_t  data[ORCH_SOTFS_WRITE_AT_CHUNK];
} orch_sotfs_write_at_req_t;
/* reply: MessageInfo label = rc (0 ok, <0 error) */
/* CRITICAL: the MR marshalling does nw = sizeof/sizeof(seL4_Word) · if the
 * struct is not a whole number of words, the trailing bytes of data[] are
 * never transferred and the receiver reads them as zero → null bytes
 * corrupt every 256-byte save chunk.  Keep sizeof a multiple of 8. */
_Static_assert(sizeof(orch_sotfs_write_at_req_t) % sizeof(long) == 0,
               "write_at req must be a whole number of seL4 words");

#define ORCH_SOTFS_READ_AT_CHUNK 512
typedef struct {
    char     path[ORCH_SOTFS_PATH_MAX];
    uint32_t offset;
    uint32_t max;
} orch_sotfs_read_at_req_t;
typedef struct {
    int32_t  rc;       /* >=0 = bytes read, <0 = error */
    uint32_t len;
    uint8_t  data[ORCH_SOTFS_READ_AT_CHUNK];
} orch_sotfs_read_at_reply_t;

_Static_assert(sizeof(orch_sotfs_write_at_req_t)   <= 120 * sizeof(long),
               "write_at req exceeds seL4 MR budget");
_Static_assert(sizeof(orch_sotfs_read_at_reply_t)  <= 120 * sizeof(long),
               "read_at reply exceeds seL4 MR budget");

/* sotNet-ζ · DNS deception operator interface.
 * ORCH_OP_DNS_LIST  · list all canary domain entries.
 * ORCH_OP_DNS_INSTALL · operator installs a new canary domain at runtime.
 */
#define ORCH_OP_DNS_LIST  16
#define ORCH_OP_DNS_INSTALL 17

/* sotNet-γ Phase 3-C · synth server sends synthetic response BACK to orch.
 * Orch queues it for the originating sotbox's next recvfrom() (Phase 3-D).
 * MR(0) = pid          (sotbox synthetic_pid)
 * MR(1) = src_ip_be    (synth's source IP, network byte order)
 * MR(2) = src_port_be  (synth's source port, network byte order)
 * MR(3) = body_len     (byte count, max 64)
 * MR(4..) = body bytes packed 8 bytes per word (ceil(body_len/8) words)
 */
#define ORCH_OP_SYNTH_RESPONSE 18

/* sotNet-γ Phase 3-D-2 · operator-driven synth redirect trigger.
 * sotShell command `synth-trigger <dst_ip> <dst_port>` synthesizes a Tier 2
 * sendto-style redirect on demand, exercising the close-the-loop path for
 * operator demos without needing a real Tier 2 sotbox transmission.
 * MR(0) = dst_ip_be    (destination IP, network byte order)
 * MR(1) = dst_port_be  (destination port, network byte order)
 */
#define ORCH_OP_SYNTH_TRIGGER  19

/* sotNet-γ Phase 3-D-2 · pending_recv queue introspection.
 * sotShell command `synth-queue` asks orch to dump the in-orch sotnet
 * pending_recv table (synthetic synth responses awaiting recvfrom delivery
 * by LUCAS · δ-D-3 will wire the consumer side).  No payload, no reply MRs.
 */
#define ORCH_OP_SYNTH_QUEUE_DUMP 20

/* ANOMALY-DASHBOARD · sotShell `anomaly-log` command.
 * Asks orch to return the in-orch ring buffer of recent anomaly events
 * (operator promotes, pledge violations, dns hits, etc.).  Reply payload
 * is an orch_anomaly_log_reply_t packed into MRs. */
#define ORCH_OP_QUERY_ANOMALY_LOG 21

#define ORCH_ANOMALY_LOG_MAX 16   /* ring buffer depth */

typedef struct orch_anomaly_log_entry {
    uint32_t pid;          /* sotbox synthetic_pid (load-bearing index into anomaly ring) */
    uint32_t display_pid;  /* OBSD-ζ · sotbox-visible getpid result · S-PID translation
                            * filled by orch at reply time via sotbox_synthetic_to_display_pid;
                            * 0 if slot is empty / pid out of range */
    uint16_t kind;         /* ANOMALY_EV_* */
    uint16_t seq;          /* monotonic sequence */
    uint32_t pad0;
    uint64_t arg0;
    uint64_t arg1;
} orch_anomaly_log_entry_t;   /* 4 + 4 + 2 + 2 + 4 + 8 + 8 = 32 bytes = 4 words */

typedef struct orch_anomaly_log_reply {
    uint32_t count;        /* # entries returned (0..ORCH_ANOMALY_LOG_MAX) */
    uint32_t pad0;
    orch_anomaly_log_entry_t entries[ORCH_ANOMALY_LOG_MAX];
} orch_anomaly_log_reply_t;  /* 8 + 16*32 = 520 bytes = 65 words */

/* sottrace · sotShell `sottrace` snapshot. Reply = orch_trace_reply_t in MRs. */
#define ORCH_OP_QUERY_TRACE_RING 32
#define ORCH_OP_TRACE_LIVE 33   /* MR(0)=1 enable live drain, 0 disable */
#define ORCH_TRACE_REPLY_MAX 24   /* entries per reply (97 words <= 120 MR cap) */

/* sottrace · `sottrace payload <conn_id>` · paginated dump of a connection's
 * captured forensic payload (T8 store). Request: MR(0)=conn_id, MR(1)=offset.
 * Reply = orch_trace_payload_reply_t in MRs, one page per Call. */
#define ORCH_OP_QUERY_TRACE_PAYLOAD 34
#define ORCH_TRACE_PAYLOAD_PAGE 896   /* bytes per reply page (fits the seL4 MR budget) */
typedef struct orch_trace_payload_reply {
    uint16_t conn_id;
    uint16_t found;        /* 1 if the conn_id has a capture slot */
    uint32_t total_len;    /* total captured bytes */
    uint32_t dropped;      /* bytes seen past CAP */
    uint32_t page_len;     /* bytes in this page */
    uint8_t  page[ORCH_TRACE_PAYLOAD_PAGE];
} orch_trace_payload_reply_t;
_Static_assert(sizeof(orch_trace_payload_reply_t) <= 120 * sizeof(long),
    "orch_trace_payload_reply_t must fit the seL4 MR budget");

/* sottrace · P3 · `sottrace graph` · paginated dump of the process->file FS
 * mutation graph (G pid= tier= op= bytes= path= text lines built by
 * sottrace_graph_build). Request: MR(1)=offset. Reply reuses
 * orch_trace_payload_reply_t (conn_id/found unused; page carries text). */
#define ORCH_OP_QUERY_TRACE_GRAPH 36

/* Pillar-4 P4a · concurrent 3-malware validation run · seeds the 3 canonical
 * Tier-2 fixtures into a validation storage pool, runs one fault loop until all
 * exit, then frees the pool.  No payload (the triple is orch-side). */
#define ORCH_OP_VALIDATE 37

/* Interactive canary shell · sotShell `bbsh` builtin spawns a foreground
 * interactive `busybox sh -i` at Tier-2 (canary VFS).  Unlike ORCH_OP_SPAWN,
 * orch replies to sotShell ONLY AFTER the fault loop returns (busybox exit),
 * so sotShell stays blocked and does not poll the serial UART concurrently.
 * No payload (the busybox argv is orch-side). */
#define ORCH_OP_BBSH 38

/* Doom-on-sotOs phase 1 · spawn doomgeneric (doom.bin) at Tier-0 trusted.
 * doom.bin + doom1.wad are bundled in the binstore; /doom1.wad is served by
 * the doom-wad VFS backend.  orch replies immediately after spawning, then
 * runs orch_fault_loop until doom exits (200 render ticks).  No payload. */
#define ORCH_OP_DOOM 39

/* Interactive-mode default shell · sotShell sends this as the LAST demo command.
 * orch spawns the SAME `busybox sh -i` as ORCH_OP_BBSH but ONLY when a real
 * keyboard (virtio-keyboard) is present — i.e. `just run-interactive`. When
 * headless (no keyboard), orch replies immediately (no-op) so the demo + gates
 * are unchanged. This drops a `run-interactive` session into a keyboard-driven
 * on-screen busybox shell automatically. No payload. */
#define ORCH_OP_BBSH_AUTO 40

/* sotShell asks orch whether this is an interactive boot (a virtio-keyboard is
 * present · just run-interactive). orch replies with label=1 if interactive,
 * else 0. sotShell uses it to SKIP the scripted demo and drop straight into a
 * keyboard busybox terminal (no auto-demo / no churn spam). */
#define ORCH_OP_QUERY_INTERACTIVE 41

/* F12 toggle · operator console keyboard fetch.  In the interactive (GTK
 * window / virtio-keyboard) boot, the operator's sotShell reads the UART, which
 * the GTK keyboard does not feed.  ORCH_OP_GETKEY lets sotShell poll orch for a
 * keyboard byte so the operator console becomes keyboard-driven.  orch runs
 * kbd_poll() then replies:
 *   label = 0 · no byte available (non-blocking)
 *   label = 1 · one byte ready in MR(0)
 *   label = 2 · F12 pressed → sotShell switches back to the canary shell
 * Used ONLY while the operator console is active (gated sotShell-side), so the
 * headless demo / smoke serial path is unchanged. */
#define ORCH_OP_GETKEY 42

/* Badge for the sotShell command EP (orch_spawn_native mints sotShell's cap with
 * it).  orch's shell-window NBRecv MUST distinguish "real op arrived" from
 * "nothing pending": the seL4 kernel writes this badge into the badge register on
 * a successful NBRecv and zeroes it via doNBRecvFailedTransfer on a failed one —
 * but it does NOT touch the MessageInfo register on failure, so the returned
 * label is STALE.  Testing the label (== 0) for "empty" is therefore unreliable
 * (a stale non-zero label busy-floods the op handler); testing shell_badge == 0
 * is correct.  Same rationale as BADGE_SOTCRON_OPERATOR. */
#define BADGE_SOTSHELL_OPERATOR 0xC0FFEAUL

/* IRQ-driven virtio-net RX · badge stamped on the notification the kernel Signals
 * when the virtio-net IOAPIC IRQ (GSI 11) fires.  MUST be non-zero so a
 * seL4_Wait/Poll on it returns a truthy badge (an unbadged cap signals badge 0,
 * indistinguishable from "no event"). */
#define VIRTIO_NET_IRQ_BADGE 0x56495251UL  /* 'VIRQ' */
#define LWIP_NET_IRQ_BADGE   0x100UL       /* RX IRQ · distinct bit (badges OR in the shared ntf) */
#define LWIP_PIT_IRQ_BADGE   0x200UL       /* PIT periodic tick · distinct bit → same ntf as RX */

/* F12 toggle · render the operator console to the GTK framebuffer.  sotShell is a
 * native process whose printf goes to the kernel debug console (serial), NOT
 * through orch's console_fb — so the operator console was invisible in the
 * window.  While the operator console is active sotShell tees its stdout here:
 * MR(0)=byte count (<=64), MR(1..8)=packed bytes; orch renders each via
 * console_fb_putc (which also parses ANSI, so a \033[2J clear works). */
#define ORCH_OP_FB_PUTS 43

/* v2.3-M5 · Doom over REAL Wayland (wl_shm, no EGL) · spawn doomwl.bin — the
 * doomgeneric engine over the patched dynamic SDL2 (SDL_VIDEODRIVER=wayland +
 * SDL_FRAMEBUFFER_ACCELERATION=0 → the SW renderer's window framebuffer is a
 * wl_shm pool/buffer on the honest compositor).  Tier-0 trusted, mirrors
 * ORCH_OP_DOOM: orch replies after spawning, then runs orch_fault_loop until
 * doomwl exits (200 render ticks · the compositor logs genuine Doom commits over
 * wl_shm).  No payload. */
#define ORCH_OP_DOOMWL 44

/* v2.4 · GTK3 over REAL Wayland (cairo software / wl_shm, no EGL) spike · spawn
 * gtkspike.bin (a real GTK3 app + its 57-lib closure in the sysroot).  Tier-0
 * trusted, mirrors ORCH_OP_DOOMWL: orch replies after spawning then runs the
 * fault loop until it exits.  Proof = the compositor logs the GTK window's
 * wl_shm commits.  No payload. */
#define ORCH_OP_GTKSPIKE 45

/* v2.9 · headless network-activity query · reply MR(0) = tcp_inbound_total()
 * (monotonic count of inbound conns that reached ESTABLISHED).  sotShell polls
 * this during its post-demo idle window so an unattended boot stays alive WHILE
 * being probed/attacked (the count keeps climbing → extend the window) and
 * powers off only once the network is idle.  Fixes multi-connection network
 * gates (e.g. the 9-probe TLS gate) that the fixed window cut off mid-sequence. */
#define ORCH_OP_QUERY_NET 46

/* v2.x · run an UNMODIFIED off-the-shelf Linux GTK3 app (Alpine gtk3-demo) over
 * the honest compositor — the "real Linux app, no per-app code" proof.  Same
 * orch contract as ORCH_OP_GTKSPIKE, but the binary does NOT self-setenv, so the
 * handler supplies the full GTK environment (GDK_BACKEND/WAYLAND_DISPLAY/XDG/
 * fontconfig) via sotbox_spawn_set_envp_next.  No payload. */
#define ORCH_OP_GTK3DEMO 47

/* Wine-prep · run the MAP_FIXED-low gate fixture (mapfixed.bin · the wine-
 * preloader mmap PATTERN: reserve large PROT_NONE Windows ranges, then commit
 * sub-ranges via MAP_FIXED and mprotect).  Same orch contract as ORCH_OP_DOOM:
 * orch replies after spawning, then runs orch_fault_loop until it exits.  Proves
 * LUCAS honors fixed low-address reservations before the Wine swamp.  No payload. */
#define ORCH_OP_MAPFIXED 48

/* Wine M1 SPIKE · spawn the `wine` loader on a trivial console PE (hello.exe).
 * Heavy arena + full Wine env (WINEDLLPATH/WINEPREFIX).  Same orch contract as
 * gtk3-demo (reply after spawn, run the fault loop until exit).  Exploratory:
 * finds the next wall after MAP_FIXED-low (likely the %fs/%gs TEB/PEB segment
 * ABI or wineserver IPC).  No payload. */
#define ORCH_OP_WINE 49
/* Wine M1 · Track M1 (PE execution) · run `wine hello.exe` against a PRE-BAKED,
 * version-matched wine prefix seeded into /.wine — wine SKIPS the in-guest
 * wineboot bootstrap and runs the PE directly in the launcher process.  EXPLICIT
 * mode (a distinct op + a distinct sotshell command), never a default; the seeder
 * logs that the prefix is pre-baked, not booted.  Real wineboot/TEB bootstrap is
 * Track correctness (Wine M2a), not a prerequisite for executing a simple PE. */
#define ORCH_OP_WINE_BAKED 50
/* Wine M2 · run `wine hello_crt.exe` — a REAL C-runtime PE (msvcrt printf/malloc
 * + the mingw CRT startup).  Same launcher/wineboot path as ORCH_OP_WINE; the PE
 * is the only difference.  Exercises the M1 wall (msvcrt.dll DllMain locale/NLS
 * init) the CRT-less M1 PE deliberately avoided. */
#define ORCH_OP_WINE_CRT 67
/* Wine GUI · run `wine hello_gui.exe` — a real Win32 GUI PE (RegisterClass +
 * CreateWindowEx + ShowWindow + paint) driving user32/gdi32/win32u →
 * winewayland.so → wl_shm/xdg_shell on the honest compositor (the GTK/SDL/Doom
 * path).  The first GUI milestone: a Windows window on the sotOs compositor. */
#define ORCH_OP_WINE_GUI 68
/* GTK fidelity (#2 · broader-apps) · run the UNMODIFIED off-the-shelf Alpine
 * gtk3-widget-factory — the canonical GTK widget showcase (buttons, switches,
 * sliders, GtkTreeView, GtkNotebook, dialogs, spinners).  Same launcher contract
 * + GTK env as gtk3-demo; proves the FULL GTK3 widget set rasterizes over wl_shm,
 * not just the demo-browser window.  Its lib closure is a subset of gtk3-demo's. */
#define ORCH_OP_WIDGETFACTORY 69

/* Compat-host · run real Alpine git (musl-dynamic PIE) at Tier-0 in /tmp/gitrepo:
 * `git init` -> `git commit --allow-empty` -> `git log`.  Same orch contract as
 * doom (reply after the first spawn, then run the fault loop per step until each
 * git exits).  Proves the real rename() + /dev/urandom + libz/libpcre2 dynamic
 * closure.  No payload. */
#define ORCH_OP_GITDEMO 51

/* Compat-host · run a glibc-static binary (glibc-probe) at Tier-0 — proves the
 * GNU/glibc libc ABI (not just musl) runs on sotOs.  Same orch contract as doom
 * (reply after spawn, run the fault loop until it exits).  No payload. */
#define ORCH_OP_GLIBC 52

/* Compat-host · run real GNU tools (musl-dynamic: coreutils/grep/sed/gawk) at
 * Tier-0 on /etc/passwd.  Same orch contract as doom (reply after the first
 * spawn, run the fault loop per tool).  No payload. */
#define ORCH_OP_GNU 53

/* Compat-host · run an off-the-shelf glibc-DYNAMIC PIE at Tier-0, loaded by the
 * real ld-linux-x86-64.so.2 (the glibc dynamic linker, not ld-musl).  Same orch
 * contract as doom.  Exploratory — the glibc loader bring-up.  No payload. */
#define ORCH_OP_GLIBCDYN 54

/* Install-arc P0.2 · run a real `dpkg-deb -x /tmp/hello.deb /tmp/root` at Tier-0
 * (the off-the-shelf Debian dpkg-deb, a glibc-dynamic PIE via ld-linux, which
 * execve's the real `tar` + `xz` to unpack the .deb's data.tar.xz into the
 * writable /tmp).  Same orch contract as doom (reply after the first spawn, run
 * the fault loop per step).  No payload. */
#define ORCH_OP_INSTALL 55

/* Internet-egress Phase 1 · run the dnsprobe fixture twice to prove the DNS
 * forwarder: once as a Tier-0e (egress-functor) sotbox resolving example.com
 * (real forward out the wire) and once as a non-egress sotbox resolving the
 * canary domain malicious-c2.example (the hermetic DNS-intercept synth answers
 * it = 10.0.2.15).  Same orch contract as doom (reply after the first spawn,
 * run the fault loop per step until each dnsprobe exits).  No payload. */
#define ORCH_OP_EGRESS_DNS 56
/* egress P1 demo · spawn a REAL off-the-shelf busybox `wget http://example.com`
 * as a Tier-0e (is_egress) sotbox: musl getaddrinfo (UDP:53 → our DNS forward →
 * real A record) → connect(:80, resolved IP) → tcp_active_open → HTTP GET +
 * response.  Needs live internet egress.  Same orch contract as egress-dns. */
#define ORCH_OP_EGRESS_HTTP 57
/* egress · network install · wget a REAL .deb over VERIFIED HTTPS (real CA bundle)
 * → /tmp/hello-net.deb on sotfs → dpkg-deb -x extracts it → ls proves the tree.
 * Chains the Tier-0e TLS client with the local dpkg path.  Needs live internet. */
#define ORCH_OP_EGRESS_INSTALL 58
/* egress · pip foundation · real CPython (python3.12-static, static _ssl) does an
 * IN-PROCESS HTTPS GET over the egress, verifying the real cert vs the CA bundle. */
#define ORCH_OP_EGRESS_PYTHON 59
/* arena reclaim validation · python churns 300 MiB through the 128 MiB heavy arena;
 * only completes (ARENA_CHURN_OK) with the in-life frame reclaim. */
#define ORCH_OP_ARENA_CHURN 60
/* egress · FULL pip install · real CPython runs `python -m pip` (pip rides in the
 * stdlib zip) → `pip --version` (heavy-import sanity, survives via arena reclaim)
 * then `pip install --target /tmp/sp six` from PyPI over the verified egress →
 * `import six` from the writable target.  The complete network-install-the-tool. */
#define ORCH_OP_EGRESS_PIP 61
/* egress · pip BUILD from sdist · real CPython downloads a source dist (six-1.16.0
 * .tar.gz · no wheel) over verified HTTPS, then the REAL setuptools/wheel BUILD
 * BACKEND builds the wheel IN-PROCESS (setuptools.build_meta.build_wheel · egg-info
 * + bdist_wheel, no subprocess — sidesteps the fork-child-execve arena swamp the
 * way the in-process download+extract sidestepped the dpkg pipe chain), installs
 * the built wheel into the writable /tmp/sp, and imports it.  setuptools+wheel ride
 * in the stdlib zip (the "build deps"). */
#define ORCH_OP_EGRESS_PIP_BUILD 62
/* egress · pip install WITH DEPENDENCIES · `pip install requests` over the verified
 * egress resolves requests + its 4 deps (urllib3/certifi/idna/charset-normalizer)
 * on pypi.org/simple, downloads all 5 wheels from files.pythonhosted.org, installs
 * them into the writable /tmp/sp, and imports the whole tree.  Exercises pip's
 * dependency RESOLVER + multi-package install (the dir-fd VFS support enables the
 * multi-wheel extract). */
#define ORCH_OP_EGRESS_PIPDEPS 63
/* real-tools fs battery · GNU bash -c drives REAL off-the-shelf tools (GNU tar +
 * coreutils) through a recursive-filesystem workflow: build a nested dir tree,
 * `tar -cf` it, `tar -xf` it elsewhere (the extract recreates the nested dirs via
 * dir-fd-relative openat/mkdirat — what the dir-fd VFS support newly enables;
 * GNU tar's dirfd-openat mis-resolved to "/" before), `cat` a deep file, `cp -r`,
 * `rm -rf`.  Uncompressed tar (no gzip subprocess → no single-threaded pipe
 * deadlock).  Proves real CLI tools do real recursive fs work on sotOs. */
#define ORCH_OP_TOOLS_FS 64
/* python real END-TO-END · a real CPython program that chains network + parse +
 * filesystem + crypto: verified-HTTPS GET of example.com → extract the <title> →
 * write the HTML + a JSON sidecar (title/bytes/sha256) to /tmp/e2e → read both
 * back → verify the sha256 round-trips.  Proves sotOs is a real Python compute
 * host (egress + fs + json + hashlib), not just demos. */
#define ORCH_OP_PY_E2E 65
/* `shell --trusted` · operator-gated interactive busybox shell spawned at
 * Tier-0e (FUNCTOR_TIER_EGRESS, trusted) instead of the Tier-2 canary.  Real
 * egress is live for the WHOLE session: `python3 -m pip install …` / `pip
 * install …` typed by hand reach real PyPI (the python child inherits the
 * trust via g_shell_trusted_egress).  This is the operator's own shell — NOT
 * the attacker-facing one (that stays bbsh/Tier-2 + the pip-deception facade). */
#define ORCH_OP_BBSH_TRUSTED 66
/* world-#3 native operator plane · `sotctl [sub]` typed at the trusted sotShell
 * console spawns the NATIVE sotctl seL4 binary (sotcrt+sotlibc+sel4runtime · NOT
 * a Linux guest) which pulls the operator-chosen truth-plane view over sotabi and
 * prints it.  MR1 carries the SOTABI_OP_* content op (default SESSIONS).  Mirrors
 * the execve launcher trigger (g_sotctl_op/g_sotctl_request) but driveable from
 * the scripted demo / console, so the native runtime is headlessly gateable. */
#define ORCH_OP_SOTCTL 70

typedef struct orch_trace_entry {
    uint64_t seq;          /* global monotonic order */
    uint32_t pid;          /* synthetic_pid (0 for system ring, e.g. DNS) */
    uint16_t kind;         /* sotguard_event_type_t */
    uint16_t pad;
    uint64_t a;            /* ENTER/EXIT: sysno · TIER: old_tier · DNS: ip_be */
    uint64_t b;            /* ENTER: arg0 · EXIT: ret · TIER: new_tier */
} orch_trace_entry_t;      /* 32 bytes = 4 words */

typedef struct orch_trace_reply {
    uint32_t count;        /* entries returned (0..ORCH_TRACE_REPLY_MAX) */
    uint32_t total;        /* events currently held across all rings (ring-window
                            * size, <= NRINGS*RING_N = 1152) · truncation visibility
                            * · NOT a monotonic total-ever-emitted count */
    orch_trace_entry_t entries[ORCH_TRACE_REPLY_MAX];
} orch_trace_reply_t;      /* 8 + 24*32 = 776 bytes = 97 words */
_Static_assert(sizeof(orch_trace_entry_t) == 32,
    "orch_trace_entry_t must be 32 bytes (4 message-register words)");
_Static_assert(sizeof(orch_trace_reply_t) <= 120 * sizeof(long),
    "orch_trace_reply_t must fit in the 120-word seL4 message-register cap");

/* OBSD-η / sotBoot · sotShell operator commands for TPM attestation.
 * Companion to TPM driver (sibling unit T2).
 *
 * ORCH_OP_TPM_PCRS  · read PCR 8 / 9 / 10 (sotBoot measurement bank).
 *                     No request payload.  Reply is orch_tpm_pcrs_reply_t.
 * ORCH_OP_TPM_QUOTE · request a TPM quote (signed PCR digest) over a nonce
 *                     supplied by the operator.  Request payload: nonce_len
 *                     in MR(0) then nonce bytes packed 8/word.  Reply is
 *                     orch_tpm_quote_reply_t.
 */
#define ORCH_OP_TPM_QUOTE 22
#define ORCH_OP_TPM_PCRS  23

#define TPM_QUOTE_MAX_SIG_BYTES 256
#define TPM_QUOTE_MAX_NONCE     64

typedef struct orch_tpm_pcrs_reply {
    uint8_t available;          /* 1 if TPM is initialized, 0 otherwise */
    uint8_t pad[3];
    uint8_t pcr8[32];
    uint8_t pcr9[32];
    uint8_t pcr10[32];
    uint8_t pad_tail[4];        /* word-align struct to 104 bytes = 13 words ·
                                 * avoids stack over-write when the receiver
                                 * casts &reply to seL4_Word * and writes
                                 * past the 100-byte payload. */
} orch_tpm_pcrs_reply_t;        /* 4 + 96 + 4 = 104 bytes = 13 words */

typedef struct orch_tpm_quote_reply {
    uint8_t  available;
    uint8_t  pad[3];
    uint32_t sig_len;
    uint8_t  sig[TPM_QUOTE_MAX_SIG_BYTES];
} orch_tpm_quote_reply_t;       /* 8 + 256 = 264 bytes = 33 words */

#include <sotnet/dns.h>

#define ORCH_DNS_MAX_ENTRIES 8
typedef struct orch_dns_list_reply {
    uint32_t entry_count;
    uint32_t pad0;
    dns_list_entry_t entries[ORCH_DNS_MAX_ENTRIES];
} orch_dns_list_reply_t;

/* sotGuard live-dump · sotShell `dump-heap <pid> <out_path>`.
 * Captures the sotbox's heap range [brk_base, brk_top) into a sotfs file
 * for Tier-2 promotion forensics.  Bounded at 1 MiB to avoid OOM.
 *
 * Request:  orch_dump_heap_msg_t   (target_pid + out_path packed into MRs)
 * Reply:    orch_dump_heap_reply_t (bytes_dumped + brk range)
 *   bytes_dumped > 0 → success
 *   bytes_dumped < 0 → -errno (e.g. -ESRCH if pid not found, -EFAULT on
 *                       client_vaddr read failure, -EIO on install failure)
 */
#define ORCH_OP_DUMP_HEAP 24

typedef struct orch_dump_heap_msg {
    uint32_t target_pid;       /* synthetic_pid of sotbox to dump */
    uint32_t pad0;             /* word-align out_path to 13-word struct */
    char     out_path[96];     /* sotfs path to write the dump to */
} orch_dump_heap_msg_t;        /* 4 + 4 + 96 = 104 bytes = 13 words */

typedef struct orch_dump_heap_reply {
    int64_t  bytes_dumped;     /* >0 = success, <0 = -errno */
    uint64_t brk_base;
    uint64_t brk_top;
} orch_dump_heap_reply_t;      /* 24 bytes = 3 words */

/* SOTSHELL-REOPEN · root sends this after the L4-L11 demo sequence
 * completes so orch re-enters the sotShell command-window loop on the
 * previously-allocated shell_ep.  Without this, the scripted demo's
 * trailing `quit` permanently closes the window and sotShell's
 * interactive mode cannot reach orch.  No payload. */
#define ORCH_OP_REOPEN_SHELL 25

/* α · PR 7 · sotShell-to-orch: trigger userspace-only reset cascade.
 *
 * 5-phase teardown + respawn + replay-apply in orch's vspace.  Orch
 * hosts sotos-sotfs as a linked library (the only ELF that does), so
 * the WAL CHECKPOINT writer + replay dispatcher live here · root is a
 * conceptual supervisor but cannot drive the WAL directly.
 *
 * Per the PR 7 plan "scope reductions allowed" section: Phase 2-4
 * (TCB suspend / cap free / TCB respawn) require root cooperation
 * (root owns the Path D TCBs/CSpaces), which is out of scope for PR 7.
 * Those phases emit banner lines that prove the cascade ran.  Phase 1
 * (CHECKPOINT) + Phase 5 (replay-apply) ARE real: they write a WAL
 * record + flush, then re-run sotfs_wal_replay_apply().  The
 * end-to-end persistence proof is: records written before simreboot
 * survive virtio-blk + are observable via Phase 5 replay banners.
 *
 * No payload.  Reply MR(0) = rc · 0 = success, negative = failure.
 */
#define SOTOS_OP_SIMREBOOT  0x80

/* γ · F_persistence PR 5 · cross-process audit emission.
 *
 * sotinit / sotcron (separate ELFs from orch) marshal their audit events
 * over this op so they all land in orch's unified anomaly-log ring (the
 * same buffer sotShell `anomaly-log` queries).  Lucas — which lives in
 * orch's vspace — calls orch_anomaly_log_append directly · no IPC.
 *
 * Wire format:
 *   MR(0) = ORCH_OP_AUDIT_APPEND
 *   MR(1) = (slot << 16) | (kind & 0xFFFF)
 *   MR(2) = arg0
 *   MR(3) = reserved (0)
 *
 * Reply · MR(0) = 0 (always success today · the ring is a fixed-size
 * wrap buffer · overflow drops oldest, no error path).
 *
 * Value 0x91 chosen to sit just above SOTFS_OP_WAL_LOG (0x90) which is
 * the WAL writer EP · keeps the cross-process orch-bound op codes
 * clustered in 0x80-0x9F.
 */
#define ORCH_OP_AUDIT_APPEND  0x91

/* γ · F_persistence PR 7 · cross-process sotfs inode stat for F_persistence.
 *
 * sotinit / sotcron (separate ELFs) seL4_Call this op to ask orch's in-vspace
 * sotfs_graph (backends_sotfs_get_graph) whether a path resolves to an inode
 * carrying functor_persistence=1.  Used at boot by sotinit_sotfs_scan / the
 * sotcron sister scan (PR 9) to tag persistence-install unit files (e.g.
 * /etc/systemd/system/backdoor.service) without dragging the full sotfs
 * graph into every daemon's vspace.
 *
 * Wire format (LABEL-based · matches SYNTH_RESPONSE / ORCH_OP_SPAWN
 * convention · the AUDIT_APPEND op is the lone exception that stuffs the
 * op into MR(0)):
 *   request:
 *     label    = ORCH_OP_F_PERSIST_STAT
 *     MR(0..15) = path[128] packed 8 chars per word, null-terminated
 *   reply:
 *     MR(0) = result (0 = found, -1 = not found / not resolved)
 *     MR(1) = functor_persistence (uint8_t · 0 or 1 · meaningful only if result==0)
 *
 * Value 0x92 chosen to sit just above AUDIT_APPEND (0x91) · keeps the
 * cross-process orch-bound op codes clustered in 0x80-0x9F.
 */
#define ORCH_OP_F_PERSIST_STAT  0x92

#define ORCH_F_PERSIST_STAT_PATH_BYTES 128

typedef struct orch_f_persist_stat_req {
    char path[ORCH_F_PERSIST_STAT_PATH_BYTES];
} orch_f_persist_stat_req_t;

typedef struct orch_f_persist_stat_reply {
    int32_t  result;                /* 0 = found, -1 = not found */
    uint8_t  functor_persistence;   /* 0 / 1 · meaningful when result==0 */
    uint8_t  pad[3];
} orch_f_persist_stat_reply_t;

#endif
