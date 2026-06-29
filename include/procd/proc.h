/* sotOs · procd · process and thread types · ABI v1.
 *
 * Consumed by procd (writer), orch/lucas/anomaly/sotfs/sotnet (readers).
 * No malloc; bounded arrays only. Sizes locked by ABI v1.
 *
 * Spec: procd-process-server-design §4.
 */
#ifndef PROCD_PROC_H
#define PROCD_PROC_H

#include <stdint.h>
#include <sel4/sel4.h>

#define PROCD_MAX_PROCS    256
#define PROCD_MAX_THREADS  1024
#define PROCD_ABI_VERSION  2u   /* v2 · proc_t gains comm[16] + cow_session */

typedef enum {
    PROC_STATE_FREE     = 0,
    PROC_STATE_NASCENT  = 1,
    PROC_STATE_RUNNING  = 2,
    PROC_STATE_STOPPED  = 3,
    PROC_STATE_ZOMBIE   = 4,
    PROC_STATE_DEAD     = 5,
} proc_state_t;

typedef enum {
    PROC_TIER_0 = 0,
    PROC_TIER_1 = 1,
    PROC_TIER_2 = 2,
    PROC_TIER_3 = 3,
} proc_tier_t;

typedef struct {
    /* identidad */
    uint32_t      slot;
    uint32_t      synthetic_pid;
    uint32_t      real_pid;
    uint32_t      ppid;
    uint32_t      pgid;
    uint32_t      sid;

    /* estado */
    proc_state_t  state;
    proc_tier_t   tier;
    int32_t       exit_code;
    uint32_t      _pad32;
    uint64_t      birth_tsc;

    /* composición seL4 */
    seL4_CPtr     tcb_root;
    seL4_CPtr     cspace_root;
    seL4_CPtr     vspace_root;
    seL4_CPtr     fault_ep_badged;
    seL4_CPtr     ipc_buffer;

    /* threads */
    uint32_t      n_threads;
    uint32_t      thread_slot_base;

    /* functor binding */
    uint16_t      functor_fs;
    uint16_t      functor_net;
    uint16_t      functor_proc;
    uint16_t      _functor_pad;

    /* pledge */
    uint64_t      pledge_mask;

    /* audit cursor */
    uint64_t      audit_seq;

    /* PR 14 · CLONE_FS / CLONE_FILES / CLONE_SIGHAND inheritance bits
     * carried over from the parent on OP_CLONE fork-like path.  Procd
     * only records the *intent* to share · the actual fs_struct /
     * fd_table / sighand_struct sharing stays in orch (no new pool
     * structs in PR 14 per the spec's scope reduction).  Bit layout
     * mirrors the LX_CLONE_* mask so a single mask AND uncovers all
     * three flags simultaneously. */
    uint32_t      share_flags;
    uint32_t      _share_pad;

    /* persona / procfs (ABI v2) · short command name + the owning SSH session id
     * (cow_session, 0 = not an interactive session).  Lets the procfs renderer
     * show the attacker their OWN session's real processes in `ps`, named +
     * filtered, instead of dumping all live sotboxes or hiding them.  Written by
     * the procd server (spawn comm + a post-spawn session/execve update); read by
     * LUCAS via lucas_proct_load → truth_list_processes. */
    char          comm[16];
    uint32_t      cow_session;
    uint32_t      _persona_pad;

    /* seqlock · MUST stay the LAST field */
    volatile uint64_t version;
} proc_t;

typedef struct {
    uint32_t   tid;
    uint32_t   owner_slot;
    seL4_CPtr  tcb;
    uintptr_t  tls_base;
    uintptr_t  ipc_buffer_vaddr;
    uintptr_t  clear_tid_ptr;
    uintptr_t  robust_list_head;
    uint8_t    state;
    uint8_t    _pad[7];
    volatile uint64_t version;
} thread_t;

_Static_assert(sizeof(proc_t)   <= 192, "proc_t exceeds ABI v2 size budget");
_Static_assert(sizeof(thread_t) <=  72, "thread_t exceeds ABI v1 size budget");

#endif /* PROCD_PROC_H */
