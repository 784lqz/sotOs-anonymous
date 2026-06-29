#include "client_setup.h"
#include "state.h"

#include <sel4utils/mapping.h>
#include <sel4utils/api.h>
#include <vka/object.h>
#include <vka/capops.h>
#include <sel4/sel4.h>
#include <simple/simple.h>
#include <orch/sotbox.h>   /* orch_get_fault_ep */
#include <stdio.h>
#include <string.h>

/* Client CNode size: 4 bits = 16 slots.
 * Slot layout:
 *   0 = seL4 null slot (cannot be used)
 *   1 = fault endpoint copy (used by seL4_TCB_Configure fault_ep)
 */
#define CLIENT_CNODE_BITS   4
#define CLIENT_FAULT_EP_SLOT 1

int lucas_client_setup(lucas_state_t *st) {
    int err;

    /* L3b-T1: use the shared fault EP (allocated by bootstrap.c).
     * Mint a badged copy into orch's own CSpace (badge = slot_index + 1),
     * then copy that badged cap into the client's CNode at slot 1.
     * The kernel delivers faults to the shared EP with badge set to the
     * sotBox's slot_index+1, enabling orch_fault_loop to dispatch by badge. */
    seL4_CPtr shared_ep = orch_get_fault_ep();
    if (!shared_ep) {
        printf("[lucas] shared fault EP not set · call orch_bootstrap_init first\n");
        return -1;
    }

    /* Build a cspacepath_t for the shared EP in orch's CSpace. */
    cspacepath_t shared_ep_path;
    vka_cspace_make_path(st->vka, shared_ep, &shared_ep_path);

    /* Allocate a fresh slot in orch's CSpace for the badged copy. */
    seL4_CPtr badged_slot = 0;
    err = vka_cspace_alloc(st->vka, &badged_slot);
    if (err || !badged_slot) {
        printf("[lucas] vka_cspace_alloc for badged EP slot failed (%d)\n", err);
        return err ? err : -1;
    }
    cspacepath_t badged_path;
    vka_cspace_make_path(st->vka, badged_slot, &badged_path);

    /* Mint: badged_path = shared_ep_path with badge = slot_index + 1. */
    seL4_Word badge = (seL4_Word)(st->slot_index + 1);
    err = vka_cnode_mint(&badged_path, &shared_ep_path, seL4_AllRights, badge);
    if (err) {
        printf("[lucas] vka_cnode_mint (badge=%lu) failed (%d)\n",
               (unsigned long)badge, err);
        vka_cspace_free(st->vka, badged_slot);
        return err;
    }

    /* Store the badged EP slot in st->fault_ep (orch CSpace CPtr of the
     * badged copy; used only for diagnostics / future cleanup). */
    st->fault_ep = badged_slot;

    /* Allocate the client's CNode.  4 bits = 16 slots; slot 0 is the seL4
     * null slot, slot 1 will hold a copy of the badged fault endpoint. */
    vka_object_t cnode_obj;
    err = vka_alloc_cnode_object(st->vka, CLIENT_CNODE_BITS, &cnode_obj);
    if (err) { printf("[lucas] cnode alloc failed (%d)\n", err); return err; }
    st->client_cnode = cnode_obj.cptr;
    st->client_cnode_obj = cnode_obj;   /* P2a · capture for teardown (size_bits + .ut cookie) */

    /* Copy the BADGED endpoint cap into the client's CNode slot 1.
     *
     * seL4_TCB_Configure's fault_ep param is "CPtr in the CSpace of the
     * thread being configured".  When a fault fires, the kernel sends to
     * this cap with badge = slot_index+1 · orch_fault_loop reads the badge
     * to look up the correct sotbox_t.
     *
     * seL4_CNode_Copy args:
     *   _service   = destination CNode (client_cnode, in orch CSpace)
     *   dest_index = slot within dest CNode = CLIENT_FAULT_EP_SLOT
     *   dest_depth = CLIENT_CNODE_BITS (4)
     *   src_root   = orch's CNode cap (via simple)
     *   src_index  = badged_slot  (slot of badged copy in orch CSpace)
     *   src_depth  = seL4_WordBits (64)
     *   rights     = seL4_AllRights
     *
     * Use simple to resolve the CNode cap so this works both in root task
     * (CNode at seL4_CapInitThreadCNode=2) and in orch child
     * (CNode at SEL4UTILS_CNODE_SLOT=1). */
    seL4_CPtr cnode_cap = simple_get_init_cap(st->simple, seL4_CapInitThreadCNode);
    err = seL4_CNode_Copy(
        st->client_cnode,               /* dest CNode */
        CLIENT_FAULT_EP_SLOT,           /* dest slot */
        CLIENT_CNODE_BITS,              /* dest depth */
        cnode_cap,                      /* src CNode (orch's own CNode) */
        badged_slot,                    /* src slot (badged copy) */
        seL4_WordBits,                  /* src depth */
        seL4_AllRights
    );
    if (err) {
        printf("[lucas] badged EP copy to client CNode failed (%d)\n", err);
        return err;
    }

    /* Allocate IPC buffer frame (4 KiB) and map it into client vspace.
     * sel4utils_map_page_leaky allocates page-table intermediates and does
     * not track them for later free (sufficient for L1).
     *
     * Actual sel4utils_map_page signature (confirmed in
     * external/seL4_libs/libsel4utils/include/sel4utils/mapping.h):
     *   int sel4utils_map_page(vka, vspace_root, frame, vaddr,
     *                           rights, cacheable, objects, &num_objects);
     * The leaky wrapper passes a temporary 3-element objects array. */
    vka_object_t ipc_frame_obj;
    err = vka_alloc_frame(st->vka, 12, &ipc_frame_obj);
    if (err) { printf("[lucas] IPC frame alloc failed (%d)\n", err); return err; }
    st->client_ipc_buffer_frame = ipc_frame_obj.cptr;
    st->client_ipc_buffer_obj = ipc_frame_obj;   /* P2a · capture for teardown (.ut cookie) */

    uintptr_t ipc_vaddr = 0x7ffff1000000UL;
    err = sel4utils_map_page_leaky(st->vka, st->client_vspace,
                                    st->client_ipc_buffer_frame,
                                    (void *)ipc_vaddr,
                                    seL4_ReadWrite, 1);
    if (err) { printf("[lucas] map IPC buffer failed (%d)\n", err); return err; }

    /* Allocate TCB. */
    vka_object_t tcb_obj;
    err = vka_alloc_tcb(st->vka, &tcb_obj);
    if (err) { printf("[lucas] TCB alloc failed (%d)\n", err); return err; }
    st->client_tcb = tcb_obj.cptr;
    st->client_tcb_obj = tcb_obj;   /* P2a · capture for teardown (.ut cookie) */

    /* cspace_root_data: the kernel uses this to set the guard on the root
     * CNode when resolving caps in the client's CSpace.  For a single-level
     * CSpace with CLIENT_CNODE_BITS bits, the guard must skip
     * (seL4_WordBits - CLIENT_CNODE_BITS) bits so that the total resolving
     * depth = 64.  api_make_guard_skip_word sets guard=0 with the given size. */
    seL4_Word cspace_root_data = api_make_guard_skip_word(
        seL4_WordBits - CLIENT_CNODE_BITS);

    /* Configure TCB: bind fault EP (slot in client CSpace), CSpace, VSpace,
     * IPC buffer.
     *
     * Non-MCS signature (CONFIG_KERNEL_MCS is disabled in this build,
     * confirmed in build/libsel4/include/interfaces/sel4_client.h):
     *   seL4_TCB_Configure(tcb, fault_ep_slot, cspace_root, cspace_root_data,
     *                       vspace_root, vspace_root_data, buffer, bufferFrame)
     *
     * fault_ep = CLIENT_FAULT_EP_SLOT: the kernel resolves this in the
     *   client's CSpace (via client_cnode + cspace_root_data guard) when a
     *   fault fires.
     * cspace_root, vspace_root, bufferFrame are passed as caps in root
     *   CSpace via seL4_SetCap (the kernel looks them up directly from the
     *   IPC transfer caps, not via the client CSpace). */
    err = seL4_TCB_Configure(st->client_tcb,
                              CLIENT_FAULT_EP_SLOT,
                              st->client_cnode,
                              cspace_root_data,
                              st->client_vspace,
                              seL4_NilData,
                              ipc_vaddr,
                              st->client_ipc_buffer_frame);
    if (err) { printf("[lucas] TCB_Configure failed (%d)\n", err); return err; }

    /* Set priority (same as ourselves so Yield rotates).
     * The 'authority' parameter is our own TCB cap, obtainable via simple. */
    err = seL4_TCB_SetPriority(st->client_tcb,
                                simple_get_init_cap(st->simple, seL4_CapInitThreadTCB),
                                seL4_MaxPrio);
    if (err) {
        printf("[lucas] SetPriority failed (%d) · non-fatal, continuing\n", err);
        /* non-fatal */
    }

    /* ADR-006 · mark this as a Linux-ABI thread so the kernel routes ALL its
     * syscalls to UnknownSyscall (LUCAS dispatches; avoids the seL4 syscall-selector
     * collision on e.g. poll(timeout=-1)). clear=0, set=linuxABI. */
    err = seL4_TCB_SetFlags(st->client_tcb, 0, seL4_TCBFlag_linuxABI).error;
    if (err) printf("[lucas] SetFlags(linuxABI) failed (err=%d) on main tcb\n", err);

    /* Write initial registers: RIP = entry_point, RSP = stack_top, all else 0.
     * seL4_UserContext on x86_64 has fields: rip, rsp, rflags, rax..r15,
     * fs_base, gs_base (confirmed from
     * external/kernel/libsel4/sel4_arch_include/x86_64/sel4/sel4_arch/types.h). */
    seL4_UserContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rip = (seL4_Word)st->entry_point;
    ctx.rsp = (seL4_Word)st->stack_top;
#ifdef LUCAS_TRACE_L2_WR
    printf("[l:wr-client_setup:182] tcb=%lu rax=0x%lx rip=0x%lx (initial)\n",
           (unsigned long)st->client_tcb,
           (unsigned long)ctx.rax,
           (unsigned long)ctx.rip);
#endif
    err = seL4_TCB_WriteRegisters(st->client_tcb, false, 0,
                                   sizeof(ctx)/sizeof(seL4_Word), &ctx);
    if (err) { printf("[lucas] WriteRegisters failed (%d)\n", err); return err; }

    printf("[lucas] client TCB configured · badged_ep=%lu (badge=%d) cnode=%lu tcb=%lu\n",
           (unsigned long)st->fault_ep, st->slot_index + 1,
           (unsigned long)st->client_cnode,
           (unsigned long)st->client_tcb);
    return 0;
}

int lucas_client_resume(lucas_state_t *st) {
    extern void lucas_doom_probe(const char *tag);
    lucas_doom_probe("client_resume:PRE-TCB_Resume");
    int err = seL4_TCB_Resume(st->client_tcb);
    lucas_doom_probe("client_resume:POST-TCB_Resume");
    if (err) printf("[lucas] TCB_Resume failed (%d)\n", err);
    else      printf("[lucas] client resumed · executing Linux ELF\n");
    return err;
}
