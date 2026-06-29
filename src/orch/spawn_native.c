/*
 * sotOs · orchestrator · native (non-Linux) process spawner.
 *
 * L4-T3: orch_spawn_native spawns a seL4-native binary from orch's CPIO
 * using orch's own VKA (delegated untypeds).  This avoids draining root's
 * allocman budget which is tight after loading the heavy orch ELF.
 *
 * DESIGN — endpoint delegation:
 *   Root minted a badged EP into orch's CSpace (badge=0xC0FFEE).  seL4 does
 *   not allow re-minting an already-badged cap (error: "Mutated cap would be
 *   invalid").  Therefore orch_spawn_native allocates a fresh unbadged EP from
 *   its own VKA, mints that into the child's CSpace, and returns the new EP via
 *   *out_shell_ep so the caller (orch/main.c) can open a short IPC window on
 *   that EP for the child to call into.
 *
 * For L4 this is used exclusively to spawn sotOs-shell.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sel4/sel4.h>
#include <sel4utils/process.h>
#include <sel4utils/process_config.h>
#include <sel4utils/elf.h>   /* A1 · sel4utils_elf_load from a byte buffer */
#include <elf/elf.h>         /* A1 · elf_newFile */
#include <vka/vka.h>
#include <vka/object.h>
#include <vka/capops.h>
#include <orch/sotbox.h>
#include <orch/proto.h>      /* BADGE_SOTSHELL_OPERATOR */
#include <sotcron/proto.h>   /* β · PR 9 · BADGE_SOTCRON_OPERATOR */

/* From spawn.c / bootstrap.c */
extern vka_t       *orch_vka(void);
extern simple_t    *orch_simple(void);
extern vspace_t    *orch_parent_vspace_ptr(void);
extern int          orch_env_init(void);
/* From sotbox_table.c · the x86 IOPort cap delegated from root */
extern seL4_CPtr    orch_get_io_port_cap(void);

/*
 * orch_spawn_native — spawn a native seL4 binary from orch's CPIO.
 *
 * binname        : CPIO filename (e.g. "sotOs-shell")
 * elf_bytes      : ELF data (already located in CPIO by caller)
 * elf_size       : byte count
 * listen_ep      : unused (kept for API compatibility; was the badged EP from
 *                 root — cannot be re-minted)
 * extra_cap_in_orch  : β · PR 5 · optional extra cap (in orch's CSpace) to
 *                     mint unbadged into the child as argv[3].  Today this
 *                     is the sotinit listen EP forwarded to sotShell so the
 *                     operator can drive `systemctl <action> <unit>`.  Pass 0
 *                     to skip the mint · argv[3] then carries "0" and the
 *                     child treats it as "feature disabled".
 * extra_cap_in_orch_2 : β · PR 9 · optional second extra cap (in orch's
 *                       CSpace) to mint BADGED into the child as argv[4].
 *                       Today this is the sotcron listen EP forwarded to
 *                       sotShell so the operator can drive `cron list` /
 *                       `cron now <timer>` directly against sotcron's
 *                       non-blocking IPC drain.  Pass 0 to skip the mint
 *                       · argv[4] then carries "0" and cmd_cron prints
 *                       "sotcron EP not available".  Badged with
 *                       BADGE_SOTCRON_OPERATOR so sotcron's NBRecv drain
 *                       can detect message arrival via the badge register.
 * out_shell_ep   : on success, receives the fresh unbadged EP allocated from
 *                 orch's VKA that the child will use to call back into orch.
 *                 The caller must seL4_Recv on this EP to serve the child.
 *
 * Returns 0 on success, -1 on failure.
 */
int orch_spawn_native(const char *binname, const void *elf_bytes,
                      unsigned long elf_size, seL4_CPtr listen_ep,
                      seL4_CPtr extra_cap_in_orch,
                      seL4_CPtr extra_cap_in_orch_2,
                      seL4_CPtr *out_shell_ep)
{
    (void)listen_ep;   /* badged — cannot be re-minted; we use a fresh EP */

    if (orch_env_init() != 0) return -1;
    vka_t   *vka    = orch_vka();
    simple_t *simp  = orch_simple();
    vspace_t *vs    = orch_parent_vspace_ptr();

    /* Allocate a fresh unbadged EP from orch's VKA.  This EP is fully owned
     * by orch so we can freely mint it into the child's CSpace. */
    vka_object_t shell_ep_obj;
    int err = vka_alloc_endpoint(vka, &shell_ep_obj);
    if (err) {
        printf("[orch] spawn_native(%s): vka_alloc_endpoint failed (err=%d)\n",
               binname, err);
        return -1;
    }

    /* Configure the child process using orch's simple and VKA. */
    sel4utils_process_config_t config = process_config_default_simple(
        simp, binname, seL4_MaxPrio);
    config = process_config_mcp(config, seL4_MaxPrio);

    sel4utils_process_t child;

    if (elf_bytes != NULL) {
        /* A1 · load the ELF from the supplied byte buffer (binstore/sotfs)
         * instead of letting sel4utils auto-load it from the CPIO by name.
         * Disable the config's ELF auto-load so configure_process_custom only
         * sets up CNode/fault-EP/vspace/IPC-buffer, then load the segments
         * manually with the SAME elf_newFile + sel4utils_elf_load the CPIO
         * path uses (libsel4utils process.c:548-551). */
        config.is_elf = false;
        err = sel4utils_configure_process_custom(&child, vka, vs, config);
        if (err) {
            printf("[orch] spawn_native(%s): configure_process_custom failed (err=%d)\n",
                   binname, err);
            return -1;
        }
        elf_t elf;
        int eerr = elf_newFile(elf_bytes, (size_t)elf_size, &elf);
        if (eerr) {
            printf("[orch] spawn_native(%s): elf_newFile failed (err=%d)\n", binname, eerr);
            return -1;
        }
        void *entry = sel4utils_elf_load(&child.vspace, vs, vka, vka, &elf);
        if (entry == NULL) {
            printf("[orch] spawn_native(%s): sel4utils_elf_load failed\n", binname);
            return -1;
        }
        child.entry_point = entry;

        /* A1 · the is_elf auto-load path (process.c:567-590) ALSO records the
         * sysinfo (vsyscall) pointer and the ELF program headers on the
         * process struct.  sel4utils_spawn_process_v consumes both
         * (process.c:275-299) to write the phdrs onto the child stack and to
         * build the auxv (AT_PHDR / AT_PHNUM / AT_SYSINFO).  With is_elf=false
         * configure_process_custom leaves these zero/NULL, which yields a
         * broken auxv and a C runtime that loads but never starts.  Mirror the
         * auto-load bookkeeping here (public sel4utils API · no lib change). */
        child.sysinfo = sel4utils_elf_get_vsyscall(&elf);
        child.num_elf_phdrs = sel4utils_elf_num_phdrs(&elf);
        child.elf_phdrs = calloc(child.num_elf_phdrs, sizeof(Elf_Phdr));
        if (child.elf_phdrs == NULL) {
            printf("[orch] spawn_native(%s): elf_phdrs calloc failed\n", binname);
            return -1;
        }
        sel4utils_elf_read_phdrs(&elf, child.num_elf_phdrs, child.elf_phdrs);
        /* Neutralise PT_PHDR so muslc does not relocate the phdr block (the
         * exact fixup the auto-load path applies · process.c:578-590). */
        for (uint32_t i = 0; i < child.num_elf_phdrs; i++) {
            if (child.elf_phdrs[i].p_type == PT_PHDR) {
                child.elf_phdrs[i].p_type = PT_NULL;
            }
        }

        printf("[spawn-native] '%s' from bytes · %lu bytes · entry=%p\n",
               binname, elf_size, entry);
    } else {
        /* Legacy path · ELF auto-loaded from the CPIO by image_name=binname. */
        err = sel4utils_configure_process_custom(&child, vka, vs, config);
        if (err) {
            printf("[orch] spawn_native(%s): configure_process_custom failed (err=%d)\n",
                   binname, err);
            return -1;
        }
    }

    /* Mint the fresh EP into child's CSpace BADGED with BADGE_SOTSHELL_OPERATOR.
     * orch's shell-window NBRecv loop relies on the badge to tell "real op
     * arrived" (badge != 0) from "nothing pending" (kernel zeroes the badge on a
     * failed NBRecv but leaves the MessageInfo/label STALE).  Unbadged collapses
     * both states to badge==0 and the loop busy-floods the stale label's handler
     * (e.g. a synth DNS_INSTALL storm) — the same bug the sotcron EP avoids. */
    cspacepath_t ep_path;
    vka_cspace_make_path(vka, shell_ep_obj.cptr, &ep_path);
    seL4_CPtr child_slot = sel4utils_mint_cap_to_process(
        &child, ep_path, seL4_AllRights, BADGE_SOTSHELL_OPERATOR);
    if (child_slot == 0) {
        printf("[orch] spawn_native(%s): mint_cap_to_process failed\n", binname);
        return -1;
    }

    /* L4-Phase-C v2: copy the IO_Port cap into sotShell's CSpace so it can
     * poll the UART (0x3F8/0x3FD) for interactive serial input. */
    seL4_CPtr io_port_child_slot = 0;
    seL4_CPtr io_cap = orch_get_io_port_cap();
    if (io_cap != 0) {
        io_port_child_slot = sel4utils_copy_cap_to_process(&child, vka, io_cap);
        if (io_port_child_slot == 0) {
            printf("[orch] spawn_native(%s): copy io_port cap failed · serial disabled\n",
                   binname);
        } else {
            printf("[orch] spawn_native(%s): IO_Port cap copied · child_slot=%lu\n",
                   binname, (unsigned long)io_port_child_slot);
        }
    } else {
        printf("[orch] spawn_native(%s): no IO_Port cap available · serial disabled\n", binname);
    }

    /* β · PR 5 · mint the optional extra cap (sotinit listen EP) into the
     * child's CSpace unbadged.  Skips silently when extra_cap_in_orch is 0
     * (sotinit not pre-spawned by root) · the child sees "0" in argv[3]
     * and disables the dependent feature (cmd_systemctl for sotShell).
     * Unbadged because sotinit's PR 5 IPC loop accepts the wire protocol
     * verb (MR(0)) without per-caller authentication. */
    seL4_CPtr extra_child_slot = 0;
    if (extra_cap_in_orch != 0) {
        cspacepath_t extra_path;
        vka_cspace_make_path(vka, extra_cap_in_orch, &extra_path);
        extra_child_slot = sel4utils_mint_cap_to_process(
            &child, extra_path, seL4_AllRights, 0 /* unbadged */);
        if (extra_child_slot == 0) {
            printf("[orch] spawn_native(%s): mint extra cap (slot=%lu) failed · feature disabled\n",
                   binname, (unsigned long)extra_cap_in_orch);
        } else {
            printf("[orch] spawn_native(%s): extra cap minted · child_slot=%lu (sotinit EP forward)\n",
                   binname, (unsigned long)extra_child_slot);
        }
    }

    /* β · PR 9 · mint the optional second extra cap (sotcron listen EP)
     * into the child's CSpace BADGED with BADGE_SOTCRON_OPERATOR so
     * sotcron's non-blocking IPC drain can distinguish "real message
     * arrived" from "no message pending" · the kernel writes the cap
     * badge into the badge register on a successful seL4_NBRecv and
     * zeroes it via doNBRecvFailedTransfer on a failed one.  Unbadged
     * would collapse both states to badge==0 and the drain would loop
     * forever on stale IPC-buffer contents.  Skips silently when
     * extra_cap_in_orch_2 is 0 · the child sees "0" in argv[4] and
     * disables the dependent feature (cmd_cron for sotShell). */
    seL4_CPtr extra_child_slot_2 = 0;
    if (extra_cap_in_orch_2 != 0) {
        cspacepath_t extra_path_2;
        vka_cspace_make_path(vka, extra_cap_in_orch_2, &extra_path_2);
        extra_child_slot_2 = sel4utils_mint_cap_to_process(
            &child, extra_path_2, seL4_AllRights, BADGE_SOTCRON_OPERATOR);
        if (extra_child_slot_2 == 0) {
            printf("[orch] spawn_native(%s): mint extra cap 2 (slot=%lu) failed · feature disabled\n",
                   binname, (unsigned long)extra_cap_in_orch_2);
        } else {
            printf("[orch] spawn_native(%s): extra cap 2 minted · child_slot=%lu badge=0x%lx (sotcron EP forward)\n",
                   binname, (unsigned long)extra_child_slot_2,
                   (unsigned long)BADGE_SOTCRON_OPERATOR);
        }
    }

    /* Build argv: argv[0]=binname, argv[1]=orch_ep_slot, argv[2]=io_port_slot,
     * argv[3]=sotinit_ep_slot (β · PR 5 · 0 if not forwarded),
     * argv[4]=sotcron_ep_slot (β · PR 9 · 0 if not forwarded). */
    char slot_str[32];
    char io_slot_str[32];
    char extra_slot_str[32];
    char extra_slot_str_2[32];
    snprintf(slot_str,         sizeof(slot_str),         "%lu", (unsigned long)child_slot);
    snprintf(io_slot_str,      sizeof(io_slot_str),      "%lu", (unsigned long)io_port_child_slot);
    snprintf(extra_slot_str,   sizeof(extra_slot_str),   "%lu", (unsigned long)extra_child_slot);
    snprintf(extra_slot_str_2, sizeof(extra_slot_str_2), "%lu", (unsigned long)extra_child_slot_2);
    char *argv[6];
    argv[0] = (char *)binname;
    argv[1] = slot_str;
    argv[2] = io_slot_str;
    argv[3] = extra_slot_str;
    argv[4] = extra_slot_str_2;
    argv[5] = NULL;

    err = sel4utils_spawn_process_v(&child, vka, vs,
                                     5, argv, 1 /* resume */);
    if (err) {
        printf("[orch] spawn_native(%s): spawn_process_v failed (err=%d)\n",
               binname, err);
        return -1;
    }

    printf("[orch] spawn_native(%s) OK · shell_ep=%lu child_slot=%lu extra_slot=%lu extra_slot_2=%lu\n",
           binname, (unsigned long)shell_ep_obj.cptr,
           (unsigned long)child_slot, (unsigned long)extra_child_slot,
           (unsigned long)extra_child_slot_2);

    if (out_shell_ep) *out_shell_ep = shell_ep_obj.cptr;
    return 0;
}

/*
 * orch_spawn_bench — spawn a performance-benchmark harness.
 *
 * Mirrors orch_spawn_native's byte-load path (no-ELF config + manual
 * elf_newFile + sel4utils_elf_load + auxv bookkeeping) but, instead of
 * minting a fresh orch callback EP, it COPIES orch's STO endpoint (sto_ep,
 * already badged 0xA003 in orch's CSpace) into the child and passes that slot
 * as argv[1] — the bench's `session_ep` contract (it seL4_Calls the STO
 * server directly and times the roundtrip). No IO/sotinit/sotcron caps.
 *
 *   binname   : "sotOs-bench_<name>" (resolved to bytes by the caller)
 *   sto_ep    : orch_get_sto_ep() · the STO server endpoint to hand the bench
 * Returns 0 on success, -1 on failure.
 */
int orch_spawn_bench(const char *binname, const void *elf_bytes,
                     unsigned long elf_size, seL4_CPtr sto_ep, seL4_Word badge,
                     seL4_CPtr *out_done_ep)
{
    if (orch_env_init() != 0) return -1;
    vka_t    *vka  = orch_vka();
    simple_t *simp = orch_simple();
    vspace_t *vs   = orch_parent_vspace_ptr();

    /* badge == 0 → copy orch's badged (0xA003) STO EP as-is (micro_baseline ·
     *              only needs a replying endpoint for the invalid-op ping).
     * badge != 0 → sto_ep is the UNBADGED listen EP · mint a DISTINCT
     *              per-bench session badge from it so the STO-session benches
     *              (sto_ops/throughput/sweep_cost) get their own tx namespace. */
    if (sto_ep == 0) {
        printf("[orch] spawn_bench(%s): no STO EP available · bench would halt\n", binname);
        return -1;
    }

    sel4utils_process_config_t config = process_config_default_simple(
        simp, binname, seL4_MaxPrio);
    config = process_config_mcp(config, seL4_MaxPrio);

    sel4utils_process_t child;
    int err;

    if (elf_bytes != NULL) {
        config.is_elf = false;
        err = sel4utils_configure_process_custom(&child, vka, vs, config);
        if (err) {
            printf("[orch] spawn_bench(%s): configure_process_custom failed (err=%d)\n", binname, err);
            return -1;
        }
        elf_t elf;
        if (elf_newFile(elf_bytes, (size_t)elf_size, &elf)) {
            printf("[orch] spawn_bench(%s): elf_newFile failed\n", binname);
            return -1;
        }
        void *entry = sel4utils_elf_load(&child.vspace, vs, vka, vka, &elf);
        if (entry == NULL) {
            printf("[orch] spawn_bench(%s): sel4utils_elf_load failed\n", binname);
            return -1;
        }
        child.entry_point = entry;
        child.sysinfo = sel4utils_elf_get_vsyscall(&elf);
        child.num_elf_phdrs = sel4utils_elf_num_phdrs(&elf);
        child.elf_phdrs = calloc(child.num_elf_phdrs, sizeof(Elf_Phdr));
        if (child.elf_phdrs == NULL) {
            printf("[orch] spawn_bench(%s): elf_phdrs calloc failed\n", binname);
            return -1;
        }
        sel4utils_elf_read_phdrs(&elf, child.num_elf_phdrs, child.elf_phdrs);
        for (uint32_t i = 0; i < child.num_elf_phdrs; i++)
            if (child.elf_phdrs[i].p_type == PT_PHDR)
                child.elf_phdrs[i].p_type = PT_NULL;
    } else {
        err = sel4utils_configure_process_custom(&child, vka, vs, config);
        if (err) {
            printf("[orch] spawn_bench(%s): configure_process_custom failed (err=%d)\n", binname, err);
            return -1;
        }
    }

    /* Give the bench its argv[1] STO session cap.  badge==0 → copy orch's
     * badged 0xA003 EP (baseline ping); badge!=0 → mint a fresh per-bench
     * badge from the unbadged listen EP (sto_ep) so the bench has its own
     * STO tx namespace. */
    seL4_CPtr sto_child_slot;
    if (badge == 0) {
        sto_child_slot = sel4utils_copy_cap_to_process(&child, vka, sto_ep);
    } else {
        cspacepath_t sto_path;
        vka_cspace_make_path(vka, sto_ep, &sto_path);
        sto_child_slot = sel4utils_mint_cap_to_process(&child, sto_path,
                                                        seL4_AllRights, badge);
    }
    if (sto_child_slot == 0) {
        printf("[orch] spawn_bench(%s): %s STO cap into child failed\n",
               binname, badge == 0 ? "copy" : "mint");
        return -1;
    }

    /* Isolation · a fresh orch-owned "done" EP minted into the bench as argv[2].
     * The bench seL4_Sends on it after emitting its JSON; orch seL4_Recvs on it
     * (in the SPAWN_BENCH handler) so the bench runs ALONE — orch and the shell
     * stay blocked until it finishes, giving clean (un-preempted) numbers. */
    vka_object_t done_ep_obj;
    if (vka_alloc_endpoint(vka, &done_ep_obj) != 0) {
        printf("[orch] spawn_bench(%s): vka_alloc_endpoint(done) failed\n", binname);
        return -1;
    }
    cspacepath_t done_path;
    vka_cspace_make_path(vka, done_ep_obj.cptr, &done_path);
    seL4_CPtr done_child_slot = sel4utils_mint_cap_to_process(&child, done_path,
                                                              seL4_AllRights, 0);
    if (done_child_slot == 0) {
        printf("[orch] spawn_bench(%s): mint done EP into child failed\n", binname);
        return -1;
    }

    char slot_str[32], done_str[32];
    snprintf(slot_str, sizeof(slot_str), "%lu", (unsigned long)sto_child_slot);
    snprintf(done_str, sizeof(done_str), "%lu", (unsigned long)done_child_slot);
    char *argv[4];
    argv[0] = (char *)binname;
    argv[1] = slot_str;
    argv[2] = done_str;
    argv[3] = NULL;

    err = sel4utils_spawn_process_v(&child, vka, vs, 3, argv, 1 /* resume */);
    if (err) {
        printf("[orch] spawn_bench(%s): spawn_process_v failed (err=%d)\n", binname, err);
        return -1;
    }

    if (out_done_ep) *out_done_ep = done_ep_obj.cptr;
    printf("[orch] spawn_bench(%s) OK · sto_session_slot=%lu · badge=0x%lx · done_ep=%lu\n",
           binname, (unsigned long)sto_child_slot, (unsigned long)badge,
           (unsigned long)done_ep_obj.cptr);
    return 0;
}
