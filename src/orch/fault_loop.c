/*
 * sotOs · orchestrator · shared fault EP loop (L3b-T1).
 *
 * orch_fault_loop runs in orch's main thread after all sotBoxes have been
 * initialised.  It calls seL4_NBRecv on the shared fault EP (non-blocking
 * busy-poll: when no fault is pending it drives sotnet_poll + tcp_timer_tick
 * + seL4_Yield to keep the inbound TCP stack live), reads the badge to
 * identify the faulting sotBox, and dispatches to lucas_handle_one_fault.
 *
 * Badge encoding (set by client_setup.c via vka_cnode_mint):
 *   badge = st->slot_index + 1
 * Badge 0 means an unbadged message · treated as a protocol error and ignored.
 *
 * The loop exits when sotbox_alive_count() reaches 0 (all sotBoxes have
 * called exit/exit_group and been freed from the slot table).
 */

#include <orch/sotbox.h>
#include <orch/proto.h>          /* ORCH_OP_SOTCTL · operator shell op labels */
#include <sotabi/proto.h>        /* SOTABI_OP_SESSIONS · sotctl default view */
#include <lucas/syscalls.h>
#include <sel4/sel4.h>
#include <vka/capops.h>
#include <stdio.h>
#include <sottrace/trace.h>

/* Defined in lucas/fault_loop.c (part of sotOs-lucas static lib). */
extern int lucas_handle_one_fault(lucas_state_t *st, seL4_MessageInfo_t info);

/* L3b-T2: declared in sotbox.h · forward-declare here for clarity. */
extern int sotbox_try_wakeup_waiter(int exited_pid, int exit_code);

/* Per-syscall trace prints (wait4-defer / execve-reply).  These fire on EVERY
 * deferred wait4 and every execve — fine during bring-up, but in an interactive
 * boot (`just run-interactive`) orch's printf tees to the framebuffer console, so
 * they flood the honey-shell view an attacker sees (a deception leak) and bury the
 * shell prompt.  Off by default; set to 1 to re-enable the bring-up trace. */
#ifndef ORCH_FAULTLOOP_VERBOSE
#define ORCH_FAULTLOOP_VERBOSE 0
#endif
#if ORCH_FAULTLOOP_VERBOSE
#define FL_TRACE(...) printf(__VA_ARGS__)
#else
#define FL_TRACE(...) ((void)0)
#endif

extern int  sotnet_poll(void);     /* drains one inbound frame · -1 if RX empty */
extern void tcp_timer_tick(void);  /* retransmit/timeout timers · self-gated */
extern void lucas_console_resume_parked(void); /* wake a shell parked on read(fd0) */
extern void orch_bytepipe_drain_in_p2c_pub(void); /* SSH replies flow while busybox runs */
extern void orch_ssh_shell_kick_out(void);        /* wake net-synth to pump busybox stdout */
extern void kbd_poll(void);    /* virtio-keyboard · no-op if no device (headless) */
extern void mouse_poll(void);  /* virtio-tablet  · no-op if no device · moves the cursor */
extern int  g_doom_request;    /* M2 · operator typed 'doom' in the terminal */
extern void orch_spawn_doom_pool(void);  /* spawn Doom into the current fault loop */
extern int  g_python_request;  /* attacker execve('python') in the canary shell */
extern void orch_spawn_python_pool(void);/* spawn CPython into the current fault loop */
extern int  g_apt_request;     /* Debian attacker execve('apt'/'apt-get'/'apt-cache') */
extern void orch_spawn_apt_pool(void);   /* spawn the REAL apt into a heavy arena, contained */
extern int  g_apk_request;     /* Alpine attacker execve('apk') */
extern void orch_spawn_apk_pool(void);   /* spawn the REAL apk into a heavy arena, contained */
extern int  g_hx_request;      /* attacker execve('d a LARGE binary (micro/Go) too big for the regular arena */
extern void orch_spawn_heavy_exec_pool(void); /* respawn the staged large binary into a heavy box */
extern int  g_sotctl_request;  /* operator typed `sotctl <sub>` in the trusted shell */
extern void orch_spawn_sotctl_pool(void);/* spawn the NATIVE sotctl + serve its render-stream */
extern int  kbd_f12_take(void);/* F12 toggle · operator pressed F12 (clears) */
extern int  g_bbsh_exit_f12;   /* set when this loop exits because of F12 (vs a guest exit) */
/* OPERATOR-DURING-ATTACK · the operator's sotShell command endpoint + the sotctl
 * op/arg.  While a live SSH attacker keeps orch in THIS nested loop, main()'s
 * command-window poll of shell_ep is suspended, so an operator `sotctl` would hang.
 * This loop polls shell_ep too and services the truth-plane (ORCH_OP_SOTCTL) so the
 * operator can OBSERVE + set egress policy WHILE the attacker is active. */
extern seL4_CPtr g_orch_shell_ep;
extern int       g_sotctl_op;
extern uint32_t  g_sotctl_arg;
extern bool      g_ssh_shell_active;   /* gate: poll shell_ep only during a live SSH session */

void orch_fault_loop(seL4_CPtr shared_ep) {
    printf("[orch] orch_fault_loop entering · shared_ep=%lu · alive=%d\n",
           (unsigned long)shared_ep, sotbox_alive_count());

    while (sotbox_alive_count() > 0) {
        /* HARDENING · service the inbound deception path + the stuck-conn reaper on
         * EVERY iteration, not only in the badge==0 idle branch below: a sotbox faulting
         * in a tight loop keeps badge!=0 and would otherwise starve :443/:80 responses
         * and tcp_timer_tick's reaper.  These are orthogonal to the fault handled below,
         * and the in_p2c drain is re-entrancy-safe (it stashes a SHELL_START rather than
         * re-entering this loop).  So a live SSH attacker — or a fault storm — no longer
         * dims the TLS/HTTP bait or lets stuck conns leak. */
        (void)sotnet_poll();              /* inbound request bytes → in_c2p (net-synth)   */
        tcp_timer_tick();                 /* retransmit timers + idle/stuck-conn reaper    */
        orch_bytepipe_drain_in_p2c_pub(); /* net-synth replies → tcp_send_data (ALL conns) */

        seL4_Word badge = 0;
        sottrace_drain_to_serial();          /* gated: no-op unless g_trace_live */
        seL4_MessageInfo_t info = seL4_NBRecv(shared_ep, &badge);

        if (badge == 0) {
            /* v1 · no fault pending · operator/input housekeeping only (the inbound TCP
             * pump, reaper and in_p2c drain were hoisted above so a fault storm can't
             * starve them).  seL4_Yield keeps this a cooperative busy-poll. */
            kbd_poll();                      /* continuous input: keys flow into the ring */
            mouse_poll();                    /* continuous input: cursor moves even when idle */
            { extern void gpu_flush_if_dirty(void);   /* coalesced present · one full-screen
                                              * flush per idle pass (vs a flood per commit) */
              gpu_flush_if_dirty(); }
            if (g_doom_request) {            /* operator typed 'doom' → spawn it into THIS loop */
                g_doom_request = 0;
                orch_spawn_doom_pool();
            }
            if (g_python_request) {          /* attacker ran 'python' → spawn CPython here */
                g_python_request = 0;
                orch_spawn_python_pool();
            }
            if (g_apt_request) {             /* Debian attacker ran 'apt' → heavy-arena apt here */
                g_apt_request = 0;
                orch_spawn_apt_pool();
            }
            if (g_apk_request) {             /* Alpine attacker ran 'apk' → heavy-arena apk here */
                g_apk_request = 0;
                orch_spawn_apk_pool();
            }
            if (g_hx_request) {              /* attacker ran a LARGE binary (micro/Go) → heavy box */
                g_hx_request = 0;
                orch_spawn_heavy_exec_pool();
            }

            if (g_sotctl_request) {          /* operator ran `sotctl <sub>` → native CLI */
                g_sotctl_request = 0;
                orch_spawn_sotctl_pool();
            }
            /* OPERATOR-DURING-ATTACK · poll the operator's shell_ep so `sotctl`
             * works WHILE a live SSH attacker keeps orch in this nested loop (the
             * sotctl-freeze the operator hit).  g_orch_shell_ep is 0 until main()
             * opens the command window (after boot demos), so boot/demo loops skip
             * this.  Badge != 0 = a real op (cap is BADGE_SOTSHELL_OPERATOR); an
             * empty NBRecv zeroes the badge.  Only SOTCTL is serviced here (it
             * renders inline · no nested loop / no IPC, so the reply cap from this
             * NBRecv stays valid); any other op gets a benign error reply so the
             * operator's Call returns instead of hanging (retry after the session). */
            if (g_orch_shell_ep != 0 && g_ssh_shell_active) {
                seL4_Word op_badge = 0;
                seL4_MessageInfo_t op_info = seL4_NBRecv(g_orch_shell_ep, &op_badge);
                if (op_badge != 0) {
                    seL4_Word op = seL4_MessageInfo_get_label(op_info);
                    if (op == ORCH_OP_SOTCTL) {
                        seL4_Word len = seL4_MessageInfo_get_length(op_info);
                        g_sotctl_op  = (len >= 2) ? (int)seL4_GetMR(1) : SOTABI_OP_SESSIONS;
                        g_sotctl_arg = (len >= 3) ? (uint32_t)seL4_GetMR(2) : 0;
                        orch_spawn_sotctl_pool();
                        seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                    } else {
                        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));  /* busy · not serviceable mid-attacker */
                    }
                }
            }
            if (kbd_f12_take()) {            /* operator pressed F12 → hand the window
                                             * back to the sotShell operator console */
                g_bbsh_exit_f12 = 1;
                /* Tear the interactive primary (slot 0) down EXACTLY like a guest
                 * exit (the result==1 path below) so alive_count→0 and this loop
                 * returns via its NATURAL condition — that is the path whose
                 * reply-to-sotShell works.  A bare `break` returns through a
                 * different door (last op was an empty NBRecv) and the bbsh
                 * handler's post-loop seL4_Reply never reaches sotShell. */
                lucas_state_t *prim = sotbox_get_slot(0);   /* NULL when slot free */
                if (prim) {
                    int slot = prim->slot_index;
                    sotbox_record_exit(prim->synthetic_pid, 0);
                    if (prim->waiting_reply_cap != 0) {
                        cspacepath_t rp;
                        vka_cspace_make_path(prim->vka, prim->waiting_reply_cap, &rp);
                        seL4_CNode_Delete(rp.root, rp.capPtr, rp.capDepth);
                        vka_cspace_free(prim->vka, prim->waiting_reply_cap);
                        prim->waiting_reply_cap = 0;
                    }
                    sotbox_destroy(slot);
                    sotbox_free_slot(slot);
                    sotbox_fork_release_storage(prim);
                }
                continue;   /* alive_count==0 next check → loop returns like a guest exit */
            }
            lucas_console_resume_parked();   /* wake a shell parked on read(fd0) */
            orch_ssh_shell_kick_out();       /* wake net-synth to pump busybox stdout */
            seL4_Yield();
            continue;
        }

        lucas_state_t *st = sotbox_lookup_by_badge(badge);
        if (!st) {
            printf("[orch] orch_fault_loop: unknown badge=%lu · ignored\n",
                   (unsigned long)badge);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
            continue;
        }

        /* zero-leak · charge any client-vspace bookkeeping grown while serving
         * this fault (lazy mmap/brk/execve) to the faulting box's window+arena. */
        extern void orch_set_vspace_owner(lucas_state_t *st);
        orch_set_vspace_owner(st);
        int result = lucas_handle_one_fault(st, info);
        orch_set_vspace_owner(NULL);
        if (result == -2) {
            /* L3b-T2: wait4 DEFERRED · sotBox is parked with a saved reply
             * cap.  Do NOT reply (handler already skipped it), do NOT free
             * the slot.  Just loop back to seL4_Recv.
             * alive_count() still includes this sotBox so the loop continues. */
            FL_TRACE("[orch] sotbox pid=%d wait4 DEFERRED · loop continues\n",
                     st->synthetic_pid);
            continue;
        }
        if (result == -3) {
            /* L3b-T3: execve REPLY_RAW · handler reset registers and already
             * called seL4_Reply.  sotBox is live with a new image; keep looping. */
            FL_TRACE("[orch] sotbox pid=%d execve REPLY_RAW · new image running\n",
                     st->synthetic_pid);
            continue;
        }
        if (result == 1) {
            /* Client exited: record in zombie table, free slot.
             * This covers both the normal lucas_sys_exit_group path and
             * forced exits (e.g. VM fault cap limit).  lucas_sys_exit_group
             * already called sotbox_try_wakeup_waiter (to unblock a waiting
             * parent via SaveCaller before returning); we call
             * sotbox_record_exit here for the normal exit path so the zombie
             * is visible to future wait4 calls (quick-path reap). */
            int pid  = st->synthetic_pid;
            int code = st->exit_code;
            int slot = st->slot_index;
            int ppid = (st->parent_slot >= 0) ? (st->parent_slot + 1) : 0;
            printf("[orch] sotBox pid=%d (slot=%d) exited code=%d · reaping\n",
                   pid, slot, code);
            extern void sotbox_record_exit_p(int pid, int exit_code, int parent_pid);
            extern int  sotbox_try_wakeup_waiter_p(int exited_pid, int exit_code, int parent_pid);
            sotbox_record_exit_p(pid, code, ppid);
            /* For forced exits (where lucas_sys_exit_group did NOT run),
             * also try to wake a waiter now. */
            if (!st->exited) {
                sotbox_try_wakeup_waiter_p(pid, code, ppid);
            }
            /* WINE-M1 · safety net · a vfork child force-reaped by a fault
             * (never reached execve/exit) would otherwise leave its parent
             * wedged forever in WAITING_FOR_VFORK.  Resume it (no-op unless
             * this is a vfork child still borrowing the parent's vspace). */
            {
                extern void sotbox_vfork_resume_parent(lucas_state_t *st);
                sotbox_vfork_resume_parent(st);
            }
            /* WINE-M1 · safety net · a vfork child force-reaped by a fault
             * (never reached execve/exit) would otherwise leave its parent
             * wedged forever in WAITING_FOR_VFORK.  Resume it (no-op unless
             * this is a vfork child still borrowing the parent's vspace). */
            {
                extern void sotbox_vfork_resume_parent(lucas_state_t *st);
                sotbox_vfork_resume_parent(st);
            }
            /* v1.1 · a sotBox torn down while PARKED in
             * WAITING_FOR_ACCEPT/WAITING_FOR_RECV still owns the cslot it
             * allocated via vka_cspace_alloc + SaveCaller (both park paths
             * share st->waiting_reply_cap).  Neither the exit handler nor
             * sotbox_free_slot frees it, so a forced/normal exit-while-parked
             * leaks the cslot.  Free it here (the single teardown chokepoint
             * for both exit kinds).  Guarded: only when non-zero, zero after,
             * so the wait4-wakeup path (which already freed + zeroed it)
             * cannot double-free. */
            if (st->waiting_reply_cap != 0) {
                /* P2a · DELETE the kernel-minted reply cap (arena_cspace_free is a
                 * no-op + revoke won't touch a non-arena-untyped-child cap, so the
                 * cap must be explicitly deleted or the slot stays occupied). */
                cspacepath_t rp;
                vka_cspace_make_path(st->vka, st->waiting_reply_cap, &rp);
                seL4_CNode_Delete(rp.root, rp.capPtr, rp.capDepth);
                vka_cspace_free(st->vka, st->waiting_reply_cap); /* no-op for arena; frees cslot for global */
                st->waiting_reply_cap = 0;
            }
            /* P2a · arena-revoke teardown · reclaim the sotbox's whole arena
             * untyped (client PML4/TCB/CNode/IPC/ELF/stack + client-side PTs)
             * BEFORE freeing the slot. */
            /* Console FOCUS · if the box that just exited held the keyboard focus
             * (an interactive `python` REPL), return input to the shell that
             * spawned it. */
            { extern void lucas_console_clear_focus(int slot); lucas_console_clear_focus(slot); }
            sotbox_destroy(slot);
            sotbox_free_slot(slot);
            sotbox_fork_release_storage(st);   /* P2b · free the child_storage slot if forked */
            /* Note: st memory is not freed here (it lives in child_storage[]
             * in fork.c or on the stack in lucas_run_l1).  The slot is the
             * important thing to clear so sotbox_alive_count() decrements. */
        }

        /* P2b · reap any cell flagged marked_for_teardown by lucas_antidos_quarantine (a quarantined
         * fork-bomb subtree). They are suspended (won't fault again) so they must be
         * reaped explicitly here rather than via their own fault. */
        for (int s = 0; s < SOTBOX_MAX_SLOTS; ++s) {
            lucas_state_t *d = sotbox_get_slot(s);
            if (d && d->marked_for_teardown) {
                printf("[p2b] reaping marked_for_teardown slot=%d pid=%d\n", s, d->synthetic_pid);
                if (d->waiting_reply_cap != 0) {
                    cspacepath_t rp; vka_cspace_make_path(d->vka, d->waiting_reply_cap, &rp);
                    seL4_CNode_Delete(rp.root, rp.capPtr, rp.capDepth);
                    vka_cspace_free(d->vka, d->waiting_reply_cap);
                    d->waiting_reply_cap = 0;
                }
                d->marked_for_teardown = 0;
                sotbox_destroy(s);
                sotbox_free_slot(s);
                sotbox_fork_release_storage(d);
            }
        }
    }

    printf("[orch] orch_fault_loop: all sotBoxes exited\n");
}
