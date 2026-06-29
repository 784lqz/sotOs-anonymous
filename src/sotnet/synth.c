/*
 * sotOs · sotNet-γ Phase 2/3 · Synth Internet stub.
 *
 * When a sotbox at Tier 2 (isolated-write path) calls sendto, instead of
 * routing to the real network stack the request is diverted here.
 * Phase 2 scaffold: just counters + log line.
 * Phase 3-A: also forwards the event to the sotOs-net-synth server
 * process via the delegated EP (Path D).  Phase 3-B+ adds scripted
 * response_profile (synthetic HTTP responses, synthetic TLS handshakes, etc.).
 */
#include <sotnet/synth.h>
#include <sotnet/bytepipe.h>
#include <orch/proto.h>
#include <sel4/sel4.h>
#include <stdio.h>

/* sotNet γ-3-γ-1 · byte-channel readiness, defined in orch/main.c. */
extern int orch_bytepipe_ready(void);

static uint32_t g_synth_redirects_total = 0;
static uint32_t g_synth_bytes_total = 0;

/* STAR Tier-2 · PER-PID-SYNTH-COUNTER.
 * Bounded per-pid counter mirroring g_synth_redirects_total.
 * Indexed by synthetic_pid (slot+1), so index 0 is unused and indices
 * 1..ORCH_STATUS_MAX_ENTRIES hold per-sotbox counts.  Sized to
 * ORCH_STATUS_MAX_ENTRIES + 1 so the bounds check below maps the
 * full valid pid range directly without offset arithmetic. */
static uint32_t g_synth_redirects_pid[ORCH_STATUS_MAX_ENTRIES + 1];

/* sotNet-γ Phase 3-D-1 · one-shot synthetic boot trigger.
 * Fires a recognizable SYNTHETIC_C2 redirect on the FIRST organic invocation of
 * synth_record_redirect, exercising the full synth→orch callback loop
 * at boot for demo evidence (close-the-loop smoke check).  Guarded so it
 * only fires once per boot. */
static int g_synthetic_fired = 0;

extern seL4_CPtr orch_get_synth_event_ep(void);

/* Inner helper: do the actual IPC.  Split out so the synthetic boot trigger
 * can reuse it without recursing into synth_record_redirect (which would
 * re-arm g_synthetic_fired logic and could re-enter). */
static void synth_redirect_emit(uint32_t pid, uint32_t dst_ip_be,
                                   uint16_t dst_port_be, uint32_t len) {
    g_synth_redirects_total++;
    g_synth_bytes_total += len;
    /* STAR Tier-2 · PER-PID-SYNTH-COUNTER · bump per-sotbox counter.
     * Synthetic boot trigger and operator-driven trigger use pid=99 which
     * falls outside the valid 1..ORCH_STATUS_MAX_ENTRIES range and is
     * intentionally not counted per-pid (the global counter still bumps). */
    if (pid > 0 && pid <= ORCH_STATUS_MAX_ENTRIES) {
        g_synth_redirects_pid[pid]++;
    }
    printf("[synth] pid=%u tier=2 · would redirect %u.%u.%u.%u:%u (len=%u)\n",
           pid,
           dst_ip_be & 0xFF, (dst_ip_be >> 8) & 0xFF,
           (dst_ip_be >> 16) & 0xFF, (dst_ip_be >> 24) & 0xFF,
           ((dst_port_be & 0xFF) << 8) | ((dst_port_be >> 8) & 0xFF),
           len);

    /* sotNet-γ Phase 3-A · forward to the synth server.
     *
     * Phase 3-D-1 · switched from seL4_Call to seL4_NBSend.  Rationale:
     * synth_record_redirect is typically called from orch's single-threaded
     * fault-handler context (lucas_sys_sendto for a Tier 2 sotbox).  If we
     * Call (synchronous) here, orch's only thread blocks waiting for
     * synth-srv to Reply.  But synth-srv's Phase 3-C handler tries to
     * seL4_Call back into orch's main EP BEFORE replying — which would
     * deadlock because orch is suspended in the fault thread Call.
     *
     * NBSend decouples: orch fires-and-forgets the redirect, the sotbox
     * sendto returns, orch_fault_loop eventually exits, orch returns to
     * its main seL4_Recv loop, and at THAT point it receives synth-srv's
     * ORCH_OP_SYNTH_RESPONSE callback Call.  Loop closes asynchronously.
     *
     * NBSend semantics: drops the message if synth-srv is not currently
     * blocked in seL4_Recv on this EP.  At boot, synth-srv spends its
     * entire lifetime in that Recv (it's a single-purpose server), so the
     * drop case is essentially never hit. */
    seL4_CPtr ep = orch_get_synth_event_ep();
    if (ep != 0) {
        seL4_SetMR(0, pid);
        seL4_SetMR(1, dst_ip_be);
        seL4_SetMR(2, dst_port_be);
        seL4_SetMR(3, len);
        seL4_NBSend(ep,
                    seL4_MessageInfo_new(ORCH_OP_SYNTH_REDIRECT, 0, 0, 4));
    }
}

/* γ-3-ε · NBSend an operator response_profile-install to the synth server.
 * Fire-and-forget (same pattern as synth_redirect_emit) so the caller
 * (orch's shell-op handler) never blocks / clobbers its reply cap. */
void synth_install_emit(uint32_t dst_ip_be, uint16_t dst_port_be, uint32_t response_profile_kind) {
    seL4_CPtr ep = orch_get_synth_event_ep();
    if (ep == 0) return;
    seL4_SetMR(0, (seL4_Word)dst_ip_be);
    seL4_SetMR(1, (seL4_Word)dst_port_be);
    seL4_SetMR(2, (seL4_Word)response_profile_kind);
    seL4_NBSend(ep, seL4_MessageInfo_new(ORCH_OP_SYNTH_INSTALL, 0, 0, 3));
}

void synth_record_redirect(uint32_t pid, uint32_t dst_ip_be,
                              uint16_t dst_port_be, uint32_t len) {
    /* sotNet-γ Phase 3-D-1 · synthetic boot trigger.
     * On the first organic redirect (any Tier 2 sotbox sendto), additionally
     * emit a synthetic SYNTHETIC_C2 redirect (1.2.3.4:6667) to demonstrate the
     * full synth→orch close-the-loop path with a recognizable response_profile
     * destination.  One-shot guarded · won't re-fire on subsequent calls. */
    if (!g_synthetic_fired && orch_get_synth_event_ep() != 0) {
        g_synthetic_fired = 1;
        printf("[synth] Phase 3-D-1 · synthetic boot trigger · SYNTHETIC_C2 10.0.2.15:80\n");
        /* Destination matches SYNTHETIC_C2 response_profile in net-synth/response_profiles.c
         * (10.0.2.15 = 0x0F02000A, port 80 = 0x0050 as stored in the
         * response_profile table).  Either the catch-all SYNTHETIC_UPDATER or SYNTHETIC_C2
         * response_profile will match · both call response_profile_get_payload → 0 →
         * net-synth seL4_Calls back with ORCH_OP_SYNTH_RESPONSE,
         * closing the γ Phase 3-D loop visibly in the boot log. */
        /* γ-3-γ-1 · deterministic byte-channel boot probe: push a recognizable
         * 200-byte pattern through c2p (this runs in orch, which holds the c2p
         * RW mapping) so the round-trip exercises with the responder idle. */
        if (orch_bytepipe_ready()) {
            static uint8_t probe[200];
            const char *tag = "BYTEPIPE-PROBE-";  /* 15 bytes */
            for (size_t i = 0; i < sizeof(probe); ++i)
                probe[i] = (i < 15) ? (uint8_t)tag[i]
                                    : (uint8_t)('0' + (int)(i % 10));
            bytepipe_ring_t *c2p = (bytepipe_ring_t *)BYTEPIPE_C2P_VADDR;
            uint32_t pushed = bytepipe_push(c2p, probe, sizeof(probe));
            printf("[sotnet-γ] c2p tx · pid=99 pushed=%u bytes (boot probe)\n",
                   pushed);
        }
        synth_redirect_emit(/*pid=*/99,
                              /*dst_ip_be=*/0x0F02000A,
                              /*dst_port_be=*/0x0050,
                              /*len=*/200);
    }

    synth_redirect_emit(pid, dst_ip_be, dst_port_be, len);
}

uint32_t synth_get_redirects(void) { return g_synth_redirects_total; }
uint32_t synth_get_bytes(void)     { return g_synth_bytes_total; }

uint32_t synth_get_redirects_pid(uint32_t pid) {
    if (pid == 0 || pid > ORCH_STATUS_MAX_ENTRIES) return 0;
    return g_synth_redirects_pid[pid];
}

/* PR 6 · WAL replay-applies path · increments redirect totals + per-pid
 * counter using the same arithmetic synth_redirect_emit uses, but
 * silently · no synthetic boot trigger, no orch ORCH_OP_SYNTH_REDIRECT
 * IPC, no printf.  This restores the pre-reboot counter state on cold
 * boot without re-driving any live deception side effects.  Out-of-
 * range pids skip the per-pid bump (mirrors emit's clamp). */
void synth_replay_bump(uint32_t src_slot, uint32_t bytes) {
    g_synth_redirects_total++;
    g_synth_bytes_total += bytes;
    if (src_slot > 0 && src_slot <= ORCH_STATUS_MAX_ENTRIES) {
        g_synth_redirects_pid[src_slot]++;
    }
}
