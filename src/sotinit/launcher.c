/* sotOs · sotinit · service launcher (procd OP_SPAWN client).
 *
 * For each parsed UNIT_KIND_SERVICE with state == LOADED, sotinit_activate_service:
 *   1. Tokenises ExecStart= into argv[].
 *   2. Calls procd OP_SPAWN to allocate a procd slot for the service.
 *   3. Stores procd_slot back into the unit_t · flips state to ACTIVE.
 *   4. Logs `[sotinit] <name> started · slot=N synthetic_pid=M`.
 *
 * MR layout mirrors src/orch/procd_client.c::orch_procd_spawn exactly · the
 * canonical client that procd_handle_spawn was designed to accept:
 *   MR(0) = PROCD_OP_SPAWN
 *   MR(1) = caller_slot       (0 = root spawn / init)
 *   MR(2) = initial_tier      (0 = Tier 0)
 *   MR(3) = pledge & 0xFFFFFFFF
 *   MR(4) = (pledge >> 32) & 0xFFFFFFFF
 *
 * Reply:
 *   MR(0) = result (procd slot >= 0, or -errno)
 *   MR(1) = out_slot
 *   MR(2) = out_extra (synthetic_pid)
 *
 * Scope reductions (PR 3 · "Scope reductions allowed" path #2):
 *   - procd_handle_spawn is announce-only in the current procd build
 *     (PR 5/6 of procd's series · the seL4 mechanics still live in orch).
 *     sotinit's announce is sufficient to demonstrate the activation
 *     pipeline end-to-end: procd allocates the slot, publishes
 *     PROC_BORN, and prints the [procd] spawn line.  The actual ELF
 *     loader integration arrives when procd takes ownership of the
 *     seL4 mechanics (post-Stage-7 procd PR 16+).
 *   - ExecStart= is tokenised on whitespace and the argv array is built,
 *     but argv isn't currently shipped to procd (no SHM scratch for
 *     argv blobs yet · PR 7+ adds SHM cross-mapping).  The tokenisation
 *     is kept so the smoke gate proves the parser ran and the argc count
 *     surfaces in the log.
 *   - CPIO ELF resolution is deliberately skipped because sotinit does
 *     not bundle a CPIO archive (only orch does · sotinit is a small ELF
 *     by design).  When procd starts owning the seL4 mechanics it will
 *     read the ELF from the sotfs storage backend (PR 16+).
 *
 * Spec: init-cron-scheduler-design §3, §5.
 */
#include <stdio.h>
#include <string.h>
#include <sel4/sel4.h>
#include <procd/proto.h>
#include <procd/proc.h>
#include <sotinit/unit.h>
#include <sotguard/event.h>  /* β · PR 11 · SOTGUARD_KIND_SOTINIT_* audit kinds */
#include <sotos/audit_ipc.h> /* γ · PR 8 · sotos_audit_emit for NEVER_ACTIVATE */

/* procd listen EP in sotinit's CSpace · set from argv[2] in main().  0 means
 * root either did not configure procd or the mint failed · activate_service
 * marks the unit FAILED and prints "[sotinit] <name> · procd EP unavailable". */
extern seL4_CPtr g_procd_listen_ep;

/* Split "/usr/sbin/sshd -D" into argv tokens (whitespace, no shell metachars).
 * Mutates the input buffer in place · caller passes a private copy of
 * exec_start so the registry's stored line is preserved for diagnostics. */
static int split_exec(char *line, char **argv, int max) {
    int n = 0;
    char *p = line;
    while (*p && n < max - 1) {
        while (*p == ' ' || *p == '\t') *p++ = 0;
        if (!*p) break;
        argv[n++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
    }
    argv[n] = NULL;
    return n;
}

/* Call procd's OP_SPAWN to allocate a procd slot for a new service.  Mirrors
 * the MR layout in src/orch/procd_client.c::orch_procd_spawn (the canonical
 * client) · procd_handle_spawn reads (caller_slot, initial_tier, pledge) and
 * publishes PROCD_EV_PROC_BORN on success.  Returns the slot (>=0) on
 * success or -1/-errno on failure. */
int sotinit_procd_spawn(uint32_t caller_slot, uint32_t initial_tier,
                         uint64_t pledge, const char *comm,
                         uint32_t *out_slot, uint32_t *out_synthetic_pid) {
    if (g_procd_listen_ep == 0) return -1;

    /* ABI v2 · pack comm[16] into MR5,MR6 · must match the message-count
     * (7) procd_handle_spawn's dispatcher unpacks, else MR5/MR6 read stale
     * IPC-buffer bytes as the comm. */
    char commbuf[16];
    memset(commbuf, 0, sizeof(commbuf));
    if (comm) {
        size_t cn = strlen(comm);
        if (cn > 15) cn = 15;
        memcpy(commbuf, comm, cn);
    }
    uint64_t comm_lo, comm_hi;
    memcpy(&comm_lo, commbuf,     8);
    memcpy(&comm_hi, commbuf + 8, 8);

    seL4_SetMR(0, PROCD_OP_SPAWN);
    seL4_SetMR(1, (seL4_Word)caller_slot);
    seL4_SetMR(2, (seL4_Word)initial_tier);
    seL4_SetMR(3, (seL4_Word)(pledge & 0xFFFFFFFFull));
    seL4_SetMR(4, (seL4_Word)((pledge >> 32) & 0xFFFFFFFFull));
    seL4_SetMR(5, (seL4_Word)comm_lo);
    seL4_SetMR(6, (seL4_Word)comm_hi);

    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 7));
    (void)r;

    int32_t result = (int32_t)seL4_GetMR(0);
    if (out_slot)     *out_slot     = (uint32_t)seL4_GetMR(1);
    if (out_synthetic_pid) *out_synthetic_pid = (uint32_t)seL4_GetMR(2);
    return result;
}

/* Activate one UNIT_KIND_SERVICE entry · tokenise ExecStart, fire OP_SPAWN,
 * record the procd_slot back-reference, flip state to ACTIVE.  Failure
 * paths mark the unit FAILED and emit an audit line that smoke greps for.
 *
 * Per-unit cost is bounded: one SHM seqlock write in procd + one MR-only
 * round-trip · well under the 5 ms per-service activation budget in §6.2. */
int sotinit_activate_service(unit_t *u) {
    if (!u || u->kind != UNIT_KIND_SERVICE) return -1;

    /* γ · PR 8 · F_persistence short-circuit.
     *
     * Units tagged UNIT_FLAG_F_PERSISTENCE were registered by the
     * sotinit_sotfs_scan_now() pass that ran at the top of the activate
     * loop.  The sotfs inode carries functor_persistence=1, meaning the
     * backing file looks like a persistence-install (e.g. the
     * simulated_attacker Stage 7 demo's backdoor.service installed into
     * /etc/systemd/system).  Policy: stay LOADED but NEVER reach procd ·
     * no ELF loads, no procd slot, no PROC_BORN event.  We "lie" to the
     * caller by returning 0 (success) so the operator-visible list still
     * shows the unit and malware that polls `systemctl status` sees its
     * install present.  An AUDIT line + SOTGUARD_KIND_PERSISTENCE_NEVER_ACTIVATE
     * event surface the silent skip on the anomaly timeline. */
    if (u->flags & UNIT_FLAG_F_PERSISTENCE) {
        printf("[sotinit] skip activate %s · F_persistence (silent)\n",
               u->name);
        sotos_audit_emit(SOTGUARD_KIND_PERSISTENCE_NEVER_ACTIVATE,
                         u->index, /*arg0=*/0);
        u->state = UNIT_STATE_LOADED;  /* stays loaded but never active */
        return 0;  /* lie · report success so callers don't escalate */
    }

    /* Tokenise ExecStart into a private buffer so the registry copy stays
     * intact for operator queries (PR 5+ systemctl status).  argv[] points
     * into exec_copy after split_exec mutates it · the tokens are valid
     * for the duration of this function. */
    char exec_copy[SOTINIT_EXEC_MAX];
    strncpy(exec_copy, u->exec_start, sizeof(exec_copy) - 1);
    exec_copy[sizeof(exec_copy) - 1] = '\0';

    char *argv_buf[8];
    int argc = split_exec(exec_copy, argv_buf, 8);
    if (argc == 0) {
        u->state = UNIT_STATE_FAILED;
        printf("[sotinit] %s · empty ExecStart · marked FAILED\n", u->name);
        /* β · PR 11 · audit · empty ExecStart is a structural unit defect ·
         * surface as UNIT_INVALID so operators can triage from anomaly-log. */
        printf("[sotinit] AUDIT kind=0x%02x SOTINIT_UNIT_INVALID unit=%s reason=empty_execstart\n",
               (unsigned)SOTGUARD_KIND_SOTINIT_UNIT_INVALID, u->name);
        return -1;
    }

    if (g_procd_listen_ep == 0) {
        u->state = UNIT_STATE_FAILED;
        printf("[sotinit] %s · procd EP unavailable · marked FAILED\n",
               u->name);
        printf("[sotinit] AUDIT kind=0x%02x SOTINIT_SERVICE_FAILED unit=%s reason=no_procd_ep\n",
               (unsigned)SOTGUARD_KIND_SOTINIT_SERVICE_FAILED, u->name);
        return -1;
    }

    /* PR 3 scope · all services activate at Tier 0 (no pledge yet).
     * Tier/pledge per-unit configuration arrives once .service file
     * SecurityTier= / Pledge= keys land (PR 6+ · spec §4.2).  caller_slot
     * = 0 means "init" · matches procd_handle_spawn's ppid=0 convention
     * for root-initiated spawns. */
    uint32_t slot = 0;
    uint32_t synthetic_pid = 0;
    /* comm · basename of ExecStart's program (argv_buf[0]). */
    const char *svc_comm = argv_buf[0] ? argv_buf[0] : u->name;
    for (const char *q = svc_comm; q && *q; ++q) if (*q == '/') svc_comm = q + 1;
    int rc = sotinit_procd_spawn(0 /* caller_slot = init */,
                                  0 /* tier = 0 */,
                                  0ull /* pledge = none */,
                                  svc_comm,
                                  &slot, &synthetic_pid);
    if (rc < 0) {
        u->state = UNIT_STATE_FAILED;
        printf("[sotinit] %s · procd OP_SPAWN failed rc=%d · marked FAILED\n",
               u->name, rc);
        printf("[sotinit] AUDIT kind=0x%02x SOTINIT_SERVICE_FAILED unit=%s rc=%d\n",
               (unsigned)SOTGUARD_KIND_SOTINIT_SERVICE_FAILED, u->name, rc);
        return rc;
    }

    u->procd_slot = slot;
    u->state      = UNIT_STATE_ACTIVE;
    printf("[sotinit] %s started · slot=%u synthetic_pid=%u argc=%d exec=%s\n",
           u->name, slot, synthetic_pid, argc, argv_buf[0]);
    /* β · PR 11 · audit · per-service start event for the unified anomaly-log
     * timeline.  arg0=procd_slot, arg1=synthetic_pid carry the same identifiers
     * that the [sotinit] started line above already prints. */
    printf("[sotinit] AUDIT kind=0x%02x SOTINIT_SERVICE_START unit=%s slot=%u synthetic_pid=%u\n",
           (unsigned)SOTGUARD_KIND_SOTINIT_SERVICE_START, u->name, slot, synthetic_pid);
    return 0;
}
