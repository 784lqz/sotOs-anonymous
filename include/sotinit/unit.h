/* sotOs · sotinit · unit registry types.
 *
 * A unit is the systemd-style abstraction the operator activates and the
 * launcher tracks.  PR 1 declares the data layout only · subsequent PRs
 * wire in:
 *   - PR 2 · INI -> unit_t parser and SHM-backed registry array
 *   - PR 3 · launcher (procd OP_SPAWN client) + procd_slot back-link
 *   - PR 4 · After= dependency graph + topological sort
 *   - PR 6 · restart policy + EV_PROC_EXITED drainer
 *
 * Sizing rationale (UNIT_*_MAX):
 *   NAME_MAX=64  · systemd-style "name.service" leaves head-room for our
 *                  longest expected unit names (e.g. "lucas-orch.service").
 *   DESC_MAX=128 · one-line Description= matches typical .service files.
 *   EXEC_MAX=256 · ExecStart= line · enough for argv split + paths.
 *
 * Spec: init-cron-scheduler-design §4.1.
 */
#ifndef SOTINIT_UNIT_H
#define SOTINIT_UNIT_H

#include <stdint.h>

#define SOTINIT_MAX_UNITS 64
#define SOTINIT_NAME_MAX  64
#define SOTINIT_DESC_MAX  128
#define SOTINIT_EXEC_MAX  256
#define SOTINIT_MAX_AFTER 3

typedef enum {
    UNIT_KIND_SERVICE = 1,
    UNIT_KIND_TIMER   = 2,
    UNIT_KIND_TARGET  = 3,
} unit_kind_t;

typedef enum {
    UNIT_STATE_LOADED   = 1,
    UNIT_STATE_ACTIVE   = 2,
    UNIT_STATE_FAILED   = 3,
    UNIT_STATE_DISABLED = 4,
} unit_state_t;

/* γ · PR 7 · unit_t.flags bitfield.
 *
 * UNIT_FLAG_F_PERSISTENCE is set by sotinit_sotfs_scan when a unit's
 * backing sotfs inode carries functor_persistence=1.  PR 8 wires the
 * activate-side skip behavior · sotinit_activate_service checks this
 * flag and emits an AUDIT (kind=SOTGUARD_KIND_PERSISTENCE_DEFER) instead
 * of dispatching the service to procd.  The same flag drives sotcron's
 * never-fire guard (PR 9).
 */
#define UNIT_FLAG_F_PERSISTENCE  (1u << 0)
#define UNIT_FLAG_ACTIVATE_LOGGED (1u << 1)  /* idempotent-activate line already printed once */

typedef struct {
    uint32_t      index;
    unit_kind_t   kind;
    unit_state_t  state;
    char          name[SOTINIT_NAME_MAX];
    char          description[SOTINIT_DESC_MAX];
    char          exec_start[SOTINIT_EXEC_MAX];
    char          on_calendar[64];
    char          timer_unit[64];
    uint32_t      procd_slot;
    uint32_t      restart_policy;
    uint64_t      next_fire_tsc;
    uint64_t      last_fire_tsc;
    /* PR 4 · After= dependency names · whitespace-split from the
     * `[Unit] After=` directive · sotinit_topo_sort walks these to
     * build the activation order.  Capped at SOTINIT_MAX_AFTER=3 per
     * unit · enough for the demo (demo-b → demo-a) plus head-room for
     * a small fan-in (e.g. "After=multi-user.target network.target"). */
    char          after[SOTINIT_MAX_AFTER][SOTINIT_NAME_MAX];
    uint8_t       after_count;
    uint8_t       _pad[3];     /* explicit pad before 4-byte flags */
    uint32_t      flags;       /* γ · PR 7 · UNIT_FLAG_* bitfield */
} unit_t;

/* Plan budget · 900 B is the post-PR-4 upper bound.  PR 4 added 3 × 64-byte
 * name slots + a 1-byte counter (192 B + padding · live sizeof = 816 B).
 * Char-array fields are 8-aligned which keeps the layout dense; if a future
 * PR grows the trailing 8-byte scalars beyond 4, raise this in lockstep
 * with the actual layout. */
_Static_assert(sizeof(unit_t) <= 900, "unit_t too large");

/* ── unit registry (PR 2) ─────────────────────────────────────────────────
 *
 * Backing store + lookup API · bounded by SOTINIT_MAX_UNITS.  Today the
 * table lives in sotinit's .bss; a later PR moves it into a 64 KiB SHM
 * region shared read-only with sotcron (spec §4.5).  Call sites depend
 * only on these prototypes so the storage swap is invisible.
 */
unit_t  *sotinit_unit_alloc(void);
unit_t  *sotinit_unit_by_index(uint32_t idx);
unit_t  *sotinit_unit_by_name(const char *name);
unit_t  *sotinit_unit_by_procd_slot(uint32_t slot);
uint32_t sotinit_unit_count(void);
unit_t  *sotinit_unit_table(void);

/* Scan + parse the bundled `/etc/systemd/system/*.{service,timer,target}`
 * candidates · returns the number of units successfully loaded, or a
 * negative value if the source directory is unreachable.  Prints the
 * "[sotinit] N unit files found" + "[sotinit] loaded N units" banners
 * that the smoke gates assert against.
 */
int sotinit_scan_units(const char *dir);

/* γ · PR 7 · sotfs scan for F_persistence units.
 *
 * Walks a hardcoded list of paths known to be common persistence-install
 * targets (systemd backdoor.service / backdoor.timer) and seL4_Calls
 * orch's ORCH_OP_F_PERSIST_STAT op to ask the in-orch sotfs graph
 * whether each path resolves to an inode with functor_persistence=1.
 * Tagged hits are added to the unit registry as stub LOADED units with
 * UNIT_FLAG_F_PERSISTENCE set · PR 8 wires the activate guard so they
 * never reach procd, and sotcron's PR 9 sister scan keeps timer-style
 * persistence files from firing.
 *
 * Returns the number of units successfully loaded into the registry.
 * Today the path list is bounded + hardcoded (γ scope); generalized
 * directory listing is a δ follow-up once sotfs grows a readdir IPC.
 *
 * Boot-time behavior: sotinit_sotfs_scan() at boot is observationally a
 * no-op (logs "deferred" + returns 0) because orch's inner sotShell
 * command-window loop blocks the listen_ep at that time.  PR 8 wires
 * the per-unit query via sotinit_f_persist_stat_ipc() from
 * sotinit_activate_service · IPC succeeds there since orch has left
 * the inner shell loop by activation time.
 */
int sotinit_sotfs_scan(void);

/* γ · PR 8 · activate-time sotfs scan · runs the actual ORCH_OP_F_PERSIST_STAT
 * IPC for each path in sotinit_sotfs_paths[].  Called from main.c at the top
 * of the activate loop · post boot orch has left its inner sotShell command
 * loop so the seL4_Call to the listen_ep succeeds.  Tagged hits become stub
 * LOADED units with UNIT_FLAG_F_PERSISTENCE set; the activate guard in
 * launcher.c short-circuits them so they never reach procd.  Returns the
 * count of units successfully loaded into the registry. */
int sotinit_sotfs_scan_now(void);

/* γ · PR 7 · single-path F_persistence query helper.
 *
 * seL4_Call ORCH_OP_F_PERSIST_STAT for `path` and return:
 *   >0  · path resolves to a sotfs inode with functor_persistence=1
 *    0  · path does not resolve OR inode has functor_persistence=0
 *   <0  · IPC EP unavailable (audit_ep never set · caller treats as 0)
 *
 * Exposed alongside sotinit_sotfs_scan so PR 8's activate-side guard
 * can issue the query directly per-unit without duplicating the wire
 * format.  Hardcoded path list lives in sotinit_sotfs_paths[] (also
 * exported) for PR 9's sotcron sister scan to reuse. */
int sotinit_f_persist_stat_ipc(const char *path);

extern const char *sotinit_sotfs_paths[];

/* ── topological sort (PR 4) ──────────────────────────────────────────────
 *
 * Kahn's algorithm over the After= dependency DAG.  Writes the activation
 * order (indices into the unit table) into `out_order` and the count into
 * `*out_n`.  Returns 0 on success and -1 on cycle detection · in the
 * cycle case the remaining units are appended in definition order so the
 * caller can still drive activation (degraded but progresses).  The
 * "[sotinit] CYCLE_DETECTED · N units left out" diagnostic is printed on
 * the fallback path.
 */
int sotinit_topo_sort(uint32_t *out_order, uint32_t *out_n);

#endif
