/* sotOs · sotinit · directory scan + per-file parse.
 *
 * Wires the PR 1 INI parser into the PR 2 unit registry: for each candidate
 * unit file under the conceptual `/etc/systemd/system/` directory, allocate
 * a registry slot, parse the INI body, and route key/value pairs into the
 * appropriate unit_t fields.
 *
 * SCOPE-REDUCTION NOTE (PR 2 · "Scope reductions allowed" path #2):
 *
 *   The β spec (§3.3, §5.1) expects sotinit to walk a real sotfs directory
 *   via IPC.  sotinit runs in its own seL4 process; the sotfs graph lives
 *   inside orch and is not addressable from sotinit's CSpace until an
 *   `sotfs_query_ep` IPC channel is plumbed in PR 3 / PR 5.  Rather than
 *   block PR 2 on that IPC work, we ship the two β-mandated demo units
 *   (`multi-user.target` + `demo-noop.service`) as `.rodata` blobs inside
 *   the sotinit ELF.  The scan/parse pipeline is exercised end-to-end at
 *   boot and the smoke gates light up · only the source of the bytes is
 *   different.  When PR 3 lands the sotfs IPC channel, swap `g_bundled[]`
 *   below for a `sotfs_query_list_dir(dir, ...) + sotfs_query_read_file()`
 *   pair.  The kv_callback + sotinit_unit_alloc plumbing does NOT change.
 *
 * Spec: init-cron-scheduler-design §4.5.
 */
#include <stdio.h>
#include <string.h>
#include <sotinit/ini.h>
#include <sotinit/unit.h>
#include <sotguard/event.h>  /* β · PR 11 · SOTGUARD_KIND_SOTINIT_UNIT_INVALID */

/* ── bundled demo units (Option C · embedded in .rodata) ────────────────
 *
 * Kept here (not in a separate translation unit) so the entire scan path
 * is reviewable in one place.  The two β-mandated demo unit files match
 * spec §4.1 / §4.3 verbatim.
 */
static const char k_demo_multi_user_target[] =
    "[Unit]\n"
    "Description=Multi-user run level\n";

static const char k_demo_noop_service[] =
    "[Unit]\n"
    "Description=Beta-demo no-op service\n"
    "[Service]\n"
    "Type=simple\n"
    "ExecStart=/bin/true\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n";

/* PR 4 · ordering-test fixtures.  demo-a has no deps · demo-b declares
 * After=demo-a.service.  Kahn's algorithm must emit demo-a first; the
 * smoke gate proves this by greping for the "started" lines in order.
 * Registry insertion order is intentionally inverted (B before A) so a
 * naive linear-walk launcher would FAIL the smoke check · the only way
 * to pass is for sotinit_topo_sort to flip the order. */
static const char k_demo_a_service[] =
    "[Unit]\n"
    "Description=Demo A (first)\n"
    "[Service]\n"
    "Type=simple\n"
    "ExecStart=/bin/true\n";

static const char k_demo_b_service[] =
    "[Unit]\n"
    "Description=Demo B (after A)\n"
    "After=demo-a.service\n"
    "[Service]\n"
    "Type=simple\n"
    "ExecStart=/bin/true\n";

/* PR 6 · restart-policy demo · ExecStart=/bin/false exits with code=1
 * which triggers Restart=on-failure.  The procd announce-only path
 * doesn't actually fork the child today (procd PR 5/6 punted ELF load
 * to a future series) so the spawn lifecycle is observable but the
 * exit isn't auto-fired here · operator can synthesize one via the
 * SHM ring or via a future `procd-test` opcode.  PR 6's value is the
 * machinery (parser → registry → sotinit_on_proc_exited dispatch →
 * sotinit_activate_service) being in place and exercisable. */
static const char k_demo_fail_service[] =
    "[Unit]\n"
    "Description=Demo failure (exits 1)\n"
    "[Service]\n"
    "Type=simple\n"
    "ExecStart=/bin/false\n"
    "Restart=on-failure\n";

typedef struct {
    const char *name;
    const char *body;
    size_t      body_len;
} bundled_unit_t;

static const bundled_unit_t g_bundled[] = {
    { "multi-user.target", k_demo_multi_user_target,
       sizeof(k_demo_multi_user_target) - 1 },
    { "demo-noop.service", k_demo_noop_service,
       sizeof(k_demo_noop_service) - 1 },
    /* Intentionally inverted insertion order · B is parsed before A so
     * the topo sort must flip the activation order at boot. */
    { "demo-b.service", k_demo_b_service,
       sizeof(k_demo_b_service) - 1 },
    { "demo-a.service", k_demo_a_service,
       sizeof(k_demo_a_service) - 1 },
    /* PR 6 · Restart=on-failure fixture · scan/parse pipeline must
     * surface this and store restart_policy=1 in the registry · the
     * smoke gate greps for "[sotinit] demo-fail.service started" to
     * prove the unit was loaded + dispatched at boot.  Actual restart
     * loop is observable when an EV_PROC_EXITED arrives for this
     * unit's procd slot (requires the procd kill/exit path · spec §3). */
    { "demo-fail.service", k_demo_fail_service,
       sizeof(k_demo_fail_service) - 1 },
};

#define G_BUNDLED_N ((uint32_t)(sizeof(g_bundled) / sizeof(g_bundled[0])))

/* ── parser callback context ────────────────────────────────────────── */

typedef struct {
    unit_t *u;
} parse_ctx_t;

static int kv_callback(ini_section_t section,
                        const char *key, const char *value,
                        void *userdata) {
    parse_ctx_t *ctx = (parse_ctx_t *)userdata;
    unit_t *u = ctx->u;

    if (section == INI_SECTION_UNIT) {
        if (strcmp(key, "Description") == 0) {
            strncpy(u->description, value, SOTINIT_DESC_MAX - 1);
            u->description[SOTINIT_DESC_MAX - 1] = '\0';
        } else if (strcmp(key, "After") == 0) {
            /* PR 4 · whitespace-split After= value · store up to
             * SOTINIT_MAX_AFTER dependency names.  Tokens longer than
             * SOTINIT_NAME_MAX-1 are truncated · matches systemd's
             * forgiving behavior for over-long names. */
            const char *p = value;
            while (*p && u->after_count < SOTINIT_MAX_AFTER) {
                while (*p == ' ' || *p == '\t') p++;
                if (!*p) break;
                const char *start = p;
                while (*p && *p != ' ' && *p != '\t') p++;
                size_t len = (size_t)(p - start);
                if (len >= SOTINIT_NAME_MAX) len = SOTINIT_NAME_MAX - 1;
                memcpy(u->after[u->after_count], start, len);
                u->after[u->after_count][len] = 0;
                u->after_count++;
            }
        }
    } else if (section == INI_SECTION_SERVICE) {
        if (strcmp(key, "ExecStart") == 0) {
            strncpy(u->exec_start, value, SOTINIT_EXEC_MAX - 1);
            u->exec_start[SOTINIT_EXEC_MAX - 1] = '\0';
        } else if (strcmp(key, "Restart") == 0) {
            if      (strcmp(value, "no")         == 0) u->restart_policy = 0;
            else if (strcmp(value, "on-failure") == 0) u->restart_policy = 1;
            else if (strcmp(value, "always")     == 0) u->restart_policy = 2;
        } else if (strcmp(key, "Type") == 0) {
            if (strcmp(value, "simple") != 0) {
                printf("[sotinit] %s · WARNING · unsupported Type=%s\n",
                       u->name, value);
            }
        }
    } else if (section == INI_SECTION_TIMER) {
        if (strcmp(key, "OnCalendar") == 0) {
            strncpy(u->on_calendar, value, sizeof(u->on_calendar) - 1);
            u->on_calendar[sizeof(u->on_calendar) - 1] = '\0';
        } else if (strcmp(key, "OnUnitActiveSec") == 0) {
            strncpy(u->on_calendar, value, sizeof(u->on_calendar) - 1);
            u->on_calendar[sizeof(u->on_calendar) - 1] = '\0';
        } else if (strcmp(key, "Unit") == 0) {
            strncpy(u->timer_unit, value, sizeof(u->timer_unit) - 1);
            u->timer_unit[sizeof(u->timer_unit) - 1] = '\0';
        }
    }
    return 0;
}

static unit_kind_t kind_from_filename(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    if (strcmp(dot, ".service") == 0) return UNIT_KIND_SERVICE;
    if (strcmp(dot, ".timer")   == 0) return UNIT_KIND_TIMER;
    if (strcmp(dot, ".target")  == 0) return UNIT_KIND_TARGET;
    return 0;
}

int sotinit_scan_units(const char *dir) {
    /* PR 2 · use the bundled demo-unit list as the candidate set.  The
     * `dir` argument is retained for logging + API compatibility with
     * the PR 3+ sotfs IPC swap-in. */
    uint32_t n = G_BUNDLED_N;
    printf("[sotinit] %u unit files found in %s\n",
           (unsigned)n, dir ? dir : "(null)");

    uint32_t loaded = 0;
    for (uint32_t i = 0; i < n; i++) {
        const bundled_unit_t *src = &g_bundled[i];
        unit_kind_t kind = kind_from_filename(src->name);
        if (kind == 0) {
            /* β · PR 11 · audit · file rejected for unknown suffix.  The
             * bundled list is curated so this branch is unreachable today,
             * but emitting the kind here makes the contract visible for
             * the future sotfs-IPC scan path where arbitrary directories
             * may contain stray files. */
            printf("[sotinit] AUDIT kind=0x%02x SOTINIT_UNIT_INVALID name=%s reason=unknown_suffix\n",
                   (unsigned)SOTGUARD_KIND_SOTINIT_UNIT_INVALID, src->name);
            continue;
        }

        unit_t *u = sotinit_unit_alloc();
        if (!u) {
            printf("[sotinit] %s · ERROR · registry full\n", src->name);
            /* β · PR 11 · audit · registry-exhaustion bubble.  Operator-
             * visible signal that the next units (if any) will be dropped. */
            printf("[sotinit] AUDIT kind=0x%02x SOTINIT_UNIT_INVALID name=%s reason=registry_full\n",
                   (unsigned)SOTGUARD_KIND_SOTINIT_UNIT_INVALID, src->name);
            break;
        }
        u->kind = kind;
        strncpy(u->name, src->name, SOTINIT_NAME_MAX - 1);
        u->name[SOTINIT_NAME_MAX - 1] = '\0';

        parse_ctx_t ctx = { .u = u };
        int kv = sotinit_ini_parse(src->body, src->body_len,
                                    kv_callback, &ctx);
        (void)kv;  /* kv_count is informational only · cb returns 0 always */
        loaded++;
    }
    printf("[sotinit] loaded %u units\n", (unsigned)loaded);
    return (int)loaded;
}
