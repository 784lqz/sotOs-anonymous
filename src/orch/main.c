/*
 * sotOs · lucas-orchestrator process · IPC dispatch loop.
 *
 * argv[0] = elf name ("sotOs-lucas-orch")
 * argv[1] = badged-EP cap (set by sotos_spawn_child via
 *           sel4utils_mint_cap_to_process) · this is the EP we listen on
 *           for orchestrator API calls from root (and later from sotBoxes
 *           if we add IPC capabilities to them).
 *
 * T2 scaffolds the loop with BOOTSTRAP / SPAWN / SHUTDOWN handlers.
 * T3 will populate the BOOTSTRAP payload with real cap delegation
 * info; T6 wires SPAWN to call into the sotOs-lucas library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sel4/sel4.h>
#include <orch/proto.h>
#include <orch/sotbox.h>
#include <sottrace/trace.h>
#include <cpio/cpio.h>
#include <lucas/functor.h>
#include "canary_screenshot.h"   /* L14a · orch Canary Screenshot pool */
#include "keymap.h"  /* L14b · orch xkb keymap pool */
/* PR 4 · WAL IPC dispatch · cross-process clients (procd / anomaly)
 * seL4_Call the orch listen EP with SOTFS_OP_WAL_LOG; we unpack the kind
 * from MR(1) and route to the local sotfs_wal_log_* function. */
#include <sotfs/wal.h>
#include <sotfs/wal_ipc.h>
/* γ · F_persistence PR 7 · cross-process sotfs inode stat.
 * sotinit / sotcron seL4_Call ORCH_OP_F_PERSIST_STAT to query the
 * in-orch sotfs_graph (via backends_sotfs_get_graph) for an inode's
 * functor_persistence byte · keeps the graph singleton local to orch. */
#include <sotfs/graph.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <vka/capops.h>
#include <sel4utils/process.h>
#include <sel4utils/process_config.h>
/* procd PR 4 · event ring drain · header-only when SHM cross-mapping
 * ships in PR 5; today we only consume the NTF half so we print a
 * synthesized event line from the marker procd publishes at startup. */
#include <procd/events.h>
/* procd-authoritative-GC · real cross-vspace ring drain + proc_t WAL mirror. */
#include <procd/shm.h>    /* procd_shm_header_t, PROCD_SHM_MAGIC, PROCD_SHM_BYTES */
#include <procd/proc.h>   /* proc_t (Task 5 WAL mirror) */
#include <sotabi/proto.h>      /* sotctl-native arc · the formal native ABI (M4) */
#include <sotabi/wire.h>       /* sotabi · the render-stream chunk codec (M4) */
#include <lucas/truth.h>       /* truth_list_processes (sotabi OP_STATS reply) */
#include <lucas/persona_session.h> /* M3 · per-session persona context (lucas_persona_t) */
#include <libsot/sot_session.h>/* sot_session_list  (sotabi OP_STATS reply) */
/* β · init-cron PR 6 · orch forwards each PROCD_EV_PROC_EXITED into
 * sotinit's listen EP as a one-way SOTINIT_OP_PROC_EXITED notification.
 * sotinit applies its per-unit Restart= policy (no / on-failure /
 * always) with a 500 ms TSC backoff.  Forward is best-effort: NBSend
 * drops the message if sotinit isn't currently in Recv (e.g. mid-spawn);
 * sotinit catches up the next time procd publishes. */
#include <sotinit/proto.h>

extern int orch_bootstrap_init(const orch_bootstrap_info_t *bs);
extern int sotbox_init(const void *elf_bytes, unsigned long elf_size,
                        const char *const argv[], int initial_tier,
                        uint64_t pledge, bool trusted);
/* P4a · the real from-scratch init parameterized on a caller-provided state,
 * so independent sotboxes can coexist (concurrent multi-spawn). */
extern int sotbox_spawn_into(lucas_state_t *st, const void *elf_bytes, unsigned long elf_size,
                             const char *const argv[], int initial_tier,
                             uint64_t pledge_mask, bool trusted);
/* P4b · root-vka leak watermark accessor (defined in spawn.c). */
extern long orch_root_pages_total(void);
extern void orch_fault_loop(seL4_CPtr shared_ep);
extern seL4_CPtr orch_get_fault_ep(void);
extern void sotbox_reset_primary(void);   /* reset after fault_loop returns */
extern int orch_spawn_native(const char *binname, const void *elf_bytes,
                               unsigned long elf_size, seL4_CPtr listen_ep,
                               seL4_CPtr extra_cap_in_orch,
                               seL4_CPtr extra_cap_in_orch_2,
                               seL4_CPtr *out_shell_ep);
/* sotFS-β-Phase-B · STO endpoint accessor from sotbox_table.c */
extern void orch_set_sto_ep(seL4_CPtr ep);
/* L5: profile selector in the static VFS backend (typed per vfs.h). */
#include <lucas/vfs.h>
#include <lucas/clock.h>
#include <sotnet/sotnet.h>
#include <sotnet/synth.h>
#include <sotnet/bytepipe.h>
#include "sotguard_pump.h"
#include <orch/virtio_gpu.h>   /* gpu_init · virtio-gpu probe + GET_DISPLAY_INFO spike */

/* Set when a real virtio-keyboard is present (just run-interactive). Gates the
 * ORCH_OP_BBSH_AUTO default-interactive-shell so headless boots stay no-op. */
static int g_kbd_present = 0;

/* M2 · set by LUCAS execve when the operator types 'doom' in the terminal; the
 * orch fault-loop idle branch spawns Doom into the same loop (serviced alongside
 * the live busybox shell). NON-static: execve.c + fault_loop.c extern it. */
int g_doom_request = 0;
/* sotctl-native arc · Slice 3 · set by LUCAS execve when the OPERATOR types
 * `sotctl <sub>` in the trusted shell.  The fault-loop idle branch spawns the
 * NATIVE sotctl binary and serves its sotabi render-stream (the op the operator
 * chose).  g_sotctl_op = SOTABI_OP_*, g_sotctl_arg = the optional arg (overlay
 * --session).  execve.c sets them; fault_loop.c externs the request flag. */
int      g_sotctl_request = 0;
int      g_sotctl_op      = 0;
uint32_t g_sotctl_arg     = 0;
/* OPERATOR-DURING-ATTACK · the operator sotShell's command endpoint, published so
 * orch_fault_loop (the nested loop that runs while a live SSH attacker owns orch)
 * can also poll it and service `sotctl` — otherwise the operator's Call hangs for
 * the whole attacker session (the sotctl-freeze).  Set when the command window
 * opens; 0 before then so boot/demo loops don't poll it. */
seL4_CPtr g_orch_shell_ep = 0;
/* F12 toggle · set by orch_fault_loop (via kbd_f12_take) when the operator
 * presses F12, so the ORCH_OP_BBSH handler can tell a F12-exit from a guest
 * `exit` and signal sotShell to open the operator console. fault_loop.c externs it. */
int g_bbsh_exit_f12 = 0;
#include <orch/console_fb.h>
#include <orch/virtio_input.h>
#include <orch/virtio_mouse.h>

/* v2.8 · framebuffer sink for the sottrace `watch` deception monitor: paint one
 * dashboard line to the console framebuffer (no-op if no fb is up). Registered
 * with sottrace once the interactive console is online. */
static void orch_trace_fb_sink(const char *line)
{
    /* one batched flush per line (console_fb_puts) · per-char gpu_flush stalled
     * orch's network servicing during a live SSH attack (broke `watch` demos). */
    char b[176]; int n = 0;
    while (line[n] && n < (int)sizeof(b) - 2) { b[n] = line[n]; n++; }
    b[n++] = '\n'; b[n] = '\0';
    console_fb_puts(b);
}

/* From backends_sotfs.c · operator-side VFS accessors (L4-Phase-D). */
typedef struct sotfs_dirent {
    char     name[32];
    uint32_t size;
    uint8_t  kind;
    uint8_t  pad[3];
} sotfs_dirent_t;
extern int lucas_sotfs_list_dir(const char *path, sotfs_dirent_t *out, int max);
extern int lucas_sotfs_read_file(const char *path, void *buf, size_t max);
extern int lucas_sotfs_install(const char *path, const void *content, size_t len);
extern int lucas_sotfs_install_at(const char *path, const void *content, size_t len);
extern int lucas_sotfs_mkdir(const char *path, uint32_t mode);
extern int lucas_sotfs_unlink(const char *path);
extern int lucas_sotfs_read_at(const char *path, uint32_t off, uint8_t *out, uint32_t max);

/* Operator merged-root accessors · the real Alpine sysroot (/usr,/lib) and the
 * synthetic static tree (/, /etc, /bin…).  See backends_sysroot.c / _static.c. */
extern int lucas_sysroot_list_dir(const char *path, void *out, int max);
extern int lucas_sysroot_read_abs(const char *path, void *buf, size_t max);
extern int lucas_sysroot_read_abs_at(const char *path, void *buf, size_t max, int64_t off);
extern int lucas_static_list_dir(const char *path, void *out, int max);
extern int lucas_static_read_file(const char *path, void *buf, size_t max);

/* Route an absolute operator path to the backend that serves it — mirroring the
 * guest vfs_resolve() prefix logic so the operator console sees the SAME merged
 * '/' a sotBox sees: writable sotfs store at /tmp, real Alpine sysroot at /usr
 * (+ the /lib alias), synthetic static tree for everything else. */
static int oproot_is_sysroot(const char *p) {
    return (strcmp(p, "/usr") == 0 || strncmp(p, "/usr/", 5) == 0 ||
            strcmp(p, "/lib") == 0 || strncmp(p, "/lib/", 5) == 0);
}
static int oproot_is_sotfs(const char *p) {
    return (strcmp(p, "/tmp") == 0 || strncmp(p, "/tmp/", 5) == 0);
}
static int oproot_list_dir(const char *path, sotfs_dirent_t *out, int max) {
    if (!path || !*path) path = "/";
    if (oproot_is_sotfs(path))   return lucas_sotfs_list_dir(path, out, max);
    if (oproot_is_sysroot(path)) return lucas_sysroot_list_dir(path, out, max);
    int n = lucas_static_list_dir(path, out, max);
    /* At "/" surface the writable store + standard runtime dirs the synthetic
     * table omits, so the operator sees a believable Linux root incl. tmp. */
    if (strcmp(path, "/") == 0 && n >= 0) {
        static const char *extra[] = { "tmp", "dev", "var", "run", "mnt", "opt" };
        for (size_t k = 0; k < sizeof(extra) / sizeof(extra[0]) && n < max; ++k) {
            int dup = 0;
            for (int j = 0; j < n; ++j) if (strcmp(out[j].name, extra[k]) == 0) { dup = 1; break; }
            if (dup) continue;
            strncpy(out[n].name, extra[k], 31); out[n].name[31] = '\0';
            out[n].size = 0; out[n].kind = 2;
            out[n].pad[0] = out[n].pad[1] = out[n].pad[2] = 0;
            n++;
        }
    }
    return n;
}
static int oproot_read_file(const char *path, void *buf, size_t max) {
    if (!path || !*path) return -2;
    if (oproot_is_sotfs(path))   return lucas_sotfs_read_file(path, buf, max);
    if (oproot_is_sysroot(path)) return lucas_sysroot_read_abs(path, buf, max);
    int n = lucas_static_read_file(path, buf, max);
    if (n == -2) {                       /* not synthetic · try the writable store
                                          * (canary/persistence aliases live there) */
        int s = lucas_sotfs_read_file(path, buf, max);
        if (s >= 0) return s;
    }
    return n;
}
static int oproot_read_at(const char *path, uint32_t off, uint8_t *out, uint32_t max) {
    if (!path || !*path) return -2;
    if (oproot_is_sysroot(path)) return lucas_sysroot_read_abs_at(path, out, max, (int64_t)off);
    return lucas_sotfs_read_at(path, off, out, max);
}
/* γ · F_persistence PR 7 · accessor returning the singleton sotfs graph
 * lucas/backends_sotfs.c lazily initialises.  Defined non-static in that
 * TU · the same symbol simreboot.c uses to drive replay-apply.  Returns
 * NULL only if lazy_init hasn't fired yet (impossible after the first
 * lucas_sotfs_* call · we treat NULL as "no inode" in the dispatcher). */
extern sotfs_graph_t *backends_sotfs_get_graph(void);
/* sotGuard live-dump · read sotbox heap via the LUCAS page-walk helper.
 * Defined in src/lucas/handlers_fs.c · linked via target sotOs-lucas. */
extern int lucas_copy_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                    void *dst_buf, size_t size);

/* Strip /tmp prefix from operator paths before calling sotfs accessors
 * that work on internal graph paths (mkdir/unlink expect /<leaf> not /tmp/<leaf>). */
static const char *orch_strip_tmp(const char *path)
{
    if (!path) return "/";
    if (strncmp(path, "/tmp", 4) == 0) {
        const char *rest = path + 4;
        return (*rest == '\0') ? "/" : rest;
    }
    return path;
}

/* From spawn.c / bootstrap.c */
extern vka_t    *orch_vka(void);
extern simple_t *orch_simple(void);
extern vspace_t *orch_parent_vspace_ptr(void);
extern int       orch_env_init(void);
extern seL4_CPtr orch_get_anomaly_ep(void);

/* OBSD-η · TPM driver hooks (sibling unit T2 provides strong defs in
 * src/orch/tpm.c).  Until T2 lands we keep the orch build green with
 * weak fallbacks that report "TPM unavailable" · sotShell prints the
 * graceful "TPM not available" message and exits with rc=0. */
__attribute__((weak)) int tpm_is_available(void) { return 0; }
__attribute__((weak)) int tpm_pcr_read(uint32_t pcr_idx, uint8_t *out)
{
    (void)pcr_idx;
    if (out) memset(out, 0, 32);
    return -1;
}
__attribute__((weak)) int tpm_quote(const uint8_t *nonce, size_t nonce_len,
                                    uint8_t *out, size_t *inout_size)
{
    (void)nonce; (void)nonce_len; (void)out;
    if (inout_size) *inout_size = 0;
    return -1;
}

/* Path D: anomaly is now pre-spawned by root as a sibling of orch.
 * orch_spawn_anomaly() from commit 7d110fd has been removed.
 * The anomaly event EP is received via bs.anomaly_event_ep_slot at BOOTSTRAP
 * and stored via orch_set_anomaly_ep() in bootstrap.c. */

extern char _cpio_archive[];
extern char _cpio_archive_end[];

#include <sotfs/binstore.h>
#include "spawn.h"
#include <sotnet/bytepipe_frame.h>
#include <sotnet/tcp_conn.h>

_Static_assert(SOTTRACE_MAX_SLOTS == SOTBOX_MAX_SLOTS,
    "sottrace ring count must track the sotbox slot count");

/* ABI v2 · procd comm · the short program name procd records is the
 * basename of the spawned ELF / argv0.  NULL-safe, slash-stripping. */
static const char *orch_basename(const char *p) {
    if (!p) return "";
    const char *base = p;
    for (const char *q = p; *q; ++q) if (*q == '/') base = q + 1;
    return base;
}

/* SP2 · unified ELF-source resolver.
 *   "/path"   → sotfs writable DPO graph (TCC-emitted ELFs)
 *   "name"    → binstore (migrated binaries) first, else CPIO fallback
 * On success returns 0, sets *out_bytes / *out_len, and *out_src (label).
 * For sotfs/binstore the bytes are read into a transient buffer that
 * persists through validate+load (orch is single-threaded · safe).  For CPIO
 * *out_bytes points into the archive (no copy). */
#define ORCH_SPAWN_ELF_BUF_BYTES (2u * 1024u * 1024u)   /* small binaries + emitted ELFs */
static uint8_t g_spawn_elf_buf[ORCH_SPAWN_ELF_BUF_BYTES];

/* Pick a buffer that fits `need` bytes: the static 2 MiB for small loads,
 * else the on-demand staging region (up to 28 MiB · python). */
static void *spawn_pick_buf(size_t need)
{
    if (need <= sizeof(g_spawn_elf_buf)) return g_spawn_elf_buf;
    return orch_spawn_stage(need);
}

static int spawn_load_elf(const char *name, const void **out_bytes,
                          unsigned long *out_len, const char **out_src)
{
    if (!name || !*name) return -1;

    if (name[0] == '/') {
        /* sotfs writable graph · emitted ELFs are small → static buffer. */
        extern int lucas_sotfs_read_file(const char *path, void *buf, size_t max);
        int n = lucas_sotfs_read_file(name, g_spawn_elf_buf, sizeof(g_spawn_elf_buf));
        if (n > 0) {
            *out_bytes = g_spawn_elf_buf;
            *out_len   = (unsigned long)n;
            *out_src   = "sotfs-graph";
            printf("[spawn] load '%s' · source=sotfs-graph · %d bytes\n", name, n);
            return 0;
        }
        printf("[spawn] load '%s' · sotfs-graph miss (rc=%d)\n", name, n);
        return -1;
    }

    /* A2 · writable store shadows the read-only binstore. */
    {
        extern long rwbinstore_lookup(const char *name, uint64_t *offset_out);
        extern long rwbinstore_read(const char *name, void *buf, size_t cap);
        uint64_t rw_off = 0;
        long rw_size = rwbinstore_lookup(name, &rw_off);
        if (rw_size > 0) {
            void *buf = spawn_pick_buf((size_t)rw_size);
            if (buf && rwbinstore_read(name, buf, (size_t)rw_size) == rw_size) {
                *out_bytes = buf; *out_len = (unsigned long)rw_size; *out_src = "rwbinstore";
                printf("[spawn] load '%s' · source=rwbinstore · %ld bytes\n", name, rw_size);
                return 0;
            }
        }
    }

    /* binstore: look up the size first, then stage a buffer that fits it. */
    extern long binstore_lookup(const char *name, uint64_t *offset_out);
    uint64_t bs_off = 0;
    long bs_size = binstore_lookup(name, &bs_off);
    if (bs_size > 0) {
        void *buf = spawn_pick_buf((size_t)bs_size);
        if (!buf) {
            printf("[spawn] load '%s' · no staging buffer for %ld bytes\n", name, bs_size);
            return -1;
        }
        long bn = binstore_read(name, buf, (size_t)bs_size);
        if (bn == bs_size) {
            *out_bytes = buf;
            *out_len   = (unsigned long)bn;
            *out_src   = "binstore";
            printf("[spawn] load '%s' · source=binstore · %ld bytes\n", name, bn);
            return 0;
        }
        printf("[spawn] load '%s' · binstore short read %ld/%ld\n", name, bn, bs_size);
        return -1;
    }

    unsigned long cpio_size = (unsigned long)(_cpio_archive_end - _cpio_archive);
    unsigned long elf_size  = 0;
    const void *eb = cpio_get_file(_cpio_archive, cpio_size, name, &elf_size);
    if (eb) {
        *out_bytes = eb;
        *out_len   = elf_size;
        *out_src   = "cpio";
        printf("[spawn] load '%s' · source=cpio · %lu bytes\n", name, elf_size);
        return 0;
    }
    return -1;
}

/* Pillar-4 P4a · concurrent 3-malware validation. Seeds the 3 canonical Tier-2
 * fixtures into a small storage pool (independent of g_primary_st / fork's
 * child_storage), runs ONE fault loop until all exit, then frees the pool.
 * REAP INVARIANT: each pool sotbox is reaped solely by the normal exit path
 * (lucas_sys_exit_group -> orch_fault_loop -> sotbox_destroy + sotbox_free_slot);
 * this handler must NEVER call sotbox_destroy itself (double-revoke). It does NOT
 * touch g_primary_inited (pool sotboxes are not the primary). */
#define P4_VALIDATE_MAX 4
static lucas_state_t g_validate_st[P4_VALIDATE_MAX];
static bool          g_validate_used[P4_VALIDATE_MAX];

static void orch_handle_validate(void)
{
    static const struct { const char *name; int tier; bool trusted; } TRIPLE[3] = {
        { "wl_capture_client.bin",     2, false },   /* graphical trojan  (canary capture)  */
        { "tls_probe.bin",   2, false },   /* network infostealer (synth C2)   */
        { "stage7_demo.bin", 2, false },   /* destructive ransomware (persistence) */
    };
    extern int orch_procd_spawn(uint64_t, uint32_t, int, const char *const argv[],
                                proc_tier_t, uint64_t, uint32_t, const char *,
                                uint32_t *, uint32_t *);
    vfs_set_profile(0);
    vfs_set_tier(2);                       /* all 3 tier-2 -> the global switch is consistent;
                                              is_isolated functor makes egress synth-redirect (5-critic (b)) */
    int seeded = 0;
    for (int i = 0; i < 3; ++i) {
        const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
        if (spawn_load_elf(TRIPLE[i].name, &elf, &sz, &src) != 0) {
            printf("[validate] fixture '%s' not found · ABORT\n", TRIPLE[i].name); break;
        }
        int p = -1; for (int k = 0; k < P4_VALIDATE_MAX; ++k) if (!g_validate_used[k]) { p = k; break; }
        if (p < 0) { printf("[validate] pool full\n"); break; }
        const char *argv[2] = { TRIPLE[i].name, NULL };
        int rc = sotbox_spawn_into(&g_validate_st[p], elf, sz, argv, TRIPLE[i].tier, 0, TRIPLE[i].trusted);
        if (rc != 0) { printf("[validate] spawn '%s' rc=%d · ABORT\n", TRIPLE[i].name, rc); break; }
        g_validate_used[p] = true;
        lucas_state_t *st = &g_validate_st[p];
        uint32_t pslot = 0, pfpid = 0;
        orch_procd_spawn(0, 0, 1, argv, (proc_tier_t)TRIPLE[i].tier, 0, 0,
                         orch_basename(TRIPLE[i].name), &pslot, &pfpid);  /* per-sotbox, NOT slot 0 */
        st->procd_slot = pslot;
        printf("[validate] spawn '%s' slot=%d pid=%d\n", TRIPLE[i].name, st->slot_index, st->synthetic_pid);
        seeded++;
    }
    if (seeded == 3) { printf("[validate] START 3 families concurrent\n"); seL4_Reply(seL4_MessageInfo_new(0,0,0,0)); }
    else             { printf("[validate] seeded %d/3 · draining\n", seeded); seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); }

    orch_fault_loop(orch_get_fault_ep());   /* services ALL seeded sotboxes until alive_count==0 */
    printf("[validate] DONE · all families exited (alive=%d)\n", sotbox_alive_count());

    /* slots + arenas were already reclaimed at each reap; only release the pool bookkeeping. */
    for (int k = 0; k < P4_VALIDATE_MAX; ++k) g_validate_used[k] = false;
}

/* M2 · spawn Doom into a dedicated box WITHOUT a nested fault loop — the CURRENT
 * orch_fault_loop (the interactive bbsh terminal loop) services it alongside the
 * live shell. Triggered by g_doom_request (operator typed 'doom'). Tier-0 trusted
 * via the param so it can mmap the zone + isn't silenced-suppressed; the global vfs
 * tier is NOT touched (busybox stays contained at Tier-2). */
void orch_spawn_doom_pool(void)
{
    static lucas_state_t s_term_doom_st;
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("chocodoom.bin", &elf, &sz, &src) != 0 &&
        spawn_load_elf("doom.bin", &elf, &sz, &src) != 0 &&
        spawn_load_elf("doomsdl.bin", &elf, &sz, &src) != 0) {
        printf("[doom] (terminal) chocodoom/doom not found\n"); return;
    }
    /* -mb 8 caps Chocolate's zone to fit the 32 MiB / 8192-cslot arena
     * (doomgeneric ignores it). */
    const char *argv[] = { "doom", "-iwad", "/doom1.wad", "-mb", "8", NULL };
    int rc = sotbox_spawn_into(&s_term_doom_st, elf, sz, argv,
                               /*initial_tier=*/0, /*pledge=*/0, /*trusted=*/true);
    printf("[doom] (terminal) spawn rc=%d slot=%d\n",
           rc, rc == 0 ? s_term_doom_st.slot_index : -1);
}

/* DECEPTION · attacker `python`/`python3` in the canary shell → real CPython.
 * Same isolated-launcher pattern as doom: a fork-child execve can't swap its own
 * arena (its TCB/CNode live in the regular arena), so instead execve records the
 * argv + flags g_python_request; the orch idle loop spawns python3.12-static into
 * a fresh HEAVY arena (>16 MiB → heavy; routed by sotbox_spawn_into) here, and
 * the same fault loop services it.  Output (fd1 → serial_putc) reaches the live
 * console the attacker is watching.  Tier-2 keeps the VFS canary + write
 * containment; the python_stdlib mount serves regardless of tier. */
int  g_python_request = 0;
int  g_apt_request    = 0;   /* apt arc P1 T4 · Debian attacker ran apt/apt-get/apt-cache */
int  g_apt_sudo       = 0;   /* apt arc · the apt was invoked via `sudo` → run the pool euid-root */
/* Set while the operator's `shell --trusted` (ORCH_OP_BBSH_TRUSTED) owns the
 * foreground.  Read by orch_spawn_python_pool (python/pip inherit Tier-0e) and
 * by execve.c (the `pip` intercept runs REAL pip vs the synthetic facade). */
int  g_shell_trusted_egress = 0;
static char        g_python_argv_pool[512];
static const char *g_python_argv[16];
static int         g_python_argc;

void orch_record_python_argv(const char *const argv[])
{
    size_t off = 0; int i = 0;
    for (; argv && argv[i] && i < 15; i++) {
        size_t l = strlen(argv[i]) + 1;
        if (off + l > sizeof(g_python_argv_pool)) break;
        memcpy(g_python_argv_pool + off, argv[i], l);
        g_python_argv[i] = g_python_argv_pool + off;
        off += l;
    }
    g_python_argv[i] = NULL;
    g_python_argc = i;
}

void orch_spawn_python_pool(void)
{
    static lucas_state_t s_py_st;
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("python3.12-static", &elf, &sz, &src) != 0) {
        printf("[python] (canary) python3.12-static not found\n"); return;
    }
    if (g_python_argc == 0) {            /* bare `python` → interactive-style banner */
        g_python_argv[0] = "python3"; g_python_argv[1] = NULL; g_python_argc = 1;
    }
    /* TRUSTED-EGRESS inheritance · when the operator's `shell --trusted` is the
     * foreground session, a python (or `pip` → `python3 -m pip`) execve'd from it
     * spawns at Tier-0e/trusted with the egress envp → it reaches the REAL wire
     * (pip install from PyPI works interactively).  Otherwise it stays the Tier-2
     * canary (contained, synthetic net) exactly as before. */
    int   py_tier    = 2;
    bool  py_trusted = false;
    if (g_shell_trusted_egress) {
        py_tier    = FUNCTOR_TIER_EGRESS;
        py_trusted = true;
        extern void sotbox_spawn_set_envp_next(const char *const envp[]);
        extern const char *const TRUSTED_SHELL_PY_ENVP[];  /* defined later · writable PIP_TARGET */
        sotbox_spawn_set_envp_next(TRUSTED_SHELL_PY_ENVP);
    }
    printf("[python] (%s) spawn argc=%d argv0=%s · %lu bytes · %s\n",
           py_trusted ? "trusted-egress" : "canary",
           g_python_argc, g_python_argv[0], sz, src);
    int rc = sotbox_spawn_into(&s_py_st, elf, sz, g_python_argv,
                               py_tier, /*pledge=*/0, py_trusted);
    printf("[python] (%s) spawn rc=%d slot=%d\n",
           py_trusted ? "trusted-egress" : "canary",
           rc, rc == 0 ? s_py_st.slot_index : -1);
    /* Console FOCUS · hand keyboard input to the python box so the shell (busybox,
     * parked at its prompt) stops competing for it (no display glitch) AND the
     * REPL can be Ctrl-D'd to exit → its heavy arena is released (no OOM-pileup).
     * Cleared when the box is reaped (orch_fault_loop). */
    if (rc == 0) {
        extern void lucas_console_set_focus(int slot);
        lucas_console_set_focus(s_py_st.slot_index);
    }
}

/* apt arc P1 T4 · the attacker's apt argv + originating session, captured at the
 * execve interception, consumed by orch_spawn_apt_pool (heavy-arena launcher). */
static char        g_apt_argv_pool[512];
static const char *g_apt_argv[16];
static int         g_apt_argc;
uint32_t           g_apt_cow_session = 0;   /* the Debian Tier-2 session apt runs for (containment) */

void orch_record_apt_argv(const char *const argv[])
{
    size_t off = 0; int i = 0;
    for (; argv && argv[i] && i < 15; i++) {
        size_t l = strlen(argv[i]) + 1;
        if (off + l > sizeof(g_apt_argv_pool)) break;
        memcpy(g_apt_argv_pool + off, argv[i], l);
        g_apt_argv[i] = g_apt_argv_pool + off;
        off += l;
    }
    g_apt_argv[i] = NULL;
    g_apt_argc = i;
}

extern bool g_ssh_shell_active;   /* defined below (~2461) · gate launcher error emit */

/* Surface a realistic tool error on the attacker's SSH shell when a heavy-pool
 * launcher spawn FAILS — otherwise the launcher's placeholder child exit_group(0)'d
 * and the command silently vanishes ($?=0, no output), which no real host does.
 * Pushes straight to the shared SHELL_OUT ring (net-synth re-encrypts), CRLF'd.
 * Gated by the caller on g_ssh_shell_active so it only fires for a live session.
 * (A non-zero $? would need to rewrite the already-exited placeholder's exit code —
 * that touches exit_group/wait4, deferred; this at least kills the silent-vanish.) */
static void orch_ssh_shell_emit(const char *s)
{
    bytepipe_ring_t *out = (bytepipe_ring_t *)BYTEPIPE_SHELL_OUT_VADDR;
    for (; *s; ++s) {
        if (*s == '\n') { uint8_t cr = '\r'; bytepipe_push(out, &cr, 1); }
        bytepipe_push(out, (const uint8_t *)s, 1);
    }
}

void orch_spawn_apt_pool(void)
{
    static lucas_state_t s_apt_st;
    /* IN-FLIGHT GUARD · same re-entrancy hazard as the apk pool (see there): a
     * second request while the box is live would memset() the live static state
     * and orphan its heavy arena.  Drop it; the next apt runs after this reaps. */
    if (s_apt_st.seL4_objects_owned) {
        printf("[apt] pool box still live (slot=%d) · ignoring re-entrant request\n",
               s_apt_st.slot_index);
        return;
    }
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    const char *bin = (g_apt_argc > 0 && g_apt_argv[0]) ? g_apt_argv[0] : "apt-get";
    for (const char *p = bin; *p; ++p) if (*p == '/') bin = p + 1;   /* basename */
    if (spawn_load_elf(bin, &elf, &sz, &src) != 0) {
        printf("[apt] (canary) %s not found in binstore\n", bin);
        if (g_ssh_shell_active) orch_ssh_shell_emit("E: Unable to locate package (temporary resolver failure)\n");
        return;
    }
    printf("[apt] (canary) spawn argc=%d argv0=%s sess=%u · %lu bytes · %s\n",
           g_apt_argc, g_apt_argv[0] ? g_apt_argv[0] : "?", g_apt_cow_session, sz, src);
    /* apt is a SMALL ELF (~60 KiB dispatcher) but DynamicMMap's a large index
     * cache at runtime + forks its http method → it exhausts a regular arena's
     * 8192 cslots.  Force the HEAVY arena (32768 cslots) one-shot, like gtkspike. */
    extern void sotbox_request_heavy_next(void);
    sotbox_request_heavy_next();
    int rc = sotbox_spawn_into(&s_apt_st, elf, sz, g_apt_argv,
                               /*tier=*/2, /*pledge=*/0, /*trusted=*/false);
    if (rc == 0) {
        /* sotbox_spawn_into memset cow_session to 0 — restore the originating
         * session so apt's /var/lib/apt writes are session-tagged + contained,
         * the Debian persona resolves, and the box streams stdout to the SSH ring. */
        s_apt_st.cow_session         = g_apt_cow_session;
        s_apt_st.console_interactive = 1;
        s_apt_st.console_src         = LUCAS_CONSOLE_SRC_SSH_RING;
        /* `sudo apt …` → run the pool (and its forked dpkg, via *child=*parent)
         * euid-root so dpkg doesn't refuse "requires superuser privilege".  The
         * honey shell itself stays uid 1000; containment is VFS-session-based. */
        s_apt_st.euid_root           = (uint8_t)g_apt_sudo;
        s_apt_st.pkg_install         = 1;  /* exempt apt's mass-file-ops from the RANSOMWARE curvature alert */
        extern void lucas_console_set_focus(int slot);
        lucas_console_set_focus(s_apt_st.slot_index);
    }
    g_apt_sudo = 0;
    printf("[apt] (canary) spawn rc=%d slot=%d\n", rc, rc == 0 ? s_apt_st.slot_index : -1);
    if (rc != 0 && g_ssh_shell_active)
        orch_ssh_shell_emit("E: Could not get lock /var/lib/dpkg/lock-frontend (resource temporarily unavailable)\n");
}

/* package-manager request QUEUE · attacker apk invocations are ENQUEUED (with a
 * per-request argv + session snapshot) and drained one-at-a-time into the heavy
 * pool box.  This is what makes `apk update && apk add X` work: both intercepts
 * enqueue, the second runs after the first box reaps.  (A single request bool + the
 * in-flight guard DROPPED the second → `apk add` showed success but installed
 * nothing.)  apk must run heavy (it mmaps a large index DB + extracts archives,
 * overflowing a regular arena) and a fork-child execve can't swap its own arena, so
 * it respawns into a fresh heavy box carrying the originating session (contained). */
#define SOT_PKG_Q_DEPTH 4
struct sot_pkg_req { char pool[256]; const char *argv[16]; uint32_t cow_session; };

static void sot_pkg_enqueue(struct sot_pkg_req *q, int *tail, int *n,
                            const char *const argv[], uint32_t cow_session, const char *tag) {
    if (*n >= SOT_PKG_Q_DEPTH) { printf("[%s] request queue full · dropping\n", tag); return; }
    struct sot_pkg_req *r = &q[*tail];
    size_t off = 0; int i = 0;
    for (; argv && argv[i] && i < 15; i++) {
        size_t l = strlen(argv[i]) + 1;
        if (off + l > sizeof(r->pool)) break;
        memcpy(r->pool + off, argv[i], l);
        r->argv[i] = r->pool + off; off += l;
    }
    r->argv[i] = NULL;
    r->cow_session = cow_session;
    *tail = (*tail + 1) % SOT_PKG_Q_DEPTH; (*n)++;
}

int                       g_apk_request = 0;
static struct sot_pkg_req g_apk_q[SOT_PKG_Q_DEPTH];
static int                g_apk_qhead = 0, g_apk_qtail = 0, g_apk_qn = 0;

void orch_enqueue_apk(const char *const argv[], uint32_t cow_session) {
    sot_pkg_enqueue(g_apk_q, &g_apk_qtail, &g_apk_qn, argv, cow_session, "apk");
}

void orch_spawn_apk_pool(void)
{
    static lucas_state_t s_apk_st;
    if (g_apk_qn == 0) return;
    /* In-flight · box still doing slow egress I/O?  LEAVE the queue and retry next
     * idle pass (re-arm, do NOT drop — that was the lost-`apk add` bug). */
    if (s_apk_st.seL4_objects_owned) { g_apk_request = 1; return; }
    struct sot_pkg_req *r = &g_apk_q[g_apk_qhead];
    g_apk_qhead = (g_apk_qhead + 1) % SOT_PKG_Q_DEPTH; g_apk_qn--;
    if (g_apk_qn > 0) g_apk_request = 1;   /* more queued · keep draining */
    if (!r->argv[0]) { r->argv[0] = "apk"; r->argv[1] = NULL; }   /* bare apk → usage banner */
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("apk.static", &elf, &sz, &src) != 0) {
        printf("[apk] (canary) apk.static not found in binstore\n");
        if (g_ssh_shell_active) orch_ssh_shell_emit("ERROR: unable to select packages (temporary error · retry)\n");
        return;
    }
    printf("[apk] (canary) spawn argv0=%s sess=%u · %lu bytes · %s · q=%d\n",
           r->argv[0], r->cow_session, sz, src, g_apk_qn);
    extern void sotbox_request_heavy_next(void);
    sotbox_request_heavy_next();
    int rc = sotbox_spawn_into(&s_apk_st, elf, sz, r->argv,
                               /*tier=*/2, /*pledge=*/0, /*trusted=*/false);
    if (rc == 0) {
        /* Restore the originating Alpine session: apk's writes are session-tagged +
         * contained, the persona resolves, stdout streams to the SSH ring, runs root
         * (Tier-2 cow contains it).  NO console focus (apk doesn't read stdin). */
        s_apk_st.cow_session         = r->cow_session;
        s_apk_st.console_interactive = 1;
        s_apk_st.console_src         = LUCAS_CONSOLE_SRC_SSH_RING;
        s_apk_st.euid_root           = 1;
        s_apk_st.pkg_install         = 1;  /* exempt apk's mass-file-ops from the RANSOMWARE curvature alert */
    }
    printf("[apk] (canary) spawn rc=%d slot=%d\n", rc, rc == 0 ? s_apk_st.slot_index : -1);
    if (rc != 0 && g_ssh_shell_active)
        orch_ssh_shell_emit("ERROR: unable to select packages (temporary error · retry)\n");
}

/* heavy-exec arc · a LARGE attacker-installed binary (a Go editor like `micro`,
 * ~13 MB + a runtime that mmaps multi-MiB heap arenas) bounced from its in-place
 * execve into a fresh HEAVY (256 MiB) box: it does not fit the 32 MiB regular arena
 * and an in-place execve cannot swap its own arena.  Captured at the execve
 * interception (staged ELF bytes + argv + env + session), consumed here.  Mirrors
 * apk/apt/python but loads the staged VFS bytes (not a fixed binstore asset). */
int                g_hx_request     = 0;
const void        *g_hx_elf         = NULL;   /* staged bytes (orch_spawn_stage buf · valid until consumed) */
unsigned long      g_hx_sz          = 0;
uint32_t           g_hx_cow_session = 0;
uint8_t            g_hx_euid_root   = 0;
static char        g_hx_argv_pool[512];
static const char *g_hx_argv[16];
static char        g_hx_envp_pool[1024];
static const char *g_hx_envp[32];

void orch_record_hx(const char *const argv[], const char *const envp[])
{
    size_t off = 0; int i = 0;
    for (; argv && argv[i] && i < 15; i++) {
        size_t l = strlen(argv[i]) + 1;
        if (off + l > sizeof(g_hx_argv_pool)) break;
        memcpy(g_hx_argv_pool + off, argv[i], l);
        g_hx_argv[i] = g_hx_argv_pool + off;
        off += l;
    }
    g_hx_argv[i] = NULL;
    off = 0; i = 0;
    for (; envp && envp[i] && i < 31; i++) {          /* forward env (TERM/HOME/… · micro's TUI needs TERM) */
        size_t l = strlen(envp[i]) + 1;
        if (off + l > sizeof(g_hx_envp_pool)) break;
        memcpy(g_hx_envp_pool + off, envp[i], l);
        g_hx_envp[i] = g_hx_envp_pool + off;
        off += l;
    }
    g_hx_envp[i] = NULL;
}

void orch_spawn_heavy_exec_pool(void)
{
    static lucas_state_t s_hx_st;
    if (s_hx_st.seL4_objects_owned) {   /* in-flight guard · same hazard as apk/apt */
        printf("[heavyexec] box still live (slot=%d) · ignoring re-entrant request\n",
               s_hx_st.slot_index);
        return;
    }
    if (!g_hx_elf || g_hx_sz == 0) { printf("[heavyexec] no staged binary\n"); return; }
    printf("[heavyexec] spawn '%s' · %lu bytes · heavy arena · sess=%u\n",
           g_hx_argv[0] ? g_hx_argv[0] : "?", g_hx_sz, g_hx_cow_session);
    extern void sotbox_require_heavy_next(void);   /* MUST be heavy · no regular fallback */
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    sotbox_require_heavy_next();
    sotbox_spawn_set_envp_next(g_hx_envp);
    int rc = sotbox_spawn_into(&s_hx_st, g_hx_elf, g_hx_sz, g_hx_argv,
                               /*tier=*/2, /*pledge=*/0, /*trusted=*/false);
    if (rc == -2) {
        /* Heavy pool busy (typically the apk box that just installed this binary is
         * still holding/revoking its 256 MiB).  KEEP the staged bytes and retry on a
         * later idle pass once a heavy slot frees — running micro in a regular arena
         * would just reproduce the Go OOM.  Bounded so a wedged pool eventually gives
         * up instead of spinning forever. */
        static long s_hx_retries = 0;
        if (++s_hx_retries < 4000000L) {
            if ((s_hx_retries & 0x3FFFF) == 1)
                printf("[heavyexec] heavy pool busy · re-queueing '%s'\n",
                       g_hx_argv[0] ? g_hx_argv[0] : "?");
            g_hx_request = 1;   /* re-arm · g_hx_elf/g_hx_sz preserved */
            return;
        }
        s_hx_retries = 0;
        printf("[heavyexec] heavy pool never freed · giving up on '%s'\n",
               g_hx_argv[0] ? g_hx_argv[0] : "?");
        if (g_ssh_shell_active) orch_ssh_shell_emit("bash: cannot execute binary: Resource temporarily unavailable\n");
        g_hx_elf = NULL; g_hx_sz = 0;
        return;
    }
    if (rc == 0) {
        s_hx_st.cow_session         = g_hx_cow_session;
        s_hx_st.console_interactive = 1;
        s_hx_st.console_src         = LUCAS_CONSOLE_SRC_SSH_RING;
        s_hx_st.euid_root           = g_hx_euid_root;
        /* Interactive TUI (micro reads stdin keystrokes + draws the screen) · take
         * console focus like the python REPL so the attacker's input reaches it;
         * the reap clears focus + un-parks the SSH shell. */
        extern void lucas_console_set_focus(int slot);
        lucas_console_set_focus(s_hx_st.slot_index);
    }
    g_hx_elf = NULL; g_hx_sz = 0;   /* consumed (staging buffer freed for reuse) */
    printf("[heavyexec] spawn rc=%d slot=%d\n", rc, rc == 0 ? s_hx_st.slot_index : -1);
    if (rc != 0 && g_ssh_shell_active)
        orch_ssh_shell_emit("bash: cannot execute binary: Resource temporarily unavailable\n");
}

/*
 * sotctl-native arc · M4 · serve one native sotctl invocation over the formal
 * sotabi ABI.  The native binary (already spawned, Call'ing on `ep`) drives the
 * envelope: request MR0 = op.  We dispatch:
 *   OP_HELLO        → reply status + SOTABI_VERSION (the handshake)
 *   OP_STATS        → reply status + live session/process counts (truth-core)
 *   OP_RENDER_PULL  → render the operator-chosen content op ONCE (offset 0) via
 *                     libsot sot_render, then stream chunks (status + nbytes +
 *                     packed bytes via the shared sotabi_pack_chunk codec).
 * The loop ends after the final (nbytes=0) render chunk, when the native binary
 * stops pulling and exits.  Reply MR0 is always the sotabi status.
 */
static void __attribute__((unused))
orch_serve_sotctl_stream(seL4_CPtr ep, int content_op, uint32_t arg)
{
    static char buf[8192];
    int rlen = 0, rendered = 0;
    /* NON-BLOCKING serve · orch is single-threaded.  A plain blocking seL4_Recv here
     * froze the WHOLE VM on `sotctl sessions`: it stops pumping the netstack + the
     * live SSH session for the stream's duration, AND the native sotctl box has a
     * private (unattended) fault EP — if it faults it never Calls, so the Recv never
     * returns and orch wedges forever.  Fix: NBRecv + pump the netstack between
     * messages (mirrors the fault-loop idle), with a bounded idle cap so a silent /
     * faulted box returns control instead of hanging.  Every real sotabi op carries
     * MR0=op, so a received message has length>=1; length==0 means no Call pending. */
    extern int  sotnet_poll(void);
    extern void tcp_timer_tick(void);
    long idle = 0; int handshaked = 0;
    /* Two-phase cap: the box must issue its sotabi_hello FAST (a few hundred k pump
     * iters covers spawn+runtime init) or it is DEAD — e.g. the native runtime
     * exit-127 path (setpgid on a bogus pid before main → never Calls).  Bounding
     * the PRE-handshake wait tightly means a dead box returns the operator console
     * in well under a second instead of spinning the full stream cap.  Once it has
     * handshaked, allow a longer cap for a genuinely long render stream. */
    const long PRE_HELLO_CAP = 400000;
    const long STREAM_CAP    = 3000000;
    for (;;) {
        seL4_Word badge = 0;
        seL4_MessageInfo_t mi = seL4_NBRecv(ep, &badge);
        if (seL4_MessageInfo_get_length(mi) == 0) {   /* no Call pending → pump + retry */
            (void)sotnet_poll();
            if ((idle & 0x3FF) == 0) tcp_timer_tick();
            seL4_Yield();
            if (++idle > (handshaked ? STREAM_CAP : PRE_HELLO_CAP)) {
                printf("[sotctl] native box %s · returning console (no VM freeze)\n",
                       handshaked ? "stalled mid-stream"
                                  : "never handshaked (native runtime exited at init?)");
                break;
            }
            continue;
        }
        idle = 0;
        seL4_Word op = seL4_GetMR(0);
        if (op == SOTABI_OP_HELLO) handshaked = 1;

        if (op == SOTABI_OP_HELLO) {
            seL4_SetMR(0, SOTABI_OK);
            seL4_SetMR(1, SOTABI_VERSION);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 2));
            continue;
        }
        if (op == SOTABI_OP_STATS) {
            struct sot_session ss[SOT_SESSION_MAX];
            struct truth_proc_entry pe[64];
            int nsess = sot_session_list(ss, SOT_SESSION_MAX);
            int nproc = truth_list_processes(pe, 64);
            seL4_SetMR(0, SOTABI_OK);
            seL4_SetMR(1, (seL4_Word)(nsess < 0 ? 0 : nsess));
            seL4_SetMR(2, (seL4_Word)(nproc < 0 ? 0 : nproc));
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 3));
            continue;
        }
        if (op == SOTABI_OP_RENDER_PULL) {
            if (!rendered) { rlen = sot_render(content_op, arg, buf, (int)sizeof(buf)); rendered = 1; }
            int off = (seL4_MessageInfo_get_length(mi) >= 2) ? (int)seL4_GetMR(1) : 0;
            uint64_t words[SOTABI_CHUNK_WORDS];
            int nwords = 0;
            int n = sotabi_pack_chunk(buf, rlen, off, words, &nwords);
            seL4_SetMR(0, SOTABI_OK);
            seL4_SetMR(1, (seL4_Word)n);
            for (int w = 0; w < nwords; ++w) seL4_SetMR(2 + w, (seL4_Word)words[w]);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 2 + nwords));
            if (n == 0) break;     /* stream exhausted · the native sotctl now exits */
            continue;
        }
        /* unknown op */
        seL4_SetMR(0, SOTABI_E_BADOP);
        seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 1));
        break;
    }
}

/* Spawn the NATIVE sotctl binary for op g_sotctl_op and serve its render-stream.
 * Called from the orch fault-loop idle branch when the operator typed `sotctl`. */
void orch_spawn_sotctl_pool(void)
{
    /* Render the operator-chosen truth-plane view DIRECTLY (libsot sot_render reads
     * truth-core · the SAME pure path the boot self-tests use) and write it to the
     * OPERATOR console (COM1) via seL4_DebugPutChar — which goes straight to the
     * kernel debug port, BYPASSING the COM3 firehose stdio redirect, so the table
     * lands in the operator's pane (not the diagnostics pane).
     *
     * We do NOT spawn the native world-#3 sotctl binary: its runtime exits 127 at
     * init (a setpgid on a bogus pid before main → it never reaches the sotabi
     * handshake), and spawning + blocking-serving it only froze/hung the
     * single-threaded orch (the `sotctl sessions` freeze).  Direct render is robust,
     * instant, and shows the same table.  The native-binary showcase (the 127 init
     * bug · orch_spawn_native pid injection / sotlibc crt) is a separate follow-up;
     * orch_serve_sotctl_stream is kept (unused) for when that lands. */
    extern int sot_render(int, uint32_t, char *, int);
    static char buf[8192];
    int n = sot_render(g_sotctl_op, g_sotctl_arg, buf, (int)sizeof(buf));
    if (n <= 0) {
        const char *m = "[sotctl] (no data for this view)\r\n";
        for (const char *p = m; *p; ++p) seL4_DebugPutChar(*p);
        return;
    }
    for (int i = 0; i < n; ++i) {
        if (buf[i] == '\n') seL4_DebugPutChar('\r');   /* ONLCR · operator terminal alignment */
        seL4_DebugPutChar((unsigned char)buf[i]);
    }
}

/* doom · spawn doomgeneric (doom.bin) at Tier-0 trusted so it can mmap freely.
 * Mirrors orch_handle_validate: spawn into pool slot 0, run ONE fault loop until
 * doom exits, then release the pool bookkeeping.
 * doom's main() calls doomgeneric_Create(3, {"doom","-iwad","/doom1.wad"}) then
 * 200 render ticks.  /doom1.wad is served by the doom-wad VFS backend. */
static void orch_handle_doom(void)
{
    printf("[doom] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    /* chocodoom.bin (full Chocolate Doom 3.1.1 / real SDL2) FIRST — the marquee
     * target.  doom.bin (doomgeneric-direct, /dev/doomkbd play path) +
     * doomsdl.bin (SDL showcase) are fallbacks. */
    if (spawn_load_elf("chocodoom.bin", &elf, &sz, &src) != 0 &&
        spawn_load_elf("doom.bin", &elf, &sz, &src) != 0 &&
        spawn_load_elf("doomsdl.bin", &elf, &sz, &src) != 0) {
        printf("[doom] chocodoom/doom/doomsdl not found in binstore/sotfs/CPIO · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[doom] doom.bin found via %s · %lu bytes\n", src, sz);

    /* Use pool slot 0 (same as validate). */
    int p = 0;
    if (g_validate_used[p]) {
        printf("[doom] pool slot 0 busy · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }

    /* -mb 8 caps the engine zone heap at 8 MiB (Chocolate's default is 16 MiB,
     * which alone needs 4096 frame-cslots + a 16 MiB arena slice; 8 MiB keeps
     * the footprint comfortably inside the 32 MiB / 8192-cslot arena). doom-
     * generic ignores the unknown arg; Chocolate honours it. */
    const char *argv[] = { "doom", "-iwad", "/doom1.wad", "-mb", "8", NULL };
    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);   /* Tier-0: pass-through, not silenced-suppressed */

    extern void sotbox_arena_trace(int on);
    sotbox_arena_trace(0);   /* corruption root cause fixed · per-frame trace off */
    int rc = sotbox_spawn_into(&g_validate_st[p], elf, sz, argv,
                               /*initial_tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) {
        sotbox_arena_trace(0);
        printf("[doom] sotbox_spawn_into rc=%d · ABORT\n", rc);
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    g_validate_used[p] = true;
    printf("[doom] spawned doom.bin · slot=%d pid=%d\n",
           g_validate_st[p].slot_index, g_validate_st[p].synthetic_pid);

    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));

    orch_fault_loop(orch_get_fault_ep());
    sotbox_arena_trace(0);   /* ARENA-DBG off · trace covered spawn + fault loop */
    printf("[doom] handler DONE alive=%d\n", sotbox_alive_count());

    g_validate_used[p] = false;
}

/* Compat-host · run REAL Alpine git (musl-dynamic) at Tier-0 in /tmp/gitrepo:
 *   git init /tmp/gitrepo
 *   (orch seeds /tmp/gitrepo/README into the working tree)
 *   git -C /tmp/gitrepo add README
 *   git -C /tmp/gitrepo commit --allow-empty -m "track README on sotOs"
 *   git -C /tmp/gitrepo ls-files          (proof: README is a TRACKED file)
 *   git -C /tmp/gitrepo log --oneline
 * Each git subcommand is a fresh Tier-0 sotbox (a fork-child execve can't become
 * a fresh dynamic process — the same reason doom/python use the launcher pattern).
 * The spawns share the /tmp sotfs graph, so init's repo + the seeded README carry
 * into add/commit/log.  Proves the real rename() (handlers_abi → lucas_sotfs_rename),
 * the /dev/urandom node, and the libz/libpcre2 dynamic closure from the sysroot.
 * Identity + safe.directory come via -c flags (no /etc/gitconfig — the sysroot
 * packer has no /etc; safe.directory='*' avoids git 2.45's dubious-ownership
 * refusal).  gc.auto/maintenance.auto=off + --no-pager stop git re-exec'ing
 * helpers (the in-process fork+execve of dynamic git isn't supported).
 * commit --allow-empty keeps it idempotent across simreboot: the sotfs WAL
 * persists the repo, so on a re-boot README is already tracked and a normal
 * commit would say "nothing to commit" — --allow-empty still records a commit
 * while ls-files keeps proving README is tracked.  PASS = ls-files shows README
 * + log prints a commit. */
static lucas_state_t s_git_st;

/* Spawn one fresh Tier-0 git sotbox for `argv` and run it to completion under its
 * own fault loop.  Returns 0 on spawn success, -1 on failure. */
static int gitdemo_run(const char *const argv[], const char *label)
{
    const void *e = NULL; unsigned long s = 0; const char *sr = "?";
    if (spawn_load_elf("git", &e, &s, &sr) != 0) {
        printf("[gitdemo] reload 'git' failed (%s) · ABORT\n", label); return -1;
    }
    if (g_validate_used[0]) { printf("[gitdemo] pool slot 0 busy · ABORT\n"); return -1; }
    printf("[gitdemo] === git %s ===\n", label);
    memset(&s_git_st, 0, sizeof(s_git_st));
    int rc = sotbox_spawn_into(&s_git_st, e, s, argv,
                               /*initial_tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[gitdemo] spawn (%s) rc=%d · ABORT\n", label, rc); return -1; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());   /* run THIS git to completion */
    g_validate_used[0] = false;
    return 0;
}

static void orch_handle_gitdemo(void)
{
    printf("[gitdemo] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("git", &elf, &sz, &src) != 0) {
        printf("[gitdemo] 'git' not found in binstore/sotfs/CPIO · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[gitdemo] git found via %s · %lu bytes\n", src, sz);
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));   /* unblock sotShell · run the sequence below */

    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);   /* Tier-0 · real writes + sysroot libs */

    static const char *const A_INIT[]    = { "git", "init", "/tmp/gitrepo", NULL };
    static const char *const A_ADD[]     = { "git", "-c", "safe.directory=*", "-C", "/tmp/gitrepo",
                                             "add", "README", NULL };
    static const char *const A_COMMIT[]  = { "git", "-c", "safe.directory=*", "-c", "user.name=sotOs",
                                             "-c", "user.email=root@sotos.local", "-c", "gc.auto=0",
                                             "-c", "maintenance.auto=false", "-C", "/tmp/gitrepo",
                                             "commit", "--allow-empty", "-m", "track README on sotOs", NULL };
    static const char *const A_LSFILES[] = { "git", "-c", "safe.directory=*", "-C", "/tmp/gitrepo",
                                             "ls-files", NULL };
    static const char *const A_LOG[]     = { "git", "--no-pager", "-c", "safe.directory=*",
                                             "-C", "/tmp/gitrepo", "log", "--oneline", NULL };

    if (gitdemo_run(A_INIT, "init /tmp/gitrepo") != 0) goto done;
    /* Seed a file into the working tree git just created.  lucas_sotfs_install_at
     * resolves the nested parent /gitrepo (the root-only lucas_sotfs_install can't).
     * Overwrites on a re-boot (WAL-persisted repo) — harmless. */
    {
        static const char README[] =
            "sotOs - a capability-based deception & compatibility host on seL4.\n"
            "This file is tracked by REAL git running as a Tier-0 sotbox.\n";
        int ir = lucas_sotfs_install_at("/tmp/gitrepo/README", README, sizeof(README) - 1);
        printf("[gitdemo] seeded /tmp/gitrepo/README rc=%d\n", ir);
    }
    if (gitdemo_run(A_ADD,     "add README") != 0)            goto done;
    if (gitdemo_run(A_COMMIT,  "commit --allow-empty") != 0)  goto done;
    if (gitdemo_run(A_LSFILES, "ls-files (tracked?)") != 0)   goto done;
    (void)gitdemo_run(A_LOG,   "log --oneline");
done:
    printf("[gitdemo] handler DONE alive=%d\n", sotbox_alive_count());
}

/* Internet-egress Phase 1 · run the dnsprobe fixture (static musl · UDP:53
 * A-query) twice to demonstrate the DNS forwarder + its containment split:
 *   1. Tier-0e (FUNCTOR_TIER_EGRESS · is_egress=true) resolving example.com —
 *      the authorised real forward out the wire.
 *   2. a NORMAL (non-egress) sotbox resolving the canary domain
 *      malicious-c2.example — the hermetic DNS-intercept synth answers it
 *      (= 10.0.2.15) WITHOUT touching the real wire.
 * Same orch contract as gitdemo: spawn one fresh sotbox per step under its own
 * fault loop, reply to sotShell first.  Each spawn reuses pool slot 0. */
static lucas_state_t s_dnsprobe_st;

/* Spawn one fresh dnsprobe sotbox for `argv` at the given tier/trust and run it
 * to completion under its own fault loop.  Returns 0 on spawn success. */
static int egress_dns_run(const char *const argv[], int tier, bool trusted,
                          const char *label)
{
    const void *e = NULL; unsigned long s = 0; const char *sr = "?";
    if (spawn_load_elf("dnsprobe.bin", &e, &s, &sr) != 0 &&
        spawn_load_elf("dnsprobe",     &e, &s, &sr) != 0) {
        printf("[egress-dns] reload 'dnsprobe' failed (%s) · ABORT\n", label); return -1;
    }
    if (g_validate_used[0]) { printf("[egress-dns] pool slot 0 busy · ABORT\n"); return -1; }
    memset(&s_dnsprobe_st, 0, sizeof(s_dnsprobe_st));
    int rc = sotbox_spawn_into(&s_dnsprobe_st, e, s, argv,
                               /*initial_tier=*/tier, /*pledge=*/0, /*trusted=*/trusted);
    if (rc != 0) { printf("[egress-dns] spawn (%s) rc=%d · ABORT\n", label, rc); return -1; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());   /* run THIS dnsprobe to completion */
    g_validate_used[0] = false;
    return 0;
}

static void orch_handle_egress_dns(void)
{
    printf("[egress-dns] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("dnsprobe.bin", &elf, &sz, &src) != 0 &&
        spawn_load_elf("dnsprobe",     &elf, &sz, &src) != 0) {
        printf("[egress-dns] 'dnsprobe' not found in binstore/sotfs/CPIO · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[egress-dns] dnsprobe found via %s · %lu bytes\n", src, sz);
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));   /* unblock sotShell · run the sequence below */

    /* 1 · non-egress (default Tier-2) · canary domain → hermetic synth answer.
     * Runs FIRST: the DNS-intercept synth enqueues the answer immediately, so
     * the probe's recvfrom always returns and this leg ALWAYS completes (no
     * internet needed).  Keeping it ahead of the real-forward leg guarantees
     * the canary assertions + `handler DONE` land in the headless boot window
     * even when there is no egress connectivity. */
    static const char *const A_CANARY[] = { "dnsprobe", "malicious-c2.example", NULL };
    printf("[egress-dns] === Tier-2 dnsprobe malicious-c2.example (canary synth) ===\n");
    (void)egress_dns_run(A_CANARY, /*tier=*/2, /*trusted=*/false,
                         "malicious-c2.example (Tier-2 canary synth)");

    /* 2 · Tier-0e REAL forward (example.com → 1.1.1.1) is deliberately NOT run in
     * the unconditional boot demo.  It is a network-dependent operation: with no
     * internet egress its forward spin-poll occupies the orch fault loop for the
     * whole forward window and starves concurrent inbound services (the TLS
     * responder) — i.e. it would wedge every OTHER gate's boot (the tls13/ssh
     * gates run with no real egress).  The forward CODE is wired into the DNS
     * intercept (handlers_net.c · A→dns_forward_query, AAAA→empty-NOERROR) and the
     * pure helpers are host-unit-tested; the UDP connect() no longer opens a stray
     * TCP SYN (handlers_net.c connect fix).  Its live end-to-end proof needs a
     * dedicated internet-connected, non-boot trigger (EGRESS_LIVE) — a Phase-1
     * follow-up.  The hermetic Tier-2 canary leg above is the always-on boot
     * assertion that the intercept + injection path works. */

    printf("[egress-dns] handler DONE\n");
}

/* egress P1 · the END-TO-END proof: a REAL off-the-shelf busybox `wget` does the
 * full userland HTTP fetch as a Tier-0e (is_egress) sotbox — musl getaddrinfo
 * (UDP:53 → our DNS forward → real A record over SLIRP) → socket(TCP) →
 * connect(:80, the RESOLVED IP) → tcp_active_open (real SYN) → HTTP GET +
 * response.  Needs live internet egress (triggered in isolation by
 * tools/egress-http-gate.sh via sendkey, NOT auto-run). */
static lucas_state_t s_egress_http_st;
static void orch_handle_egress_http(void)
{
    printf("[egress-http] handler START\n");
    const void *e = NULL; unsigned long s = 0; const char *sr = "?";
    if (spawn_load_elf("busybox-static.bin", &e, &s, &sr) != 0 &&
        spawn_load_elf("busybox",            &e, &s, &sr) != 0) {
        printf("[egress-http] 'busybox' not found in binstore · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[egress-http] busybox found via %s · %lu bytes\n", sr, s);
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));   /* unblock sotShell · run below */
    if (g_validate_used[0]) { printf("[egress-http] pool slot 0 busy · ABORT\n"); return; }
    /* Full real TLS WITH certificate verification: the real ca-certificates bundle
     * is served read-only at /etc/ssl/cert.pem (backends_cacert.c), so busybox
     * wget's openssl s_client helper (-verify_return_error) verifies the real
     * example.com chain against a real trust store — no --no-check-certificate. */
    static const char *const WGET[] = {
        "wget", "-q", "-O", "-", "https://example.com", NULL };
    printf("[egress-http] === Tier-0e busybox wget https://example.com (REAL egress · TLS) ===\n");
    memset(&s_egress_http_st, 0, sizeof(s_egress_http_st));
    int rc = sotbox_spawn_into(&s_egress_http_st, e, s, WGET,
                               /*initial_tier=*/FUNCTOR_TIER_EGRESS, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[egress-http] spawn rc=%d · ABORT\n", rc); return; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());   /* run the wget to completion */
    g_validate_used[0] = false;
    printf("[egress-http] handler DONE\n");
}

/* Compat-host · run a glibc-static binary at Tier-0.  Proves the GNU/glibc libc
 * ABI runs on sotOs (not just musl): the probe exercises stdio (printf/fopen/
 * fgets), malloc/free, strtol, uname, getpid — real glibc library code.  Static
 * (no ld-linux loader · that's the glibc-dynamic arc); its whole syscall surface
 * is already supported, so this is a staging-only win, like git.  Mirrors
 * orch_handle_doom: spawn, reply, run ONE fault loop until it exits. */
static lucas_state_t s_glibc_st;
static void orch_handle_glibc(void)
{
    printf("[glibc] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("glibc-probe", &elf, &sz, &src) != 0) {
        printf("[glibc] 'glibc-probe' not found in binstore/sotfs/CPIO · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[glibc] glibc-probe found via %s · %lu bytes\n", src, sz);
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));   /* unblock sotShell */

    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);   /* Tier-0 trusted compat workload */
    if (g_validate_used[0]) { printf("[glibc] pool slot 0 busy · ABORT\n"); goto done; }
    {
        const char *argv[] = { "glibc-probe", NULL };
        memset(&s_glibc_st, 0, sizeof(s_glibc_st));
        int rc = sotbox_spawn_into(&s_glibc_st, elf, sz, argv,
                                   /*initial_tier=*/0, /*pledge=*/0, /*trusted=*/true);
        if (rc != 0) { printf("[glibc] sotbox_spawn_into rc=%d · ABORT\n", rc); goto done; }
        g_validate_used[0] = true;
        orch_fault_loop(orch_get_fault_ep());   /* run glibc-probe to completion */
        g_validate_used[0] = false;
    }
done:
    printf("[glibc] handler DONE alive=%d\n", sotbox_alive_count());
}

/* Compat-host · run real GNU tools (musl-dynamic, from Alpine) at Tier-0:
 * GNU coreutils 9.5 (multi-call ls/cat/wc), grep, sed, gawk — on the honey
 * /etc/passwd.  Each tool is a fresh Tier-0 sotbox; libs resolve from the
 * sysroot.  Proves the GNU userland (not busybox) runs on sotOs. */
static lucas_state_t s_gnu_st;
static int gnu_run(const char *binname, const char *const argv[], const char *label)
{
    const void *e = NULL; unsigned long s = 0; const char *sr = "?";
    if (spawn_load_elf(binname, &e, &s, &sr) != 0) {
        printf("[gnu] '%s' not found in binstore · skip (%s)\n", binname, label); return -1;
    }
    if (g_validate_used[0]) { printf("[gnu] pool slot 0 busy · ABORT\n"); return -1; }
    printf("[gnu] === %s ===\n", label);
    memset(&s_gnu_st, 0, sizeof(s_gnu_st));
    int rc = sotbox_spawn_into(&s_gnu_st, e, s, argv, /*tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[gnu] spawn (%s) rc=%d · ABORT\n", label, rc); return -1; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());
    g_validate_used[0] = false;
    return 0;
}
static void orch_handle_gnu(void)
{
    printf("[gnu] handler START\n");
    const void *e = NULL; unsigned long s = 0; const char *sr = "?";
    if (spawn_load_elf("grep", &e, &s, &sr) != 0) {
        printf("[gnu] GNU tools not staged in binstore · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);
    gnu_run("coreutils", (const char *const[]){ "coreutils", "--coreutils-prog=ls", "-la", "/tmp", NULL },
            "GNU coreutils ls -la /tmp");
    gnu_run("coreutils", (const char *const[]){ "coreutils", "--coreutils-prog=cat", "/etc/passwd", NULL },
            "GNU coreutils cat /etc/passwd");
    gnu_run("coreutils", (const char *const[]){ "coreutils", "--coreutils-prog=wc", "-l", "/etc/passwd", NULL },
            "GNU coreutils wc -l /etc/passwd");
    gnu_run("grep", (const char *const[]){ "grep", "-c", "", "/etc/passwd", NULL },
            "GNU grep -c (line count via empty pattern)");
    gnu_run("grep", (const char *const[]){ "grep", "root", "/etc/passwd", NULL },
            "GNU grep root /etc/passwd");
    gnu_run("sed", (const char *const[]){ "sed", "s/root/ROOT/g", "/etc/passwd", NULL },
            "GNU sed s/root/ROOT/g");
    gnu_run("gawk", (const char *const[]){ "gawk", "-F:", "{ print \"user=\" $1 }", "/etc/passwd", NULL },
            "GNU awk -F: print usernames");
    printf("[gnu] handler DONE alive=%d\n", sotbox_alive_count());
}

/* Compat-host · run an off-the-shelf glibc-DYNAMIC PIE at Tier-0, loaded by the
 * REAL glibc dynamic linker ld-linux-x86-64.so.2 (not ld-musl).  sotOs's dynamic
 * path already fetches the interp by basename, so this exercises the glibc loader
 * bring-up: ld-linux self-relocates, opens libc.so.6 (sysroot /usr/lib/x86_64-
 * linux-gnu via the /lib alias), relocates it, runs its init, jumps to the PIE.
 * Exploratory — finds the gaps between the proven ld-musl path and glibc's loader. */
static lucas_state_t s_glibcdyn_st;
static int glibcdyn_run(const char *binname, const char *const argv[], const char *label)
{
    const void *e = NULL; unsigned long s = 0; const char *sr = "?";
    if (spawn_load_elf(binname, &e, &s, &sr) != 0) {
        printf("[glibcdyn] '%s' not in binstore · skip (%s)\n", binname, label); return -1;
    }
    if (g_validate_used[0]) { printf("[glibcdyn] pool slot 0 busy · ABORT\n"); return -1; }
    printf("[glibcdyn] === %s ===\n", label);
    memset(&s_glibcdyn_st, 0, sizeof(s_glibcdyn_st));
    int rc = sotbox_spawn_into(&s_glibcdyn_st, e, s, argv, /*tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[glibcdyn] spawn (%s) rc=%d · ABORT\n", label, rc); return -1; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());
    g_validate_used[0] = false;
    return 0;
}
/* real-tools fs battery · GNU bash -c drives real GNU tar + coreutils through a
 * recursive-fs workflow.  The `tar -xf` extract of a nested tree exercises the
 * dir-fd VFS support (GNU tar uses dirfd-relative openat/mkdirat for nested
 * paths, which mis-resolved to "/" before).  Uncompressed tar so there is no
 * gzip subprocess+pipe (which deadlocks the single-threaded orch). */
static void orch_handle_toolsfs(void)
{
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    static const char *const TOOLSFS_ENVP[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root", NULL };
    printf("[tools-fs] handler START\n");
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));   /* unblock sotShell · run below */
    static const char *const BASH_ARGV[] = {
        "bash", "-c",
        "set -e\n"
        "cd /tmp\n"                                  /* relative paths · mkdir -p never touches / */
        "rm -rf tb; mkdir -p tb/src/a/b/c\n"
        "echo deepfile-contents > tb/src/a/b/c/deep.txt\n"
        "echo topfile > tb/src/top.txt\n"
        "echo '  [1] GNU tar -cf (archive the nested tree)'\n"
        "tar -cf tb/arc.tar -C tb src\n"
        "mkdir -p tb/out\n"
        "echo '  [2] GNU tar -xf (extract -> recreate nested dirs via dir-fd)'\n"
        "tar -xf tb/arc.tar -C tb/out\n"
        "echo \"  [3] read back the deep file: $(cat tb/out/src/a/b/c/deep.txt)\"\n"
        "echo '  [4] cp -r (recursive copy)'\n"
        "cp -r tb/out/src tb/copy\n"
        "echo \"  [5] copy has the deep file: $(cat tb/copy/a/b/c/deep.txt)\"\n"
        "echo '  [6] rm -rf (recursive remove · scandir+unlinkat by dir-fd)'\n"
        "rm -rf tb/copy\n"
        "[ ! -e tb/copy ] && echo '  [7] copy removed'\n"
        "echo TOOLS_FS_OK nested-tar-extract+cat+cp-r+rm-rf\n",
        NULL };
    sotbox_spawn_set_envp_next(TOOLSFS_ENVP);   /* PATH so bash finds tar/cp/rm/cat */
    glibcdyn_run("debian-bash", BASH_ARGV,
                 "real-tools fs battery · GNU tar nested extract + cp -r + rm -rf");
    printf("[tools-fs] handler DONE alive=%d\n", sotbox_alive_count());
}

static void orch_handle_glibcdyn(void)
{
    printf("[glibcdyn] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("hello-glibc-dyn", &elf, &sz, &src) != 0) {
        printf("[glibcdyn] 'hello-glibc-dyn' not in binstore · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[glibcdyn] hello-glibc-dyn found via %s · %lu bytes\n", src, sz);
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));

    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);

    /* the fixture hello (the loader smoke test) */
    glibcdyn_run("hello-glibc-dyn", (const char *const[]){ "hello-glibc-dyn", NULL },
                 "fixture hello (glibc PIE via ld-linux)");
    /* REAL off-the-shelf DEBIAN binaries (glibc PIE · their closures resolve from
     * the sysroot multiarch dir).  /bin/ls -la / exercises the VFS-root stat fix. */
    glibcdyn_run("debian-ls",   (const char *const[]){ "ls", "-la", "/", NULL },     "Debian /bin/ls -la /");
    glibcdyn_run("debian-ls",   (const char *const[]){ "ls", "-la", "/tmp", NULL },  "Debian /bin/ls -la /tmp");
    glibcdyn_run("debian-cat",  (const char *const[]){ "cat", "/etc/passwd", NULL }, "Debian cat /etc/passwd");
    glibcdyn_run("debian-uname",(const char *const[]){ "uname", "-a", NULL },        "Debian uname -a");
    glibcdyn_run("debian-head", (const char *const[]){ "head", "-n", "1", "/etc/passwd", NULL }, "Debian head -n1 /etc/passwd");
    glibcdyn_run("debian-env",  (const char *const[]){ "env", NULL },                "Debian env");
    /* clock fidelity · `date -u` prints the wall clock via the rewired
     * clock_gettime → a believable 202x persona year (NOT 1970). */
    glibcdyn_run("debian-date", (const char *const[]){ "date", "-u", NULL },          "Debian date -u");
    /* CROSS-DISTRO · a FEDORA binary running on the Debian glibc runtime
     * (Fedora 40 glibc 2.39 ≤ Debian 2.41 → forward-compatible). */
    glibcdyn_run("fedora-uname",(const char *const[]){ "uname", "-a", NULL },        "Fedora uname -a (on Debian glibc)");
    glibcdyn_run("fedora-cat",  (const char *const[]){ "cat", "/etc/passwd", NULL }, "Fedora cat /etc/passwd (on Debian glibc)");

    /* A REAL glibc SHELL · GNU bash 5.2.  `bash -c` exercises the parser + builtins
     * (loop, arithmetic, parameter expansion, conditionals) — no TTY, no external
     * exec needed.  libtinfo.so.6 joins the closure. */
    glibcdyn_run("debian-bash", (const char *const[]){ "bash", "--version", NULL },
                 "Debian bash --version");
    glibcdyn_run("debian-bash", (const char *const[]){ "bash", "-c",
            "echo 'GNU bash on sotOs'; "
            "for i in 1 2 3; do echo \"  iter $i\"; done; "
            "x=$((6 * 7)); echo \"  arithmetic 6*7=$x\"; "
            "s=sotos; echo \"  upcase=${s^^}\"; "
            "[ \"$x\" = 42 ] && echo '  conditional OK'",
            NULL },
            "Debian bash -c (loop/arith/param-expand/conditional)");

    printf("[glibcdyn] handler DONE alive=%d\n", sotbox_alive_count());

    /* A5 · TUI editors · off-the-shelf Debian glibc-dynamic PIEs (less/nano/
     * vim-tiny) via the real ld-linux.  ncurses/tinfo closure ships in the
     * sysroot (libtinfo/libncursesw + vim's libm/libselinux/libacl/libpcre2-8);
     * the xterm terminfo is at /usr/share/terminfo/x.  --version proves each one
     * loads+links+runs non-interactively (interactive use over SSH = Task A6). */
    glibcdyn_run("less",  (const char *const[]){ "less", "--version", NULL }, "less --version");
    glibcdyn_run("nano",  (const char *const[]){ "nano", "--version", NULL }, "nano --version");
    glibcdyn_run("vim",   (const char *const[]){ "vim",  "--version", NULL }, "vim --version");
    printf("[tui] handler DONE\n");

    /* Install-arc P0.1 · the real Debian dpkg toolchain (glibc-dynamic PIEs via
     * the real ld-linux).  --version proves each tool loads+links+runs (its NEW
     * lib closure libmd/libz/liblzma/libzstd/libbz2/liblz4/libxxhash resolves
     * from the sysroot multiarch dir).  Phase 0.2 does the real `dpkg-deb -x`. */
    glibcdyn_run("dpkg-deb",   (const char *const[]){ "dpkg-deb", "--version", NULL }, "dpkg-deb --version");
    glibcdyn_run("dpkg",       (const char *const[]){ "dpkg",     "--version", NULL }, "dpkg --version");
    glibcdyn_run("dpkg-split", (const char *const[]){ "dpkg-split", "--version", NULL }, "dpkg-split --version");
    glibcdyn_run("tar",        (const char *const[]){ "tar",  "--version", NULL }, "tar --version");
    glibcdyn_run("xz",         (const char *const[]){ "xz",   "--version", NULL }, "xz --version");
    glibcdyn_run("gzip",       (const char *const[]){ "gzip", "--version", NULL }, "gzip --version");
    glibcdyn_run("zstd",       (const char *const[]){ "zstd", "--version", NULL }, "zstd --version");
    printf("[dpkg-stage] DONE alive=%d\n", sotbox_alive_count());
}

/* ------------------------------------------------------------------ */
/* Install-arc P0.2 · `dpkg-deb -x /tmp/hello.deb /tmp/root`           */
/* ------------------------------------------------------------------ */
/* Spawns the real off-the-shelf Debian `dpkg-deb` (glibc-dynamic PIE  */
/* via ld-linux) at Tier-0 to EXTRACT a .deb: ar→data.tar.xz→tar -x,   */
/* writing /tmp/root/usr/bin/hello (a real ELF) onto the writable /tmp */
/* sotfs.  dpkg-deb execve's the real `tar` + `xz` (both staged in P0.1)*/
/* internally; the dest tree is mkdir'd through the A1/A2 /tmp routing. */
/* Mirrors glibcdyn_run's spawn-then-fault-loop contract.              */
static lucas_state_t s_install_st;
/* dpkg searches PATH for its helper programs (dpkg-deb/rm/diff/ldconfig/
 * start-stop-daemon) and aborts if any is missing; give the install tools a
 * believable root PATH + HOME so those lookups resolve to the /usr/bin (and
 * /sbin) stubs. */
static const char *const install_envp[] = {
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/root",
    "TERM=xterm",
    "DPKG_COLORS=never",
    NULL,
};

static int install_run(const char *binname, const char *const argv[], const char *label)
{
    const void *e = NULL; unsigned long s = 0; const char *sr = "?";
    if (spawn_load_elf(binname, &e, &s, &sr) != 0) {
        printf("[install] '%s' not in binstore · skip (%s)\n", binname, label); return -1;
    }
    if (g_validate_used[0]) { printf("[install] pool slot 0 busy · ABORT\n"); return -1; }
    printf("[install] === %s ===\n", label);
    memset(&s_install_st, 0, sizeof(s_install_st));
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    sotbox_spawn_set_envp_next(install_envp);
    int rc = sotbox_spawn_into(&s_install_st, e, s, argv, /*tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[install] spawn (%s) rc=%d · ABORT\n", label, rc); return -1; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());
    g_validate_used[0] = false;
    return 0;
}
static void orch_handle_install(void)
{
    printf("[install] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("dpkg-deb", &elf, &sz, &src) != 0) {
        printf("[install] 'dpkg-deb' not in binstore · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[install] dpkg-deb found via %s · %lu bytes\n", src, sz);
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));

    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);

    /* The real extraction: dpkg-deb -x unpacks data.tar.xz → /tmp/root tree.
     * dpkg-deb mkdir's /tmp/root and each subdir, execve's `tar`+`xz`, and
     * writes /tmp/root/usr/bin/hello (the ELF) via the sotfs write path. */
    install_run("dpkg-deb",
                (const char *const[]){ "dpkg-deb", "-x", "/tmp/hello.deb", "/tmp/root", NULL },
                "dpkg-deb -x /tmp/hello.deb /tmp/root");

    /* Prove the tree landed: list the extracted /usr/bin (the hello ELF) with
     * the REAL off-the-shelf Debian /bin/ls (glibc-dynamic · binstore 'debian-
     * ls') — a busybox applet would not load via spawn_load_elf (it's not a
     * binstore entry). */
    install_run("debian-ls",
                (const char *const[]){ "ls", "-la", "/tmp/root/usr/bin", NULL },
                "ls -la /tmp/root/usr/bin (extracted tree)");

    install_run("dpkg",
                (const char *const[]){ "/usr/bin/dpkg", "-i", "/tmp/hello.deb", NULL },
                "dpkg -i /tmp/hello.deb");
    /* RUN the just-installed binary · spawn_load_elf("/usr/bin/hello") reads the
     * ELF from the sotfs overlay upper (where dpkg unpacked it). */
    install_run("/usr/bin/hello",
                (const char *const[]){ "/usr/bin/hello", NULL },
                "/usr/bin/hello (the installed binary → Hello, world!)");

    /* P1b · a package with a REAL postinst.  dpkg -i unpacks sotmark.deb, then
     * `configure` runs /var/lib/dpkg/info/sotmark.postinst via fork+execve
     * /bin/sh (binfmt_script shebang → busybox sh), which writes /etc/sotmark.conf
     * into the writable /etc union upper — the maintainer-script + /etc-side-effect
     * proof.  Then read it back with the real glibc-dynamic Debian `cat` to show
     * the side effect is observable (and the honey base is otherwise intact). */
    install_run("dpkg",
                (const char *const[]){ "/usr/bin/dpkg", "-i", "/tmp/sotmark.deb", NULL },
                "dpkg -i /tmp/sotmark.deb (postinst writes /etc)");
    install_run("debian-cat",
                (const char *const[]){ "cat", "/etc/sotmark.conf", NULL },
                "cat /etc/sotmark.conf (the postinst /etc side effect)");

    /* P1.4 · the REAL install `dpkg -i /tmp/hello.deb` is wired and drives the
     * full path (DB lock/read, status update + link-backup, split-check, control
     * extraction).  RE-ENABLE once the fork-memory-exhaustion blocker is solved:
     * dpkg's fork tree (dpkg→dpkg-deb→tar concurrent, each a full glibc-dynamic
     * process whose eager fork-copy duplicates a ~64MB WIN-THREAD-HIGH region)
     * exhausts orch's allocator mid-copy → the child runs with missing pages →
     * VMFault.  Needs COW-fork or bounding the eager copy (own task).
     *   install_run("dpkg", (const char *const[]){ "/usr/bin/dpkg", "-i",
     *               "/tmp/hello.deb", NULL }, "dpkg -i /tmp/hello.deb");
     *   install_run("/usr/bin/hello", (const char *const[]){ "/usr/bin/hello",
     *               NULL }, "/usr/bin/hello → Hello, world!");
     * argv[0] must be the FULL path (/usr/bin/dpkg) so dpkg locates its sibling
     * dpkg-deb (it searches argv[0]'s dir). */

    printf("[install] handler DONE alive=%d\n", sotbox_alive_count());
}

extern int g_egress_trusted_active; /* sotbox_table.c · trusted egress → suppress anomaly EP (anti-deadlock) */

/* Apply an anomaly-driven tier promotion IN-PROCESS, with NO orch_ep IPC
 * callback.  The auto-promote anomaly events (TCP_OPEN / NET_PRECOMMIT-Rule-D /
 * CURVATURE / DNS_HIT / MSYSCALL) now return the target tier in their REPLY
 * (mirroring the reply-driven WRITE/CRED path) and the in-orch emit site calls
 * this directly — instead of anomaly-ext doing a re-entrant
 * seL4_Call(orch_ep, ORCH_OP_PROMOTE_TIER).  That re-entrant Call deadlocks
 * whenever the triggering event was emitted while orch is NOT parked in its main
 * seL4_Recv (e.g. inside a nested egress fault loop — anomaly-ext blocks off its
 * own Recv and the next event's Call(anomaly_ep) then hangs forever).  Every
 * emit site runs in the orch address space, so the apply is a plain function
 * call here · works from ANY orch context (main loop OR nested fault loop). */
extern void anomaly_apply_reply_tier(lucas_state_t *st, int target); /* lucas/anomaly.c */
void orch_anomaly_apply_promote(uint32_t pid, int target_tier)
{
    if (target_tier <= 0 || pid < 1 || pid > (uint32_t)SOTBOX_MAX_SLOTS) return;
    lucas_state_t *st = sotbox_get_slot(pid - 1);
    if (st) anomaly_apply_reply_tier(st, target_tier);  /* never-downgrade + [trust] log */
}

/* native CONTROL · `sotctl promote/quarantine <pid>` · escalate a LIVE sotbox's
 * containment tier BY its DISPLAY pid (what the operator sees in `sotctl
 * process`).  quarantine=1 → tier 2 (max canary containment); else promote one
 * tier (current+1, capped at 2).  Uses anomaly_apply_reply_tier (never-downgrade
 * + [trust] log).  Returns the new tier, or -1 if no live sotbox matches. */
/* native CONTROL · `sotctl persona set <name>` · the persona-selection policy for
 * NEW SSH sessions.  -1 = round-robin (alternate Alpine/Debian); 0 = pin Alpine;
 * 1 = pin Debian.  Read by orch_ssh_shell_run's persona pick.
 *
 * DEFAULT = 0 (pin Alpine · prod-db-01) so the honey is ONE coherent host: a single IP
 * that flips between prod-db-01 (Alpine) and debian-app-01 (Debian) per connection is a
 * glaring tell and breaks any cross-session comparison.  Round-robin (-1) is a demo of
 * the per-session persona seam — opt in with `sotctl persona set rr` when you want it. */
static int g_persona_pin = 0;
void orch_persona_pin_set(int pin) { g_persona_pin = (pin < 0 || pin > 1) ? -1 : pin; }
int  orch_persona_pin_get(void)    { return g_persona_pin; }

/* native VIEW · `sotctl canary list` live-hits · iterate the sotbox slots and
 * report each box that has READ a canary file (canary_read_count > 0) — an IOC.
 * Returns the hit count.  (The inventory of armed tripwires is static in libsot.) */
int orch_canary_hits(struct sot_canary_hit *out, int max)
{
    extern uint32_t sotos_pid_display(uint32_t synthetic_pid);
    if (!out || max <= 0) return 0;
    int n = 0;
    for (int i = 0; i < SOTBOX_MAX_SLOTS && n < max; i++) {
        lucas_state_t *st = sotbox_get_slot(i);
        if (!st || st->canary_read_count <= 0) continue;
        if (st->display_pid == 0)
            st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid);
        out[n].pid     = (uint32_t)st->display_pid;
        out[n].session = st->cow_session;
        out[n].reads   = st->canary_read_count;
        n++;
    }
    return n;
}

int orch_tier_control(uint32_t display_pid, int quarantine)
{
    extern uint32_t sotos_pid_display(uint32_t synthetic_pid);
    for (int i = 0; i < SOTBOX_MAX_SLOTS; i++) {
        lucas_state_t *st = sotbox_get_slot(i);
        if (!st) continue;
        if (st->display_pid == 0)
            st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid);
        if ((uint32_t)st->display_pid == display_pid) {
            int target = quarantine ? 2 : (st->tier < 2 ? st->tier + 1 : 2);
            anomaly_apply_reply_tier(st, target);
            return st->tier;   /* the new (possibly clamped / never-downgraded) tier */
        }
    }
    return -1;
}
/* ------------------------------------------------------------------ */
/* Egress install · download a REAL package over verified HTTPS + EXTRACT. */
/* ------------------------------------------------------------------ */
/* The COMPLETE network install, end to end: (1) the Tier-0e TLS egress client */
/* — busybox `wget -O /tmp/pkg.tgz https://files.pythonhosted.org/.../six-…tar.gz` */
/* downloads a REAL package (a pypi sdist) over a VERIFIED TLS handshake (real  */
/* CA bundle at /etc/ssl/cert.pem) onto sotfs /tmp; (2) the real GNU `tar -xzf` */
/* EXTRACTS it (gzip · the working dpkg-style path · NOT xz, whose dpkg-deb→xz→ */
/* tar pipe chain deadlocks under the single-threaded orch), and the real glibc */
/* `ls` proves the package tree landed.  pypi sdists are .tar.gz, which is why  */
/* this is the clean complete-install target (modern Debian .deb is all xz).    */
/* Network-dependent · sendkey-triggered (tools/egress-install-gate.sh).        */
static lucas_state_t s_egress_dl_st;
extern void sotbox_spawn_set_envp_next(const char *const envp[]);
extern const char *const EGRESS_PY_ENVP[];   /* defined just below (SSL_CERT_FILE etc.) */
static void orch_handle_egress_install(void)
{
    printf("[egress-install] handler START\n");
    g_egress_trusted_active = 1;  /* trusted egress · suppress anomaly EP (anti-deadlock) */
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("python3.12-static", &elf, &sz, &src) != 0) {
        printf("[egress-install] python3.12-static not found · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));   /* unblock sotShell · run below */
    if (g_validate_used[0]) { printf("[egress-install] pool slot 0 busy · ABORT\n"); return; }

    /* The COMPLETE network install, ENTIRELY IN-PROCESS in real CPython — which
     * sidesteps every single-threaded-orch infra limit the busybox path hit:
     *   - DOWNLOAD: python's static _ssl does the verified TLS GET and reads the
     *     wire DIRECTLY (lucas_tcp_recv) — NO openssl→wget socketpair relay, so no
     *     >ring-size truncation of a large file-bound transfer.
     *   - DECOMPRESS+EXTRACT: tarfile inflates gzip IN-PROCESS — NO tar↔gzip pipe
     *     (the multi-process pipe deadlocks) and NO dirfd-relative openat (which
     *     LUCAS mis-resolves to the static "/" mount).
     * It fetches a REAL pypi sdist (six-1.16.0.tar.gz) over a cert-verified HTTPS
     * handshake (real CA bundle at /etc/ssl/cert.pem), extracts it to /tmp, and
     * prints the extracted file list. */
    static const char *const PYARGV[] = {
        "python3", "-c",
        "import socket,ssl,io,tarfile,os\n"
        "h='files.pythonhosted.org'\n"
        "p='/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz'\n"
        "c=ssl.create_default_context()\n"
        "s=c.wrap_socket(socket.create_connection((h,443),timeout=60),server_hostname=h)\n"
        "s.sendall(('GET %s HTTP/1.0\\r\\nHost: %s\\r\\nUser-Agent: sotos\\r\\n\\r\\n'%(p,h)).encode())\n"
        "buf=b''\n"
        "while b'\\r\\n\\r\\n' not in buf:\n"
        " buf+=s.recv(4096)\n"
        "head,body=buf.split(b'\\r\\n\\r\\n',1)\n"
        "clen=0\n"
        "for L in head.split(b'\\r\\n'):\n"
        " if L.lower().startswith(b'content-length:'): clen=int(L.split(b':',1)[1])\n"
        "while len(body)<clen:\n"
        " d=s.recv(65536)\n"
        " if not d: break\n"
        " body+=d\n"
        "print('PYINSTALL download',len(body),'of',clen,'bytes verified TLS')\n"
        "tarfile.open(fileobj=io.BytesIO(body)).extractall('/tmp')\n"
        "print('PYINSTALL_OK',sorted(os.listdir('/tmp/six-1.16.0'))[:5])\n",
        NULL };
    printf("[egress-install] === Tier-0e python in-process: download+extract six-1.16.0.tar.gz ===\n");
    memset(&s_egress_dl_st, 0, sizeof(s_egress_dl_st));
    sotbox_spawn_set_envp_next(EGRESS_PY_ENVP);
    int rc = sotbox_spawn_into(&s_egress_dl_st, elf, sz, PYARGV,
                               /*tier=*/FUNCTOR_TIER_EGRESS, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[egress-install] python spawn rc=%d · ABORT\n", rc); return; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());   /* run download+extract to completion */
    g_validate_used[0] = false;

    g_egress_trusted_active = 0;
    printf("[egress-install] handler DONE alive=%d\n", sotbox_alive_count());
}

/* ------------------------------------------------------------------ */
/* Egress python · real CPython does an HTTPS GET over the egress.     */
/* ------------------------------------------------------------------ */
/* The pip foundation: python3.12-static (with its statically-linked OpenSSL      */
/* _ssl module) at Tier-0e does an IN-PROCESS TLS 1.3 handshake — socket →        */
/* SSL_connect → recv — verifying the real server cert against /etc/ssl/cert.pem   */
/* (the real CA bundle).  No subprocess relay: python's _ssl drives the egress     */
/* wire (lucas_tcp_send/recv) directly.  Heavy arena auto-routed by the ELF size.  */
/* Network-dependent · sendkey-triggered (tools/egress-python-gate.sh).            */
static lucas_state_t s_egress_py_st;
const char *const EGRESS_PY_ENVP[] = {
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/root",
    /* point python's ssl at the real CA bundle; do NOT set PYTHONHOME — the
     * static interp's compiled-in prefix already finds the stdlib zip mounted at
     * /install/lib/python312.zip (overriding it breaks the `encodings` import). */
    "SSL_CERT_FILE=/etc/ssl/cert.pem",
    "PYTHONDONTWRITEBYTECODE=1",
    NULL,
};
/* Operator `shell --trusted` python env · EGRESS_PY_ENVP + a WRITABLE default
 * install location so a plain interactive `pip install <pkg>` (no --target) just
 * works.  The interp's site-packages is /install/lib (read-only · the stdlib zip
 * mount) → a bare `pip install` would EROFS; PIP_TARGET redirects every install
 * to writable /tmp/site-packages (sotfs blkdev) and PYTHONPATH puts it on
 * sys.path so the freshly-installed package imports.  (The demos keep their own
 * explicit --target /tmp/sp and are unaffected — they use EGRESS_PY_ENVP.) */
const char *const TRUSTED_SHELL_PY_ENVP[] = {
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/root",
    "SSL_CERT_FILE=/etc/ssl/cert.pem",
    "PYTHONDONTWRITEBYTECODE=1",
    "PIP_TARGET=/tmp/site-packages",
    "PYTHONPATH=/tmp/site-packages",
    NULL,
};
static void orch_handle_egress_python(void)
{
    printf("[egress-python] handler START\n");
    g_egress_trusted_active = 1;  /* trusted egress · suppress anomaly EP (anti-deadlock) */
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("python3.12-static", &elf, &sz, &src) != 0) {
        printf("[egress-python] python3.12-static not found · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));   /* unblock sotShell · run below */
    if (g_validate_used[0]) { printf("[egress-python] pool slot 0 busy · ABORT\n"); return; }

    /* python -c : fetch https://example.com in-process via the LOW-LEVEL socket+ssl
     * path (NOT urllib.request, which imports ~50 modules — email/http.client/… —
     * and exhausts the heavy arena).  socket+ssl is the real in-process TLS: a
     * default-verifying SSLContext (checks the cert vs /etc/ssl/cert.pem) wraps the
     * connected socket, sends an HTTP/1.0 GET, reads the response.  Prints a marker
     * the gate keys on. */
    static const char *const PYARGV[] = {
        "python3", "-c",
        "import socket,ssl;"
        "c=ssl.create_default_context();"
        "s=c.wrap_socket(socket.create_connection(('example.com',443),timeout=30),"
        "server_hostname='example.com');"
        "s.sendall(b'GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n');"
        "d=b''\n"
        "while True:\n"
        " b=s.recv(4096)\n"
        " if not b: break\n"
        " d+=b\n"
        "print('PYHTTPS_OK',len(d),b'Example Domain' in d,d[:15])",
        NULL };
    printf("[egress-python] === Tier-0e python3 HTTPS GET https://example.com (in-process _ssl) ===\n");
    memset(&s_egress_py_st, 0, sizeof(s_egress_py_st));
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    sotbox_spawn_set_envp_next(EGRESS_PY_ENVP);
    int rc = sotbox_spawn_into(&s_egress_py_st, elf, sz, PYARGV,
                               /*tier=*/FUNCTOR_TIER_EGRESS, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[egress-python] spawn rc=%d · ABORT\n", rc); return; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());
    g_validate_used[0] = false;
    g_egress_trusted_active = 0;
    printf("[egress-python] handler DONE alive=%d\n", sotbox_alive_count());
}

/* ------------------------------------------------------------------ */
/* Arena reclaim VALIDATION · churn >arena-size through a heavy box.   */
/* ------------------------------------------------------------------ */
/* Proves the in-life arena reclaim: python mmaps+frees a 1 MiB buffer 300× — 300
 * MiB cycled through the 128 MiB heavy arena.  WITHOUT reclaim each mmap leaks the
 * frames (munmap was a no-op) → the arena exhausts at ~120 MiB → MemoryError.
 * WITH reclaim the freed frames are recycled+reused → it completes (ARENA_CHURN_OK).
 * Tier-0 (no egress) · heavy arena auto-routed · sendkey (tools/arena-churn-gate). */
static lucas_state_t s_churn_st;
static void orch_handle_arena_churn(void)
{
    printf("[arena-churn] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("python3.12-static", &elf, &sz, &src) != 0) {
        printf("[arena-churn] python3.12-static not found · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
    if (g_validate_used[0]) { printf("[arena-churn] pool slot 0 busy · ABORT\n"); return; }
    static const char *const PYARGV[] = {
        "python3", "-c",
        "N=300\n"
        "for i in range(N):\n"
        " x=bytearray(1048576)\n"
        " x[0]=1; x[1048575]=1\n"
        " del x\n"
        " if i%50==0: print('CHURN',i,'of',N)\n"
        "print('ARENA_CHURN_OK',N,'MiB cycled through the 128 MiB arena')\n",
        NULL };
    printf("[arena-churn] === python: mmap+free 1 MiB ×300 (300 MiB through 128 MiB arena) ===\n");
    memset(&s_churn_st, 0, sizeof(s_churn_st));
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    sotbox_spawn_set_envp_next(EGRESS_PY_ENVP);
    int rc = sotbox_spawn_into(&s_churn_st, elf, sz, PYARGV,
                               /*tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[arena-churn] spawn rc=%d · ABORT\n", rc); return; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());
    g_validate_used[0] = false;
    printf("[arena-churn] handler DONE alive=%d\n", sotbox_alive_count());
}

/* ------------------------------------------------------------------ */
/* Egress · FULL pip install · the network-install-the-tool marquee.  */
/* ------------------------------------------------------------------ */
/* real CPython runs pip ITSELF (pip rides in the stdlib zip · staged by
 * scripts/build-python-stdlib-zip.sh from the bundled wheel).  Two steps in one
 * process via pip's library entry (pip._internal.cli.main.main, which returns an
 * int instead of sys.exit-ing like the console script):
 *   1. `pip --version`  → exercises pip's heavy import tree (~150 modules); only
 *      survives the 128 MiB heavy arena because of the in-life FRAME RECLAIM
 *      (now unconditional for heavy arenas) + the .pyc-only stdlib (no per-import
 *      compile spike).
 *   2. `pip install --target /tmp/sp six`  → pip resolves six on pypi.org/simple,
 *      downloads the wheel from files.pythonhosted.org over a cert-verified TLS
 *      handshake (pip's vendored certifi + our egress _ssl path), and unpacks it
 *      into the WRITABLE /tmp/sp (sotfs upper) — a real site-packages.
 * Then `import six` from /tmp/sp proves the installed package is usable.
 * Tier-0e (is_egress) · heavy arena auto-routed · sendkey (tools/egress-pip-gate). */
static lucas_state_t s_egress_pip_st;
static void orch_handle_egress_pip(void)
{
    printf("[egress-pip] handler START\n");
    g_egress_trusted_active = 1;  /* trusted egress · suppress anomaly EP (anti-deadlock) */
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("python3.12-static", &elf, &sz, &src) != 0) {
        printf("[egress-pip] python3.12-static not found · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));   /* unblock sotShell · run below */
    if (g_validate_used[0]) { printf("[egress-pip] pool slot 0 busy · ABORT\n"); return; }

    /* pip's library entry returns an int for `install` but RAISES SystemExit for
     * `--version` (argparse) — wrap both in run() (SystemExit code None == 0). */
    static const char *const PYARGV[] = {
        "python3", "-c",
        "import sys\n"
        "from pip._internal.cli.main import main as pip\n"
        "def run(a):\n"
        " try: return pip(a)\n"
        " except SystemExit as e: return 0 if e.code is None else e.code\n"
        "print('PIP_VERSION_RC', run(['--version']))\n"
        "rc=run(['install','--no-cache-dir','--disable-pip-version-check',"
        "'--no-input','--target','/tmp/sp','six'])\n"
        "print('PIP_INSTALL_RC', rc)\n"
        "sys.path.insert(0,'/tmp/sp')\n"
        "import six\n"
        "print('PIP_FULL_OK six', six.__version__, six.__file__)\n",
        NULL };
    printf("[egress-pip] === Tier-0e python -m pip: --version + install six from PyPI ===\n");
    memset(&s_egress_pip_st, 0, sizeof(s_egress_pip_st));
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    sotbox_spawn_set_envp_next(EGRESS_PY_ENVP);
    int rc = sotbox_spawn_into(&s_egress_pip_st, elf, sz, PYARGV,
                               /*tier=*/FUNCTOR_TIER_EGRESS, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[egress-pip] python spawn rc=%d · ABORT\n", rc); return; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());   /* run pip to completion */
    g_validate_used[0] = false;
    g_egress_trusted_active = 0;
    printf("[egress-pip] handler DONE alive=%d\n", sotbox_alive_count());
}

/* ------------------------------------------------------------------ */
/* Python real END-TO-END · network + parse + filesystem + crypto.    */
/* ------------------------------------------------------------------ */
/* A real CPython program (not a demo) that chains the whole stack: a verified
 * HTTPS GET of example.com → extract the <title> → write the HTML + a JSON
 * sidecar (title/bytes/sha256) to /tmp/e2e → read both back → verify the sha256
 * round-trips byte-for-byte.  socket/ssl/json/hashlib/os, all stdlib. */
static lucas_state_t s_py_e2e_st;
static void orch_handle_py_e2e(void)
{
    printf("[py-e2e] handler START\n");
    g_egress_trusted_active = 1;   /* trusted egress · suppress anomaly EP (anti-deadlock) */
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("python3.12-static", &elf, &sz, &src) != 0) {
        printf("[py-e2e] python3.12-static not found · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));   /* unblock sotShell · run below */
    if (g_validate_used[0]) { printf("[py-e2e] pool slot 0 busy · ABORT\n"); return; }

    static const char *const PYARGV[] = {
        "python3", "-c",
        "import socket,ssl,json,hashlib,os\n"
        "h='example.com'\n"
        "c=ssl.create_default_context()\n"
        "s=c.wrap_socket(socket.create_connection((h,443),timeout=30),server_hostname=h)\n"
        "s.sendall(b'GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n')\n"
        "d=b''\n"
        "while True:\n"
        " b=s.recv(4096)\n"
        " if not b: break\n"
        " d+=b\n"
        "body=d.split(b'\\r\\n\\r\\n',1)[1]\n"
        "title=body.split(b'<title>')[1].split(b'</title>')[0].decode().strip()\n"
        "os.makedirs('/tmp/e2e',exist_ok=True)\n"
        "open('/tmp/e2e/page.html','wb').write(body)\n"
        "meta={'title':title,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}\n"
        "open('/tmp/e2e/meta.json','w').write(json.dumps(meta))\n"
        "m2=json.load(open('/tmp/e2e/meta.json'))\n"
        "back=open('/tmp/e2e/page.html','rb').read()\n"
        "ok=hashlib.sha256(back).hexdigest()==m2['sha256']\n"
        "print('PY_E2E_OK title=%r bytes=%d sha=%s roundtrip=%s'%(m2['title'],m2['bytes'],m2['sha256'][:12],ok))\n",
        NULL };
    printf("[py-e2e] === Tier-0e python: HTTPS GET → parse → write fs → read back → verify sha256 ===\n");
    memset(&s_py_e2e_st, 0, sizeof(s_py_e2e_st));
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    sotbox_spawn_set_envp_next(EGRESS_PY_ENVP);
    int rc = sotbox_spawn_into(&s_py_e2e_st, elf, sz, PYARGV,
                               /*tier=*/FUNCTOR_TIER_EGRESS, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[py-e2e] python spawn rc=%d · ABORT\n", rc); return; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());
    g_validate_used[0] = false;
    g_egress_trusted_active = 0;
    printf("[py-e2e] handler DONE alive=%d\n", sotbox_alive_count());
}

/* ------------------------------------------------------------------ */
/* Egress · pip install WITH DEPENDENCIES (requests + 4 deps).         */
/* ------------------------------------------------------------------ */
/* The dependency-resolver case: `pip install requests` resolves requests + its
 * 4 deps (urllib3/certifi/idna/charset-normalizer) with version constraints on
 * pypi.org/simple, downloads all 5 wheels from files.pythonhosted.org over the
 * verified egress, installs them into the writable /tmp/sp, and imports the whole
 * tree.  Many sequential HTTPS connections (5 metadata + 5 wheels) over the
 * spin-pump egress → a generous gate window.  Heavy arena auto-routed · reclaim
 * carries the resolver churn · dir-fd VFS enables the multi-wheel extract. */
static lucas_state_t s_egress_pipdeps_st;
static void orch_handle_egress_pipdeps(void)
{
    printf("[egress-pipdeps] handler START\n");
    g_egress_trusted_active = 1;   /* trusted egress · suppress anomaly EP (anti-deadlock) */
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("python3.12-static", &elf, &sz, &src) != 0) {
        printf("[egress-pipdeps] python3.12-static not found · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));   /* unblock sotShell · run below */
    if (g_validate_used[0]) { printf("[egress-pipdeps] pool slot 0 busy · ABORT\n"); return; }

    static const char *const PYARGV[] = {
        "python3", "-c",
        "import sys\n"
        "from pip._internal.cli.main import main as pip\n"
        "def run(a):\n"
        " try: return pip(a)\n"
        " except SystemExit as e: return 0 if e.code is None else e.code\n"
        "rc=run(['install','--no-cache-dir','--disable-pip-version-check',"
        "'--no-input','--target','/tmp/sp','requests'])\n"
        "print('PIPDEPS_INSTALL_RC', rc)\n"
        "sys.path.insert(0,'/tmp/sp')\n"
        "import requests, urllib3, certifi, idna, charset_normalizer\n"
        "print('PIPDEPS_OK requests', requests.__version__, 'urllib3', urllib3.__version__,"
        "'idna', idna.__version__, 'cn', charset_normalizer.__version__)\n",
        NULL };
    printf("[egress-pipdeps] === Tier-0e python -m pip install requests (5-package dep tree) ===\n");
    memset(&s_egress_pipdeps_st, 0, sizeof(s_egress_pipdeps_st));
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    sotbox_spawn_set_envp_next(EGRESS_PY_ENVP);
    int rc = sotbox_spawn_into(&s_egress_pipdeps_st, elf, sz, PYARGV,
                               /*tier=*/FUNCTOR_TIER_EGRESS, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[egress-pipdeps] python spawn rc=%d · ABORT\n", rc); return; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());   /* run resolve+download+install to completion */
    g_validate_used[0] = false;
    g_egress_trusted_active = 0;
    printf("[egress-pipdeps] handler DONE alive=%d\n", sotbox_alive_count());
}

/* ------------------------------------------------------------------ */
/* Egress · pip BUILD from sdist · build a wheel in-process.           */
/* ------------------------------------------------------------------ */
/* The hardest pip case: install a package that has NO wheel, so it must be BUILT
 * from a source dist.  pip-the-tool builds via a SUBPROCESS (`python setup.py
 * bdist_wheel`), which can't run here — a fork-child execve(python) can't swap
 * into the heavy arena CPython needs (the canary launcher spawns a fresh box +
 * exits, with no pipe back to pip).  So we drive the build OURSELVES, in the ONE
 * python process: download the sdist over the verified egress, then call the REAL
 * setuptools/wheel build backend IN-PROCESS (setuptools.build_meta.build_wheel —
 * egg-info + bdist_wheel, the exact code pip's subprocess would run), install the
 * built wheel into the writable /tmp/sp, and import it.  setuptools+wheel (the
 * build deps) ride in the stdlib zip.  Mirrors how the in-process download+extract
 * sidestepped the dpkg→xz→tar pipe chain. */
static lucas_state_t s_egress_pipbuild_st;
static void orch_handle_egress_pip_build(void)
{
    printf("[egress-pipbuild] handler START\n");
    g_egress_trusted_active = 1;   /* trusted egress · suppress anomaly EP (anti-deadlock) */
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("python3.12-static", &elf, &sz, &src) != 0) {
        printf("[egress-pipbuild] python3.12-static not found · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));   /* unblock sotShell · run below */
    if (g_validate_used[0]) { printf("[egress-pipbuild] pool slot 0 busy · ABORT\n"); return; }

    static const char *const PYARGV[] = {
        "python3", "-c",
        "import socket,ssl,io,tarfile,os,sys,zipfile\n"
        "h='files.pythonhosted.org'\n"
        "p='/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz'\n"
        "c=ssl.create_default_context()\n"
        "s=c.wrap_socket(socket.create_connection((h,443),timeout=60),server_hostname=h)\n"
        "s.sendall(('GET %s HTTP/1.0\\r\\nHost: %s\\r\\nUser-Agent: sotos\\r\\n\\r\\n'%(p,h)).encode())\n"
        "buf=b''\n"
        "while b'\\r\\n\\r\\n' not in buf:\n"
        " buf+=s.recv(4096)\n"
        "head,body=buf.split(b'\\r\\n\\r\\n',1)\n"
        "clen=0\n"
        "for L in head.split(b'\\r\\n'):\n"
        " if L.lower().startswith(b'content-length:'): clen=int(L.split(b':',1)[1])\n"
        "while len(body)<clen:\n"
        " d=s.recv(65536)\n"
        " if not d: break\n"
        " body+=d\n"
        "print('PIPBUILD download',len(body),'of',clen,'bytes verified TLS')\n"
        "import importlib\n"
        "tarfile.open(fileobj=io.BytesIO(body)).extractall('/tmp')\n"
        "os.makedirs('/tmp/wheels',exist_ok=True)\n"
        /* In-VM, importlib.metadata can't enumerate setuptools' entry points from
         * the VFS-mounted stdlib zip, so setuptools' command overrides are not
         * discovered → build commands that ALSO exist in distutils (install_egg_info
         * …) resolve to the DISTUTILS version (writes the egg-info as a FILE), which
         * bdist_wheel then opens as a DIRECTORY → ENOTDIR.  Force the setuptools
         * command class (its proper directory-style install_egg_info etc.) for any
         * command setuptools provides; honour explicit cmdclass first. */
        /* Two in-VM build fixes (importlib.metadata can't enumerate setuptools'
         * entry points from the VFS-mounted stdlib zip, so command resolution is
         * degraded · both validated to be harmless on a normal host build):
         *  (1) get_command_class fallback · setuptools-only commands (egg_info …)
         *      aren't in distutils → resolution raises 'invalid command' → import
         *      setuptools.command.<name> directly.
         *  (2) distutils' install_egg_info writes the egg-info as a FILE; bdist_wheel
         *      then opens it as a DIRECTORY → ENOTDIR.  Patch its run() to COPY the
         *      egg-info DIR (setuptools' behaviour), stdlib-only (no setuptools dep). */
        "import setuptools.dist as sd, glob\n"
        "_o=sd.Distribution.get_command_class\n"
        "def _fb(self,c):\n"
        " try: return _o(self,c)\n"
        " except Exception:\n"
        "  m=importlib.import_module('setuptools.command.'+c); k=getattr(m,c)\n"
        "  self.cmdclass[c]=k; return k\n"
        "sd.Distribution.get_command_class=_fb\n"
        "def _cptree(s,d):\n"
        " os.makedirs(d,exist_ok=True)\n"
        " for n in os.listdir(s):\n"
        "  sp=os.path.join(s,n); dp=os.path.join(d,n)\n"
        "  if os.path.isdir(sp): _cptree(sp,dp)\n"
        "  else:\n"
        "   f=open(sp,'rb'); b=f.read(); f.close()\n"
        "   g=open(dp,'wb'); g.write(b); g.close()\n"
        "import distutils.command.install_egg_info as diei\n"
        "def _ieirun(self):\n"
        " self.run_command('egg_info')\n"
        " src=None\n"
        " for d in glob.glob(os.path.join(os.getcwd(),'*.egg-info')):\n"
        "  if os.path.isdir(d): src=d; break\n"
        " if not src: return\n"
        " tgt=getattr(self,'target',None) or os.path.join(self.install_dir,os.path.basename(src))\n"
        " _cptree(src,tgt); self.outputs=[tgt]\n"
        "diei.install_egg_info.run=_ieirun\n"
        "os.chdir('/tmp/six-1.16.0')\n"
        "sys.path.insert(0,os.getcwd())\n"
        "import setuptools.build_meta as bm\n"
        "name=bm.build_wheel('/tmp/wheels')\n"
        "print('PIPBUILD built wheel',name)\n"
        "zipfile.ZipFile('/tmp/wheels/'+name).extractall('/tmp/sp')\n"
        "sys.path=[x for x in sys.path if x!='/tmp/six-1.16.0']\n"
        "sys.path.insert(0,'/tmp/sp')\n"
        "import six\n"
        "print('PIPBUILD_OK',six.__version__,six.__file__)\n",
        NULL };
    printf("[egress-pipbuild] === Tier-0e python: download sdist + setuptools build_wheel IN-PROCESS ===\n");
    memset(&s_egress_pipbuild_st, 0, sizeof(s_egress_pipbuild_st));
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    sotbox_spawn_set_envp_next(EGRESS_PY_ENVP);
    int rc = sotbox_spawn_into(&s_egress_pipbuild_st, elf, sz, PYARGV,
                               /*tier=*/FUNCTOR_TIER_EGRESS, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) { printf("[egress-pipbuild] python spawn rc=%d · ABORT\n", rc); return; }
    g_validate_used[0] = true;
    orch_fault_loop(orch_get_fault_ep());   /* run download+build+install to completion */
    g_validate_used[0] = false;
    g_egress_trusted_active = 0;
    printf("[egress-pipbuild] handler DONE alive=%d\n", sotbox_alive_count());
}

/* v2.3-M5 · Doom over REAL Wayland (wl_shm, NO EGL).  Mirrors orch_handle_doom
 * but spawns doomwl.bin — the doomgeneric engine over the patched DYNAMIC SDL2
 * (SDL_VIDEODRIVER=wayland + SDL_FRAMEBUFFER_ACCELERATION=0 → the SOFTWARE
 * renderer's window framebuffer is a wl_shm pool/buffer on the honest
 * compositor, via patches/sdl2/0002).  Tier-0 trusted so it can mmap the engine
 * zone + isn't silenced-suppressed; ONE fault loop services it (alongside the
 * compositor, a separate process) until it exits.  The compositor logs genuine
 * 640x400 Doom commits over wl_shm (distinct fnv1a per frame = a moving demo).
 * No /dev/fb0 here — the wl_shm commit IS the present. */
static void orch_handle_doomwl(void)
{
    printf("[doom-wl] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("doomwl.bin", &elf, &sz, &src) != 0) {
        printf("[doom-wl] doomwl.bin not found in binstore/sotfs/CPIO · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[doom-wl] doomwl.bin found via %s · %lu bytes\n", src, sz);

    int p = 0;                       /* same pool slot as doom (never concurrent) */
    if (g_validate_used[p]) {
        printf("[doom-wl] pool slot 0 busy · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }

    const char *argv[] = { "doom", "-iwad", "/doom1.wad", NULL };
    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);                 /* Tier-0: pass-through, not silenced-suppressed */

    extern void sotbox_arena_trace(int on);
    sotbox_arena_trace(0);
    int rc = sotbox_spawn_into(&g_validate_st[p], elf, sz, argv,
                               /*initial_tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) {
        printf("[doom-wl] sotbox_spawn_into rc=%d · ABORT\n", rc);
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    g_validate_used[p] = true;
    printf("[doom-wl] spawned doomwl.bin · slot=%d pid=%d\n",
           g_validate_st[p].slot_index, g_validate_st[p].synthetic_pid);

    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));

    orch_fault_loop(orch_get_fault_ep());
    printf("[doom-wl] handler DONE alive=%d\n", sotbox_alive_count());

    g_validate_used[p] = false;
}

/* v2.4 · GTK3 over REAL Wayland (cairo software / wl_shm) spike.  Mirrors
 * orch_handle_doomwl — spawns gtkspike.bin (a real GTK3 app; its 57-lib closure
 * + runtime data live in the sysroot /usr/lib + /usr/share).  Tier-0 trusted,
 * one fault loop until it exits.  This is exploratory (a spike): it surfaces the
 * first wall GTK hits on a desktop-less seL4 host. */
static void orch_handle_gtkspike(void)
{
    printf("[gtk-wl] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("gtkspike.bin", &elf, &sz, &src) != 0) {
        printf("[gtk-wl] gtkspike.bin not found in binstore/sotfs/CPIO · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[gtk-wl] gtkspike.bin found via %s · %lu bytes\n", src, sz);

    int p = 0;
    if (g_validate_used[p]) {
        printf("[gtk-wl] pool slot 0 busy · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }

    const char *argv[] = { "gtkspike", NULL };
    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);

    extern void sotbox_arena_trace(int on);
    extern void sotbox_request_heavy_next(void);
    sotbox_arena_trace(0);
    sotbox_request_heavy_next();   /* GTK's 57-lib closure + heap needs the 64 MiB arena */
    int rc = sotbox_spawn_into(&g_validate_st[p], elf, sz, argv,
                               /*initial_tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) {
        printf("[gtk-wl] sotbox_spawn_into rc=%d · ABORT\n", rc);
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    g_validate_used[p] = true;
    printf("[gtk-wl] spawned gtkspike.bin · slot=%d pid=%d\n",
           g_validate_st[p].slot_index, g_validate_st[p].synthetic_pid);

    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));

    orch_fault_loop(orch_get_fault_ep());
    printf("[gtk-wl] handler DONE alive=%d\n", sotbox_alive_count());

    g_validate_used[p] = false;
}

/* v2.x · run the UNMODIFIED off-the-shelf gtk3-demo (Alpine gtk+3.0-demo) over
 * the honest compositor — the "real Linux app, no per-app code" proof.  Mirrors
 * orch_handle_gtkspike, but gtk3-demo does NOT self-setenv, so the launcher
 * supplies the full GTK environment (our fixtures set it in their own main). */
static void orch_handle_gtk3demo(void)
{
    printf("[gtk3-demo] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("gtk3-demo.bin", &elf, &sz, &src) != 0) {
        printf("[gtk3-demo] gtk3-demo.bin not found in binstore/sotfs/CPIO · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[gtk3-demo] gtk3-demo.bin found via %s · %lu bytes\n", src, sz);

    int p = 0;
    if (g_validate_used[p]) {
        printf("[gtk3-demo] pool slot 0 busy · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }

    const char *argv[] = { "gtk3-demo", NULL };
    /* launcher-provided Linux env — gtk3-demo (unmodified) does not self-setenv
     * the way gtkspike does; the loader must give it a real desktop-less env. */
    static const char *gtk_envp[] = {
        "XDG_RUNTIME_DIR=/run/user/1000",
        "WAYLAND_DISPLAY=wayland-0",
        "GDK_BACKEND=wayland",
        "GSETTINGS_BACKEND=memory",
        "NO_AT_BRIDGE=1",
        "XDG_DATA_DIRS=/usr/share",
        "FONTCONFIG_FILE=/usr/share/fontconfig/fonts.conf",
        "GDK_PIXBUF_MODULE_FILE=/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache",
        "XCURSOR_PATH=/usr/share/icons",
        "XCURSOR_THEME=Adwaita",
        "HOME=/root",
        "PATH=/usr/bin",
        NULL
    };
    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);

    extern void sotbox_arena_trace(int on);
    extern void sotbox_request_heavy_next(void);
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    sotbox_arena_trace(0);
    sotbox_request_heavy_next();   /* GTK's closure + heap needs the heavy arena */
    sotbox_spawn_set_envp_next(gtk_envp);
    int rc = sotbox_spawn_into(&g_validate_st[p], elf, sz, argv,
                               /*initial_tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) {
        printf("[gtk3-demo] sotbox_spawn_into rc=%d · ABORT\n", rc);
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    g_validate_used[p] = true;
    printf("[gtk3-demo] spawned gtk3-demo.bin · slot=%d pid=%d\n",
           g_validate_st[p].slot_index, g_validate_st[p].synthetic_pid);

    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));

    orch_fault_loop(orch_get_fault_ep());
    printf("[gtk3-demo] handler DONE alive=%d\n", sotbox_alive_count());

    g_validate_used[p] = false;
}

/* GTK fidelity (#2 · broader-apps) · run the UNMODIFIED off-the-shelf Alpine
 * gtk3-widget-factory — the canonical GTK widget showcase (every GTK3 widget:
 * buttons/switches/sliders/GtkTreeView/GtkNotebook/dialogs/spinners).  Identical
 * launcher contract + GTK env as gtk3-demo (it also does NOT self-setenv); proves
 * the FULL widget set rasterizes over wl_shm, not just the demo-browser window. */
static void orch_handle_widgetfactory(void)
{
    printf("[widget-factory] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("widget-factory.bin", &elf, &sz, &src) != 0) {
        printf("[widget-factory] widget-factory.bin not found in binstore/sotfs/CPIO · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[widget-factory] widget-factory.bin found via %s · %lu bytes\n", src, sz);

    int p = 0;
    if (g_validate_used[p]) {
        printf("[widget-factory] pool slot 0 busy · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }

    const char *argv[] = { "gtk3-widget-factory", NULL };
    /* launcher-provided Linux env — identical to gtk3-demo (the widget-factory is
     * unmodified and does not self-setenv); the loader supplies the desktop-less env. */
    static const char *gtk_envp[] = {
        "XDG_RUNTIME_DIR=/run/user/1000",
        "WAYLAND_DISPLAY=wayland-0",
        "GDK_BACKEND=wayland",
        "GSETTINGS_BACKEND=memory",
        "NO_AT_BRIDGE=1",
        "XDG_DATA_DIRS=/usr/share",
        "FONTCONFIG_FILE=/usr/share/fontconfig/fonts.conf",
        "GDK_PIXBUF_MODULE_FILE=/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache",
        "XCURSOR_PATH=/usr/share/icons",
        "XCURSOR_THEME=Adwaita",
        "HOME=/root",
        "PATH=/usr/bin",
        NULL
    };
    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);

    extern void sotbox_arena_trace(int on);
    extern void sotbox_request_heavy_next(void);
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    sotbox_arena_trace(0);
    sotbox_request_heavy_next();   /* GTK's closure + heap needs the heavy arena */
    sotbox_spawn_set_envp_next(gtk_envp);
    int rc = sotbox_spawn_into(&g_validate_st[p], elf, sz, argv,
                               /*initial_tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) {
        printf("[widget-factory] sotbox_spawn_into rc=%d · ABORT\n", rc);
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    g_validate_used[p] = true;
    printf("[widget-factory] spawned widget-factory.bin · slot=%d pid=%d\n",
           g_validate_st[p].slot_index, g_validate_st[p].synthetic_pid);

    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));

    /* widget-factory is an UNMODIFIED forever-running GUI app — like gtk3-demo it
     * renders its window then blocks on the wl_display fd.  It is the TERMINAL GUI
     * app of the auto-demo (the last wl client), so the fault loop runs unbounded
     * until the boot ends — exactly the proven gtk3-demo-as-terminal pattern. */
    orch_fault_loop(orch_get_fault_ep());
    printf("[widget-factory] handler DONE alive=%d\n", sotbox_alive_count());

    g_validate_used[p] = false;
}

/* Wine-prep · run mapfixed.bin — the wine-preloader mmap PATTERN (reserve large
 * PROT_NONE Windows ranges, commit sub-ranges via MAP_FIXED + mprotect).  A
 * static Tier-0 fixture; same orch contract as gtkspike (reply after spawn, run
 * the fault loop until it exits).  Proves LUCAS honors fixed low-address
 * reservations — the de-risk step before the Wine loader/wineserver swamp. */
static void orch_handle_mapfixed(void)
{
    printf("[mapfixed] handler START\n");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("mapfixed.bin", &elf, &sz, &src) != 0) {
        printf("[mapfixed] mapfixed.bin not found in binstore/sotfs/CPIO · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[mapfixed] mapfixed.bin found via %s · %lu bytes\n", src, sz);

    int p = 0;
    if (g_validate_used[p]) {
        printf("[mapfixed] pool slot 0 busy · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }

    const char *argv[] = { "mapfixed", NULL };
    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);

    extern void sotbox_arena_trace(int on);
    sotbox_arena_trace(0);
    int rc = sotbox_spawn_into(&g_validate_st[p], elf, sz, argv,
                               /*initial_tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) {
        printf("[mapfixed] sotbox_spawn_into rc=%d · ABORT\n", rc);
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    g_validate_used[p] = true;
    printf("[mapfixed] spawned mapfixed.bin · slot=%d pid=%d\n",
           g_validate_st[p].slot_index, g_validate_st[p].synthetic_pid);

    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));

    orch_fault_loop(orch_get_fault_ep());
    printf("[mapfixed] handler DONE alive=%d\n", sotbox_alive_count());

    g_validate_used[p] = false;
}

/* Wine M1 SPIKE · spawn the `wine` loader on a trivial console PE.  `wine` is a
 * dynamic Alpine-musl ELF (interp ld-musl · NEEDED libc.musl) that dlopens
 * ntdll.so (the unix bootstrap) from WINEDLLPATH and calls __wine_main; the PE
 * loader then runs the low-range reservations MAP_FIXED-low now supports.
 * Exploratory — reports the next wall.  Heavy arena (Wine's RSS) + full env. */
int g_wine_pe = 0;   /* Wine PE selector · 0=M1 CRT-less · 1=M2 real-CRT · 2=GUI */
static void orch_handle_wine(int baked)
{
    printf("[wine] handler START%s\n", baked ? " · BAKED PREFIX MODE (Track M1 · PE execution · wineboot SKIPPED)" : "");
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    if (spawn_load_elf("wine", &elf, &sz, &src) != 0) {
        printf("[wine] `wine` loader not found in binstore · run tools/wine-stage.sh + rebuild · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    printf("[wine] wine loader found via %s · %lu bytes\n", src, sz);

    int p = 0;
    if (g_validate_used[p]) {
        printf("[wine] pool slot 0 busy · ABORT\n");
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }

    /* Run the test PE from the x86_64-windows arch dir so its app-dir (the first
     * entry of wine's DLL search path) is /usr/lib/wine/x86_64-windows — beside the
     * builtin kernel32/kernelbase/etc., which the launcher then resolves on the
     * first probe (no WINEBOOTSTRAPMODE needed; the arch-subdir append is gated). */
    /* g_wine_pe selects the main PE: 0=M1 CRT-less, 1=M2 real-CRT (msvcrt
     * printf/malloc), 2=GUI (Win32 window → user32/gdi32 → winewayland).  Same
     * launcher/wineboot path; the PE (and, for GUI, the display env) differ. */
    extern int g_wine_pe;
    const char *pe = g_wine_pe == 2 ? "/usr/lib/wine/x86_64-windows/hello_gui.exe"
                   : g_wine_pe == 1 ? "/usr/lib/wine/x86_64-windows/hello_crt.exe"
                                    : "/usr/lib/wine/x86_64-windows/hello.exe";
    const char *argv[] = { "/usr/bin/wine", pe, NULL };
    /* Wine env · console PE, no GUI surface (DISPLAY empty), winewayland deferred.
     * argv[0]=/usr/bin/wine → /proc/self/exe → wine's bindir=/usr/bin → its dll
     * dir <bindir>/../lib/wine = /usr/lib/wine (ntdll.so lives there).  The VFS
     * aliases /usr/bin/wine[-preloader] to the /usr/lib/wine copies the preloader
     * open()s.  WINEDLLPATH points at the unix .so set + the PE dlls. */
    static const char *wine_envp[] = {
        "WINELOADER=/usr/bin/wine",
        "WINEDLLPATH=/usr/lib/wine/x86_64-unix:/usr/lib/wine/x86_64-windows",
        /* Wine M1 · WINEPREFIX=/tmp/.wine.  The writable sotfs backend is mounted
         * at the VFS prefix "/tmp" (strip_tmp_prefix in backends_sotfs.c), so the
         * g_sotfs root maps to /tmp.  lucas_seed_baked_wineprefix() seeds into the
         * g_sotfs root as ".wine" → reachable here at /tmp/.wine.  (A bare /.wine
         * resolves to the READ-ONLY static sysroot mount → chdir ENOENT → wine
         * exits code=1 · run29.)  /tmp/.wine is writable; wine's ownership check
         * (stat st_uid==euid) passes via the wine sotbox's root identity
         * (getuid()=0, wine-gated in handlers_proc.c). */
        "WINEPREFIX=/tmp/.wine",
        /* Wine M1 · Phase 5k diagnosis · warn+heap exposes allocate_region's
         * "Could not allocate %Ix bytes, status %lx" WARN (off by default) so we
         * see WHY the spawned wineboot's RtlCreateHeap(process heap) returns NULL
         * — the NtAllocateVirtualMemory(MEM_RESERVE) status. warn+virtual surfaces
         * the unix-side address-space reason.  (Confirmed: imports_fixup_done==0 →
         * loader_init runs the first-time block → RtlCreateHeap @ntdll+0x355b7
         * returns NULL → init_user_process_params @+0x235c0 faults on GetProcessHeap()=NULL.) */
        "WINEDEBUG=+loaddll,+module,+seh,+server",
        "HOME=/root",
        "PATH=/usr/bin",
        "DISPLAY=",
        /* Wine GUI · winewayland connects to our honest compositor at
         * $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY (the GTK/SDL/Doom path).  With DISPLAY
         * empty + WAYLAND set, wine selects the wayland driver.  Loaded LAZILY on
         * the first USER32 call, so console PEs (M1/M2) ignore these. */
        "XDG_RUNTIME_DIR=/run/user/1000",
        "WAYLAND_DISPLAY=wayland-0",
        /* C.UTF-8 so wine's init_unix_codepage resolves a UTF-8 codepage instead
         * of the unrecognized 'ASCII' that bare LANG=C yields. */
        "LANG=C.UTF-8",
        NULL
    };
    vfs_set_profile(LUCAS_PROFILE_ALPINE);
    vfs_set_tier(0);

    extern void sotbox_arena_trace(int on);
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    sotbox_arena_trace(0);
    /* CAPACITY · do NOT route the LAUNCHER (pid=1) to the heavy arena. The wine
     * loader is lightweight (~574 cslots) and fits a regular arena; the real
     * heavy consumer is the spawned wineboot (8 builtin DLLs + heaps + locale.nls
     * + 3.4 MiB sortdefault.nls), which is born via the new_process → fork path.
     * Heavy is now routed to that wineboot fork-child in sotbox_fork/sotbox_vfork
     * (wine-gated, deepest child only) so it lands where the footprint actually is.
     * (Previously: sotbox_request_heavy_next() here pinned the single heavy arena
     * on the launcher for the whole run, starving the wineboot on regular/8192.) */
    /* Track M1 · seed the pre-baked, version-matched wine prefix into /.wine so
     * wine treats the prefix as initialized and skips the (still-incomplete)
     * in-guest wineboot bootstrap.  Explicit + logged · the prefix is pre-baked,
     * NOT booted (real wineboot is Track correctness · Wine M2a). */
    if (baked) {
        extern int lucas_seed_baked_wineprefix(void);
        int src = lucas_seed_baked_wineprefix();
        printf("[wine] baked-prefix seed rc=%d · %s\n", src,
               src == 0 ? "wine will load /.wine and SKIP wineboot"
                        : "seed FAILED · wine falls back to wineboot");
    }
    /* Wine M2 · the CRT PE just needs to RUN (msvcrt init is proven), so quiet
     * the verbose +loaddll/+module/+seh/+server tracing (≈10× slowdown · 114k
     * serial lines before main()) down to fixme-only — reaches main() fast. */
    if (g_wine_pe != 0) wine_envp[3] = "WINEDEBUG=fixme-all";  /* CRT/GUI just need to RUN */
    /* Wine GUI memory budget · FOLLOW-UP.  The GUI launcher (pid=1) loads the whole
     * GUI stack (user32/gdi32/win32u + winewayland.so + heaps) and OOMs a regular
     * arena ('Out of memory' in win32u map_view).  Routing it to the heavy arena
     * clears that, but then services.exe + the wineserver subtree starve and orch
     * itself exhausts its untyped (root-server abort).  The GUI multi-process
     * closure needs a real memory-budget pass (VM RAM + orch untyped pool + a
     * per-process heavy strategy) — the documented "swamp".  Left on the regular
     * arena for now (a clean wine-level OOM · no host crash). */
    sotbox_spawn_set_envp_next(wine_envp);
    int rc = sotbox_spawn_into(&g_validate_st[p], elf, sz, argv,
                               /*initial_tier=*/0, /*pledge=*/0, /*trusted=*/true);
    if (rc != 0) {
        printf("[wine] sotbox_spawn_into rc=%d · ABORT\n", rc);
        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
        return;
    }
    g_validate_used[p] = true;
    printf("[wine] spawned wine loader · slot=%d pid=%d · argv=[wine /usr/lib/wine/hello.exe] · prefix=%s\n",
           g_validate_st[p].slot_index, g_validate_st[p].synthetic_pid,
           baked ? "PRE-BAKED (wineboot skipped · Track M1)" : "fresh (real wineboot path)");

    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));

    orch_fault_loop(orch_get_fault_ep());
    printf("[wine] handler DONE alive=%d\n", sotbox_alive_count());

    g_validate_used[p] = false;
}

/* SSH canary shell (Phase B) · spawn a real `busybox sh -i` at Tier-2 bound to
 * the SHELL_IN/SHELL_OUT rings + run a nested fault loop until busybox exits.
 *
 * Mirrors orch_handle_validate / the bbsh handler.  Called by the op/shell-window
 * loops AFTER their orch_bytepipe_drain_in_p2c() returns (the SHELL_START frame
 * handler only stashes g_ssh_shell_pending · per critic-revision R1) so the
 * nested orch_fault_loop here is the SOLE in_p2c drainer while it runs — no
 * re-entrant g_in_p2c_rd corruption.  At most one concurrent shell (R2). */
/* SSH canary shell (Phase B) · orch is the SHELL_OUT producer (busybox stdout)
 * and the SHELL_IN consumer (the consumer cursor lives on the SSH-shell sotbox
 * state · g_ssh_shell_st.shell_in_rd · per critic-revision R0).  Defined here
 * (above the users) so orch_ssh_shell_run can gate on it (R7). */
static int           g_bytepipe3_ready = 0;
static lucas_state_t g_ssh_shell_st;
bool                 g_ssh_shell_active = false;   /* non-static: orch_fault_loop gates its
                                                    * operator shell_ep poll on a live session */
static uint16_t      g_ssh_shell_conn   = 0;   /* conn_id of the live SSH shell (0 = none) */
/* Override sotnet's weak tcp_conn_protected: the δ idle-reaper (tcp_timer.c) must NOT
 * free the live interactive SSH shell conn — it is legitimately long-lived and idle
 * between keystrokes (no TX), unlike a stuck/abandoned deception conn. */
int tcp_conn_protected(uint16_t conn_id) { return conn_id != 0 && conn_id == g_ssh_shell_conn; }
/* R1 · SHELL_START stashes the conn_id here; the op/shell-window loops hoist
 * the actual spawn OUT of the drain to avoid re-entering orch_fault_loop. */
static uint16_t      g_ssh_shell_pending = 0;
/* exec-mode · the command carried in the SHELL_START payload (`ssh host 'cmd'`); empty
 * for an interactive shell.  orch_ssh_shell_run spawns `bash -c <cmd>` when set so the
 * output is clean (no prompt) and the channel closes when the command exits. */
static char          g_ssh_exec_cmd[256];
static uint16_t      g_ssh_exec_len = 0;
/* apk-fs T6 · SHELL_IN ring->w snapshotted at SHELL_START receipt time.
 * SSH guarantees that CHANNEL_DATA (attacker keystrokes) can only arrive AFTER
 * the shell request that triggers SHELL_START, so this snapshot is always ≤ the
 * ring position of the first real keystroke.  Used as shell_in_rd at spawn so
 * bash sees ALL the keystrokes the attacker typed — even those that arrived in
 * the time between SHELL_START and bash actually starting. */
static uint32_t      g_ssh_shell_pending_ring_rd = 0;
/* B5 · pty-req winsize stashed before busybox spawns: OpenSSH sends pty-req
 * (→ SHELL_WINCH) BEFORE the shell request (→ SHELL_START), so the WINCH
 * arrives while g_ssh_shell_active is still false.  Stash the latest size here
 * and apply it at spawn so the TUI opens at the client's real size, not 80x24
 * (an 80x24 box on a non-80x24 client is a honeypot tell). Reset on teardown. */
static uint16_t      g_ssh_shell_pending_cols = 0;
static uint16_t      g_ssh_shell_pending_rows = 0;

void orch_ssh_shell_run(uint16_t conn_id)
{
    if (!g_bytepipe3_ready) return;            /* R7 · no-op if the shell rings didn't map */
    if (g_ssh_shell_active) {                  /* R2 · single concurrent shell */
        printf("[orch] ssh-shell: already active · refusing conn=%u\n", conn_id);
        return;
    }
    /* 2nd-persona arc · round-robin persona selection: alternate Alpine / Debian
     * per SSH session so consecutive sessions wear DIFFERENT coherent personas —
     * proving the M3 per-session seam serves distinct stories, not a global skin.
     * Counter 0 (the FIRST session after boot) = Alpine, so single-session gates
     * stay Alpine-deterministic; the 2nd session gets Debian. */
    /* `sotctl persona set <name>` can PIN the selection (g_persona_pin: -1 =
     * round-robin · 0 = alpine · 1 = debian).  Default round-robin; counter 0 (the
     * first session after boot) = Alpine so single-session gates stay determinate. */
    extern int orch_persona_pin_get(void);
    static unsigned g_persona_rr = 0;
    int pin = orch_persona_pin_get();
    uint8_t persona_profile = (pin >= 0) ? (uint8_t)pin
                                         : (uint8_t)(g_persona_rr++ % 2);
    int want_debian = (persona_profile == LUCAS_PERSONA_DEBIAN);
    lucas_persona_t sess_persona;
    lucas_persona_for_profile(persona_profile, &sess_persona);

    /* The interactive honey shell is a REAL bash for the chosen persona:
     *  • Alpine → alpine-bash (musl · ld-musl + libreadline/libncursesw from the
     *    sysroot /usr/lib) · a musl box has NO glibc multiarch, which we hide.
     *  • Debian → debian-bash (glibc · ld-linux + /lib/x86_64-linux-gnu, which
     *    stays VISIBLE for this persona — it is the Debian glibc norm).
     * Falls back to busybox sh -i if the persona's bash is absent. */
    const void *elf = NULL; unsigned long sz = 0; const char *src = "?";
    int use_bash = want_debian
        ? (spawn_load_elf("debian-bash", &elf, &sz, &src) == 0)
        : (spawn_load_elf("alpine-bash", &elf, &sz, &src) == 0);
    if (!use_bash &&
        spawn_load_elf("busybox-static.bin", &elf, &sz, &src) != 0 &&
        spawn_load_elf("busybox", &elf, &sz, &src) != 0) {
        printf("[orch] ssh-shell: no shell binary for persona %u found\n", persona_profile);
        return;
    }
    printf("[orch] ssh-shell: persona=%s (%s · %s)\n",
           sess_persona.name, want_debian ? "debian/glibc" : "alpine/musl", src);
    const char *bash_argv[] = { "bash", "-i", NULL };
    const char *bb_argv[]   = { "busybox", "sh", "-i", NULL };
    /* exec-mode (`ssh host 'cmd'`): run the command non-interactively and let it exit
     * (→ SHELL_EOF → CHANNEL_CLOSE) instead of an interactive bash -i.  The output is
     * then clean (no prompt/MOTD) and matches a real sshd — what the recon eval compares. */
    const char *bash_exec[] = { "bash", "-c", g_ssh_exec_cmd, NULL };
    const char *bb_exec[]   = { "busybox", "sh", "-c", g_ssh_exec_cmd, NULL };
    const char *const *argv;
    if (g_ssh_exec_len > 0) argv = use_bash ? bash_exec : bb_exec;
    else                    argv = use_bash ? bash_argv : bb_argv;
    /* Interactive env so bash finds commands (PATH), $HOME/$USER, and a real TERM
     * (readline + colors).  Applied to the next spawn only. */
    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
    static const char *const SSH_BASH_ENVP[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root", "USER=root", "LOGNAME=root", "SHELL=/bin/bash",
        "TERM=xterm-256color", NULL };
    vfs_set_profile(want_debian ? LUCAS_PROFILE_DEBIAN : LUCAS_PROFILE_ALPINE);
    vfs_set_tier(2);
    if (use_bash) sotbox_spawn_set_envp_next(SSH_BASH_ENVP);
    if (sotbox_spawn_into(&g_ssh_shell_st, elf, sz, argv, 2, 0, false) != 0) {
        printf("[orch] ssh-shell: spawn failed\n");
        return;
    }
    /* ABI v2 · procd · announce the SSH shell so it owns a procd slot (the
     * spawn-into path doesn't do the shadow-announce that the SPAWN-IPC path
     * does).  The slot is needed so the post-spawn OP_SET_SESSION below has a
     * target · without it the attacker's shell wouldn't appear named/sessioned
     * in their own `ps`.  comm = the shell basename (bash/busybox). */
    {
        extern int orch_procd_spawn(uint64_t, uint32_t, int, const char *const argv[],
                                    proc_tier_t, uint64_t, uint32_t, const char *,
                                    uint32_t *, uint32_t *);
        uint32_t sh_slot = 0, sh_pid = 0;
        const char *sh_comm = use_bash ? "bash" : "busybox";
        int sp_rc = orch_procd_spawn(0, 0, (use_bash ? 2 : 3), argv,
                                     PROC_TIER_2, 0, 0, sh_comm,
                                     &sh_slot, &sh_pid);
        if (sp_rc >= 0) g_ssh_shell_st.procd_slot = sh_slot;
        printf("[orch] ssh-shell: procd announce slot=%u pid=%u comm=%s rc=%d\n",
               sh_slot, sh_pid, sh_comm, sp_rc);
    }
    /* R9 · re-source busybox stdin/stdout to the SSH rings BEFORE the box runs
     * (so its first read(fd0) already sees SSH_RING · no UART race). */
    g_ssh_shell_st.console_interactive = 1;
    g_ssh_shell_st.console_src         = LUCAS_CONSOLE_SRC_SSH_RING;
    /* exec-mode (`ssh host 'cmd'`) has no PTY → its stdout is a pipe: emit raw LF, not
     * CRLF, exactly like a real sshd (set per spawn, so an interactive shell keeps ONLCR). */
    g_ssh_shell_st.no_onlcr            = (g_ssh_exec_len > 0) ? 1 : 0;
    /* apk-fs T6 · set the SHELL_IN read cursor to the ring position snapshotted
     * at SHELL_START receipt time (g_ssh_shell_pending_ring_rd), NOT ring->w now.
     *
     * Why not ring->w now?  SSH guarantees that CHANNEL_DATA (attacker keystrokes)
     * only arrives AFTER the shell request that triggers SHELL_START, so the
     * snapshot taken at SHELL_START is always ≤ the position of the first real
     * keystroke.  If we sample ring->w here at spawn time instead, we skip over
     * any CHANNEL_DATA that arrived between SHELL_START and bash's spawn (e.g. a
     * scripted attacker that types commands right after auth).
     *
     * Why not 0?  The ring is never cleared; resetting to 0 causes the new session
     * to re-read the previous session's stale bytes from the beginning of the ring.
     * The SHELL_START snapshot is always ≥ the end of the previous session's bytes,
     * so it cleanly separates session N's data from session N+1's data. */
    g_ssh_shell_st.shell_in_rd = g_ssh_shell_pending_ring_rd;
    /* Phase C · key the per-session COW-lite overlay to this SSH connection.
     * conn_id is non-zero for a live SSH shell, so a Tier-2 `:w` of a canary
     * file reads back the attacker's own edit within the session while the base
     * stays pristine; reaped on disconnect (C4).  Inherited by the vim child via
     * sotbox_fork's `*child = *parent`. */
    g_ssh_shell_st.cow_session         = conn_id;
    /* M3 · per-session persona context · stamp this SSH session's persona identity
     * (the canonical Alpine today) into the per-session table keyed by conn_id.
     * truth-core renders the operator view (sotctl sessions) from this record, and
     * uname's nodename resolves from it — the g_profile→per-session seam.  Reaped
     * on disconnect alongside the COW/sotfs uppers. */
    {
        extern int  lucas_persona_session_set(uint32_t, const lucas_persona_t *);
        int p_rc = lucas_persona_session_set(conn_id, &sess_persona);
        printf("[orch] ssh-shell: persona_ctx set sess=%u persona=%s host=%s profile=%u rc=%d\n",
               conn_id, sess_persona.name, sess_persona.host,
               sess_persona.profile, p_rc);
    }
    /* ABI v2 · procd · push the now-known cow_session + the shell's comm into
     * the procd proc_t so the attacker's own `ps` (via truth_list_processes)
     * shows their session's real, named shell.  procd_slot==0 (announce
     * skipped) makes this a no-op.  comm = the interactive shell basename. */
    {
        extern int orch_procd_set_session(uint32_t, uint32_t, const char *);
        const char *shell_comm = use_bash ? "bash" : "busybox";
        int ss_rc = orch_procd_set_session(g_ssh_shell_st.procd_slot,
                                           conn_id, shell_comm);
        printf("[orch] ssh-shell: procd set_session slot=%u sess=%u comm=%s rc=%d\n",
               g_ssh_shell_st.procd_slot, conn_id, shell_comm, ss_rc);
    }
    /* B5 · open the TUI at the client's real terminal size: the pty-req WINCH
     * arrived before this spawn and stashed cols/rows. Fall back to 80x24 if
     * the client sent no pty size (so a non-80x24 client sees vim full-size,
     * not a honeypot-tell 80x24 box). */
    g_ssh_shell_st.ws.ws_col = g_ssh_shell_pending_cols ? g_ssh_shell_pending_cols : 80;
    g_ssh_shell_st.ws.ws_row = g_ssh_shell_pending_rows ? g_ssh_shell_pending_rows : 24;
    printf("[tty] initial winsize cols=%u rows=%u\n",
           g_ssh_shell_st.ws.ws_col, g_ssh_shell_st.ws.ws_row);
    g_ssh_shell_active = true;
    g_ssh_shell_conn   = conn_id;
    printf("[orch] ssh-shell: %s Tier-2 over SSH conn=%u · entering fault loop\n",
           use_bash ? "Alpine musl bash -i (alpine-bash)" : "busybox sh -i", conn_id);

    orch_fault_loop(orch_get_fault_ep());      /* idle branch keeps draining in_p2c (Task 2) */

    sotbox_reset_primary();
    g_ssh_shell_active = false;
    /* C4 · the per-session COW overlay is session-lifetime: free this
     * attacker's file edits so the next session (and the operator) sees the
     * pristine base, not a prior attacker's writes. */
    extern void lucas_cow_reap(uint32_t session);
    lucas_cow_reap(conn_id);
    /* apk-fs Phase 1 · the sotfs-backed per-session upper is session-lifetime
     * too: free this session's installed files (graph + disk blocks) so the
     * base stays pristine for the operator and the next attacker. No-op until
     * Phase 2 wires create-site tagging. */
    extern void lucas_sotfs_session_reap(uint32_t session);
    lucas_sotfs_session_reap(conn_id);
    /* M3 · …and this session's persona context (session-lifetime: the next
     * attacker on a reused conn_id is stamped fresh at spawn). */
    extern void lucas_persona_session_clear(uint32_t session);
    lucas_persona_session_clear(conn_id);
    /* …and the per-session symlinks the attacker created in /tmp (same
     * session-lifetime contract as the COW overlay). */
    extern void lucas_symlink_reap(uint32_t session);
    lucas_symlink_reap(conn_id);
    /* B5 · reset the stashed pty-req size so a stale size from this session does
     * not leak into the next attacker's shell (they re-send their own pty-req). */
    g_ssh_shell_pending_cols = g_ssh_shell_pending_rows = 0;
    /* R4 · busybox exited → tell net-synth to CHANNEL_EOF+CLOSE this conn. */
    bytepipe_ring_t *in_c2p = (bytepipe_ring_t *)BYTEPIPE_IN_C2P_VADDR;
    bytepipe_push_frame(in_c2p, conn_id, BYTEPIPE_PORT_SHELL_EOF, NULL, 0);
    g_ssh_shell_conn = 0;
    printf("[orch] ssh-shell: busybox exited · SHELL_EOF → conn=%u\n", conn_id);
}

/* SSH canary shell (Phase B) · R4 · attacker disconnected (net-synth pushed
 * SHELL_KILL on in_p2c).  Suspend the live SSH-shell busybox + tear down its
 * slot so its nested orch_fault_loop returns (alive_count→0).  Mirrors the
 * antidos doom-reap teardown. */
static void orch_ssh_shell_kill(uint16_t conn_id)
{
    if (!g_ssh_shell_active) return;
    if (conn_id != 0 && conn_id != g_ssh_shell_conn) return;  /* not our shell */
    lucas_state_t *st = &g_ssh_shell_st;
    printf("[orch] ssh-shell: SHELL_KILL · reaping busybox (conn=%u slot=%d)\n",
           conn_id, st->slot_index);
    if (st->client_tcb != 0) seL4_TCB_Suspend(st->client_tcb);
    if (st->waiting_reply_cap != 0) {
        cspacepath_t rp;
        vka_cspace_make_path(st->vka, st->waiting_reply_cap, &rp);
        seL4_CNode_Delete(rp.root, rp.capPtr, rp.capDepth);
        vka_cspace_free(st->vka, st->waiting_reply_cap);
        st->waiting_reply_cap = 0;
    }
    int slot = st->slot_index;
    sotbox_destroy(slot);
    sotbox_free_slot(slot);
    sotbox_fork_release_storage(st);
    /* alive_count now 0 → the nested fault loop in orch_ssh_shell_run returns,
     * which pushes SHELL_EOF and clears g_ssh_shell_conn/active. */
    /* Session-lifetime resources (COW overlay, sotfs upper, /tmp symlinks) are
     * NOT reaped here: tearing the slot down makes orch_ssh_shell_run's nested
     * fault loop return into its post-loop teardown block, which runs all three
     * reaps with this conn's session id.  Add new session-lifetime reaps THERE,
     * not here, to keep clean-exit and abrupt-kill on one path. */
}

/* P4b · periodic stability heartbeat. free_arenas (wholesale-reclaim metric — must
 * return to MAX each reap → no arena leak); live_sotbox (must return to baseline);
 * root_pages (cumulative ROOT-vka bookkeeping pages — the leak slope). printf ALONE
 * on the line (serial_putc interleave gotcha).
 * NOTE: tsc=%llu field DROPPED — sottrace_rdtsc() is static-inline-private to
 * src/sottrace/trace.c (not declared in <sottrace/trace.h>), so unreachable here
 * (plan Step 3 fallback). */
#define STATS_EVERY 25u
static uint32_t g_soak_spawn_count = 0;
static void orch_emit_stats(uint32_t iter)
{
    extern int sotbox_arena_pool_count_free(void);
    extern int sotbox_alive_count(void);
    printf("[stats] iter=%u free_arenas=%d/%d live_sotbox=%d root_pages=%ld\n",
           iter, sotbox_arena_pool_count_free(), (int)SOTBOX_MAX_SLOTS,
           sotbox_alive_count(), orch_root_pages_total());
}

/* ANOMALY-DASHBOARD · in-orch ring buffer of recent anomaly events.
 * Populated alongside every ORCH_OP_ANOMALY_EVENT IPC orch fires (today:
 * sotShell-driven PROMOTE_TIER · future producer sites should call
 * orch_anomaly_log_append() directly).  Read by sotShell via
 * ORCH_OP_QUERY_ANOMALY_LOG.  Wraps on overflow. */
static orch_anomaly_log_entry_t g_anomaly_log[ORCH_ANOMALY_LOG_MAX];
static uint16_t g_anomaly_log_seq  = 0;
static uint16_t g_anomaly_log_head = 0;   /* next write index */
static uint8_t  g_anomaly_log_full = 0;

/* procd PR 4 · NTF half of the procd→orch event channel.
 *   g_procd_ntf      · notification cap minted into orch's CSpace by root
 *                       (orch seL4_Polls on this each main-loop pass).
 *   g_procd_ring     · base of procd's 1 MiB SHM region, mapped RO into
 *                       orch.  PR 5 wires this; in PR 4 it stays NULL
 *                       and orch synthesizes the marker event line off
 *                       the NTF alone (NTF-only fallback).
 *   g_procd_tail     · orch-side consumer cursor into the ring.
 *   g_procd_signals  · count of NTF wake-ups observed (for diagnostics). */
static seL4_CPtr           g_procd_ntf      = 0;
static procd_event_ring_t *g_procd_ring     = NULL;
static uint64_t            g_procd_tail     = 0;
/* IRQ-driven virtio-net RX · caps delegated by root (0 = busy-poll fallback). */
static seL4_CPtr           g_vnet_irq_ntf     = 0;   /* Notification the kernel Signals on RX IRQ */
static seL4_CPtr           g_vnet_irq_handler = 0;   /* IRQHandler · Ack to re-arm the level IRQ */
static uint64_t            g_vnet_irq_count   = 0;   /* diagnostics · IRQs observed */
static seL4_CPtr           g_lwip_irq_ntf     = 0;   /* 2nd NIC (lwIP egress) RX Notification */
static seL4_CPtr           g_lwip_irq_handler = 0;   /* 2nd NIC IRQHandler · Ack to re-arm */
static seL4_CPtr           g_lwip_pit_handler = 0;   /* PIT tick IRQHandler · same ntf, periodic wake */
static uint64_t            g_procd_signals  = 0;

/* IRQ-driven virtio-net RX · expose the IRQ caps to the lucas net handlers
 * (lucas_tcp_recv blocks on the Notification + Acks the IRQHandler instead of
 * busy-polling for inbound).  Return 0 when root didn't wire the IRQ → callers
 * fall back to the legacy busy-poll spin. */
seL4_CPtr orch_vnet_irq_ntf(void)     { return g_vnet_irq_ntf; }
seL4_CPtr orch_vnet_irq_handler(void) { return g_vnet_irq_handler; }

/* 2nd virtio-net (lwIP egress) IRQ caps · the egress pump (lwip_egress.c) blocks
 * on the Notification + Acks the IRQHandler instead of busy-polling.  0 = root
 * didn't wire it → busy-poll fallback. */
seL4_CPtr orch_lwip_irq_ntf(void)     { return g_lwip_irq_ntf; }
seL4_CPtr orch_lwip_irq_handler(void) { return g_lwip_irq_handler; }
seL4_CPtr orch_lwip_pit_handler(void) { return g_lwip_pit_handler; }

/* orch's RO view of procd's 1 MiB SHM · drives the event-ring drain (real
 * procd events → anomaly-log) and the boot-time WAL snapshot of procd's
 * authoritative proc table (sotfs/replay_procd.c reads this).
 *
 * DELIBERATELY DISTINCT from procd_client.c's g_procd_shm_base, which gates
 * the LATENCY-CRITICAL lucas/fork hot-path readers (lucas_procd_view_*,
 * synth-fork detection).  That global stays 0 by design: pointing it at the
 * live table puts an unbounded-seqlock-spin + 256-slot scan on every syscall
 * lookup and slows the demo ~3×.  Making the hot-path readers consume the live
 * table is a separate future arc (findings doc §5 · "do NOT re-route the
 * latency-critical wait4 quick-path"). */
void *g_procd_shm_ro = NULL;

/* sotNet γ-3-γ-1 · byte channel.  g_bytepipe_ready is set from
 * bs.bytepipe_ready at BOOTSTRAP.  orch is the PRODUCER of c2p (it pushes the
 * bytes a redirected sendto carried) and the CONSUMER of p2c (it drains the
 * responder's reply).  g_p2c_rd is orch's private read cursor into p2c. */
static int      g_bytepipe_ready = 0;
static uint32_t g_p2c_rd         = 0;
/* N2-T · inbound framed transport · orch is the in_c2p producer + in_p2c consumer. */
static int      g_bytepipe2_ready = 0;
static uint32_t g_in_p2c_rd       = 0;   /* orch is the in_p2c consumer */
/* g_bytepipe3_ready is defined earlier (above orch_ssh_shell_run, which uses it). */

/* Accessor for lucas/sotnet (separate translation units) · mirrors
 * orch_get_synth_event_ep. */
int orch_bytepipe_ready(void) { return g_bytepipe_ready; }

/* L12-beta · Wayland compositor route.  The cap itself stays in orch's CSpace;
 * LUCAS only needs readiness for connect(AF_UNIX, wayland-0) in this cut. */
static seL4_CPtr g_wayland_listen_ep = 0;
int orch_wayland_ready(void) { return g_wayland_listen_ep != 0; }
seL4_CPtr orch_wayland_listen_ep(void) { return g_wayland_listen_ep; }

/* L13-A1 · compositor page-directory (PML4) cap minted by root into orch's
 * CSpace.  Used by L13-A2 orch_shm_pool to call sel4utils_map_page and
 * install shared SHM frames into the compositor vspace.  0 = absent. */
static seL4_CPtr g_wayland_pd_cap = 0;
seL4_CPtr orch_wayland_pd_cap(void) { return g_wayland_pd_cap; }

/* L14a-A1 · shadow compositor listen EP minted by root into orch's CSpace.
 * Used by L14a routing logic to forward flagged-hostile clients to the shadow
 * instead of the honest compositor.  0 = absent · L14a deception disabled. */
static seL4_CPtr g_wayland_canary_ep = 0;
seL4_CPtr orch_wayland_canary_ep(void) { return g_wayland_canary_ep; }

/* sotNet γ-3-γ-1 · drain any reply bytes the responder pushed into p2c and
 * deliver them to the addressed sotbox's recv queue.  Cursor-driven and
 * idempotent: safe to call both opportunistically (every main-loop pass) and
 * on the responder's NBSend wake.  Decoupled from the wake — a dropped doorbell
 * just means the bytes are drained on the next pass (the ring cursor is the
 * source of truth).  MUST run before the blocking seL4_Recv (it touches the IPC
 * buffer via the recv-wake path · same ordering rule as orch_procd_drain). */
/* N2-T · push one inbound request frame to in_c2p + ring the inbound doorbell.
 * Called from sotnet (tcp_data_on_segment) on the orch thread. No-op until ready. */
void orch_inbound_push(uint16_t conn_id, uint16_t local_port,
                       const uint8_t *data, uint32_t len)
{
    if (!g_bytepipe2_ready) return;
    bytepipe_ring_t *in_c2p = (bytepipe_ring_t *)BYTEPIPE_IN_C2P_VADDR;
    if (bytepipe_push_frame(in_c2p, conn_id, local_port, data, len) == 0) return;
    extern seL4_CPtr orch_get_synth_event_ep(void);
    seL4_CPtr ep = orch_get_synth_event_ep();
    if (ep != 0)
        seL4_NBSend(ep, seL4_MessageInfo_new(ORCH_OP_SYNTH_INBOUND, 0, 0, 0));
}

static void orch_bytepipe_drain_p2c(void)
{
    if (!g_bytepipe_ready) return;
    bytepipe_ring_t *p2c = (bytepipe_ring_t *)BYTEPIPE_P2C_VADDR;
    if (__atomic_load_n(&p2c->w, __ATOMIC_ACQUIRE) == g_p2c_rd) return;  /* nothing new */

    /* Peek the reply's routing without advancing the cursor (the pull below or
     * the recvfrom stream advances it). */
    uint32_t pid = p2c->meta_pid;

    /* γ-3-γ-2b · STREAM mode: a real Tier-2 sotbox owns its p2c stream.
     *  - parked on recvfrom → wake it; the wake drains p2c (recvfrom_deliver).
     *  - running (not parked) → leave the bytes; its next recvfrom drains them.
     * Either way orch does NOT consume here (single consumer · shared cursor). */
    extern int lucas_recv_waiter_present(uint32_t pid);
    extern int lucas_recv_wake_waiter(uint32_t pid);
    if (pid != 99u) {
        if (lucas_recv_waiter_present(pid)) lucas_recv_wake_waiter(pid);
        return;
    }

    /* γ-3-γ-1 · synthetic boot probe (pid=99 · no real recv consumer) ·
     * drain to the pending_recv queue (preserves the SOTNET·bytepipe gate). */
    uint8_t  body[SOTNET_RECV_BODY_MAX];
    uint32_t got = bytepipe_pull(p2c, &g_p2c_rd, body, sizeof(body));
    if (got == 0) return;
    uint32_t ip_be   = p2c->meta_src_ip;
    uint16_t port_be = (uint16_t)p2c->meta_src_port;
    uint8_t  src_ip[4] = {
        (uint8_t)(ip_be & 0xFF),  (uint8_t)((ip_be >> 8)  & 0xFF),
        (uint8_t)((ip_be >> 16) & 0xFF), (uint8_t)((ip_be >> 24) & 0xFF),
    };
    printf("[orch] bytepipe p2c rx %u bytes · pid=%u (probe→queue)\n", got, pid);
    sotnet_recv_enqueue(pid, src_ip, port_be, body, (size_t)got);
}

/* N2-T · drain inbound reply frames from in_p2c and send each back to its
 * connection by conn_id. orch is the in_p2c consumer (poll-driven, no doorbell). */
static void orch_bytepipe_drain_in_p2c(void)
{
    if (!g_bytepipe2_ready) return;
    bytepipe_ring_t *in_p2c = (bytepipe_ring_t *)BYTEPIPE_IN_P2C_VADDR;
    if (__atomic_load_n(&in_p2c->w, __ATOMIC_ACQUIRE) == g_in_p2c_rd) return;
    bytepipe_frame_hdr_t fh;
    static uint8_t rbuf[BYTEPIPE_DATA_BYTES];
    while (bytepipe_pull_frame(in_p2c, &g_in_p2c_rd, &fh, rbuf, sizeof rbuf)) {
        /* SSH canary shell (Phase B) · in-band control markers (R1/R4) · these
         * are NOT wire data — never tcp_send them. */
        if (fh.local_port == BYTEPIPE_PORT_SHELL_START) {
            if (!g_bytepipe3_ready) continue;
            if (g_ssh_shell_active && fh.conn_id != g_ssh_shell_conn) {
                /* R2 · single concurrent interactive shell.  A 2nd session is
                 * authenticated (its cred was already captured in net-synth) but
                 * the nested busybox fault loop serves ONE shell at a time.  Close
                 * the new channel cleanly (SHELL_EOF) rather than silently drop the
                 * START → the attacker gets a believable disconnect, not a hang. */
                bytepipe_ring_t *in_c2p = (bytepipe_ring_t *)BYTEPIPE_IN_C2P_VADDR;
                bytepipe_push_frame(in_c2p, fh.conn_id, BYTEPIPE_PORT_SHELL_EOF, NULL, 0);
                printf("[orch] ssh-shell: conn=%u refused · shell busy (conn=%u) · SHELL_EOF\n",
                       fh.conn_id, g_ssh_shell_conn);
                continue;
            }
            /* R1 · stash + continue · the op/shell-window loop hoists the spawn
             * OUT of this drain (re-entering orch_fault_loop here would corrupt
             * g_in_p2c_rd via the nested idle drain). */
            g_ssh_shell_pending = fh.conn_id;
            /* exec-mode · a non-empty SHELL_START payload IS the command line; stash it
             * for orch_ssh_shell_run (empty payload → interactive bash -i). */
            if (fh.len > 0 && fh.len < sizeof g_ssh_exec_cmd) {
                memcpy(g_ssh_exec_cmd, rbuf, fh.len);
                g_ssh_exec_cmd[fh.len] = '\0';
                g_ssh_exec_len = (uint16_t)fh.len;
            } else {
                g_ssh_exec_len = 0;
            }
            /* apk-fs T6 · snapshot the SHELL_IN ring write-position NOW,
             * before any CHANNEL_DATA for the new session is pushed.  bash
             * will use this as its initial shell_in_rd so it sees all the
             * attacker's keystrokes that arrive between now and bash's first
             * read(fd0) — even ones that arrive before bash actually spawns. */
            {
                bytepipe_ring_t *in_shell = (bytepipe_ring_t *)BYTEPIPE_SHELL_IN_VADDR;
                g_ssh_shell_pending_ring_rd =
                    __atomic_load_n(&in_shell->w, __ATOMIC_ACQUIRE);
            }
            continue;
        }
        if (fh.local_port == BYTEPIPE_PORT_SHELL_KILL) {
            orch_ssh_shell_kill(fh.conn_id);         /* R4 · attacker gone · reap busybox */
            continue;
        }
        if (fh.local_port == BYTEPIPE_PORT_SHELL_WINCH) {
            /* TUI · pty resize · payload = 4 bytes big-endian: u16 cols, u16 rows
             * (bytepipe_pull_frame already copied fh.len payload bytes into rbuf,
             * exactly like the wire-data path below). Update the session winsize
             * and raise SIGWINCH on the busybox (and its TUI child) so a parked
             * read(fd0) returns -EINTR → the handler runs → the editor redraws. */
            if (fh.len >= 4) {
                uint16_t cols = (uint16_t)(((uint16_t)rbuf[0] << 8) | rbuf[1]);
                uint16_t rows = (uint16_t)(((uint16_t)rbuf[2] << 8) | rbuf[3]);
                if (cols && rows) {
                    /* B5 · always stash the latest size (the pty-req WINCH lands
                     * BEFORE busybox spawns) so spawn can open at the client size. */
                    g_ssh_shell_pending_cols = cols;
                    g_ssh_shell_pending_rows = rows;
                    if (g_ssh_shell_active) {       /* live resize while the TUI runs */
                        printf("[tty] winch cols=%u rows=%u\n", cols, rows);
                        extern int lucas_console_winch_foreground(uint32_t session,
                                                                  uint16_t cols, uint16_t rows);
                        /* F1 · deliver to the session's FOREGROUND reader (the forked
                         * vim/nano child if any, else busybox) — keyed on the conn_id
                         * that all session boxes carry as cow_session. */
                        lucas_console_winch_foreground(g_ssh_shell_conn, cols, rows);
                    }
                }
            }
            continue;
        }
        /* Reserved control-port range (0xFF00-0xFFFF) carries in-band orch<->net-synth
         * signals (SHELL_START/KILL handled above; SHELL_WINCH consumed in a later task),
         * NOT attacker wire data.  Never forward these to the TCP stream — doing so injects
         * bytes into the encrypted SSH/TLS transport and corrupts it.  Skip any unhandled one. */
        if (fh.local_port >= 0xFF00u) continue;
        struct tcp_conn *c = tcp_conn_by_id(fh.conn_id);
        if (!c) continue;                            /* conn closed · drop reply */
        /* N2-R · tcp_send_data caps one segment at TCP_TX_BUF_SIZE (256 B), so a
         * reply larger than that (e.g. a >1 KB TLS ServerHello+Cert flight, or a
         * full HTTP body) must go out as several back-to-back segments.  Loop over
         * the frame, advancing by the bytes each call actually consumed. */
        uint32_t sent = 0;
        while (sent < fh.len) {
            int n = tcp_send_data(c, rbuf + sent, (size_t)(fh.len - sent));
            if (n <= 0) break;                       /* conn not sendable · stop */
            sent += (uint32_t)n;
        }
        /* sottrace · record the wire reply bytes as this conn's OUT stream.
         * Fires per in_p2c frame and ACCUMULATES (a multi-frame reply chunks). */
        sottrace_capture_append(fh.conn_id, SOTTRACE_DIR_OUT, rbuf, (uint32_t)sent);
        trace_emit_response_profile(-1, fh.conn_id, fh.local_port, sent);  /* sottrace · response_profile served (slot=-1 → system ring) */
        if (!g_orch_quiet)
        printf("[orch] inbound reply · conn=%u %u/%u bytes → tcp_send_data (segmented)\n",
               fh.conn_id, sent, fh.len);
    }
}

/* SSH canary shell (Phase B) · non-static wrapper so orch_fault_loop's idle
 * branch (fault_loop.c, a separate TU) can drain in_p2c while busybox runs —
 * the encrypted CHANNEL_DATA replies pushed by net-synth must keep flowing
 * during an SSH session.  Mirrors how sotnet_poll is reached from fault_loop.c. */
void orch_bytepipe_drain_in_p2c_pub(void) { orch_bytepipe_drain_in_p2c(); }

/* SSH canary shell (Phase B) · busybox stdout lands in SHELL_OUT (a ring net-
 * synth consumes), but net-synth blocks in seL4_Recv between inbound frames.
 * When busybox produces output without a coincident keystroke, net-synth would
 * not wake to pump SHELL_OUT → the wire.  So while an SSH shell is live, kick
 * net-synth (the same fire-and-forget NBSend orch_inbound_push uses) whenever
 * SHELL_OUT's write cursor advances.  net-synth then runs its SHELL_OUT pump
 * (R5/R6) in the SAME main-loop body as the inbound dispatch.  Called from the
 * fault-loop idle branch (fault_loop.c) — a separate TU, hence non-static. */
void orch_ssh_shell_kick_out(void)
{
    if (!g_bytepipe3_ready || !g_ssh_shell_active) return;
    static uint32_t last_w = 0;
    bytepipe_ring_t *so = (bytepipe_ring_t *)BYTEPIPE_SHELL_OUT_VADDR;
    uint32_t w = __atomic_load_n(&so->w, __ATOMIC_ACQUIRE);
    if (w == last_w) return;                 /* no new busybox output */
    last_w = w;
    extern seL4_CPtr orch_get_synth_event_ep(void);
    seL4_CPtr ep = orch_get_synth_event_ep();
    if (ep != 0)
        seL4_NBSend(ep, seL4_MessageInfo_new(ORCH_OP_SYNTH_INBOUND, 0, 0, 0));
}

/* γ-3-γ-2b · pull up to `max` bytes from p2c via the SHARED read cursor (the
 * sole p2c consumer for real sotboxes · called from recvfrom_deliver). */
uint32_t orch_bytepipe_p2c_pull(uint8_t *dst, uint32_t max)
{
    if (!g_bytepipe_ready) return 0;
    bytepipe_ring_t *p2c = (bytepipe_ring_t *)BYTEPIPE_P2C_VADDR;
    return bytepipe_pull(p2c, &g_p2c_rd, dst, max);
}

/* β · PR 5 · sotinit listen EP cap in orch's CSpace.  Captured from the
 * BOOTSTRAP message (bs.sotinit_listen_ep_slot) so the ORCH_OP_SPAWN_NATIVE
 * handler can forward the same slot to sotShell as argv[3].  0 if root
 * did not pre-spawn sotinit or the mint failed · sotShell's
 * cmd_systemctl short-circuits with "sotinit EP not available". */
static seL4_CPtr           g_sotinit_listen_ep = 0;

/* β · PR 9 · sotcron listen EP cap in orch's CSpace.  Captured from the
 * BOOTSTRAP message (bs.sotcron_listen_ep_slot) so the ORCH_OP_SPAWN_NATIVE
 * handler can forward the same slot to sotShell as argv[4].  0 if root
 * did not pre-spawn sotcron or the mint failed · sotShell's cmd_cron
 * short-circuits with "sotcron EP not available". */
static seL4_CPtr           g_sotcron_listen_ep = 0;

/* α · PR 4 · WAL writer gate for orch-internal callers (lucas/handlers_net.c
 * → sotfs_wal_log_sotnet_synth, sotguard_emit → sotfs_wal_log_anomaly_ev).
 * Set to 1 after BOOTSTRAP completes · orch hosts sotos-sotfs as a linked
 * library so the writes are direct calls (no IPC).  This is the LOCAL
 * version of g_wal_attached for orch's address space · procd / anomaly
 * own their own copies that gate their seL4_Call into SOTFS_OP_WAL_LOG. */
int g_wal_attached = 0;

/* Forward declaration · the audit-trail bridge in orch_procd_drain
 * (PR 15) calls orch_anomaly_log_append which is defined below.
 * α · PR 9 · v0.26.0 · NOT static so wal.c (via weak-symbol bridge
 * sotfs_wal_audit_emit) and simreboot.c can append audit events
 * directly into the anomaly-log ring without going through IPC. */
void orch_anomaly_log_append(uint32_t pid, uint16_t kind,
                              uint64_t arg0, uint64_t arg1);

/* procd-authoritative-GC · continuous WAL mirror.  When orch drains a procd
 * lifecycle event it reads the event's proc_t through the RO cross-mapping
 * (g_procd_shm_ro · seqlock-safe, bounded retry) and appends a procd_mut
 * record to the WAL in-process.  This upgrades the boot-time snapshot to a
 * CONTINUOUS durable mirror of procd's authoritative state as it mutates at
 * runtime (tier changes, exits, ...).  Off the latency-critical path: it runs
 * at event-drain time via g_procd_shm_ro, NOT the syscall-hot g_procd_shm_base
 * (which stays 0 by design).  Best-effort: skips if the WAL isn't armed, the
 * slot is out of range, or the read tears. */
static void orch_procd_wal_mirror_slot(uint32_t slot)
{
    extern int g_wal_attached;
    if (!g_wal_attached || g_procd_shm_ro == NULL) return;
    if (slot == 0 || slot >= PROCD_MAX_PROCS) return;

    procd_shm_header_t *hdr = (procd_shm_header_t *)g_procd_shm_ro;
    if (hdr->magic != PROCD_SHM_MAGIC || slot >= hdr->table_n) return;
    const volatile proc_t *p = (const volatile proc_t *)
        ((const uint8_t *)g_procd_shm_ro + hdr->table_ofs
         + (size_t)slot * sizeof(proc_t));

    proc_t snap;
    int ok = 0;
    for (int tries = 0; tries < 8; ++tries) {
        uint64_t v1 = p->version;
        if (v1 & 1ull) continue;                 /* writer mid-update */
        memcpy(&snap, (const void *)p, sizeof(snap));
        uint64_t v2 = p->version;
        if (v1 == v2) { ok = 1; break; }
    }
    if (!ok || snap.state == PROC_STATE_FREE) return;

    sotfs_wal_payload_procd_mut_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.slot         = snap.slot;
    rec.synthetic_pid     = snap.synthetic_pid;
    rec.ppid         = snap.ppid;
    rec.pgid         = snap.pgid;
    rec.sid          = snap.sid;
    rec.tier         = (uint16_t)snap.tier;
    rec.functor_fs   = snap.functor_fs;
    rec.functor_net  = snap.functor_net;
    rec.functor_proc = snap.functor_proc;
    rec.state        = (uint8_t)snap.state;
    rec.pledge_mask  = snap.pledge_mask;
    (void)sotfs_wal_log_procd_mut(&rec);
}

/* procd PR 4 · non-blocking poll for procd NTF wake-ups.  Called from
 * the main loop after every seL4_Recv returns; if procd has Signaled
 * since the last poll, the notification word is non-zero and we either
 * (a) drain the SHM ring when g_procd_ring is mapped (PR 5+), or
 * (b) print a synthesized 'procd-ev kind=0x10 slot=0' line based on
 *     the marker procd publishes at startup (PR 4 NTF-only mode).
 * Cost: one syscall when nothing is pending (seL4_Poll returns null
 * MessageInfo).  Side-effect-free for the wider IPC dispatch. */
static void orch_procd_drain(void)
{
    if (g_procd_ntf == 0) return;
    seL4_Word badge = 0;
    seL4_Poll(g_procd_ntf, &badge);
    if (badge == 0) return;
    g_procd_signals++;
    /* procd-authoritative-GC · lazy-resolve the ring from the RO SHM header.
     * procd stamps PROCD_SHM_MAGIC + evring_ofs in procd_shm_init; until then
     * we stay in the NTF-only fallback.  Magic + bounds checked before we
     * trust the offset (a stale/uninitialized header must not be treated as
     * a ring). */
    if (g_procd_ring == NULL && g_procd_shm_ro != NULL) {
        procd_shm_header_t *hdr = (procd_shm_header_t *)g_procd_shm_ro;
        if (hdr->magic == PROCD_SHM_MAGIC &&
            hdr->evring_ofs > 0 &&
            hdr->evring_ofs + sizeof(procd_event_ring_t) <= PROCD_SHM_BYTES) {
            g_procd_ring = (procd_event_ring_t *)
                ((uint8_t *)g_procd_shm_ro + hdr->evring_ofs);
            printf("[orch] procd ring resolved · base=%p evring_ofs=%u ring=%p\n",
                   g_procd_shm_ro, (unsigned)hdr->evring_ofs,
                   (void *)g_procd_ring);
        }
    }
    if (g_procd_ring != NULL) {
        procd_event_t buf[16];
        int overflow = 0;
        uint32_t n = procd_event_drain(g_procd_ring, &g_procd_tail,
                                        buf, 16, &overflow);
        for (uint32_t i = 0; i < n; i++) {
            printf("[orch] procd-ev kind=0x%02x slot=%u seq=%lu\n",
                   (unsigned)buf[i].kind, (unsigned)buf[i].slot,
                   (unsigned long)buf[i].seq);

            /* PR 15 · audit-trail bridge.  Re-emit each procd event into
             * the in-orch anomaly ring so it appears in `anomaly-log`
             * alongside operator-promote/pledge/DNS_HIT/TCP_OPEN/etc.  The
             * operator now has a single chronological view of every
             * security-relevant lifecycle and policy event.  We translate
             * the load-bearing PROCD_EV_* kinds into dedicated
             * ANOMALY_EV_PROCD_* slots and collapse the rest into
             * ANOMALY_EV_PROCD_OTHER (procd kind preserved in arg1). */
            uint16_t skind;
            uint64_t arg1;
            switch (buf[i].kind) {
                case PROCD_EV_PROC_BORN:
                    skind = ANOMALY_EV_PROCD_PROC_BORN;
                    arg1  = 0;
                    break;
                case PROCD_EV_PROC_EXITED:
                    skind = ANOMALY_EV_PROCD_PROC_EXITED;
                    arg1  = (uint64_t)buf[i].extra32;  /* exit_code */
                    break;
                case PROCD_EV_TIER_CHANGED:
                    skind = ANOMALY_EV_PROCD_TIER_CHANGED;
                    arg1  = (uint64_t)buf[i].extra32;  /* new tier */
                    break;
                case PROCD_EV_FUNCTOR_REBOUND:
                    skind = ANOMALY_EV_PROCD_FUNCTOR_REBOUND;
                    arg1  = (uint64_t)buf[i].extra32;  /* functor id */
                    break;
                case PROCD_EV_SYNTH_FORK:
                    skind = ANOMALY_EV_PROCD_SYNTH_FORK;
                    arg1  = (uint64_t)buf[i].extra32;  /* parent slot */
                    break;
                case PROCD_EV_DENIED_TIER3:
                    skind = ANOMALY_EV_PROCD_DENIED_TIER3;
                    arg1  = (uint64_t)buf[i].extra32;  /* op */
                    break;
                default:
                    skind = ANOMALY_EV_PROCD_OTHER;
                    arg1  = (uint64_t)buf[i].kind;     /* preserve PROCD_EV_* */
                    break;
            }
            orch_anomaly_log_append((uint32_t)buf[i].slot, skind,
                                      (uint64_t)buf[i].slot, arg1);

            /* procd-authoritative-GC · continuous WAL mirror · durably log the
             * authoritative proc_t for this event's slot (off hot-path · via
             * g_procd_shm_ro at drain time · no procd→orch seL4_Call). */
            orch_procd_wal_mirror_slot((uint32_t)buf[i].slot);

            /* β · init-cron PR 6 · forward PROC_EXITED to sotinit so it
             * can apply Restart= policy.  One-way NBSend so orch never
             * blocks on sotinit · if sotinit isn't currently in seL4_Recv
             * the message is dropped and the next event resyncs.  We do
             * this AFTER the anomaly-log append so the audit trail is
             * always complete even if sotinit happens to be busy. */
            if (g_sotinit_listen_ep != 0 &&
                buf[i].kind == PROCD_EV_PROC_EXITED) {
                seL4_SetMR(0, SOTINIT_OP_PROC_EXITED);
                seL4_SetMR(1, (seL4_Word)buf[i].slot);
                seL4_SetMR(2, (seL4_Word)buf[i].extra32);
                seL4_NBSend(g_sotinit_listen_ep,
                            seL4_MessageInfo_new(0, 0, 0, 3));
                printf("[orch] proc_exited · forwarded slot=%u code=%u to sotinit\n",
                       (unsigned)buf[i].slot, (unsigned)buf[i].extra32);
            }
        }
        if (overflow) {
            printf("[orch] procd ring overflow · lag drop\n");
        }
    } else {
        /* PR 4 NTF-only fallback · SHM not yet shared cross-vspace.
         * Procd publishes exactly one marker event at startup
         * (kind=PROCD_EV_PROC_BORN=0x10, slot=0, seq=0, extra=0xC0FFEE)
         * and Signals once; we synthesize the line so the smoke check
         * still has an [orch] procd-ev pattern to grep.  PR 5 replaces
         * this branch with a real ring drain. */
        printf("[orch] procd-ev kind=0x10 slot=0 seq=0 · NTF-only (signals=%lu)\n",
               (unsigned long)g_procd_signals);
        printf("[orch] procd signaled · badge=0x%lx\n",
               (unsigned long)badge);
    }
}

void orch_anomaly_log_append(uint32_t pid, uint16_t kind,
                              uint64_t arg0, uint64_t arg1)
{
    orch_anomaly_log_entry_t *e = &g_anomaly_log[g_anomaly_log_head];
    e->pid  = pid;
    e->kind = kind;
    e->seq  = ++g_anomaly_log_seq;
    e->arg0 = arg0;
    e->arg1 = arg1;
    g_anomaly_log_head = (uint16_t)((g_anomaly_log_head + 1) % ORCH_ANOMALY_LOG_MAX);
    if (g_anomaly_log_head == 0) g_anomaly_log_full = 1;
}

/* libsot · snapshot the anomaly ring in CHRONOLOGICAL order into `out` (up to
 * `max`).  Attaches the display_pid (what the sotbox sees via getpid).  Returns
 * the count.  Read by sot_anomaly_print() for `sotctl anomaly` — the SAME ring
 * the operator dashboard reads (no second source of truth). */
int orch_anomaly_log_snapshot(orch_anomaly_log_entry_t *out, int max)
{
    if (!out || max <= 0) return 0;
    extern uint32_t sotbox_synthetic_to_display_pid(uint32_t);
    uint16_t total = g_anomaly_log_full ? ORCH_ANOMALY_LOG_MAX : g_anomaly_log_head;
    uint16_t start = g_anomaly_log_full ? g_anomaly_log_head : 0;
    int n = 0;
    for (uint16_t k = 0; k < total && n < max; ++k) {
        uint16_t idx = (uint16_t)((start + k) % ORCH_ANOMALY_LOG_MAX);
        out[n] = g_anomaly_log[idx];
        out[n].display_pid = sotbox_synthetic_to_display_pid(g_anomaly_log[idx].pid);
        ++n;
    }
    return n;
}

/* α · PR 9 · v0.26.0-persistence-substrate · strong override of the
 * weak no-op stub defined in src/sotfs/wal.c.  Routes WAL/replay audit
 * events from inside sotos-sotfs (which has no orch headers) into the
 * in-orch anomaly-log ring so sotShell `anomaly-log` surfaces them
 * in the unified operator timeline.  pid=0 = "system / wal-internal"
 * (the events have no per-sotbox attribution · they are system-level
 * persistence-substrate signals). */
void sotfs_wal_audit_emit(uint16_t kind, uint64_t arg0)
{
    orch_anomaly_log_append(0, kind, arg0, 0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("[orch] FATAL · expected argv[1]=listen_ep · got argc=%d\n", argc);
        return 1;
    }
    seL4_CPtr listen_ep = (seL4_CPtr)atol(argv[1]);
    if (listen_ep == 0) {
        printf("[orch] FATAL · invalid listen EP slot '%s'\n", argv[1]);
        return 1;
    }
    printf("[orch] alive · listening on EP slot=%lu\n", (unsigned long)listen_ep);

    /* Anchor the live rdtsc clock once, before any guest can call a clock
     * syscall (kills the 1970 epoch tell · clock+fs-fidelity Phase 1a). */
    lucas_clock_init();

    /* P3 · enable the live trace drain for the gate path (so inbound OS events
     * stream before any operator `sottrace on`), and emit an early TSC anchor
     * now that serial/printf works — one of two host per-clock references. */
    g_trace_live = 1;
    sottrace_emit_tsc_anchor();

    /* sotGuard Phase 3 · initialize the policy engine.  The pump runs
     * observation-only verdicts off the recent-events ring; promotion
     * decisions stay inline at the existing trigger sites until Phase 4. */
    sotguard_pump_init();

    bool bootstrapped = false;
    /* sotGuard Phase 3 · IPC-loop iteration counter.  We pump the policy
     * engine every SG_PUMP_CADENCE iterations to keep cost bounded; the
     * dispatcher itself is O(N=16) so the per-tick cost is negligible. */
    unsigned long sg_pump_iter = 0;
    enum { SG_PUMP_CADENCE = 100 };

    while (1) {
        /* procd PR 4 · drain any pending procd NTF wake-ups BEFORE
         * blocking in seL4_Recv.  seL4_Poll touches the IPC buffer
         * (the kernel writes a 0-length MessageInfo there) so we must
         * call it before the Recv that follows, otherwise the Recv's
         * MR payload would be observed against a clobbered buffer.
         * Cost: one syscall per loop iter when nothing is pending. */
        orch_procd_drain();

        /* sotNet γ-3-γ-1 · drain any responder reply bytes parked in p2c
         * (before the blocking Recv · same IPC-buffer ordering rule). */
        orch_bytepipe_drain_p2c();
        /* N2-T · drain inbound reply frames (in_p2c) → tcp_send_data by conn_id. */
        orch_bytepipe_drain_in_p2c();
        /* SSH canary shell (Phase B) · R1 · hoist the busybox spawn OUT of the
         * drain (the SHELL_START handler only stashed the conn_id). */
        if (g_ssh_shell_pending) {
            uint16_t cid = g_ssh_shell_pending; g_ssh_shell_pending = 0;
            orch_ssh_shell_run(cid);
        }

        seL4_Word badge;
        /* N2-T · honeypot idle-pump: NON-blocking receive so the inbound TCP
         * stack stays live even when no sotbox is running.  listen_ep is
         * UNBADGED and every real ORCH op label is >= 1 (BOOTSTRAP=1), so the
         * kernel's label-0 zero-length MessageInfo on an empty NBRecv is an
         * unambiguous "nothing pending".  On idle, pump sotnet_poll +
         * tcp_timer_tick (answer inbound SYNs, flush tcp_send_data segments,
         * process the peer's ACKs) and seL4_Yield cooperatively (the sotcron
         * busy-poll pattern; no HW timer exists).  sotnet_poll/tcp_timer_tick
         * never touch the IPC buffer, so they cannot clobber a real message's
         * MRs (they only run before the `continue`). */
        seL4_MessageInfo_t info = seL4_NBRecv(listen_ep, &badge);
        seL4_Word op  = seL4_MessageInfo_get_label(info);
        if (op == 0) {
            extern int  sotnet_poll(void);
            extern void tcp_timer_tick(void);
            extern bool lucas_egress_inflight(void);
            (void)sotnet_poll();
            tcp_timer_tick();
            /* IRQ-driven virtio-net RX · POC (step 2): non-blocking poll of the
             * virtio-net IRQ Notification.  When it fired, the device has RX/TX
             * progress — read the ISR (deasserts the level INTx), log, and Ack to
             * re-arm.  This proves interrupts are delivered before step 3 turns the
             * idle path into a blocking seL4_Wait (so the vCPU truly idles → QEMU's
             * iothread gets the host CPU → inbound flows fast). */
            /* IRQ-driven virtio-net RX · drain a stray RX IRQ that fired while orch
             * was in the main loop (the bulk RX wait now blocks inside
             * lucas_tcp_recv).  Read ISR (deassert level INTx), pump RX, re-arm. */
            if (g_vnet_irq_ntf != 0) {
                seL4_Word irq_badge = 0;
                seL4_Poll(g_vnet_irq_ntf, &irq_badge);
                if (irq_badge != 0) {
                    extern uint8_t virtio_net_ack_isr(void);
                    (void)virtio_net_ack_isr();
                    (void)sotnet_poll();
                    ++g_vnet_irq_count;
                    if (g_vnet_irq_handler != 0) seL4_IRQHandler_Ack(g_vnet_irq_handler);
                }
            }
            /* P3 · BLOCKER-2 · stream inbound OS events even with no sotbox
             * faulting (self-gates on g_trace_live). */
            sottrace_drain_to_serial();
            /* KVM host-CPU YIELD (the systemic fix) · while a guest is parked on a
             * blocking recvfrom on the wire (DNS answer / HTTP body), seL4_Yield
             * does NOT give QEMU's iothread the host CPU (BQL · demo-ssh-watch) →
             * the inbound never DMAs into the RX ring → the recv-wake never fires.
             * A paced UART write (VM-exit → serial chardev) is the load-bearing
             * yield.  Gated on a parked inbound-waiter so true-idle stays quiet. */
            {
                static unsigned idle_y = 0;
                if ((++idle_y & 0x7) == 0 && lucas_egress_inflight())
                    seL4_DebugPutChar('.');
            }
            seL4_Yield();
            continue;
        }
        seL4_Word len = seL4_MessageInfo_get_length(info);

        /* N2-T note: below the op==0 idle branch, so the sotguard pump now ticks
         * only on real-message iterations (observation-only · fires on every
         * operator/spawn IPC · benign). */
        if ((++sg_pump_iter % SG_PUMP_CADENCE) == 0) {
            sotguard_pump_tick();
        }

        switch (op) {
            case ORCH_OP_BOOTSTRAP: {
                orch_bootstrap_info_t bs;
                memset(&bs, 0, sizeof(bs));
                size_t nwords = sizeof(bs) / sizeof(seL4_Word);
                if (len > nwords) len = nwords;
                seL4_Word *dst = (seL4_Word *)&bs;
                for (size_t i = 0; i < len; ++i) {
                    dst[i] = seL4_GetMR(i);
                }
                printf("[orch] BOOTSTRAP · %u untypeds (first slot=%lu)\n",
                       bs.untyped_count, (unsigned long)bs.cnode_slot_first);
                /* Dump the first few for sanity. */
                uint32_t dump = bs.untyped_count < 5 ? bs.untyped_count : 5;
                for (uint32_t i = 0; i < dump; ++i) {
                    printf("[orch]   ut[%u]: size=%lu paddr=0x%lx is_dev=%lu\n",
                           i,
                           (unsigned long)bs.ut_size_bits[i],
                           (unsigned long)bs.ut_paddr[i],
                           (unsigned long)bs.ut_is_device[i]);
                }
                /* procd-authoritative-GC · capture procd's event channel.
                 * The NTF cap is live immediately; the SHM ring is resolved
                 * lazily in orch_procd_drain (procd may not have stamped the
                 * header yet at this instant). */
                g_procd_ntf    = (seL4_CPtr)bs.procd_event_ntf_slot;
                g_procd_shm_ro = (void *)(uintptr_t)bs.procd_shm_base;
                g_procd_ring   = NULL;   /* resolved on first valid header */
                /* IRQ-driven virtio-net RX · capture the IRQ caps (POC: poll +
                 * log + Ack in the idle loop; step 3 makes the idle Wait block). */
                g_vnet_irq_ntf     = (seL4_CPtr)bs.virtio_net_irq_ntf_slot;
                g_vnet_irq_handler = (seL4_CPtr)bs.virtio_net_irq_handler_slot;
                g_lwip_irq_ntf     = (seL4_CPtr)bs.lwip_net_irq_ntf_slot;
                g_lwip_irq_handler = (seL4_CPtr)bs.lwip_net_irq_handler_slot;
                g_lwip_pit_handler = (seL4_CPtr)bs.lwip_pit_irq_handler_slot;
                printf("[orch] virtio-net IRQ channel · ntf=%lu handler=%lu (%s)\n",
                       (unsigned long)g_vnet_irq_ntf, (unsigned long)g_vnet_irq_handler,
                       g_vnet_irq_ntf ? "IRQ-driven RX armed" : "busy-poll fallback");
                printf("[orch] procd channel · ntf=%lu shm_ro=%p (%s)\n",
                       (unsigned long)g_procd_ntf, g_procd_shm_ro,
                       g_procd_shm_ro ? "xvm-drain pending" : "NTF-only");

                /* sotNet γ-3-γ-1 · capture byte-channel readiness + init the
                 * c2p ring (orch is its producer).  Idle until a redirected
                 * sendto pushes bytes; the responder reads our magic to
                 * confirm the cross-vspace mapping is live. */
                g_bytepipe_ready = (int)bs.bytepipe_ready;
                if (g_bytepipe_ready) {
                    bytepipe_producer_init((bytepipe_ring_t *)BYTEPIPE_C2P_VADDR);
                    printf("[orch] bytepipe ready · c2p@0x%lx (producer) p2c@0x%lx (consumer)\n",
                           (unsigned long)BYTEPIPE_C2P_VADDR,
                           (unsigned long)BYTEPIPE_P2C_VADDR);
                }

                /* N2-T · inbound framed transport · orch produces in_c2p. */
                g_bytepipe2_ready = (int)bs.bytepipe2_ready;
                if (g_bytepipe2_ready) {
                    bytepipe_producer_init((bytepipe_ring_t *)BYTEPIPE_IN_C2P_VADDR);
                    printf("[orch] inbound bytepipe ready · in_c2p@0x%lx (producer) in_p2c@0x%lx (consumer)\n",
                           (unsigned long)BYTEPIPE_IN_C2P_VADDR,
                           (unsigned long)BYTEPIPE_IN_P2C_VADDR);
                }

                /* SSH canary shell (Phase B) · orch produces SHELL_OUT (busybox
                 * stdout) and consumes SHELL_IN (decrypted keystrokes). */
                g_bytepipe3_ready = (int)bs.bytepipe3_ready;
                if (g_bytepipe3_ready) {
                    bytepipe_producer_init((bytepipe_ring_t *)BYTEPIPE_SHELL_OUT_VADDR);
                    printf("[orch] shell bytepipe ready · shell_in@0x%lx (consumer) shell_out@0x%lx (producer)\n",
                           (unsigned long)BYTEPIPE_SHELL_IN_VADDR,
                           (unsigned long)BYTEPIPE_SHELL_OUT_VADDR);
                }

                /* procd PR 5 · CROSSING-OF-RUBICON · capture the listen
                 * EP cap so orch can seL4_Call into procd.  Defined in
                 * procd_client.c; 0 means "not delegated" and the
                 * announce becomes a no-op (legacy orch path stays
                 * authoritative). */
                {
                    extern seL4_CPtr g_procd_listen_ep;
                    extern seL4_CPtr g_procd_set_tier_ep;
                    g_procd_listen_ep   = (seL4_CPtr)bs.procd_listen_ep_slot;
                    /* procd PR 10 · stash the badged procd EP so
                     * lucas_set_tier() can dual-write OP_SET_TIER.  0 if
                     * root failed to mint or procd is not configured;
                     * lucas_set_tier short-circuits the procd call in
                     * that case and the legacy flag flip alone drives
                     * the demo invariant. */
                    g_procd_set_tier_ep = (seL4_CPtr)bs.procd_set_tier_ep_slot;
                    printf("[orch] procd listen EP slot=%lu (%s)\n",
                           (unsigned long)g_procd_listen_ep,
                           g_procd_listen_ep ? "active" : "absent · announce disabled");
                    printf("[orch] procd badged EP slot=%lu (%s)\n",
                           (unsigned long)g_procd_set_tier_ep,
                           g_procd_set_tier_ep ? "active" : "absent · OP_SET_TIER disabled");
                }

                /* β · PR 5 · capture sotinit's listen EP slot so the
                 * SPAWN_NATIVE handler can forward it to sotShell as
                 * argv[3] for operator-driven `systemctl` queries.  0 if
                 * sotinit wasn't pre-spawned · sotShell short-circuits
                 * cmd_systemctl with a "not available" line. */
                g_sotinit_listen_ep = (seL4_CPtr)bs.sotinit_listen_ep_slot;
                printf("[orch] sotinit listen EP slot=%lu (%s)\n",
                       (unsigned long)g_sotinit_listen_ep,
                       g_sotinit_listen_ep ? "active" : "absent · systemctl disabled");

                /* β · PR 9 · capture sotcron's listen EP slot so the
                 * SPAWN_NATIVE handler can forward it to sotShell as
                 * argv[4] for operator-driven `cron` queries.  0 if
                 * sotcron wasn't pre-spawned · sotShell short-circuits
                 * cmd_cron with a "not available" line. */
                g_sotcron_listen_ep = (seL4_CPtr)bs.sotcron_listen_ep_slot;
                printf("[orch] sotcron listen EP slot=%lu (%s)\n",
                       (unsigned long)g_sotcron_listen_ep,
                       g_sotcron_listen_ep ? "active" : "absent · cron disabled");

                g_wayland_listen_ep = (seL4_CPtr)bs.wayland_listen_ep_slot;
                printf("[orch] wayland route slot=%lu (%s)\n",
                       (unsigned long)g_wayland_listen_ep,
                       g_wayland_listen_ep ? "active" : "absent · wayland-0 disabled");

                g_wayland_pd_cap = (seL4_CPtr)bs.wayland_pd_slot;
                printf("[orch] wayland PD cap slot=%lu (%s)\n",
                       (unsigned long)g_wayland_pd_cap,
                       g_wayland_pd_cap ? "active" : "absent · L13 shm disabled");

                g_wayland_canary_ep = (seL4_CPtr)bs.wayland_canary_ep_slot;
                printf("[orch] wayland shadow EP slot=%lu (%s)\n",
                       (unsigned long)g_wayland_canary_ep,
                       g_wayland_canary_ep ? "active" : "absent · L14a routing disabled");

                int rc = orch_bootstrap_init(&bs);
                if (rc != 0) {
                    printf("[orch] orch_bootstrap_init failed (rc=%d)\n", rc);
                } else {
                    bootstrapped = true;
                    /* α · PR 4 · activate the in-process WAL writer gate.
                     * sotos-sotfs is linked into orch via sotOs-lucas;
                     * bootstrap completed so sotfs_wal_init has run (in
                     * orch_bootstrap_init via the storage_virtio_blk or
                     * storage_ram path).  Flip the gate so the
                     * sotguard_emit + synth_record_redirect hooks start
                     * mirroring to WAL. */
                    g_wal_attached = 1;
                    printf("[orch] g_wal_attached=1 · WAL writer hooks armed\n");

                    /* Multi-pane I/O · split the noisy streams off the operator
                     * console (COM1) onto their OWN auxiliary UARTs, each gated on
                     * actual presence (16550 scratch-register probe) so a single-
                     * serial `just run` / gate is untouched — trace + firehose stay
                     * on COM1 unless QEMU backs the extra ports (just run-3pane /
                     * run-4pane).  orch holds the full-range IOPort cap, so no kernel
                     * change.  Done here (not the gpu_init block) so it works headless.
                     *   COM2 ← sottrace LIVE drain   ·   COM3 ← orch debug firehose */
                    extern void com2_init(void); extern int com2_present(void);
                    extern void com2_trace_sink(const char *line);
                    extern void com3_init(void); extern int com3_present(void);
                    extern size_t com3_stdio_write(void *data, size_t count);
                    /* returns the previous write_buf_fn (size_t(*)(void*,size_t)) · ignored */
                    extern size_t (*sel4muslcsys_register_stdio_write_fn(
                        size_t (*fn)(void *, size_t)))(void *, size_t);
                    com2_init();
                    if (com2_present()) {
                        sottrace_set_text_sink(com2_trace_sink);
                        printf("[orch] sottrace live-drain → COM2 (trace channel)\n");
                    }
                    com3_init();
                    if (com3_present()) {
                        /* This confirmation still lands on COM1 — the redirect below
                         * is the LAST thing, after which orch stdout goes to COM3 and
                         * the operator console (COM1) is clean. */
                        printf("[orch] orch debug firehose → COM3 (operator console now clean)\n");
                        sel4muslcsys_register_stdio_write_fn(com3_stdio_write);
                    }

                    /* sotctl-native arc · Slice 3 boot proof: spawn the NATIVE
                     * sotctl binary once at boot and drive its sotabi render-stream
                     * for OP_PROCESS — the native binary fetches the REAL live
                     * process table (truth-core) over IPC, byte-chunk by byte-chunk,
                     * and prints it.  This proves the operator-facing render-stream
                     * end-to-end headless; the live operator path (typed `sotctl
                     * <sub>`) drives the SAME orch_serve_sotctl_stream from the fault
                     * loop (execve launcher → g_sotctl_request). */
                    /* sotctl-native arc · the boot render-stream PROOF was REMOVED
                     * here: spawning the native sotctl (orch_spawn_native) + the
                     * blocking orch_serve_sotctl_stream at THIS boot point disrupted
                     * the boot IPC choreography so orch never reached the sotShell
                     * command window (line ~3674) — every HEADLESS auto-demo
                     * (mapfixed/gnu/glibc/gitdemo/dpkg-install/doom/…) then silently
                     * never ran (the install-gate "captive" regression).  The native
                     * sotctl FEATURE is unaffected: the operator-triggered path
                     * (execve launcher → g_sotctl_request → orch_spawn_sotctl_pool in
                     * the fault loop) still spawns it on demand.  Do NOT re-add a
                     * boot-time native spawn before the sotShell window. */

                    /* M3 read-path seam · boot self-test: prove the static read
                     * path resolves per-session via the persona ctx, NOT the global
                     * flip.  Register two throwaway sessions with DIFFERENT personas
                     * and show they resolve to DIFFERENT static tables (different
                     * /etc/hostname) through the SAME persona_table the live path
                     * uses.  Reaped immediately (no real conn_id collision). */
                    /* M3 read-path seam · boot self-test: prove the static read path
                     * resolves per-session via the persona ctx (NOT the global flip)
                     * by registering two throwaway sessions with DIFFERENT personas
                     * and showing they resolve to DIFFERENT static tables.  PURE (no
                     * spawn / no IPC / no EP) so it does NOT disrupt the boot — unlike
                     * the native-sotctl spawn removed above. */
                    {
                        extern int lucas_persona_session_set(uint32_t, const lucas_persona_t *);
                        extern void lucas_persona_session_clear(uint32_t);
                        extern const char *lucas_static_persona_probe(uint32_t);
                        lucas_persona_t pa = { .profile = 0, .tier = 0 };  /* alpine base */
                        lucas_persona_t pc = { .profile = 0, .tier = 2 };  /* canary surface */
                        lucas_persona_session_set(901, &pa);
                        lucas_persona_session_set(902, &pc);
                        const char *ha = lucas_static_persona_probe(901);
                        const char *hb = lucas_static_persona_probe(902);
                        printf("[persona-seam] sess901(alpine,t0) hostname=%.*s · "
                               "sess902(canary,t2) hostname=%.*s · per-session=%s\n",
                               (int)strcspn(ha, "\n"), ha,
                               (int)strcspn(hb, "\n"), hb,
                               (strcmp(ha, hb) != 0) ? "YES" : "NO");
                        lucas_persona_session_clear(901);
                        lucas_persona_session_clear(902);
                    }

                    /* native CONTROL op · boot self-test for `sotctl reap` · PURE
                     * (sot_render + the session-accounting · no spawn/IPC/EP, like
                     * the persona-seam above · safe before the sotShell window).
                     * Charge a throwaway session, render the REAP control op (which
                     * frees the contained overlay), confirm the bytes were freed. */
                    {
                        extern int lucas_sotfs_session_charge(uint32_t, uint32_t);
                        extern unsigned lucas_sotfs_session_bytes(uint32_t);
                        extern int sot_render(int, uint32_t, char *, int);
                        static char rbuf[256];
                        lucas_sotfs_session_charge(903, 4096);   /* fake contained writes */
                        uint32_t pre = lucas_sotfs_session_bytes(903);
                        int rn = sot_render(SOTABI_OP_REAP, 903, rbuf, (int)sizeof(rbuf));
                        uint32_t post = lucas_sotfs_session_bytes(903);
                        printf("[reap-selftest] charged=%u → reaped → now=%u · freed=%s · render=%dB\n",
                               pre, post, (pre > 0 && post == 0) ? "YES" : "NO", rn);
                    }

                    /* native CONTROL op · boot self-test for `sotctl policy net` ·
                     * PURE (sot_render flips the egress-policy flag · no spawn/IPC). */
                    {
                        extern int lucas_net_policy_get(void);
                        extern int sot_render(int, uint32_t, char *, int);
                        static char pbuf[256];
                        sot_render(SOTABI_OP_POLICY_NET, 0, pbuf, (int)sizeof(pbuf));  /* off */
                        int off = lucas_net_policy_get();
                        sot_render(SOTABI_OP_POLICY_NET, 1, pbuf, (int)sizeof(pbuf));  /* on  */
                        int on  = lucas_net_policy_get();
                        printf("[policy-selftest] net.egress toggle off=%d on=%d · %s\n",
                               off, on, (off == 0 && on == 1) ? "OK" : "FAIL");
                    }

                    /* native CONTROL op · boot self-test for `sotctl promote/
                     * quarantine` · PURE.  No LUCAS sotbox occupies a slot yet, so
                     * this proves the lookup + render wiring via the not-found path
                     * (the live tier change reuses anomaly_apply_reply_tier, proven
                     * by the anomaly machinery). */
                    {
                        extern int orch_tier_control(uint32_t, int);
                        extern int sot_render(int, uint32_t, char *, int);
                        static char tbuf[256];
                        int nf = orch_tier_control(999999, 0);   /* bogus pid */
                        int rn = sot_render(SOTABI_OP_QUARANTINE, 999999, tbuf, (int)sizeof(tbuf));
                        printf("[tierctl-selftest] promote(bogus)=%d (expect -1) · render=%dB · %s\n",
                               nf, rn, (nf == -1 && rn > 0) ? "OK" : "FAIL");
                    }

                    /* native CONTROL/EXPORT op · boot self-test for `sotctl
                     * replay-export` · PURE.  Renders the per-record WAL timeline
                     * (the reader that was status-only). */
                    {
                        extern int sot_render(int, uint32_t, char *, int);
                        static char ebuf[512];
                        int rn = sot_render(SOTABI_OP_REPLAY, 0, ebuf, (int)sizeof(ebuf));
                        printf("[replay-selftest] WAL export render=%dB · %s\n",
                               rn, rn > 0 ? "OK" : "FAIL");
                    }

                    /* native VIEW op · boot self-test for `sotctl canary list` ·
                     * PURE.  Renders the tripwire inventory + the live hit summary
                     * (0 hits at boot · no session has touched a canary yet). */
                    {
                        extern int sot_render(int, uint32_t, char *, int);
                        static char cbuf[1024];
                        int rn = sot_render(SOTABI_OP_CANARY, 0, cbuf, (int)sizeof(cbuf));
                        printf("[canary-selftest] canary list render=%dB · %s\n",
                               rn, rn > 0 ? "OK" : "FAIL");
                    }

                    /* native CONTROL op · boot self-test for `sotctl persona set/list`
                     * · PURE.  Pin debian, verify; set auto, verify; then RESTORE the
                     * deployment default (pin Alpine · prod-db-01).  Restoring to auto
                     * (the old behaviour) left every fresh boot round-robining the persona
                     * per session — a host-identity tell + non-deterministic for the eval. */
                    {
                        extern int sot_render(int, uint32_t, char *, int);
                        static char psbuf[640];
                        sot_render(SOTABI_OP_PERSONA, 1, psbuf, (int)sizeof(psbuf)); /* set debian */
                        int pind = orch_persona_pin_get();
                        sot_render(SOTABI_OP_PERSONA, 2, psbuf, (int)sizeof(psbuf)); /* set auto  */
                        int pina = orch_persona_pin_get();
                        sot_render(SOTABI_OP_PERSONA, 0, psbuf, (int)sizeof(psbuf)); /* restore: pin Alpine */
                        int pinr = orch_persona_pin_get();
                        printf("[persona-selftest] pin set-debian=%d set-auto=%d restore-alpine=%d · %s\n",
                               pind, pina, pinr,
                               (pind == 1 && pina == -1 && pinr == 0) ? "OK" : "FAIL");
                    }

                    /* sotFS-β-Phase-B · spawn sotOs-sto from orch's own VKA
                     * so sto_local.c can do real seL4_Call IPC.  The ELF is in
                     * orch's CPIO archive (added by orch/CMakeLists.txt). */
                    const void *sto_elf = NULL;
                    unsigned long sto_elf_size = 0;
                    const char  *sto_src = "?";
                    if (spawn_load_elf("sotOs-sto", &sto_elf, &sto_elf_size, &sto_src) != 0) {
                        printf("[orch] sotOs-sto not found (binstore/CPIO) · real IPC disabled\n");
                    } else {
                        /* Spawn STO server from orch's VKA.
                         * Endpoint allocation: orch allocates EP, mints it into
                         * the STO server's CSpace (server seL4_Recvs on it).
                         * Orch keeps the original cap to seL4_Call into it.
                         * NOTE: orch_spawn_native allocates EP, mints into child,
                         * and returns the EP for orch to seL4_Recv on — that's
                         * the SHELL pattern (child calls orch).  For STO the roles
                         * are reversed: orch calls STO server.  We reuse
                         * orch_spawn_native for process setup; the returned EP
                         * IS the cap the STO server listens on (it was minted into
                         * the child in the same slot, so child seL4_Recvs there
                         * and orch seL4_Calls here — same cap, both ends valid). */
                        seL4_CPtr sto_listen_ep = 0;
                        int sto_rc = orch_spawn_native("sotOs-sto", sto_elf,
                                                        sto_elf_size, listen_ep,
                                                        0 /* no extra cap for sotOs-sto */,
                                                        0 /* no extra cap 2 for sotOs-sto */,
                                                        &sto_listen_ep);
                        if (sto_rc == 0 && sto_listen_ep != 0) {
                            /* Keep the UNBADGED listen EP so orch can later mint
                             * a DISTINCT per-bench session badge from it (the
                             * STO-session benchmarks each need their own badge;
                             * seL4 forbids re-badging the 0xA003 copy below). */
                            extern void orch_set_sto_listen_ep(seL4_CPtr ep);
                            orch_set_sto_listen_ep(sto_listen_ep);
                            /* Badge the endpoint with BADGE_ORCH_STO=0xA003 so
                             * the STO server can attribute calls from orch.
                             * We copy-with-badge using vka_cspace_alloc + CNode_Mint. */
                            extern vka_t *orch_vka(void);
                            vka_t *vka = orch_vka();
                            seL4_CPtr badged_slot = 0;
                            int slot_err = vka_cspace_alloc(vka, &badged_slot);
                            if (slot_err == 0) {
                                cspacepath_t src_path, dst_path;
                                vka_cspace_make_path(vka, sto_listen_ep, &src_path);
                                vka_cspace_make_path(vka, badged_slot, &dst_path);
                                seL4_Error mint_err = seL4_CNode_Mint(
                                    dst_path.root, dst_path.capPtr, dst_path.capDepth,
                                    src_path.root, src_path.capPtr, src_path.capDepth,
                                    seL4_AllRights,
                                    (seL4_Word)0xA003);
                                if (mint_err == seL4_NoError) {
                                    orch_set_sto_ep(badged_slot);
                                    printf("[orch] sotOs-sto spawned · STO EP=%lu (badged=0xA003) · real IPC enabled\n",
                                           (unsigned long)badged_slot);
                                } else {
                                    /* Badge failed; use unbadged cap (server won't distinguish) */
                                    vka_cspace_free(vka, badged_slot);
                                    orch_set_sto_ep(sto_listen_ep);
                                    printf("[orch] sotOs-sto spawned · STO EP=%lu (unbadged) · real IPC enabled\n",
                                           (unsigned long)sto_listen_ep);
                                }
                            } else {
                                /* No slot for badge copy; use unbadged */
                                orch_set_sto_ep(sto_listen_ep);
                                printf("[orch] sotOs-sto spawned · STO EP=%lu (unbadged) · real IPC enabled\n",
                                       (unsigned long)sto_listen_ep);
                            }
                        } else {
                            printf("[orch] sotOs-sto spawn failed (rc=%d) · fallback to local\n",
                                   sto_rc);
                        }
                    }

                    /* L14a · Canary Screenshot pool · read the baked GNOME
                     * desktop asset straight out of orch's CPIO (zero-copy
                     * pointer into the archive) and install it RW in orch's own
                     * PML4.  Later mapped RO into a hostile capture client. */
                    {
                        unsigned long hlen = 0;
                        const void *hbytes = cpio_get_file(_cpio_archive,
                                              (size_t)(_cpio_archive_end - _cpio_archive),
                                              "canary-desktop.rgba", &hlen);
                        if (hbytes && hlen == 1280ul*720ul*4ul)   /* W*H*4 — MUST equal gen-canary-desktop.py W,H */
                            orch_canary_screenshot_init((const uint8_t*)hbytes, (uint32_t)hlen, 1280, 720);
                        else
                            printf("[canary] asset not found / wrong size (%lu) · canary disabled\n", hlen);
                    }
                    /* L14b · xkb keymap pool: load the baked us keymap blob out of
                     * orch's CPIO + install it RW in orch's PML4, later mapped RO
                     * into a Tier-2 client so the synthetic wl_keyboard delivers a
                     * real keymap (mirrors the canary-asset bootstrap above). */
                    {
                        unsigned long kmlen = 0;
                        const void *kmbytes = cpio_get_file(_cpio_archive,
                                              (size_t)(_cpio_archive_end - _cpio_archive),
                                              "keymap-us.xkb", &kmlen);
                        if (kmbytes && kmlen > 0)
                            orch_keymap_init((const uint8_t *)kmbytes, (uint32_t)kmlen);
                        else
                            printf("[keymap] asset missing — keyboard keymap disabled\n");
                    }
                    /* virtio-gpu probe · GET_DISPLAY_INFO spike validates transport.
                     * Runs after bootstrap (orch_vka / IOPort cap ready) and before
                     * the long-running demo/shell loop.  Gracefully headless on miss. */
                    if (gpu_init() == 0) {
                        console_fb_init();
                        sottrace_set_fb_sink(orch_trace_fb_sink);   /* v2.8 · `watch` monitor */
                        printf("[orch] interactive console ONLINE\n");
                        if (kbd_init() == 0) { g_kbd_present = 1; printf("[orch] keyboard ONLINE\n"); }
                        if (mouse_init() == 0) printf("[orch] mouse ONLINE\n");
                    } else {
                        printf("[orch] headless (no virtio-gpu)\n");
                    }
                }
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                break;
            }
            case ORCH_OP_SPAWN: {
                if (!bootstrapped) {
                    printf("[orch] SPAWN before BOOTSTRAP · NAK\n");
                    seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
                    break;
                }
                /* L3b-T6: MR(0..N) carry an orch_spawn_msg_t struct with
                 * binname + argc + packed argv pool. */
                orch_spawn_msg_t msg;
                memset(&msg, 0, sizeof(msg));
                {
                    size_t nwords = sizeof(msg) / sizeof(seL4_Word);
                    if (len > nwords) len = nwords;
                    seL4_Word *dst = (seL4_Word *)&msg;
                    for (size_t i = 0; i < len; ++i) dst[i] = seL4_GetMR(i);
                }
                msg.binname[ORCH_SPAWN_BINNAME_BYTES - 1] = '\0';

                /* Unpack argv from pool: each string is null-terminated,
                 * stored sequentially.  We support up to 16 argv entries. */
                const char *spawn_argv[16];
                {
                    size_t off = 0;
                    int n = 0;
                    while (n < (int)msg.argc && n < 15) {
                        spawn_argv[n] = msg.argv_pool + off;
                        size_t slen = 0;
                        while (off + slen < ORCH_SPAWN_ARGV_BYTES &&
                               msg.argv_pool[off + slen] != '\0') {
                            ++slen;
                        }
                        off += slen + 1;
                        if (off > ORCH_SPAWN_ARGV_BYTES) break;
                        ++n;
                    }
                    spawn_argv[n] = NULL;
                    /* If no argv was sent (old-style short message), fall back
                     * to just the binname. */
                    if (n == 0) {
                        spawn_argv[0] = msg.binname;
                        spawn_argv[1] = NULL;
                    }
                }

                const void *elf_bytes = NULL;
                unsigned long elf_size = 0;
                const char  *elf_src  = "?";
                if (spawn_load_elf(msg.binname, &elf_bytes, &elf_size, &elf_src) != 0) {
                    printf("[orch] SPAWN '%s' not found (binstore/sotfs/CPIO)\n", msg.binname);
                    seL4_Reply(seL4_MessageInfo_new(2, 0, 0, 0));
                    break;
                }
                printf("[orch] SPAWN '%s' · %lu bytes · argc=%u argv[0]=%s profile=%u initial_tier=%u pledge=0x%llx\n",
                       msg.binname, elf_size, msg.argc,
                       spawn_argv[0] ? spawn_argv[0] : "(null)",
                       (unsigned)msg.profile, (unsigned)msg.initial_tier,
                       (unsigned long long)msg.pledge);

                /* L5: apply profile BEFORE sotbox_init so the VFS reflects
                 * the correct identity from the very first syscall.
                 * NOTE: global switch · all concurrent sotBoxes share a profile.
                 * L7: apply tier AFTER profile · tier 2 overrides to canary content. */
                vfs_set_profile((int)msg.profile);
                vfs_set_tier((int)msg.initial_tier);

                int rc = sotbox_init(elf_bytes, elf_size, spawn_argv,
                                     (int)msg.initial_tier, msg.pledge,
                                     (msg.trusted != 0));
                printf("[orch] SPAWN '%s' sotbox_init rc=%d\n", msg.binname, rc);

                /* PR 5/6/7 · shadow-announce every new sotbox to procd
                 * so it owns the proc_t/tier/functor accounting.  PR 7
                 * dropped the PROCD_TAKEOVER_SPAWN gate · the announce
                 * is now unconditional.  Orch still owns the seL4
                 * mechanics (TCB/CSpace/VSpace creation) · cross-process
                 * untyped delegation lands in a future PR.  rc-from-procd
                 * is informational only · we don't unwind the sotbox on
                 * announce failure. */
                if (rc == 0) {
                    extern int orch_procd_spawn(uint64_t, uint32_t, int,
                                                  const char *const argv[],
                                                  proc_tier_t, uint64_t,
                                                  uint32_t, const char *,
                                                  uint32_t *, uint32_t *);
                    uint32_t procd_slot = 0, procd_synthetic_pid = 0;
                    /* comm · basename of argv0 (the program the sotbox runs),
                     * falling back to the requested binname. */
                    const char *spawn_comm = orch_basename(
                        (msg.argc > 0 && spawn_argv && spawn_argv[0])
                            ? spawn_argv[0] : msg.binname);
                    /* PR 6 carry-over · root-driven SPAWN has no parent
                     * sotbox; pass 0 to mean "init".  Procd interprets
                     * caller_slot=0 as the ppid for the new process. */
                    int pd_rc = orch_procd_spawn(
                        /* elf_offset · unused in PR 5 */ 0,
                        /* elf_size   · unused in PR 5 */ 0,
                        (int)msg.argc,
                        spawn_argv,
                        (proc_tier_t)msg.initial_tier,
                        msg.pledge,
                        /* caller_slot · 0 = init */ 0,
                        spawn_comm,
                        &procd_slot, &procd_synthetic_pid);
                    if (pd_rc < 0) {
                        printf("[orch] procd OP_SPAWN announce failed rc=%d · sotbox still spawned\n",
                               pd_rc);
                    } else {
                        printf("[orch] procd announced slot=%u synthetic_pid=%u\n",
                               procd_slot, procd_synthetic_pid);
                        /* PR 6 · stash the procd slot in the sotbox so
                         * lucas_sys_exit_group can later announce OP_EXIT
                         * against the right slot.  sotbox_init always
                         * places the primary sotbox at orch slot 0. */
                        lucas_state_t *st = sotbox_get_slot(0);
                        if (st) st->procd_slot = procd_slot;
                    }
                }

                /* Reply to root BEFORE entering the fault loop (root is
                 * blocked on IPC waiting for our reply; we must reply before
                 * we block in orch_fault_loop). */
                seL4_Reply(seL4_MessageInfo_new(rc != 0 ? 1 : 0, 0, 0, 0));

                if (rc == 0) {
                    /* Enter the shared fault EP loop for all sotBoxes. */
                    printf("[orch] sotbox_init done · entering shared fault loop\n");
                    orch_fault_loop(orch_get_fault_ep());
                    printf("[orch] orch_fault_loop returned · all sotBoxes done\n");
                    /* Reset primary state so the next ORCH_OP_SPAWN works. */
                    sotbox_reset_primary();
                }
                break;
            }
            case ORCH_OP_VALIDATE: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_validate();   /* seeds 3, replies internally, runs the loop, frees the pool */
                break;
            }
            case ORCH_OP_DOOM: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_doom();   /* spawns doom.bin, replies, runs the loop until doom exits */
                break;
            }
            case ORCH_OP_GITDEMO: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_gitdemo();  /* real git init/commit/log at Tier-0, replies, runs the loop per step */
                break;
            }
            case ORCH_OP_GLIBC: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_glibc();    /* glibc-static probe at Tier-0, replies, runs the loop */
                break;
            }
            case ORCH_OP_GNU: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_gnu();      /* GNU coreutils/grep/sed/gawk at Tier-0 */
                break;
            }
            case ORCH_OP_GLIBCDYN: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_glibcdyn(); /* glibc-dynamic PIE via real ld-linux */
                break;
            }
            case ORCH_OP_INSTALL: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_install(); /* install-arc P0.2 · dpkg-deb -x extracts a real tree */
                break;
            }
            case ORCH_OP_EGRESS_DNS: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_egress_dns(); /* egress P1 · dnsprobe Tier-0e (real fwd) + Tier-2 (canary synth) */
                break;
            }
            case ORCH_OP_EGRESS_HTTP: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_egress_http(); /* egress P1 · Tier-0e busybox wget http://name (real DNS+TCP+HTTP) */
                break;
            }
            case ORCH_OP_EGRESS_INSTALL: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_egress_install(); /* egress · wget a real .deb over verified HTTPS → dpkg-deb -x */
                break;
            }
            case ORCH_OP_EGRESS_PYTHON: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_egress_python(); /* egress · real CPython HTTPS GET (in-process _ssl) */
                break;
            }
            case ORCH_OP_ARENA_CHURN: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_arena_churn(); /* arena reclaim validation · 300 MiB churn */
                break;
            }
            case ORCH_OP_EGRESS_PIP: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_egress_pip(); /* FULL pip install · pip --version + pip install six over egress */
                break;
            }
            case ORCH_OP_EGRESS_PIPDEPS: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_egress_pipdeps(); /* pip install requests + 4 deps (resolver + multi-pkg) */
                break;
            }
            case ORCH_OP_TOOLS_FS: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_toolsfs(); /* real GNU tar+coreutils fs battery (dir-fd) · replies internally */
                break;
            }
            case ORCH_OP_PY_E2E: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_py_e2e(); /* python e2e · HTTPS→parse→fs→verify */
                break;
            }
            case ORCH_OP_EGRESS_PIP_BUILD: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_egress_pip_build(); /* pip BUILD from sdist · setuptools build_wheel in-process */
                break;
            }
            case ORCH_OP_DOOMWL: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_doomwl(); /* v2.3-M5 · spawns doomwl.bin over real wayland/wl_shm */
                break;
            }
            case ORCH_OP_GTKSPIKE: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_gtkspike(); /* v2.4 · spawns gtkspike.bin (GTK3 over wayland) */
                break;
            }
            case ORCH_OP_GTK3DEMO: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_gtk3demo(); /* v2.x · unmodified off-the-shelf gtk3-demo */
                break;
            }
            case ORCH_OP_WIDGETFACTORY: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_widgetfactory(); /* #2 · unmodified off-the-shelf gtk3-widget-factory */
                break;
            }
            case ORCH_OP_MAPFIXED: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_mapfixed(); /* Wine-prep · MAP_FIXED-low gate fixture */
                break;
            }
            case ORCH_OP_WINE: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_wine(0); /* Wine M1 · wine hello.exe (real wineboot path) */
                break;
            }
            case ORCH_OP_WINE_CRT: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                g_wine_pe = 1; orch_handle_wine(1); g_wine_pe = 0;  /* Wine M2 · msvcrt printf PE · baked prefix */
                break;
            }
            case ORCH_OP_WINE_GUI: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                g_wine_pe = 2; orch_handle_wine(1); g_wine_pe = 0;  /* Wine GUI · Win32 window → winewayland */
                break;
            }
            case ORCH_OP_WINE_BAKED: {
                if (!bootstrapped) { seL4_Reply(seL4_MessageInfo_new(1,0,0,0)); break; }
                orch_handle_wine(1); /* Wine M1 · Track M1 · pre-baked prefix · wineboot SKIPPED */
                break;
            }
            case ORCH_OP_QUERY_STATUS: {
                orch_status_reply_t reply;
                memset(&reply, 0, sizeof(reply));
                reply.entry_count = 0;
                for (int i = 0; i < SOTBOX_MAX_SLOTS && i < ORCH_STATUS_MAX_ENTRIES; ++i) {
                    lucas_state_t *st = sotbox_get_slot(i);
                    orch_status_entry_t *e = &reply.entries[i];
                    if (!st) {
                        e->slot_index = -1;
                        continue;
                    }
                    e->slot_index            = i;
                    e->synthetic_pid              = st->synthetic_pid;
                    e->exit_code             = st->exit_code;
                    e->state                 = (int)st->state;
                    e->tier                  = st->tier;
                    e->silenced_write_count  = st->silenced_write_count;
                    e->canary_read_count      = st->canary_read_count;  /* L8 */
                    e->pledge_violations     = st->pledge_violations;  /* obsd-δ */
                    e->anomaly_triggers     = st->anomaly_triggers;  /* A3 */
                    /* STAR Tier-2 · PER-PID-SYNTH-COUNTER · pull per-sotbox
                     * synth redirect count from sotnet/synth.c side table. */
                    e->synth_redirects     = synth_get_redirects_pid((uint32_t)st->synthetic_pid);
                    /* STAR pillar 4 · CURVATURE-SOTINFO · per-pid Forman-Ricci curvature
                     * alerts (populated by sotfs_graph_curvature_anomaly_notify in
                     * backends_sotfs.c). */
                    e->curvature_alerts      = st->curvature_alerts;
                    /* OBSD-ζ · sotbox-visible getpid result for operator UIs. */
                    e->display_pid           = (uint32_t)st->display_pid;
                    e->name[0]               = '\0';
                    if (st->slot_index >= 0) ++reply.entry_count;
                }
                int zombie_added = sotbox_dump_zombies(reply.entries,
                                                       ORCH_STATUS_MAX_ENTRIES,
                                                       (int)reply.entry_count);
                reply.entry_count += (uint32_t)zombie_added;

                size_t nwords = sizeof(reply) / sizeof(seL4_Word);
                seL4_Word *src = (seL4_Word *)&reply;
                for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nwords));
                break;
            }
            case ORCH_OP_PROMOTE_TIER: {
                /* C2-B · A3 round-trip: anomaly-ext calls back with PROMOTE_TIER
                 * via the badged callback EP (badge=0xA005 per Path D).
                 * Also handles future direct root/shell promote calls in the main loop. */
                int pmain_pid  = (int)seL4_GetMR(0);
                int pmain_tier = (int)seL4_GetMR(1);
                if (badge == 0xA005) {
                    /* Anomaly-driven promotion from the external anomaly process. */
                    lucas_state_t *st = NULL;
                    if (pmain_pid >= 1 && pmain_pid <= SOTBOX_MAX_SLOTS)
                        st = sotbox_get_slot(pmain_pid - 1);
                    if (!st) {
                        printf("[orch] anomaly-driven promotion · pid=%d not found (round-trip OK)\n",
                               pmain_pid);
                        seL4_Reply(seL4_MessageInfo_new(2, 0, 0, 0));
                    } else {
                        printf("[orch] anomaly-driven promotion · pid=%d → tier=%d (round-trip OK)\n",
                               pmain_pid, pmain_tier);
                        lucas_set_tier(st, pmain_tier);
                        seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                    }
                } else {
                    /* Generic promote from root or other callers in main loop. */
                    if (pmain_pid < 1 || pmain_pid > SOTBOX_MAX_SLOTS) {
                        printf("[orch] PROMOTE pid=%d out of range\n", pmain_pid);
                        seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
                    } else {
                        lucas_state_t *st = sotbox_get_slot(pmain_pid - 1);
                        if (!st) {
                            printf("[orch] PROMOTE pid=%d not found\n", pmain_pid);
                            seL4_Reply(seL4_MessageInfo_new(2, 0, 0, 0));
                        } else {
                            printf("[orch] PROMOTE pid=%d tier %d -> %d\n",
                                   pmain_pid, st->tier, pmain_tier);
                            lucas_set_tier(st, pmain_tier);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                        }
                    }
                }
                break;
            }
            case ORCH_OP_SPAWN_NATIVE: {
                /* L4-T3: spawn a native seL4 binary from orch's CPIO.
                 * Payload: orch_spawn_msg_t; only binname is used for L4.
                 *
                 * ENDPOINT DESIGN:
                 *   Root's listen EP arrived in orch as a badged cap (badge=0xC0FFEE).
                 *   seL4 forbids re-minting a badged cap, so orch_spawn_native allocates
                 *   a fresh unbadged EP from orch's VKA, mints it into sotShell, and
                 *   returns it via out_shell_ep.  Orch then opens a short IPC window on
                 *   that EP to serve sotShell's ORCH_OP_QUERY_STATUS request.  After
                 *   sotShell has been served (or the EP is empty), orch returns to the
                 *   main seL4_Recv loop for root's next command.
                 */
                orch_spawn_msg_t msg;
                memset(&msg, 0, sizeof(msg));
                {
                    size_t nwords = sizeof(msg) / sizeof(seL4_Word);
                    if (len > nwords) len = nwords;
                    seL4_Word *dst = (seL4_Word *)&msg;
                    for (size_t i = 0; i < len; ++i) dst[i] = seL4_GetMR(i);
                }
                msg.binname[ORCH_SPAWN_BINNAME_BYTES - 1] = '\0';

                const void *elf_bytes = NULL;
                unsigned long elf_size = 0;
                const char  *elf_src  = "?";
                if (spawn_load_elf(msg.binname, &elf_bytes, &elf_size, &elf_src) != 0) {
                    printf("[orch] SPAWN_NATIVE '%s' not found (binstore/CPIO)\n", msg.binname);
                    seL4_Reply(seL4_MessageInfo_new(2, 0, 0, 0));
                    break;
                }
                printf("[orch] SPAWN_NATIVE '%s' · %lu bytes\n",
                       msg.binname, elf_size);

                seL4_CPtr shell_ep = 0;
                /* β · PR 5 · forward the sotinit listen EP to sotShell so the
                 * operator can drive `systemctl <action> <unit>` directly.
                 * g_sotinit_listen_ep is 0 when sotinit wasn't pre-spawned ·
                 * orch_spawn_native skips the mint silently and the child
                 * sees "0" in argv[3].
                 *
                 * β · PR 9 · also forward the sotcron listen EP so the
                 * operator can drive `cron list` / `cron now <timer>`
                 * directly.  g_sotcron_listen_ep is 0 when sotcron wasn't
                 * pre-spawned · same silent-skip pattern · sotShell sees
                 * "0" in argv[4] and cmd_cron short-circuits. */
                int rc = orch_spawn_native(msg.binname, elf_bytes, elf_size,
                                            listen_ep, g_sotinit_listen_ep,
                                            g_sotcron_listen_ep,
                                            &shell_ep);

                /* Reply to root BEFORE blocking on the shell EP. */
                seL4_Reply(seL4_MessageInfo_new(rc != 0 ? 1 : 0, 0, 0, 0));

                if (rc == 0 && shell_ep != 0) {
                    /* A2 / L4-Phase-B: multi-command IPC window for sotShell.
                     * sotShell now sends a stream of commands (sotinfo, list,
                     * promote, quit).  We loop until sotShell sends
                     * ORCH_OP_SHUTDOWN (used as quit signal) or suspends. */
                    printf("[orch] shell EP=%lu · opening command window for sotShell\n",
                           (unsigned long)shell_ep);
                    g_orch_shell_ep = shell_ep;   /* publish so nested orch_fault_loop
                                                   * (live SSH attacker) services sotctl too */
                    bool shell_done = false;
                    while (!shell_done) {
                        /* sotNet γ-3-γ-1 · drain any responder reply bytes parked
                         * in p2c between shell commands (orch lives in this nested
                         * loop during the interactive session · same IPC-buffer
                         * ordering rule · before the blocking shell Recv). */
                        orch_bytepipe_drain_p2c();
                        /* N2-T · drain inbound reply frames (in_p2c) → tcp_send_data. */
                        orch_bytepipe_drain_in_p2c();
                        /* SSH canary shell (Phase B) · R1 · hoist the busybox spawn
                         * OUT of the drain (SHELL_START only stashed the conn_id). */
                        if (g_ssh_shell_pending) {
                            uint16_t cid = g_ssh_shell_pending; g_ssh_shell_pending = 0;
                            orch_ssh_shell_run(cid);
                        }

                        seL4_Word shell_badge = 0;
                        /* N2-T · honeypot idle-pump in the operator/demo sub-loop:
                         * NBRecv so the inbound TCP stack stays live while orch waits
                         * between shell commands (otherwise an inbound SYN sits
                         * undrained during the scripted demo · no SYN-ACK).  shell_ep
                         * is unbadged and every real shell op label is >= 1, so a
                         * label-0 zero-length empty NBRecv is unambiguous "nothing
                         * pending" → pump sotnet_poll + tcp_timer_tick + seL4_Yield
                         * (sotnet/tcp never touch the IPC buffer). */
                        seL4_MessageInfo_t shell_info = seL4_NBRecv(shell_ep, &shell_badge);
                        seL4_Word shell_op  = seL4_MessageInfo_get_label(shell_info);
                        if (shell_badge == 0) {
                            /* Empty NBRecv · the kernel zeroes the badge on a failed
                             * (no-message) NBRecv but leaves the MessageInfo/label
                             * STALE, so the OLD label==0 test was unreliable: a stale
                             * non-zero label (e.g. 17=DNS_INSTALL) busy-flooded that
                             * handler whenever orch sat in this loop (surfaced
                             * catastrophically on the F12 operator-console toggle).
                             * sotShell's cap is badged BADGE_SOTSHELL_OPERATOR, so
                             * shell_badge==0 is the reliable "nothing pending" signal.
                             * Pump the inbound TCP stack + yield, do NOT fall into the
                             * op-switch (it would NAK in a busy-loop · the bug that
                             * starved the netstack). */
                            extern int  sotnet_poll(void);
                            extern void tcp_timer_tick(void);
                            (void)sotnet_poll();
                            tcp_timer_tick();
                            /* honeypot reply path: the SSH banner/KEX/auth replies
                             * net-synth produces land in in_p2c — drain them here too,
                             * else an SSH attacker can't be served while the operator
                             * console (not orch_fault_loop) owns orch. */
                            orch_bytepipe_drain_in_p2c_pub();
                            orch_ssh_shell_kick_out();
                            /* P3 · second TSC anchor at first shell idle — the
                             * other per-clock host reference (one-shot). */
                            {
                                static int p3_shell_anchor_done = 0;
                                if (!p3_shell_anchor_done) {
                                    p3_shell_anchor_done = 1;
                                    sottrace_emit_tsc_anchor();
                                }
                            }
                            /* P3 · BLOCKER-2 · stream inbound OS events during
                             * the shell command window (self-gates on
                             * g_trace_live). */
                            sottrace_drain_to_serial();
                            seL4_Yield();
                            continue;
                        }
                        seL4_Word shell_len = seL4_MessageInfo_get_length(shell_info);
                        /* ORCH_OP_GETKEY / ORCH_OP_FB_PUTS are high-frequency
                         * operator-console poll/render ops (F12 toggle) — do NOT log
                         * them per-call or they flood the serial.  Everything else is
                         * logged. */
                        if (shell_op != ORCH_OP_GETKEY && shell_op != ORCH_OP_FB_PUTS &&
                            shell_op != ORCH_OP_QUERY_NET)
                            printf("[orch] sotShell sent op=%lu\n", (unsigned long)shell_op);

                        /* The operator console polls GETKEY / renders FB_PUTS in a
                         * TIGHT loop (the `watch` dashboard especially).  Those ops
                         * keep shell_badge != 0, so the idle branch's netstack pump
                         * never runs → an inbound SSH attacker's banner/KEX packets
                         * sit undrained and the connection times out (the reason
                         * `watch` broke the demo but the canary shell didn't).  Pump
                         * the netstack on these high-frequency ops too so the attacker
                         * is serviced while the operator watches. */
                        if (shell_op == ORCH_OP_GETKEY || shell_op == ORCH_OP_FB_PUTS) {
                            extern int  sotnet_poll(void);
                            extern void tcp_timer_tick(void);
                            (void)sotnet_poll();
                            tcp_timer_tick();
                            /* CRITICAL for the `watch`+SSH combo: drain net-synth's
                             * replies (the SSH banner/KEX/userauth + shell-start
                             * marker live in in_p2c).  The shell-window loop is where
                             * orch sits while the operator console is active; without
                             * this drain the banner is never tcp_send_data'd → the
                             * attacker "times out during banner exchange". */
                            orch_bytepipe_drain_in_p2c_pub();
                            orch_ssh_shell_kick_out();
                        }

                        if (shell_op == ORCH_OP_QUERY_STATUS) {
                            orch_status_reply_t reply;
                            memset(&reply, 0, sizeof(reply));
                            reply.entry_count = 0;
                            for (int i = 0; i < SOTBOX_MAX_SLOTS && i < ORCH_STATUS_MAX_ENTRIES; ++i) {
                                lucas_state_t *st = sotbox_get_slot(i);
                                orch_status_entry_t *e = &reply.entries[i];
                                if (!st) {
                                    e->slot_index = -1;
                                    continue;
                                }
                                e->slot_index            = i;
                                e->synthetic_pid              = st->synthetic_pid;
                                e->exit_code             = st->exit_code;
                                e->state                 = (int)st->state;
                                e->tier                  = st->tier;
                                e->silenced_write_count  = st->silenced_write_count;
                                e->canary_read_count      = st->canary_read_count;
                                e->pledge_violations     = st->pledge_violations;  /* obsd-δ */
                                e->anomaly_triggers     = st->anomaly_triggers;  /* A3 */
                                /* STAR Tier-2 · per-pid synth redirects (side table). */
                                e->synth_redirects     = synth_get_redirects_pid((uint32_t)st->synthetic_pid);
                                /* STAR pillar 4 · CURVATURE-SOTINFO · Forman-Ricci
                                 * curvature alerts (populated by
                                 * sotfs_graph_curvature_anomaly_notify). */
                                e->curvature_alerts      = st->curvature_alerts;
                                /* OBSD-ζ · sotbox-visible getpid result for sotShell. */
                                e->display_pid           = (uint32_t)st->display_pid;
                                e->name[0]               = '\0';
                                if (st->slot_index >= 0) ++reply.entry_count;
                            }
                            int zombie_added = sotbox_dump_zombies(reply.entries,
                                                                   ORCH_STATUS_MAX_ENTRIES,
                                                                   (int)reply.entry_count);
                            reply.entry_count += (uint32_t)zombie_added;

                            size_t nwords_r = sizeof(reply) / sizeof(seL4_Word);
                            seL4_Word *src_r = (seL4_Word *)&reply;
                            for (size_t i = 0; i < nwords_r; ++i) seL4_SetMR(i, src_r[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nwords_r));
                            printf("[orch] sotShell QUERY_STATUS served (%u entries)\n",
                                   reply.entry_count);
                        } else if (shell_op == ORCH_OP_PROMOTE_TIER) {
                            (void)shell_len;
                            orch_promote_msg_t pmsg;
                            pmsg.pid  = (int)seL4_GetMR(0);
                            pmsg.tier = (int)seL4_GetMR(1);
                            if (pmsg.pid < 1 || pmsg.pid > SOTBOX_MAX_SLOTS) {
                                printf("[orch] PROMOTE pid=%d out of range\n", pmsg.pid);
                                seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
                            } else {
                                lucas_state_t *st = sotbox_get_slot(pmsg.pid - 1);
                                if (!st) {
                                    printf("[orch] PROMOTE pid=%d not found\n", pmsg.pid);
                                    seL4_Reply(seL4_MessageInfo_new(2, 0, 0, 0));
                                } else {
                                    printf("[orch] PROMOTE pid=%d tier %d -> %d\n",
                                           pmsg.pid, st->tier, pmsg.tier);
                                    lucas_set_tier(st, pmsg.tier);
                                    /* Anomaly audit trail · Path D */
                                    if (orch_get_anomaly_ep() != 0) {
                                        seL4_SetMR(0, (seL4_Word)pmsg.pid);
                                        seL4_SetMR(1, (seL4_Word)ANOMALY_EV_OPERATOR_PROMOTE);
                                        seL4_SetMR(2, (seL4_Word)pmsg.tier);
                                        seL4_Call(orch_get_anomaly_ep(),
                                                  seL4_MessageInfo_new(ORCH_OP_ANOMALY_EVENT, 0, 0, 3));
                                    }
                                    /* ANOMALY-DASHBOARD · also stash event in
                                     * orch's local ring so sotShell can read it
                                     * back via `anomaly-log`. */
                                    orch_anomaly_log_append((uint32_t)pmsg.pid,
                                                             (uint16_t)ANOMALY_EV_OPERATOR_PROMOTE,
                                                             (uint64_t)pmsg.tier, 0);
                                    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                                }
                            }
                        } else if (shell_op == ORCH_OP_QUERY_NET_FLOWS) {
                            orch_net_flows_reply_t net_reply;
                            memset(&net_reply, 0, sizeof(net_reply));
                            net_reply.flow_count = (uint32_t)sotnet_get_flows(
                                net_reply.flows, SOTNET_MAX_FLOWS);
                            size_t nwords_n = sizeof(net_reply) / sizeof(seL4_Word);
                            seL4_Word *src_n = (seL4_Word *)&net_reply;
                            for (size_t i = 0; i < nwords_n; ++i) seL4_SetMR(i, src_n[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nwords_n));
                            printf("[orch] sotShell QUERY_NET_FLOWS served (%u flows)\n",
                                   net_reply.flow_count);
                        } else if (shell_op == ORCH_OP_SOTFS_LS) {
                            /* Decode path from MRs. */
                            orch_sotfs_path_req_t req;
                            memset(&req, 0, sizeof(req));
                            {
                                size_t nw = sizeof(req) / sizeof(seL4_Word);
                                if (shell_len < nw) nw = shell_len;
                                seL4_Word *dst = (seL4_Word *)&req;
                                for (size_t i = 0; i < nw; ++i) dst[i] = seL4_GetMR(i);
                                req.path[ORCH_SOTFS_PATH_MAX - 1] = '\0';
                            }
                            orch_sotfs_ls_reply_t ls_reply;
                            memset(&ls_reply, 0, sizeof(ls_reply));
                            sotfs_dirent_t dirents[ORCH_SOTFS_LS_MAX_ENTRIES];
                            int n = oproot_list_dir(req.path, dirents, ORCH_SOTFS_LS_MAX_ENTRIES);
                            if (n < 0) {
                                ls_reply.entry_count = 0;
                            } else {
                                ls_reply.entry_count = (uint32_t)n;
                                for (int ei = 0; ei < n && ei < ORCH_SOTFS_LS_MAX_ENTRIES; ++ei) {
                                    memcpy(ls_reply.entries[ei].name, dirents[ei].name, 32);
                                    ls_reply.entries[ei].size = dirents[ei].size;
                                    ls_reply.entries[ei].kind = dirents[ei].kind;
                                }
                            }
                            size_t nw_ls = sizeof(ls_reply) / sizeof(seL4_Word);
                            seL4_Word *src_ls = (seL4_Word *)&ls_reply;
                            for (size_t i = 0; i < nw_ls; ++i) seL4_SetMR(i, src_ls[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nw_ls));
                            printf("[orch] sotShell SOTFS_LS path=%s · %d entries\n",
                                   req.path, n);
                        } else if (shell_op == ORCH_OP_SOTFS_CAT) {
                            orch_sotfs_path_req_t req;
                            memset(&req, 0, sizeof(req));
                            {
                                size_t nw = sizeof(req) / sizeof(seL4_Word);
                                if (shell_len < nw) nw = shell_len;
                                seL4_Word *dst = (seL4_Word *)&req;
                                for (size_t i = 0; i < nw; ++i) dst[i] = seL4_GetMR(i);
                                req.path[ORCH_SOTFS_PATH_MAX - 1] = '\0';
                            }
                            orch_sotfs_cat_reply_t cat_reply;
                            memset(&cat_reply, 0, sizeof(cat_reply));
                            int nr = oproot_read_file(req.path, cat_reply.data,
                                                      ORCH_SOTFS_CAT_MAX_BYTES);
                            if (nr < 0) {
                                cat_reply.rc       = nr;
                                cat_reply.data_len = 0;
                            } else {
                                cat_reply.rc       = 0;
                                cat_reply.data_len = (uint32_t)nr;
                            }
                            size_t nw_cat = sizeof(cat_reply) / sizeof(seL4_Word);
                            seL4_Word *src_cat = (seL4_Word *)&cat_reply;
                            for (size_t i = 0; i < nw_cat; ++i) seL4_SetMR(i, src_cat[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nw_cat));
                            /* sottrace · P3 · operator/shell disk read → forensic graph
                             * (slot=-1 → system ring · pid 0 → operator). cat is one-shot
                             * (whole file in one reply), so emit once on success. */
                            if (nr >= 0)
                                trace_emit_fs(-1, 0, SG_EV_FS_READ, (uint64_t)nr, req.path);
                            printf("[orch] sotShell SOTFS_CAT path=%s · %d bytes\n",
                                   req.path, nr);
                        } else if (shell_op == ORCH_OP_SOTFS_INSTALL) {
                            orch_sotfs_install_req_t req;
                            memset(&req, 0, sizeof(req));
                            {
                                size_t nw = sizeof(req) / sizeof(seL4_Word);
                                if (shell_len < nw) nw = shell_len;
                                seL4_Word *dst = (seL4_Word *)&req;
                                for (size_t i = 0; i < nw; ++i) dst[i] = seL4_GetMR(i);
                                req.path[ORCH_SOTFS_PATH_MAX - 1] = '\0';
                                if (req.content_len > ORCH_SOTFS_INSTALL_CONTENT_MAX)
                                    req.content_len = ORCH_SOTFS_INSTALL_CONTENT_MAX;
                            }
                            int pr = lucas_sotfs_install(req.path, req.content, req.content_len);
                            seL4_SetMR(0, (seL4_Word)pr);
                            seL4_Reply(seL4_MessageInfo_new(pr != 0 ? 1 : 0, 0, 0, 1));
                            /* sottrace · P3 · operator/shell disk write (install/overwrite)
                             * → forensic graph. one-shot per command, emit on success. */
                            if (pr == 0)
                                trace_emit_fs(-1, 0, SG_EV_FS_WRITE,
                                              (uint64_t)req.content_len, req.path);
                            printf("[orch] sotShell SOTFS_INSTALL path=%s len=%u rc=%d\n",
                                   req.path, req.content_len, pr);
                        } else if (shell_op == ORCH_OP_SOTFS_WRITE_AT) {
                            orch_sotfs_write_at_req_t req;
                            memset(&req, 0, sizeof(req));
                            {
                                size_t nw = sizeof(req) / sizeof(seL4_Word);
                                if (shell_len < nw) nw = shell_len;
                                seL4_Word *dst = (seL4_Word *)&req;
                                for (size_t i = 0; i < nw; ++i) dst[i] = seL4_GetMR(i);
                                req.path[ORCH_SOTFS_PATH_MAX - 1] = '\0';
                            }
                            extern int lucas_sotfs_write_at(const char *, uint32_t, const uint8_t *,
                                                            uint32_t, int);
                            int rc = lucas_sotfs_write_at(req.path, req.offset, req.data,
                                                          req.len, req.truncate);
                            seL4_Reply(seL4_MessageInfo_new((unsigned)(rc < 0 ? -rc : 0), 0, 0, 0));
                            printf("[orch] sotShell SOTFS_WRITE_AT path=%s off=%u len=%u trunc=%u rc=%d\n",
                                   req.path, req.offset, req.len, req.truncate, rc);
                        } else if (shell_op == ORCH_OP_SOTFS_READ_AT) {
                            orch_sotfs_read_at_req_t req;
                            memset(&req, 0, sizeof(req));
                            {
                                size_t nw = sizeof(req) / sizeof(seL4_Word);
                                if (shell_len < nw) nw = shell_len;
                                seL4_Word *dst = (seL4_Word *)&req;
                                for (size_t i = 0; i < nw; ++i) dst[i] = seL4_GetMR(i);
                                req.path[ORCH_SOTFS_PATH_MAX - 1] = '\0';
                            }
                            orch_sotfs_read_at_reply_t rep;
                            memset(&rep, 0, sizeof(rep));
                            uint32_t want = req.max > ORCH_SOTFS_READ_AT_CHUNK
                                          ? ORCH_SOTFS_READ_AT_CHUNK : req.max;
                            int nr = oproot_read_at(req.path, req.offset, rep.data, want);
                            rep.rc  = nr;
                            rep.len = (nr > 0) ? (uint32_t)nr : 0;
                            size_t nw_r = sizeof(rep) / sizeof(seL4_Word);
                            seL4_Word *src_r = (seL4_Word *)&rep;
                            for (size_t i = 0; i < nw_r; ++i) seL4_SetMR(i, src_r[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nw_r));
                            /* sottrace · P3 · paged read → forensic graph. READ_AT is
                             * chunked, so emit once on the first page (offset==0) to
                             * avoid flooding the ring on a multi-page cat. */
                            if (nr > 0 && req.offset == 0)
                                trace_emit_fs(-1, 0, SG_EV_FS_READ, (uint64_t)nr, req.path);
                            printf("[orch] sotShell SOTFS_READ_AT path=%s off=%u rc=%d\n",
                                   req.path, req.offset, nr);
                        } else if (shell_op == ORCH_OP_RWBIN_INSTALL) {
                            /* A2 · copy a binary (binstore name or sotfs path)
                             * into the writable on-disk store, then it shadows
                             * the read-only binstore at spawn time. */
                            orch_rwbin_install_req_t req;
                            memset(&req, 0, sizeof(req));
                            {
                                size_t nw = sizeof(req) / sizeof(seL4_Word);
                                if (shell_len < nw) nw = shell_len;
                                seL4_Word *dst = (seL4_Word *)&req;
                                for (size_t i = 0; i < nw; ++i) dst[i] = seL4_GetMR(i);
                                req.src[sizeof(req.src) - 1]   = '\0';
                                req.dest[sizeof(req.dest) - 1] = '\0';
                            }
                            extern int  lucas_sotfs_read_file(const char *path, void *buf, size_t max);
                            extern long binstore_lookup(const char *name, uint64_t *offset_out);
                            extern long binstore_read(const char *name, void *buf, size_t cap);
                            extern int  rwbinstore_write(const char *name, const void *bytes, size_t len);
                            long  n   = -1;
                            void *buf = NULL;
                            if (req.src[0] == '/') {
                                n   = lucas_sotfs_read_file(req.src, g_spawn_elf_buf, sizeof(g_spawn_elf_buf));
                                buf = g_spawn_elf_buf;
                            } else {
                                uint64_t off = 0;
                                long sz = binstore_lookup(req.src, &off);
                                if (sz > 0) {
                                    buf = spawn_pick_buf((size_t)sz);
                                    if (buf) n = binstore_read(req.src, buf, (size_t)sz);
                                }
                            }
                            int rc = -1;
                            if (n > 0 && buf) rc = rwbinstore_write(req.dest, buf, (size_t)n);
                            seL4_SetMR(0, (seL4_Word)rc);
                            seL4_Reply(seL4_MessageInfo_new(rc == 0 ? 0 : 1, 0, 0, 1));
                            printf("[orch] sotShell RWBIN_INSTALL src=%s dest=%s · %ld bytes · rc=%d\n",
                                   req.src, req.dest, n, rc);
                        } else if (shell_op == ORCH_OP_SPAWN_BENCH) {
                            /* Perf benchmarks · spawn sotOs-bench_<name> with a
                             * copy of orch's STO endpoint as its argv[1]. */
                            orch_bench_req_t req;
                            memset(&req, 0, sizeof(req));
                            {
                                size_t nw = sizeof(req) / sizeof(seL4_Word);
                                if (shell_len < nw) nw = shell_len;
                                seL4_Word *dst = (seL4_Word *)&req;
                                for (size_t i = 0; i < nw; ++i) dst[i] = seL4_GetMR(i);
                                req.name[sizeof(req.name) - 1] = '\0';
                            }
                            const char *binname = req.name[0] ? req.name : "sotOs-bench_baseline";
                            const void *bbytes = NULL; unsigned long bsize = 0; const char *bsrc = "?";
                            int lr = spawn_load_elf(binname, &bbytes, &bsize, &bsrc);
                            int rc = -1;
                            seL4_CPtr bench_done_ep = 0;
                            if (lr == 0) {
                                extern seL4_CPtr orch_get_sto_ep(void);
                                extern seL4_CPtr orch_get_sto_listen_ep(void);
                                extern int orch_spawn_bench(const char *, const void *, unsigned long, seL4_CPtr, seL4_Word, seL4_CPtr *);
                                /* baseline only pings (badge irrelevant) → copy the
                                 * 0xA003 EP (badge 0).  The STO-session benches each
                                 * get a DISTINCT badge minted from the unbadged EP. */
                                seL4_Word bench_badge = 0;
                                if      (strstr(binname, "sto_ops")    != NULL) bench_badge = 0xB001;
                                else if (strstr(binname, "throughput") != NULL) bench_badge = 0xB002;
                                else if (strstr(binname, "sweep_cost") != NULL) bench_badge = 0xB003;
                                seL4_CPtr bep = (bench_badge == 0)
                                              ? orch_get_sto_ep()          /* badged 0xA003 */
                                              : orch_get_sto_listen_ep();  /* unbadged · mint from */
                                rc = orch_spawn_bench(binname, bbytes, bsize, bep, bench_badge, &bench_done_ep);
                            } else {
                                printf("[orch] bench '%s' not found (rc=%d)\n", binname, lr);
                            }
                            seL4_SetMR(0, (seL4_Word)rc);
                            seL4_Reply(seL4_MessageInfo_new(rc == 0 ? 0 : 1, 0, 0, 1));
                            printf("[orch] sotShell SPAWN_BENCH name=%s · rc=%d\n", binname, rc);
                            /* Isolation · block until the bench signals done on its
                             * done EP.  orch is unavailable to the shell meanwhile, so
                             * the demo pauses and the bench runs ALONE (no preemption
                             * from the shell · no concurrent STO clients) → clean
                             * numbers.  The bench reliably Sends after emitting its
                             * JSON; the Reply above already returned to the shell so
                             * there is no reply-cap conflict with this Recv. */
                            if (rc == 0 && bench_done_ep != 0) {
                                seL4_Word done_badge;
                                seL4_Recv(bench_done_ep, &done_badge);
                                printf("[orch] bench '%s' · isolated run complete\n", binname);
                            }
                        } else if (shell_op == ORCH_OP_SOTFS_MKDIR) {
                            orch_sotfs_path_req_t req;
                            memset(&req, 0, sizeof(req));
                            {
                                size_t nw = sizeof(req) / sizeof(seL4_Word);
                                if (shell_len < nw) nw = shell_len;
                                seL4_Word *dst = (seL4_Word *)&req;
                                for (size_t i = 0; i < nw; ++i) dst[i] = seL4_GetMR(i);
                                req.path[ORCH_SOTFS_PATH_MAX - 1] = '\0';
                            }
                            int mr = lucas_sotfs_mkdir(orch_strip_tmp(req.path), 0755);
                            seL4_SetMR(0, (seL4_Word)mr);
                            seL4_Reply(seL4_MessageInfo_new(mr != 0 ? 1 : 0, 0, 0, 1));
                            printf("[orch] sotShell SOTFS_MKDIR path=%s rc=%d\n",
                                   req.path, mr);
                        } else if (shell_op == ORCH_OP_SOTFS_RM) {
                            orch_sotfs_path_req_t req;
                            memset(&req, 0, sizeof(req));
                            {
                                size_t nw = sizeof(req) / sizeof(seL4_Word);
                                if (shell_len < nw) nw = shell_len;
                                seL4_Word *dst = (seL4_Word *)&req;
                                for (size_t i = 0; i < nw; ++i) dst[i] = seL4_GetMR(i);
                                req.path[ORCH_SOTFS_PATH_MAX - 1] = '\0';
                            }
                            int rr = lucas_sotfs_unlink(orch_strip_tmp(req.path));
                            seL4_SetMR(0, (seL4_Word)rr);
                            seL4_Reply(seL4_MessageInfo_new(rr != 0 ? 1 : 0, 0, 0, 1));
                            printf("[orch] sotShell SOTFS_RM path=%s rc=%d\n",
                                   req.path, rr);
                        } else if (shell_op == ORCH_OP_DNS_LIST) {
                            extern int dns_list(dns_list_entry_t *, int);
                            orch_dns_list_reply_t dns_reply;
                            memset(&dns_reply, 0, sizeof(dns_reply));
                            dns_reply.entry_count = (uint32_t)dns_list(dns_reply.entries, ORCH_DNS_MAX_ENTRIES);
                            size_t nwords_d = sizeof(dns_reply) / sizeof(seL4_Word);
                            seL4_Word *src_d = (seL4_Word *)&dns_reply;
                            for (size_t i = 0; i < nwords_d; ++i) seL4_SetMR(i, src_d[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nwords_d));
                            printf("[orch] sotShell DNS_LIST served (%u entries)\n",
                                   dns_reply.entry_count);
                        } else if (shell_op == ORCH_OP_DNS_INSTALL) {
                            char domain[64];
                            memset(domain, 0, sizeof(domain));
                            for (size_t i = 0; i < 8; ++i) {
                                seL4_Word w = seL4_GetMR(i);
                                memcpy(domain + i * 8, &w, 8);
                            }
                            domain[63] = '\0';
                            uint32_t ip_be = (uint32_t)seL4_GetMR(8);
                            extern int dns_install(const char *, uint32_t);
                            int drc = dns_install(domain, ip_be);
                            seL4_Reply(seL4_MessageInfo_new(drc == 0 ? 0 : 1, 0, 0, 0));
                            printf("[orch] sotShell DNS_INSTALL domain=%s rc=%d\n", domain, drc);
                        } else if (shell_op == ORCH_OP_SYNTH_RESPONSE) {
                            /* sotNet-γ Phase 3-C · synth server sends synthetic
                             * response back for a Tier 2 sotbox's sendto.
                             * Phase 3-D will enqueue in sotnet's pending-recv queue;
                             * Phase 3-C just logs the close-the-loop arrival. */
                            uint32_t pr_pid      = (uint32_t)seL4_GetMR(0);
                            uint32_t pr_src_ip   = (uint32_t)seL4_GetMR(1);
                            uint16_t pr_src_port = (uint16_t)seL4_GetMR(2);
                            uint32_t pr_body_len = (uint32_t)seL4_GetMR(3);
                            char pr_body[64 + 1];
                            memset(pr_body, 0, sizeof(pr_body));
                            if (pr_body_len > 64) pr_body_len = 64;
                            size_t pr_nwords = (pr_body_len + 7) / 8;
                            for (size_t i = 0; i < pr_nwords; ++i) {
                                seL4_Word w = seL4_GetMR(4 + i);
                                size_t chunk = (pr_body_len - i * 8 < 8)
                                               ? pr_body_len - i * 8 : 8;
                                memcpy(pr_body + i * 8, &w, chunk);
                            }
                            pr_body[pr_body_len] = '\0';
                            printf("[orch] synth→sotbox response · pid=%u src=%u.%u.%u.%u:%u body_len=%u body='%.40s%s'\n",
                                   pr_pid,
                                   pr_src_ip & 0xFF, (pr_src_ip >> 8) & 0xFF,
                                   (pr_src_ip >> 16) & 0xFF, (pr_src_ip >> 24) & 0xFF,
                                   ((pr_src_port & 0xFF) << 8) | ((pr_src_port >> 8) & 0xFF),
                                   pr_body_len, pr_body,
                                   pr_body_len > 40 ? "..." : "");
                            /* γ Phase 3-D-2 · stash payload in sotnet pending_recv
                             * queue keyed by (pid, src_ip, src_port); LUCAS recvfrom
                             * dispatch (δ-D-3) will dequeue on next syscall. */
                            {
                                uint8_t src_ip[4] = {
                                    (uint8_t)(pr_src_ip & 0xFF),
                                    (uint8_t)((pr_src_ip >> 8) & 0xFF),
                                    (uint8_t)((pr_src_ip >> 16) & 0xFF),
                                    (uint8_t)((pr_src_ip >> 24) & 0xFF),
                                };
                                sotnet_recv_enqueue(pr_pid, src_ip, pr_src_port,
                                                    (const uint8_t *)pr_body,
                                                    (size_t)pr_body_len);
                            }
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                        } else if (shell_op == ORCH_OP_SYNTH_TRIGGER) {
                            /* sotNet-γ Phase 3-D-2 · operator-driven synth
                             * redirect demo · sotShell `synth-trigger` cmd.
                             * Synthesize a Tier 2 sendto-style redirect using
                             * the operator pid anomaly (99 · same convention
                             * as the synthetic boot trigger in synth.c). */
                            uint32_t pt_ip_be   = (uint32_t)seL4_GetMR(0);
                            uint16_t pt_port_be = (uint16_t)seL4_GetMR(1);
                            printf("[orch] sotShell SYNTH_TRIGGER dst=%u.%u.%u.%u:%u\n",
                                   pt_ip_be & 0xFF, (pt_ip_be >> 8) & 0xFF,
                                   (pt_ip_be >> 16) & 0xFF, (pt_ip_be >> 24) & 0xFF,
                                   ((pt_port_be & 0xFF) << 8) | ((pt_port_be >> 8) & 0xFF));
                            synth_record_redirect(/*pid=*/99, pt_ip_be,
                                                    pt_port_be, /*len=*/16);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                        } else if (shell_op == ORCH_OP_SYNTH_QUEUE_DUMP) {
                            /* γ Phase 3-D-2 · sotShell `synth-queue` cmd:
                             * dump in-orch sotnet pending_recv table.  No
                             * payload either direction · printing happens
                             * orch-side via sotnet_recv_dump(). */
                            printf("[orch] sotShell SYNTH_QUEUE_DUMP\n");
                            sotnet_recv_dump();
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                        } else if (shell_op == ORCH_OP_SYNTH_INSTALL) {
                            /* γ-3-ε · relay an operator response_profile-install to the
                             * synth server (NBSend · fire-and-forget · same
                             * non-blocking pattern as the redirect path · must
                             * NOT seL4_Call here, which would clobber the
                             * implicit reply cap to sotShell). */
                            extern void synth_install_emit(uint32_t, uint16_t, uint32_t);
                            uint32_t pl_ip_be   = (uint32_t)seL4_GetMR(0);
                            uint16_t pl_port_be = (uint16_t)seL4_GetMR(1);
                            uint32_t pl_kind    = (uint32_t)seL4_GetMR(2);
                            printf("[orch] sotShell SYNTH_INSTALL dst=%u.%u.%u.%u:%u kind=%u\n",
                                   pl_ip_be & 0xFF, (pl_ip_be >> 8) & 0xFF,
                                   (pl_ip_be >> 16) & 0xFF, (pl_ip_be >> 24) & 0xFF,
                                   ((pl_port_be & 0xFF) << 8) | ((pl_port_be >> 8) & 0xFF),
                                   pl_kind);
                            synth_install_emit(pl_ip_be, pl_port_be, pl_kind);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                        } else if (shell_op == ORCH_OP_QUERY_ANOMALY_LOG) {
                            /* ANOMALY-DASHBOARD · pack the ring buffer into
                             * the reply.  Emit entries in chronological order:
                             * if the ring has wrapped, start from g_anomaly_log_head
                             * (oldest); otherwise start from index 0. */
                            orch_anomaly_log_reply_t slog_reply;
                            memset(&slog_reply, 0, sizeof(slog_reply));
                            uint16_t total = g_anomaly_log_full
                                           ? ORCH_ANOMALY_LOG_MAX
                                           : g_anomaly_log_head;
                            uint16_t start = g_anomaly_log_full
                                           ? g_anomaly_log_head
                                           : 0;
                            slog_reply.count = (uint32_t)total;
                            for (uint16_t k = 0; k < total; ++k) {
                                uint16_t idx = (uint16_t)((start + k) % ORCH_ANOMALY_LOG_MAX);
                                slog_reply.entries[k] = g_anomaly_log[idx];
                                /* S-PID · attach the OBSD-ζ display_pid the
                                 * sotbox sees through getpid().  Translation
                                 * happens here at display-time so the on-wire
                                 * producer side (orch_anomaly_log_append)
                                 * keeps storing only synthetic_pid · the
                                 * load-bearing ring/state index. */
                                slog_reply.entries[k].display_pid =
                                    sotbox_synthetic_to_display_pid(
                                        slog_reply.entries[k].pid);
                            }
                            size_t nwords_s = sizeof(slog_reply) / sizeof(seL4_Word);
                            seL4_Word *src_s = (seL4_Word *)&slog_reply;
                            for (size_t i = 0; i < nwords_s; ++i) seL4_SetMR(i, src_s[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nwords_s));
                            printf("[orch] sotShell QUERY_ANOMALY_LOG served (%u entries)\n",
                                   slog_reply.count);
                        } else if (shell_op == ORCH_OP_QUERY_TRACE_RING) {
                            sotguard_event_t recent[ORCH_TRACE_REPLY_MAX];
                            uint32_t total = 0;
                            uint32_t n = sottrace_peek_recent(recent,
                                            ORCH_TRACE_REPLY_MAX, &total);
                            orch_trace_reply_t tr;
                            memset(&tr, 0, sizeof(tr));
                            tr.count = n;
                            tr.total = total;
                            for (uint32_t k = 0; k < n; ++k) {
                                const sotguard_event_t *e = &recent[k];
                                tr.entries[k].seq  = e->timestamp;
                                tr.entries[k].pid  = e->pid;
                                tr.entries[k].kind = e->type;
                                tr.entries[k].pad  = e->conn_id;  /* v1 · session correlation id */
                                switch (e->type) {
                                    case SG_EV_SYSCALL_ENTER:
                                        tr.entries[k].a = e->detail.syscall.sysno;
                                        tr.entries[k].b = e->detail.syscall.args[0];
                                        break;
                                    case SG_EV_SYSCALL_EXIT:
                                        tr.entries[k].a = e->detail.syscall.sysno;
                                        tr.entries[k].b = (uint64_t)e->detail.syscall.ret;
                                        break;
                                    case SG_EV_TIER_ASSIGN:
                                        tr.entries[k].a = e->detail.tier.old_tier;
                                        tr.entries[k].b = e->detail.tier.new_tier;
                                        break;
                                    case SG_EV_DNS_LOOKUP:
                                        tr.entries[k].a = e->detail.dns.ip_be;
                                        break;
                                    case SG_EV_INBOUND_ACCEPT:
                                        tr.entries[k].a = e->detail.net.ip_be;
                                        tr.entries[k].b = ((uint64_t)e->detail.net.port_be << 16)
                                                          | e->detail.net.pad;
                                        break;
                                    case SG_EV_CONN_CLOSE:
                                        tr.entries[k].a = e->detail.net.len;      /* rx */
                                        tr.entries[k].b = e->detail.net.ip_be;    /* tx */
                                        break;
                                    default: break;
                                }
                            }
                            size_t nwords_tr = sizeof(tr) / sizeof(seL4_Word);
                            seL4_Word *src_tr = (seL4_Word *)&tr;
                            for (size_t i = 0; i < nwords_tr; ++i) seL4_SetMR(i, src_tr[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nwords_tr));
                            printf("[orch] sotShell QUERY_TRACE_RING served (%u of %u)\n",
                                   tr.count, tr.total);
                        } else if (shell_op == ORCH_OP_TRACE_LIVE) {
                            /* MR(0) bits: 1=live drain (serial), 2=render the clean
                             * dashboard feed to the framebuffer, 4=quiet (suppress the
                             * per-packet/syscall/mmap firehose) — the operator `watch`. */
                            seL4_Word m = seL4_GetMR(0);
                            g_trace_live  = (m & 1u) ? 1 : 0;
                            g_trace_to_fb = (m & 2u) ? 1 : 0;
                            g_orch_quiet  = (m & 4u) ? 1 : 0;
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                            printf("[orch] sottrace live drain %s%s%s\n",
                                   g_trace_live ? "ON" : "OFF",
                                   g_trace_to_fb ? " +fb" : "",
                                   g_orch_quiet ? " +quiet" : "");
                        } else if (shell_op == ORCH_OP_QUERY_TRACE_PAYLOAD) {
                            /* sottrace payload <conn_id> · paginated dump of the
                             * T8 forensic capture store. MR(0)=conn_id, MR(1)=offset
                             * with bit31 = stream selector (0=IN, 1=OUT); cap=4096
                             * so bit31 of a real offset is always free (no MR(2)). */
                            uint16_t conn_id = (uint16_t)seL4_GetMR(0);
                            uint32_t raw = (uint32_t)seL4_GetMR(1);
                            int dir = (raw >> 31) & 1;
                            uint32_t offset = raw & 0x7fffffffu;
                            const sottrace_capture_t *c = sottrace_capture_get(conn_id);
                            orch_trace_payload_reply_t pr;
                            memset(&pr, 0, sizeof(pr));
                            pr.conn_id = conn_id;
                            if (c) {
                                const uint8_t *src_buf = (dir == SOTTRACE_DIR_OUT) ? c->buf_out : c->buf;
                                uint32_t       src_len = (dir == SOTTRACE_DIR_OUT) ? c->len_out : c->len;
                                uint32_t       src_drp = (dir == SOTTRACE_DIR_OUT) ? c->dropped_out : c->dropped;
                                pr.found = 1; pr.total_len = src_len; pr.dropped = src_drp;
                                if (offset < src_len) {
                                    uint32_t avail = src_len - offset;
                                    pr.page_len = avail < ORCH_TRACE_PAYLOAD_PAGE ? avail : ORCH_TRACE_PAYLOAD_PAGE;
                                    memcpy(pr.page, src_buf + offset, pr.page_len);
                                }
                            }
                            size_t nw = sizeof(pr) / sizeof(seL4_Word);
                            seL4_Word *src = (seL4_Word *)&pr;
                            for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nw));
                            printf("[orch] QUERY_TRACE_PAYLOAD conn=%u found=%u total=%u page=%u\n",
                                   conn_id, pr.found, pr.total_len, pr.page_len);
                        } else if (shell_op == ORCH_OP_QUERY_TRACE_GRAPH) {
                            /* sottrace graph · paginated dump of the process->file
                             * FS-mutation graph. MR(1)=offset; build on offset==0. */
                            static char g_graph_buf[32 * 1024];
                            static uint32_t g_graph_len = 0;
                            uint32_t offset = (uint32_t)seL4_GetMR(1);
                            if (offset == 0)
                                g_graph_len = (uint32_t)sottrace_graph_build(
                                    g_graph_buf, sizeof(g_graph_buf));
                            orch_trace_payload_reply_t gr;
                            memset(&gr, 0, sizeof(gr));
                            gr.found = 1;
                            gr.total_len = g_graph_len;
                            if (offset < g_graph_len) {
                                uint32_t avail = g_graph_len - offset;
                                gr.page_len = avail < ORCH_TRACE_PAYLOAD_PAGE ? avail : ORCH_TRACE_PAYLOAD_PAGE;
                                memcpy(gr.page, g_graph_buf + offset, gr.page_len);
                            }
                            size_t nwg = sizeof(gr) / sizeof(seL4_Word);
                            seL4_Word *srcg = (seL4_Word *)&gr;
                            for (size_t i = 0; i < nwg; ++i) seL4_SetMR(i, srcg[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nwg));
                            printf("[orch] QUERY_TRACE_GRAPH offset=%u total=%u page=%u\n",
                                   offset, gr.total_len, gr.page_len);
                        } else if (shell_op == ORCH_OP_TPM_PCRS) {
                            /* OBSD-η · operator reads PCR 8/9/10 (sotBoot bank). */
                            orch_tpm_pcrs_reply_t tpm_reply;
                            memset(&tpm_reply, 0, sizeof(tpm_reply));
                            if (tpm_is_available()) {
                                tpm_reply.available = 1;
                                (void)tpm_pcr_read(8,  tpm_reply.pcr8);
                                (void)tpm_pcr_read(9,  tpm_reply.pcr9);
                                (void)tpm_pcr_read(10, tpm_reply.pcr10);
                            }
                            size_t nwords_t = sizeof(tpm_reply) / sizeof(seL4_Word);
                            seL4_Word *src_t = (seL4_Word *)&tpm_reply;
                            for (size_t i = 0; i < nwords_t; ++i) seL4_SetMR(i, src_t[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nwords_t));
                            printf("[orch] sotShell TPM_PCRS served (available=%u)\n",
                                   (unsigned)tpm_reply.available);
                        } else if (shell_op == ORCH_OP_TPM_QUOTE) {
                            /* OBSD-η · operator requests TPM quote over a nonce.
                             * MR(0) = nonce_len (bytes, 0..TPM_QUOTE_MAX_NONCE),
                             * MR(1..) = nonce bytes packed 8/word. */
                            uint32_t nonce_len = (uint32_t)seL4_GetMR(0);
                            if (nonce_len > TPM_QUOTE_MAX_NONCE) {
                                nonce_len = TPM_QUOTE_MAX_NONCE;
                            }
                            uint8_t nonce_buf[TPM_QUOTE_MAX_NONCE];
                            memset(nonce_buf, 0, sizeof(nonce_buf));
                            size_t nonce_words = (nonce_len + 7) / 8;
                            for (size_t i = 0; i < nonce_words; ++i) {
                                seL4_Word w = seL4_GetMR(1 + i);
                                size_t chunk = (nonce_len - i * 8 < 8)
                                               ? nonce_len - i * 8 : 8;
                                memcpy(nonce_buf + i * 8, &w, chunk);
                            }
                            orch_tpm_quote_reply_t qreply;
                            memset(&qreply, 0, sizeof(qreply));
                            if (tpm_is_available()) {
                                size_t sig_size = TPM_QUOTE_MAX_SIG_BYTES;
                                int qrc = tpm_quote(nonce_buf, (size_t)nonce_len,
                                                    qreply.sig, &sig_size);
                                if (qrc == 0) {
                                    qreply.available = 1;
                                    if (sig_size > TPM_QUOTE_MAX_SIG_BYTES) {
                                        sig_size = TPM_QUOTE_MAX_SIG_BYTES;
                                    }
                                    qreply.sig_len = (uint32_t)sig_size;
                                }
                            }
                            size_t nwords_q = sizeof(qreply) / sizeof(seL4_Word);
                            seL4_Word *src_q = (seL4_Word *)&qreply;
                            for (size_t i = 0; i < nwords_q; ++i) seL4_SetMR(i, src_q[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nwords_q));
                            printf("[orch] sotShell TPM_QUOTE served (available=%u sig_len=%u nonce_len=%u)\n",
                                   (unsigned)qreply.available,
                                   (unsigned)qreply.sig_len,
                                   (unsigned)nonce_len);
                        } else if (shell_op == ORCH_OP_DUMP_HEAP) {
                            /* sotGuard live-dump · capture [brk_base, brk_top) of
                             * the target sotbox into a sotfs file.  Reply payload
                             * is orch_dump_heap_reply_t (bytes_dumped + brk range).
                             *
                             * The 1 MiB static buffer caps memory · larger heaps
                             * are truncated; bytes_dumped reflects the actual
                             * write length so callers can detect truncation by
                             * comparing against (brk_top - brk_base). */
                            orch_dump_heap_msg_t dmsg;
                            memset(&dmsg, 0, sizeof(dmsg));
                            {
                                size_t nw = sizeof(dmsg) / sizeof(seL4_Word);
                                if (shell_len < nw) nw = shell_len;
                                seL4_Word *dst = (seL4_Word *)&dmsg;
                                for (size_t i = 0; i < nw; ++i) dst[i] = seL4_GetMR(i);
                                dmsg.out_path[sizeof(dmsg.out_path) - 1] = '\0';
                            }

                            orch_dump_heap_reply_t dreply;
                            memset(&dreply, 0, sizeof(dreply));

                            lucas_state_t *tgt = NULL;
                            if (dmsg.target_pid >= 1 &&
                                dmsg.target_pid <= (uint32_t)SOTBOX_MAX_SLOTS) {
                                tgt = sotbox_get_slot((int)dmsg.target_pid - 1);
                            }
                            if (!tgt || tgt->slot_index < 0) {
                                dreply.bytes_dumped = -3; /* -ESRCH */
                                printf("[dump-heap] pid=%u not found\n",
                                       (unsigned)dmsg.target_pid);
                            } else {
                                dreply.brk_base = (uint64_t)tgt->brk_base;
                                dreply.brk_top  = (uint64_t)tgt->brk_top;
                                /* Static 1 MiB scratch buffer · no malloc,
                                 * shared across invocations (single-threaded
                                 * dispatch loop · safe). */
                                static uint8_t dump_buf[1024 * 1024];
                                size_t size = 0;
                                if (tgt->brk_top > tgt->brk_base) {
                                    size = (size_t)(tgt->brk_top - tgt->brk_base);
                                }
                                if (size > sizeof(dump_buf)) {
                                    size = sizeof(dump_buf);
                                }
                                if (size == 0) {
                                    /* Empty heap · still install a zero-byte file
                                     * so the caller observes the snapshot. */
                                    int pr = lucas_sotfs_install(dmsg.out_path,
                                                                dump_buf, 0);
                                    if (pr != 0) {
                                        dreply.bytes_dumped = -5; /* -EIO */
                                        printf("[dump-heap] pid=%u install failed rc=%d\n",
                                               (unsigned)dmsg.target_pid, pr);
                                    } else {
                                        dreply.bytes_dumped = 0;
                                        printf("[dump-heap] pid=%u bytes=0 path=%s (empty heap)\n",
                                               (unsigned)dmsg.target_pid,
                                               dmsg.out_path);
                                    }
                                } else if (lucas_copy_from_client(
                                               tgt, (uintptr_t)tgt->brk_base,
                                               dump_buf, size) != 0) {
                                    dreply.bytes_dumped = -14; /* -EFAULT */
                                    printf("[dump-heap] pid=%u read failed at brk_base=0x%lx size=%zu\n",
                                           (unsigned)dmsg.target_pid,
                                           (unsigned long)tgt->brk_base, size);
                                } else {
                                    int pr = lucas_sotfs_install(dmsg.out_path,
                                                                dump_buf, size);
                                    if (pr != 0) {
                                        dreply.bytes_dumped = -5; /* -EIO */
                                        printf("[dump-heap] pid=%u install failed rc=%d\n",
                                               (unsigned)dmsg.target_pid, pr);
                                    } else {
                                        dreply.bytes_dumped = (int64_t)size;
                                        printf("[dump-heap] pid=%u bytes=%zu path=%s\n",
                                               (unsigned)dmsg.target_pid, size,
                                               dmsg.out_path);
                                    }
                                }
                            }

                            size_t nw_dh = sizeof(dreply) / sizeof(seL4_Word);
                            seL4_Word *src_dh = (seL4_Word *)&dreply;
                            for (size_t i = 0; i < nw_dh; ++i) seL4_SetMR(i, src_dh[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, nw_dh));
                        } else if (shell_op == ORCH_OP_SPAWN) {
                            /* sotShell-driven SPAWN · used by `python "code"`
                             * and `inject-script <path>`.  Mirrors the listen_ep
                             * SPAWN handler · enters orch_fault_loop after the
                             * sotbox is up, returns here when the sotbox exits.
                             * The shell command window resumes after that. */
                            orch_spawn_msg_t s_msg;
                            memset(&s_msg, 0, sizeof(s_msg));
                            {
                                size_t snwords = sizeof(s_msg) / sizeof(seL4_Word);
                                if (shell_len > snwords) shell_len = snwords;
                                seL4_Word *s_dst = (seL4_Word *)&s_msg;
                                for (size_t i = 0; i < shell_len; ++i)
                                    s_dst[i] = seL4_GetMR(i);
                            }
                            s_msg.binname[ORCH_SPAWN_BINNAME_BYTES - 1] = '\0';

                            const char *s_argv[16];
                            {
                                size_t off = 0;
                                int n = 0;
                                while (n < (int)s_msg.argc && n < 15) {
                                    s_argv[n] = s_msg.argv_pool + off;
                                    size_t sl = 0;
                                    while (off + sl < ORCH_SPAWN_ARGV_BYTES &&
                                           s_msg.argv_pool[off + sl] != '\0') {
                                        ++sl;
                                    }
                                    off += sl + 1;
                                    if (off > ORCH_SPAWN_ARGV_BYTES) break;
                                    ++n;
                                }
                                s_argv[n] = NULL;
                                if (n == 0) {
                                    s_argv[0] = s_msg.binname;
                                    s_argv[1] = NULL;
                                }
                            }

                            const void *s_elf = NULL;
                            unsigned long s_elf_size = 0;
                            const char  *s_elf_src  = "?";
                            if (spawn_load_elf(s_msg.binname, &s_elf,
                                               &s_elf_size, &s_elf_src) != 0) {
                                printf("[orch] sotShell SPAWN '%s' not found (binstore/sotfs/CPIO)\n",
                                       s_msg.binname);
                                seL4_Reply(seL4_MessageInfo_new(2, 0, 0, 0));
                            } else {
                                printf("[orch] sotShell SPAWN '%s' · %lu bytes · argv[0]=%s\n",
                                       s_msg.binname, s_elf_size,
                                       s_argv[0] ? s_argv[0] : "(null)");
                                vfs_set_profile((int)s_msg.profile);
                                vfs_set_tier((int)s_msg.initial_tier);
                                int s_rc = sotbox_init(s_elf, s_elf_size, s_argv,
                                                       (int)s_msg.initial_tier,
                                                       s_msg.pledge,
                                                       (s_msg.trusted != 0));
                                printf("[orch] sotShell SPAWN '%s' sotbox_init rc=%d\n",
                                       s_msg.binname, s_rc);
                                /* PR 5/6/7 · same shadow-announce as the
                                 * root SPAWN path above · see that handler
                                 * for rationale.  PR 7 dropped the
                                 * PROCD_TAKEOVER_SPAWN gate · the announce
                                 * is now unconditional. */
                                if (s_rc == 0) {
                                    extern int orch_procd_spawn(uint64_t,
                                                                  uint32_t,
                                                                  int,
                                                                  const char *const argv[],
                                                                  proc_tier_t,
                                                                  uint64_t,
                                                                  uint32_t,
                                                                  const char *,
                                                                  uint32_t *,
                                                                  uint32_t *);
                                    uint32_t procd_slot = 0, procd_synthetic_pid = 0;
                                    const char *s_spawn_comm = orch_basename(
                                        (s_msg.argc > 0 && s_argv && s_argv[0])
                                            ? s_argv[0] : s_msg.binname);
                                    /* PR 6 carry-over · sotShell-nested
                                     * SPAWN should pass sotShell's procd slot
                                     * as the parent, but sotShell's slot is
                                     * not yet tracked in orch (TODO PR 8 ·
                                     * clone path adds the wiring).  Pass 0
                                     * for now so the new sotbox parents to
                                     * init; procd treats 0 as "no parent". */
                                    int pd_rc = orch_procd_spawn(
                                        0, 0,
                                        (int)s_msg.argc, s_argv,
                                        (proc_tier_t)s_msg.initial_tier,
                                        s_msg.pledge,
                                        /* caller_slot · 0 = init (TODO PR 8) */ 0,
                                        s_spawn_comm,
                                        &procd_slot, &procd_synthetic_pid);
                                    if (pd_rc < 0) {
                                        printf("[orch] procd OP_SPAWN announce failed rc=%d · sotbox still spawned\n",
                                               pd_rc);
                                    } else {
                                        printf("[orch] procd announced slot=%u synthetic_pid=%u\n",
                                               procd_slot, procd_synthetic_pid);
                                        /* PR 6 · stash procd_slot · see
                                         * root-driven SPAWN handler above. */
                                        lucas_state_t *st = sotbox_get_slot(0);
                                        if (st) st->procd_slot = procd_slot;
                                    }
                                }
                                seL4_Reply(seL4_MessageInfo_new(s_rc != 0 ? 1 : 0,
                                                                 0, 0, 0));
                                if (s_rc == 0) {
                                    printf("[orch] sotShell SPAWN entering fault loop\n");
                                    orch_fault_loop(orch_get_fault_ep());
                                    printf("[orch] sotShell SPAWN fault loop returned · resuming shell\n");
                                    sotbox_reset_primary();
                                    /* P4b · stats heartbeat: at the FIRST spawn (start
                                     * anchor, S4) + every STATS_EVERY after. Fires at the
                                     * post-reap point so free_arenas/live_sotbox are at
                                     * steady-state (no in-flight sibling). */
                                    ++g_soak_spawn_count;
                                    if (g_soak_spawn_count == 1 ||
                                        g_soak_spawn_count % STATS_EVERY == 0)
                                        orch_emit_stats(g_soak_spawn_count);
                                }
                            }
                        } else if (shell_op == SOTOS_OP_SIMREBOOT) {
                            /* α · PR 7 · sotShell-driven userspace-only reset
                             * cascade.  Drives sotfs CHECKPOINT write + replay
                             * apply in orch's vspace (where sotfs is linked).
                             * See src/orch/simreboot.c for the 5-phase logic
                             * + scope-reduction rationale. */
                            extern int orch_simreboot_cascade(void);
                            printf("[orch] sotShell SOTOS_OP_SIMREBOOT · invoking cascade\n");
                            int sr_rc = orch_simreboot_cascade();
                            /* A2 · persistence proof · re-read the rwbinstore
                             * index from disk after the reset boundary so the
                             * post-cascade "ready · N entries" line proves any
                             * installed binaries survived (analogue of Phase 5
                             * WAL replay for the writable binary store). */
                            extern void rwbinstore_reinit(void);
                            rwbinstore_reinit();
                            seL4_SetMR(0, (seL4_Word)sr_rc);
                            seL4_Reply(seL4_MessageInfo_new(sr_rc != 0 ? 1 : 0,
                                                            0, 0, 1));
                            printf("[orch] simreboot cascade returned rc=%d\n", sr_rc);
                        } else if (shell_op == ORCH_OP_VALIDATE) {
                            /* Pillar-4 P4a · concurrent 3-malware validation run.
                             * The demo's cmd_validate routes here (shell-window
                             * loop), NOT the top-level op switch.  orch_handle_validate
                             * seeds the 3 fixtures, REPLIES internally, runs ONE
                             * fault loop until all exit, then frees the pool —
                             * exactly like the SPAWN branch enters orch_fault_loop.
                             * No extra reply needed here. */
                            orch_handle_validate();
                        } else if (shell_op == ORCH_OP_DOOM) {
                            /* doom · spawn doomgeneric at Tier-0 trusted.
                             * orch_handle_doom seeds doom.bin, REPLIES internally,
                             * runs ONE fault loop until doom exits, frees pool.
                             * No extra reply needed here. */
                            orch_handle_doom();
                        } else if (shell_op == ORCH_OP_GITDEMO) {
                            /* compat-host · real git at Tier-0 · same spawn-reply-
                             * run-loop contract as doom; the demo's cmd_gitdemo
                             * routes here (shell-window loop). */
                            orch_handle_gitdemo();
                        } else if (shell_op == ORCH_OP_SOTCTL) {
                            /* world-#3 native operator plane · spawn the NATIVE sotctl
                             * binary (sotcrt+sotlibc+sel4runtime) for the chosen content
                             * op and serve its sotabi render-stream.  Bounded — the binary
                             * exits at stream EOF — so this is NOT captive.  MR1 = the
                             * SOTABI_OP_* content op (default SESSIONS).  Unlike doom we
                             * reply HERE (orch_spawn_sotctl_pool does not reply to sotShell). */
                            seL4_Word slen = seL4_MessageInfo_get_length(shell_info);
                            g_sotctl_op  = (slen >= 2) ? (int)seL4_GetMR(1) : SOTABI_OP_SESSIONS;
                            g_sotctl_arg = (slen >= 3) ? (uint32_t)seL4_GetMR(2) : 0;
                            orch_spawn_sotctl_pool();
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                        } else if (shell_op == ORCH_OP_GLIBC) {
                            /* compat-host · glibc-static probe at Tier-0 · same contract. */
                            orch_handle_glibc();
                        } else if (shell_op == ORCH_OP_GNU) {
                            /* compat-host · GNU coreutils/grep/sed/gawk at Tier-0 · same contract. */
                            orch_handle_gnu();
                        } else if (shell_op == ORCH_OP_GLIBCDYN) {
                            /* compat-host · glibc-dynamic PIE via real ld-linux · same contract. */
                            orch_handle_glibcdyn();
                        } else if (shell_op == ORCH_OP_INSTALL) {
                            /* install-arc P0.2 · dpkg-deb -x extracts a real tree to /tmp · same contract. */
                            orch_handle_install();
                        } else if (shell_op == ORCH_OP_EGRESS_DNS) {
                            /* internet-egress Phase 1 · dnsprobe Tier-0e (real DNS
                             * forward example.com) + Tier-2 (canary synth) · same
                             * spawn-reply-run-loop contract; the demo's cmd_egress_dns
                             * routes here (shell-window loop, NOT the switch(op) site). */
                            orch_handle_egress_dns();
                        } else if (shell_op == ORCH_OP_EGRESS_HTTP) {
                            /* internet-egress Phase 1 · END-TO-END · a Tier-0e
                             * busybox `wget http://example.com` does the full real
                             * DNS-forward + TCP connect + HTTP fetch.  Routed here
                             * from cmd_egress_http (shell-window loop). */
                            orch_handle_egress_http();
                        } else if (shell_op == ORCH_OP_EGRESS_INSTALL) {
                            /* egress · download a real .deb over verified HTTPS →
                             * dpkg-deb -x.  Routed from cmd_egress_install. */
                            orch_handle_egress_install();
                        } else if (shell_op == ORCH_OP_EGRESS_PYTHON) {
                            /* egress · real CPython HTTPS GET (in-process _ssl).
                             * Routed from cmd_egress_python (pip foundation). */
                            orch_handle_egress_python();
                        } else if (shell_op == ORCH_OP_ARENA_CHURN) {
                            /* arena reclaim validation · routed from cmd_arena_churn. */
                            orch_handle_arena_churn();
                        } else if (shell_op == ORCH_OP_EGRESS_PIP) {
                            /* FULL pip install · pip --version + pip install six over
                             * the verified egress · routed from cmd_egress_pip. */
                            orch_handle_egress_pip();
                        } else if (shell_op == ORCH_OP_EGRESS_PIPDEPS) {
                            /* pip install requests + deps · routed from cmd_egress_pipdeps. */
                            orch_handle_egress_pipdeps();
                        } else if (shell_op == ORCH_OP_TOOLS_FS) {
                            /* real GNU tar+coreutils fs battery · routed from cmd_tools_fs. */
                            orch_handle_toolsfs();
                        } else if (shell_op == ORCH_OP_PY_E2E) {
                            /* python real e2e · routed from cmd_py_e2e. */
                            orch_handle_py_e2e();
                        } else if (shell_op == ORCH_OP_EGRESS_PIP_BUILD) {
                            /* pip BUILD from sdist · setuptools build_wheel in-process
                             * · routed from cmd_egress_pip_build. */
                            orch_handle_egress_pip_build();
                        } else if (shell_op == ORCH_OP_DOOMWL) {
                            /* v2.3-M5 · Doom over REAL Wayland (wl_shm).  Same
                             * spawn-reply-run-loop contract as doom; the demo's
                             * cmd_doomwl routes here (shell-window loop). */
                            orch_handle_doomwl();
                        } else if (shell_op == ORCH_OP_GTKSPIKE) {
                            /* v2.4 · GTK3 over REAL Wayland spike · same contract. */
                            orch_handle_gtkspike();
                        } else if (shell_op == ORCH_OP_GTK3DEMO) {
                            /* v2.x · unmodified off-the-shelf gtk3-demo · same contract. */
                            orch_handle_gtk3demo();
                        } else if (shell_op == ORCH_OP_WIDGETFACTORY) {
                            /* #2 · unmodified off-the-shelf gtk3-widget-factory · same contract. */
                            orch_handle_widgetfactory();
                        } else if (shell_op == ORCH_OP_MAPFIXED) {
                            /* Wine-prep · MAP_FIXED-low gate fixture · same contract. */
                            orch_handle_mapfixed();
                        } else if (shell_op == ORCH_OP_WINE) {
                            /* Wine M1 · wine hello.exe (real wineboot path) · same contract. */
                            orch_handle_wine(0);
                        } else if (shell_op == ORCH_OP_WINE_CRT) {
                            /* Wine M2 · wine hello_crt.exe (real msvcrt printf/malloc PE). */
                            g_wine_pe = 1; orch_handle_wine(1); g_wine_pe = 0;
                        } else if (shell_op == ORCH_OP_WINE_GUI) {
                            /* Wine GUI · wine hello_gui.exe (Win32 window → winewayland). */
                            g_wine_pe = 2; orch_handle_wine(1); g_wine_pe = 0;
                        } else if (shell_op == ORCH_OP_WINE_BAKED) {
                            /* Wine M1 · Track M1 · pre-baked prefix · wineboot SKIPPED. */
                            orch_handle_wine(1);
                        } else if (shell_op == ORCH_OP_QUERY_INTERACTIVE) {
                            /* sotShell asks what kind of boot this is so it can skip
                             * the scripted demo for operator boots:
                             *   0 = headless/gate (run the demo · gates grep markers)
                             *   1 = keyboard-interactive (GUI · bbsh ⇄ operator console)
                             *   2 = serial-interactive (an aux UART is present →
                             *       run-3pane/4pane/clean run) → drop straight into the
                             *       serial operator console, no demo, no banners. */
                            extern int com2_present(void);
                            int imode = g_kbd_present ? 1 : (com2_present() ? 2 : 0);
                            seL4_Reply(seL4_MessageInfo_new(imode, 0, 0, 0));
                        } else if (shell_op == ORCH_OP_QUERY_NET) {
                            /* v2.9 · headless keepalive · reply MR(0) = count of
                             * inbound conns that reached ESTABLISHED.  sotShell's
                             * post-demo idle loop polls this: a climbing count means
                             * the host is being probed/attacked → keep it alive;
                             * a stable count means the network is idle → poweroff. */
                            extern uint32_t tcp_inbound_total(void);
                            seL4_SetMR(0, (seL4_Word)tcp_inbound_total());
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 1));
                        } else if (shell_op == ORCH_OP_FB_PUTS) {
                            /* F12 toggle · render the operator console's stdout to
                             * the GTK framebuffer (sotShell tees it here). */
                            seL4_Word cnt = seL4_GetMR(0);
                            if (cnt > 64) cnt = 64;
                            char fbbuf[64];
                            for (int i = 0; i < 8; ++i) {
                                seL4_Word w = seL4_GetMR(1 + i);
                                memcpy(fbbuf + i * 8, &w, 8);
                            }
                            for (seL4_Word i = 0; i < cnt; ++i)
                                console_fb_putc(fbbuf[i]);
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                        } else if (shell_op == ORCH_OP_GETKEY) {
                            /* F12 toggle · the operator console polls orch for a
                             * keyboard byte (the GTK keyboard feeds the virtio ring,
                             * not the UART sotShell reads).  Drain virtio events,
                             * then reply: label 2 = F12 (switch to canary shell),
                             * label 1 = byte in MR(0), label 0 = nothing pending. */
                            kbd_poll();
                            if (kbd_f12_take()) {
                                seL4_Reply(seL4_MessageInfo_new(2, 0, 0, 0));
                            } else {
                                int kb = kbd_getbyte();
                                if (kb >= 0) {
                                    seL4_SetMR(0, (seL4_Word)kb);
                                    seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 1));
                                } else {
                                    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                                }
                            }
                        } else if (shell_op == ORCH_OP_BBSH_AUTO && !g_kbd_present) {
                            /* Default-interactive-shell request, but headless (no
                             * virtio-keyboard) → no-op so the demo + gates are
                             * unchanged. Reply immediately; sotShell continues. */
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                        } else if (shell_op == ORCH_OP_BBSH ||
                                   shell_op == ORCH_OP_BBSH_AUTO ||
                                   shell_op == ORCH_OP_BBSH_TRUSTED) {
                            /* Interactive shell · foreground `busybox sh -i`.  Two
                             * flavours share this branch:
                             *   • ORCH_OP_BBSH / _AUTO  → Tier-2 canary (attacker).
                             *   • ORCH_OP_BBSH_TRUSTED  → Tier-0e/trusted (operator)
                             *     with REAL egress live for the whole session, so
                             *     `pip install …` / `python3 …` typed by hand reach
                             *     the real wire (g_shell_trusted_egress gates the
                             *     python-child inheritance + the real-pip path).
                             * Structurally identical to the shell-window
                             * ORCH_OP_SPAWN branch above, with ONE difference: orch
                             * replies to sotShell ONLY AFTER orch_fault_loop returns
                             * (busybox exit) — so sotShell stays blocked and does NOT
                             * poll the serial UART while busybox owns it (no serial
                             * contention).  busybox spawns interactive · we set
                             * console_interactive=1 so stdout flushes per-write (the
                             * prompt has no trailing \n). */
                            /* Reply-after-fault-loop fix · SaveCaller sotShell's
                             * reply cap NOW, before any op (spawn_load_elf /
                             * sotbox_init / the fault loop) does a Recv that clobbers
                             * the single per-thread implicit reply cap.  We reply via
                             * THIS saved cap after the loop returns.  Without it the
                             * post-loop seL4_Reply hit a stale fault cap → sotShell
                             * hung forever → the "perpetual terminal" never respawned
                             * on `exit` and the F12 operator-console toggle could not
                             * return.  Mirrors the accept/recv SaveCaller park. */
                            extern vka_t *orch_vka(void);
                            vka_t *bb_ov = orch_vka();
                            seL4_CPtr bb_reply_slot = 0;
                            if (vka_cspace_alloc(bb_ov, &bb_reply_slot) == 0) {
                                cspacepath_t bb_rp;
                                vka_cspace_make_path(bb_ov, bb_reply_slot, &bb_rp);
                                if (seL4_CNode_SaveCaller(bb_rp.root, bb_rp.capPtr,
                                                          bb_rp.capDepth) != 0) {
                                    vka_cspace_free(bb_ov, bb_reply_slot);
                                    bb_reply_slot = 0;
                                }
                            }
                            const char *bb_argv[] = { "busybox", "sh", "-i", NULL };
                            const void *bb_elf = NULL;
                            unsigned long bb_elf_size = 0;
                            const char  *bb_elf_src  = "?";
                            int bb_label;
                            if (spawn_load_elf("busybox-static.bin", &bb_elf,
                                               &bb_elf_size, &bb_elf_src) != 0 &&
                                spawn_load_elf("busybox", &bb_elf,
                                               &bb_elf_size, &bb_elf_src) != 0) {
                                printf("[orch] bbsh: busybox not found (binstore/sotfs/CPIO)\n");
                                bb_label = 2;
                            } else {
                                int  bb_trusted = (shell_op == ORCH_OP_BBSH_TRUSTED);
                                int  bb_tier    = bb_trusted ? FUNCTOR_TIER_EGRESS : 2;
                                printf("[orch] bbsh: spawning interactive 'busybox sh -i' %s · %lu bytes\n",
                                       bb_trusted ? "Tier-0e TRUSTED (real egress)" : "Tier-2 canary",
                                       bb_elf_size);
                                vfs_set_profile(LUCAS_PROFILE_ALPINE);
                                vfs_set_tier(bb_tier);
                                if (bb_trusted) {
                                    /* real egress for the session: suppress the
                                     * malware auto-promote (this is OUR shell) +
                                     * make python/pip children inherit Tier-0e +
                                     * give busybox the egress envp (PATH/CA). */
                                    g_egress_trusted_active = 1;
                                    g_shell_trusted_egress  = 1;
                                    extern void sotbox_spawn_set_envp_next(const char *const envp[]);
                                    sotbox_spawn_set_envp_next(EGRESS_PY_ENVP);
                                }
                                int bb_rc = sotbox_init(bb_elf, bb_elf_size, bb_argv,
                                                        /*initial_tier=*/bb_tier,
                                                        /*pledge=*/0,
                                                        /*trusted=*/bb_trusted);
                                printf("[orch] bbsh: sotbox_init rc=%d\n", bb_rc);
                                if (bb_rc == 0) {
                                    /* sotbox_init always places the primary at slot 0.
                                     * Mark it interactive so write_serial flushes each
                                     * byte (prompt + echo appear immediately). */
                                    lucas_state_t *bb_st = sotbox_get_slot(0);
                                    if (bb_st) bb_st->console_interactive = 1;
                                    printf("[orch] bbsh: entering fault loop (reply AFTER busybox exits)\n");
                                    orch_fault_loop(orch_get_fault_ep());
                                    printf("[orch] bbsh: fault loop returned · %s · resuming shell\n",
                                           g_bbsh_exit_f12 ? "F12 → operator console" : "busybox exited");
                                    sotbox_reset_primary();
                                }
                                /* label 3 = exited via F12 (open the operator console);
                                 * label 1 = spawn failure; label 0 = normal guest exit. */
                                bb_label = (bb_rc != 0) ? 1 : (g_bbsh_exit_f12 ? 3 : 0);
                                g_bbsh_exit_f12 = 0;
                                if (bb_trusted) {   /* session over · drop egress trust */
                                    g_egress_trusted_active = 0;
                                    g_shell_trusted_egress  = 0;
                                }
                            }
                            /* Reply to sotShell via the saved cap (the fault loop
                             * clobbered the implicit reply cap). */
                            if (bb_reply_slot) {
                                seL4_Send(bb_reply_slot,
                                          seL4_MessageInfo_new(bb_label, 0, 0, 0));
                                cspacepath_t bb_rp;
                                vka_cspace_make_path(bb_ov, bb_reply_slot, &bb_rp);
                                seL4_CNode_Delete(bb_rp.root, bb_rp.capPtr, bb_rp.capDepth);
                                vka_cspace_free(bb_ov, bb_reply_slot);
                            } else {
                                seL4_Reply(seL4_MessageInfo_new(bb_label, 0, 0, 0));
                            }
                        } else if (shell_op == ORCH_OP_SHUTDOWN) {
                            /* sotShell uses SHUTDOWN as its quit signal. */
                            printf("[orch] sotShell quit · closing command window\n");
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                            shell_done = true;
                        } else if (shell_op == ORCH_OP_POWEROFF) {
                            /* Clean poweroff · persist state (WAL checkpoint +
                             * flush · the simreboot Phase 1 "fsync boundary")
                             * then power off the QEMU VM via the ACPI PM1a
                             * control port (S5 soft-off · outw(0x604,0x2000)).
                             * orch holds the full-range x86 IOPort cap, so no
                             * new capability is needed. */
                            printf("[orch] POWEROFF · clean shutdown requested\n");
                            /* procd-authoritative-GC · final durable snapshot
                             * of procd's authoritative table before the
                             * checkpoint, so any runtime mutation not yet
                             * drained is persisted at the shutdown boundary. */
                            {
                                extern int procd_wal_snapshot(void);
                                (void)procd_wal_snapshot();
                            }
                            {
                                sotfs_wal_payload_checkpoint_t ck;
                                memset(&ck, 0, sizeof(ck));
                                ck.shutdown_reason = 2;   /* POWEROFF (vs SIMREBOOT=1) */
                                ck.total_records   = sotfs_wal_cursor();
                                int wrc = sotfs_wal_log_checkpoint(&ck);
                                sotfs_wal_flush();        /* durability boundary */
                                printf("[orch] POWEROFF · WAL checkpoint+flush · rc=%d · records=%lu\n",
                                       wrc, (unsigned long)ck.total_records);
                            }
                            /* Reply so the caller's seL4_Call returns before the VM dies. */
                            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                            printf("[orch] POWEROFF · powering off VM (ACPI S5 · port 0x604)\n");
                            {
                                extern seL4_CPtr orch_get_io_port_cap(void);
                                seL4_CPtr iocap = orch_get_io_port_cap();
                                if (iocap != 0) {
                                    /* Modern QEMU (PIIX4/Q35, PMBA=0x600):
                                     * PM1a_CNT=0x604 · 0x2000 = SLP_EN|S5 → exit.
                                     * Try the older 0xB004 base as a fallback. */
                                    seL4_X86_IOPort_Out16(iocap, 0x604, 0x2000);
                                    seL4_X86_IOPort_Out16(iocap, 0xB004, 0x2000);
                                }
                            }
                            /* If still alive (port unavailable) halt the CPU so
                             * we don't busy-spin · QEMU's timeout then reaps it. */
                            printf("[orch] POWEROFF · ACPI write returned · halting CPU\n");
                            seL4_DebugHalt();
                            for (;;) seL4_Yield();
                        } else {
                            printf("[orch] sotShell sent unexpected op=%lu · NAK\n",
                                   (unsigned long)shell_op);
                            seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
                        }
                    }
                }
                break;
            }
            case ORCH_OP_SYNTH_RESPONSE: {
                /* sotNet-γ · responder signals that a reply is ready.
                 * γ-3-γ-1 byte-channel path: the reply bytes are in p2c and
                 * this is a bare NBSend wake (no MRs, no reply expected) · the
                 * loop-top drain already delivers it, but drain here too for
                 * immediacy. */
                if (g_bytepipe_ready) {
                    orch_bytepipe_drain_p2c();
                    break;
                }
                /* Legacy fallback (byte channel disabled): body packed in MRs,
                 * delivered by seL4_Call · decode + log + enqueue + Reply. */
                uint32_t pr_pid      = (uint32_t)seL4_GetMR(0);
                uint32_t pr_src_ip   = (uint32_t)seL4_GetMR(1);
                uint16_t pr_src_port = (uint16_t)seL4_GetMR(2);
                uint32_t pr_body_len = (uint32_t)seL4_GetMR(3);
                char pr_body[64 + 1];
                memset(pr_body, 0, sizeof(pr_body));
                if (pr_body_len > 64) pr_body_len = 64;
                size_t pr_nwords = (pr_body_len + 7) / 8;
                for (size_t i = 0; i < pr_nwords; ++i) {
                    seL4_Word w = seL4_GetMR(4 + i);
                    size_t chunk = (pr_body_len - i * 8 < 8)
                                   ? pr_body_len - i * 8 : 8;
                    memcpy(pr_body + i * 8, &w, chunk);
                }
                pr_body[pr_body_len] = '\0';
                printf("[orch] synth→sotbox response · pid=%u src=%u.%u.%u.%u:%u body_len=%u body='%.40s%s'\n",
                       pr_pid,
                       pr_src_ip & 0xFF, (pr_src_ip >> 8) & 0xFF,
                       (pr_src_ip >> 16) & 0xFF, (pr_src_ip >> 24) & 0xFF,
                       ((pr_src_port & 0xFF) << 8) | ((pr_src_port >> 8) & 0xFF),
                       pr_body_len, pr_body,
                       pr_body_len > 40 ? "..." : "");
                {
                    uint8_t src_ip[4] = {
                        (uint8_t)(pr_src_ip & 0xFF),
                        (uint8_t)((pr_src_ip >> 8) & 0xFF),
                        (uint8_t)((pr_src_ip >> 16) & 0xFF),
                        (uint8_t)((pr_src_ip >> 24) & 0xFF),
                    };
                    sotnet_recv_enqueue(pr_pid, src_ip, pr_src_port,
                                        (const uint8_t *)pr_body,
                                        (size_t)pr_body_len);
                }
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                break;
            }
            case ORCH_OP_SHUTDOWN: {
                printf("[orch] SHUTDOWN received · halting\n");
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                return 0;
            }
            /* γ · F_persistence PR 5 · cross-process audit emission.
             *
             * sotinit / sotcron seL4_Call here to land their audit events
             * in orch's anomaly_log ring (same buffer sotShell queries via
             * ORCH_OP_QUERY_ANOMALY_LOG).  Lucas — in orch's vspace —
             * calls orch_anomaly_log_append directly; this op only serves
             * the out-of-vspace callers.  Wire format documented in
             * include/orch/proto.h alongside the op define. */
            case ORCH_OP_AUDIT_APPEND: {
                uint64_t packed = seL4_GetMR(1);
                uint16_t kind = (uint16_t)(packed & 0xFFFF);
                uint32_t slot = (uint32_t)((packed >> 16) & 0xFFFFFFFF);
                uint64_t arg0 = seL4_GetMR(2);
                orch_anomaly_log_append(slot, kind, arg0, /*arg1=*/0);
                seL4_SetMR(0, 0);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 1));
                break;
            }
            /* γ · F_persistence PR 7 · sotfs inode stat for F_persistence.
             *
             * sotinit_sotfs_scan (and the sotcron sister scan from PR 9)
             * seL4_Calls here with a 128-byte path packed into MR(0..15).
             * We resolve the path through the in-orch sotfs_graph (the
             * same graph lucas/backends_sotfs.c manages · accessed via
             * backends_sotfs_get_graph) and report back the inode's
             * functor_persistence byte.  Returning result=-1 for "not
             * resolved" keeps the caller's loop trivial · no path means
             * no tag, fall through with zero side effects.  Wire format
             * documented in include/orch/proto.h alongside the op define. */
            case ORCH_OP_F_PERSIST_STAT: {
                char path[ORCH_F_PERSIST_STAT_PATH_BYTES];
                memset(path, 0, sizeof(path));
                for (int i = 0; i < 16; i++) {
                    uint64_t w = (uint64_t)seL4_GetMR(i);
                    memcpy(&path[i * 8], &w, sizeof(w));
                }
                path[ORCH_F_PERSIST_STAT_PATH_BYTES - 1] = '\0';

                sotfs_graph_t *g = backends_sotfs_get_graph();
                int inode_id = (g != NULL) ? sotfs_resolve_path(g, path) : -1;
                if (g == NULL || inode_id <= 0) {
                    seL4_SetMR(0, (seL4_Word)(int64_t)-1);
                    seL4_SetMR(1, 0);
                    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 2));
                    break;
                }
                uint8_t flag = g->inodes[inode_id].functor_persistence;
                seL4_SetMR(0, 0);
                seL4_SetMR(1, (seL4_Word)flag);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 2));
                break;
            }
            /* α · PR 4 · cross-process WAL writer EP.
             * Path D siblings (procd, anomaly) call this op to mirror
             * their proc_t / event mutations into the sotfs WAL · sotfs
             * lives inside orch as a linked library so we just unpack the
             * payload and call the local sotfs_wal_log_* function.
             *
             * Wire format · see include/sotfs/wal_ipc.h:
             *   MR(1) = kind (SOTFS_WAL_KIND_*)
             *   MR(2..N) = payload bytes packed 8 B per MR
             *
             * Reply · MR(0) = rc (0 on commit, negative on full / IO error).
             */
            case SOTFS_OP_WAL_LOG: {
                uint32_t kind = (uint32_t)seL4_GetMR(1);
                int rc = -22; /* EINVAL default · unknown kind */

                if (kind == SOTFS_WAL_KIND_PROCD_MUT) {
                    /* 48-byte payload · 6 MRs (MR(2..7)). */
                    sotfs_wal_payload_procd_mut_t p;
                    memset(&p, 0, sizeof(p));
                    uint64_t *dst = (uint64_t *)&p;
                    for (size_t i = 0; i < sizeof(p) / sizeof(uint64_t); i++) {
                        dst[i] = (uint64_t)seL4_GetMR(2 + i);
                    }
                    rc = sotfs_wal_log_procd_mut(&p);
                } else if (kind == SOTFS_WAL_KIND_ANOMALY_EV) {
                    /* 24-byte payload · 3 MRs (MR(2..4)). */
                    sotfs_wal_payload_anomaly_ev_t p;
                    memset(&p, 0, sizeof(p));
                    uint64_t *dst = (uint64_t *)&p;
                    for (size_t i = 0; i < sizeof(p) / sizeof(uint64_t); i++) {
                        dst[i] = (uint64_t)seL4_GetMR(2 + i);
                    }
                    rc = sotfs_wal_log_anomaly_ev(&p);
                } else if (kind == SOTFS_WAL_KIND_SOTNET_SYNTH) {
                    /* 16-byte payload · 2 MRs (MR(2..3)). */
                    sotfs_wal_payload_sotnet_synth_t p;
                    memset(&p, 0, sizeof(p));
                    uint64_t *dst = (uint64_t *)&p;
                    for (size_t i = 0; i < sizeof(p) / sizeof(uint64_t); i++) {
                        dst[i] = (uint64_t)seL4_GetMR(2 + i);
                    }
                    rc = sotfs_wal_log_sotnet_synth(&p);
                } else if (kind == SOTFS_WAL_KIND_CHECKPOINT) {
                    /* 24-byte payload · 3 MRs (MR(2..4)). */
                    sotfs_wal_payload_checkpoint_t p;
                    memset(&p, 0, sizeof(p));
                    uint64_t *dst = (uint64_t *)&p;
                    for (size_t i = 0; i < sizeof(p) / sizeof(uint64_t); i++) {
                        dst[i] = (uint64_t)seL4_GetMR(2 + i);
                    }
                    rc = sotfs_wal_log_checkpoint(&p);
                } else {
                    printf("[orch] WAL_LOG · unknown kind=0x%x · ignored\n", kind);
                }

                seL4_SetMR(0, (seL4_Word)rc);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 1));
                break;
            }
            default: {
                printf("[orch] unknown op=%lu · NAK\n", (unsigned long)op);
                seL4_Reply(seL4_MessageInfo_new(1, 0, 0, 0));
                break;
            }
        }
    }
}
