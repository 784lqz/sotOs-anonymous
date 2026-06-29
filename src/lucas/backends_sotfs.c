/*
 * sotOs · LUCAS · sotFS VFS backend · DPO graph mounted at /tmp.
 *
 * Single shared sotfs_graph_t per orch (all sotBoxes see the same /tmp).
 * Each open file occupies a slot in a fixed-size handle pool.
 *
 * Phase 2 wires the 5 DPO rewrites from sotos-sotfs into the existing
 * LUCAS VFS interface.  No persistence (Phase γ adds the WAL).
 *
 * Hard constraints (§12.6):
 *   - selftest is NOT called here; it lives in sotos-sotfs-test only.
 *   - -Os is applied only to this NEW file, never to existing orch/lucas
 *     files (constraint 2 from Phase 2 spec).
 *   - The graph is a file-scope static · single shared instance for all
 *     sotBoxes (orch is single-threaded).
 */

#include <sottrace/trace.h>
#include <sotfs/graph.h>
#include "lucas/clock.h"
#include <sotfs/rewrite.h>
#include <sotfs/graph_curvature.h>
#include <sotfs/wal.h>
#include <sotfs/wal_ipc.h>
#include <sotfs/storage_virtio_blk.h>
#include <sotfs/blkdev.h>
#include <sotfs/layout.h>
#include <lucas/vfs.h>
#include <lucas/sotfs_mount.h>   /* Install-arc · per-mount root state */
#include <orch/proto.h>
#include "lucas/cow_overlay.h"   /* Phase C · per-session COW-lite read-merge */
#include "lucas/sotfs_session.h" /* apk-fs · per-session sotfs-upper ownership + reap */
/* apk-fs · the per-session owner map (sotfs_session.h, kept seL4-dep-free for the
 * host unit test) hand-mirrors SOTFS_MAX_INODES; assert they stay in lockstep so a
 * future graph bump can't silently leave high inodes untaggable (ownership leak). */
_Static_assert(LUCAS_SOTFS_SESS_MAX_INODES == SOTFS_MAX_INODES,
               "owner-map size must equal the sotfs graph inode count — bump LUCAS_SOTFS_SESS_MAX_INODES in include/lucas/sotfs_session.h");
#include <sotguard/event.h>
#include <lucas/simulated_attacker_py.h>   /* xxd-generated · installs /simulated_attacker.py */
#include <lucas/tcc_runmain_o.h>        /* xxd-generated · installs /runmain.o (tcc -run stub) */
#include <lucas/hello_dyn_bin.h>        /* xxd-generated · installs /hello_dyn.bin (=/tmp/hello_dyn.bin · apk-fs P3 T4) */
#include <lucas/spike_dyn_bin.h>        /* xxd-generated · installs /spike_dyn.bin (=/tmp/spike_dyn.bin · slice-2 C4 spike) */
#include <lucas/spikelib_so.h>          /* xxd-generated · installs /libspikelib.so (=/tmp/libspikelib.so · slice-2 C4 spike) */
#include <lucas/dpkg_hello_deb.h>       /* xxd-generated · installs /hello.deb (=/tmp/hello.deb · install arc P0.1) */
#include <lucas/dpkg_sotmark_deb.h>     /* xxd-generated · installs /sotmark.deb (postinst /etc demo · P1b) */
#include <lucas/dpkg_db_seed.h>         /* xxd-generated · seeds /var/lib/dpkg DB (install arc P1.3) */
#include <lucas/apt_tree_seed.h>        /* committed · apt /etc config bytes (apt arc P0 · /var dirs seeded here) */
#include "sto_local.h"
#include "state.h"
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#define SOTFS_HANDLE_POOL 128   /* dir-fd/build churn opens many concurrent handles */

/* Per-open-file descriptor in the handle pool. */
typedef struct {
    bool in_use;
    int  inode_id;
    int  flags;
    size_t next_child_edge; /* getdents iterator: index into g_sotfs.edges[] */
    char path[64];          /* sottrace · P3 · VFS path captured at open time */
} sotfs_handle_t;

/* Single shared graph for the whole orch instance. */
static sotfs_graph_t  g_sotfs;
static sotfs_handle_t g_handles[SOTFS_HANDLE_POOL];
static bool           g_initialised = false;

/* Deception-fidelity · per-mount roots (var/usr/etc) are created as children of
 * the graph root, which is ALSO /tmp's resolution root — so without this they
 * would show up in `ls /tmp` (a real Linux host has no /tmp/var → anti-honeypot
 * tell).  Registered names are hidden from the GRAPH-ROOT getdents listing only.
 * The explicit-path alias (cat /tmp/var/x) still resolves — a far subtler
 * residual that requires guessing the internal layout. */
static const char *g_hidden_roots[8];
static int         g_hidden_root_count;

static void sotfs_hidden_root_register(const char *name)
{
    if (!name || !*name) return;
    for (int i = 0; i < g_hidden_root_count; ++i)
        if (strcmp(g_hidden_roots[i], name) == 0) return;   /* dedup */
    if (g_hidden_root_count >= (int)(sizeof(g_hidden_roots)/sizeof(g_hidden_roots[0])))
        return;                                              /* bounded */
    g_hidden_roots[g_hidden_root_count++] = name;
}

static int sotfs_is_hidden_root(const char *name)
{
    for (int i = 0; i < g_hidden_root_count; ++i)
        if (strcmp(g_hidden_roots[i], name) == 0) return 1;
    return 0;
}

/* Forward declaration: lazy_init is defined below lucas_sotfs_install
 * because the two are mutually recursive (lazy_init calls install, install
 * calls lazy_init which returns immediately via g_initialised guard). */
static void lazy_init(void);

/* Install-arc · per-mount root resolution.  A sotfs mount carries a
 * sotfs_mount_t* in backend_state; each mount resolves its mount-relative
 * suffix from its OWN root inode (so /tmp, /var, and the /usr upper are
 * distinct top-level subtrees in the one shared g_sotfs graph).  A NULL
 * backend (or root_id<=0) falls back to the real graph root — keeping every
 * legacy/direct caller (orch honey-install, the public lucas_sotfs_*) working
 * exactly as before. */
static inline int backend_root(void *backend)
{
    if (backend) {
        int r = ((sotfs_mount_t *)backend)->root_id;
        if (r > 0) return r;
    }
    return g_sotfs.root_id;
}

/* Clock-fidelity · wall-clock seconds from the real-time clock.  The pure
 * sotfs library stays clock-free; the lucas layer stamps the inode here. */
static int64_t sotfs_now_sec(void) { int64_t s, n; lucas_now_realtime(&s, &n); (void)n; return s; }

/* Stamp ctime+mtime+atime on a freshly-created inode (by 1-based id). */
static void sotfs_stamp_create(int inode_id)
{
    if (inode_id <= 0) return;
    int slot = inode_id - 1;
    if (slot < 0 || slot >= SOTFS_MAX_INODES) return;
    int64_t now = sotfs_now_sec();
    g_sotfs.inodes[slot].mtime_sec = now;
    g_sotfs.inodes[slot].ctime_sec = now;
    g_sotfs.inodes[slot].atime_sec = now;
}

/* Bump mtime (and ctime · metadata-changing write) on a written inode. */
static void sotfs_stamp_write(int inode_id)
{
    if (inode_id <= 0) return;
    int slot = inode_id - 1;
    if (slot < 0 || slot >= SOTFS_MAX_INODES) return;
    int64_t now = sotfs_now_sec();
    g_sotfs.inodes[slot].mtime_sec = now;
    g_sotfs.inodes[slot].ctime_sec = now;
}

/* sotFS-η · expose the graph to graph_curvature.c without coupling the header. */
sotfs_graph_t *backends_sotfs_get_graph(void)
{
    if (!g_initialised) return NULL;
    return &g_sotfs;
}

/* apk-fs Phase 1 · free a session's entire sotfs-upper subtree.
 *
 * Order-independent: every inode owned by the session is freed directly (its
 * blocks via sotfs_free_block — which releases the disk bitmap, unlike the raw
 * memset in sotfs_rewrite_unlink — then its parent edge, then the inode).  The
 * whole subtree is session-owned, so no base inode can reference a freed node.
 * Until Phase 2 wires create-site tagging, no inode is owned and this is a
 * no-op, so it is safe to wire into the disconnect path now.
 *
 * Precondition: every child of every owned directory is itself session-owned
 * (guaranteed by Phase 2 create-site tagging) — else a freed dir could leave an
 * edge dangling to a live base child.  Phase 2 TODO: WAL-log the reap so a
 * mid-disconnect crash replays a consistent graph. */
void lucas_sotfs_session_reap(uint32_t session)
{
    if (session == 0) return;
    sotfs_graph_t *g = &g_sotfs;
    int id = 0;
    while ((id = lucas_sotfs_session_next_owned(session, id)) != 0) {
        for (int b = 0; b < SOTFS_MAX_BLOCKS; b++)
            if (g->blocks[b].id != 0 && g->blocks[b].file_id == id) {
                int bid = g->blocks[b].id;  /* snapshot: sotfs_free_block zeroes the slot */
                sotfs_free_block(g, bid);
            }
        for (int e = 0; e < SOTFS_MAX_EDGES; e++)
            if (g->edges[e].id != 0 && g->edges[e].child_id == id)
                sotfs_free_edge(g, g->edges[e].id);
        sotfs_free_inode(g, id);
    }
    lucas_sotfs_session_clear(session);
}

/* γ · PR 3 · apply caller's pending SOTFS hint to the just-resolved inode.
 * Reads lucas_state_t.pending_sotfs_hint (set by PR 4 right before the op),
 * stamps inode->functor_persistence on SOTFS_HINT_FUNCTOR_PERSISTENCE, and
 * clears the hint so it never bleeds across subsequent ops.  No-op when
 * there is no caller (boot-time install, internal init). */
static void apply_pending_sotfs_hint(int inode_id)
{
    if (inode_id <= 0) return;
    int slot = inode_id - 1;
    if (slot < 0 || slot >= SOTFS_MAX_INODES) return;

    lucas_state_t *caller = lucas_get_current_caller();
    if (!caller) return;
    uint32_t hint = caller->pending_sotfs_hint;
    if (hint == 0) return;

    if (hint & SOTFS_HINT_FUNCTOR_PERSISTENCE) {
        g_sotfs.inodes[slot].functor_persistence = 1;
    }
    caller->pending_sotfs_hint = 0;
}

/* sotFS-ζ · canary-installing API · atomic create-or-overwrite.
 *
 * Path semantics: full path under /tmp (root of the sotFS mount).
 * Content is copied into the graph as a single transactional rewrite.
 * Returns 0 on success, negative errno-like on failure.
 *
 * Currently this is two underlying ops (create_file + file_write) +
 * one STO transaction.  sotFS-ζ-Phase-B will make it a single
 * compound DPO rewrite once the rewrite engine supports composite
 * rules.
 */
int lucas_sotfs_install(const char *path, const void *content, size_t len)
{
    lazy_init();   /* ensure g_sotfs.root_id is set */
    if (!path || !*path) return -22; /* EINVAL */

    /* For Phase 1 we assume path is just /<leaf> (no nested dirs).
     * Strip the leading '/'. */
    const char *leaf = (path[0] == '/') ? path + 1 : path;

    char op_extra[64];
    snprintf(op_extra, sizeof(op_extra), "path=%s", path);
    sto_local_tx_t tx = sto_local_begin("sotfs:install", op_extra);

    /* If a file with this name already exists, unlink first (overwrite). */
    int existing = sotfs_find_edge(&g_sotfs, g_sotfs.root_id, leaf);
    if (existing != 0) {
        sotfs_rewrite_unlink(&g_sotfs, g_sotfs.root_id, leaf);
    }

    int rc = sotfs_rewrite_create_file(&g_sotfs, g_sotfs.root_id, leaf, 0644);
    if (rc <= 0) {
        sto_local_abort(tx);
        return -28; /* ENOSPC */
    }
    int file_id = sotfs_resolve_path(&g_sotfs, path);
    if (file_id == 0) {
        sto_local_abort(tx);
        return -5; /* EIO · should not happen */
    }

    int w = sotfs_file_write(&g_sotfs, file_id, 0,
                              (const uint8_t *)content, (uint32_t)len);
    if (w < 0) {
        sotfs_rewrite_unlink(&g_sotfs, g_sotfs.root_id, leaf);
        sto_local_abort(tx);
        return -28;
    }
    sotfs_stamp_create(file_id);   /* clock-fidelity · real mtime/atime/ctime */

    sotfs_wal_log_install((uint64_t)tx, path, content, (uint32_t)len);
    sto_local_commit(tx);
    /* CURVATURE-AUTOPROMOTE · install runs from bootstrap (lazy_init) with no
     * sotbox caller; pass pid=0 for system/operator attribution. */
    sotfs_graph_curvature_on_commit(0, "sotfs:install"); /* sotFS-η hook */
    printf("[install] %s · %zu bytes · inode=%d\n", path, len, file_id);
    return 0;
}

/* WINE-M1 (M2a) · recursive mkdir -p in the writable sotfs graph.  Materializes
 * the Windows prefix directory skeleton that wine's symlink-based drive setup
 * (symlink ../drive_c -> dosdevices/c:) would create on a real FS — but LUCAS's
 * symlink is a no-op, so the literal path dosdevices/c:/... must exist as real
 * dirs or wineboot fails "Cannot set the dir to C:\\windows" (ENOENT). */
static int sotfs_mkdir_p(const char *abspath)
{
    if (sotfs_resolve_path(&g_sotfs, abspath) > 0) return 0;     /* already exists */
    char buf[256];
    size_t n = 0;
    while (abspath[n] && n < sizeof(buf) - 1) { buf[n] = abspath[n]; ++n; }
    buf[n] = '\0';
    char *slash = NULL;
    for (char *p = buf; *p; ++p) if (*p == '/') slash = p;       /* last '/' */
    if (!slash) return -1;
    *slash = '\0';
    const char *leaf   = slash + 1;
    const char *parent = buf[0] ? buf : "/";
    int pid = sotfs_resolve_path(&g_sotfs, parent);
    if (pid <= 0) {                                              /* create parents first */
        if (sotfs_mkdir_p(parent) != 0) return -1;
        pid = sotfs_resolve_path(&g_sotfs, parent);
    }
    if (pid <= 0) return -1;
    int id = sotfs_rewrite_mkdir(&g_sotfs, pid, leaf, 0755);
    if (id > 0) sotfs_stamp_create(id);   /* clock-fidelity */
    return id > 0 ? 0 : -1;
}

/* WINE-M1 · Track M1 (PE execution) · seed a PRE-BAKED, version-matched wine
 * prefix into the writable sotfs graph at /.wine so wine treats the prefix as
 * already initialized and SKIPS the heavy in-guest wineboot bootstrap.  This is
 * an EXPLICIT mode (driven by ORCH_OP_WINE_BAKED), NOT a default — and it does
 * NOT pretend wineboot is solved: it separates "run a user PE" from "full prefix
 * bootstrap" (the latter is Track correctness · Wine M2a).  The .reg hives were
 * generated by tools/wine-bake-prefix.sh in the same alpine wine the subset is
 * staged from, then staged read-only at /usr/share/wine/baseprefix/.  Returns 0
 * on success (any file seeded), -1 on a hard failure. */
int lucas_seed_baked_wineprefix(void)
{
    lazy_init();
    extern int64_t lucas_sysroot_pread(const char *relpath, void *buf, size_t count, int64_t off);

    int dir_id = sotfs_resolve_path(&g_sotfs, "/.wine");
    if (dir_id == 0) { dir_id = sotfs_rewrite_mkdir(&g_sotfs, g_sotfs.root_id, ".wine", 0700); sotfs_stamp_create(dir_id); }
    if (dir_id <= 0) { printf("[wine-baked] FAILED to create /.wine (rc=%d)\n", dir_id); return -1; }

    /* WINE-M1 (M2a) · materialize the Windows prefix directory skeleton at the
     * literal path wine resolves C: to (dosdevices/c:/...), since LUCAS's symlink
     * is a no-op and wineboot's wine.inf dir-creation is skipped by the matched
     * .update-timestamp.  Unblocks `chdir C:\\windows` (run: err:wineboot:main
     * "Cannot set the dir to C:\\windows" (2)=ENOENT).  DLLs/NLS still resolve via
     * the unix /usr/lib/wine + /usr/share/wine paths; this is only the dir shell. */
    static const char *const SKEL[] = {
        "/.wine/drive_c",
        "/.wine/dosdevices",
        "/.wine/dosdevices/c:",
        "/.wine/dosdevices/c:/windows",
        "/.wine/dosdevices/c:/windows/system32",
        "/.wine/dosdevices/c:/windows/fonts",
        "/.wine/dosdevices/c:/windows/temp",
        "/.wine/dosdevices/c:/users",
        "/.wine/dosdevices/c:/users/Public",
        "/.wine/dosdevices/c:/users/root",
        "/.wine/dosdevices/c:/users/root/AppData",
        "/.wine/dosdevices/c:/users/root/AppData/Local",
        "/.wine/dosdevices/c:/users/root/AppData/Roaming",
        "/.wine/dosdevices/c:/users/root/Temp",
    };
    int skel_ok = 0;
    for (size_t s = 0; s < sizeof(SKEL) / sizeof(SKEL[0]); ++s)
        if (sotfs_mkdir_p(SKEL[s]) == 0) ++skel_ok;
    printf("[wine-baked] prefix dir skeleton · %d/%zu dirs created (C:\\windows navigable)\n",
           skel_ok, sizeof(SKEL) / sizeof(SKEL[0]));

    static const struct { const char *rel; const char *name; } F[] = {
        { "share/wine/baseprefix/system.reg",        "system.reg"       },
        { "share/wine/baseprefix/user.reg",          "user.reg"         },
        { "share/wine/baseprefix/userdef.reg",       "userdef.reg"      },
        { "share/wine/baseprefix/.update-timestamp", ".update-timestamp"},
    };
    static uint8_t chunk[65536];
    int seeded = 0;
    sto_local_tx_t tx = sto_local_begin("sotfs:baked-prefix", "path=/.wine");
    for (size_t k = 0; k < sizeof(F) / sizeof(F[0]); ++k) {
        if (sotfs_find_edge(&g_sotfs, dir_id, F[k].name) != 0)
            sotfs_rewrite_unlink(&g_sotfs, dir_id, F[k].name);
        int fid = sotfs_rewrite_create_file(&g_sotfs, dir_id, F[k].name, 0644);
        if (fid <= 0) { printf("[wine-baked] create /.wine/%s failed (rc=%d)\n", F[k].name, fid); continue; }
        sotfs_stamp_create(fid);   /* clock-fidelity */
        int64_t off = 0, total = 0; int bad = 0;
        for (;;) {
            int64_t got = lucas_sysroot_pread(F[k].rel, chunk, sizeof(chunk), off);
            if (got < 0) { printf("[wine-baked] read %s @%ld → %ld\n", F[k].rel, (long)off, (long)got); bad = 1; break; }
            if (got == 0) break;
            if (sotfs_file_write(&g_sotfs, fid, (uint32_t)off, chunk, (uint32_t)got) < 0) {
                printf("[wine-baked] write /.wine/%s @%ld failed\n", F[k].name, (long)off); bad = 1; break;
            }
            off += got; total += got;
            if (got < (int64_t)sizeof(chunk)) break;
        }
        if (!bad) { printf("[wine-baked] seeded /.wine/%s · %ld bytes (inode=%d)\n", F[k].name, (long)total, fid); seeded++; }
    }
    sto_local_commit(tx);
    printf("[wine-baked] PRE-BAKED PREFIX seeded · %d/%zu hives into /.wine · "
           "wine should SKIP wineboot (prefix is pre-baked, NOT in-guest booted)\n",
           seeded, sizeof(F) / sizeof(F[0]));
    return seeded > 0 ? 0 : -1;
}

static void lazy_init(void)
{
    if (g_initialised) return;
    sotfs_graph_init(&g_sotfs);
    g_initialised = true;

    /* clock-fidelity · the pure graph lib is clock-free, so the root dir inode
     * (the /tmp mount-root) is born with mtime=0 → `ls -la /` shows "Jan 1 1970
     * tmp".  Stamp it here with the wall clock (children are stamped on create). */
    sotfs_stamp_create(g_sotfs.root_id);

    printf("[sotfs] graph capacity · inodes=%d edges=%d blocks=%d (%d KiB writable)\n",
           SOTFS_MAX_INODES, SOTFS_MAX_EDGES, SOTFS_MAX_BLOCKS,
           (SOTFS_MAX_BLOCKS * SOTFS_BLOCK_SIZE) / 1024);

    /* sotFS-γ Phase 2d · prefer virtio-blk if the device is ready;
     * fall back to RAM if virtio-blk failed init (keeps boot safe). */
    sotfs_storage_t storage;
    if (sotfs_storage_virtio_blk_ready()) {
        storage = sotfs_storage_virtio_blk();
        printf("[sotfs] WAL backend = virtio-blk · 4 MiB persistent\n");
    } else {
        storage = sotfs_storage_ram();
        printf("[sotfs] WAL backend = RAM · NOT persistent (virtio-blk not ready)\n");
    }
    sotfs_wal_init(&storage);

    /* Phase 1b · bring up the disk-backed block store on the same virtio-blk
     * device (data region after the WAL).  Must run BEFORE wal_replay_apply,
     * because replay calls sotfs_file_write which needs the block store live.
     * Falls back gracefully: over RAM storage (RAM-WAL boot) the data region is
     * just RAM-backed and non-persistent that boot.  A freshly-zeroed region
     * (first boot of a new image) self-formats; an existing one re-attaches. */
    if (sotfs_blkdev_init(&storage, SOTFS_DATA_OFFSET, SOTFS_DATA_REGION_BYTES, /*fresh=*/0) == 0) {
        printf("[sotfs] blkdev · data heap up · %lu blocks total\n",
               (unsigned long)sotfs_blk_total());
    } else {
        printf("[sotfs] blkdev · init FAILED · writable fs degraded\n");
    }

    /* PR 5 · top-level WAL replay dispatcher.  Drives the file-only
     * handler today; PR 6 will extend it to dispatch non-FS kinds
     * (procd / anomaly / sotnet) to per-subsystem replays. */
    sotfs_wal_replay_apply(&g_sotfs);   /* replays any records written in a prior boot */

    /* procd-authoritative-GC · now that the WAL backend is up AND replay-apply
     * has finalized the append cursor, durably snapshot procd's authoritative
     * proc table to the WAL (orch-side, in-process · the non-blocking
     * replacement for procd's retired blocking WAL writer).  Must run AFTER
     * replay_apply returns — writing mid-replay corrupts the append cursor. */
    extern int procd_wal_snapshot(void);
    (void)procd_wal_snapshot();

    /* procd-readers · prove the bounded lucas accessor reads procd's live
     * table via g_procd_shm_ro (table is populated by now). One-shot. */
    {
        extern void lucas_proct_selftest(void);
        lucas_proct_selftest();
    }

    /* sotFS-ζ · install welcome + canary bait files via the new API. */
    const char *welcome = "HOLA from sotFS-α DPO\n";
    lucas_sotfs_install("/welcome", welcome, strlen(welcome));

    /* sotFS-ζ demonstration · install canary credentials + a note.
     * These are anomaly-placed bait files; a Tier 2 sotBox reading
     * them is signaling attack intent. */
    /* Content reads as GENUINE leaked credentials (real AKIA/secret format, no
     * self-disclosing words) so `cat` reveals nothing about the trap — the old
     * body literally said "SOTOS CANARY · FAKE · tripwire", a 100% honeypot tell.
     * The filename stays (canary detection + boot/operator self-tests key on the
     * path); the honey-* → plausible-home RENAME is a boot-verified follow-up. */
    const char *aws_creds =
        "[default]\n"
        "aws_access_key_id = AKIA5XK7QJ3NVB8TPLM2\n"
        "aws_secret_access_key = wJ8rXuP1fEMI/K7MDleNG+bPxRfiCYz9aQ2RsTvL\n"
        "region = us-east-1\n"
        "[deploy-s3]\n"
        "aws_access_key_id = AKIA5XK7QJ3NVB8TQ9RT\n"
        "aws_secret_access_key = aB3kPq7Xz1nMv5RsT9uWp2YdGf8HjKlN0QcErZxV\n"
        "region = us-east-1\n";
    lucas_sotfs_install("/honey-aws-creds", aws_creds, strlen(aws_creds));

    const char *readme =
        "S3 backup rotation: prod-db snapshots → s3 nightly via cron (see runbook).\n"
        "keys rotated quarterly; last rotation 2026-03-01 by deploy@prod-db-01\n";
    lucas_sotfs_install("/honey-readme.txt", readme, strlen(readme));

    /* SP1 PR 5 · install the `tcc -run` milestone files FIRST (before the
     * ~30-block simulated_attacker.py) so their blocks are reserved while the
     * sotfs graph has the most free space · the boot-driven TCC gates
     * depend on both being present every boot, even after WAL replay has
     * pre-populated the graph from prior boots.
     *
     * runmain.o · `tcc -run` ALWAYS links its _runmain entry (the stub that
     * calls main) from <tccdir>/runmain.o, even for a freestanding source.
     * With -nostdlib (no libc) and a freestanding program (no headers, no
     * compiler-helper symbols) this is the ONLY runtime object TCC needs —
     * libtcc1.a is not pulled in.  Installed at sotfs /runmain.o, it appears
     * to the sotbox VFS as /tmp/runmain.o, so the trusted tcc sotbox finds
     * it via "-B/tmp".  (~3.5 KiB · 7 sotfs blocks.) */
    lucas_sotfs_install("/runmain.o", runmain_o, runmain_o_len);

    /* Install-arc P0.1 · the real Debian `hello_2.10-5_amd64.deb`, installed
     * into the writable sotfs at /hello.deb.  The sotfs mounts at /tmp inside a
     * sotbox, so a guest sees it as /tmp/hello.deb — Phase 0.2's
     * `dpkg-deb -x /tmp/hello.deb /tmp/root` reads it back off the writable fs.
     * The .deb is DATA (an ar archive), so it ships as an embedded blob (xxd),
     * NOT a binstore executable entry. (~52 KiB.) */
    lucas_sotfs_install("/hello.deb", hello_deb, hello_deb_len);

    /* Install-arc P1b · sotmark.deb · a package whose postinst writes /etc.  Same
     * blob-install as hello.deb (guest sees /tmp/sotmark.deb).  `dpkg -i` unpacks
     * + runs its maintainer script (fork+execve /bin/sh → /etc/sotmark.conf via
     * the writable /etc union). (~1 KiB.) */
    lucas_sotfs_install("/sotmark.deb", sotmark_deb, sotmark_deb_len);

    /* apk-fs Phase 3 Task 4 · hello_dyn.bin · the dynamically-linked musl PIE
     * (NEEDED libc.so, interp /lib/ld-musl-x86_64.so.1, ~7.5 KiB).  Installed
     * at sotfs /hello_dyn.bin → guest sees /tmp/hello_dyn.bin.  The apk-upperexec
     * gate does: cat /tmp/hello_dyn.bin > /usr/bin/upbin && /usr/bin/upbin
     * (ld-musl resolves libc from sysroot, prints "[hello-dyn] dynamic musl OK",
     * exits 0 — proves runtime-staged VFS-upper ELF is executable). */
    lucas_sotfs_install("/hello_dyn.bin", hello_dyn_bin, hello_dyn_bin_len);

    /* apk-fs slice-2 C4 spike · a NEEDED .so + its client, staged to /tmp.  The
     * gate copies BOTH into the per-session upper (/usr/lib/libspikelib.so +
     * /usr/bin/spikebin) and execs spikebin: ld-musl must open the .so FROM THE
     * UPPER (the apk-installed libncursesw.so.6 case).  libspikelib.so is NOT in
     * the sysroot, so a successful resolve PROVES the upper read path (not a
     * baked-base fallback).  Blobs ship as C arrays so they ride the VFS upper. */
    lucas_sotfs_install("/spike_dyn.bin", spike_dyn_bin, spike_dyn_bin_len);
    lucas_sotfs_install("/libspikelib.so", libspikelib_so, libspikelib_so_len);

    /* st-hello.c · the freestanding C source for the milestone.  No libc,
     * no headers, raw inline-asm syscalls — so TinyCC needs no runtime lib
     * (libtcc1.a) nor system include path to compile + JIT it.  Installed at
     * sotfs root "/st-hello.c"; the sotfs is mounted at /tmp inside the
     * sotbox, so the trusted tcc sotbox opens it as "/tmp/st-hello.c" (the
     * path cmd_tcc is invoked with at boot). */
    static const char st_hello_c[] =
        "/* st-hello.c · freestanding · raw syscalls, no libc, no headers. */\n"
        "static long sc3(long n,long a,long b,long c){long r;\n"
        "  __asm__ volatile(\"syscall\":\"=a\"(r):\"a\"(n),\"D\"(a),\"S\"(b),\"d\"(c):\"rcx\",\"r11\",\"memory\");\n"
        "  return r;}\n"
        "int main(void){ const char m[]=\"[st-hello] tcc-run OK\\n\";\n"
        "  sc3(1,1,(long)m,sizeof(m)-1);   /* write(1,m,len) */\n"
        "  sc3(60,0,0,0);                  /* exit(0) */\n"
        "  return 0;}\n";
    lucas_sotfs_install("/st-hello.c", st_hello_c, sizeof(st_hello_c) - 1);

    /* SP2 · freestanding source that DEFINES _start (no crt0) so `tcc -o`
     * emits a valid static EXEC with e_entry=_start (no runmain.o needed,
     * that is a `-run`-only stub).  Installed at sotfs /st-hello-emit.c · the
     * sotbox sees it as /tmp/st-hello-emit.c (sotfs mounts at /tmp). */
    static const char st_hello_emit_c[] =
        "/* st-hello-emit.c · freestanding · defines _start · no libc/crt0. */\n"
        "static long sc3(long n,long a,long b,long c){long r;\n"
        "  __asm__ volatile(\"syscall\":\"=a\"(r):\"a\"(n),\"D\"(a),\"S\"(b),\"d\"(c):\"rcx\",\"r11\",\"memory\");\n"
        "  return r;}\n"
        "void _start(void){ const char m[]=\"[sp2-hello] elf-run OK\\n\";\n"
        "  sc3(1,1,(long)m,sizeof(m)-1);   /* write(1,m,len) */\n"
        "  sc3(60,0,0,0);                  /* exit(0) */\n"
        "}\n";
    lucas_sotfs_install("/st-hello-emit.c", st_hello_emit_c, sizeof(st_hello_emit_c) - 1);

    /* tcc-libc · hosted milestone source: a REAL libc program (#include <stdio.h>
     * + printf), linked against the standard x86_64 musl sysroot at /usr.
     * Installed at sotfs /hello-libc.c (sotbox sees /tmp/hello-libc.c). */
    static const char hello_libc_c[] =
        "#include <stdio.h>\n"
        "int main(void){ printf(\"[sp2-libc] hello from musl printf\\n\"); return 0; }\n";
    lucas_sotfs_install("/hello-libc.c", hello_libc_c, sizeof(hello_libc_c) - 1);

    /* STAR demo · install the simulated_attacker.py script (5-stage Python agent
     * that exercises all 7 STAR triggers).  Operator runs it via:
     *   sotos> inject-script /simulated_attacker.py
     * sotShell spawns python3.12-static with the path as argv (NOT -c), so
     * the script size is not bounded by the spawn argv pool. */
    lucas_sotfs_install("/simulated_attacker.py",
                      scripts_demo_simulated_attacker_py,
                      scripts_demo_simulated_attacker_py_len);

    /* sotFS-θ trigger demo · simulate ransomware behavior.
     *
     * The Forman-Ricci formula κ_F(xy) = deg(x)+deg(y)-tri-2 always
     * RISES when adding leaf files to a star.  To manufacture a drop
     * ≥ 2.0 we use a two-phase approach that faithfully models the
     * real ransomware pattern (encrypt-and-delete-originals):
     *
     * Phase 1 · "encrypt": install 8 .enc twins, each calling graph_curvature.
     *   Every install raises mean_k by ~1 (graph grows, root degree rises).
     *   After 8 installs, mean_k ≈ 10, g_last_mean_k ≈ 10.
     *
     * Phase 2 · "delete originals": silently unlink 4 originals via
     *   sotfs_rewrite_unlink (no intermediate graph_curvature call) to collapse
     *   root degree from 11 to 7.  mean_k = 6 when we fire the next
     *   graph_curvature commit.  delta = 10 - 6 = 4.0 ≥ 2.0 → RANSOMWARE rule fires.
     *
     * Note: enc content is empty (len=0) to avoid exhausting the tiny
     *   SOTFS_MAX_BLOCKS=4 pool.  The graph topology (inodes + edges) is
     *   what the curvature monitor cares about, not file content. */

    /* Phase 1: install .enc twins — builds up mean_k. */
    static const char *enc_paths[] = {
        "/welcome.enc",
        "/honey-aws-creds.enc",
        "/honey-readme.txt.enc",
        "/passwords.txt.enc",
        "/keys.pem.enc",
        "/financial.csv.enc",
        "/photos.tar.enc",
        "/medical-records.enc",
    };
    for (size_t i = 0; i < sizeof(enc_paths)/sizeof(enc_paths[0]); ++i) {
        lucas_sotfs_install(enc_paths[i], "", 0);
    }

    /* Phase 2: silently delete 4 .enc twins (no graph_curvature between unlinks).
     * This drops the graph curvature WITHOUT updating g_last_mean_k,
     * so the next graph_curvature commit sees a large drop and fires the rule.
     * The 3 baseline canary files are preserved for the L1-L8 smoke tests. */
    sotfs_rewrite_unlink(&g_sotfs, g_sotfs.root_id, "welcome.enc");
    sotfs_rewrite_unlink(&g_sotfs, g_sotfs.root_id, "honey-aws-creds.enc");
    sotfs_rewrite_unlink(&g_sotfs, g_sotfs.root_id, "honey-readme.txt.enc");
    sotfs_rewrite_unlink(&g_sotfs, g_sotfs.root_id, "passwords.txt.enc");

    /* sotFS-η · run initial curvature snapshot now that graph is live.
     * This commit fires with mean_k ≈ 6 while g_last_mean_k ≈ 10,
     * triggering the RANSOMWARE candidate rule (delta ≥ 2.0). */
    sotfs_graph_curvature_recompute_all(&g_sotfs);
    /* CURVATURE-AUTOPROMOTE · boot-time snapshot · pid=0 (system). */
    sotfs_graph_curvature_on_commit(0, "sotfs:init");  /* emit first [graph-curvature] line */
    printf("[sotfs] mounted /tmp · root_id=%d\n", g_sotfs.root_id);
}

/* ── path helpers ─────────────────────────────────────────────────────── */

/*
 * Split a VFS suffix into parent path + leaf name.
 *
 * The VFS layer strips the mount prefix ("/tmp") from the client path
 * before calling us, so `path` here is the suffix portion:
 *   "/foo"     → parent "/", leaf "foo"
 *   "/a/b/c"   → parent "/a/b", leaf "c"
 *   "/"        → root directory (no leaf)
 *
 * `parent_out` must be at least 256 bytes.
 * Returns 0 on success, -1 if the path is malformed or the leaf is empty.
 */
static int split_path(const char *path,
                      char parent_out[256], const char **leaf_out)
{
    if (!path || path[0] != '/') return -1;

    const char *last_slash = strrchr(path, '/');
    if (!last_slash) return -1;

    size_t parent_len = (size_t)(last_slash - path);

    if (parent_len == 0) {
        /* path == "/foo": parent is root "/" */
        parent_out[0] = '/';
        parent_out[1] = '\0';
    } else {
        if (parent_len >= 256) return -1;
        memcpy(parent_out, path, parent_len);
        parent_out[parent_len] = '\0';
    }

    const char *leaf = last_slash + 1;
    if (leaf[0] == '\0') return -1; /* trailing slash or plain "/" */
    *leaf_out = leaf;
    return 0;
}

/* ── sotShell operator-side accessors ────────────────────────────────── */

/*
 * lucas_sotfs_list_dir · enumerate children of the directory at `path`.
 * `out` must point to an array of at least `max` sotfs_dirent structs.
 * Returns number of entries filled, or negative on error.
 *
 * This is a read-only accessor; it does not mutate the graph.
 */
/* NB: name[32] is the OPERATOR-display cap (the `ls` command's IPC reply budget,
 * mirrored by op_dirent_t / orch_sotfs_dirent_t), INTENTIONALLY narrower than the
 * 64-byte SOTFS_MAX_NAME graph edges.  A guest's own getdents64 (op_getdents)
 * uses the full edge name, so git's 38-char object names are intact for git;
 * only the operator `ls` of such a dir truncates the display to 31 chars. */
typedef struct sotfs_dirent {
    char     name[32];
    uint32_t size;
    uint8_t  kind;   /* 1=file, 2=dir */
    uint8_t  pad[3];
} sotfs_dirent_t;

/* Strip the sotfs VFS mount prefix "/tmp" from an operator path.
 * e.g. "/tmp" -> "/", "/tmp/welcome" -> "/welcome". */
static const char *strip_tmp_prefix(const char *path)
{
    if (!path) return "/";
    /* Strip "/tmp" ONLY when it is a COMPLETE path component (followed by '/'
     * or end-of-string) — never as a prefix of a longer name.  Python tempfiles
     * are named "tmpXXXXXX", so a mount-relative "/tmpXXXXXX" must NOT be treated
     * as "/tmp" + "XXXXXX": that second (false) strip dropped the leading '/',
     * split_path() then failed (no '/') → -EINVAL on unlink, which pip surfaced
     * as the interactive `pip install` "Connection broken: OSError(22)". */
    if (strncmp(path, "/tmp", 4) == 0 && (path[4] == '/' || path[4] == '\0')) {
        const char *rest = path + 4;
        return (*rest == '\0') ? "/" : rest;
    }
    return path;
}

int lucas_sotfs_list_dir(const char *path, sotfs_dirent_t *out, int max)
{
    lazy_init();
    if (!path || !out || max <= 0) return -22; /* EINVAL */

    const char *fs_path = strip_tmp_prefix(path);
    int dir_id = sotfs_resolve_path(&g_sotfs, fs_path);
    if (dir_id == 0) return -2; /* ENOENT */

    int slot = dir_id - 1;
    if (slot < 0 || slot >= SOTFS_MAX_INODES) return -2;
    if (g_sotfs.inodes[slot].kind != SOTFS_KIND_DIR) return -20; /* ENOTDIR */

    int count = 0;
    for (int i = 0; i < SOTFS_MAX_EDGES && count < max; ++i) {
        const sotfs_edge_t *e = &g_sotfs.edges[i];
        if (e->id == 0) continue;
        if (e->parent_id != dir_id) continue;

        int child_slot = e->child_id - 1;
        if (child_slot < 0 || child_slot >= SOTFS_MAX_INODES) continue;

        const sotfs_inode_t *ino = &g_sotfs.inodes[child_slot];
        strncpy(out[count].name, e->name, 31);
        out[count].name[31] = '\0';
        out[count].size = ino->size;
        out[count].kind = (ino->kind == SOTFS_KIND_DIR) ? 2 : 1;
        out[count].pad[0] = out[count].pad[1] = out[count].pad[2] = 0;
        count++;
    }
    return count;
}

/*
 * lucas_sotfs_read_file · read up to `max` bytes from the file at `path`.
 * Returns number of bytes read, or negative on error.
 *
 * This is a read-only accessor; it does not mutate the graph.
 */
int lucas_sotfs_read_file(const char *path, void *buf, size_t max)
{
    lazy_init();
    if (!path || !buf || max == 0) return -22; /* EINVAL */

    const char *fs_path = strip_tmp_prefix(path);
    int file_id = sotfs_resolve_path(&g_sotfs, fs_path);
    if (file_id == 0) return -2; /* ENOENT */

    int slot = file_id - 1;
    if (slot < 0 || slot >= SOTFS_MAX_INODES) return -2;
    if (g_sotfs.inodes[slot].kind == SOTFS_KIND_DIR) return -21; /* EISDIR */

    int rc = sotfs_file_read(&g_sotfs, file_id, 0, (uint8_t *)buf, (uint32_t)max);
    return rc;
}

/* sotnano · read up to `max` bytes from `path` starting at `off`.
 * Returns bytes read (0 at/after EOF), or negative errno-style on error. */
int lucas_sotfs_read_at(const char *path, uint32_t off, uint8_t *out, uint32_t max)
{
    lazy_init();
    if (!path || !out || max == 0) return -22; /* EINVAL */
    const char *fs_path = strip_tmp_prefix(path);
    int file_id = sotfs_resolve_path(&g_sotfs, fs_path);
    if (file_id == 0) return -2; /* ENOENT */
    int slot = file_id - 1;
    if (slot < 0 || slot >= SOTFS_MAX_INODES) return -2;
    if (g_sotfs.inodes[slot].kind == SOTFS_KIND_DIR) return -21; /* EISDIR */
    int rc = sotfs_file_read(&g_sotfs, file_id, off, out, max);
    return rc; /* sotfs_file_read returns bytes read (clamped at EOF) */
}

/* sotnano · write `len` bytes to `path` at `off`.  If `truncate`, the file
 * is reset to empty first (unlink+recreate) so a shrunk document leaves no
 * stale tail.  Creates the file if missing.  WAL-logged → survives simreboot. */
int lucas_sotfs_write_at(const char *path, uint32_t off, const uint8_t *data,
                         uint32_t len, int truncate)
{
    lazy_init();
    if (!path) return -22;
    const char *fs_path = strip_tmp_prefix(path);

    char parent_path[256];
    const char *leaf;
    if (split_path(fs_path, parent_path, &leaf) != 0) return -22;
    int parent_id = sotfs_resolve_path(&g_sotfs, parent_path);
    if (parent_id == 0) return -2; /* ENOENT · parent dir missing */

    if (truncate) {
        int existing = sotfs_find_edge(&g_sotfs, parent_id, leaf);
        if (existing != 0) {
            /* WAL-log the unlink inside a tx · without this the shrink is
             * not replayed on simreboot and the old (longer) file
             * resurrects, leaving a stale tail past the new content. */
            char ux[80];
            snprintf(ux, sizeof(ux), "path=%s", fs_path);
            sto_local_tx_t utx = sto_local_begin("sotfs:unlink", ux);
            sotfs_rewrite_unlink(&g_sotfs, parent_id, leaf);
            sotfs_wal_log_unlink((uint64_t)utx, parent_id, leaf);
            sto_local_commit(utx);
        }
    }

    int file_id = sotfs_resolve_path(&g_sotfs, fs_path);
    if (file_id == 0) {
        char ex[80];
        snprintf(ex, sizeof(ex), "path=%s", fs_path);
        sto_local_tx_t ctx = sto_local_begin("sotfs:create_file", ex);
        int rc = sotfs_rewrite_create_file(&g_sotfs, parent_id, leaf, 0644);
        if (rc <= 0) { sto_local_abort(ctx); return -28; }
        sotfs_wal_log_create_file((uint64_t)ctx, parent_id, leaf, 0644);
        sto_local_commit(ctx);
        file_id = sotfs_resolve_path(&g_sotfs, fs_path);
        if (file_id == 0) return -5;
        sotfs_stamp_create(file_id);   /* clock-fidelity */
    }

    if (len == 0) return 0; /* truncate-only call (empty file) */

    char ex2[80];
    snprintf(ex2, sizeof(ex2), "off=%u len=%u", off, len);
    sto_local_tx_t tx = sto_local_begin("sotfs:write", ex2);
    int w = sotfs_file_write(&g_sotfs, file_id, off, data, len);
    if (w < 0) { sto_local_abort(tx); return -28; }
    sotfs_stamp_write(file_id);   /* clock-fidelity · bump mtime on write */
    /* Log keyed on PATH (not inode_id) so the file survives simreboot:
     * inode IDs are not stable across WAL replay (demo installs run after
     * replay and shift allocation), so a target_id-keyed write replays to
     * the wrong inode and the edited file comes back empty. */
    sotfs_wal_log_write_path((uint64_t)tx, fs_path, off, data, len);
    sto_local_commit(tx);
    return w;
}

/* ── op_open ──────────────────────────────────────────────────────────── */

static int op_open(void *backend, const char *path, int flags, uint32_t mode,
                   void **out_handle)
{
    (void)mode;
    lazy_init();
    int root = backend_root(backend);

    int inode_id = sotfs_resolve_path_from(&g_sotfs, root, path);

    if (inode_id == 0) {
        /* Linux O_CREAT is 0x40 (64) on x86_64. */
        if (!(flags & 0x40 /* O_CREAT */)) return -2; /* -ENOENT */

        /* sotFS-ε: Tier 2 isolated-write path · silence create, no graph mutation.
         *
         * γ · F_persistence override: persistence-sensitive paths (crontab,
         * unit files, shell rc, freedesktop autostart) MUST be allowed to
         * create even from a Tier-2 sotbox · the whole point of the lie is
         * that the malware reads back its install intact post-simreboot.
         * sotinit/sotcron then refuse to fire on functor_persistence=1
         * inodes · the bytes persist but nothing executes. */
        {
            lucas_state_t *caller = lucas_get_current_caller();
            bool fpersist_override = (caller != NULL) &&
                (caller->pending_sotfs_hint & SOTFS_HINT_FUNCTOR_PERSISTENCE);
            /* apk-fs P2 · a Tier-2 SSH session (cow_session != 0) is allowed to
             * CREATE into the shared graph — the inode is tagged to the session
             * (Step 3) so it is operator-invisible + reaped on disconnect.  This
             * REPLACES the legacy -EACCES "Synth-drop" so apk can really create
             * /usr/bin/<pkg>, /etc/apk/world, /lib/apk/db/installed, etc.  A
             * Tier-2 caller WITHOUT a session (cow_session == 0, e.g. a Tier-0
             * fork child) keeps the legacy drop · no per-session owner to tag. */
            bool session_create = (caller != NULL) && (caller->cow_session != 0);
            if (caller && caller->functor && caller->functor->is_isolated &&
                !fpersist_override && !session_create) {
                printf("[isolated] pid=%d tier=2 · sotfs create_file %s silently dropped (Synth branch)\n",
                       caller->synthetic_pid, path);
                if (caller) trace_emit_isolated_write_drop(caller->slot_index,
                                                   (uint32_t)caller->synthetic_pid, path);
                return -13; /* -EACCES · shell will report "Permission denied" */
            }
            if (session_create) {
                printf("[isolated] pid=%d tier=2 sess=%u · sotfs create %s → session upper (tagged, base intact)\n",
                       caller->synthetic_pid, caller->cow_session, path);
                /* TODO(apk-fs P4/C5): trace_emit_isolated_write_drop renders as
                 * "write denied" on the operator dashboard, but this path is a
                 * SUCCESSFUL contained create, not a drop.  Re-emit as the proper
                 * PACKAGE_INSTALL/contained-create IOC when C5 lands; for now we
                 * keep this so the create stays observable in the trace. */
                trace_emit_isolated_write_drop(caller->slot_index,
                                               (uint32_t)caller->synthetic_pid, path);
            }
            if (fpersist_override) {
                printf("[mirror+fpersist] pid=%d tier=2 · %s · F_persistence override · proceeding with create\n",
                       caller ? caller->synthetic_pid : -1, path);
            }
        }

        char parent_path[256];
        const char *leaf;
        if (split_path(path, parent_path, &leaf) != 0) return -22; /* -EINVAL */

        int parent_id = sotfs_resolve_path_from(&g_sotfs, root, parent_path);
        if (parent_id == 0) {
            /* γ · F_persistence mkdir -p · for persistence-install paths
             * (/etc/systemd/system/foo.service, /etc/cron.d/bar, etc.) the
             * intermediate directories likely don't exist in the sotfs
             * graph yet · auto-create them so the malware's open(O_CREAT)
             * succeeds the same way it would on a real Linux system. */
            lucas_state_t *caller_for_mkdir = lucas_get_current_caller();
            bool needs_auto_mkdir = (caller_for_mkdir != NULL) &&
                (caller_for_mkdir->pending_sotfs_hint & SOTFS_HINT_FUNCTOR_PERSISTENCE);
            if (!needs_auto_mkdir) return -2; /* -ENOENT · non-persistence path */

            /* Walk components left-to-right under the root, creating each
             * missing directory.  parent_path looks like "/etc/systemd/system"
             * · we mkdir "/etc", "/etc/systemd", "/etc/systemd/system" as
             * needed. */
            char cur[256];
            cur[0] = '\0';
            int cur_parent = (root > 0) ? root : g_sotfs.root_id;
            if (cur_parent == 0) return -2;
            const char *p = parent_path;
            if (*p == '/') p++;          /* skip leading slash */
            while (*p) {
                const char *seg_start = p;
                while (*p && *p != '/') p++;
                size_t seg_len = (size_t)(p - seg_start);
                if (seg_len == 0 || seg_len >= 64) return -22;
                char seg[64];
                memcpy(seg, seg_start, seg_len);
                seg[seg_len] = '\0';

                /* extend cur for path lookup */
                size_t cur_len = strlen(cur);
                if (cur_len + 1 + seg_len + 1 >= sizeof(cur)) return -22;
                cur[cur_len] = '/';
                memcpy(cur + cur_len + 1, seg, seg_len + 1);

                int existing = sotfs_resolve_path_from(&g_sotfs, root, cur);
                if (existing == 0) {
                    /* auto-mkdir this component */
                    char mk_extra[80];
                    snprintf(mk_extra, sizeof(mk_extra), "path=%s", cur);
                    sto_local_tx_t mtx = sto_local_begin("sotfs:mkdir", mk_extra);
                    int mrc = sotfs_rewrite_mkdir(&g_sotfs, cur_parent, seg, 0755);
                    if (mrc <= 0) { sto_local_abort(mtx); return -28; }
                    /* apk-fs · a Tier-2 SSH session (cow_session!=0) auto-mkdir is
                     * SESSION-LIFETIME like every other session create: do NOT
                     * WAL-log it (durability would resurrect it UNTAGGED →
                     * operator-visible on reboot · concern-3 variant) and TAG it
                     * to the session (else the intermediate dir is an untagged
                     * base dir the operator sees immediately).  A sessionless
                     * fpersist caller (cow_session==0 · captured-malware
                     * persistence) keeps the durable, observable behavior. */
                    if (!caller_for_mkdir || caller_for_mkdir->cow_session == 0)
                        sotfs_wal_log_mkdir((uint64_t)mtx, cur_parent, seg, 0755);
                    sto_local_commit(mtx);
                    existing = sotfs_resolve_path_from(&g_sotfs, root, cur);
                    if (existing == 0) return -5;
                    sotfs_stamp_create(existing);   /* clock-fidelity */
                    if (caller_for_mkdir && caller_for_mkdir->cow_session != 0)
                        lucas_sotfs_session_tag(existing, caller_for_mkdir->cow_session);
                    printf("[fpersist] auto-mkdir %s · inode=%d\n", cur, existing);
                }
                cur_parent = existing;
                if (*p == '/') p++;
            }
            parent_id = cur_parent;
        }

        char op_extra[64];
        snprintf(op_extra, sizeof(op_extra), "path=%s", path);
        sto_local_tx_t tx = sto_local_begin("sotfs:create_file", op_extra);
        int rc = sotfs_rewrite_create_file(&g_sotfs, parent_id, leaf,
                                            mode ? mode : 0644);
        /* sotfs_rewrite_create_file returns positive inode_id on success,
         * negative error code (SOTFS_ERR_*) on failure.  Checking
         * `!= SOTFS_OK` (== 0) would incorrectly abort on success. */
        if (rc <= 0) {
            sto_local_abort(tx);
            /* Map the sotfs error to the right errno · a blanket -ENOSPC
             * mislabeled a NAMETOOLONG (-7) on apt's long list filenames as
             * "No space left on device". */
            switch (rc) {
                case SOTFS_ERR_NAMETOOLONG: return -36; /* -ENAMETOOLONG */
                case SOTFS_ERR_EXISTS:      return -17; /* -EEXIST */
                case SOTFS_ERR_NOTDIR:      return -20; /* -ENOTDIR */
                case SOTFS_ERR_INVAL:       return -22; /* -EINVAL */
                default:                    return -28; /* -ENOSPC */
            }
        }
        /* apk-fs · a Tier-2 session-tagged create is SESSION-LIFETIME (reaped on
         * disconnect, base pristine).  Do NOT WAL-log it: durability would resurrect
         * it on reboot as an empty, UNTAGGED (g_owner is BSS) operator-visible base
         * inode (containment leak "concern-3") AND break a later session's write→read
         * of the same path.  The live graph + on-disk data blocks serve the session;
         * on reboot it is correctly gone.  (Tier-0/boot creates stay WAL-logged.) */
        {
            lucas_state_t *wc = lucas_get_current_caller();
            bool sess = wc && wc->cow_session != 0;
            if (!sess)
                sotfs_wal_log_create_file((uint64_t)tx, parent_id, leaf, mode ? mode : 0644);
        }
        sto_local_commit(tx);
        /* CURVATURE-AUTOPROMOTE · attribute curvature to calling sotbox. */
        {
            lucas_state_t *caller = lucas_get_current_caller();
            uint32_t cpid = (caller ? (uint32_t)caller->synthetic_pid : 0u);
            sotfs_graph_curvature_on_commit(cpid, "sotfs:create_file"); /* sotFS-η */
        }

        inode_id = sotfs_resolve_path_from(&g_sotfs, root, path);
        if (inode_id == 0) return -5; /* -EIO: shouldn't happen */
        sotfs_stamp_create(inode_id);   /* clock-fidelity · real mtime/atime/ctime */

        /* apk-fs P2 · tag this new inode to the creating SSH session so it is
         * operator-invisible (op_read/op_stat/op_getdents gate · added in Task 3)
         * and reaped on disconnect (lucas_sotfs_session_reap already walks
         * g_sotfs).  Gated on cow_session != 0 → Tier-0/boot creates stay untagged
         * (= base, visible). */
        {
            lucas_state_t *tag_caller = lucas_get_current_caller();
            if (tag_caller && tag_caller->cow_session != 0)
                lucas_sotfs_session_tag(inode_id, tag_caller->cow_session);
        }

        /* γ · PR 3 · stamp F_persistence at create time so an
         * open(O_CREAT|O_WRONLY, ...) install gets flagged on the very
         * first byte (write follows on the same handle). */
        apply_pending_sotfs_hint(inode_id);
    }

    /* Allocate a handle slot. */
    for (int i = 0; i < SOTFS_HANDLE_POOL; ++i) {
        if (!g_handles[i].in_use) {
            g_handles[i].in_use          = true;
            g_handles[i].inode_id        = inode_id;
            sotfs_inode_open(&g_sotfs, inode_id);   /* POSIX delete-on-last-close ref */
            g_handles[i].flags           = flags;
            g_handles[i].next_child_edge = 0;
            g_handles[i].path[0]         = '\0';
            if (path) {
                strncpy(g_handles[i].path, path, sizeof(g_handles[i].path) - 1);
                g_handles[i].path[sizeof(g_handles[i].path) - 1] = '\0';
            }
            *out_handle = &g_handles[i];
            /* sottrace · P3 · FS_OPEN with the resolved VFS path. */
            {
                lucas_state_t *caller = lucas_get_current_caller();
                trace_emit_fs(caller ? caller->slot_index : -1,
                              caller ? (uint32_t)caller->synthetic_pid : 0u,
                              SG_EV_FS_OPEN, 0, g_handles[i].path);
            }
            return 0;
        }
    }
    return -24; /* -EMFILE */
}

static int sotfs_err_to_errno(int rc);   /* fwd · defined below */

/* ── op_close ─────────────────────────────────────────────────────────── */

static int op_close(void *backend, void *handle)
{
    (void)backend;
    sotfs_handle_t *h = handle;
    if (h && h->in_use) {
        /* POSIX delete-on-last-close: drop the inode ref · frees an orphaned
         * (unlinked-while-open) inode when this is the last handle. */
        sotfs_inode_close(&g_sotfs, h->inode_id);
        h->in_use = false;
    }
    return 0;
}

/* ── op_dup_handle ────────────────────────────────────────────────────────
 * Allocate a fresh, independent handle for the same open file as `src` (same
 * inode/path/flags).  Used by SCM_RIGHTS fd-passing so the receiving sotbox owns
 * a handle whose lifetime is decoupled from the sender's pooled handle (which it
 * close()s right after the send, and which the pool recycles).  Returns NULL on
 * pool exhaustion or a bad source handle. */
static void *op_dup_handle(void *backend, void *src)
{
    (void)backend;
    sotfs_handle_t *s = src;
    /* Accept a closed-but-not-yet-recycled handle too: op_close only clears
     * in_use, leaving inode_id/path intact, and wine close()s the section fd
     * before SCM-sending it.  inode_id>0 means the identity is still valid. */
    if (!s || s->inode_id <= 0) return NULL;
    for (int i = 0; i < SOTFS_HANDLE_POOL; ++i) {
        if (!g_handles[i].in_use) {
            g_handles[i] = *s;            /* copy inode_id/flags/path/iterator */
            g_handles[i].in_use = true;
            sotfs_inode_open(&g_sotfs, g_handles[i].inode_id);  /* ref the dup */
            return &g_handles[i];
        }
    }
    return NULL; /* pool full */
}

/* apk-fs P2 · a session-owned (tagged) inode is hidden from non-owners: the
 * operator (no caller / cow_session 0) and any OTHER session.  Wraps the
 * Phase-1 visibility predicate (owner 0 = base → visible to everyone). */
static bool inode_hidden_from_caller(int inode_id)
{
    lucas_state_t *vc = lucas_get_current_caller();
    uint32_t sess = vc ? vc->cow_session : 0;
    return !lucas_sotfs_session_visible(inode_id, sess);
}

/* ── op_read ──────────────────────────────────────────────────────────── */

static int64_t op_read(void *backend, void *handle, void *buf,
                        size_t count, int64_t cursor)
{
    (void)backend;
    sotfs_handle_t *h = handle;
    if (!h || !h->in_use) {
        printf("[sotfs] op_read EBADF · handle=%p in_use=%d inode=%d\n",
               h, h ? h->in_use : -1, h ? h->inode_id : -1);
        return -9; /* -EBADF */
    }

    int slot = h->inode_id - 1;
    if (slot < 0 || slot >= SOTFS_MAX_INODES) return -9;
    if (g_sotfs.inodes[slot].kind == SOTFS_KIND_DIR) return -21; /* -EISDIR */

    /* apk-fs P2 · a tagged (session-owned) inode is served ONLY to its owner;
     * the operator (cow_session==0) and other sessions get EBADF (they should
     * never hold a handle to a hidden inode, but guard the read path too).
     * Untagged base inodes (owner 0) pass for everyone. */
    if (inode_hidden_from_caller(h->inode_id))
        return -9; /* -EBADF · not visible to this caller */

    /* Phase C · per-session COW-lite read-merge.  A Tier-2 `:w` to a /tmp file
     * is silently dropped (op_write's isolated branch never mutates the graph),
     * so a re-read would otherwise show the OLD bytes — a honeypot tell.  If the
     * caller belongs to an SSH session (cow_session != 0) and has overlaid this
     * exact handle path, serve the overlay instead.  h->path is the VFS suffix
     * (mount "/tmp" already stripped) — the SAME form op_write keys on (C3), so
     * the (session,path) key is self-consistent.  cow_session==0 (Tier-0) and
     * the empty-overlay pre-C3 case fall through to the unchanged base read. */
    {
        lucas_state_t *cow_caller = lucas_get_current_caller();
        if (cow_caller && cow_caller->cow_session != 0 &&
            lucas_cow_has(cow_caller->cow_session, h->path)) {
            static uint8_t cow_scratch[LUCAS_COW_MAX_BYTES];
            int total = lucas_cow_read(cow_caller->cow_session, h->path,
                                       cow_scratch, sizeof(cow_scratch));
            if (total < 0) total = 0;
            if (cursor >= (int64_t)total) return 0;
            size_t avail   = (size_t)total - (size_t)cursor;
            size_t to_copy = count < avail ? count : avail;
            memcpy(buf, cow_scratch + (size_t)cursor, to_copy);
            return (int64_t)to_copy;
        }
    }

    int rc = sotfs_file_read(&g_sotfs, h->inode_id,
                              (uint32_t)cursor,
                              (uint8_t *)buf, (uint32_t)count);
    if (rc < 0) return (int64_t)rc;
    /* sottrace · P3 · FS_READ once per open (cursor==0), path from the handle. */
    if (cursor == 0) {
        lucas_state_t *rc_caller = lucas_get_current_caller();
        trace_emit_fs(rc_caller ? rc_caller->slot_index : -1,
                      rc_caller ? (uint32_t)rc_caller->synthetic_pid : 0u,
                      SG_EV_FS_READ, (uint64_t)rc, h->path);
    }
    return (int64_t)rc;
}

/* ── op_write ─────────────────────────────────────────────────────────── */

static int64_t op_write(void *backend, void *handle, const void *buf,
                         size_t count, int64_t cursor)
{
    (void)backend;
    sotfs_handle_t *h = handle;
    if (!h || !h->in_use) return -9; /* -EBADF */

    int slot = h->inode_id - 1;
    if (slot < 0 || slot >= SOTFS_MAX_INODES) return -9;
    if (g_sotfs.inodes[slot].kind == SOTFS_KIND_DIR) return -21; /* -EISDIR */

    /* sotFS-ε / Phase C3: Tier 2 isolated-write path.  The base sotfs graph is
     * NEVER mutated by a Tier-2 write.  Pre-C3 the bytes were silently dropped —
     * but an attacker who `vim :w`-edits a /tmp file then re-reads it would see
     * the OLD content (a honeypot tell).  C3 redirects the write into the
     * per-session COW overlay instead: the attacker reads its edit back within
     * the session (op_read's C2 read-merge serves the overlay), while the base
     * graph stays pristine and the operator still observes the containment via
     * the same [isolated] trace event.
     *
     * KEYING CONTRACT (C2): the sotfs backend keys the overlay by the handle's
     * SUFFIX (h->path · mount "/tmp" already stripped) — the SAME form op_read's
     * read-merge keys on, so the (session,path) key is self-consistent.
     *
     * The overlay is whole-entry replace (lucas_cow_write sets len=n from off 0),
     * so a positional write (cursor>0, e.g. vim chunking a >4 KiB buffer across
     * the handler's 4096-byte bounce) must splice into the existing overlay
     * content rather than clobber it.  We read the current overlay (if any),
     * place the new bytes at `cursor`, zero-fill any gap, and write the merged
     * image back — keyed by h->path. */
    {
        lucas_state_t *caller = lucas_get_current_caller();
        if (caller && caller->functor && caller->functor->is_isolated) {
            /* Throttle · a 50 MiB cache write is 12800 of these; the per-write
             * UART printf dominated runtime.  Log first 4 + every 512th. */
            static unsigned long s_iso_w = 0;
            if (++s_iso_w <= 4 || (s_iso_w & 0x1FFUL) == 0)
                printf("[isolated] pid=%d tier=2 · sotfs write inode=%d len=%zu → session overlay (base intact) (#%lu)\n",
                       caller->synthetic_pid, h->inode_id, count, s_iso_w);
            if (caller) trace_emit_isolated_write_drop(caller->slot_index,
                                               (uint32_t)caller->synthetic_pid, h->path);

            /* Tier-0 fork children with no SSH session (cow_session==0) cannot
             * have an overlay (keyed on a 0 session would alias all sessions);
             * keep the legacy synthetic-success-drop for them. */
            if (caller->cow_session == 0)
                return (int64_t)count;

            /* apk-fs P2 · if THIS inode is owned by the caller's session (created
             * via Task-2's tagged create), the write lands in the shared graph —
             * charged against the 32 MiB cap — so bulk apk payload + the apk DB
             * read back at full size and execve/ld can map them.  The base graph
             * is untouched because a session-owned inode is, by construction, one
             * the session itself created (never a base inode). */
            if (lucas_sotfs_session_owner(h->inode_id) == caller->cow_session) {
                uint32_t old_size  = (uint32_t)g_sotfs.inodes[h->inode_id - 1].size;
                uint64_t off64     = (cursor > 0) ? (uint64_t)cursor : 0;
                uint64_t new_end64 = off64 + (uint64_t)count;
                if (new_end64 > UINT32_MAX) return -28; /* -ENOSPC · pathological write */
                uint32_t off     = (uint32_t)off64;
                uint32_t new_end = (uint32_t)new_end64;
                if (new_end > old_size) {
                    int crc = lucas_sotfs_session_charge(caller->cow_session,
                                                         new_end - old_size);
                    if (crc != 0) return (int64_t)crc;   /* -ENOSPC over 32 MiB */
                }
                int wr = sotfs_file_write(&g_sotfs, h->inode_id, off,
                                          (const uint8_t *)buf, (uint32_t)count);
                if (wr < 0)
                    return sotfs_err_to_errno(wr);   /* the REAL errno (was a blanket
                                                      * -28 that mislabeled NOENT as
                                                      * ENOSPC · cost a deep mis-debug) */
                sotfs_stamp_write(h->inode_id);
                return (int64_t)count;
            }
            /* else: a Tier-2 write to a BASE inode (e.g. vim :w /etc/passwd) keeps
             * the existing cow-overlay containment below — base never mutated. */

            /* Splice [buf,count) at `cursor` into the session overlay. */
            static uint8_t cow_merge[LUCAS_COW_MAX_BYTES];
            uint32_t cur_len = 0;
            if (lucas_cow_has(caller->cow_session, h->path)) {
                int got = lucas_cow_read(caller->cow_session, h->path,
                                         cow_merge, sizeof(cow_merge));
                if (got > 0) cur_len = (uint32_t)got;
            }
            uint64_t off = (cursor > 0) ? (uint64_t)cursor : 0;
            uint64_t end = off + (uint64_t)count;
            if (end > (uint64_t)LUCAS_COW_MAX_BYTES)
                return -28; /* -ENOSPC · believable for an over-cap :w */
            /* Zero-fill any gap between the prior length and the write offset. */
            if (off > cur_len)
                memset(cow_merge + cur_len, 0, (size_t)(off - cur_len));
            memcpy(cow_merge + off, buf, count);
            uint32_t new_len = (uint32_t)end;
            if (new_len < cur_len) new_len = cur_len; /* partial overwrite keeps tail */
            /* KNOWN LIMITATION (shrink-on-resave): Tier-2 ftruncate(fd,0) is a no-op
             * (no vfs truncate hook), so a SECOND, SHORTER :w in the SAME session leaves
             * the prior overlay entry's longer tail (new_len floors at cur_len above).
             * A single edit + :wq is unaffected (overlay starts empty). FOLLOW-UP: route
             * Tier-2 ftruncate → overlay truncate (recover the path from the fd) to fix. */
            int wrc = lucas_cow_write(caller->cow_session, h->path,
                                      cow_merge, new_len);
            if (wrc != 0)
                return (int64_t)wrc; /* propagate -ENOSPC etc. */
            return (int64_t)count;   /* synthetic success · base graph untouched */
        }
    }

    char op_extra[64];
    snprintf(op_extra, sizeof(op_extra), "inode=%d offset=%ld len=%zu",
             h->inode_id, (long)cursor, count);
    sto_local_tx_t tx = sto_local_begin("sotfs:write", op_extra);
    int rc = sotfs_file_write(&g_sotfs, h->inode_id, (uint32_t)cursor,
                               (const uint8_t *)buf, (uint32_t)count);
    if (rc < 0) {
        sto_local_abort(tx);
        return (int64_t)rc;
    }
    sotfs_wal_log_write((uint64_t)tx, h->inode_id, (uint32_t)cursor, buf, (uint32_t)rc);
    sto_local_commit(tx);
    sotfs_stamp_write(h->inode_id);   /* clock-fidelity · bump mtime/ctime on write */
    /* γ · PR 3 · stamp F_persistence at write time too · covers the
     * truncate-then-write install pattern where O_CREAT was never used. */
    apply_pending_sotfs_hint(h->inode_id);
    /* CURVATURE-AUTOPROMOTE · attribute curvature to calling sotbox. */
    {
        lucas_state_t *caller = lucas_get_current_caller();
        uint32_t cpid = (caller ? (uint32_t)caller->synthetic_pid : 0u);
        sotfs_graph_curvature_on_commit(cpid, "sotfs:write"); /* sotFS-η */
    }

    printf("[sotfs] write inode=%d offset=%ld len=%zu · %d bytes\n",
           h->inode_id, (long)cursor, count, rc);
    /* sottrace · P3 · FS_WRITE once per open (cursor==0), path from the handle. */
    if (cursor == 0) {
        lucas_state_t *fs_caller = lucas_get_current_caller();
        trace_emit_fs(fs_caller ? fs_caller->slot_index : -1,
                      fs_caller ? (uint32_t)fs_caller->synthetic_pid : 0u,
                      SG_EV_FS_WRITE, (uint64_t)rc, h->path);
    }
    return (int64_t)rc;
}

/* ── op_stat ──────────────────────────────────────────────────────────── */

static int op_stat(void *backend, const char *path, struct lx_stat *out)
{
    lazy_init();

    int inode_id = sotfs_resolve_path_from(&g_sotfs, backend_root(backend), path);
    if (inode_id == 0) return -2; /* -ENOENT */

    int slot = inode_id - 1;
    if (slot < 0 || slot >= SOTFS_MAX_INODES) return -2;

    /* apk-fs P2 · hide a session-owned inode from non-owners (operator/2nd sess). */
    if (inode_hidden_from_caller(inode_id))
        return -2; /* -ENOENT · pristine base view */

    sotfs_inode_t *ino = &g_sotfs.inodes[slot];
    memset(out, 0, sizeof(*out));

    if (ino->kind == SOTFS_KIND_DIR)
        out->st_mode = LX_S_IFDIR | (ino->mode & 0777);
    else if ((ino->mode & LX_S_IFMT) == LX_S_IFSOCK)   /* WINE-M1 · AF_UNIX socket node */
        out->st_mode = LX_S_IFSOCK | (ino->mode & 0777);
    else
        out->st_mode = LX_S_IFREG | (ino->mode & 0777);

    out->st_size    = (int64_t)ino->size;
    out->st_blksize = 4096;
    out->st_blocks  = ((int64_t)ino->size + 511) / 512;
    out->st_nlink   = ino->nlink > 0 ? (uint64_t)ino->nlink : 1;
    out->st_ino     = (uint64_t)inode_id;
    out->st_dev     = 2; /* distinct from static backend's dev=1 */
    /* clock-fidelity · real wall-clock mtime/atime/ctime (no more Jan 1 1970). */
    out->st_mtime   = (uint64_t)ino->mtime_sec;
    out->st_atime   = (uint64_t)(ino->atime_sec ? ino->atime_sec : ino->mtime_sec);
    out->st_ctime   = (uint64_t)ino->ctime_sec;
    return 0;
}

/* ── op_fstat ─────────────────────────────────────────────────────────── */

static int op_fstat(void *backend, void *handle, struct lx_stat *out)
{
    (void)backend;
    sotfs_handle_t *h = handle;
    if (!h || !h->in_use) return -9; /* -EBADF */

    int slot = h->inode_id - 1;
    if (slot < 0 || slot >= SOTFS_MAX_INODES) return -9;

    /* apk-fs P2 · a dup'd handle (SCM_RIGHTS) can cross session contexts; gate
     * fstat too so a non-owner can't read a session-owned inode's size/mtime. */
    if (inode_hidden_from_caller(h->inode_id))
        return -9; /* -EBADF · not visible to this caller */

    sotfs_inode_t *ino = &g_sotfs.inodes[slot];
    memset(out, 0, sizeof(*out));

    if (ino->kind == SOTFS_KIND_DIR)
        out->st_mode = LX_S_IFDIR | (ino->mode & 0777);
    else if ((ino->mode & LX_S_IFMT) == LX_S_IFSOCK)   /* WINE-M1 · AF_UNIX socket node */
        out->st_mode = LX_S_IFSOCK | (ino->mode & 0777);
    else
        out->st_mode = LX_S_IFREG | (ino->mode & 0777);

    out->st_size    = (int64_t)ino->size;
    out->st_blksize = 4096;
    out->st_blocks  = ((int64_t)ino->size + 511) / 512;
    out->st_nlink   = ino->nlink > 0 ? (uint64_t)ino->nlink : 1;
    out->st_ino     = (uint64_t)h->inode_id;
    out->st_dev     = 2;
    /* clock-fidelity · real wall-clock mtime/atime/ctime (no more Jan 1 1970). */
    out->st_mtime   = (uint64_t)ino->mtime_sec;
    out->st_atime   = (uint64_t)(ino->atime_sec ? ino->atime_sec : ino->mtime_sec);
    out->st_ctime   = (uint64_t)ino->ctime_sec;
    return 0;
}

/* ── op_getdents ──────────────────────────────────────────────────────── */

/*
 * Iterate child edges of the directory whose inode_id == handle->inode_id.
 * Advances h->next_child_edge as a cursor so repeated calls drain the
 * directory.  Returns total bytes written into dirp (0 == end of dir).
 */
static int64_t op_getdents(void *backend, void *handle, void *dirp,
                            size_t count, int64_t *cursor)
{
    (void)backend; (void)cursor;
    sotfs_handle_t *h = handle;
    if (!h || !h->in_use) return -9; /* -EBADF */

    int slot = h->inode_id - 1;
    if (slot < 0 || slot >= SOTFS_MAX_INODES) return -9;
    if (g_sotfs.inodes[slot].kind != SOTFS_KIND_DIR) return -20; /* -ENOTDIR */

    uint8_t *out   = dirp;
    size_t  written = 0;

    while (h->next_child_edge < (size_t)SOTFS_MAX_EDGES) {
        const sotfs_edge_t *e = &g_sotfs.edges[h->next_child_edge];
        h->next_child_edge++;

        if (e->id == 0) continue;                     /* free slot */
        if (e->parent_id != h->inode_id) continue;    /* not a child */

        /* Deception-fidelity · when serving `ls /tmp` (the GRAPH ROOT), hide the
         * mount-root names (var/usr/etc) — a real host has no /tmp/var.  Scoped
         * by inode: /var's own listing (root == the `var` inode) is unaffected. */
        if (h->inode_id == g_sotfs.root_id && sotfs_is_hidden_root(e->name))
            continue;

        int child_slot = e->child_id - 1;
        if (child_slot < 0 || child_slot >= SOTFS_MAX_INODES) continue;

        /* apk-fs P2 · do not emit a session-owned child to a non-owner.  The
         * operator (cow_session==0) lists the pristine base; a session lists base
         * + its OWN children; another session never sees this session's installs.
         * h->next_child_edge was already incremented above, so a bare continue
         * does not re-process this entry (the loop form is pre-increment). */
        if (inode_hidden_from_caller(e->child_id))
            continue;

        const char *name     = e->name;
        size_t      name_len = strlen(name) + 1; /* include NUL */
        size_t      reclen   = (offsetof(struct lx_dirent64, d_name)
                                + name_len + 7) & ~(size_t)7;

        if (written + reclen > count) break;

        struct lx_dirent64 *de = (struct lx_dirent64 *)(out + written);
        de->d_ino    = (uint64_t)e->child_id;
        de->d_off    = (int64_t)h->next_child_edge;
        de->d_reclen = (uint16_t)reclen;
        de->d_type   = (g_sotfs.inodes[child_slot].kind == SOTFS_KIND_DIR)
                       ? LX_DT_DIR : LX_DT_REG;
        memcpy(de->d_name, name, name_len);
        written += reclen;
    }

    return (int64_t)written;
}

/* ── op_readlink ──────────────────────────────────────────────────────── */

static int op_readlink(void *backend, const char *path, char *buf, size_t size)
{
    (void)backend; (void)path; (void)buf; (void)size;
    return -22; /* -EINVAL · no symlinks in sotFS Phase 2 */
}

/* ── mkdir / unlink ───────────────────────────────────────────────────── */

/*
 * These operations are not in vfs_ops_t in the current header (L2 VFS
 * is read+write-file only).  They are provided here as static helpers
 * and are exported via the public mount-installation call so that future
 * VFS extension (mkdir/unlink syscall handlers) can reference them.
 * No-op stubs ensure the ops table compiles cleanly today.
 */
/* Install-arc · per-mount-root core.  `root` is the inode the mount-relative
 * path resolves from (g_sotfs.root_id for /tmp + the legacy public wrapper). */
static int lucas_sotfs_mkdir_root(int root, const char *path, uint32_t mode)
{
    lazy_init();

    /* WINE-M1 · map the guest /tmp mount prefix to the sotfs root, exactly like
     * every other op in this file (open/read/write/create/stat/unlink all call
     * strip_tmp_prefix first).  mkdir was the lone exception: it resolved the
     * literal parent "/tmp" (no such graph node) → -ENOENT, so `mkdir /tmp/.wine`
     * silently failed and wine's chdir into its prefix died "No such file or
     * directory" (same bug starved gtk's /tmp/fontconfig cache).  Idempotent vs
     * the orch caller's orch_strip_tmp pre-strip (an already-stripped path no
     * longer begins with /tmp). */
    path = strip_tmp_prefix(path);

    /* apk-fs G1 · a Tier-2 SSH session (cow_session != 0) is allowed to mkdir
     * into the shared graph — the new dir inode is tagged to the session (Step 2)
     * so it is operator-invisible + reaped on disconnect.  This mirrors the
     * op_open create bypass (Phase-2 Task 2) so apk can `mkdir /lib/apk/db`,
     * /usr/lib, etc.  A Tier-2 caller WITHOUT a session (cow_session == 0, e.g. a
     * Tier-0 fork child) keeps the legacy drop · no per-session owner to tag. */
    {
        lucas_state_t *caller = lucas_get_current_caller();
        bool session_create = (caller != NULL) && (caller->cow_session != 0);
        if (caller && caller->functor && caller->functor->is_isolated &&
            !session_create) {
            printf("[isolated] pid=%d tier=2 · sotfs mkdir %s silently dropped (Synth branch)\n",
                   caller->synthetic_pid, path);
            if (caller) trace_emit_isolated_write_drop(caller->slot_index,
                                               (uint32_t)caller->synthetic_pid, path);
            return -13; /* -EACCES */
        }
        if (session_create) {
            printf("[isolated] pid=%d tier=2 sess=%u · sotfs mkdir %s → session upper (tagged, base intact)\n",
                   caller->synthetic_pid, caller->cow_session, path);
            trace_emit_isolated_write_drop(caller->slot_index,
                                           (uint32_t)caller->synthetic_pid, path);
        }
    }

    char parent_path[256];
    const char *leaf;
    if (split_path(path, parent_path, &leaf) != 0) return -22;
    int parent_id = sotfs_resolve_path_from(&g_sotfs, root, parent_path);
    if (parent_id == 0) return -2;
    /* WINE-M1 (M2a) · idempotent mkdir.  If the leaf already exists, return
     * -EEXIST (which wine + `mkdir -p` callers tolerate) instead of collapsing
     * to -ENOSPC below.  Without this, wine's own `mkdir dosdevices/drive_c`
     * over a pre-seeded prefix skeleton hit "No space left on device" and aborted
     * ("wine: cannot create /tmp/.wine/dosdevices : No space left on device"). */
    if (sotfs_find_edge(&g_sotfs, parent_id, leaf) != 0) return -17;  /* -EEXIST */
    char op_extra[64];
    snprintf(op_extra, sizeof(op_extra), "path=%s", path);
    sto_local_tx_t tx = sto_local_begin("sotfs:mkdir", op_extra);
    int rc = sotfs_rewrite_mkdir(&g_sotfs, parent_id, leaf, mode ? mode : 0755);
    /* sotfs_rewrite_mkdir returns positive inode_id on success, negative
     * SOTFS_ERR_* on failure.  `!= SOTFS_OK` (== 0) aborts on success. */
    if (rc <= 0) {
        sto_local_abort(tx);
        return -28;
    }
    /* apk-fs · a Tier-2 session-tagged mkdir is SESSION-LIFETIME (reaped on
     * disconnect, base pristine).  Do NOT WAL-log it: durability would resurrect
     * it on reboot as an empty, UNTAGGED (g_owner is BSS) operator-visible base
     * inode (containment leak "concern-3") AND break a later session's write→read
     * of the same path.  The live graph + on-disk data blocks serve the session;
     * on reboot it is correctly gone.  (Tier-0/boot mkdirs stay WAL-logged.) */
    {
        lucas_state_t *wc = lucas_get_current_caller();
        bool sess = wc && wc->cow_session != 0;
        if (!sess)
            sotfs_wal_log_mkdir((uint64_t)tx, parent_id, leaf, mode ? mode : 0755);
    }
    sto_local_commit(tx);
    sotfs_stamp_create(rc);   /* clock-fidelity · rc == created inode_id */
    /* apk-fs G1 · tag the new dir to the creating SSH session (operator-invisible
     * + reaped on disconnect).  Gated on cow_session != 0 → Tier-0/boot mkdirs
     * stay untagged (= base, visible). */
    {
        lucas_state_t *tag_caller = lucas_get_current_caller();
        if (tag_caller && tag_caller->cow_session != 0)
            lucas_sotfs_session_tag(rc, tag_caller->cow_session);
    }
    /* CURVATURE-AUTOPROMOTE · attribute curvature to calling sotbox. */
    {
        lucas_state_t *caller = lucas_get_current_caller();
        uint32_t cpid = (caller ? (uint32_t)caller->synthetic_pid : 0u);
        sotfs_graph_curvature_on_commit(cpid, "sotfs:mkdir"); /* sotFS-η */
    }
    printf("[mkdir] %s · inode created\n", path);
    return 0;
}

/* Public/legacy entry · resolves from the real graph root. */
int lucas_sotfs_mkdir(const char *path, uint32_t mode)
{
    return lucas_sotfs_mkdir_root(g_sotfs.root_id, path, mode);
}

/* Map a sotfs_rewrite_* result (SOTFS_ERR_* · graph-internal codes) to a Linux
 * -errno.  The raw codes (NOTDIR=-3, NOTEMPTY=-5, …) used to leak straight out
 * as errnos: -3 surfaced as ESRCH "No such process", -5 as EIO "Input/output
 * error" — which broke `dpkg -i`'s cleanup (it rmdir's each tmp.ci entry and
 * treats -ENOTDIR as "it's a file, unlink instead", but got ESRCH → fatal
 * "rmdir of 'control' didn't say not a dir: No such process"). */
static int sotfs_err_to_errno(int rc)
{
    switch (rc) {
        case SOTFS_OK:              return 0;
        case SOTFS_ERR_EXISTS:      return -17; /* -EEXIST */
        case SOTFS_ERR_NOENT:       return -2;  /* -ENOENT */
        case SOTFS_ERR_NOTDIR:      return -20; /* -ENOTDIR */
        case SOTFS_ERR_ISDIR:       return -21; /* -EISDIR */
        case SOTFS_ERR_NOTEMPTY:    return -39; /* -ENOTEMPTY */
        case SOTFS_ERR_NOSPACE:     return -28; /* -ENOSPC */
        case SOTFS_ERR_NAMETOOLONG: return -36; /* -ENAMETOOLONG */
        case SOTFS_ERR_INVAL:       return -22; /* -EINVAL */
        default:                    return -5;  /* -EIO */
    }
}

/* Spec A · unlink a file by path.  WAL-logged by parent_id+name (stable
 * across replay like create_file) so the deletion survives simreboot.
 * Accepts either a raw VFS path (/tmp/...) from the lucas_sys_unlink
 * handler or an already-root-relative path from orch (orch_strip_tmp) ·
 * strip_tmp_prefix is idempotent on a path with no /tmp prefix. */
static int lucas_sotfs_unlink_root(int root, const char *path)
{
    lazy_init();

    /* sotFS-ε: Tier 2 isolated-write path.  A Tier-2 SSH session (cow_session != 0)
     * is allowed a REAL unlink in its per-session upper (mirrors the op_mkdir /
     * op_open(create) / rename cow_session bypass): apt's index download is
     * write-to-partial → rename-to-final, and apt unlink's the partial along the
     * way — without this it Synth-drops and the rename can't finalize the lists.
     * A Tier-2 caller WITHOUT a session (cow_session == 0, e.g. a Tier-0 fork
     * child) keeps the legacy deception drop.  CONTAINMENT: a session only really
     * unlinks a SESSION-OWNED inode (its own partial); a base inode is a no-op
     * (return success · base pristine), so an attacker can never delete a base
     * file through this path. */
    lucas_state_t *ul_caller = lucas_get_current_caller();
    bool ul_session = (ul_caller != NULL) && (ul_caller->cow_session != 0);
    if (ul_caller && ul_caller->functor && ul_caller->functor->is_isolated &&
        !ul_session) {
        printf("[isolated] pid=%d tier=2 · sotfs unlink %s silently dropped (Synth branch · sessionless)\n",
               ul_caller->synthetic_pid, path);
        trace_emit_isolated_write_drop(ul_caller->slot_index,
                                       (uint32_t)ul_caller->synthetic_pid, path);
        return -13; /* -EACCES */
    }

    if (!path) return -22; /* EINVAL */
    const char *fs_path = strip_tmp_prefix(path);
    char parent_path[256];
    const char *leaf;
    if (split_path(fs_path, parent_path, &leaf) != 0) return -22;
    int parent_id = sotfs_resolve_path_from(&g_sotfs, root, parent_path);
    if (parent_id == 0) return -2;

    /* CONTAINMENT guard · a session unlink only removes a SESSION-OWNED inode.
     * If the target is a base inode (owner != this session), drop it to a no-op
     * success so the base stays pristine (the attacker sees "deleted", we don't
     * touch the base graph). */
    uint32_t ul_credit_bytes = 0, ul_credit_session = 0;
    if (ul_session && ul_caller->functor && ul_caller->functor->is_isolated) {
        int tgt = sotfs_find_edge(&g_sotfs, parent_id, leaf);
        if (tgt == 0) return -2;   /* -ENOENT */
        if (lucas_sotfs_session_owner(tgt) != ul_caller->cow_session) {
            printf("[isolated] pid=%d tier=2 sess=%u · sotfs unlink %s → base inode · contained no-op (base intact)\n",
                   ul_caller->synthetic_pid, ul_caller->cow_session, path);
            return 0;   /* deception: report success, base untouched */
        }
        /* Refund the removed inode's charged bytes so the per-session cap tracks
         * LIVE bytes, not cumulative (apt's write-temp/rename/delete churn). */
        ul_credit_bytes   = (uint32_t)g_sotfs.inodes[tgt - 1].size;
        ul_credit_session = ul_caller->cow_session;
        printf("[isolated] pid=%d tier=2 sess=%u · sotfs unlink %s → session upper (contained)\n",
               ul_caller->synthetic_pid, ul_caller->cow_session, path);
    }
    char op_extra[64];
    snprintf(op_extra, sizeof(op_extra), "path=%s", fs_path);
    sto_local_tx_t tx = sto_local_begin("sotfs:unlink", op_extra);
    int rc = sotfs_rewrite_unlink(&g_sotfs, parent_id, leaf);
    if (rc != SOTFS_OK) {
        sto_local_abort(tx);
        return -2;
    }
    if (ul_credit_session != 0 && ul_credit_bytes != 0)
        lucas_sotfs_session_uncharge(ul_credit_session, ul_credit_bytes);
    /* apk-fs · a Tier-2 session unlink is SESSION-LIFETIME (reaped on disconnect,
     * base pristine) · do NOT WAL-log it, mirroring the session mkdir/create gate
     * (a WAL-logged session op would replay on reboot as an untagged base mutation
     * = containment leak).  Tier-0/boot unlinks stay WAL-logged (durable). */
    if (!ul_session)
        sotfs_wal_log_unlink((uint64_t)tx, parent_id, leaf);
    sto_local_commit(tx);
    /* CURVATURE-AUTOPROMOTE · attribute curvature to calling sotbox. */
    {
        lucas_state_t *caller = lucas_get_current_caller();
        uint32_t cpid = (caller ? (uint32_t)caller->synthetic_pid : 0u);
        sotfs_graph_curvature_on_commit(cpid, "sotfs:unlink"); /* sotFS-η */
    }
    printf("[rm] %s · unlinked\n", fs_path);
    return 0;
}

/* Public/legacy entry · resolves from the real graph root. */
int lucas_sotfs_unlink(const char *path)
{
    return lucas_sotfs_unlink_root(g_sotfs.root_id, path);
}

/* Spec A · rmdir a directory by path (used by unlinkat AT_REMOVEDIR in
 * PR 2).  Mirrors lucas_sotfs_unlink: Tier-2 mirror guard, /tmp strip,
 * WAL-log by parent_id+name, graph_curvature hook.  sotfs_rewrite_rmdir returns
 * SOTFS_OK(0) or a negative SOTFS_ERR_* (e.g. NOTEMPTY/NOENT). */
static int lucas_sotfs_rmdir_root(int root, const char *path)
{
    lazy_init();

    /* sotFS-ε: Tier 2 isolated-write path · silence rmdir, no graph mutation —
     * EXCEPT a real per-session caller (cow_session != 0), which rmdir's into the
     * shared graph (the dir was session-tagged at mkdir, operator-invisible +
     * reaped on disconnect).  Mirrors the mkdir/create session bypass: without it
     * apt's dpkg child got -EACCES removing its own session-upper /var/lib/dpkg/
     * tmp.ci → "unable to securely remove … Permission denied" → unpack error 1.
     * A sessionless Tier-2 caller (cow_session == 0) keeps the legacy drop. */
    {
        lucas_state_t *caller = lucas_get_current_caller();
        bool session_rmdir = (caller != NULL) && (caller->cow_session != 0);
        if (caller && caller->functor && caller->functor->is_isolated &&
            !session_rmdir) {
            printf("[isolated] pid=%d tier=2 · sotfs rmdir %s silently dropped (Synth branch)\n",
                   caller->synthetic_pid, path);
            trace_emit_isolated_write_drop(caller->slot_index,
                                               (uint32_t)caller->synthetic_pid, path);
            return -13; /* -EACCES */
        }
        if (session_rmdir) {
            printf("[isolated] pid=%d tier=2 sess=%u · sotfs rmdir %s → session upper (contained)\n",
                   caller->synthetic_pid, caller->cow_session, path);
            trace_emit_isolated_write_drop(caller->slot_index,
                                           (uint32_t)caller->synthetic_pid, path);
        }
    }

    if (!path) return -22; /* EINVAL */
    const char *fs_path = strip_tmp_prefix(path);
    char parent_path[256];
    const char *leaf;
    if (split_path(fs_path, parent_path, &leaf) != 0) return -22;
    int parent_id = sotfs_resolve_path_from(&g_sotfs, root, parent_path);
    if (parent_id == 0) return -2;
    char op_extra[64];
    snprintf(op_extra, sizeof(op_extra), "path=%s", fs_path);
    sto_local_tx_t tx = sto_local_begin("sotfs:rmdir", op_extra);
    int rc = sotfs_rewrite_rmdir(&g_sotfs, parent_id, leaf);
    if (rc < 0) {
        sto_local_abort(tx);
        return sotfs_err_to_errno(rc);   /* SOTFS_ERR_* → -errno (NOTDIR/NOTEMPTY/…) */
    }
    sotfs_wal_log_rmdir((uint64_t)tx, parent_id, leaf);
    sto_local_commit(tx);
    /* CURVATURE-AUTOPROMOTE · attribute curvature to calling sotbox. */
    {
        lucas_state_t *caller = lucas_get_current_caller();
        uint32_t cpid = (caller ? (uint32_t)caller->synthetic_pid : 0u);
        sotfs_graph_curvature_on_commit(cpid, "sotfs:rmdir"); /* sotFS-η */
    }
    printf("[rmdir] %s · removed\n", fs_path);
    return 0;
}

/* Public/legacy entry · resolves from the real graph root. */
int lucas_sotfs_rmdir(const char *path)
{
    return lucas_sotfs_rmdir_root(g_sotfs.root_id, path);
}

/* Spec A · rename old -> new on the sotfs graph.  REAL at Tier-0/1 (trusted
 * compat workloads): real software finalizes files via write-tmp-then-rename
 * (git's objects/refs/index/HEAD all land via rename).  The lucas_sys_rename
 * handler keeps the Tier-2 "accepted, contained" deception, so an isolated
 * sotbox never reaches here (the guard below is defense-in-depth).
 *
 * POSIX rename REPLACES an existing destination, but sotfs_rewrite_rename
 * carries a formal NAC forbidding an existing dst (DPO-purity).  We add the
 * clobber here, at the integration layer, leaving the rewrite kernel pure:
 * unlink the existing dst edge first (git's HEAD.lock->HEAD, index.lock->index,
 * <ref>.lock-><ref> all rename onto existing files). */
static int lucas_sotfs_rename_root(int root, const char *oldpath, const char *newpath)
{
    lazy_init();

    /* sotFS-ε: Tier 2 isolated-write path · silence rename, no graph mutation. */
    {
        lucas_state_t *caller = lucas_get_current_caller();
        if (caller && caller->functor && caller->functor->is_isolated &&
            caller->cow_session == 0) {
            /* Tier-2 WITHOUT an SSH session: keep the deception drop. */
            printf("[isolated] pid=%d tier=2 · sotfs rename %s -> %s silently dropped (Synth branch · sessionless)\n",
                   caller->synthetic_pid, oldpath, newpath);
            if (caller) trace_emit_isolated_write_drop(caller->slot_index,
                                               (uint32_t)caller->synthetic_pid, newpath);
            return -13; /* -EACCES */
        }
        /* apk-fs · a Tier-2 SSH session (cow_session!=0) does a REAL rename in the
         * per-session upper: the source is a session-owned inode (an apk temp like
         * .apk.<hash> / installed.new), so re-edging it to the final name stays
         * CONTAINED (the inode keeps its session tag, base untouched) and makes
         * apk's write-temp-then-rename atomic install read-back coherent. Mirrors
         * the op_open(create)/op_mkdir cow_session bypass. */
        if (caller && caller->functor && caller->functor->is_isolated &&
            caller->cow_session != 0)
            printf("[isolated] pid=%d tier=2 sess=%u · sotfs rename %s -> %s → session upper (contained)\n",
                   caller->synthetic_pid, caller->cow_session, oldpath, newpath);
    }

    if (!oldpath || !newpath) return -22; /* -EINVAL */
    const char *src = strip_tmp_prefix(oldpath);
    const char *dst = strip_tmp_prefix(newpath);
    /* POSIX: rename(x, x) is a successful no-op.  Must short-circuit BEFORE the
     * clobber below — else the clobber would unlink x (decrementing nlink) and
     * the subsequent rewrite_rename would then fail NOENT, corrupting the inode. */
    if (strcmp(src, dst) == 0) return 0;
    char sparent[256], dparent[256];
    const char *sleaf, *dleaf;
    if (split_path(src, sparent, &sleaf) != 0) return -22;
    if (split_path(dst, dparent, &dleaf) != 0) return -22;
    int p_src = sotfs_resolve_path_from(&g_sotfs, root, sparent);
    int p_dst = sotfs_resolve_path_from(&g_sotfs, root, dparent);
    if (p_src == 0 || p_dst == 0) return -2; /* -ENOENT (a parent dir is missing) */

    char op_extra[96];
    snprintf(op_extra, sizeof(op_extra), "%s -> %s", src, dst);
    sto_local_tx_t tx = sto_local_begin("sotfs:rename", op_extra);

    /* POSIX clobber: drop an existing destination before the (NAC-guarded)
     * rewrite.  sotfs_rewrite_unlink refuses a directory (SOTFS_ERR_ISDIR) — so
     * a clobber failure is surfaced (EISDIR/EINVAL) rather than silently leaving
     * the dest in place and letting the rename fail EXISTS. */
    int dst_tgt = sotfs_find_edge(&g_sotfs, p_dst, dleaf);
    int had_dst = (dst_tgt != 0);
    uint32_t rn_credit_bytes = 0, rn_credit_session = 0;
    if (had_dst) {
        /* Credit the clobbered destination's bytes back (apt renames a fresh
         * ~50 MiB cache temp OVER the prior cache file) so the cap tracks LIVE. */
        rn_credit_session = lucas_sotfs_session_owner(dst_tgt);
        if (rn_credit_session != 0)
            rn_credit_bytes = (uint32_t)g_sotfs.inodes[dst_tgt - 1].size;
        int ru = sotfs_rewrite_unlink(&g_sotfs, p_dst, dleaf);
        if (ru != SOTFS_OK) {
            sto_local_abort(tx);
            return (ru == SOTFS_ERR_ISDIR) ? -21 : -22;  /* -EISDIR / -EINVAL */
        }
    }

    int rc = sotfs_rewrite_rename(&g_sotfs, p_src, sleaf, p_dst, dleaf);
    if (rc != SOTFS_OK) {
        sto_local_abort(tx);
        return sotfs_err_to_errno(rc);   /* SOTFS_ERR_* → -errno */
    }
    /* WAL-log only AFTER both in-memory mutations succeed: on replay either
     * unlink-then-rename both apply, or neither does.  Logging the clobber-unlink
     * before a rename that then failed would, on replay, delete the dest without
     * the rename — a destination-loss on simreboot. */
    if (had_dst) sotfs_wal_log_unlink((uint64_t)tx, p_dst, dleaf);
    sotfs_wal_log_rename((uint64_t)tx, p_src, sleaf, p_dst, dleaf);
    sto_local_commit(tx);
    if (rn_credit_session != 0 && rn_credit_bytes != 0)
        lucas_sotfs_session_uncharge(rn_credit_session, rn_credit_bytes);
    {
        lucas_state_t *caller = lucas_get_current_caller();
        uint32_t cpid = (caller ? (uint32_t)caller->synthetic_pid : 0u);
        sotfs_graph_curvature_on_commit(cpid, "sotfs:rename"); /* sotFS-η */
    }
    printf("[mv] %s -> %s · renamed\n", src, dst);
    return 0;
}

/* Public/legacy entry · resolves from the real graph root. */
int lucas_sotfs_rename(const char *oldpath, const char *newpath)
{
    return lucas_sotfs_rename_root(g_sotfs.root_id, oldpath, newpath);
}

/* Like lucas_sotfs_install but for a NESTED path: resolves the parent directory
 * (which must already exist) and creates the leaf under it, instead of assuming
 * the root.  Used to seed a file into a guest-created subdir (e.g. a file in the
 * git working tree after `git init`).  Overwrites an existing leaf. */
int lucas_sotfs_install_at(const char *path, const void *content, size_t len)
{
    lazy_init();
    if (!path || !*path) return -22; /* -EINVAL */
    const char *fs = strip_tmp_prefix(path);
    char parent_path[256];
    const char *leaf;
    if (split_path(fs, parent_path, &leaf) != 0) return -22;
    int parent_id = sotfs_resolve_path(&g_sotfs, parent_path);
    if (parent_id == 0) return -2; /* -ENOENT (parent dir missing) */

    char op_extra[96];
    snprintf(op_extra, sizeof(op_extra), "path=%s", fs);
    sto_local_tx_t tx = sto_local_begin("sotfs:install", op_extra);
    if (sotfs_find_edge(&g_sotfs, parent_id, leaf) != 0)
        sotfs_rewrite_unlink(&g_sotfs, parent_id, leaf);   /* overwrite */
    int rc = sotfs_rewrite_create_file(&g_sotfs, parent_id, leaf, 0644);
    if (rc <= 0) { sto_local_abort(tx); return -28; }
    int file_id = sotfs_resolve_path(&g_sotfs, fs);
    if (file_id == 0) { sto_local_abort(tx); return -5; }
    if (len && sotfs_file_write(&g_sotfs, file_id, 0,
                                (const uint8_t *)content, (uint32_t)len) < 0) {
        sotfs_rewrite_unlink(&g_sotfs, parent_id, leaf);
        sto_local_abort(tx);
        return -28;
    }
    sotfs_stamp_create(file_id);   /* clock-fidelity */
    sotfs_wal_log_install((uint64_t)tx, fs, content, (uint32_t)len);
    sto_local_commit(tx);
    sotfs_graph_curvature_on_commit(0, "sotfs:install");
    printf("[install] %s · %zu bytes · inode=%d (nested)\n", fs, len, file_id);
    return 0;
}

/* ── op_truncate ──────────────────────────────────────────────────────── */

/* F3 · COW shrink-on-resave · a Tier-2 session caller truncates its per-session
 * overlay entry, keyed by the handle's SUFFIX (h->path · mount "/tmp" already
 * stripped) — the SAME key op_read/op_write use, so the (session,path) key is
 * self-consistent.  The base sotfs graph is NEVER mutated.  cow_session==0
 * (Tier-0) → success-silently (matches the ftruncate contract). */
static int op_truncate(void *backend, void *handle, int64_t newlen)
{
    (void)backend;
    sotfs_handle_t *h = handle;
    if (!h || !h->in_use) return -9; /* -EBADF */
    lucas_state_t *caller = lucas_get_current_caller();
    if (caller && caller->cow_session != 0)
        return lucas_cow_truncate(caller->cow_session, h->path,
                                  newlen > 0 ? (uint32_t)newlen : 0);
    return 0;
}

/* ── Install-arc · writable-mount ops ─────────────────────────────────── */
/*
 * Thin wrappers over the existing lucas_sotfs_{mkdir,unlink,rename} so the
 * unlink/rename/mkdir syscall handlers can dispatch through vfs_resolve →
 * mount->ops->{...} instead of calling the sotfs backend by hardcoded name.
 * `path` here is the mount-relative SUFFIX (the same string op_open/op_write
 * receive · "/tmp" already stripped by vfs_resolve).  The lucas_sotfs_* funcs
 * call strip_tmp_prefix() themselves, which is idempotent on an already-stripped
 * suffix — so feeding the suffix straight through is correct (and identical to
 * the old hardcoded path, which passed the full /tmp-rooted path).
 */
static int op_mkdir(void *backend, const char *path, uint32_t mode)
{
    return lucas_sotfs_mkdir_root(backend_root(backend), path, mode);
}

static int op_unlink(void *backend, const char *path)
{
    return lucas_sotfs_unlink_root(backend_root(backend), path);
}

static int op_rmdir(void *backend, const char *path)
{
    return lucas_sotfs_rmdir_root(backend_root(backend), path);
}

static int op_rename(void *backend, const char *oldp, const char *newp)
{
    return lucas_sotfs_rename_root(backend_root(backend), oldp, newp);
}

/* ── vfs_ops_t table ─────────────────────────────────────────────────── */

static const vfs_ops_t sotfs_ops = {
    .open     = op_open,
    .close    = op_close,
    .read     = op_read,
    .write    = op_write,
    .stat     = op_stat,
    .fstat    = op_fstat,
    .getdents = op_getdents,
    .readlink = op_readlink,
    .dup_handle = op_dup_handle,
    .truncate = op_truncate,
    .mkdir    = op_mkdir,
    .unlink   = op_unlink,
    .rmdir    = op_rmdir,
    .rename   = op_rename,
};

/* Install-arc · the /usr overlay backend composes the sotfs ops over a per-mount
 * upper root; expose the (otherwise static) table so backends_union_ops.c can
 * delegate upper-layer ops through the public vfs_ops interface. */
const vfs_ops_t *lucas_sotfs_ops(void) { return &sotfs_ops; }

/* ── public mount-installation entrypoint ────────────────────────────── */

/* Install-arc · idempotently create a top-level directory `name` under the
 * REAL graph root and return its inode id (the existing one if already there).
 * This gives /var and the /usr upper their own distinct mount roots — distinct
 * subtrees in the one shared g_sotfs graph (no /tmp/foo == /var/foo collision).
 * Resolves from the real root regardless of any caller's per-mount root: a
 * mount root is always a child of the graph root. */
int sotfs_mount_make_root(const char *name)
{
    lazy_init();   /* graph must be live (blkdev/replay done) */
    if (!name || !*name) return 0;

    char abspath[72];
    snprintf(abspath, sizeof(abspath), "/%s", name);
    int existing = sotfs_resolve_path_from(&g_sotfs, g_sotfs.root_id, abspath);
    if (existing > 0) { sotfs_hidden_root_register(name); return existing; } /* idempotent */

    char op_extra[80];
    snprintf(op_extra, sizeof(op_extra), "mount-root=%s", name);
    sto_local_tx_t tx = sto_local_begin("sotfs:mkdir", op_extra);
    int rc = sotfs_rewrite_mkdir(&g_sotfs, g_sotfs.root_id, name, 0755);
    if (rc <= 0) { sto_local_abort(tx); return 0; }
    sotfs_wal_log_mkdir((uint64_t)tx, g_sotfs.root_id, name, 0755);
    sto_local_commit(tx);
    sotfs_stamp_create(rc);   /* clock-fidelity · rc == created inode_id */
    sotfs_hidden_root_register(name);   /* hide from the /tmp graph-root listing */
    printf("[sotfs] mount-root /%s · inode=%d\n", name, rc);
    return rc;
}

/* The /tmp mount root == the real graph root (byte-identical legacy behavior:
 * /tmp files live at the graph root, exactly as before this change). */
static sotfs_mount_t g_tmp_mount;

vfs_mount_t lucas_sotfs_mount(void)
{
    /* Eagerly initialise the graph so [sotfs] mounted appears at boot
     * (when vfs_install_defaults runs) rather than on the first /tmp access. */
    lazy_init();

    g_tmp_mount.root_id = g_sotfs.root_id;   /* /tmp keeps resolving from root */
    g_tmp_mount.label   = "tmp";

    return (vfs_mount_t) {
        .prefix        = "/tmp",
        .ops           = &sotfs_ops,
        .backend_state = &g_tmp_mount,
    };
}

/* Install-arc · /var mount · a writable sotfs subtree rooted at a distinct
 * top-level "/var" dir node (sotfs_mount_make_root) so /var/foo and /tmp/foo
 * are NOT the same inode.  One shared graph, two disjoint roots. */
static sotfs_mount_t g_var_mount;

/* install-arc · one-shot boot self-test · prove the per-mount root works:
 * /var/probe and /tmp/probe land on DISTINCT inodes (no suffix collision) and
 * both read back their own bytes.  Resolves each "/probe" from its OWN root via
 * the sotfs op layer.  Runs once at /var-mount install (g_var_st guard). */
static bool g_var_selftest_done = false;
static void var_root_selftest(void)
{
    if (g_var_selftest_done) return;
    g_var_selftest_done = true;

    /* write /var/probe = "V" via the var root, /tmp/probe = "T" via the tmp root */
    sotfs_mount_t tmp_bs = { .root_id = g_sotfs.root_id, .label = "tmp" };
    void *hv = NULL, *ht = NULL;
    int rcv = op_open(&g_var_mount, "/probe", 0x40 /*O_CREAT*/ | 0x1 /*O_WRONLY*/, 0644, &hv);
    int rct = op_open(&tmp_bs,      "/probe", 0x40 | 0x1, 0644, &ht);
    if (rcv == 0 && hv) { op_write(&g_var_mount, hv, "V", 1, 0); op_close(&g_var_mount, hv); }
    if (rct == 0 && ht) { op_write(&tmp_bs,      ht, "T", 1, 0); op_close(&tmp_bs, ht); }

    int iv = sotfs_resolve_path_from(&g_sotfs, g_var_mount.root_id, "/probe");
    int it = sotfs_resolve_path_from(&g_sotfs, g_sotfs.root_id,     "/probe");
    char bv = '?', bt = '?';
    if (iv > 0) sotfs_file_read(&g_sotfs, iv, 0, (uint8_t *)&bv, 1);
    if (it > 0) sotfs_file_read(&g_sotfs, it, 0, (uint8_t *)&bt, 1);
    printf("[var-selftest] /var/probe inode=%d byte=%c · /tmp/probe inode=%d byte=%c · %s\n",
           iv, bv, it, bt,
           (iv > 0 && it > 0 && iv != it && bv == 'V' && bt == 'T')
               ? "DISTINCT-OK" : "COLLISION-FAIL");

    /* clean up the probes so they don't pollute the gitdemo /tmp tree */
    op_unlink(&g_var_mount, "/probe");
    op_unlink(&tmp_bs,      "/probe");
}

/* install-arc P1.3 · boot-seed the trimmed /var/lib/dpkg DB into the writable
 * /var so `dpkg -l` is non-empty and `dpkg -i` finds its base packages
 * (hello's Depends: libc6 is satisfied).  Paths are relative to the /var root
 * (the mount suffix), so the sotfs ops resolve them under g_var_mount.root_id.
 * mkdir is idempotent (-EEXIST tolerated); runs ONCE (g_dpkg_db_seeded). */
static bool g_dpkg_db_seeded = false;
static void dpkg_db_seed(void)
{
    if (g_dpkg_db_seeded) return;
    g_dpkg_db_seeded = true;

    op_mkdir(&g_var_mount, "/lib",               0755);
    op_mkdir(&g_var_mount, "/lib/dpkg",          0755);
    op_mkdir(&g_var_mount, "/lib/dpkg/info",     0755);
    op_mkdir(&g_var_mount, "/lib/dpkg/updates",  0755);
    op_mkdir(&g_var_mount, "/lib/dpkg/triggers", 0755);

    static const struct { const char *path; const unsigned char *data; unsigned int *len; } files[] = {
        { "/lib/dpkg/status",         dpkg_status,         &dpkg_status_len },
        { "/lib/dpkg/arch",           dpkg_arch,           &dpkg_arch_len },
        { "/lib/dpkg/info/dpkg.list", dpkg_info_dpkg_list, &dpkg_info_dpkg_list_len },
        { "/lib/dpkg/info/tar.list",  dpkg_info_tar_list,  &dpkg_info_tar_list_len },
        { "/lib/dpkg/info/format",    dpkg_info_format,    &dpkg_info_format_len },
    };
    for (unsigned i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        void *h = NULL;
        int rc = op_open(&g_var_mount, files[i].path,
                         0x40 /*O_CREAT*/ | 0x1 /*O_WRONLY*/, 0644, &h);
        if (rc == 0 && h) {
            op_write(&g_var_mount, h, files[i].data, (size_t)*files[i].len, 0);
            op_close(&g_var_mount, h);
        } else {
            printf("[install] dpkg DB seed · open %s failed rc=%d\n", files[i].path, rc);
        }
    }
    printf("[install] dpkg DB seeded · /var/lib/dpkg/status (%u bytes)\n", dpkg_status_len);
}

/* apt arc P0 · boot-seed the WRITABLE /var tree the real Debian apt expects:
 * /var/lib/apt/lists/partial (index downloads) + /var/cache/apt/archives/partial
 * (.deb cache).  Created as empty dirs in the /var sotfs root via the SAME
 * op_mkdir helper + g_var_mount that dpkg_db_seed uses for /var/lib/dpkg.
 *
 * The /etc/apt config (sources.list + apt.conf.d/99sotos) is NOT seeded here:
 * /etc is a read-only honey BASE union (backends_union_ops.c · static-view), and
 * every other /etc honey file (passwd, sources.list, sshd_config) is served as a
 * static debian_entries[] entry in backends_static.c — so the apt config lives
 * there too (debian_sources_list / debian_apt_conf_99sotos), readable at boot by
 * any process at /etc/apt/*.  apt_tree_seed.h keeps those bytes in sync with the
 * src/test/sotOs-apt fixture.  Idempotent one-shot (g_apt_tree_seeded);
 * mkdir tolerates -EEXIST. */
static bool g_apt_tree_seeded = false;
static void apt_tree_seed(void)
{
    if (g_apt_tree_seeded) return;
    g_apt_tree_seeded = true;

    /* /var/lib/apt/lists/partial — apt's package-index download tree. */
    op_mkdir(&g_var_mount, "/lib",                0755);  /* may already exist (dpkg) */
    op_mkdir(&g_var_mount, "/lib/apt",            0755);
    op_mkdir(&g_var_mount, "/lib/apt/lists",      0755);
    op_mkdir(&g_var_mount, "/lib/apt/lists/partial", 0755);

    /* /var/cache/apt/archives/partial — apt's downloaded-.deb cache. */
    op_mkdir(&g_var_mount, "/cache",              0755);  /* may already exist (apk) */
    op_mkdir(&g_var_mount, "/cache/apt",          0755);
    op_mkdir(&g_var_mount, "/cache/apt/archives", 0755);
    op_mkdir(&g_var_mount, "/cache/apt/archives/partial", 0755);

    /* /var/log/apt — apt writes term.log / history.log / eipp.log here during an
     * install; a missing dir → "E: Directory '/var/log/apt/' missing" abort. */
    op_mkdir(&g_var_mount, "/log",     0755);
    op_mkdir(&g_var_mount, "/log/apt", 0755);

    printf("[apt] /var tree seeded · /var/lib/apt/lists/partial + "
           "/var/cache/apt/archives/partial + /var/log/apt (config from /etc honey base)\n");
}

vfs_mount_t lucas_sotfs_var_mount(void)
{
    lazy_init();
    g_var_mount.root_id = sotfs_mount_make_root("var");
    g_var_mount.label   = "var";
    printf("[sotfs] mounted /var · root_id=%d\n", g_var_mount.root_id);
    var_root_selftest();
    dpkg_db_seed();
    apt_tree_seed();

    /* apk-local-install · pre-create /var/cache/apk so apk does not have to
     * mkdir it at runtime (safer than relying on per-session upper mkdir).
     * Paths are relative to the /var root — mirrors the dpkg_db_seed pattern. */
    op_mkdir(&g_var_mount, "/cache",     0755);
    op_mkdir(&g_var_mount, "/cache/apk", 0755);
    printf("[sotfs] /var/cache/apk seeded\n");

    return (vfs_mount_t) {
        .prefix        = "/var",
        .ops           = &sotfs_ops,
        .backend_state = &g_var_mount,
    };
}

/* ── sotFS-θ → anomaly-ext correlation ─────────────────────────────── */

/* Strong override of the weak stub in graph_curvature.c.
 * Called when a RANSOMWARE (rule_kind=1) or LATERAL (rule_kind=2) rule fires.
 * Sends ANOMALY_EV_CURVATURE to anomaly-ext for audit + correlation.
 * This function lives here (not in graph_curvature.c) so it can use seL4 IPC headers
 * without polluting sotos-sotfs with autoconf/seL4 include requirements.
 *
 * CURVATURE-AUTOPROMOTE · pid attributes the alert to the calling sotbox so
 * anomaly-ext can auto-promote it to Tier-2.  pid=0 = "system" (operator
 * / bootstrap commit · no per-sotbox context). */
void sotfs_graph_curvature_anomaly_notify(uint32_t pid, int rule_kind, int severity)
{
    extern seL4_CPtr orch_get_anomaly_ep(void);
    seL4_CPtr ep = orch_get_anomaly_ep();
    if (ep == 0) return;

    /* CURVATURE-AUTOPROMOTE · bump the per-sotbox curvature-alert counter when
     * the event is attributed.  Uses the current caller (set by the dispatch
     * layer before each VFS op) and matches the cap_revoke_count pattern. */
    if (pid != 0) {
        lucas_state_t *caller = lucas_get_current_caller();
        if (caller && (uint32_t)caller->synthetic_pid == pid) {
            caller->curvature_alerts++;
        }
    }

    seL4_SetMR(0, (seL4_Word)pid);          /* pid · 0 = system, >0 = sotbox synthetic_pid */
    seL4_SetMR(1, ANOMALY_EV_CURVATURE);
    seL4_SetMR(2, (seL4_Word)rule_kind);
    seL4_SetMR(3, (seL4_Word)severity);
    /* REPLY-DRIVEN promote · anomaly returns the tier in MR(0) (no re-entrant
     * seL4_Call(orch_ep) · that deadlocks from a captive-orch context). */
    seL4_MessageInfo_t cr = seL4_Call(ep, seL4_MessageInfo_new(ORCH_OP_ANOMALY_EVENT, 0, 0, 4));
    {
        int pt = (seL4_MessageInfo_get_length(cr) > 0) ? (int)seL4_GetMR(0) : 0;
        if (pt > 0 && pid >= 1) {
            extern void orch_anomaly_apply_promote(uint32_t pid, int tier);
            orch_anomaly_apply_promote(pid, pt);
        }
    }

    /* SG-FS Phase 2 · additive sotGuard event emit (anomaly-ext IPC above
     * stays as-is).  rule_kind==1 → RANSOMWARE, otherwise → LATERAL.
     * Best-effort: ignore the sotguard_emit return value. */
    {
        static uint64_t sg_graph_curvature_monotonic = 0;
        sotguard_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.pid = pid;
        ev.type = (rule_kind == 1) ? SG_EV_GRAPH_CURVATURE_RANSOM : SG_EV_GRAPH_CURVATURE_LATERAL;
        ev.timestamp = ++sg_graph_curvature_monotonic;
        ev.detail.graph_curvature.rule_kind = (uint32_t)rule_kind;
        ev.detail.graph_curvature.severity = (uint32_t)severity;
        (void)sotguard_emit(&ev);
    }
}
