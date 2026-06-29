#include <lucas/vfs.h>
#include <lucas/backends_python_stdlib.h>  /* L11-γ · U2 provides */
#include <lucas/backends_sysroot.h>        /* tcc-libc · /usr musl sysroot */
#include "backends_doom_wad.h"             /* doom · /doom1.wad WAD backend */
#include "backends_cacert.h"               /* egress · /etc/ssl/cert.pem real CA bundle */
#include <sotos/path_matcher.h>             /* γ · F_persistence sensitive-path detector */

#include "state.h"
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

/* Backend forward declarations · real symbols provided by backends_static.c
 * (T3), backends_proc.c (T4), and backends_sotfs.c (Phase 2). */

extern const vfs_ops_t vfs_static_ops;
extern void *vfs_static_state(void);

extern const vfs_ops_t vfs_proc_ops;
extern void *vfs_proc_state(struct lucas_state *st);

extern vfs_mount_t lucas_sotfs_mount(void);
extern vfs_mount_t lucas_sotfs_var_mount(void);   /* install-arc · writable /var (own root) */
extern vfs_mount_t lucas_etc_union_mount(void);   /* install-arc P1b · writable /etc (honey base + sotfs upper) */
extern vfs_mount_t lucas_pty_mount(void);
extern vfs_mount_t lucas_shm_mount(void);    /* U4 · /dev/shm backend */
/* L11-γ · lucas_python_stdlib_mount declared in <lucas/backends_python_stdlib.h>;
 * defined by U2 in src/lucas/backends_python_stdlib.c. */

const vfs_mount_t *vfs_resolve(struct lucas_state *st,
                                const char *path,
                                const char **out_suffix) {
    const vfs_mount_t *best = NULL;
    size_t best_len = 0;
    for (size_t i = 0; i < LUCAS_MAX_MOUNTS; ++i) {
        const vfs_mount_t *m = &st->mount_table[i];
        if (m->prefix == NULL) continue;
        size_t plen = strlen(m->prefix);
        bool matches;
        if (plen == 1 && m->prefix[0] == '/') {
            /* "/" mount matches any absolute path. */
            matches = (path[0] == '/');
        } else {
            /* Match prefix exactly OR prefix followed by '/'. */
            matches = (strncmp(path, m->prefix, plen) == 0) &&
                      (path[plen] == '\0' || path[plen] == '/');
        }
        if (matches && plen > best_len) {
            best = m;
            best_len = plen;
        }
    }
    /* V-CANARY-ALIAS · the simulated_attacker.py demo opens "/canary-*" without
     * the "/tmp/" prefix.  Longest-prefix match routes those to the root
     * mount (vfs_static_ops), which returns ENOENT.  Redirect "/canary-*"
     * paths to the sotFS mount (where canary files are installed at boot)
     * by handing the sotFS mount the path as its own suffix.  sotFS's
     * sotfs_resolve_path() accepts leading-slash paths relative to its
     * root, so "/honey-aws-creds" resolves directly without rewriting. */
    if (best && best_len == 1 && best->prefix[0] == '/' &&
        strncmp(path, "/canary-", 7) == 0) {
        for (size_t i = 0; i < LUCAS_MAX_MOUNTS; ++i) {
            const vfs_mount_t *m = &st->mount_table[i];
            if (m->prefix != NULL && strcmp(m->prefix, "/tmp") == 0) {
                *out_suffix = path;
                return m;
            }
        }
        /* sotFS mount missing · fall through to root mount (will ENOENT). */
    }

    /* F-PERSISTENCE-ALIAS · paths that path_matcher considers persistence-
     * install vectors (crontab, unit files, shell rc, freedesktop autostart)
     * MUST route to the writable sotfs backend rather than vfs_static_ops
     * (which is read-only and returns -ENOENT for unknown paths).  Without
     * this alias the malware's open(O_CREAT) calls silently fail and the γ
     * demo never persists anything · post-simreboot `cat /etc/crontab`
     * returns -ENOENT instead of the lie.  Mirrors the V-CANARY-ALIAS
     * pattern · sotfs_resolve_path accepts the leading-slash path as-is. */
    if (best && best_len == 1 && best->prefix[0] == '/' &&
        sotos_path_is_persistence_sensitive(path)) {
        for (size_t i = 0; i < LUCAS_MAX_MOUNTS; ++i) {
            const vfs_mount_t *m = &st->mount_table[i];
            if (m->prefix != NULL && strcmp(m->prefix, "/tmp") == 0) {
                *out_suffix = path;
                return m;
            }
        }
        /* sotFS mount missing · fall through to root mount (will ENOENT). */
    }

    /* N3/D2 · /lib → sysroot /usr/lib alias.  ld-musl resolves DT_NEEDED .so's
     * via its default search path (/lib first).  Route "/lib/<x>" to the sysroot
     * mount (prefix "/usr"), which serves the real recursive lib tree (incl.
     * symlinks).  The sysroot keys entries relative to /usr ("lib/<x>") and
     * rel() strips the leading '/', so "/lib/<x>" resolves to "lib/<x>".
     * Wine M1 · also match BARE "/lib": wine dlopens ntdll.so from /lib/wine then
     * realpath()s it, and musl's realpath lstat()s every component INCLUDING
     * "/lib" — which would otherwise hit the empty /lib placeholder mount and
     * ENOENT, failing realpath → "cannot get path to ntdll.so".  "/lib" → sysroot
     * rel() "lib" → the real lib-tree root DIR entry. */
    if (strncmp(path, "/lib/", 5) == 0 || strcmp(path, "/lib") == 0) {
        for (size_t i = 0; i < LUCAS_MAX_MOUNTS; ++i) {
            const vfs_mount_t *m = &st->mount_table[i];
            if (m->prefix != NULL && strcmp(m->prefix, "/usr") == 0) {
                *out_suffix = path;   /* "/lib/x.so" → sysroot rel() → "lib/x.so" */
                return m;
            }
        }
        /* sysroot mount missing · fall through (will hit /lib placeholder → ENOENT). */
    }

    if (best) {
        if (best_len == 1 && best->prefix[0] == '/') {
            /* For root mount, the suffix is the full path. */
            *out_suffix = path;
        } else {
            *out_suffix = path + best_len;
            if (**out_suffix == '\0') *out_suffix = "/";
        }
        return best;
    }
    *out_suffix = NULL;
    return NULL;
}

void vfs_install_defaults(struct lucas_state *st) {
    memset(st->mount_table, 0, sizeof(st->mount_table));

    /* /proc backend · pid-aware (T4 will give it real ops). */
    st->mount_table[0].prefix        = "/proc";
    st->mount_table[0].ops           = &vfs_proc_ops;
    st->mount_table[0].backend_state = vfs_proc_state(st);

    /* /etc and other static content under root mount. */
    st->mount_table[1].prefix        = "/";
    st->mount_table[1].ops           = &vfs_static_ops;
    st->mount_table[1].backend_state = vfs_static_state();

    /* sotFS-α Phase 2: writable in-memory DPO graph backend at /tmp. */
    st->mount_table[2] = lucas_sotfs_mount();

    /* L10: PTY backend at /dev/p (covers /dev/ptmx + /dev/pts/N). */
    st->mount_table[3] = lucas_pty_mount();

    /* U4 · POSIX shared-memory backend at /dev/shm.  Longest-prefix match
     * ensures "/dev/shm/<name>" binds here rather than "/" or "/dev/p". */
    st->mount_table[4] = lucas_shm_mount();

    /* MS-M5 scaffold · /lib for dynamic loader (placeholder · real ld-musl
     * loaded in future batch). */
    st->mount_table[5].prefix     = "/lib";
    st->mount_table[5].ops        = &vfs_static_ops;
    /* (no backend_state needed for static_vfs · uses global table) */

    /* L11-γ scaffold · /install/lib for Python stdlib zip (slot 6). */
    st->mount_table[6] = lucas_python_stdlib_mount();

    /* Install-arc · /usr as a writable OVERLAY (sotfs upper + sysroot base, slot 7).
     * Reads fall back to the read-only sysroot (the baked /usr lib closures stay
     * byte-identical); writes/creates land in the disk-backed upper subtree. */
    st->mount_table[7] = lucas_usr_union_mount();
    printf("[vfs] /usr mount installed (writable overlay · sotfs upper + sysroot base)\n");

    /* doom · /doom1.wad WAD backend (slot 8). */
    st->mount_table[8] = lucas_doom_wad_mount();
    printf("[vfs] /doom1.wad mount installed (doom-wad backend)\n");

    /* install-arc · writable /var (slot 9) · sotfs backend, OWN root inode so
     * /var/foo and /tmp/foo are distinct subtrees in the one shared graph.
     * Installed AFTER the /tmp mount (slot 2) so the graph + blkdev are live
     * (lucas_sotfs_mount → lazy_init runs the disk-backed setup). */
    st->mount_table[9] = lucas_sotfs_var_mount();
    printf("[vfs] /var mount installed (sotfs writable · distinct root)\n");

    /* install-arc P1b · /etc as a writable OVERLAY (slot 10) · the static honey
     * tree (passwd/group/shadow/os-release/…) stays the read-only BASE; a real
     * postinst's `cp foo /etc/foo` lands in the writable sotfs upper and reads
     * back, while `cat /etc/passwd` still returns the persona honey (deception
     * intact).  Longer prefix "/etc" shadows the static "/" mount for /etc/*. */
    st->mount_table[10] = lucas_etc_union_mount();
    printf("[vfs] /etc mount installed (writable overlay · honey base + sotfs upper)\n");

    /* egress · the real CA trust store at /etc/ssl/cert.pem (OpenSSL default) so
     * the Tier-0e TLS client VERIFIES real server certs.  Longest-prefix beats
     * the "/etc" union above. */
    st->mount_table[11] = lucas_cacert_mount();
    printf("[vfs] /etc/ssl/cert.pem mount installed (real CA bundle · egress TLS verify)\n");

    /* The legacy "(4 entries ..." log line is preserved verbatim for the
     * smoke harness, then augmented with the U4 mount on a second line. */
    printf("[lucas] vfs: installed mount table (4 entries · /proc + / + /tmp + /dev/p) + U4 /dev/shm\n");
    printf("[vfs] /lib mount installed (MS-M5 scaffold · placeholder)\n");
    printf("[vfs] /install/lib mount installed (L11-γ · stdlib zip)\n");
}
