/*
 * sotOs · LUCAS · Linux-ABI tier handlers (deception).
 *
 * Closes the syscall gaps that make the honeypot detectable (ENOSYS under
 * strace) or that crash real attacker tooling.  Three tiers:
 *   Tier 1 · file mutations (mkdir/rename/chmod/...) with realistic returns.
 *   Tier 2 · modern-binary compatibility (prctl/statx/clone3/...).
 *   Tier 3 · capture juicy attacker behavior (init_module/mount/setxattr/...).
 *
 * Deception principle: a real Linux almost never returns ENOSYS for a common
 * syscall.  Each handler returns what a real (root-on-a-box) kernel would —
 * success (0), or a believable EPERM/EEXIST — so `strace`/`mkdir`/`chmod`
 * behave normally while side effects stay contained in the canary layer.
 */
#include "handlers.h"
#include "state.h"
#include <lucas/linux_abi.h>
#include <lucas/vfs.h>
#include <lucas/syscalls.h>
#include <lucas/anomaly.h>
#include <lucas/symlink_table.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Helpers implemented in handlers_fs.c (non-static) + the sotfs rw backend. */
extern int lucas_copy_cstr_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                       char *buf, size_t buf_size);
extern int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                                const void *buf, size_t n);
extern int lucas_sotfs_mkdir(const char *path, uint32_t mode);
extern int lucas_sotfs_rmdir(const char *path);
extern int lucas_sotfs_rename(const char *oldpath, const char *newpath);
extern int64_t lucas_sys_access(lucas_state_t *, uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint64_t);
/* G2: thread the calling sotbox into the sotfs backend (session tagging).
 * Defined in handlers_fs.c; must be set before any backend mutation op and
 * cleared (NULL) immediately after so the caller is never leaked. */
extern void lucas_set_current_caller(lucas_state_t *st);

#ifndef LX_AT_FDCWD
#define LX_AT_FDCWD ((int64_t)-100)
#endif

/* Copy a client path; -EFAULT on failure.  Empty buffer on NULL ptr. */
static int abi_path(lucas_state_t *st, uint64_t vaddr, char *buf, size_t n)
{
    if (vaddr == 0) { buf[0] = '\0'; return 0; }
    char raw[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, (uintptr_t)vaddr, raw, sizeof(raw)) < 0)
        return -(int)LX_EFAULT;
    /* WINE-M1 · resolve relative + "."/".." against the process cwd (set by
     * chdir), exactly like open/stat/unlink do via lucas_resolve_path.  The abi
     * dir ops (mkdir/rmdir/rename) previously took the raw client string, so a
     * relative path reached the sotfs backend unresolved: wine chdir's into its
     * prefix and builds the skeleton (dosdevices, drive_c, …) with RELATIVE
     * mkdir, and "dosdevices" failed split_path → -EINVAL.  Resolving here also
     * makes the attacker shell's post-`cd` relative ops behave correctly. */
    lucas_resolve_path(st, raw, buf, n);
    return 0;
}

/* Copy + resolve a client path against `dirfd` (AT_FDCWD/absolute/real-dir-fd).
 * Defined below (after the u7_resolve_at extern) · forward-declared so the *at
 * dir handlers (mkdirat/renameat/…) can resolve a relative name against a real
 * directory fd — what GNU tar's `-C dir` extraction (mkdirat(dirfd,…)) needs. */
static int abi_path_at(lucas_state_t *st, int64_t dirfd, uint64_t vaddr,
                       char *buf, size_t n);

/* ===== Tier 1 · directory create/remove (backed by the sotfs rw layer) ==== */

int64_t lucas_sys_mkdir(lucas_state_t *st, uint64_t path_v, uint64_t mode,
                        uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    char path[LUCAS_PATH_MAX];
    int e = abi_path(st, path_v, path, sizeof(path));
    if (e) return e;
    printf("[abi] mkdir %s mode=0%o\n", path, (unsigned)mode);
    /* Route through the VFS: resolve mount + suffix, call the mount's mkdir op.
     * NULL op == read-only mount → -EROFS.  /tmp's sotfs op preserves the prior
     * hardcoded behavior exactly. */
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m) return -(int64_t)2;            /* -ENOENT */
    if (!m->ops->mkdir) return -(int64_t)LX_EROFS;
    lucas_set_current_caller(st);
    int rc = m->ops->mkdir(m->backend_state, suffix, (uint32_t)mode);
    lucas_set_current_caller(NULL);
    return (int64_t)rc;
}

/* mkdirat(dirfd, path, mode) · dir-fd-aware: resolve `path` against the dirfd
 * (AT_FDCWD/absolute/real-dir-fd), then mkdir the resolved path.  GNU tar's
 * `-C dir` extraction creates the nested tree via mkdirat(dir_fd, "src/a/…"). */
int64_t lucas_sys_mkdirat(lucas_state_t *st, uint64_t dirfd, uint64_t path_v,
                          uint64_t mode, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a3; (void)_a4; (void)_a5;
    char path[LUCAS_PATH_MAX];
    int e = abi_path_at(st, (int64_t)dirfd, path_v, path, sizeof(path));
    if (e) return (int64_t)e;
    printf("[abi] mkdirat dirfd=%ld %s mode=0%o\n", (long)(int64_t)dirfd, path, (unsigned)mode);
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m) return -(int64_t)2;            /* -ENOENT */
    if (!m->ops->mkdir) return -(int64_t)LX_EROFS;
    lucas_set_current_caller(st);
    int rc = m->ops->mkdir(m->backend_state, suffix, (uint32_t)mode);
    lucas_set_current_caller(NULL);
    return (int64_t)rc;
}

int64_t lucas_sys_rmdir(lucas_state_t *st, uint64_t path_v, uint64_t _a1,
                        uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    char path[LUCAS_PATH_MAX];
    int e = abi_path(st, path_v, path, sizeof(path));
    if (e) return e;
    printf("[abi] rmdir %s\n", path);
    /* Route through the VFS, mirroring mkdir: resolve mount + suffix, call the
     * mount's rmdir op (dir removal · NOTEMPTY-aware).  NULL op == read-only
     * mount → -EROFS.  /tmp's sotfs op preserves the prior hardcoded behavior
     * (incl. the Tier-2 isolated-write guard inside lucas_sotfs_rmdir). */
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m) return -(int64_t)2;            /* -ENOENT */
    if (!m->ops->rmdir) return -(int64_t)LX_EROFS;
    lucas_set_current_caller(st);
    int rc = m->ops->rmdir(m->backend_state, suffix);
    lucas_set_current_caller(NULL);
    return (int64_t)rc;
}

/* ===== Tier 1 · metadata/rename · accept (root would succeed); contained === */

/* dir-fd path resolution (handlers_fs.c) · resolve a relative name against a real
 * directory fd's stored path · what os.scandir/os.walk/shutil.rmtree need. */
extern int64_t u7_resolve_at(lucas_state_t *st, int64_t dirfd,
                             const char *pathname, char *out, size_t outsz);

/* Copy + resolve a client path against `dirfd` (AT_FDCWD/absolute/real-dir-fd). */
static int abi_path_at(lucas_state_t *st, int64_t dirfd, uint64_t vaddr,
                       char *buf, size_t n)
{
    if (vaddr == 0) { buf[0] = '\0'; return 0; }
    char raw[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, (uintptr_t)vaddr, raw, sizeof(raw)) < 0)
        return -(int)LX_EFAULT;
    int64_t r = u7_resolve_at(st, dirfd, raw, buf, n);
    return (r < 0) ? (int)r : 0;
}

/* Rename two already-resolved absolute paths · the shared core of rename/
 * renameat/renameat2 (deception-contained for F_2, real VFS rename otherwise). */
static int64_t lucas_rename_resolved(lucas_state_t *st, const char *oldp, const char *newp)
{
    /* Isolated (F_2 · the honey/attacker sotbox): keep the deception — pretend
     * success but never touch the graph (writes are contained).  Gate on the
     * SAME condition as write()/mkdir()/unlink() (functor->is_isolated), NOT a
     * tier number — Tier-1 (F_1) is not the isolation tier and op_write doesn't
     * silence it either, so a `tier>=2` gate was both inconsistent and let a
     * never-isolated F_1 do real renames. */
    if (st->functor && st->functor->is_isolated && st->cow_session == 0) {
        /* Tier-2 WITHOUT an SSH session (cow_session==0): keep the deception
         * drop — there is no per-session upper to rename within. */
        printf("[abi] rename %s -> %s (accepted, contained · F_2 sessionless)\n", oldp, newp);
        return 0;
    }
    /* apk-network-install · if the source is a per-session symlink-table entry (a
     * contained symlink the session created — e.g. apk writes its soname link at a
     * `.apk.<hash>` temp then renames it to libncursesw.so.6), MOVE the table entry
     * to the new name.  The VFS rename below only knows real inodes and would
     * -ENOENT on a table-only symlink, breaking apk's install (RC!=0).  The stale
     * source key is harmless (reaped at session end). */
    if (st->cow_session != 0) {
        const char *sl = lucas_symlink_get(st->cow_session, oldp);
        if (sl) {
            char sltgt[LUCAS_PATH_MAX];
            size_t n = strlen(sl);
            if (n >= sizeof(sltgt)) n = sizeof(sltgt) - 1;
            memcpy(sltgt, sl, n); sltgt[n] = '\0';
            /* By the time apk renames the soname temp to its final name, the
             * symlink TARGET (e.g. libncursesw.so.6.4) is already materialized in
             * the upper.  Make the final name a REAL COPY of the target so ld-musl
             * opens it DIRECTLY (a NEEDED soname link like libncursesw.so.6 must be
             * openable by the loader — a table-only entry is not, and adding a
             * general open-follow would weaken the symlink-escape containment).
             * Resolve the (relative) target against the link's directory, then
             * copy same-mount (mirrors lucas_sys_link).  Falls back to the table
             * move if the target is still unreadable (a genuine forward-ref). */
            char rtgt[LUCAS_PATH_MAX];
            if (sltgt[0] == '/') {
                size_t m = strlen(sltgt);
                if (m >= sizeof(rtgt)) m = sizeof(rtgt) - 1;
                memcpy(rtgt, sltgt, m); rtgt[m] = '\0';
            } else {
                size_t dn = strlen(newp);
                if (dn >= sizeof(rtgt)) dn = sizeof(rtgt) - 1;
                memcpy(rtgt, newp, dn); rtgt[dn] = '\0';
                char *slash = strrchr(rtgt, '/');
                if (slash) slash[1] = '\0'; else rtgt[0] = '\0';
                size_t rl = strlen(rtgt), tl = strlen(sltgt);
                if (rl + tl < sizeof(rtgt)) memcpy(rtgt + rl, sltgt, tl + 1);
            }
            const char *ssuf, *dsuf;
            const vfs_mount_t *sm = vfs_resolve(st, rtgt, &ssuf);
            const vfs_mount_t *dm = vfs_resolve(st, newp, &dsuf);
            if (sm && dm && sm == dm && sm->ops->open && sm->ops->read &&
                sm->ops->write && sm->ops->close) {
                void *hs = NULL, *hd = NULL;
                lucas_set_current_caller(st);
                int ro = sm->ops->open(sm->backend_state, ssuf, 0, 0, &hs);
                if (ro == 0 && hs) {
                    int wo = sm->ops->open(sm->backend_state, dsuf,
                                           0x40 | 0x1 | 0x200, 0644, &hd);
                    if (wo == 0 && hd) {
                        static uint8_t rbuf[4096];
                        int64_t off = 0, total = 0;
                        for (;;) {
                            int64_t r = sm->ops->read(sm->backend_state, hs, rbuf,
                                                      sizeof(rbuf), off);
                            if (r <= 0) break;
                            int64_t w = sm->ops->write(sm->backend_state, hd, rbuf,
                                                       (size_t)r, off);
                            if (w < 0) { total = w; break; }
                            off += r; total += r;
                        }
                        sm->ops->close(sm->backend_state, hd);
                        sm->ops->close(sm->backend_state, hs);
                        lucas_set_current_caller(NULL);
                        if (total >= 0) {
                            /* total >= 0 · BOTH opens succeeded → the target was
                             * present (even a 0-byte file is a valid copy).  Return
                             * the real file ONLY — do NOT also add a table entry
                             * (that left an empty file + a shadowing symlink at the
                             * same name · inconsistent).  total < 0 (write error)
                             * falls through to the table move. */
                            printf("[abi] rename %s -> %s (session symlink → real COPY %lld B · loader-openable · contained)\n",
                                   oldp, newp, (long long)total);
                            return 0;
                        }
                    } else { sm->ops->close(sm->backend_state, hs); lucas_set_current_caller(NULL); }
                } else { lucas_set_current_caller(NULL); }
            }
            /* Forward-ref (target not yet materialized) → keep the table move. */
            int arc = lucas_symlink_add(st->cow_session, newp, sltgt);
            printf("[abi] rename %s -> %s (session symlink-table move · target unreadable · contained)\n",
                   oldp, newp);
            return arc;
        }
    }
    /* apk-fs · a Tier-2 SSH SESSION (cow_session!=0) does a REAL rename — but it
     * lands in the per-session upper (the source is a session-owned inode the
     * session itself created; rename only re-edges it, base untouched), so the
     * rename stays CONTAINED + operator-invisible while being read-back coherent.
     * This is what makes apk's atomic install (write `.apk.<hash>` / `installed.new`
     * then rename to the final name) actually MATERIALIZE the final paths — without
     * it apk extracts temps that never become real files (apk info empty, no
     * /etc/terminfo).  Falls through to the real-rename path below (which brackets
     * the caller so the backend's session gate sees st->cow_session).
     * Trusted compat (F_0/F_1) takes the same path — git/dpkg finalize via
     * write-tmp-then-rename too. */
    /* Route through the VFS: resolve BOTH paths.  Cross-mount rename is copy-up
     * territory (out of scope for the foundation) → -EXDEV.  A NULL rename op ==
     * read-only mount → -EROFS.  Same-mount sotfs rename preserves the prior
     * hardcoded behavior exactly. */
    const char *osuffix, *nsuffix;
    const vfs_mount_t *om = vfs_resolve(st, oldp, &osuffix);
    const vfs_mount_t *nm = vfs_resolve(st, newp, &nsuffix);
    if (!om || !nm) return -(int64_t)2;        /* -ENOENT */
    if (om != nm) return -(int64_t)LX_EXDEV;   /* cross-mount rename */
    if (!om->ops->rename) return -(int64_t)LX_EROFS;
    lucas_set_current_caller(st);
    int rc = om->ops->rename(om->backend_state, osuffix, nsuffix);
    lucas_set_current_caller(NULL);
    printf("[abi] rename %s -> %s · real rc=%d\n", oldp, newp, rc);
    return (int64_t)rc;
}

int64_t lucas_sys_rename(lucas_state_t *st, uint64_t old_v, uint64_t new_v,
                         uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    char oldp[LUCAS_PATH_MAX], newp[LUCAS_PATH_MAX];
    if (abi_path(st, old_v, oldp, sizeof(oldp)) || abi_path(st, new_v, newp, sizeof(newp)))
        return -(int64_t)LX_EFAULT;
    return lucas_rename_resolved(st, oldp, newp);
}

/* renameat(olddirfd, old, newdirfd, new) · dir-fd-aware: resolve each name
 * against ITS dirfd (AT_FDCWD/absolute/real-dir-fd).  shutil.rmtree / bdist_wheel
 * move the wheel + rename egg-info→dist-info via renameat(dir_fd,…). */
int64_t lucas_sys_renameat(lucas_state_t *st, uint64_t od, uint64_t old_v,
                           uint64_t nd, uint64_t new_v, uint64_t _a4, uint64_t _a5)
{
    (void)_a4; (void)_a5;
    char oldp[LUCAS_PATH_MAX], newp[LUCAS_PATH_MAX];
    int e1 = abi_path_at(st, (int64_t)od, old_v, oldp, sizeof(oldp));
    if (e1) return (int64_t)e1;
    int e2 = abi_path_at(st, (int64_t)nd, new_v, newp, sizeof(newp));
    if (e2) return (int64_t)e2;
    return lucas_rename_resolved(st, oldp, newp);
}

int64_t lucas_sys_renameat2(lucas_state_t *st, uint64_t od, uint64_t old_v,
                            uint64_t nd, uint64_t new_v, uint64_t _flags, uint64_t _a5)
{
    (void)_flags; (void)_a5;
    char oldp[LUCAS_PATH_MAX], newp[LUCAS_PATH_MAX];
    int e1 = abi_path_at(st, (int64_t)od, old_v, oldp, sizeof(oldp));
    if (e1) return (int64_t)e1;
    int e2 = abi_path_at(st, (int64_t)nd, new_v, newp, sizeof(newp));
    if (e2) return (int64_t)e2;
    return lucas_rename_resolved(st, oldp, newp);
}

int64_t lucas_sys_chmod(lucas_state_t *st, uint64_t path_v, uint64_t mode,
                        uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    char path[LUCAS_PATH_MAX];
    int e = abi_path(st, path_v, path, sizeof(path));
    if (e) return e;
    /* chmod +x on a dropped payload is a strong attacker tell · log loudly. */
    printf("[abi] chmod %s mode=0%o%s (accepted)\n", path, (unsigned)mode,
           (mode & 0111) ? " [+x EXECUTABLE]" : "");
    return 0;
}

int64_t lucas_sys_fchmodat(lucas_state_t *st, uint64_t dirfd, uint64_t path_v,
                           uint64_t mode, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a3; (void)_a4; (void)_a5;
    /* dir-fd-aware · GNU tar -xf sets perms on extracted files via
     * fchmodat(dir_fd, name, mode).  Resolve against the dirfd · chmod is
     * accept-only on the sotfs, so success is all tar needs. */
    char path[LUCAS_PATH_MAX];
    int e = abi_path_at(st, (int64_t)dirfd, path_v, path, sizeof(path));
    if (e) return (int64_t)e;
    printf("[abi] fchmodat %s mode=0%o (accepted)\n", path, (unsigned)mode);
    return 0;
}

int64_t lucas_sys_chown(lucas_state_t *st, uint64_t path_v, uint64_t uid,
                        uint64_t gid, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a3; (void)_a4; (void)_a5;
    char path[LUCAS_PATH_MAX];
    int e = abi_path(st, path_v, path, sizeof(path));
    if (e) return e;
    printf("[abi] chown %s uid=%u gid=%u (accepted)\n", path,
           (unsigned)uid, (unsigned)gid);
    return 0;
}

int64_t lucas_sys_lchown(lucas_state_t *st, uint64_t path_v, uint64_t uid,
                         uint64_t gid, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    return lucas_sys_chown(st, path_v, uid, gid, _a3, _a4, _a5);
}

int64_t lucas_sys_fchownat(lucas_state_t *st, uint64_t dirfd, uint64_t path_v,
                           uint64_t uid, uint64_t gid, uint64_t _flags, uint64_t _a5)
{
    (void)_flags; (void)_a5;
    /* dir-fd-aware · GNU tar -xf sets owner via fchownat(dir_fd, name, …).
     * Resolve against the dirfd · chown is accept-only on the sotfs. */
    char path[LUCAS_PATH_MAX];
    int e = abi_path_at(st, (int64_t)dirfd, path_v, path, sizeof(path));
    if (e) return (int64_t)e;
    printf("[abi] fchownat %s uid=%u gid=%u (accepted)\n", path,
           (unsigned)uid, (unsigned)gid);
    return 0;
}

int64_t lucas_sys_symlink(lucas_state_t *st, uint64_t target_v, uint64_t link_v,
                          uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    /* The target is stored VERBATIM (readlink returns it literally · resolving
     * it here would mangle relative targets like `../foo`); only the link path
     * is canonicalised to an absolute key. */
    char tgt[LUCAS_PATH_MAX], lnk[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, (uintptr_t)target_v, tgt, sizeof(tgt)) < 0)
        return -(int64_t)LX_EFAULT;
    if (abi_path(st, link_v, lnk, sizeof(lnk)))
        return -(int64_t)LX_EFAULT;
    /* Only writable space (/tmp) accepts a symlink — a link under a read-only
     * honey zone (/etc, /bin, …) is contained exactly like a write there. The
     * link is recorded in the per-session symlink table (NOT followed by open),
     * so readlink/lstat surface it like real Linux without an escape surface. */
    if (strncmp(lnk, "/tmp/", 5) != 0 && strcmp(lnk, "/tmp") != 0) {
        /* apk-network-install · a Tier-2 SSH session (cow_session != 0) installing
         * real packages creates symlinks OUTSIDE /tmp — the soname links
         * (/usr/lib/libncursesw.so.6 → libncursesw.so.6.4) and applet aliases
         * (/usr/bin/rnano → nano).  Record them in the per-session symlink table
         * (contained, reaped, surfaced by readlink/lstat, NOT open-followed → no
         * escape) rather than the deception EACCES.  apk creates the symlink at a
         * `.apk.<hash>` temp then renames it to the final name; lucas_sys_rename
         * moves the table entry so the temp-then-rename install completes (RC=0).
         * Lazy by design — works for forward-reference links (the soname symlink
         * extracted before its target).  A sessionless isolated caller keeps the
         * deception EACCES (no per-session table to contain it). */
        if (st->cow_session != 0) {
            int frc = lucas_symlink_add(st->cow_session, lnk, tgt);
            printf("[abi] symlink %s -> %s (recorded · session=%u · contained)\n",
                   lnk, tgt, (unsigned)st->cow_session);
            return frc;
        }
        printf("[abi] symlink %s -> %s (contained · read-only zone · EACCES)\n", lnk, tgt);
        return -(int64_t)LX_EACCES;
    }
    int rc = lucas_symlink_add(st->cow_session, lnk, tgt);
    printf("[abi] symlink %s -> %s (recorded · session=%u · contained)\n",
           lnk, tgt, (unsigned)st->cow_session);
    return rc;
}

int64_t lucas_sys_symlinkat(lucas_state_t *st, uint64_t target_v, uint64_t _nd,
                            uint64_t link_v, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_nd; (void)_a3; (void)_a4; (void)_a5;
    return lucas_sys_symlink(st, target_v, link_v, 0, 0, 0, 0);
}

int64_t lucas_sys_link(lucas_state_t *st, uint64_t old_v, uint64_t new_v,
                       uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    char oldp[LUCAS_PATH_MAX], newp[LUCAS_PATH_MAX];
    if (abi_path(st, old_v, oldp, sizeof(oldp)) || abi_path(st, new_v, newp, sizeof(newp)))
        return -(int64_t)LX_EFAULT;
    /* Isolated (F_2 · honey/attacker) WITHOUT an SSH session: keep the deception
     * drop (no per-session upper to copy into). */
    if (st->functor && st->functor->is_isolated && st->cow_session == 0) {
        printf("[abi] link %s -> %s (accepted, contained · F_2 sessionless)\n", newp, oldp);
        return 0;
    }
    /* apk-fs · a Tier-2 SSH session (cow_session!=0) emulates the hardlink via a
     * real COPY into the per-session upper (contained, base untouched).  apk
     * hardlinks duplicate package files (e.g. terminfo vt220→vt200) then renames
     * the link to the final name; without a real link the rename finds no source
     * (-ENOENT · "failed to rename ... to vt220").  Falls through to the same-mount
     * copy-emulation below (already caller-bracketed). */
    /* Trusted compat (F_0/F_1): the sotfs graph has no hardlink op.  git +
     * fontconfig fall back to copy when link() returns -EXDEV, but dpkg does
     * NOT for its atomic status update (link status → status-old backup, then
     * rename status-new → status) — it treats EXDEV as fatal ("error creating
     * new backup file '/var/lib/dpkg/status-old': Invalid cross-device link").
     * When BOTH paths live in the SAME writable mount, emulate the hardlink with
     * a real COPY of old→new (a backup copy is what the caller wants).  Cross-
     * mount or a non-openable source keeps the prior -EXDEV. */
    const char *osuffix, *nsuffix;
    const vfs_mount_t *om = vfs_resolve(st, oldp, &osuffix);
    const vfs_mount_t *nm = vfs_resolve(st, newp, &nsuffix);
    if (om && nm && om == nm && om->ops->open && om->ops->read &&
        om->ops->write && om->ops->close) {
        void *hsrc = NULL, *hdst = NULL;
        lucas_set_current_caller(st);
        int ro = om->ops->open(om->backend_state, osuffix, 0 /*O_RDONLY*/, 0, &hsrc);
        if (ro != 0 || !hsrc) {
            lucas_set_current_caller(NULL);
            printf("[abi] link %s -> %s · src open rc=%d → -EXDEV\n", newp, oldp, ro);
            return -(int64_t)LX_EXDEV;
        }
        int wo = om->ops->open(om->backend_state, nsuffix,
                               0x40 | 0x1 | 0x200 /*O_CREAT|O_WRONLY|O_TRUNC*/, 0644, &hdst);
        if (wo != 0 || !hdst) {
            om->ops->close(om->backend_state, hsrc);
            lucas_set_current_caller(NULL);
            printf("[abi] link %s -> %s · dst open rc=%d → -EXDEV\n", newp, oldp, wo);
            return -(int64_t)LX_EXDEV;
        }
        static uint8_t lbuf[4096];
        int64_t off = 0, total = 0;
        for (;;) {
            int64_t r = om->ops->read(om->backend_state, hsrc, lbuf, sizeof(lbuf), off);
            if (r <= 0) break;
            int64_t w = om->ops->write(om->backend_state, hdst, lbuf, (size_t)r, off);
            if (w < 0) { total = w; break; }
            off += r; total += r;
        }
        om->ops->close(om->backend_state, hsrc);
        om->ops->close(om->backend_state, hdst);
        lucas_set_current_caller(NULL);
        printf("[abi] link %s -> %s · same-mount COPY %lld bytes (hardlink emulated)\n",
               newp, oldp, (long long)total);
        return total < 0 ? total : 0;
    }
    printf("[abi] link %s -> %s · -EXDEV → caller copies\n", newp, oldp);
    return -(int64_t)LX_EXDEV;
}

int64_t lucas_sys_linkat(lucas_state_t *st, uint64_t _od, uint64_t old_v,
                         uint64_t _nd, uint64_t new_v, uint64_t _flags, uint64_t _a5)
{
    (void)_od; (void)_nd; (void)_flags; (void)_a5;
    return lucas_sys_link(st, old_v, new_v, 0, 0, 0, 0);
}

int64_t lucas_sys_truncate(lucas_state_t *st, uint64_t path_v, uint64_t length,
                           uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    char path[LUCAS_PATH_MAX];
    int e = abi_path(st, path_v, path, sizeof(path));
    if (e) return e;
    printf("[abi] truncate %s len=%lu (accepted, contained)\n",
           path, (unsigned long)length);
    return 0;
}

/* utime/utimes/futimesat · timestamps · accept silently (same as utimensat). */
int64_t lucas_sys_utimes(lucas_state_t *st, uint64_t path_v, uint64_t _times,
                         uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_times; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    char path[LUCAS_PATH_MAX];
    int e = abi_path(st, path_v, path, sizeof(path));
    if (e) return e;
    printf("[abi] utimes %s (accepted)\n", path);
    return 0;
}

int64_t lucas_sys_utime(lucas_state_t *st, uint64_t path_v, uint64_t times,
                        uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
    return lucas_sys_utimes(st, path_v, times, a2, a3, a4, a5);
}

int64_t lucas_sys_futimesat(lucas_state_t *st, uint64_t dirfd, uint64_t path_v,
                            uint64_t times, uint64_t a3, uint64_t a4, uint64_t a5)
{
    if ((int64_t)(int)dirfd != LX_AT_FDCWD) return -(int64_t)LX_EBADF;
    return lucas_sys_utimes(st, path_v, times, a3, a4, a5, 0);
}

/* faccessat/faccessat2 · delegate to the path-based access check. */
int64_t lucas_sys_faccessat(lucas_state_t *st, uint64_t dirfd, uint64_t path_v,
                            uint64_t mode, uint64_t _flags, uint64_t _a4, uint64_t _a5)
{
    (void)_flags; (void)_a4; (void)_a5;
    if ((int64_t)(int)dirfd != LX_AT_FDCWD) return -(int64_t)LX_EBADF;
    return lucas_sys_access(st, path_v, mode, 0, 0, 0, 0);
}

/* ==========================================================================
 * Tier 2 · modern-binary compatibility (no clean libc fallback → must work).
 * statx/waitid/recvmmsg/timerfd/signalfd/inotify deliberately stay ENOSYS:
 * libc falls back (fstatat/wait4/recvmsg) and an inert timerfd/inotify fd
 * would risk hanging a poll loop — a clean error is safer + still plausible.
 * ========================================================================== */

extern int lucas_copy_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                  void *buf, size_t n);
extern int64_t lucas_sys_clone(lucas_state_t *, uint64_t, uint64_t, uint64_t,
                               uint64_t, uint64_t, uint64_t);

/* prctl · most ops are advisory; succeed.  A few GETs return a plausible value
 * so a program that branches on them behaves like it's on a normal box. */
#define LX_PR_SET_DUMPABLE       4
#define LX_PR_GET_DUMPABLE       3
#define LX_PR_SET_NAME           15
#define LX_PR_GET_NAME           16
#define LX_PR_CAPBSET_READ       23
#define LX_PR_GET_NO_NEW_PRIVS   39
int64_t lucas_sys_prctl(lucas_state_t *st, uint64_t option, uint64_t a2,
                        uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6)
{
    (void)st; (void)a3; (void)a4; (void)a5; (void)a6;
    switch ((int)option) {
        case LX_PR_GET_DUMPABLE:     return 1;   /* normal process is dumpable */
        case LX_PR_GET_NO_NEW_PRIVS: return 0;
        case LX_PR_CAPBSET_READ:     return 1;   /* root · cap present */
        case LX_PR_SET_NAME:
            printf("[abi] prctl(PR_SET_NAME) (accepted)\n");
            return 0;
        default:
            (void)a2;
            return 0;                 /* SET_DUMPABLE / NO_NEW_PRIVS / ... succeed */
    }
}

/* clone3(struct clone_args *, size) · translate to the clone() path so modern
 * glibc/musl thread + process creation works.  clone_args layout (uapi):
 *   0:flags 8:pidfd 16:child_tid 24:parent_tid 32:exit_signal 40:stack
 *   48:stack_size 56:tls ...  Note clone3 passes the stack BASE+size; clone
 *   wants the stack TOP, so newsp = stack + stack_size. */
int64_t lucas_sys_clone3(lucas_state_t *st, uint64_t args_v, uint64_t size,
                         uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    uint64_t a[8] = {0};
    size_t n = (size < sizeof(a)) ? (size_t)size : sizeof(a);
    if (lucas_copy_from_client(st, (uintptr_t)args_v, a, n) != 0)
        return -(int64_t)LX_EFAULT;
    uint64_t flags  = a[0];
    uint64_t ctid   = a[2];
    uint64_t ptid   = a[3];
    uint64_t stack  = a[5];
    uint64_t ssize  = a[6];
    uint64_t tls    = a[7];
    uint64_t newsp  = stack ? (stack + ssize) : 0;
    printf("[abi] clone3 flags=0x%lx → clone\n", (unsigned long)flags);
    return lucas_sys_clone(st, flags, newsp, ptid, ctid, tls, 0);
}

/* Privilege ops · root would succeed · accept (contained: no real uid change). */
int64_t lucas_sys_setresuid(lucas_state_t *st, uint64_t r, uint64_t e, uint64_t s,
                            uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)st; (void)_a3; (void)_a4; (void)_a5;
    printf("[abi] setresuid r=%d e=%d s=%d (accepted)\n", (int)r, (int)e, (int)s);
    return 0;
}
int64_t lucas_sys_setresgid(lucas_state_t *st, uint64_t r, uint64_t e, uint64_t s,
                            uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)r;(void)e;(void)s;(void)a3;(void)a4;(void)a5; return 0; }
int64_t lucas_sys_setreuid(lucas_state_t *st, uint64_t r, uint64_t e, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)r;(void)e;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }
int64_t lucas_sys_setregid(lucas_state_t *st, uint64_t r, uint64_t e, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)r;(void)e;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }
int64_t lucas_sys_setfsuid(lucas_state_t *st, uint64_t u, uint64_t a1, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)u;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return 0; /* prev fsuid (root) */ }
int64_t lucas_sys_setfsgid(lucas_state_t *st, uint64_t g, uint64_t a1, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)g;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }
int64_t lucas_sys_setgroups(lucas_state_t *st, uint64_t n, uint64_t list, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)n;(void)list;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }

/* getresuid/getresgid · write {root,root,root} into the three out pointers. */
int64_t lucas_sys_getresuid(lucas_state_t *st, uint64_t r, uint64_t e, uint64_t s,
                            uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a3; (void)_a4; (void)_a5;
    uint32_t zero = 0;
    if (r) lucas_copy_to_client(st, (uintptr_t)r, &zero, sizeof(zero));
    if (e) lucas_copy_to_client(st, (uintptr_t)e, &zero, sizeof(zero));
    if (s) lucas_copy_to_client(st, (uintptr_t)s, &zero, sizeof(zero));
    return 0;
}
int64_t lucas_sys_getresgid(lucas_state_t *st, uint64_t r, uint64_t e, uint64_t s,
                            uint64_t a3, uint64_t a4, uint64_t a5)
{ return lucas_sys_getresuid(st, r, e, s, a3, a4, a5); }

/* membarrier(cmd,flags) · QUERY(0) returns 0 (no commands → caller uses its
 * fallback barrier); other cmds succeed. */
int64_t lucas_sys_membarrier(lucas_state_t *st, uint64_t cmd, uint64_t a1, uint64_t a2,
                             uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)cmd;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }

/* flock(fd,op) · advisory lock · succeed. */
int64_t lucas_sys_flock(lucas_state_t *st, uint64_t fd, uint64_t op, uint64_t a2,
                        uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)fd;(void)op;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }

/* ==========================================================================
 * Tier 3 · capture juicy attacker behavior.  These are the syscalls an
 * intruder uses to install a rootkit, escape, or tamper with the host.  We
 * LOG them loudly ([abi-capture] · deception intelligence) and return what a
 * real (contained / unprivileged-for-this-op) Linux returns — usually EPERM —
 * so the attacker sees a believable failure while we record the attempt.
 * ========================================================================== */

/* Kernel-module loading · the classic rootkit vector. */
int64_t lucas_sys_init_module(lucas_state_t *st, uint64_t _img, uint64_t len,
                              uint64_t _param, uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)st; (void)_img; (void)_param; (void)a3; (void)a4; (void)a5;
    printf("[abi-capture] init_module len=%lu · ROOTKIT-LOAD attempt · -EPERM\n",
           (unsigned long)len);
    return -(int64_t)LX_EPERM;
}
int64_t lucas_sys_finit_module(lucas_state_t *st, uint64_t fd, uint64_t _param,
                               uint64_t flags, uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)st; (void)_param; (void)a3; (void)a4; (void)a5;
    printf("[abi-capture] finit_module fd=%d flags=0x%lx · ROOTKIT-LOAD attempt · -EPERM\n",
           (int)fd, (unsigned long)flags);
    return -(int64_t)LX_EPERM;
}
int64_t lucas_sys_delete_module(lucas_state_t *st, uint64_t name_v, uint64_t flags,
                                uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)flags; (void)a2; (void)a3; (void)a4; (void)a5;
    char name[64];
    abi_path(st, name_v, name, sizeof(name));
    printf("[abi-capture] delete_module '%s' · -EPERM\n", name);
    return -(int64_t)LX_EPERM;
}

/* Filesystem escape / remount. */
int64_t lucas_sys_mount(lucas_state_t *st, uint64_t _src, uint64_t tgt_v,
                        uint64_t fstype_v, uint64_t flags, uint64_t _data, uint64_t a5)
{
    (void)_src; (void)_data; (void)a5;
    char tgt[LUCAS_PATH_MAX], fstype[32];
    abi_path(st, tgt_v, tgt, sizeof(tgt));
    abi_path(st, fstype_v, fstype, sizeof(fstype));
    printf("[abi-capture] mount type=%s target=%s flags=0x%lx · -EPERM\n",
           fstype, tgt, (unsigned long)flags);
    return -(int64_t)LX_EPERM;
}
int64_t lucas_sys_umount2(lucas_state_t *st, uint64_t tgt_v, uint64_t flags,
                          uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)flags; (void)a2; (void)a3; (void)a4; (void)a5;
    char tgt[LUCAS_PATH_MAX];
    abi_path(st, tgt_v, tgt, sizeof(tgt));
    printf("[abi-capture] umount2 %s · -EPERM\n", tgt);
    return -(int64_t)LX_EPERM;
}
int64_t lucas_sys_chroot(lucas_state_t *st, uint64_t path_v, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    char path[LUCAS_PATH_MAX];
    abi_path(st, path_v, path, sizeof(path));
    printf("[abi-capture] chroot %s · -EPERM\n", path);
    return -(int64_t)LX_EPERM;
}
int64_t lucas_sys_pivot_root(lucas_state_t *st, uint64_t newr, uint64_t oldr,
                             uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)newr; (void)oldr; (void)a2; (void)a3; (void)a4; (void)a5;
    printf("[abi-capture] pivot_root · CONTAINER-ESCAPE attempt · -EPERM\n");
    (void)st; return -(int64_t)LX_EPERM;
}

/* Extended attributes · capabilities / immutable-flag tampering.  Accept SETs
 * (so `setcap`/`chattr`-style tools "work"), report no data on GETs. */
int64_t lucas_sys_setxattr(lucas_state_t *st, uint64_t path_v, uint64_t name_v,
                           uint64_t _val, uint64_t size, uint64_t flags, uint64_t a5)
{
    (void)_val; (void)flags; (void)a5;
    char path[LUCAS_PATH_MAX], name[64];
    abi_path(st, path_v, path, sizeof(path));
    abi_path(st, name_v, name, sizeof(name));
    printf("[abi-capture] setxattr %s name=%s size=%lu (accepted)\n",
           path, name, (unsigned long)size);
    return 0;
}
int64_t lucas_sys_lsetxattr(lucas_state_t *st, uint64_t p, uint64_t n, uint64_t v,
                            uint64_t s, uint64_t f, uint64_t a5)
{ return lucas_sys_setxattr(st, p, n, v, s, f, a5); }
int64_t lucas_sys_fsetxattr(lucas_state_t *st, uint64_t fd, uint64_t name_v, uint64_t _v,
                            uint64_t size, uint64_t f, uint64_t a5)
{
    (void)_v; (void)f; (void)a5;
    char name[64]; abi_path(st, name_v, name, sizeof(name));
    printf("[abi-capture] fsetxattr fd=%d name=%s size=%lu (accepted)\n",
           (int)fd, name, (unsigned long)size);
    return 0;
}
int64_t lucas_sys_getxattr(lucas_state_t *st, uint64_t p, uint64_t n, uint64_t v,
                           uint64_t s, uint64_t a4, uint64_t a5)
{ (void)st;(void)p;(void)n;(void)v;(void)s;(void)a4;(void)a5; return -(int64_t)LX_ENODATA; }
int64_t lucas_sys_listxattr(lucas_state_t *st, uint64_t p, uint64_t l, uint64_t s,
                            uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)p;(void)l;(void)s;(void)a3;(void)a4;(void)a5; return 0; /* no xattrs */ }
int64_t lucas_sys_removexattr(lucas_state_t *st, uint64_t p, uint64_t n, uint64_t a2,
                              uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)p;(void)n;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }

/* Advanced recon / privileged subsystems · capture + EPERM. */
int64_t lucas_sys_bpf(lucas_state_t *st, uint64_t cmd, uint64_t a1, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)st; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    printf("[abi-capture] bpf cmd=%d · -EPERM\n", (int)cmd);
    return -(int64_t)LX_EPERM;
}
int64_t lucas_sys_perf_event_open(lucas_state_t *st, uint64_t a0, uint64_t a1, uint64_t a2,
                                  uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)st; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    printf("[abi-capture] perf_event_open · -EPERM\n");
    return -(int64_t)LX_EPERM;
}
int64_t lucas_sys_keyctl(lucas_state_t *st, uint64_t op, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)st; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    printf("[abi-capture] keyctl op=%d · -EOPNOTSUPP\n", (int)op);
    return -(int64_t)LX_EOPNOTSUPP;
}
int64_t lucas_sys_add_key(lucas_state_t *st, uint64_t a0, uint64_t a1, uint64_t a2,
                          uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5;
  printf("[abi-capture] add_key · -EOPNOTSUPP\n"); return -(int64_t)LX_EOPNOTSUPP; }

/* Host identity / time tampering · capture + EPERM. */
int64_t lucas_sys_sethostname(lucas_state_t *st, uint64_t name_v, uint64_t len,
                              uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)len; (void)a2; (void)a3; (void)a4; (void)a5;
    char name[64]; abi_path(st, name_v, name, sizeof(name));
    printf("[abi-capture] sethostname '%s' · -EPERM\n", name);
    return -(int64_t)LX_EPERM;
}
int64_t lucas_sys_setdomainname(lucas_state_t *st, uint64_t n, uint64_t l, uint64_t a2,
                                uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)n;(void)l;(void)a2;(void)a3;(void)a4;(void)a5;
  printf("[abi-capture] setdomainname · -EPERM\n"); return -(int64_t)LX_EPERM; }
int64_t lucas_sys_reboot(lucas_state_t *st, uint64_t m1, uint64_t m2, uint64_t cmd,
                         uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)st; (void)m1; (void)m2; (void)a3; (void)a4; (void)a5;
    printf("[abi-capture] reboot cmd=0x%x · HOST-REBOOT attempt · -EPERM\n", (unsigned)cmd);
    return -(int64_t)LX_EPERM;
}
int64_t lucas_sys_settimeofday(lucas_state_t *st, uint64_t a0, uint64_t a1, uint64_t a2,
                               uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5;
  printf("[abi-capture] settimeofday · -EPERM\n"); return -(int64_t)LX_EPERM; }
int64_t lucas_sys_clock_settime(lucas_state_t *st, uint64_t a0, uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5;
  printf("[abi-capture] clock_settime · -EPERM\n"); return -(int64_t)LX_EPERM; }
int64_t lucas_sys_adjtimex(lucas_state_t *st, uint64_t a0, uint64_t a1, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5)
{ (void)st;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5;
  printf("[abi-capture] adjtimex · -EPERM\n"); return -(int64_t)LX_EPERM; }
