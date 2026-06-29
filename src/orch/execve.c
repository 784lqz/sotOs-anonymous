/*
 * sotOs · LUCAS L3b · execve() implementation.
 *
 * Replaces the calling sotBox's process image with a new ELF.  Same
 * TCB / CSpace / pid identity · fresh vspace, fresh stack, fresh
 * registers.  On success, does NOT return to the caller (the
 * old instructions no longer exist).  On failure, returns -errno
 * to the caller.
 *
 * For L3b, path resolution is limited: only /bin/busybox and /bin/sh
 * are recognised, both mapping to orch's embedded busybox-static.bin.
 * Other paths return -ENOENT.
 */

#include <orch/sotbox.h>
#include <orch/pipe.h>
#include <orch/proto.h>        /* Spec B · ANOMALY_EV_EXEC */
#include <sotabi/proto.h>      /* sotctl-native arc · SOTABI_OP_* (the native CLI launcher) */
#include <lucas/persona_session.h> /* 2nd-persona · persona-aware apt/apk facades */
#include <lucas/syscalls.h>
#include <lucas/anomaly.h>    /* Spec B · anomaly_forward_sync / apply_reply_tier */
#include <lucas/shellhook.h>   /* PR 10 · execve argv shell-hook rewrite */
#include <lucas/vfs.h>         /* P1b · vfs_resolve for #! maintainer-script exec */
#include <sotos/random.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sel4/sel4.h>
#include <sel4utils/api.h>
#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <vspace/vspace.h>
#include <cpio/cpio.h>
#include <sotfs/binstore.h>    /* SP2-migración · binstore_lookup/read for busybox re-exec */

extern char _cpio_archive[];
extern char _cpio_archive_end[];

/* From lucas static library. */
extern int  create_client_vspace(lucas_state_t *st);
extern int  lucas_stack_setup(lucas_state_t *st, const char *const argv[],
                               const char *const envp[]);
extern bool lucas_elf_validate(const void *elf_bytes, size_t size);
extern int  lucas_elf_load_into_client(lucas_state_t *st, const void *elf_bytes,
                                        size_t elf_size);
extern uint64_t lucas_elf_entry(const void *elf_bytes);
extern int  lucas_copy_cstr_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                         char *buf, size_t buf_size);
extern int  lucas_elf_reload_data(lucas_state_t *st,
                                   const void *elf_bytes, size_t elf_size);
/* WINE-M1 · dynamic-aware loader (PT_INTERP → ld-musl at a PIE base).  Used by
 * the spawn path; execve's full-reload now uses it too so a dynamic PIE target
 * (e.g. wineserver) is loaded WITH its interpreter instead of jumping into an
 * unrelocated entry.  For dynamic binaries it OVERRIDES st->entry_point (→ the
 * ld-musl entry) and st->brk_base (→ above the high load bases). */
extern int  lucas_elf_load_program(lucas_state_t *st, const void *elf_bytes,
                                    unsigned long elf_size);
/* WINE-M1 · true iff the ELF carries a PT_INTERP (needs ld-musl).  Selects the
 * dynamic loader for wineserver while leaving the no-interp wine-preloader on
 * the original static path (which must NOT touch st->is_dynamic). */
extern bool lucas_elf_is_dynamic(const void *elf_bytes);

#define LUCAS_EXEC_ARGV_MAX  16
#define LUCAS_EXEC_ENVP_MAX  16
#define LUCAS_EXEC_PATH_MAX  256

/* Read one 64-bit pointer value from the client's vspace at client_vaddr.
 * Uses the same dup_and_map pattern as lucas_copy_cstr_from_client.
 * Returns 0 on success, -1 on EFAULT. */
static int read_client_ptr(lucas_state_t *st, uintptr_t client_vaddr,
                            uint64_t *out_ptr) {
    uintptr_t page_base  = client_vaddr & ~0xFFFUL;
    size_t    off        = (size_t)(client_vaddr - page_base);

    /* Pointer must not straddle a page boundary (char** entries are 8-byte
     * aligned by the ABI; if they do straddle we return EFAULT). */
    if (off + 8 > 4096) {
        printf("[execve] read_client_ptr: pointer straddles page boundary at 0x%lx\n",
               (unsigned long)client_vaddr);
        return -1;
    }

    seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)page_base);
    if (!frame) {
        printf("[execve] read_client_ptr: no frame at 0x%lx\n",
               (unsigned long)page_base);
        return -1;
    }
    void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                         frame, seL4_PageBits);
    if (!local) {
        printf("[execve] read_client_ptr: dup_and_map failed\n");
        return -1;
    }
    memcpy(out_ptr, (const uint8_t *)local + off, 8);
    sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
    return 0;
}

/* Read a NUL-terminated char* array (char **) from client vspace.
 * array_vaddr is the client-side pointer to the first element (char *).
 * Copies each string into string_pool, fills out_argv with local pointers,
 * sets out_argv[n] = NULL, returns the count n on success, -1 on error. */
static int read_cstr_array_from_client(lucas_state_t *st,
                                        uintptr_t array_vaddr,
                                        char *string_pool, size_t pool_size,
                                        const char *out_argv[], int max_count) {
    size_t pool_used = 0;
    int n = 0;

    for (int i = 0; i < max_count; ++i) {
        /* Read the i-th pointer (char *) from the array. */
        uint64_t ptr_val = 0;
        if (read_client_ptr(st, array_vaddr + (uintptr_t)(i * 8), &ptr_val) < 0)
            return -1;

        if (ptr_val == 0) {
            /* NULL terminator of the array. */
            out_argv[n] = NULL;
            return n;
        }

        /* Copy the string at ptr_val into the pool. */
        if (pool_used >= pool_size - 1) {
            printf("[execve] read_cstr_array: pool exhausted at entry %d\n", i);
            return -1;
        }
        char *dst = string_pool + pool_used;
        int slen = lucas_copy_cstr_from_client(st, (uintptr_t)ptr_val,
                                                dst, pool_size - pool_used);
        if (slen < 0) {
            printf("[execve] read_cstr_array: copy_cstr failed at entry %d\n", i);
            return -1;
        }
        out_argv[n] = dst;
        pool_used += (size_t)slen + 1;
        ++n;
    }

    /* Exceeded max_count. */
    printf("[execve] read_cstr_array: exceeded max_count=%d\n", max_count);
    return -1;
}

/* Resolve a path to an ELF image in orch's embedded CPIO archive.
 *
 * L3b-T6: all common busybox applet paths in /bin and /usr/bin map to
 * busybox-static.bin.  Busybox dispatches to the correct applet via argv[0].
 * The list below covers what busybox sh uses for the pipeline demo. */
static bool path_is_busybox_applet(const char *path) {
    /* busybox-static is the single multi-call binary; EVERY executable under
     * the standard bin dirs resolves to it (it dispatches to the right applet
     * via argv[0]). A broad prefix match (vs the old hardcoded strcmp list)
     * means bare recon commands — `uname`/`id`/`whoami`/`ps`/`hostname`/… — work
     * over the canary shell the moment a /bin/<applet> stub exists in the VFS.
     * If a path names a non-applet, busybox itself prints "applet not found"
     * (realistic), so the broad match is safe. The static-VFS PATH-search only
     * resolves stubs that actually exist, so non-stub names never reach here. */
    return strncmp(path, "/bin/", 5)      == 0 ||
           strncmp(path, "/usr/bin/", 9)  == 0 ||
           strncmp(path, "/sbin/", 6)     == 0 ||
           strncmp(path, "/usr/sbin/", 10) == 0;
}

/* apk-fs Phase 3 · read an ELF at an absolute path through the VFS mount table.
 * resolve_path's final fallback (after binstore + busybox-applet miss) so a
 * binary WRITTEN into the per-session sotfs upper this session — apk's
 * /usr/bin/<pkg> — becomes executable.  vfs_resolve longest-prefix-routes /usr/*
 * to the session-gated /usr union (upper→sysroot→static); we stat the size,
 * stage it, and read it whole.  lucas_set_current_caller(st) is REQUIRED so the
 * union's upper layer is visible to st->cow_session (Phase-2 visibility gate) —
 * the operator (cow_session 0) never resolves a session's upper binary (I1).
 * Returns staged bytes or NULL (caller proceeds to its applet/ENOENT handling). */
extern void lucas_set_current_caller(lucas_state_t *st);
/* A binary larger than this is bounced to a heavy (256 MiB) arena · the 32 MiB
 * regular arena can't hold a multi-MiB image + a Go/runtime heap (see the
 * HEAVY-EXEC RESPAWN intercept below).  8 MiB clears the editors (less/nano/vim ·
 * ~MB) + git + bash and only catches genuinely large tools (micro is ~13 MB). */
#define LUCAS_HEAVY_EXEC_MIN (8u * 1024u * 1024u)

static const void *resolve_path_vfs(lucas_state_t *st, const char *path,
                                    unsigned long *out_size) {
    extern void *orch_spawn_stage(size_t bytes);
    const char *suffix = NULL;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m || !m->ops || !m->ops->open || !m->ops->read || !m->ops->stat)
        return NULL;

    lucas_set_current_caller(st);   /* session-visible upper for stat+read */

    struct lx_stat sb; memset(&sb, 0, sizeof(sb));
    if (m->ops->stat(m->backend_state, suffix, &sb) != 0 || sb.st_size <= 0) {
        lucas_set_current_caller(NULL); return NULL;
    }
    size_t want = (size_t)sb.st_size;
    void *buf = orch_spawn_stage(want);
    if (!buf) { lucas_set_current_caller(NULL); return NULL; }

    void *h = NULL;
    if (m->ops->open(m->backend_state, suffix, 0 /*O_RDONLY*/, 0, &h) != 0) {
        lucas_set_current_caller(NULL); return NULL;
    }
    size_t got = 0;
    while (got < want) {
        int64_t n = m->ops->read(m->backend_state, h, (uint8_t *)buf + got,
                                 want - got, (int64_t)got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    if (m->ops->close) m->ops->close(m->backend_state, h);
    lucas_set_current_caller(NULL);

    if (got != want)
        return NULL;   /* short read = not a full ELF in the upper (e.g. an applet
                        * stub) → caller falls through to busybox.  No log: this is
                        * the EXPECTED common path for every applet exec. */
    *out_size = (unsigned long)want;
    printf("[execve] '%s' → VFS upper · %zu bytes\n", path, want);
    /* NB: buf is the shared orch_spawn_stage buffer — valid only until the next
     * orch_spawn_stage call.  The loader maps the main image before re-staging
     * the interpreter, so elf_bytes stays intact across the load (same invariant
     * the binstore path relies on). */
    return buf;
}

static int execve_caller_is_debian(lucas_state_t *st);  /* fwd · persona gate (apk deny) */

static const void *resolve_path(lucas_state_t *st, const char *path, unsigned long *out_size) {
    extern void *orch_spawn_stage(size_t bytes);

    /* basename of the path */
    const char *base = path;
    for (const char *p = path; *p; ++p) if (*p == '/') base = p + 1;

    /* binstore-shadowing fix (apk-network-install) · an apk-installed binary at
     * the EXACT path in the per-session upper (a real ELF the session itself
     * wrote — e.g. /usr/bin/nano, 295 KB) must run AS ITSELF, not be shadowed by
     * a binstore applet of the same basename.  The binstore lookup below keys on
     * the BASENAME, so `nano`/`vim`/`less` would otherwise always run the binstore
     * build even after `apk add` installed a real one into the session upper.  Try
     * the VFS upper for the full path FIRST — but ONLY for an interactive SSH
     * session (cow_session != 0) and NOT the busybox-static.bin re-exec, so the
     * boot/operator/trusted exec order is unchanged.  resolve_path_vfs short-reads
     * (→ NULL) on an applet stub or a missing path, so a session running a normal
     * binstore binary or a busybox applet still falls through to the lookups
     * below.  (The unconditional resolve_path_vfs at the end stays as the
     * non-session / fallthrough path.) */
    if (st && st->cow_session != 0 && strcmp(base, "busybox-static.bin") != 0) {
        const void *sess = resolve_path_vfs(st, path, out_size);
        if (sess) return sess;
    }

    /* 2nd-persona (Debian 13) · GNU coreutils coherence: a Debian session's
     * ls/cat/id/wc/tail/… are the REAL Debian glibc GNU binaries (coreutils 9.7 ·
     * ld-linux), not busybox — so `ls --version` says "GNU coreutils 9.7", not
     * "BusyBox v1.36" (the deepest distro tell).  If the basename is a GNU coreutil
     * we stage, resolve to its `debian-<name>` binary BEFORE the busybox fallback.
     * Only for Debian sessions — Alpine keeps busybox (musl-coherent). */
    if (execve_caller_is_debian(st)) {
        /* The staged GNU set · the full Debian-13 coreutils surface (read tools +
         * file-mutating tools) + GNU grep, each mapping to debian-<name>.  Enabled
         * by the binstore region bump (layout.h 56->60 MiB · 80 entries packed). */
        static const char *const cu[] = {
            "ls","cat","head","tail","uname","sort","env","date","wc","id","whoami",
            "du","stat","tr","cut","nl","tac","tee","basename","dirname",
            "realpath","readlink","sleep","seq","grep",
            "mkdir","touch","rm","cp","mv","ln","chmod", NULL };
        int is_cu = 0;
        for (int i = 0; cu[i]; ++i) if (strcmp(base, cu[i]) == 0) { is_cu = 1; break; }
        if (is_cu) {
            char gname[64];
            snprintf(gname, sizeof(gname), "debian-%s", base);
            uint64_t goff = 0;
            long gsz = binstore_lookup(gname, &goff);
            if (gsz > 0) {
                void *buf = orch_spawn_stage((size_t)gsz);
                if (buf) {
                    long n = binstore_read(gname, buf, (size_t)gsz);
                    if (n == gsz) {
                        *out_size = (unsigned long)n;
                        printf("[execve] '%s' → Debian GNU '%s' · %ld bytes\n", path, gname, n);
                        return buf;
                    }
                    printf("[execve] GNU '%s' short read %ld/%ld · falling back\n", gname, n, gsz);
                }
            }
        }
    }

    /* Wine M1 · real binstore binaries must load as THEMSELVES, not fall back to
     * busybox.  The wine loader re-execs `/bin/wine-preloader` (the static low-
     * range reserver), which re-execs the wine loader again — both must resolve
     * to the real ELF.  Look the basename up in the binstore FIRST; busybox
     * applets (ls/cat/sh/…) are not binstore entries so they fall through to the
     * applet path below unchanged.  Exclude busybox itself (its own staged load
     * + in-place-restart cache live below). */
    if (strcmp(base, "busybox-static.bin") != 0) {
        uint64_t off = 0;
        long sz = binstore_lookup(base, &off);
        if (sz > 0) {
            void *buf = orch_spawn_stage((size_t)sz);
            if (buf) {
                long n = binstore_read(base, buf, (size_t)sz);
                if (n == sz) {
                    *out_size = (unsigned long)n;
                    printf("[execve] '%s' → binstore '%s' · %ld bytes\n", path, base, n);
                    return buf;
                }
                printf("[execve] binstore '%s' short read %ld/%ld\n", base, n, sz);
            }
        }
        /* apk-local-install · basename alias: /sbin/apk (base="apk") → binstore
         * entry "apk.static" (the real Alpine 3.20 static-musl binary).
         * Mirrors the busybox-static.bin staging pattern above. */
        if (strcmp(base, "apk") == 0 && !execve_caller_is_debian(st)) {
            uint64_t apk_off = 0;
            long apk_sz = binstore_lookup("apk.static", &apk_off);
            if (apk_sz > 0) {
                void *buf = orch_spawn_stage((size_t)apk_sz);
                if (buf) {
                    long n = binstore_read("apk.static", buf, (size_t)apk_sz);
                    if (n == apk_sz) {
                        *out_size = (unsigned long)n;
                        printf("[execve] '%s' → binstore 'apk.static' · %ld bytes\n", path, n);
                        return buf;
                    }
                    printf("[execve] binstore 'apk.static' short read %ld/%ld\n", n, apk_sz);
                }
            }
        }
    }

    /* apk-fs Phase 3 · a binary written into THIS session's sotfs upper (apk's
     * /usr/bin/<pkg>) must be executable.  Try the VFS upper before the busybox
     * multi-call fallback: a real ELF at /usr/bin/<pkg> (size>0) loads as itself;
     * an applet stub falls through to busybox (it is not a full ELF in the upper,
     * so the read is short → NULL).  Non-applet paths that miss the upper return
     * NULL (caller then tries the shebang / ENOENT). */
    const void *up = resolve_path_vfs(st, path, out_size);
    if (up) return up;

    if (!path_is_busybox_applet(path)) {
        printf("[execve] '%s' not a known busybox applet path\n", path);
        return NULL;
    }
    /* SP2-migración · busybox-static.bin moved CPIO->binstore.  This execve
     * re-exec path is a fourth CPIO-direct fetch the migration spec did not
     * enumerate (alongside sto/SPAWN_NATIVE); route it binstore-first, then
     * CPIO fallback, mirroring spawn_load_elf.  busybox (1.1 MB) is read into
     * the on-demand staging region (orch_spawn_stage · reused, sequential). */
    extern void *orch_spawn_stage(size_t bytes);
    uint64_t bs_off = 0;
    long bs_size = binstore_lookup("busybox-static.bin", &bs_off);
    if (bs_size > 0) {
        void *buf = orch_spawn_stage((size_t)bs_size);
        if (buf) {
            long bn = binstore_read("busybox-static.bin", buf, (size_t)bs_size);
            if (bn == bs_size) {
                *out_size = (unsigned long)bn;
                printf("[spawn] load 'busybox-static.bin' · source=binstore · %ld bytes\n", bn);
                return buf;
            }
            printf("[execve] busybox-static.bin · binstore short read %ld/%ld\n", bn, bs_size);
        }
    }
    unsigned long cpio_size = (unsigned long)(_cpio_archive_end - _cpio_archive);
    return cpio_get_file(_cpio_archive, cpio_size, "busybox-static.bin", out_size);
}

/* Track whether the primary sotBox (slot 0) has been loaded with busybox.
 * When a child calls execve for the same binary, we can reuse the existing
 * vspace's TEXT segment (identical) and only reload DATA + new stack.
 *
 * L3b-T6: "in-place restart" optimisation.
 * Since all busybox applets are the same binary (same ELF), execve in
 * a child (post-fork) can avoid allocating a new vspace.  Instead we:
 *   1. Reload only the DATA PT_LOAD segment over existing pages.
 *   2. Allocate a new stack.
 *   3. Reset entry_point + brk.
 * This saves ~512 frame allocations per execve (no new vspace = no new
 * bookkeeping frames + no new ELF load frames for TEXT). */

/* The ELF bytes pointer (in CPIO, read-only) stays valid across execves. */
static const void *g_busybox_elf = NULL;
static unsigned long g_busybox_elf_size = 0;

extern int lucas_elf_reload_data(lucas_state_t *st,
                                  const void *elf_bytes, size_t elf_size);
extern uint64_t lucas_elf_load_end(const void *elf_bytes);

/* Sentinel: `path` is not a #! script (caller proceeds to its normal ENOENT). */
#define SHEBANG_NOT_A_SCRIPT  0x7fffffffffffffffLL

/* P1b · binfmt_script.  Real dpkg runs maintainer scripts (postinst/prerm/…) via
 * execvp(scriptpath) and relies on the kernel reading "#!/bin/sh" and re-exec'ing
 * the interpreter.  resolve_path only knows binstore binaries + busybox applets,
 * so a script path returns NULL; here, when that happens, peek the VFS file's
 * first line and — if it is a shebang — re-exec the interpreter with the script
 * path inserted as argv[1] (the interpreter, busybox sh, then opens + runs it).
 * Returns the recursive execve result, or SHEBANG_NOT_A_SCRIPT if `path` is
 * absent / not a shebang. */
int64_t sotbox_execve(lucas_state_t *st, const char *path,
                      const char *const argv[], const char *const envp[]);
static int64_t execve_try_shebang(lucas_state_t *st, const char *path,
                                  const char *const argv[], const char *const envp[]) {
    const char *suffix = NULL;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m || !m->ops || !m->ops->open) return SHEBANG_NOT_A_SCRIPT;
    void *h = NULL;
    if (m->ops->open(m->backend_state, suffix, 0 /*O_RDONLY*/, 0, &h) != 0)
        return SHEBANG_NOT_A_SCRIPT;
    char line[160];
    int64_t n = m->ops->read ? m->ops->read(m->backend_state, h, line, sizeof(line) - 1, 0) : -1;
    if (m->ops->close) m->ops->close(m->backend_state, h);
    if (n < 2 || line[0] != '#' || line[1] != '!') return SHEBANG_NOT_A_SCRIPT;
    line[n] = '\0';

    /* Parse "#! <interp> [<arg>]\n".  binfmt_script collapses everything after the
     * interpreter into ONE optional argument; keep that simple shape. */
    char *p = line + 2;
    while (*p == ' ' || *p == '\t') p++;
    char *interp = p;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
    char interp_arg[128]; interp_arg[0] = '\0';
    if (*p && *p != '\n') {
        *p++ = '\0';
        while (*p == ' ' || *p == '\t') p++;
        char *a = p;
        while (*p && *p != '\n') p++;
        *p = '\0';
        if (*a) { strncpy(interp_arg, a, sizeof(interp_arg) - 1); interp_arg[sizeof(interp_arg) - 1] = '\0'; }
    } else {
        *p = '\0';
    }
    if (interp[0] == '\0') return SHEBANG_NOT_A_SCRIPT;

    /* New argv: [interp, (interp_arg,) scriptpath, original argv[1..]]. */
    const char *newargv[40];
    int ai = 0;
    newargv[ai++] = interp;
    if (interp_arg[0]) newargv[ai++] = interp_arg;
    newargv[ai++] = path;
    if (argv) for (int i = 1; argv[i] && ai < 38; i++) newargv[ai++] = argv[i];
    newargv[ai] = NULL;
    printf("[execve] pid=%d shebang '%s' → interp '%s' %s\n",
           st->synthetic_pid, path, interp, interp_arg);
    return sotbox_execve(st, interp, newargv, envp);
}

/* ---- pip deception facade (Tier-2 canary) ----------------------------------
 * Emit a believable `pip install` transcript to the attacker's stdout with no
 * real network and no install.  Kills the 'pip: not found' / no-egress tell;
 * the attacker sees a clean success.  Transcript-deep by design (a later
 * `import` would fail) — see docs/superpowers + the AskUserQuestion decision. */
extern void lucas_console_emit_kstr(lucas_state_t *st, const char *s);

/* case-insensitive ASCII compare (no strcasecmp dependency in orch). */
static int pip_cieq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
    }
    return *a == *b;
}

/* Extract a bare package name from a requirement token: copy [A-Za-z0-9._-],
 * stopping at a version specifier ('=' '<' '>' '!' '~') or end.  Caps at n. */
static const char *pip_pkgname(const char *in, char *out, size_t n) {
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 1 < n; i++) {
        char c = in[i];
        if (c=='='||c=='<'||c=='>'||c=='!'||c=='~') break;
        if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-')
            out[j++] = c;
    }
    out[j] = '\0';
    return out;
}

/* Plausible version for a well-known package; generic fallback otherwise. */
static const char *pip_version_for(const char *pkg) {
    static const struct { const char *n, *v; } K[] = {
        {"requests","2.32.3"}, {"urllib3","2.2.2"}, {"idna","3.7"},
        {"certifi","2024.7.4"}, {"charset-normalizer","3.3.2"},
        {"numpy","2.0.1"}, {"flask","3.0.3"}, {"django","5.0.7"},
        {"six","1.16.0"}, {"pyyaml","6.0.1"}, {"boto3","1.34.144"},
        {"pandas","2.2.2"}, {"scapy","2.5.0"}, {"paramiko","3.4.0"},
        {"cryptography","42.0.8"}, {"pillow","10.4.0"}, {"setuptools","70.3.0"},
        {"wheel","0.43.0"}, {"beautifulsoup4","4.12.3"}, {"lxml","5.2.2"},
    };
    for (size_t i = 0; i < sizeof(K)/sizeof(K[0]); i++)
        if (pip_cieq(pkg, K[i].n)) return K[i].v;
    return "1.0.0";
}

/* Emit the synthetic transcript over a fixed stack buffer (no orch heap). */
static void execve_pip_facade(lucas_state_t *st, const char *const argv[]) {
    /* Scan args: detect --version, find the subcommand, collect packages.
     * Skip flags and the value of value-taking flags (-r/-t/-i/-c/--target…). */
    int want_version = 0;
    const char *sub = NULL;
    char pkgs[12][64];
    int  npkg = 0;
    for (int i = 1; argv && argv[i] && npkg < 12; i++) {
        const char *a = argv[i];
        if (pip_cieq(a, "--version") || (a[0]=='-' && a[1]=='V' && a[2]=='\0')) { want_version = 1; continue; }
        if (a[0] == '-') {
            /* swallow the value of value-taking flags so it isn't seen as a pkg */
            if (pip_cieq(a,"-r")||pip_cieq(a,"--requirement")||pip_cieq(a,"-t")||
                pip_cieq(a,"--target")||pip_cieq(a,"-i")||pip_cieq(a,"--index-url")||
                pip_cieq(a,"-c")||pip_cieq(a,"--constraint")) { if (argv[i+1]) i++; }
            continue;
        }
        if (!sub) { sub = a; continue; }
        pip_pkgname(a, pkgs[npkg], sizeof(pkgs[0]));
        if (pkgs[npkg][0]) npkg++;
    }

    if (want_version) {
        lucas_console_emit_kstr(st,
            "pip 24.0 from /usr/lib/python3.12/site-packages/pip (python 3.12)\n");
        return;
    }
    if (!sub) {  /* bare `pip` → terse usage (matches real pip's no-command output) */
        lucas_console_emit_kstr(st,
            "\nUsage:   \n  pip <command> [options]\n\n"
            "You must give a command (use \"pip --help\" to see a list of commands).\n");
        return;
    }
    if (!pip_cieq(sub, "install")) {  /* list/show/freeze/uninstall… → believable no-op */
        if (pip_cieq(sub, "list") || pip_cieq(sub, "freeze"))
            lucas_console_emit_kstr(st, "pip 24.0\nsetuptools 70.3.0\nwheel 0.43.0\n");
        else
            lucas_console_emit_kstr(st, "");
        return;
    }
    if (npkg == 0) {
        lucas_console_emit_kstr(st,
            "ERROR: You must give at least one requirement to install (see \"pip help install\")\n");
        return;
    }

    /* install transcript · Collecting/Downloading per package, then the summary. */
    char line[256];
    for (int i = 0; i < npkg; i++) {
        const char *v = pip_version_for(pkgs[i]);
        /* size: deterministic-ish from name length, in kB (12–220). */
        unsigned kb = 12 + (unsigned)((pkgs[i][0] * 7u + (i + 1) * 53u) % 210u);
        snprintf(line, sizeof(line), "Collecting %s\n", pkgs[i]);
        lucas_console_emit_kstr(st, line);
        snprintf(line, sizeof(line),
            "  Downloading %s-%s-py3-none-any.whl (%u kB)\n", pkgs[i], v, kb);
        lucas_console_emit_kstr(st, line);
    }
    /* "Installing collected packages: a, b, c" */
    lucas_console_emit_kstr(st, "Installing collected packages: ");
    for (int i = 0; i < npkg; i++) {
        lucas_console_emit_kstr(st, pkgs[i]);
        if (i + 1 < npkg) lucas_console_emit_kstr(st, ", ");
    }
    lucas_console_emit_kstr(st, "\n");
    /* "Successfully installed a-1 b-2 c-3" */
    lucas_console_emit_kstr(st, "Successfully installed");
    for (int i = 0; i < npkg; i++) {
        snprintf(line, sizeof(line), " %s-%s", pkgs[i], pip_version_for(pkgs[i]));
        lucas_console_emit_kstr(st, line);
    }
    lucas_console_emit_kstr(st, "\n");
}

/* True iff the calling SSH session wears the Ubuntu persona (per its M3 ctx). */
static int execve_caller_is_debian(lucas_state_t *st) {
    extern int lucas_persona_session_get(uint32_t, lucas_persona_t *);
    lucas_persona_t pc;
    return st && st->cow_session != 0 &&
           lucas_persona_session_get(st->cow_session, &pc) &&
           pc.profile == LUCAS_PERSONA_DEBIAN;
}

/*
 * dpkg facade (2nd-persona · Debian) — a believable Debian dpkg for the Tier-2
 * canary.  A real Debian box has dpkg; the recon checks are `dpkg -l` (what's
 * installed) and `dpkg --version`.  Synthetic + coherent with the prod-app-server
 * persona (nginx/postgresql/openssh).  Only fires for a Debian-persona session;
 * the operator/compat dpkg -i path (cow_session 0) still runs the REAL dpkg.
 */
static void execve_dpkg_facade(lucas_state_t *st, const char *const argv[]) {
    /* find the first non-flag-ish action.  dpkg's actions are -l/-L/-s/-i/-r and
     * the long --list/--status/--install/--version/--print-architecture. */
    int want_version = 0, want_list = 0, want_arch = 0, want_foreign_arch = 0;
    const char *qpkg = NULL, *status_pkg = NULL;
    for (int i = 1; argv && argv[i]; ++i) {
        const char *a = argv[i];
        /* dpkg --assert-<feature> · apt probes dpkg's capabilities (multi-arch,
         * protected-field, working-epoch, …) before an install.  REAL dpkg exits
         * 0 SILENTLY when the feature is supported (it is, in 1.22).  The old
         * facade fell through to the "need an action option" usage line + exit 0;
         * apt's AssertFeature only checks the exit code so that was 'supported',
         * but the spurious stderr is a tell.  Recognise + succeed silently. */
        if (!strncmp(a, "--assert-", 9)) return;
        if (!strcmp(a, "--version")) { want_version = 1; }
        else if (!strcmp(a, "-l") || !strcmp(a, "--list")) { want_list = 1; if (argv[i+1] && argv[i+1][0] != '-') qpkg = argv[++i]; }
        else if (!strcmp(a, "--print-architecture")) { want_arch = 1; }
        else if (!strcmp(a, "--print-foreign-architectures")) { want_foreign_arch = 1; }
        else if (!strcmp(a, "-s") || !strcmp(a, "--status")) { if (argv[i+1]) status_pkg = argv[++i]; }
    }
    char line[256];
    /* apt-get update probes the dpkg arch set early.  A vanilla single-arch
     * Debian box has NO foreign architectures configured → dpkg prints nothing
     * and exits 0.  Without this, the facade fell through to the "need an action
     * option" usage line, which apt treated as a fatal dpkg error and aborted
     * the whole update.  Print an empty list (success). */
    if (want_foreign_arch) { return; }
    if (want_version) {
        lucas_console_emit_kstr(st,
            "Debian 'dpkg' package management program version 1.22.21 (amd64).\n"
            "This is free software; see the GNU General Public License version 2 or\n"
            "later for copying conditions. There is NO warranty.\n");
        return;
    }
    if (want_arch) { lucas_console_emit_kstr(st, "amd64\n"); return; }
    if (status_pkg) {
        snprintf(line, sizeof(line),
            "Package: %s\nStatus: install ok installed\nPriority: optional\n"
            "Architecture: amd64\nVersion: 1.0\n", status_pkg);
        lucas_console_emit_kstr(st, line);
        return;
    }
    if (want_list) {
        lucas_console_emit_kstr(st,
            "Desired=Unknown/Install/Remove/Purge/Hold\n"
            "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
            "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
            "||/ Name                     Version            Architecture Description\n"
            "+++-========================-==================-============-=========================================\n"
            "ii  apt                      2.9.18             amd64        commandline package manager\n"
            "ii  bash                     5.2.21-2.1         amd64        GNU Bourne Again SHell\n"
            "ii  coreutils                9.7-3              amd64        GNU core utilities\n"
            "ii  dpkg                     1.22.21            amd64        Debian package management system\n"
            "ii  libc6:amd64              2.41-12            amd64        GNU C Library: Shared libraries\n"
            "ii  nginx                    1.26.0-2           amd64        small, powerful, scalable web/proxy server\n"
            "ii  openssh-server           1:9.9p1-3          amd64        secure shell (SSH) server\n"
            "ii  postgresql-16            16.4-1             amd64        object-relational SQL database\n"
            "ii  python3                  3.12.6-1           amd64        interactive high-level object-oriented language\n"
            "ii  sudo                     1.9.15p5-3         amd64        Provide limited super user privileges\n");
        return;
    }
    /* -i / -r / bare → dpkg's terse usage line (a recon `dpkg` with no args). */
    lucas_console_emit_kstr(st,
        "dpkg: error: need an action option\n"
        "\nType dpkg --help for help about installing and deinstalling packages [*];\n");
}

/*
 * sotbox_execve — core implementation called from lucas_sys_execve.
 *
 * path, argv, envp are LOCAL (orch-side) pointers — the handler has
 * already copied them from the client's vspace.
 *
 * Returns LUCAS_EXEC_REPLY_RAW on success (fault loop sends Reply but
 * does NOT write rax/rip — the fresh registers are already installed).
 * Returns -errno on failure (caller is expected to resume the client
 * with a normal error return).
 *
 * L3b-T6 optimisation: if the target is busybox and current vspace already
 * has busybox loaded, skip create_client_vspace + ELF TEXT reload.  Only
 * reload DATA segment and set up new stack.  Saves ~512 frame objects.
 */
int64_t sotbox_execve(lucas_state_t *st, const char *path,
                       const char *const argv[], const char *const envp[]) {
    /* M2 · 'doom' launcher. Typing `doom` in the interactive terminal execs the
     * /bin/doom stub; intercept it (isolated — no real command is "doom"): flag
     * orch to spawn the real Doom (serviced by the same fault loop) and cleanly
     * exit THIS exec'd box via the normal exit path. The live busybox shell
     * stays (it reaps this child); Doom plays, then back to the shell. */
    {
        const char *base = path;
        for (const char *p = path; *p; ++p) if (*p == '/') base = p + 1;
        if (strcmp(base, "doom") == 0) {
            extern int g_doom_request;
            extern int64_t lucas_sys_exit_group(lucas_state_t*, uint64_t, uint64_t,
                                                uint64_t, uint64_t, uint64_t, uint64_t);
            printf("[execve] pid=%d · 'doom' → request orch Doom spawn + exit\n", st->synthetic_pid);
            g_doom_request = 1;
            return lucas_sys_exit_group(st, 0, 0, 0, 0, 0, 0);
        }
        /* sotctl · the operator's NATIVE control CLI (libsot over truth-core ·
         * NOT /proc).  ONLY the trusted operator shell (st->trusted) may run it —
         * /usr/bin/sotctl is persona-hidden from the attacker, so this never fires
         * in a honey session (a real Alpine has no `sotctl`).  Slice 3: this is now
         * an isolated LAUNCHER (like doom/python) — it selects the op from the
         * subcommand, flags g_sotctl_request, and exits THIS child.  The orch fault
         * loop then spawns the NATIVE sotctl binary (a real seL4 sotbox) which pulls
         * the rendered truth-plane back over sotabi IPC and prints it.  No more
         * in-orch formatting: the operator-facing process is the native binary. */
        if (strcmp(base, "sotctl") == 0 && st->trusted) {
            extern int      g_sotctl_request;
            extern int      g_sotctl_op;
            extern uint32_t g_sotctl_arg;
            extern int64_t lucas_sys_exit_group(lucas_state_t*, uint64_t, uint64_t,
                                                uint64_t, uint64_t, uint64_t, uint64_t);
            const char *sub = (argv && argv[1]) ? argv[1] : "sessions";
            int op = SOTABI_OP_SESSIONS;
            uint32_t arg = 0;
            if (strcmp(sub, "sessions") == 0)                                op = SOTABI_OP_SESSIONS;
            else if (strcmp(sub, "process") == 0 || strcmp(sub, "ps") == 0)  op = SOTABI_OP_PROCESS;
            else if (strcmp(sub, "overlay") == 0) {
                op = SOTABI_OP_OVERLAY;
                for (int i = 2; argv && argv[i]; ++i)
                    if (strcmp(argv[i], "--session") == 0 && argv[i + 1]) {
                        arg = 0;
                        for (const char *c = argv[i + 1]; *c >= '0' && *c <= '9'; ++c)
                            arg = arg * 10 + (uint32_t)(*c - '0');
                    }
            }
            else if (strcmp(sub, "anomaly") == 0)                            op = SOTABI_OP_ANOMALY;
            else if (strcmp(sub, "trace") == 0)                              op = SOTABI_OP_TRACE;
            else if (strcmp(sub, "wal") == 0)                                op = SOTABI_OP_WAL;
            else if (strcmp(sub, "reap") == 0) {     /* CONTROL · reap <session> */
                op = SOTABI_OP_REAP;
                if (argv && argv[2])                 /* the session id operand */
                    for (const char *c = argv[2]; *c >= '0' && *c <= '9'; ++c)
                        arg = arg * 10 + (uint32_t)(*c - '0');
            }
            else if (strcmp(sub, "policy") == 0 && argv && argv[2] &&
                     strcmp(argv[2], "net") == 0) {  /* CONTROL · policy net on|off */
                op = SOTABI_OP_POLICY_NET;
                arg = 2;                             /* default: query (no arg) */
                if (argv[3]) {
                    if (strcmp(argv[3], "on") == 0)  arg = 1;
                    else if (strcmp(argv[3], "off") == 0) arg = 0;
                }
            }
            else if (strcmp(sub, "promote") == 0 || strcmp(sub, "quarantine") == 0) {
                op = (strcmp(sub, "quarantine") == 0) ? SOTABI_OP_QUARANTINE
                                                      : SOTABI_OP_PROMOTE;
                if (argv && argv[2])                 /* the display-pid operand */
                    for (const char *c = argv[2]; *c >= '0' && *c <= '9'; ++c)
                        arg = arg * 10 + (uint32_t)(*c - '0');
            }
            else if (strcmp(sub, "replay-export") == 0 || strcmp(sub, "replay") == 0)
                                                                             op = SOTABI_OP_REPLAY;
            else if (strcmp(sub, "canary") == 0)                             op = SOTABI_OP_CANARY;
            else if (strcmp(sub, "persona") == 0) {  /* list | set <alpine|debian|auto> */
                op = SOTABI_OP_PERSONA;
                arg = 3;                             /* default: list */
                if (argv && argv[2] && strcmp(argv[2], "set") == 0 && argv[3]) {
                    if (strcmp(argv[3], "alpine") == 0)      arg = 0;
                    else if (strcmp(argv[3], "debian") == 0) arg = 1;
                    else if (strcmp(argv[3], "auto") == 0)   arg = 2;
                }
            }
            else                                                             op = SOTABI_OP_HELP;
            printf("[sotctl] operator · `sotctl %s` → spawn NATIVE sotctl (op=%d · sotabi)\n",
                   sub, op);
            g_sotctl_op = op;
            g_sotctl_arg = arg;
            g_sotctl_request = 1;
            return lucas_sys_exit_group(st, 0, 0, 0, 0, 0, 0);
        }
        /* DECEPTION · `python`/`python3` → real CPython, contained. Same isolated
         * launcher as doom: record the attacker's argv, flag orch to spawn
         * python3.12-static into a fresh HEAVY arena (>16 MiB → heavy; the regular
         * arena is too small), and exit THIS child. The python box prints to the
         * console (serial → the live window) so the attacker sees the output. A
         * fork-child execve can't swap its own arena (TCB/CNode live in the regular
         * arena), so the doom-style fresh-box spawn is the clean path. */
        if (strcmp(base, "python") == 0 || strcmp(base, "python3") == 0 ||
            strcmp(base, "python3.12") == 0 || strcmp(base, "python2") == 0) {
            extern int  g_python_request;
            extern void orch_record_python_argv(const char *const argv[]);
            extern int64_t lucas_sys_exit_group(lucas_state_t*, uint64_t, uint64_t,
                                                uint64_t, uint64_t, uint64_t, uint64_t);
            printf("[execve] pid=%d · 'python' → request orch CPython spawn + exit\n", st->synthetic_pid);
            orch_record_python_argv(argv);
            g_python_request = 1;
            return lucas_sys_exit_group(st, 0, 0, 0, 0, 0, 0);
        }
        /* `pip`/`pip3` · two faces.
         *  • In the OPERATOR trusted-egress shell (`shell --trusted`,
         *    g_shell_trusted_egress) → run REAL pip: rewrite to
         *    `python3 -m pip <args>` and take the same CPython spawn path as
         *    above (the python child inherits Tier-0e, so it reaches PyPI).
         *  • In the Tier-2 canary (attacker) → emit a believable synthetic pip
         *    install transcript to the attacker's stdout and exit 0.  No real
         *    egress, no `pip: not found` / ENOSYS tell.  See execve_pip_facade. */
        if (strcmp(base, "pip") == 0 || strcmp(base, "pip3") == 0) {
            extern int  g_shell_trusted_egress;
            extern int  g_python_request;
            extern void orch_record_python_argv(const char *const argv[]);
            extern int64_t lucas_sys_exit_group(lucas_state_t*, uint64_t, uint64_t,
                                                uint64_t, uint64_t, uint64_t, uint64_t);
            if (g_shell_trusted_egress) {
                const char *pyargv[18];
                int n = 0;
                pyargv[n++] = "python3";
                pyargv[n++] = "-m";
                pyargv[n++] = "pip";
                if (argv) for (int i = 1; argv[i] && n < 16; i++) pyargv[n++] = argv[i];
                pyargv[n] = NULL;
                printf("[execve] pid=%d · 'pip' (trusted) → real python3 -m pip\n", st->synthetic_pid);
                orch_record_python_argv(pyargv);
                g_python_request = 1;
                return lucas_sys_exit_group(st, 0, 0, 0, 0, 0, 0);
            }
            execve_pip_facade(st, argv);   /* deception · synthetic transcript */
            return lucas_sys_exit_group(st, 0, 0, 0, 0, 0, 0);
        }
        /* 2nd-persona · `apt`/`apt-get`/`apt-cache` is the Debian package manager.
         * The synthetic facade was RETIRED — apt now resolves to the REAL apt
         * binary by basename via the binstore (resolve_path), the same path dpkg -i
         * uses.  On Alpine apt is absent (no stub in canary_entries) → ENOENT
         * (`apt: not found`), exactly as a real Alpine box.  (The inverse — `apk`
         * on a Debian session — is denied in resolve_path below.) */
        /* 2nd-persona · `dpkg` is Debian's low-level package tool.  A Debian session
         * serves the dpkg facade (`dpkg -l`/`--version` recon); on Alpine dpkg is
         * absent (no stub in canary_entries → command not found).  The operator/
         * compat `dpkg -i` path (cow_session 0) is NOT a Debian persona, so it falls
         * through to the REAL dpkg below (the install-arc is unaffected). */
        /* apt arc P1 T4 · the Debian attacker's apt is a heavy glibc-C++ binary
         * that exhausts a forked Tier-2 arena's 8192 cslots at DynamicMMap time.
         * Route it through the doom/python isolated heavy-arena launcher (32768
         * cslots): record argv + the originating session, flag orch, exit THIS
         * child; orch_spawn_apt_pool spawns the real apt into a fresh heavy arena
         * carrying this session's cow_session (contained).  Only fires for a
         * Debian-persona Tier-2 session; the operator/compat path is unaffected. */
        /* sudo · the honey shell is a compromised NON-root user (uid 1000, sudo
         * group); `sudo apt install …` is how an attacker installs software (a
         * non-root apt correctly fails "requires superuser privilege").  Strip
         * the sudo wrapper + its options, re-point `base`/argv at the inner apt
         * command, and flag the apt pool euid-root (the forked dpkg inherits it
         * via fork's *child=*parent).  Containment is VFS-session-based, so the
         * Tier-2 overlay still contains the install regardless of the uid. */
        const char *const *apt_argv = argv;
        int apt_via_sudo = 0;
        if (strcmp(base, "sudo") == 0 &&
            st->cow_session != 0 && execve_caller_is_debian(st)) {
            int ri = 1;
            while (argv[ri] && argv[ri][0] == '-') {
                if (!strcmp(argv[ri],"-u")||!strcmp(argv[ri],"--user")||
                    !strcmp(argv[ri],"-g")||!strcmp(argv[ri],"--group")||
                    !strcmp(argv[ri],"-p")||!strcmp(argv[ri],"-C")) {
                    if (argv[ri+1]) ri++;   /* value-taking option */
                }
                ri++;
            }
            if (argv[ri] && !strcmp(argv[ri], "--")) ri++;
            if (argv[ri]) {
                const char *ic = argv[ri];
                for (const char *p = ic; *p; ++p) if (*p == '/') ic = p + 1;
                if (!strcmp(ic,"apt")||!strcmp(ic,"apt-get")||!strcmp(ic,"apt-cache")) {
                    apt_argv = &argv[ri];
                    base = ic;
                    apt_via_sudo = 1;
                }
            }
        }
        if ((strcmp(base, "apt") == 0 || strcmp(base, "apt-get") == 0 ||
             strcmp(base, "apt-cache") == 0) &&
            st->cow_session != 0 && execve_caller_is_debian(st)) {
            extern int      g_apt_request;
            extern int      g_apt_sudo;
            extern uint32_t g_apt_cow_session;
            extern void     orch_record_apt_argv(const char *const argv[]);
            extern int64_t lucas_sys_exit_group(lucas_state_t*, uint64_t, uint64_t,
                                                uint64_t, uint64_t, uint64_t, uint64_t);
            printf("[execve] pid=%d · '%s'%s (Debian) → heavy-arena apt spawn + exit\n",
                   st->synthetic_pid, base, apt_via_sudo ? " (sudo·root)" : "");
            orch_record_apt_argv(apt_argv);
            g_apt_cow_session = st->cow_session;
            g_apt_sudo    = apt_via_sudo;
            g_apt_request = 1;
            return lucas_sys_exit_group(st, 0, 0, 0, 0, 0, 0);
        }
        /* apk arc · the Alpine attacker's apk is the mirror image of apt: it mmaps
         * a large package-DB index (and extracts .apk archives) at runtime and so
         * exhausts a forked Tier-2 arena's 8192 cslots.  Route it through the SAME
         * isolated heavy-arena launcher: record argv + the originating session,
         * flag orch, exit THIS child; orch_spawn_apk_pool respawns apk.static into
         * a fresh heavy arena carrying this session's cow_session (contained).
         * Only fires for an Alpine-persona Tier-2 session (the inverse of apt). */
        if (strcmp(base, "apk") == 0 &&
            st->cow_session != 0 && !execve_caller_is_debian(st)) {
            extern int      g_apk_request;
            extern void     orch_enqueue_apk(const char *const argv[], uint32_t cow_session);
            extern int64_t lucas_sys_exit_group(lucas_state_t*, uint64_t, uint64_t,
                                                uint64_t, uint64_t, uint64_t, uint64_t);
            printf("[execve] pid=%d · 'apk' (Alpine) → enqueue heavy-arena apk spawn + exit\n",
                   st->synthetic_pid);
            orch_enqueue_apk(argv, st->cow_session);   /* per-request snapshot · FIFO drained one at a time */
            g_apk_request = 1;
            return lucas_sys_exit_group(st, 0, 0, 0, 0, 0, 0);
        }
        /* LATERAL-PIVOT BAIT (phase 1) · the canary bash_history hints at other
         * hosts (`ssh deploy@10.0.4.12`, `scp ... backup@10.0.4.30`).  ssh/scp MUST
         * exist — "command not found" while the history shows their use is a
         * coherence tell — and must behave like a real client reaching a
         * real-but-locked-down host: we record the pivot target as a lateral IOC
         * (operator-visible + already in the keystroke transcript) and reply
         * "Permission denied (publickey)" — implying the target is UP, baiting the
         * attacker to try harder / other creds, while NO real packet leaves the
         * host.  Landing them on a DECOY second-host shell is a follow-up phase;
         * capturing the ATTEMPT (who they pivot to) is the core observability win. */
        if ((strcmp(base, "ssh") == 0 || strcmp(base, "scp") == 0) &&
            st->cow_session != 0) {
            extern void    lucas_console_emit_kstr(lucas_state_t *st, const char *s);
            extern int64_t lucas_sys_exit_group(lucas_state_t*, uint64_t, uint64_t,
                                                uint64_t, uint64_t, uint64_t, uint64_t);
            const char *target = NULL;
            for (int i = 1; argv && argv[i]; ++i) {
                if (argv[i][0] == '-') continue;       /* skip flags (best-effort) */
                if (!target) target = argv[i];
                if (strchr(argv[i], '@')) { target = argv[i]; break; }  /* prefer user@host */
            }
            if (!target) target = "host";
            /* host part only (strip a scp ':path' suffix) for the message */
            char host[128]; size_t hn = 0;
            for (const char *p = target; *p && *p != ':' && hn < sizeof(host) - 1; ++p)
                host[hn++] = *p;
            host[hn] = '\0';
            printf("[execve] pid=%d · LATERAL-PIVOT %s '%s' → IOC + synth reject (no real pivot)\n",
                   st->synthetic_pid, base, target);
            char line[192];
            snprintf(line, sizeof line, "%s: Permission denied (publickey).\n", host);
            lucas_console_emit_kstr(st, line);
            return lucas_sys_exit_group(st, 255, 0, 0, 0, 0, 0);
        }
        if ((strcmp(base, "dpkg") == 0 || strcmp(base, "dpkg-query") == 0) &&
            execve_caller_is_debian(st)) {
            /* `apt install` drives dpkg to actually UNPACK/CONFIGURE the
             * downloaded .deb.  Those ACTION invocations must run the REAL dpkg
             * (contained in the session upper, with the real /var/lib/dpkg/status)
             * — only pure RECON (dpkg -l / --version / -s / --print-*) uses the
             * believable facade.  Without this, the facade no-op'd the install and
             * `apt install` resolved+downloaded but installed nothing. */
            int is_action = 0;
            for (int i = 1; argv && argv[i]; ++i) {
                const char *a = argv[i];
                if (!strcmp(a,"-i")||!strcmp(a,"--install")||!strcmp(a,"--unpack")||
                    !strcmp(a,"--configure")||!strcmp(a,"--triggers-only")||
                    !strcmp(a,"-a")||!strcmp(a,"--pending")||!strcmp(a,"-r")||
                    !strcmp(a,"--remove")||!strcmp(a,"-P")||!strcmp(a,"--purge")||
                    !strcmp(a,"--audit")||!strcmp(a,"-C")) { is_action = 1; break; }
            }
            if (!is_action) {
                extern int64_t lucas_sys_exit_group(lucas_state_t*, uint64_t, uint64_t,
                                                    uint64_t, uint64_t, uint64_t, uint64_t);
                printf("[execve] pid=%d · '%s' → Debian dpkg facade (recon)\n", st->synthetic_pid, base);
                execve_dpkg_facade(st, argv);
                return lucas_sys_exit_group(st, 0, 0, 0, 0, 0, 0);
            }
            printf("[execve] pid=%d · '%s' install-action → REAL dpkg (contained)\n",
                   st->synthetic_pid, base);
            /* fall through to the real dpkg load below */
        }
    }
    /* Busybox applet stubs are EMPTY files; a #! script that shares the broad
     * applet path prefix (the /sbin/apk facade) must run as a script instead of
     * being captured by the busybox multi-call binary.  Probe the shebang first
     * for applet-prefix paths — empty stubs read 0 bytes (not a shebang) and
     * fall through to busybox unchanged; only real #! content diverts here. */
    if (path_is_busybox_applet(path)) {
        int64_t sb = execve_try_shebang(st, path, argv, envp);
        if (sb != SHEBANG_NOT_A_SCRIPT) return sb;
    }
    unsigned long elf_size = 0;
    const void *elf_bytes = resolve_path(st, path, &elf_size);
    if (!elf_bytes) {
        /* Not a binstore binary / busybox applet — maybe a #! script on the VFS
         * (a dpkg maintainer script in /var/lib/dpkg/info, …) outside the applet
         * prefix.  Honour the shebang before giving up. */
        if (!path_is_busybox_applet(path)) {
            int64_t sb = execve_try_shebang(st, path, argv, envp);
            if (sb != SHEBANG_NOT_A_SCRIPT) return sb;
        }
        printf("[execve] '%s' not found · returning ENOENT\n", path);
        return -(int64_t)2;   /* -ENOENT */
    }

    if (!lucas_elf_validate(elf_bytes, (size_t)elf_size)) {
        /* Not an ELF — it may be a #! script that resolve_path found as a file
         * (e.g. a dpkg maintainer postinst written into the VFS upper:
         * /var/lib/dpkg/info/<pkg>.postinst, a `#!/bin/sh` script).  Honour the
         * shebang in-orch (re-exec the interpreter) BEFORE bouncing -ENOEXEC back
         * to the guest — so sotOs's binfmt_script runs it directly (and a caller
         * without the shell's own ENOEXEC fallback still works). */
        int64_t sb = execve_try_shebang(st, path, argv, envp);
        if (sb != SHEBANG_NOT_A_SCRIPT) return sb;
        printf("[execve] '%s' failed ELF validation (not a shebang)\n", path);
        return -(int64_t)8;   /* -ENOEXEC */
    }

    /* HEAVY-EXEC RESPAWN · a LARGE attacker-installed binary (a Go editor like
     * `micro`, ~13 MB + a runtime that mmaps multi-MiB heap arenas) does not fit the
     * 32 MiB regular arena this in-place execve runs in, and an in-place execve
     * cannot swap its own arena → its Go runtime OOMs on the first heap mmap.
     * Bounce it into a fresh HEAVY box via the same exit+respawn launcher apk/python
     * use: capture the STAGED bytes (elf_bytes is the orch_spawn_stage buffer, valid
     * until the next stage call — none happens before the respawn consumes it) +
     * argv + env + session, flag orch, exit THIS box.  Only an interactive attacker
     * session (cow_session != 0), never an already-heavy pool box (pkg_install). */
    if (elf_size > LUCAS_HEAVY_EXEC_MIN && st->cow_session != 0 && !st->pkg_install) {
        extern int          g_hx_request;
        extern const void  *g_hx_elf;        extern unsigned long g_hx_sz;
        extern uint32_t     g_hx_cow_session; extern uint8_t       g_hx_euid_root;
        extern void         orch_record_hx(const char *const argv[],
                                           const char *const envp[]);
        extern int64_t      lucas_sys_exit_group(lucas_state_t*, uint64_t, uint64_t,
                                                 uint64_t, uint64_t, uint64_t, uint64_t);
        printf("[execve] pid=%d · '%s' (%lu bytes) exceeds the regular arena → "
               "heavy-arena respawn + exit\n", st->synthetic_pid, path, elf_size);
        orch_record_hx(argv, envp);
        g_hx_elf         = elf_bytes;
        g_hx_sz          = elf_size;
        g_hx_cow_session = st->cow_session;
        g_hx_euid_root   = st->euid_root;
        g_hx_request     = 1;
        return lucas_sys_exit_group(st, 0, 0, 0, 0, 0, 0);
    }

    /* Save the ELF pointer for the in-place restart optimisation. */
    if (!g_busybox_elf) {
        g_busybox_elf = elf_bytes;
        g_busybox_elf_size = elf_size;
    }

    printf("[execve] pid=%d replacing image with '%s' (%lu bytes)\n",
           st->synthetic_pid, path, elf_size);

    /* L3b-T6 in-place restart: if the child has a valid vspace (post-fork),
     * reuse it.  Only reload the DATA segment (write-able pages) and
     * allocate a new stack.  TEXT is identical and can stay. */
    /* WINE-M1 · a vfork child (vfork_parent_slot1 != 0) is STILL borrowing the
     * parent's PML4 here — st->client_vspace is the PARENT's.  The in-place
     * restart would reload DATA over the parent's live image and corrupt it.
     * Force the full-reload path so the child gets its OWN fresh vspace before
     * we resume the parent (below, post-SetSpace). */
    /* TUI-A6 · the in-place restart's whole premise is "TEXT is identical" — it
     * reloads only DATA over the SAME (static busybox) TEXT and never sets up an
     * interpreter.  A DYNAMIC target (glibc less/nano/vim via ld-linux) has a
     * different TEXT, needs PT_INTERP + relocation + the dynamic auxv, and must
     * set st->is_dynamic.  Force the full-reload path for any dynamic image so a
     * busybox `sh` exec'ing the real editors loads them correctly (else it would
     * splat less's DATA over busybox's TEXT and jump to an unrelocated entry). */
    bool have_vspace = (st->client_vspace != 0) && (st->vfork_parent_slot1 == 0)
                       && !lucas_elf_is_dynamic(elf_bytes);
    if (have_vspace) {
        printf("[execve] pid=%d in-place restart (reusing vspace)\n", st->synthetic_pid);
        /* Reload DATA segment to reinitialise global variables. */
        if (lucas_elf_reload_data(st, elf_bytes, (size_t)elf_size) != 0) {
            printf("[execve] elf_reload_data failed · falling back to full reload\n");
            have_vspace = false;  /* fall through to full reload */
        } else {
            /* In-place execve: keep brk_top and mmap_high_water as-is.
             * The child's vspace still has the fork-copied parent pages at
             * brk_base..brk_top and 0x40000000..mmap_high_water.  Resetting
             * to base values causes reserve_range_at failures because those
             * pages are already mapped.  By keeping the old high-water marks,
             * the brk/mmap handlers start from where the old pages end and
             * only reserve truly-free addresses.
             *
             * The new busybox image's first brk(0) query returns brk_top
             * (inherited from parent), and malloc grows the heap from there. */
            st->brk_base    = (uintptr_t)lucas_elf_load_end(elf_bytes);
            /* OBSD-ζ HEAP-BASE-RANDOM (kbind-equivalent) · per-execve jitter so
             * a sotbox calling execve() does not get a deterministic brk_base.
             * Mirrors the spawn-side jitter pattern.  1 MiB aligned · max 256 MiB.
             * In-place path: brk_top/mmap_high_water inherited from parent
             * vspace; do NOT reset (existing mapped pages would cause
             * reserve_range_at failures).  Jitter only shifts the reported
             * base for diagnostic visibility · the inherited brk_top still
             * dictates where new brk() pages land. */
            uint32_t heap_jitter_mb = sotos_arc4random_uniform(256);
            st->brk_base += ((uintptr_t)heap_jitter_mb) << 20;
            printf("[orch] execve slot=%d brk_base jittered by %u MiB -> 0x%lx\n",
                   st->slot_index, (unsigned)heap_jitter_mb,
                   (unsigned long)st->brk_base);
            /* brk_top and mmap_high_water intentionally NOT reset here. */
            st->entry_point = (uintptr_t)lucas_elf_entry(elf_bytes);
        }
    }

    if (!have_vspace) {
        /* Full reload path (first spawn, or in-place failed). */
        st->client_vspace = 0;
        memset(&st->client_vspace_abs,  0, sizeof(st->client_vspace_abs));
        memset(&st->client_vspace_data, 0, sizeof(st->client_vspace_data));
        st->brk_base          = 0;
        st->brk_top           = 0;
        st->mmap_high_water   = 0;
        st->stack_region_top  = 0;   /* γ-0 · clear so stack_setup allocates fresh */

        /* WINE-M1 · execve replaces the ENTIRE address space (POSIX).  The
         * fresh vspace created below has none of the old image's mappings, so
         * the old image's lazy file-backed regions and frame-less reservations
         * MUST be discarded too — they index the dead vspace.  Without this, a
         * post-execve VMFault inside an old lazy span is resurrected from the
         * stale (now-dangling) file handle into the NEW image: the wine launcher
         * lazily maps ntdll.so (~720 KiB) at 0x40000000, then execve's the
         * wine-preloader (full reload here), which maps the 14 KiB wine loader at
         * 0x40000000; a later fault at 0x40068xxx (inside the old ntdll.so span,
         * past the loader's 5 pages) was lazy-backed from the dead ntdll.so → the
         * loader ran ntdll code against a layout that no longer exists → a
         * non-canonical pointer deref → #GP (docs/wine-spike.md frontier).  Only
         * the full-reload path clears these; the in-place busybox-applet
         * optimisation (same ELF, mappings still valid) intentionally keeps them. */
        memset(st->lazy_regions, 0, sizeof(st->lazy_regions));
        memset(st->resv_regions, 0, sizeof(st->resv_regions));

        if (create_client_vspace(st) != 0) {
            printf("[execve] create_client_vspace failed\n");
            return -(int64_t)12;  /* -ENOMEM */
        }

        /* vDSO arc · Task 4 · re-map [vvar][vdso] at SOTOS_VDSO_BASE into the
         * fresh post-execve vspace (non-fatal · libc syscall fallback on miss). */
        if (lucas_map_vdso(st) != 0)
            printf("[execve] vDSO map failed · syscall fallback\n");

        /* WINE-M1 · choose the loader by whether the TARGET carries a PT_INTERP.
         *
         *  - HAS PT_INTERP (true dynamic · e.g. wineserver = PIE + /lib/ld-musl):
         *    lucas_elf_load_program loads the PIE at LUCAS_DYN_BIN_BASE + ld-musl
         *    at LUCAS_DYN_INTERP_BASE, sets st->is_dynamic, and makes
         *    lucas_stack_setup emit the dynamic auxv (AT_BASE/AT_PHDR/AT_ENTRY).
         *    The old static-only loader mapped it at its raw low p_vaddrs with no
         *    interp/relocation → it jumped to an unrelocated entry and VMFaulted.
         *
         *  - NO PT_INTERP (static, OR a no-interp PIE like the wine PRELOADER):
         *    keep the original static load path EXACTLY — in particular it does
         *    NOT touch st->is_dynamic, so the wine-preloader re-exec inherits the
         *    prior (dynamic launcher) image's is_dynamic + bin/interp bases and
         *    thus the dynamic-shaped auxv the preloader requires.  Routing the
         *    preloader through load_program (which sets is_dynamic=false) flipped
         *    that auxv to static-shaped and crashed the wine loader at 0x40068xxx. */
        bool target_is_dynamic = lucas_elf_is_dynamic(elf_bytes);
        if (target_is_dynamic) {
            st->entry_point     = (uintptr_t)lucas_elf_entry(elf_bytes);   /* overridden below */
            st->brk_base        = (uintptr_t)lucas_elf_load_end(elf_bytes);
            {
                uint32_t heap_jitter_mb = sotos_arc4random_uniform(256);
                st->brk_base += ((uintptr_t)heap_jitter_mb) << 20;
                st->brk_top = st->brk_base;
            }
            st->mmap_high_water = 0x40000000UL;
            /* Loads the main binary into the fresh vspace FIRST, then re-stages
             * the interpreter (so the shared orch_spawn_stage buffer holding
             * elf_bytes is reused only after the main image is mapped). */
            if (lucas_elf_load_program(st, elf_bytes, (unsigned long)elf_size) != 0) {
                printf("[execve] dynamic ELF load failed\n");
                return -(int64_t)8;   /* -ENOEXEC */
            }
            printf("[execve] slot=%d dynamic image · entry=0x%lx (interp) brk_base=0x%lx\n",
                   st->slot_index, (unsigned long)st->entry_point,
                   (unsigned long)st->brk_base);
        } else {
            /* Static / no-interp PIE path · UNCHANGED from the pre-WINE-M1 code. */
            if (lucas_elf_load_into_client(st, elf_bytes, (size_t)elf_size) != 0) {
                printf("[execve] ELF load failed\n");
                return -(int64_t)8;   /* -ENOEXEC */
            }
            st->entry_point     = (uintptr_t)lucas_elf_entry(elf_bytes);
            st->brk_base        = (uintptr_t)lucas_elf_load_end(elf_bytes);
            /* OBSD-ζ HEAP-BASE-RANDOM (kbind-equivalent) · per-execve jitter so
             * a sotbox calling execve() does not get a deterministic brk_base.
             * 1 MiB aligned · max 256 MiB (keeps heap_top < mmap_base 0x40000000). */
            {
                uint32_t heap_jitter_mb = sotos_arc4random_uniform(256);
                st->brk_base += ((uintptr_t)heap_jitter_mb) << 20;
                st->brk_top = st->brk_base;
                printf("[orch] execve slot=%d brk_base jittered by %u MiB -> 0x%lx\n",
                       st->slot_index, (unsigned)heap_jitter_mb,
                       (unsigned long)st->brk_base);
            }
            st->mmap_high_water = 0x40000000UL;

            /* apk-fs · a static ET_EXEC (no PT_INTERP) execve'd from a DYNAMIC
             * parent (e.g. apk.static from debian-bash) must NOT inherit the
             * parent's dynamic-image state: stack_setup emits AT_BASE = interp_base
             * when is_dynamic, so a stale is_dynamic=1 gives the static binary a
             * bogus AT_BASE (the parent's 0x140000000) → musl static startup
             * dereferences AT_BASE+0x20 → VMFault.  Reset it here.  EXCEPTION: the
             * wine-preloader (no-PT_INTERP PIE) DELIBERATELY inherits the dynamic
             * launcher's auxv (comment above) — detect it by path and keep the
             * workaround.  (bin_phdr_vaddr is left to lucas_elf_load_into_client,
             * which sets the correct static value for AT_PHDR.) */
            if (!strstr(path, "wine-preloader")) {
                st->is_dynamic      = false;
                st->interp_base     = 0;
                st->bin_base        = 0;
                st->bin_entry_vaddr = 0;
            }
        }
    }

    /* Reset fds to clear any inherited pipe ends (execve semantics:
     * close CLOEXEC fds; for L3b close all non-stdio pipe fds). */
    #ifndef LX_O_CLOEXEC
    #define LX_O_CLOEXEC 02000000   /* O_CLOEXEC · x86_64 Linux */
    #endif
    /* apt's transport methods (/usr/lib/apt/methods/{http,store,gpgv}) are
     * forked from apt then execve'd; they communicate ONLY over their stdio
     * pipes (fd0/1/2) and never need apt's inherited data files.  apt does not
     * reliably mark those O_CLOEXEC, so the method inherited up to 5 of apt's
     * VFS fds (cache/status/lists/locks) on top of its own lazy-pinned lib-load
     * fds → ld.so EMFILE'd (Error 24) loading its closure during `apt install`
     * (apt holds more fds than during update).  Close ALL inherited VFS fds 3+
     * for a method execve so it starts with a clean table. */
    int is_apt_method = (path && strstr(path, "/apt/methods/") != NULL);
    for (int i = 3; i < LUCAS_MAX_FDS; ++i) {
        lucas_fd_t *e = &st->fds[i];
        /* POSIX execve PRESERVES non-CLOEXEC fds — including inherited pipe ends.
         * apt passes its dpkg status pipe via `--status-fd N` WITHOUT O_CLOEXEC
         * and expects dpkg to inherit it; an unconditional pipe-close here made
         * dpkg's `fcntl(N,F_GETFD)` return EBADF → "unable to read filedescriptor
         * flags for <status fd>" → exit 2, no unpack.  So close a pipe end only
         * when O_CLOEXEC is set (POSIX, every guest) OR for an apt transport
         * method (clean-table heuristic: methods talk only over fd0/1/2). */
        if (e->kind == LUCAS_FD_PIPE_READ && e->pipe &&
                   (is_apt_method || (e->flags & LX_O_CLOEXEC))) {
            lucas_pipe_close_reader(e->pipe);
            e->pipe = NULL;
            e->kind = LUCAS_FD_INVALID;
        } else if (e->kind == LUCAS_FD_PIPE_WRITE && e->pipe &&
                   (is_apt_method || (e->flags & LX_O_CLOEXEC))) {
            lucas_pipe_close_writer(e->pipe);
            e->pipe = NULL;
            e->kind = LUCAS_FD_INVALID;
        } else if (e->kind == LUCAS_FD_VFS &&
                   (is_apt_method || (e->flags & LX_O_CLOEXEC))) {
            /* POSIX O_CLOEXEC close (every guest) + the apt-method clean-table. */
            if (e->mount && e->mount->ops && e->mount->ops->close && e->handle)
                e->mount->ops->close(e->mount->backend_state, e->handle);
            e->handle = NULL;
            e->mount  = NULL;
            e->kind   = LUCAS_FD_INVALID;
        }
    }

    /* Build the new stack with the new argv/envp. */
    if (lucas_stack_setup(st, argv, envp) != 0) {
        printf("[execve] stack_setup failed\n");
        return -(int64_t)12;  /* -ENOMEM */
    }

    /* Rebind the TCB to the vspace (required even for in-place restart to
     * ensure the ASID binding is current after fork created a new PML4).
     *
     * fault_ep_slot = 1: the badged fault EP was copied into client_cnode[1]
     * by lucas_client_setup.  This matches CLIENT_FAULT_EP_SLOT in client_setup.c.
     * Must pass 1 (not 0) so seL4 keeps delivering faults to orch's shared EP.
     * Passing 0 would unbind the fault EP and cause "cap fault in send phase". */
    seL4_Word cspace_root_data = api_make_guard_skip_word(
        seL4_WordBits - 4);  /* CLIENT_CNODE_BITS = 4 */
    int err = seL4_TCB_SetSpace(st->client_tcb,
                                 1 /* CLIENT_FAULT_EP_SLOT */,
                                 st->client_cnode, cspace_root_data,
                                 st->client_vspace, seL4_NilData);
    if (err) {
        printf("[execve] TCB_SetSpace failed (err=%d)\n", err);
        return -(int64_t)5;   /* -EIO */
    }

    /* WINE-M1 · the child's TCB is now bound to its OWN fresh vspace — it has
     * stopped borrowing the parent's address space, so the vfork contract is
     * satisfied.  Resume the parent parked in clone(CLONE_VM|CLONE_VFORK) now
     * (no-op when this isn't a vfork child).  Parent + exec'd child then run
     * concurrently on separate vspaces, exactly like a real post-vfork exec. */
    {
        extern void sotbox_vfork_resume_parent(lucas_state_t *child);
        sotbox_vfork_resume_parent(st);
    }

    /* Reset registers: new image starts at entry_point with the new stack.
     * rax = 0, rip = entry_point (NOT advanced — the new image starts here
     * directly, not via a syscall return path).
     * rcx = rip mirrors rip for the sysret path (belt-and-suspenders).
     * fs_base = 0: the new image will call arch_prctl to set up its own TLS. */
    seL4_UserContext regs;
    memset(&regs, 0, sizeof(regs));
    regs.rip    = (seL4_Word)st->entry_point;
    regs.rsp    = (seL4_Word)st->stack_top;
    regs.rax    = 0;
    regs.rcx    = (seL4_Word)st->entry_point;
    regs.rflags = 0x202;   /* IF set, reserved bit 1 */
    /* fs_base = 0 · new musl startup will call arch_prctl SET_FS */

#ifdef LUCAS_TRACE_L2_WR
    printf("[l:wr-orch_execve:337] tcb=%lu rax=0x%lx rip=0x%lx (execve reset)\n",
           (unsigned long)st->client_tcb,
           (unsigned long)regs.rax,
           (unsigned long)regs.rip);
#endif
    err = seL4_TCB_WriteRegisters(st->client_tcb, false, 0,
                                   sizeof(regs)/sizeof(seL4_Word), &regs);
    if (err) {
        printf("[execve] WriteRegisters failed (err=%d)\n", err);
        return -(int64_t)5;
    }

    printf("[execve] pid=%d image replaced · entry=0x%lx stack=0x%lx\n",
           st->synthetic_pid,
           (unsigned long)st->entry_point,
           (unsigned long)st->stack_top);

    /* PR 7 · shadow-announce the image replacement to procd so its proc_t
     * view flips to RUNNING and EV_EXEC_OK lands on the ring.  Procd
     * keeps the same slot · POSIX-correct identity is preserved across
     * the image swap.  Orch retains the seL4 mechanics above (vspace,
     * ELF map, register reset); the announce is informational for
     * procd's accounting + subscribers.
     *
     * procd_slot==0 means "no procd binding" (spawn announce failed or
     * the slot was reset between fork and the image swap · the announce
     * becomes a no-op then, mirroring the OP_EXIT fallback shape). */
    if (st->procd_slot != 0) {
        extern int orch_procd_exec(uint32_t caller_slot);
        int pd_rc = orch_procd_exec(st->procd_slot);
        if (pd_rc < 0) {
            printf("[lucas] procd OP_EXEC announce failed rc=%d · sotbox continues\n",
                   pd_rc);
        }
        /* ABI v2 · comm changes on execve · update procd's comm (keeping the
         * existing cow_session) to the new binary's basename so the attacker's
         * `ps` reflects the program they exec'd, named.  comm-only update. */
        extern int orch_procd_set_session(uint32_t, uint32_t, const char *);
        const char *ebase = path;
        for (const char *q = path; q && *q; ++q) if (*q == '/') ebase = q + 1;
        orch_procd_set_session(st->procd_slot, st->cow_session, ebase);
    }

    /* Return LUCAS_EXEC_REPLY_RAW: the fault loop sends seL4_Reply (unblocking
     * the client's syscall entry) but does NOT overwrite our fresh registers. */
    return LUCAS_EXEC_REPLY_RAW;
}

/*
 * lucas_sys_execve — syscall handler for execve(path, argv, envp) [sysno=59].
 *
 * Reads path string and argv array from client vspace, then delegates to
 * sotbox_execve.  envp is ignored for L3b (busybox doesn't need it for
 * ls/grep).
 */
int64_t lucas_sys_execve(lucas_state_t *st,
                           uint64_t path_vaddr, uint64_t argv_vaddr,
                           uint64_t envp_vaddr,
                           uint64_t _3, uint64_t _4, uint64_t _5) {
    (void)_3; (void)_4; (void)_5;

    /* Copy the path string from client vspace. */
    char path[LUCAS_EXEC_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, (uintptr_t)path_vaddr,
                                     path, sizeof(path)) < 0) {
        printf("[execve] failed to copy path from client\n");
        return -(int64_t)14;  /* -EFAULT */
    }

    /* Read argv array from client vspace. */
    char argv_pool[1024];
    const char *argv_local[LUCAS_EXEC_ARGV_MAX + 1];

    int n_argv = read_cstr_array_from_client(st, (uintptr_t)argv_vaddr,
                                              argv_pool, sizeof(argv_pool),
                                              argv_local, LUCAS_EXEC_ARGV_MAX);
    if (n_argv < 0) {
        printf("[execve] failed to read argv from client\n");
        return -(int64_t)14;  /* -EFAULT */
    }
    argv_local[n_argv] = NULL;
    {
        char ab[256]; size_t ap = 0;
        for (int i = 0; i < n_argv && ap < sizeof(ab) - 1; i++) {
            int w = snprintf(ab + ap, sizeof(ab) - ap, "%s ", argv_local[i] ? argv_local[i] : "(null)");
            if (w < 0) break; ap += (size_t)w;
        }
        printf("[execve] pid=%d argv(%d): %s\n", st->synthetic_pid, n_argv, ab);
    }

    /* Read envp array from client vspace.  Previously execve passed an EMPTY env
     * (busybox applets don't need one) — but a real multi-stage loader does: Wine
     * re-execs `wine → wine-preloader → wine` and the inherited env (WINELOADER /
     * WINEDLLPATH / WINEPREFIX) MUST survive each hop, else the preloader can't
     * find the loader.  A larger pool (env is bigger than argv); on any failure or
     * a NULL envp, fall back to an empty env (matches the old behavior). */
    #define LUCAS_EXEC_ENVP_MAX 64     /* env is bigger than argv (Wine sets many) */
    static char        envp_pool[8192];
    static const char *envp_local[LUCAS_EXEC_ENVP_MAX + 1];
    const char *const *envp_use = (const char *const *)envp_local;
    if (envp_vaddr) {
        int n_envp = read_cstr_array_from_client(st, (uintptr_t)envp_vaddr,
                                                 envp_pool, sizeof(envp_pool),
                                                 envp_local, LUCAS_EXEC_ENVP_MAX);
        if (n_envp < 0) {
            printf("[execve] failed to read envp · proceeding with empty env\n");
            envp_local[0] = NULL;
        } else {
            envp_local[n_envp] = NULL;
            printf("[execve] pid=%d · forwarding %d env var(s) across execve\n",
                   st->synthetic_pid, n_envp);
        }
    } else {
        envp_local[0] = NULL;
    }

    /* PR 10 · shell-hook · if the target is a shell binary, rewrite
     * argv to source /etc/bashrc + /root/.bashrc before running the
     * intended command.  This runs BEFORE sotbox_execve so the rewritten
     * argv flows through the normal lucas_stack_setup path into the new
     * vspace.  No client-vspace writes; no register patching.
     *
     * The scratch buffer is sized for the worst-case wrapper string
     * ("source /etc/bashrc 2>/dev/null; source /root/.bashrc 2>/dev/null;
     *  exec sh" = ~80 chars) with comfortable headroom.  argv_pool is
     * left untouched so existing argv strings remain valid pointers.
     *
     * Failure modes:
     *   should_apply==0 · non-shell target · skip silently (preserves
     *                     the demo's Python / native ELF execve paths).
     *   apply returns 0 · already-wrapped argv (-c present) · skip.
     *   apply returns -1 · scratch too small · log + continue with
     *                     untouched argv (safer than blocking the
     *                     execve).
     */
    /* SSH canary-shell (Phase B): SKIP the shellhook for the interactive SSH
     * subtree (console_src == SSH_RING, inherited through fork).  busybox is a
     * multi-call binary — every applet the attacker runs (`cat`, `id`, `ls`)
     * is an execve("/bin/busybox", [applet,...]), whose path matches the
     * shellhook whitelist.  Rewriting it to the `. /root/.bashrc; exec sh`
     * wrapper would discard the real applet and the attacker would never see
     * `cat /etc/passwd` output.  The canary-.bashrc installing stays active for
     * the serial demo shell (console_src == SERIAL); over SSH, a working shell
     * that streams real canary content back is the higher-fidelity deception. */
    if (st->console_src != LUCAS_CONSOLE_SRC_SSH_RING &&
        lucas_shellhook_should_apply(path)) {
        static char shellhook_scratch[512];
        int rc = lucas_shellhook_apply(path, argv_local,
                                        LUCAS_EXEC_ARGV_MAX + 1,
                                        shellhook_scratch,
                                        sizeof(shellhook_scratch));
        if (rc < 0) {
            printf("[execve] shellhook apply failed · proceeding with "
                   "original argv\n");
        }
    }

    /* Spec B · exec signal (weight 8).  Forward to the anomaly and
     * apply the reply tier (reply-driven · no callback).  Fires before
     * the image swap so the attempt is scored even if exec later fails. */
    {
        int target = anomaly_forward_sync(st, ANOMALY_EV_EXEC, 0);
        if (target > 0) anomaly_apply_reply_tier(st, target);
    }

    return sotbox_execve(st, path,
                          (const char *const *)argv_local,
                          envp_use);
}
