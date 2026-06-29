/*
 * sotOs · LUCAS · PR 10 · shell hook · source rc files on execve.
 *
 * Detects when execve() targets a shell binary (sh / bash / busybox-static)
 * and rewrites argv so that /etc/bashrc + /root/.bashrc are sourced before
 * the original command runs.  Operator visibility:
 *
 *   [lucas] shellhook · injected N rc files into execve of <path>
 *   [BASHRC-MARKER]              (printed by the installed rc content)
 *
 * Scope:
 *   - Only triggers on a whitelist of shell binaries.  Python / native
 *     ELFs are untouched.  Demo-critical paths (simulated_attacker.py via
 *     inject-script · busybox-shell pipeline childs) keep working
 *     because the wrapper is a `sh -c '...'` form that busybox-static
 *     already supports.
 *   - The implementation is orch-side: we rewrite the LOCAL argv array
 *     in lucas_sys_execve BEFORE the image swap.  No client-vspace
 *     writes (the new vspace will receive the rewritten argv through
 *     the standard lucas_stack_setup path).  No register patching.
 *
 * Plan's deviation: state.h has no argv_vaddr/client_tcb argv field and
 * no lucas_vfs_exists helper.  The cleanest place to do the rewrite is
 * BEFORE sotbox_execve (where argv is already in orch-local memory)
 * rather than after the image swap.  rc-file presence is determined by
 * a static rodata check (the installed /etc/bashrc + /root/.bashrc live
 * in backends_static.c as the canonical static-VFS entries · same
 * pattern as /etc/passwd).
 */

#ifndef SOTOS_LUCAS_SHELLHOOK_H
#define SOTOS_LUCAS_SHELLHOOK_H

#include <stddef.h>

/* Return 1 if path is a shell binary whose execve should be wrapped, 0
 * otherwise.  Whitelist · sh / bash / ash / busybox / busybox-static in
 * both /bin and /usr/bin. */
int lucas_shellhook_should_apply(const char *path);

/* Rewrite the argv array so the shell sources /etc/bashrc + /root/.bashrc
 * before running the original command.  Returns the number of rc files
 * injected (0..2) on success, or -1 if the pool/argv slots are too small.
 *
 * Layout after rewrite:
 *   out_argv[0] = original path (or "sh" if path was a busybox applet)
 *   out_argv[1] = "-c"
 *   out_argv[2] = "<wrapper>"                 (in scratch buffer)
 *   out_argv[3] = NULL
 *
 * scratch / scratch_size · scratch buffer for the wrapper string (e.g.
 * the trailing space in argv_pool).  Must be at least 256 bytes.
 *
 * orig_path · the resolved path lucas_sys_execve was about to exec.
 *             Preserved as out_argv[0] for diagnostics + so applet
 *             dispatch via argv[0] still works inside busybox.
 *
 * NOTE: this rewrite is intentionally a no-op if the caller passed -c
 * already (e.g. busybox-shell's internal pipeline expansion uses -c) so
 * we don't recursively wrap.  Detection · if argv[1] is already "-c"
 * (after the binary path) we skip. */
int lucas_shellhook_apply(const char *orig_path,
                           const char *argv_local[], int max_argv,
                           char *scratch, size_t scratch_size);

#endif /* SOTOS_LUCAS_SHELLHOOK_H */
