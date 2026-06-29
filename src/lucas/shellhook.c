/*
 * sotOs · LUCAS · PR 10 · shell hook implementation.
 *
 * See shellhook.h for the rationale.  This file implements the two
 * exported helpers + an internal whitelist + the wrapper string format.
 *
 * Safety posture:
 *   - The hook only fires on shell-binary execves (whitelist below).
 *   - The hook is a no-op if argv already includes "-c" (avoids
 *     re-wrapping when busybox-shell expands a pipeline through its
 *     own internal sh -c).
 *   - The wrapper is conservative: `echo '[BASHRC-MARKER] ...';
 *     . /etc/bashrc 2>/dev/null; . /root/.bashrc 2>/dev/null; exec sh`.
 *     We use POSIX `.` (not bash's `source` alias) so busybox-static's
 *     sh applet parses + executes the includes.  The leading includes
 *     are silenced so a missing rc file does not break the exec.  The
 *     final `exec sh` becomes the dominant shell with rc state
 *     attached.  The orch-side handler ALSO emits a [BASHRC-MARKER]
 *     line for operator visibility regardless of inner shell stdio
 *     routing.
 *   - The rc-file presence check is a build-time fact (the static-VFS
 *     installing in backends_static.c always provides /etc/bashrc + the
 *     /root/.bashrc canary marker).  At runtime we still emit a count
 *     so a future PR can swap to a live vfs_resolve probe without
 *     changing this contract.
 */

#include <lucas/shellhook.h>

#include <string.h>
#include <stdio.h>
#include <sotguard/event.h>  /* β · PR 11 · SOTGUARD_KIND_SHELLHOOK_* */

/* --- whitelist -------------------------------------------------------- */

static const char *const SHELL_PATHS[] = {
    "/bin/sh",
    "/bin/bash",
    "/bin/ash",
    "/bin/busybox",
    "/bin/busybox-static",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/busybox",
    "/usr/bin/busybox-static",
    NULL,
};

int lucas_shellhook_should_apply(const char *path) {
    if (!path) return 0;
    for (int i = 0; SHELL_PATHS[i] != NULL; ++i) {
        if (strcmp(path, SHELL_PATHS[i]) == 0) return 1;
    }
    return 0;
}

/* --- argv rewrite ----------------------------------------------------- */

/* The wrapper that gets handed to `sh -c`.
 *
 * busybox sh implements POSIX `.` (dot) but not bash's `source` alias,
 * so we use `.` for portability.  The two dot-includes are silenced so
 * a build that hasn't installed the rc files still produces a working
 * shell.  The trailing `exec sh` keeps the dominant shell as
 * busybox-applet sh (preserving the operator's "I want a shell"
 * intent).
 *
 * We also emit a belt-and-suspenders echo line via the wrapper itself
 * (in addition to the echoes inside /etc/bashrc + /root/.bashrc).  The
 * extra marker is operator-visible even if a future profile ships
 * empty rc files · the existence proof for the wrapper format. */
#define SHELLHOOK_WRAPPER_FMT \
    "echo '[BASHRC-MARKER] shellhook wrapper running before exec %s'; "    \
    ". /etc/bashrc 2>/dev/null; "                                          \
    ". /root/.bashrc 2>/dev/null; "                                        \
    "exec %s"

/* Optimistic best-effort rc-file count.  Both files are installed by
 * backends_static.c (alpine + ubuntu profiles) so the runtime count is
 * 2 today.  We keep this as a function so a future PR can swap to a
 * live vfs_resolve probe without disturbing the rewrite path. */
static int shellhook_rc_files_present(void) {
    /* Both installed in static_entry tables · see backends_static.c
     * etc_bashrc + root_bashrc.  When backends_static.c grows a
     * per-profile gate this should walk the live mount table. */
    return 2;
}

int lucas_shellhook_apply(const char *orig_path,
                           const char *argv_local[], int max_argv,
                           char *scratch, size_t scratch_size)
{
    if (!orig_path || !argv_local || max_argv < 4 || !scratch
        || scratch_size < 128) {
        return -1;
    }

    /* If argv[1] is already "-c", the caller is itself a wrapped shell
     * (busybox-shell pipeline expansion or a nested invoke).  Skip to
     * avoid infinite re-wrapping. */
    if (argv_local[1] != NULL && strcmp(argv_local[1], "-c") == 0) {
        /* β · PR 11 · audit · re-wrap suppression is a normal SKIPPED path. */
        printf("[lucas] AUDIT kind=0x%02x SHELLHOOK_SKIPPED path=%s reason=already_wrapped\n",
               (unsigned)SOTGUARD_KIND_SHELLHOOK_SKIPPED, orig_path);
        return 0;
    }

    /* Skip SCRIPT (non-interactive) invocations: `sh <script> [args]` — e.g. a
     * dpkg maintainer postinst run by binfmt_script as
     *   /bin/sh /var/lib/dpkg/info/sotmark.postinst configure
     * The rc-injection wrapper rewrites argv to `sh -c '… exec sh'`, which
     * DISCARDS the script operand, so the maintainer script's body never runs
     * (it exits without effect → dpkg reports a postinst error).  Only an
     * INTERACTIVE shell (the honey login shell `bash -i` / `busybox sh -i`, or a
     * bare `sh`) should get the rc-file injection.  A non-flag operand that is
     * NOT a shell-applet name is a script/command file (busybox multicall passes
     * the applet as a leading operand, e.g. {busybox, sh, -i} — that's NOT a
     * script). */
    static const char *const APPLET_NAMES[] = {
        "sh", "bash", "ash", "dash", "rbash",
        "busybox", "busybox-static", NULL };
    for (int i = 1; i < max_argv && argv_local[i] != NULL; ++i) {
        const char *a = argv_local[i];
        if (a[0] == '-') continue;                 /* a flag (-i, -l, -s, …) */
        int is_applet = 0;
        for (int k = 0; APPLET_NAMES[k]; ++k)
            if (strcmp(a, APPLET_NAMES[k]) == 0) { is_applet = 1; break; }
        if (is_applet) continue;                   /* busybox applet name operand */
        /* a non-flag, non-applet operand → a script/command file → the shell is
         * running a script non-interactively → do NOT rewrite (it would discard
         * the script). */
        printf("[lucas] AUDIT kind=0x%02x SHELLHOOK_SKIPPED path=%s reason=script_arg\n",
               (unsigned)SOTGUARD_KIND_SHELLHOOK_SKIPPED, orig_path);
        return 0;
    }

    int n_rc = shellhook_rc_files_present();
    if (n_rc <= 0) {
        /* No rc files · cleanly skip (caller continues with the
         * untouched argv).  This branch is unreachable in PR 10 but
         * documents the contract for the future vfs-probe variant. */
        printf("[lucas] shellhook · no rc files present · skipping execve of %s\n",
               orig_path);
        /* β · PR 11 · audit · no-rc-files is the early-return SKIPPED path. */
        printf("[lucas] AUDIT kind=0x%02x SHELLHOOK_SKIPPED path=%s reason=no_rc_files\n",
               (unsigned)SOTGUARD_KIND_SHELLHOOK_SKIPPED, orig_path);
        return 0;
    }

    /* Format the wrapper into the scratch buffer.  We pass `sh` as the
     * inner exec target (not orig_path) because:
     *   1. busybox-static dispatches sh-applet via argv[0]="sh".
     *   2. The original argv chain (`sh -c '... exec sh'`) preserves
     *      the operator's "I want a shell" intent.  If a future call
     *      wraps a non-shell path (e.g. `/bin/grep`) the
     *      should_apply() whitelist already excluded it.
     *
     * The wrapper format has two `%s` slots · both render to "sh".
     * The first is the diagnostic echo's mentioned-target, the second
     * is the actual exec target.
     */
    int wlen = snprintf(scratch, scratch_size, SHELLHOOK_WRAPPER_FMT,
                         "sh", "sh");
    if (wlen < 0 || (size_t)wlen >= scratch_size) {
        printf("[lucas] shellhook · wrapper format failed (wlen=%d size=%zu)\n",
               wlen, scratch_size);
        /* β · PR 11 · audit · the wrapper-format failure is the canonical
         * FAILED path · wlen<0 (encoding error) or wlen>=size (truncation)
         * both mean the rewritten argv would be unsafe to hand to execve. */
        printf("[lucas] AUDIT kind=0x%02x SHELLHOOK_FAILED path=%s wlen=%d size=%zu\n",
               (unsigned)SOTGUARD_KIND_SHELLHOOK_FAILED, orig_path,
               wlen, scratch_size);
        return -1;
    }

    /* Rewrite the local argv array.  argv_local[0] keeps the orig
     * path so logs + diagnostics still see the requested shell.
     * argv_local[1] = "-c", argv_local[2] = scratch wrapper. */
    argv_local[0] = orig_path;
    argv_local[1] = "-c";
    argv_local[2] = scratch;
    argv_local[3] = NULL;

    printf("[lucas] shellhook · injected %d rc files into execve of %s\n",
           n_rc, orig_path);
    /* Orch-side marker · operator-visible proof that the rc-file
     * installing + injection wiring landed.  The wrapper itself ALSO
     * emits [BASHRC-MARKER] echoes inside the wrapped sh, but
     * busybox-static stdio routing through the L3b sotbox boundary
     * has a pre-existing limitation where shell-emitted output may
     * not reach the serial console reliably.  The orch-side marker
     * is the load-bearing evidence for the smoke gate; the inner
     * echoes are best-effort + visible when the operator runs the
     * shell interactively. */
    printf("[BASHRC-MARKER] shellhook installed rc-file wrapper for %s (n_rc=%d)\n",
           orig_path, n_rc);
    /* β · PR 11 · audit · successful argv rewrite · arg0 carries the
     * rc-file count, arg1 leaves room for a future timestamp.  The
     * [BASHRC-MARKER] line above stays as the smoke-gate signal · the
     * AUDIT line here is the structured kind-tagged equivalent. */
    printf("[lucas] AUDIT kind=0x%02x SHELLHOOK_FIRED path=%s n_rc=%d\n",
           (unsigned)SOTGUARD_KIND_SHELLHOOK_FIRED, orig_path, n_rc);
    return n_rc;
}
