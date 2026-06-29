/*
 * sotOs · sotShell · v0.7 · S2 · glob expansion
 *
 * Simple wildcard expansion against the sotFS via existing
 * ORCH_OP_SOTFS_LS IPC.  Supports `*` and `?` only — no character
 * classes, no recursive globs.
 *
 * Bounded: MAX_GLOB_EXPANSIONS expansions per call.  Result paths
 * are written into a caller-supplied buffer (no malloc).
 */
#ifndef SOTSHELL_GLOB_H
#define SOTSHELL_GLOB_H

#include <stddef.h>
#include <sel4/sel4.h>

#define MAX_GLOB_EXPANSIONS 32
#define MAX_GLOB_PATH_LEN   128

struct glob_result {
    int n_matches;
    /* Caller-allocated output buffer is filled with up to n_matches
     * NUL-terminated path strings.  out_paths[i] points into out_buf. */
    char *out_paths[MAX_GLOB_EXPANSIONS];
};

/*
 * glob_expand — expand a pattern containing * or ?
 *
 * pattern    : input (e.g. "/tmp/canary-*.txt" or "*.log")
 * orch_ep    : orchestrator endpoint cap for VFS LS IPC
 * result     : output structure populated by callee
 * buf, bufsz : storage for matched paths (NUL-terminated, packed)
 *
 * Returns the number of matches (>= 0) on success, or negative on error.
 * If the pattern contains no wildcard the function returns 1 with the
 * single path being the pattern itself.
 */
int glob_expand(const char *pattern,
                seL4_CPtr orch_ep,
                struct glob_result *result,
                char *buf, size_t bufsz);

/*
 * glob_match — pure helper: does `name` match shell wildcard `pattern`?
 * Returns 1 on match, 0 otherwise.  Pure function, no I/O.
 */
int glob_match(const char *pattern, const char *name);

#endif /* SOTSHELL_GLOB_H */
