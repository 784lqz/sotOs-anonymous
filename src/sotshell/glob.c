/*
 * sotOs · sotShell · v0.7 · S2 · glob expansion implementation
 *
 * Pure wildcard matcher + a thin layer that lists a sotFS directory
 * via ORCH_OP_SOTFS_LS and emits matching basenames as full paths.
 *
 * Constraints:
 *  - No malloc.  Output paths live in caller-supplied buffer.
 *  - Bounded to MAX_GLOB_EXPANSIONS = 32 matches per call.
 *  - Patterns with no '*' or '?' return the literal pattern as one match.
 *  - Only the LAST path component may contain wildcards.  Earlier
 *    components are taken literally as the directory to scan.
 */
#include "glob.h"
#include <orch/proto.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* glob_match — recursive wildcard matcher                            */
/* '*' matches zero-or-more chars, '?' matches exactly one.           */
/* ------------------------------------------------------------------ */
int glob_match(const char *pattern, const char *name)
{
    if (!pattern || !name) return 0;

    while (*pattern) {
        if (*pattern == '*') {
            /* Collapse runs of '*'. */
            while (*pattern == '*') pattern++;
            if (*pattern == '\0') return 1;   /* trailing * matches rest */
            /* Try to match the remainder at every position. */
            while (*name) {
                if (glob_match(pattern, name)) return 1;
                name++;
            }
            return glob_match(pattern, name);  /* end-of-name case */
        }
        if (*name == '\0') return 0;
        if (*pattern != '?' && *pattern != *name) return 0;
        pattern++;
        name++;
    }
    return *name == '\0';
}

/* ------------------------------------------------------------------ */
/* has_wildcard — does the pattern contain * or ?                     */
/* ------------------------------------------------------------------ */
static int has_wildcard(const char *p)
{
    for (; *p; ++p) {
        if (*p == '*' || *p == '?') return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* split_dir_pattern — split "/tmp/canary-*.txt" into dir="/tmp" and  */
/* basename="canary-*.txt".  If no slash, dir="/tmp" (default).        */
/* ------------------------------------------------------------------ */
static void split_dir_pattern(const char *pattern, char *dir, size_t dirsz,
                              const char **basename_out)
{
    const char *last_slash = strrchr(pattern, '/');
    if (!last_slash) {
        strncpy(dir, "/tmp", dirsz - 1);
        dir[dirsz - 1] = '\0';
        *basename_out = pattern;
        return;
    }
    size_t dlen = (size_t)(last_slash - pattern);
    if (dlen == 0) {
        strncpy(dir, "/", dirsz - 1);
    } else {
        if (dlen >= dirsz) dlen = dirsz - 1;
        memcpy(dir, pattern, dlen);
        dir[dlen] = '\0';
    }
    *basename_out = last_slash + 1;
}

/* ------------------------------------------------------------------ */
/* sotfs_ls_dir — list directory via ORCH_OP_SOTFS_LS                 */
/* Returns reply (zero-initialised on error).                         */
/* ------------------------------------------------------------------ */
static orch_sotfs_ls_reply_t sotfs_ls_dir(seL4_CPtr orch_ep, const char *path)
{
    orch_sotfs_path_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, path, ORCH_SOTFS_PATH_MAX - 1);

    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SOTFS_LS, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    orch_sotfs_ls_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);
    return reply;
}

/* ------------------------------------------------------------------ */
/* glob_expand — see glob.h                                           */
/* ------------------------------------------------------------------ */
int glob_expand(const char *pattern,
                seL4_CPtr orch_ep,
                struct glob_result *result,
                char *buf, size_t bufsz)
{
    if (!pattern || !result || !buf) return -1;
    memset(result, 0, sizeof(*result));

    /* No wildcard · single-match identity case. */
    if (!has_wildcard(pattern)) {
        size_t plen = strlen(pattern);
        if (plen + 1 > bufsz) return -1;
        memcpy(buf, pattern, plen + 1);
        result->out_paths[0] = buf;
        result->n_matches = 1;
        return 1;
    }

    char dir[MAX_GLOB_PATH_LEN];
    const char *base_pat = NULL;
    split_dir_pattern(pattern, dir, sizeof(dir), &base_pat);

    /* List directory via VFS. */
    orch_sotfs_ls_reply_t reply = sotfs_ls_dir(orch_ep, dir);

    size_t buf_used = 0;
    int n = 0;
    for (uint32_t i = 0;
         i < reply.entry_count
         && i < ORCH_SOTFS_LS_MAX_ENTRIES
         && n < MAX_GLOB_EXPANSIONS;
         ++i)
    {
        const char *name = reply.entries[i].name;
        if (!glob_match(base_pat, name)) continue;

        /* Compose full path "<dir>/<name>" into buf. */
        size_t dlen = strlen(dir);
        size_t nlen = strlen(name);
        int need_slash = (dlen > 0 && dir[dlen - 1] != '/');
        size_t total = dlen + (need_slash ? 1 : 0) + nlen + 1;
        if (buf_used + total > bufsz) break;

        char *p = buf + buf_used;
        memcpy(p, dir, dlen);
        size_t pos = dlen;
        if (need_slash) p[pos++] = '/';
        memcpy(p + pos, name, nlen);
        pos += nlen;
        p[pos] = '\0';

        result->out_paths[n++] = p;
        buf_used += total;
    }
    result->n_matches = n;

    /* If no matches, fall back to literal pattern (POSIX-like). */
    if (n == 0) {
        size_t plen = strlen(pattern);
        if (plen + 1 > bufsz) return -1;
        memcpy(buf, pattern, plen + 1);
        result->out_paths[0] = buf;
        result->n_matches = 1;
        return 1;
    }
    return n;
}
