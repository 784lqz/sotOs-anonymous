/*
 * sotOs · sotShell · v0.7 S1 · tab completion.
 *
 * Two completion sources:
 *   1. Built-in command list (compile-time table).
 *   2. VFS paths when the current word starts with '/' · queries the
 *      orchestrator via ORCH_OP_SOTFS_LS for the parent directory and
 *      filters by basename prefix.  Falls through to no-op if no orch
 *      EP is wired.
 *
 * Behaviour:
 *   - Unique match · rewrite buffer in place (replace prefix with full
 *     completion · append ' ' on commands, '/' on dirs).
 *   - Multiple matches · print them on a fresh line for the readline
 *     caller (caller will redraw prompt + buffer afterwards).
 *   - No match · return COMPLETION_NONE, buffer unchanged.
 */

#include "completion.h"

#include <stdio.h>
#include <string.h>
#include <orch/proto.h>

/* ------------------------------------------------------------------ */
/* Built-in command table                                              */
/* ------------------------------------------------------------------ */
static const char *const g_builtins[] = {
    "sotinfo", "list", "sotnet", "ls", "cat", "mkdir", "rm", "tail",
    "grep", "install", "silence", "synth", "synth-trigger", "synth-queue",
    "dns", "promote", "kill", "clear", "help", "quit",
    NULL,
};

/* ------------------------------------------------------------------ */
/* Helper · find the start of the word containing cursor              */
/* ------------------------------------------------------------------ */
static size_t word_start(const char *buf, size_t cursor)
{
    size_t i = cursor;
    while (i > 0 && buf[i - 1] != ' ') i--;
    return i;
}

/* Splice `repl` into buf at [word_begin .. cursor), updating len + cursor.
 * Returns 1 on success, 0 if buf would overflow. */
static int splice_replacement(char *buf, size_t buf_size,
                              size_t word_begin, size_t *inout_cursor,
                              size_t *inout_len,
                              const char *repl, size_t repl_len,
                              char trailing /* 0 = none */)
{
    size_t cursor = *inout_cursor;
    size_t len    = *inout_len;
    size_t tail   = len - cursor;
    size_t extra  = (trailing != 0) ? 1u : 0u;
    size_t new_len = word_begin + repl_len + extra + tail;
    if (new_len + 1 > buf_size) return 0;

    /* Move the tail (chars right of cursor) to its new position. */
    if (tail > 0) {
        memmove(buf + word_begin + repl_len + extra,
                buf + cursor,
                tail);
    }
    memcpy(buf + word_begin, repl, repl_len);
    if (trailing) buf[word_begin + repl_len] = trailing;

    *inout_cursor = word_begin + repl_len + extra;
    *inout_len    = new_len;
    buf[new_len]  = '\0';
    return 1;
}

/* ------------------------------------------------------------------ */
/* Built-in command completion                                         */
/* ------------------------------------------------------------------ */
static completion_result_t complete_builtin(char *buf, size_t buf_size,
                                            size_t word_begin,
                                            size_t *inout_len,
                                            size_t *inout_cursor)
{
    size_t cursor = *inout_cursor;
    size_t prefix_len = cursor - word_begin;

    const char *matches[32];
    int n_matches = 0;
    for (int i = 0; g_builtins[i]; ++i) {
        if (strncmp(g_builtins[i], buf + word_begin, prefix_len) == 0) {
            if (n_matches < 32) matches[n_matches] = g_builtins[i];
            n_matches++;
        }
    }
    if (n_matches == 0) return COMPLETION_NONE;
    if (n_matches == 1) {
        const char *m = matches[0];
        if (splice_replacement(buf, buf_size, word_begin, inout_cursor,
                               inout_len, m, strlen(m), ' ')) {
            return COMPLETION_UNIQUE;
        }
        return COMPLETION_NONE;
    }

    /* Multiple matches · print on a fresh line. */
    printf("\n");
    for (int i = 0; i < n_matches && i < 32; ++i) {
        printf("%s  ", matches[i]);
    }
    printf("\n");
    return COMPLETION_MULTIPLE;
}

/* ------------------------------------------------------------------ */
/* VFS path completion · query orch ORCH_OP_SOTFS_LS                   */
/* ------------------------------------------------------------------ */
static completion_result_t complete_vfs(char *buf, size_t buf_size,
                                         size_t word_begin,
                                         size_t *inout_len,
                                         size_t *inout_cursor,
                                         seL4_CPtr orch_ep)
{
    if (orch_ep == 0) return COMPLETION_NONE;

    size_t cursor = *inout_cursor;
    const char *word = buf + word_begin;
    size_t word_len  = cursor - word_begin;
    if (word_len == 0 || word[0] != '/') return COMPLETION_NONE;

    /* Split word into parent dir + basename prefix. */
    size_t last_slash = 0;
    for (size_t i = 0; i < word_len; ++i) {
        if (word[i] == '/') last_slash = i;
    }
    char parent[ORCH_SOTFS_PATH_MAX];
    memset(parent, 0, sizeof(parent));
    if (last_slash == 0) {
        parent[0] = '/'; parent[1] = '\0';
    } else {
        size_t plen = last_slash;
        if (plen >= sizeof(parent)) plen = sizeof(parent) - 1;
        memcpy(parent, word, plen);
        parent[plen] = '\0';
    }
    const char *base = word + last_slash + 1;
    size_t base_len  = word_len - last_slash - 1;

    /* IPC: ORCH_OP_SOTFS_LS on parent. */
    orch_sotfs_path_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, parent, ORCH_SOTFS_PATH_MAX - 1);
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

    if (reply.entry_count == 0) return COMPLETION_NONE;

    /* Filter by basename prefix. */
    int match_idx[ORCH_SOTFS_LS_MAX_ENTRIES];
    int n_matches = 0;
    for (uint32_t i = 0; i < reply.entry_count && i < ORCH_SOTFS_LS_MAX_ENTRIES; ++i) {
        if (strncmp(reply.entries[i].name, base, base_len) == 0) {
            match_idx[n_matches++] = (int)i;
        }
    }
    if (n_matches == 0) return COMPLETION_NONE;

    if (n_matches == 1) {
        const orch_sotfs_dirent_t *e = &reply.entries[match_idx[0]];
        /* Rebuild full path: parent + '/' + name (avoid double slash for "/"). */
        char full[ORCH_SOTFS_PATH_MAX * 2];
        size_t plen = strlen(parent);
        size_t nlen = strnlen(e->name, sizeof(e->name));
        size_t off = 0;
        if (plen + 1 + nlen + 1 > sizeof(full)) return COMPLETION_NONE;
        memcpy(full + off, parent, plen); off += plen;
        if (!(plen == 1 && parent[0] == '/')) {
            full[off++] = '/';
        }
        memcpy(full + off, e->name, nlen); off += nlen;
        full[off] = '\0';
        char trail = (e->kind == 2) ? '/' : ' ';
        /* For directories we append '/' but no space; for files ' '. */
        if (splice_replacement(buf, buf_size, word_begin, inout_cursor,
                                inout_len, full, off, trail)) {
            return COMPLETION_UNIQUE;
        }
        return COMPLETION_NONE;
    }

    /* Multiple matches · print basenames. */
    printf("\n");
    for (int i = 0; i < n_matches; ++i) {
        const orch_sotfs_dirent_t *e = &reply.entries[match_idx[i]];
        printf("%s%s  ", e->name, (e->kind == 2) ? "/" : "");
    }
    printf("\n");
    return COMPLETION_MULTIPLE;
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
/* ------------------------------------------------------------------ */
completion_result_t completion_complete(char *buf,
                                         size_t buf_size,
                                         size_t *inout_len,
                                         size_t *inout_cursor,
                                         seL4_CPtr orch_ep)
{
    if (!buf || !inout_len || !inout_cursor) return COMPLETION_NONE;
    size_t cursor = *inout_cursor;
    if (cursor > *inout_len) cursor = *inout_len;

    size_t word_begin = word_start(buf, cursor);
    /* If the word starts with '/' do VFS completion regardless of whether
     * it's the first token (e.g. `cat /tmp/<TAB>` → path completion). */
    if (cursor > word_begin && buf[word_begin] == '/') {
        return complete_vfs(buf, buf_size, word_begin,
                            inout_len, inout_cursor, orch_ep);
    }
    /* Otherwise builtin completion (only meaningful when it's the first
     * token · for later tokens, builtin completion won't match anything
     * harmful, so we still try it).
     *
     * If word is on the first token AND empty, list all builtins.  We
     * handle that by feeding the empty-prefix match path. */
    return complete_builtin(buf, buf_size, word_begin,
                            inout_len, inout_cursor);
}
