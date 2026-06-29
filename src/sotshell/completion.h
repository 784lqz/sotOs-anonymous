/*
 * sotOs · sotShell · v0.7 S1 · tab completion.
 *
 * Matches the current word (from start of buf to cursor_pos) against:
 *   1. The built-in command list.
 *   2. If the word starts with '/', the orch-side VFS via ORCH_OP_SOTFS_LS
 *      (longest path prefix · list parent directory · filter).
 *
 * On a unique match the buffer is rewritten in place and the new length is
 * returned via *inout_len; *inout_cursor advances accordingly.
 * On multiple matches the completion list is printed (caller will redraw).
 * On no match nothing is changed.
 */

#ifndef SOTOS_SOTSHELL_COMPLETION_H
#define SOTOS_SOTSHELL_COMPLETION_H

#include <stddef.h>
#include <sel4/sel4.h>

/* Result codes for diagnostics · readline uses the return value only to
 * decide whether the line needs a redraw. */
typedef enum {
    COMPLETION_NONE     = 0,  /* no match  · buffer unchanged */
    COMPLETION_UNIQUE   = 1,  /* unique completion · buffer rewritten */
    COMPLETION_MULTIPLE = 2,  /* multiple matches · list printed to stdout */
} completion_result_t;

/* Run tab completion in place.  buf is NUL-terminated.
 * On COMPLETION_UNIQUE / COMPLETION_MULTIPLE *inout_len and *inout_cursor are
 * updated to reflect the new contents.
 *
 * orch_ep may be 0 · in that case VFS-path completion is skipped (only
 * built-in commands considered). */
completion_result_t completion_complete(char *buf,
                                         size_t buf_size,
                                         size_t *inout_len,
                                         size_t *inout_cursor,
                                         seL4_CPtr orch_ep);

#endif /* SOTOS_SOTSHELL_COMPLETION_H */
