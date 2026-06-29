/*
 * sotOs · sotShell · v0.7 S1 · command history (RAM-only ring buffer).
 *
 * 32-entry ring buffer.  Up/Down navigation copies entries into the caller's
 * line buffer.  History is not persisted to disk (operator-only · sotShell
 * runs as a native sel4 process with no FS of its own).
 */

#ifndef SOTOS_SOTSHELL_HISTORY_H
#define SOTOS_SOTSHELL_HISTORY_H

#include <stddef.h>

#define SOTSHELL_HISTORY_SIZE 32
#define SOTSHELL_HISTORY_LINE_MAX 128

/* Add a line to history.  Empty lines are ignored.  Duplicate of the most
 * recent entry is also ignored. */
void history_add(const char *line);

/* Move the history cursor backward (older) and copy that entry into out_buf.
 * Returns the length on success, -1 if no older entry exists.
 * The cursor is sticky · history_reset() must be called when a new edit
 * begins (i.e. when the user types or hits Enter). */
int  history_prev(char *out_buf, size_t out_buf_size);

/* Move the history cursor forward (newer).  Returns length, or -1 once we
 * walk past the most recent entry (in which case out_buf is set to ""). */
int  history_next(char *out_buf, size_t out_buf_size);

/* Reset the navigation cursor to "no history walk in progress".  Called when
 * the user submits a line or starts a fresh edit. */
void history_reset(void);

#endif /* SOTOS_SOTSHELL_HISTORY_H */
