/*
 * sotOs · sotShell · v0.7 S1 · command history (RAM-only).
 *
 * 32-entry ring buffer.  Insertion order is preserved; nav cursor walks
 * backward from "after the newest entry" toward index 0.
 *
 * Memory · g_entries lives in BSS · ~4 KiB worst case.  No malloc.
 */

#include "history.h"

#include <string.h>

static char g_entries[SOTSHELL_HISTORY_SIZE][SOTSHELL_HISTORY_LINE_MAX];
static int  g_count = 0;       /* total entries, capped at SIZE */
static int  g_head  = 0;       /* next write slot (ring) */
static int  g_cursor = -1;     /* nav cursor · -1 = not walking */

void history_add(const char *line)
{
    if (!line || !*line) return;

    /* Skip duplicate of most-recent entry. */
    if (g_count > 0) {
        int last = (g_head - 1 + SOTSHELL_HISTORY_SIZE) % SOTSHELL_HISTORY_SIZE;
        if (strncmp(g_entries[last], line, SOTSHELL_HISTORY_LINE_MAX) == 0) {
            history_reset();
            return;
        }
    }

    size_t n = strlen(line);
    if (n >= SOTSHELL_HISTORY_LINE_MAX) n = SOTSHELL_HISTORY_LINE_MAX - 1;
    memcpy(g_entries[g_head], line, n);
    g_entries[g_head][n] = '\0';

    g_head = (g_head + 1) % SOTSHELL_HISTORY_SIZE;
    if (g_count < SOTSHELL_HISTORY_SIZE) g_count++;

    history_reset();
}

void history_reset(void)
{
    g_cursor = -1;
}

/* Index into ring · `back` counts from newest (0) toward oldest. */
static const char *history_at(int back)
{
    if (back < 0 || back >= g_count) return NULL;
    int slot = (g_head - 1 - back + 2 * SOTSHELL_HISTORY_SIZE) % SOTSHELL_HISTORY_SIZE;
    return g_entries[slot];
}

int history_prev(char *out_buf, size_t out_buf_size)
{
    if (g_count == 0 || !out_buf || out_buf_size == 0) return -1;

    int next = (g_cursor < 0) ? 0 : g_cursor + 1;
    if (next >= g_count) return -1;   /* already at oldest */

    const char *src = history_at(next);
    if (!src) return -1;

    size_t n = strlen(src);
    if (n >= out_buf_size) n = out_buf_size - 1;
    memcpy(out_buf, src, n);
    out_buf[n] = '\0';

    g_cursor = next;
    return (int)n;
}

int history_next(char *out_buf, size_t out_buf_size)
{
    if (!out_buf || out_buf_size == 0) return -1;
    if (g_cursor <= 0) {
        /* Either not walking, or at newest entry · stepping forward yields
         * an empty draft line. */
        g_cursor = -1;
        out_buf[0] = '\0';
        return 0;
    }

    g_cursor--;
    const char *src = history_at(g_cursor);
    if (!src) {
        out_buf[0] = '\0';
        return 0;
    }
    size_t n = strlen(src);
    if (n >= out_buf_size) n = out_buf_size - 1;
    memcpy(out_buf, src, n);
    out_buf[n] = '\0';
    return (int)n;
}
