/* sotOs · sotnano · gap-buffer text model. */
#include "sotnano.h"
#include <string.h>
#include <stdio.h>

void sotnano_gap_init(sotnano_gap_t *g) {
    g->gap_start = 0;
    g->gap_end   = SOTNANO_BUF_MAX;
}

uint32_t sotnano_gap_len(const sotnano_gap_t *g) {
    return SOTNANO_BUF_MAX - (g->gap_end - g->gap_start);
}

void sotnano_gap_move_to(sotnano_gap_t *g, uint32_t pos) {
    uint32_t len = sotnano_gap_len(g);
    if (pos > len) pos = len;
    if (pos < g->gap_start) {
        uint32_t n = g->gap_start - pos;             /* move n chars right across gap */
        memmove(&g->buf[g->gap_end - n], &g->buf[pos], n);
        g->gap_start -= n;
        g->gap_end   -= n;
    } else if (pos > g->gap_start) {
        uint32_t n = pos - g->gap_start;             /* move n chars left across gap */
        memmove(&g->buf[g->gap_start], &g->buf[g->gap_end], n);
        g->gap_start += n;
        g->gap_end   += n;
    }
}

int sotnano_gap_insert(sotnano_gap_t *g, char c) {
    if (g->gap_start >= g->gap_end) return -1;       /* gap empty → buffer full */
    g->buf[g->gap_start++] = c;
    return 0;
}

int sotnano_gap_delete_back(sotnano_gap_t *g) {
    if (g->gap_start == 0) return -1;
    g->gap_start--;
    return 0;
}

int sotnano_gap_delete_fwd(sotnano_gap_t *g) {
    if (g->gap_end >= SOTNANO_BUF_MAX) return -1;
    g->gap_end++;
    return 0;
}

char sotnano_gap_char_at(const sotnano_gap_t *g, uint32_t i) {
    if (i < g->gap_start) return g->buf[i];
    return g->buf[i + (g->gap_end - g->gap_start)];  /* skip the gap */
}

uint32_t sotnano_gap_serialize(const sotnano_gap_t *g, char *out, uint32_t max) {
    uint32_t len = sotnano_gap_len(g);
    if (len > max) len = max;
    for (uint32_t i = 0; i < len; ++i) out[i] = sotnano_gap_char_at(g, i);
    return len;
}

void sotnano_gap_cursor_rowcol(const sotnano_gap_t *g, int *row, int *col) {
    int r = 0, c = 0;
    for (uint32_t i = 0; i < g->gap_start; ++i) {   /* scan text before the gap */
        if (g->buf[i] == '\n') { r++; c = 0; }
        else c++;
    }
    *row = r; *col = c;
}

/* Count total logical rows (newlines + 1). */
static int sotnano_total_rows(const sotnano_gap_t *g) {
    int rows = 1; uint32_t len = sotnano_gap_len(g);
    for (uint32_t i = 0; i < len; ++i)
        if (sotnano_gap_char_at(g, i) == '\n') rows++;
    return rows;
}

/* Logical offset of the first char of logical row `target` (0-based). */
static uint32_t sotnano_row_start(const sotnano_gap_t *g, int target) {
    if (target <= 0) return 0;
    int row = 0; uint32_t len = sotnano_gap_len(g);
    for (uint32_t i = 0; i < len; ++i)
        if (sotnano_gap_char_at(g, i) == '\n') { if (++row == target) return i + 1; }
    return len;
}

void sotnano_render(sotnano_editor_t *e) {
    int text_rows = e->rows - 2;             /* title + status reserve 2 */
    int cur_row, cur_col;
    sotnano_gap_cursor_rowcol(&e->gap, &cur_row, &cur_col);

    /* keep cursor visible */
    if (cur_row < e->scroll_top) e->scroll_top = cur_row;
    if (cur_row >= e->scroll_top + text_rows) e->scroll_top = cur_row - text_rows + 1;

    printf("\033[H");                        /* home (no full clear · per-row \e[K) */
    /* Title bar (reverse video). */
    printf("\033[7m\033[K sotnano · %s · %d lines%s\033[0m\r\n",
           e->path, sotnano_total_rows(&e->gap), e->dirty ? " · [modified]" : "");

    uint32_t len = sotnano_gap_len(&e->gap);
    for (int sr = 0; sr < text_rows; ++sr) {
        int lr = e->scroll_top + sr;
        printf("\033[K");
        if (lr < sotnano_total_rows(&e->gap)) {
            uint32_t off = sotnano_row_start(&e->gap, lr);
            int col = 0;
            for (uint32_t i = off; i < len; ++i) {
                char ch = sotnano_gap_char_at(&e->gap, i);
                if (ch == '\n') break;
                if (col >= e->cols - 1) { printf(">"); break; }
                putchar(ch); col++;
            }
        } else {
            printf("~");
        }
        printf("\r\n");
    }
    /* Status bar. */
    printf("\033[7m\033[K ^O Save  ^X Exit  ^K Cut  ^U Uncut  ^W Search  ^Z Undo\033[0m");

    /* Place hardware cursor. */
    int screen_row = (cur_row - e->scroll_top) + 2;   /* +1 title, +1 to 1-based */
    int screen_col = (cur_col < e->cols - 1 ? cur_col : e->cols - 1) + 1;
    printf("\033[%d;%dH", screen_row, screen_col);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* PR 5 · cursor movement helpers.  Cursor position is gap_start        */
/* (logical).  Movement maps row/col intent back to a logical offset.   */
/* Exposed via sotnano.h so the run loop in main.c can dispatch keys.    */
/* ------------------------------------------------------------------ */

/* Move cursor up/down by one display row, preserving column where possible. */
void sotnano_move_vert(sotnano_editor_t *e, int delta) {
    int row, col; sotnano_gap_cursor_rowcol(&e->gap, &row, &col);
    int target = row + delta;
    if (target < 0) target = 0;
    int total = sotnano_total_rows(&e->gap);
    if (target >= total) target = total - 1;
    uint32_t start = sotnano_row_start(&e->gap, target);
    /* advance col chars within the target line (stop at newline) */
    uint32_t len = sotnano_gap_len(&e->gap);
    uint32_t pos = start; int c = 0;
    while (pos < len && c < col && sotnano_gap_char_at(&e->gap, pos) != '\n') { pos++; c++; }
    sotnano_gap_move_to(&e->gap, pos);
}

void sotnano_move_horiz(sotnano_editor_t *e, int delta) {
    uint32_t pos = e->gap.gap_start;
    if (delta < 0 && pos > 0) sotnano_gap_move_to(&e->gap, pos - 1);
    else if (delta > 0 && pos < sotnano_gap_len(&e->gap)) sotnano_gap_move_to(&e->gap, pos + 1);
}

void sotnano_move_home(sotnano_editor_t *e) {
    int row, col; sotnano_gap_cursor_rowcol(&e->gap, &row, &col);
    sotnano_gap_move_to(&e->gap, sotnano_row_start(&e->gap, row));
}
void sotnano_move_end(sotnano_editor_t *e) {
    int row, col; sotnano_gap_cursor_rowcol(&e->gap, &row, &col);
    uint32_t pos = sotnano_row_start(&e->gap, row);
    uint32_t len = sotnano_gap_len(&e->gap);
    while (pos < len && sotnano_gap_char_at(&e->gap, pos) != '\n') pos++;
    sotnano_gap_move_to(&e->gap, pos);
}

/* ------------------------------------------------------------------ */
/* PR 8 · cut / uncut line (Ctrl+K / Ctrl+U).  These live here beside  */
/* sotnano_row_start / sotnano_total_rows (static) which they need ·   */
/* exposed to the run loop in main.c via sotnano.h prototypes.         */
/* ------------------------------------------------------------------ */

static char g_sotnano_cut[SOTNANO_BUF_MAX]; static uint32_t g_sotnano_cut_len;

void sotnano_cut_line(sotnano_editor_t *e) {
    int row, col; sotnano_gap_cursor_rowcol(&e->gap, &row, &col);
    uint32_t start = sotnano_row_start(&e->gap, row);
    uint32_t len = sotnano_gap_len(&e->gap);
    uint32_t end = start;
    while (end < len && sotnano_gap_char_at(&e->gap, end) != '\n') end++;
    /* copy [start,end) to cut buffer */
    g_sotnano_cut_len = 0;
    for (uint32_t i = start; i < end && g_sotnano_cut_len < SOTNANO_BUF_MAX; ++i)
        g_sotnano_cut[g_sotnano_cut_len++] = sotnano_gap_char_at(&e->gap, i);
    /* delete [start, end] including trailing newline if present */
    uint32_t del_end = (end < len) ? end + 1 : end;
    sotnano_gap_move_to(&e->gap, del_end);
    for (uint32_t i = start; i < del_end; ++i) sotnano_gap_delete_back(&e->gap);
    e->dirty = 1;
}

void sotnano_uncut_line(sotnano_editor_t *e) {
    for (uint32_t i = 0; i < g_sotnano_cut_len; ++i)
        sotnano_gap_insert(&e->gap, g_sotnano_cut[i]);
    sotnano_gap_insert(&e->gap, '\n');
    e->dirty = 1;
}

/* ------------------------------------------------------------------ */
/* PR 9 · search (Ctrl+W) + status-bar prompt.                          */
/* serial_getchar is `static` in main.c → sotnano.c cannot link to it.  */
/* Inject `getch` (just like sotnano_probe_size) so search is testable  */
/* + decoupled · the dispatch in main.c passes serial_getchar.          */
/* ------------------------------------------------------------------ */

/* Read a line into `out` from the status bar · Enter ends, Esc cancels (ret 0). */
static int sotnano_prompt(sotnano_editor_t *e, const char *label,
                          char *out, uint32_t max, int (*getch)(void)) {
    uint32_t n = 0;
    for (;;) {
        printf("\033[%d;1H\033[7m\033[K %s%.*s\033[0m", e->rows, label, (int)n, out);
        fflush(stdout);
        int c = 0; while ((c = getch()) == 0) seL4_Yield();
        if (c == 0x0D || c == 0x0A) { out[n] = '\0'; return 1; }
        if (c == 0x1B) return 0;                       /* Esc · cancel */
        if ((c == 0x7F || c == 0x08) && n > 0) { n--; continue; }
        if (c >= 0x20 && c < 0x7F && n < max - 1) out[n++] = (char)c;
    }
}

static char g_sotnano_search[128];

void sotnano_search_fwd(sotnano_editor_t *e, int (*getch)(void)) {
    if (!sotnano_prompt(e, "Search: ", g_sotnano_search, sizeof(g_sotnano_search), getch))
        return;
    uint32_t qlen = (uint32_t)strlen(g_sotnano_search);
    if (qlen == 0) return;
    uint32_t len = sotnano_gap_len(&e->gap);
    uint32_t from = e->gap.gap_start + 1;
    for (uint32_t i = from; i + qlen <= len; ++i) {
        uint32_t k = 0;
        while (k < qlen && sotnano_gap_char_at(&e->gap, i + k) == g_sotnano_search[k]) k++;
        if (k == qlen) { sotnano_gap_move_to(&e->gap, i); return; }
    }
    /* wrap from start */
    for (uint32_t i = 0; i + qlen <= from && i + qlen <= len; ++i) {
        uint32_t k = 0;
        while (k < qlen && sotnano_gap_char_at(&e->gap, i + k) == g_sotnano_search[k]) k++;
        if (k == qlen) { sotnano_gap_move_to(&e->gap, i); return; }
    }
    /* not found · status shown by next render */
}

/* ------------------------------------------------------------------ */
/* PR 10 · undo snapshot ring + pure per-key handler.                  */
/*                                                                      */
/* The full sotnano_run loop in main.c mixes IPC/serial keys (Ctrl+O    */
/* save, Ctrl+X dirty-prompt, Ctrl+W search, ESC arrows/paste · all     */
/* need extra serial_getchar reads or an orch_ep) with pure edit keys.  */
/* sotnano_handle_key handles ONLY the pure subset so the headless unit */
/* fixture can drive synthetic keystrokes with no terminal / no orch.   */
/*                                                                      */
/* Undo batching: snapshot is taken on the FIRST edit key of a burst    */
/* (g_undo_pending==0), then g_undo_pending is set so subsequent chars  */
/* of the same burst share that one snapshot.  main.c calls             */
/* sotnano_undo_end_batch() after any non-edit key (cursor move / save  */
/* / search / paste) to reset the flag · so Ctrl+Z rolls back a whole   */
/* burst rather than one character.                                     */
/* ------------------------------------------------------------------ */

typedef struct { char text[SOTNANO_BUF_MAX]; uint32_t len; uint32_t cursor; } sotnano_snap_t;
static sotnano_snap_t g_undo[SOTNANO_UNDO_DEPTH];
static int g_undo_top;        /* number of valid snapshots */
static int g_undo_pending;    /* 1 if an edit batch has started since last snapshot */

static void sotnano_snapshot(sotnano_editor_t *e) {
    if (g_undo_top == SOTNANO_UNDO_DEPTH) {           /* ring · drop oldest */
        memmove(&g_undo[0], &g_undo[1], (SOTNANO_UNDO_DEPTH - 1) * sizeof(g_undo[0]));
        g_undo_top--;
    }
    sotnano_snap_t *s = &g_undo[g_undo_top++];
    s->len = sotnano_gap_serialize(&e->gap, s->text, SOTNANO_BUF_MAX);
    s->cursor = e->gap.gap_start;
}

static void sotnano_restore(sotnano_editor_t *e) {
    if (g_undo_top == 0) return;
    sotnano_snap_t *s = &g_undo[--g_undo_top];
    sotnano_gap_init(&e->gap);
    for (uint32_t i = 0; i < s->len; ++i) sotnano_gap_insert(&e->gap, s->text[i]);
    sotnano_gap_move_to(&e->gap, s->cursor);
    e->dirty = 1;
}

void sotnano_undo_end_batch(void) {
    g_undo_pending = 0;                               /* next edit starts a fresh snapshot */
}

/* Reset the undo ring · MUST be called on editor entry so a second nano
 * invocation does not inherit the previous session's snapshots (an early
 * Ctrl+Z would otherwise restore the prior file's text into the new one). */
void sotnano_undo_reset(void) {
    g_undo_top = 0;
    g_undo_pending = 0;
}

/* Snapshot before the first edit of a batch.  No-op while a batch is
 * already pending so a burst of chars shares one snapshot. */
static void sotnano_undo_begin_batch(sotnano_editor_t *e) {
    if (g_undo_pending == 0) {
        sotnano_snapshot(e);
        g_undo_pending = 1;
    }
}

int sotnano_handle_key(sotnano_editor_t *e, int c) {
    if (c == 0x1A) {                          /* Ctrl+Z · undo last batch */
        sotnano_restore(e);
        sotnano_undo_end_batch();             /* a fresh edit starts a new snapshot */
        return 1;
    } else if (c == 0x0B) {                   /* Ctrl+K · cut line */
        sotnano_undo_begin_batch(e);
        sotnano_cut_line(e);
    } else if (c == 0x15) {                   /* Ctrl+U · uncut line */
        sotnano_undo_begin_batch(e);
        sotnano_uncut_line(e);
    } else if (c == 0x7F || c == 0x08) {      /* Backspace */
        sotnano_undo_begin_batch(e);
        sotnano_gap_delete_back(&e->gap); e->dirty = 1;
    } else if (c == 0x0D || c == 0x0A) {      /* Enter */
        /* Interactive newline is a natural undo boundary · close the
         * current batch then snapshot fresh so the line just typed and the
         * next line are undoable independently (Ctrl+Z after "abc<CR>d" →
         * "abc").  Inside a bracketed paste the whole block is ONE batch,
         * so a pasted newline must NOT split it · just join the open batch. */
        if (!e->paste_mode) sotnano_undo_end_batch();
        sotnano_undo_begin_batch(e);
        sotnano_gap_insert(&e->gap, '\n'); e->dirty = 1;
    } else if (c >= 0x20 && c < 0x7F) {       /* printable */
        sotnano_undo_begin_batch(e);
        if (sotnano_gap_insert(&e->gap, (char)c) < 0)
            /* full · ignore (status shown by render of [modified]) */;
        else e->dirty = 1;
    }
    return 1;
}

void sotnano_probe_size(int (*getch)(void), int *rows, int *cols) {
    *rows = 24; *cols = 80;                 /* fallback */
    printf("\033[999;999H\033[6n");
    fflush(stdout);
    /* Expect "\033[<rows>;<cols>R".  Bounded poll loop ~ up to 20000 idle reads. */
    int state = 0, r = 0, c = 0, idle = 0;
    while (idle < 20000) {
        int ch = getch();
        if (ch == 0) { idle++; continue; }
        idle = 0;
        switch (state) {
            case 0: if (ch == 0x1B) state = 1; break;          /* ESC */
            case 1: state = (ch == '[') ? 2 : 0; break;
            case 2: if (ch >= '0' && ch <= '9') { r = r*10 + (ch-'0'); }
                    else if (ch == ';') state = 3; else state = 0; break;
            case 3: if (ch >= '0' && ch <= '9') { c = c*10 + (ch-'0'); }
                    else if (ch == 'R') {
                        if (r >= 4 && r <= 200 && c >= 20 && c <= 400) {
                            *rows = r; *cols = c;
                        }
                        return;
                    } else state = 0;
                    break;
        }
    }
    /* timeout → keep fallback */
}
