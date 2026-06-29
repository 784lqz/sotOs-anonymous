#ifndef SOTNANO_H
#define SOTNANO_H

#include <stdint.h>
#include <stddef.h>
#include <sel4/sel4.h>

#define SOTNANO_BUF_MAX  8192
#define SOTNANO_UNDO_DEPTH 8     /* PR 10 · depth of the undo snapshot ring */

typedef struct {
    char     buf[SOTNANO_BUF_MAX];
    uint32_t gap_start;   /* cursor · first byte of gap */
    uint32_t gap_end;     /* one past last gap byte */
} sotnano_gap_t;

/* Gap buffer ops (PR 2). */
void     sotnano_gap_init(sotnano_gap_t *g);
uint32_t sotnano_gap_len(const sotnano_gap_t *g);            /* logical text length */
void     sotnano_gap_move_to(sotnano_gap_t *g, uint32_t pos);/* cursor → logical pos */
int      sotnano_gap_insert(sotnano_gap_t *g, char c);       /* 0 ok, -1 full */
int      sotnano_gap_delete_back(sotnano_gap_t *g);          /* backspace */
int      sotnano_gap_delete_fwd(sotnano_gap_t *g);           /* delete */
char     sotnano_gap_char_at(const sotnano_gap_t *g, uint32_t i); /* logical read */
uint32_t sotnano_gap_serialize(const sotnano_gap_t *g, char *out, uint32_t max);
void     sotnano_gap_cursor_rowcol(const sotnano_gap_t *g, int *row, int *col);

typedef struct {
    sotnano_gap_t gap;
    int   rows, cols;       /* screen size */
    int   scroll_top;       /* first visible logical row */
    int   dirty;
    int   paste_mode;       /* PR 7 · 1 between \e[200~ and \e[201~ markers */
    char  path[128];
    seL4_CPtr orch_ep;
} sotnano_editor_t;

void sotnano_probe_size(int (*getch)(void), int *rows, int *cols);

void sotnano_render(sotnano_editor_t *e);

/* Cursor movement helpers (PR 5) · used by the key-dispatch loop. */
void sotnano_move_vert(sotnano_editor_t *e, int delta);  /* up/down · preserve col */
void sotnano_move_horiz(sotnano_editor_t *e, int delta); /* left/right by one char  */
void sotnano_move_home(sotnano_editor_t *e);             /* line start               */
void sotnano_move_end(sotnano_editor_t *e);              /* line end                 */

/* Cut / uncut line (PR 8) · Ctrl+K / Ctrl+U. */
void sotnano_cut_line(sotnano_editor_t *e);              /* cut current logical line */
void sotnano_uncut_line(sotnano_editor_t *e);            /* paste cut buffer + \n    */

/* Search (PR 9) · Ctrl+W.  getch injected (serial_getchar is static in
 * main.c) · status-bar prompt then forward substring scan with wrap. */
void sotnano_search_fwd(sotnano_editor_t *e, int (*getch)(void));

/* Pure (IPC-free) per-key handler (PR 10).  Handles ONLY the edit keys
 * that need no terminal serial reads / orch IPC: printable insert,
 * Backspace, Enter, Ctrl+K cut, Ctrl+U uncut, Ctrl+Z undo.  ESC
 * sequences (arrows/paste), Ctrl+O/X/W/L stay inline in sotnano_run.
 * Returns 1 = keep running, 0 = should-exit (reserved · Ctrl+Z never
 * exits).  Drivable from the unit fixture with no orch (orch_ep==0). */
int  sotnano_handle_key(sotnano_editor_t *e, int c);

/* End the current undo batch (PR 10).  main.c calls this after any
 * non-edit key (cursor move / save / search) so the next edit starts a
 * fresh snapshot · Ctrl+Z then undoes a burst, not a single char. */
void sotnano_undo_end_batch(void);

/* Reset the undo ring · called on editor entry so a fresh nano session
 * does not inherit the previous session's snapshots. */
void sotnano_undo_reset(void);

/* Editor entry point (wired in later PRs). */
int sotnano_run(seL4_CPtr orch_ep, const char *path);

#endif /* SOTNANO_H */
