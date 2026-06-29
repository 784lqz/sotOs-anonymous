/* sotOs · sotnano gap-buffer unit test.
 *
 * Standalone ELF spawned by root at boot.  Mirrors the wal-unit /
 * procd-unit fixtures: prints PASS/FAIL lines that scripts/smoke-procd.sh
 * greps from the QEMU serial log.  Compiles the freestanding gap-buffer
 * ops from src/sotshell/sotnano.c directly (string.h only · no IPC).
 */
#include <stdio.h>
#include <string.h>
#include <sel4/sel4.h>
#include "sotnano.h"

static int fails = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("[sotnano-unit] PASS %s\n", name); \
    else { printf("[sotnano-unit] FAIL %s\n", name); fails++; } } while (0)

static void load(sotnano_gap_t *g, const char *s) {
    sotnano_gap_init(g);
    for (const char *p = s; *p; ++p) sotnano_gap_insert(g, *p);
}

/* PR 10 · headless selftest · drives synthetic keystrokes through the
 * pure, IPC-free sotnano_handle_key (orch_ep==0 · no terminal, no orch)
 * and asserts buffer state + undo.  The IPC paths (Ctrl+O save / Ctrl+X
 * exit) live in sotnano_run, not handle_key, so no orch is needed. */
static void selftest(void) {
    sotnano_editor_t e; memset(&e, 0, sizeof(e));
    e.rows = 24; e.cols = 80; e.orch_ep = 0; sotnano_gap_init(&e.gap);

    const char *seq = "abc";                       /* type abc */
    for (const char *p = seq; *p; ++p) sotnano_handle_key(&e, *p);
    sotnano_handle_key(&e, 0x0D);                  /* Enter */
    sotnano_handle_key(&e, 'd');
    char out[64]; uint32_t n = sotnano_gap_serialize(&e.gap, out, sizeof(out));
    out[n] = '\0';
    CHECK(strcmp(out, "abc\nd") == 0, "selftest_type_enter");

    sotnano_handle_key(&e, 0x1A);                  /* Ctrl+Z · undo last batch */
    n = sotnano_gap_serialize(&e.gap, out, sizeof(out)); out[n] = '\0';
    CHECK(strcmp(out, "abc") == 0, "selftest_undo");

    printf("[sotnano-selftest] %s\n", "done");
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    printf("[sotnano-unit] start\n");
    sotnano_gap_t g;

    /* insert + length */
    load(&g, "hello");
    CHECK(sotnano_gap_len(&g) == 5, "insert_len");

    /* serialize round-trip */
    char out[64]; uint32_t n = sotnano_gap_serialize(&g, out, sizeof(out));
    out[n] = '\0';
    CHECK(strcmp(out, "hello") == 0, "serialize_roundtrip");

    /* move_to + insert in middle */
    sotnano_gap_move_to(&g, 2);
    sotnano_gap_insert(&g, 'X');           /* "heXllo" */
    n = sotnano_gap_serialize(&g, out, sizeof(out)); out[n] = '\0';
    CHECK(strcmp(out, "heXllo") == 0, "insert_middle");

    /* delete_back at cursor (after X, pos=3) */
    sotnano_gap_delete_back(&g);           /* removes X → "hello" */
    n = sotnano_gap_serialize(&g, out, sizeof(out)); out[n] = '\0';
    CHECK(strcmp(out, "hello") == 0, "delete_back");

    /* delete_fwd at pos 2 removes 'l' → "helo" */
    sotnano_gap_move_to(&g, 2);
    sotnano_gap_delete_fwd(&g);
    n = sotnano_gap_serialize(&g, out, sizeof(out)); out[n] = '\0';
    CHECK(strcmp(out, "helo") == 0, "delete_fwd");

    /* cursor_rowcol on multi-line */
    sotnano_gap_init(&g);
    load(&g, "ab\ncd\nef");                /* cursor at end (pos 8) */
    int row, col; sotnano_gap_cursor_rowcol(&g, &row, &col);
    CHECK(row == 2 && col == 2, "cursor_rowcol_end");

    sotnano_gap_move_to(&g, 4);            /* "ab\nc|d\nef" → row1 col1 */
    sotnano_gap_cursor_rowcol(&g, &row, &col);
    CHECK(row == 1 && col == 1, "cursor_rowcol_mid");

    /* PR 10 · headless key-dispatch + undo selftest. */
    selftest();

    if (fails == 0) printf("[sotnano-unit] ALL PASS\n");
    else            printf("[sotnano-unit] %d FAILED\n", fails);

    while (1) seL4_Yield();
}
