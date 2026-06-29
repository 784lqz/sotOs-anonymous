/*
 * sotOs · sotShell · v0.7 S1 · readline-style input layer.
 *
 * Drives a polling loop on the operator UART (via a getchar fn supplied at
 * init time) and implements:
 *   - ANSI escape state machine: \e [ X
 *       \e[A  Up      · history_prev → replace line
 *       \e[B  Down    · history_next → replace line
 *       \e[C  Right   · cursor right
 *       \e[D  Left    · cursor left
 *       \e[H  Home    · cursor to col 0
 *       \e[F  End     · cursor to end
 *   - Backspace (\b / 0x7F) at cursor position with redraw
 *   - Tab     · completion_complete · redraw
 *   - Enter   · history_add(buf), return chars written
 *   - Printable 0x20..0x7E · insert at cursor, advance
 *
 * Line redraw convention (used after history/tab/edits at non-end positions):
 *   1. emit "\r"                 · cursor to column 0
 *   2. emit "sotos> "            · re-print the prompt
 *   3. emit "\e[K"               · clear to end of line
 *   4. emit the buffer
 *   5. if cursor != end, emit "\e[<n>D" to walk back n columns
 *
 * The prompt "sotos> " is hard-coded · main.c::cmd_interactive prints it
 * BEFORE calling read_line, so the redraw path must match.
 */

#include "readline.h"
#include "history.h"
#include "completion.h"

#include <stdio.h>
#include <string.h>
#include <sel4/sel4.h>

#define SOTSHELL_PROMPT "sotos> "

static sotshell_getchar_fn g_getchar = NULL;
static seL4_CPtr           g_orch_ep = 0;

void sotshell_readline_init(sotshell_getchar_fn getchar_fn,
                             seL4_CPtr orch_ep)
{
    g_getchar = getchar_fn;
    g_orch_ep = orch_ep;
}

/* Print an unsigned int in base 10 (small, avoids pulling extra printf). */
static void print_uint(unsigned n)
{
    char tmp[16];
    int i = 0;
    if (n == 0) { putchar('0'); return; }
    while (n > 0 && i < 16) { tmp[i++] = (char)('0' + (n % 10)); n /= 10; }
    while (i > 0) { putchar(tmp[--i]); }
}

/* Redraw the line + reposition the cursor. */
static void redraw_line(const char *buf, size_t len, size_t cursor)
{
    /* \r · prompt · clear to EOL · buf · maybe step back */
    printf("\r" SOTSHELL_PROMPT);
    printf("\033[K");
    if (len > 0) {
        fwrite(buf, 1, len, stdout);
    }
    if (cursor < len) {
        size_t back = len - cursor;
        printf("\033[");
        print_uint((unsigned)back);
        printf("D");
    }
    fflush(stdout);
}

int sotshell_readline(char *buf, size_t buf_size)
{
    if (!g_getchar || !buf || buf_size < 2) return -1;

    size_t len = 0;
    size_t cursor = 0;
    buf[0] = '\0';

    /* ANSI escape parser state:
     *  0 = normal
     *  1 = saw ESC, waiting for '['
     *  2 = inside CSI, waiting for final byte
     */
    int esc_state = 0;
    /* History reset · a fresh edit ignores any previous walk. */
    history_reset();

    while (len < buf_size - 1) {
        int c = g_getchar();
        if (c == 0) {
            seL4_Yield();
            continue;
        }

        if (esc_state == 1) {
            if (c == '[') { esc_state = 2; continue; }
            /* Lone ESC or unrecognized · drop and resume. */
            esc_state = 0;
            continue;
        }
        if (esc_state == 2) {
            /* Final byte of CSI · consume any params we don't recognise. */
            if (c >= '0' && c <= '9') {
                /* Numeric param · we don't use them, keep state. */
                continue;
            }
            if (c == ';') continue;
            switch (c) {
                case 'A': {  /* Up · history prev */
                    char tmp[SOTSHELL_HISTORY_LINE_MAX];
                    int n = history_prev(tmp, sizeof(tmp));
                    if (n > 0) {
                        size_t nn = (size_t)n;
                        if (nn >= buf_size) nn = buf_size - 1;
                        memcpy(buf, tmp, nn);
                        buf[nn] = '\0';
                        len = nn;
                        cursor = len;
                        redraw_line(buf, len, cursor);
                    }
                    break;
                }
                case 'B': {  /* Down · history next */
                    char tmp[SOTSHELL_HISTORY_LINE_MAX];
                    int n = history_next(tmp, sizeof(tmp));
                    if (n >= 0) {
                        size_t nn = (size_t)n;
                        if (nn >= buf_size) nn = buf_size - 1;
                        memcpy(buf, tmp, nn);
                        buf[nn] = '\0';
                        len = nn;
                        cursor = len;
                        redraw_line(buf, len, cursor);
                    }
                    break;
                }
                case 'C': {  /* Right */
                    if (cursor < len) {
                        cursor++;
                        printf("\033[C");
                        fflush(stdout);
                    }
                    break;
                }
                case 'D': {  /* Left */
                    if (cursor > 0) {
                        cursor--;
                        printf("\033[D");
                        fflush(stdout);
                    }
                    break;
                }
                case 'H': {  /* Home */
                    cursor = 0;
                    redraw_line(buf, len, cursor);
                    break;
                }
                case 'F': {  /* End */
                    cursor = len;
                    redraw_line(buf, len, cursor);
                    break;
                }
                default:
                    /* Unknown final byte · ignore. */
                    break;
            }
            esc_state = 0;
            continue;
        }

        /* esc_state == 0 · normal path */
        if (c == 0x1B) {           /* ESC */
            esc_state = 1;
            continue;
        }
        if (c == '\r' || c == '\n') {
            putchar('\n');
            fflush(stdout);
            buf[len] = '\0';
            history_add(buf);
            return (int)len;
        }
        if (c == '\b' || c == 0x7F) {
            if (cursor > 0) {
                memmove(buf + cursor - 1, buf + cursor, len - cursor);
                cursor--;
                len--;
                buf[len] = '\0';
                redraw_line(buf, len, cursor);
            }
            continue;
        }
        if (c == '\t') {
            completion_result_t r = completion_complete(buf, buf_size,
                                                         &len, &cursor,
                                                         g_orch_ep);
            if (r != COMPLETION_NONE) {
                redraw_line(buf, len, cursor);
            }
            continue;
        }
        if (c >= 0x20 && c < 0x7F) {
            if (len + 1 >= buf_size) continue;  /* full · drop */
            if (cursor < len) {
                /* Insert · shift tail right by one. */
                memmove(buf + cursor + 1, buf + cursor, len - cursor);
                buf[cursor] = (char)c;
                cursor++;
                len++;
                buf[len] = '\0';
                redraw_line(buf, len, cursor);
            } else {
                buf[cursor++] = (char)c;
                len++;
                buf[len] = '\0';
                putchar(c);
                fflush(stdout);
            }
            /* Editing invalidates any history walk in progress. */
            history_reset();
            continue;
        }
        /* Unknown control byte · ignore. */
    }
    buf[len] = '\0';
    history_add(buf);
    return (int)len;
}
