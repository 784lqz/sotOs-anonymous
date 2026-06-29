/*
 * sotOs · sotShell · v0.7 S1 · readline-style input layer.
 *
 * Polls serial_getchar via the IO_Port cap (set up by main.c) and provides
 *   - arrow-key cursor movement (Left/Right/Home/End)
 *   - history navigation (Up/Down) via history.h
 *   - tab completion via completion.h
 *   - backspace + insert at arbitrary cursor positions
 *
 * Returns the length of the assembled line on Enter, or -1 on fatal error
 * (in which case the caller should fall back to the simple poll loop).
 *
 * The implementation reuses the existing serial_getchar() in main.c via a
 * function pointer · readline.c does not poke the IO_Port cap directly so
 * the layering stays clean.
 */

#ifndef SOTOS_SOTSHELL_READLINE_H
#define SOTOS_SOTSHELL_READLINE_H

#include <stddef.h>
#include <sel4/sel4.h>

/* Type of the serial-poll callback.  Returns 0 if no byte is available,
 * otherwise the byte (0x01-0xFF).  Matches main.c's serial_getchar(). */
typedef int (*sotshell_getchar_fn)(void);

/* One-time install of the serial backend + orch EP cap.  Called from main.c
 * before the first readline() invocation. */
void sotshell_readline_init(sotshell_getchar_fn getchar_fn,
                             seL4_CPtr orch_ep);

/* Read one line into buf (NUL-terminated).  Returns chars written (excluding
 * NUL) on Enter, or -1 if no backend is installed (caller falls back). */
int  sotshell_readline(char *buf, size_t buf_size);

#endif /* SOTOS_SOTSHELL_READLINE_H */
