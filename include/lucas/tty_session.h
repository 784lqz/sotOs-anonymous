#ifndef LUCAS_TTY_SESSION_H
#define LUCAS_TTY_SESSION_H
#include <stdint.h>
#include <stddef.h>
/* Extract cols/rows from an SSH pty-req payload (skips the leading TERM string).
 * Returns 0 on success, -1 on a short/truncated buffer. */
int lucas_tty_ptyreq_winsize(const uint8_t *p, size_t len, uint16_t *cols, uint16_t *rows);
/* Extract cols/rows from a window-change payload (cols,rows,wpx,hpx). 0 / -1. */
int lucas_tty_winch_winsize(const uint8_t *p, size_t len, uint16_t *cols, uint16_t *rows);
#endif
