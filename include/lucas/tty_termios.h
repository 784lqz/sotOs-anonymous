#ifndef LUCAS_TTY_TERMIOS_H
#define LUCAS_TTY_TERMIOS_H
#include <string.h>
#include "lucas/linux_abi.h"   /* struct lx_termios */

/* Plausible cooked default (matches the historic hardcoded TCGETS reply). */
static inline void lucas_tty_termios_default(struct lx_termios *t) {
    memset(t, 0, sizeof(*t));
    t->c_iflag = 0x4500; t->c_oflag = 0x5; t->c_cflag = 0xbf; t->c_lflag = 0x8a3b;
}
static inline void lucas_tty_termios_set(struct lx_termios *cur, const struct lx_termios *in) { *cur = *in; }
static inline void lucas_tty_termios_get(const struct lx_termios *cur, struct lx_termios *out) { *out = *cur; }
#endif
