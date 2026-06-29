#ifndef LUCAS_TTY_FG_H
#define LUCAS_TTY_FG_H
#include <stdint.h>
/* The SSH-session foreground console reader: an SSH-ring box belonging to
 * `want_session`, currently parked in read(fd0) (WAITING_FOR_CONSOLE==10).
 * Pure (no seL4) so it host-unit-tests; the caller supplies the per-box fields.
 * console_src: LUCAS_CONSOLE_SRC_SSH_RING==1.  state: SOTBOX_STATE_WAITING_FOR_CONSOLE==10. */
static inline int lucas_tty_fg_is_reader(uint8_t console_src, uint32_t cow_session,
                                         int state, uint32_t want_session) {
    return console_src == 1 /*SSH_RING*/ && cow_session != 0 &&
           cow_session == want_session && state == 10 /*WAITING_FOR_CONSOLE*/;
}
#endif
