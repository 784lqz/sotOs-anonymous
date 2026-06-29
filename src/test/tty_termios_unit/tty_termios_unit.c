/* Host unit · `cc -I include src/test/tty_termios_unit/tty_termios_unit.c -o /tmp/ttu && /tmp/ttu`
 * Verifies the pure termios round-trip helper: a TCSETS stores the client's
 * struct, and the next TCGETS returns exactly what was set (raw-mode survives). */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "lucas/tty_termios.h"

int main(void) {
    struct lx_termios cur;
    lucas_tty_termios_default(&cur);             /* cooked default */
    assert(cur.c_lflag & 0x2);                   /* ICANON on by default (0x2) */

    struct lx_termios raw; memset(&raw, 0, sizeof(raw));
    raw.c_iflag = 0; raw.c_oflag = 0; raw.c_cflag = 0xbf;
    raw.c_lflag = 0;                             /* vim clears ICANON|ECHO|ISIG */
    raw.c_cc[6] = 1;                             /* VMIN=1 */
    lucas_tty_termios_set(&cur, &raw);           /* TCSETS */

    struct lx_termios got;
    lucas_tty_termios_get(&cur, &got);           /* TCGETS */
    assert(got.c_lflag == 0 && got.c_iflag == 0 && got.c_cc[6] == 1);  /* raw round-trips */
    printf("[tty-termios-unit] ALL PASS\n");
    return 0;
}
