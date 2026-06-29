/* Host unit · `cc -I include src/test/tty_fg_unit/tty_fg_unit.c -o /tmp/tfu && /tmp/tfu`
 * The foreground-reader predicate: SSH_RING + matching session + parked-on-console. */
#include <assert.h>
#include <stdio.h>
#include "lucas/tty_fg.h"

int main(void) {
    /* SSH_RING(1), session 7, WAITING_FOR_CONSOLE(10), want session 7 → match */
    assert(lucas_tty_fg_is_reader(1, 7, 10, 7) == 1);
    /* wrong session → no */
    assert(lucas_tty_fg_is_reader(1, 9, 10, 7) == 0);
    /* not SSH_RING (UART bbsh) → no */
    assert(lucas_tty_fg_is_reader(0, 7, 10, 7) == 0);
    /* SSH_RING + right session but RUNNING(0) not parked → no (not the fg reader) */
    assert(lucas_tty_fg_is_reader(1, 7, 0, 7) == 0);
    printf("[tty-fg-unit] ALL PASS\n");
    return 0;
}
