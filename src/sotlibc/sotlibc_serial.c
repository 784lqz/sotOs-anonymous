/*
 * sotlibc · the serial sink (seL4-only · NOT host-testable).
 *
 * A world-#3 native binary's stdout is the seL4 debug serial (seL4_DebugPutChar),
 * NOT a Linux write(2)/fd.  sot_printf drives the host-free sot_vformat engine
 * (sotlibc.c) through this putchar.
 */
#include "sotlibc/sotlibc.h"
#include <sel4/sel4.h>

void sot_putchar(char c) { seL4_DebugPutChar(c); }

static void serial_emit(char c, void *ctx) { (void)ctx; seL4_DebugPutChar(c); }

int sot_printf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = sot_vformat(serial_emit, 0, fmt, ap);
    va_end(ap);
    return n;
}
