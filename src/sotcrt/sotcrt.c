/*
 * sotcrt · the crt0 / C-runtime bridge for world-#3 NATIVE sotOs binaries.
 *
 * The seL4 process startup (_start → TLS + IPC-buffer + auxv → main) is provided
 * by sel4runtime (load-bearing · the seL4 ABI).  sotcrt is the THIN layer on top
 * that bridges the few STANDARD C-runtime symbols a native binary (and the seL4
 * support libs) reference to sotlibc's sot_* implementations — so a world-#3
 * binary links sotcrt + sotlibc + sel4 + sel4runtime and needs NO muslc (the
 * Linux libc the LUCAS guests use).  Add a bridge here only when the link reports
 * the symbol undefined (sel4runtime already provides its own memcpy/memset/etc.).
 */
#include "sotlibc/sotlibc.h"
#include <sel4/sel4.h>
#include <stdarg.h>
#include <stddef.h>

/* the native binary's stdout is the seL4 debug serial. */
static void serial_emit(char c, void *ctx) { (void)ctx; seL4_DebugPutChar(c); }

/* the standard-name libc symbols sotctl (and the seL4 support libs) reference,
 * bridged to sotlibc's sot_* implementations. */
int printf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = sot_vformat(serial_emit, (void *)0, fmt, ap);
    va_end(ap);
    return n;
}
int vprintf(const char *fmt, va_list ap) {
    return sot_vformat(serial_emit, (void *)0, fmt, ap);
}
int putchar(int c) { seL4_DebugPutChar((char)c); return c; }
int puts(const char *s) {
    while (*s) seL4_DebugPutChar(*s++);
    seL4_DebugPutChar('\n');
    return 0;
}
int snprintf(char *buf, size_t cap, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = sot_vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
    return n;
}
int vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap) {
    return sot_vsnprintf(buf, cap, fmt, ap);
}
unsigned long strtoul(const char *s, char **end, int base) {
    return sot_strtoul(s, end, base);
}
