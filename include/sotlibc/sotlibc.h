#ifndef SOTLIBC_H
#define SOTLIBC_H
/*
 * sotlibc · the freestanding C runtime for world-#3 NATIVE sotOs binaries.
 *
 * NOT a Linux libc.  The third world (sotOs-native · sotctl) does not pretend to
 * be Linux (LUCAS/muslc) or Win32 (Wine) — it KNOWS it is on sotOs and talks
 * sotabi to truth-core.  sotlibc gives such a binary only the minimal C runtime
 * it needs — mem/string/format/parse with output to the seL4 debug serial — and
 * deliberately NOTHING ELSE (no fork/exec/pthreads/signals/dlopen/NSS/locale/
 * POSIX-fs/DNS).  Distinct from muslc, which the Linux-ABI guests link.
 *
 * Pairs with sotcrt (the crt0 over sel4runtime) and sotabi (the IPC contract).
 */
#include <stddef.h>
#include <stdarg.h>

/* memory */
void  *sot_memcpy (void *d, const void *s, size_t n);
void  *sot_memset (void *d, int c, size_t n);
int    sot_memcmp (const void *a, const void *b, size_t n);

/* string */
size_t sot_strlen (const char *s);
int    sot_strcmp (const char *a, const char *b);
int    sot_strncmp(const char *a, const char *b, size_t n);

/* parse · base 0/8/10/16 like strtoul (0 = auto by 0x/0 prefix) */
unsigned long sot_strtoul(const char *s, char **end, int base);

/* format · the core printf engine drives an emit callback (so it is host-unit
 * testable against a buffer, and drives the serial in the native binary).
 * Supports: %s %c %d %i %u %x %p %% · the 'l'/'ll' length modifiers · a numeric
 * field width and the '-' (left) / '0' (zero-pad) flags.  Enough for sotctl. */
typedef void (*sot_emit_fn)(char c, void *ctx);
int sot_vformat (sot_emit_fn emit, void *ctx, const char *fmt, va_list ap);
int sot_vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap);
int sot_snprintf (char *buf, size_t cap, const char *fmt, ...);

/* serial output (seL4 debug putchar) · the native binary's stdout. */
void sot_putchar(char c);
int  sot_printf (const char *fmt, ...);

#endif /* SOTLIBC_H */
