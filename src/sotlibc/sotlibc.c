/*
 * sotlibc · the freestanding C runtime core (mem / string / parse / format).
 *
 * No seL4, no muslc, no host libc — pure C, host-unit-testable with plain `cc`.
 * The serial sink (sot_putchar / sot_printf) lives in sotlibc_serial.c (seL4
 * only); everything here is platform-free.
 */
#include "sotlibc/sotlibc.h"
#include <stdint.h>   /* uintptr_t (the %p case) */

void *sot_memcpy(void *d, const void *s, size_t n) {
    unsigned char *dp = d; const unsigned char *sp = s;
    for (size_t i = 0; i < n; i++) dp[i] = sp[i];
    return d;
}
void *sot_memset(void *d, int c, size_t n) {
    unsigned char *dp = d;
    for (size_t i = 0; i < n; i++) dp[i] = (unsigned char)c;
    return d;
}
int sot_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *ap = a, *bp = b;
    for (size_t i = 0; i < n; i++) if (ap[i] != bp[i]) return (int)ap[i] - (int)bp[i];
    return 0;
}
size_t sot_strlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
int sot_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}
int sot_strncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
        if (!a[i]) break;
    }
    return 0;
}

unsigned long sot_strtoul(const char *s, char **end, int base) {
    const char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (base == 0) {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { base = 16; p += 2; }
        else if (p[0] == '0') { base = 8; }
        else base = 10;
    } else if (base == 16 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }
    unsigned long v = 0;
    for (;;) {
        char c = *p; int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'z') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'Z') d = c - 'A' + 10;
        else break;
        if (d >= base) break;
        v = v * (unsigned long)base + (unsigned long)d;
        p++;
    }
    if (end) *end = (char *)p;
    return v;
}

/* ── the printf engine ──────────────────────────────────────────────────── */

static void emit_str(sot_emit_fn emit, void *ctx, const char *s, int *n) {
    while (*s) { emit(*s++, ctx); (*n)++; }
}

/* render an unsigned value in `base` into a temp buffer (reversed), then emit
 * with optional zero/space pad to `width`.  `neg` prepends '-'. */
static void emit_num(sot_emit_fn emit, void *ctx, unsigned long v, int base,
                     int width, int zero, int left, int neg, int *n) {
    char tmp[24]; int ti = 0;
    const char *digs = "0123456789abcdef";
    if (v == 0) tmp[ti++] = '0';
    while (v) { tmp[ti++] = digs[v % (unsigned)base]; v /= (unsigned)base; }
    int len = ti + (neg ? 1 : 0);
    if (!left) for (int i = len; i < width; i++) { emit(zero ? '0' : ' ', ctx); (*n)++; }
    if (neg) { emit('-', ctx); (*n)++; }
    while (ti > 0) { emit(tmp[--ti], ctx); (*n)++; }
    if (left) for (int i = len; i < width; i++) { emit(' ', ctx); (*n)++; }
}

int sot_vformat(sot_emit_fn emit, void *ctx, const char *fmt, va_list ap) {
    int n = 0;
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') { emit(*p, ctx); n++; continue; }
        p++;
        int left = 0, zero = 0;
        for (;; p++) { if (*p == '-') left = 1; else if (*p == '0') zero = 1; else break; }
        int width = 0;
        while (*p >= '0' && *p <= '9') { width = width * 10 + (*p - '0'); p++; }
        int lng = 0;
        while (*p == 'l') { lng++; p++; }
        switch (*p) {
        case 's': { const char *s = va_arg(ap, const char *); if (!s) s = "(null)";
                    int len = (int)sot_strlen(s);
                    if (!left) for (int i = len; i < width; i++) { emit(' ', ctx); n++; }
                    emit_str(emit, ctx, s, &n);
                    if (left) for (int i = len; i < width; i++) { emit(' ', ctx); n++; }
                    break; }
        case 'c': { char c = (char)va_arg(ap, int); emit(c, ctx); n++; break; }
        case 'd': case 'i': {
            long v = lng ? va_arg(ap, long) : (long)va_arg(ap, int);
            int neg = v < 0; unsigned long uv = neg ? (unsigned long)(-v) : (unsigned long)v;
            emit_num(emit, ctx, uv, 10, width, zero, left, neg, &n); break; }
        case 'u': {
            unsigned long v = lng ? va_arg(ap, unsigned long) : (unsigned long)va_arg(ap, unsigned int);
            emit_num(emit, ctx, v, 10, width, zero, left, 0, &n); break; }
        case 'x': {
            unsigned long v = lng ? va_arg(ap, unsigned long) : (unsigned long)va_arg(ap, unsigned int);
            emit_num(emit, ctx, v, 16, width, zero, left, 0, &n); break; }
        case 'p': {
            unsigned long v = (unsigned long)(uintptr_t)va_arg(ap, void *);
            emit('0', ctx); emit('x', ctx); n += 2;
            emit_num(emit, ctx, v, 16, width, zero, left, 0, &n); break; }
        case '%': emit('%', ctx); n++; break;
        case '\0': return n;
        default:  emit('%', ctx); emit(*p, ctx); n += 2; break;
        }
    }
    return n;
}

/* snprintf · emit into a bounded buffer (NUL-terminated). */
struct snbuf { char *buf; size_t cap; size_t pos; };
static void sn_emit(char c, void *ctx) {
    struct snbuf *b = ctx;
    if (b->pos + 1 < b->cap) b->buf[b->pos] = c;
    b->pos++;
}
int sot_vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap) {
    struct snbuf b = { buf, cap, 0 };
    int n = sot_vformat(sn_emit, &b, fmt, ap);
    if (cap > 0) buf[b.pos < cap ? b.pos : cap - 1] = '\0';
    return n;
}
int sot_snprintf(char *buf, size_t cap, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = sot_vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
    return n;
}
