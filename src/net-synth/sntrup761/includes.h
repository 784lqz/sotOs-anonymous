/* shim · OpenSSH's sntrup761.c #includes "includes.h"; sotOs supplies its own.
 * The vendored constant-time code wipes scratch with explicit_bzero(); musl
 * gates the prototype behind feature macros not set under the net-synth
 * -nostdinc build.  Rename the call to a local wipe (a macro, so it never
 * clashes with a libc explicit_bzero on the host KAT build). */
#ifndef SOTOS_SNTRUP_INCLUDES_H
#define SOTOS_SNTRUP_INCLUDES_H
#include <stddef.h>
/* The host KAT builds against glibc (which declares explicit_bzero in <string.h>),
 * so only shim under the sotOs net-synth build (-nostdinc musl · prototype gated). */
#ifndef SNTRUP_HOST_KAT
static inline void sntrup_wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}
#define explicit_bzero(p, n) sntrup_wipe((p), (n))
#endif
#endif
