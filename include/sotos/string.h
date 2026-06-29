/*
 * sotOs · safe string primitives · vendored from OpenBSD libc.
 *
 * strlcpy and strlcat are 30-line ISC-licensed functions that always
 * NUL-terminate the destination (unless dsize == 0) and return the
 * size that *would have been* needed.  Truncation detection idiom:
 *
 *     if (strlcpy(buf, src, sizeof(buf)) >= sizeof(buf)) {
 *         // truncated
 *     }
 *
 * Both functions never write past dst[dsize-1].  No NUL-without-bound
 * footgun like strncpy.
 *
 * Original copyright preserved verbatim per the ISC license.
 */
#ifndef SOTOS_STRING_H
#define SOTOS_STRING_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t sotos_strlcpy(char *dst, const char *src, size_t dsize);
size_t sotos_strlcat(char *dst, const char *src, size_t dsize);

/* Convenience aliases · prefer the prefixed forms in new code. */
#ifndef SOTOS_NO_STRLCPY_ALIAS
#define strlcpy sotos_strlcpy
#define strlcat sotos_strlcat
#endif

#ifdef __cplusplus
}
#endif

#endif /* SOTOS_STRING_H */
