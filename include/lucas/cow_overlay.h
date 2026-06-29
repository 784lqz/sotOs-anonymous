#ifndef LUCAS_COW_OVERLAY_H
#define LUCAS_COW_OVERLAY_H
#include <stdint.h>
#define LUCAS_COW_MAX_ENTRIES 16
#define LUCAS_COW_MAX_PATH    96
#define LUCAS_COW_MAX_BYTES   (64*1024)   /* per-entry cap → believable ENOSPC if exceeded */
void lucas_cow_init(void);
int  lucas_cow_has  (uint32_t session, const char *path);                                 /* 1 / 0 */
int  lucas_cow_write(uint32_t session, const char *path, const uint8_t *src, uint32_t n);  /* 0 / -errno */
int  lucas_cow_read (uint32_t session, const char *path, uint8_t *dst, uint32_t max);       /* bytes / -1 */
int  lucas_cow_truncate(uint32_t session, const char *path, uint32_t newlen); /* 0 / -errno */
void lucas_cow_reap (uint32_t session);                                                     /* free all entries for session */
#endif
