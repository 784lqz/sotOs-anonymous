/* sotfs · CRC-64 ECMA implementation for WAL record integrity. */
#ifndef SOTFS_CRC64_H
#define SOTFS_CRC64_H

#include <stdint.h>
#include <stddef.h>

uint64_t sotfs_crc64(const void *buf, size_t len);

#endif
