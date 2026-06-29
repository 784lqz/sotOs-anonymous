/* sotfs · CRC-64 ECMA · table-based, branchless inner loop.
 * Polynomial: 0x42F0E1EBA9EA3693 (ECMA-182), reversed for LSB-first.
 *
 * Lazy-initialised single-threaded table.  Safe in our context · the WAL
 * is a single-writer / single-replayer subsystem (orch thread serialises
 * all appends; replay runs once at boot before any other thread).
 */
#include <sotfs/crc64.h>

static uint64_t crc64_table[256];
static int crc64_table_initialized = 0;

static void init_table(void) {
    const uint64_t poly = 0xC96C5795D7870F42ull;  /* ECMA-182 reversed */
    for (int i = 0; i < 256; i++) {
        uint64_t c = (uint64_t)i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? ((c >> 1) ^ poly) : (c >> 1);
        }
        crc64_table[i] = c;
    }
    crc64_table_initialized = 1;
}

uint64_t sotfs_crc64(const void *buf, size_t len) {
    if (!crc64_table_initialized) init_table();
    const uint8_t *p = (const uint8_t *)buf;
    uint64_t crc = 0xFFFFFFFFFFFFFFFFull;
    for (size_t i = 0; i < len; i++) {
        crc = crc64_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}
