/*
 * sotOs · LUCAS · binstore backend (SP2).
 *
 * Reads the read-only binary blob region of sotfs.img via virtio_blk_read_sector,
 * mirroring backends_python_stdlib.c.  orch (single-threaded) calls these
 * functions directly (non-VFS) to load ELF bytes for ORCH_OP_SPAWN.
 */

#include <sotfs/binstore.h>
#include <sotfs/layout.h>
#include <sotfs/storage_virtio_blk.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static sotfs_binstore_header_t g_bs_header;
static int g_bs_initialized = 0;
static int g_bs_ready       = 0;

static int binstore_lazy_init(void)
{
    if (g_bs_initialized) return g_bs_ready ? 0 : -2;
    g_bs_initialized = 1;

    /* Header lives at SOTFS_BINSTORE_HEADER_OFFSET · read enough sectors to
     * cover sizeof(header), then memcpy. */
    _Static_assert(sizeof(sotfs_binstore_header_t) <= 16u * 512u,
                   "binstore header must fit in the sectors we read");
    uint8_t buf[16u * 512u];
    uint64_t base_sector = (uint64_t)SOTFS_BINSTORE_HEADER_OFFSET / 512u;
    size_t   nsect = (sizeof(sotfs_binstore_header_t) + 511u) / 512u;
    for (size_t s = 0; s < nsect; ++s) {
        if (virtio_blk_read_sector(base_sector + s, buf + s * 512u) != 0) {
            printf("[binstore] header read failed · sector=%lu\n",
                   (unsigned long)(base_sector + s));
            return -2;
        }
    }
    memcpy(&g_bs_header, buf, sizeof(g_bs_header));

    if (g_bs_header.magic != SOTFS_BINSTORE_MAGIC) {
        printf("[binstore] header magic mismatch · got 0x%x expected 0x%x · region not populated\n",
               g_bs_header.magic, SOTFS_BINSTORE_MAGIC);
        return -2;
    }
    if (g_bs_header.count == 0 || g_bs_header.count > SOTFS_BINSTORE_MAX_ENTRIES) {
        printf("[binstore] invalid count=%u\n", g_bs_header.count);
        return -2;
    }

    g_bs_ready = 1;
    printf("[binstore] ready · %u entr%s · region@%u\n",
           g_bs_header.count, g_bs_header.count == 1 ? "y" : "ies",
           (unsigned)SOTFS_BINSTORE_HEADER_OFFSET);
    for (uint32_t i = 0; i < g_bs_header.count; ++i) {
        printf("[binstore] entry '%s' · off=%lu size=%lu\n",
               g_bs_header.entries[i].name,
               (unsigned long)g_bs_header.entries[i].offset,
               (unsigned long)g_bs_header.entries[i].size);
    }
    return 0;
}

long binstore_lookup(const char *name, uint64_t *offset_out)
{
    if (binstore_lazy_init() != 0) return -2;
    if (!name) return -22;
    for (uint32_t i = 0; i < g_bs_header.count; ++i) {
        if (strncmp(g_bs_header.entries[i].name, name, SOTFS_BINSTORE_NAME_BYTES) == 0) {
            if (offset_out) *offset_out = g_bs_header.entries[i].offset;
            return (long)g_bs_header.entries[i].size;
        }
    }
    return -2; /* ENOENT */
}

long binstore_read(const char *name, void *buf, size_t cap)
{
    if (!buf || cap == 0) return -22;
    uint64_t off = 0;
    long size = binstore_lookup(name, &off);
    if (size < 0) return size;

    uint64_t want = (uint64_t)size;
    if (want > cap) want = cap;

    uint64_t disk_off = off;
    size_t   copied   = 0;
    static uint8_t sector_buf[512];
    while (copied < want) {
        uint64_t sector    = disk_off / 512u;
        size_t   inner_off = (size_t)(disk_off % 512u);
        if (virtio_blk_read_sector(sector, sector_buf) != 0) {
            printf("[binstore] read '%s' failed · sector=%lu\n",
                   name, (unsigned long)sector);
            return -5; /* EIO */
        }
        size_t chunk = 512 - inner_off;
        if (chunk > want - copied) chunk = want - copied;
        memcpy((uint8_t *)buf + copied, sector_buf + inner_off, chunk);
        copied   += chunk;
        disk_off += chunk;
    }
    return (long)copied;
}

void binstore_selftest(void)
{
    if (binstore_lazy_init() != 0) {
        printf("[binstore] selftest · region not populated\n");
        return;
    }
    uint8_t magic[4];
    long n = binstore_read("tcc.bin", magic, sizeof(magic));
    uint64_t off = 0;
    long size = binstore_lookup("tcc.bin", &off);
    if (n == 4 && magic[0] == 0x7f && magic[1] == 'E' &&
        magic[2] == 'L' && magic[3] == 'F') {
        printf("[binstore] selftest tcc.bin · elf-magic OK · size=%lu\n",
               (unsigned long)size);
    } else {
        printf("[binstore] selftest tcc.bin · FAILED · n=%ld magic=%02x%02x%02x%02x\n",
               n, magic[0], magic[1], magic[2], magic[3]);
    }
}
