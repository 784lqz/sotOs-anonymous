/* sotOs · WAL unit tests · CRC roundtrip + record framing sanity.
 *
 * Standalone ELF spawned by root at boot.  Mirrors the procd-unit
 * fixture: prints PASS/FAIL lines that scripts/smoke-procd.sh greps
 * from the QEMU serial log.  Tests are pure userspace (no IPC, no
 * storage backend) · they exercise the public ABI surface that PR 2
 * (CRC64) and PR 1 (v2 payload structs) introduced.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sel4/sel4.h>
#include <sotfs/wal.h>
#include <sotfs/crc64.h>

static int test_crc64_roundtrip(void) {
    const char *data = "the quick brown fox jumps over the lazy dog";
    size_t len = 43;
    uint64_t crc1 = sotfs_crc64(data, len);
    uint64_t crc2 = sotfs_crc64(data, len);
    if (crc1 != crc2) {
        printf("[wal-unit] FAIL test_crc64_roundtrip · crc1=%lu crc2=%lu\n",
               (unsigned long)crc1, (unsigned long)crc2);
        return 1;
    }
    /* Verify CRC changes when input changes. */
    char altered[64];
    memcpy(altered, data, len);
    altered[0] = 'T';
    uint64_t crc3 = sotfs_crc64(altered, len);
    if (crc1 == crc3) {
        printf("[wal-unit] FAIL test_crc64_roundtrip · altered crc matches\n");
        return 2;
    }
    return 0;
}

static int test_payload_sizes(void) {
    /* The _Static_asserts in wal.h already fire at compile time.
     * This test verifies they hold at runtime too · cheap sanity
     * check that the ABI layout matches the budget the plan
     * (and the on-disk framing in PR 3-4 writers) assumes. */
    if (sizeof(sotfs_wal_v2_header_t) != 24) return 1;
    if (sizeof(sotfs_wal_payload_procd_mut_t) != 48) return 2;
    if (sizeof(sotfs_wal_payload_anomaly_ev_t) != 24) return 3;
    if (sizeof(sotfs_wal_payload_sotnet_synth_t) != 16) return 4;
    if (sizeof(sotfs_wal_payload_checkpoint_t) != 24) return 5;
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    printf("[wal-unit] start\n");

    int rc;
    rc = test_crc64_roundtrip();
    printf("[wal-unit] %s test_crc64_roundtrip rc=%d\n",
           rc == 0 ? "PASS" : "FAIL", rc);
    if (rc) return 1;

    rc = test_payload_sizes();
    printf("[wal-unit] %s test_payload_sizes rc=%d\n",
           rc == 0 ? "PASS" : "FAIL", rc);
    if (rc) return 1;

    printf("[wal-unit] ALL PASS\n");
    while (1) seL4_Yield();
}
