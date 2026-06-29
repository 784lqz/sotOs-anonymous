/*
 * sotOs · OBSD-η · userland TPM 2.0 TIS driver.
 *
 * Implements the PC-Client TPM Interface Specification (TIS) register
 * interface at MMIO base 0xFED40000 (QEMU/swtpm default).  Used by orch
 * at boot to extend PCRs (measured boot) and at runtime by sotShell
 * (Unit T3 · `tpm-quote <nonce>` operator command).
 *
 * Crypto: we do NOT implement SHA-256 in software.  Every tpm_pcr_extend
 * issues a TPM2_Hash command (CC=0x0000017D) to make the TPM hash the
 * payload itself, then feeds the digest back via TPM2_PCR_Extend.  Two
 * round-trips per extend, no crypto code in orch.
 *
 * Graceful degrade: if vka_alloc_frame_at(0xFED40000) fails (no device
 * untyped delegated) or the ACCESS register reads 0xFF (no chip behind
 * the frame), tpm_init returns -1.  All subsequent tpm_* calls then
 * short-circuit to -1 and the rest of orch boots normally.
 */

#include <orch/tpm.h>
#include <sel4/sel4.h>
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

extern vka_t *orch_vka(void);

/* =========================================================================
 * TIS register map · all offsets relative to TPM_TIS_BASE + locality*0x1000.
 * We operate exclusively on locality 0.
 * ========================================================================= */
#define TPM_TIS_BASE        0xFED40000UL
#define TPM_TIS_FRAME_BITS  12                 /* one 4 KiB page covers locality 0 */

#define TPM_REG_ACCESS         0x0000
#define TPM_REG_INT_ENABLE     0x0008
#define TPM_REG_STS            0x0018
#define TPM_REG_DATA_FIFO      0x0024
#define TPM_REG_DID_VID        0x0F00
#define TPM_REG_RID            0x0F04

/* ACCESS bits */
#define TPM_ACCESS_VALID            0x80
#define TPM_ACCESS_ACTIVE_LOCALITY  0x20
#define TPM_ACCESS_REQUEST_USE      0x02

/* STS bits */
#define TPM_STS_VALID           0x80
#define TPM_STS_COMMAND_READY   0x40
#define TPM_STS_TPM_GO          0x20
#define TPM_STS_DATA_AVAIL      0x10
#define TPM_STS_EXPECT          0x08

/* TPM 2.0 command codes (CC).  All big-endian on the wire. */
#define TPM_ST_NO_SESSIONS      0x8001
#define TPM_ST_SESSIONS         0x8002

#define TPM_CC_STARTUP          0x00000144u
#define TPM_CC_GET_CAPABILITY   0x0000017Au
#define TPM_CC_PCR_READ         0x0000017Eu
#define TPM_CC_PCR_EXTEND       0x00000182u
#define TPM_CC_HASH             0x0000017Du
#define TPM_CC_QUOTE            0x00000158u

#define TPM_SU_CLEAR            0x0000

#define TPM_ALG_SHA256          0x000B
#define TPM_ALG_NULL            0x0010

#define TPM_RH_NULL             0x40000007u
#define TPM_RH_OWNER            0x40000001u

#define TPM_RS_PW               0x40000009u

/* =========================================================================
 * State
 * ========================================================================= */
static int           g_tpm_ready    = 0;
static volatile uint8_t *g_tpm_mmio = NULL;
static vka_object_t  g_tpm_frame;
static uint8_t       g_tpm_cmdbuf[1024] __attribute__((aligned(8)));

/* Generous polling bounds.  The TPM TIS bus is synchronous; under
 * QEMU/swtpm each transition completes in microseconds.  We bound at
 * ~10M iterations to guarantee we never hang forever even if the chip
 * misbehaves. */
#define TPM_POLL_LIMIT  10000000UL

/* =========================================================================
 * MMIO helpers · volatile loads/stores against the locality-0 page.
 * ========================================================================= */
static inline uint8_t tpm_r8(uint32_t off)
{
    return *((volatile uint8_t *)(g_tpm_mmio + off));
}

static inline void tpm_w8(uint32_t off, uint8_t v)
{
    *((volatile uint8_t *)(g_tpm_mmio + off)) = v;
}

static inline uint32_t tpm_r32(uint32_t off)
{
    return *((volatile uint32_t *)(g_tpm_mmio + off));
}

static inline void tpm_w32(uint32_t off, uint32_t v)
{
    *((volatile uint32_t *)(g_tpm_mmio + off)) = v;
}

/* =========================================================================
 * Big-endian marshaling helpers.  TPM 2.0 wire format is BE for everything.
 * ========================================================================= */
static inline void be16_put(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void be32_put(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline uint16_t be16_get(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t be32_get(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

/* =========================================================================
 * TIS state machine · request locality, send command, read response.
 * ========================================================================= */
static int tpm_request_locality(void)
{
    /* Already active? */
    if (tpm_r8(TPM_REG_ACCESS) & TPM_ACCESS_ACTIVE_LOCALITY) return 0;

    tpm_w8(TPM_REG_ACCESS, TPM_ACCESS_REQUEST_USE);
    for (unsigned long i = 0; i < TPM_POLL_LIMIT; ++i) {
        uint8_t a = tpm_r8(TPM_REG_ACCESS);
        if ((a & (TPM_ACCESS_VALID | TPM_ACCESS_ACTIVE_LOCALITY))
            == (TPM_ACCESS_VALID | TPM_ACCESS_ACTIVE_LOCALITY)) {
            return 0;
        }
    }
    return -1;
}

static int tpm_wait_for_ready(void)
{
    tpm_w32(TPM_REG_STS, TPM_STS_COMMAND_READY);
    for (unsigned long i = 0; i < TPM_POLL_LIMIT; ++i) {
        if (tpm_r32(TPM_REG_STS) & TPM_STS_COMMAND_READY) return 0;
    }
    return -1;
}

static int tpm_send_command(const uint8_t *cmd, size_t cmd_len,
                             uint8_t *resp, size_t resp_cap,
                             size_t *resp_len_out)
{
    if (tpm_request_locality() < 0) return -1;
    if (tpm_wait_for_ready() < 0) return -1;

    /* Burst-write the command bytes into the FIFO.  We do NOT optimise via
     * burstCount; one byte at a time is correct (slow but reliable). */
    for (size_t i = 0; i < cmd_len; ++i) {
        tpm_w8(TPM_REG_DATA_FIFO, cmd[i]);
    }

    /* Verify TPM accepted exactly cmd_len bytes (Expect should clear). */
    {
        unsigned long i;
        for (i = 0; i < TPM_POLL_LIMIT; ++i) {
            uint32_t s = tpm_r32(TPM_REG_STS);
            if ((s & TPM_STS_VALID) && !(s & TPM_STS_EXPECT)) break;
        }
        if (i == TPM_POLL_LIMIT) return -1;
    }

    /* Issue the command. */
    tpm_w32(TPM_REG_STS, TPM_STS_TPM_GO);

    /* Wait for dataAvail. */
    {
        unsigned long i;
        for (i = 0; i < TPM_POLL_LIMIT; ++i) {
            uint32_t s = tpm_r32(TPM_REG_STS);
            if ((s & (TPM_STS_VALID | TPM_STS_DATA_AVAIL))
                == (TPM_STS_VALID | TPM_STS_DATA_AVAIL)) break;
        }
        if (i == TPM_POLL_LIMIT) return -1;
    }

    /* Read response: header first (10 bytes), then trailing payload bytes
     * implied by the response size field. */
    size_t n = 0;
    while (n < 10 && n < resp_cap) {
        resp[n++] = tpm_r8(TPM_REG_DATA_FIFO);
    }
    if (n < 10) return -1;

    uint32_t total = be32_get(resp + 2);
    if (total < 10 || total > resp_cap) {
        /* Drain remaining bytes to leave the TPM in a clean state. */
        unsigned long drained = 0;
        while ((tpm_r32(TPM_REG_STS) & TPM_STS_DATA_AVAIL)
               && drained < 4096) {
            (void)tpm_r8(TPM_REG_DATA_FIFO);
            ++drained;
        }
        return -1;
    }
    while (n < total) {
        resp[n++] = tpm_r8(TPM_REG_DATA_FIFO);
    }

    /* Return the chip to ready / idle. */
    tpm_w32(TPM_REG_STS, TPM_STS_COMMAND_READY);
    if (resp_len_out) *resp_len_out = total;

    /* Check TPM response code (offset 6 in header, big-endian). */
    uint32_t rc = be32_get(resp + 6);
    if (rc != 0) return -1;
    return 0;
}

/* =========================================================================
 * TPM2_Startup · must be sent once per power-on cycle.
 * ========================================================================= */
static int tpm_startup(void)
{
    uint8_t *c = g_tpm_cmdbuf;
    be16_put(c + 0, TPM_ST_NO_SESSIONS);
    be32_put(c + 2, 12);                /* total size */
    be32_put(c + 6, TPM_CC_STARTUP);
    be16_put(c + 10, TPM_SU_CLEAR);

    uint8_t resp[64];
    size_t resp_len = 0;
    int rc = tpm_send_command(c, 12, resp, sizeof(resp), &resp_len);
    if (rc != 0) {
        /* TPM_RC_INITIALIZED (0x100) is returned if TPM2_Startup has already
         * been sent (e.g. by firmware).  Treat that as success. */
        if (resp_len >= 10 && be32_get(resp + 6) == 0x00000100) return 0;
        return -1;
    }
    return 0;
}

/* =========================================================================
 * TPM2_Hash · ask the chip to SHA-256 a buffer.
 *
 * Request layout (no sessions):
 *   tag(2)=TPM_ST_NO_SESSIONS, size(4), cc(4)=TPM_CC_HASH,
 *   data_size(2), data[N], hashAlg(2)=TPM_ALG_SHA256, hierarchy(4)=TPM_RH_NULL.
 *
 * Response layout:
 *   header(10), out_size(2), digest[N], validation_tag(2), validation_hier(4),
 *   ticket_size(2), ticket_data[T].
 *
 * We need only the digest.  Returns 0 on success and fills out_digest[32].
 * ========================================================================= */
static int tpm_hash(const uint8_t *data, size_t len, uint8_t *out_digest)
{
    if (len > 1024 - 22) return -1;     /* leave headroom for header */

    uint8_t *c = g_tpm_cmdbuf;
    uint32_t total = 10 + 2 + (uint32_t)len + 2 + 4;
    be16_put(c + 0, TPM_ST_NO_SESSIONS);
    be32_put(c + 2, total);
    be32_put(c + 6, TPM_CC_HASH);
    be16_put(c + 10, (uint16_t)len);
    if (len) memcpy(c + 12, data, len);
    be16_put(c + 12 + len, TPM_ALG_SHA256);
    be32_put(c + 14 + len, TPM_RH_NULL);

    uint8_t resp[256];
    size_t resp_len = 0;
    if (tpm_send_command(c, total, resp, sizeof(resp), &resp_len) != 0) return -1;
    if (resp_len < 10 + 2 + 32) return -1;
    uint16_t out_size = be16_get(resp + 10);
    if (out_size != 32) return -1;
    memcpy(out_digest, resp + 12, 32);
    return 0;
}

/* =========================================================================
 * TPM2_PCR_Extend · feed digest into PCR.  Uses the empty password session.
 *
 * Request layout (with sessions):
 *   tag(2)=TPM_ST_SESSIONS, size(4), cc(4)=TPM_CC_PCR_EXTEND,
 *   pcrHandle(4),
 *   authSize(4)=9, authArea: sessionHandle(4)=TPM_RS_PW, nonceSize(2)=0,
 *     sessionAttributes(1)=0, hmacSize(2)=0,
 *   digests count(4)=1, hashAlg(2)=TPM_ALG_SHA256, digest[32].
 * ========================================================================= */
static int tpm_pcr_extend_digest(uint32_t pcr_idx, const uint8_t *digest)
{
    uint8_t *c = g_tpm_cmdbuf;
    uint32_t total = 10 + 4 + 4 + 9 + 4 + 2 + 32;
    be16_put(c + 0, TPM_ST_SESSIONS);
    be32_put(c + 2, total);
    be32_put(c + 6, TPM_CC_PCR_EXTEND);
    be32_put(c + 10, pcr_idx);
    /* authSize */
    be32_put(c + 14, 9);
    /* authArea: sessionHandle, nonceSize=0, sessionAttributes=0, hmacSize=0 */
    be32_put(c + 18, TPM_RS_PW);
    be16_put(c + 22, 0);
    c[24] = 0;
    be16_put(c + 25, 0);
    /* digests TPML_DIGEST_VALUES: count=1, hashAlg=SHA256, digest[32] */
    be32_put(c + 27, 1);
    be16_put(c + 31, TPM_ALG_SHA256);
    memcpy(c + 33, digest, 32);

    uint8_t resp[64];
    size_t resp_len = 0;
    return tpm_send_command(c, total, resp, sizeof(resp), &resp_len);
}

/* =========================================================================
 * TPM2_PCR_Read · read one PCR bank entry.
 *
 * Request layout (no sessions):
 *   tag(2), size(4), cc(4)=TPM_CC_PCR_READ,
 *   pcrSelectionIn: count(4)=1, hashAlg(2)=SHA256, sizeOfSelect(1)=3,
 *     pcrSelect[3]  (bit `pcr_idx` set).
 *
 * Response layout (no sessions):
 *   header(10), pcrUpdateCounter(4),
 *   pcrSelectionOut: count(4), hashAlg(2), size(1), select[3],
 *   pcrValues: count(4)=1, size(2)=32, digest[32].
 * ========================================================================= */
int tpm_pcr_read(uint32_t pcr_idx, uint8_t *out_hash)
{
    if (!g_tpm_ready || !out_hash) return -1;
    if (pcr_idx >= 24) return -1;

    uint8_t *c = g_tpm_cmdbuf;
    uint32_t total = 10 + 4 + 2 + 1 + 3;
    be16_put(c + 0, TPM_ST_NO_SESSIONS);
    be32_put(c + 2, total);
    be32_put(c + 6, TPM_CC_PCR_READ);
    /* pcrSelectionIn */
    be32_put(c + 10, 1);                       /* count of TPMS_PCR_SELECTION */
    be16_put(c + 14, TPM_ALG_SHA256);
    c[16] = 3;                                  /* sizeOfSelect */
    c[17] = 0;
    c[18] = 0;
    c[19] = 0;
    c[17 + (pcr_idx / 8)] |= (uint8_t)(1u << (pcr_idx & 7));

    uint8_t resp[128];
    size_t resp_len = 0;
    if (tpm_send_command(c, total, resp, sizeof(resp), &resp_len) != 0) return -1;
    /* Walk to the digest: header(10) + counter(4) + sel_count(4) + alg(2) +
     * sizeOfSelect(1) + pcrSelect(3) + digest_count(4) + digest_size(2) → 30. */
    if (resp_len < 30 + 32) return -1;
    uint16_t dsize = be16_get(resp + 28);
    if (dsize != 32) return -1;
    memcpy(out_hash, resp + 30, 32);
    return 0;
}

/* =========================================================================
 * tpm_pcr_extend · hash data on the chip, then extend the PCR with the digest.
 * ========================================================================= */
int tpm_pcr_extend(uint32_t pcr_idx, const uint8_t *data, size_t len)
{
    if (!g_tpm_ready || !data) return -1;
    if (pcr_idx >= 24) return -1;

    uint8_t digest[32];
    if (tpm_hash(data, len, digest) != 0) return -1;
    return tpm_pcr_extend_digest(pcr_idx, digest);
}

/* =========================================================================
 * tpm_pcr_extend_precomputed · caller already has sha256(payload), so we
 * skip TPM2_Hash and feed the digest straight into TPM2_PCR_Extend.
 * Used by measured-boot when the payload exceeds TPM2_Hash's ~1 KiB ceiling.
 * ========================================================================= */
int tpm_pcr_extend_precomputed(uint32_t pcr_idx,
                                const uint8_t digest[TPM_PCR_SHA256_SIZE])
{
    if (!g_tpm_ready || !digest) return -1;
    if (pcr_idx >= 24) return -1;
    return tpm_pcr_extend_digest(pcr_idx, digest);
}

/* =========================================================================
 * TPM2_Quote · signed PCR attestation.
 *
 * We invoke TPM2_Quote against the NULL hierarchy (TPM_RH_NULL) using the
 * empty password session.  In practice TPM2_Quote requires a signing key
 * handle (TPMI_DH_OBJECT) so a real attestation flow would first run
 * TPM2_CreatePrimary to materialise an AIK.  For OBSD-η scope we ship a
 * stub that emits the command structure and reports the raw TPM response;
 * if the TPM lacks a usable signing key the response RC will reflect that
 * and we return -1.  A future iteration wires up proper key provisioning.
 * ========================================================================= */
int tpm_quote(const uint8_t *nonce, size_t nonce_len,
              uint8_t *out_quote, size_t *out_size_inout)
{
    if (!g_tpm_ready || !out_quote || !out_size_inout) return -1;
    if (nonce_len > 64) return -1;

    uint8_t *c = g_tpm_cmdbuf;
    /* Header + signHandle(4) + authSize(4) + authArea(9) + qualifyingData
     * size(2)+nonce + inScheme alg(2) + PCRselection count(4)+alg(2)+
     * sizeOfSelect(1)+select(3). */
    uint32_t total = 10 + 4 + 4 + 9 + 2 + (uint32_t)nonce_len + 2
                   + 4 + 2 + 1 + 3;
    be16_put(c + 0, TPM_ST_SESSIONS);
    be32_put(c + 2, total);
    be32_put(c + 6, TPM_CC_QUOTE);
    /* signHandle = NULL · without a provisioned AIK this will fail with
     * TPM_RC_VALUE.  We keep the marshaling correct so a future patch can
     * pass a real handle without restructuring callers. */
    be32_put(c + 10, TPM_RH_NULL);
    be32_put(c + 14, 9);
    be32_put(c + 18, TPM_RS_PW);
    be16_put(c + 22, 0);
    c[24] = 0;
    be16_put(c + 25, 0);

    uint32_t off = 27;
    be16_put(c + off, (uint16_t)nonce_len); off += 2;
    if (nonce_len) memcpy(c + off, nonce, nonce_len);
    off += (uint32_t)nonce_len;
    be16_put(c + off, TPM_ALG_NULL); off += 2;
    be32_put(c + off, 1); off += 4;
    be16_put(c + off, TPM_ALG_SHA256); off += 2;
    c[off++] = 3;
    c[off++] = 0;
    c[off++] = 0;
    c[off++] = 0;
    /* Select PCRs 8, 9, 10 (bits in byte 1). */
    c[off - 2] = (uint8_t)((1u << (8 & 7)) | (1u << (9 & 7)) | (1u << (10 & 7)));

    uint8_t resp[512];
    size_t resp_len = 0;
    int rc = tpm_send_command(c, total, resp, sizeof(resp), &resp_len);
    if (rc != 0) {
        return -1;
    }
    if (resp_len > *out_size_inout) return -1;
    memcpy(out_quote, resp, resp_len);
    *out_size_inout = resp_len;
    return 0;
}

/* =========================================================================
 * Frame mapping helper.  Allocates a 4 KiB frame at TPM_TIS_BASE from a
 * device untyped (if delegated) and maps it cacheable into orch's vspace.
 *
 * Returns 0 on success, -1 if no device untyped covers TPM_TIS_BASE or the
 * map call fails.  On -1 the caller treats the TPM as absent and degrades.
 * ========================================================================= */
static int tpm_map_mmio(void)
{
    vka_t *vka = orch_vka();
    int err = vka_alloc_frame_at(vka, TPM_TIS_FRAME_BITS,
                                  (uintptr_t)TPM_TIS_BASE, &g_tpm_frame);
    if (err) {
        return -1;
    }

    /* Pick a vaddr in a region that does not collide with bump-mapped DMA
     * buffers from virtio.  The virtio-blk driver uses 0x20000000-0x28000000
     * (see storage_virtio_blk.c); 0x3F000000 sits clear of that. */
    void *vaddr = (void *)0x3F000000UL;
    vka_object_t paging[8];
    int npaging = 8;
    err = sel4utils_map_page(vka, SEL4UTILS_PD_SLOT, g_tpm_frame.cptr,
                              vaddr, seL4_AllRights,
                              0 /* cacheable=0 · MMIO must not cache */,
                              paging, &npaging);
    if (err) {
        return -1;
    }
    g_tpm_mmio = (volatile uint8_t *)vaddr;
    return 0;
}

/* =========================================================================
 * tpm_init · probe + TIS handshake + TPM2_Startup.
 * ========================================================================= */
int tpm_init(void)
{
    if (g_tpm_ready) return 0;

    if (tpm_map_mmio() != 0) {
        printf("[tpm] no device · measured boot disabled\n");
        return -1;
    }

    /* Probe ACCESS register.  An empty MMIO region returns 0xFF on reads
     * when nothing answers, or 0x00 when the chipset returns zero-fill for
     * unimplemented decode (QEMU without `-device tpm-tis`).  A real TIS
     * device always reports ACCESS_VALID (bit 7) set after power-on. */
    uint8_t access = tpm_r8(TPM_REG_ACCESS);
    uint32_t did_vid = tpm_r32(TPM_REG_DID_VID);
    if (access == 0xFF || access == 0x00
        || did_vid == 0x00000000 || did_vid == 0xFFFFFFFFu) {
        printf("[tpm] no device · measured boot disabled\n");
        return -1;
    }

    printf("[tpm] TIS present @0x%lx · DID_VID=0x%08x access=0x%02x\n",
           (unsigned long)TPM_TIS_BASE, did_vid, access);

    if (tpm_request_locality() != 0) {
        printf("[tpm] could not acquire locality 0 · measured boot disabled\n");
        return -1;
    }

    if (tpm_startup() != 0) {
        printf("[tpm] TPM2_Startup failed · measured boot disabled\n");
        return -1;
    }

    g_tpm_ready = 1;
    printf("[tpm] startup OK · driver active\n");
    return 0;
}

int tpm_is_available(void)
{
    return g_tpm_ready;
}
