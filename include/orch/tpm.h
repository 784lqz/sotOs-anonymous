/*
 * sotOs · OBSD-η · userland TPM 2.0 TIS driver (orch-side).
 *
 * Provides a minimal TPM 2.0 client speaking the TIS register interface at
 * MMIO base 0xFED40000 (the QEMU/swtpm default).  All commands are marshaled
 * big-endian per the TPM 2.0 spec; SHA-256 is provided by the TPM itself
 * (TPM2_Hash) so we never need our own crypto.
 *
 * Graceful degrade: if no TPM device responds at the TIS base address
 * (probe reads 0xFF), tpm_init() returns -1 and every subsequent
 * tpm_* call returns -1 immediately without faulting.  Boot continues
 * normally with "[tpm] no device · measured boot disabled".
 *
 * The driver requires that the orch process holds an MMIO frame cap
 * covering the TPM region.  Frame mapping is attempted at init via
 * vka_alloc_frame_at(); if root has not delegated a device untyped
 * covering 0xFED40000, this fails and we degrade silently.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#define TPM_PCR_SHA256_SIZE 32

/* PCR indices used for sotOs measured boot.
 *   PCR 8  · orch bootstrap stub
 *   PCR 9  · kernel image (deferred · symbols not yet exposed)
 *   PCR 10 · initrd / sotfs header (deferred)
 */
#define TPM_PCR_ORCH_BOOTSTRAP  8
#define TPM_PCR_KERNEL_IMAGE    9
#define TPM_PCR_INITRD_SOTFS    10

/* Initialize the TPM TIS driver.  Returns 0 on success, -1 if no TPM
 * device is present (graceful degrade).  Sends TPM2_Startup on success. */
int tpm_init(void);

/* Returns 1 if tpm_init() succeeded, 0 otherwise. */
int tpm_is_available(void);

/* Extend pcr_idx with sha256(data) via the TPM's own hash service.
 * Returns 0 on success, -1 on TPM/comm failure or unavailable driver. */
int tpm_pcr_extend(uint32_t pcr_idx, const uint8_t *data, size_t len);

/* Extend pcr_idx with a caller-supplied SHA-256 digest (32 bytes).  Used by
 * bootstrap measured-boot when the payload is larger than the TPM2_Hash
 * single-shot ceiling (~1 KiB) and we hash in software via sotos_sha256.
 * Returns 0 on success, -1 on TPM/comm failure or unavailable driver. */
int tpm_pcr_extend_precomputed(uint32_t pcr_idx,
                                const uint8_t digest[TPM_PCR_SHA256_SIZE]);

/* Read PCR value into out_hash (caller-allocated TPM_PCR_SHA256_SIZE bytes).
 * Returns 0 on success, -1 on TPM/comm failure or unavailable driver. */
int tpm_pcr_read(uint32_t pcr_idx, uint8_t *out_hash);

/* Sign a Quote of PCRs 8..10 with the operator nonce.  Writes the raw
 * TPM2_Quote response (attestation + signature) to *out_quote.  On entry
 * *out_size_inout is the caller-supplied buffer capacity; on success it
 * is overwritten with the number of bytes written.  Returns 0/-1. */
int tpm_quote(const uint8_t *nonce, size_t nonce_len,
              uint8_t *out_quote, size_t *out_size_inout);
