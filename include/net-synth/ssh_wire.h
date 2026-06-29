/* sotOs · net-synth · SSH-2.0 wire encoders (arc-ζ1).
 * Pure (no BearSSL, no seL4) → host-unit-testable. RFC 4251 §5 data types +
 * the RFC 4253 §6 binary-packet framer. All encoders APPEND at `off` into
 * b[0..cap); they return the new offset, or SSH_WIRE_ERR on overflow.
 * Errors propagate: feed the returned offset into the next call and check
 * != SSH_WIRE_ERR once at the end. */
#ifndef NET_SYNTH_SSH_WIRE_H
#define NET_SYNTH_SSH_WIRE_H
#include <stdint.h>
#include <stddef.h>

#define SSH_WIRE_ERR 0xFFFFFFFFu

uint32_t ssh_put_byte(uint8_t *b, uint32_t off, uint32_t cap, uint8_t v);
uint32_t ssh_put_u32(uint8_t *b, uint32_t off, uint32_t cap, uint32_t v);   /* big-endian */
uint32_t ssh_put_bytes(uint8_t *b, uint32_t off, uint32_t cap, const uint8_t *p, uint32_t n);
uint32_t ssh_put_string(uint8_t *b, uint32_t off, uint32_t cap, const uint8_t *p, uint32_t n); /* u32 len + bytes */
uint32_t ssh_put_cstr(uint8_t *b, uint32_t off, uint32_t cap, const char *s);  /* string of strlen(s) */
/* mpint (RFC 4251 §5): strip leading 0x00; value 0 -> 00000000; if the first
 * kept byte has bit7 set, prepend a 0x00. `be` is a big-endian unsigned int. */
uint32_t ssh_put_mpint(uint8_t *b, uint32_t off, uint32_t cap, const uint8_t *be, uint32_t n);

/* Frame an SSH binary packet (RFC 4253 §6) pre-NEWKEYS (cleartext, block=8):
 * uint32 packet_length + byte padding_length + payload + zero padding, with
 * 4+packet_length a multiple of 8 and padding >= 4. Returns total bytes
 * written, or 0 if it would not fit in out[0..outmax). */
uint32_t ssh_pkt_frame(uint8_t *out, uint32_t outmax, const uint8_t *payload, uint32_t plen);

#endif /* NET_SYNTH_SSH_WIRE_H */
