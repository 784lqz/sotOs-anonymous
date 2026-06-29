/* sotOs · net-synth · SSH-2.0 wire encoders (arc-ζ1). Pure; see ssh_wire.h. */
#include <net-synth/ssh_wire.h>
#include <string.h>

uint32_t ssh_put_byte(uint8_t *b, uint32_t off, uint32_t cap, uint8_t v) {
    if (off == SSH_WIRE_ERR || off + 1 > cap) return SSH_WIRE_ERR;
    b[off] = v;
    return off + 1;
}

uint32_t ssh_put_u32(uint8_t *b, uint32_t off, uint32_t cap, uint32_t v) {
    if (off == SSH_WIRE_ERR || off + 4 > cap) return SSH_WIRE_ERR;
    b[off + 0] = (uint8_t)(v >> 24);
    b[off + 1] = (uint8_t)(v >> 16);
    b[off + 2] = (uint8_t)(v >> 8);
    b[off + 3] = (uint8_t)(v);
    return off + 4;
}

uint32_t ssh_put_bytes(uint8_t *b, uint32_t off, uint32_t cap, const uint8_t *p, uint32_t n) {
    if (off == SSH_WIRE_ERR || off + n > cap || off + n < off) return SSH_WIRE_ERR;
    if (n) memcpy(b + off, p, n);
    return off + n;
}

uint32_t ssh_put_string(uint8_t *b, uint32_t off, uint32_t cap, const uint8_t *p, uint32_t n) {
    off = ssh_put_u32(b, off, cap, n);
    return ssh_put_bytes(b, off, cap, p, n);
}

uint32_t ssh_put_cstr(uint8_t *b, uint32_t off, uint32_t cap, const char *s) {
    return ssh_put_string(b, off, cap, (const uint8_t *)s, (uint32_t)strlen(s));
}

uint32_t ssh_put_mpint(uint8_t *b, uint32_t off, uint32_t cap, const uint8_t *be, uint32_t n) {
    uint32_t i = 0;
    while (i < n && be[i] == 0) i++;          /* strip leading zero bytes */
    uint32_t klen = n - i;                    /* kept length */
    if (klen == 0) return ssh_put_u32(b, off, cap, 0);  /* value 0 -> empty string */
    uint32_t pad = (be[i] & 0x80) ? 1u : 0u;  /* prepend 0x00 if MSB set */
    off = ssh_put_u32(b, off, cap, klen + pad);
    if (pad) off = ssh_put_byte(b, off, cap, 0x00);
    return ssh_put_bytes(b, off, cap, be + i, klen);
}

uint32_t ssh_pkt_frame(uint8_t *out, uint32_t outmax, const uint8_t *payload, uint32_t plen) {
    uint8_t padlen = (uint8_t)(8 - ((plen + 5) % 8));
    if (padlen < 4) padlen += 8;
    uint32_t pktlen = 1u + plen + padlen;     /* padding_length byte + payload + padding */
    if (4 + pktlen > outmax || 4 + pktlen < plen) return 0;
    out[0] = (uint8_t)(pktlen >> 24); out[1] = (uint8_t)(pktlen >> 16);
    out[2] = (uint8_t)(pktlen >> 8);  out[3] = (uint8_t)pktlen;
    out[4] = padlen;
    if (plen) memcpy(out + 5, payload, plen);
    memset(out + 5 + plen, 0, padlen);
    return 4 + pktlen;
}
