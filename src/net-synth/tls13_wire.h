#ifndef NET_SYNTH_TLS13_WIRE_H
#define NET_SYNTH_TLS13_WIRE_H
#include <stdint.h>
#include <stddef.h>
size_t tls13_wr8 (uint8_t *p, uint8_t v);
size_t tls13_wr16(uint8_t *p, uint16_t v);
size_t tls13_wr24(uint8_t *p, uint32_t v);
size_t tls13_wr32(uint8_t *p, uint32_t v);
uint16_t tls13_rd16(const uint8_t *p);
uint32_t tls13_rd24(const uint8_t *p);
#endif
