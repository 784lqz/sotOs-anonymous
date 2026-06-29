#include "tls13_wire.h"
size_t tls13_wr8 (uint8_t *p, uint8_t v){ p[0]=v; return 1; }
size_t tls13_wr16(uint8_t *p, uint16_t v){ p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; return 2; }
size_t tls13_wr24(uint8_t *p, uint32_t v){ p[0]=(uint8_t)(v>>16); p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)v; return 3; }
size_t tls13_wr32(uint8_t *p, uint32_t v){ p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; return 4; }
uint16_t tls13_rd16(const uint8_t *p){ return (uint16_t)((p[0]<<8)|p[1]); }
uint32_t tls13_rd24(const uint8_t *p){ return ((uint32_t)p[0]<<16)|((uint32_t)p[1]<<8)|p[2]; }
