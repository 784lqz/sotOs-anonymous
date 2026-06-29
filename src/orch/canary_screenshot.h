#ifndef SOTOS_ORCH_CANARY_SCREENSHOT_H
#define SOTOS_ORCH_CANARY_SCREENSHOT_H
#include <sel4/sel4.h>
#include <vspace/vspace.h>
#include <stdint.h>
int orch_canary_screenshot_init(const uint8_t *bgra, uint32_t len, uint32_t w, uint32_t h);
uintptr_t orch_canary_screenshot_map_view(vspace_t *client_vspace, uintptr_t base,
                              uint32_t *w, uint32_t *h, uint32_t *stride);
uint32_t orch_canary_screenshot_checksum(void);
int orch_canary_screenshot_ready(void);
#endif
