/* sotOs · orch · Wayland L14b xkb keymap pool. Mirrors orch_canary: orch owns a
 * baked xkb_v1 keymap blob and maps it READ-ONLY into a Tier-2 client so the
 * synthetic wl_keyboard can deliver a real keymap. */
#ifndef ORCH_KEYMAP_H
#define ORCH_KEYMAP_H
#include <stdint.h>
#include <sel4utils/vspace.h>
int       orch_keymap_init(const uint8_t *blob, uint32_t len);
uintptr_t orch_keymap_map_view(vspace_t *cv, uintptr_t base, uint32_t *size);
uint32_t  orch_keymap_checksum(void);
int       orch_keymap_ready(void);
uint32_t  orch_keymap_size(void);
#endif
