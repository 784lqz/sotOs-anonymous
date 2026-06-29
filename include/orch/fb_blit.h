#ifndef ORCH_FB_BLIT_H
#define ORCH_FB_BLIT_H
#include <stdint.h>
/* Integer-scale (nearest-neighbor) a BGRX source image to the largest integer
 * factor that fits dst, centered, letterboxed with black. 4 bytes/pixel. */
void fb_blit_scale_fill(uint8_t *dst, int dw, int dh, int dstride,
                        const uint8_t *src, int sw, int sh);
#endif
