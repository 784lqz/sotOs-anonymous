#include <orch/fb_blit.h>
#include <string.h>

void fb_blit_scale_fill(uint8_t *dst, int dw, int dh, int dstride,
                        const uint8_t *src, int sw, int sh) {
    if (dw<=0||dh<=0||sw<=0||sh<=0) return;
    int fx = dw / sw, fy = dh / sh;
    int f = fx < fy ? fx : fy;            /* largest integer factor that fits */
    if (f < 1) f = 1;
    int ow = sw * f, oh = sh * f;          /* on-screen image size */
    int ox = (dw - ow) / 2, oy = (dh - oh) / 2;  /* centering offset */
    for (int y=0; y<dh; ++y) memset(dst + (size_t)y*dstride, 0, (size_t)dw*4);  /* black letterbox */
    for (int sy=0; sy<sh; ++sy) {
        const uint8_t *srow = src + (size_t)sy*sw*4;
        for (int ry=0; ry<f; ++ry) {
            int dy = oy + sy*f + ry;
            if ((unsigned)dy >= (unsigned)dh) continue;
            uint8_t *drow = dst + (size_t)dy*dstride + (size_t)ox*4;
            for (int sx=0; sx<sw; ++sx) {
                const uint8_t *sp = srow + (size_t)sx*4;
                for (int rx=0; rx<f; ++rx) {
                    int dx = sx*f + rx;
                    if ((unsigned)(ox+dx) >= (unsigned)dw) continue;
                    uint8_t *dp = drow + (size_t)dx*4;
                    dp[0]=sp[0]; dp[1]=sp[1]; dp[2]=sp[2]; dp[3]=0xFF;
                }
            }
        }
    }
}
