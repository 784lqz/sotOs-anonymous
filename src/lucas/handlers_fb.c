/* Doom Phase 1a · /dev/fb0 present handler. write(fb_fd, frame, len) lands here:
 * copy the client's frame, hash it, count it, and base64-dump one frame over
 * serial (between markers) for a PPM eyeball. */
#include "state.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <orch/virtio_gpu.h>
#include <orch/fb_blit.h>

#define DOOM_RESX 640
#define DOOM_RESY 400
#define DOOM_DUMP_FRAME 320   /* gameplay · after the scripted ENTERs reach E1M1 */

extern int lucas_copy_from_client(lucas_state_t *st, uintptr_t client_vaddr, void *buf, size_t size);
extern int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr, const void *src, size_t n);

uint32_t lucas_fnv1a(const uint8_t *p, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static void fb_b64_line(const uint8_t *src, size_t n) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char out[80]; int oi = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)src[i] << 16;
        if (i + 1 < n) v |= (uint32_t)src[i+1] << 8;
        if (i + 2 < n) v |= (uint32_t)src[i+2];
        out[oi++] = T[(v>>18)&63]; out[oi++] = T[(v>>12)&63];
        out[oi++] = (i+1<n) ? T[(v>>6)&63] : '=';
        out[oi++] = (i+2<n) ? T[v&63]      : '=';
        if (oi >= 72) { out[oi]=0; printf("%s\n", out); oi=0; }
    }
    if (oi) { out[oi]=0; printf("%s\n", out); }
}

/* write(LUCAS_FD_FB) → here. Returns `count` (client believes it succeeded). */
int64_t lucas_fb_present(lucas_state_t *st, uint64_t buf_vaddr, uint64_t count) {
    static uint8_t frame[DOOM_RESX * DOOM_RESY * 4];
    size_t n = (count < sizeof(frame)) ? (size_t)count : sizeof(frame);
    if (lucas_copy_from_client(st, (uintptr_t)buf_vaddr, frame, n) != 0)
        return (int64_t)count;
    uint32_t h = lucas_fnv1a(frame, n);
    int f = ++st->doom_frame;
    printf("[doom] frame=%d fnv1a=0x%08x bytes=%zu\n", f, h, n);
    /* Derive the frame dims from the byte count · doomgeneric presents 640x400,
     * Chocolate Doom presents the native 320x200. The decoder builds the PPM
     * header from the [doom-ppm-begin] WxH line, so we b64 only the RGB rows. */
    int w = 0, ht = 0;
    if      (n == (size_t)320 * 200 * 4) { w = 320; ht = 200; }
    else if (n == (size_t)640 * 400 * 4) { w = 640; ht = 400; }
    /* Live plane: if the virtio-gpu console is up, scale-fill this Doom frame
     * into the scanout and flush — Doom renders live in the QEMU window. */
    int gw = 0, gh = 0, gstride = 0;
    uint8_t *gfb = w ? gpu_fb(&gw, &gh, &gstride) : NULL;

    /* Headless ONLY (no live window): base64-dump one frame over serial so the
     * headless doom-gate can decode + eyeball it.  Skipped when a GPU console is
     * present — the operator already sees the live window, and the synchronous
     * UART dump (200-400 base64 lines) would freeze the interactive frame loop
     * for a couple of seconds at frame 320. */
    if (f == DOOM_DUMP_FRAME && w && !gfb) {
        printf("[doom-ppm-begin] %dx%d\n", w, ht);
        static uint8_t row[640 * 3];
        for (int y = 0; y < ht; ++y) {
            const uint8_t *s = frame + (size_t)y * w * 4;
            for (int x = 0; x < w; ++x) {   /* mem is [B,G,R,A] → PPM RGB */
                row[x*3+0] = s[x*4+2];  /* R */
                row[x*3+1] = s[x*4+1];  /* G */
                row[x*3+2] = s[x*4+0];  /* B */
            }
            fb_b64_line(row, (size_t)w * 3);
        }
        printf("[doom-ppm-end]\n");
    }

    if (gfb) {
        fb_blit_scale_fill(gfb, gw, gh, gstride, frame, w, ht);
        gpu_flush(0, 0, gw, gh);
    }
    return (int64_t)count;
}

/* fbdev GET ioctls · canned 640x400 32bpp so a vanilla fbdev consumer is happy. */
int64_t lucas_fb_ioctl(lucas_state_t *st, uint64_t request, uint64_t argp) {
    uint8_t buf[160]; memset(buf, 0, sizeof(buf));
    if (request == 0x4600u) {            /* FBIOGET_VSCREENINFO */
        ((uint32_t*)buf)[0] = DOOM_RESX; /* xres */
        ((uint32_t*)buf)[1] = DOOM_RESY; /* yres */
        ((uint32_t*)buf)[6] = 32;        /* bits_per_pixel (offset 24) */
        lucas_copy_to_client(st, (uintptr_t)argp, buf, sizeof(buf));
        return 0;
    }
    if (request == 0x4602u) {            /* FBIOGET_FSCREENINFO */
        lucas_copy_to_client(st, (uintptr_t)argp, buf, sizeof(buf));
        return 0;
    }
    return -(int64_t)22;   /* -EINVAL */
}
