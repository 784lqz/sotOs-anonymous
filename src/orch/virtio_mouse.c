#include <orch/virtio_mouse.h>
#include <stdint.h>

/* ---- pure mapping (always compiled; host-unit-tested) ---- */

/*
 * Virtio tablet reports ABS_X/ABS_Y in the range [0, 32767] (QEMU default).
 * Map to [0, screen_dim-1] with correct rounding and clamping.
 */
int mouse_abs_to_screen(uint32_t absval, int screen_dim)
{
    if (screen_dim <= 0) return 0;
    uint64_t v = (uint64_t)absval * (uint64_t)screen_dim / 32768u;
    if ((int)v >= screen_dim) v = (uint64_t)(screen_dim - 1);
    return (int)v;
}

/* ======================================================================== */
#ifndef VIRTIO_MOUSE_HOST_TEST
/* ======================================================================== */

#include <sotfs/virtio_modern.h>
#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>
#include <orch/virtio_gpu.h>
#include <stdio.h>
#include <string.h>

extern vka_t *orch_vka(void);

#define VIRTIO_INPUT_DEVID 0x1052

struct virtio_input_event {
    uint16_t type;
    uint16_t code;
    uint32_t value;
} __attribute__((packed));

/* EV_* types */
#define EV_SYN 0
#define EV_KEY 1
#define EV_ABS 3

/* ABS axis codes */
#define ABS_X 0
#define ABS_Y 1

/* Button codes */
#define BTN_LEFT 0x110

/* Cursor sprite dimensions.  The 8x12 base glyph is tiny on a 1280x800 scanout
 * shown live in a window — scale it up so it is actually visible. */
#define CURSOR_W 8
#define CURSOR_H 12
#define CURSOR_SCALE 3
#define CUR_PW (CURSOR_W * CURSOR_SCALE)   /* drawn footprint width  = 24 */
#define CUR_PH (CURSOR_H * CURSOR_SCALE)   /* drawn footprint height = 36 */

/* ---- device state ---- */
static virtio_dev_t g_tab;
static virtq_t      g_evq;
static struct virtio_input_event *g_evbuf;
static uintptr_t    g_evbuf_pa;
static int          g_inited;

/* ---- cursor state ---- */
static int      g_mx, g_my;
static int      g_btn;
static uint32_t g_rawx, g_rawy;
static uint8_t  g_under[CUR_PW * CUR_PH * 4];   /* saved pixels under the scaled sprite (BGRX) */
static int      g_have_under;

/*
 * Allocate one 4K page from the kernel, mapped at a static VA in the
 * 0x32000000 region (distinct from kbd's 0x31000000 and gpu's 0x30000000).
 */
static void *mouse_alloc_page(uintptr_t *pa)
{
    static uintptr_t va = 0x32000000UL;
    vka_t *vka = orch_vka();
    vka_object_t f;
    if (vka_alloc_frame(vka, seL4_PageBits, &f)) return NULL;
    void *v = (void *)va;
    vka_object_t pg[VSPACE_MAP_PAGING_OBJECTS];
    int np = VSPACE_MAP_PAGING_OBJECTS;
    if (sel4utils_map_page(vka, SEL4UTILS_PD_SLOT, f.cptr, v,
                           seL4_AllRights, 1, pg, &np))
        return NULL;
    va += 0x1000;
    *pa = (uintptr_t)seL4_X86_Page_GetAddress(f.cptr).paddr;
    memset(v, 0, 0x1000);
    return v;
}

/* ---- framebuffer pixel helpers ---- */

/* Read one BGRX pixel (4 bytes) at (px,py); bounds-clamped. */
static uint32_t fb_read_px(uint8_t *fb, int stride, int w, int h, int px, int py)
{
    if (px < 0 || py < 0 || px >= w || py >= h) return 0;
    uint32_t v;
    memcpy(&v, fb + py * stride + px * 4, 4);
    return v;
}

/* Write one BGRX pixel at (px,py); bounds-checked. */
static void fb_write_px(uint8_t *fb, int stride, int w, int h,
                        int px, int py, uint32_t pixel)
{
    if (px < 0 || py < 0 || px >= w || py >= h) return;
    memcpy(fb + py * stride + px * 4, &pixel, 4);
}

/*
 * A minimal arrow-style cursor sprite: solid white body with a 1-px black
 * border.  1=white body, 2=black border, 0=transparent.
 *
 *   BBBBBBB_
 *   BWWWWWB_
 *   BWWWBB__
 *   BWWBWB__
 *   BWBWWBB_
 *   BB_BWWWB
 *   B___BWWB
 *   ____BWWB  (12 rows × 8 cols, _ = transparent)
 *   ____BBWB
 *   _____BWB
 *   _____BBB
 *   _______B  (trailing pixel for bottom-right corner)
 *
 * Encoded as a 12×8 table: 0=transparent, 1=white (0x00FFFFFF in BGRX),
 * 2=black (0x00000000 in BGRX).
 */
static const uint8_t k_cursor[CURSOR_H][CURSOR_W] = {
    { 2,2,2,2,2,2,2,0 },
    { 2,1,1,1,1,1,2,0 },
    { 2,1,1,1,2,2,0,0 },
    { 2,1,1,2,1,2,0,0 },
    { 2,1,2,1,1,2,2,0 },
    { 2,2,0,2,1,1,1,2 },
    { 2,0,0,0,2,1,1,2 },
    { 0,0,0,0,2,1,1,2 },
    { 0,0,0,0,2,2,1,2 },
    { 0,0,0,0,0,2,1,2 },
    { 0,0,0,0,0,2,2,2 },
    { 0,0,0,0,0,0,0,2 },
};

#define PX_WHITE 0x00FFFFFFu
#define PX_BLACK 0x00000000u

/*
 * cursor_update — called on every EV_SYN after accumulating ABS_X/ABS_Y.
 * 1. Restore saved pixels under OLD cursor position.
 * 2. Compute new screen position.
 * 3. Save pixels under NEW cursor position.
 * 4. Draw cursor sprite at new position.
 * 5. gpu_flush the union bounding box of old and new rects.
 */
static void cursor_update(void)
{
    int w, h, stride;
    uint8_t *fb = gpu_fb(&w, &h, &stride);
    if (!fb) return;

    int nx = mouse_abs_to_screen(g_rawx, w);
    int ny = mouse_abs_to_screen(g_rawy, h);

    /* Early-out: skip redundant restore/save/draw/flush if the cursor
     * hasn't moved and the under-buffer is already valid. */
    if (nx == g_mx && ny == g_my && g_have_under) return;

    /* Always restore old cursor (even if position unchanged, to handle fb
     * content that may have changed underneath). */
    int ox = g_mx, oy = g_my;

    if (g_have_under) {
        /* Restore saved pixels under old cursor (scaled footprint). */
        for (int row = 0; row < CUR_PH; row++) {
            for (int col = 0; col < CUR_PW; col++) {
                if (k_cursor[row / CURSOR_SCALE][col / CURSOR_SCALE] == 0) continue;
                int px = ox + col, py = oy + row;
                if (px < 0 || py < 0 || px >= w || py >= h) continue;
                uint32_t saved;
                memcpy(&saved, g_under + (row * CUR_PW + col) * 4, 4);
                fb_write_px(fb, stride, w, h, px, py, saved);
            }
        }
    }

    /* Save pixels under new cursor position (scaled footprint). */
    for (int row = 0; row < CUR_PH; row++) {
        for (int col = 0; col < CUR_PW; col++) {
            if (k_cursor[row / CURSOR_SCALE][col / CURSOR_SCALE] == 0) continue;
            uint32_t px_val = fb_read_px(fb, stride, w, h, nx + col, ny + row);
            memcpy(g_under + (row * CUR_PW + col) * 4, &px_val, 4);
        }
    }
    g_have_under = 1;

    /* Draw cursor at new position (each base glyph pixel → CURSOR_SCALE² block). */
    for (int row = 0; row < CUR_PH; row++) {
        for (int col = 0; col < CUR_PW; col++) {
            uint8_t kind = k_cursor[row / CURSOR_SCALE][col / CURSOR_SCALE];
            if (kind == 0) continue;
            uint32_t pixel = (kind == 1) ? PX_WHITE : PX_BLACK;
            fb_write_px(fb, stride, w, h, nx + col, ny + row, pixel);
        }
    }

    g_mx = nx;
    g_my = ny;

    /* Flush the union bounding box of old and new cursor rects. */
    int ux0 = (ox < nx) ? ox : nx;
    int uy0 = (oy < ny) ? oy : ny;
    int ux1 = (ox + CUR_PW > nx + CUR_PW) ? ox + CUR_PW : nx + CUR_PW;
    int uy1 = (oy + CUR_PH > ny + CUR_PH) ? oy + CUR_PH : ny + CUR_PH;
    /* Clamp to framebuffer dimensions. */
    if (ux0 < 0)  ux0 = 0;
    if (uy0 < 0)  uy0 = 0;
    if (ux1 > w)  ux1 = w;
    if (uy1 > h)  uy1 = h;
    if (ux1 > ux0 && uy1 > uy0)
        gpu_flush(ux0, uy0, ux1 - ux0, uy1 - uy0);
}

/* ---- public API ---- */

int mouse_init(void)
{
    if (virtio_modern_probe(VIRTIO_INPUT_DEVID, 1, &g_tab) != 0) {
        printf("[mouse] no virtio-tablet\n");
        return -1;
    }
    if (virtio_modern_negotiate(&g_tab, 0) != 0) return -1;
    if (virtio_modern_setup_queue(&g_tab, 0, &g_evq) != 0) return -1;
    virtio_modern_driver_ok(&g_tab);

    g_evbuf = mouse_alloc_page(&g_evbuf_pa);
    if (!g_evbuf) return -1;

    /* Pre-post all descriptors as device-writable (device fills events in). */
    for (int i = 0; i < g_evq.qsz; ++i) {
        g_evq.desc[i].addr  = g_evbuf_pa + (uintptr_t)i * sizeof(struct virtio_input_event);
        g_evq.desc[i].len   = sizeof(struct virtio_input_event);
        g_evq.desc[i].flags = VIRTQ_DESC_F_WRITE;
        g_evq.desc[i].next  = 0;
        g_evq.avail->ring[i] = (uint16_t)i;
    }
    __atomic_store_n(&g_evq.avail->idx, (uint16_t)g_evq.qsz, __ATOMIC_RELEASE);
    *g_evq.notify = 0;
    g_evq.last_used = 0;
    g_inited = 1;

    printf("[mouse] virtio-tablet ready (qsz=%u)\n", g_evq.qsz);
    return 0;
}

void mouse_poll(void)
{
    if (!g_inited) return;

    uint16_t ui = __atomic_load_n(&g_evq.used->idx, __ATOMIC_ACQUIRE);
    while (g_evq.last_used != ui) {
        uint16_t slot = g_evq.last_used % g_evq.qsz;
        uint32_t id   = g_evq.used->ring[slot].id;
        struct virtio_input_event *e = &g_evbuf[id];

        if (e->type == EV_ABS) {
            if      (e->code == ABS_X) g_rawx = e->value;
            else if (e->code == ABS_Y) g_rawy = e->value;
        } else if (e->type == EV_KEY) {
            if (e->code == BTN_LEFT) g_btn = (e->value != 0);
        } else if (e->type == EV_SYN) {
            cursor_update();
        }

        /* Re-post the descriptor back into the avail ring. */
        uint16_t a = __atomic_load_n(&g_evq.avail->idx, __ATOMIC_RELAXED);
        g_evq.avail->ring[a % g_evq.qsz] = (uint16_t)id;
        __atomic_store_n(&g_evq.avail->idx, (uint16_t)(a + 1), __ATOMIC_RELEASE);
        g_evq.last_used++;
    }
    *g_evq.notify = 0;
}

/* M2 #3 · Doom mouse-look. Relative motion (delta of the absolute tablet
 * position since the last call, tablet units) + button bitmask (bit0=left).
 * Returns 0 + fills outs; -1 if no device. Read via /dev/doommouse. */
int mouse_raw_get(int *dx, int *dy, int *buttons)
{
    if (!g_inited) return -1;
    static uint32_t last_x = 0, last_y = 0; static int seeded = 0;
    mouse_poll();   /* fresh absolute position */
    if (!seeded) { last_x = g_rawx; last_y = g_rawy; seeded = 1; }
    *dx = (int)g_rawx - (int)last_x;
    *dy = (int)g_rawy - (int)last_y;
    *buttons = g_btn ? 1 : 0;
    last_x = g_rawx; last_y = g_rawy;
    return 0;
}
int mouse_present(void) { return g_inited; }

/* v2.7 live wayland pointer · absolute cursor in SCREEN pixels (0..scanout_w/h)
 * + left-button state.  Unlike mouse_raw_get (relative deltas, Doom mouse-look),
 * this exposes the current absolute position so LUCAS can map it to a surface and
 * synthesize wl_pointer.enter/motion/button.  Returns 1 if a tablet is present
 * (outs valid), 0 if headless. */
int mouse_state(int *x, int *y, int *btn)
{
    if (!g_inited) return 0;
    if (x)   *x   = g_mx;
    if (y)   *y   = g_my;
    if (btn) *btn = g_btn ? 1 : 0;
    return 1;
}

/* ======================================================================== */
#else   /* VIRTIO_MOUSE_HOST_TEST stubs */
/* ======================================================================== */

int  mouse_init(void) { return -1; }
void mouse_poll(void) {}
int  mouse_raw_get(int *dx, int *dy, int *b) { (void)dx;(void)dy;(void)b; return -1; }
int  mouse_present(void) { return 0; }
int  mouse_state(int *x, int *y, int *btn) { (void)x;(void)y;(void)btn; return 0; }

#endif  /* VIRTIO_MOUSE_HOST_TEST */
