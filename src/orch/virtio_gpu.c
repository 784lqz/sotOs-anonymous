#include <orch/virtio_gpu.h>
#include <sotfs/virtio_modern.h>
#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <vka/capops.h>          /* v2.6 · vka_cnode_copy (export scanout to the compositor) */
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>
#include <string.h>
#include <stdio.h>
extern vka_t *orch_vka(void);

#define VIRTIO_GPU_DEVID                  0x1050
#define VIRTIO_GPU_CMD_GET_DISPLAY_INFO   0x0100
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D 0x0101
#define VIRTIO_GPU_CMD_RESOURCE_UNREF     0x0102
#define VIRTIO_GPU_CMD_SET_SCANOUT        0x0103
#define VIRTIO_GPU_CMD_RESOURCE_FLUSH     0x0104
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D 0x0105
#define VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING 0x0106
#define VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING 0x0107
#define VIRTIO_GPU_RESP_OK_NODATA         0x1100
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO   0x1101
#define VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM  2

struct gpu_ctrl_hdr {
    uint32_t type, flags;
    uint64_t fence_id;
    uint32_t ctx_id, padding;
};
struct gpu_rect { uint32_t x, y, width, height; };
struct gpu_resp_display_info {
    struct gpu_ctrl_hdr hdr;
    struct { struct gpu_rect r; uint32_t enabled, flags; } pmodes[16];
};
struct gpu_resource_create_2d {
    struct gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
};
struct gpu_mem_entry {
    uint64_t addr;
    uint32_t length;
    uint32_t padding;
};
struct gpu_resource_attach_backing {
    struct gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
};
struct gpu_set_scanout {
    struct gpu_ctrl_hdr hdr;
    struct gpu_rect r;
    uint32_t scanout_id;
    uint32_t resource_id;
};
struct gpu_transfer_to_host_2d {
    struct gpu_ctrl_hdr hdr;
    struct gpu_rect r;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t padding;
};
struct gpu_resource_flush {
    struct gpu_ctrl_hdr hdr;
    struct gpu_rect r;
    uint32_t resource_id;
    uint32_t padding;
};

static virtio_dev_t g_gpu;
static virtq_t      g_controlq;
static uint8_t     *g_cmd;      /* shared cmd page: req@+0, resp@+2048 */
static uintptr_t    g_cmd_pa;

/* Alloc one zeroed 4K frame (cached, for DMA), map it into orch vspace.
 * Uses the same pattern as alloc_page() in virtio_pci_modern.c. */
static uintptr_t g_gpu_va_bump = 0x2D000000UL;

static void *gpu_alloc_page(uintptr_t *pa_out)
{
    vka_t *vka = orch_vka();
    vka_object_t f;
    if (vka_alloc_frame(vka, seL4_PageBits, &f)) return NULL;
    void *va = (void *)g_gpu_va_bump;
    vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
    int npaging = VSPACE_MAP_PAGING_OBJECTS;
    if (sel4utils_map_page(vka, SEL4UTILS_PD_SLOT, f.cptr, va,
                           seL4_AllRights, 1 /* cached */,
                           paging, &npaging))
        return NULL;
    g_gpu_va_bump += 0x1000;
    *pa_out = (uintptr_t)seL4_X86_Page_GetAddress(f.cptr).paddr;
    memset(va, 0, 0x1000);
    return va;
}

/* One request: req in g_cmd[0..req_len), resp in g_cmd[2048..2048+resp_len). */
static int gpu_cmd(uint32_t req_len, uint32_t resp_len)
{
    struct vio_buf bufs[2] = {
        { g_cmd_pa,        req_len,  0 },   /* device-readable  */
        { g_cmd_pa + 2048, resp_len, 1 },   /* device-writable  */
    };
    return virtio_modern_request(&g_gpu, &g_controlq, bufs, 2, 2000000);
}

/* Framebuffer state */
#define GPU_MAX_FB_PAGES 2048   /* up to 8 MiB fb (1280x800x4 ≈ 1000 pages) */
static uint8_t  *g_fb;
static int       g_fb_w, g_fb_h, g_fb_stride;
static uintptr_t g_fb_pa[GPU_MAX_FB_PAGES];
static seL4_CPtr g_fb_caps[GPU_MAX_FB_PAGES];   /* v2.6 · frame caps, to map the scanout into the compositor */
static int       g_fb_pages;

int gpu_init(void)
{
    if (virtio_modern_probe(VIRTIO_GPU_DEVID, 0, &g_gpu) != 0) {
        printf("[gpu] no virtio-gpu · headless\n");
        return -1;
    }
    if (virtio_modern_negotiate(&g_gpu, 0) != 0) return -1;
    if (virtio_modern_setup_queue(&g_gpu, 0, &g_controlq) != 0) return -1;
    virtio_modern_driver_ok(&g_gpu);

    g_cmd = gpu_alloc_page(&g_cmd_pa);
    if (!g_cmd) {
        printf("[gpu] cmd page alloc failed\n");
        return -1;
    }

    /* SPIKE: GET_DISPLAY_INFO round-trip validates the whole transport. */
    struct gpu_ctrl_hdr *req = (struct gpu_ctrl_hdr *)g_cmd;
    memset(req, 0, sizeof *req);
    req->type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO;
    if (gpu_cmd(sizeof *req, sizeof(struct gpu_resp_display_info)) != 0) {
        printf("[gpu] GET_DISPLAY_INFO request failed\n");
        return -1;
    }
    struct gpu_resp_display_info *di =
        (struct gpu_resp_display_info *)(g_cmd + 2048);
    printf("[gpu] DISPLAY_INFO resp=0x%x scanout0 %ux%u enabled=%u\n",
           (unsigned)di->hdr.type,
           (unsigned)di->pmodes[0].r.width,
           (unsigned)di->pmodes[0].r.height,
           (unsigned)di->pmodes[0].enabled);

    /* framebuffer size from scanout 0 (fallback 1024x768). */
    g_fb_w = di->pmodes[0].r.width  ? (int)di->pmodes[0].r.width  : 1024;
    g_fb_h = di->pmodes[0].r.height ? (int)di->pmodes[0].r.height : 768;
    g_fb_stride = g_fb_w * 4;
    size_t fb_bytes = (size_t)g_fb_stride * g_fb_h;
    g_fb_pages = (int)((fb_bytes + 0xFFF) / 0x1000);
    if (g_fb_pages > GPU_MAX_FB_PAGES) {
        printf("[gpu] fb too big (%d pages)\n", g_fb_pages);
        return -1;
    }

    /* allocate fb as per-page frames mapped at consecutive vaddrs (so g_fb is a
     * contiguous virtual buffer to draw into); capture each paddr for backing. */
    {
        static uintptr_t fb_va = 0x30000000UL;
        g_fb = (uint8_t *)fb_va;
        vka_t *vka = orch_vka();
        for (int i = 0; i < g_fb_pages; ++i) {
            vka_object_t f;
            if (vka_alloc_frame(vka, seL4_PageBits, &f)) {
                printf("[gpu] fb alloc fail @%d\n", i);
                return -1;
            }
            vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
            int npaging = VSPACE_MAP_PAGING_OBJECTS;
            if (sel4utils_map_page(vka, SEL4UTILS_PD_SLOT, f.cptr,
                                   (void *)(fb_va + (uintptr_t)i * 0x1000),
                                   seL4_AllRights, 1, paging, &npaging)) {
                printf("[gpu] fb map fail @%d\n", i);
                return -1;
            }
            g_fb_pa[i]   = (uintptr_t)seL4_X86_Page_GetAddress(f.cptr).paddr;
            g_fb_caps[i] = f.cptr;   /* v2.6 · keep the cap so the compositor can map the scanout */
        }
        memset(g_fb, 0, fb_bytes);
    }

    /* RESOURCE_CREATE_2D (id=1, BGRX, WxH). */
    {
        struct gpu_resource_create_2d *cr = (void *)g_cmd;
        memset(cr, 0, sizeof *cr);
        cr->hdr.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;
        cr->resource_id = 1;
        cr->format = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM;
        cr->width = (uint32_t)g_fb_w;
        cr->height = (uint32_t)g_fb_h;
        if (gpu_cmd(sizeof *cr, sizeof(struct gpu_ctrl_hdr)) != 0) {
            printf("[gpu] create_2d fail\n");
            return -1;
        }
        struct gpu_ctrl_hdr *r = (void *)(g_cmd + 2048);
        printf("[gpu] create_2d resp=0x%x\n", r->type);
    }

    /* RESOURCE_ATTACH_BACKING (id=1) via multi-descriptor chain (1000 entries).
     * The mem_entry array does NOT fit in the 2KB request half of g_cmd, so we
     * build a multi-descriptor chain using virtio_modern_request directly:
     *   desc0: the 32-byte attach_backing struct  (device-readable, in g_cmd[0..))
     *   desc1..M: pages each holding 256 gpu_mem_entry structs (device-readable)
     *   last desc: the response gpu_ctrl_hdr (device-writable, in g_cmd[2048..))
     */
    {
        int entries_per_page = 0x1000 / (int)sizeof(struct gpu_mem_entry);  /* 256 */
        int npages = (g_fb_pages + entries_per_page - 1) / entries_per_page;

        /* desc0 = the 32-byte command struct in g_cmd[0..]. */
        struct gpu_resource_attach_backing *ab = (void *)g_cmd;
        memset(ab, 0, sizeof *ab);
        ab->hdr.type = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING;
        ab->resource_id = 1;
        ab->nr_entries = (uint32_t)g_fb_pages;

        /* alloc + fill the entry pages. */
        /* GPU_MAX_FB_PAGES/256 = 8 worst case for 1000-page fb; +2 for safety. */
        #define GPU_MAX_ENT_PAGES (GPU_MAX_FB_PAGES / 256 + 2)
        static uint8_t  *ent_va[GPU_MAX_ENT_PAGES];
        static uintptr_t ent_pa[GPU_MAX_ENT_PAGES];

        for (int p = 0; p < npages; ++p) {
            ent_va[p] = gpu_alloc_page(&ent_pa[p]);
            if (!ent_va[p]) {
                printf("[gpu] backing page alloc fail\n");
                return -1;
            }
        }
        for (int i = 0; i < g_fb_pages; ++i) {
            struct gpu_mem_entry *e =
                (struct gpu_mem_entry *)(ent_va[i / entries_per_page])
                + (i % entries_per_page);
            e->addr    = g_fb_pa[i];
            e->length  = 0x1000;
            e->padding = 0;
        }

        /* build the descriptor chain: [cmd struct][entry pages...][resp]. */
        /* Max total descriptors: 1 (cmd) + GPU_MAX_ENT_PAGES + 1 (resp) */
        struct vio_buf bufs[2 + GPU_MAX_ENT_PAGES];
        int n = 0;
        bufs[n].paddr          = g_cmd_pa;
        bufs[n].len            = (uint32_t)sizeof *ab;
        bufs[n].device_writable = 0;
        n++;
        for (int p = 0; p < npages; ++p) {
            int remaining    = g_fb_pages - p * entries_per_page;
            int this_entries = remaining < entries_per_page ? remaining : entries_per_page;
            bufs[n].paddr          = ent_pa[p];
            bufs[n].len            = (uint32_t)this_entries * (uint32_t)sizeof(struct gpu_mem_entry);
            bufs[n].device_writable = 0;
            n++;
        }
        bufs[n].paddr          = g_cmd_pa + 2048;
        bufs[n].len            = (uint32_t)sizeof(struct gpu_ctrl_hdr);
        bufs[n].device_writable = 1;
        n++;

        if (virtio_modern_request(&g_gpu, &g_controlq, bufs, n, 2000000) != 0) {
            printf("[gpu] attach_backing fail\n");
            return -1;
        }
        struct gpu_ctrl_hdr *r = (void *)(g_cmd + 2048);
        printf("[gpu] attach_backing resp=0x%x (%d entries, %d pages)\n",
               r->type, g_fb_pages, npages);
    }

    /* SET_SCANOUT (scanout 0 -> resource 1). */
    {
        struct gpu_set_scanout *ss = (void *)g_cmd;
        memset(ss, 0, sizeof *ss);
        ss->hdr.type    = VIRTIO_GPU_CMD_SET_SCANOUT;
        ss->r.x         = 0;
        ss->r.y         = 0;
        ss->r.width     = (uint32_t)g_fb_w;
        ss->r.height    = (uint32_t)g_fb_h;
        ss->scanout_id  = 0;
        ss->resource_id = 1;
        if (gpu_cmd(sizeof *ss, sizeof(struct gpu_ctrl_hdr)) != 0) {
            printf("[gpu] set_scanout fail\n");
            return -1;
        }
        struct gpu_ctrl_hdr *r = (void *)(g_cmd + 2048);
        printf("[gpu] set_scanout resp=0x%x %dx%d\n", r->type, g_fb_w, g_fb_h);
    }

    return 0;
}

uint8_t *gpu_fb(int *w, int *h, int *stride)
{
    if (!g_fb) return NULL;
    if (w)      *w      = g_fb_w;
    if (h)      *h      = g_fb_h;
    if (stride) *stride = g_fb_stride;
    return g_fb;
}

/* v2.6 · map the scanout framebuffer into ANOTHER process's PD (the honest Wayland
 * compositor) at `va`, so the compositor can blit committed surfaces straight into
 * the scanout (orch keeps owning the virtqueue flush → no compositor→orch IPC on
 * the commit path, which would deadlock LUCAS while it awaits the commit reply).
 * Each fb page's cap is COPIED (a cap maps once per slot; orch's mapping stays) and
 * the copy is mapped RW.  Returns `va` and reports dims; 0 on failure. */
uintptr_t gpu_export_to_pd(seL4_CPtr pd, uintptr_t va, int *w, int *h, int *stride)
{
    if (!g_fb || pd == 0) return 0;
    vka_t *vka = orch_vka();
    for (int i = 0; i < g_fb_pages; ++i) {
        cspacepath_t src, dst;
        vka_cspace_make_path(vka, g_fb_caps[i], &src);
        if (vka_cspace_alloc_path(vka, &dst)) { printf("[gpu] export cspace_alloc fail @%d\n", i); return 0; }
        if (vka_cnode_copy(&dst, &src, seL4_AllRights)) { printf("[gpu] export cnode_copy fail @%d\n", i); return 0; }
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS]; int npaging = VSPACE_MAP_PAGING_OBJECTS;
        if (sel4utils_map_page(vka, pd, dst.capPtr, (void *)(va + (uintptr_t)i * 0x1000),
                               seL4_AllRights, 1, paging, &npaging)) {
            printf("[gpu] export map fail @%d @0x%lx\n", i, (unsigned long)(va + (uintptr_t)i*0x1000)); return 0;
        }
    }
    if (w)      *w      = g_fb_w;
    if (h)      *h      = g_fb_h;
    if (stride) *stride = g_fb_stride;
    printf("[gpu] scanout exported to compositor %dx%d stride=%d @0x%lx (%d pages)\n",
           g_fb_w, g_fb_h, g_fb_stride, (unsigned long)va, g_fb_pages);
    return va;
}

void gpu_flush(int x, int y, int w, int h)
{
    if (!g_fb) return;

    /* TRANSFER_TO_HOST_2D: copy the dirty rect from guest framebuffer to device. */
    struct gpu_transfer_to_host_2d *tr = (void *)g_cmd;
    memset(tr, 0, sizeof *tr);
    tr->hdr.type    = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D;
    tr->r.x         = (uint32_t)x;
    tr->r.y         = (uint32_t)y;
    tr->r.width     = (uint32_t)w;
    tr->r.height    = (uint32_t)h;
    tr->offset      = (uint64_t)y * (uint32_t)g_fb_stride + (uint64_t)x * 4;
    tr->resource_id = 1;
    gpu_cmd(sizeof *tr, sizeof(struct gpu_ctrl_hdr));

    /* RESOURCE_FLUSH: tell the host to push the rect to the display. */
    struct gpu_resource_flush *fl = (void *)g_cmd;
    memset(fl, 0, sizeof *fl);
    fl->hdr.type    = VIRTIO_GPU_CMD_RESOURCE_FLUSH;
    fl->r.x         = (uint32_t)x;
    fl->r.y         = (uint32_t)y;
    fl->r.width     = (uint32_t)w;
    fl->r.height    = (uint32_t)h;
    fl->resource_id = 1;
    gpu_cmd(sizeof *fl, sizeof(struct gpu_ctrl_hdr));
}

/* COALESCED present · a full-screen gpu_flush per wl_surface.commit (and per
 * cursor move) floods the virtio-gpu when the mouse moves over a GTK app — every
 * hover redraw + cursor-surface commit fires a 4 MiB TRANSFER+FLUSH, which
 * saturates QEMU's -display gtk iothread and freezes the window.  Instead, those
 * callers mark the scanout dirty and the orch fault-loop idle branch flushes ONCE
 * per pass, coalescing a whole burst of commits into a single present. */
static volatile int g_scanout_dirty;
void gpu_mark_dirty(void) { g_scanout_dirty = 1; }
void gpu_flush_if_dirty(void)
{
    if (!g_scanout_dirty) return;
    g_scanout_dirty = 0;
    if (g_fb) gpu_flush(0, 0, g_fb_w, g_fb_h);
}
