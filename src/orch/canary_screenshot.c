/* sotOs · orch · Wayland L14a Canary Screenshot pool.
 *
 * The INVERSE of L13's shm_pool.  L13 took a client's own RW pool and exposed a
 * RO copy to the compositor (client draws, compositor scans out).  Here orch
 * OWNS a baked GNOME-desktop frame (the "Canary Screenshot") and maps it
 * READ-ONLY into a hostile client's address space — so a screen-capture /
 * frame-grab attempt reads the installed scene, never the real screen.
 *
 * Originals → orch's OWN PML4, read-write (orch memcpy's the baked asset in).
 * RO copies → hostile client vspace, read-only  (the client reads the install).
 *
 * Self-map uses sel4utils_map_page into SEL4UTILS_PD_SLOT (the
 * orch_parent_new_pages idiom in spawn.c:163) — orch's g_parent_vspace
 * implements only new_pages/map_pages/get_cap, so vspace_reserve_range_at /
 * orch_parent_vspace_ptr are NOT usable for orch's own space.  Per-view RO caps
 * are minted per-call (vka_cspace_alloc_path + vka_cnode_copy with seL4_CanRead)
 * because one frame cap maps into at most one vspace — exactly shm_pool.c's
 * cap-copy idiom.
 */
#include "canary_screenshot.h"
#include <stdio.h>
#include <string.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <vka/capops.h>          /* vka_cnode_copy / vka_cnode_delete */
#include <sel4utils/mapping.h>
#include <sel4utils/vspace.h>
#include <sel4utils/process.h>   /* SEL4UTILS_PD_SLOT */

extern vka_t *orch_vka(void);
#define PAGE_4K 4096u
#define CANARY_SCREENSHOT_MAX_FRAMES 1024
#define CANARY_SCREENSHOT_ORCH_VIEW_BASE 0x3000000000UL   /* orch self-view window to draw the asset */

static struct { int used; size_t nframes; uint32_t w,h,stride,csum; uintptr_t orch_va;
                vka_object_t frames[CANARY_SCREENSHOT_MAX_FRAMES]; } g_canary_screenshot;

static uint32_t fnv1a(const uint8_t *p, size_t n){uint32_t h=2166136261u;for(size_t i=0;i<n;i++){h^=p[i];h*=16777619u;}return h;}

int orch_canary_screenshot_init(const uint8_t *bgra, uint32_t len, uint32_t w, uint32_t h)
{
    if (g_canary_screenshot.used) return 0;
    size_t nframes = (len + PAGE_4K - 1) / PAGE_4K;
    if (nframes > CANARY_SCREENSHOT_MAX_FRAMES) { printf("[canary] %u B too big\n", len); return -1; }
    vka_t *vka = orch_vka();
    for (size_t i = 0; i < nframes; ++i)
        if (vka_alloc_frame(vka, seL4_PageBits, &g_canary_screenshot.frames[i])) {
            printf("[canary] alloc_frame %zu failed\n", i);
            for (size_t j=0;j<i;++j) vka_free_object(vka,&g_canary_screenshot.frames[j]); return -1;
        }
    /* Map ORIGINALS RW into orch's OWN PML4 (SEL4UTILS_PD_SLOT) at a fixed bump
     * vaddr, then memcpy the asset. (orch_parent_new_pages idiom — g_parent_vspace
     * has no reserve/map_at_vaddr.) */
    uintptr_t base = CANARY_SCREENSHOT_ORCH_VIEW_BASE;
    for (size_t i = 0; i < nframes; ++i) {
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS]; int npaging = VSPACE_MAP_PAGING_OBJECTS;
        if (sel4utils_map_page(vka, SEL4UTILS_PD_SLOT, g_canary_screenshot.frames[i].cptr,
                               (void *)(base + i*PAGE_4K), seL4_AllRights, 1, paging, &npaging)) {
            printf("[canary] orch self-map frame %zu @0x%lx failed\n", i, base+i*PAGE_4K);
            for (size_t j=0;j<nframes;++j) vka_free_object(vka,&g_canary_screenshot.frames[j]); return -1;
        }
    }
    memcpy((void *)base, bgra, len);
    g_canary_screenshot.used=1; g_canary_screenshot.nframes=nframes; g_canary_screenshot.w=w; g_canary_screenshot.h=h; g_canary_screenshot.stride=w*4;
    g_canary_screenshot.orch_va=base;
    g_canary_screenshot.csum = fnv1a((const uint8_t*)base, len);
    printf("[canary] init %ux%u %u frames fnv1a=0x%08x\n", w, h, (unsigned)nframes, g_canary_screenshot.csum);
    return 0;
}

uintptr_t orch_canary_screenshot_map_view(vspace_t *cv, uintptr_t base, uint32_t *w, uint32_t *h, uint32_t *stride)
{
    if (!g_canary_screenshot.used || !cv) return 0;
    vka_t *vka = orch_vka();
    /* β·static: orch_main is single-threaded — one map_view completes before the next begins,
     * so a shared static view-buffer is safe and avoids a ~120 KiB stack frame at full-res. */
    static seL4_CPtr ro[CANARY_SCREENSHOT_MAX_FRAMES]; static cspacepath_t rop[CANARY_SCREENSHOT_MAX_FRAMES]; size_t made = 0;
    for (size_t i=0;i<g_canary_screenshot.nframes;++i) {            /* fresh RO copy per view */
        cspacepath_t src; vka_cspace_make_path(vka, g_canary_screenshot.frames[i].cptr, &src);
        if (vka_cspace_alloc_path(vka,&rop[i]) || vka_cnode_copy(&rop[i],&src,seL4_CanRead)) {
            printf("[canary] view copy %zu failed\n", i);
            for (size_t j=0;j<made;++j){ vka_cnode_delete(&rop[j]); vka_cspace_free_path(vka,rop[j]); }
            return 0;
        }
        ro[i]=rop[i].capPtr; made++;
    }
    reservation_t r = vspace_reserve_range_at(cv,(void*)base,g_canary_screenshot.nframes*PAGE_4K,seL4_CanRead,1);
    if (!r.res) { printf("[canary] client reserve @0x%lx failed\n", base);
        for (size_t j=0;j<made;++j){ vka_cnode_delete(&rop[j]); vka_cspace_free_path(vka,rop[j]); } return 0; }
    if (vspace_map_pages_at_vaddr(cv, ro, NULL, (void*)base, g_canary_screenshot.nframes, seL4_PageBits, r)) {
        printf("[canary] client map @0x%lx failed\n", base);
        /* map_pages_at_vaddr may install some pages before failing — unmap the
         * range so no frames dangle in the client vspace, then free caps+reservation. */
        vspace_unmap_pages(cv, (void*)base, g_canary_screenshot.nframes, seL4_PageBits, NULL);
        vspace_free_reservation(cv, r);
        for (size_t j=0;j<made;++j){ vka_cnode_delete(&rop[j]); vka_cspace_free_path(vka,rop[j]); } return 0; }
    if (w)*w=g_canary_screenshot.w; if (h)*h=g_canary_screenshot.h; if (stride)*stride=g_canary_screenshot.stride;
    printf("[canary] view mapped @0x%lx (%zu frames RO)\n", base, g_canary_screenshot.nframes);
    return base;
}
uint32_t orch_canary_screenshot_checksum(void){ return g_canary_screenshot.csum; }
int orch_canary_screenshot_ready(void){ return g_canary_screenshot.used; }
