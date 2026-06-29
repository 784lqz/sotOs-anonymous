/* sotOs · orch · Wayland L14b xkb keymap pool — see keymap.h. A near-clone of
 * canary_screenshot.c (same self-map + per-view RO-copy idiom), for the keymap blob. */
#include "keymap.h"
#include <stdio.h>
#include <string.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <vka/capops.h>
#include <sel4utils/mapping.h>
#include <sel4utils/vspace.h>
#include <sel4utils/process.h>   /* SEL4UTILS_PD_SLOT */

extern vka_t *orch_vka(void);
#define PAGE_4K 4096u
#define KEYMAP_MAX_FRAMES 32                  /* 128 KiB cap, ample for a us keymap */
#define KEYMAP_ORCH_VIEW_BASE 0x3100000000UL  /* clear of canary's 0x3000000000 */

static struct { int used; size_t nframes; uint32_t size, csum; uintptr_t orch_va;
                vka_object_t frames[KEYMAP_MAX_FRAMES]; } g_km;

static uint32_t fnv1a(const uint8_t *p, size_t n){uint32_t h=2166136261u;for(size_t i=0;i<n;i++){h^=p[i];h*=16777619u;}return h;}

int orch_keymap_init(const uint8_t *blob, uint32_t len)
{
    if (g_km.used) return 0;
    size_t nframes = (len + PAGE_4K - 1) / PAGE_4K;
    if (nframes > KEYMAP_MAX_FRAMES) { printf("[keymap] %u B too big\n", len); return -1; }
    vka_t *vka = orch_vka();
    for (size_t i = 0; i < nframes; ++i)
        if (vka_alloc_frame(vka, seL4_PageBits, &g_km.frames[i])) {
            printf("[keymap] alloc_frame %zu failed\n", i);
            for (size_t j=0;j<i;++j) vka_free_object(vka,&g_km.frames[j]); return -1;
        }
    uintptr_t base = KEYMAP_ORCH_VIEW_BASE;
    for (size_t i = 0; i < nframes; ++i) {
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS]; int npaging = VSPACE_MAP_PAGING_OBJECTS;
        if (sel4utils_map_page(vka, SEL4UTILS_PD_SLOT, g_km.frames[i].cptr,
                               (void *)(base + i*PAGE_4K), seL4_AllRights, 1, paging, &npaging)) {
            printf("[keymap] orch self-map frame %zu failed\n", i);
            for (size_t j=0;j<nframes;++j) vka_free_object(vka,&g_km.frames[j]); return -1;
        }
    }
    memcpy((void *)base, blob, len);
    g_km.used=1; g_km.nframes=nframes; g_km.size=len; g_km.orch_va=base;
    g_km.csum = fnv1a((const uint8_t*)base, len);
    printf("[keymap] init %u B %u frames fnv1a=0x%08x\n", len, (unsigned)nframes, g_km.csum);
    return 0;
}

uintptr_t orch_keymap_map_view(vspace_t *cv, uintptr_t base, uint32_t *size)
{
    if (!g_km.used || !cv) return 0;
    vka_t *vka = orch_vka();
    static seL4_CPtr ro[KEYMAP_MAX_FRAMES]; static cspacepath_t rop[KEYMAP_MAX_FRAMES]; size_t made = 0;
    for (size_t i=0;i<g_km.nframes;++i) {
        cspacepath_t src; vka_cspace_make_path(vka, g_km.frames[i].cptr, &src);
        if (vka_cspace_alloc_path(vka,&rop[i]) || vka_cnode_copy(&rop[i],&src,seL4_CanRead)) {
            printf("[keymap] view copy %zu failed\n", i);
            for (size_t j=0;j<made;++j){ vka_cnode_delete(&rop[j]); vka_cspace_free_path(vka,rop[j]); }
            return 0;
        }
        ro[i]=rop[i].capPtr; made++;
    }
    reservation_t r = vspace_reserve_range_at(cv,(void*)base,g_km.nframes*PAGE_4K,seL4_CanRead,1);
    if (!r.res) { printf("[keymap] client reserve @0x%lx failed\n", base);
        for (size_t j=0;j<made;++j){ vka_cnode_delete(&rop[j]); vka_cspace_free_path(vka,rop[j]); } return 0; }
    if (vspace_map_pages_at_vaddr(cv, ro, NULL, (void*)base, g_km.nframes, seL4_PageBits, r)) {
        printf("[keymap] client map @0x%lx failed\n", base);
        vspace_unmap_pages(cv, (void*)base, g_km.nframes, seL4_PageBits, NULL);
        vspace_free_reservation(cv, r);
        for (size_t j=0;j<made;++j){ vka_cnode_delete(&rop[j]); vka_cspace_free_path(vka,rop[j]); } return 0; }
    if (size) *size = g_km.size;
    printf("[keymap] view mapped @0x%lx (%zu frames RO)\n", base, g_km.nframes);
    return base;
}
uint32_t orch_keymap_checksum(void){ return g_km.csum; }
int      orch_keymap_ready(void){ return g_km.used; }
uint32_t orch_keymap_size(void){ return g_km.size; }
