/*
 * sotOs · native Wayland compositor scaffold.
 *
 * L12-alpha: Path-D process only. Root passes a listen EP in argv[1] and
 * forwards a copy to orch so the next slice can route
 * /run/user/1000/wayland-0 connects here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sel4/sel4.h>

#define SEL4UTILS_INITIAL_EP_SLOT 1

/* L12-delta · advertised registry globals (name / interface / len-incl-NUL / version). */
struct wl_global { uint32_t name; const char *iface; uint32_t ifacelen; uint32_t version; };
static const struct wl_global GLOBALS[] = {
    { 1, "wl_compositor", 14, 4 },
    { 2, "wl_shm",         7, 1 },
    /* M2 · xdg_shell window-management. name=5 deliberately skips 3/4 (the
     * shadow compositor's sotos_capture/wl_seat names that LUCAS bind-tracking
     * special-cases) so a real toolkit binding xdg_wm_base isn't misread. */
    { 5, "xdg_wm_base",   12, 1 },
    /* M3 · a real toolkit (SDL2) unconditionally derefs d->input in
     * Wayland_InitMouse, which is only allocated when a wl_seat global exists →
     * a NULL deref (#PF at +0x100) without one.  name=6 keeps clear of the
     * shadow compositor's 3/4 (sotos_capture/wl_seat) that LUCAS special-cases. */
    /* v2.4 · GTK3's GDK binds wl_seat at MIN(version,5) and builds its GdkSeat
     * state machine for a modern seat (capabilities + name).  v1 left the seat
     * degenerate → gdk_display_get_default_seat()==NULL → GDK_IS_SEAT assert →
     * downstream xkb_keymap_ref(NULL) crash.  Bumped 1→5 + send wl_seat.name. */
    { 6, "wl_seat",        8, 5 },
    /* M3 · SDL's Wayland_VideoInit fails ("did not add any displays") unless a
     * wl_output exists.  v2 → geometry/mode/scale/done finalize one display. */
    { 7, "wl_output",     10, 2 },
    /* v2.4 · GTK3's GDK gates GdkWaylandSeat creation on BOTH wl_compositor AND
     * wl_data_device_manager being present (its deferred seat-creation closure).
     * Without this global GDK never creates a seat → the crash above.  name=8 is
     * clear of the shadow compositor's special-cased 3/4. */
    { 8, "wl_data_device_manager", 23, 3 },
};
#define N_GLOBALS (sizeof(GLOBALS) / sizeof(GLOBALS[0]))

/* L13-C1 · server-side object table. Dispatch is by object TYPE, not by
 * (obj!=1): wl_shm.create_pool and wl_registry.bind are both (obj!=1, op0). */
enum wl_otype { WL_NONE=0, WL_REGISTRY, WL_SHM, WL_COMPOSITOR_OBJ, WL_POOL, WL_BUFFER, WL_SURFACE,
                WL_XDG_WM_BASE, WL_XDG_SURFACE, WL_XDG_TOPLEVEL,    /* M2 · xdg_shell */
                WL_SEAT, WL_POINTER, WL_KEYBOARD, WL_TOUCH,         /* M3 · input seat */
                WL_OUTPUT, WL_REGION,                              /* M3 · display + region */
                WL_DATA_DEVICE_MANAGER, WL_DATA_DEVICE };          /* v2.4 · GTK seat gate */
struct wl_obj { uint32_t id; enum wl_otype type;
                uintptr_t vaddr; uint32_t size;                  /* pool */
                uint32_t offset, w, h, stride, format;           /* buffer (vaddr=pool.vaddr+offset) */
                uint32_t pending_buffer;                         /* surface */
                uint32_t role_xdg;                               /* surface → its xdg_surface id */
                uint32_t xs_wl_surface, xs_toplevel;             /* xdg_surface → wl_surface / toplevel */
                uint8_t  xs_needs_cfg; };                        /* xdg_surface → owes initial configure */
static struct wl_obj g_objs[64]; static int g_nobjs = 0;
#define N_OBJS ((int)(sizeof(g_objs)/sizeof(g_objs[0])))
/* v2.6 present · the virtio-gpu scanout, mapped into THIS PD by orch (via
 * gpu_export_to_pd) and reported to us in the create_pool appended words.  On a
 * surface commit we blit the committed buffer here; orch flushes it to the QEMU
 * display after replying.  va==0 → headless (no virtio-gpu / the gate boot) →
 * skip the blit (the protocol path still runs end to end). */
static uintptr_t g_scanout_va = 0;
static uint32_t  g_scanout_w = 0, g_scanout_h = 0, g_scanout_stride = 0;
/* M4 · reuse a freed slot (type==WL_NONE) before appending, so a client that
 * creates+destroys objects across window cycles doesn't monotonically exhaust
 * the table (was the obj=N EPROTO under create/destroy churn). */
static struct wl_obj *obj_add(uint32_t id, enum wl_otype t){
    int slot = -1;
    for (int i = 0; i < g_nobjs; ++i) if (g_objs[i].type == WL_NONE) { slot = i; break; }
    if (slot < 0) { if (g_nobjs >= N_OBJS) return 0; slot = g_nobjs++; }
    struct wl_obj *o = &g_objs[slot]; memset(o,0,sizeof(*o)); o->id=id; o->type=t; return o; }
/* M4 · free an object's slot on destroy (latest-binding-wins, like obj_find). */
static void obj_del(uint32_t id){
    for (int i=g_nobjs-1;i>=0;--i) if (g_objs[i].id==id && g_objs[i].type!=WL_NONE){
        g_objs[i].type=WL_NONE; g_objs[i].id=0; return; } }
/* Return the MOST-RECENT object with this id. The L13 object table is global
 * across all wayland clients, but Wayland object ids are per-connection; when
 * sequential clients reuse an id, latest-binding-wins approximates per-client
 * semantics (the active client's objects were added last). Per-connection state
 * is a future (L14 multi-client) refinement. */
static struct wl_obj *obj_find(uint32_t id){
    for (int i=g_nobjs-1;i>=0;--i) if (g_objs[i].id==id && g_objs[i].type!=WL_NONE) return &g_objs[i]; return 0; }
static uint32_t fnv1a(const uint8_t *p, size_t n){ uint32_t h=2166136261u; for(size_t i=0;i<n;i++){h^=p[i];h*=16777619u;} return h; }

/* Emit one wl_registry.global(name, interface, version) event into the reply
 * message registers starting at word index `mr`; return the next free index.
 * One 32-bit wire word per MR; the interface string is NUL-terminated and
 * zero-padded to a 4-byte boundary. */
static size_t emit_global(size_t mr, uint32_t registry, const struct wl_global *g)
{
    uint32_t slen   = g->ifacelen;             /* string length incl NUL */
    uint32_t padded = (slen + 3u) & ~3u;
    uint32_t nstr   = padded / 4;
    uint32_t words  = 2 + 1 + 1 + nstr + 1;    /* hdr + name + strlen + string + version */
    uint32_t size   = words * 4;
    seL4_SetMR(mr + 0, (seL4_Word)registry);
    seL4_SetMR(mr + 1, ((seL4_Word)size << 16) | 0);   /* opcode 0 = wl_registry.global */
    seL4_SetMR(mr + 2, (seL4_Word)g->name);
    seL4_SetMR(mr + 3, (seL4_Word)slen);
    for (uint32_t w = 0; w < nstr; ++w) {
        uint32_t word = 0;
        for (uint32_t bi = 0; bi < 4; ++bi) {
            uint32_t idx = w * 4 + bi;
            uint8_t  c   = (idx < slen) ? (uint8_t)g->iface[idx] : 0;
            word |= (uint32_t)c << (8 * bi);
        }
        seL4_SetMR(mr + 4 + w, (seL4_Word)word);
    }
    seL4_SetMR(mr + 4 + nstr, (seL4_Word)g->version);
    return mr + words;
}

/* M3 · pack a NUL-terminated, 4-byte-padded Wayland wire string (length word
 * incl NUL, then the padded bytes little-endian) starting at MR index `mr`;
 * return the next free index.  Mirrors emit_global's inner string loop — used
 * by the wl_output.geometry event (make/model strings). */
static size_t emit_str(size_t mr, const char *s, uint32_t slen)
{
    uint32_t padded = (slen + 3u) & ~3u, nstr = padded / 4;
    seL4_SetMR(mr++, (seL4_Word)slen);
    for (uint32_t w = 0; w < nstr; ++w) {
        uint32_t word = 0;
        for (uint32_t bi = 0; bi < 4; ++bi) {
            uint32_t idx = w * 4 + bi;
            uint8_t  c   = (idx < slen) ? (uint8_t)s[idx] : 0;
            word |= (uint32_t)c << (8 * bi);
        }
        seL4_SetMR(mr++, (seL4_Word)word);
    }
    return mr;
}

int main(int argc, char *argv[])
{
    seL4_CPtr listen_ep = SEL4UTILS_INITIAL_EP_SLOT;
    if (argc > 1 && argv[1]) {
        seL4_CPtr slot = (seL4_CPtr)atol(argv[1]);
        if (slot != 0) listen_ep = slot;
    }

    printf("[wl-compositor] alive · listen_ep=%lu path=/run/user/1000/wayland-0\n",
           (unsigned long)listen_ep);

    uint32_t serial = 0;   /* monotonic · wl_callback.done serial source */

    while (1) {
        seL4_MessageInfo_t info = seL4_Recv(listen_ep, NULL);
        seL4_Word len = seL4_MessageInfo_get_length(info);

        if (len < 2) {   /* min valid request = object id + header word (e.g. wl_surface.commit) */
            printf("[wl-compositor] short frame len=%lu · status EPROTO\n",
                   (unsigned long)len);
            seL4_Reply(seL4_MessageInfo_new(71, 0, 0, 0));   /* EPROTO */
            continue;
        }

        uint32_t obj    = (uint32_t)seL4_GetMR(0);
        uint32_t hdr1   = (uint32_t)seL4_GetMR(1);
        uint16_t opcode = (uint16_t)(hdr1 & 0xFFFF);
        uint16_t size   = (uint16_t)(hdr1 >> 16);
        uint32_t arg2   = (uint32_t)seL4_GetMR(2);   /* sync/get_registry: new_id · bind: name */

        if (obj == 1 && opcode == 0) {        /* wl_display.sync(new_id) */
            uint32_t s = ++serial;
            seL4_SetMR(0, (seL4_Word)arg2);                /* wl_callback.done on new_id */
            seL4_SetMR(1, ((seL4_Word)12 << 16) | 0);
            seL4_SetMR(2, (seL4_Word)s);
            seL4_SetMR(3, (seL4_Word)1);                   /* wl_display.delete_id(new_id) */
            seL4_SetMR(4, ((seL4_Word)12 << 16) | 1);
            seL4_SetMR(5, (seL4_Word)arg2);
            printf("[wl-compositor] sync obj=%u new_id=%u · done serial=%u + delete_id\n",
                   obj, arg2, s);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 6));
            continue;
        }

        if (obj == 1 && opcode == 1) {        /* wl_display.get_registry(new_id) */
            uint32_t registry = arg2;
            obj_add(registry, WL_REGISTRY);
            size_t mr = 0;
            for (size_t i = 0; i < N_GLOBALS; ++i)
                mr = emit_global(mr, registry, &GLOBALS[i]);
            printf("[wl-compositor] get_registry registry=%u · %u globals, %zu words\n",
                   registry, (unsigned)N_GLOBALS, mr);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, mr));
            continue;
        }

        /* obj != 1 · dispatch by OBJECT TYPE (not by obj!=1): wl_shm.create_pool
         * and wl_registry.bind are both (obj!=1, op0) and must not collide. */
        struct wl_obj *o = obj_find(obj);
        if (o) {
            if (o->type == WL_REGISTRY && opcode == 0) {   /* wl_registry.bind(name,iface,ver,new_id) */
                uint32_t name = arg2;             /* MR2 */
                if (len < 4) {
                    printf("[wl-compositor] bind short frame len=%lu · status EPROTO\n",
                           (unsigned long)len);
                    seL4_Reply(seL4_MessageInfo_new(71, 0, 0, 0));
                    continue;
                }
                uint32_t slen = (uint32_t)seL4_GetMR(3);
                uint32_t nstr = ((slen + 3u) & ~3u) / 4;
                if (slen > 64 || len < (seL4_Word)(4 + nstr + 2)) {
                    printf("[wl-compositor] bind name=%u bad iface len=%u (frame %lu words) · status EINVAL\n",
                           name, slen, (unsigned long)len);
                    seL4_Reply(seL4_MessageInfo_new(22, 0, 0, 0));   /* EINVAL */
                    continue;
                }
                uint32_t version = (uint32_t)seL4_GetMR(4 + nstr);
                uint32_t bound   = (uint32_t)seL4_GetMR(4 + nstr + 1);
                const struct wl_global *g = 0;
                for (size_t i = 0; i < N_GLOBALS; ++i)
                    if (GLOBALS[i].name == name) g = &GLOBALS[i];
                if (!g) {
                    printf("[wl-compositor] bind name=%u UNKNOWN · status EINVAL\n", name);
                    seL4_Reply(seL4_MessageInfo_new(22, 0, 0, 0));   /* EINVAL */
                    continue;
                }
                obj_add(bound, name == 1 ? WL_COMPOSITOR_OBJ
                            : name == 5 ? WL_XDG_WM_BASE
                            : name == 6 ? WL_SEAT
                            : name == 7 ? WL_OUTPUT
                            : name == 8 ? WL_DATA_DEVICE_MANAGER : WL_SHM);
                printf("[wl-compositor] bind name=%u interface=%s version=%u new_id=%u\n",
                       name, g->iface, version, bound);
                if (name == 2) {                  /* wl_shm: advertise supported formats */
                    seL4_SetMR(0, (seL4_Word)bound);
                    seL4_SetMR(1, ((seL4_Word)12 << 16) | 0);   /* wl_shm.format */
                    seL4_SetMR(2, (seL4_Word)0);                /* ARGB8888 */
                    seL4_SetMR(3, (seL4_Word)bound);
                    seL4_SetMR(4, ((seL4_Word)12 << 16) | 0);
                    seL4_SetMR(5, (seL4_Word)1);                /* XRGB8888 */
                    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 6));
                } else if (name == 6) {           /* wl_seat.capabilities(POINTER) + name */
                    /* v2.7 · capabilities=POINTER(1): advertise a pointer so a real
                     * toolkit calls wl_seat.get_pointer and accepts live
                     * wl_pointer.enter/motion/button (LUCAS synthesizes those from the
                     * virtio-tablet · see lucas_wl_try_stage_input).  KEYBOARD(2) is
                     * deliberately NOT set: wl_keyboard.keymap must pass the xkb map as
                     * an fd via SCM_RIGHTS, which the synchronous seL4_Call transport
                     * cannot carry — every toolkit would hang waiting for the keymap.
                     * With pointer-only, d->input is still allocated (Wayland_InitMouse
                     * happy) and GDK (v>=2) keeps its built-in default xkb keymap. */
                    seL4_SetMR(0, (seL4_Word)bound);
                    seL4_SetMR(1, ((seL4_Word)12 << 16) | 0);   /* wl_seat.capabilities · 12 B */
                    seL4_SetMR(2, (seL4_Word)1);                /* caps = WL_SEAT_CAPABILITY_POINTER */
                    seL4_SetMR(3, (seL4_Word)bound);            /* wl_seat.name (opcode 1) */
                    size_t nhdr = 4;                            /* header word placeholder */
                    size_t mr = emit_str(5, "seat0", 6);        /* name string from MR5 */
                    seL4_SetMR(nhdr, ((seL4_Word)((mr - 3) * 4) << 16) | 1);
                    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, mr));
                } else if (name == 7) {           /* M3 · wl_output: one 1280x720 display */
                    /* geometry(0) + mode(1) + scale(3) + done(2): one atomic update
                     * the client finalizes on `done` → SDL_AddVideoDisplay. */
                    size_t mr = 0;
                    size_t g0 = mr;                              /* geometry */
                    seL4_SetMR(mr++, (seL4_Word)bound);
                    size_t ghdr = mr++;                          /* size/opcode placeholder */
                    seL4_SetMR(mr++, 0);                         /* x */
                    seL4_SetMR(mr++, 0);                         /* y */
                    seL4_SetMR(mr++, 300);                       /* phys_width  mm */
                    seL4_SetMR(mr++, 190);                       /* phys_height mm */
                    seL4_SetMR(mr++, 0);                         /* subpixel unknown */
                    mr = emit_str(mr, "sotOS", 6);              /* make */
                    mr = emit_str(mr, "HONEY0", 7);             /* model */
                    seL4_SetMR(mr++, 0);                         /* transform normal */
                    seL4_SetMR(ghdr, ((seL4_Word)((mr - g0) * 4) << 16) | 0);
                    size_t m0 = mr;                              /* mode */
                    seL4_SetMR(mr++, (seL4_Word)bound);
                    seL4_SetMR(mr++, ((seL4_Word)(6 * 4) << 16) | 1);
                    seL4_SetMR(mr++, 0x3);                       /* current|preferred */
                    seL4_SetMR(mr++, 1280);                      /* width  px */
                    seL4_SetMR(mr++, 720);                       /* height px */
                    seL4_SetMR(mr++, 60000);                     /* refresh mHz */
                    (void)m0;
                    seL4_SetMR(mr++, (seL4_Word)bound);          /* scale (opcode 3) */
                    seL4_SetMR(mr++, ((seL4_Word)(3 * 4) << 16) | 3);
                    seL4_SetMR(mr++, 1);                         /* factor 1 */
                    seL4_SetMR(mr++, (seL4_Word)bound);          /* done (opcode 2) */
                    seL4_SetMR(mr++, ((seL4_Word)(2 * 4) << 16) | 2);
                    printf("[wl-compositor] wl_output %u · 1280x720 geometry+mode+scale+done (%zu words)\n",
                           bound, mr);
                    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, mr));
                } else {
                    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));    /* ack · no events */
                }
                continue;
            }

            if (o->type == WL_SHM && opcode == 0) {        /* wl_shm.create_pool(new_id, fd, size) */
                /* wire [wl_shm_id(obj), hdr, pool_new_id, (memfd_fd), pool_size] + 6
                 * appended sotOs words from LUCAS:
                 *   [compositor_vaddr_lo32, pool_size,
                 *    scanout_va_lo32, scanout_w, scanout_h, scanout_stride].
                 * obj is the wl_shm target; the new pool id is arg0 at MR2.  When the
                 * pool's backing is a real LUCAS memfd, LUCAS appends the present
                 * block (len-relative · last 6 words; the hand-rolled-5-word and
                 * libwayland-4-word wire shapes both work).  When it is NOT (e.g.
                 * libwayland-cursor's pool, whose fd never registered as a memfd) the
                 * create_pool is forwarded RAW (no append) → vaddr unknown: track the
                 * pool but mark it unmappable (vaddr=0).  Such a pool is never
                 * committed as a window surface, so it is never blitted/read. */
                uint32_t pool_id = (uint32_t)seL4_GetMR(2);
                uintptr_t vaddr; uint32_t size;
                if (len >= 8) {                /* wire(>=2) + 6-word present block */
                    vaddr = (uintptr_t)seL4_GetMR(len - 6);
                    size  = (uint32_t)seL4_GetMR(len - 5);
                    if (!g_scanout_va) {       /* learn the present-target once */
                        g_scanout_va     = (uintptr_t)seL4_GetMR(len - 4);
                        g_scanout_w      = (uint32_t)seL4_GetMR(len - 3);
                        g_scanout_h      = (uint32_t)seL4_GetMR(len - 2);
                        g_scanout_stride = (uint32_t)seL4_GetMR(len - 1);
                        if (g_scanout_va)
                            printf("[wl-compositor] scanout present-target @0x%lx %ux%u stride=%u\n",
                                   (unsigned long)g_scanout_va, g_scanout_w, g_scanout_h, g_scanout_stride);
                    }
                } else {                       /* raw forward · unmappable pool */
                    vaddr = 0;
                    size  = (uint32_t)seL4_GetMR(len - 1);
                }
                struct wl_obj *o2 = obj_add(pool_id, WL_POOL);
                if (!o2) {
                    printf("[wl-compositor] create_pool id=%u · object table full · status EINVAL\n", pool_id);
                    seL4_Reply(seL4_MessageInfo_new(22, 0, 0, 0));   /* EINVAL */
                    continue;
                }
                o2->vaddr = vaddr; o2->size = size;
                printf("[wl-compositor] create_pool id=%u vaddr=0x%lx size=%u\n",
                       pool_id, (unsigned long)vaddr, size);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }

            if (o->type == WL_POOL && opcode == 0) {       /* wl_shm_pool.create_buffer */
                /* wire [pool_obj, hdr, buffer_new_id, offset, w, h, stride, format] */
                if (len < 8) {
                    printf("[wl-compositor] create_buffer short frame len=%lu · status EPROTO\n",
                           (unsigned long)len);
                    seL4_Reply(seL4_MessageInfo_new(71, 0, 0, 0));
                    continue;
                }
                uint32_t buffer_id = (uint32_t)seL4_GetMR(2);
                uint32_t offset    = (uint32_t)seL4_GetMR(3);
                uint32_t w         = (uint32_t)seL4_GetMR(4);
                uint32_t h         = (uint32_t)seL4_GetMR(5);
                uint32_t stride    = (uint32_t)seL4_GetMR(6);
                uint32_t format    = (uint32_t)seL4_GetMR(7);
                if ((uint64_t)offset + (uint64_t)h * stride > o->size) {
                    printf("[wl-compositor] create_buffer id=%u out of pool bounds "
                           "(off=%u h=%u stride=%u pool=%u) · status EPROTO\n",
                           buffer_id, offset, h, stride, o->size);
                    seL4_Reply(seL4_MessageInfo_new(71, 0, 0, 0));   /* EPROTO */
                    continue;
                }
                struct wl_obj *b = obj_add(buffer_id, WL_BUFFER);
                if (!b) {
                    printf("[wl-compositor] create_buffer id=%u · object table full · status EINVAL\n", buffer_id);
                    seL4_Reply(seL4_MessageInfo_new(22, 0, 0, 0));   /* EINVAL */
                    continue;
                }
                b->offset = offset; b->w = w; b->h = h;
                b->stride = stride; b->format = format;
                b->vaddr = o->vaddr + offset;
                printf("[wl-compositor] create_buffer id=%u %ux%u stride=%u fmt=%u off=%u\n",
                       buffer_id, w, h, stride, format, offset);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }

            if (o->type == WL_POOL) {  /* wl_shm_pool.destroy(1)/resize(2).
                                        * A real toolkit (SDL2 wl_shm framebuffer)
                                        * destroys the pool right after creating its
                                        * buffer; we keep the pool mapped (existing
                                        * buffers stay valid), so just ack — an
                                        * EPROTO here errors the client's wl_display
                                        * and hangs every later request. */
                if (opcode == 1) {
                    obj_del(obj);   /* M4 · wl_shm_pool.destroy → free slot */
                } else if (opcode == 2 && len >= 3) {   /* wl_shm_pool.resize(size) */
                    /* GTK/cairo + libwayland-cursor GROW a pool in place: ftruncate
                     * the memfd, then wl_shm_pool.resize.  The matching ftruncate
                     * already grew the backing (for a mapped memfd pool, orch_shm_pool
                     * _grow also extended this pool's compositor RO mapping); we only
                     * need to track the new size here so the create_buffer bounds
                     * check uses it.  Without it, a later create_buffer at the grown
                     * offset wrongly trips the out-of-pool-bounds EPROTO —
                     * libwayland-cursor resizes its shared cursor pool as it loads
                     * each cursor image (observed 4096->8832->18624, off>4096). */
                    uint32_t newsz = (uint32_t)seL4_GetMR(2);
                    if (newsz > o->size) {
                        printf("[wl-compositor] pool resize id=%u %u->%u\n", obj, o->size, newsz);
                        o->size = newsz;
                    }
                }
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }

            if (o->type == WL_BUFFER) {  /* wl_buffer.destroy(0): no-op ack (the
                                          * SHM frame is owned by orch; the toolkit
                                          * destroys/recreates buffers across frames
                                          * and on teardown). */
                if (opcode == 0) obj_del(obj);   /* M4 · wl_buffer.destroy → free slot */
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }

            if (o->type == WL_COMPOSITOR_OBJ && opcode == 0) {  /* wl_compositor.create_surface */
                uint32_t surface_id = arg2;       /* MR2 */
                obj_add(surface_id, WL_SURFACE);
                printf("[wl-compositor] create_surface id=%u\n", surface_id);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
            if (o->type == WL_COMPOSITOR_OBJ && opcode == 1) {  /* wl_compositor.create_region */
                /* M3 · SDL sets opaque/input regions on its window surface.  We
                 * don't composite, so track the object and treat region edits as
                 * no-ops (add/subtract/destroy). */
                uint32_t region_id = arg2;        /* MR2 */
                obj_add(region_id, WL_REGION);
                printf("[wl-compositor] create_region id=%u\n", region_id);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
            if (o->type == WL_REGION) {           /* add(1)/subtract(2)/destroy(0) · no-op */
                if (opcode == 0) obj_del(obj);   /* M4 · wl_region.destroy → free slot */
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }

            if (o->type == WL_SURFACE && opcode == 1) {    /* wl_surface.attach(buffer,x,y) */
                o->pending_buffer = arg2;         /* MR2 = buffer id */
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }

            /* M2 · xdg_shell ----------------------------------------------- */
            if (o->type == WL_XDG_WM_BASE && opcode == 2) { /* get_xdg_surface(new_id, wl_surface) */
                uint32_t xs_id = arg2;                       /* MR2 */
                uint32_t surf  = (uint32_t)seL4_GetMR(3);    /* MR3 */
                struct wl_obj *xs = obj_add(xs_id, WL_XDG_SURFACE);
                if (xs) { xs->xs_wl_surface = surf; xs->xs_needs_cfg = 1; }
                struct wl_obj *s = obj_find(surf);
                if (s) s->role_xdg = xs_id;
                printf("[wl-compositor] get_xdg_surface xdg=%u surf=%u\n", xs_id, surf);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
            if (o->type == WL_XDG_WM_BASE && opcode == 3) { /* pong */
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
            if (o->type == WL_XDG_WM_BASE) {  /* destroy(0)/create_positioner(1): no-op
                                               * ack (teardown must not EPROTO). */
                if (opcode == 0) obj_del(obj);   /* M4 · xdg_wm_base.destroy → free slot */
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
            if (o->type == WL_XDG_SURFACE && opcode == 1) { /* get_toplevel(new_id) */
                uint32_t tl_id = arg2;                       /* MR2 */
                obj_add(tl_id, WL_XDG_TOPLEVEL);
                o->xs_toplevel = tl_id;
                printf("[wl-compositor] get_toplevel toplevel=%u xdg=%u\n", tl_id, obj);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
            if (o->type == WL_XDG_SURFACE) {                /* ack_configure / set_window_geometry / destroy */
                if (opcode == 0) obj_del(obj);   /* M4 · xdg_surface.destroy → free slot */
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
            if (o->type == WL_XDG_TOPLEVEL) {               /* set_title/app_id/min/max/... · all no-op */
                if (opcode == 0) obj_del(obj);   /* M4 · xdg_toplevel.destroy → free slot */
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }

            if (o->type == WL_SURFACE && opcode == 6) {    /* wl_surface.commit */
                /* M2 · xdg_shell initial configure handshake.  The first commit of
                 * a surface that has an xdg role (and no buffer yet) must elicit
                 * xdg_toplevel.configure + xdg_surface.configure(serial).  In the
                 * synchronous transport the events ride the commit reply; the
                 * client's roundtrip batches commit+sync so they arrive in order. */
                struct wl_obj *xs = o->role_xdg ? obj_find(o->role_xdg) : 0;
                if (xs && xs->xs_needs_cfg) {
                    uint32_t s = ++serial;
                    size_t mr = 0;
                    /* xdg_toplevel.configure(width=0, height=0, states=empty) · opcode 0 */
                    seL4_SetMR(mr++, (seL4_Word)xs->xs_toplevel);
                    seL4_SetMR(mr++, ((seL4_Word)(5 * 4) << 16) | 0);
                    seL4_SetMR(mr++, 0);                 /* width  (0 = client picks) */
                    seL4_SetMR(mr++, 0);                 /* height */
                    seL4_SetMR(mr++, 0);                 /* states wl_array length = 0 */
                    /* xdg_surface.configure(serial) · opcode 0 */
                    seL4_SetMR(mr++, (seL4_Word)xs->id);
                    seL4_SetMR(mr++, ((seL4_Word)(3 * 4) << 16) | 0);
                    seL4_SetMR(mr++, (seL4_Word)s);
                    xs->xs_needs_cfg = 0;
                    printf("[wl-compositor] xdg configure surf=%u xdg=%u toplevel=%u serial=%u\n",
                           obj, xs->id, xs->xs_toplevel, s);
                    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, mr));
                    continue;
                }
                struct wl_obj *buf = obj_find(o->pending_buffer);
                if (buf && buf->vaddr) {
                    uint32_t sum = fnv1a((const uint8_t *)buf->vaddr,
                                         (size_t)buf->h * buf->stride);
                    uint32_t px0 = *(volatile uint32_t *)buf->vaddr;
                    printf("[wl-compositor] commit surf=%u buf=%u %ux%u stride=%u fmt=%u "
                           "fnv1a=0x%08x px0=0x%08x\n",
                           obj, buf->id, buf->w, buf->h, buf->stride, buf->format, sum, px0);
                    if (px0 == 0xDEADBEEFu)
                        printf("[wl-compositor] zero-copy anomaly observed\n");
                    /* v2.6 present · blit the committed surface into the scanout orch
                     * mapped here; orch flushes it to the QEMU display after this
                     * reply (the opcode-6 flush in LUCAS).  Both surfaces are 4-byte
                     * little-endian (wl_shm ARGB/XRGB8888 ↔ BGRX scanout), so a
                     * per-row copy works directly (the A/X byte is ignored on scan
                     * out).  Centered + clamped to the scanout.  Skipped when headless
                     * (g_scanout_va==0 · the gate boot has no virtio-gpu).
                     * v2.7 · only blit the xdg toplevel WINDOW surface (role_xdg set);
                     * a toolkit's cursor surface (wl_pointer.set_cursor) is also a
                     * committed wl_surface but must NOT overwrite the window scanout. */
                    if (g_scanout_va && buf->w && buf->h && o->role_xdg) {
                        uint32_t cw = buf->w < g_scanout_w ? buf->w : g_scanout_w;
                        uint32_t ch = buf->h < g_scanout_h ? buf->h : g_scanout_h;
                        uint32_t ox = (g_scanout_w - cw) / 2, oy = (g_scanout_h - ch) / 2;
                        uint32_t rowb = cw * 4;
                        for (uint32_t row = 0; row < ch; ++row) {
                            const uint8_t *s = (const uint8_t *)buf->vaddr + (size_t)row * buf->stride;
                            uint8_t *d = (uint8_t *)g_scanout_va
                                       + (size_t)(oy + row) * g_scanout_stride + (size_t)ox * 4;
                            memcpy(d, s, rowb);
                        }
                    }
                    /* wl_buffer.release event on the buffer id */
                    seL4_SetMR(0, (seL4_Word)buf->id);
                    seL4_SetMR(1, ((seL4_Word)8 << 16) | 0);
                    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 2));
                } else {
                    printf("[wl-compositor] commit surf=%u · no attached buffer\n", obj);
                    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                }
                continue;
            }

            /* M3 · wl_seat: get_pointer(0)/get_keyboard(1)/get_touch(2) create the
             * device object; release(3)/other are no-ops.  With capabilities=0 SDL
             * shouldn't request these, but accept them so a toolkit that does
             * doesn't EPROTO-stall. */
            if (o->type == WL_SEAT) {
                if (opcode <= 2) {
                    uint32_t new_id = arg2;       /* MR2 = new device id */
                    obj_add(new_id, opcode == 0 ? WL_POINTER
                                  : opcode == 1 ? WL_KEYBOARD : WL_TOUCH);
                    printf("[wl-compositor] wl_seat op=%u new_id=%u\n", opcode, new_id);
                }
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
            if (o->type == WL_POINTER || o->type == WL_KEYBOARD ||
                o->type == WL_TOUCH || o->type == WL_OUTPUT) { /* release/... no-op */
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
            /* v2.4 · wl_data_device_manager: create_data_source(op=0, new_id) +
             * get_data_device(op=1, new_id, seat) → a live WL_DATA_DEVICE object
             * (GDK's _gdk_wayland_device_manager_add_seat HARD-derefs the result
             * of get_data_device, so it must return a real object).  No
             * selection/DnD events are needed for startup. */
            if (o->type == WL_DATA_DEVICE_MANAGER) {
                if (opcode == 0 || opcode == 1) {
                    uint32_t new_id = arg2;       /* MR2 = new object id (first arg) */
                    obj_add(new_id, WL_DATA_DEVICE);
                    printf("[wl-compositor] wl_data_device_manager op=%u new_id=%u\n",
                           opcode, new_id);
                }
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
            if (o->type == WL_DATA_DEVICE) {  /* set_selection/release/... no-op ack */
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }

            if (o->type == WL_SURFACE && opcode == 3) {    /* wl_surface.frame(new_callback) */
                /* M3 · real frame callback.  A toolkit (SDL2 sw-render) registers a
                 * frame callback then BLOCKS the next present until its done event
                 * arrives (vsync throttle) — a no-op frame would hang it.  In the
                 * synchronous transport the done rides the frame request's reply:
                 * wl_callback.done(time) on the new callback id + wl_display.delete_id
                 * (the callback is one-shot; libwayland destroys it on done and
                 * expects the id reclaimed).  Firing immediately = "ready to draw",
                 * which paces the client without a real vblank clock. */
                uint32_t cb = arg2;                 /* MR2 = new wl_callback id */
                uint32_t t  = ++serial;             /* monotonic-ish ms stand-in */
                seL4_SetMR(0, (seL4_Word)cb);
                seL4_SetMR(1, ((seL4_Word)12 << 16) | 0);   /* wl_callback.done */
                seL4_SetMR(2, (seL4_Word)t);
                seL4_SetMR(3, (seL4_Word)1);                /* wl_display.delete_id */
                seL4_SetMR(4, ((seL4_Word)12 << 16) | 1);
                seL4_SetMR(5, (seL4_Word)cb);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 6));
                continue;
            }

            if (o->type == WL_SURFACE) {   /* destroy(0)/damage(2)/set_*_region(4,5)/
                                            * set_buffer_transform(7)/scale(8)/offset(10):
                                            * state-setting requests · accept as no-op so a
                                            * real libwayland client's commit sequence flows. */
                if (opcode == 0) obj_del(obj);   /* M4 · wl_surface.destroy → free slot */
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
        }

        printf("[wl-compositor] unhandled obj=%u op=%u size=%u · status EPROTO\n",
               obj, opcode, size);
        seL4_Reply(seL4_MessageInfo_new(71, 0, 0, 0));   /* EPROTO */
    }
}

