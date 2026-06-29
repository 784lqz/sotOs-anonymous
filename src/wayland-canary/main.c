/*
 * sotOs · native Wayland shadow compositor (L14a deception path).
 *
 * L14a-A1: Path-D process only. Root passes a listen EP in argv[1] and
 * mints a copy into orch so a later task can route flagged-hostile clients
 * here (away from the honest compositor).
 *
 * The shadow advertises ONE extra registry global that the honest compositor
 * does NOT: sotos_capture (name=3).  Bind handling is a no-op ack for now —
 * the actual capture-request dispatch is a LATER task.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sel4/sel4.h>

#define SEL4UTILS_INITIAL_EP_SLOT 1

/* L14a · advertised registry globals (name / interface / len-incl-NUL / version).
 * Honest compositor advertises name=1 (wl_compositor) and name=2 (wl_shm).
 * Shadow adds name=3 (sotos_capture, 14 bytes incl NUL) as the deception marker. */
struct wl_global { uint32_t name; const char *iface; uint32_t ifacelen; uint32_t version; };
static const struct wl_global GLOBALS[] = {
    { 1, "wl_compositor",  14, 4 },
    { 2, "wl_shm",          7, 1 },
    { 3, "sotos_capture",  14, 1 },
    { 4, "wl_seat",         8, 1 },
};
#define N_GLOBALS (sizeof(GLOBALS) / sizeof(GLOBALS[0]))

/* Server-side object table — same approach as honest compositor. */
enum wl_otype { WL_NONE=0, WL_REGISTRY, WL_SHM, WL_COMPOSITOR_OBJ, WL_POOL, WL_BUFFER, WL_SURFACE, WL_CAPTURE_OBJ, WL_SEAT_OBJ };
struct wl_obj { uint32_t id; enum wl_otype type; };
static struct wl_obj g_objs[32]; static int g_nobjs = 0;
static struct wl_obj *obj_add(uint32_t id, enum wl_otype t){
    if (g_nobjs >= 32) return 0;
    struct wl_obj *o = &g_objs[g_nobjs++]; memset(o,0,sizeof(*o)); o->id=id; o->type=t; return o; }
static struct wl_obj *obj_find(uint32_t id){
    for (int i=g_nobjs-1;i>=0;--i) if (g_objs[i].id==id) return &g_objs[i]; return 0; }

/* Emit one wl_registry.global(name, interface, version) event into the reply
 * message registers starting at word index `mr`; return the next free index. */
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

int main(int argc, char *argv[])
{
    seL4_CPtr listen_ep = SEL4UTILS_INITIAL_EP_SLOT;
    if (argc > 1 && argv[1]) {
        seL4_CPtr slot = (seL4_CPtr)atol(argv[1]);
        if (slot != 0) listen_ep = slot;
    }

    printf("[wl-canary] alive · listen_ep=%lu\n",
           (unsigned long)listen_ep);

    uint32_t serial = 0;   /* monotonic · wl_callback.done serial source */

    while (1) {
        seL4_MessageInfo_t info = seL4_Recv(listen_ep, NULL);
        seL4_Word len = seL4_MessageInfo_get_length(info);

        if (len < 2) {   /* min valid request = object id + header word */
            printf("[wl-canary] short frame len=%lu · status EPROTO\n",
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
            printf("[wl-canary] sync obj=%u new_id=%u · done serial=%u + delete_id\n",
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
            printf("[wl-canary] get_registry registry=%u · %u globals, %zu words\n",
                   registry, (unsigned)N_GLOBALS, mr);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, mr));
            continue;
        }

        /* obj != 1 · dispatch by object type */
        struct wl_obj *o = obj_find(obj);
        if (o) {
            if (o->type == WL_REGISTRY && opcode == 0) {   /* wl_registry.bind(name,iface,ver,new_id) */
                uint32_t name = arg2;             /* MR2 */
                if (len < 4) {
                    printf("[wl-canary] bind short frame len=%lu · status EPROTO\n",
                           (unsigned long)len);
                    seL4_Reply(seL4_MessageInfo_new(71, 0, 0, 0));
                    continue;
                }
                uint32_t slen = (uint32_t)seL4_GetMR(3);
                uint32_t nstr = ((slen + 3u) & ~3u) / 4;
                if (slen > 64 || len < (seL4_Word)(4 + nstr + 2)) {
                    printf("[wl-canary] bind name=%u bad iface len=%u (frame %lu words) · status EINVAL\n",
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
                    printf("[wl-canary] bind name=%u UNKNOWN · status EINVAL\n", name);
                    seL4_Reply(seL4_MessageInfo_new(22, 0, 0, 0));   /* EINVAL */
                    continue;
                }
                enum wl_otype t = (name==1) ? WL_COMPOSITOR_OBJ
                                : (name==2) ? WL_SHM
                                : (name==3) ? WL_CAPTURE_OBJ
                                : (name==4) ? WL_SEAT_OBJ : WL_NONE;
                obj_add(bound, t);
                printf("[wl-canary] bind name=%u interface=%s version=%u new_id=%u · ack\n",
                       name, g->iface, version, bound);
                /* Capture-request handling for sotos_capture (name=3) is a LATER task.
                 * For now all binds ack with an empty reply. */
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
                continue;
            }
        }

        printf("[wl-canary] unhandled obj=%u op=%u size=%u · status EPROTO\n",
               obj, opcode, size);
        seL4_Reply(seL4_MessageInfo_new(71, 0, 0, 0));   /* EPROTO */
    }
}
