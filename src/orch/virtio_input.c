#include <orch/virtio_input.h>
#include <stdint.h>
#include <string.h>

static const char k_lo[128] = {
 0,27,'1','2','3','4','5','6','7','8',
 '9','0','-','=',8,'\t','q','w','e','r',
 't','y','u','i','o','p','[',']','\r',0,
 'a','s','d','f','g','h','j','k','l',';',
 '\'','`',0,'\\','z','x','c','v','b','n',
 'm',',','.','/',0,'*',0,' ',0,0,
};
static const char k_hi[128] = {
 0,27,'!','@','#','$','%','^','&','*',
 '(',')','_','+',8,'\t','Q','W','E','R',
 'T','Y','U','I','O','P','{','}','\r',0,
 'A','S','D','F','G','H','J','K','L',':',
 '"','~',0,'|','Z','X','C','V','B','N',
 'M','<','>','?',0,'*',0,' ',0,0,
};
char kbd_translate(uint16_t keycode, int shift){
    if (keycode >= 128) return 0;
    return shift ? k_hi[keycode] : k_lo[keycode];
}

#ifndef VIRTIO_INPUT_HOST_TEST
#include <sotfs/virtio_modern.h>
#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>
#include <stdio.h>
extern vka_t *orch_vka(void);

#define VIRTIO_INPUT_DEVID 0x1052
#define EV_KEY 1
struct virtio_input_event { uint16_t type, code; uint32_t value; } __attribute__((packed));

static virtio_dev_t g_kb;
static virtq_t      g_evq;
static struct virtio_input_event *g_evbuf;
static uintptr_t    g_evbuf_pa;
static int          g_shift;
static int          g_ctrl;
static uint8_t g_ring[256]; static volatile int g_rh, g_rt;       /* ASCII ring (shell) */
static uint16_t g_raw[256]; static volatile int g_qh, g_qt;       /* raw (keycode|down<<8) ring (Doom) */
static int g_inited;
static volatile int g_f12_pending;   /* F12 toggle · set on F12 press, NOT pushed to a ring */

#define KEY_F12 88   /* Linux evdev keycode for F12 (the operator shell-toggle key) */

static void ring_push(uint8_t c){ int n=(g_rh+1)&255; if(n!=g_rt){ g_ring[g_rh]=c; g_rh=n; } }
static void raw_push(uint8_t code, int down){ int n=(g_qh+1)&255; if(n!=g_qt){ g_raw[g_qh]=(uint16_t)(code | (down?0x100:0)); g_qh=n; } }

/* Raw keyboard event (keycode + press/release) for the Doom box (read via the
 * /dev/doomkbd LUCAS fd). Returns 0 + fills *code/*down, or -1 if none. */
int kbd_raw_get(uint8_t *code, int *down){
    if (g_qt==g_qh) return -1;
    uint16_t v=g_raw[g_qt]; g_qt=(g_qt+1)&255;
    *code=(uint8_t)(v&0xff); *down=(v&0x100)?1:0; return 0;
}
int kbd_present(void){ return g_inited; }

static void *kbd_alloc_page(uintptr_t *pa){
    static uintptr_t va=0x31000000UL;
    vka_t *vka=orch_vka(); vka_object_t f;
    if (vka_alloc_frame(vka, seL4_PageBits, &f)) return NULL;
    void *v=(void*)va;
    vka_object_t pg[VSPACE_MAP_PAGING_OBJECTS]; int np=VSPACE_MAP_PAGING_OBJECTS;
    if (sel4utils_map_page(vka, SEL4UTILS_PD_SLOT, f.cptr, v, seL4_AllRights, 1, pg, &np)) return NULL;
    va+=0x1000; *pa=(uintptr_t)seL4_X86_Page_GetAddress(f.cptr).paddr; memset(v,0,0x1000); return v;
}

int kbd_init(void){
    if (virtio_modern_probe(VIRTIO_INPUT_DEVID, 0, &g_kb)!=0){ printf("[kbd] no virtio-keyboard\n"); return -1; }
    if (virtio_modern_negotiate(&g_kb,0)!=0) return -1;
    if (virtio_modern_setup_queue(&g_kb,0,&g_evq)!=0) return -1;
    virtio_modern_driver_ok(&g_kb);
    g_evbuf = kbd_alloc_page(&g_evbuf_pa);
    if (!g_evbuf) return -1;
    for (int i=0;i<g_evq.qsz;++i){
        g_evq.desc[i].addr = g_evbuf_pa + (uintptr_t)i*sizeof(struct virtio_input_event);
        g_evq.desc[i].len  = sizeof(struct virtio_input_event);
        g_evq.desc[i].flags= VIRTQ_DESC_F_WRITE;
        g_evq.desc[i].next = 0;
        g_evq.avail->ring[i] = (uint16_t)i;
    }
    __atomic_store_n(&g_evq.avail->idx, (uint16_t)g_evq.qsz, __ATOMIC_RELEASE);
    *g_evq.notify = 0;
    g_evq.last_used = 0; g_inited = 1;
    printf("[kbd] virtio-keyboard ready (qsz=%u)\n", g_evq.qsz);
    return 0;
}

void kbd_poll(void){
    if (!g_inited) return;
    uint16_t ui = __atomic_load_n(&g_evq.used->idx, __ATOMIC_ACQUIRE);
    while (g_evq.last_used != ui){
        uint16_t slot = g_evq.last_used % g_evq.qsz;
        uint32_t id = g_evq.used->ring[slot].id;
        struct virtio_input_event *e = &g_evbuf[id];
        if (e->type == EV_KEY){
            uint16_t code=e->code; uint32_t val=e->value;
            raw_push((uint8_t)code, val!=0);   /* Doom: every press/release, raw keycode */
            if (code==KEY_F12){ if (val==1) g_f12_pending = 1; }  /* operator toggle · swallow (not to a ring) */
            else if (code==42||code==54){ g_shift = (val!=0); }
            else if (code==29||code==97){ g_ctrl = (val!=0); }   /* L/R Ctrl modifier */
            else if (val==1 || val==2){
                char c = kbd_translate(code, g_shift);
                if (c) {
                    if (g_ctrl) {
                        /* Ctrl-<letter> → the control char (Ctrl-D=0x04 EOF exits a
                         * REPL, Ctrl-C=0x03 SIGINT, Ctrl-L=0x0c clear, …).  Without
                         * this the windowed shell could not send EOF, so an
                         * interactive `python` REPL was unexitable → it held its
                         * heavy arena forever (the OOM-after-a-while). */
                        unsigned char uc=(unsigned char)c;
                        if (uc>='a'&&uc<='z')      c=(char)(uc-'a'+1);
                        else if (uc>='A'&&uc<='Z') c=(char)(uc-'A'+1);
                        else if (uc=='[')          c=0x1b;   /* Ctrl-[ = ESC */
                    }
                    ring_push((uint8_t)c);
                }
            }
        }
        uint16_t a = __atomic_load_n(&g_evq.avail->idx, __ATOMIC_RELAXED);
        g_evq.avail->ring[a % g_evq.qsz] = (uint16_t)id;
        __atomic_store_n(&g_evq.avail->idx, (uint16_t)(a+1), __ATOMIC_RELEASE);
        g_evq.last_used++;
    }
    *g_evq.notify = 0;
}

int kbd_getbyte(void){
    if (!g_inited) return -1;
    if (g_rt==g_rh) return -1;
    uint8_t c=g_ring[g_rt]; g_rt=(g_rt+1)&255; return (int)c;
}
int kbd_ready(void){ kbd_poll(); return (g_rt!=g_rh); }
int kbd_f12_take(void){ int v=g_f12_pending; g_f12_pending=0; return v; }
#else
void kbd_poll(void){} int kbd_getbyte(void){return -1;} int kbd_ready(void){return 0;}
int kbd_init(void){return -1;} int kbd_f12_take(void){return 0;}
#endif
