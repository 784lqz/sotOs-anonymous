#ifndef ORCH_VIRTIO_INPUT_H
#define ORCH_VIRTIO_INPUT_H
#include <stdint.h>
int  kbd_init(void);     /* probe virtio-keyboard + post eventq buffers; -1 if none */
void kbd_poll(void);     /* drain pending events → ASCII ring (call often) */
int  kbd_getbyte(void);  /* pop one ASCII byte, or -1 if none */
int  kbd_ready(void);    /* kbd_poll() then 1 if the ring has a byte */
char kbd_translate(uint16_t keycode, int shift);  /* pure; 0 if none */
int  kbd_raw_get(uint8_t *code, int *down);  /* raw event for Doom; 0 ok / -1 none */
int  kbd_present(void);                       /* 1 if a virtio-keyboard is live */
int  kbd_f12_take(void);  /* F12 toggle · 1 if F12 was pressed since last call (clears) */
#endif
