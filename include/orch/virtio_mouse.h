#ifndef ORCH_VIRTIO_MOUSE_H
#define ORCH_VIRTIO_MOUSE_H
#include <stdint.h>
int  mouse_init(void);   /* probe virtio-tablet (2nd virtio-input) + eventq; -1 if none */
void mouse_poll(void);   /* drain events → update cursor x/y/buttons + redraw cursor */
int  mouse_abs_to_screen(uint32_t absval, int screen_dim);  /* pure */
int  mouse_raw_get(int *dx, int *dy, int *buttons);  /* Doom mouse-look: relative delta + buttons; -1 if none */
int  mouse_present(void);                              /* 1 if a virtio-tablet is live */
int  mouse_state(int *x, int *y, int *btn);           /* v2.7 · absolute cursor screen px + L button; 0 if none */
#endif
