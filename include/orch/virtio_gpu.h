#ifndef ORCH_VIRTIO_GPU_H
#define ORCH_VIRTIO_GPU_H
#include <stdint.h>
#include <sel4/sel4.h>
/* Probe + set up scanout 0 backed by an internal framebuffer.
 * Returns 0 on success (interactive display available), -1 if no device
 * (headless boot — caller skips the whole interactive path). */
int      gpu_init(void);
/* The shared drawing surface (BGRX, stride bytes/row). NULL before gpu_init. */
uint8_t *gpu_fb(int *w, int *h, int *stride);
/* Transfer the dirty rect to host + flush to the display. */
void     gpu_flush(int x, int y, int w, int h);
/* v2.6 · map the scanout into another PD (the Wayland compositor) at `va` so it can
 * blit committed surfaces directly; reports dims.  Returns `va`, or 0 on failure. */
uintptr_t gpu_export_to_pd(seL4_CPtr pd, uintptr_t va, int *w, int *h, int *stride);
#endif
