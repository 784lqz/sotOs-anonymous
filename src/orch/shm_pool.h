#ifndef SOTOS_ORCH_SHM_POOL_H
#define SOTOS_ORCH_SHM_POOL_H
#include <sel4/sel4.h>
#include <vspace/vspace.h>
#include <stdint.h>
#include <stddef.h>
#define ORCH_SHM_MAX_POOLS   4
/* 1024 * 4 KiB = 4 MiB per pool — enough for a real toolkit's window
 * framebuffer up to the advertised 1280x720 output (900 frames). The L13/L14
 * deception pools (4 frames) and the SDL2 wl_shm software framebuffer
 * (v2.3-M3) both allocate only their actual size, so the larger cap costs
 * static array space (~frames[1024]+copies[1024] per pool, 4 pools) but no
 * extra runtime frames. Was 16 (64 KiB), too small for a window surface. */
#define ORCH_SHM_MAX_FRAMES  1024
int  orch_shm_pool_alloc(size_t size, uint32_t owner);
int  orch_shm_pool_grow(int id, size_t new_size);   /* extend frames + live mappings */
uintptr_t orch_shm_pool_map_guest(int id, vspace_t *guest_vspace, uintptr_t base, size_t want_size);
uintptr_t orch_shm_pool_map_compositor(int id, seL4_CPtr comp_pd, uintptr_t base);
size_t orch_shm_pool_size(int id);
size_t orch_shm_pool_nframes(int id);
/* M4 · pool lifetime/refcount (see shm_pool.c). */
void orch_shm_pool_attach(int id, uint32_t owner, uint64_t conn_fd, uint32_t pool_wire_id); /* create_pool */
void orch_shm_pool_wire_event(uint32_t owner, uint64_t conn_fd, uint32_t obj, uint32_t opcode, uint32_t new_id);
void orch_shm_pool_free_owner(uint32_t owner);  /* sotbox teardown sweep */
#endif
