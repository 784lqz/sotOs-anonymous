/* sotOs · lucas · procd_view · SHM seqlock loader. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <procd/proc.h>
#include <procd/shm.h>
#include <lucas/procd_view.h>

extern void *g_procd_shm_base;  /* set by orch bootstrap; lucas inherits */

static proc_t *proc_t_at_slot(uint32_t slot) {
    if (slot == 0 || g_procd_shm_base == NULL) return NULL;
    procd_shm_header_t *hdr = (procd_shm_header_t *)g_procd_shm_base;
    if (slot >= hdr->table_n) return NULL;
    return (proc_t *)((uint8_t *)g_procd_shm_base + hdr->table_ofs +
                       sizeof(proc_t) * slot);
}

static void view_clear(lucas_proc_view_t *out) {
    memset(out, 0, sizeof(*out));
    out->valid = 0;
}

int lucas_procd_view_load(uint32_t slot, lucas_proc_view_t *out) {
    if (out == NULL) return -1;
    proc_t *p = proc_t_at_slot(slot);
    if (p == NULL) { view_clear(out); return -1; }

    /* Seqlock read · mirror of include/procd/shm.h:32-41 procd_tier_load,
     * but capturing the full snapshot in one consistent pass. */
    for (;;) {
        uint64_t v1 = __atomic_load_n(&p->version, __ATOMIC_ACQUIRE);
        if (v1 & 1ull) { __builtin_ia32_pause(); continue; }
        out->synthetic_pid     = p->synthetic_pid;
        out->ppid         = p->ppid;
        out->pgid         = p->pgid;
        out->sid          = p->sid;
        out->tier         = (uint32_t)p->tier;
        out->functor_proc = p->functor_proc;
        out->state        = (uint8_t)p->state;
        memcpy(out->comm, p->comm, sizeof(out->comm));
        out->comm[sizeof(out->comm) - 1] = '\0';
        out->cow_session  = p->cow_session;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        uint64_t v2 = __atomic_load_n(&p->version, __ATOMIC_RELAXED);
        if (v1 == v2) { out->valid = 1; return 0; }
    }
}

int lucas_procd_view_by_synthetic_pid(uint32_t synthetic_pid, lucas_proc_view_t *out) {
    if (out == NULL || synthetic_pid == 0 || g_procd_shm_base == NULL) {
        view_clear(out);
        return -1;
    }
    procd_shm_header_t *hdr = (procd_shm_header_t *)g_procd_shm_base;
    for (uint32_t i = 1; i < hdr->table_n; i++) {
        if (lucas_procd_view_load(i, out) == 0 &&
            out->valid && out->synthetic_pid == synthetic_pid &&
            out->state != PROC_STATE_FREE) {
            return 0;
        }
    }
    view_clear(out);
    return -1;
}

extern void *g_procd_shm_ro;   /* orch's dedicated RO view · set at BOOTSTRAP */

#define LUCAS_PROCT_MAX_SPINS 64

static proc_t *proc_t_ro_at_slot(uint32_t slot) {
    if (slot == 0 || g_procd_shm_ro == NULL) return NULL;
    procd_shm_header_t *hdr = (procd_shm_header_t *)g_procd_shm_ro;
    if (hdr->magic != PROCD_SHM_MAGIC || slot >= hdr->table_n) return NULL;
    return (proc_t *)((uint8_t *)g_procd_shm_ro + hdr->table_ofs +
                       sizeof(proc_t) * slot);
}

int lucas_proct_load(uint32_t slot, lucas_proc_view_t *out) {
    if (out == NULL) return -1;
    proc_t *p = proc_t_ro_at_slot(slot);
    if (p == NULL) { view_clear(out); return -1; }

    for (int tries = 0; tries < LUCAS_PROCT_MAX_SPINS; ++tries) {
        uint64_t v1 = __atomic_load_n(&p->version, __ATOMIC_ACQUIRE);
        if (v1 & 1ull) { __builtin_ia32_pause(); continue; }
        out->synthetic_pid     = p->synthetic_pid;
        out->ppid         = p->ppid;
        out->pgid         = p->pgid;
        out->sid          = p->sid;
        out->tier         = (uint32_t)p->tier;
        out->functor_proc = p->functor_proc;
        out->state        = (uint8_t)p->state;
        memcpy(out->comm, p->comm, sizeof(out->comm));
        out->comm[sizeof(out->comm) - 1] = '\0';
        out->cow_session  = p->cow_session;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        uint64_t v2 = __atomic_load_n(&p->version, __ATOMIC_RELAXED);
        if (v1 == v2) { out->valid = 1; return 0; }
    }
    view_clear(out);   /* seqlock did not settle within the bound · fall back */
    return -1;
}

int lucas_proct_find_synthetic_pid(uint32_t synthetic_pid, lucas_proc_view_t *out) {
    if (out == NULL || synthetic_pid == 0 || g_procd_shm_ro == NULL) {
        if (out) view_clear(out);
        return -1;
    }
    procd_shm_header_t *hdr = (procd_shm_header_t *)g_procd_shm_ro;
    if (hdr->magic != PROCD_SHM_MAGIC) { view_clear(out); return -1; }
    uint32_t n = hdr->table_n;
    if (n > PROCD_MAX_PROCS) n = PROCD_MAX_PROCS;
    for (uint32_t i = 1; i < n; i++) {
        if (lucas_proct_load(i, out) == 0 &&
            out->valid && out->synthetic_pid == synthetic_pid &&
            out->state != PROC_STATE_FREE) {
            return 0;
        }
    }
    view_clear(out);
    return -1;
}

void lucas_proct_selftest(void) {
    if (g_procd_shm_ro == NULL) {
        printf("[lucas] proct self-test · g_procd_shm_ro NULL · skipped\n");
        return;
    }
    lucas_proc_view_t v;
    for (uint32_t slot = 1; slot < PROCD_MAX_PROCS; ++slot) {
        if (lucas_proct_load(slot, &v) == 0 && v.valid &&
            v.state != PROC_STATE_FREE) {
            printf("[lucas] proct self-test · slot=%u synthetic_pid=%u ppid=%u "
                   "tier=%u state=%u (read via g_procd_shm_ro)\n",
                   slot, v.synthetic_pid, v.ppid, v.tier, (unsigned)v.state);
            return;
        }
    }
    printf("[lucas] proct self-test · no live proc found\n");
}
