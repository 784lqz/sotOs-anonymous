/*
 * sotOs · LUCAS · scheduler-family handlers.
 *
 * L11-α-4 · close the third ENOSYS gap for CPython hello-world.
 *
 * Currently houses sched_getaffinity only · single-CPU model: the
 * client always sees exactly bit 0 set in its CPU mask (cpu_count() == 1).
 * Real multi-CPU affinity is deferred until LUCAS has SMP-aware scheduling
 * (post-L11).
 *
 * WINE-M1 follow-up · the rest of the POSIX scheduler family.  A real Linux
 * never returns ENOSYS for these (wine probed sched_setaffinity → ENOSYS in
 * run25, a fidelity tell).  Single-CPU, SCHED_OTHER-only model: the only CPU is
 * 0, the only policy is SCHED_OTHER whose static-priority range is [0,0], and
 * the client runs as root (uid 0) so even RT-policy requests are "permitted"
 * (we still model them as SCHED_OTHER).  Every member is satisfiable exactly.
 */

#include "handlers.h"
#include "state.h"
#include <lucas/linux_abi.h>
#include <lucas/syscalls.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                                 const void *src_buf, size_t size);

/* sched_getaffinity(pid, cpusetsize, mask):
 *   - write 0x01 (bit 0) into the first 8 bytes of mask
 *   - return the number of bytes written (one cpu_set_t word = 8)
 * Linux semantics: rax = number of bytes actually copied (must be a
 * multiple of sizeof(long); glibc/musl expect >= 8 on x86_64). */
int64_t lucas_sys_sched_getaffinity(lucas_state_t *st,
                                     uint64_t pid, uint64_t cpusetsize,
                                     uint64_t mask_vaddr,
                                     uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)pid; (void)_a3; (void)_a4; (void)_a5;

    if (cpusetsize < sizeof(uint64_t)) return -(int64_t)LX_EINVAL;
    if (mask_vaddr == 0)               return -(int64_t)LX_EFAULT;

    uint64_t one_cpu = 0x1ULL;  /* bit 0 = CPU 0 (the only CPU we model) */
    if (lucas_copy_to_client(st, mask_vaddr, &one_cpu, sizeof(one_cpu)) != 0)
        return -(int64_t)LX_EFAULT;

    printf("[lucas] sched_getaffinity(pid=%lu, size=%lu) → mask=0x01 (single CPU)\n",
           (unsigned long)pid, (unsigned long)cpusetsize);
    return (int64_t)sizeof(uint64_t);  /* 8 bytes written */
}

/* Linux scheduling policies (uapi/linux/sched.h). */
#define LX_SCHED_OTHER 0
#define LX_SCHED_FIFO  1
#define LX_SCHED_RR    2
#define LX_SCHED_BATCH 3
#define LX_SCHED_IDLE  5

extern int lucas_copy_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                  void *dst_buf, size_t size);

/* sched_setaffinity(pid, cpusetsize, mask): we model a single CPU (0).  Accept
 * any non-empty mask (it can only include CPU 0) and return 0.  Linux returns
 * EINVAL for a zero-sized set and EFAULT for a bad pointer — honour both so the
 * ABI is faithful, otherwise succeed (the process cannot leave CPU 0). */
int64_t lucas_sys_sched_setaffinity(lucas_state_t *st,
                                    uint64_t pid, uint64_t cpusetsize,
                                    uint64_t mask_vaddr,
                                    uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;
    if (cpusetsize < sizeof(uint64_t)) return -(int64_t)LX_EINVAL;
    if (mask_vaddr == 0)               return -(int64_t)LX_EFAULT;
    uint64_t requested = 0;
    if (lucas_copy_from_client(st, mask_vaddr, &requested, sizeof(requested)) != 0)
        return -(int64_t)LX_EFAULT;
    printf("[lucas] sched_setaffinity(pid=%lu, mask=0x%lx) → accepted (single CPU 0)\n",
           (unsigned long)pid, (unsigned long)requested);
    return 0;
}

/* sched_getscheduler(pid): the only policy we model is SCHED_OTHER. */
int64_t lucas_sys_sched_getscheduler(lucas_state_t *st,
                                     uint64_t pid, uint64_t _a1, uint64_t _a2,
                                     uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)st; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    printf("[lucas] sched_getscheduler(pid=%lu) → SCHED_OTHER\n", (unsigned long)pid);
    return LX_SCHED_OTHER;
}

/* sched_setscheduler(pid, policy, param): the client is root (uid 0) so any
 * policy is "permitted"; we collapse all of them to SCHED_OTHER and report
 * success (Linux returns 0 on success).  Reject obviously invalid policy ids. */
int64_t lucas_sys_sched_setscheduler(lucas_state_t *st,
                                     uint64_t pid, uint64_t policy, uint64_t param_vaddr,
                                     uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)st; (void)param_vaddr; (void)_a3; (void)_a4; (void)_a5;
    if (policy > LX_SCHED_IDLE || policy == 4) return -(int64_t)LX_EINVAL;
    printf("[lucas] sched_setscheduler(pid=%lu, policy=%lu) → accepted\n",
           (unsigned long)pid, (unsigned long)policy);
    return 0;
}

/* sched_getparam(pid, param): SCHED_OTHER has a single static priority of 0.
 * struct sched_param { int sched_priority; }. */
int64_t lucas_sys_sched_getparam(lucas_state_t *st,
                                 uint64_t pid, uint64_t param_vaddr, uint64_t _a2,
                                 uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)pid; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (param_vaddr == 0) return -(int64_t)LX_EINVAL;
    int32_t sched_priority = 0;
    if (lucas_copy_to_client(st, param_vaddr, &sched_priority, sizeof(sched_priority)) != 0)
        return -(int64_t)LX_EFAULT;
    return 0;
}

/* sched_setparam(pid, param): only priority 0 is valid for SCHED_OTHER; accept. */
int64_t lucas_sys_sched_setparam(lucas_state_t *st,
                                 uint64_t pid, uint64_t param_vaddr, uint64_t _a2,
                                 uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)st; (void)pid; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (param_vaddr == 0) return -(int64_t)LX_EINVAL;
    return 0;
}

/* sched_get_priority_max/min(policy): real-time policies (FIFO/RR) use [1,99];
 * the time-sharing policies (OTHER/BATCH/IDLE) use [0,0]. */
int64_t lucas_sys_sched_get_priority_max(lucas_state_t *st,
                                         uint64_t policy, uint64_t _a1, uint64_t _a2,
                                         uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)st; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (policy > LX_SCHED_IDLE || policy == 4) return -(int64_t)LX_EINVAL;
    return (policy == LX_SCHED_FIFO || policy == LX_SCHED_RR) ? 99 : 0;
}

int64_t lucas_sys_sched_get_priority_min(lucas_state_t *st,
                                         uint64_t policy, uint64_t _a1, uint64_t _a2,
                                         uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)st; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (policy > LX_SCHED_IDLE || policy == 4) return -(int64_t)LX_EINVAL;
    return (policy == LX_SCHED_FIFO || policy == LX_SCHED_RR) ? 1 : 0;
}
