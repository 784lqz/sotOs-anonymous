/* sotOs · procd · wire protocol (op enum + request/reply) · ABI v1.
 *
 * Spec: procd-process-server-design §5.1.
 */
#ifndef PROCD_PROTO_H
#define PROCD_PROTO_H

#include <stdint.h>
#include <procd/proc.h>

typedef enum {
    PROCD_OP_SPAWN        = 0x01,
    PROCD_OP_FORK         = 0x02,
    PROCD_OP_CLONE        = 0x03,
    PROCD_OP_EXEC         = 0x04,
    PROCD_OP_EXIT         = 0x05,
    PROCD_OP_THREAD_EXIT  = 0x06,
    PROCD_OP_WAIT         = 0x07,
    PROCD_OP_KILL         = 0x08,
    PROCD_OP_SETSID       = 0x09,
    PROCD_OP_SETPGID      = 0x0A,
    PROCD_OP_GETPGID      = 0x0B,
    PROCD_OP_SET_TLS      = 0x0C,
    PROCD_OP_SET_TID_ADDR = 0x0D,
    PROCD_OP_SET_ROBUST   = 0x0E,

    PROCD_OP_GETPID       = 0x20,
    PROCD_OP_GETPPID      = 0x21,
    PROCD_OP_LIST         = 0x22,

    PROCD_OP_SET_TIER       = 0x40,
    PROCD_OP_REBIND_FUNCTOR = 0x41,
    PROCD_OP_SUSPEND         = 0x42,
    PROCD_OP_TERMINATE      = 0x43,
    /* ABI v2 · post-spawn session/comm update.  cow_session is assigned at
     * SSH login (AFTER spawn) and comm changes on execve, so neither is
     * known at spawn time · this op carries both for a target slot. */
    PROCD_OP_SET_SESSION    = 0x44,
} procd_op_t;

typedef struct {
    uint32_t op;            /* procd_op_t */
    uint32_t caller_slot;
    union {
        struct {
            uint64_t elf_offset_in_cpio;
            uint32_t elf_size;
            uint32_t argv_count;
            uint64_t argv_blob_offset;
            uint32_t envp_count;
            uint64_t envp_blob_offset;
            uint64_t initial_pledge;
            uint32_t initial_tier;          /* proc_tier_t */
            uint16_t initial_functor_fs;
            uint16_t initial_functor_net;
            char     comm[16];              /* ABI v2 · short program name */
        } spawn;
        struct {
            uint64_t flags;
            uint64_t child_stack;
            uint64_t parent_tid_ptr;
            uint64_t child_tid_ptr;
            uint64_t tls;
            uint64_t start_func;
        } clone;
        struct {
            int32_t  which;
            int32_t  options;
        } wait;
        struct {
            uint32_t target_slot;
            uint32_t new_tier;              /* proc_tier_t */
        } set_tier;
        struct {
            uint32_t target_slot;
            uint32_t cow_session;           /* ABI v2 · SSH session id (0=none) */
            char     comm[16];              /* ABI v2 · updated comm (e.g. on execve) */
        } set_session;
        struct {
            uint32_t target_slot;
            uint16_t new_functor_fs;
            uint16_t new_functor_net;
            uint16_t new_functor_proc;
            uint16_t _pad;
        } rebind_functor;
        struct {
            int32_t  exit_status;
        } exit;
        struct {
            uint32_t tid;
        } thread_exit;
        struct {
            uint64_t robust_head;
            /* PR 13 · the procd-assigned tid for the calling thread ·
             * 0 is the "main thread" anomaly (procd falls back to the
             * proc's first thread_t entry).  Sits adjacent to the head
             * so both fields are read with two seL4_GetMR calls on the
             * receive side. */
            uint32_t tid;
            uint32_t _pad;
        } set_robust;
        uint8_t raw[64];
    };
} procd_request_t;

typedef struct {
    int32_t   result;           /* >=0 ok, <0 -errno */
    uint32_t  out_slot;
    uint64_t  out_extra;
} procd_reply_t;

_Static_assert(sizeof(procd_request_t) <= 128, "procd_request_t too large");
_Static_assert(sizeof(procd_reply_t)   <= 32,  "procd_reply_t too large");

#endif /* PROCD_PROTO_H */
