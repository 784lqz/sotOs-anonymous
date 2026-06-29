/*
 * sotOs · LUCAS · syscall handler signature common to all handlers.
 *
 * Args follow Linux x86_64: RAX = syscall_no, then RDI, RSI, RDX, R10, R8, R9.
 * Handlers receive args[0..5] = those registers (in that order; note: r10, not rcx).
 *
 * Handlers may issue STO IPC, modify *st, etc. They return an int64_t that
 * the dispatcher writes back to RAX.
 */

#ifndef SOTOS_LUCAS_HANDLERS_H
#define SOTOS_LUCAS_HANDLERS_H

#include <stdint.h>
#include <stddef.h>

struct lucas_state;

typedef int64_t (*lucas_handler_fn)(struct lucas_state *st,
                                     uint64_t a0, uint64_t a1, uint64_t a2,
                                     uint64_t a3, uint64_t a4, uint64_t a5);

/* Copy `size` bytes from the client's virtual address space into the local
 * buffer `dst_buf`.  Returns 0 on success, -1 on fault. */
int lucas_copy_from_client(struct lucas_state *st, uintptr_t client_vaddr,
                            void *dst_buf, size_t size);

/* BG2 · wake-up hook for blocking recvfrom · called by sotnet_recv_enqueue
 * when a synth response (or any future sotnet RX path) lands a payload
 * for `pid`.  If a sotbox is parked in SOTBOX_STATE_WAITING_FOR_RECV with
 * matching synthetic_pid, drains the queue into its vspace and Sends to the
 * saved reply cap.  Returns 1 if a waiter was woken, 0 otherwise. */
int lucas_recv_wake_waiter(uint32_t pid);

/* sottrace v1 · accept wake-up hook · called by tcp_server_on_ack when a
 * handshake reaches ESTABLISHED.  If a sotbox is parked in
 * SOTBOX_STATE_WAITING_FOR_ACCEPT, dequeues the completed conn, allocates a
 * fresh fd, rewrites RAX and Sends to the saved reply cap.  Returns 1 if a
 * waiter was woken, 0 otherwise (no box parked / queue race). */
int lucas_accept_wake_waiter(void);

#endif
