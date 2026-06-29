/*
 * sotOs · LUCAS L3b · pipe object interface.
 *
 * A pipe is a 4 KiB ring buffer with reader/writer refcounts.  When all
 * readers close, writes return -EPIPE.  When all writers close, reads
 * return 0 (EOF).  Blocking is implemented via SaveCaller / seL4_Send on
 * the orchestrator's fault-EP reply path (same as wait4).
 */

#ifndef SOTOS_ORCH_PIPE_H
#define SOTOS_ORCH_PIPE_H

#include <stdint.h>
#include <stddef.h>

/* Opaque · defined in src/orch/pipe.c */
struct lucas_pipe;

/* Forward-declare lucas_state_t without pulling in the full state header. */
struct lucas_state;

/* Allocate a fresh pipe from the static pool.  Returns NULL if the pool is
 * exhausted.  Initialises readers_open=1, writers_open=1. */
struct lucas_pipe *lucas_pipe_alloc(void);

/* Read up to count bytes from p into client_vaddr in st's vspace.
 * Returns bytes read on success; 0 on EOF (all writers closed);
 * negative errno on error.  If the pipe is empty and writers_open > 0,
 * parks the caller (SaveCaller) and returns LUCAS_WAIT4_DEFERRED so the
 * fault loop knows not to Reply immediately. */
int64_t lucas_pipe_read(struct lucas_state *st, struct lucas_pipe *p,
                         uintptr_t client_vaddr, size_t count);

/* Write up to count bytes from client_vaddr in st's vspace into p.
 * Returns bytes written on success; -EPIPE (-32) if all readers are
 * closed.  If the buffer is full, parks the caller and returns
 * LUCAS_WAIT4_DEFERRED. */
int64_t lucas_pipe_write(struct lucas_state *st, struct lucas_pipe *p,
                          uintptr_t client_vaddr, size_t count);

/* Kernel-buffer pipe write (sendfile sink = pipe write end). Copies `count`
 * bytes from `buf` into the ring, wakes readers, returns bytes written. */
int64_t lucas_pipe_write_kbuf(struct lucas_pipe *p, const void *buf, size_t count);

/* Decrement the reader refcount.  If it hits 0, wake any blocked writer
 * with -EPIPE and free the pipe if writers are also zero. */
void lucas_pipe_close_reader(struct lucas_pipe *p);

/* Decrement the writer refcount.  If it hits 0, wake any blocked reader
 * with 0 (EOF) and free the pipe if readers are also zero. */
void lucas_pipe_close_writer(struct lucas_pipe *p);

/* Increment refcounts (used by fork() when child inherits pipe fds). */
void lucas_pipe_add_reader(struct lucas_pipe *p);
void lucas_pipe_add_writer(struct lucas_pipe *p);

/* U3 · readiness predicates used by epoll/select/poll.
 * read_ready:  bytes available, OR all writers closed (EOF · still readable
 *              for the purposes of edge-triggered wake-ups).
 * write_ready: free space available AND readers still open.
 * hup:         all writers closed and no data left to drain.
 */
int lucas_pipe_read_ready (const struct lucas_pipe *p);
int lucas_pipe_write_ready(const struct lucas_pipe *p);
int lucas_pipe_hup        (const struct lucas_pipe *p);

/* apt arc · empty pipe with a writer still open → a blocking read would park;
 * a non-blocking (O_NONBLOCK) read must instead return -EAGAIN.  Used by
 * lucas_sys_read to honour O_NONBLOCK on PIPE_READ fds (the apt http method
 * drains fd0 read-until-EAGAIN). */
int lucas_pipe_would_block_read(const struct lucas_pipe *p);

#endif /* SOTOS_ORCH_PIPE_H */
