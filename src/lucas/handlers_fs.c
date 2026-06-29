/*
 * sotOs · LUCAS · fs handlers · lucas_sys_write, lucas_sys_read.
 *
 * L1 only handles fd in {1, 2} for write (stdout/stderr → serial)
 * and fd == 0 for read (always returns 0 / EOF). No real fd table yet.
 *
 * NOTE: sel4utils_copy_from_vspace does not exist in this version of
 * seL4_libs. We use the manual fallback (Option B):
 *   1. vspace_get_cap(&st->client_vspace_abs, page_vaddr) → frame cap
 *   2. sel4utils_dup_and_map(vka, parent_vspace, cap, seL4_PageBits) → local ptr
 *   3. memcpy the relevant bytes
 *   4. sel4utils_unmap_dup to release the temporary mapping
 *
 * This is done one 4 KiB page at a time, spanning the exact byte range
 * [buf_vaddr, buf_vaddr + count).
 */

#include "handlers.h"
#include "state.h"
#include <lucas/linux_abi.h>
#include <lucas/vfs.h>
#include <lucas/syscalls.h>
#include <lucas/anomaly.h>
#include <lucas/fs_trace.h>
#include <lucas/unveil.h>
#include <lucas/symlink_table.h>
#include <lucas/persona_session.h>  /* 2nd-persona arc · persona-aware libc hide */
#include <lucas/clock.h>
#include <lucas/apk_ioc.h>         /* apk_is_db_install_path · PACKAGE_INSTALL IOC */

/* Sentinel for "this path was not handled by a helper" (symlink + proc-fd
 * fast-paths · INT64_MIN can't collide with a byte count or a -errno). */
#ifndef LUCAS_NOT_FDLINK
#define LUCAS_NOT_FDLINK INT64_MIN
#endif
#include <orch/pipe.h>
#include <orch/proto.h>
#include <sotos/random.h>
#include <sotos/path_matcher.h>
#include <sotos/audit_ipc.h>
#include <sotfs/wal_ipc.h>
#include <sotguard/event.h>
#include <sottrace/trace.h>    /* trace_emit_persistence · operator monitor */
#include <sotnet/bytepipe.h>   /* SSH canary shell · SHELL_IN/OUT bytepipes */
#include <orch/console_fb.h>
#include <orch/virtio_input.h>
#include <orch/virtio_mouse.h>

/* Linux open() access-mode mask · O_RDONLY=0, O_WRONLY=1, O_RDWR=2.
 * Used by the unveil gate to map open flags to UNVEIL_R/W perms. */
#define LUCAS_O_ACCMODE  0x3
#define LUCAS_EACCES_VAL 13

#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>   /* SEL4UTILS_PD_SLOT · round-10 anomaly raw read */
#include <vspace/vspace.h>
#include <sel4/sel4.h>
#include <stdio.h>
#include <string.h>

/* OBSD-ε OMALLOC · bounded-array alignment asserts (defense-in-depth).
 * Verify the fd table fits the assumptions of the zero-on-release path:
 * its byte size is a multiple of 8 so memset is well-defined, and it has
 * the bounded element count we expect.  Fails the build loudly if the
 * struct layout ever changes underneath us. */
_Static_assert((sizeof(((lucas_state_t *)0)->fds) % 8) == 0,
               "OBSD-ε: fd table size must be 8-byte aligned");
_Static_assert((sizeof(((lucas_state_t *)0)->fds) /
                 sizeof(((lucas_state_t *)0)->fds[0])) == LUCAS_MAX_FDS,
               "OBSD-ε: fd table must have LUCAS_MAX_FDS slots");

/* L8: global pointer to the sotBox currently executing a VFS read.
 * Set by lucas_sys_read before calling the backend op so static_vfs
 * can attribute canary access to the correct sotBox state. */
lucas_state_t *g_current_caller_st = NULL;

void lucas_set_current_caller(lucas_state_t *st) { g_current_caller_st = st; }
lucas_state_t *lucas_get_current_caller(void)    { return g_current_caller_st; }

/* Forward declarations for helpers defined later in this file. */
int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                          const void *src_buf, size_t size);

/* Output one byte to the serial console. seL4 debug build provides
 * seL4_DebugPutChar. */
static void serial_putc(char c)
{
#ifdef CONFIG_PRINTING
    seL4_DebugPutChar(c);
#else
    (void)c;
#endif
    console_fb_putc(c);      /* mirror to the on-screen console (no-op if headless) */
}

/* Interactive console RX · poll one byte from the UART (0x3F8) via orch's
 * IO_Port cap.  Returns 0..255, or -1 if none. Mirrors sotshell serial_getchar
 * (LSR 0x3FD bit0 → data 0x3F8). LUCAS handlers run in orch's CSpace, so the
 * cap is directly usable. */
extern seL4_CPtr orch_get_io_port_cap(void);   /* src/orch/sotbox_table.c */
static int lucas_console_getbyte(void)
{
    int kb = kbd_getbyte();
    if (kb >= 0) return kb;
    seL4_CPtr io = orch_get_io_port_cap();
    if (io == 0) return -1;
    seL4_X86_IOPort_In8_t lsr = seL4_X86_IOPort_In8(io, 0x3FD);
    if (lsr.error || !(lsr.result & 0x01)) return -1;
    seL4_X86_IOPort_In8_t data = seL4_X86_IOPort_In8(io, 0x3F8);
    return data.error ? -1 : (int)data.result;
}

/* Non-consuming readiness check: 1 if the UART has a byte waiting (LSR bit0),
 * else 0.  Used by poll/select on stdin so an interactive shell's blocking
 * poll(stdin,-1) returns once the operator types — without draining the byte
 * (the subsequent read() consumes it via lucas_console_getbyte). */
int lucas_console_data_ready(void)
{
    if (kbd_ready()) return 1;
    mouse_poll();   /* drain tablet events + redraw cursor; does not affect stdin */
    seL4_CPtr io = orch_get_io_port_cap();
    if (io == 0) return 0;
    seL4_X86_IOPort_In8_t lsr = seL4_X86_IOPort_In8(io, 0x3FD);
    return (!lsr.error && (lsr.result & 0x01)) ? 1 : 0;
}

/* Copy a NUL-terminated C string from client_vaddr in the client's
 * vspace into the local `buf` (size `buf_size`).  Returns the string
 * length on success, or -1 on EFAULT.  Walks page-by-page to support
 * paths spanning page boundaries. */
int lucas_copy_cstr_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                 char *buf, size_t buf_size) {
    if (buf_size == 0) return -1;
    size_t out = 0;
    while (out < buf_size - 1) {
        uintptr_t addr = client_vaddr + out;
        uintptr_t page_base = addr & ~0xFFFUL;
        size_t   off_in_page = (size_t)(addr - page_base);
        size_t   in_page_remaining = 4096 - off_in_page;
        if (in_page_remaining > buf_size - 1 - out) {
            in_page_remaining = buf_size - 1 - out;
        }

        seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)page_base);
        if (!frame) {
            printf("[lucas] copy_cstr: no frame at 0x%lx\n",
                   (unsigned long)page_base);
            return -1;
        }
        void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                             frame, seL4_PageBits);
        if (!local) return -1;
        const char *src = (const char *)local + off_in_page;
        for (size_t i = 0; i < in_page_remaining; ++i) {
            char c = src[i];
            buf[out++] = c;
            if (c == '\0') {
                sel4utils_unmap_dup(st->vka, st->parent_vspace,
                                    local, seL4_PageBits);
                return (int)(out - 1);
            }
        }
        sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
    }
    buf[buf_size - 1] = '\0';
    return (int)(buf_size - 1);
}

/* Emit a NUL-terminated string DIRECTLY to the console (byte-by-byte via
 * serial_putc · seL4_DebugPutChar). */
static void serial_puts(const char *s) { while (*s) { serial_putc(*s); ++s; } }

/* C2 #3 (v2) · flush one complete guest stdout/stderr line with a per-sotbox
 * "│guest:<pid>│ " prefix.  CRITICAL: the ENTIRE line (prefix + content + \n)
 * is emitted via serial_putc (DIRECT), never printf.  printf in this build is
 * line-buffered (flushes on \n); mixing a no-newline printf prefix with
 * serial_putc'd content left the prefix in printf's buffer to be prepended to
 * the next [subsystem] line — exactly the mis-attribution that sank the
 * v0.39.0 attempt.  serial_putc-only keeps prefix+content ordered + atomic.
 * Non-static: lucas_sys_exit_group flushes any trailing partial line at exit. */
void lucas_guest_line_flush(lucas_state_t *st) {
    if (st == NULL || st->guest_line_len == 0) return;
    serial_puts("\xe2\x94\x82guest:");          /* "│guest:" (UTF-8) */
    int v = st->synthetic_pid;
    if (v <= 0) {
        serial_putc('0');
    } else {
        char d[12]; int n = 0;
        while (v > 0 && n < 12) { d[n++] = (char)('0' + (v % 10)); v /= 10; }
        while (n > 0) serial_putc(d[--n]);
    }
    serial_puts("\xe2\x94\x82 ");                /* "│ " (UTF-8 + space) */
    for (uint16_t k = 0; k < st->guest_line_len; ++k) serial_putc(st->guest_line[k]);
    serial_putc('\n');
    st->guest_line_len = 0;
}

/* Serial write helper: emit bytes from local buffer to the debug console. */
/* Emit ONE stdout/stderr byte for a sotbox, honouring its console routing.
 * Factored out of write_serial so sendfile(2) (kernel-side file→stdout copy)
 * can stream bytes through the exact same path: interactive boxes emit raw
 * (SSH canary shell → SHELL_OUT ring; serial demo → UART) while non-interactive
 * boxes accumulate into the per-sotbox guest-line buffer. */
/* ONLCR · a cooked terminal maps NL → CR-NL on output (c_oflag OPOST|ONLCR).  We
 * have no kernel line discipline, so without this the guest's bare '\n' leaves the
 * SSH client / serial console staircased (each line drops down but not back to
 * column 0).  Default ON (a fresh tty is cooked) until a program clears it via
 * TCSETS (raw mode · vim, busybox lineedit) — then we leave its output untouched. */
static int lucas_onlcr_on(const lucas_state_t *st) {
    if (st->no_onlcr) return 0;                        /* non-PTY exec · raw pipe, no CRLF */
    if (!st->tty_init) return 1;                       /* default cooked tty */
    return (st->cur_termios.c_oflag & 0x1u) /*OPOST*/ &&
           (st->cur_termios.c_oflag & 0x4u) /*ONLCR*/;
}

static void lucas_stdio_emit_byte(lucas_state_t *st, char c) {
    if (st->console_interactive) {
        /* Interactive sotbox (bbsh): emit each byte raw + unbuffered so
         * busybox's prompt ("/ # ", no trailing \n) and per-keystroke echo
         * appear immediately.  SSH canary shell (Phase B): when the console
         * source is the SSH ring, push the byte to SHELL_OUT (net-synth
         * encrypts it as CHANNEL_DATA) instead of the UART.  NL → CR-NL per
         * ONLCR so the line-based output (apk/apt/ls) isn't staircased. */
        if (st->console_src == LUCAS_CONSOLE_SRC_SSH_RING) {
            /* Block B · forensic capture · record the shell-output byte (the OUT
             * half of the session transcript) keyed by the SSH conn_id (== cow_session)
             * BEFORE the ONLCR \r injection, so the debrief sees the logical stream.
             * Invisible to the attacker (separate store, never on the wire). */
            extern void sottrace_capture_append(uint16_t, int, const uint8_t *, uint32_t);
            sottrace_capture_append((uint16_t)st->cow_session, SOTTRACE_DIR_OUT,
                                    (const uint8_t *)&c, 1);
            if (c == '\n' && lucas_onlcr_on(st)) {
                uint8_t cr = '\r';
                bytepipe_push((bytepipe_ring_t *)BYTEPIPE_SHELL_OUT_VADDR, &cr, 1);
            }
            bytepipe_push((bytepipe_ring_t *)BYTEPIPE_SHELL_OUT_VADDR,
                          (const uint8_t *)&c, 1);
        } else {
            if (c == '\n' && lucas_onlcr_on(st)) serial_putc('\r');
            serial_putc(c);
        }
        /* ANSI DSR detect: busybox lineedit emits ESC[6n; queue the
         * "\x1b[1;1R" reply for the next read(fd0) (lucas_console_src_getbyte). */
        switch (st->dsr_scan) {
            case 0: st->dsr_scan = (c == 0x1b) ? 1 : 0; break;
            case 1: st->dsr_scan = (c == '[')  ? 2 : (c == 0x1b ? 1 : 0); break;
            case 2: st->dsr_scan = (c == '6')  ? 3 : (c == 0x1b ? 1 : 0); break;
            case 3: if (c == 'n') st->dsr_emit = 6;
                    st->dsr_scan = (c == 0x1b ? 1 : 0); break;
        }
        return;
    }
    if (c == '\n') {
        lucas_guest_line_flush(st);            /* emit the complete line */
    } else {
        if (st->guest_line_len >= (uint16_t)(sizeof(st->guest_line) - 1))
            lucas_guest_line_flush(st);        /* overflow · force a break */
        st->guest_line[st->guest_line_len++] = c;
    }
}

/* TUI · per-byte ANSI DSR (ESC[6n) detector, factored out of lucas_stdio_emit_byte
 * so the batched SHELL_OUT path can push a whole write() chunk in one bytepipe_push
 * while still arming the cursor-position reply. */
static void lucas_stdio_emit_dsr_scan(lucas_state_t *st, char c) {
    switch (st->dsr_scan) {
        case 0: st->dsr_scan = (c == 0x1b) ? 1 : 0; break;
        case 1: st->dsr_scan = (c == '[')  ? 2 : (c == 0x1b ? 1 : 0); break;
        case 2: st->dsr_scan = (c == '6')  ? 3 : (c == 0x1b ? 1 : 0); break;
        case 3: if (c == 'n') st->dsr_emit = 6;
                st->dsr_scan = (c == 0x1b ? 1 : 0); break;
    }
}

/* Emit an orch-side (kernel) NUL-terminated string to a sotbox's stdout via the
 * exact routing lucas_stdio_emit_byte uses (SSH ring / UART / guest-line buffer).
 * Used by the execve pip-deception facade to stream a synthetic install
 * transcript to the attacker's terminal without a real binary. */
void lucas_console_emit_kstr(lucas_state_t *st, const char *s) {
    if (!st || !s) return;
    for (; *s; ++s) lucas_stdio_emit_byte(st, *s);
}

static int64_t write_serial(lucas_state_t *st, uint64_t buf_vaddr, uint64_t count) {
    if (count == 0) return 0;
    const size_t page_sz = (size_t)1 << seL4_PageBits;
    size_t total_written = 0;
    while (total_written < (size_t)count) {
        uintptr_t cur_vaddr  = buf_vaddr + total_written;
        uintptr_t page_base  = cur_vaddr & ~(page_sz - 1);
        size_t    page_off   = cur_vaddr - page_base;
        size_t    remaining  = (size_t)count - total_written;
        size_t    this_chunk = remaining < (page_sz - page_off)
                               ? remaining : (page_sz - page_off);
        seL4_CPtr frame_cap = vspace_get_cap(&st->client_vspace_abs,
                                              (void *)page_base);
        if (frame_cap == seL4_CapNull) {
            ZF_LOGE("[lucas] sys_write: vspace_get_cap failed for vaddr 0x%lx",
                    (unsigned long)page_base);
            return -(int64_t)LX_EFAULT;
        }
        void *mapped = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                              frame_cap, seL4_PageBits);
        if (mapped == NULL) {
            ZF_LOGE("[lucas] sys_write: sel4utils_dup_and_map failed");
            return -(int64_t)LX_EFAULT;
        }
        const char *src = (const char *)mapped + page_off;
        if (st->console_interactive && st->console_src == LUCAS_CONSOLE_SRC_SSH_RING) {
            bytepipe_ring_t *out = (bytepipe_ring_t *)BYTEPIPE_SHELL_OUT_VADDR;
            if (lucas_onlcr_on(st)) {
                /* NL → CR-NL: push each NL-terminated run, then a literal "\r\n". */
                size_t start = 0;
                for (size_t i = 0; i < this_chunk; ++i) {
                    if (src[i] == '\n') {
                        if (i > start)
                            bytepipe_push(out, (const uint8_t *)(src + start), (uint32_t)(i - start));
                        bytepipe_push(out, (const uint8_t *)"\r\n", 2);
                        start = i + 1;
                    }
                }
                if (this_chunk > start)
                    bytepipe_push(out, (const uint8_t *)(src + start), (uint32_t)(this_chunk - start));
            } else {
                bytepipe_push(out, (const uint8_t *)src, (uint32_t)this_chunk);   /* raw · one push */
            }
            for (size_t i = 0; i < this_chunk; ++i) lucas_stdio_emit_dsr_scan(st, src[i]); /* DSR detect only */
        } else {
            for (size_t i = 0; i < this_chunk; ++i) lucas_stdio_emit_byte(st, src[i]);
        }
        sel4utils_unmap_dup(st->vka, st->parent_vspace, mapped, seL4_PageBits);
        total_written += this_chunk;
    }
    return (int64_t)total_written;
}

/* sendfile(2) · L-sendfile · real file→fd copy (replaces the importlib stub).
 *
 * busybox `cat FILE` (and other coreutils) copy a regular file to stdout with
 * sendfile(out_fd, in_fd, NULL, count) rather than a read()/write() loop — the
 * old stub returned 0 ("nothing sent"), so over the SSH canary shell the
 * attacker saw an empty `cat /etc/passwd`.  We now stream the bytes for real:
 * read from in_fd's VFS backend into a kernel bounce, then emit to out_fd via
 * the shared stdio path (STDIO → SHELL_OUT / UART) or the VFS backend write.
 *
 * in_fd must be a VFS-backed regular file (the only sendfile source we serve);
 * any other source returns 0 so CPython's importlib falls back to read+write
 * exactly as before.  *offset semantics: if offset_vaddr is non-NULL we copy
 * from that absolute offset and write the new offset back WITHOUT advancing the
 * fd cursor (Linux contract); otherwise we read from and advance in_fd's
 * cursor. */
int64_t lucas_sys_sendfile(lucas_state_t *st,
                            uint64_t fd_out, uint64_t fd_in,
                            uint64_t offset_vaddr, uint64_t count,
                            uint64_t _4, uint64_t _5)
{
    (void)_4; (void)_5;
    if (fd_in >= LUCAS_MAX_FDS || fd_out >= LUCAS_MAX_FDS)
        return -(int64_t)LX_EBADF;

    lucas_fd_t *ein  = &st->fds[fd_in];
    lucas_fd_t *eout = &st->fds[fd_out];

    /* Source must be a readable VFS file · else fall back (return 0). */
    if (ein->kind != LUCAS_FD_VFS || !ein->mount || !ein->mount->ops->read)
        return 0;

    /* CONTAINMENT PARITY · sendfile is a general syscall (any sotbox, incl.
     * Tier-1/Tier-2 fixtures), so the SINK must pass the SAME gates as
     * lucas_sys_write BEFORE any backend write fires — else sendfile is a
     * write-containment bypass.  These are copied verbatim from lucas_sys_write
     * (the canary-shell case is fd_out==1/2 STDIO, for which both are no-ops). */
    if (eout->writes_denied) {
        st->cap_revoke_count++;
        printf("[tier1-revoke] pid=%d sendfile(fd_out=%lu) on locked fd · -EACCES (cap_revokes=%u)\n",
               st->synthetic_pid, (unsigned long)fd_out,
               (unsigned int)st->cap_revoke_count);
        return -(int64_t)LUCAS_EACCES_VAL;
    }
    if (st->functor && st->functor->writes_silenced && fd_out >= 3) {
        st->silenced_write_count++;
        printf("[silenced] pid=%d sendfile(fd_out=%lu, file-backed, %lu bytes) · SILENT (rollback #%d)\n",
               st->synthetic_pid, (unsigned long)fd_out, (unsigned long)count,
               st->silenced_write_count);
        return (int64_t)count;   /* claim full success, write nothing */
    }

    /* Resolve the read offset + whether to write it back. */
    int64_t cursor   = ein->cursor;
    int     have_off = 0;
    if (offset_vaddr) {
        int64_t off = 0;
        if (lucas_copy_from_client(st, (uintptr_t)offset_vaddr, &off, sizeof(off)) != 0)
            return -(int64_t)LX_EFAULT;
        cursor   = off;
        have_off = 1;
    }

    /* Destination is stdio (canary-shell), a VFS file, or a pipe write end
     * (busybox `cat FILE | grep X` does sendfile(pipe_wr, file) after dup2). */
    int out_is_stdio = (eout->kind == LUCAS_FD_STDIO) ||
                       (eout->is_std && (fd_out == 1 || fd_out == 2));
    int out_is_vfs   = (eout->kind == LUCAS_FD_VFS && eout->mount &&
                        eout->mount->ops->write);
    int out_is_pipe  = (eout->kind == LUCAS_FD_PIPE_WRITE && eout->pipe);
    if (!out_is_stdio && !out_is_vfs && !out_is_pipe)
        return 0;   /* unsupported sink · let the caller fall back */

    /* Thread the caller so the backend read/write ops apply Tier-2 synth
     * containment + canary-read observability + unveil/persistence hints
     * exactly as lucas_sys_read / lucas_sys_write do (g_current_caller_st).
     * Cleared on EVERY path that leaves the backend-op region below. */
    lucas_set_current_caller(st);
    static uint8_t sf_buf[4096];
    int64_t total = 0;
    while ((uint64_t)total < count) {
        size_t want = (count - (uint64_t)total) < sizeof(sf_buf)
                      ? (size_t)(count - (uint64_t)total) : sizeof(sf_buf);
        int64_t r = ein->mount->ops->read(ein->mount->backend_state,
                                          ein->handle, sf_buf, want, cursor);
        if (r <= 0) break;                       /* EOF or error */

        if (out_is_stdio) {
            for (int64_t i = 0; i < r; ++i)
                lucas_stdio_emit_byte(st, (char)sf_buf[i]);
        } else if (out_is_pipe) {
            int64_t w = lucas_pipe_write_kbuf(eout->pipe, sf_buf, (size_t)r);
            if (w <= 0) break;
            if (w < r) { cursor += w; total += w; break; }
        } else {
            int64_t w = eout->mount->ops->write(eout->mount->backend_state,
                                                eout->handle, sf_buf,
                                                (size_t)r, eout->cursor);
            if (w <= 0) break;
            eout->cursor += w;
            if (w < r) { cursor += w; total += w; break; }
        }
        cursor += r;
        total  += r;
    }
    lucas_set_current_caller(NULL);

    if (total > 0) {
        if (have_off) {
            if (lucas_copy_to_client(st, (uintptr_t)offset_vaddr,
                                     &cursor, sizeof(cursor)) != 0)
                return -(int64_t)LX_EFAULT;
        } else {
            ein->cursor = cursor;
        }
        anomaly_on_write(st, fd_out, (uint64_t)total);
    }
    return total;
}

/* L12-gamma · Wayland wire transport (defined in handlers_net.c). */
int64_t lucas_wayland_forward(lucas_state_t *st, uint64_t fd,
                              uint64_t buf_vaddr, uint64_t len);
int64_t lucas_wayland_drain(lucas_state_t *st, uint64_t fd,
                            uint64_t buf_vaddr, uint64_t count);

/* N1 · δ-2 · connected-TCP data path (defined in handlers_net.c). */
int64_t lucas_tcp_send(lucas_state_t *st, uint64_t fd, uint64_t buf_vaddr, uint64_t len);
int64_t lucas_tcp_recv(lucas_state_t *st, uint64_t fd, uint64_t buf_vaddr, uint64_t count);
void    lucas_socket_close_conn(lucas_state_t *st, uint64_t fd);

int64_t lucas_sys_write(lucas_state_t *st, uint64_t fd, uint64_t buf_vaddr,
                        uint64_t count, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a3; (void)_a4; (void)_a5;
    if (fd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;

    /* TIER1-REVOKE-GATES · if this fd was locked at the moment the sotbox
     * was promoted to Tier-1, return real -EACCES rather than the legacy
     * synthetic success.  This closes the existing-open-writable-fd
     * escape hole.  Runs BEFORE the legacy writes_silenced short-circuit so the
     * locked path is observable. */
    if (st->fds[fd].writes_denied) {
        st->cap_revoke_count++;
        printf("[tier1-revoke] pid=%d write(fd=%lu) on locked fd · -EACCES (cap_revokes=%u)\n",
               st->synthetic_pid, (unsigned long)fd,
               (unsigned int)st->cap_revoke_count);
        return -(int64_t)LUCAS_EACCES_VAL;
    }

    /* L6 Tier 1 Silenced Mode: claim success without writing for file-backed
     * fds (fd >= 3).  The binary thinks its data went out; the operator
     * console (serial) sees nothing.  Spec §4 asymmetry property: tier
     * is invisible from inside the sotBox.
     *
     * G-STDOUT · stdin (fd=0), stdout (fd=1), and stderr (fd=2) MUST
     * pass through to the real write_serial path.  Silencing those would
     * also hide the demo malware's print() output after Tier-1 promote,
     * which destroys the operator-visible asymmetric-truth narrative
     * (the operator needs to see the malware's "[+] SUCCESS" lines while
     * its file writes get dropped).  fd 0/1/2 are kernel-reserved
     * stdio in our ABI · sotBoxes never see real file content on those
     * fds, so passing them through cannot leak silenced-mode state.
     *
     * NOTE: silenced silenced writes still do NOT increment write_count;
     * the sotBox is already at tier 1 (anomaly Rule 1 only promotes
     * tier 0 → 1).  Stdio writes that pass through DO go through the
     * normal anomaly_on_write hook below, which is fine because that
     * hook is a no-op for already-tier-1 sotboxes. */
    if (st->functor && st->functor->writes_silenced && fd >= 3 &&
        st->cow_session == 0) {
        /* DETECTION-TELL FIX · only silence NON-session captured malware
         * (cow_session == 0).  An INTERACTIVE attacker (cow_session != 0)
         * promoted to Tier-1 must NOT get silent-dropped writes: `echo X > f;
         * cat f` returning stale content while write() reported success is a
         * trivial sandbox/monitor tell.  The interactive session's writes fall
         * through to the per-session COW upper (like Tier-2), so write/read stays
         * coherent and the activity is still contained + captured. */
        st->silenced_write_count++;
        printf("[silenced] pid=%d write(fd=%lu, file-backed, %lu bytes) · SILENT (rollback #%d)\n",
               st->synthetic_pid, (unsigned long)fd, (unsigned long)count,
               st->silenced_write_count);
        return (int64_t)count;   /* claim full success */
    }

    lucas_fd_t *e = &st->fds[fd];

    int64_t ret;
    switch (e->kind) {
        case LUCAS_FD_STDIO:
            ret = write_serial(st, buf_vaddr, count);
            break;
        case LUCAS_FD_PIPE_WRITE:
            ret = lucas_pipe_write(st, e->pipe, (uintptr_t)buf_vaddr, (size_t)count);
            break;
        case LUCAS_FD_VFS:
            if (e->mount && e->mount->ops->write) {
                /* LOOP the write in 4 KiB bounce-buffer chunks until the whole
                 * `count` is written.  THE BUG (apk-network-install): the old code
                 * bounced ONE 4096-byte chunk and returned a SHORT write for any
                 * count > 4096.  Small writers (vim :w) tolerate a short write,
                 * but apk writes the APKINDEX in 128 KiB chunks and treats a short
                 * write on a regular file as ENOSPC ("No space left on device") —
                 * so a multi-MiB fetch failed to commit even though the disk had
                 * 256 MiB free.  A regular-file write() must complete the full
                 * count (or stop at a genuine backend error / short write).
                 *
                 * Phase C · thread the caller into op_write so the Tier-2 isolated
                 * branch reads st->cow_session / functor and routes the write into
                 * the per-session upper (mirrors the read path); set it ONCE around
                 * the whole loop. */
                static uint8_t wbounce[4096];
                size_t total = 0;
                lucas_set_current_caller(st);
                ret = 0;
                while (total < (size_t)count) {
                    size_t rem  = (size_t)count - total;
                    size_t want = (rem < sizeof(wbounce)) ? rem : sizeof(wbounce);
                    if (lucas_copy_from_client(st, (uintptr_t)buf_vaddr + total,
                                               wbounce, want) != 0) {
                        ret = (total > 0) ? (int64_t)total : -(int64_t)LX_EFAULT;
                        break;
                    }
                    int64_t w = e->mount->ops->write(e->mount->backend_state,
                                                     e->handle, wbounce, want,
                                                     e->cursor);
                    if (w < 0) { ret = (total > 0) ? (int64_t)total : w; break; }
                    e->cursor += w;
                    total     += (size_t)w;
                    ret        = (int64_t)total;
                    if ((size_t)w < want) break;   /* genuine backend short write */
                }
                lucas_set_current_caller(NULL);
                break;
            }
            return -(int64_t)LX_EBADF;
        case LUCAS_FD_FB: {
            extern int64_t lucas_fb_present(lucas_state_t*, uint64_t, uint64_t);
            ret = lucas_fb_present(st, buf_vaddr, count);
            break;
        }
        case LUCAS_FD_NULL:
        case LUCAS_FD_URANDOM:
            ret = (int64_t)count;   /* /dev/null + /dev/urandom · discard writes */
            break;
        case LUCAS_FD_SOCKET:
            if (e->is_netlink) {             /* apt-T7 · netlink route socket write */
                extern int64_t lucas_sys_sendto(lucas_state_t *, uint64_t, uint64_t,
                                                uint64_t, uint64_t, uint64_t, uint64_t);
                ret = lucas_sys_sendto(st, fd, buf_vaddr, count, 0, 0, 0);
                break;
            }
            if (e->wayland_connected) {
                ret = lucas_wayland_forward(st, fd, buf_vaddr, count);
                break;
            }
            if (e->unix_chan_idx1) {         /* WINE-M1 · AF_UNIX stream (wineserver) */
                extern int64_t lucas_unix_send(lucas_state_t *, uint64_t, uint64_t, uint64_t);
                ret = lucas_unix_send(st, fd, buf_vaddr, count);
                break;
            }
            if (e->tcp_conn != NULL || e->lwip_sess != NULL) {  /* δ TCP or lwIP egress (demux) */
                ret = lucas_tcp_send(st, fd, buf_vaddr, count);  /* routes to the right stack */
                break;
            }
            return -(int64_t)LX_EBADF;
        default:
            /* Legacy path: treat fd 1/2 as stdio for old-style initialised fds
             * (is_std == true but kind may still be INVALID in pre-T4 sotBoxes). */
            if (e->is_std && (fd == 1 || fd == 2)) {
                ret = write_serial(st, buf_vaddr, count);
                break;
            }
            return -(int64_t)LX_EBADF;
    }

    /* A3 anomaly: count successful writes and evaluate Rule 1.
     * Called AFTER the tier-1 silenced short-circuit above, so silenced
     * silenced writes never increment write_count. */
    if (ret > 0) {
        anomaly_on_write(st, fd, (uint64_t)ret);
    }
    return ret;
}

/* Interactive console read · fd0 STDIO. Deliver one raw byte from the serial
 * UART (no echo / no line discipline — busybox ash lineedit does that). If none
 * is buffered, PARK (mirror WAITING_FOR_RECV) and let orch_fault_loop's idle
 * pump wake us. A 1-byte short read is correct — lineedit reads byte-at-a-time.
 * Returns: 1 (byte delivered) / 0 (count==0) / -EFAULT / -EAGAIN, OR
 * LUCAS_WAIT4_DEFERRED when the caller must propagate the park up to the fault
 * loop (do NOT fall through to a Reply). */
/* SSH canary shell (Phase B) · fetch one console byte respecting console_src:
 * SSH_RING pulls from the SHELL_IN bytepipe (the consumer cursor lives on the
 * sotbox state), SERIAL reads the UART.  Returns the byte (0..255) or <0 if
 * none is available right now (caller parks). */
/* Console FOCUS · when an interactive foreground box (a `python` REPL spawned
 * from the shell) is live, ALL console input must go to it — not to the shell
 * that spawned it (busybox sits parked at its prompt).  Without this, every
 * keystroke went to the lowest parked slot (busybox), so the REPL got no input,
 * could not be Ctrl-D'd, and never exited → it held its 128 MiB heavy arena
 * forever (4 of those exhaust the pool → the OOM) AND the two readers fighting
 * over the console glitched the display.  -1 = no focus (normal single-shell). */
int g_console_focus_slot = -1;
void lucas_console_set_focus(int slot)   { g_console_focus_slot = slot; }
void lucas_console_clear_focus(int slot) { if (g_console_focus_slot == slot) g_console_focus_slot = -1; }

static int lucas_console_src_getbyte(lucas_state_t *st)
{
    /* ANSI DSR responder: if busybox just wrote ESC[6n (detected in write_serial),
     * feed back "\x1b[1;1R" before any real input so its lineedit doesn't eat the
     * next typed command as the cursor-position reply. */
    if (st->dsr_emit > 0) {
        static const char rep[6] = { 0x1b, '[', '1', ';', '1', 'R' };
        char ch = rep[6 - st->dsr_emit];
        st->dsr_emit--;
        return (unsigned char)ch;
    }
    /* Source-scoped focus gate: a non-focused box parks ONLY for a foreground box
     * within its OWN console source.  This keeps nested foreground correct (a
     * python/apt box that stole focus parks the shell it was launched from — same
     * source) while DECOUPLING the operator console (SERIAL) from the attacker
     * shell (SSH_RING): an operator-side REPL holding focus must not starve the
     * attacker's SSH stdin, and vice-versa, so the two run on separate terminals
     * at the same time.  Applies to both the direct read() and resume_parked. */
    if (g_console_focus_slot >= 0 && st->slot_index != g_console_focus_slot) {
        extern lucas_state_t *sotbox_get_slot(int i);
        lucas_state_t *fg = sotbox_get_slot(g_console_focus_slot);
        if (fg && fg->console_src == st->console_src)
            return -1;
    }
    if (st->console_src == LUCAS_CONSOLE_SRC_SSH_RING) {
        bytepipe_ring_t *in = (bytepipe_ring_t *)BYTEPIPE_SHELL_IN_VADDR;
        uint8_t ch;
        if (bytepipe_pull(in, &st->shell_in_rd, &ch, 1) == 1) {
            /* Block B · forensic capture · record the attacker keystroke (the IN
             * half of the transcript) keyed by the SSH conn_id (== cow_session). */
            extern void sottrace_capture_append(uint16_t, int, const uint8_t *, uint32_t);
            sottrace_capture_append((uint16_t)st->cow_session, SOTTRACE_DIR_IN, &ch, 1);
            return (int)ch;
        }
        return -1;
    }
    return lucas_console_getbyte();   /* existing UART path */
}

static int64_t lucas_console_read_or_park(lucas_state_t *st, uint64_t buf_vaddr,
                                          uint64_t count)
{
    if (count == 0) return 0;
    int b = lucas_console_src_getbyte(st);
    /* VEOF · Ctrl-D (0x04) → read returns 0 (EOF) for the FOCUSED interactive box
     * (the `python` REPL · which clears ICANON but doesn't treat 0x04 as EOF
     * itself).  busybox is never the focused box → it gets the raw 0x04 and runs
     * its own Ctrl-D (exit-shell) logic. */
    if (b == 0x04 && g_console_focus_slot >= 0 && st->slot_index == g_console_focus_slot)
        return 0;
    if (b >= 0) {
        uint8_t ch = (uint8_t)b;
        if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr, &ch, 1) != 0)
            return -(int64_t)LX_EFAULT;
        return 1;
    }
    /* No byte → park.  Reuse ONE per-sotbox reply cslot: the arena vka's
     * cspace_free is a no-op (reclaimed wholesale by revoke), and an
     * interactive shell parks once per keystroke, so a fresh cslot per read
     * would exhaust the 768-slot arena.  Allocate lazily on the first park,
     * then SaveCaller into the SAME slot every park (only one console read is
     * ever outstanding — the client blocks until resumed). */
    if (st->console_reply_cslot == 0) {
        seL4_CPtr cslot;
        if (vka_cspace_alloc(st->vka, &cslot) != 0) return -(int64_t)11 /*EAGAIN*/;
        st->console_reply_cslot = cslot;
    }
    cspacepath_t cpath;
    vka_cspace_make_path(st->vka, st->console_reply_cslot, &cpath);
    /* The previous reply cap was consumed by seL4_Send in the resume; Delete
     * first so SaveCaller always lands in an empty slot (idempotent on empty). */
    seL4_CNode_Delete(cpath.root, cpath.capPtr, cpath.capDepth);
    if (seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth) != seL4_NoError) {
        return -(int64_t)11;   /* keep the cslot for the next attempt */
    }
    st->waiting_reply_cap  = st->console_reply_cslot;
    st->console_buf_vaddr  = (uint64_t)buf_vaddr;
    st->console_wait_kind  = LUCAS_CONSOLE_WAIT_READ;
    st->state              = SOTBOX_STATE_WAITING_FOR_CONSOLE;
    return LUCAS_WAIT4_DEFERRED;   /* fault loop leaves us parked (result==-2) */
}

/* Task 5 · park a blocking poll(stdin,-1).  Same machinery as the read-park
 * (reusable console_reply_cslot + SOTBOX_STATE_WAITING_FOR_CONSOLE), but the
 * resume re-runs iomux_poll_scan (writing revents) and wakes with the
 * ready-count.  Caller (lucas_sys_poll) has already verified the scan returned
 * 0, timeout<0, and the only POLLIN fd is stdin.  Returns LUCAS_WAIT4_DEFERRED
 * on success, or a negative errno / 0 (don't park → immediate scan) on failure. */
int64_t lucas_console_poll_park(lucas_state_t *st, uint64_t fds_vaddr,
                                uint32_t nfds)
{
    if (st->console_reply_cslot == 0) {
        seL4_CPtr cslot;
        if (vka_cspace_alloc(st->vka, &cslot) != 0) return 0; /* fall back to scan */
        st->console_reply_cslot = cslot;
    }
    cspacepath_t cpath;
    vka_cspace_make_path(st->vka, st->console_reply_cslot, &cpath);
    seL4_CNode_Delete(cpath.root, cpath.capPtr, cpath.capDepth);
    if (seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth) != seL4_NoError) {
        return 0;   /* fall back to immediate scan */
    }
    st->waiting_reply_cap       = st->console_reply_cslot;
    st->console_poll_fds_vaddr  = fds_vaddr;
    st->console_poll_nfds       = nfds;
    st->console_wait_kind       = LUCAS_CONSOLE_WAIT_POLL;
    st->state                   = SOTBOX_STATE_WAITING_FOR_CONSOLE;
    return LUCAS_WAIT4_DEFERRED;
}

/* Park a blocking select/pselect that waits on the console fd (GNU bash readline
 * blocks in pselect(fd0) for input — unlike busybox's poll(stdin,-1)).  Same park
 * machinery as poll; the resume re-runs iomux_select_scan, writing the fd_sets. */
int64_t lucas_console_select_park(lucas_state_t *st, uint32_t nfds,
                                  uint64_t rfds, uint64_t wfds, uint64_t efds)
{
    if (st->console_reply_cslot == 0) {
        seL4_CPtr cslot;
        if (vka_cspace_alloc(st->vka, &cslot) != 0) return 0;
        st->console_reply_cslot = cslot;
    }
    cspacepath_t cpath;
    vka_cspace_make_path(st->vka, st->console_reply_cslot, &cpath);
    seL4_CNode_Delete(cpath.root, cpath.capPtr, cpath.capDepth);
    if (seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth) != seL4_NoError)
        return 0;
    st->waiting_reply_cap       = st->console_reply_cslot;
    st->console_poll_fds_vaddr  = rfds;      /* reuse for rfds */
    st->console_poll_nfds       = nfds;
    st->console_sel_wfds_vaddr  = wfds;
    st->console_sel_efds_vaddr  = efds;
    st->console_wait_kind       = LUCAS_CONSOLE_WAIT_SELECT;
    st->state                   = SOTBOX_STATE_WAITING_FOR_CONSOLE;
    return LUCAS_WAIT4_DEFERRED;
}

int64_t lucas_sys_read(lucas_state_t *st, uint64_t fd, uint64_t buf_vaddr,
                       uint64_t count, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a3; (void)_a4; (void)_a5;
    int64_t rc;
    if (fd >= LUCAS_MAX_FDS) { rc = -(int64_t)LX_EBADF; goto out; }
    lucas_fd_t *e = &st->fds[fd];

    switch (e->kind) {
        case LUCAS_FD_STDIO:
            if (fd == 0 || e->is_console_tty) {   /* fd0, or /dev/tty (bash readline) */
                rc = lucas_console_read_or_park(st, buf_vaddr, count);
                if (rc == LUCAS_WAIT4_DEFERRED) return rc;  /* propagate park */
                goto out;
            }
            /* Stdout/stderr are not readable. */
            rc = 0;
            goto out;
        case LUCAS_FD_PIPE_READ:
            /* apt arc · O_NONBLOCK (04000) pipe-read MUST return -EAGAIN on an
             * empty pipe, NOT park.  The Debian apt http method sets fd0
             * non-blocking (fcntl F_SETFL O_NONBLOCK) and drains its input pipe
             * in a read-until-EAGAIN loop to know it has the WHOLE `600 URI
             * Acquire` message before it acts.  lucas_pipe_read parks
             * unconditionally on an empty pipe (it has no fd-flag context), so
             * the method's drain loop never saw EAGAIN → it parked forever
             * without ever processing the URI / calling socket(): the apt↔method
             * worker handshake deadlocked.  A blocking read still parks (writers
             * open) or returns 0 (writers gone = EOF) via lucas_pipe_read. */
            if ((e->flags & 04000) && lucas_pipe_would_block_read(e->pipe)) {
                rc = -(int64_t)LX_EAGAIN;
                goto out;
            }
            rc = lucas_pipe_read(st, e->pipe, (uintptr_t)buf_vaddr, (size_t)count);
            goto out;
        case LUCAS_FD_DOOMKBD: {
            /* M2 · Doom raw keyboard. Drain pending events as 2-byte pairs
             * {keycode, down}; non-blocking (rc=0 → DG_GetKey reports "no key").
             * Poll fresh first so a key pressed since the last read is seen. */
            extern void kbd_poll(void);
            extern int  kbd_raw_get(uint8_t*, int*);
            kbd_poll();
            uint8_t kbuf[64]; size_t n = 0;
            size_t cap = (count < sizeof(kbuf)) ? (size_t)count : sizeof(kbuf);
            uint8_t code; int down;
            while (n + 2 <= cap && kbd_raw_get(&code, &down) == 0) {
                kbuf[n++] = code; kbuf[n++] = (uint8_t)down;
            }
            if (n == 0) { rc = 0; goto out; }
            if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr, kbuf, n) != 0) {
                rc = -(int64_t)LX_EFAULT; goto out;
            }
            rc = (int64_t)n; goto out;
        }
        case LUCAS_FD_DOOMMOUSE: {
            /* M2 · Doom mouse-look · one 5-byte sample {dx(LE16),dy(LE16),btn}. */
            extern int mouse_raw_get(int*, int*, int*);
            int dx = 0, dy = 0, btn = 0;
            if (mouse_raw_get(&dx, &dy, &btn) != 0) { rc = 0; goto out; }
            if (dx > 32767) dx = 32767; if (dx < -32768) dx = -32768;
            if (dy > 32767) dy = 32767; if (dy < -32768) dy = -32768;
            uint8_t mb[5] = { (uint8_t)(dx & 0xff), (uint8_t)((dx >> 8) & 0xff),
                              (uint8_t)(dy & 0xff), (uint8_t)((dy >> 8) & 0xff),
                              (uint8_t)btn };
            size_t want = (count < 5) ? (size_t)count : 5;
            if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr, mb, want) != 0) {
                rc = -(int64_t)LX_EFAULT; goto out;
            }
            rc = (int64_t)want; goto out;
        }
        case LUCAS_FD_NULL:
            rc = 0; goto out;   /* /dev/null · EOF */
        case LUCAS_FD_URANDOM: {
            /* /dev/urandom · fill from the arc4random CSPRNG (same pool as
             * getrandom(2)).  Chunked through a stack buffer like getrandom. */
            extern void sotos_arc4random_buf(void *buf, size_t n);
            uint8_t rbuf[4096];
            size_t want = (count < sizeof(rbuf)) ? (size_t)count : sizeof(rbuf);
            if (want == 0) { rc = 0; goto out; }
            sotos_arc4random_buf(rbuf, want);
            if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr, rbuf, want) != 0) {
                rc = -(int64_t)LX_EFAULT; goto out;
            }
            rc = (int64_t)want; goto out;
        }
        case LUCAS_FD_VFS:
            if (!e->mount || !e->mount->ops->read) { rc = -(int64_t)LX_EBADF; goto out; }
            {
                /* VFS read bounce buffer (file-scope g_rd_bounce so the doom
                 * anomaly probe can write a marker into the exact buffer mtio.h
                 * is read into · round-8 suspect for the arena↔orch alias). */
                extern uint8_t g_rd_bounce[4096];
                uint8_t *bounce = g_rd_bounce;
                /* WINE-M1 · Linux returns the FULL count for a regular-file
                 * read(); single-read callers depend on it.  Wine's
                 * read_nls_file() does one read(fd, buf, st_size) and FREES the
                 * buffer + returns NULL unless it gets exactly st_size — so a
                 * 4096-capped read left ntdll's casemap table NULL (→ #VMFault
                 * in ntdll_wcsicmp).  The backends (sotfs/proc) return
                 * min(want, remaining) honouring the offset, so a short backend
                 * read means EOF; loop the 4096 bounce to satisfy the request. */
                size_t total = 0;
                while (total < count) {
                    size_t want = (count - total < 4096) ? (size_t)(count - total) : 4096;
                    /* L8: thread caller state into op_read for canary tracking. */
                    lucas_set_current_caller(st);
                    int64_t got = e->mount->ops->read(e->mount->backend_state,
                                                       e->handle, bounce, want,
                                                       e->cursor);
                    lucas_set_current_caller(NULL);
                    if (got < 0) { rc = (total > 0) ? (int64_t)total : got; goto out; }
                    if (got == 0) break;                       /* EOF */
                    if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr + total,
                                             bounce, (size_t)got) != 0) {
                        rc = -(int64_t)LX_EFAULT;
                        goto out;
                    }
                    e->cursor += got;
                    total     += (size_t)got;
                    if ((size_t)got < want) break;             /* short read · EOF */
                }
                rc = (int64_t)total;
                goto out;
            }
        case LUCAS_FD_SOCKET:
            if (e->is_netlink) {             /* apt-T7 · netlink route socket read */
                extern int64_t lucas_sys_recvfrom(lucas_state_t *, uint64_t, uint64_t,
                                                  uint64_t, uint64_t, uint64_t, uint64_t);
                rc = lucas_sys_recvfrom(st, fd, buf_vaddr, count, 0, 0, 0);
                goto out;
            }
            if (e->wayland_connected) {
                rc = lucas_wayland_drain(st, fd, buf_vaddr, count);
                goto out;
            }
            if (e->unix_chan_idx1) {         /* WINE-M1 · AF_UNIX stream (wineserver) */
                extern int64_t lucas_unix_recv(lucas_state_t *, uint64_t, uint64_t, uint64_t);
                rc = lucas_unix_recv(st, fd, buf_vaddr, count);  /* may park (DEFERRED) */
                goto out;
            }
            if (e->tcp_conn != NULL || e->lwip_sess != NULL) {  /* δ TCP or lwIP egress (demux) */
                rc = lucas_tcp_recv(st, fd, buf_vaddr, count);  /* routes to the right stack */
                goto out;
            }
            rc = -(int64_t)LX_EBADF;
            goto out;
        default:
            break;
    }
    /* Legacy path for is_std fd=0 before kind was set (pre-T4 sotBoxes). */
    if (e->is_std && fd == 0) {
        rc = lucas_console_read_or_park(st, buf_vaddr, count);
        if (rc == LUCAS_WAIT4_DEFERRED) return rc;  /* propagate park */
        goto out;
    }
    rc = -(int64_t)LX_EBADF;
out:
    LUCAS_FS_TRACE("read fd=%lu count=%lu -> %ld",
                   (unsigned long)fd, (unsigned long)count, (long)rc);
    return rc;
}

extern lucas_state_t *sotbox_get_slot(int i);
#ifndef SOTBOX_MAX_SLOTS
#define SOTBOX_MAX_SLOTS 8  /* fall-back · matches include/orch/sotbox.h */
#endif

/* Called from orch_fault_loop's idle branch. If a sotbox is parked in
 * WAITING_FOR_CONSOLE and a UART byte is ready, deliver it and unblock the
 * read(fd0). Single foreground shell → at most one parked reader in practice.
 * Wake is best-effort: it fires only in the idle branch (no sotbox faulting);
 * with one interactive busybox that is always true. No deadlock — faults are
 * finite — but with concurrent sotboxes a parked read may wait for a fault to
 * clear (acceptable: this arc runs one foreground shell). */
void lucas_console_resume_parked(void)
{
    extern int64_t iomux_poll_scan(lucas_state_t *st, uintptr_t fds_vaddr,
                                   unsigned int nfds);
    for (int slot = 0; slot < SOTBOX_MAX_SLOTS; ++slot) {
        lucas_state_t *st = sotbox_get_slot(slot);
        if (!st || st->state != SOTBOX_STATE_WAITING_FOR_CONSOLE) continue;
        /* Focus: don't wake a non-focused box (the shell parked behind a REPL). */
        if (g_console_focus_slot >= 0 && slot != g_console_focus_slot) continue;

        int64_t r;
        if (st->console_wait_kind == LUCAS_CONSOLE_WAIT_POLL) {
            /* poll(stdin,-1): only wake once a byte is ready (do NOT consume
             * it — the client's follow-up read(fd0) drains it). Re-run the scan
             * so revents is written back; wake with the ready-count.  SSH canary
             * shell (Phase B): an SSH_RING box's readiness is the SHELL_IN ring,
             * not the UART. */
            if (st->console_src == LUCAS_CONSOLE_SRC_SSH_RING) {
                bytepipe_ring_t *in = (bytepipe_ring_t *)BYTEPIPE_SHELL_IN_VADDR;
                if (__atomic_load_n(&in->w, __ATOMIC_ACQUIRE) == st->shell_in_rd)
                    continue;   /* no SSH byte yet · stay parked */
            } else if (!lucas_console_data_ready()) {
                continue;
            }
            r = iomux_poll_scan(st, (uintptr_t)st->console_poll_fds_vaddr,
                                (unsigned int)st->console_poll_nfds);
            if (r == 0) continue;   /* still nothing the client asked for · stay parked */
        } else if (st->console_wait_kind == LUCAS_CONSOLE_WAIT_SELECT) {
            /* blocking select/pselect on the console (bash readline): wake once a
             * console byte is ready.  The initial scan already wrote the result
             * sets EMPTY; the wait is on fd0, so report fd0 readable directly
             * (set bit 0 of rfds; wfds/efds stay empty) + return 1. */
            if (st->console_src == LUCAS_CONSOLE_SRC_SSH_RING) {
                bytepipe_ring_t *in = (bytepipe_ring_t *)BYTEPIPE_SHELL_IN_VADDR;
                if (st->dsr_emit == 0 &&
                    __atomic_load_n(&in->w, __ATOMIC_ACQUIRE) == st->shell_in_rd)
                    continue;   /* no SSH byte yet · stay parked */
            } else if (st->dsr_emit == 0 && !lucas_console_data_ready()) {
                continue;
            }
            uint8_t fd0bit = 0x01;
            if (!st->console_poll_fds_vaddr ||
                lucas_copy_to_client(st, st->console_poll_fds_vaddr, &fd0bit, 1) != 0)
                continue;   /* can't report · stay parked */
            r = 1;
        } else {
            /* read(fd0): deliver exactly one byte (UART or SHELL_IN per console_src). */
            int b = lucas_console_src_getbyte(st);
            if (b < 0) continue;
            if (b == 0x04 && g_console_focus_slot >= 0 && st->slot_index == g_console_focus_slot) {
                r = 0;   /* VEOF · Ctrl-D → EOF for the focused REPL (exits it) */
            } else {
                uint8_t ch = (uint8_t)b;
                r = (lucas_copy_to_client(st, st->console_buf_vaddr, &ch, 1) == 0)
                        ? 1 : -(int64_t)LX_EFAULT;
            }
        }

        seL4_UserContext regs;
        if (seL4_TCB_ReadRegisters(st->client_tcb, false, 0, 18, &regs) == 0) {
            regs.rax = (uint64_t)r;
            regs.rip += 2;          /* advance past the syscall instruction */
            regs.rcx  = regs.rip;
            regs.r11  = regs.rflags;
            seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 18, &regs);
        }
        seL4_Send(st->waiting_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));
        /* Do NOT free console_reply_cslot — it is REUSED for the next park
         * (the arena cspace_free is a no-op anyway; the slot is reclaimed
         * wholesale at sotbox teardown via arena revoke). Just drop the
         * waiting marker so the exit-teardown chokepoint won't re-handle it. */
        st->waiting_reply_cap      = 0;
        st->console_buf_vaddr      = 0;
        st->console_poll_fds_vaddr = 0;
        st->console_poll_nfds      = 0;
        st->console_sel_wfds_vaddr = 0;
        st->console_sel_efds_vaddr = 0;
        st->console_wait_kind      = LUCAS_CONSOLE_WAIT_READ;
        st->state                  = SOTBOX_STATE_RUNNING;
    }
}

/* TUI · deliver an async signal to a sotbox parked in read(fd0): reply to its
 * saved caller with -EINTR so the read returns, the pending signal is delivered
 * on the return path (lucas_signals_try_deliver), and the guest's handler runs.
 * Returns true if it woke a parked reader, false if the sotbox wasn't parked.
 *
 * Mirrors lucas_console_resume_parked's reply path EXACTLY (register-inject +
 * seL4_Send on the SaveCaller'd console_reply_cslot), but instead of delivering
 * a byte it returns -EINTR (Linux errno 4 → the syscall returns -4) and does NOT
 * consume any input.  Because that resume path bypasses the fault loop's own
 * post-syscall try_deliver (fault_loop.c:501-504), we MUST call try_deliver here
 * after staging the -EINTR return: try_deliver saves the just-staged regs (rax=-4,
 * rip past the syscall) into a sigframe and redirects rip to the SIGWINCH handler.
 * After the handler's rt_sigreturn the guest resumes at the post-read instruction
 * with rax=-4 — exactly Linux's "handler ran, the interrupted read() returns
 * EINTR" semantics.  Only ever called for the WAIT_READ park (SHELL_WINCH); the
 * normal keystroke read-park/resume path is untouched. */
bool lucas_console_wake_parked_eintr(lucas_state_t *st)
{
    extern int lucas_signals_try_deliver(lucas_state_t *st,
                                          seL4_UserContext *regs);
    if (!st || st->state != SOTBOX_STATE_WAITING_FOR_CONSOLE) return false;
    /* Only EINTR a plain read(fd0) park.  A poll-park's contract is a ready-count,
     * not -EINTR; leave it parked (the SIGWINCH still delivers on the next syscall
     * return through the fault loop). */
    if (st->console_wait_kind != LUCAS_CONSOLE_WAIT_READ) return false;
    if (st->waiting_reply_cap == 0) return false;

    seL4_UserContext regs;
    if (seL4_TCB_ReadRegisters(st->client_tcb, false, 0, 18, &regs) == 0) {
        regs.rax = (uint64_t)(int64_t)(-4);  /* -EINTR · the interrupted read */
        regs.rip += 2;                       /* advance past the syscall instruction */
        regs.rcx  = regs.rip;
        regs.r11  = regs.rflags;
        /* Deliver the pending signal NOW (this wake path bypasses the fault
         * loop's post-syscall try_deliver).  If a deliverable signal is queued,
         * try_deliver rewrites regs in-place to enter the user handler with the
         * staged -EINTR saved in the sigframe. */
        if (st->n_pending > 0) {
            (void)lucas_signals_try_deliver(st, &regs);
        }
        seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 18, &regs);
    }
    seL4_Send(st->waiting_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));
    /* Do NOT free console_reply_cslot — it is REUSED for the next park (same as
     * the resume path).  Just drop the waiting marker. */
    st->waiting_reply_cap      = 0;
    st->console_buf_vaddr      = 0;
    st->console_poll_fds_vaddr = 0;
    st->console_poll_nfds      = 0;
    st->console_wait_kind      = LUCAS_CONSOLE_WAIT_READ;
    st->state                  = SOTBOX_STATE_RUNNING;
    return true;
}

/* TUI · F1 · deliver a winsize change to the SSH-session FOREGROUND reader.
 * vim/nano run as a forked CHILD sotbox parked in read(fd0); the parent busybox
 * is parked in wait4.  Scan for the box belonging to `session` that is parked on
 * the SSH-ring console (the foreground reader — the child if one is forked, else
 * the busybox itself), update ITS ws, queue SIGWINCH on IT, and EINTR-wake IT so
 * its handler runs and it re-queries TIOCGWINSZ → redraw.  Returns the count
 * woken (0 if none parked — the size still updates so the next read sees it). */
int lucas_console_winch_foreground(uint32_t session, uint16_t cols, uint16_t rows)
{
    extern void lucas_signals_queue_pending(lucas_state_t *st, int sig);
    int woke = 0;
    for (int slot = 0; slot < SOTBOX_MAX_SLOTS; ++slot) {
        lucas_state_t *st = sotbox_get_slot(slot);
        if (!st) continue;
        if (st->console_src != LUCAS_CONSOLE_SRC_SSH_RING) continue;
        if (st->cow_session == 0 || st->cow_session != session) continue;
        /* Update ws on EVERY box in the session (parent + any children) so a
         * subsequent TIOCGWINSZ from any of them is current. */
        if (cols && rows) { st->ws.ws_col = cols; st->ws.ws_row = rows; }
        /* SIGWINCH + EINTR-wake the one that is parked reading the console (the
         * foreground editor; lucas_console_wake_parked_eintr no-ops if not parked). */
        if (st->state == SOTBOX_STATE_WAITING_FOR_CONSOLE) {
            lucas_signals_queue_pending(st, 28 /*SIGWINCH*/);
            if (lucas_console_wake_parked_eintr(st)) woke++;
        } else {
            /* Not parked (running, or parked in wait4): still queue SIGWINCH so it
             * delivers on the next syscall return through the fault loop. */
            lucas_signals_queue_pending(st, 28 /*SIGWINCH*/);
        }
    }
    printf("[tty] winch-fg woke=%d cols=%u rows=%u\n", woke, cols, rows);
    return woke;
}

/* OBSD-ε RANDOM-FD · pick a random free slot from [3, LUCAS_MAX_FDS).
 * Defeats emulator-fingerprinting via sequential fd pattern.  Try up
 * to LUCAS_FD_RAND_TRIES random picks; if all collide, fall back to a
 * linear scan (mostly-full table).  stdio slots 0/1/2 are reserved
 * and never touched here. */
#define LUCAS_FD_RAND_TRIES 16
static int alloc_fd(lucas_state_t *st) {
    for (int try = 0; try < LUCAS_FD_RAND_TRIES; ++try) {
        uint32_t pick = 3 + sotos_arc4random_uniform(LUCAS_MAX_FDS - 3);
        if (st->fds[pick].kind == LUCAS_FD_INVALID) {
            return (int)pick;
        }
    }
    /* Random picks exhausted · fall back to linear (mostly-full table). */
    for (int i = 3; i < LUCAS_MAX_FDS; ++i) {
        if (st->fds[i].kind == LUCAS_FD_INVALID) return i;
    }
    return -1;
}

/* L13 · memfd_create(name, flags) → allocate a fresh fd flagged as a wl_shm
 * pool backing.  The fd is sized + pool-allocated by a later ftruncate (the
 * orch shm-pool from A2), then mapped into the guest by mmap (Task B2).  The
 * name/flags are advisory and ignored. */
int64_t lucas_sys_memfd_create(lucas_state_t *st,
                               uint64_t name_ptr, uint64_t flags,
                               uint64_t _a2, uint64_t _a3,
                               uint64_t _a4, uint64_t _a5)
{
    (void)name_ptr; (void)flags; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    int fd = alloc_fd(st);
    if (fd < 0) return -24;                 /* -EMFILE */
    /* Mark the slot in-use so alloc_fd won't hand it out again before mmap.
     * VFS kind with no mount/handle is inert until ftruncate/mmap wire it. */
    st->fds[fd].kind            = LUCAS_FD_VFS;
    st->fds[fd].is_memfd        = 1;
    st->fds[fd].shm_pool_id     = -1;
    st->fds[fd].shm_pool_size   = 0;
    st->fds[fd].shm_guest_vaddr = 0;
    printf("[l13-memfd] fd=%d\n", fd);
    return fd;
}

/* Resolve a client pathname against the sotbox cwd into an absolute, normalized
 * path (collapses "//", ".", ".."). Relative inputs are prefixed with cwd
 * (empty cwd == "/"). Output always starts with '/'. Fidelity: lets the canary
 * shell's `cd`/`ls .`/relative paths behave like a real FS; absolute-path
 * callers are unaffected (an already-absolute, already-normal path round-trips). */
void lucas_resolve_path(lucas_state_t *st, const char *in, char *out, size_t outsz) {
    if (outsz == 0) return;
    char tmp[LUCAS_PATH_MAX * 2];
    const char *cwd = (st && st->cwd[0]) ? st->cwd : "/";
    size_t ti = 0;
    if (in[0] != '/') {                          /* relative → prefix cwd + '/' */
        for (size_t i = 0; cwd[i] && ti < sizeof(tmp) - 2; ++i) tmp[ti++] = cwd[i];
        if (ti == 0 || tmp[ti - 1] != '/') tmp[ti++] = '/';
    }
    for (size_t i = 0; in[i] && ti < sizeof(tmp) - 1; ++i) tmp[ti++] = in[i];
    tmp[ti] = '\0';

    /* Segment-wise normalize: skip empty + ".", pop on "..". */
    const char *segs[64]; size_t seglen[64]; int n = 0;
    size_t i = 0;
    while (tmp[i] && n < 64) {
        while (tmp[i] == '/') i++;
        if (!tmp[i]) break;
        size_t j = i;
        while (tmp[j] && tmp[j] != '/') j++;
        size_t len = j - i;
        if (len == 1 && tmp[i] == '.') {
            /* current dir · skip */
        } else if (len == 2 && tmp[i] == '.' && tmp[i + 1] == '.') {
            if (n > 0) n--;                       /* parent · pop (clamps at root) */
        } else {
            segs[n] = tmp + i; seglen[n] = len; n++;
        }
        i = j;
    }

    size_t oi = 0;
    if (n == 0) { if (outsz >= 2) { out[0] = '/'; out[1] = '\0'; } else out[0] = '\0'; return; }
    for (int s = 0; s < n; ++s) {
        if (oi < outsz - 1) out[oi++] = '/';
        for (size_t k = 0; k < seglen[s] && oi < outsz - 1; ++k) out[oi++] = segs[s][k];
    }
    out[oi] = '\0';
}

/* WINE-M1 · create an empty VFS node at `path` (resolved against the caller's
 * cwd) so a later lstat/stat sees it exist.  Used by AF_UNIX bind() to
 * materialize the wineserver "socket" file: the wine launcher polls
 * lstat("socket") in a retry loop and only proceeds to connect() once the file
 * appears — our rendezvous registered the listener but created no filesystem
 * node, so wine spun and bailed.  Returns 0 on success / already-exists, <0 on
 * error.  (op_stat reports it S_IFREG, not S_IFSOCK — wine's poll only needs
 * existence; the actual connect rides the AF_UNIX rendezvous, not the file.) */
int lucas_vfs_create_node(lucas_state_t *st, const char *path) {
    char resolved[LUCAS_PATH_MAX];
    lucas_resolve_path(st, path, resolved, sizeof(resolved));
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, resolved, &suffix);
    if (!m || !m->ops->open) return -1;
    void *handle = NULL;
    /* O_CREAT(0x40)|O_WRONLY(0x1) · mode S_IFSOCK|0600 so op_stat/op_fstat
     * report S_ISSOCK (wine rejects a non-socket: "'…/socket' is not a socket"). */
    int rc = m->ops->open(m->backend_state, suffix, 0x40 | 0x1,
                          LX_S_IFSOCK | 0600, &handle);
    if (rc < 0) return rc;
    if (handle && m->ops->close) m->ops->close(m->backend_state, handle);
    printf("[unix] bind · materialized socket node '%s' (S_IFSOCK)\n", resolved);
    return 0;
}

int64_t lucas_chdir_resolve(lucas_state_t *st, const char *in) {
    char resolved[LUCAS_PATH_MAX];
    lucas_resolve_path(st, in, resolved, sizeof(resolved));
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, resolved, &suffix);
    if (!m || !m->ops->stat) return -(int64_t)2;             /* -ENOENT */
    struct lx_stat sb;
    if (m->ops->stat(m->backend_state, suffix, &sb) < 0) return -(int64_t)2;
    if ((sb.st_mode & LX_S_IFMT) != LX_S_IFDIR) return -(int64_t)20;  /* -ENOTDIR */
    size_t i = 0;
    for (; resolved[i] && i < sizeof(st->cwd) - 1; ++i) st->cwd[i] = resolved[i];
    st->cwd[i] = '\0';
    return 0;
}

/* One-shot absolute-path override · openat sets this to a dir-fd-resolved path so
 * lucas_sys_open opens THAT instead of cwd-resolving path_vaddr.  Single-threaded
 * orch · consumed (cleared) on the next lucas_sys_open entry. */
/* persona-coherence · in a Tier-2 honey SSH session (cow_session != 0) the
 * persona is Alpine/musl, which has NO glibc multiarch dir.  Hide any path under
 * /lib/x86_64-linux-gnu (or /usr/lib/x86_64-linux-gnu) so stat/open/getdents
 * report it absent — the one Debian/Ubuntu tell in the otherwise-Alpine session.
 * Safe now that the SSH login shell is musl alpine-bash (it loads its libs from
 * /usr/lib, not the glibc multiarch dir).  Operator (cow_session == 0) sees the
 * real tree (the glibcdyn / TUI fixtures still need it for their guests). */
bool lucas_persona_hides(const lucas_state_t *st, const char *path) {
    if (!st || st->cow_session == 0 || !path) return false;
    /* sotctl · the operator's native CLI — a real distro has no such binary, so it
     * is invisible to EVERY attacker session (stat/open/getdents → ENOENT); the
     * operator's trusted shell (cow_session == 0) still sees + runs it. */
    if (strstr(path, "sotctl") != NULL) return true;
    /* The libc tell is PERSONA-AWARE (2nd-persona arc): an Alpine (musl) session
     * must not show the glibc multiarch dir; a Ubuntu (glibc) session must not
     * show musl's ld-musl loader.  Resolve the session's persona profile. */
    {
        extern int lucas_persona_session_get(uint32_t, lucas_persona_t *);
        lucas_persona_t pc;
        int ubuntu = (lucas_persona_session_get(st->cow_session, &pc) &&
                      pc.profile == LUCAS_PERSONA_DEBIAN);
        if (ubuntu)
            return strstr(path, "ld-musl") != NULL ||
                   strstr(path, "/lib/apk") != NULL;   /* musl/apk tells on Ubuntu */
        return strstr(path, "x86_64-linux-gnu") != NULL; /* glibc tell on Alpine */
    }
}

static const char *g_open_path_override = NULL;

int64_t lucas_sys_open(lucas_state_t *st, uint64_t path_vaddr,
                       uint64_t flags, uint64_t mode,
                       uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;
    char rawpath[LUCAS_PATH_MAX];
    int slen = lucas_copy_cstr_from_client(st, path_vaddr, rawpath, sizeof(rawpath));
    if (slen < 0) return -(int64_t)LX_EFAULT;
    char path[LUCAS_PATH_MAX];
    if (g_open_path_override) {                            /* openat dir-fd path */
        strncpy(path, g_open_path_override, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
        g_open_path_override = NULL;                       /* one-shot · consumed */
    } else {
        lucas_resolve_path(st, rawpath, path, sizeof(path));   /* cwd + "."/".." → absolute */
    }

    /* O_TMPFILE (__O_TMPFILE 0x400000 | O_DIRECTORY 0x10000 == 0x410000) ·
     * `open(dir, O_TMPFILE|O_RDWR)` asks the kernel to create an ANONYMOUS
     * regular file in directory `dir`.  Our VFS has no anonymous-inode support,
     * and without this guard the open silently succeeds with a handle to the
     * DIRECTORY inode → the caller's first write returns EISDIR.  apt's FileFd
     * (and most O_TMPFILE users) fall back to a named mkstemp + rename when the
     * O_TMPFILE open returns an error — a path our session-upper VFS handles
     * (partial/<name> creates + rename are proven).  Return EOPNOTSUPP so the
     * caller takes that fallback instead of writing into a directory. */
    if ((flags & 0x410000) == 0x410000) {
        printf("[fs] open · O_TMPFILE on '%s' → -EOPNOTSUPP (caller falls back to named temp)\n",
               path);
        return -(int64_t)95;  /* -EOPNOTSUPP */
    }

    /* apk-network-install · open-follow a per-session symlink (cow_session != 0).
     * apk's soname links (e.g. /usr/lib/libncursesw.so.6 → libncursesw.so.6.4) are
     * recorded in the per-session table — a FORWARD-REF (the link is created
     * before its target materializes, so a copy-at-rename can't snapshot it).
     * ld-musl must open the link and reach the real .so.  Substitute the target
     * here, in the OPEN path ONLY (lstat/readlink still surface the link verbatim).
     * No new escape surface: the target is re-resolved through the same contained
     * VFS path, and anything reachable via the link is reachable directly — all
     * honey / session-upper, no real host FS.  One level (soname links are flat). */
    if (st->cow_session != 0) {
        const char *sl = lucas_symlink_get(st->cow_session, path);
        if (sl) {
            char cand[LUCAS_PATH_MAX];
            if (sl[0] == '/') {
                strncpy(cand, sl, sizeof(cand) - 1); cand[sizeof(cand) - 1] = '\0';
            } else {
                size_t dn = strlen(path);
                if (dn >= sizeof(cand)) dn = sizeof(cand) - 1;
                memcpy(cand, path, dn); cand[dn] = '\0';
                char *slash = strrchr(cand, '/');
                if (slash) slash[1] = '\0'; else cand[0] = '\0';
                size_t cl = strlen(cand), tl = strlen(sl);
                if (cl + tl < sizeof(cand)) memcpy(cand + cl, sl, tl + 1);
            }
            char followed[LUCAS_PATH_MAX];
            lucas_resolve_path(st, cand, followed, sizeof(followed));
            strncpy(path, followed, sizeof(path) - 1); path[sizeof(path) - 1] = '\0';
            printf("[fs] open · session symlink followed → %s\n", path);
        }
    }

    /* persona-coherence · hide the glibc multiarch dir from the Alpine honey
     * session (musl persona has no /lib/x86_64-linux-gnu).  ENOENT on open. */
    if (lucas_persona_hides(st, path)) return -(int64_t)2;

    /* /dev/tty · GNU bash's readline does ALL its interactive terminal I/O on
     * /dev/tty (open O_RDWR), not on fd0/1/2.  For an interactive console box
     * (the SSH honey shell), alias it to the console: a STDIO fd flagged
     * is_console_tty so read()/poll() pull from the console (SHELL_IN ring / UART)
     * and write() pushes to it (SHELL_OUT / UART) — exactly like fd0/1/2.  Without
     * this, /dev/tty read returns EOF → bash sees Ctrl-D and exits immediately. */
    if (st->console_interactive && strcmp(path, "/dev/tty") == 0) {
        int fd = alloc_fd(st);
        if (fd < 0) return -(int64_t)24;  /* -EMFILE */
        st->fds[fd].kind           = LUCAS_FD_STDIO;
        st->fds[fd].is_std         = true;
        st->fds[fd].is_console_tty = 1;
        return (int64_t)fd;
    }

    /* Doom Phase 1a · /dev/fb0 present sink.  No VFS mount needed; return a
     * real fd whose kind is LUCAS_FD_FB so write() routes to lucas_fb_present. */
    if (strcmp(path, "/dev/fb0") == 0) {
        int fd = alloc_fd(st);
        if (fd < 0) return -(int64_t)24;  /* -EMFILE */
        st->fds[fd].kind   = LUCAS_FD_FB;
        st->fds[fd].is_std = false;
        return (int64_t)fd;
    }

    /* M2 · Doom keyboard source. /dev/doomkbd opens ONLY when a real
     * virtio-keyboard is present (just run-interactive); read() returns raw
     * 2-byte {keycode,down} events. Headless → -ENOENT so the doom shim falls
     * back to its scripted g_keyseq + frame cap (gates unchanged). */
    if (strcmp(path, "/dev/doomkbd") == 0) {
        extern int kbd_present(void);
        if (!kbd_present()) return -(int64_t)2;   /* -ENOENT */
        int fd = alloc_fd(st);
        if (fd < 0) return -(int64_t)24;
        st->fds[fd].kind   = LUCAS_FD_DOOMKBD;
        st->fds[fd].is_std = false;
        return (int64_t)fd;
    }
    /* M2 · Doom mouse-look source · /dev/doommouse · only when a virtio-tablet
     * is present. read() → 5 bytes {dx(LE16), dy(LE16), buttons}. */
    if (strcmp(path, "/dev/doommouse") == 0) {
        extern int mouse_present(void);
        if (!mouse_present()) return -(int64_t)2;   /* -ENOENT */
        int fd = alloc_fd(st);
        if (fd < 0) return -(int64_t)24;
        st->fds[fd].kind   = LUCAS_FD_DOOMMOUSE;
        st->fds[fd].is_std = false;
        return (int64_t)fd;
    }

    /* /dev/null · reads return EOF, writes are discarded. Busybox redirects to
     * it constantly, so the canary shell needs it to run normally. */
    if (strcmp(path, "/dev/null") == 0) {
        int fd = alloc_fd(st);
        if (fd < 0) return -(int64_t)24;
        st->fds[fd].kind   = LUCAS_FD_NULL;
        st->fds[fd].is_std = false;
        return (int64_t)fd;
    }

    /* /dev/urandom (+ /dev/random) · reads return CSPRNG bytes from the same
     * arc4random pool as getrandom(2).  Real software needs it: git aborts
     * "unable to get random bytes for temporary file" without it (it reads
     * /dev/urandom directly rather than calling getrandom on musl). */
    if (strcmp(path, "/dev/urandom") == 0 || strcmp(path, "/dev/random") == 0) {
        int fd = alloc_fd(st);
        if (fd < 0) return -(int64_t)24;
        st->fds[fd].kind   = LUCAS_FD_URANDOM;
        st->fds[fd].is_std = false;
        return (int64_t)fd;
    }

    /* Spec B · cred-access signal.  Any open of a credential path (read
     * OR write intent) is a recon signal at ANY tier — a write-open of
     * /etc/shadow is at least as suspicious as a read.  Fires pre-unveil:
     * the attempt itself is the signal, even if a later gate denies it.
     * Forward to the anomaly and apply the reply tier (reply-driven). */
    if (sotos_path_is_cred_sensitive(path)) {
        /* Tier-0e EXEMPTION · a trusted egress sandbox (the real TLS client:
         * busybox wget → openssl s_client) MUST read the CA trust store
         * (/etc/ssl/cert.pem) to verify certificates.  Promoting it to Tier-1
         * on that read rebinds its functor with net=0 → the egress capability
         * is revoked → no DNS forward, no connect → the TLS fetch dies before
         * the handshake.  The cred-access canary exists to catch MALWARE recon,
         * not the trusted Tier-0e leg.  Log it for observability, skip the
         * promotion. */
        if (st->functor && st->functor->is_egress) {
            printf("[lucas] cred-access · pid=%d path=%s · Tier-0e egress (trusted · no promote)\n",
                   st->synthetic_pid, path);
        } else {
            printf("[lucas] cred-access · pid=%d path=%s\n", st->synthetic_pid, path);
            int target = anomaly_forward_sync(st, ANOMALY_EV_CRED_ACCESS, 0);
            if (target > 0) anomaly_apply_reply_tier(st, target);
        }
    }

    /* UNVEIL-CORE · gate by path before resolving the mount.  Map
     * O_RDONLY → R, O_WRONLY → W, O_RDWR → R|W. */
    {
        uint64_t accmode = flags & LUCAS_O_ACCMODE;
        uint32_t want = (accmode == 0) ? UNVEIL_R
                      : (accmode == 1) ? UNVEIL_W
                                       : (uint32_t)(UNVEIL_R | UNVEIL_W);
        if (lucas_unveil_check(st, path, want) < 0)
            return -(int64_t)LUCAS_EACCES_VAL;
    }

    /* TIER1-REVOKE-GATES · in Tier-1 (Silenced), deny any open that asks
     * for write capability.  Closes the new-open(O_WRONLY) escape hole.
     * O_WRONLY=1, O_RDWR=2 (low bits of accmode); O_CREAT=0x40,
     * O_TRUNC=0x200 on Linux x86_64. */
    if (st->functor && st->functor->writes_silenced) {
        uint64_t accmode = flags & LUCAS_O_ACCMODE;
        if (accmode == LX_O_WRONLY || accmode == LX_O_RDWR ||
            (flags & 0x40 /* O_CREAT */) ||
            (flags & 0x200 /* O_TRUNC */)) {
            st->cap_revoke_count++;
            printf("[tier1-revoke] pid=%d open('%s', 0x%lx) · -EACCES (cap_revokes=%u)\n",
                   st->synthetic_pid, path, (unsigned long)flags,
                   (unsigned int)st->cap_revoke_count);
            return -(int64_t)LUCAS_EACCES_VAL;
        }
    }

    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m || !m->ops->open) return -(int64_t)2;  /* -ENOENT */

    /* F_persistence γ PR 4 · when a Tier-2 sotbox opens a persistence-sensitive
     * path with create-or-write intent, flag the inode via the pending hint so
     * sotfs's apply_pending_sotfs_hint() (PR 3) stamps functor_persistence=1.
     * The hint is consumed by the very next VFS op on this caller, then
     * cleared by the backend.  Tier-0/1 writes pass through unmodified.
     *
     * Scope: openat / open with O_CREAT|O_WRONLY|O_RDWR · dominant install
     * vector.  write-by-fd (lucas_sys_write) is NOT instrumented · the fd
     * table has no path field, so a fd→path lookup is not trivially
     * available.  The malware's first call to a persistence path goes
     * through openat, so this single intercept catches the install. */
    {
        uint64_t accmode = flags & LUCAS_O_ACCMODE;
        bool writeable = (accmode == LX_O_WRONLY) || (accmode == LX_O_RDWR) ||
                         (flags & 0x40 /* O_CREAT */) ||
                         (flags & 0x200 /* O_TRUNC */);
        if (st->tier == 2 && writeable &&
            sotos_path_is_persistence_sensitive(path)) {
            st->pending_sotfs_hint |= SOTFS_HINT_FUNCTOR_PERSISTENCE;
            printf("[lucas] persistence install · path=%s · slot=%d (openat)\n",
                   path, st->slot_index);
            sotos_audit_emit(SOTGUARD_KIND_PERSISTENCE_INSTALL,
                             (uint32_t)st->slot_index, /*arg0=*/0);
            /* Surface the persistence attempt as a distinct event so the
             * operator `watch` monitor flags it (⛔ PERSIST) instead of letting
             * it read as a generic CYAN "RECON open". */
            trace_emit_persistence(st->slot_index,
                                   (uint32_t)st->synthetic_pid, path);
        }
        /* P4 Task 7 · apk DB write → PACKAGE_INSTALL IOC.
         * Fires for /lib/apk/db/installed* and /etc/apk/world only.
         * Disjoint from the persistence-sensitive set above (no double-emit). */
        if (st->tier == 2 && writeable && apk_is_db_install_path(path)) {
            printf("[lucas] package install · path=%s · slot=%d (openat)\n",
                   path, st->slot_index);
            sotos_audit_emit(SOTGUARD_KIND_PACKAGE_INSTALL,
                             (uint32_t)st->slot_index, /*arg0=*/0);
            trace_emit_persistence(st->slot_index,
                                   (uint32_t)st->synthetic_pid, path);
        }
    }

    void *handle = NULL;
    /* L8-ε: thread caller state so op_open can attribute tier info. */
    lucas_set_current_caller(st);
    int rc = m->ops->open(m->backend_state, suffix, (int)flags,
                           (uint32_t)mode, &handle);
    lucas_set_current_caller(NULL);

    /* γ · PR 4 follow-up · clear pending_sotfs_hint unconditionally so it
     * does not bleed into the next syscall from this caller.  On success
     * paths the hint was already consumed (and cleared) by
     * apply_pending_sotfs_hint() inside the sotfs backend (op_open create
     * branch / op_write).  On error paths (e.g. shadow -EACCES, -ENOENT
     * without O_CREAT, -EMFILE) the consumer never fires, so without this
     * clear a future open()/write() from the same sotbox would incorrectly
     * inherit the F_persistence flag and stamp an unrelated inode. */
    st->pending_sotfs_hint = 0;

    if (rc < 0) return (int64_t)rc;

    int fd = alloc_fd(st);
    if (fd < 0) {
        if (m->ops->close) m->ops->close(m->backend_state, handle);
        return -(int64_t)24;  /* -EMFILE */
    }
    st->fds[fd].kind   = LUCAS_FD_VFS;
    st->fds[fd].mount  = m;
    st->fds[fd].handle = handle;
    st->fds[fd].cursor = 0;
    st->fds[fd].flags  = (int)flags;
    st->fds[fd].is_std = false;
    st->fds[fd].pipe   = NULL;
    /* dir-fd support · remember the absolute path so a later *at syscall on this
     * fd (when it's a directory) can resolve relative names against it. */
    strncpy(st->fds[fd].fd_path, path, sizeof(st->fds[fd].fd_path) - 1);
    st->fds[fd].fd_path[sizeof(st->fds[fd].fd_path) - 1] = '\0';
    LUCAS_FS_TRACE("open path=%s flags=0x%lx -> fd=%d", path,
                   (unsigned long)flags, fd);
    return (int64_t)fd;
}

static int  reclock_inode_of(lucas_state_t *st, uint64_t fd);       /* fwd · record-lock release on close */
static void lucas_reclock_release_inode(int synth_pid, int inode);  /* fwd */

int64_t lucas_sys_close(lucas_state_t *st, uint64_t fd,
                        uint64_t _a1, uint64_t _a2, uint64_t _a3,
                        uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (fd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;
    lucas_fd_t *e = &st->fds[fd];
    int rc = 0;

    /* M4 · the memfd close is NOT a pool ref — close() is immediate and races
     * ahead of libwayland's buffered wl_buffer.destroy.  The pool is freed by
     * the wayland refcount (pool.destroy + buffer.destroy) or the teardown
     * sweep; just clear the back-pointer so a re-close can't dangle. */
    if (e->is_memfd && e->shm_pool_id >= 0) {
        e->shm_pool_id = -1;
    }

    switch (e->kind) {
        case LUCAS_FD_STDIO:
            e->kind   = LUCAS_FD_INVALID;
            e->is_std = false;
            /* OBSD-ε OMALLOC · junk on free · zero stale slot fields so a
             * future UAF cannot misuse residual handle/mount/pipe pointers. */
            memset(&st->fds[fd], 0, sizeof(lucas_fd_t));
            return 0;
        case LUCAS_FD_PIPE_READ:
            lucas_pipe_close_reader(e->pipe);
            e->pipe = NULL;
            e->kind = LUCAS_FD_INVALID;
            /* OBSD-ε OMALLOC · junk on free. */
            memset(&st->fds[fd], 0, sizeof(lucas_fd_t));
            return 0;
        case LUCAS_FD_PIPE_WRITE:
            lucas_pipe_close_writer(e->pipe);
            e->pipe = NULL;
            e->kind = LUCAS_FD_INVALID;
            /* OBSD-ε OMALLOC · junk on free. */
            memset(&st->fds[fd], 0, sizeof(lucas_fd_t));
            return 0;
        case LUCAS_FD_VFS:
            /* POSIX · closing an fd releases this process's record locks on its
             * inode (apt's UnLockInner closes the dpkg DB lock fd this way so the
             * forked dpkg can take it).  Do it BEFORE the handle is dropped so the
             * inode is still resolvable. */
            { int rli = reclock_inode_of(st, fd);
              if (rli >= 0) lucas_reclock_release_inode(st->synthetic_pid, rli); }
            /* N3/D3 · a lazy file-backed mmap region pinned this fd's VFS
             * handle; lazy faults read through it AFTER the guest closes the
             * .so fd.  Skip op_close so the backend handle stays alive (the
             * region holds its own mount+handle copies · the slot memset below
             * is harmless to those). */
            if (!e->lazy_pinned && e->mount && e->mount->ops->close) {
                rc = e->mount->ops->close(e->mount->backend_state, e->handle);
            }
            e->mount  = NULL;
            e->handle = NULL;
            e->cursor = 0;
            e->kind   = LUCAS_FD_INVALID;
            /* OBSD-ε OMALLOC · junk on free. */
            memset(&st->fds[fd], 0, sizeof(lucas_fd_t));
            return (int64_t)rc;
        case LUCAS_FD_SOCKET:
            lucas_socket_close_conn(st, fd);   /* N1 · δ-2 · release the real TCP conn */
            {                                  /* WINE-M1 · AF_UNIX rendezvous teardown */
                extern void lucas_unix_close_fd(lucas_state_t *, int);
                lucas_unix_close_fd(st, (int)fd);
            }
            e->kind  = LUCAS_FD_INVALID;
            e->flags = 0;
            /* OBSD-ε OMALLOC · junk on free. */
            memset(&st->fds[fd], 0, sizeof(lucas_fd_t));
            return 0;
        default:
            break;
    }
    /* Legacy path: is_std without kind set (pre-T4 sotBoxes). */
    if (e->is_std) {
        e->is_std = false;
        /* OBSD-ε OMALLOC · junk on free. */
        memset(&st->fds[fd], 0, sizeof(lucas_fd_t));
        return 0;
    }
    if (!e->mount) return -(int64_t)LX_EBADF;
    if (e->mount->ops->close) {
        rc = e->mount->ops->close(e->mount->backend_state, e->handle);
    }
    e->mount  = NULL;
    e->handle = NULL;
    e->cursor = 0;
    /* OBSD-ε OMALLOC · junk on free. */
    memset(&st->fds[fd], 0, sizeof(lucas_fd_t));
    return (int64_t)rc;
}

/* close_range(first, last, flags) — Linux 5.9+ (syscall 436).  apt's ExecFork()
 * (apt-pkg/contrib/fileutl.cc) closes inherited fds in the forked method-worker
 * child with `close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)` FIRST; only on -ENOSYS
 * does it fall back to a `for (k=3; k<sysconf(_SC_OPEN_MAX); k++) fcntl(F_SETFD)`
 * loop — and _SC_OPEN_MAX resolves to RLIMIT_NOFILE.rlim_cur (524288 here), so
 * the child issued ~524k fcntl fault round-trips and never reached execv → apt's
 * pkgAcquire worker timed out the `100 Capabilities` handshake and reported
 * "Method /usr/lib/apt/methods/http did not start correctly".  Implementing the
 * call (return 0, not ENOSYS) lets the child close fds in one syscall and proceed
 * straight to dup2+execv.  Our fd table is LUCAS_MAX_FDS slots; CLOSE_RANGE_CLOEXEC
 * (0x2) is a no-op in this ABI (FD_CLOEXEC is already a stub) so we honour the
 * plain-close semantics for the requested range and clamp to the table size. */
int64_t lucas_sys_close_range(lucas_state_t *st, uint64_t first, uint64_t last,
                              uint64_t flags, uint64_t _a3, uint64_t _a4,
                              uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;
    if (first > last) return -(int64_t)LX_EINVAL;
    /* CLOSE_RANGE_CLOEXEC (0x2): mark-cloexec rather than close.  FD_CLOEXEC is a
     * no-op in this ABI (fds don't survive execve image-replace except via dup2),
     * so just succeed — the fds will not leak across the imminent execv. */
    if (flags & 0x2u) return 0;
    uint64_t hi = (last >= LUCAS_MAX_FDS) ? (uint64_t)(LUCAS_MAX_FDS - 1) : last;
    for (uint64_t fd = first; fd <= hi; ++fd) {
        lucas_fd_t *e = &st->fds[fd];
        if (e->kind == LUCAS_FD_INVALID && !e->is_std) continue;  /* already closed */
        (void)lucas_sys_close(st, fd, 0, 0, 0, 0, 0);
    }
    return 0;
}

/* DOOM-DBG · write-path paddr watch.  Armed by lucas_verify_text_pages with the
 * REAL text-frame paddr (the chocodoom text page 0x54b000).  Every client-frame
 * WRITE site calls lucas_doom_watch_frame() with the frame cap it is about to
 * memcpy into + the client vaddr it thinks it is targeting.  A hit names the
 * exact call (and the vaddr) that physically clobbers the text frame — the
 * smoking gun for the chocodoom text-corruption.  Off until armed. */
uint64_t g_doom_watch_pa = 0;
int      g_doom_wp_on     = 0;
/* Victim-content probe · stash the doom box st so any orch code path can re-read
 * the text page 0x54b000 (→ cap 376 → paddr 0x3158000) and detect the exact
 * moment its content flips to the foreign mtio.h header ("#ifndef "). */
lucas_state_t *g_doom_st = NULL;
static int     g_doom_probe_done = 0;
/* file-scope VFS read bounce (used by sys_read) so the anomaly can mark it. */
uint8_t g_rd_bounce[4096];

/* ROUND 11 · reliable client-frame read (no dup_and_map window): cnode_copy the
 * frame cap → sel4utils_map_page to a fresh bumped orch vaddr (allocates PTs) →
 * read → explicit unmap. Ground truth, unlike copy_from_client. -1 on failure. */
int lucas_reliable_read(lucas_state_t *st, uintptr_t vaddr, void *buf, size_t n) {
    uintptr_t base = vaddr & ~0xFFFUL; size_t off = (size_t)(vaddr - base);
    if (off + n > 4096) n = 4096 - off;
    seL4_CPtr fc = vspace_get_cap(&st->client_vspace_abs, (void *)base);
    if (!fc) return -1;
    cspacepath_t src, dst;
    vka_cspace_make_path(st->vka, fc, &src);
    if (vka_cspace_alloc_path(st->vka, &dst) != 0) return -1;
    int rc = -1;
    if (seL4_CNode_Copy(dst.root, dst.capPtr, dst.capDepth,
                        src.root, src.capPtr, src.capDepth, seL4_AllRights) == seL4_NoError) {
        static uintptr_t va_bump = 0x2E000000UL;
        if (va_bump > 0x2FE00000UL) va_bump = 0x2E000000UL;   /* bounded window */
        void *va = (void *)va_bump; va_bump += 0x10000;
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS]; int np = VSPACE_MAP_PAGING_OBJECTS;
        if (sel4utils_map_page(st->vka, SEL4UTILS_PD_SLOT, dst.capPtr, va,
                               seL4_AllRights, 1, paging, &np) == 0) {
            memcpy(buf, (uint8_t *)va + off, n); rc = 0;
            seL4_X86_Page_Unmap(dst.capPtr);
        }
        seL4_CNode_Delete(dst.root, dst.capPtr, dst.capDepth);
    }
    vka_cspace_free(st->vka, dst.capPtr);
    return rc;
}

/* ROUND 10 · ANOMALY TEST. Write a unique marker into the orch staging buffer
 * `g_rd_bounce`, then read chocodoom's text frame (0x54b000 → cap 376 → paddr
 * 0x3158000). If the marker appears in the box frame, that buffer is PHYSICALLY
 * the box text frame → arena↔orch double-use CONFIRMED (a freshly-written marker
 * can only appear there if they share RAM — robust even to a stale-window read).
 * Read it BOTH ways: copy_from_client (the suspect tool) AND a reliable raw
 * Page_Map of a fresh cap copy to a dedicated orch vaddr + explicit unmap (no
 * window reuse) → also settles whether copy_from_client is reliable here. */
void lucas_doom_sentinel_probe(const char *tag) {
    if (!g_doom_st) { printf("[doom-sentinel] %s · g_doom_st NULL · skip\n", tag); return; }
    static const uint8_t SENT[8] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22};
    memcpy(g_rd_bounce, SENT, 8);   /* mark the sys_read bounce */

    /* (1) copy_from_client read of the box text page. */
    uint8_t a[8] = {0};
    int rc_a = lucas_copy_from_client(g_doom_st, 0x54b000UL, a, 8);

    /* (2) reliable read: copy cap376, map to a dedicated fresh vaddr, read, unmap. */
    uint8_t b[8] = {0}; int rc_b = -1; uint64_t pa = 0;
    seL4_CPtr fc = vspace_get_cap(&g_doom_st->client_vspace_abs, (void *)0x54b000UL);
    if (fc) {
        seL4_X86_Page_GetAddress_t r = seL4_X86_Page_GetAddress(fc);
        if (!r.error) pa = (uint64_t)r.paddr;
        cspacepath_t src, dst;
        vka_cspace_make_path(g_doom_st->vka, fc, &src);
        if (vka_cspace_alloc_path(g_doom_st->vka, &dst) == 0) {
            if (seL4_CNode_Copy(dst.root, dst.capPtr, dst.capDepth,
                                src.root, src.capPtr, src.capDepth, seL4_AllRights) == seL4_NoError) {
                /* fresh vaddr per call (avoids PT-reuse conflict); sel4utils_map_page
                 * allocates the intermediate page tables, then explicit unmap flushes. */
                static uintptr_t va_bump = 0x2E000000UL;
                void *va = (void *)va_bump; va_bump += 0x10000;
                vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS]; int np = VSPACE_MAP_PAGING_OBJECTS;
                if (sel4utils_map_page(g_doom_st->vka, SEL4UTILS_PD_SLOT, dst.capPtr, va,
                                       seL4_AllRights, 1, paging, &np) == 0) {
                    memcpy(b, va, 8); rc_b = 0;
                    seL4_X86_Page_Unmap(dst.capPtr);   /* flush this mapping */
                }
                seL4_CNode_Delete(dst.root, dst.capPtr, dst.capDepth);
            }
            vka_cspace_free(g_doom_st->vka, dst.capPtr);
        }
    }
    int hit_a = (rc_a==0 && memcmp(a, SENT, 8)==0);
    int hit_b = (rc_b==0 && memcmp(b, SENT, 8)==0);
    printf("[doom-sentinel] %s · cap=%lu paddr=0x%lx\n", tag, (unsigned long)fc, (unsigned long)pa);
    printf("[doom-sentinel]   copy_from_client(rc=%d): %02x%02x%02x%02x%02x%02x%02x%02x %s\n",
           rc_a,a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7], hit_a?"<<SENTINEL HIT":"");
    printf("[doom-sentinel]   reliable-rawmap(rc=%d): %02x%02x%02x%02x%02x%02x%02x%02x %s\n",
           rc_b,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7], hit_b?"<<SENTINEL HIT":"");
    if (hit_a || hit_b)
        printf("[doom-sentinel] %s · RESULT: bounce IS the box text frame → arena↔orch DOUBLE-USE CONFIRMED\n", tag);
    else if (rc_a==0 || rc_b==0)
        printf("[doom-sentinel] %s · RESULT: no overlap with bounce (box frame != g_rd_bounce)\n", tag);
    if (rc_a==0 && rc_b==0 && memcmp(a,b,8)!=0)
        printf("[doom-sentinel] %s · NOTE: copy_from_client != reliable-rawmap → copy_from_client IS UNRELIABLE here\n", tag);
}
void lucas_doom_watch_set(uint64_t pa) { g_doom_watch_pa = pa; g_doom_wp_on = (pa != 0); }
void lucas_doom_st_set(lucas_state_t *st) { g_doom_st = st; g_doom_probe_done = 0; }
int lucas_copy_from_client(lucas_state_t *st, uintptr_t client_vaddr, void *dst_buf, size_t size);
/* On a trip, print the cap# + its GetAddress paddr the abs-view resolves 0x54b000
 * to, so we can tell a real physical change of 0x3158000 from a stale-window
 * read or an abs-view↔real-PTE divergence. */
static void doom_trip_report(const char *tag, const uint8_t *cur) {
    seL4_CPtr c = vspace_get_cap(&g_doom_st->client_vspace_abs, (void *)0x54b000UL);
    uint64_t pa = 0;
    if (c) { seL4_X86_Page_GetAddress_t r = seL4_X86_Page_GetAddress(c);
             if (!r.error) pa = (uint64_t)r.paddr; }
    printf("[doom-dbg] PROBE-TRIP tag=%s · abs-view 0x54b000 → cap=%lu paddr=0x%lx · bytes %02x %02x %02x %02x %02x %02x %02x %02x\n",
           tag, (unsigned long)c, (unsigned long)pa,
           cur[0],cur[1],cur[2],cur[3],cur[4],cur[5],cur[6],cur[7]);
}
void lucas_doom_probe(const char *tag) {
    if (!g_doom_wp_on || !g_doom_st || g_doom_probe_done) return;
    uint8_t cur[8];
    if (lucas_copy_from_client(g_doom_st, 0x54b000UL, cur, 8) != 0) return;
    if (memcmp(cur, "#ifndef ", 8) == 0) {
        g_doom_probe_done = 1;
        doom_trip_report(tag, cur);
    }
}
void lucas_doom_probe_sys(unsigned long sysno, int pid) {
    if (!g_doom_wp_on || !g_doom_st || g_doom_probe_done) return;
    uint8_t cur[8];
    if (lucas_copy_from_client(g_doom_st, 0x54b000UL, cur, 8) != 0) return;
    if (memcmp(cur, "#ifndef ", 8) == 0) {
        g_doom_probe_done = 1;
        char t[48];
        /* tag carries syscall+pid */
        (void)pid;
        snprintf(t, sizeof(t), "syscall=%lu", sysno);
        doom_trip_report(t, cur);
    }
}
void lucas_doom_watch_frame(seL4_CPtr frame, uintptr_t client_vaddr, const char *tag) {
    if (!g_doom_wp_on || !frame) return;
    seL4_X86_Page_GetAddress_t r = seL4_X86_Page_GetAddress(frame);
    if (!r.error && (uint64_t)r.paddr == g_doom_watch_pa)
        printf("[doom-dbg] CLOBBER %s WRITE client_vaddr=0x%lx paddr=0x%lx (==text) frame=%lu\n",
               tag, (unsigned long)client_vaddr, (unsigned long)r.paddr,
               (unsigned long)frame);
}

/* Copy `size` bytes from the client's vspace at client_vaddr into the local
 * buffer dst_buf.  Returns 0 on success, -1 on EFAULT.  Walks page-by-page. */
int lucas_copy_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                            void *dst_buf, size_t size) {
    uint8_t *dst = (uint8_t *)dst_buf;
    size_t copied = 0;
    while (copied < size) {
        uintptr_t addr = client_vaddr + copied;
        uintptr_t page_base = addr & ~0xFFFUL;
        size_t off = (size_t)(addr - page_base);
        size_t in_page = 4096 - off;
        if (in_page > size - copied) in_page = size - copied;
        seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)page_base);
        if (!frame) return -1;
        void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                             frame, seL4_PageBits);
        if (!local) return -1;
        memcpy(dst + copied, (const uint8_t *)local + off, in_page);
        sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
        copied += in_page;
    }
    return 0;
}

/* Copy `size` bytes from local `src_buf` into the client's vspace at
 * client_vaddr.  Returns 0 on success, -1 on EFAULT.  Walks page-by-page. */
int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                         const void *src_buf, size_t size) {
    const uint8_t *src = src_buf;
    size_t copied = 0;
    while (copied < size) {
        uintptr_t addr = client_vaddr + copied;
        uintptr_t page_base = addr & ~0xFFFUL;
        size_t off = (size_t)(addr - page_base);
        size_t in_page = 4096 - off;
        if (in_page > size - copied) in_page = size - copied;
        seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)page_base);
        if (!frame) return -1;
        lucas_doom_watch_frame(frame, addr, "copy_to_client");
        void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                             frame, seL4_PageBits);
        if (!local) return -1;
        memcpy((uint8_t *)local + off, src + copied, in_page);
        sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
        copied += in_page;
    }
    return 0;
}

/* creat(path, mode) · the legacy create syscall (85) · GNU tar creates its
 * archive with it.  Equivalent to open(path, O_CREAT|O_WRONLY|O_TRUNC, mode). */
int64_t lucas_sys_creat(lucas_state_t *st, uint64_t path_vaddr, uint64_t mode,
                        uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    return lucas_sys_open(st, path_vaddr,
                          0x40 /*O_CREAT*/ | 0x1 /*O_WRONLY*/ | 0x200 /*O_TRUNC*/,
                          mode, 0, 0, 0);
}

static int64_t symlink_stat_fill(lucas_state_t *st, const char *path,
                                 uint64_t out_statbuf);   /* defined below */

/* MERGED-USR · Debian trixie (apt 3.0 / dpkg 1.22) REFUSES to operate on an
 * unmerged-usr system: apt's pkgDPkgPM stats /bin vs /usr/bin (also /sbin, /lib,
 * /lib64…) and, if the two directory inodes differ, aborts the unpack with
 * "/bin resolved to a different inode than /usr/bin · Unmerged usr is no longer
 * supported" — never exec'ing `dpkg --unpack`.  Our honey tree serves /bin from
 * the static backend and /usr/bin from the sysroot overlay (independent inode
 * spaces), so the pair can never collide naturally.  apt compares (st_dev,
 * st_ino), so the call sites pin BOTH a shared dev and this inode per merged
 * pair — exactly what a real /bin→usr/bin symlink yields under stat() — applied
 * centrally (after every backend stat) so stat/lstat/newfstatat/statx all agree.
 * Only the exact dir paths match (never files under them, so the sysroot's
 * per-library (dev,ino) dedup is untouched).  No recon tell: trixie IS
 * merged-usr.  Returns the canonical inode for a pair member, or 0. */
static uint64_t merged_usr_ino(const char *path) {
    if (!strcmp(path, "/bin")    || !strcmp(path, "/usr/bin"))    return 0x4D550001;
    if (!strcmp(path, "/sbin")   || !strcmp(path, "/usr/sbin"))   return 0x4D550002;
    if (!strcmp(path, "/lib")    || !strcmp(path, "/usr/lib"))    return 0x4D550003;
    if (!strcmp(path, "/lib32")  || !strcmp(path, "/usr/lib32"))  return 0x4D550004;
    if (!strcmp(path, "/lib64")  || !strcmp(path, "/usr/lib64"))  return 0x4D550005;
    if (!strcmp(path, "/libx32") || !strcmp(path, "/usr/libx32")) return 0x4D550006;
    return 0;
}

int64_t lucas_sys_stat(lucas_state_t *st, uint64_t path_vaddr,
                       uint64_t out_statbuf, uint64_t _a2, uint64_t _a3,
                       uint64_t _a4, uint64_t _a5) {
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    char rawpath[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, path_vaddr, rawpath, sizeof(rawpath)) < 0)
        return -(int64_t)LX_EFAULT;
    char path[LUCAS_PATH_MAX];
    lucas_resolve_path(st, rawpath, path, sizeof(path));   /* cwd + "."/".." → absolute */

    /* contained per-session symlink → S_IFLNK (lstat/`ls -l` fidelity). */
    int64_t sl = symlink_stat_fill(st, path, out_statbuf);
    if (sl != LUCAS_NOT_FDLINK) return sl;

    /* UNVEIL-CORE · stat requires UNVEIL_R · refuse if path is unveiled
     * but lacks read perms. */
    if (lucas_unveil_check(st, path, UNVEIL_R) < 0)
        return -(int64_t)LUCAS_EACCES_VAL;

    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m || !m->ops->stat) return -(int64_t)2;  /* -ENOENT */

    struct lx_stat sb;
    int rc = m->ops->stat(m->backend_state, suffix, &sb);
    if (rc < 0) return (int64_t)rc;
    { uint64_t mu = merged_usr_ino(path); if (mu) { sb.st_ino = mu; sb.st_dev = 0x4D55; } }

    return lucas_copy_to_client(st, out_statbuf, &sb, sizeof(sb))
            ? -(int64_t)LX_EFAULT : 0;
}

/* Linux-ABI · statx(dirfd, path, flags, mask, statxbuf).  Modern glibc/musl
 * coreutils (ls/stat/find) use statx; without it they fall back to fstatat,
 * and the strace shows `statx = -1 ENOSYS` — a honeypot tell.  Implement the
 * path-based AT_FDCWD case (the dominant one) by reusing the VFS stat and
 * translating lx_stat → struct statx.  The fd/AT_EMPTY_PATH case returns
 * ENOSYS so glibc cleanly falls back to fstat (which is handled). */
struct lx_statx_ts { int64_t tv_sec; uint32_t tv_nsec; int32_t __res; };
struct lx_statx {
    uint32_t stx_mask, stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink, stx_uid, stx_gid;
    uint16_t stx_mode; uint16_t __spare0[1];
    uint64_t stx_ino, stx_size, stx_blocks, stx_attributes_mask;
    struct lx_statx_ts stx_atime, stx_btime, stx_ctime, stx_mtime;
    uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
    uint64_t stx_mnt_id;
    uint64_t __spare2[13];
};
#ifndef LX_AT_FDCWD
#define LX_AT_FDCWD ((int64_t)-100)
#endif
#define LX_AT_EMPTY_PATH 0x1000
#define LX_STATX_BASIC_STATS 0x000007ffU

int64_t lucas_sys_statx(lucas_state_t *st, uint64_t dirfd, uint64_t path_vaddr,
                        uint64_t flags, uint64_t mask, uint64_t statxbuf,
                        uint64_t _a5) {
    (void)mask; (void)_a5;
    /* fd-relative / AT_EMPTY_PATH → ENOSYS so glibc falls back to fstat. */
    if ((int64_t)(int)dirfd != LX_AT_FDCWD || (flags & LX_AT_EMPTY_PATH))
        return -(int64_t)LX_ENOSYS;
    char rawpath[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, path_vaddr, rawpath, sizeof(rawpath)) < 0)
        return -(int64_t)LX_EFAULT;
    char path[LUCAS_PATH_MAX];
    lucas_resolve_path(st, rawpath, path, sizeof(path));
    if (lucas_unveil_check(st, path, UNVEIL_R) < 0)
        return -(int64_t)LUCAS_EACCES_VAL;
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m || !m->ops->stat) return -(int64_t)2;   /* -ENOENT */
    struct lx_stat sb;
    int rc = m->ops->stat(m->backend_state, suffix, &sb);
    if (rc < 0) return (int64_t)rc;
    { uint64_t mu = merged_usr_ino(path); if (mu) { sb.st_ino = mu; sb.st_dev = 0x4D55; } }

    struct lx_statx sx;
    memset(&sx, 0, sizeof(sx));
    sx.stx_mask    = LX_STATX_BASIC_STATS;
    sx.stx_blksize = (uint32_t)sb.st_blksize;
    sx.stx_nlink   = (uint32_t)sb.st_nlink;
    sx.stx_uid     = sb.st_uid;
    sx.stx_gid     = sb.st_gid;
    sx.stx_mode    = (uint16_t)sb.st_mode;
    sx.stx_ino     = sb.st_ino;
    sx.stx_size    = (uint64_t)sb.st_size;
    sx.stx_blocks  = (uint64_t)sb.st_blocks;
    sx.stx_atime.tv_sec = (int64_t)sb.st_atime; sx.stx_atime.tv_nsec = (uint32_t)sb.st_atime_nsec;
    sx.stx_mtime.tv_sec = (int64_t)sb.st_mtime; sx.stx_mtime.tv_nsec = (uint32_t)sb.st_mtime_nsec;
    sx.stx_ctime.tv_sec = (int64_t)sb.st_ctime; sx.stx_ctime.tv_nsec = (uint32_t)sb.st_ctime_nsec;
    sx.stx_btime   = sx.stx_mtime;
    return lucas_copy_to_client(st, statxbuf, &sx, sizeof(sx))
            ? -(int64_t)LX_EFAULT : 0;
}

int64_t lucas_sys_fstat(lucas_state_t *st, uint64_t fd, uint64_t out_statbuf,
                        uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    int64_t rc;
    struct lx_stat sb;
    memset(&sb, 0, sizeof(sb));
    if (fd >= LUCAS_MAX_FDS) { rc = -(int64_t)LX_EBADF; goto out; }
    lucas_fd_t *e = &st->fds[fd];
    switch (e->kind) {
        case LUCAS_FD_STDIO:
            sb.st_mode    = LX_S_IFCHR | 0666;
            sb.st_rdev    = 0x500 + fd;
            sb.st_blksize = 4096;
            sb.st_nlink   = 1;
            break;
        case LUCAS_FD_PIPE_READ:
        case LUCAS_FD_PIPE_WRITE:
            /* Appear as a FIFO to the client (not a tty). */
            sb.st_mode    = LX_S_IFIFO | 0666;
            sb.st_blksize = 4096;
            sb.st_nlink   = 1;
            break;
        case LUCAS_FD_VFS:
            if (e->mount && e->mount->ops->fstat) {
                int r = e->mount->ops->fstat(e->mount->backend_state, e->handle, &sb);
                if (r < 0) { rc = (int64_t)r; goto out; }
            } else {
                rc = -(int64_t)LX_EBADF;
                goto out;
            }
            break;
        default:
            /* Legacy is_std path. */
            if (e->is_std) {
                sb.st_mode    = LX_S_IFCHR | 0666;
                sb.st_rdev    = 0x500 + fd;
                sb.st_blksize = 4096;
                sb.st_nlink   = 1;
            } else if (e->mount && e->mount->ops->fstat) {
                int r = e->mount->ops->fstat(e->mount->backend_state, e->handle, &sb);
                if (r < 0) { rc = (int64_t)r; goto out; }
            } else {
                rc = -(int64_t)LX_EBADF;
                goto out;
            }
            break;
    }
    rc = lucas_copy_to_client(st, out_statbuf, &sb, sizeof(sb))
            ? -(int64_t)LX_EFAULT : 0;
out:
    LUCAS_FS_TRACE("fstat fd=%lu -> rc=%ld size=%ld",
                   (unsigned long)fd, (long)rc, (long)sb.st_size);
    return rc;
}

/* U7 · dirfd resolution helper.
 *
 * Validates dirfd against the spec for openat / newfstatat / etc.:
 *   - AT_FDCWD (-100) → cwd-relative (cwd is "/" in LUCAS) · returns 0
 *   - absolute path  → dirfd is ignored by POSIX · returns 0
 *   - fd is an open VFS handle on a directory → returns 0 (best-effort:
 *     we lack a per-fd path field so relative-path concat falls back to
 *     root, which matches LUCAS's flat namespace · still log it).
 *   - anything else → returns -LX_EBADF
 *
 * `pathname` may be NULL when only the dirfd is being validated
 * (e.g. future fchdir).  When non-NULL we use it only to detect the
 * absolute/relative case so callers can short-circuit.
 */
#ifndef LX_AT_FDCWD
#define LX_AT_FDCWD ((int64_t)-100)
#endif

static int64_t u7_validate_dirfd(lucas_state_t *st, int64_t dirfd,
                                  const char *pathname) {
    (void)st;
    if (dirfd == LX_AT_FDCWD) return 0;
    /* AT_FDCWD (-100) sometimes arrives ZERO-extended (0x00000000FFFFFF9C) from
     * glibc's *at wrappers (e.g. tar's fstatat(AT_FDCWD,".") to stat its
     * extraction dir → was a spurious -EBADF "Cannot stat: Bad file descriptor"
     * that aborted dpkg-deb --control).  Recognise it ONLY for the cwd-SELF
     * paths "."/".."/"" — arbitrary relative paths keep the int64 mismatch →
     * -EBADF, because making THEM resolve-from-cwd broke vim's relative config/
     * temp probes (vim's prior :w-window stopped exiting cleanly).  Absolute
     * paths are handled by the next check regardless of the extension. */
    if ((int32_t)dirfd == LX_AT_FDCWD && pathname &&
        (pathname[0] == '\0' ||
         (pathname[0] == '.' && (pathname[1] == '\0' ||
           (pathname[1] == '.' && pathname[2] == '\0')))))
        return 0;
    if (pathname && pathname[0] == '/') return 0;  /* absolute · dirfd ignored */
    /* Invalid fd range → -EBADF (POSIX). */
    if (dirfd < 0 || dirfd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;
    lucas_fd_t *e = &st->fds[dirfd];
    if (e->kind == LUCAS_FD_INVALID && !e->is_std) return -(int64_t)LX_EBADF;
    /* Open fd that is NOT a directory → -ENOTDIR (POSIX).  STDIO/pipes are
     * never directories; VFS fds need an fstat probe. */
    if (e->kind != LUCAS_FD_VFS || !e->mount) return -(int64_t)20; /* -ENOTDIR */
    if (e->mount->ops->fstat) {
        struct lx_stat sb;
        memset(&sb, 0, sizeof(sb));
        int rc = e->mount->ops->fstat(e->mount->backend_state, e->handle, &sb);
        if (rc < 0) return -(int64_t)LX_EBADF;
        if ((sb.st_mode & LX_S_IFMT) != LX_S_IFDIR) return -(int64_t)20; /* -ENOTDIR */
    }
    /* Valid directory fd · resolution against its stored path is done by
     * u7_resolve_at (below) for callers that need the actual path. */
    return 0;
}

/* dir-fd path resolution · resolve `pathname` relative to `dirfd` into an
 * absolute, normalized path in `out`.  This is what makes os.scandir / os.walk
 * (and the in-process wheel build) work: a real directory fd + a relative name
 * resolves against the fd's stored path, NOT against "/".  Returns 0 on success,
 * a negative -errno for a bad / non-directory dirfd. */
int64_t u7_resolve_at(lucas_state_t *st, int64_t dirfd,
                      const char *pathname, char *out, size_t outsz) {
    if (pathname && pathname[0] == '/') {            /* absolute · dirfd ignored */
        lucas_resolve_path(st, pathname, out, outsz);
        return 0;
    }
    if (dirfd == LX_AT_FDCWD || (int32_t)dirfd == LX_AT_FDCWD) {   /* cwd-relative */
        lucas_resolve_path(st, (pathname && pathname[0]) ? pathname : ".", out, outsz);
        return 0;
    }
    if (dirfd < 0 || dirfd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;
    lucas_fd_t *e = &st->fds[dirfd];
    if (e->kind != LUCAS_FD_VFS || !e->mount) return -(int64_t)20; /* -ENOTDIR */
    if (e->mount->ops->fstat) {
        struct lx_stat sb; memset(&sb, 0, sizeof(sb));
        if (e->mount->ops->fstat(e->mount->backend_state, e->handle, &sb) < 0)
            return -(int64_t)LX_EBADF;
        if ((sb.st_mode & LX_S_IFMT) != LX_S_IFDIR) return -(int64_t)20;
    }
    if (e->fd_path[0] == '\0') return -(int64_t)LX_EBADF;
    char joined[LUCAS_PATH_MAX * 2];
    if (!pathname || pathname[0] == '\0')
        snprintf(joined, sizeof(joined), "%s", e->fd_path);
    else
        snprintf(joined, sizeof(joined), "%s/%s", e->fd_path, pathname);
    lucas_resolve_path(st, joined, out, outsz);
    return 0;
}

/* stat an already-resolved absolute path (shared by lucas_sys_stat and the
 * dir-fd-aware *at handlers). */
/* Sentinel for "this path was not handled here" (shared by the symlink + proc-fd
 * helpers · INT64_MIN can't collide with a byte count or a -errno). */
#ifndef LUCAS_NOT_FDLINK
#define LUCAS_NOT_FDLINK INT64_MIN
#endif

/* If `path` names a contained per-session symlink, write an S_IFLNK stat
 * (size = target length, like real Linux) to the client and return 0/-EFAULT;
 * return LUCAS_NOT_FDLINK when it is not a symlink (caller stats normally).
 * Surfacing S_IFLNK is what makes `ls -l <link>` show "lrwxrwxrwx … -> tgt"
 * (busybox ls lstats then readlinks).  No following → no escape surface. */
static int64_t symlink_stat_fill(lucas_state_t *st, const char *path,
                                 uint64_t out_statbuf) {
    const char *tgt = lucas_symlink_get(st->cow_session, path);
    if (!tgt) return LUCAS_NOT_FDLINK;
    size_t tl = 0; while (tgt[tl]) tl++;
    struct lx_stat sb;
    memset(&sb, 0, sizeof(sb));
    sb.st_mode    = LX_S_IFLNK | 0777;
    sb.st_size    = (int64_t)tl;
    sb.st_nlink   = 1;
    sb.st_blksize = 4096;
    { int64_t s, n; lucas_now_realtime(&s, &n); (void)n;
      sb.st_mtime = (uint64_t)s; sb.st_atime = (uint64_t)s; sb.st_ctime = (uint64_t)s; }
    return lucas_copy_to_client(st, out_statbuf, &sb, sizeof(sb))
            ? -(int64_t)LX_EFAULT : 0;
}

static int64_t lucas_stat_path(lucas_state_t *st, const char *path,
                               uint64_t out_statbuf) {
    /* persona-coherence · glibc multiarch dir is hidden in the Alpine honey
     * session (musl persona).  ENOENT before any backend stat. */
    if (lucas_persona_hides(st, path)) return -(int64_t)2;
    int64_t sl = symlink_stat_fill(st, path, out_statbuf);
    if (sl != LUCAS_NOT_FDLINK) return sl;
    if (lucas_unveil_check(st, path, UNVEIL_R) < 0)
        return -(int64_t)LUCAS_EACCES_VAL;
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m || !m->ops->stat) return -(int64_t)2;  /* -ENOENT */
    struct lx_stat sb;
    int rc = m->ops->stat(m->backend_state, suffix, &sb);
    if (rc < 0) return (int64_t)rc;
    { uint64_t mu = merged_usr_ino(path); if (mu) { sb.st_ino = mu; sb.st_dev = 0x4D55; } }
    return lucas_copy_to_client(st, out_statbuf, &sb, sizeof(sb))
            ? -(int64_t)LX_EFAULT : 0;
}

/* newfstatat(dirfd, path, statbuf, flags).  dir-fd-aware:
 * - AT_EMPTY_PATH + empty path → fstat the dirfd itself.
 * - else resolve `path` against dirfd (AT_FDCWD/absolute/real-dir-fd) and stat
 *   the RESOLVED path · this is what os.scandir/os.walk's per-entry stat needs. */
int64_t lucas_sys_newfstatat(lucas_state_t *st, uint64_t dirfd, uint64_t path_vaddr,
                              uint64_t statbuf, uint64_t flags,
                              uint64_t _a4, uint64_t _a5) {
    (void)_a4; (void)_a5;
    char rawpath[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, path_vaddr, rawpath, sizeof(rawpath)) < 0)
        return -(int64_t)LX_EFAULT;
    if ((flags & LX_AT_EMPTY_PATH) && rawpath[0] == '\0')
        return lucas_sys_fstat(st, dirfd, statbuf, 0, 0, 0, 0);
    char resolved[LUCAS_PATH_MAX];
    int64_t rc = u7_resolve_at(st, (int64_t)dirfd, rawpath, resolved, sizeof(resolved));
    if (rc < 0) return rc;
    return lucas_stat_path(st, resolved, statbuf);
}

int64_t lucas_sys_lseek(lucas_state_t *st, uint64_t fd, uint64_t offset,
                        uint64_t whence, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;
    if (fd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;
    lucas_fd_t *e = &st->fds[fd];
    if (e->kind == LUCAS_FD_INVALID && !e->mount && !e->is_std)
        return -(int64_t)LX_EBADF;
    if (e->kind == LUCAS_FD_STDIO   || e->is_std)     return -(int64_t)29; /* -ESPIPE */
    if (e->kind == LUCAS_FD_PIPE_READ || e->kind == LUCAS_FD_PIPE_WRITE)
        return -(int64_t)29;  /* -ESPIPE */
    int64_t new_cursor;
    switch (whence) {
        case 0:  new_cursor = (int64_t)offset; break;             /* SEEK_SET */
        case 1:  new_cursor = e->cursor + (int64_t)offset; break;  /* SEEK_CUR */
        case 2: {                                                  /* SEEK_END · L9 */
            if (!e->mount || !e->mount->ops || !e->mount->ops->fstat)
                return -(int64_t)22;
            struct lx_stat sb;
            int rc = e->mount->ops->fstat(e->mount->backend_state, e->handle, &sb);
            if (rc < 0) return (int64_t)rc;
            new_cursor = (int64_t)sb.st_size + (int64_t)offset;
            break;
        }
        default: return -(int64_t)22;                              /* -EINVAL */
    }
    if (new_cursor < 0) return -(int64_t)22;
    e->cursor = new_cursor;
    return new_cursor;
}

int64_t lucas_sys_getdents64(lucas_state_t *st, uint64_t fd, uint64_t dirp_vaddr,
                              uint64_t count, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;
    if (fd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;
    lucas_fd_t *e = &st->fds[fd];
    if (!e->mount || !e->mount->ops->getdents) return -(int64_t)LX_EBADF;

    /* Allocate a local bounded buffer · 2 KiB is enough for most dir
     * snapshots; client may need multiple syscalls if the dir is huge. */
    static uint8_t local[2048];
    size_t local_count = count < sizeof(local) ? count : sizeof(local);

    int64_t got = e->mount->ops->getdents(e->mount->backend_state,
                                           e->handle, local,
                                           local_count, &e->cursor);
    if (got < 0) return got;
    if (got == 0) return 0;

    if (lucas_copy_to_client(st, dirp_vaddr, local, (size_t)got))
        return -(int64_t)LX_EFAULT;
    return got;
}

int64_t lucas_sys_access(lucas_state_t *st, uint64_t path_vaddr,
                         uint64_t mode, uint64_t _a2, uint64_t _a3,
                         uint64_t _a4, uint64_t _a5) {
    (void)mode; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    char rawpath[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, path_vaddr, rawpath, sizeof(rawpath)) < 0)
        return -(int64_t)LX_EFAULT;
    char path[LUCAS_PATH_MAX];
    lucas_resolve_path(st, rawpath, path, sizeof(path));   /* cwd + "."/".." → absolute */
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m || !m->ops->stat) return -(int64_t)2;
    struct lx_stat sb;
    int rc = m->ops->stat(m->backend_state, suffix, &sb);
    if (rc < 0) return (int64_t)rc;
    return 0;
}

/* Resolve a /proc/self/fd/<n> (or /proc/<pid>/fd/<n>) magic link to the path the
 * fd was opened with.  musl's realpath() opens the target O_PATH then readlinks
 * that fd link to canonicalize it — so without this, `realpath`/coreutils -e and
 * anything using realpath(3) on a regular file fail with EINVAL.  Returns the
 * resolved length copied to the client (>=0), a negative -errno, or the sentinel
 * LUCAS_NOT_FDLINK when `path` is not an fd link (caller continues normally). */
static int64_t readlink_proc_fd(lucas_state_t *st, const char *path,
                                uint64_t buf_vaddr, uint64_t bufsiz) {
    /* ONLY the caller's own magic fd dir — musl realpath uses /proc/self/fd/N.
     * A /proc/<other-pid>/fd/N (the synthetic process table's socket links) must
     * fall through to the proc backend, NOT be resolved against this guest's fds. */
    if (strncmp(path, "/proc/self/fd/", 14) != 0 &&
        strncmp(path, "/proc/thread-self/fd/", 21) != 0) return LUCAS_NOT_FDLINK;
    const char *fdmark = strstr(path, "/fd/");
    if (!fdmark) return LUCAS_NOT_FDLINK;
    const char *digits = fdmark + 4;   /* past "/fd/" */
    if (!*digits) return -(int64_t)LX_EINVAL;
    int n = 0;
    for (const char *c = digits; *c; ++c) {
        if (*c < '0' || *c > '9') return -(int64_t)LX_EINVAL;
        n = n * 10 + (*c - '0');
    }
    if (n < 0 || n >= LUCAS_MAX_FDS ||
        st->fds[n].kind == LUCAS_FD_INVALID || !st->fds[n].fd_path[0])
        return -(int64_t)LX_EINVAL;
    size_t fl = 0; while (st->fds[n].fd_path[fl]) fl++;
    size_t out = (bufsiz < fl) ? (size_t)bufsiz : fl;
    if (out && lucas_copy_to_client(st, buf_vaddr, st->fds[n].fd_path, out) != 0)
        return -(int64_t)LX_EFAULT;
    return (int64_t)out;
}

int64_t lucas_sys_readlink(lucas_state_t *st, uint64_t path_vaddr,
                           uint64_t buf_vaddr, uint64_t size,
                           uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;
    char rawpath[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, path_vaddr, rawpath, sizeof(rawpath)) < 0)
        return -(int64_t)LX_EFAULT;
    /* Canonicalize "."/".." (lexically · the final component, a potential link, is
     * NOT followed) BEFORE resolving — like open does.  musl's realpath readlinks
     * every accumulated prefix INCLUDING ones with ".." (e.g. "/usr/bin/..") and
     * needs EINVAL ("a dir, not a link"); without collapsing, the sysroot find()
     * sees "bin/.." → ENOENT and realpath aborts (Wine ntdll's self-path is
     * /usr/bin/../lib/wine/...). */
    char path[LUCAS_PATH_MAX];
    lucas_resolve_path(st, rawpath, path, sizeof(path));
    int64_t fdr = readlink_proc_fd(st, path, buf_vaddr, size);
    if (fdr != LUCAS_NOT_FDLINK) return fdr;
    /* Contained per-session symlinks (attacker `ln -s` in /tmp) · return the
     * stored target verbatim so `readlink`/`ls -l` behave like real Linux. */
    const char *sl_tgt = lucas_symlink_get(st->cow_session, path);
    if (sl_tgt) {
        size_t tl = 0; while (sl_tgt[tl]) tl++;
        size_t out = (size < tl) ? (size_t)size : tl;
        if (out && lucas_copy_to_client(st, buf_vaddr, sl_tgt, out))
            return -(int64_t)LX_EFAULT;
        return (int64_t)out;
    }
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m || !m->ops->readlink) return -(int64_t)22;
    char local[256];
    int got = m->ops->readlink(m->backend_state, suffix, local,
                                (size < sizeof(local) ? size : sizeof(local)));
    if (got < 0) return (int64_t)got;
    if (lucas_copy_to_client(st, buf_vaddr, local, (size_t)got))
        return -(int64_t)LX_EFAULT;
    return got;
}

/* L11-α-4 · readlinkat stub.  CPython hello-world probes /proc/self/exe to
 * populate sys.executable.  Resolve that one path synthetically; reject the
 * rest with -EINVAL (busybox / musl tolerate this on non-symlink paths).
 * dirfd is ignored · we treat the path as absolute. */
int64_t lucas_sys_readlinkat(lucas_state_t *st,
                              uint64_t dirfd, uint64_t path_vaddr,
                              uint64_t buf_vaddr, uint64_t bufsiz,
                              uint64_t _a4, uint64_t _a5) {
    (void)dirfd; (void)_a4; (void)_a5;
    char path[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, path_vaddr, path, sizeof(path)) < 0)
        return -(int64_t)LX_EFAULT;

    size_t plen = 0; while (plen < sizeof(path) && path[plen]) plen++;

    /* /proc/self/fd/<n> (or /proc/<pid>/fd/<n>) · musl's realpath() opens the
     * target with O_PATH and readlinks the magic fd link to canonicalize it. */
    int64_t fdr = readlink_proc_fd(st, path, buf_vaddr, bufsiz);
    if (fdr != LUCAS_NOT_FDLINK) return fdr;

    int is_proc_exe = (strstr(path, "/proc/self/exe") != NULL) ||
                      (plen >= 4 && strcmp(path + plen - 4, "/exe") == 0);
    if (!is_proc_exe) return -(int64_t)LX_EINVAL;

    /* Wine M1 · /proc/self/exe MUST route through the proc backend's op_readlink
     * (the per-sotbox exe_path for a TRUSTED compat guest — e.g. the wine loader
     * needs /usr/bin/wine to derive its dll dir — else the /bin/busybox deception
     * default).  musl's readlink() lowers to readlinkat(), so this stub previously
     * shadowed the readlink path with a hardcoded value → wine got the wrong exe
     * path → "cannot get path to ntdll.so".  Keep the /sotbox/python synthetic as
     * a fallback only when the backend can't answer (preserves CPython). */
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, "/proc/self/exe", &suffix);
    if (m && m->ops && m->ops->readlink) {
        char local[256];
        int got = m->ops->readlink(m->backend_state, suffix, local,
                                   (bufsiz < sizeof(local) ? bufsiz : sizeof(local)));
        if (got > 0) {
            if (lucas_copy_to_client(st, buf_vaddr, local, (size_t)got) != 0)
                return -(int64_t)LX_EFAULT;
            printf("[lucas] readlinkat(\"%s\") → \"%.*s\" (%d)\n", path, got, local, got);
            return (int64_t)got;
        }
    }
    static const char synth[] = "/sotbox/python";   /* fallback · CPython sys.executable */
    const size_t synth_len = sizeof(synth) - 1;
    size_t out_len = (bufsiz < synth_len) ? (size_t)bufsiz : synth_len;
    if (out_len == 0) return 0;
    if (lucas_copy_to_client(st, buf_vaddr, synth, out_len) != 0)
        return -(int64_t)LX_EFAULT;
    printf("[lucas] readlinkat(\"%s\") → \"%.*s\" (%zu · fallback)\n",
           path, (int)out_len, synth, out_len);
    return (int64_t)out_len;
}

/* === L10: openat · open with dirfd ======================================== */

/* openat(dirfd, path, flags, mode): vi uses this to open its edit file.
 *
 * U7 · dirfd-aware:
 *  - dirfd == AT_FDCWD (-100): existing behavior · forward to open().
 *  - pathname is absolute ("/..."): POSIX says dirfd is ignored · forward.
 *  - dirfd is an open VFS directory fd: validate, then forward.  LUCAS
 *    has no per-fd path slot so the path is resolved from "/" (same as
 *    AT_FDCWD); a [openat] log line marks the case for the operator.
 *  - dirfd is not a directory or is invalid: -EBADF.
 */
int64_t lucas_sys_openat(lucas_state_t *st, uint64_t dirfd, uint64_t path_vaddr,
                          uint64_t flags, uint64_t mode,
                          uint64_t _a4, uint64_t _a5) {
    (void)_a4; (void)_a5;
    char path[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, path_vaddr, path, sizeof(path)) < 0) {
        LUCAS_FS_TRACE("openat dirfd=%ld path=<EFAULT> -> %ld",
                       (long)(int64_t)dirfd, (long)-(int64_t)LX_EFAULT);
        return -(int64_t)LX_EFAULT;
    }
    /* UNVEIL-CORE · gate openat by path/flags before any dirfd validation.
     * lucas_sys_open repeats the check after the path is re-copied; both
     * paths converge on the same result via the same backing entries. */
    {
        uint64_t accmode = flags & LUCAS_O_ACCMODE;
        uint32_t want = (accmode == 0) ? UNVEIL_R
                      : (accmode == 1) ? UNVEIL_W
                                       : (uint32_t)(UNVEIL_R | UNVEIL_W);
        if (lucas_unveil_check(st, path, want) < 0) {
            LUCAS_FS_TRACE("openat dirfd=%ld path=%s -> -EACCES (unveil)",
                           (long)(int64_t)dirfd, path);
            return -(int64_t)LUCAS_EACCES_VAL;
        }
    }
    /* dir-fd-aware · for a real directory fd + relative name, resolve against the
     * fd's path and hand the absolute result to lucas_sys_open via the one-shot
     * override.  AT_FDCWD / absolute paths fall through to the normal cwd resolve.
     * os.scandir(name, dir_fd=…) / os.walk / shutil.rmtree need this. */
    int64_t rc;
    bool real_dirfd = ((int32_t)(int64_t)dirfd != LX_AT_FDCWD) &&
                      !(path[0] == '/') && (int64_t)dirfd != LX_AT_FDCWD;
    if (real_dirfd) {
        static char g_openat_resolved[LUCAS_PATH_MAX];
        int64_t r = u7_resolve_at(st, (int64_t)dirfd, path, g_openat_resolved,
                                  sizeof(g_openat_resolved));
        if (r < 0) {
            LUCAS_FS_TRACE("openat dirfd=%ld path=%s -> %ld", (long)(int64_t)dirfd, path, (long)r);
            return r;
        }
        g_open_path_override = g_openat_resolved;
    } else {
        int64_t vrc = u7_validate_dirfd(st, (int64_t)dirfd, path);
        if (vrc < 0) {
            LUCAS_FS_TRACE("openat dirfd=%ld path=%s -> %ld", (long)(int64_t)dirfd, path, (long)vrc);
            return vrc;
        }
    }
    rc = lucas_sys_open(st, path_vaddr, flags, mode, 0, 0, 0);
    LUCAS_FS_TRACE("openat dirfd=%ld path=%s -> %ld",
                   (long)(int64_t)dirfd, path, (long)rc);
    return rc;
}

/* === Spec A · unlink(87) · delete a file by path ========================== */

extern int lucas_sotfs_unlink(const char *path);

/* unlink(path): copy the path from the client vspace and route to the sotfs
 * backend, which WAL-logs the deletion by parent_id+name (replay-stable like
 * create_file) so the removal survives simreboot.  The [vfs] log line makes
 * the /tmp→root path-namespace mapping explicit. */
int64_t lucas_sys_unlink(lucas_state_t *st, uint64_t path_vaddr,
                         uint64_t _a1, uint64_t _a2, uint64_t _a3,
                         uint64_t _a4, uint64_t _a5)
{
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    char raw[LUCAS_PATH_MAX], path[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, (uintptr_t)path_vaddr,
                                    raw, sizeof(raw)) < 0)
        return -(int64_t)LX_EFAULT;
    /* Resolve relative + "."/".." against the process cwd, exactly like
     * open/mkdir/rename do.  unlink was the lone op taking the raw client
     * string, so a relative unlink (git's `.git/AUTO_MERGE` pseudo-ref cleanup)
     * reached the backend unresolved → split_path failed → -EINVAL.  git
     * tolerates it but it's a real fidelity bug for any relative-path unlink. */
    lucas_resolve_path(st, raw, path, sizeof(path));
    printf("[vfs] unlink %s\n", path);
    /* Route through the VFS: resolve the mount + suffix (like open), then call
     * the mount's unlink op.  A NULL op == read-only mount → -EROFS.  /tmp's
     * sotfs op preserves the prior hardcoded behavior exactly. */
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m) return -(int64_t)2;            /* -ENOENT */
    if (!m->ops->unlink) return -(int64_t)LX_EROFS;
    int rc = m->ops->unlink(m->backend_state, suffix);
    if (rc != 0) return (int64_t)rc;
    /* Spec B · unlink suspicion.  Forward EV_UNLINK with bit0 set when
     * the deleted path is credential/canary (weighs higher · mass-delete
     * of decoys is a strong ransomware tell).  Burst escalation is
     * computed anomaly-side. */
    {
        uint64_t flag = sotos_path_is_cred_sensitive(path) ? 1u : 0u;
        int target = anomaly_forward_sync(st, ANOMALY_EV_UNLINK, flag);
        if (target > 0) anomaly_apply_reply_tier(st, target);
    }
    return 0;
}

extern int lucas_sotfs_rmdir(const char *path);

/* unlinkat(dirfd, path, flags): the *at variant of unlink.  sotOs has a single
 * /tmp-rooted namespace, so only AT_FDCWD (cwd-relative · cwd is "/") is
 * meaningful; any other dirfd returns -EBADF (dirfd-relative paths are a future
 * extension).  Routed through the VFS like lucas_sys_unlink: AT_REMOVEDIR ->
 * m->ops->rmdir (directory removal), otherwise -> m->ops->unlink (file
 * removal), so non-/tmp writable mounts (dpkg's /usr,/var) reach the right
 * backend.  LX_AT_FDCWD is already defined above for the openat/newfstatat
 * dirfd validators. */
#ifndef LX_AT_REMOVEDIR
#define LX_AT_REMOVEDIR 0x200
#endif

int64_t lucas_sys_unlinkat(lucas_state_t *st, uint64_t dirfd, uint64_t path_vaddr,
                           uint64_t flags, uint64_t _a3, uint64_t _a4, uint64_t _a5)
{
    (void)_a3; (void)_a4; (void)_a5;
    char raw[LUCAS_PATH_MAX], path[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, (uintptr_t)path_vaddr,
                                    raw, sizeof(raw)) < 0)
        return -(int64_t)LX_EFAULT;
    /* dir-fd-aware · resolve `raw` against AT_FDCWD / absolute / a real directory
     * fd (the in-process wheel build removes staging files via unlinkat(dirfd,…)).
     * dpkg/git route unlink+rmdir through unlinkat too. */
    int64_t rrc = u7_resolve_at(st, (int64_t)dirfd, raw, path, sizeof(path));
    if (rrc < 0) return rrc;
    /* Route through the VFS the same way lucas_sys_unlink does: resolve the
     * mount + suffix, then call the mount's op.  AT_REMOVEDIR dispatches to
     * ->rmdir (dir removal · NOTEMPTY-aware), the file case to ->unlink.  A
     * NULL op == read-only mount → -EROFS; no mount → -ENOENT.  /tmp's sotfs
     * ops preserve the prior hardcoded behavior exactly (incl. the Tier-2
     * isolated-write deception guard inside lucas_sotfs_{unlink,rmdir}). */
    const char *suffix;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m) return -(int64_t)2;            /* -ENOENT */
    if (flags & LX_AT_REMOVEDIR) {
        printf("[vfs] unlinkat(rmdir) %s\n", path);
        if (!m->ops->rmdir) return -(int64_t)LX_EROFS;
        int rc = m->ops->rmdir(m->backend_state, suffix);
        return (rc == 0) ? 0 : (int64_t)rc;
    }
    printf("[vfs] unlinkat %s\n", path);
    if (!m->ops->unlink) return -(int64_t)LX_EROFS;
    int rc = m->ops->unlink(m->backend_state, suffix);
    if (rc != 0) return (int64_t)rc;
    /* Spec B · unlink suspicion.  Forward EV_UNLINK with bit0 set when
     * the deleted path is credential/canary (weighs higher · mass-delete
     * of decoys is a strong ransomware tell).  Burst escalation is
     * computed anomaly-side. */
    {
        uint64_t flag = sotos_path_is_cred_sensitive(path) ? 1u : 0u;
        int target = anomaly_forward_sync(st, ANOMALY_EV_UNLINK, flag);
        if (target > 0) anomaly_apply_reply_tier(st, target);
    }
    return 0;
}

/* === L10: pread64 · positional read ======================================= */

/* pread64(fd, buf, count, offset): vi reads file content at a specific offset.
 * We implement by saving/restoring the cursor around a regular read. */
int64_t lucas_sys_pread64(lucas_state_t *st, uint64_t fd, uint64_t buf_vaddr,
                           uint64_t count, uint64_t offset,
                           uint64_t _a4, uint64_t _a5) {
    (void)_a4; (void)_a5;
    if (fd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;
    lucas_fd_t *e = &st->fds[fd];
    /* Save, seek, read, restore. */
    int64_t saved = e->cursor;
    e->cursor = (int64_t)offset;
    int64_t n = lucas_sys_read(st, fd, buf_vaddr, count, 0, 0, 0);
    /* Restore cursor only if read failed (on success cursor already advanced). */
    if (n < 0) e->cursor = saved;
    return n;
}

/* pwrite64(fd, buf, count, offset) · sysno 18.  WINE-M1: wineserver extends its
 * shared-memory temp file (tmpmap-*) by pwrite'ing at offset size-1, then mmaps
 * it; without this the write hit ENOSYS → "file_set_error: Function not
 * implemented" → NULL deref.  POSIX: pwrite does NOT move the file offset, so we
 * save/seek/write/restore unconditionally (unlike pread64's model). */
int64_t lucas_sys_pwrite64(lucas_state_t *st, uint64_t fd, uint64_t buf_vaddr,
                            uint64_t count, uint64_t offset,
                            uint64_t _a4, uint64_t _a5) {
    (void)_a4; (void)_a5;
    if (fd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;
    lucas_fd_t *e = &st->fds[fd];
    int64_t saved = e->cursor;
    e->cursor = (int64_t)offset;
    int64_t n = lucas_sys_write(st, fd, buf_vaddr, count, 0, 0, 0);
    e->cursor = saved;   /* pwrite leaves the file offset unchanged */
    return n;
}

/* === WINE-M1 · fcntl advisory record locks (F_SETLK/F_GETLK) ============ */
/*
 * wine's per-prefix server election uses an fcntl write lock on the "lock"
 * file as its liveness token: the running wineserver holds F_WRLCK on it for
 * its whole life; a launching wine F_GETLK's to see if a server owns the
 * prefix (holder present → connect to it; free → the server it started failed).
 * The old no-op stub (always-grant F_SETLK, F_GETLK leaving *arg garbage) made
 * wine see a phantom holder with a bogus pid and bail.  This is a minimal but
 * REAL cross-process arbiter: all sotbox syscalls run in orch's address space,
 * so one process-global table suffices.  Keyed by the sotfs INODE of the lock
 * file (the single shared graph → wine and wineserver opening the same path
 * resolve to the same inode), so it is stable across address spaces.  Byte
 * ranges are ignored (wine locks byte [0,1) only); whole-file granularity. */
#define LUCAS_MAX_RECLOCKS 16
typedef struct {
    int      in_use;
    int      inode;          /* sotfs inode id of the locked file */
    int      owner_synth;    /* st->synthetic_pid that holds it (release key) */
    uint32_t owner_display;  /* st->display_pid (reported as F_GETLK l_pid) */
} lucas_reclock_t;
static lucas_reclock_t g_reclocks[LUCAS_MAX_RECLOCKS];

/* sotfs inode of a VFS-backed fd (cross-process key), or -1 if the fd is not a
 * real lockable VFS file (stdio/pipe/socket → caller keeps the benign stub). */
static int reclock_inode_of(lucas_state_t *st, uint64_t fd) {
    if (fd >= LUCAS_MAX_FDS) return -1;
    lucas_fd_t *e = &st->fds[fd];
    if (e->kind != LUCAS_FD_VFS || !e->mount || !e->mount->ops ||
        !e->mount->ops->fstat || !e->handle)
        return -1;
    struct lx_stat sb;
    if (e->mount->ops->fstat(e->mount->backend_state, e->handle, &sb) != 0) return -1;
    return (int)sb.st_ino;
}

/* Drop every record lock held by `synth_pid` (called on close of a locked fd
 * and on process exit — the wineserver-liveness release: server dies → its
 * F_WRLCK frees → next wine becomes the starter). */
void lucas_reclock_release_owner(int synth_pid) {
    for (int i = 0; i < LUCAS_MAX_RECLOCKS; ++i)
        if (g_reclocks[i].in_use && g_reclocks[i].owner_synth == synth_pid)
            memset(&g_reclocks[i], 0, sizeof(g_reclocks[i]));
}

/* POSIX · closing ANY fd referring to a file releases ALL record locks the
 * process holds on that file.  apt's pkgDPkgPM::Go releases the dpkg DB lock
 * this way (UnLockInner → close(lock_fd), no explicit F_UNLCK) right before it
 * forks dpkg, so dpkg can acquire /var/lib/dpkg/lock; without releasing on
 * close, apt's stale lock made dpkg fail "dpkg database lock was locked by
 * <unknown> process". */
static void lucas_reclock_release_inode(int synth_pid, int inode) {
    if (inode < 0) return;
    for (int i = 0; i < LUCAS_MAX_RECLOCKS; ++i)
        if (g_reclocks[i].in_use && g_reclocks[i].owner_synth == synth_pid &&
            g_reclocks[i].inode == inode)
            memset(&g_reclocks[i], 0, sizeof(g_reclocks[i]));
}

/* === L2 fcntl stub ====================================================== */

int64_t lucas_sys_fcntl(lucas_state_t *st, uint64_t fd, uint64_t cmd,
                        uint64_t arg, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;
    if (fd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;
    lucas_fd_t *e = &st->fds[fd];
    if (e->kind == LUCAS_FD_INVALID && !e->mount && !e->is_std) return -(int64_t)LX_EBADF;
    #ifndef LX_O_CLOEXEC
    #define LX_O_CLOEXEC 02000000   /* O_CLOEXEC · x86_64 Linux */
    #endif
    #define LX_FD_CLOEXEC 1
    switch (cmd) {
        case 1:  /* F_GETFD · report FD_CLOEXEC from the tracked O_CLOEXEC bit */
            return (e->flags & LX_O_CLOEXEC) ? LX_FD_CLOEXEC : 0;
        case 2:  /* F_SETFD · honor FD_CLOEXEC (so execve closes this fd).  apt's
                  * http/dpkg method fork relies on this: without it the method
                  * inherits apt's cache/lists/status fds and ld.so EMFILEs (24)
                  * loading its lib closure (libsystemd.so.0 et al). */
            if (arg & LX_FD_CLOEXEC) e->flags |= LX_O_CLOEXEC;
            else                     e->flags &= ~LX_O_CLOEXEC;
            return 0;
        case 3:  /* F_GETFL */
            return e->flags;
        case 4:  /* F_SETFL */
            e->flags = (int)arg;
            return 0;
        case 0:    /* F_DUPFD          · arg = min fd */
        case 1030: /* F_DUPFD_CLOEXEC  · arg = min fd, set CLOEXEC */
        {
            int min_fd = (int)arg;
            if (min_fd < 0 || min_fd >= LUCAS_MAX_FDS) return -(int64_t)LX_EINVAL;
            int newfd = -1;
            for (int i = min_fd; i < LUCAS_MAX_FDS; ++i) {
                if (st->fds[i].kind == LUCAS_FD_INVALID && !st->fds[i].is_std) {
                    newfd = i;
                    break;
                }
            }
            if (newfd < 0) return -(int64_t)24;  /* -EMFILE */
            /* Re-fetch source pointer (st->fds may have been written above). */
            lucas_fd_t *src = &st->fds[fd];
            lucas_fd_t *dst = &st->fds[newfd];
            *dst = *src;
            /* Bump pipe refcount so a future close on dst is symmetric. */
            if (src->kind == LUCAS_FD_PIPE_READ && src->pipe) {
                lucas_pipe_add_reader(src->pipe);
            } else if (src->kind == LUCAS_FD_PIPE_WRITE && src->pipe) {
                lucas_pipe_add_writer(src->pipe);
            } else if (src->kind == LUCAS_FD_VFS && src->mount &&
                       src->mount->ops->dup_handle && src->handle) {
                /* Give the dup its OWN backend handle (same open file) so closing
                 * one fd doesn't dangle the other — see lucas_sys_dup2. */
                void *nh = src->mount->ops->dup_handle(src->mount->backend_state, src->handle);
                if (nh) dst->handle = nh;
            }
            /* F_DUPFD sets CLOEXEC OFF on the dup (POSIX); F_DUPFD_CLOEXEC sets
             * it ON.  Now that execve honors O_CLOEXEC, track it on the new fd. */
            if (cmd == 1030) dst->flags |= LX_O_CLOEXEC;
            else             dst->flags &= ~LX_O_CLOEXEC;
            printf("[fcntl] F_DUPFD%s fd=%lu min=%d → newfd=%d\n",
                   (cmd == 1030) ? "_CLOEXEC" : "",
                   (unsigned long)fd, min_fd, newfd);
            return (int64_t)newfd;
        }
        case 5: {  /* F_GETLK · advisory lock query · report the real holder */
            /* struct flock x86-64: l_type@0 (short), l_whence@2, l_start@8,
             * l_len@16, l_pid@24 (int); 32 bytes.  The old stub returned 0
             * WITHOUT writing *arg → wine read garbage l_type (phantom holder)
             * + garbage l_pid (0x404A0000) and bailed.  Now report the real
             * record-lock state so wine's server-liveness check is coherent:
             * another owner holds it → l_type=F_WRLCK + l_pid=holder display_pid
             * ("server running, connect to it"); free → l_type=F_UNLCK. */
            uint8_t fl[32];
            if (!arg || lucas_copy_from_client(st, (uintptr_t)arg, fl, sizeof(fl)) != 0)
                return 0;  /* unreadable flock · benign (matches old stub) */
            int ino = reclock_inode_of(st, fd);
            lucas_reclock_t *h = NULL;
            if (ino >= 0)
                for (int i = 0; i < LUCAS_MAX_RECLOCKS; ++i)
                    if (g_reclocks[i].in_use && g_reclocks[i].inode == ino &&
                        g_reclocks[i].owner_synth != st->synthetic_pid) { h = &g_reclocks[i]; break; }
            if (h) {
                fl[0] = 1; fl[1] = 0;                  /* l_type = F_WRLCK */
                uint32_t p = h->owner_display;
                fl[24] = p & 0xff; fl[25] = (p >> 8) & 0xff;
                fl[26] = (p >> 16) & 0xff; fl[27] = (p >> 24) & 0xff;
            } else {
                fl[0] = 2; fl[1] = 0;                  /* l_type = F_UNLCK */
                fl[24] = fl[25] = fl[26] = fl[27] = 0;
            }
            (void)lucas_copy_to_client(st, (uintptr_t)arg, fl, sizeof(fl));
            printf("[fcntl] F_GETLK fd=%lu ino=%d -> %s%s\n", (unsigned long)fd, ino,
                   h ? "WRLCK held by pid=" : "UNLCK", h ? "" : "");
            return 0;
        }
        case 6:    /* F_SETLK  · acquire/release advisory record lock */
        case 7: {  /* F_SETLKW · blocking variant · treated non-blocking here */
            int ino = reclock_inode_of(st, fd);
            if (ino < 0) {   /* non-VFS fd (stdio/pipe) · keep the benign grant */
                printf("[fcntl] F_SETLK%s fd=%lu · stub OK (non-VFS)\n",
                       (cmd == 7) ? "W" : "", (unsigned long)fd);
                return 0;
            }
            uint8_t fl[32];
            if (!arg || lucas_copy_from_client(st, (uintptr_t)arg, fl, sizeof(fl)) != 0)
                return 0;
            short ltype = (short)((uint16_t)fl[0] | ((uint16_t)fl[1] << 8));
            if (ltype == 2 /*F_UNLCK*/) {              /* release this owner's lock */
                for (int i = 0; i < LUCAS_MAX_RECLOCKS; ++i)
                    if (g_reclocks[i].in_use && g_reclocks[i].inode == ino &&
                        g_reclocks[i].owner_synth == st->synthetic_pid)
                        memset(&g_reclocks[i], 0, sizeof(g_reclocks[i]));
                printf("[fcntl] F_SETLK UNLCK fd=%lu ino=%d · released\n", (unsigned long)fd, ino);
                return 0;
            }
            /* F_WRLCK/F_RDLCK acquire · conflict iff another owner holds this inode. */
            for (int i = 0; i < LUCAS_MAX_RECLOCKS; ++i)
                if (g_reclocks[i].in_use && g_reclocks[i].inode == ino &&
                    g_reclocks[i].owner_synth != st->synthetic_pid) {
                    printf("[fcntl] F_SETLK%s fd=%lu ino=%d · held by pid=%d · -EAGAIN\n",
                           (cmd == 7) ? "W" : "", (unsigned long)fd, ino, g_reclocks[i].owner_synth);
                    return -(int64_t)11;  /* -EAGAIN · a server already owns the prefix */
                }
            lucas_reclock_t *slot = NULL;
            for (int i = 0; i < LUCAS_MAX_RECLOCKS; ++i)
                if (g_reclocks[i].in_use && g_reclocks[i].inode == ino &&
                    g_reclocks[i].owner_synth == st->synthetic_pid) { slot = &g_reclocks[i]; break; }
            if (!slot)
                for (int i = 0; i < LUCAS_MAX_RECLOCKS; ++i)
                    if (!g_reclocks[i].in_use) { slot = &g_reclocks[i]; break; }
            if (!slot) return -(int64_t)11;  /* table full · fail-safe toward contended */
            slot->in_use = 1; slot->inode = ino;
            slot->owner_synth = st->synthetic_pid; slot->owner_display = st->display_pid;
            printf("[fcntl] F_SETLK%s fd=%lu ino=%d · GRANTED pid=%d\n",
                   (cmd == 7) ? "W" : "", (unsigned long)fd, ino, st->synthetic_pid);
            return 0;
        }
        case 9:    /* F_GETOWN · returns the pid receiving SIGIO */
            /* δ-1: log + return 0 · no signal-on-fd yet. */
            printf("[fcntl] F_GETOWN fd=%lu · stub returns 0\n", (unsigned long)fd);
            return 0;
        case 8:    /* F_SETOWN · sets pid receiving SIGIO */
            printf("[fcntl] F_SETOWN fd=%lu arg=%ld · stub OK\n",
                   (unsigned long)fd, (long)arg);
            return 0;
        default:
            return 0;  /* unknown cmd · permissive */
    }
}

/* === Spec A · readv(19) / writev(20): scatter-gather IO =================== */

/* Bounded iovcnt · Linux IOV_MAX is 1024.  An iovcnt outside [0, IOV_MAX]
 * is -EINVAL. */
#define LX_IOV_MAX 1024

/* x86_64 struct iovec · 16 bytes (void *iov_base; size_t iov_len). */
struct lx_iovec { uint64_t iov_base; uint64_t iov_len; };

/* Vectored write.  Iterate the iovec array, copying each 16-byte entry from
 * the client vspace and delegating the segment to the existing per-fd
 * lucas_sys_write (which validates the fd and the per-iov data pointer via
 * its own lucas_copy_*, and applies the console/FS anomaly boundary).
 * Partial-return: stop at the first short/error and return bytes so far;
 * return the error only when nothing has been written yet.  iovcnt bounded
 * to [0, IOV_MAX] → -EINVAL. */
int64_t lucas_sys_writev(lucas_state_t *st, uint64_t fd, uint64_t iov_vaddr,
                         uint64_t iovcnt, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;
    if ((int64_t)iovcnt < 0 || iovcnt > LX_IOV_MAX) return -(int64_t)LX_EINVAL;
    int64_t total = 0;
    for (uint64_t i = 0; i < iovcnt; ++i) {
        struct lx_iovec iov;
        if (lucas_copy_from_client(st, (uintptr_t)(iov_vaddr + i * sizeof(iov)),
                                   &iov, sizeof(iov)) != 0)
            return (total > 0) ? total : -(int64_t)LX_EFAULT;
        if (iov.iov_len == 0) continue;
        int64_t n = lucas_sys_write(st, fd, iov.iov_base, iov.iov_len, 0, 0, 0);
        if (n < 0) return (total > 0) ? total : n;   /* partial → return so far */
        total += n;
        if ((uint64_t)n < iov.iov_len) break;          /* short write · stop */
    }
    return total;
}

/* Vectored read · mirror of writev over lucas_sys_read. */
int64_t lucas_sys_readv(lucas_state_t *st, uint64_t fd, uint64_t iov_vaddr,
                        uint64_t iovcnt, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;
    if ((int64_t)iovcnt < 0 || iovcnt > LX_IOV_MAX) return -(int64_t)LX_EINVAL;
    int64_t total = 0;
    for (uint64_t i = 0; i < iovcnt; ++i) {
        struct lx_iovec iov;
        if (lucas_copy_from_client(st, (uintptr_t)(iov_vaddr + i * sizeof(iov)),
                                   &iov, sizeof(iov)) != 0)
            return (total > 0) ? total : -(int64_t)LX_EFAULT;
        if (iov.iov_len == 0) continue;
        int64_t n = lucas_sys_read(st, fd, iov.iov_base, iov.iov_len, 0, 0, 0);
        if (n < 0) return (total > 0) ? total : n;
        total += n;
        if ((uint64_t)n < iov.iov_len) break;          /* short read (EOF) · stop */
    }
    return total;
}

/* === L3b-T4 · pipe() / pipe2() =========================================== */

int64_t lucas_sys_pipe(lucas_state_t *st, uint64_t fds_vaddr,
                        uint64_t _1, uint64_t _2, uint64_t _3,
                        uint64_t _4, uint64_t _5) {
    (void)_1; (void)_2; (void)_3; (void)_4; (void)_5;

    struct lucas_pipe *p = lucas_pipe_alloc();
    if (!p) return -(int64_t)24;  /* -EMFILE */

    /* Allocate two free fds (rfd first, then wfd). */
    int rfd = -1, wfd = -1;
    for (int i = 0; i < LUCAS_MAX_FDS && (rfd < 0 || wfd < 0); ++i) {
        if (st->fds[i].kind == LUCAS_FD_INVALID && !st->fds[i].is_std) {
            if (rfd < 0) rfd = i;
            else          wfd = i;
        }
    }
    if (rfd < 0 || wfd < 0) return -(int64_t)24;

    st->fds[rfd].kind  = LUCAS_FD_PIPE_READ;
    st->fds[rfd].pipe  = p;
    st->fds[rfd].mount = NULL;
    st->fds[rfd].handle= NULL;
    st->fds[wfd].kind  = LUCAS_FD_PIPE_WRITE;
    st->fds[wfd].pipe  = p;
    st->fds[wfd].mount = NULL;
    st->fds[wfd].handle= NULL;

    int32_t pair[2] = { rfd, wfd };
    if (lucas_copy_to_client(st, (uintptr_t)fds_vaddr, pair, sizeof(pair)) != 0)
        return -(int64_t)14;  /* -EFAULT */
    printf("[pipe] pipe() rfd=%d wfd=%d\n", rfd, wfd);
    return 0;
}

int64_t lucas_sys_pipe2(lucas_state_t *st, uint64_t fds_vaddr,
                         uint64_t flags, uint64_t _2, uint64_t _3,
                         uint64_t _4, uint64_t _5) {
    /* L3b: O_NONBLOCK / O_CLOEXEC flags are ignored for now. */
    (void)flags;
    return lucas_sys_pipe(st, fds_vaddr, 0, 0, 0, 0, 0);
}

/* Close fd entry · helper for dup2 (which must close newfd if open). */
static void close_fd_entry(lucas_fd_t *e) {
    switch (e->kind) {
        case LUCAS_FD_PIPE_READ:
            if (e->pipe) lucas_pipe_close_reader(e->pipe);
            break;
        case LUCAS_FD_PIPE_WRITE:
            if (e->pipe) lucas_pipe_close_writer(e->pipe);
            break;
        case LUCAS_FD_VFS:
            if (e->mount && e->mount->ops->close) {
                e->mount->ops->close(e->mount->backend_state, e->handle);
            }
            break;
        default:
            break;
    }
    /* OBSD-ε OMALLOC · junk on free · zero whole slot so future bugs that
     * race a UAF can't misuse stale handle/mount/pipe pointers. */
    memset(e, 0, sizeof(*e));
}

/* Close all open file descriptors in the state.  Called on process exit to
 * release pipe refcounts (which unblocks any reader/writer waiting for EOF). */
void lucas_close_all_fds(lucas_state_t *st) {
    for (int i = 0; i < LUCAS_MAX_FDS; ++i) {
        if (st->fds[i].kind != LUCAS_FD_INVALID)
            close_fd_entry(&st->fds[i]);
    }
}

int64_t lucas_sys_dup2(lucas_state_t *st, uint64_t oldfd, uint64_t newfd,
                       uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5) {
    (void)_2; (void)_3; (void)_4; (void)_5;
    if (oldfd >= LUCAS_MAX_FDS || newfd >= LUCAS_MAX_FDS)
        return -(int64_t)LX_EBADF;
    lucas_fd_t *src = &st->fds[oldfd];
    if (src->kind == LUCAS_FD_INVALID && !src->is_std)
        return -(int64_t)LX_EBADF;
    if (oldfd == newfd) return (int64_t)newfd;

    lucas_fd_t *dst = &st->fds[newfd];
    if (dst->kind != LUCAS_FD_INVALID || dst->is_std) {
        close_fd_entry(dst);
    }

    /* Copy the entry. */
    *dst = *src;
    /* Bump pipe refcount so the close_fd_entry(dst) on a future close
     * symmetrically decrements. */
    if (src->kind == LUCAS_FD_PIPE_READ && src->pipe) {
        lucas_pipe_add_reader(src->pipe);
    } else if (src->kind == LUCAS_FD_PIPE_WRITE && src->pipe) {
        lucas_pipe_add_writer(src->pipe);
    } else if (src->kind == LUCAS_FD_SOCKET && src->unix_chan_idx1) {
        /* A socketpair channel end (busybox wget's https path: dup2(sp,0)→dup2(0,1)
         * then close the original) is refcounted exactly like a pipe.  A plain
         * struct-copy ALIASES the end without bumping the channel refcount → when
         * the caller closes oldfd the refcount drops while newfd still holds the
         * end; the peer's last close then takes it to 0 and the channel is marked
         * closed prematurely → the still-open holder gets EPIPE ("Broken pipe").
         * Bump the inherited end's refcount, mirroring lucas_unix_inherit_fd. */
        extern void lucas_unix_inherit_fd(lucas_state_t *, int);
        lucas_unix_inherit_fd(st, (int)newfd);
    } else if (src->kind == LUCAS_FD_VFS && src->mount &&
               src->mount->ops->dup_handle && src->handle) {
        /* A VFS fd carries a backend handle whose lifetime is the fd's.  A plain
         * struct-copy ALIASES it → when the caller closes oldfd (the very common
         * shell redirect `cmd > file`: open→dup2(fd,1)→close(fd)), close_fd_entry
         * frees the shared handle and newfd is left dangling → write/read EBADF.
         * Give newfd its OWN handle (same open file), exactly as SCM_RIGHTS does. */
        void *nh = src->mount->ops->dup_handle(src->mount->backend_state, src->handle);
        if (nh) dst->handle = nh;
        /* dup_handle NULL (pool full / unsupported) → keep the alias (best effort,
         * the pre-existing behaviour); the close-dangles-newfd risk remains only
         * in that exhausted-pool corner. */
    }
    printf("[lucas] dup2(oldfd=%lu, newfd=%lu) · kind=%d\n",
           (unsigned long)oldfd, (unsigned long)newfd, (int)dst->kind);
    return (int64_t)newfd;
}

int64_t lucas_sys_dup3(lucas_state_t *st, uint64_t oldfd, uint64_t newfd,
                       uint64_t flags, uint64_t _3, uint64_t _4, uint64_t _5) {
    (void)flags; (void)_3; (void)_4; (void)_5;
    if (oldfd == newfd) return -(int64_t)LX_EINVAL;
    return lucas_sys_dup2(st, oldfd, newfd, 0, 0, 0, 0);
}

/* === U1 · MS-M1 · tar-metadata syscalls ===================================
 *
 * busybox tar (and any POSIX archiver) calls these after each file extraction
 * to restore permissions, ownership, and timestamps. sotFS does NOT track any
 * of those, so the honest implementation is: log the call so the operator can
 * see what tar tried to do, then return 0 ("done") for fchmod/fchown/utimensat
 * so the extractor keeps walking. mknod/mknodat refuse with -EPERM because
 * device-special files have no sotFS analogue and silently lying about them
 * would mask a real bug (tar archives containing /dev nodes).
 */

int64_t lucas_sys_fchmod(lucas_state_t *st, uint64_t a0, uint64_t a1,
                          uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)st; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    int fd = (int)a0;
    unsigned int mode = (unsigned int)a1;
    printf("[lucas] fchmod fd=%d mode=0%o (no-op · sotFS doesn't track perms)\n",
           fd, mode);
    return 0;  /* accept silently · let tar proceed */
}

int64_t lucas_sys_fchown(lucas_state_t *st, uint64_t a0, uint64_t a1, uint64_t a2,
                          uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)st; (void)_a3; (void)_a4; (void)_a5;
    int fd = (int)a0;
    unsigned int uid = (unsigned int)a1;
    unsigned int gid = (unsigned int)a2;
    printf("[lucas] fchown fd=%d uid=%u gid=%u (no-op · sotFS doesn't track owners)\n",
           fd, uid, gid);
    return 0;  /* accept silently · let tar proceed */
}

int64_t lucas_sys_utimensat(lucas_state_t *st, uint64_t a0, uint64_t a1,
                             uint64_t a2, uint64_t a3,
                             uint64_t _a4, uint64_t _a5) {
    (void)st; (void)a2; (void)_a4; (void)_a5;
    int dirfd = (int)a0;
    /* path may be NULL (then dirfd refers to a fd) · don't deref · just log. */
    printf("[lucas] utimensat dirfd=%d path_vaddr=0x%lx flags=0x%lx (no-op · sotFS doesn't track timestamps)\n",
           dirfd, (unsigned long)a1, (unsigned long)a3);
    return 0;  /* accept silently · let tar proceed */
}

int64_t lucas_sys_mknod(lucas_state_t *st, uint64_t a0, uint64_t a1, uint64_t a2,
                         uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)st; (void)a0; (void)_a3; (void)_a4; (void)_a5;
    unsigned int mode = (unsigned int)a1;
    unsigned long dev = (unsigned long)a2;
    printf("[lucas] mknod mode=0%o dev=0x%lx · -EPERM (device files not supported)\n",
           mode, dev);
    return -(int64_t)1;  /* EPERM */
}

int64_t lucas_sys_mknodat(lucas_state_t *st, uint64_t a0, uint64_t a1, uint64_t a2,
                           uint64_t a3, uint64_t _a4, uint64_t _a5) {
    (void)st; (void)a1; (void)_a4; (void)_a5;
    int dirfd = (int)a0;
    unsigned int mode = (unsigned int)a2;
    unsigned long dev = (unsigned long)a3;
    printf("[lucas] mknodat dirfd=%d mode=0%o dev=0x%lx · -EPERM (device files not supported)\n",
           dirfd, mode, dev);
    return -(int64_t)1;  /* EPERM */
}
