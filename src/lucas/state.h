/*
 * sotOs · LUCAS L1 state.
 *
 * One instance per Linux client. Holds caps to the client (TCB / vspace /
 * fault EP) and Linux process state. For L1, the seL4 environment (vka,
 * vspace, simple) is borrowed from the root task; the L3 refactor that
 * extracts LUCAS into its own process will let it own its environment.
 *
 * No malloc · all bounded (LUCAS_MAX_FDS, etc).
 */

#ifndef SOTOS_LUCAS_STATE_H
#define SOTOS_LUCAS_STATE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <lucas/pledge.h>
#include <lucas/unveil.h>
#include <lucas/functor.h>
#include <lucas/linux_abi.h>   /* struct lx_termios / lx_winsize (per-session tty state) */
#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vka/object.h>   /* P2a · vka_object_t (owned-object capture for teardown) */
#include <vspace/vspace.h>
#include <simple/simple.h>
#include <sel4utils/vspace.h>
#include <lucas/vfs.h>

/* Forward declaration so lucas_fd_t can hold a pipe pointer without
 * requiring pipe.h to be included here. */
struct lucas_pipe;
struct tcp_conn;
struct sotbox_arena;

/* L3b-T2/T4: sotBox state machine. */
typedef enum {
    SOTBOX_STATE_RUNNING                = 0,
    SOTBOX_STATE_WAITING_FOR_CHILD      = 1,
    SOTBOX_STATE_WAITING_FOR_PIPE_READ  = 2,
    SOTBOX_STATE_WAITING_FOR_PIPE_WRITE = 3,
    SOTBOX_STATE_EXITED                 = 4,
    /* LUCAS-surface batch · pre-scaffolded by coordinator · used by U1/U2/U3 workers. */
    SOTBOX_STATE_WAITING_FOR_FUTEX      = 5,  /* U2 · futex(FUTEX_WAIT) */
    SOTBOX_STATE_WAITING_FOR_EPOLL      = 6,  /* U3 · epoll_wait blocking */
    SOTBOX_STATE_WAITING_FOR_SIGNAL     = 7,  /* U1 · sigsuspend / rt_sigtimedwait */
    SOTBOX_STATE_WAITING_FOR_RECV       = 8,  /* sotNet · blocking recvfrom (BG2) */
    SOTBOX_STATE_WAITING_FOR_ACCEPT     = 9,  /* sottrace v1 · blocking accept (mirrors RECV) */
    SOTBOX_STATE_WAITING_FOR_CONSOLE    = 10, /* interactive shell · blocking read(fd0) on serial */
    SOTBOX_STATE_WAITING_FOR_VFORK      = 11, /* WINE-M1 · parent parked in clone(CLONE_VM|CLONE_VFORK)
                                               * until the vfork child execve()s or _exit()s (Linux
                                               * vfork semantics: caller blocks, sharing its address
                                               * space, until the child stops borrowing it). */
    SOTBOX_STATE_WAITING_FOR_UNIX       = 12, /* WINE-M1 · blocked read/recv on an empty AF_UNIX
                                               * stream channel (wineserver IPC); woken when the peer
                                               * writes or closes (g_unix_channels). */
    SOTBOX_STATE_WAITING_FOR_POLL       = 13, /* apt arc · blocking poll() whose sole readable interest
                                               * is a not-ready pipe-read fd; woken from pipe.c on
                                               * data-or-HUP (iomux_check_poll_waiters). */
    SOTBOX_STATE_WAITING_FOR_SELECT     = 14, /* apt arc · blocking (p)select() whose sole readable
                                               * interest is a not-ready pipe-read fd (apt's http method
                                               * handshake uses pselect6); woken from pipe.c on data-or-HUP
                                               * (iomux_check_select_waiters). */
} sotbox_state_t;

/* console_wait_kind discriminator (Task 5) · a box parked in
 * SOTBOX_STATE_WAITING_FOR_CONSOLE is either waiting on read(fd0) (deliver 1
 * byte) or on a blocking poll(stdin,-1) (re-scan + deliver revents+ready-count). */
#define LUCAS_CONSOLE_WAIT_READ 0
#define LUCAS_CONSOLE_WAIT_POLL 1
#define LUCAS_CONSOLE_WAIT_SELECT 2   /* blocking select/pselect on the console (GNU bash readline) */

/* SSH canary shell (Phase B) · console byte source (console_src field). */
#define LUCAS_CONSOLE_SRC_SERIAL   0   /* UART (bbsh / operator) */
#define LUCAS_CONSOLE_SRC_SSH_RING 1   /* SHELL_IN/OUT bytepipe (decrypted SSH) */

/* WINE-M1 · 16 → 64.  wineserver opens many persistent fds (master AF_UNIX
 * socket + epoll + lock + dup2'd stdio + one self-pipe PER handled signal +
 * per-client sockets); 16 overflowed during init_signals (4th signal pipe hit
 * EMFILE → "failed to initialize signal handlers").  64 covers wineserver + a
 * wine client comfortably; lucas_fd_t is ~1 KiB so the per-sotbox table grows
 * ~48 KiB (acceptable across the slot pool). */
#define LUCAS_MAX_FDS         64
#define LUCAS_PATH_MAX        256
#define LUCAS_INITIAL_STACK   (64 * 1024)
#define LUCAS_MMAP_BASE       0x40000000UL  /* where MAP_ANONYMOUS lives */
/* L13 · wl_shm pool guest vaddr window. Chosen clear of LUCAS_MMAP_BASE (0x40000000
 * anon high-water) and the D3/N3 lazy file-backed spans (PIE 0x100000000,
 * ld-musl 0x140000000). */
#define LUCAS_SHM_POOL_BASE   0x200000000UL

/* vDSO arc · Task 4 · guest vaddr where the [vvar][vdso] pair is mapped.
 *
 * Layout (contiguous, fixed −4096 vvar→vdso offset so the in-guest vDSO code
 * can find its data page at ehdr-0x1000):
 *   SOTOS_VDSO_BASE          .. +0x1000   [vvar]  r--  (sotos_vvar page)
 *   SOTOS_VDSO_BASE + 0x1000 .. +N*0x1000 [vdso]  r-x  (the vdso.so ELF blob)
 * AT_SYSINFO_EHDR (auxv type 33) = SOTOS_VDSO_EHDR = the vdso ELF header addr.
 *
 * Collision argument — this base collides with NONE of the guest regions:
 *   - static TEXT/DATA      [0x00400000, ~0x01300000)   (24 MiB window)
 *   - initial stack         ~[0x0fff0000, 0x10000000)   (256 MiB region)
 *   - MAP_ANONYMOUS         [0x40000000, …)             grows UP from 1 GiB
 *   - wl_shm pool window     0x200000000  (8 GiB)
 *   - dynamic PIE base       0x100000000  (4 GiB)
 *   - ld-musl interp base    0x140000000  (5 GiB)
 *   - dynamic brk/heap       0x180000000+ (6 GiB, grows UP)
 *
 * Address choice: must be in x86_64 PML4 entry 0-254 (below 0x7f8000000000).
 * seL4Utils pre-marks top-level entry 255+ as RESERVED in every fresh client
 * vspace (common_init_post_bootstrap, KERNEL_RESERVED_START = seL4_UserTop =
 * 0x7ffffffff000 → PML4 entry 255), so any address ≥ 0x7f8000000000 causes
 * vspace_reserve_range_at to fail.  0x7f5000000000 (PML4 entry 254) is far
 * above all user regions and looks like a plausible shared-library address.
 */
#define SOTOS_VDSO_BASE       0x7f5000000000UL
#define SOTOS_VDSO_EHDR       (SOTOS_VDSO_BASE + 0x1000UL)

/* L3b-T4: fd kind discriminant. */
typedef enum {
    LUCAS_FD_INVALID    = 0,
    LUCAS_FD_STDIO      = 1,
    LUCAS_FD_VFS        = 2,
    LUCAS_FD_PIPE_READ  = 3,
    LUCAS_FD_PIPE_WRITE = 4,
    LUCAS_FD_SOCKET     = 5,   /* sotNet-α · stub socket fd (spec §12.8.4) */
    LUCAS_FD_EPOLL      = 6,   /* U3 · epoll instance fd */
    LUCAS_FD_FB         = 7,   /* Doom · /dev/fb0 present sink */
    LUCAS_FD_DOOMKBD    = 8,   /* Doom · /dev/doomkbd raw-key source (virtio-keyboard) */
    LUCAS_FD_DOOMMOUSE  = 9,   /* Doom · /dev/doommouse relative-motion source (virtio-tablet) */
    LUCAS_FD_NULL       = 10,  /* /dev/null · reads EOF, writes discarded */
    LUCAS_FD_URANDOM    = 11,  /* /dev/urandom · reads = CSPRNG bytes (real software: git) */
} lucas_fd_kind_t;

/* Per-open-fd entry for the companion's fd table. */
typedef struct lucas_fd {
    lucas_fd_kind_t    kind;     /* discriminant · replaces ad-hoc is_std test */
    /* VFS fields: */
    const vfs_mount_t *mount;
    void              *handle;
    int64_t            cursor;
    int                flags;
    /* Socket address-family + type, packed (family<<16)|(type&0xFFFF), set at
     * socket()/accept() time.  Kept SEPARATE from `flags` because `flags` holds
     * the fd's open-flags (O_NONBLOCK/O_CLOEXEC) which fcntl(F_SETFL/F_SETFD)
     * overwrites — that previously clobbered the socket type, so a TCP socket
     * apt made non-blocking was misread as UDP and connect() sent no SYN. */
    int                sock_typefam;
    bool               is_std;  /* kept for backward compat · true when kind==STDIO */
    uint8_t            is_console_tty; /* /dev/tty alias of the interactive console:
                                        * read/poll route to the console like fd0 (GNU
                                        * bash's readline does all I/O via /dev/tty). */
    /* Pipe fields (non-NULL only when kind == PIPE_READ or PIPE_WRITE): */
    struct lucas_pipe *pipe;
    /* TIER1-REVOKE-GATES · set to 1 by lucas_set_tier() at the moment the
     * sotbox is promoted to Tier-1 (Silenced).  When set, all writable ops
     * (write / sendto / etc.) on this fd return -EACCES instead of the
     * legacy synthetic-success silenced rollback.  Stdio is never locked. */
    uint8_t            writes_denied;
    /* N-SYNTH · one-shot guard for synth-redirected recv reply.
     * Set to 1 after the first synthesized HTTP 200 reply is delivered on
     * a Tier-2 socket; subsequent recvfrom/recv calls return 0 (EOF) so
     * Python's recv-loop terminates cleanly.  Cleared by close() via the
     * existing memset-on-free path. */
    uint8_t            synth_recv_consumed;
    /* Gate 0 · egress sinkhole · set by connect() when a GUARDED real-wire
     * session targets a non-allowlisted third party: NO real socket is opened,
     * recv() returns the canned synth reply + send() is dropped, so the attacker
     * believes egress works while no packet leaves the host.  Cleared on close
     * via the whole-fd memset. */
    uint8_t            synth_sinkhole;
    /* L12-beta · narrow AF_UNIX route state for /run/user/1000/wayland-0.
     * General AF_UNIX stays out of scope; this records only the compositor
     * path and route cap captured by orch bootstrap. */
    uint8_t            wayland_connected;
    seL4_CPtr          wayland_route_ep;
    char               unix_path[108];
    /* WINE-M1 · Phase 4 · general AF_UNIX rendezvous (wineserver IPC).  A
     * socket fd is EITHER a listener (unix_listener_idx1>0 → g_unix_listeners)
     * OR a connected stream endpoint (unix_chan_idx1>0 → g_unix_channels, with
     * unix_server_end selecting which ring half it reads vs writes).  Indices
     * are 1-based so the whole-fd memset on close clears them to 0 = "none". */
    int                unix_listener_idx1;
    int                unix_chan_idx1;
    uint8_t            unix_server_end;
    /* L12-gamma · compositor reply bytes buffered by a wayland write(),
     * drained by the following read(s).  Tiny control frames only; the
     * whole fd struct is memset on close, so this clears automatically. */
    uint8_t            wl_rx[256];   /* L12-delta · holds the multi-event get_registry reply */
    uint16_t           wl_rx_len;
    uint16_t           wl_rx_cursor;
    /* v2.x · TX reassembly · libwayland can split a wl request across sendmsg/
     * iov boundaries (real apps like gtk3-demo do; gtkspike never did).  The
     * forwarder buffers a trailing PARTIAL message here and prepends it to the
     * next sendmsg so messages are reassembled before forwarding (a single wl
     * message is <= LUCAS_WL_MAX_WORDS*4 = 256B, so 512 is ample).  Cleared on
     * close via the whole-fd memset. */
    uint8_t            wl_txacc[512];
    uint16_t           wl_txacc_len;
    /* sotNet γ-3-γ-2b · connected-socket peer cached at connect() time, so a
     * connected send()/recv() (no per-call address) routes over the byte-pipe.
     * Network byte order · 0 = not connected. */
    uint32_t           connect_peer_ip_be;
    uint32_t           connect_peer_port_be;
    /* N1 · δ-2 · the real TCP connection bound to this fd by connect() once it
     * reaches ESTABLISHED.  NULL unless a real (non-synth) TCP connect
     * succeeded; write()/read() then drive tcp_send_data / conn->rx_buf. */
    struct tcp_conn   *tcp_conn;
    /* SOCKET DEMUX · when non-NULL this fd's OUTBOUND connection rides the lwIP
     * egress stack (orch_lwip_egress_*) instead of the δ stack — opaque handle
     * (oeg_session_t*) so state.h needn't pull in lwIP headers.  Set by connect()
     * for egress; send/recv/close route to lwIP when set.  Cleared on close. */
    void              *lwip_sess;
    /* N3/D3 · set when this fd backs a lazy file-backed mmap region.  The
     * region pins the VFS handle, so close() must NOT op_close it (lazy faults
     * read through the handle after the guest closes the .so fd). */
    bool               lazy_pinned;
    /* L13 · wl_shm pool fd: memfd_create -> ftruncate sizes/allocs the pool -> mmap maps it. */
    int       is_memfd;        /* 1 if this fd was memfd_create'd */
    int       shm_pool_id;     /* orch_shm_pool id, or -1 */
    uint64_t  shm_pool_size;   /* ftruncate size */
    uint64_t  shm_guest_vaddr; /* set by mmap (Task B2), else 0 */
    uint32_t  wl_shm_obj_id;   /* L13-B3 · bound wl_shm object id (0 = not yet bound) */
    uint32_t  wl_capture_obj_id; /* L14a-C1 · bound sotos_capture object id (0 = not yet bound) */
    uint32_t  wl_seat_obj_id;  /* L14b · bound wl_seat object id (0 = not yet bound) */
    /* v2.7 live pointer input · ids sniffed off the HONEST client's forwarded
     * requests so LUCAS can synthesize real wl_pointer events into wl_rx from the
     * virtio-tablet cursor (the sync transport has no async push, so events ride
     * the client's next poll/read of the wayland fd · see lucas_wl_try_stage_input). */
    uint32_t  wl_xdg_obj_id;        /* bound xdg_wm_base (registry name=5) */
    uint32_t  wl_pointer_obj_id;    /* wl_seat.get_pointer new_id (0 = none) */
    uint32_t  wl_surface_obj_id;    /* the xdg toplevel's wl_surface (enter target · NOT the cursor surface) */
    uint32_t  wl_pool_obj_id;       /* wl_shm.create_pool new_id (to sniff create_buffer dims) */
    uint16_t  wl_win_w, wl_win_h;   /* committed buffer dims (for centered-scanout coord map) */
    uint8_t   wl_ptr_entered;       /* 1 once wl_pointer.enter was delivered */
    int16_t   wl_ptr_x, wl_ptr_y;   /* last-delivered surface-local cursor (px) */
    uint8_t   wl_ptr_btn;           /* last-delivered left-button state (0/1) */
    /* Synthesized wl_pointer events live in their OWN buffer (not wl_rx) so a
     * compositor reply (which overwrites wl_rx on any client request) can never
     * clobber staged-but-unread input → no lost-enter / state desync.  Drained
     * only after wl_rx is fully consumed (never spliced mid-reply). 96B > the
     * largest batch (enter+motion+frame = 52B). */
    uint8_t   wl_in[96];
    uint16_t  wl_in_len, wl_in_cursor;
    /* dir-fd support · the absolute, normalized path this fd was opened with.
     * Lets the *at family (openat/newfstatat/statx/unlinkat/getdents-by-fd …)
     * resolve a RELATIVE pathname against a real directory fd — what os.scandir
     * / os.walk (and the in-process wheel build) need.  Empty string = unknown
     * (dev nodes, sockets, pipes · those are never dir fds anyway). */
    char      fd_path[LUCAS_PATH_MAX];
    /* apt-T7 · AF_NETLINK(NETLINK_ROUTE) socket state.  glibc getaddrinfo's
     * AI_ADDRCONFIG probe opens a netlink route socket and dumps RTM_GETADDR to
     * enumerate interfaces; we synthesize one IPv4 RTM_NEWADDR (10.0.2.15) so it
     * sees a usable IPv4 iface and proceeds to query A records.  is_netlink set
     * at socket(); netlink_dump_pending+netlink_seq recorded by the RTM_GETADDR
     * send, consumed by the next recvmsg.  Cleared by the whole-fd memset on close. */
    uint8_t   is_netlink;
    uint8_t   netlink_dump_pending;
    uint8_t   netlink_dump_type;  /* RTM_GETADDR(22) or RTM_GETLINK(18) · phase-1 reply shape */
    uint32_t  netlink_seq;
    uint32_t  netlink_pid;   /* the request's nlmsg_pid · echoed in the reply (glibc skips a pid mismatch) */
} lucas_fd_t;

/* N3/D3 · lazy file-backed mmap region.  A large .so is mapped by reserving its
 * span WITHOUT frames; pages are backed on first-touch by the VMFault handler,
 * which reads file bytes via the pinned VFS mount+handle (the guest closes the
 * .so fd right after mmap, so we cannot use the fd at fault time). */
/* One lazy region per file-backed mmap that stays live for on-demand faulting —
 * i.e. one per shared library ld-musl maps.  A small static-musl app needs a
 * handful; the SDL2 closure ~7.  But a real GTK3 app drags a 57-lib closure
 * (glib/gobject/cairo/pango/harfbuzz/fontconfig/...) + runtime anon/font mmaps,
 * so 8 overflowed ("region table full · -ENOMEM" → ld-musl "Out of memory"
 * loading libharfbuzz).  256 covers GTK with headroom (and bigger toolkits to
 * come).  Per-sotbox cost: 256 * sizeof(lucas_lazy_region_t) ≈ 18 KiB of BSS. */
#define LUCAS_MAX_LAZY_REGIONS 256
typedef struct lucas_lazy_region {
    bool             in_use;
    uintptr_t        vstart;     /* page-aligned span start */
    uintptr_t        vend;       /* page-aligned span end (exclusive) */
    uint64_t         file_off;   /* file offset mapped at vstart */
    uint64_t         file_len;   /* bytes of real file content (rest = zero) */
    seL4_CapRights_t rights;     /* rights to map backed pages with */
    reservation_t    res;        /* the span reservation (for new_pages) */
    const void      *mount;      /* pinned vfs_mount_t* (survives fd close) */
    void            *handle;     /* pinned backend handle */
} lucas_lazy_region_t;

typedef struct lucas_state {
    /* Borrowed from root's environment · NOT freed by lucas. */
    simple_t   *simple;
    vka_t      *vka;
    vspace_t   *parent_vspace;   /* root's vspace · used for copy ops */

    /* Client-specific caps and address space (owned by lucas). */
    seL4_CPtr   client_tcb;
    seL4_CPtr   client_vspace;
    seL4_CPtr   client_cnode;
    seL4_CPtr   fault_ep;
    seL4_CPtr   client_ipc_buffer_frame;
    vspace_t    client_vspace_abs;
    sel4utils_alloc_data_t client_vspace_data;

    /* P2a · the untyped arena this sotbox allocates from; revoked wholesale at
     * reap.  NULL for sotboxes not yet arena-backed (fork children · slots>=1). */
    struct sotbox_arena *arena;

    /* P2a · zero-leak teardown.  The full vka_object_t captured at the moment
     * each owned object is vka_alloc_*'d.  vka_free_object NEEDS the .ut cookie
     * (allocman casts it back to a utspace node and dereferences it) — a
     * hand-built {.cptr,.size_bits,.ut=0} would NULL-deref the allocator, so we
     * keep the originals here and free THESE at reap (sotbox_destroy).  cptr==0
     * (memset-zeroed state) means "not allocated / already freed". */
    vka_object_t client_tcb_obj;
    vka_object_t client_cnode_obj;
    vka_object_t client_vspace_obj;       /* PML4 / vspace root */
    vka_object_t client_ipc_buffer_obj;

    /* Linux process state */
    uintptr_t   entry_point;        /* RIP at start */
    /* N3/D1 · dynamic ELF loading.  When is_dynamic, the binary is a PIE
     * loaded at bin_base and its interpreter (ld-musl) at interp_base; the
     * client RIP is the interpreter's entry, and the auxv carries the binary's
     * program-header / entry addresses so ld-musl can relocate + hand off. */
    bool        is_dynamic;         /* binary has PT_INTERP */
    uintptr_t   bin_base;           /* load base of the main PIE */
    uintptr_t   interp_base;        /* load base of ld-musl */
    uintptr_t   bin_phdr_vaddr;     /* AT_PHDR: bin_base + e_phoff */
    uint16_t    bin_phnum;          /* AT_PHNUM */
    uint16_t    bin_phent;          /* AT_PHENT */
    uintptr_t   bin_entry_vaddr;    /* AT_ENTRY: bin_base + binary e_entry */
    /* N3/D1 · dynamic-load base addresses (client vspace, 2 MiB-aligned),
     * shared by the loader (lucas_l1.c) and the MSYSCALL text-range check
     * (fault_loop.c).  The whole [BIN_BASE, BRK_BASE) window is legitimate
     * program text+data for a dynamic sotbox (the PIE + ld-musl). */
    #define LUCAS_DYN_BIN_BASE     0x100000000UL   /* 4 GiB · main PIE */
    #define LUCAS_DYN_INTERP_BASE  0x140000000UL   /* 5 GiB · ld-musl */
    #define LUCAS_DYN_BRK_BASE     0x180000000UL   /* 6 GiB · dynamic brk */
    /* N3/D3 · lazy file-backed mmap regions (the .so spans · backed on-fault). */
    lucas_lazy_region_t lazy_regions[LUCAS_MAX_LAZY_REGIONS];
    /* Wine-prep · address-space RESERVATIONS (frame-less).  A large PROT_NONE
     * anonymous mmap (the wine-preloader reserves the Windows low ranges: the DOS
     * area + ~1.7 GiB low + a high top-down window, all PROT_NONE, BEFORE the PE
     * loader runs so Win32 images land where they expect) records a LOGICAL span
     * here with NO vspace reservation or frames — committing 1.7 GiB of bookkeeping
     * would explode the arena.  A later MAP_FIXED mmap into the span commits only
     * the touched sub-range; the high-water allocator skips these spans so a
     * non-fixed mmap never lands inside a reserved-but-uncommitted Windows range. */
    #define LUCAS_MAX_RESV_REGIONS 16
    struct lucas_resv_region {
        bool      in_use;
        uintptr_t vstart;   /* page-aligned span start          */
        uintptr_t vend;     /* page-aligned span end (exclusive) */
    } resv_regions[LUCAS_MAX_RESV_REGIONS];
    uintptr_t   stack_top;          /* RSP at start (final value after content setup) */
    uintptr_t   stack_region_top;   /* Top of the allocated stack region (highest vaddr) */
    uintptr_t   brk_base;
    uintptr_t   brk_top;
    uintptr_t   mmap_high_water;
    /* vDSO arc · Task 4 · actual [vvar][vdso] mapping recorded by lucas_map_vdso
     * so /proc/self/maps emits the REAL span.  vvar_base == SOTOS_VDSO_BASE,
     * vdso_base == SOTOS_VDSO_EHDR, vdso_code_pages == ceil(blob/4096).
     * Zero until mapped. */
    uintptr_t   vvar_base;
    uintptr_t   vdso_base;
    uint32_t    vdso_code_pages;
    lucas_fd_t  fds[LUCAS_MAX_FDS];

    int         synthetic_pid;
    uint32_t    display_pid;  /* OBSD-ζ · random uint32_t returned by getpid/gettid */
    int         exited;
    int         exit_code;

    /* C2 #3 (v2) · per-sotbox stdout/stderr line buffer.  write_serial
     * accumulates the guest's own output here and flushes WHOLE lines with a
     * "│guest:<pid>│ " prefix, so guest output is correctly attributed and can
     * never interleave mid-line with the system "[subsystem]" trace on the
     * shared serial (the v0.39.0 global-flag attempt mis-attributed · reverted
     * in v0.39.1).  Flushed on newline, on overflow, and at exit_group. */
    char        guest_line[256];
    uint16_t    guest_line_len;

    /* L3a-T7: which slot we occupy in the orchestrator's sotbox_table.
     * Stored so the fault loop can recover state from the badge. */
    int         slot_index;

    /* procd PR 6/7 · procd-side slot index assigned by OP_SPAWN / OP_FORK.
     * Distinct from slot_index because procd allocates monotonically
     * (zombies/dead slots never reuse) while orch's sotbox table
     * recycles slot 0 across processes via sotbox_reset_primary.  0
     * means "no procd slot bound yet" (e.g. spawn announce failed at
     * runtime · safe sentinel because procd's slot 0 is the "no parent"
     * reservation).  PR 7 removed the PROCD_TAKEOVER_SPAWN cmake gate ·
     * announce is now unconditional, so the 0-sentinel path is only
     * taken on a true runtime failure. */
    uint32_t    procd_slot;

    /* L3a-T12: set by sotbox_fork() BEFORE the nested child fault loop
     * so the outer fault loop uses seL4_Send(saved_reply_cap) instead
     * of seL4_Reply() (the nested Recvs clobber the reply slot). */
    int         reply_already_sent;
    seL4_CPtr   saved_reply_cap;    /* slot to seL4_Send the reply to */

    /* L3b-T2: blocking wait4 state machine. */
    volatile sotbox_state_t state;          /* RUNNING by default */
    seL4_CPtr               waiting_reply_cap;    /* 0 when not waiting (shared by wait4 + pipe) */
    int                     waiting_for_pid;      /* -1 = any; >0 = specific */
    uint64_t                waiting_status_vaddr; /* client vaddr for wstatus, or 0 */

    /* L3b-T4: pipe-blocking fields. */
    struct lucas_pipe      *waiting_pipe;       /* pipe being awaited */
    uintptr_t               waiting_pipe_buf;   /* client vaddr of the I/O buffer */
    size_t                  waiting_pipe_count; /* requested byte count */
    /* Install-arc · DEDICATED pipe-waiter tracking, independent of the shared
     * `state` + `waiting_reply_cap` (which wait4 AND futex also use).  A
     * MULTI-THREADED process (e.g. dpkg-deb's liblzma decompressor: a main I/O
     * thread + a worker thread) parks DIFFERENT threads on DIFFERENT primitives
     * at once: the main thread blocks on a pipe write while the worker blocks on
     * a futex.  Both threads belong to ONE lucas_state_t (slot), so the worker's
     * futex park overwrote `state` (WAITING_FOR_PIPE_WRITE → WAITING_FOR_FUTEX)
     * and a futex wake zeroed `waiting_reply_cap` — so lucas_pipe_wake_writers
     * could no longer match the parked writer and tar deadlocked.  These fields
     * are touched ONLY by pipe.c, so a sibling thread's futex/wait4 can't lose
     * the pipe wait.  pipe_wait_kind: 0=none, 1=read, 2=write. */
    seL4_CPtr               pipe_reply_cap;     /* SaveCaller cap for the pipe-parked thread */
    uint8_t                 pipe_wait_kind;     /* 0 none · 1 read · 2 write */

    /* BG2 · recvfrom-blocking fields (valid when state == WAITING_FOR_RECV).
     * Stash the caller's recvfrom args so the wake-up path can copy out the
     * payload + src sockaddr_in into the parked sotbox's vspace, then Send
     * to the saved reply cap.  All vaddrs are 0 when unused. */
    int                     waiting_recv_fd;          /* socket fd */
    uintptr_t               waiting_recv_buf_vaddr;   /* user buf · 0 = ignore */
    size_t                  waiting_recv_buf_size;    /* user buf capacity */
    uintptr_t               waiting_recv_addr_vaddr;  /* user sockaddr · 0 = ignore */
    uintptr_t               waiting_recv_addrlen_vaddr;

    /* sottrace v1 · accept-blocking fields (valid when state == WAITING_FOR_ACCEPT).
     * Stash the caller's accept args so the wake-up path can dequeue the
     * completed conn, alloc a fresh fd, copy out the peer sockaddr_in, then
     * Send to the saved reply cap (reuses waiting_reply_cap). */
    int                     waiting_accept_fd;            /* listening socket fd */
    uintptr_t               waiting_accept_addr_vaddr;    /* user sockaddr · 0 = ignore */
    uintptr_t               waiting_accept_addrlen_vaddr;

    /* WINE-M1 · Phase 4 · AF_UNIX blocking-read park (state==WAITING_FOR_UNIX).
     * Stash the channel + caller's read args so lucas_unix_wake_reader can drain
     * the ring into the parked sotbox's buffer and Send to waiting_reply_cap. */
    int                     waiting_unix_chan1;        /* 1-based g_unix_channels idx; 0=none */
    uint8_t                 waiting_unix_server_end;   /* which end is reading */
    uintptr_t               waiting_unix_buf_vaddr;    /* user dst buffer */
    size_t                  waiting_unix_count;        /* requested byte count */
    /* WINE-M1 · recvmsg park · so the wake can also deliver SCM_RIGHTS fds into
     * the client msghdr (0 = a plain read() park, no control message). */
    uintptr_t               waiting_unix_msg_vaddr;    /* client struct msghdr * */
    uintptr_t               waiting_unix_msgctl;       /* msghdr.msg_control vaddr */
    size_t                  waiting_unix_msgctllen;    /* msghdr.msg_controllen */

    /* interactive console · read(fd0) park/resume (valid when state ==
     * WAITING_FOR_CONSOLE).  Mirrors the recv stash: the client dst vaddr for
     * the one byte the UART RX wake delivers. */
    uint64_t                console_buf_vaddr;   /* valid when state==WAITING_FOR_CONSOLE: client dst for the byte */
    uint8_t                 console_interactive; /* 1 = stdout flushes per-write (no line buffer); set by bbsh spawn */
    uint8_t                 no_onlcr;            /* 1 = emit raw '\n' (NO ONLCR): a non-PTY exec
                                                  * session (`ssh host cmd`) is a pipe not a tty —
                                                  * a real sshd returns LF, so CRLF here is a tell */
    /* SSH canary shell (Phase B) · console byte source selector.  SERIAL = the
     * UART (the bbsh / operator path); SSH_RING = the SHELL_IN/SHELL_OUT
     * bytepipes (decrypted SSH stream · set by orch_ssh_shell_run). */
    uint8_t                 console_src;         /* LUCAS_CONSOLE_SRC_{SERIAL,SSH_RING} */
    uint32_t                shell_in_rd;         /* private read cursor into SHELL_IN (console_src==SSH_RING) */
    /* TUI · per-sotbox terminal state for the ring-backed stdio (console_src==SSH_RING).
     * tty_init=0 → lazily seeded to the cooked default on first tty ioctl. */
    struct lx_termios       cur_termios;
    struct lx_winsize       ws;
    uint8_t                 tty_init;
    seL4_CPtr               console_reply_cslot; /* 0 = unallocated · ONE reusable reply cslot for console read-park.
                                                  * The arena vka's cspace_free is a NO-OP (reclaimed wholesale by
                                                  * revoke), so a fresh cslot per read-park would exhaust the 768-slot
                                                  * arena on an interactive shell (one read per keystroke). Allocate
                                                  * once, SaveCaller into it each park, reuse forever. */

    /* interactive console · poll(stdin,-1) blocking park (Task 5).  Both the
     * read-park and the poll-park share console_reply_cslot + the
     * SOTBOX_STATE_WAITING_FOR_CONSOLE state and the same idle-pump UART wake;
     * console_wait_kind discriminates what the resume delivers (1 byte vs poll
     * revents+ready-count). */
    uint8_t                 console_wait_kind;       /* LUCAS_CONSOLE_WAIT_{READ,POLL,SELECT} */
    uint64_t                console_poll_fds_vaddr;  /* poll-park: client pollfds array vaddr · select-park: rfds */
    uint32_t                console_poll_nfds;       /* poll/select-park: nfds */
    uint64_t                console_sel_wfds_vaddr;  /* select-park: client wfds set vaddr (0 if none) */
    uint64_t                console_sel_efds_vaddr;  /* select-park: client efds set vaddr (0 if none) */
    /* ANSI DSR responder · busybox ash lineedit writes ESC[6n (cursor-position
     * request) then READS the reply; without one it eats the next typed command
     * as the (malformed) reply. dsr_scan matches ESC[6n in the output stream;
     * dsr_emit counts the bytes of "\x1b[1;1R" left to inject into read(fd0). */
    uint8_t                 dsr_scan;
    uint8_t                 dsr_emit;

    /* Fidelity · per-sotbox current working directory (canary-shell `cd`/`ls`).
     * Empty string == "/" (the default · avoids touching every spawn path).
     * chdir/fchdir set it; relative + "."/".." client paths resolve against it
     * (lucas_resolve_path); inherited by fork via *child=*parent; execve keeps
     * it. Stays "/" for non-shell sotboxes so existing absolute-path callers are
     * unaffected. */
    char                    cwd[LUCAS_PATH_MAX];

    /* L6: Tier (0 = pass-through, 1 = silenced mode).  Set at spawn time from
     * orch_spawn_msg_t.initial_tier; never visible to the Linux client. */
    int                    tier;     /* legacy · still read by call sites */
    /* SP1 · operator-trusted sotbox (the in-OS C compiler).  When set,
     * lucas_set_tier refuses promotion: the monitor still scores + logs
     * this sotbox (observability) but it stays pinned at Tier 0.  Set at
     * spawn from orch_spawn_msg_t.trusted; never visible to the client. */
    bool        trusted;
    /* apt arc · euid-elevation for a `sudo …` subtree in an untrusted Tier-2
     * honey session.  The honey shell is a compromised NON-root user (uid 1000,
     * sudo group); `sudo apt install` must run dpkg as root (geteuid()==0 or dpkg
     * refuses "requires superuser privilege").  Set on the sudo'd apt pool, copied
     * to its forked dpkg via fork's `*child=*parent`.  Affects ONLY the reported
     * uid/gid — containment stays VFS-session-based (uid-independent), so the
     * Tier-2 overlay still contains every write. */
    uint8_t     euid_root;
    /* Package-manager box (apk/apt pool) · its install legitimately does mass file
     * ops (extract → many creates/renames) that would trip the Forman-Ricci
     * RANSOMWARE/LATERAL curvature heuristics.  Set by orch_spawn_apk/apt_pool so
     * sotfs_curvature_exempt() skips the false alert for this box. */
    uint8_t     pkg_install;
    const lucas_functor_t *functor;  /* sotFS-ι · new · Phase 2 reads this */
    int         silenced_write_count;  /* writes silenced in Tier 1 */
    int         canary_read_count;      /* L8 · Tier 2 sotBox reads of canary files */
    int         doom_frame;            /* Doom · presented-frame counter (/dev/fb0) */

    /* Phase C · per-session COW-lite overlay key.  Set to the SSH conn_id on the
     * SSH-shell sotbox at spawn; 0 means no overlay (Tier-0 / non-SSH).  Copied
     * verbatim to fork children (sotbox_fork does `*child = *parent`), so the
     * vim child inherits the session and its `:w` edits read back within the
     * session while the base canary file stays pristine. */
    uint32_t    cow_session;

    /* TIER1-REVOKE-GATES · operator-visible counter incremented every
     * time the Tier-1 gates actively deny an escape attempt: a write on
     * a writes_denied fd, an open(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC), a
     * new socket() / connect(), or a sendto() drop.  Separate from
     * silenced_write_count which counts silent-success writes. */
    uint32_t    cap_revoke_count;

    /* A3 · anomaly write-rate rule counters. */
    uint32_t    write_count;         /* total successful writes on this sotbox */
    uint32_t    anomaly_triggers;   /* count of rules that fired on this sotbox */

    /* CURVATURE-AUTOPROMOTE · per-sotbox curvature-alert counter.  Incremented
     * by the strong override of sotfs_graph_curvature_anomaly_notify() in
     * backends_sotfs.c each time a Forman-Ricci rule (RANSOMWARE / LATERAL)
     * fires attributed to this sotbox's synthetic_pid. */
    uint32_t    curvature_alerts;

    /* obsd-δ: pledge template bitmask + violation counter. */
    uint64_t    pledge;              /* PLEDGE_ALL = unrestricted (default) */
    uint32_t    pledge_violations;   /* counter for sotinfo / diagnostics */

    /* UNVEIL-CORE · OpenBSD-style per-path access table.  Default-permit
     * until first lucas_sys_unveil() call flips initialized=1. */
    lucas_unveil_state_t unveil;

    /* VFS · L2 mount table (populated by vfs_install_defaults). */
#define LUCAS_MAX_MOUNTS 12   /* install-arc · +/var (+headroom for /usr union, /etc) */
    vfs_mount_t mount_table[LUCAS_MAX_MOUNTS];

    /* === LUCAS-surface batch · pre-scaffolded sentinels ===
     * Each U-numbered worker inserts its struct fields under its named sentinel.
     * Do NOT insert outside your anomaly.  Do NOT reorder existing fields.
     * Anomalys stay after merge as ownership markers for future readers. */

    /* === U1 · signals · owned by signals-real worker === */
    uint64_t signal_handlers[64];  /* handler ptr per signal · 0 = SIG_DFL */
    uint64_t signal_flags[64];     /* sa_flags per signal · SA_RESTORER etc */
    uint64_t signal_restorers[64]; /* sa_restorer ptr per signal (trampoline) */
    uint64_t signal_sa_mask[64];   /* sa_mask per signal · applied during delivery */
    uint64_t signal_mask;          /* current sigprocmask · bits 0-63 = sig 1-64 */
    uint8_t  pending_signals[8];   /* small queue · signal numbers */
    int      n_pending;            /* count of valid entries in pending_signals */
    uint64_t sigaltstack_sp;       /* alt stack pointer (0 if not set) */
    size_t   sigaltstack_size;
    int      in_signal_handler;    /* nonzero while running a handler · prevents re-entry storms */

    /* === U2 · threading · owned by futex+clone worker ===
     *
     * PR 13 promoted thread_list[] from a bare cap array to a struct array
     * so each cloned thread carries:
     *   - tcb           · the seL4 TCB cap (was the only field pre-PR-13)
     *   - procd_tid     · procd-assigned synthetic_tid from the OP_CLONE reply ·
     *                     needed by OP_THREAD_EXIT + OP_SET_ROBUST so the
     *                     announce addresses the same thread_t entry that
     *                     was minted at clone-announce time.
     *   - robust_list_head · per-thread head pointer published by
     *                     set_robust_list(2) · walked on thread exit to
     *                     mark owned robust mutexes with FUTEX_OWNER_DIED.
     *   - clear_tid_ptr · userspace address the kernel zeroes on thread
     *                     exit + wakes via futex(addr, 1).  Mirror of the
     *                     procd-side thread_t.clear_tid_ptr · plumbed
     *                     locally for per-thread exit path. */
    struct {
        seL4_CPtr  tcb;                 /* 0 = empty slot */
        uint32_t   procd_tid;           /* tid assigned by procd at clone announce · 0 if not announced */
        uint64_t   robust_list_head;    /* per-thread robust list head ptr · 0 = none registered */
        uint64_t   clear_tid_ptr;       /* per-thread clear_child_tid · 0 = none registered */
    } thread_list[16];  /* 8 -> 16 · GTK/GLib's thread pool spawns 9 threads (cap-8 → the 9th create EAGAIN'd + the SP-match stale-slot path → garbage-register child thread → #GP) */
    int       n_threads;
    /* L8-set_tid · Linux clear_child_tid: address in the calling thread's
     * user space that the kernel zeroes on thread exit (futex wake target
     * for joiners).  Stored verbatim from set_tid_address(tidptr) so a
     * future on-exit path can honour the contract.  Currently unused on
     * the exit side; set_tid_address still returns synthetic_pid unchanged. */
    uint64_t  clear_child_tid;
    struct {
        uint64_t  addr;             /* userspace address being waited on */
        seL4_CPtr reply_cap;        /* saved reply for blocked sotbox */
        int       owner_slot;       /* sotbox slot of waiter */
        int       in_use;
        uint32_t  bitset;           /* PR 12 · WAIT_BITSET filter (default ~0u) */
        seL4_CPtr parked_tcb;       /* the THREAD that called FUTEX_WAIT (NOT
                                     * necessarily client_tcb in a multi-thread
                                     * box) · the wake fixup restores ITS regs */
    } futex_waiters[32];
    int       n_futex_waiters;
    /* The TCB that issued the syscall currently being dispatched.  Set by
     * lucas_handle_one_fault (the SP-matched faulting thread) before
     * lucas_dispatch_call so a parking syscall (FUTEX_WAIT) can record WHICH
     * thread to restore at wake.  In a single-thread box this == client_tcb. */
    seL4_CPtr cur_fault_tcb;
    int       next_tid;             /* monotonic per-state thread id allocator */

    /* === U3 · epoll · owned by io-mux worker === */
    struct {
        int      in_use;
        int      epfd;             /* LUCAS fd allocated by epoll_create1 */
        struct {
            int      fd;
            uint32_t events;       /* EPOLLIN, EPOLLOUT, etc. */
            uint64_t user_data;    /* opaque from epoll_event.data */
        } entries[16];
        int      n_entries;
    } epoll_table[8];
    int n_epoll_instances;
    /* When blocked in epoll_wait: which slot we're waiting on. */
    int epoll_wait_slot;           /* -1 when not waiting */
    /* Saved args for resumption from blocking epoll_wait. */
    uintptr_t epoll_wait_events_vaddr;
    int       epoll_wait_maxevents;
    /* apt arc · saved args for resumption from a blocking poll() parked on a
     * not-ready pipe-read fd (SOTBOX_STATE_WAITING_FOR_POLL). */
    uintptr_t    poll_wait_fds_vaddr;
    unsigned int poll_wait_nfds;
    /* apt arc · saved args for resumption from a blocking (p)select() parked on
     * a not-ready pipe-read fd (SOTBOX_STATE_WAITING_FOR_SELECT).  We also keep
     * a COPY of the ORIGINAL read-set bitmap because iomux_select_scan
     * destructively overwrites the client's rfds with the result on each scan;
     * the wake re-scan restores this copy into the client set first.  (LUCAS_MAX
     * _FDS=64 → exactly one 64-bit word.) */
    int          sel_wait_nfds;
    uintptr_t    sel_wait_rfds_vaddr;
    uintptr_t    sel_wait_wfds_vaddr;
    uintptr_t    sel_wait_efds_vaddr;
    uint64_t     sel_wait_rfds_orig[(LUCAS_MAX_FDS + 63) / 64];

    /* === U4 · shmem · owned by shmem worker === */

    /* === U5 · mprotect · owned by mprotect worker === */

    /* === U6 · small-stubs · owned by small-stubs worker === */
    uint64_t robust_list_head;
    size_t   robust_list_len;
    uint64_t rseq_addr;
    int      rseq_registered;
    uint64_t eventfd_counters[8];  /* indexed by fd slot · sized matching LUCAS_MAX_FDS / 2 */
    int      n_eventfds;

    /* === U7 · fcntl/openat · owned by fs-extensions worker === */

    /* MS-M3 scaffold · interpreter path captured by elf_loader when
     * PT_INTERP is present.  Populated by future dynamic-loader work. */
    char interp_path[128];

    /* Wine M1 · the program's own absolute path (argv[0] at spawn/execve), for
     * /proc/self/exe.  Wine's launcher reads /proc/self/exe to derive the install
     * dir (→ the preloader + loader paths).  Set from an ABSOLUTE argv[0] in
     * lucas_stack_setup; /proc/self/exe returns it for TRUSTED guests, falling
     * back to the /bin/busybox deception default for untrusted attacker shells. */
    char exe_path[128];

    /* OBSD-ε MSYSCALL · per-sotbox count of UnknownSyscall faults whose
     * syscall-site RIP fell outside the legitimate ELF .text range.
     * Incremented in lucas_handle_one_fault and used by the anomaly to
     * auto-promote the offending sotbox to Tier-2 (STAR deception · the
     * malware "feels like" its exploit worked but ends up in the
     * synth layer).  Placed at end of struct to avoid disturbing any
     * implicit field offsets used elsewhere. */
    uint32_t    msyscall_violations;

    /* γ · PR 3 · pending SOTFS hint bits (SOTFS_HINT_* in wal_ipc.h).
     * Producer (PR 4 · lucas write/openat F_persistence detector) sets
     * this just before invoking the sotfs VFS op; the sotfs backend
     * (backends_sotfs.c · op_open create branch + op_write) inspects it
     * after resolving/allocating the target inode and stamps
     * inode->functor_persistence.  Cleared by the backend after apply
     * so a single hint never bleeds across distinct ops. */
    uint32_t    pending_sotfs_hint;

    /* P2a · zero-leak teardown ownership flags.
     * seL4_objects_owned == 1 once sotbox_init / sotbox_fork has fully built
     * the client's seL4 objects (vspace + TCB + CNode + IPC frame + fault EP)
     * and resumed the child.  sotbox_destroy() is a no-op unless this is set,
     * so spawn-FAILURE paths (which return before the flag is set) and sibling
     * slots stay safe no-ops.  forked == 1 marks a child built by sotbox_fork:
     * its TEXT frames are cap-COPIES of the LIVE parent's frames, so its vspace
     * must be torn down WITHOUT freeing the shared frame objects (B2). */
    int         seL4_objects_owned;
    int         forked;

    /* P2b · anti-DoS fork-bomb containment. */
    uint32_t fork_attempts;     /* cumulative fork+clone calls (success OR -EAGAIN) */
    int      marked_for_teardown;            /* 1 = flagged for teardown (quarantined hostile cell/subtree) */
    int      parent_slot;       /* fork parent's slot_index; -1 for the primary / non-forked */
    int      child_storage_idx; /* fork.c child_storage[] index, or -1; freed on reap */

    /* v1.0-rc1 lifetime fix · slot whose per-sotbox ARENA owns the TEXT+RODATA
     * frame OBJECTS this sotbox executes from.  A forked child's 0x400000 text
     * is RO cap-COPIES of the parent's arena frames (share_region_ro); revoking
     * the parent arena deletes those frame objects, so a still-runnable child
     * would ifetch-fault at its ELF entry.  INVARIANT: before sotbox_destroy()
     * revokes an owner's arena, every live sotbox with
     * forked && text_owner_slot == owner_slot must first be suspended+destroyed.
     * -1 = self-owned (primary spawn, no shared text). */
    int      text_owner_slot;

    /* WINE-M1 · TRUE vfork bookkeeping (clone(CLONE_VM|CLONE_VFORK, !CLONE_THREAD)).
     * A vfork child SHARES the parent's vspace (no copy-fork) and runs on the
     * live shared stack while the parent is parked in WAITING_FOR_VFORK; the
     * parent is resumed (rax=child_pid) only once the child execve()s into its
     * own fresh vspace or _exit()s.  This is what posix_spawn / glibc's
     * vfork-based exec helper needs — copy-fork hands the child a FROZEN stack
     * snapshot, so its vfork-continuation epilogue pops stale bytes and #GPs.
     *
     * Sentinels chosen so a memset(0) at spawn means "not a vfork participant":
     *   vfork_parent_slot1 : 1-based parent slot on the CHILD (0 = not a vfork child).
     *   vfork_child_pid    : on the PARENT, the pid to return when resumed.
     *   vfork_parent_tcb   : on the PARENT, the faulting TCB to write rax/rip into. */
    int       vfork_parent_slot1;
    int       vfork_child_pid;
    seL4_CPtr vfork_parent_tcb;
} lucas_state_t;

/* L8: current-caller accessor — set in handlers_fs.c before every VFS read
 * so that static_vfs op_read can attribute canary access to the right sotBox. */
extern lucas_state_t *g_current_caller_st;
void  lucas_set_current_caller(lucas_state_t *st);
lucas_state_t *lucas_get_current_caller(void);

/* vDSO arc · Task 4 · map [vvar][vdso] into st->client_vspace_abs at
 * SOTOS_VDSO_BASE and fill the vvar page (lucas_vvar_fill).  Defined in
 * src/orch/vdso_map.c — resolved at orch link time (the vdso.so blob is
 * embedded in the orchestrator), like sotbox_alloc_slot.  Returns 0 on
 * success, -1 on failure (non-fatal: guest libc falls back to syscalls). */
int lucas_map_vdso(lucas_state_t *st);

/* Fidelity · cwd-aware path resolution (defined in handlers_fs.c). */
void    lucas_resolve_path(lucas_state_t *st, const char *in, char *out, size_t outsz);
/* chdir core: resolve `in` against cwd, verify it's a directory in the VFS, and
 * store it as the new cwd. Returns 0 or a negative Linux errno. */
int64_t lucas_chdir_resolve(lucas_state_t *st, const char *in);

#endif /* SOTOS_LUCAS_STATE_H */
