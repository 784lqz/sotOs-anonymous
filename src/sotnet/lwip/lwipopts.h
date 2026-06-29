/* SPDX-License-Identifier: BSD-3-Clause
 *
 * sotOs lwIP configuration · egress (outbound) TCP/IP stack.
 *
 * This is the SOURCE OF TRUTH for the lwIP build config.  external/ is cloned by
 * bootstrap and gitignored, so bootstrap.sh copies this file into the cloned
 * util_libs/liblwip/include/lwipopts.h (liblwip's CMake puts that dir on the lwip
 * target's include path).  Based on liblwip's default_opts template, tuned for a
 * real egress download (apk/apt/pip) on QEMU virtio-net.
 *
 * Mode: NO_SYS=1 (no OS abstraction layer / no threads) + LWIP_TIMERS=1 — orch
 * drives the stack single-threaded: feed RX frames to lwIP's netif input, call
 * sys_check_timeouts() from the loop, and provide sys_now() (TSC-based ms).  The
 * raw/callback API (tcp_new/tcp_connect/tcp_recv) is used for egress; sockets
 * (LWIP_SOCKET) would need NO_SYS=0 + a sys_arch and are deferred.
 */

#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

#define NO_SYS                          1
/* TCP needs the timeout subsystem (retransmit / TIME_WAIT / delayed-ACK).
 * NO_SYS=1 + LWIP_TIMERS=1 → we provide sys_now() and call sys_check_timeouts(). */
#define NO_SYS_NO_TIMERS                0
#define LWIP_TIMERS                     1
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0
#define LWIP_RAND                       rand

#define MEM_ALIGNMENT 4
/* ALL lwIP memory (heap + pools + pbufs + PCBs) must be DMA-pinnable, because the
 * libethdrivers TX path pins pbuf payloads to hand the NIC a physical address
 * (lwip.c: ps_dma_pin + assert).  Route every allocation through the heap
 * (MEMP_MEM_MALLOC) and place the heap in a DMA-alloc'd buffer via
 * LWIP_RAM_HEAP_POINTER (orch sets oeg_lwip_heap before lwip_init).  Then every
 * pbuf lives in orch's ps_dma_man region → dma_pin returns a valid paddr. */
#define MEMP_MEM_MALLOC                 1
/* 512 KiB heap.  With MEMP_MEM_MALLOC, ALL lwIP memory comes from here — including
 * the libethdrivers RX ring buffers (PBUF_RAM, ~2 KiB each, kept posted to the
 * virtio RX queue) + TX pbufs + PCBs.  At 128 KiB the heap exhausted right around
 * the download's ~138 KB mark → fill_rx_bufs couldn't post buffers → the device
 * had nowhere to DMA → RX stalled though the host had data ready. */
#define MEM_SIZE                        0x80000          /* 512 KiB */
extern unsigned char *oeg_lwip_heap;                    /* set by orch (lwip_egress.c) */
#define LWIP_RAM_HEAP_POINTER           oeg_lwip_heap

#define ETHARP_SUPPORT_STATIC_ENTRIES   1
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_NETIF_STATUS_CALLBACK      1

/* Ethernet MSS + a coherent window/pool budget.  liblwip's default had
 * TCP_WND=100*MSS but default PBUF_POOL sizing (16 * ~592 B) → the
 * lwip_sanity_check #error; size the pbuf pool to cover the window. */
#define TCP_MSS                         1460
#define TCP_SND_QUEUELEN                256
#define MEMP_NUM_TCP_SEG                TCP_SND_QUEUELEN
#define TCP_SND_BUF                     (24 * TCP_MSS)   /* ~35 KiB */
#define TCP_WND                         (24 * TCP_MSS)   /* ~35 KiB */
#define PBUF_POOL_SIZE                  48               /* 48 * 1536 = 72 KiB > TCP_WND */
#define PBUF_POOL_BUFSIZE               1536             /* MSS + eth/ip/tcp headers */
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   0

#endif /* __LWIPOPTS_H__ */
