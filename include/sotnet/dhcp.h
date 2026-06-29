/*
 * sotOs · sotNet · DHCP client (RFC 2131) · N1 worker
 *
 * Tiny client that runs once at orch bootstrap, against the QEMU built-in
 * user-mode DHCP server at 10.0.2.2.  Drives the four-step handshake:
 *   DISCOVER (broadcast) -> OFFER -> REQUEST (broadcast) -> ACK
 * and on success calls sotnet_init(leased_ip).  On any failure (timeout,
 * malformed reply) it falls back to the hard-coded address 10.0.2.15
 * (0x0F02000A in network byte order).
 *
 * The function is intentionally synchronous and bounded — it returns 0
 * unconditionally so the rest of bootstrap never stalls on a missing
 * server.
 */
#ifndef SOTNET_DHCP_H
#define SOTNET_DHCP_H

#include <stdint.h>
#include <stddef.h>

/*
 * sotnet_dhcp_acquire_or_fallback:
 *   - Send a DHCPDISCOVER, wait briefly for an OFFER, then DHCPREQUEST and
 *     wait for an ACK.
 *   - On full success: calls sotnet_init(leased_ip_be) and logs the trace.
 *   - On timeout or malformed reply: calls sotnet_init(0x0F02000A).
 *   - Always returns 0.
 */
int sotnet_dhcp_acquire_or_fallback(void);

#endif /* SOTNET_DHCP_H */
