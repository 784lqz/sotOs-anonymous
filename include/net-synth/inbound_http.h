/* sotOs · net-synth · N2-R Phase A · inbound HTTP response_profile router.
 * Pure + transport/TLS-agnostic: takes a raw request buffer, writes a complete
 * HTTP/1.1 response into out[]. Reused by Phase C INSIDE the TLS tunnel. */
#ifndef NET_SYNTH_INBOUND_HTTP_H
#define NET_SYNTH_INBOUND_HTTP_H
#include <stdint.h>
#include <stddef.h>
/* Parse the request line of `req` (method+path), build a credible Nginx
 * response into out[0..outmax). Returns the response length (>0), never 0
 * (a lenient honeypot always answers). */
uint32_t http_route(const uint8_t *req, uint32_t reqlen, uint8_t *out, uint32_t outmax);
#endif
