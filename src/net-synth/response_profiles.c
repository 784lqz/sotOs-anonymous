/*
 * sotOs · sotOs-net-synth · response_profile dispatch.
 *
 * Maps (dst_ip, dst_port) → scripted response_profile.  Phase 3-B serves
 * an HTTP-shaped log line per redirect; Phase 3-C will emit real
 * bytes back to the sotbox connection.
 */
#include <net-synth/response_profiles.h>
#include <stdio.h>
#include <string.h>

void response_profile_template(response_profile_kind_t kind,
                      const char **out_banner, const char **out_body) {
    const char *banner = "", *body = "";
    switch (kind) {
        case RESPONSE_PROFILE_SYNTHETIC_C2:
            banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.26.3\r\n\r\n";
            body   = "ACK 7d9a · NEXT-STAGE-PAYLOAD-URL: hxxp://shell.example/x.bin";
            break;
        case RESPONSE_PROFILE_SYNTHETIC_UPDATER:
            banner = "HTTP/1.1 200 OK\r\nServer: update-server/2.0\r\n\r\n";
            body   = "{\"version\":\"1.0\",\"url\":\"trap://update.example/v1\"}";
            break;
        case RESPONSE_PROFILE_SYNTHETIC_DNS:
            banner = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\n";
            body   = "synthetic-doh-answer";
            break;
        case RESPONSE_PROFILE_SYNTHETIC_BANK_LOGIN:
            banner = "HTTP/1.1 200 OK\r\nServer: apache\r\n\r\n";
            body   = "<html><form>synthetic bank login</form></html>";
            break;
        case RESPONSE_PROFILE_SYNTHETIC_SUPPLY_CHAIN:
            banner = "HTTP/1.1 200 OK\r\nServer: registry/1.0\r\n\r\n";
            body   = "{\"dist\":{\"tarball\":\"trap://registry.example/p.tgz\"}}";
            break;
        default: break;
    }
    if (out_banner) *out_banner = banner;
    if (out_body)   *out_body   = body;
}

static const struct {
    uint32_t dst_ip_be;
    uint16_t dst_port_be;
    response_profile_kind_t kind;
    const char *banner;
    const char *body_sample;
} g_response_profile_table[] = {
    /* malicious-c2.example. resolves to 10.0.2.15 via DNS deception
     * (sotNet-ε · commit 35d3036) · synth catches the connect. */
    { 0x0F02000A, 0x0050,  /* :80 */  RESPONSE_PROFILE_SYNTHETIC_C2,
      "HTTP/1.1 200 OK\r\nServer: nginx/1.26.3\r\n\r\n",
      "ACK 7d9a · NEXT-STAGE-PAYLOAD-URL: hxxp://shell.example/x.bin" },
    { 0x0F02000A, 0x01BB,  /* :443 · would TLS · Phase 3-C */ RESPONSE_PROFILE_SYNTHETIC_C2,
      "TLS handshake (Phase 3-C)", "encrypted payload (Phase 3-C)" },
    /* generic catch-all for outbound web traffic */
    { 0x0F02000A, 0,  RESPONSE_PROFILE_SYNTHETIC_UPDATER,
      "HTTP/1.1 200 OK\r\nServer: update-server/2.0\r\n\r\n",
      "{\"version\":\"1.0\",\"url\":\"trap://update.example/v1\"}" },
    /* γ-3-γ-2c-fix · the sotOs-tls-probe fixture connects here
     * (dst_ip_be=0x077100CB = 203.0.113.7 · non-local → Tier-2 redirect).
     * Serve the synthetic-C2 response_profile so the responder's encrypted TLS app-data reply
     * IS that response_profile. Port 0 = any port on this IP (sidesteps the static
     * table's port byte-order subtlety). Safe now that response_profile_dispatch is
     * flattened to one line. */
    { 0x077100CB, 0,  RESPONSE_PROFILE_SYNTHETIC_C2,
      "HTTP/1.1 200 OK\r\nServer: nginx/1.26.3\r\n\r\n",
      "ACK 7d9a · NEXT-STAGE-PAYLOAD-URL: hxxp://shell.example/x.bin" },
};

#define RESPONSE_PROFILE_TABLE_SIZE (sizeof(g_response_profile_table) / sizeof(g_response_profile_table[0]))

/* γ-3-ε · operator-installed response_profiles · consulted BEFORE the static table.
 * Long-lived (the synth process never exits), so installs persist across
 * operator commands.  In-memory only · not durable across reboot. */
#define RUNTIME_RESPONSE_PROFILE_MAX 16
static struct {
    uint32_t       dst_ip_be;
    uint16_t       dst_port_be;
    response_profile_kind_t kind;
    int            used;
} g_runtime_response_profiles[RUNTIME_RESPONSE_PROFILE_MAX];

int response_profile_install(uint32_t dst_ip_be, uint16_t dst_port_be, response_profile_kind_t kind) {
    if (kind == RESPONSE_PROFILE_UNKNOWN) return -1;
    /* Replace an existing entry for the same (ip,port). */
    for (int i = 0; i < RUNTIME_RESPONSE_PROFILE_MAX; ++i) {
        if (g_runtime_response_profiles[i].used &&
            g_runtime_response_profiles[i].dst_ip_be == dst_ip_be &&
            g_runtime_response_profiles[i].dst_port_be == dst_port_be) {
            g_runtime_response_profiles[i].kind = kind;
            return 0;
        }
    }
    /* Else take the first free slot. */
    for (int i = 0; i < RUNTIME_RESPONSE_PROFILE_MAX; ++i) {
        if (!g_runtime_response_profiles[i].used) {
            g_runtime_response_profiles[i].dst_ip_be  = dst_ip_be;
            g_runtime_response_profiles[i].dst_port_be = dst_port_be;
            g_runtime_response_profiles[i].kind       = kind;
            g_runtime_response_profiles[i].used       = 1;
            return 0;
        }
    }
    return -1;   /* table full */
}

/* Runtime lookup · returns the installed kind for (ip,port), or RESPONSE_PROFILE_UNKNOWN.
 * Port 0 in a install entry is a catch-all for any port on that IP. */
static response_profile_kind_t runtime_response_profile_lookup(uint32_t dst_ip_be, uint16_t dst_port_be) {
    for (int i = 0; i < RUNTIME_RESPONSE_PROFILE_MAX; ++i) {
        if (!g_runtime_response_profiles[i].used) continue;
        if (g_runtime_response_profiles[i].dst_ip_be != dst_ip_be) continue;
        if (g_runtime_response_profiles[i].dst_port_be != 0 &&
            g_runtime_response_profiles[i].dst_port_be != dst_port_be) continue;
        return g_runtime_response_profiles[i].kind;
    }
    return RESPONSE_PROFILE_UNKNOWN;
}

/* response_profile_get_payload · Phase 3-C accessor.
 * Returns 0 + fills out_banner/out_body if a response_profile is found for the given
 * (dst_ip_be, dst_port_be).  Returns -1 if no response_profile matches. */
int response_profile_get_payload(uint32_t dst_ip_be, uint16_t dst_port_be,
                        char *out_banner, size_t banner_max,
                        char *out_body,   size_t body_max)
{
    response_profile_kind_t rk = runtime_response_profile_lookup(dst_ip_be, dst_port_be);
    if (rk != RESPONSE_PROFILE_UNKNOWN) {
        const char *banner = NULL, *body = NULL;
        response_profile_template(rk, &banner, &body);
        if (out_banner && banner_max > 0) {
            size_t blen = banner ? strlen(banner) : 0;
            if (blen >= banner_max) blen = banner_max - 1;
            if (banner) memcpy(out_banner, banner, blen);
            out_banner[blen] = '\0';
        }
        if (out_body && body_max > 0) {
            size_t blen = body ? strlen(body) : 0;
            if (blen >= body_max) blen = body_max - 1;
            if (body) memcpy(out_body, body, blen);
            out_body[blen] = '\0';
        }
        return 0;
    }
    for (size_t i = 0; i < RESPONSE_PROFILE_TABLE_SIZE; ++i) {
        if (g_response_profile_table[i].dst_ip_be != dst_ip_be) continue;
        if (g_response_profile_table[i].dst_port_be != 0 &&
            g_response_profile_table[i].dst_port_be != dst_port_be) continue;
        if (out_banner && banner_max > 0 && g_response_profile_table[i].banner) {
            size_t blen = strlen(g_response_profile_table[i].banner);
            if (blen >= banner_max) blen = banner_max - 1;
            memcpy(out_banner, g_response_profile_table[i].banner, blen);
            out_banner[blen] = '\0';
        } else if (out_banner && banner_max > 0) {
            out_banner[0] = '\0';
        }
        if (out_body && body_max > 0 && g_response_profile_table[i].body_sample) {
            size_t blen = strlen(g_response_profile_table[i].body_sample);
            if (blen >= body_max) blen = body_max - 1;
            memcpy(out_body, g_response_profile_table[i].body_sample, blen);
            out_body[blen] = '\0';
        } else if (out_body && body_max > 0) {
            out_body[0] = '\0';
        }
        return 0;
    }
    return -1;
}

void response_profile_dispatch(uint32_t pid, uint32_t dst_ip_be, uint16_t dst_port_be, uint32_t len) {
    response_profile_kind_t kind = runtime_response_profile_lookup(dst_ip_be, dst_port_be);
    if (kind == RESPONSE_PROFILE_UNKNOWN) {
        for (size_t i = 0; i < RESPONSE_PROFILE_TABLE_SIZE; ++i) {
            if (g_response_profile_table[i].dst_ip_be != dst_ip_be) continue;
            if (g_response_profile_table[i].dst_port_be != 0 &&
                g_response_profile_table[i].dst_port_be != dst_port_be) continue;
            kind = g_response_profile_table[i].kind;
            break;
        }
    }

    const char *kind_str = "unknown";
    switch (kind) {
        case RESPONSE_PROFILE_SYNTHETIC_C2:           kind_str = "SYNTHETIC-C2"; break;
        case RESPONSE_PROFILE_SYNTHETIC_UPDATER:      kind_str = "SYNTHETIC-UPDATER"; break;
        case RESPONSE_PROFILE_SYNTHETIC_DNS:          kind_str = "SYNTHETIC-DNS"; break;
        case RESPONSE_PROFILE_SYNTHETIC_BANK_LOGIN:   kind_str = "SYNTHETIC-BANK-LOGIN"; break;
        case RESPONSE_PROFILE_SYNTHETIC_SUPPLY_CHAIN: kind_str = "SYNTHETIC-SUPPLY-CHAIN"; break;
        default: break;
    }

    printf("[synth-srv] response_profile=%s · pid=%u dst=%u.%u.%u.%u:%u len=%u\n",
           kind_str, pid,
           dst_ip_be & 0xFF, (dst_ip_be >> 8) & 0xFF,
           (dst_ip_be >> 16) & 0xFF, (dst_ip_be >> 24) & 0xFF,
           ((dst_port_be & 0xFF) << 8) | ((dst_port_be >> 8) & 0xFF),
           len);
}
