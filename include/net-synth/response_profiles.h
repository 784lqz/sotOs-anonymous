#ifndef NET_SYNTH_RESPONSE_PROFILES_H
#define NET_SYNTH_RESPONSE_PROFILES_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ResponseProfile kinds · shared between the synth (writer of responses) and
 * sotShell (which maps an operator name → a kind before installing). */
typedef enum {
    RESPONSE_PROFILE_UNKNOWN = 0,
    RESPONSE_PROFILE_SYNTHETIC_C2,
    RESPONSE_PROFILE_SYNTHETIC_UPDATER,
    RESPONSE_PROFILE_SYNTHETIC_DNS,
    RESPONSE_PROFILE_SYNTHETIC_BANK_LOGIN,
    RESPONSE_PROFILE_SYNTHETIC_SUPPLY_CHAIN,
} response_profile_kind_t;

/* Operator response_profile name → kind.  Inline so sotShell gets it via the header
 * without linking the synth's response_profiles.c.  Unknown name → RESPONSE_PROFILE_UNKNOWN. */
static inline response_profile_kind_t response_profile_name_to_kind(const char *name) {
    if (!name) return RESPONSE_PROFILE_UNKNOWN;
    if (strcmp(name, "c2-ack") == 0)  return RESPONSE_PROFILE_SYNTHETIC_C2;
    if (strcmp(name, "updater") == 0) return RESPONSE_PROFILE_SYNTHETIC_UPDATER;
    if (strcmp(name, "dns") == 0)     return RESPONSE_PROFILE_SYNTHETIC_DNS;
    if (strcmp(name, "bank") == 0)    return RESPONSE_PROFILE_SYNTHETIC_BANK_LOGIN;
    if (strcmp(name, "supply") == 0)  return RESPONSE_PROFILE_SYNTHETIC_SUPPLY_CHAIN;
    return RESPONSE_PROFILE_UNKNOWN;
}

void response_profile_dispatch(uint32_t pid, uint32_t dst_ip_be, uint16_t dst_port_be, uint32_t len);

/* Phase 3-C: returns 0+fills buffers if response_profile found, -1 otherwise. */
int response_profile_get_payload(uint32_t dst_ip_be, uint16_t dst_port_be,
                        char *out_banner, size_t banner_max,
                        char *out_body,   size_t body_max);

/* γ-3-ε · install/override the runtime response_profile for a destination.
 * Returns 0 on success, -1 if the runtime table is full or kind is unknown. */
int response_profile_install(uint32_t dst_ip_be, uint16_t dst_port_be, response_profile_kind_t kind);

/* Canonical banner+body templates per kind (used by the runtime table). */
void response_profile_template(response_profile_kind_t kind,
                      const char **out_banner, const char **out_body);

#endif
