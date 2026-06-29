/* sotOs · sotinit · INI-style parser (bounded, no malloc).
 *
 * Parses systemd-style unit fragments:
 *
 *   [Unit]
 *   Description=Some service
 *
 *   [Service]
 *   ExecStart=/bin/sotos-foo
 *
 * The parser is callback-driven so the caller decides where the KV pairs
 * land · PR 2 wires a populating callback into unit_t; PR 7 (sotcron) can
 * reuse the same parser for timer fragments without code duplication.
 *
 * No heap allocation · the implementation runs on a 256-byte stack line
 * buffer.  Lines longer than 256 B are truncated, NOT split.
 *
 * Spec: init-cron-scheduler-design §4.2.
 */
#ifndef SOTINIT_INI_H
#define SOTINIT_INI_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    INI_SECTION_NONE    = 0,
    INI_SECTION_UNIT    = 1,
    INI_SECTION_SERVICE = 2,
    INI_SECTION_TIMER   = 3,
    INI_SECTION_INSTALL = 4,
} ini_section_t;

/* Callback signature.  Return 0 to count the KV as accepted (sotinit_ini_parse
 * sums these into the returned kv_count); any non-zero return is treated as
 * "skip this KV" but does NOT abort parsing.  Userdata is opaque · the caller
 * threads its registry pointer / unit_t* through it. */
typedef int (*ini_kv_cb)(ini_section_t section,
                         const char *key, const char *value,
                         void *userdata);

int sotinit_ini_parse(const char *buf, size_t len,
                      ini_kv_cb cb, void *userdata);

#endif
