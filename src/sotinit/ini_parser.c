/* sotOs · sotinit · INI parser · bounded, no malloc.
 *
 * Supports systemd-style [Section] / Key=Value with `#` and `;` comments.
 * Whitespace around keys / values is trimmed; lines longer than 256 B are
 * truncated rather than split (a unit fragment with that much on a single
 * line is malformed by spec).
 *
 * The parser is intentionally callback-driven · the caller decides whether
 * a KV pair belongs in unit_t (PR 2), a cron timer entry (PR 8), or any
 * other consumer.  Section transitions reset state automatically.
 *
 * Spec: init-cron-scheduler-design §4.2.
 */
#include <string.h>
#include <sotinit/ini.h>

static ini_section_t section_from_name(const char *name) {
    if (strcmp(name, "Unit")    == 0) return INI_SECTION_UNIT;
    if (strcmp(name, "Service") == 0) return INI_SECTION_SERVICE;
    if (strcmp(name, "Timer")   == 0) return INI_SECTION_TIMER;
    if (strcmp(name, "Install") == 0) return INI_SECTION_INSTALL;
    return INI_SECTION_NONE;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                        end[-1] == '\n' || end[-1] == '\r'))
        end--;
    *end = 0;
    return s;
}

int sotinit_ini_parse(const char *buf, size_t len,
                      ini_kv_cb cb, void *userdata) {
    char line[256];
    size_t i = 0;
    int kv_count = 0;
    ini_section_t current = INI_SECTION_NONE;

    while (i < len) {
        size_t j = 0;
        while (i < len && buf[i] != '\n' && j < sizeof(line) - 1) {
            line[j++] = buf[i++];
        }
        line[j] = 0;
        /* Skip the rest of the line if it overflowed the 256 B buffer so
         * the next iteration starts on a clean line. */
        while (i < len && buf[i] != '\n') i++;
        if (i < len && buf[i] == '\n') i++;

        char *trimmed = trim(line);
        if (*trimmed == 0 || *trimmed == '#' || *trimmed == ';') continue;

        if (*trimmed == '[') {
            char *close = strchr(trimmed, ']');
            if (close) {
                *close = 0;
                current = section_from_name(trimmed + 1);
            }
            continue;
        }

        char *eq = strchr(trimmed, '=');
        if (!eq) continue;
        *eq = 0;
        char *key   = trim(trimmed);
        char *value = trim(eq + 1);

        if (cb(current, key, value, userdata) == 0) {
            kv_count++;
        }
    }
    return kv_count;
}
