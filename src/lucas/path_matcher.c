/* sotOs · F_persistence path matcher · γ.
 *
 * Heuristic: suffix + parent-dir prefix + exact-match whitelist.
 * Covers crontab, systemd units, freedesktop autostart, shell rc files.
 */
#include <stddef.h>
#include <string.h>

#include <sotos/path_matcher.h>

bool sotos_path_has_suffix(const char *path, const char *suffix) {
    if (!path || !suffix) return false;
    size_t lp = strlen(path);
    size_t ls = strlen(suffix);
    if (ls > lp) return false;
    return strcmp(path + (lp - ls), suffix) == 0;
}

bool sotos_path_starts_with(const char *path, const char *prefix) {
    if (!path || !prefix) return false;
    return strncmp(path, prefix, strlen(prefix)) == 0;
}

bool sotos_path_is_persistence_sensitive(const char *path) {
    if (!path || !path[0]) return false;

    /* 1. Suffix match · systemd / freedesktop. */
    if (sotos_path_has_suffix(path, ".service")) return true;
    if (sotos_path_has_suffix(path, ".timer"))   return true;
    if (sotos_path_has_suffix(path, ".desktop")) return true;

    /* 2. Parent-dir prefix · cron / systemd / autostart. */
    if (sotos_path_starts_with(path, "/etc/cron."))               return true;
    if (sotos_path_starts_with(path, "/etc/systemd/system/"))     return true;
    if (sotos_path_starts_with(path, "/root/.config/autostart/")) return true;

    /* 3. Exact match · classic rc files + crontab + profile. */
    static const char *exact[] = {
        "/etc/crontab", "/etc/profile",
        "/root/.bashrc", "/root/.bash_profile", "/root/.profile",
        NULL
    };
    for (int i = 0; exact[i]; i++)
        if (strcmp(path, exact[i]) == 0) return true;

    return false;
}

bool sotos_path_is_cred_sensitive(const char *path) {
    if (!path || !path[0]) return false;

    /* 1. Exact credential files.  Real secrets only · /etc/passwd is
     * deliberately EXCLUDED: it is world-readable and read by routine
     * libc/NSS calls (getpwuid, login, ls -l), so weighting it as
     * cred-access falsely promotes benign processes to Tier 1.  The
     * actual secrets (hashes, sudoers) stay.  (/canary-* paths are
     * covered by the prefix rule below, so they are NOT listed here.) */
    static const char *const exact[] = {
        "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
        NULL
    };
    for (int i = 0; exact[i]; i++)
        if (strcmp(path, exact[i]) == 0) return true;

    /* 2. Canary mount (vfs aliases /canary-* to the sotfs canary install ·
     * includes /honey-aws-creds). */
    if (sotos_path_starts_with(path, "/canary-")) return true;

    /* 3. SSH / cloud key material. */
    if (sotos_path_starts_with(path, "/root/.ssh/")) return true;
    if (sotos_path_starts_with(path, "/home/") &&
        sotos_path_has_suffix(path, "/credentials")) return true;
    if (sotos_path_has_suffix(path, ".pem")) return true;
    if (sotos_path_has_suffix(path, ".key")) return true;

    return false;
}
