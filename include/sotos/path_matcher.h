/* sotOs · F_persistence path matcher · γ.
 *
 * Heuristic detector for "persistence install" sensitive paths.
 * Used by lucas to flag Tier-2 sotbox writes to crontab / unit files / rc files.
 *
 * Pure C, no malloc, bounded scan.
 */
#ifndef SOTOS_PATH_MATCHER_H
#define SOTOS_PATH_MATCHER_H

#include <stdbool.h>

bool sotos_path_is_persistence_sensitive(const char *path);

/* Spec B · credential-bearing path classifier.  True for paths whose
 * READ is a credential-recon signal (drives the anomaly suspicion
 * score independent of tier).  Distinct from canary_read_count, which
 * only counts at Tier 2. */
bool sotos_path_is_cred_sensitive(const char *path);

/* Helpers exposed for testing. */
bool sotos_path_has_suffix(const char *path, const char *suffix);
bool sotos_path_starts_with(const char *path, const char *prefix);

#endif
