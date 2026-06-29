#include "lucas/apk_ioc.h"
#include <string.h>
int apk_is_db_install_path(const char *path)
{
    if (!path) return 0;
    /* /lib/apk/db/installed (+ apk writes installed.<pid> then renames it) */
    if (strncmp(path, "/lib/apk/db/installed", 21) == 0) return 1;
    if (strcmp(path, "/etc/apk/world") == 0) return 1;
    return 0;
}
