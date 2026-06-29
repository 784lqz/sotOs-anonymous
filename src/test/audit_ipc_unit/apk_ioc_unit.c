/* Host unit · the apk-DB-install path predicate. */
#include <assert.h>
#include <stdio.h>
#include "lucas/apk_ioc.h"

int main(void) {
    assert(apk_is_db_install_path("/lib/apk/db/installed") == 1);
    assert(apk_is_db_install_path("/lib/apk/db/installed.12345") == 1); /* apk temp-then-rename */
    assert(apk_is_db_install_path("/etc/apk/world") == 1);
    assert(apk_is_db_install_path("/etc/passwd") == 0);
    assert(apk_is_db_install_path("/usr/bin/bc") == 0);
    assert(apk_is_db_install_path(0) == 0);
    printf("[apk-ioc-unit] PATH->IOC MAPPING PASS\n");
    return 0;
}
