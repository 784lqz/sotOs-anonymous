#ifndef LUCAS_APK_IOC_H
#define LUCAS_APK_IOC_H
/* 1 if `path` is an apk DB-install path (the apk DB or the world file, incl.
 * apk's temp-suffixed atomic-rename variants). Pure · host-unit-testable. */
int apk_is_db_install_path(const char *path);
#endif
