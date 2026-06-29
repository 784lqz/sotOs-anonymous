/* sotOs v2-real-vfs gate · a real .so reachable ONLY via the SONAME symlink
 * libvfsprobe.so -> libvfsprobe.so.1 (exercises sysroot symlink-follow). */
volatile int vfs_state = 0x5A;
int vfs_probe(void) { return vfs_state; }
