/* sotOs apk-fs slice-2 · dynamically-linked PIE · DT_NEEDED = [libspikelib.so, libc.so].
 * Calls spk_probe() (in libspikelib.so · runtime-mmap'd FROM THE SESSION UPPER).
 * The gate stages BOTH the .so and this client into the per-session upper, then
 * execs this binary: ld-musl must resolve libspikelib.so from the upper. */
#include <unistd.h>
extern int spk_probe(void);
int main(void) {
    int v = spk_probe();
    if (v == 0x5DC) write(1, "[spike] upper-so OK\n", 20);
    else            write(1, "[spike] upper-so FAIL\n", 22);
    return 0;
}
