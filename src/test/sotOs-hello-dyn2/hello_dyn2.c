/* sotOs N3/D2 · dynamically-linked PIE · DT_NEEDED = [libonefn.so, libc.so].
 * Calls d2_probe() (in libonefn.so · runtime-mmap'd) and prints the gate. */
#include <unistd.h>
extern int d2_probe(void);
int main(void) {
    int v = d2_probe();
    if (v == 0x0D2) write(1, "[hello-dyn2] libonefn OK\n", 25);
    else            write(1, "[hello-dyn2] libonefn FAIL\n", 27);
    return 0;
}
