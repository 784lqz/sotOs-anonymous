/*
 * EXPERIMENT T5 · SYSCALL OVERHEAD / LATENCY MICROBENCH
 * 
 * Target: measure round-trip latency (fault -> lucas dispatch -> return) for
 * representative syscalls in sotOs vs native Alpine 3.20 / linux-lts 6.6.30.
 *
 * Syscalls tested (representative coverage):
 *   - getpid (getsyscall + return, fault-cost baseline)
 *   - read / write (VFS + buffer copy)
 *   - mmap (memory allocation)
 *   - open / close (FD mgmt + filesystem)
 *   - stat / lstat (filesystem metadata)
 *   - clock_gettime (time query)
 *
 * Design: tight inner loop, rdtsc bracketing, N=1,000,000 iterations,
 * report median + p95/p99 percentile latencies.
 *
 * Compile (native Alpine or cross-compile for guest):
 *   gcc -O2 -static -o microbench microbench.c -lc
 *
 * Run in sotOs (via binstored guest binary):
 *   sotos> bench syscall-latency
 *
 * Run on native Alpine:
 *   # ssh to :18022 (Alpine 3.20, linux-lts 6.6.30)
 *   $ ./microbench
 *
 * Output: CSV (machine-readable) + plaintext (human-readable) on stdout.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

/* Portable rdtsc · x86_64 CPU cycle counter (0 if unavailable on non-x86). */
static inline unsigned long rdtsc(void) {
#ifdef __x86_64__
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long)hi << 32) | lo;
#else
    return 0;
#endif
}

/* Statistics: compute median, p95, p99 from a sorted array. */
typedef struct {
    unsigned long median;
    unsigned long p95;
    unsigned long p99;
    unsigned long min;
    unsigned long max;
} stats_t;

static stats_t compute_stats(unsigned long *data, int n) {
    stats_t s = {0};
    if (n == 0) return s;
    
    s.min = data[0];
    s.max = data[n - 1];
    s.median = data[n / 2];
    s.p95 = data[(n * 95) / 100];
    s.p99 = data[(n * 99) / 100];
    return s;
}

/* qsort comparator for unsigned long. */
static int cmp_ulong(const void *a, const void *b) {
    unsigned long ua = *(unsigned long *)a;
    unsigned long ub = *(unsigned long *)b;
    return (ua > ub) - (ua < ub);
}

#define N_SAMPLES 1000000
#define WARMUP 1000

/* Test 1: getpid — baseline syscall cost (no payload). */
static stats_t bench_getpid(void) {
    unsigned long *latencies = malloc(N_SAMPLES * sizeof(unsigned long));
    if (!latencies) { perror("malloc"); exit(1); }
    
    /* Warmup. */
    for (int i = 0; i < WARMUP; i++) getpid();
    
    /* Measure. */
    for (int i = 0; i < N_SAMPLES; i++) {
        unsigned long t0 = rdtsc();
        pid_t p = getpid();
        unsigned long t1 = rdtsc();
        latencies[i] = t1 - t0;
        (void)p;  /* suppress unused */
    }
    
    qsort(latencies, N_SAMPLES, sizeof(unsigned long), cmp_ulong);
    stats_t s = compute_stats(latencies, N_SAMPLES);
    free(latencies);
    return s;
}

/* Test 2: read — VFS read from /proc/self/cmdline. */
static stats_t bench_read(void) {
    unsigned long *latencies = malloc(N_SAMPLES * sizeof(unsigned long));
    if (!latencies) { perror("malloc"); exit(1); }
    
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) { perror("open /proc/self/cmdline"); exit(1); }
    
    /* Warmup. */
    for (int i = 0; i < WARMUP; i++) {
        lseek(fd, 0, SEEK_SET);
        char buf[256];
        read(fd, buf, sizeof(buf));
    }
    
    /* Measure. */
    for (int i = 0; i < N_SAMPLES; i++) {
        lseek(fd, 0, SEEK_SET);
        char buf[256];
        unsigned long t0 = rdtsc();
        ssize_t n = read(fd, buf, sizeof(buf));
        unsigned long t1 = rdtsc();
        latencies[i] = t1 - t0;
        (void)n;  /* suppress unused */
    }
    
    close(fd);
    qsort(latencies, N_SAMPLES, sizeof(unsigned long), cmp_ulong);
    stats_t s = compute_stats(latencies, N_SAMPLES);
    free(latencies);
    return s;
}

/* Test 3: write — VFS write to /tmp. */
static stats_t bench_write(void) {
    unsigned long *latencies = malloc(N_SAMPLES * sizeof(unsigned long));
    if (!latencies) { perror("malloc"); exit(1); }
    
    int fd = open("/tmp/bench-write.tmp", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open /tmp/bench-write.tmp"); exit(1); }
    
    char buf[256];
    memset(buf, 'x', sizeof(buf));
    
    /* Warmup. */
    for (int i = 0; i < WARMUP; i++) {
        write(fd, buf, sizeof(buf));
    }
    
    /* Measure. */
    for (int i = 0; i < N_SAMPLES; i++) {
        unsigned long t0 = rdtsc();
        ssize_t n = write(fd, buf, sizeof(buf));
        unsigned long t1 = rdtsc();
        latencies[i] = t1 - t0;
        (void)n;  /* suppress unused */
    }
    
    close(fd);
    unlink("/tmp/bench-write.tmp");
    qsort(latencies, N_SAMPLES, sizeof(unsigned long), cmp_ulong);
    stats_t s = compute_stats(latencies, N_SAMPLES);
    free(latencies);
    return s;
}

/* Test 4: mmap — memory mapping. */
static stats_t bench_mmap(void) {
    unsigned long *latencies = malloc(N_SAMPLES * sizeof(unsigned long));
    if (!latencies) { perror("malloc"); exit(1); }
    
    int fd = open("/tmp/bench-mmap.tmp", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open /tmp/bench-mmap.tmp"); exit(1); }
    
    /* Pre-allocate file. */
    unsigned char page[4096];
    memset(page, 0, sizeof(page));
    for (int i = 0; i < 256; i++) write(fd, page, sizeof(page));
    close(fd);
    
    /* Warmup. */
    for (int i = 0; i < WARMUP; i++) {
        fd = open("/tmp/bench-mmap.tmp", O_RDONLY);
        void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (m != MAP_FAILED) munmap(m, 4096);
        close(fd);
    }
    
    /* Measure. */
    for (int i = 0; i < N_SAMPLES; i++) {
        fd = open("/tmp/bench-mmap.tmp", O_RDONLY);
        unsigned long t0 = rdtsc();
        void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        unsigned long t1 = rdtsc();
        latencies[i] = t1 - t0;
        if (m != MAP_FAILED) munmap(m, 4096);
        close(fd);
    }
    
    unlink("/tmp/bench-mmap.tmp");
    qsort(latencies, N_SAMPLES, sizeof(unsigned long), cmp_ulong);
    stats_t s = compute_stats(latencies, N_SAMPLES);
    free(latencies);
    return s;
}

/* Test 5: open / close — file descriptor management. */
static stats_t bench_open(void) {
    unsigned long *latencies = malloc(N_SAMPLES * sizeof(unsigned long));
    if (!latencies) { perror("malloc"); exit(1); }
    
    /* Create target file. */
    int fd = open("/tmp/bench-open.tmp", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open /tmp/bench-open.tmp"); exit(1); }
    close(fd);
    
    /* Warmup. */
    for (int i = 0; i < WARMUP; i++) {
        fd = open("/tmp/bench-open.tmp", O_RDONLY);
        if (fd >= 0) close(fd);
    }
    
    /* Measure. */
    for (int i = 0; i < N_SAMPLES; i++) {
        unsigned long t0 = rdtsc();
        fd = open("/tmp/bench-open.tmp", O_RDONLY);
        unsigned long t1 = rdtsc();
        latencies[i] = t1 - t0;
        if (fd >= 0) close(fd);
    }
    
    unlink("/tmp/bench-open.tmp");
    qsort(latencies, N_SAMPLES, sizeof(unsigned long), cmp_ulong);
    stats_t s = compute_stats(latencies, N_SAMPLES);
    free(latencies);
    return s;
}

/* Test 6: stat — filesystem metadata. */
static stats_t bench_stat(void) {
    unsigned long *latencies = malloc(N_SAMPLES * sizeof(unsigned long));
    if (!latencies) { perror("malloc"); exit(1); }
    
    /* Use /etc/passwd as stable file. */
    struct stat st;
    
    /* Warmup. */
    for (int i = 0; i < WARMUP; i++) {
        stat("/etc/passwd", &st);
    }
    
    /* Measure. */
    for (int i = 0; i < N_SAMPLES; i++) {
        unsigned long t0 = rdtsc();
        int r = stat("/etc/passwd", &st);
        unsigned long t1 = rdtsc();
        latencies[i] = t1 - t0;
        (void)r;  /* suppress unused */
    }
    
    qsort(latencies, N_SAMPLES, sizeof(unsigned long), cmp_ulong);
    stats_t s = compute_stats(latencies, N_SAMPLES);
    free(latencies);
    return s;
}

/* Test 7: clock_gettime — time query (CLOCK_MONOTONIC). */
static stats_t bench_clock_gettime(void) {
    unsigned long *latencies = malloc(N_SAMPLES * sizeof(unsigned long));
    if (!latencies) { perror("malloc"); exit(1); }
    
    struct timespec ts;
    
    /* Warmup. */
    for (int i = 0; i < WARMUP; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
    }
    
    /* Measure. */
    for (int i = 0; i < N_SAMPLES; i++) {
        unsigned long t0 = rdtsc();
        int r = clock_gettime(CLOCK_MONOTONIC, &ts);
        unsigned long t1 = rdtsc();
        latencies[i] = t1 - t0;
        (void)r;  /* suppress unused */
    }
    
    qsort(latencies, N_SAMPLES, sizeof(unsigned long), cmp_ulong);
    stats_t s = compute_stats(latencies, N_SAMPLES);
    free(latencies);
    return s;
}

int main(void) {
    printf("=== EXPERIMENT T5 · SYSCALL LATENCY MICROBENCH ===\n");
    printf("Platform: %s\n", __VERSION__);
    printf("Samples: %d per syscall (median/p95/p99)\n\n", N_SAMPLES);
    
    printf("syscall,median_cycles,p95_cycles,p99_cycles,min_cycles,max_cycles\n");
    
    #define RUN_BENCH(name, func) \
        do { \
            stats_t s = func(); \
            printf("%s,%lu,%lu,%lu,%lu,%lu\n", \
                   name, s.median, s.p95, s.p99, s.min, s.max); \
            fflush(stdout); \
        } while (0)
    
    RUN_BENCH("getpid", bench_getpid);
    RUN_BENCH("read", bench_read);
    RUN_BENCH("write", bench_write);
    RUN_BENCH("mmap", bench_mmap);
    RUN_BENCH("open", bench_open);
    RUN_BENCH("stat", bench_stat);
    RUN_BENCH("clock_gettime", bench_clock_gettime);
    
    printf("\n=== MICROBENCH COMPLETE ===\n");
    return 0;
}
