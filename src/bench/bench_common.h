/*
 * sotOs · benchmark common utilities
 *
 * Todo lo que comparten los harnesses: medición de ciclos vía rdtsc,
 * estadísticas mínimas (mean, median, p99, stddev), output JSON.
 *
 * Disclaimer: en QEMU sin KVM accel, los números TSC no corresponden
 * 1:1 con tiempo wall-clock real, pero SÍ son reproducibles y útiles
 * para comparar configuraciones bajo la misma máquina virtual. Para
 * absolute timing, hay que correr en bare metal — TODO post-paper.
 */

#ifndef SOTOS_BENCH_COMMON_H
#define SOTOS_BENCH_COMMON_H

#include <stdint.h>
#include <stddef.h>

#define BENCH_WARMUP_ITERATIONS   100
#define BENCH_MEASURE_ITERATIONS  1000
#define BENCH_MAX_SAMPLES         10000

/* x86_64 cycle counter. No serialization · mediciones relativas. */
static inline uint64_t bench_rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* Serialized cycle counter using rdtscp + lfence para reducir reordering.
 * Más caro pero más preciso para microbenchmarks de ops muy cortas. */
static inline uint64_t bench_rdtscp(void) {
    uint32_t lo, hi, aux;
    __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
    __asm__ volatile("lfence" ::: "memory");
    return ((uint64_t)hi << 32) | lo;
}

typedef struct {
    const char *name;
    uint64_t   *samples;
    size_t      count;
    size_t      capacity;
} bench_run_t;

void   bench_run_init(bench_run_t *r, const char *name,
                       uint64_t *buffer, size_t capacity);
void   bench_run_record(bench_run_t *r, uint64_t cycles);
void   bench_run_sort(bench_run_t *r);

uint64_t bench_stat_min   (const bench_run_t *r);
uint64_t bench_stat_max   (const bench_run_t *r);
uint64_t bench_stat_median(const bench_run_t *r);
uint64_t bench_stat_p99   (const bench_run_t *r);
double   bench_stat_mean  (const bench_run_t *r);
double   bench_stat_stddev(const bench_run_t *r);

void bench_emit_json(const bench_run_t *r);

void bench_emit_header(const char *bench_name,
                        const char *config_summary,
                        uint64_t    seed);
void bench_emit_footer(void);

#endif /* SOTOS_BENCH_COMMON_H */
