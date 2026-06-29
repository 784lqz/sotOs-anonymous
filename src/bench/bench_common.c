#include "bench_common.h"
#include <stdio.h>

/* Newton's method sqrt · seL4 musllibc port does not ship libm. */
static double bench_sqrt(double x)
{
    if (x <= 0.0) return 0.0;
    double r = x;
    for (int i = 0; i < 20; ++i) {
        r = 0.5 * (r + x / r);
    }
    return r;
}

void bench_run_init(bench_run_t *r, const char *name,
                     uint64_t *buffer, size_t capacity)
{
    r->name     = name;
    r->samples  = buffer;
    r->count    = 0;
    r->capacity = capacity;
}

void bench_run_record(bench_run_t *r, uint64_t cycles)
{
    if (r->count < r->capacity) {
        r->samples[r->count++] = cycles;
    }
}

void bench_run_sort(bench_run_t *r)
{
    for (size_t i = 1; i < r->count; ++i) {
        uint64_t key = r->samples[i];
        size_t j = i;
        while (j > 0 && r->samples[j-1] > key) {
            r->samples[j] = r->samples[j-1];
            --j;
        }
        r->samples[j] = key;
    }
}

uint64_t bench_stat_min   (const bench_run_t *r) { return r->count ? r->samples[0] : 0; }
uint64_t bench_stat_max   (const bench_run_t *r) { return r->count ? r->samples[r->count-1] : 0; }
uint64_t bench_stat_median(const bench_run_t *r) { return r->count ? r->samples[r->count/2] : 0; }
uint64_t bench_stat_p99   (const bench_run_t *r) {
    if (!r->count) return 0;
    size_t idx = (r->count * 99) / 100;
    if (idx >= r->count) idx = r->count - 1;
    return r->samples[idx];
}

double bench_stat_mean(const bench_run_t *r)
{
    if (!r->count) return 0.0;
    double sum = 0;
    for (size_t i = 0; i < r->count; ++i) sum += (double)r->samples[i];
    return sum / (double)r->count;
}

double bench_stat_stddev(const bench_run_t *r)
{
    if (r->count < 2) return 0.0;
    double m = bench_stat_mean(r);
    double s = 0;
    for (size_t i = 0; i < r->count; ++i) {
        double d = (double)r->samples[i] - m;
        s += d * d;
    }
    return bench_sqrt(s / (double)(r->count - 1));
}

void bench_emit_json(const bench_run_t *r)
{
    printf("{\"name\":\"%s\",\"n\":%zu,"
           "\"min\":%lu,\"max\":%lu,"
           "\"median\":%lu,\"p99\":%lu,"
           "\"mean\":%.2f,\"stddev\":%.2f}",
           r->name, r->count,
           (unsigned long)bench_stat_min(r),
           (unsigned long)bench_stat_max(r),
           (unsigned long)bench_stat_median(r),
           (unsigned long)bench_stat_p99(r),
           bench_stat_mean(r),
           bench_stat_stddev(r));
}

void bench_emit_header(const char *bench_name,
                        const char *config_summary,
                        uint64_t    seed)
{
    printf("===BENCH-JSON-BEGIN===\n");
    printf("{\"bench\":\"%s\","
           "\"config\":\"%s\","
           "\"seed\":%lu,"
           "\"runs\":[",
           bench_name, config_summary, (unsigned long)seed);
}

void bench_emit_footer(void)
{
    printf("]}\n===BENCH-JSON-END===\n");
}
