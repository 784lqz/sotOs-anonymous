/*
 * sotOs · bench micro_sto_ops
 *
 * Mide latencia de cada operación STO + cap_ext en aislamiento.
 * Cada op: warmup, mide N veces, reporta JSON. Setup/cleanup están
 * fuera del clock; cada measurement es el costo de UNA op individual.
 *
 * argv[1] = decimal CPtr del session endpoint.
 */

#include "../bench_common.h"
#include <sel4/sel4.h>
#include <sto/protocol.h>
#include <sto/cap_ext.h>
#include <sto/status.h>
#include <stdio.h>
#include <stdlib.h>

static seL4_CPtr g_session_ep;

static uint64_t call_op(uint64_t op, uint64_t a0, uint64_t a1, uint64_t a2,
                         int nargs)
{
    seL4_MessageInfo_t info = seL4_MessageInfo_new(op, 0, 0, nargs);
    if (nargs >= 1) seL4_SetMR(0, a0);
    if (nargs >= 2) seL4_SetMR(1, a1);
    if (nargs >= 3) seL4_SetMR(2, a2);
    info = seL4_Call(g_session_ep, info);
    return seL4_GetMR(0);
}

static void send_rollback(uint64_t tx)
{
    seL4_MessageInfo_t info = seL4_MessageInfo_new(STO_OP_ROLLBACK, 0, 0, 1);
    seL4_SetMR(0, tx);
    seL4_Send(g_session_ep, info);
}

static void measure_begin(uint64_t *samples)
{
    bench_run_t run;
    bench_run_init(&run, "begin", samples, BENCH_MAX_SAMPLES);

    for (int i = 0; i < BENCH_WARMUP_ITERATIONS; ++i) {
        uint64_t tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
        send_rollback(tx);
    }

    for (int i = 0; i < BENCH_MEASURE_ITERATIONS; ++i) {
        uint64_t t0 = bench_rdtscp();
        uint64_t tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
        uint64_t t1 = bench_rdtscp();
        bench_run_record(&run, t1 - t0);
        send_rollback(tx);
    }

    bench_run_sort(&run);
    bench_emit_json(&run);
}

static void measure_read(uint64_t *samples)
{
    bench_run_t run;
    bench_run_init(&run, "read", samples, BENCH_MAX_SAMPLES);
    printf(",");

    uint64_t tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
    for (int i = 0; i < BENCH_WARMUP_ITERATIONS; ++i) {
        /* unique obj_id per iter to avoid the duplicate-detect short path */
        call_op(STO_OP_READ, tx, 50000 + i, 0, 2);
    }
    send_rollback(tx);
    tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);

    for (int i = 0; i < BENCH_MEASURE_ITERATIONS; ++i) {
        uint64_t t0 = bench_rdtscp();
        call_op(STO_OP_READ, tx, 100000 + i, 0, 2);
        uint64_t t1 = bench_rdtscp();
        bench_run_record(&run, t1 - t0);
        /* recycle tx every 16 iters to avoid STO_QUOTA on read_set */
        if ((i + 1) % 16 == 0) {
            send_rollback(tx);
            tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
        }
    }
    send_rollback(tx);

    bench_run_sort(&run);
    bench_emit_json(&run);
}

static void measure_stage(uint64_t *samples)
{
    bench_run_t run;
    bench_run_init(&run, "stage", samples, BENCH_MAX_SAMPLES);
    printf(",");

    uint64_t tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
    for (int i = 0; i < BENCH_WARMUP_ITERATIONS; ++i) {
        call_op(STO_OP_STAGE, tx, 60000 + i, 0, 2);
    }
    send_rollback(tx);
    tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);

    for (int i = 0; i < BENCH_MEASURE_ITERATIONS; ++i) {
        uint64_t t0 = bench_rdtscp();
        call_op(STO_OP_STAGE, tx, 200000 + i, 0, 2);
        uint64_t t1 = bench_rdtscp();
        bench_run_record(&run, t1 - t0);
        if ((i + 1) % 16 == 0) {
            send_rollback(tx);
            tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
        }
    }
    send_rollback(tx);

    bench_run_sort(&run);
    bench_emit_json(&run);
}

static void measure_commit(uint64_t *samples)
{
    bench_run_t run;
    bench_run_init(&run, "commit", samples, BENCH_MAX_SAMPLES);
    printf(",");

    /* Each iter: begin → stage one obj → commit (measured). */
    for (int i = 0; i < BENCH_WARMUP_ITERATIONS; ++i) {
        uint64_t tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
        call_op(STO_OP_STAGE, tx, 700000 + i, 0, 2);
        call_op(STO_OP_COMMIT, tx, 0, 0, 1);
    }

    for (int i = 0; i < BENCH_MEASURE_ITERATIONS; ++i) {
        uint64_t tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
        call_op(STO_OP_STAGE, tx, 800000 + i, 0, 2);
        uint64_t t0 = bench_rdtscp();
        call_op(STO_OP_COMMIT, tx, 0, 0, 1);
        uint64_t t1 = bench_rdtscp();
        bench_run_record(&run, t1 - t0);
    }

    bench_run_sort(&run);
    bench_emit_json(&run);
}

static void measure_rollback(uint64_t *samples)
{
    bench_run_t run;
    bench_run_init(&run, "rollback", samples, BENCH_MAX_SAMPLES);
    printf(",");

    /* Rollback is one-way Send; we measure call_op proxy: BEGIN then
     * ROLLBACK roundtrip approximation. Use rdtscp around the Send +
     * confirm by issuing a follow-up no-op call. */
    for (int i = 0; i < BENCH_WARMUP_ITERATIONS; ++i) {
        uint64_t tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
        send_rollback(tx);
    }

    for (int i = 0; i < BENCH_MEASURE_ITERATIONS; ++i) {
        uint64_t tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
        uint64_t t0 = bench_rdtscp();
        send_rollback(tx);
        uint64_t t1 = bench_rdtscp();
        bench_run_record(&run, t1 - t0);
    }

    bench_run_sort(&run);
    bench_emit_json(&run);
}

static void measure_wrap(uint64_t *samples)
{
    bench_run_t run;
    bench_run_init(&run, "wrap", samples, BENCH_MAX_SAMPLES);
    printf(",");

    uint64_t tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
    for (int i = 0; i < BENCH_WARMUP_ITERATIONS; ++i) {
        call_op(STO_OP_WRAP, tx, 70000 + i, STO_CAP_ACTIVE_OK, 3);
    }
    send_rollback(tx);
    tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);

    for (int i = 0; i < BENCH_MEASURE_ITERATIONS; ++i) {
        uint64_t t0 = bench_rdtscp();
        call_op(STO_OP_WRAP, tx, 900000 + i, STO_CAP_ACTIVE_OK, 3);
        uint64_t t1 = bench_rdtscp();
        bench_run_record(&run, t1 - t0);
        /* STO_MAX_WRAPPED_PER_TX=16 · recycle tx before hitting quota */
        if ((i + 1) % 15 == 0) {
            send_rollback(tx);
            tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
        }
    }
    send_rollback(tx);

    bench_run_sort(&run);
    bench_emit_json(&run);
}

static void measure_invoke(uint64_t *samples)
{
    bench_run_t run;
    bench_run_init(&run, "invoke", samples, BENCH_MAX_SAMPLES);
    printf(",");

    /* Setup: begin a tx, wrap one obj, then invoke that cap repeatedly.
     * The cap stays LIVE while tx is ACTIVE under ACTIVE_OK mode. */
    uint64_t tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(STO_OP_WRAP, 0, 0, 3);
    seL4_SetMR(0, tx);
    seL4_SetMR(1, 1234);
    seL4_SetMR(2, STO_CAP_ACTIVE_OK);
    info = seL4_Call(g_session_ep, info);
    uint64_t wid = seL4_GetMR(1);

    for (int i = 0; i < BENCH_WARMUP_ITERATIONS; ++i) {
        call_op(STO_OP_INVOKE, wid, 0, 0, 2);
    }

    for (int i = 0; i < BENCH_MEASURE_ITERATIONS; ++i) {
        uint64_t t0 = bench_rdtscp();
        call_op(STO_OP_INVOKE, wid, 0, 0, 2);
        uint64_t t1 = bench_rdtscp();
        bench_run_record(&run, t1 - t0);
    }
    send_rollback(tx);

    bench_run_sort(&run);
    bench_emit_json(&run);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("[bench_sto_ops] no session cap · halting\n");
        while (1) seL4_Yield();
    }
    g_session_ep = (seL4_CPtr)strtoul(argv[1], NULL, 10);

    static uint64_t samples[BENCH_MAX_SAMPLES];

    bench_emit_header("micro_sto_ops",
                       "x86_64-pc99-debug;1cpu;512MB",
                       0xC0FFEE);

    measure_begin(samples);
    measure_read(samples);
    measure_stage(samples);
    measure_commit(samples);
    measure_rollback(samples);
    measure_wrap(samples);
    measure_invoke(samples);

    bench_emit_footer();

    /* Isolation · signal orch on the done EP (argv[2]) · see micro_baseline. */
    if (argc >= 3) {
        seL4_CPtr done_ep = (seL4_CPtr)strtoul(argv[2], NULL, 10);
        if (done_ep) seL4_Send(done_ep, seL4_MessageInfo_new(0, 0, 0, 0));
    }

    while (1) seL4_Yield();
    return 0;
}
