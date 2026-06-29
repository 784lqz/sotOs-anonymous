/*
 * sotOs · bench sweep_cost
 *
 * Mide rollback cost en función de wrapped_count para esa tx.
 * Hipótesis: lineal en N. Para cada N ∈ {1, 2, 4, 8, 16}, abre una
 * tx, wrappea N obj_ids en ACTIVE_OK, mide el rollback con rdtscp.
 * Repite cada N varias veces.
 *
 * argv[1] = session cap.
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

static const int sweep_sizes[] = {1, 2, 4, 8, 16};
#define SWEEP_RUNS_PER_SIZE 50

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("[bench_sweep_cost] no session cap · halting\n");
        while (1) seL4_Yield();
    }
    g_session_ep = (seL4_CPtr)strtoul(argv[1], NULL, 10);

    static uint64_t samples[SWEEP_RUNS_PER_SIZE];
    bench_run_t run;
    char name_buf[32];

    bench_emit_header("sweep_cost",
                       "x86_64-pc99-debug;mode=ACTIVE_OK",
                       0xDEAD);

    int first = 1;
    for (size_t s = 0; s < sizeof(sweep_sizes)/sizeof(sweep_sizes[0]); ++s) {
        int N = sweep_sizes[s];
        snprintf(name_buf, sizeof(name_buf), "rollback_n%d", N);
        bench_run_init(&run, name_buf, samples, SWEEP_RUNS_PER_SIZE);

        for (int i = 0; i < SWEEP_RUNS_PER_SIZE; ++i) {
            uint64_t tx = call_op(STO_OP_BEGIN, 0, 0, 0, 0);
            for (int j = 0; j < N; ++j) {
                call_op(STO_OP_WRAP, tx, j, STO_CAP_ACTIVE_OK, 3);
            }
            uint64_t t0 = bench_rdtscp();
            seL4_MessageInfo_t info = seL4_MessageInfo_new(STO_OP_ROLLBACK, 0, 0, 1);
            seL4_SetMR(0, tx);
            seL4_Send(g_session_ep, info);
            uint64_t t1 = bench_rdtscp();
            bench_run_record(&run, t1 - t0);
        }

        bench_run_sort(&run);
        if (!first) printf(",");
        bench_emit_json(&run);
        first = 0;
    }

    bench_emit_footer();

    /* Isolation · signal orch on the done EP (argv[2]) · see micro_baseline. */
    if (argc >= 3) {
        seL4_CPtr done_ep = (seL4_CPtr)strtoul(argv[2], NULL, 10);
        if (done_ep) seL4_Send(done_ep, seL4_MessageInfo_new(0, 0, 0, 0));
    }

    while (1) seL4_Yield();
    return 0;
}
