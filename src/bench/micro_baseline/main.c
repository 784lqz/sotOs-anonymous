/*
 * sotOs · bench micro_baseline
 *
 * Mide el costo de un seL4_Call → server-reply roundtrip sin lógica STO.
 * El "server" para este bench es el STO server existente, recibiendo
 * un opcode inválido (responde inmediatamente con STO_PROTOCOL).
 * Esto captura el overhead puro del IPC: scheduling, message register
 * copy, badge delivery, reply path.
 *
 * argv[1] = decimal CPtr del session endpoint (mintado por root).
 */

#include "../bench_common.h"
#include <sel4/sel4.h>
#include <stdio.h>
#include <stdlib.h>

#define BASELINE_INVALID_OP  0xFFFF

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("[bench_baseline] no session cap in argv[1] · halting\n");
        while (1) seL4_Yield();
    }
    seL4_CPtr session_ep = (seL4_CPtr)strtoul(argv[1], NULL, 10);

    static uint64_t samples[BENCH_MAX_SAMPLES];
    bench_run_t run;

    bench_run_init(&run, "ipc_roundtrip_invalid", samples, BENCH_MAX_SAMPLES);

    for (int i = 0; i < BENCH_WARMUP_ITERATIONS; ++i) {
        seL4_MessageInfo_t info = seL4_MessageInfo_new(BASELINE_INVALID_OP, 0, 0, 0);
        seL4_Call(session_ep, info);
    }

    for (int i = 0; i < BENCH_MEASURE_ITERATIONS; ++i) {
        uint64_t t0 = bench_rdtscp();
        seL4_MessageInfo_t info = seL4_MessageInfo_new(BASELINE_INVALID_OP, 0, 0, 0);
        seL4_Call(session_ep, info);
        uint64_t t1 = bench_rdtscp();
        bench_run_record(&run, t1 - t0);
    }

    bench_run_sort(&run);
    /* Emit the WHOLE JSON block (header+run+footer) AFTER the measure loop so
     * it lands as one contiguous burst on the shared serial · emitting the
     * header before the loop split the block across the demo output that runs
     * concurrently during the ~1000 measured IPC calls. */
    bench_emit_header("micro_baseline",
                       "x86_64-pc99-debug;1cpu;512MB",
                       0xC0FFEE);
    bench_emit_json(&run);
    bench_emit_footer();

    /* Isolation · signal orch on the done EP (argv[2]) so it stops blocking
     * and the next bench / demo resumes (this bench ran alone). */
    if (argc >= 3) {
        seL4_CPtr done_ep = (seL4_CPtr)strtoul(argv[2], NULL, 10);
        if (done_ep) seL4_Send(done_ep, seL4_MessageInfo_new(0, 0, 0, 0));
    }

    while (1) seL4_Yield();
    return 0;
}
