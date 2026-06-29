/*
 * sotOs · bench throughput
 *
 * Single-process steady-state: un cliente sostenido haciendo begin →
 * read → stage → commit cycles. Reporta cycles/tx totales y conflict
 * rate observado.
 *
 * Multi-client real requiere wiring multi-process completo
 * (deepen-3 sigte iteración). Acá medimos single-client.
 *
 * argv[1] = session cap.
 */

#include "../bench_common.h"
#include <sel4/sel4.h>
#include <sto/protocol.h>
#include <sto/status.h>
#include <stdio.h>
#include <stdlib.h>

#define THROUGHPUT_DURATION_TX  10000

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("[bench_throughput] no session cap · halting\n");
        while (1) seL4_Yield();
    }
    seL4_CPtr session_ep = (seL4_CPtr)strtoul(argv[1], NULL, 10);

    bench_emit_header("throughput_singleclient",
                       "x86_64-pc99-debug;tx=begin+read+stage+commit",
                       0xBEEF);

    /* Local helper · same op interface as other benches */
    #define CALL(op, a0, a1, n) ({                                      \
        seL4_MessageInfo_t _info = seL4_MessageInfo_new((op), 0, 0, (n));\
        if ((n) >= 1) seL4_SetMR(0, (a0));                              \
        if ((n) >= 2) seL4_SetMR(1, (a1));                              \
        _info = seL4_Call(session_ep, _info);                           \
        seL4_GetMR(0);                                                  \
    })

    /* Warmup */
    for (int i = 0; i < 100; ++i) {
        uint64_t tx = CALL(STO_OP_BEGIN, 0, 0, 0);
        CALL(STO_OP_READ,   tx, i, 2);
        CALL(STO_OP_STAGE,  tx, i, 2);
        CALL(STO_OP_COMMIT, tx, 0, 1);
    }

    uint64_t t0 = bench_rdtscp();
    uint64_t completed = 0;
    uint64_t conflicts = 0;

    for (int i = 0; i < THROUGHPUT_DURATION_TX; ++i) {
        uint64_t tx = CALL(STO_OP_BEGIN, 0, 0, 0);
        if (tx == 0) {
            /* registry full · skip */
            continue;
        }
        CALL(STO_OP_READ,  tx, i % 1024, 2);
        CALL(STO_OP_STAGE, tx, i % 1024, 2);
        uint64_t st = CALL(STO_OP_COMMIT, tx, 0, 1);
        if (st == STO_OK)            completed++;
        else if (st == STO_CONFLICT) conflicts++;
    }

    uint64_t t1 = bench_rdtscp();
    uint64_t total_cycles = t1 - t0;
    uint64_t total_tx = completed + conflicts;

    printf("{\"name\":\"single_client\","
           "\"total_cycles\":%lu,"
           "\"completed\":%lu,"
           "\"conflicts\":%lu,"
           "\"cycles_per_tx\":%lu}",
           (unsigned long)total_cycles,
           (unsigned long)completed,
           (unsigned long)conflicts,
           total_tx ? (unsigned long)(total_cycles / total_tx) : 0UL);

    bench_emit_footer();

    /* Isolation · signal orch on the done EP (argv[2]) · see micro_baseline. */
    if (argc >= 3) {
        seL4_CPtr done_ep = (seL4_CPtr)strtoul(argv[2], NULL, 10);
        if (done_ep) seL4_Send(done_ep, seL4_MessageInfo_new(0, 0, 0, 0));
    }

    while (1) seL4_Yield();
    return 0;
}
