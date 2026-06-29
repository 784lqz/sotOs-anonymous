/*
 * sotOs · sto_conflict adversarial test
 *
 * Two sessions (distinct badges) race on the same object. First commit
 * wins, second must return STO_CONFLICT. This validates the NoLostUpdate
 * invariant from the TLA+ spec operationally.
 *
 * Sessions: argv[1] and argv[2] are the slot indices of two session
 * endpoint caps minted by the root task with distinct badges. The root's
 * spawner needs to be extended to pass two slots (currently only passes
 * one); until that lands, this test will exit early reporting missing
 * args. The code path is correct and will run as soon as the wiring is.
 */

#include <sto/protocol.h>
#include <sto/status.h>
#include <sel4/sel4.h>
#include <stdio.h>
#include <stdlib.h>

static uint64_t do_call(seL4_CPtr ep, uint64_t op,
                        uint64_t arg0, uint64_t arg1)
{
    seL4_MessageInfo_t info = seL4_MessageInfo_new(op, 0, 0, 2);
    seL4_SetMR(0, arg0);
    seL4_SetMR(1, arg1);
    info = seL4_Call(ep, info);
    return seL4_GetMR(0);
}

int main(int argc, char *argv[])
{
    printf("[conflict] starting\n");

    if (argc < 3) {
        printf("[conflict] need argv[1]=session_a, argv[2]=session_b · "
               "missing · waiting\n");
        while (1) seL4_Yield();
    }

    seL4_CPtr session_a_ep = (seL4_CPtr)strtoul(argv[1], NULL, 10);
    seL4_CPtr session_b_ep = (seL4_CPtr)strtoul(argv[2], NULL, 10);

    uint64_t txa = do_call(session_a_ep, STO_OP_BEGIN, 0, 0);
    uint64_t txb = do_call(session_b_ep, STO_OP_BEGIN, 0, 0);
    printf("[conflict] txa=%lu txb=%lu\n",
           (unsigned long)txa, (unsigned long)txb);

    do_call(session_a_ep, STO_OP_READ,  txa, 7);
    do_call(session_b_ep, STO_OP_READ,  txb, 7);
    do_call(session_a_ep, STO_OP_STAGE, txa, 7);
    do_call(session_b_ep, STO_OP_STAGE, txb, 7);

    uint64_t st_a = do_call(session_a_ep, STO_OP_COMMIT, txa, 0);
    if (st_a != STO_OK) {
        printf("[conflict] FAIL · first commit should succeed (got %lu)\n",
               (unsigned long)st_a);
        while (1) seL4_Yield();
    }

    uint64_t st_b = do_call(session_b_ep, STO_OP_COMMIT, txb, 0);
    if (st_b != STO_CONFLICT) {
        printf("[conflict] FAIL · second should conflict (got %lu)\n",
               (unsigned long)st_b);
        while (1) seL4_Yield();
    }

    printf("[conflict] sto_conflict · OK\n");
    while (1) seL4_Yield();
    return 0;
}
