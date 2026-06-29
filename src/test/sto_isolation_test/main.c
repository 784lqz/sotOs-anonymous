/*
 * sotOs · sto_isolation_test adversarial test
 *
 * Two sessions. Attacker (B) tries to operate on victim's (A) tx_id.
 *
 *  Defensa 1 (kernel): the badge on session_b_ep is distinct from
 *  session_a_ep; the server sees a different caller and rejects by
 *  owner_badge mismatch.
 *  Defensa 2 (server): sto_registry_find filters by owner_badge, so even
 *  if the kernel's badging were broken, the server still protects.
 *
 * Sessions: argv[1] = victim, argv[2] = attacker (distinct badges).
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
    printf("[sto-isolation] starting\n");

    if (argc < 3) {
        printf("[sto-isolation] need argv[1]=victim, argv[2]=attacker · "
               "missing · waiting\n");
        while (1) seL4_Yield();
    }

    seL4_CPtr session_a_ep   = (seL4_CPtr)strtoul(argv[1], NULL, 10);
    seL4_CPtr session_b_ep = (seL4_CPtr)strtoul(argv[2], NULL, 10);

    uint64_t tx = do_call(session_a_ep, STO_OP_BEGIN, 0, 0);
    printf("[sto-isolation] victim has tx_id=%lu\n", (unsigned long)tx);

    /* Attacker tries to read on the victim's tx. Must be rejected. */
    uint64_t st = do_call(session_b_ep, STO_OP_READ, tx, 1);
    if (st != STO_INVALID_TX) {
        printf("[sto-isolation] FAIL · attacker should be rejected (got %lu)\n",
               (unsigned long)st);
        while (1) seL4_Yield();
    }

    st = do_call(session_b_ep, STO_OP_COMMIT, tx, 0);
    if (st != STO_INVALID_TX) {
        printf("[sto-isolation] FAIL · attacker commit should be rejected\n");
        while (1) seL4_Yield();
    }

    /* Victim still works. */
    if (do_call(session_a_ep, STO_OP_COMMIT, tx, 0) != STO_OK) {
        printf("[sto-isolation] FAIL · victim's own commit should succeed\n");
        while (1) seL4_Yield();
    }

    printf("[sto-isolation] sto_isolation_test · OK · attacker rebuffed\n");
    while (1) seL4_Yield();
    return 0;
}
