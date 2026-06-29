/*
 * sotOs · sto_hello smoke test
 *
 * Sends a BEGIN to the STO server and expects a reply. Receives its
 * session endpoint cap from the root task via argv[1].
 */

#include <sto/protocol.h>
#include <sel4/sel4.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    printf("[hello] sto_hello starting\n");

    seL4_CPtr server_ep = 0;
    if (argc >= 2) {
        server_ep = (seL4_CPtr)strtoul(argv[1], NULL, 10);
    }
    if (server_ep == 0) {
        printf("[hello] no session cap in argv[1] · halting\n");
        while (1) seL4_Yield();
        return -1;
    }

    seL4_MessageInfo_t info = seL4_MessageInfo_new(STO_OP_BEGIN, 0, 0, 0);
    info = seL4_Call(server_ep, info);

    seL4_Word tx_id = seL4_GetMR(0);
    printf("[hello] received tx_id=%lu\n", (unsigned long)tx_id);
    printf("[hello] sto_test · OK\n");

    while (1) seL4_Yield();
    return 0;
}
