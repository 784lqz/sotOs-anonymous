/*
 * sotOs · STO server entry point
 *
 * Receives its listen endpoint cap from the root task via argv[1], which
 * is the well-known CSpace slot index where the root mint'd the badged
 * endpoint cap. See src/root/bootstrap.{h,c}.
 */

#include "ipc.h"
#include <sel4/sel4.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    printf("[sto] server starting\n");

    seL4_CPtr listen_ep = 0;
    if (argc >= 2) {
        listen_ep = (seL4_CPtr)strtoul(argv[1], NULL, 10);
    }

    if (listen_ep == 0) {
        printf("[sto] no endpoint cap in argv[1] · halting\n");
        while (1) seL4_Yield();
        return -1;
    }

    sto_serve(listen_ep);
    return 0;
}
