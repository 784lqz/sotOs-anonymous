/*
 * sotOs · STO server IPC dispatcher
 */

#ifndef SOTOS_STO_IPC_H
#define SOTOS_STO_IPC_H

#include <sel4/sel4.h>

/* Main server loop: blocks on the listening endpoint, dispatches ops by
 * MessageInfo.label, sends replies. Returns only on fatal error. */
void sto_serve(seL4_CPtr listen_ep);

#endif /* SOTOS_STO_IPC_H */
