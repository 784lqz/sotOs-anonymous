/*
 * sotOs · STO status codes
 *
 * Compartido entre server y clients vía el header.
 */

#ifndef SOTOS_STO_STATUS_H
#define SOTOS_STO_STATUS_H

enum sto_status {
    STO_OK            = 0,
    STO_ABORTED       = 1,  /* explicit rollback or validation failure */
    STO_CONFLICT      = 2,  /* OCC validation failed */
    STO_INVALID_TX    = 3,  /* tx_id unknown or not owned by caller */
    STO_INVALID_STATE = 4,  /* op invalid for current tx state */
    STO_QUOTA         = 5,  /* server resource exhaustion */
    STO_PROTOCOL      = 6,  /* malformed message */
};

#endif /* SOTOS_STO_STATUS_H */
