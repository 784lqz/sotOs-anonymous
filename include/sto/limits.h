/*
 * sotOs · STO compile-time limits
 *
 * Todos los buffers del registry tienen tamaño fijo. Sin malloc en sotOs.
 * Cambiar estos números requiere rebuild + reasoning sobre memoria total.
 */

#ifndef SOTOS_STO_LIMITS_H
#define SOTOS_STO_LIMITS_H

/* Max active transactions across all sessions of one server instance. */
#define STO_MAX_TX              64

/* Max objects in a single tx's read or write set. */
#define STO_MAX_OBJ_PER_TX      32

/* Max committed entries kept in the in-memory log (for OCC validation). */
#define STO_MAX_COMMIT_LOG      128

/* Max wrapped caps tracked by the server across all sessions. */
#define STO_MAX_WRAPPED_CAPS    256

/* Max wrapped caps that can belong to a single tx (sweep cost in abort). */
#define STO_MAX_WRAPPED_PER_TX  16

#endif /* SOTOS_STO_LIMITS_H */
