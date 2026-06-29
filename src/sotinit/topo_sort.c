/* sotOs · sotinit · Kahn's topological sort over After= deps.
 *
 * Resolves the activation order for the parsed unit registry: emits a
 * permutation of unit indices in which every unit's After= predecessors
 * appear strictly before it.  Bounded by the registry caps:
 *   - max SOTINIT_MAX_UNITS=64 units
 *   - max SOTINIT_MAX_AFTER=3 After= names per unit
 * so worst-case cost is O(n^2 · k) = 64·64·3 = 12 288 ops · trivial at boot.
 *
 * Inputs · the unit registry (read via sotinit_unit_table + lookup helpers).
 * Outputs · out_order[0..*out_n-1] = unit indices in activation order.
 *
 * Return value:
 *    0 · DAG was acyclic; out_order is a valid topological order.
 *   -1 · A cycle was detected.  The handler:
 *          1. Emits "[sotinit] CYCLE_DETECTED · N units left out"
 *             (printed to stdout · smoke greppable diagnostic).
 *          2. Appends the unprocessed units to out_order in definition
 *             order so the caller can still drive activation (degraded
 *             but progresses · matches systemd's loose-cycle behavior).
 *        After this the caller sees out_order with *out_n == registry
 *        count and out_order[0..k-1] is a valid topological prefix of
 *        the acyclic subgraph.
 *
 * After= names that don't resolve to a known unit are silently ignored
 * (no indegree increment).  This matches systemd: After= against a unit
 * that doesn't exist is a no-op, not an error.
 *
 * Spec: init-cron-scheduler-design §4.5.
 */
#include <stdint.h>
#include <stdio.h>
#include <sotinit/unit.h>
#include <sotguard/event.h>  /* β · PR 11 · SOTGUARD_KIND_SOTINIT_CYCLE_DETECTED */

int sotinit_topo_sort(uint32_t *out_order, uint32_t *out_n) {
    uint32_t n = sotinit_unit_count();
    unit_t *units = sotinit_unit_table();

    /* Indegree per unit · how many of its After= names resolve to a
     * registered unit.  Bounded by SOTINIT_MAX_AFTER=3 so this fits in
     * a uint8_t comfortably. */
    uint8_t indeg[SOTINIT_MAX_UNITS] = {0};

    for (uint32_t i = 0; i < n; i++) {
        for (uint8_t k = 0; k < units[i].after_count; k++) {
            if (sotinit_unit_by_name(units[i].after[k]) != NULL) {
                indeg[i]++;
            }
        }
    }

    /* Kahn's algorithm · seed the queue with all zero-indegree units. */
    uint32_t queue[SOTINIT_MAX_UNITS];
    uint32_t qhead = 0, qtail = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (indeg[i] == 0) queue[qtail++] = i;
    }

    uint32_t out_count = 0;
    while (qhead < qtail) {
        uint32_t idx = queue[qhead++];
        out_order[out_count++] = idx;

        /* For each unit u: if u declares After=<units[idx].name>, drop
         * its indegree by 1.  We do an O(n·k) scan rather than building
         * an adjacency list because n ≤ 64 and k ≤ 3 · the constant
         * factor saved by a flat scan is worth the cache simplicity.
         *
         * The lookup-by-name → index match guards against name collisions
         * with stale slots · since the registry is bump-only and indices
         * are stable, dep->index == idx is the canonical "this edge
         * terminates at the unit we just emitted" check. */
        for (uint32_t i = 0; i < n; i++) {
            for (uint8_t k = 0; k < units[i].after_count; k++) {
                unit_t *dep = sotinit_unit_by_name(units[i].after[k]);
                if (dep && dep->index == idx) {
                    if (indeg[i] > 0) indeg[i]--;
                    if (indeg[i] == 0) queue[qtail++] = i;
                }
            }
        }
    }

    *out_n = out_count;
    if (out_count < n) {
        /* Cycle detected · out_count units form the acyclic prefix; the
         * remaining n-out_count units sit inside one or more cycles.
         * Append them in definition order so the caller still has a
         * full permutation to walk (degraded path · spec §4.5 mandates
         * "warn + fall back" semantics). */
        printf("[sotinit] CYCLE_DETECTED · %u units left out\n",
               n - out_count);
        /* β · PR 11 · audit · structured kind-tagged line so the unified
         * anomaly-log can surface dependency cycles next to other init
         * failures.  arg0 carries the count of units that fell into the
         * cycle (== n - out_count). */
        printf("[sotinit] AUDIT kind=0x%02x SOTINIT_CYCLE_DETECTED left_out=%u\n",
               (unsigned)SOTGUARD_KIND_SOTINIT_CYCLE_DETECTED,
               n - out_count);
        for (uint32_t i = 0; i < n; i++) {
            int found = 0;
            for (uint32_t j = 0; j < out_count; j++) {
                if (out_order[j] == i) { found = 1; break; }
            }
            if (!found) out_order[out_count++] = i;
        }
        *out_n = out_count;
        return -1;
    }
    return 0;
}
