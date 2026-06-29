#ifndef SOTFS_GRAPH_CURVATURE_H
#define SOTFS_GRAPH_CURVATURE_H

#include <sotfs/graph.h>
#include <stdint.h>

/* Compute Forman-Ricci κ(e) for the given edge.  Caller validates id. */
double sotfs_graph_curvature_forman(const sotfs_graph_t *g, int edge_id);

/* Recompute curvature on every edge.  O(E * max_degree).  Use at boot
 * or after large structural changes. */
void sotfs_graph_curvature_recompute_all(sotfs_graph_t *g);

/* Recompute curvature on edges in the 1-neighborhood of a node.
 * Called by the per-rewrite hook · O(degree²). */
void sotfs_graph_curvature_recompute_local(sotfs_graph_t *g, int node_id);

/* Aggregate statistics. */
double sotfs_graph_curvature_mean(const sotfs_graph_t *g);
int    sotfs_graph_curvature_min_edge(const sotfs_graph_t *g, double *out_kappa);

/* anomaly hook called from sto_local::sto_commit.
 * CURVATURE-AUTOPROMOTE · pid attributes the commit to the calling sotbox
 * (st->synthetic_pid); use 0 for operator/bootstrap context. */
void sotfs_graph_curvature_on_commit(uint32_t pid, const char *op_name);

/* Anomaly-ext notify hook · fired when a curvature rule matches.
 * CURVATURE-AUTOPROMOTE · pid lets anomaly-ext attribute the alert and
 * auto-promote the offending sotbox to Tier-2.  pid=0 means system
 * (no per-sotbox attribution available). */
void sotfs_graph_curvature_anomaly_notify(uint32_t pid, int rule_kind, int severity);

#endif /* SOTFS_GRAPH_CURVATURE_H */
