/*
 * sotOs · sotFS-η · Ollivier-Ricci curvature monitor (Forman approx).
 *
 * For an unweighted undirected graph the Forman-Ricci κ on edge e=xy is:
 *
 *   κ_F(xy) = deg(x) + deg(y) - |triangles through xy| - 2
 *
 * Interpretation:
 *   κ > 0 · tight cluster (project dir).
 *   κ ≈ 0 · tree-like backbone.
 *   κ < 0 · bridge edge between weakly-connected subgraphs.
 *
 * Malware signatures (per spec §12.6.1):
 *   - Ransomware → mean κ plunges.
 *   - Lateral movement → single new edge with strongly-negative κ.
 *   - Exfil staging → positive-κ spike in /tmp.
 */
#include <sotfs/graph_curvature.h>
#include <stdio.h>
#include <stdint.h>

/* sotFS-θ · anomaly notify hook · implemented in lucas/backends_sotfs.c
 * (which has full seL4 includes).  Declared here as a weak symbol so
 * sotos-sotfs compiles without autoconf/seL4 headers.
 *
 * CURVATURE-AUTOPROMOTE · pid is the calling sotbox synthetic_pid (0 = system). */
void sotfs_graph_curvature_anomaly_notify(uint32_t pid, int rule_kind, int severity) __attribute__((weak));
void sotfs_graph_curvature_anomaly_notify(uint32_t pid, int rule_kind, int severity)
{
    (void)pid; (void)rule_kind; (void)severity; /* default no-op stub */
}

/* True when `pid` is exempt from the RANSOMWARE/LATERAL curvature alert — a
 * package-manager box (apk/apt) whose install legitimately does mass file ops.
 * Weak default 0 (host unit test); orch overrides it via the sotbox table. */
int sotfs_curvature_exempt(uint32_t pid) __attribute__((weak));
int sotfs_curvature_exempt(uint32_t pid) { (void)pid; return 0; }

extern sotfs_graph_t *backends_sotfs_get_graph(void);  /* exposed by backends_sotfs */

/* Degree of node n (count of edges where parent_id == n OR child_id == n). */
static int degree(const sotfs_graph_t *g, int n)
{
    int d = 0;
    for (int i = 0; i < SOTFS_MAX_EDGES; ++i) {
        if (g->edges[i].id == 0) continue;
        if (g->edges[i].parent_id == n || g->edges[i].child_id == n) ++d;
    }
    return d;
}

/* Count triangles through edge e (= number of common neighbors of e.parent_id
 * and e.child_id, excluding the two endpoints themselves). */
static int triangles_through(const sotfs_graph_t *g, int edge_id)
{
    if (edge_id < 1 || edge_id > SOTFS_MAX_EDGES) return 0;
    const sotfs_edge_t *e = &g->edges[edge_id - 1];
    if (e->id == 0) return 0;
    int x = e->parent_id, y = e->child_id;
    int count = 0;
    /* For each potential common neighbor z, check if both xz and yz are edges. */
    for (int z = 1; z <= SOTFS_MAX_INODES; ++z) {
        if (z == x || z == y) continue;
        if (g->inodes[z - 1].id == 0) continue;
        int xz_found = 0, yz_found = 0;
        for (int i = 0; i < SOTFS_MAX_EDGES; ++i) {
            const sotfs_edge_t *e2 = &g->edges[i];
            if (e2->id == 0) continue;
            if ((e2->parent_id == x && e2->child_id == z) ||
                (e2->parent_id == z && e2->child_id == x)) xz_found = 1;
            if ((e2->parent_id == y && e2->child_id == z) ||
                (e2->parent_id == z && e2->child_id == y)) yz_found = 1;
        }
        if (xz_found && yz_found) ++count;
    }
    return count;
}

double sotfs_graph_curvature_forman(const sotfs_graph_t *g, int edge_id)
{
    if (edge_id < 1 || edge_id > SOTFS_MAX_EDGES) return 0.0;
    const sotfs_edge_t *e = &g->edges[edge_id - 1];
    if (e->id == 0) return 0.0;
    int dx  = degree(g, e->parent_id);
    int dy  = degree(g, e->child_id);
    int tri = triangles_through(g, edge_id);
    /* κ_F = dx + dy - triangles - 2.  Subtract 2 so that a pure
     * tree edge (dx=1, dy=1, tri=0) yields κ = 0, and a bridge
     * between clusters yields κ < 0. */
    return (double)(dx + dy - tri) - 2.0;
}

void sotfs_graph_curvature_recompute_all(sotfs_graph_t *g)
{
    for (int i = 0; i < SOTFS_MAX_EDGES; ++i) {
        if (g->edges[i].id == 0) {
            g->edges[i].curvature = 0.0;
            continue;
        }
        g->edges[i].curvature = sotfs_graph_curvature_forman(g, g->edges[i].id);
    }
}

void sotfs_graph_curvature_recompute_local(sotfs_graph_t *g, int node_id)
{
    /* Recompute κ on every edge touching node_id. */
    for (int i = 0; i < SOTFS_MAX_EDGES; ++i) {
        sotfs_edge_t *e = &g->edges[i];
        if (e->id == 0) continue;
        if (e->parent_id == node_id || e->child_id == node_id) {
            e->curvature = sotfs_graph_curvature_forman(g, e->id);
        }
    }
}

double sotfs_graph_curvature_mean(const sotfs_graph_t *g)
{
    double sum = 0.0;
    int    n   = 0;
    for (int i = 0; i < SOTFS_MAX_EDGES; ++i) {
        if (g->edges[i].id == 0) continue;
        sum += g->edges[i].curvature;
        ++n;
    }
    if (n == 0) return 0.0;
    return sum / (double)n;
}

int sotfs_graph_curvature_min_edge(const sotfs_graph_t *g, double *out_kappa)
{
    int    found = 0;
    double min_k = 0.0;
    for (int i = 0; i < SOTFS_MAX_EDGES; ++i) {
        if (g->edges[i].id == 0) continue;
        if (!found || g->edges[i].curvature < min_k) {
            min_k = g->edges[i].curvature;
            found = g->edges[i].id;
        }
    }
    if (out_kappa) *out_kappa = min_k;
    return found;
}

/* sotFS-θ · per-orch baseline for ransomware delta rule. */
static double g_last_mean_k   = 0.0;
static int    g_have_baseline = 0;

/* Called from sto_local::sto_commit after every successful rewrite.
 * CURVATURE-AUTOPROMOTE · pid attributes the commit to the calling sotbox
 * (0 = operator/bootstrap; >0 = sotbox synthetic_pid). */
void sotfs_graph_curvature_on_commit(uint32_t pid, const char *op_name)
{
    sotfs_graph_t *g = backends_sotfs_get_graph();
    if (!g) return;
    sotfs_graph_curvature_recompute_all(g);  /* small graph · O(E²) tolerable */
    double mean_k       = sotfs_graph_curvature_mean(g);
    double min_k        = 0.0;
    int    min_edge_id  = sotfs_graph_curvature_min_edge(g, &min_k);

    /* Print integer-multiplied curvature to avoid floating-point printf
     * issues in our minimal libc setup (printf %f may not be linked).
     * Values are scaled to milli-units (×1000) and split into integer
     * parts so the sign is always explicit. */
    int mean_raw = (int)(mean_k * 1000.0);
    int min_raw  = (int)(min_k  * 1000.0);

    /* Split into sign + whole + frac for clean formatting. */
    const char *mean_sign = (mean_raw < 0) ? "-" : "";
    const char *min_sign  = (min_raw  < 0) ? "-" : "";
    int mean_abs = mean_raw < 0 ? -mean_raw : mean_raw;
    int min_abs  = min_raw  < 0 ? -min_raw  : min_raw;

    /* C1 · human reading of the mean curvature so the number isn't bare:
     * κ>0 → tight cluster, κ≈0 → tree-like backbone, κ<0 → fragmenting. */
    const char *interp = (mean_k >  0.5) ? "tight cluster (healthy structure)"
                       : (mean_k < -0.5) ? "fragmenting · bridges forming (watch)"
                       :                   "tree-like backbone (normal)";
    printf("[graph-curvature] op=%s mean_k=%s%d.%03d min_edge=%d min_k=%s%d.%03d · %s\n",
           op_name,
           mean_sign, mean_abs / 1000, mean_abs % 1000,
           min_edge_id,
           min_sign, min_abs / 1000, min_abs % 1000,
           interp);

    /* sotFS-θ · Rule 1 · ransomware signature.
     * Mean κ drops ≥ 2.0 in a single op (mass new bridge edges typical
     * of ransomware renaming N files to N encrypted twins). */
    /* The RANSOMWARE/LATERAL rules target a Tier-2 ATTACKER box (pid > 0).  Two
     * benign sources of mass-file-ops must NOT raise a false alert:
     *   • pid == 0 — the honeypot's OWN system/boot/operator activity, e.g. the
     *     boot-time canary seeding that creates the bait files (medical-records.enc
     *     …) at sotfs:init.  That is the deception SETTING ITSELF UP, not an attack.
     *   • a live package-manager box (apk/apt pool · pkg_install) extracting a
     *     package — many creates/renames, same curvature shape as ransomware. */
    int curv_exempt = (pid == 0) || sotfs_curvature_exempt(pid);

    if (g_have_baseline) {
        double delta = g_last_mean_k - mean_k;
        if (delta >= 2.0 && !curv_exempt) {
            int delta_raw = (int)(delta * 1000.0);
            int delta_abs = delta_raw < 0 ? -delta_raw : delta_raw;
            printf("[sotfs-θ] RANSOMWARE candidate · mean_κ dropped %d.%03d · op=%s pid=%u\n",
                   delta_abs / 1000, delta_abs % 1000,
                   op_name, (unsigned int)pid);
            /* Notify anomaly-ext via hook (implemented in lucas with seL4 IPC). */
            sotfs_graph_curvature_anomaly_notify(pid, 1, delta_abs);
        }
    }

    /* sotFS-θ · Rule 2 · lateral movement signature.
     * A single new edge with κ < -1.0 signals a bridge between
     * previously-disconnected subgraphs (e.g. /tmp/payload → /etc/cron.d). */
    if (min_raw < -1000 && !curv_exempt) {
        printf("[sotfs-θ] LATERAL candidate · edge=%d κ=%s%d.%03d · op=%s pid=%u\n",
               min_edge_id,
               min_sign, min_abs / 1000, min_abs % 1000,
               op_name, (unsigned int)pid);
        /* Notify anomaly-ext via hook (implemented in lucas with seL4 IPC). */
        sotfs_graph_curvature_anomaly_notify(pid, 2, min_abs);
    }

    g_last_mean_k   = mean_k;
    g_have_baseline = 1;
}
