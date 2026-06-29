/*
 * sotOs * sotGuard * policy engine implementation.
 *
 * Per-pid state machine + sample correlation rules.  See
 * include/sotguard/engine.h for the public contract.
 *
 * Design notes:
 *
 *   - The context table is a flat array of SOTGUARD_MAX_TRACKED_PIDS
 *     slots; we use linear search because the table is tiny (16) and
 *     this keeps the implementation hash-free, malloc-free, and
 *     readable.  An open-addressed hash table is a future cut once
 *     the bus throughput justifies it.
 *
 *   - The engine never allocates and never blocks.  All scratch state
 *     fits in static BSS; rule verdicts are written into a caller-owned
 *     sotguard_rule_result_t.
 *
 *   - The burst-write window is 1 ms = 1_000_000 ns of monotonic time.
 *     `last_write_ts == 0` means "no prior write seen"; the very first
 *     write therefore never extends the burst counter.
 *
 *   - Recon scoring is additive across reads of sensitive paths:
 *     /etc/passwd and /proc/self/maps each contribute +5.  A score
 *     above 3 combined with a non-local NET_CONNECT fires the
 *     RECON_EXFIL rule.  The score is intentionally low-granularity:
 *     a single sensitive read already arms the rule.
 *
 *   - This unit does NOT subscribe to the G1 ring buffer; the caller
 *     drives the eval entry-point per event.  Future cuts may add a
 *     pump that polls sotguard_recent() and dispatches into the eval
 *     function.
 */

#include <stdint.h>
#include <stddef.h>

#include <sotguard/engine.h>
#include <sotguard/event.h>

/* ---------------------------------------------------------------------------
 * String helpers, fully self-contained.
 *
 * The engine is a static library that may be linked into freestanding
 * targets where <string.h> is unavailable in some configurations.
 * Rather than depend on sotos-string or muslc, we provide the small
 * primitives we need.  Both are O(n) on bounded inputs and have no
 * side effects.
 * ---------------------------------------------------------------------------*/

/* Returns 1 if `needle` appears as a substring of `hay`, 0 otherwise.
 * Empty needle matches.  Naive O(n*m); bounded by path length. */
static int sg_contains(const char *hay, const char *needle)
{
    if (!hay || !needle) {
        return 0;
    }
    if (*needle == '\0') {
        return 1;
    }
    for (size_t i = 0; hay[i] != '\0'; i++) {
        size_t j = 0;
        while (needle[j] != '\0' && hay[i + j] == needle[j]) {
            j++;
        }
        if (needle[j] == '\0') {
            return 1;
        }
    }
    return 0;
}

/* Bounded strcpy that always NUL-terminates.  Caller owns the
 * truncation choice (callers below pass tags <=31 chars so no
 * truncation actually occurs). */
static void sg_strcpy_bounded(char *dst, const char *src, size_t cap)
{
    if (cap == 0) {
        return;
    }
    size_t i = 0;
    for (; i + 1 < cap && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

/* ---------------------------------------------------------------------------
 * Per-pid context table.
 * ---------------------------------------------------------------------------*/

static sotguard_pid_ctx_t g_ctxs[SOTGUARD_MAX_TRACKED_PIDS];

/* Burst-write window: 1 ms in nanoseconds. */
#define SG_BURST_WINDOW_NS    1000000ULL
#define SG_BURST_THRESHOLD    10u
#define SG_RECON_THRESHOLD    3u
#define SG_CANARY_READ_THRESHOLD    2u
#define SG_RECON_INCREMENT    5u

void sotguard_engine_init(void)
{
    for (size_t i = 0; i < SOTGUARD_MAX_TRACKED_PIDS; i++) {
        g_ctxs[i].pid           = 0;
        g_ctxs[i].recon_score   = 0;
        g_ctxs[i].burst_writes  = 0;
        g_ctxs[i].last_write_ts = 0;
        g_ctxs[i].canary_reads   = 0;
        g_ctxs[i].in_use        = 0;
        g_ctxs[i].pad[0]        = 0;
        g_ctxs[i].pad[1]        = 0;
        g_ctxs[i].pad[2]        = 0;
    }
}

/* Find an existing slot for `pid` or allocate a new one.  Returns NULL
 * if the table is full and pid is not already tracked. */
static sotguard_pid_ctx_t *get_or_alloc_ctx(uint32_t pid)
{
    /* Pid 0 is reserved as the "free" anomaly.  Refuse to track it. */
    if (pid == 0) {
        return NULL;
    }
    /* First pass: look for existing slot. */
    for (size_t i = 0; i < SOTGUARD_MAX_TRACKED_PIDS; i++) {
        if (g_ctxs[i].in_use && g_ctxs[i].pid == pid) {
            return &g_ctxs[i];
        }
    }
    /* Second pass: allocate new slot. */
    for (size_t i = 0; i < SOTGUARD_MAX_TRACKED_PIDS; i++) {
        if (!g_ctxs[i].in_use) {
            g_ctxs[i].pid           = pid;
            g_ctxs[i].recon_score   = 0;
            g_ctxs[i].burst_writes  = 0;
            g_ctxs[i].last_write_ts = 0;
            g_ctxs[i].canary_reads   = 0;
            g_ctxs[i].in_use        = 1;
            return &g_ctxs[i];
        }
    }
    return NULL;
}

void sotguard_engine_reset_pid(uint32_t pid)
{
    if (pid == 0) {
        return;
    }
    for (size_t i = 0; i < SOTGUARD_MAX_TRACKED_PIDS; i++) {
        if (g_ctxs[i].in_use && g_ctxs[i].pid == pid) {
            g_ctxs[i].pid           = 0;
            g_ctxs[i].recon_score   = 0;
            g_ctxs[i].burst_writes  = 0;
            g_ctxs[i].last_write_ts = 0;
            g_ctxs[i].canary_reads   = 0;
            g_ctxs[i].in_use        = 0;
            return;
        }
    }
}

/* ---------------------------------------------------------------------------
 * Path classifiers.
 * ---------------------------------------------------------------------------*/

static int path_is_sensitive(const char *p)
{
    return sg_contains(p, "/etc/passwd") ||
           sg_contains(p, "/proc/self/maps");
}

/* ---------------------------------------------------------------------------
 * Verdict helpers.
 * ---------------------------------------------------------------------------*/

static void fill_verdict(sotguard_rule_result_t *out,
                         sotguard_rule_id_t rule,
                         uint32_t pid,
                         uint8_t target_tier,
                         const char *reason)
{
    out->rule         = rule;
    out->pid          = pid;
    out->target_tier  = target_tier;
    sg_strcpy_bounded(out->reason, reason, sizeof(out->reason));
}

/* ---------------------------------------------------------------------------
 * Public entry-point.
 * ---------------------------------------------------------------------------*/

int sotguard_engine_eval(const sotguard_event_t *ev,
                         sotguard_rule_result_t *out)
{
    if (!ev || !out) {
        return 0;
    }
    sotguard_pid_ctx_t *ctx = get_or_alloc_ctx(ev->pid);
    if (!ctx) {
        /* Table full and pid not tracked; accept event silently. */
        return 0;
    }

    switch ((sotguard_event_type_t)ev->type) {

    case SG_EV_FS_READ: {
        if (path_is_sensitive(ev->detail.fs.path)) {
            ctx->recon_score += SG_RECON_INCREMENT;
        }
        break;
    }

    case SG_EV_CANARY_READ: {
        if (ctx->canary_reads < UINT32_MAX) {
            ctx->canary_reads += 1;
        }
        if (ctx->canary_reads >= SG_CANARY_READ_THRESHOLD) {
            fill_verdict(out, SG_RULE_CANARY_TRIPPED, ctx->pid, 2,
                         "canary-tripped");
            return 1;
        }
        break;
    }

    case SG_EV_NET_CONNECT: {
        /* Non-local destination = not loopback (127.0.0.0/8).  ip_be is
         * stored in big-endian; 127.* means the LOW byte of the LE word
         * is 127.  Cast through uint32_t and inspect the first octet. */
        uint32_t ip_be = ev->detail.net.ip_be;
        uint8_t  first_octet = (uint8_t)(ip_be & 0xFF);
        int      non_local = (first_octet != 127);
        if (non_local && ctx->recon_score > SG_RECON_THRESHOLD) {
            fill_verdict(out, SG_RULE_RECON_EXFIL, ctx->pid, 2,
                         "recon-then-exfil");
            return 1;
        }
        break;
    }

    case SG_EV_FS_WRITE: {
        uint64_t now = ev->timestamp;
        if (ctx->last_write_ts != 0 &&
            (now - ctx->last_write_ts) < SG_BURST_WINDOW_NS) {
            if (ctx->burst_writes < UINT32_MAX) {
                ctx->burst_writes += 1;
            }
        } else {
            ctx->burst_writes = 1;
        }
        ctx->last_write_ts = now;
        if (ctx->burst_writes > SG_BURST_THRESHOLD) {
            fill_verdict(out, SG_RULE_BURST_WRITES, ctx->pid, 1,
                         "burst-writes");
            return 1;
        }
        break;
    }

    case SG_EV_NONE:
    default:
        /* Unknown event types are ignored.  Process-exit reset is
         * driven externally (orch calls sotguard_engine_reset_pid()
         * from the reap path · G1's event enum has no PROC_EXIT). */
        break;
    }

    return 0;
}
