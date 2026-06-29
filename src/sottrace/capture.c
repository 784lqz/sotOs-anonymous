#include <sottrace/trace.h>
#include <string.h>
static sottrace_capture_t g_trace_capture[SOTTRACE_CAPTURE_SLOTS];
static uint32_t g_capture_bind_seq = 0;

static sottrace_capture_t *find_or_bind(uint16_t conn_id) {
    if (conn_id == 0) return 0;
    for (int i = 0; i < SOTTRACE_CAPTURE_SLOTS; ++i)
        if (g_trace_capture[i].conn_id == conn_id) return &g_trace_capture[i];
    /* No slot yet · pick a free slot, else evict the oldest-bound (LRU) so the
     * current session always gets a slot and closed sessions stay readable. */
    int victim = 0;
    for (int i = 0; i < SOTTRACE_CAPTURE_SLOTS; ++i) {
        if (g_trace_capture[i].conn_id == 0) { victim = i; break; }
        if (g_trace_capture[i].bound < g_trace_capture[victim].bound) victim = i;
    }
    memset(&g_trace_capture[victim], 0, sizeof(g_trace_capture[victim]));
    g_trace_capture[victim].conn_id = conn_id;
    g_trace_capture[victim].bound   = ++g_capture_bind_seq;
    return &g_trace_capture[victim];
}
void sottrace_capture_append(uint16_t conn_id, int dir, const uint8_t *data, uint32_t len) {
    sottrace_capture_t *c = find_or_bind(conn_id);
    if (!c || !data || len == 0) return;
    if (dir == SOTTRACE_DIR_OUT) {
        uint32_t room = (c->len_out < SOTTRACE_CAPTURE_CAP) ? (SOTTRACE_CAPTURE_CAP - c->len_out) : 0;
        uint32_t take = (len < room) ? len : room;
        if (take) { memcpy(c->buf_out + c->len_out, data, take); c->len_out += take; }
        if (len > take) c->dropped_out += (len - take);
    } else {
        uint32_t room = (c->len < SOTTRACE_CAPTURE_CAP) ? (SOTTRACE_CAPTURE_CAP - c->len) : 0;
        uint32_t take = (len < room) ? len : room;
        if (take) { memcpy(c->buf + c->len, data, take); c->len += take; }
        if (len > take) c->dropped += (len - take);
    }
}
void sottrace_capture_release(uint16_t conn_id) {
    for (int i = 0; i < SOTTRACE_CAPTURE_SLOTS; ++i)
        if (g_trace_capture[i].conn_id == conn_id) { g_trace_capture[i].conn_id = 0; return; }
}
const sottrace_capture_t *sottrace_capture_get(uint16_t conn_id) {
    if (conn_id == 0) return 0;
    for (int i = 0; i < SOTTRACE_CAPTURE_SLOTS; ++i)
        if (g_trace_capture[i].conn_id == conn_id) return &g_trace_capture[i];
    return 0;
}
