/* test_ecdhe.c — ORACLE-GATED test for the group-dispatched derive_ecdhe.
 *
 * This is the crypto-core gate of ε2. It feeds the production C derive_ecdhe
 * (src/net-synth/tls13.c) the EXACT fixed server scalar + fixed client point
 * the Python ECDH oracle (oracle_ecdh.py) used, then asserts the C server public
 * point AND the C shared secret (X-coordinate only, the TLS 1.3 ECDHE secret)
 * byte-match the Python golden — for BOTH P-256 and P-384.
 *
 * The golden is NOT hard-coded here: we popen oracle_ecdh.py at runtime and parse
 * its `SRV_SCALAR / CLI_PUB / SRV_PUB / SHARED` lines, so the comparison is
 * against an INDEPENDENT cryptography-library computation (not a value derived by
 * the same BearSSL arithmetic under test). A wrong X-coord offset/length would
 * yield a wrong-but-nonzero secret that survives the all-zero guard and is caught
 * ONLY here, before any live handshake.
 *
 * derive_ecdhe normally generates a random ephemeral scalar (br_ec_keygen). To
 * pin the comparison to the oracle's deterministic scalar we set the production
 * test hook `tls13_test_scalar_hook` to hand back the parsed fixed scalar. The
 * REAL derive_ecdhe (mulgen/mul/xoff dispatch) is exercised end-to-end. */

#include <net-synth/tls13.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok : %s\n", msg); } \
    else { printf("  FAIL: %s\n", msg); failures++; } } while (0)

/* The production test hook (defined in tls13.c). When set, derive_ecdhe asks it
 * for the server ephemeral scalar instead of generating a random one. */
extern int (*tls13_test_scalar_hook)(uint16_t group, uint8_t *priv, size_t cap);

/* Thin extern accessor (defined in tls13.c) for the static derive_ecdhe. */
extern int tls13_derive_ecdhe_for_test(tls13_sess_t *s, uint16_t group,
                                       const uint8_t *client_pub,
                                       uint16_t client_pub_len);

/* ── hex helpers ───────────────────────────────────────────────────────── */
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t hex_decode(const char *hex, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (hex[0] && hex[1]) {
        if (hex[0] == '\n' || hex[0] == '\r' || hex[0] == ' ') { hex++; continue; }
        int hi = hexval(hex[0]), lo = hexval(hex[1]);
        if (hi < 0 || lo < 0) break;
        if (n >= cap) { fprintf(stderr, "hex_decode overflow\n"); exit(2); }
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

/* ── oracle golden, parsed at runtime from oracle_ecdh.py ──────────────────
 * Lines: "<NAME> SRV_SCALAR <hex>", "<NAME> CLI_PUB <hex>",
 *        "<NAME> SRV_PUB <hex>",    "<NAME> SHARED <hex>". */
typedef struct {
    uint8_t srv_scalar[48]; size_t srv_scalar_len;
    uint8_t cli_pub[97];    size_t cli_pub_len;
    uint8_t srv_pub[97];    size_t srv_pub_len;
    uint8_t shared[48];     size_t shared_len;
} golden_t;

static golden_t G_P256, G_P384;

static void store_field(const char *name, const char *field, const char *hex) {
    golden_t *g = NULL;
    if (!strcmp(name, "P256")) g = &G_P256;
    else if (!strcmp(name, "P384")) g = &G_P384;
    else return;
    if      (!strcmp(field, "SRV_SCALAR")) g->srv_scalar_len = hex_decode(hex, g->srv_scalar, sizeof g->srv_scalar);
    else if (!strcmp(field, "CLI_PUB"))    g->cli_pub_len    = hex_decode(hex, g->cli_pub,    sizeof g->cli_pub);
    else if (!strcmp(field, "SRV_PUB"))    g->srv_pub_len    = hex_decode(hex, g->srv_pub,    sizeof g->srv_pub);
    else if (!strcmp(field, "SHARED"))     g->shared_len     = hex_decode(hex, g->shared,     sizeof g->shared);
}

static void load_oracle(void) {
    /* Run from the test dir; oracle_ecdh.py is a sibling. */
    FILE *p = popen("python3 oracle_ecdh.py", "r");
    if (!p) { fprintf(stderr, "FATAL: cannot run oracle_ecdh.py\n"); exit(2); }
    char line[1024];
    int self_check_ok = 0;
    while (fgets(line, sizeof line, p)) {
        if (strstr(line, "ORACLE SELF-CHECK OK")) self_check_ok = 1;
        char name[16], field[32], hex[512];
        if (sscanf(line, "%15s %31s %511s", name, field, hex) == 3)
            store_field(name, field, hex);
    }
    int rc = pclose(p);
    if (rc != 0) { fprintf(stderr, "FATAL: oracle exited nonzero (%d)\n", rc); exit(2); }
    if (!self_check_ok) { fprintf(stderr, "FATAL: oracle self-check did not pass\n"); exit(2); }
}

/* ── test hook: feed the oracle's fixed server scalar for the curve under test ── */
static uint16_t g_hook_group;
static const uint8_t *g_hook_scalar;
static size_t g_hook_scalar_len;

static int fixed_scalar_hook(uint16_t group, uint8_t *priv, size_t cap) {
    if (group != g_hook_group) return 0;           /* decline → real RNG */
    if (g_hook_scalar_len == 0 || g_hook_scalar_len > cap) return 0;
    memcpy(priv, g_hook_scalar, g_hook_scalar_len);
    return (int)g_hook_scalar_len;
}

static void run_curve(const char *label, uint16_t group, const golden_t *g) {
    printf("--- %s (group 0x%04x) ---\n", label, group);

    /* Pin the server ephemeral scalar to the oracle's fixed value. */
    g_hook_group      = group;
    g_hook_scalar     = g->srv_scalar;
    g_hook_scalar_len = g->srv_scalar_len;
    tls13_test_scalar_hook = fixed_scalar_hook;

    tls13_sess_t s;
    memset(&s, 0, sizeof s);
    int rc = tls13_derive_ecdhe_for_test(&s, group, g->cli_pub, (uint16_t)g->cli_pub_len);

    tls13_test_scalar_hook = NULL;   /* restore production default */

    CHECK(rc == 0, "derive_ecdhe returns 0");
    CHECK(s.selected_group == group, "selected_group set to the curve");

    /* Server public point must byte-match the oracle. */
    CHECK(s.srv_eph_pub_len == g->srv_pub_len, "server pub length matches oracle");
    CHECK(s.srv_eph_pub_len == g->srv_pub_len &&
          memcmp(s.srv_eph_pub, g->srv_pub, g->srv_pub_len) == 0,
          "server pub bytes match oracle golden");

    /* Shared secret (X-coordinate) must byte-match the oracle. */
    CHECK(s.ecdhe_shared_len == g->shared_len, "shared secret length matches oracle (X-coord only)");
    CHECK(s.ecdhe_shared_len == g->shared_len &&
          memcmp(s.ecdhe_shared, g->shared, g->shared_len) == 0,
          "shared secret bytes match oracle golden");

    /* Defensive: the secret is the X-coord, NOT the full point; assert it does
     * NOT equal the wrong (offset-0 / full-point) interpretation length. */
    CHECK(s.ecdhe_shared_len != s.srv_eph_pub_len,
          "shared secret length != full-point length (X-coord trap guarded)");
}

int main(void) {
    printf("=== test_ecdhe: oracle-gated group-dispatched derive_ecdhe ===\n");
    load_oracle();

    CHECK(G_P256.srv_scalar_len == 32 && G_P256.cli_pub_len == 65 &&
          G_P256.srv_pub_len == 65 && G_P256.shared_len == 32,
          "oracle P-256 vectors loaded (scalar32/pub65/shared32)");
    CHECK(G_P384.srv_scalar_len == 48 && G_P384.cli_pub_len == 97 &&
          G_P384.srv_pub_len == 97 && G_P384.shared_len == 48,
          "oracle P-384 vectors loaded (scalar48/pub97/shared48)");

    run_curve("P-256", TLS13_GROUP_SECP256R1, &G_P256);
    run_curve("P-384", TLS13_GROUP_SECP384R1, &G_P384);

    if (failures == 0) { printf("=== PASS ===\n"); return 0; }
    printf("=== FAIL (%d) ===\n", failures);
    return 1;
}
