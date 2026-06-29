/* test_suite.c — A1: verify SUITES[] table contents and struct widening guards.
 * No behavior change; 0x1301 path stays byte-identical.
 * Gate: `just test-tls13-unit` must exit 0, ALL tests PASS. */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <net-synth/tls13.h>

#define CHECK(expr) do { \
    if (!(expr)) { fprintf(stderr, "FAIL: %s (line %d)\n", #expr, __LINE__); return 1; } \
    fprintf(stdout, "  ok : %s\n", #expr); \
} while(0)

int main(void) {
    fprintf(stdout, "=== test_suite: suite descriptor table + struct widening ===\n");

    /* --- 0x1301: TLS_AES_128_GCM_SHA256 --- */
    const tls13_suite_t *s1 = tls13_suite_by_id(0x1301);
    CHECK(s1 != NULL);
    CHECK(s1->id         == 0x1301);
    CHECK(s1->hash_len   == 32);
    CHECK(s1->key_len    == 16);
    CHECK(s1->iv_len     == 12);
    CHECK(s1->tag_len    == 16);
    CHECK(s1->finished_len == 32);
    CHECK(s1->sigalg     == 0x0804);
    CHECK(s1->aead       == TLS13_AEAD_AES_128_GCM);

    /* --- 0x1302: TLS_AES_256_GCM_SHA384 --- */
    const tls13_suite_t *s2 = tls13_suite_by_id(0x1302);
    CHECK(s2 != NULL);
    CHECK(s2->id         == 0x1302);
    CHECK(s2->hash_len   == 48);
    CHECK(s2->key_len    == 32);
    CHECK(s2->iv_len     == 12);
    CHECK(s2->tag_len    == 16);
    CHECK(s2->finished_len == 48);
    CHECK(s2->sigalg     == 0x0805);
    CHECK(s2->aead       == TLS13_AEAD_AES_256_GCM);

    /* --- 0x1303: TLS_CHACHA20_POLY1305_SHA256 --- */
    const tls13_suite_t *s3 = tls13_suite_by_id(0x1303);
    CHECK(s3 != NULL);
    CHECK(s3->id         == 0x1303);
    CHECK(s3->hash_len   == 32);
    CHECK(s3->key_len    == 32);
    CHECK(s3->iv_len     == 12);
    CHECK(s3->tag_len    == 16);
    CHECK(s3->finished_len == 32);
    CHECK(s3->sigalg     == 0x0804);
    CHECK(s3->aead       == TLS13_AEAD_CHACHA20_POLY1305);

    /* --- Unknown suite → NULL --- */
    CHECK(tls13_suite_by_id(0x1305) == NULL);
    CHECK(tls13_suite_by_id(0x0000) == NULL);

    /* --- Struct widening guards (landmine #2) ---
     * Ensure the session struct fields are wide enough for SHA-384 max. */
    CHECK(sizeof(((tls13_sess_t*)0)->c_finished_key) >= 48);
    CHECK(sizeof(((tls13_sess_t*)0)->s_finished_key) >= 48);
    CHECK(sizeof(((tls13_sess_t*)0)->c_hs_secret)    >= 48);
    CHECK(sizeof(((tls13_sess_t*)0)->s_hs_secret)    >= 48);
    CHECK(sizeof(((tls13_sess_t*)0)->master_secret)  >= 48);
    CHECK(sizeof(((tls13_sess_t*)0)->c_hs_key)       >= 32);
    CHECK(sizeof(((tls13_sess_t*)0)->s_hs_key)       >= 32);
    CHECK(sizeof(((tls13_sess_t*)0)->c_ap_key)       >= 32);
    CHECK(sizeof(((tls13_sess_t*)0)->s_ap_key)       >= 32);
    /* IVs stay [12] — don't widen */
    CHECK(sizeof(((tls13_sess_t*)0)->c_hs_iv)        == 12);
    CHECK(sizeof(((tls13_sess_t*)0)->s_hs_iv)        == 12);
    CHECK(sizeof(((tls13_sess_t*)0)->c_ap_iv)        == 12);
    CHECK(sizeof(((tls13_sess_t*)0)->s_ap_iv)        == 12);

    /* suite pointer exists on tls13_sess_t */
    CHECK(sizeof(((tls13_sess_t*)0)->suite) == sizeof(void*));

    fprintf(stdout, "=== PASS ===\n");
    return 0;
}
