#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <net-synth/tls13.h>
#include <net-synth/tls13_keysched.h>
static int eq(const uint8_t*a,const char*hex){
    for(int i=0;i<32;i++){ unsigned v; sscanf(hex+2*i,"%2x",&v); if(a[i]!=(uint8_t)v) return 0; } return 1; }
static int eqn(const uint8_t*a,const char*hex,int n){
    for(int i=0;i<n;i++){ unsigned v; sscanf(hex+2*i,"%2x",&v); if(a[i]!=(uint8_t)v) return 0; } return 1; }
int main(void){
    /* SHA-256 path (suite=NULL → default): regression, byte-identical to ε1. */
    uint8_t emptyhash[32]; tls13_transcript_hash(NULL,(const uint8_t*)"",0,emptyhash);
    assert(eq(emptyhash,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    uint8_t secret[32]={0}, out[32];
    tls13_derive_secret(NULL,secret,"derived",emptyhash,out);
    assert(eq(out,"70735bf7c7bab21c1f802d8eab67e6fac3c48974f1c9caf8c99962acd585bbd8"));
    uint8_t zeros[32]={0}, prk[32];
    tls13_hkdf_extract(NULL,NULL,0,zeros,32,prk);          /* default salt + 32-zero IKM = TLS1.3 Early Secret */
    assert(eq(prk,"33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"));
    tls13_hkdf_extract(NULL,NULL,0,(const uint8_t*)"",0,prk);
    assert(eq(prk,"b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"));

    /* ── ε3 task A2: RFC 4231 §4.5 HMAC-SHA-384 known-answer vector ──────────
     * Anchors the br_sha384_vtable HMAC wiring INDEPENDENTLY of the schedule.
     * tls13_hkdf_extract is HMAC(salt=key, ikm=data); driving it with the 0x1302
     * suite (→ SHA-384) over RFC 4231 Test Case 4 (key=0x01..0x19 25B,
     * data=0xcd×50) must reproduce the RFC's pinned MAC.  Golden from RFC 4231
     * §4.5 (authoritative external vector, not a C mirror). */
    const tls13_suite_t *s1302 = tls13_suite_by_id(0x1302);
    assert(s1302 && s1302->hash_len==48 && "0x1302 suite (SHA-384) present");
    uint8_t tc4_key[25]; for(int i=0;i<25;i++) tc4_key[i]=(uint8_t)(i+1);  /* 0x01..0x19 */
    uint8_t tc4_data[50]; memset(tc4_data,0xcd,50);
    uint8_t tc4_mac[48];
    tls13_hkdf_extract(s1302, tc4_key, 25, tc4_data, 50, tc4_mac);
    assert(eqn(tc4_mac,
        "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e"
        "6801dd23c4a7d679ccf8a386c674cffb", 48) && "RFC 4231 §4.5 HMAC-SHA-384 KAT");

    printf("test_keysched OK\n");
    return 0;
}
