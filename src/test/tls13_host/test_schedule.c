/* test_schedule.c — TLS 1.3 full key schedule (RFC 8446 §7.1) gate.
 *
 * Validation mode: RFC 8448 §3 "Simple 1-RTT Handshake" ANCHOR (authoritative).
 * Golden hex copied byte-for-byte from https://www.rfc-editor.org/rfc/rfc8448.txt §3.
 * Suite TLS_AES_128_GCM_SHA256 (0x1301, SHA-256) — identical to ε1, values apply directly.
 *
 * We feed the RFC ECDHE shared secret + the two transcript hashes into our C
 * key schedule and assert every derived secret / key / iv matches the RFC.
 * This independently validates the C (the inputs+outputs are the spec's, not ours).
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <net-synth/tls13.h>
#include <net-synth/tls13_keysched.h>

static int hexeq(const uint8_t *a, const char *hex, int n){
    for(int i=0;i<n;i++){ unsigned v; if(sscanf(hex+2*i,"%2x",&v)!=1) return 0;
        if(a[i]!=(uint8_t)v){ fprintf(stderr,"  mismatch at byte %d: got %02x want %02x\n",i,a[i],(uint8_t)v); return 0; } }
    return 1;
}
static void unhex(const char *hex, uint8_t *out, int n){
    for(int i=0;i<n;i++){ unsigned v; sscanf(hex+2*i,"%2x",&v); out[i]=(uint8_t)v; }
}

/* ---- RFC 8448 §3 golden vectors (TLS_AES_128_GCM_SHA256) ---- */
/* ECDHE shared secret (IKM for the "handshake" extract), RFC §3 lines 267-268 */
#define RFC_ECDHE     "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
/* Hash(ClientHello..ServerHello), used to derive hs traffic secrets, lines 287-288 */
#define RFC_TH_CHSH   "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
/* client/server handshake traffic secrets, lines 294-295 / 309-310 */
#define RFC_C_HS_SEC  "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
#define RFC_S_HS_SEC  "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
/* client handshake write key (16B) / iv (12B) — from RFC_C_HS_SEC via expand_label("key"/"iv") */
#define RFC_C_HS_KEY  "dbfaa693d1762c5b666af5d950258d01"
#define RFC_C_HS_IV   "5bd3c71b836e0b76bb73265f"
/* server handshake write key (16B) / iv (12B), lines 367-368 / 372 */
#define RFC_S_HS_KEY  "3fce516009c21727d0f2e4e86ee403bc"
#define RFC_S_HS_IV   "5d313eb2671276ee13000b30"
/* master secret, lines 343-344 */
#define RFC_MASTER    "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
/* Hash(ClientHello..server Finished), used for app traffic secrets, lines 537-538 */
#define RFC_TH_FULL   "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
/* client/server application traffic secret 0, lines 544-545 / 567-568 */
#define RFC_C_AP_SEC  "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"
#define RFC_S_AP_SEC  "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
/* server application write key (16B) / iv (12B), lines 592-593 / 597 */
#define RFC_S_AP_KEY  "9f02283b6c9c07efc26bb9f2ac92e356"
#define RFC_S_AP_IV   "cf782b88dd83549aadf1e984"

/* ── ε2 task 7(c): P-384 key-schedule vector (48-byte IKM) ───────────────────
 * Proves the keysched IKM-length change (tls13_hkdf_extract honors
 * s->ecdhe_shared_len) is correct for P-384.  ECDHE = oracle_ecdh.py's P384
 * SHARED (48B X-coordinate); the golden is the SAME RFC 8446 §7.1 ladder run
 * with a 48B IKM, computed independently in Python (oracle_schedule.py P-384
 * section, TH_CHSH = SHA-256("sotos-p384-th-chsh")).  X25519/P-256 use a 32B
 * shared → the ladder is unchanged for them (the RFC 8448 anchor above proves
 * byte-identity); this vector is the ONLY thing the 48B path changes. */
#define P384_ECDHE    "40507e0769c6022e52cb96c95a0e7950e89d9a3e94ac482947fbcd8f17309dc7ca28cf6adc256f3b7a122ba20725191f"
#define P384_TH_CHSH  "fb3b1921f218e919a47e97f61c781ed1d2ffb6fc41ffd80589692b025f6995aa"
#define P384_C_HS_SEC "414fe14b4060c77250f76d9e0949abad53816ce67f85eb535cfcf8b6267fdbf2"
#define P384_S_HS_SEC "8d43055e4701b58dad7511610e0902fcdb5608ae6abbc4d3cee8f9257a1e91b1"
#define P384_C_HS_KEY "1c19be2b87b3ec7c685002484623eac6"
#define P384_C_HS_IV  "adf8106c7ba973ef49c260c8"
#define P384_S_HS_KEY "251ce295ad628caf5f908358c70ea48a"
#define P384_S_HS_IV  "037f57d43c762516f7c25274"
#define P384_MASTER   "45dc58dcac04033bd7bac639290511acea8aa387172689dfe2c260609e3c6716"

/* ── ε3 task A2: SHA-384 key schedule (suite 0x1302, TLS_AES_256_GCM_SHA384) ──
 * The STRUCTURAL change: H=SHA-384, HLEN=48 → every secret/finished is 48B, the
 * AEAD key is 32B (AES-256), iv stays 12B.  Goldens are the INDEPENDENT Python
 * SHA-384 ladder (oracle_schedule.py "SHA-384 (suite 0x1302)" block), NOT a C
 * mirror.  Inputs: TH_CHSH=SHA-384("sotos-1302-th-chsh"),
 * TH_FULL=SHA-384("sotos-1302-th-full"), ECDHE = the 48B P-384 shared reused.
 * The schedule is driven with s.suite = tls13_suite_by_id(0x1302). */
#define S384_ECDHE    P384_ECDHE   /* reuse the 48B P-384 shared secret */
#define S384_TH_CHSH  "e13a84abd80aa10075e8f28f84334771925270465137c11b1ed8ebdb297665b56d0e8dd5b96d4061d70f26fac06f0a53"
#define S384_TH_FULL  "31e5c8a67bdb153145658828f476f7875359dcca1d534258ea434a8dc63f906be50ae2ea801384205a3754831798c8e2"
#define S384_C_HS_SEC "164f13f729ca4ecfa09ce8e86d54bfe678c076c5057258c4613980c8c93ae2921bfcbe18deede67ef9b4b4b78c6a52d2"
#define S384_S_HS_SEC "e1884b84860759faf7106d31f2811eda2778d838f736f27ed113c6d34d2ba2081cec9d84959b182e39b16da729acbdcc"
#define S384_C_HS_KEY "acb5dbf187e077367899fc2907b106b48df31a637a88fb7a25d8529f013bd02a"
#define S384_C_HS_IV  "4d01fe4d11bab8043247dbf8"
#define S384_S_HS_KEY "f8896bb93d54487717dbf65d5d8b75777e5bba406dc555b3354d5ff63af9b39a"
#define S384_S_HS_IV  "e074a258211ab2d194667d0b"
#define S384_C_FIN    "e13c3937a175472fb502d7cf9e7e50786b494388366802b68e06dca57bc8a96e040b41c666bbbcebd6296f21a08eaa3b"
#define S384_S_FIN    "ee0c541736118553f8626c69b0a7ee755d4975d4e8423c966a0ecccbe87e4a9bab1d97c5ebad89c50f5f33f0b0ee8e90"
#define S384_MASTER   "26cea81ac411e3f546198991d5475709bf3d3d1c546d263d581facef885053a8648a9bd297be8bbca5206fc01f5331c5"
#define S384_C_AP_SEC "802451ec23d33d61531bfe78a7859f78109cadce6d496a2471e22518021d857a7cf33f5fee65774d5e3dc551b1bc25e9"
#define S384_S_AP_SEC "d9681f161ecd8e00fe11696e091036737494eef67ddb82ccd23b01486603b18fb0503ecf2f311631a1d2e4526b90bd81"
#define S384_C_AP_KEY "0316df5007a330ccfa3e70f3aceb901faa376ddc199f3bf4dec3df06d139026f"
#define S384_C_AP_IV  "a2c2d720ec0c2a2cbe9f1546"
#define S384_S_AP_KEY "e4c523f4d4b8f63c23dbd0dcbfec53f74816817e445e0aec9c3f61619ed7efab"
#define S384_S_AP_IV  "cb10bf6f8e6551b7ee3c860c"

int main(void){
    tls13_sess_t s; memset(&s,0,sizeof s);
    uint8_t th_chsh[32], th_full[32];
    unhex(RFC_ECDHE, s.ecdhe_shared, 32);
    s.ecdhe_shared_len = 32;   /* X25519/P-256 path: 32B IKM (byte-identical to ε1) */
    unhex(RFC_TH_CHSH, th_chsh, 32);
    unhex(RFC_TH_FULL, th_full, 32);

    /* --- handshake stage --- */
    tls13_key_schedule_handshake(&s, th_chsh);
    assert(hexeq(s.c_hs_secret, RFC_C_HS_SEC, 32) && "client hs traffic secret");
    assert(hexeq(s.s_hs_secret, RFC_S_HS_SEC, 32) && "server hs traffic secret");
    assert(hexeq(s.c_hs_key,    RFC_C_HS_KEY, 16) && "client hs key");
    assert(hexeq(s.c_hs_iv,     RFC_C_HS_IV,  12) && "client hs iv");
    assert(hexeq(s.s_hs_key,    RFC_S_HS_KEY, 16) && "server hs key");
    assert(hexeq(s.s_hs_iv,     RFC_S_HS_IV,  12) && "server hs iv");
    assert(hexeq(s.master_secret, RFC_MASTER, 32) && "master secret");

    /* finished keys: derive independently from the RFC hs secrets and compare
     * (RFC §3 server finished PRK = s_hs_secret; the "finished" expanded value is
     * 008d3b66... at lines 433-434). We re-derive via our expand_label to confirm. */
    uint8_t s_fin[32];
    tls13_expand_label(NULL,s.s_hs_secret,"finished",NULL,0,s_fin,32);
    assert(hexeq(s_fin,"008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8",32) && "server finished key");
    assert(memcmp(s_fin, s.s_finished_key, 32)==0 && "s_finished_key populated by schedule");
    uint8_t c_fin[32];
    tls13_expand_label(NULL,s.c_hs_secret,"finished",NULL,0,c_fin,32);
    assert(hexeq(c_fin,"b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4",32) && "client finished key");
    assert(memcmp(c_fin, s.c_finished_key, 32)==0 && "c_finished_key populated by schedule");

    /* --- application stage --- */
    tls13_key_schedule_application(&s, th_full);
    assert(hexeq(s.s_ap_key, RFC_S_AP_KEY, 16) && "server app key");
    assert(hexeq(s.s_ap_iv,  RFC_S_AP_IV,  12) && "server app iv");
    /* The app traffic secrets are intermediate (not stored in tls13_sess), so we
     * confirm them by re-deriving from master_secret + th_full and checking they
     * produce the RFC server app key/iv we already asserted, plus assert the
     * client app key derives from the RFC client app secret. */
    uint8_t cs[32], ss[32], k[16], iv[12];
    tls13_derive_secret(NULL,s.master_secret,"c ap traffic",th_full,cs);
    tls13_derive_secret(NULL,s.master_secret,"s ap traffic",th_full,ss);
    assert(hexeq(cs, RFC_C_AP_SEC, 32) && "client app traffic secret");
    assert(hexeq(ss, RFC_S_AP_SEC, 32) && "server app traffic secret");
    /* client app key/iv land in c_ap_key/c_ap_iv; cross-check via independent derive */
    tls13_expand_label(NULL,cs,"key",NULL,0,k,16);
    tls13_expand_label(NULL,cs,"iv", NULL,0,iv,12);
    assert(memcmp(k, s.c_ap_key, 16)==0 && "c_ap_key matches independent derive");
    assert(memcmp(iv, s.c_ap_iv, 12)==0 && "c_ap_iv matches independent derive");

    /* ── ε2 task 7(c): P-384 key schedule with a 48-byte IKM ────────────────
     * Run the SAME tls13_key_schedule_handshake with ecdhe_shared_len==48 and
     * assert every handshake secret/key/iv + master match the independent
     * Python 48B-IKM ladder (oracle_schedule.py).  This is the only behavior the
     * IKM-length change alters; X25519/P-256 (32B) stay byte-identical above. */
    {
        tls13_sess_t p; memset(&p,0,sizeof p);
        uint8_t p_th_chsh[32];
        unhex(P384_ECDHE, p.ecdhe_shared, 48);
        p.ecdhe_shared_len = 48;
        unhex(P384_TH_CHSH, p_th_chsh, 32);
        tls13_key_schedule_handshake(&p, p_th_chsh);
        assert(hexeq(p.c_hs_secret, P384_C_HS_SEC, 32) && "P-384 client hs traffic secret (48B IKM)");
        assert(hexeq(p.s_hs_secret, P384_S_HS_SEC, 32) && "P-384 server hs traffic secret (48B IKM)");
        assert(hexeq(p.c_hs_key,    P384_C_HS_KEY, 16) && "P-384 client hs key (48B IKM)");
        assert(hexeq(p.c_hs_iv,     P384_C_HS_IV,  12) && "P-384 client hs iv (48B IKM)");
        assert(hexeq(p.s_hs_key,    P384_S_HS_KEY, 16) && "P-384 server hs key (48B IKM)");
        assert(hexeq(p.s_hs_iv,     P384_S_HS_IV,  12) && "P-384 server hs iv (48B IKM)");
        assert(hexeq(p.master_secret, P384_MASTER, 32) && "P-384 master secret (48B IKM)");
    }

    /* ── ε3 task A2: SHA-384 key schedule (suite 0x1302) ────────────────────
     * Drive the SAME tls13_key_schedule_handshake/_application with
     * s.suite = tls13_suite_by_id(0x1302) → H=SHA-384, HLEN=48, key=32B.  Assert
     * every secret/finished/key/iv (48B / 32B / 12B) matches the independent
     * Python SHA-384 ladder (oracle_schedule.py "SHA-384 (suite 0x1302)").  This
     * is the structural ε3 change; the SHA-256 anchors above prove 0x1301 stays
     * byte-identical (regression). */
    {
        tls13_sess_t q; memset(&q,0,sizeof q);
        q.suite = tls13_suite_by_id(0x1302);
        assert(q.suite && q.suite->hash_len==48 && q.suite->key_len==32 && "0x1302 suite present");
        uint8_t q_th_chsh[48], q_th_full[48];
        unhex(S384_ECDHE, q.ecdhe_shared, 48);
        q.ecdhe_shared_len = 48;
        unhex(S384_TH_CHSH, q_th_chsh, 48);
        unhex(S384_TH_FULL, q_th_full, 48);

        tls13_key_schedule_handshake(&q, q_th_chsh);
        assert(hexeq(q.c_hs_secret, S384_C_HS_SEC, 48) && "0x1302 client hs traffic secret (SHA-384)");
        assert(hexeq(q.s_hs_secret, S384_S_HS_SEC, 48) && "0x1302 server hs traffic secret (SHA-384)");
        assert(hexeq(q.c_hs_key,    S384_C_HS_KEY, 32) && "0x1302 client hs key (AES-256)");
        assert(hexeq(q.c_hs_iv,     S384_C_HS_IV,  12) && "0x1302 client hs iv");
        assert(hexeq(q.s_hs_key,    S384_S_HS_KEY, 32) && "0x1302 server hs key (AES-256)");
        assert(hexeq(q.s_hs_iv,     S384_S_HS_IV,  12) && "0x1302 server hs iv");
        assert(hexeq(q.c_finished_key, S384_C_FIN, 48) && "0x1302 client finished key (48B)");
        assert(hexeq(q.s_finished_key, S384_S_FIN, 48) && "0x1302 server finished key (48B)");
        assert(hexeq(q.master_secret, S384_MASTER, 48) && "0x1302 master secret (SHA-384)");

        tls13_key_schedule_application(&q, q_th_full);
        assert(hexeq(q.c_ap_key, S384_C_AP_KEY, 32) && "0x1302 client app key (AES-256)");
        assert(hexeq(q.c_ap_iv,  S384_C_AP_IV,  12) && "0x1302 client app iv");
        assert(hexeq(q.s_ap_key, S384_S_AP_KEY, 32) && "0x1302 server app key (AES-256)");
        assert(hexeq(q.s_ap_iv,  S384_S_AP_IV,  12) && "0x1302 server app iv");
    }

    printf("test_schedule OK (RFC 8448 §3 X25519 anchor + P-384 48B-IKM vector + SHA-384 0x1302 ladder: all match)\n");
    return 0;
}
