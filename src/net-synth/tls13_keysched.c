#include <string.h>
#include <net-synth/tls13_keysched.h>
#include <net-synth/tls13.h>
#include "tls13_wire.h"
#include <bearssl.h>

/* ── ε3: cipher suite table ─────────────────────────────────────────────── */
static const tls13_suite_t SUITES[] = {
    /* id      hash_vtable           hash_len aead                           key_len iv_len tag_len finished_len sigalg */
    { 0x1301, &br_sha256_vtable, 32, TLS13_AEAD_AES_128_GCM,       16, 12, 16, 32, 0x0804 },
    { 0x1302, &br_sha384_vtable, 48, TLS13_AEAD_AES_256_GCM,       32, 12, 16, 48, 0x0805 },
    { 0x1303, &br_sha256_vtable, 32, TLS13_AEAD_CHACHA20_POLY1305, 32, 12, 16, 32, 0x0804 },
};
const tls13_suite_t *tls13_suite_by_id(uint16_t id) {
    for (size_t i = 0; i < sizeof SUITES / sizeof SUITES[0]; i++)
        if (SUITES[i].id == id) return &SUITES[i];
    return NULL;
}

/* ── ε3: suite-threaded HKDF.  suite==NULL ⇒ SHA-256/32B (the ε1/ε2 default;
 * every existing call passes NULL and stays byte-identical).  suite==0x1302 ⇒
 * SHA-384/48B (the structural path).  The hash vtable is held in the descriptor
 * as const void*; cast back to const br_hash_class* and drive via the generic
 * br_hash_class init/update/out methods, and via br_hmac_key_init(vtable,...). */
static const br_hash_class *suite_hash(const tls13_suite_t *suite){
    return suite ? (const br_hash_class *)suite->hash_vtable : &br_sha256_vtable;
}
static size_t suite_hlen(const tls13_suite_t *suite){
    return suite ? (size_t)suite->hash_len : 32;
}

void tls13_transcript_hash(const tls13_suite_t *suite,
                           const uint8_t *msgs, size_t len, uint8_t *out){
    const br_hash_class *vt = suite_hash(suite);
    br_hash_compat_context c;
    vt->init(&c.vtable);
    vt->update(&c.vtable, msgs, len);
    vt->out(&c.vtable, out);                 /* writes suite->hash_len bytes */
}
void tls13_hkdf_extract(const tls13_suite_t *suite,
                        const uint8_t *salt,size_t sl,
                        const uint8_t *ikm,size_t il,uint8_t *out){
    const br_hash_class *vt = suite_hash(suite);
    size_t hlen = suite_hlen(suite);
    br_hmac_key_context kc; br_hmac_context hc;
    static const uint8_t zeros[48] = {0};
    if(!salt || sl==0){ salt=zeros; sl=hlen; }  /* HKDF salt default = HashLen zero bytes */
    br_hmac_key_init(&kc,vt,salt,sl);
    br_hmac_init(&hc,&kc,0); br_hmac_update(&hc,ikm,il); br_hmac_out(&hc,out);
}
static void hkdf_expand(const tls13_suite_t *suite,const uint8_t *secret,
                        const uint8_t *info,size_t il,uint8_t *out,size_t ol){
    const br_hash_class *vt = suite_hash(suite);
    size_t hlen = suite_hlen(suite);
    br_hmac_key_context kc; br_hmac_key_init(&kc,vt,secret,hlen);
    uint8_t t[48]; size_t tn=0,done=0; uint8_t ctr=1;
    while(done<ol){
        br_hmac_context hc; br_hmac_init(&hc,&kc,0);
        if(tn) br_hmac_update(&hc,t,tn);
        br_hmac_update(&hc,info,il); br_hmac_update(&hc,&ctr,1);
        br_hmac_out(&hc,t); tn=hlen; ctr++;
        size_t k=(ol-done<hlen)?(ol-done):hlen; memcpy(out+done,t,k); done+=k;
    }
}
void tls13_expand_label(const tls13_suite_t *suite,const uint8_t *secret,
                        const char *label,const uint8_t *ctx,size_t cl,
                        uint8_t *out,size_t ol){
    /* RFC 8446 §7.5 HkdfLabel — length-prefixed structure is hash-AGNOSTIC. */
    uint8_t info[520]; size_t p=0; char full[64]; int fl=0;
    const char *pre="tls13 ";
    for(const char*q=pre;*q;q++) full[fl++]=*q;
    for(const char*q=label;*q;q++) full[fl++]=*q;
    if(fl > 60){ memset(out,0,ol); return; }   /* defensive: no RFC 8446 label is this long */
    p+=tls13_wr16(info+p,(uint16_t)ol);
    info[p++]=(uint8_t)fl; memcpy(info+p,full,(size_t)fl); p+=(size_t)fl;
    info[p++]=(uint8_t)cl; if(cl){memcpy(info+p,ctx,cl); p+=cl;}
    hkdf_expand(suite,secret,info,p,out,ol);
}
void tls13_derive_secret(const tls13_suite_t *suite,const uint8_t *secret,
                         const char *label,const uint8_t *th,uint8_t *out){
    size_t hlen = suite_hlen(suite);
    tls13_expand_label(suite,secret,label,th,hlen,out,hlen);
}

/* RFC 8446 §7.1 key schedule.
 *   Early   = HKDF-Extract(0, 0)
 *   derived = Derive-Secret(Early, "derived", "")
 *   HS      = HKDF-Extract(derived, ECDHE)
 *   {c,s} hs traffic = Derive-Secret(HS, "{c,s} hs traffic", th_chsh)
 *   derived2 = Derive-Secret(HS, "derived", "")
 *   Master  = HKDF-Extract(derived2, 0)
 */
void tls13_key_schedule_handshake(tls13_sess_t *s, const uint8_t th_chsh[32]){
    /* ε3: all derivations driven by s->suite (NULL ⇒ SHA-256/16B-key, the ε1/ε2
     * default).  Secret/finished buffers are sized to SHA-384 max (48B); only the
     * first suite->hash_len bytes are written.  Local scratch sized to 48B max. */
    const tls13_suite_t *su = s->suite;
    size_t hlen = suite_hlen(su), klen = su ? (size_t)su->key_len : 16;
    uint8_t zero[48]={0}, early[48], derived[48], hs[48], empty_th[48];
    tls13_transcript_hash(su,(const uint8_t*)"",0,empty_th);
    tls13_hkdf_extract(su,NULL,0,zero,hlen,early);             /* Early Secret */
    tls13_derive_secret(su,early,"derived",empty_th,derived);
    tls13_hkdf_extract(su,derived,hlen,s->ecdhe_shared,s->ecdhe_shared_len,hs); /* Handshake Secret (IKM len = curve X-coord: 32 X25519/P-256, 48 P-384) */
    tls13_derive_secret(su,hs,"c hs traffic",th_chsh,s->c_hs_secret);
    tls13_derive_secret(su,hs,"s hs traffic",th_chsh,s->s_hs_secret);
    tls13_expand_label(su,s->c_hs_secret,"key",NULL,0,s->c_hs_key,klen);
    tls13_expand_label(su,s->c_hs_secret,"iv", NULL,0,s->c_hs_iv,12);
    tls13_expand_label(su,s->s_hs_secret,"key",NULL,0,s->s_hs_key,klen);
    tls13_expand_label(su,s->s_hs_secret,"iv", NULL,0,s->s_hs_iv,12);
    tls13_expand_label(su,s->c_hs_secret,"finished",NULL,0,s->c_finished_key,hlen);
    tls13_expand_label(su,s->s_hs_secret,"finished",NULL,0,s->s_finished_key,hlen);
    uint8_t derived2[48]; tls13_derive_secret(su,hs,"derived",empty_th,derived2);
    tls13_hkdf_extract(su,derived2,hlen,zero,hlen,s->master_secret); /* Master Secret */
}

/*   {c,s} ap traffic = Derive-Secret(Master, "{c,s} ap traffic", th_full) */
void tls13_key_schedule_application(tls13_sess_t *s, const uint8_t th_full[32]){
    const tls13_suite_t *su = s->suite;
    size_t klen = su ? (size_t)su->key_len : 16;
    uint8_t cs[48], ss[48];
    tls13_derive_secret(su,s->master_secret,"c ap traffic",th_full,cs);
    tls13_derive_secret(su,s->master_secret,"s ap traffic",th_full,ss);
    tls13_expand_label(su,cs,"key",NULL,0,s->c_ap_key,klen);
    tls13_expand_label(su,cs,"iv", NULL,0,s->c_ap_iv,12);
    tls13_expand_label(su,ss,"key",NULL,0,s->s_ap_key,klen);
    tls13_expand_label(su,ss,"iv", NULL,0,s->s_ap_iv,12);
}
