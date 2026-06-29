/* sotOs · net-synth · SSH-2.0 transport state (arc-ζ).
 * ζ1: cleartext KEX (version + KEXINIT + curve25519-sha256 + rsa-sha2-256
 * host-key signature + KEX_ECDH_REPLY + NEWKEYS). ζ2 will extend ssh_conn_t
 * with the derived keys + per-direction seqnums/CTR counters for the
 * encrypted layer. */
#ifndef NET_SYNTH_SSH_TRANSPORT_H
#define NET_SYNTH_SSH_TRANSPORT_H
#include <stdint.h>
#include <bearssl.h>          /* br_aes_ct64_ctr_keys for the ζ2 cipher state */

#define SSH_RX_MAX   4096   /* per-conn inbound reassembly · holds client KEXINIT (~1.7K with
                             * PQ algo lists) + the 1190B sntrup761 KEX_ECDH_INIT coalesced */
#define SSH_IC_MAX   2560   /* client KEXINIT payload (I_C) capture (full OpenSSH 9.7 lists) */
#define SSH_VC_MAX    256   /* client ID line (V_C), CRLF stripped */
#define SSH_IS_MAX   1280   /* server KEXINIT payload (I_S) · full OpenSSH 9.7 algo lists (~1043B) */
#define SSH_PL_MAX   2560   /* decrypted-payload scratch (ζ2) */

/* SSH transport message numbers (ζ1 + ζ2 userauth) */
#define SSH_MSG_DISCONNECT      1
#define SSH_MSG_SERVICE_REQUEST 5
#define SSH_MSG_SERVICE_ACCEPT  6
#define SSH_MSG_KEXINIT         20
#define SSH_MSG_NEWKEYS         21
#define SSH_MSG_KEX_ECDH_INIT   30
#define SSH_MSG_KEX_ECDH_REPLY  31
#define SSH_MSG_USERAUTH_REQUEST 50
#define SSH_MSG_USERAUTH_FAILURE 51
#define SSH_MSG_USERAUTH_BANNER  53
/* SSH connection protocol (RFC 4254) — Phase A channel layer */
#define SSH_MSG_USERAUTH_SUCCESS       52
#define SSH_MSG_GLOBAL_REQUEST         80
#define SSH_MSG_REQUEST_FAILURE        82
#define SSH_MSG_CHANNEL_OPEN           90
#define SSH_MSG_CHANNEL_OPEN_CONFIRM   91
#define SSH_MSG_CHANNEL_OPEN_FAILURE   92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST  93
#define SSH_MSG_CHANNEL_DATA           94
#define SSH_MSG_CHANNEL_EOF            96
#define SSH_MSG_CHANNEL_CLOSE          97
#define SSH_MSG_CHANNEL_REQUEST        98
#define SSH_MSG_CHANNEL_SUCCESS        99
#define SSH_MSG_CHANNEL_FAILURE        100

enum { SSH_PHASE_FRESH = 0, SSH_PHASE_IDSENT, SSH_PHASE_KEXED, SSH_PHASE_AUTH };

typedef struct {
    uint16_t conn_id;
    uint8_t  used;
    uint8_t  phase;
    uint8_t  id_done;     /* client ID line parsed */
    uint8_t  aborted;     /* fatal protocol/overflow error → stop replying */
    uint32_t rxlen;
    uint32_t vc_len, ic_len, is_len;
    uint8_t  rx[SSH_RX_MAX];
    uint8_t  vc[SSH_VC_MAX];      /* client ID, CRLF stripped (for H) */
    uint8_t  ic[SSH_IC_MAX];      /* client KEXINIT payload I_C (verbatim) */
    uint8_t  is[SSH_IS_MAX];      /* server KEXINIT payload I_S (captured pre-frame) */
    uint8_t  scalar[32];          /* our ephemeral X25519 private scalar */
    uint8_t  qs[32];              /* our ephemeral X25519 public key Q_S */
    uint8_t  session_id[64];      /* = first exchange hash H (32B SHA256 / 64B SHA512) */
    /* ζ2 encrypted transport */
    uint8_t  k_raw[32];           /* X25519 shared secret (mpint-encoded for the KDF) */
    /* KEX-hash generalisation (curve25519-sha256 vs sntrup761x25519-sha512) */
    uint8_t  kex_sha512;          /* 0 = SHA256 KEX hash, 1 = SHA512 (hybrid PQ) */
    uint32_t sid_len;             /* exchange-hash length · 32 or 64 */
    uint8_t  k_enc[80];           /* K as it enters the §7.2 KDF: mpint(K) (curve25519) or string(hash) (hybrid) */
    uint32_t k_enc_len;
    uint32_t seq_in, seq_out;     /* per-direction packet seqnums (count cleartext pkts too) */
    uint8_t  send_enc, recv_enc;  /* encryption active per direction (post our/their NEWKEYS) */
    br_aes_ct64_ctr_keys cin, cout;   /* AES-128-CTR: decrypt c2s / encrypt s2c */
    uint8_t  iv_in[12], iv_out[12];   /* SSH 16B counter = iv12 || cc(be32), iv12 fixed */
    uint32_t cc_in, cc_out;           /* the 32-bit block counter, threaded via _run's return */
    uint8_t  mac_in[32], mac_out[32]; /* hmac-sha2-256 integrity keys (Int_c2s / Int_s2c) */
    /* chacha20-poly1305@openssh.com (negotiated cipher · AEAD, encrypted length) */
    uint8_t  cipher_chacha;           /* 1 = chacha20-poly1305, 0 = aes128-ctr+hmac */
    uint8_t  cc20_c2s[64], cc20_s2c[64];  /* per-direction K_2(0..32) || K_1(32..64) */
    /* aes{128,256}-gcm@openssh.com (RFC 5647 · AEAD, CLEARTEXT length, 16B GCM tag) */
    uint8_t  cipher_gcm;              /* 1 = aes-gcm@openssh.com (overrides cipher_chacha) */
    uint8_t  gcm_keylen;             /* 16 = aes128-gcm, 32 = aes256-gcm */
    br_aes_ct64_ctr_keys gcm_bc_in, gcm_bc_out;  /* AES-CTR block ctx backing GCM (c2s / s2c) */
    br_gcm_context gcm_in, gcm_out;              /* GCM AEAD contexts (decrypt c2s / encrypt s2c) */
    uint8_t  giv_in[12], giv_out[12];            /* 12B IV; low 8B = BE64 invocation counter, ++ per packet */
    /* negotiated host-key signature + strict-KEX (OpenSSH 9.7 HASSH match) */
    uint8_t  sig_sha512;              /* 1 = rsa-sha2-512 (sign SHA512(H)), 0 = rsa-sha2-256 */
    uint8_t  strict_kex;              /* 1 = kex-strict-{c,s}-v00 → reset seqnums after NEWKEYS */
    uint32_t pllen;
    uint8_t  pl[SSH_PL_MAX];      /* decrypted-payload scratch for dispatch */
    /* Phase A connection/channel protocol */
    uint8_t  auth_fails;     /* password attempts rejected so far (accept on the 3rd) */
    uint8_t  shell_active;   /* a "shell"/"exec" CHANNEL_REQUEST succeeded */
    uint8_t  shell_start_pending; /* Phase B · signal main.c to push SHELL_START (once) */
    uint8_t  client_eof;     /* Phase B · client sent CHANNEL_EOF/CLOSE → reap busybox */
    uint8_t  is_exec;        /* request was "exec" (`ssh host cmd`): run + close, not interactive */
    uint16_t exec_len;       /* bytes in exec_cmd (0 = interactive shell) */
    char     exec_cmd[256];  /* the exec command line (bounded; longer is truncated) */
    uint32_t peer_chan;      /* the client's sender-channel id (recipient for our channel msgs) */
    uint32_t peer_window;    /* client's advertised receive window (we decrement as we send DATA) */
} ssh_conn_t;

#endif /* NET_SYNTH_SSH_TRANSPORT_H */
