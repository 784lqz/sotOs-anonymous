#ifndef SOTABI_PROTO_H
#define SOTABI_PROTO_H
/*
 * sotabi · the formal NATIVE sotOs ABI (M4).
 *
 * sotabi is the seL4-IPC contract a NATIVE sotOs binary uses to reach truth-core
 * — the THIRD world's syscall surface, distinct from the Linux ABI (LUCAS) and
 * Win32 (Wine).  A native program (e.g. sotctl) seL4_Call's its libsot endpoint
 * (handed to it in argv[1] at spawn); orch's libsot handler services the op
 * against truth-core and Replies.  No Linux syscalls, no /proc.
 *
 * ── Versioning ────────────────────────────────────────────────────────────
 * SOTABI_VERSION is the contract version.  A native binary verifies it with
 * OP_HELLO before issuing any other op; a mismatch is a hard stop (the binary
 * and orch were built against different ABIs).
 *
 * ── Wire envelope (message registers) ─────────────────────────────────────
 * Request:  MR0 = op (SOTABI_OP_*)
 *           MR1 = arg0   (op-specific; e.g. render-pull byte offset)
 *           MR2 = arg1   (op-specific; reserved)
 * Reply:    MR0 = status (SOTABI_OK or SOTABI_E_*)
 *           MR1.. = op-specific payload
 *
 * ── Ops ───────────────────────────────────────────────────────────────────
 *  OP_HELLO        reply: MR1 = SOTABI_VERSION                  (handshake)
 *  OP_STATS        reply: MR1 = n_sessions, MR2 = n_live_procs  (health)
 *  OP_RENDER_PULL  arg0 = byte offset already consumed;
 *                  reply: MR1 = nbytes this chunk (0 = end of stream),
 *                         MR2.. = the chunk's bytes packed 8-per-word (LE).
 *                  orch renders the operator-chosen content op (server-side
 *                  state) once at offset 0 and streams it in chunks.
 *
 * The CONTENT ops below name what OP_RENDER_PULL renders.  They are chosen by
 * the operator (typed `sotctl <sub>`) and held server-side, so the render
 * client stays content-agnostic — it just pulls bytes.
 */

#define SOTABI_VERSION         1

/* Transport ops (the request MR0). */
#define SOTABI_OP_HELLO        0x10   /* version handshake */
#define SOTABI_OP_STATS        0x11   /* health counts */
#define SOTABI_OP_RENDER_PULL  0x12   /* pull the next render-stream chunk */

/* Reply status codes (the reply MR0). */
#define SOTABI_OK              0
#define SOTABI_E_BADOP         1      /* unknown op */
#define SOTABI_E_BADVER        2      /* version mismatch */

/* Content ops — what OP_RENDER_PULL renders (operator-selected, server-held). */
#define SOTABI_OP_SESSIONS     2      /* live attacker sessions */
#define SOTABI_OP_PROCESS      3      /* the TRUE live process list */
#define SOTABI_OP_OVERLAY      4      /* contained writes (arg = session filter) */
#define SOTABI_OP_ANOMALY      5      /* the security-event ring */
#define SOTABI_OP_TRACE        6      /* the sottrace audit stream */
#define SOTABI_OP_WAL          7      /* the deception-replay log status */
#define SOTABI_OP_HELP         8      /* the subcommand help */
/* CONTROL ops · these MUTATE the deception host (the native plane is not just a
 * viewer).  Rendered like a content op — the render is the confirmation text —
 * but the act happens server-side when orch serves the render. */
#define SOTABI_OP_REAP         9      /* reap a session's contained overlay (arg = session) */
#define SOTABI_OP_POLICY_NET  10      /* attacker net-egress policy (arg: 0=off, 1=on, 2=query) */
#define SOTABI_OP_PROMOTE     11      /* escalate a live sotbox's tier (arg = display pid) */
#define SOTABI_OP_QUARANTINE  12      /* max-contain a live sotbox (arg = display pid) */
#define SOTABI_OP_REPLAY      13      /* export the WAL deception-replay timeline (per-record) */
#define SOTABI_OP_CANARY      14      /* canary tripwire inventory + live read-hits (IOCs) */
#define SOTABI_OP_PERSONA     15      /* persona list/set (arg: 0=set-alpine,1=set-debian,2=set-auto,3=list) */

/* Render-stream chunk size: payload words per reply (8 bytes each).  64 words =
 * 512 bytes/chunk; reply length 1(status)+1(nbytes)+64 = 66 stays under
 * seL4_MsgMaxLength (120). */
#define SOTABI_CHUNK_WORDS    64
#define SOTABI_CHUNK_BYTES    (SOTABI_CHUNK_WORDS * 8)

#endif /* SOTABI_PROTO_H */
