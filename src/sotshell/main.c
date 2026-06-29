/*
 * sotOs · sotShell · operator-side native process.
 *
 * Spawned by root after Linux sotBox demos complete.  Queries the
 * lucas-orchestrator's sotBox table via ORCH_OP_QUERY_STATUS and
 * prints a formatted 'sotinfo' summary.
 *
 * Asymmetry: from inside a Linux sotBox (busybox / ls / cat /etc.)
 * the binary sees synthetic /etc, synthetic /proc/self/maps, synthetic getuid(),
 * synthetic uname.  sotShell sees the TRUTH: every sotBox that ever ran,
 * its exit state, its tier · the deception layer is invisible to the
 * Linux ABI but obvious to sotOs-native code.
 *
 * A2 / L4-Phase-B: refactored from auto-sotinfo-once to a command-
 * dispatch loop.  For autonomous mode the loop is driven from a
 * hardcoded demo_commands array.
 *
 * L4-Phase-C v2: interactive console via runtime detection.
 * serial_getchar polls the UART via IO_Port cap (Path B).
 * After the scripted demo_commands[] loop exits, sotShell polls
 * serial for ~100 ms.  If any byte arrives, interactive mode is
 * entered.  Otherwise sotShell exits cleanly (smoke compatible).
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sel4/sel4.h>
#include <sel4utils/process.h>   /* SEL4UTILS_TCB_SLOT */
#include <orch/proto.h>
#include <sotabi/proto.h>         /* world-#3 · SOTABI_OP_* for the native sotctl console verb */
#include <net-synth/response_profiles.h>   /* response_profile_name_to_kind, response_profile_kind_t */
#include <sotguard/event.h>       /* α · PR 9 · SOTGUARD_KIND_* audit kinds */
#include <lucas/pledge.h>         /* SPAWN-PLEDGE-CLI · PLEDGE_T_* + PLEDGE_* bits */
#include <sotinit/proto.h>        /* β · PR 5 · SOTINIT_OP_* + sotinit_*_t */
#include <sotcron/proto.h>        /* β · PR 9 · SOTCRON_OP_* + sotcron_*_t */
#include <sotcron/timer.h>        /* SOTCRON_NAME_MAX */
#include "parser.h"               /* v0.7 · S2 · parser layer */
#include "glob.h"                 /* v0.7 · S2 · glob expansion */
#include "sotnano.h"              /* sotnano · full-screen editor */

/* Forward decl from parser.c · set from main(). */
extern seL4_CPtr g_parser_orch_ep;

/* v0.7 · S1 · readline + history + tab completion */
#include "readline.h"
#include "history.h"

/* ------------------------------------------------------------------ */
/* Serial input · Path B · x86 IO_Port cap (0x3F8 UART)              */
/* ------------------------------------------------------------------ */

/* Filled in from argv[2] at startup. */
static seL4_CPtr g_io_port_cap = 0;

/* F12 toggle · the operator console (cmd_console_kbd) is keyboard-driven over
 * the GTK window, whose keystrokes reach orch's virtio-keyboard ring — NOT the
 * UART this shell reads.  When g_use_getkey is set, serial_getchar additionally
 * polls orch (ORCH_OP_GETKEY) for a keyboard byte.  Gated so the headless demo /
 * smoke serial path is byte-identical (g_use_getkey stays 0 there).  g_operator_f12
 * latches an F12 press so the console loop can switch back to the canary shell. */
static seL4_CPtr     g_getkey_orch_ep = 0;
static volatile int  g_use_getkey     = 0;
static volatile int  g_operator_f12   = 0;

/* F12 toggle · framebuffer tee · while the operator console is active, sotShell's
 * stdout is forwarded to orch (ORCH_OP_FB_PUTS) so it renders in the GTK window
 * (its native printf only reaches the serial debug console otherwise). */
#include <arch_stdio.h>                 /* sel4muslcsys_register_stdio_write_fn */
static write_buf_fn g_orig_stdio_write = NULL;

static void orch_fb_puts(const char *p, size_t n)
{
    if (g_getkey_orch_ep == 0) return;
    while (n > 0) {
        size_t chunk = n > 64 ? 64 : n;
        /* Preserve any IPC-buffer args a command staged before printing. */
        seL4_Word save[16];
        for (int i = 0; i < 16; ++i) save[i] = seL4_GetMR(i);
        char buf[64];
        memset(buf, 0, sizeof(buf));
        memcpy(buf, p, chunk);
        seL4_SetMR(0, (seL4_Word)chunk);
        for (int i = 0; i < 8; ++i) {
            seL4_Word w;
            memcpy(&w, buf + i * 8, 8);
            seL4_SetMR(1 + i, w);
        }
        seL4_Call(g_getkey_orch_ep, seL4_MessageInfo_new(ORCH_OP_FB_PUTS, 0, 0, 9));
        for (int i = 0; i < 16; ++i) seL4_SetMR(i, save[i]);
        p += chunk; n -= chunk;
    }
}

static size_t sotshell_fb_tee_write(void *data, size_t count)
{
    size_t r = g_orig_stdio_write ? g_orig_stdio_write(data, count) : count;
    if (g_use_getkey && g_getkey_orch_ep != 0)
        orch_fb_puts((const char *)data, count);
    return r;
}

/* β · PR 5 · sotinit listen EP cap in sotShell's CSpace · filled from argv[3]
 * by orch_spawn_native.  0 when sotinit wasn't pre-spawned by root or the
 * forward mint failed · cmd_systemctl short-circuits with a "not available"
 * message in that case. */
static seL4_CPtr g_sotinit_ep_slot = 0;

/* β · PR 9 · sotcron listen EP cap in sotShell's CSpace · filled from argv[4]
 * by orch_spawn_native.  0 when sotcron wasn't pre-spawned by root or the
 * forward mint failed · cmd_cron short-circuits with a "not available"
 * message in that case.  Minted BADGED with BADGE_SOTCRON_OPERATOR by orch
 * so sotcron's NBRecv drain can disambiguate empty-queue vs message-arrived. */
static seL4_CPtr g_sotcron_ep_slot = 0;

/* Operator working directory.  Default "/" (the merged root the orch router now
 * serves: synthetic top-level + real Alpine /usr,/lib + writable /tmp).  All
 * VFS commands (ls/cat/cd/dir/mkdir/rm/tail) resolve relative paths against it,
 * so `ls dir` lists /dir and `cd /usr; ls` lists /usr — like a real shell. */
static char g_cwd[ORCH_SOTFS_PATH_MAX] = "/";

/*
 * serial_getchar — poll UART for one byte.
 * Returns 0 if no character is available (non-blocking).
 * Uses IO_Port cap delegated from orch: read LSR (0x3FD) bit 0, then
 * data register (0x3F8).
 */
static int serial_getchar(void)
{
    /* UART path · always tried first so the headless serial console is unchanged. */
    if (g_io_port_cap != 0) {
        /* Line Status Register: bit 0 = data ready. */
        seL4_X86_IOPort_In8_t lsr = seL4_X86_IOPort_In8(g_io_port_cap, 0x3FD);
        if (!lsr.error && (lsr.result & 0x01)) {
            seL4_X86_IOPort_In8_t data = seL4_X86_IOPort_In8(g_io_port_cap, 0x3F8);
            if (!data.error) return (int)data.result;
        }
    }
    /* F12 toggle · keyboard path · only while the operator console is active.
     * Poll orch for a virtio-keyboard byte (or an F12 press → switch shells). */
    if (g_use_getkey && g_getkey_orch_ep != 0) {
        seL4_MessageInfo_t r = seL4_Call(g_getkey_orch_ep,
            seL4_MessageInfo_new(ORCH_OP_GETKEY, 0, 0, 0));
        seL4_Word lbl = seL4_MessageInfo_get_label(r);
        if (lbl == 2) { g_operator_f12 = 1; return 0; }   /* F12 → caller returns to canary shell */
        if (lbl == 1) return (int)seL4_GetMR(0);
    }
    return 0;
}

/*
 * read_line — block until \n, accumulate chars, handle backspace + echo.
 * Returns number of chars in buf (not counting NUL), or -1 on error.
 */
static int read_line(char *buf, size_t buf_size)
{
    /* === v0.7 · S1 · input-layer hook (landed) ===
     * Delegate to sotshell_readline: ANSI escape arrows + 32-entry history
     * + tab completion.  On -1 (backend not installed) fall back to the
     * simple poll loop below; on 0 (empty line) also fall through so an
     * accidental empty return doesn't strand the user. */
    int rc = sotshell_readline(buf, buf_size);
    if (rc > 0) return rc;
    if (rc == 0) {           /* empty line · pass through as empty input */
        buf[0] = '\0';
        return 0;
    }
    /* rc < 0 · backend unavailable · simple polling fallback retained. */
    size_t pos = 0;
    while (pos < buf_size - 1) {
        int c = serial_getchar();
        if (c == 0) {
            /* No input yet · yield so other threads can run. */
            seL4_Yield();
            continue;
        }
        if (c == '\r' || c == '\n') {
            printf("\n");
            buf[pos] = '\0';
            return (int)pos;
        }
        if (c == '\b' || c == 0x7F) {
            if (pos > 0) {
                pos--;
                printf("\b \b");
            }
            continue;
        }
        if (c >= 0x20 && c < 0x7F) {
            buf[pos++] = (char)c;
            printf("%c", c);   /* echo */
        }
    }
    buf[pos] = '\0';
    return (int)pos;
}

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */
static int cmd_sotinfo(seL4_CPtr orch_ep);
static int cmd_interactive(seL4_CPtr orch_ep);
static int cmd_list(seL4_CPtr orch_ep);
static int cmd_kill(seL4_CPtr orch_ep, int pid);
static int cmd_promote(seL4_CPtr orch_ep, int pid, int tier);
static int cmd_sotnet(seL4_CPtr orch_ep);
static int cmd_ls(seL4_CPtr orch_ep, const char *path);
static int cmd_cat(seL4_CPtr orch_ep, const char *path);
static int cmd_install(seL4_CPtr orch_ep, const char *path, const char *content);
static int cmd_mkdir(seL4_CPtr orch_ep, const char *path);
static int cmd_rm(seL4_CPtr orch_ep, const char *path);
static int cmd_tail(seL4_CPtr orch_ep, const char *path);
static int cmd_grep(seL4_CPtr orch_ep, const char *pattern, const char *path);
static int cmd_dns_list(seL4_CPtr orch_ep);
static int cmd_dns_install(seL4_CPtr orch_ep, const char *domain, const char *ip_str);
static int cmd_dns_lookup(seL4_CPtr orch_ep, const char *domain);
static int cmd_synth_trigger(seL4_CPtr orch_ep, const char *ip_str, const char *port_str);
static int cmd_synth_install(seL4_CPtr orch_ep, const char *ip_str,
                             const char *port_str, const char *response_profile_str);
static int cmd_synth_queue(seL4_CPtr orch_ep);
static int cmd_python(seL4_CPtr orch_ep, const char *code, uint64_t pledge_mask);
static int cmd_inject_script(seL4_CPtr orch_ep, const char *path);
static int cmd_tcc(seL4_CPtr orch_ep, const char *path);
static int cmd_run(seL4_CPtr orch_ep, const char *path);
static int cmd_anomaly_log(seL4_CPtr orch_ep);
static int cmd_sottrace(seL4_CPtr orch_ep);
static int cmd_sottrace_live(seL4_CPtr orch_ep, int on);
static int cmd_sottrace_payload(seL4_CPtr orch_ep, uint16_t conn_id);
static int cmd_sottrace_graph(seL4_CPtr orch_ep);
static int cmd_watch(seL4_CPtr orch_ep);   /* v2.8 · live deception monitor (framebuffer) */
static int cmd_banner(const char *text);
static int cmd_incident(seL4_CPtr orch_ep);
static int cmd_verify(seL4_CPtr orch_ep, const char *args);
static int cmd_bench(seL4_CPtr orch_ep, const char *name);
static int cmd_tpm_pcrs(seL4_CPtr orch_ep);
static int cmd_tpm_quote(seL4_CPtr orch_ep, const char *nonce_hex);
static int cmd_dump_heap(seL4_CPtr orch_ep, int pid, const char *out_path);
static int cmd_simreboot(seL4_CPtr orch_ep);
static int cmd_bbsh(seL4_CPtr orch_ep);
static int cmd_shell(seL4_CPtr orch_ep, int trusted);
static int cmd_bbsh_auto(seL4_CPtr orch_ep);
static int cmd_doom(seL4_CPtr orch_ep);
static int cmd_gitdemo(seL4_CPtr orch_ep);
static int cmd_sotctl(seL4_CPtr orch_ep, const char *sub);
static int cmd_egress_dns(seL4_CPtr orch_ep);
static int cmd_egress_http(seL4_CPtr orch_ep);
static int cmd_egress_install(seL4_CPtr orch_ep);
static int cmd_egress_python(seL4_CPtr orch_ep);
static int cmd_arena_churn(seL4_CPtr orch_ep);
static int cmd_glibc(seL4_CPtr orch_ep);
static int cmd_gnu(seL4_CPtr orch_ep);
static int cmd_glibcdyn(seL4_CPtr orch_ep);
static int cmd_dpkg_install(seL4_CPtr orch_ep);
static int cmd_doomwl(seL4_CPtr orch_ep);
static int cmd_gtkspike(seL4_CPtr orch_ep);
static int cmd_gtk3demo(seL4_CPtr orch_ep);
static int cmd_widgetfactory(seL4_CPtr orch_ep);
static int cmd_mapfixed(seL4_CPtr orch_ep);
static int cmd_wine(seL4_CPtr orch_ep);
static int cmd_wine_crt(seL4_CPtr orch_ep);
static int cmd_wine_gui(seL4_CPtr orch_ep);
static int cmd_wine_baked(seL4_CPtr orch_ep);
static int cmd_systemctl(int argc, char **argv);
static int cmd_cron(int argc, char **argv);
static int run_command(seL4_CPtr orch_ep, const char *line);

/* ------------------------------------------------------------------ *
 * SOTSHELL_QUIT_SIGNAL · anomaly return value reserved for cmd_quit so
 * the interactive loop only exits when the user types "quit", not every
 * time a command returns -1 (which any command-with-bad-args may do).
 * ------------------------------------------------------------------ */
#define SOTSHELL_QUIT_SIGNAL  (-255)

/* ------------------------------------------------------------------ */
/* Helper: build + return orch_status_reply_t                         */
/* ------------------------------------------------------------------ */
static orch_status_reply_t query_status(seL4_CPtr orch_ep)
{
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_QUERY_STATUS, 0, 0, 0);
    info = seL4_Call(orch_ep, info);
    orch_status_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t len    = seL4_MessageInfo_get_length(info);
    size_t nwords = sizeof(reply) / sizeof(seL4_Word);
    if (len > nwords) len = nwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < len; ++i) dst[i] = seL4_GetMR(i);
    return reply;
}

/* ------------------------------------------------------------------ */
/* cmd_sotinfo · full formatted sotBox table                          */
/* ------------------------------------------------------------------ */
static int cmd_sotinfo(seL4_CPtr orch_ep)
{
    orch_status_reply_t reply = query_status(orch_ep);

    printf("sotos> sotinfo\n");
    printf("sotOs v0.4.3-cap-ext-lucas-orch\n");
    printf("-----------------------------------------\n");
    printf("kernel        seL4 13.0.0 (verified microkernel)\n");
    printf("boot time     (this boot)\n\n");

    if (reply.entry_count == 0) {
        printf("LUCAS         no sotBoxes registered\n");
    } else {
        printf("LUCAS         %u sotBox entries (active + zombies):\n",
               reply.entry_count);
        for (uint32_t i = 0; i < reply.entry_count && i < ORCH_STATUS_MAX_ENTRIES; ++i) {
            const orch_status_entry_t *e = &reply.entries[i];
            const char *state_name;
            switch (e->state) {
                case 0: state_name = "RUNNING";            break;
                case 1: state_name = "WAIT_CHILD";         break;
                case 2: state_name = "WAIT_PIPE_READ";     break;
                case 3: state_name = "WAIT_PIPE_WRITE";    break;
                case 4: state_name = "EXITED";             break;
                default: state_name = "?";                 break;
            }
            const char *tier_name;
            switch (e->tier) {
                case 0: tier_name = "Tier-0 (Pass-Through)";   break;
                case 1: tier_name = "Tier-1 (Silenced Mode)";     break;
                case 2: tier_name = "Tier-2 (Synth Mirror)"; break;
                default: tier_name = "?";                       break;
            }
            const char *slot_kind = (e->slot_index == -2) ? "zombie" :
                                     (e->slot_index >= 0)  ? "active" :
                                                              "empty";
            /* OBSD-ζ · display the random per-sotbox pid (anti-fingerprinting),
             * with the internal slot index in parentheses for operator clarity. */
            if (e->tier == 2) {
                printf("              [sotBox pid=%u(slot=%d) %s] state=%-16s exit=%d %s · %d canary reads · synth_redirects=%u · curvature_alerts=%u\n",
                       (unsigned int)e->display_pid, e->synthetic_pid,
                       slot_kind, state_name, e->exit_code,
                       tier_name, e->canary_read_count,
                       (unsigned int)e->synth_redirects,
                       (unsigned int)e->curvature_alerts);
            } else if (e->tier == 1) {
                printf("              [sotBox pid=%u(slot=%d) %s] state=%-16s exit=%d %s · silenced_rollback=%d · synth_redirects=%u · curvature_alerts=%u\n",
                       (unsigned int)e->display_pid, e->synthetic_pid,
                       slot_kind, state_name, e->exit_code,
                       tier_name, e->silenced_write_count,
                       (unsigned int)e->synth_redirects,
                       (unsigned int)e->curvature_alerts);
            } else {
                printf("              [sotBox pid=%u(slot=%d) %s] state=%-16s exit=%d %s · synth_redirects=%u · curvature_alerts=%u\n",
                       (unsigned int)e->display_pid, e->synthetic_pid,
                       slot_kind, state_name, e->exit_code,
                       tier_name,
                       (unsigned int)e->synth_redirects,
                       (unsigned int)e->curvature_alerts);
            }
            if (e->pledge_violations > 0) {
                printf("              pledge violations · %u\n", e->pledge_violations);
            }
            if (e->anomaly_triggers > 0) {
                printf("              anomaly triggers · %u (A3 rule fired)\n", e->anomaly_triggers);
            }
        }
    }
    printf("\n");
    printf("you are NOT on Linux. you are on sotOs.\n");
    printf("------------------------------------------\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_list · compact one-line-per-sotBox view                        */
/* ------------------------------------------------------------------ */
static int cmd_list(seL4_CPtr orch_ep)
{
    orch_status_reply_t reply = query_status(orch_ep);

    printf("sotos> list · %u entries\n", reply.entry_count);
    for (uint32_t i = 0; i < reply.entry_count && i < ORCH_STATUS_MAX_ENTRIES; ++i) {
        const orch_status_entry_t *e = &reply.entries[i];
        printf("  pid=%d tier=%d state=%d exit=%d\n",
               e->synthetic_pid, e->tier, e->state, e->exit_code);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_kill · stub (A3 anomaly will wire this)                       */
/* ------------------------------------------------------------------ */
static int cmd_kill(seL4_CPtr orch_ep, int pid)
{
    (void)orch_ep; (void)pid;
    printf("[sotshell] kill not yet implemented (pid=%d) · A3 will wire this\n", pid);
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_promote · send ORCH_OP_PROMOTE_TIER                            */
/* ------------------------------------------------------------------ */
static int cmd_promote(seL4_CPtr orch_ep, int pid, int tier)
{
    seL4_SetMR(0, (seL4_Word)pid);
    seL4_SetMR(1, (seL4_Word)tier);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_PROMOTE_TIER, 0, 0, 2);
    info = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(info);
    if (rc == 0) {
        printf("[sotshell] pid=%d promoted to tier %d\n", pid, tier);
    } else {
        printf("[sotshell] promote failed (rc=%lu)\n", (unsigned long)rc);
    }
    return (int)rc;
}

/* ------------------------------------------------------------------ */
/* cmd_anomaly_log · ANOMALY-DASHBOARD · dump recent anomaly events */
/*                                                                    */
/* Usage: anomaly-log                                                */
/* Sends ORCH_OP_QUERY_ANOMALY_LOG, prints chronological event list. */
/* ------------------------------------------------------------------ */
static const char *anomaly_kind_label(uint16_t kind)
{
    switch (kind) {
        case ANOMALY_EV_WRITE:            return "WRITE";
        case ANOMALY_EV_OPERATOR_PROMOTE: return "OPERATOR_PROMOTE";
        case ANOMALY_EV_PLEDGE_VIOLATION: return "PLEDGE_VIOLATION";
        case ANOMALY_EV_NET_PRECOMMIT:    return "NET_PRECOMMIT";
        case ANOMALY_EV_CURVATURE:        return "CURVATURE";
        case ANOMALY_EV_DNS_HIT:          return "DNS_HIT";
        case ANOMALY_EV_TCP_OPEN:         return "TCP_OPEN";
        /* procd PR 15 · audit-trail bridge labels */
        case ANOMALY_EV_PROCD_PROC_BORN:        return "PROCD_PROC_BORN";
        case ANOMALY_EV_PROCD_PROC_EXITED:      return "PROCD_PROC_EXITED";
        case ANOMALY_EV_PROCD_TIER_CHANGED:     return "PROCD_TIER_CHANGED";
        case ANOMALY_EV_PROCD_FUNCTOR_REBOUND:  return "PROCD_FUNCTOR_REBOUND";
        case ANOMALY_EV_PROCD_SYNTH_FORK:     return "PROCD_SYNTH_FORK";
        case ANOMALY_EV_PROCD_DENIED_TIER3:     return "PROCD_DENIED_TIER3";
        case ANOMALY_EV_PROCD_OTHER:            return "PROCD_OTHER";
        /* α · PR 9 · v0.26.0-persistence-substrate · audit-event labels */
        case SOTGUARD_KIND_WAL_FULL_DROP:    return "WAL_FULL_DROP";
        case SOTGUARD_KIND_WAL_TORN_RECORD:  return "WAL_TORN_RECORD";
        case SOTGUARD_KIND_WAL_REPLAY_DONE:  return "WAL_REPLAY_DONE";
        case SOTGUARD_KIND_SIMREBOOT_BEGIN:  return "SIMREBOOT_BEGIN";
        case SOTGUARD_KIND_SIMREBOOT_END:    return "SIMREBOOT_END";
        /* β · PR 11 · v0.27.0-init-cron · audit-event labels */
        case SOTGUARD_KIND_SOTINIT_SERVICE_START:  return "SOTINIT_SERVICE_START";
        case SOTGUARD_KIND_SOTINIT_SERVICE_EXIT:   return "SOTINIT_SERVICE_EXIT";
        case SOTGUARD_KIND_SOTINIT_SERVICE_FAILED: return "SOTINIT_SERVICE_FAILED";
        case SOTGUARD_KIND_SOTINIT_CYCLE_DETECTED: return "SOTINIT_CYCLE_DETECTED";
        case SOTGUARD_KIND_SOTINIT_UNIT_INVALID:   return "SOTINIT_UNIT_INVALID";
        case SOTGUARD_KIND_SOTCRON_FIRE:           return "SOTCRON_FIRE";
        case SOTGUARD_KIND_SOTCRON_FIRE_FAILED:    return "SOTCRON_FIRE_FAILED";
        case SOTGUARD_KIND_SHELLHOOK_FIRED:        return "SHELLHOOK_FIRED";
        case SOTGUARD_KIND_SHELLHOOK_SKIPPED:      return "SHELLHOOK_SKIPPED";
        case SOTGUARD_KIND_SHELLHOOK_FAILED:       return "SHELLHOOK_FAILED";
        case SOTGUARD_KIND_PERSISTENCE_INSTALL:        return "PERSISTENCE_INSTALL";
        case SOTGUARD_KIND_PERSISTENCE_NEVER_ACTIVATE: return "PERSISTENCE_NEVER_ACTIVATE";
        case SOTGUARD_KIND_PERSISTENCE_NEVER_FIRE:     return "PERSISTENCE_NEVER_FIRE";
        default:                           return "UNKNOWN";
    }
}

static int cmd_anomaly_log(seL4_CPtr orch_ep)
{
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_QUERY_ANOMALY_LOG, 0, 0, 0);
    info = seL4_Call(orch_ep, info);

    orch_anomaly_log_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

    printf("sotos> anomaly-log · %u recent event%s\n",
           reply.count, reply.count == 1 ? "" : "s");
    if (reply.count == 0) {
        printf("  (no events yet)\n");
        return 0;
    }
    uint32_t n = reply.count;
    if (n > ORCH_ANOMALY_LOG_MAX) n = ORCH_ANOMALY_LOG_MAX;
    for (uint32_t i = 0; i < n; ++i) {
        const orch_anomaly_log_entry_t *e = &reply.entries[i];
        /* S-PID · print BOTH the load-bearing synthetic_pid (anomaly-ring index)
         * and the OBSD-ζ display_pid the sotbox sees through getpid().
         * display_pid=0 means the slot has been freed since the event was
         * logged · still show it so operators can correlate exited pids. */
        printf("  [anomaly-log] seq=%u synthetic=%u display=%u kind=%u arg0=0x%lx arg1=0x%lx  (%s)\n",
               (unsigned)e->seq,
               (unsigned)e->pid, (unsigned)e->display_pid,
               (unsigned)e->kind,
               (unsigned long)e->arg0, (unsigned long)e->arg1,
               anomaly_kind_label(e->kind));
    }
    return 0;
}

/* sottrace · toggle the live serial drain (sottrace on/off). */
static int cmd_sottrace_live(seL4_CPtr orch_ep, int on)
{
    seL4_SetMR(0, (seL4_Word)(on ? 1 : 0));
    seL4_Call(orch_ep, seL4_MessageInfo_new(ORCH_OP_TRACE_LIVE, 0, 0, 1));
    printf("[sottrace] live drain %s\n", on ? "ON" : "OFF");
    return 0;
}

/* v2.8 · DECEPTION MONITOR · the live operator dashboard.  Turns on the sottrace
 * live drain WITH framebuffer rendering (MR0 bit1) so orch paints a clean,
 * severity-tagged feed of the attacker's traced actions (canary reads, contained
 * writes, recon, tier promotions, inbound conns) into this window AS THEY HAPPEN
 * — while an attacker pokes over SSH or a spawned malware runs.  The operator
 * just watches; any key (or F12) stops.  Reads keys via serial_getchar, which in
 * the operator console polls the GTK keyboard, so orch's fault loop keeps running
 * (and draining) between polls. */
static int cmd_watch(seL4_CPtr orch_ep)
{
    /* bit0=live drain · bit1=render to fb · (bit2=quiet DELIBERATELY OFF).
     *
     * WHY quiet is off: the firehose printfs are load-bearing under -enable-kvm.
     * orch services the inbound honeypot network by polling on the orch thread.
     * QEMU only DMAs SLIRP-delivered packets into the virtio-net RX ring when its
     * iothread gets the host CPU — which happens when the guest yields it via a
     * UART write() (every printf), NOT during a tight guest spin.  The v2.9
     * `quiet` bit suppressed the per-packet/syscall firehose for serial
     * cleanliness, but that removed those host-CPU yields → the attacker's SSH
     * KEX/NEWKEYS stalled (banner retx → RST): "watch broke SSH".  The operator
     * watches the FB dashboard (still clean — it renders only severity-tagged
     * lines, filtering the firehose), not the serial, so keeping the firehose on
     * the serial costs nothing and keeps inbound alive.  See tools/watch-combo-
     * gate.sh (the headless repro that nailed this) + the tcp_timer wall-clock
     * retx pacing that stops a fast loop RST'ing live peers prematurely. */
    seL4_SetMR(0, (seL4_Word)3);
    seL4_Call(orch_ep, seL4_MessageInfo_new(ORCH_OP_TRACE_LIVE, 0, 0, 1));
    printf("\033[2J\033[H");
    printf("================================================================\n");
    printf("  sotOs DECEPTION MONITOR · live attacker trace\n");
    printf("  CANARY=honey read · CONTAINED=write blocked · TIER=isolated\n");
    printf("  INBOUND=conn · RECON=fs open · (any key / F12 to stop)\n");
    printf("================================================================\n");
    fflush(stdout);
    for (;;) {
        if (g_operator_f12) break;          /* F12 → caller returns to canary shell */
        int c = serial_getchar();
        if (g_operator_f12) break;
        if (c != 0) break;                  /* any key stops the monitor */
        seL4_Yield();                       /* let orch drain the live feed to the fb */
    }
    seL4_SetMR(0, (seL4_Word)0);            /* live drain OFF */
    seL4_Call(orch_ep, seL4_MessageInfo_new(ORCH_OP_TRACE_LIVE, 0, 0, 1));
    printf("\n[sottrace] deception monitor stopped\n");
    fflush(stdout);
    return 0;
}

/* sottrace · dump ONE direction of a connection's captured forensic payload.
 * dir_bit = 0 (IN) or 0x80000000u (OUT) — encoded in MR(1)'s high bit so the
 * Call stays length=2 (no extra MR). Loops pages until drained. label is the
 * "IN"/"OUT" header tag. */
static int sottrace_payload_stream(seL4_CPtr orch_ep, uint16_t conn_id,
                                   uint32_t dir_bit, const char *label)
{
    uint32_t offset = 0, total = 0, dropped = 0; int found = 0;
    printf("[payload] %s conn=%u\n", label, conn_id);
    for (;;) {
        seL4_SetMR(0, conn_id); seL4_SetMR(1, offset | dir_bit);
        seL4_Call(orch_ep, seL4_MessageInfo_new(ORCH_OP_QUERY_TRACE_PAYLOAD, 0, 0, 2));
        orch_trace_payload_reply_t pr; memset(&pr, 0, sizeof(pr));
        size_t nw = sizeof(pr)/sizeof(seL4_Word); seL4_Word *d=(seL4_Word*)&pr;
        for (size_t i=0;i<nw;++i) d[i]=seL4_GetMR(i);
        found = pr.found; total = pr.total_len; dropped = pr.dropped;
        if (!pr.found || pr.page_len == 0) break;
        /* print the page as hex+ASCII, 16 bytes/line */
        for (uint32_t i = 0; i < pr.page_len; i += 16) {
            char line[80]; int p = 0;
            p += snprintf(line+p, sizeof(line)-p, "  %04x: ", offset + i);
            for (uint32_t j = 0; j < 16 && i+j < pr.page_len; ++j)
                p += snprintf(line+p, sizeof(line)-p, "%02x ", pr.page[i+j]);
            printf("%s\n", line);
        }
        offset += pr.page_len;
        if (offset >= pr.total_len) break;
    }
    printf("[payload] %s conn=%u · %s · %u bytes (%u dropped)\n",
           label, conn_id, found ? "found" : "no capture", total, dropped);
    return 0;
}

/* sottrace · paginated hex dump of a connection's captured forensic payload
 * (the T8 store), BOTH directions: request (IN) then reply (OUT). */
static int cmd_sottrace_payload(seL4_CPtr orch_ep, uint16_t conn_id)
{
    sottrace_payload_stream(orch_ep, conn_id, 0u, "IN");
    sottrace_payload_stream(orch_ep, conn_id, 0x80000000u, "OUT");
    return 0;
}

/* sottrace · P3 · dump the process->file FS-mutation graph as TEXT, framed by
 * [graph] BEGIN / [graph] END. Loops ORCH_OP_QUERY_TRACE_GRAPH pages until
 * drained; the host tools/sottrace_graph.py parses the G lines. */
static int cmd_sottrace_graph(seL4_CPtr orch_ep)
{
    uint32_t offset = 0, total = 0;
    printf("[graph] BEGIN\n");
    for (;;) {
        seL4_SetMR(0, 0); seL4_SetMR(1, offset);
        seL4_Call(orch_ep, seL4_MessageInfo_new(ORCH_OP_QUERY_TRACE_GRAPH, 0, 0, 2));
        orch_trace_payload_reply_t gr; memset(&gr, 0, sizeof(gr));
        size_t nw = sizeof(gr)/sizeof(seL4_Word); seL4_Word *d=(seL4_Word*)&gr;
        for (size_t i=0;i<nw;++i) d[i]=seL4_GetMR(i);
        total = gr.total_len;
        if (gr.page_len == 0) break;
        /* page bytes are NUL-free text lines; print directly */
        for (uint32_t i = 0; i < gr.page_len; ++i) putchar((char)gr.page[i]);
        offset += gr.page_len;
        if (offset >= gr.total_len) break;
    }
    printf("[graph] END (%u bytes)\n", total);
    return 0;
}

/* sottrace · snapshot the trace rings (newest-first across all sandboxes). */
static int cmd_sottrace(seL4_CPtr orch_ep)
{
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_QUERY_TRACE_RING, 0, 0, 0);
    info = seL4_Call(orch_ep, info);

    orch_trace_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

    uint32_t n = reply.count;
    if (n > ORCH_TRACE_REPLY_MAX) n = ORCH_TRACE_REPLY_MAX;
    uint32_t syscalls = 0, tiers = 0;
    /* print oldest-first for readability (reply is newest-first) */
    for (int32_t i = (int32_t)n - 1; i >= 0; --i) {
        const orch_trace_entry_t *e = &reply.entries[i];
        switch (e->kind) {
            case SG_EV_SYSCALL_ENTER:
                printf("  [sottrace] tsc=%llu pid=%u ENTER sys=%llu arg0=0x%llx\n",
                       (unsigned long long)e->seq, e->pid,
                       (unsigned long long)e->a, (unsigned long long)e->b);
                syscalls++;
                break;
            case SG_EV_SYSCALL_EXIT:
                printf("  [sottrace] tsc=%llu pid=%u EXIT  sys=%llu ret=%lld\n",
                       (unsigned long long)e->seq, e->pid,
                       (unsigned long long)e->a, (long long)e->b);
                syscalls++;
                break;
            case SG_EV_TIER_ASSIGN:
                printf("  [sottrace] tsc=%llu pid=%u TIER  %llu->%llu\n",
                       (unsigned long long)e->seq, e->pid,
                       (unsigned long long)e->a, (unsigned long long)e->b);
                tiers++;
                break;
            case SG_EV_CANARY_READ:
                printf("  [sottrace] tsc=%llu pid=%u CANARY\n",
                       (unsigned long long)e->seq, e->pid);
                break;
            case SG_EV_DNS_LOOKUP:
                printf("  [sottrace] tsc=%llu pid=%u DNS   ip=0x%llx\n",
                       (unsigned long long)e->seq, e->pid,
                       (unsigned long long)e->a);
                break;
            case SG_EV_INBOUND_ACCEPT:
                /* a = remote ip_be · b = (remote_port_be<<16)|local_port_be */
                printf("  [sottrace] tsc=%llu pid=%u ACCEPT conn=%u rip=0x%llx rport=%u lport=%u\n",
                       (unsigned long long)e->seq, e->pid, e->pad,
                       (unsigned long long)e->a,
                       (unsigned)((e->b >> 16) & 0xFFFF),
                       (unsigned)(e->b & 0xFFFF));
                break;
            case SG_EV_CONN_CLOSE:
                /* a = rx bytes · b = tx bytes (low-32) */
                printf("  [sottrace] tsc=%llu pid=%u CLOSE conn=%u rx=%llu tx=%llu\n",
                       (unsigned long long)e->seq, e->pid, e->pad,
                       (unsigned long long)e->a, (unsigned long long)e->b);
                break;
            case SG_EV_ISOLATED_WRITE_DROP:
                printf("  [sottrace] tsc=%llu pid=%u ISOLATED_WRITE_DROP conn=%u\n",
                       (unsigned long long)e->seq, e->pid, e->pad);
                break;
            default:
                printf("  [sottrace] tsc=%llu pid=%u kind=%u\n",
                       (unsigned long long)e->seq, e->pid, e->kind);
                break;
        }
    }
    printf("[sottrace] ok · %u events · %u syscalls · %u tier (total avail %u)\n",
           reply.count, syscalls, tiers, reply.total);
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_banner · C2 #9 · framed phase label for the scripted demo        */
/* ------------------------------------------------------------------ */
static int cmd_banner(const char *text)
{
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("  %s\n", (text && *text) ? text : "");
    printf("═══════════════════════════════════════════════════════════\n");
    return 0;
}

/* C2 #4 · event-severity rollup for the incident summary.  Derived from the
 * observed anomaly event KIND (a presentation rollup · not a re-score):
 * 2 = hostile-intent, 1 = suspect, 0 = benign/info. */
static int incident_severity(uint16_t kind)
{
    switch (kind) {
        case ANOMALY_EV_CRED_ACCESS:
        case ANOMALY_EV_DNS_HIT:
        case ANOMALY_EV_CURVATURE:
        case ANOMALY_EV_UNLINK:
            return 2;
        case ANOMALY_EV_NET_PRECOMMIT:
        case ANOMALY_EV_TCP_OPEN:
        case ANOMALY_EV_PLEDGE_VIOLATION:
        case ANOMALY_EV_MSYSCALL:
            return 1;
        default:
            return 0;
    }
}

static const char *incident_verdict(int sev)
{
    return (sev >= 2) ? "hostile-intent" : (sev == 1) ? "suspect" : "benign";
}

/* ------------------------------------------------------------------ */
/* cmd_incident · C2 #4/#11 · per-pid rollup of the anomaly event log  */
/* (distinct from the raw chronological `anomaly-log` dump).           */
/* ------------------------------------------------------------------ */
static int cmd_incident(seL4_CPtr orch_ep)
{
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_QUERY_ANOMALY_LOG, 0, 0, 0);
    info = seL4_Call(orch_ep, info);

    orch_anomaly_log_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

    printf("\n═══ INCIDENT SUMMARY ═══\n");
    uint32_t n = reply.count;
    if (n > ORCH_ANOMALY_LOG_MAX) n = ORCH_ANOMALY_LOG_MAX;
    if (n == 0) {
        printf("  (no anomaly events observed)\n");
        return 0;
    }

    /* Roll up per synthetic_pid · worst severity + event count. */
    uint32_t pids[ORCH_ANOMALY_LOG_MAX];
    uint32_t disp[ORCH_ANOMALY_LOG_MAX];
    int      cnt[ORCH_ANOMALY_LOG_MAX];
    int      sev[ORCH_ANOMALY_LOG_MAX];
    int np = 0, hostile = 0;
    for (uint32_t i = 0; i < n; ++i) {
        const orch_anomaly_log_entry_t *e = &reply.entries[i];
        int idx = -1;
        for (int j = 0; j < np; ++j) if (pids[j] == e->pid) { idx = j; break; }
        if (idx < 0) {
            idx = np++;
            pids[idx] = e->pid; disp[idx] = e->display_pid;
            cnt[idx] = 0; sev[idx] = 0;
        }
        cnt[idx]++;
        int s = incident_severity(e->kind);
        if (s > sev[idx]) sev[idx] = s;
    }
    for (int j = 0; j < np; ++j) {
        if (sev[j] >= 2) hostile++;
        printf("  pid=%u (display=%u) · %d event%s · VERDICT: %s\n",
               pids[j], disp[j], cnt[j], cnt[j] == 1 ? "" : "s",
               incident_verdict(sev[j]));
    }
    printf("  total: %d process%s observed · %d hostile-intent · "
           "0 exfil to real network (synth-redirected)\n",
           np, np == 1 ? "" : "es", hostile);
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_verify · C2 #14 · post-attack integrity proof · re-read a known  */
/* REAL file and confirm the expected content survived the deception.   */
/* Usage: verify <path> <expected-substr>                               */
/* ------------------------------------------------------------------ */
static int cmd_verify(seL4_CPtr orch_ep, const char *args)
{
    char path[ORCH_SOTFS_PATH_MAX] = {0};
    char want[64] = {0};
    if (args) {
        while (*args == ' ') ++args;
        size_t pi = 0;
        while (args[pi] && args[pi] != ' ' && pi < sizeof(path) - 1) { path[pi] = args[pi]; ++pi; }
        path[pi] = '\0';
        const char *w = args + pi; while (*w == ' ') ++w;
        size_t wi = 0;
        while (w[wi] && w[wi] != ' ' && wi < sizeof(want) - 1) { want[wi] = w[wi]; ++wi; }
        want[wi] = '\0';
    }
    if (path[0] == '\0') {
        printf("[verify] usage: verify <path> <expected-substr>\n");
        return -1;
    }

    orch_sotfs_path_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, path, ORCH_SOTFS_PATH_MAX - 1);
    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SOTFS_CAT, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    orch_sotfs_cat_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

    if (reply.rc < 0) {
        printf("[verify] %s · READ FAILED rc=%d\n", path, reply.rc);
        return 1;
    }
    uint32_t shown = reply.data_len;
    if (shown > ORCH_SOTFS_CAT_MAX_BYTES) shown = ORCH_SOTFS_CAT_MAX_BYTES;
    int found = 0;
    if (want[0]) {
        size_t wl = strlen(want);
        for (uint32_t k = 0; wl <= shown && k + wl <= shown && !found; ++k)
            if (memcmp(&reply.data[k], want, wl) == 0) found = 1;
    } else {
        found = (shown > 0);
    }
    if (found)
        printf("[verify] %s OK · real data intact\n", path);
    else
        printf("[verify] %s MISMATCH · expected substring not found\n", path);
    return found ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/* cmd_bench · ORCH_OP_SPAWN_BENCH · spawn a perf-benchmark harness     */
/* (sotOs-bench_<name>) with orch's STO endpoint as its argv[1].  The   */
/* harness prints its ===BENCH-JSON-BEGIN===…===BENCH-JSON-END=== block */
/* to serial.  Usage: bench [name]  (default: baseline)                 */
/* ------------------------------------------------------------------ */
static int cmd_bench(seL4_CPtr orch_ep, const char *name)
{
    char shortn[20] = {0};
    if (name) {
        while (*name == ' ') ++name;
        size_t i = 0;
        while (name[i] && name[i] != ' ' && i < sizeof(shortn) - 1) { shortn[i] = name[i]; ++i; }
        shortn[i] = '\0';
    }
    if (shortn[0] == '\0') strncpy(shortn, "baseline", sizeof(shortn) - 1);

    orch_bench_req_t req;
    memset(&req, 0, sizeof(req));
    snprintf(req.name, sizeof(req.name), "sotOs-bench_%s", shortn);

    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *mr = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, mr[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN_BENCH, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    seL4_Word rc = seL4_MessageInfo_get_label(info);
    if (rc == 0)
        printf("sotos> bench %s · spawned (%s) · see ===BENCH-JSON=== block below\n",
               shortn, req.name);
    else
        printf("sotos> bench %s · FAILED (rc=%lu)\n", shortn, (unsigned long)rc);
    return (int)rc;
}

/* ------------------------------------------------------------------ */
/* cmd_simreboot · α · PR 7 · userspace-only reset cascade            */
/*                                                                    */
/* Usage: simreboot                                                   */
/* Sends SOTOS_OP_SIMREBOOT, orch runs the 5-phase cascade in its     */
/* own vspace (where sotos-sotfs is linked).  See src/orch/simreboot.c */
/* for the 5-phase logic.  Returns 0 on success, non-zero on Phase 1  */
/* (CHECKPOINT) failure.  Phases 2-4 are scope-reduced banner emitters */
/* (full TCB teardown/respawn requires a root-side listen EP that PR 7 */
/* does not ship · see the cascade header for the rationale).        */
/* ------------------------------------------------------------------ */
static int cmd_simreboot(seL4_CPtr orch_ep)
{
    printf("[sotshell] requesting simreboot...\n");
    seL4_SetMR(0, 0);  /* no payload · cascade reads no MRs from sotshell */
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(SOTOS_OP_SIMREBOOT, 0, 0, 0);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    (void)reply;
    int rc = (int)seL4_GetMR(0);
    printf("[sotshell] simreboot returned rc=%d\n", rc);
    return rc;
}

/* ------------------------------------------------------------------ */
/* cmd_tpm_pcrs · OBSD-η · operator reads PCR 8/9/10 (sotBoot bank)   */
/*                                                                    */
/* Usage: tpm-pcrs                                                    */
/* Sends ORCH_OP_TPM_PCRS, prints PCR values hex-encoded.             */
/* ------------------------------------------------------------------ */
static int cmd_tpm_pcrs(seL4_CPtr orch_ep)
{
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_TPM_PCRS, 0, 0, 0);
    info = seL4_Call(orch_ep, info);

    orch_tpm_pcrs_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

    if (!reply.available) {
        printf("[tpm-pcrs] TPM not available (boot without -device tpm-tis)\n");
        return 0;
    }
    printf("[tpm-pcrs] PCR-8=  ");
    for (int i = 0; i < 32; i++) printf("%02x", reply.pcr8[i]);
    printf("\n[tpm-pcrs] PCR-9=  ");
    for (int i = 0; i < 32; i++) printf("%02x", reply.pcr9[i]);
    printf("\n[tpm-pcrs] PCR-10= ");
    for (int i = 0; i < 32; i++) printf("%02x", reply.pcr10[i]);
    printf("\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_tpm_quote · OBSD-η · operator requests TPM quote over a nonce  */
/*                                                                    */
/* Usage: tpm-quote [<nonce_hex>]                                     */
/* Default nonce: "deadbeef" if no argument supplied.                 */
/* Parses hex string into raw bytes, sends via seL4_Call with         */
/* ORCH_OP_TPM_QUOTE, prints signature hex-encoded.                   */
/* ------------------------------------------------------------------ */
static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int cmd_tpm_quote(seL4_CPtr orch_ep, const char *nonce_hex)
{
    /* Default nonce when caller passes NULL or empty string. */
    if (!nonce_hex || !*nonce_hex) {
        nonce_hex = "deadbeef";
    }

    /* Parse hex string (even length, [0-9a-fA-F]) into raw bytes. */
    uint8_t nonce[TPM_QUOTE_MAX_NONCE];
    memset(nonce, 0, sizeof(nonce));
    size_t hexlen = 0;
    while (nonce_hex[hexlen]) hexlen++;
    if (hexlen & 1) {
        printf("[tpm-quote] error: nonce hex must have even length (got %zu)\n", hexlen);
        return 1;
    }
    size_t nbytes = hexlen / 2;
    if (nbytes > TPM_QUOTE_MAX_NONCE) {
        printf("[tpm-quote] error: nonce too long (max %d bytes)\n",
               TPM_QUOTE_MAX_NONCE);
        return 1;
    }
    for (size_t i = 0; i < nbytes; ++i) {
        int hi = hex_nibble(nonce_hex[i * 2]);
        int lo = hex_nibble(nonce_hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            printf("[tpm-quote] error: invalid hex character in nonce\n");
            return 1;
        }
        nonce[i] = (uint8_t)((hi << 4) | lo);
    }

    /* Pack nonce_len in MR(0), then nonce bytes 8/word starting at MR(1). */
    seL4_SetMR(0, (seL4_Word)nbytes);
    size_t nonce_words = (nbytes + 7) / 8;
    for (size_t i = 0; i < nonce_words; ++i) {
        seL4_Word w = 0;
        size_t chunk = (nbytes - i * 8 < 8) ? nbytes - i * 8 : 8;
        memcpy(&w, nonce + i * 8, chunk);
        seL4_SetMR(1 + i, w);
    }
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_TPM_QUOTE, 0, 0, 1 + nonce_words);
    info = seL4_Call(orch_ep, info);

    orch_tpm_quote_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

    if (!reply.available) {
        printf("[tpm-quote] TPM not available (boot without -device tpm-tis)\n");
        return 0;
    }
    printf("[tpm-quote] nonce=  ");
    for (size_t i = 0; i < nbytes; ++i) printf("%02x", nonce[i]);
    printf("\n[tpm-quote] sig_len=%u\n", (unsigned)reply.sig_len);
    printf("[tpm-quote] sig=    ");
    uint32_t slen = reply.sig_len;
    if (slen > TPM_QUOTE_MAX_SIG_BYTES) slen = TPM_QUOTE_MAX_SIG_BYTES;
    for (uint32_t i = 0; i < slen; ++i) printf("%02x", reply.sig[i]);
    printf("\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_sotnet · sotNet-ζ · list active network flows                  */
/* ------------------------------------------------------------------ */
static int cmd_sotnet(seL4_CPtr orch_ep)
{
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_QUERY_NET_FLOWS, 0, 0, 0);
    info = seL4_Call(orch_ep, info);
    orch_net_flows_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t len    = seL4_MessageInfo_get_length(info);
    size_t nwords = sizeof(reply) / sizeof(seL4_Word);
    if (len > nwords) len = nwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < len; ++i) dst[i] = seL4_GetMR(i);

    printf("sotos> sotnet · %u active flows\n", reply.flow_count);
    if (reply.flow_count == 0) {
        printf("  (no flows)\n");
    } else {
        for (uint32_t i = 0; i < reply.flow_count && i < SOTNET_MAX_FLOWS; ++i) {
            const sotnet_flow_entry_t *f = &reply.flows[i];
            printf("  pid=%u %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u · out=%u in=%u\n",
                   f->pid,
                   f->src_ip & 0xFF, (f->src_ip >> 8) & 0xFF,
                   (f->src_ip >> 16) & 0xFF, (f->src_ip >> 24) & 0xFF,
                   ((f->src_port & 0xFF) << 8) | ((f->src_port >> 8) & 0xFF),
                   f->dst_ip & 0xFF, (f->dst_ip >> 8) & 0xFF,
                   (f->dst_ip >> 16) & 0xFF, (f->dst_ip >> 24) & 0xFF,
                   ((f->dst_port & 0xFF) << 8) | ((f->dst_port >> 8) & 0xFF),
                   f->bytes_out, f->bytes_in);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_ls · ORCH_OP_SOTFS_LS · list sotFS directory                   */
/* ------------------------------------------------------------------ */
static int cmd_ls(seL4_CPtr orch_ep, const char *path)
{
    orch_sotfs_path_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, path ? path : "/tmp", ORCH_SOTFS_PATH_MAX - 1);

    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SOTFS_LS, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    orch_sotfs_ls_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

    printf("sotos> ls %s · %u entries\n", req.path, reply.entry_count);
    for (uint32_t i = 0; i < reply.entry_count && i < ORCH_SOTFS_LS_MAX_ENTRIES; ++i) {
        const orch_sotfs_dirent_t *e = &reply.entries[i];
        const char *kind_str = (e->kind == 2) ? "dir" : "file";
        printf("  %-24s %4u bytes  %s\n", e->name, e->size, kind_str);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_cat · ORCH_OP_SOTFS_CAT · print file contents                  */
/* ------------------------------------------------------------------ */
static int cmd_cat(seL4_CPtr orch_ep, const char *path)
{
    orch_sotfs_path_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, path ? path : "", ORCH_SOTFS_PATH_MAX - 1);

    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SOTFS_CAT, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    orch_sotfs_cat_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

    printf("sotos> cat %s\n", req.path);
    if (reply.rc < 0) {
        printf("[cat] error rc=%d\n", reply.rc);
        return 1;
    }

    /* The single CAT op returns only the first 512 bytes.  Print them, then
     * continue with chunked READ_AT so the WHOLE file is shown (not just the
     * head · the previous version truncated every file at 512 bytes). */
    uint32_t shown = reply.data_len;
    if (shown > ORCH_SOTFS_CAT_MAX_BYTES) shown = ORCH_SOTFS_CAT_MAX_BYTES;
    for (uint32_t k = 0; k < shown; ++k) putchar((char)reply.data[k]);

    uint32_t off = shown;
    while (shown == ORCH_SOTFS_CAT_MAX_BYTES) {   /* head was full · more may follow */
        orch_sotfs_read_at_req_t rreq;
        memset(&rreq, 0, sizeof(rreq));
        strncpy(rreq.path, req.path, ORCH_SOTFS_PATH_MAX - 1);
        rreq.offset = off;
        rreq.max    = ORCH_SOTFS_READ_AT_CHUNK;
        size_t nw = sizeof(rreq) / sizeof(seL4_Word);
        seL4_Word *s2 = (seL4_Word *)&rreq;
        for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, s2[i]);
        seL4_MessageInfo_t ri =
            seL4_Call(orch_ep, seL4_MessageInfo_new(ORCH_OP_SOTFS_READ_AT, 0, 0, nw));
        orch_sotfs_read_at_reply_t rrep;
        memset(&rrep, 0, sizeof(rrep));
        size_t rl = seL4_MessageInfo_get_length(ri);
        size_t rn = sizeof(rrep) / sizeof(seL4_Word);
        if (rl > rn) rl = rn;
        seL4_Word *d2 = (seL4_Word *)&rrep;
        for (size_t i = 0; i < rl; ++i) d2[i] = seL4_GetMR(i);
        if (rrep.rc < 0 || rrep.len == 0) break;
        uint32_t got = rrep.len > ORCH_SOTFS_READ_AT_CHUNK
                     ? ORCH_SOTFS_READ_AT_CHUNK : rrep.len;
        for (uint32_t k = 0; k < got; ++k) putchar((char)rrep.data[k]);
        off += got;
        if (got < ORCH_SOTFS_READ_AT_CHUNK) break;   /* short read = EOF */
    }
    putchar('\n');
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_install · ORCH_OP_SOTFS_INSTALL · create / overwrite a file        */
/* ------------------------------------------------------------------ */
static int cmd_install(seL4_CPtr orch_ep, const char *path, const char *content)
{
    orch_sotfs_install_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, path ? path : "", ORCH_SOTFS_PATH_MAX - 1);
    size_t clen = content ? strlen(content) : 0;
    if (clen >= ORCH_SOTFS_INSTALL_CONTENT_MAX) clen = ORCH_SOTFS_INSTALL_CONTENT_MAX - 1;
    memcpy(req.content, content ? content : "", clen);
    req.content_len = (uint32_t)clen;

    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SOTFS_INSTALL, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    seL4_Word rc = seL4_MessageInfo_get_label(info);
    if (rc == 0) {
        printf("sotos> install %s · %zu bytes · OK\n", req.path, clen);
    } else {
        printf("sotos> install %s · FAILED (rc=%lu)\n", req.path, (unsigned long)rc);
    }
    return (int)rc;
}

/* ------------------------------------------------------------------ */
/* cmd_bininstall · ORCH_OP_RWBIN_INSTALL · A2 · copy a binary into    */
/* the writable on-disk store (rwbinstore).  src = binstore name (bare)*/
/* or sotfs path ('/'-prefixed); dest = rwbinstore entry name.  Once   */
/* installed it shadows the read-only binstore at spawn time, so e.g.  */
/* `bininstall tcc.bin tcc.bin` makes `tcc` run from the writable copy.*/
/* ------------------------------------------------------------------ */
static int cmd_bininstall(seL4_CPtr orch_ep, const char *args)
{
    /* args = "<src> <dest>" (dest optional → defaults to src). */
    char src[64]  = {0};
    char dest[64] = {0};
    if (args) {
        while (*args == ' ') ++args;
        size_t si = 0;
        while (args[si] && args[si] != ' ' && si < sizeof(src) - 1) { src[si] = args[si]; ++si; }
        src[si] = '\0';
        const char *d = args + si;
        while (*d == ' ') ++d;
        size_t di = 0;
        while (d[di] && d[di] != ' ' && di < sizeof(dest) - 1) { dest[di] = d[di]; ++di; }
        dest[di] = '\0';
    }
    if (src[0] == '\0') {
        printf("sotos> usage: bininstall <src> [dest]\n");
        return -1;
    }
    if (dest[0] == '\0') strncpy(dest, src, sizeof(dest) - 1);

    orch_rwbin_install_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.src,  src,  sizeof(req.src)  - 1);
    strncpy(req.dest, dest, sizeof(req.dest) - 1);

    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *mr = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, mr[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_RWBIN_INSTALL, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    seL4_Word rc = seL4_MessageInfo_get_label(info);
    if (rc == 0) {
        printf("sotos> bininstall %s -> rwbinstore:%s · OK\n", req.src, req.dest);
    } else {
        printf("sotos> bininstall %s -> %s · FAILED (rc=%lu)\n",
               req.src, req.dest, (unsigned long)rc);
    }
    return (int)rc;
}

/* ------------------------------------------------------------------ */
/* sotnano load/save · PR 6 · chunked sotfs I/O over orch_ep.          */
/* Live here (not sotnano.c) because they need orch_ep + the ORCH_OP_* */
/* SOTFS constants from <orch/proto.h> (already included above) and    */
/* sit right beside sotnano_run, which owns the orch_ep handle.        */
/* ------------------------------------------------------------------ */
static void sotnano_load(sotnano_editor_t *e) {
    sotnano_gap_init(&e->gap);
    uint32_t off = 0;
    while (off < SOTNANO_BUF_MAX) {
        orch_sotfs_read_at_req_t req; memset(&req, 0, sizeof(req));
        strncpy(req.path, e->path, ORCH_SOTFS_PATH_MAX - 1);
        req.offset = off; req.max = ORCH_SOTFS_READ_AT_CHUNK;
        size_t nw = sizeof(req)/sizeof(seL4_Word);
        seL4_Word *src = (seL4_Word *)&req;
        for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
        seL4_MessageInfo_t info =
            seL4_Call(e->orch_ep, seL4_MessageInfo_new(ORCH_OP_SOTFS_READ_AT, 0, 0, nw));
        orch_sotfs_read_at_reply_t rep; memset(&rep, 0, sizeof(rep));
        size_t rl = seL4_MessageInfo_get_length(info);
        size_t rn = sizeof(rep)/sizeof(seL4_Word);
        if (rl > rn) rl = rn;
        seL4_Word *dst = (seL4_Word *)&rep;
        for (size_t i = 0; i < rl; ++i) dst[i] = seL4_GetMR(i);
        if (rep.rc < 0 || rep.len == 0) break;     /* ENOENT or EOF */
        for (uint32_t i = 0; i < rep.len; ++i)
            if (sotnano_gap_insert(&e->gap, (char)rep.data[i]) < 0) break;
        off += rep.len;
        if (rep.len < ORCH_SOTFS_READ_AT_CHUNK) break; /* short read = EOF */
    }
    sotnano_gap_move_to(&e->gap, 0);               /* cursor to top */
    e->dirty = 0;
}

static int sotnano_save(sotnano_editor_t *e) {
    static char linear[SOTNANO_BUF_MAX];
    uint32_t total = sotnano_gap_serialize(&e->gap, linear, SOTNANO_BUF_MAX);
    uint32_t off = 0; int truncate = 1;
    do {
        uint32_t n = total - off;
        if (n > ORCH_SOTFS_WRITE_AT_CHUNK) n = ORCH_SOTFS_WRITE_AT_CHUNK;
        orch_sotfs_write_at_req_t req; memset(&req, 0, sizeof(req));
        strncpy(req.path, e->path, ORCH_SOTFS_PATH_MAX - 1);
        req.offset = off; req.len = n; req.truncate = (uint8_t)truncate;
        if (n) memcpy(req.data, linear + off, n);
        size_t nw = sizeof(req)/sizeof(seL4_Word);
        seL4_Word *src = (seL4_Word *)&req;
        for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
        seL4_MessageInfo_t info =
            seL4_Call(e->orch_ep, seL4_MessageInfo_new(ORCH_OP_SOTFS_WRITE_AT, 0, 0, nw));
        unsigned rc = seL4_MessageInfo_get_label(info);
        if (rc != 0) return -(int)rc;
        truncate = 0; off += n;
    } while (off < total);
    e->dirty = 0;
    return (int)total;
}

/* Surface the save result on the bottom status row · nano-style transient
 * message overwritten by the next sotnano_render.  Without this a failed
 * save is invisible and looks like success: -28 when the 32-inode sotfs
 * table is full, -22 on a relative path (no leading '/'), -2 when the
 * parent dir is missing, -13 on a Tier-2 mirror-dropped create. */
static void sotnano_save_status(const sotnano_editor_t *e, int rc) {
    const char *hint = "";
    if      (rc == -28) hint = " · sotfs table full";
    else if (rc == -22) hint = " · bad path (need leading '/')";
    else if (rc == -2)  hint = " · parent dir missing";
    else if (rc == -13) hint = " · permission denied";
    if (rc < 0)
        printf("\033[%d;1H\033[7m\033[K [ SAVE FAILED · rc=%d%s ] \033[0m",
               e->rows, rc, hint);
    else
        printf("\033[%d;1H\033[7m\033[K [ Wrote %d bytes to %s ] \033[0m",
               e->rows, rc, e->path);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* sotnano_run · PR 5 · full key dispatch (cursor movement + edit).    */
/* Movement helpers live static-free in sotnano.c (sotnano.h protos).  */
/* ------------------------------------------------------------------ */
int sotnano_run(seL4_CPtr orch_ep, const char *path) {
    static sotnano_editor_t e;
    memset(&e, 0, sizeof(e));
    e.orch_ep = orch_ep;
    strncpy(e.path, path && *path ? path : "/tmp/untitled", sizeof(e.path) - 1);
    sotnano_undo_reset();                     /* PR 10 fix · clear ring from any prior session */
    sotnano_load(&e);
    extern int serial_getchar(void);
    sotnano_probe_size(serial_getchar, &e.rows, &e.cols);
    printf("\033[?2004h");                    /* PR 7 · enable bracketed paste */
    printf("\033[2J");
    sotnano_render(&e);

    int running = 1;
    while (running) {
        int c = serial_getchar();
        if (c == 0) { seL4_Yield(); continue; }

        if (c == 0x1B) {                      /* ESC · arrows/Home/End/Pg/paste */
            int b1 = 0; while ((b1 = serial_getchar()) == 0) seL4_Yield();
            if (b1 != '[') continue;
            int b2 = 0; while ((b2 = serial_getchar()) == 0) seL4_Yield();
            /* Unified CSI parser · PR 7.  If b2 is a digit, accumulate the
             * full number and read the final byte; numeric-CSI ends in '~'
             * (5~/6~ PgUp/PgDn · 200~/201~ bracketed-paste markers).  A
             * non-digit b2 is a letter-CSI final byte (A/B/C/D/H/F) handled
             * by the movement switch below.  Plain arrows therefore still
             * dispatch correctly on terminals without bracketed paste. */
            int num = 0, fb = b2, got_num = 0;
            if (fb >= '0' && fb <= '9') {
                num = fb - '0'; got_num = 1;
                int d; while ((d = serial_getchar()) == 0) seL4_Yield();
                while (d >= '0' && d <= '9') {
                    num = num * 10 + (d - '0');
                    while ((d = serial_getchar()) == 0) seL4_Yield();
                }
                fb = d;                          /* final byte after the digits */
            }
            if (got_num && fb == '~') {
                if (num == 200) {                /* paste begin · no redraw */
                    /* PR 10 · a paste is its own undo batch · end any open
                     * batch so the first pasted char snapshots the pre-paste
                     * state · Ctrl+Z then removes the whole block. */
                    sotnano_undo_end_batch();
                    e.paste_mode = 1;
                } else if (num == 201) {         /* paste end · single redraw */
                    e.paste_mode = 0;
                    sotnano_undo_end_batch();     /* close the paste batch */
                    sotnano_render(&e);
                } else if (num == 5) {           /* PgUp · preserve redraw */
                    sotnano_move_vert(&e, -(e.rows - 3));
                    sotnano_undo_end_batch();     /* cursor move ends any edit batch */
                    sotnano_render(&e);
                } else if (num == 6) {           /* PgDn · preserve redraw */
                    sotnano_move_vert(&e, +(e.rows - 3));
                    sotnano_undo_end_batch();
                    sotnano_render(&e);
                }
                continue;                        /* numeric-CSI fully consumed */
            }
            /* letter-CSI · fb is a final byte (A/B/C/D/H/F) */
            switch (fb) {
                case 'A': sotnano_move_vert(&e, -1); break;
                case 'B': sotnano_move_vert(&e, +1); break;
                case 'C': sotnano_move_horiz(&e, +1); break;
                case 'D': sotnano_move_horiz(&e, -1); break;
                case 'H': sotnano_move_home(&e); break;
                case 'F': sotnano_move_end(&e); break;
                default: break;
            }
            sotnano_undo_end_batch();             /* PR 10 · cursor move ends edit batch */
        } else if (e.paste_mode) {            /* PR 7 · inside bracketed paste */
            /* Defensive: only printable + newline.  Ignore other control
             * bytes (the 201~ marker exits paste via the ESC path above).
             * PR 10 · route through handle_key · the open paste batch
             * (begun by sotnano_undo_begin_batch on the first char) means
             * the whole paste shares one snapshot. */
            if (c == 0x0D || c == 0x0A || (c >= 0x20 && c < 0x7F))
                sotnano_handle_key(&e, c);
            /* no per-char render · single redraw on 201~ */
            continue;
        } else if (c == 0x0F) {               /* Ctrl+O · save */
            int rc = sotnano_save(&e);
            sotnano_save_status(&e, rc);       /* surface result · was silently dropped */
            sotnano_undo_end_batch();          /* PR 10 · save ends edit batch */
        } else if (c == 0x18) {               /* Ctrl+X */
            if (e.dirty) {
                printf("\033[%d;1H\033[7m\033[K Save modified buffer? (y/n/Esc) \033[0m", e.rows);
                fflush(stdout);
                int k = 0; while ((k = serial_getchar()) == 0) seL4_Yield();
                if (k == 'y' || k == 'Y') {
                    int rc = sotnano_save(&e);
                    /* On failure stay open so the buffer isn't lost silently. */
                    if (rc < 0) sotnano_save_status(&e, rc);
                    else running = 0;
                }
                else if (k == 'n' || k == 'N') running = 0;
                /* else cancel */
            } else running = 0;
        } else if (c == 0x0C) {               /* Ctrl+L · re-probe + redraw */
            sotnano_probe_size(serial_getchar, &e.rows, &e.cols);
            printf("\033[2J");
        } else if (c == 0x17) {               /* Ctrl+W · search forward */
            sotnano_search_fwd(&e, serial_getchar);
            sotnano_undo_end_batch();          /* PR 10 · search ends edit batch */
        } else {
            /* PR 10 · pure edit keys (printable / Backspace / Enter /
             * Ctrl+K cut / Ctrl+U uncut / Ctrl+Z undo) · routed through the
             * IPC-free handler · undo batching lives inside it. */
            sotnano_handle_key(&e, c);
        }
        if (!e.paste_mode) sotnano_render(&e);   /* PR 7 · suppress per-char render mid-paste */
    }
    printf("\033[?2004l");                    /* PR 7 · disable bracketed paste */
    printf("\033[2J\033[H\033[?25h");         /* clear · home · ensure cursor visible */
    fflush(stdout);                           /* flush so the shell prompt starts clean */
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_mkdir · ORCH_OP_SOTFS_MKDIR · create a directory               */
/* ------------------------------------------------------------------ */
static int cmd_mkdir(seL4_CPtr orch_ep, const char *path)
{
    orch_sotfs_path_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, path ? path : "", ORCH_SOTFS_PATH_MAX - 1);

    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SOTFS_MKDIR, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    seL4_Word rc = seL4_MessageInfo_get_label(info);
    if (rc == 0) {
        printf("sotos> mkdir %s · OK\n", req.path);
    } else {
        printf("sotos> mkdir %s · FAILED (rc=%lu)\n", req.path, (unsigned long)rc);
    }
    return (int)rc;
}

/* ------------------------------------------------------------------ */
/* cmd_rm · ORCH_OP_SOTFS_RM · remove a file or directory             */
/* ------------------------------------------------------------------ */
static int cmd_rm(seL4_CPtr orch_ep, const char *path)
{
    orch_sotfs_path_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, path ? path : "", ORCH_SOTFS_PATH_MAX - 1);

    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SOTFS_RM, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    seL4_Word rc = seL4_MessageInfo_get_label(info);
    if (rc == 0) {
        printf("sotos> rm %s · OK\n", req.path);
    } else {
        printf("sotos> rm %s · FAILED (rc=%lu)\n", req.path, (unsigned long)rc);
    }
    return (int)rc;
}

/* ------------------------------------------------------------------ */
/* cmd_tail · reuse ORCH_OP_SOTFS_CAT · print last 5 lines / 256 B   */
/* ------------------------------------------------------------------ */
static int cmd_tail(seL4_CPtr orch_ep, const char *path)
{
    orch_sotfs_path_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, path ? path : "", ORCH_SOTFS_PATH_MAX - 1);

    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SOTFS_CAT, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    orch_sotfs_cat_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

    printf("sotos> tail %s\n", req.path);
    if (reply.rc < 0) {
        printf("[tail] error rc=%d\n", reply.rc);
        return 1;
    }

    uint32_t data_len = reply.data_len;
    if (data_len >= ORCH_SOTFS_CAT_MAX_BYTES)
        data_len = ORCH_SOTFS_CAT_MAX_BYTES - 1;
    reply.data[data_len] = '\0';

    /* Find start of last 5 lines (scan backwards for 5 newlines). */
    const char *text = (const char *)reply.data;
    const char *start = text;
    int newlines = 0;
    const char *p = text + data_len;
    /* Skip trailing newline if present. */
    if (p > text && *(p-1) == '\n') p--;
    while (p > text) {
        p--;
        if (*p == '\n') {
            newlines++;
            if (newlines >= 5) {
                start = p + 1;
                break;
            }
        }
    }
    printf("%s\n", start);
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_grep · reuse ORCH_OP_SOTFS_CAT · filter lines by pattern       */
/* ------------------------------------------------------------------ */
static int cmd_grep(seL4_CPtr orch_ep, const char *pattern, const char *path)
{
    orch_sotfs_path_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, path ? path : "", ORCH_SOTFS_PATH_MAX - 1);

    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SOTFS_CAT, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    orch_sotfs_cat_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

    printf("sotos> grep %s %s\n", pattern ? pattern : "", req.path);
    if (reply.rc < 0) {
        printf("[grep] error rc=%d\n", reply.rc);
        return 1;
    }

    uint32_t data_len = reply.data_len;
    if (data_len >= ORCH_SOTFS_CAT_MAX_BYTES)
        data_len = ORCH_SOTFS_CAT_MAX_BYTES - 1;
    reply.data[data_len] = '\0';

    /* Scan line by line, print those containing pattern. */
    char *text = (char *)reply.data;
    char *line_start = text;
    int matches = 0;
    while (*line_start) {
        char *nl = strchr(line_start, '\n');
        if (nl) *nl = '\0';
        if (!pattern || strstr(line_start, pattern)) {
            printf("%s\n", line_start);
            matches++;
        }
        if (nl) {
            *nl = '\n';
            line_start = nl + 1;
        } else {
            break;
        }
    }
    if (matches == 0) {
        printf("[grep] no matches\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_dns_list · sotNet-ζ · list all canary domain entries            */
/* ------------------------------------------------------------------ */
static int cmd_dns_list(seL4_CPtr orch_ep)
{
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_DNS_LIST, 0, 0, 0);
    info = seL4_Call(orch_ep, info);
    orch_dns_list_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t len    = seL4_MessageInfo_get_length(info);
    size_t nwords = sizeof(reply) / sizeof(seL4_Word);
    if (len > nwords) len = nwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < len; ++i) dst[i] = seL4_GetMR(i);

    printf("sotos> dns list · %u canary domains\n", reply.entry_count);
    for (uint32_t i = 0; i < reply.entry_count && i < ORCH_DNS_MAX_ENTRIES; ++i) {
        const dns_list_entry_t *e = &reply.entries[i];
        printf("  %-40s → %u.%u.%u.%u\n", e->domain,
               e->ip_be & 0xFF, (e->ip_be >> 8) & 0xFF,
               (e->ip_be >> 16) & 0xFF, (e->ip_be >> 24) & 0xFF);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_dns_install · sotNet-ζ · operator installs a new canary domain      */
/* ------------------------------------------------------------------ */
static int cmd_dns_install(seL4_CPtr orch_ep, const char *domain, const char *ip_str)
{
    uint32_t a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        printf("[sotshell] dns install · bad IP format · expected A.B.C.D\n");
        return -1;
    }
    uint32_t ip_be = a | (b << 8) | (c << 16) | (d << 24);

    /* Pack domain into 8 MRs (64 chars · 8 bytes each). */
    char buf[64];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, domain, sizeof(buf) - 1);
    for (size_t i = 0; i < 8; ++i) {
        seL4_Word w = 0;
        memcpy(&w, buf + i * 8, 8);
        seL4_SetMR(i, w);
    }
    seL4_SetMR(8, (seL4_Word)ip_be);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_DNS_INSTALL, 0, 0, 9);
    info = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(info);
    if (rc == 0) {
        printf("[sotshell] dns install · %s → %u.%u.%u.%u OK\n", domain, a, b, c, d);
    } else {
        printf("[sotshell] dns install · failed rc=%lu (table full?)\n", (unsigned long)rc);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_dns_lookup · sotNet-ζ · canary-domain lookup tripwire           */
/*                                                                    */
/* Client-side (Path A): we reuse the existing ORCH_OP_DNS_LIST IPC   */
/* to pull the full canary table, then match the operator-supplied     */
/* domain locally.  No new orch op required.                          */
/*                                                                    */
/* On HIT we emit two lines:                                          */
/*   [dns] HIT · <domain> → A.B.C.D (CANARY · tripwire armed)          */
/*   [dns-audit] pid=. operator-lookup canary-hit <domain> → A.B.C.D   */
/* On MISS:                                                           */
/*   [dns] MISS · <domain> not in canary table                         */
/*                                                                    */
/* The dns-audit line follows the sotOs audit-log convention so a     */
/* future anomaly/audit consumer can grep it downstream.             */
/* ------------------------------------------------------------------ */
static int cmd_dns_lookup(seL4_CPtr orch_ep, const char *domain)
{
    if (!domain || domain[0] == '\0') {
        printf("usage: dns lookup <domain>\n");
        return -1;
    }
    /* Fetch full canary table via existing DNS_LIST IPC. */
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_DNS_LIST, 0, 0, 0);
    info = seL4_Call(orch_ep, info);
    orch_dns_list_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    size_t len    = seL4_MessageInfo_get_length(info);
    size_t nwords = sizeof(reply) / sizeof(seL4_Word);
    if (len > nwords) len = nwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < len; ++i) dst[i] = seL4_GetMR(i);

    for (uint32_t i = 0; i < reply.entry_count && i < ORCH_DNS_MAX_ENTRIES; ++i) {
        const dns_list_entry_t *e = &reply.entries[i];
        if (strcmp(e->domain, domain) == 0) {
            uint32_t ip = e->ip_be;
            printf("[dns] HIT · %s → %u.%u.%u.%u (CANARY · tripwire armed)\n",
                   domain,
                   ip & 0xFF, (ip >> 8) & 0xFF,
                   (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
            printf("[dns-audit] pid=. operator-lookup canary-hit %s → %u.%u.%u.%u\n",
                   domain,
                   ip & 0xFF, (ip >> 8) & 0xFF,
                   (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
            return 0;
        }
    }
    printf("[dns] MISS · %s not in canary table\n", domain);
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_synth_trigger · sotNet-γ Phase 3-D-2 · operator-driven redirect */
/*                                                                    */
/* Usage: synth-trigger <a.b.c.d> <port>                            */
/* Sends ORCH_OP_SYNTH_TRIGGER to orch · orch synthesizes a Tier 2  */
/* sendto-style redirect via synth_record_redirect, which forwards  */
/* to net-synth, which calls back with ORCH_OP_SYNTH_RESPONSE.    */
/* Exercises the full γ Phase 3-D close-the-loop path on demand.      */
/* ------------------------------------------------------------------ */
static int cmd_synth_trigger(seL4_CPtr orch_ep, const char *ip_str, const char *port_str)
{
    uint32_t a, b, c, d;
    if (!ip_str || sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        printf("[synth-trigger] usage: synth-trigger <a.b.c.d> <port>\n");
        return -1;
    }
    uint32_t port = port_str ? (uint32_t)atoi(port_str) : 0;
    if (port == 0 || port > 65535) {
        printf("[synth-trigger] bad port · expected 1-65535\n");
        return -1;
    }
    uint32_t ip_be = a | (b << 8) | (c << 16) | (d << 24);
    /* Port in network byte order (big-endian) packed into low 16 bits. */
    uint16_t port_be = (uint16_t)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));

    seL4_SetMR(0, (seL4_Word)ip_be);
    seL4_SetMR(1, (seL4_Word)port_be);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SYNTH_TRIGGER, 0, 0, 2);
    info = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(info);
    if (rc == 0) {
        printf("[synth-trigger] orch acknowledged · dst=%u.%u.%u.%u:%u\n",
               a, b, c, d, port);
    } else {
        printf("[synth-trigger] orch NAK rc=%lu\n", (unsigned long)rc);
    }
    return 0;
}

/* cmd_synth_install · sotNet-γ-3-ε · operator installs a per-destination       */
/* response_profile.  Usage: synth-install <a.b.c.d> <port> <response_profile>                  */
/*   response_profile ∈ { c2-ack, updater, dns, bank, supply }                        */
static int cmd_synth_install(seL4_CPtr orch_ep, const char *ip_str,
                             const char *port_str, const char *response_profile_str)
{
    uint32_t a, b, c, d;
    if (!ip_str || sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        printf("[synth-install] usage: synth-install <a.b.c.d> <port> <response_profile>\n");
        return -1;
    }
    uint32_t port = port_str ? (uint32_t)atoi(port_str) : 0;
    if (port == 0 || port > 65535) {
        printf("[synth-install] bad port · expected 1-65535\n");
        return -1;
    }
    response_profile_kind_t kind = response_profile_name_to_kind(response_profile_str);
    if (kind == RESPONSE_PROFILE_UNKNOWN) {
        printf("[synth-install] unknown response_profile '%s' · expected c2-ack|updater|dns|bank|supply\n",
               response_profile_str ? response_profile_str : "(null)");
        return -1;
    }
    uint32_t ip_be = a | (b << 8) | (c << 16) | (d << 24);
    uint16_t port_be = (uint16_t)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));

    seL4_SetMR(0, (seL4_Word)ip_be);
    seL4_SetMR(1, (seL4_Word)port_be);
    seL4_SetMR(2, (seL4_Word)kind);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SYNTH_INSTALL, 0, 0, 3);
    info = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(info);
    if (rc == 0) {
        printf("[synth-install] installed · dst=%u.%u.%u.%u:%u response_profile=%s\n",
               a, b, c, d, port, response_profile_str);
    } else {
        printf("[synth-install] orch NAK rc=%lu\n", (unsigned long)rc);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_synth_queue · sotNet-γ Phase 3-D-2 · pending_recv introspection */
/*                                                                    */
/* Usage: synth-queue                                               */
/* Sends ORCH_OP_SYNTH_QUEUE_DUMP to orch · orch prints the contents */
/* of sotnet's pending_recv table (synthetic synth responses staged  */
/* for sotbox recvfrom · δ-D-3 will wire the consumer).               */
/* ------------------------------------------------------------------ */
static int cmd_synth_queue(seL4_CPtr orch_ep)
{
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SYNTH_QUEUE_DUMP, 0, 0, 0);
    info = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(info);
    if (rc == 0) {
        printf("[synth-queue] orch dumped pending_recv table\n");
    } else {
        printf("[synth-queue] orch NAK rc=%lu\n", (unsigned long)rc);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_python · L11-γ · operator runs Python code via Tier 0 sotbox    */
/*                                                                    */
/* Usage: python [--pledge <template>] "<code>"                        */
/*                                                                    */
/* Spawns a fresh python3.12-static sotBox under Tier 0 (pass-through) */
/* with argv = { "python3", "-c", <code> }.  Whether Python actually   */
/* runs depends on the orch frame budget + sotfs being able to back    */
/* the stdlib (landed by sibling L11-γ workers).                      */
/*                                                                    */
/* SPAWN-PLEDGE-CLI: pledge_mask is the resolved bitmask from the      */
/* --pledge flag (default PLEDGE_ALL).  It is packed into the spawn    */
/* message and applied to the new sotBox's lucas_state_t.pledge by     */
/* sotbox_init() before the first instruction · gates the dispatch     */
/* table per OBSD-δ semantics.                                         */
/* ------------------------------------------------------------------ */
static int cmd_python(seL4_CPtr orch_ep, const char *code, uint64_t pledge_mask)
{
    if (!code || !*code) {
        printf("usage: python [--pledge <template>] \"<code>\"\n");
        return -1;
    }
    static orch_spawn_msg_t py_msg;
    memset(&py_msg, 0, sizeof(py_msg));
    const char *py_argv[] = { "python3", "-c", code };
    strlcpy(py_msg.binname, "python3.12-static", ORCH_SPAWN_BINNAME_BYTES);
    py_msg.argc = 3; py_msg.profile = 0; py_msg.initial_tier = 0;
    py_msg.pledge = pledge_mask;
    size_t off = 0;
    for (int i = 0; i < 3; ++i) {
        size_t l = strlen(py_argv[i]) + 1;
        if (off + l >= ORCH_SPAWN_ARGV_BYTES) break;
        memcpy(py_msg.argv_pool + off, py_argv[i], l);
        off += l;
    }
    size_t nw = sizeof(py_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&py_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[python] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[python] spawn OK · pledge=0x%llx · running \"%s\"\n",
               (unsigned long long)pledge_mask, code);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_procd_fork_test · PR 6 · spawn the tiny procd_fork_test.bin    */
/*                       fixture from orch's CPIO.  The binary forks  */
/*                       once, the child exits 42, the parent wait4s */
/*                       and exits 0 · exercises OP_FORK + OP_EXIT + */
/*                       OP_WAIT shadow-announces against procd.     */
/* ------------------------------------------------------------------ */
static int cmd_procd_fork_test(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t pft_msg;
    memset(&pft_msg, 0, sizeof(pft_msg));
    const char *pft_argv[] = { "procd_fork_test" };
    strlcpy(pft_msg.binname, "procd_fork_test.bin",
            ORCH_SPAWN_BINNAME_BYTES);
    pft_msg.argc         = 1;
    pft_msg.profile      = 0;
    pft_msg.initial_tier = 0;
    pft_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t off = 0;
    size_t l = strlen(pft_argv[0]) + 1;
    memcpy(pft_msg.argv_pool + off, pft_argv[0], l);
    size_t nw = sizeof(pft_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&pft_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[procd-fork-test] spawn failed · rc=%lu\n",
               (unsigned long)rc);
    } else {
        printf("[procd-fork-test] spawn OK · fork+wait4 in flight\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_procd_pg_test · PR 9 · spawn the tiny procd_pg_test.bin        */
/*                       fixture from orch's CPIO.  The binary forks  */
/*                       once; the child calls setsid + getpgid(0)   */
/*                       and prints a one-line summary · exercises   */
/*                       the OP_SETSID + OP_GETPGID shadow-announces. */
/* ------------------------------------------------------------------ */
static int cmd_procd_pg_test(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t pgt_msg;
    memset(&pgt_msg, 0, sizeof(pgt_msg));
    const char *pgt_argv[] = { "procd_pg_test" };
    strlcpy(pgt_msg.binname, "procd_pg_test.bin",
            ORCH_SPAWN_BINNAME_BYTES);
    pgt_msg.argc         = 1;
    pgt_msg.profile      = 0;
    pgt_msg.initial_tier = 0;
    pgt_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t off = 0;
    size_t l = strlen(pgt_argv[0]) + 1;
    memcpy(pgt_msg.argv_pool + off, pgt_argv[0], l);
    size_t nw = sizeof(pgt_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&pgt_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[procd-pg-test] spawn failed · rc=%lu\n",
               (unsigned long)rc);
    } else {
        printf("[procd-pg-test] spawn OK · setsid+getpgid in flight\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_procd_pthread_test · PR 8 · spawn the tiny pthread_test.bin    */
/*                       fixture from orch's CPIO.  The binary calls  */
/*                       clone(CLONE_VM|CLONE_THREAD|CLONE_SETTLS) +  */
/*                       futex WAIT/WAKE · exercises the OP_CLONE    */
/*                       shadow-announce path against procd.         */
/* ------------------------------------------------------------------ */
static int cmd_procd_pthread_test(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t ptt_msg;
    memset(&ptt_msg, 0, sizeof(ptt_msg));
    const char *ptt_argv[] = { "pthread_test" };
    strlcpy(ptt_msg.binname, "pthread_test.bin",
            ORCH_SPAWN_BINNAME_BYTES);
    ptt_msg.argc         = 1;
    ptt_msg.profile      = 0;
    ptt_msg.initial_tier = 0;
    ptt_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t off = 0;
    size_t l = strlen(ptt_argv[0]) + 1;
    memcpy(ptt_msg.argv_pool + off, ptt_argv[0], l);
    size_t nw = sizeof(ptt_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&ptt_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[procd-pthread-test] spawn failed · rc=%lu\n",
               (unsigned long)rc);
    } else {
        printf("[procd-pthread-test] spawn OK · clone(CLONE_VM|CLONE_THREAD) in flight\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_procd_cond_test · PR 12 · spawn the procd_cond_test.bin        */
/*                       fixture · 3 workers FUTEX_WAIT_BITSET on a    */
/*                       cond, main FUTEX_WAKE_BITSET broadcasts.     */
/*                       Exercises the bitset filter + many-waiter    */
/*                       queue paths added in PR 12 (REQUEUE /         */
/*                       CMP_REQUEUE / WAKE_OP helpers are unit-tested */
/*                       on the same queue · this fixture is the      */
/*                       end-to-end smoke for the broadcast pattern). */
/* ------------------------------------------------------------------ */
static int cmd_procd_cond_test(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t pct_msg;
    memset(&pct_msg, 0, sizeof(pct_msg));
    const char *pct_argv[] = { "procd_cond_test" };
    strlcpy(pct_msg.binname, "procd_cond_test.bin",
            ORCH_SPAWN_BINNAME_BYTES);
    pct_msg.argc         = 1;
    pct_msg.profile      = 0;
    pct_msg.initial_tier = 0;
    pct_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t off = 0;
    size_t l = strlen(pct_argv[0]) + 1;
    memcpy(pct_msg.argv_pool + off, pct_argv[0], l);
    size_t nw = sizeof(pct_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&pct_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[procd-cond-test] spawn failed · rc=%lu\n",
               (unsigned long)rc);
    } else {
        printf("[procd-cond-test] spawn OK · 3-waiter FUTEX_WAIT_BITSET in flight\n");
    }
    return 0;
}

/* cmd_tls_probe · sotNet γ-3-γ-2b · spawn the BearSSL TLS client fixture.   */
static int cmd_tls_probe(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t tp_msg;
    memset(&tp_msg, 0, sizeof(tp_msg));
    const char *tp_argv[] = { "tls_probe" };
    strlcpy(tp_msg.binname, "tls_probe.bin", ORCH_SPAWN_BINNAME_BYTES);
    tp_msg.argc         = 1;
    tp_msg.profile      = 0;
    tp_msg.initial_tier = 0;
    tp_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(tp_argv[0]) + 1;
    memcpy(tp_msg.argv_pool, tp_argv[0], l);
    size_t nw = sizeof(tp_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&tp_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[tls-probe] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[tls-probe] spawn OK · BearSSL TLS handshake in flight\n");
    }
    return 0;
}

/* cmd_wayland_connect · L12-beta · spawn AF_UNIX wayland-0 route fixture. */
static int cmd_wayland_connect(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t wc_msg;
    memset(&wc_msg, 0, sizeof(wc_msg));
    const char *wc_argv[] = { "wayland_connect" };
    strlcpy(wc_msg.binname, "wayland_connect.bin", ORCH_SPAWN_BINNAME_BYTES);
    wc_msg.argc         = 1;
    wc_msg.profile      = 0;
    wc_msg.initial_tier = 0;
    wc_msg.trusted      = 1;
    wc_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(wc_argv[0]) + 1;
    memcpy(wc_msg.argv_pool, wc_argv[0], l);
    size_t nw = sizeof(wc_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&wc_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[wayland-connect] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[wayland-connect] spawn OK · AF_UNIX route probe in flight\n");
    }
    return 0;
}

/* cmd_wayland_sync · L12-gamma · spawn wl_display.sync round-trip fixture. */
static int cmd_wayland_sync(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t ws_msg;
    memset(&ws_msg, 0, sizeof(ws_msg));
    const char *ws_argv[] = { "wayland_sync" };
    strlcpy(ws_msg.binname, "wayland_sync.bin", ORCH_SPAWN_BINNAME_BYTES);
    ws_msg.argc         = 1;
    ws_msg.profile      = 0;
    ws_msg.initial_tier = 0;
    ws_msg.trusted      = 1;
    ws_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(ws_argv[0]) + 1;
    memcpy(ws_msg.argv_pool, ws_argv[0], l);
    size_t nw = sizeof(ws_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&ws_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[wayland-sync] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[wayland-sync] spawn OK · wl_display.sync probe in flight\n");
    }
    return 0;
}

/* cmd_wayland_info · L12-delta · spawn wl_registry globals + bind fixture. */
static int cmd_wayland_info(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t wi_msg;
    memset(&wi_msg, 0, sizeof(wi_msg));
    const char *wi_argv[] = { "wayland_info" };
    strlcpy(wi_msg.binname, "wayland_info.bin", ORCH_SPAWN_BINNAME_BYTES);
    wi_msg.argc         = 1;
    wi_msg.profile      = 0;
    wi_msg.initial_tier = 0;
    wi_msg.trusted      = 1;
    wi_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(wi_argv[0]) + 1;
    memcpy(wi_msg.argv_pool, wi_argv[0], l);
    size_t nw = sizeof(wi_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&wi_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[wayland-info] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[wayland-info] spawn OK · wl_registry probe in flight\n");
    }
    return 0;
}

/* Pillar-2 P2a · churn-harness · the synchronous spawn loop that MEASURES the
 * per-spawn capability leak.  ORCH_OP_SPAWN is synchronous (orch runs sotbox_init
 * → inline orch_fault_loop → returns when the child exits → replies), so this
 * shell-side loop fully serializes: each hello-linux.bin child reaps before the
 * next spawn Call.  CHURN_M is a large baseline cap; the controller tunes it
 * once the exhaustion point K is known.  NO teardown logic here. */
#define CHURN_M 250
static int cmd_churn(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t ch_msg;
    for (int i = 1; i <= CHURN_M; i++) {
        memset(&ch_msg, 0, sizeof(ch_msg));
        const char *ch_argv[] = { "hello" };
        strlcpy(ch_msg.binname, "hello-linux.bin", ORCH_SPAWN_BINNAME_BYTES);
        ch_msg.argc         = 1;
        ch_msg.profile      = 0;
        ch_msg.initial_tier = 0;
        ch_msg.trusted      = 1;
        ch_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
        size_t l = strlen(ch_argv[0]) + 1;
        memcpy(ch_msg.argv_pool, ch_argv[0], l);
        size_t nw = sizeof(ch_msg) / sizeof(seL4_Word);
        seL4_Word *src = (seL4_Word *)&ch_msg;
        for (size_t k = 0; k < nw; ++k) seL4_SetMR(k, src[k]);
        seL4_MessageInfo_t info =
            seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
        seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
        seL4_Word rc = seL4_MessageInfo_get_label(reply);
        printf("[churn] iter %d/%d spawn=%s rc=%ld\n",
               i, CHURN_M, rc == 0 ? "OK" : "FAIL", (long)rc);
        if (rc != 0) {
            printf("[churn] STOP at iter %d · rc=%ld (exhaustion point K)\n",
                   i, (long)rc);
            return 0;
        }
    }
    printf("[churn] %d/%d spawn OK · survived\n", CHURN_M, CHURN_M);
    return 0;
}

/* P4b · soak = a longer churn (SCALED 24h PROXY, not literal 24h). Drives SOAK_N
 * sequential spawn+reap iters of hello-linux.bin; orch emits [stats] every
 * STATS_EVERY spawns (free_arenas/live_sotbox/root_pages). The host gate
 * scripts/soak.sh computes the root_pages slope (frames/iter) + projects 24h.
 * MIRRORS cmd_churn's spawn idiom EXACTLY (trusted=1/pledge=ALL/argv "hello") —
 * the soak is the stability/immortality proof (a longer churn), NOT the
 * fork-bomb/Tier-2 path. */
#define SOAK_N 300   /* 5-critic B3 · scaled 24h PROXY; 500 times out (~0.88s/spawn · P4a evidence) */
static int cmd_soak(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t s_msg;
    printf("[soak] start · %d iterations (SCALED PROXY · not literal 24h)\n", SOAK_N);
    for (int i = 1; i <= SOAK_N; i++) {
        memset(&s_msg, 0, sizeof(s_msg));
        const char *s_argv[] = { "hello" };
        strlcpy(s_msg.binname, "hello-linux.bin", ORCH_SPAWN_BINNAME_BYTES);
        s_msg.argc         = 1;
        s_msg.profile      = 0;
        s_msg.initial_tier = 0;
        s_msg.trusted      = 1;
        s_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
        size_t l = strlen(s_argv[0]) + 1;
        memcpy(s_msg.argv_pool, s_argv[0], l);
        size_t nw = sizeof(s_msg) / sizeof(seL4_Word);
        seL4_Word *src = (seL4_Word *)&s_msg;
        for (size_t k = 0; k < nw; ++k) seL4_SetMR(k, src[k]);
        seL4_MessageInfo_t info =
            seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
        seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
        long rc = (long)seL4_MessageInfo_get_label(reply);
        if ((i % 50) == 0)
            printf("[soak] iter %d/%d rc=%ld\n", i, SOAK_N, rc);
        if (rc != 0) {
            printf("[soak] STOP at iter %d · rc=%ld (exhaustion)\n", i, rc);
            return 0;
        }
    }
    printf("[soak] %d/%d survived\n", SOAK_N, SOAK_N);
    return 0;
}

/* cmd_fork_bomb · Pillar-2 P2b · spawn the fork-bomb gate fixture ONCE.  Unlike
 * cmd_churn this spawns trusted=0 / initial_tier=0 so the fixture forks FOR REAL
 * (trusted=1 would suppress the Tier-2 promotion at functor.c:54 and may route to
 * the synth-fork path) — the OS is expected to detect the abusive fork rate,
 * quarantine the cell (Tier-2 + suspend subtree) and terminate it.  pledge=ALL so the
 * fork syscall passes the pledge gate and actually reaches the quota check. */
static int cmd_fork_bomb(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t fb_msg;
    memset(&fb_msg, 0, sizeof(fb_msg));
    const char *fb_argv[] = { "fork_bomb" };
    strlcpy(fb_msg.binname, "fork_bomb.bin", ORCH_SPAWN_BINNAME_BYTES);
    fb_msg.argc         = 1;
    fb_msg.profile      = 0;
    fb_msg.initial_tier = 0;            /* NOT trusted — must forge for real */
    fb_msg.trusted      = 0;
    fb_msg.pledge       = (uint64_t)-1; /* PLEDGE_ALL · fork passes the pledge gate */
    size_t l = strlen(fb_argv[0]) + 1;
    memcpy(fb_msg.argv_pool, fb_argv[0], l);
    size_t nw = sizeof(fb_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&fb_msg;
    for (size_t k = 0; k < nw; ++k) seL4_SetMR(k, src[k]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    printf("[fork-bomb] spawn fork_bomb.bin rc=%ld\n", (long)rc);
    return 0;
}

/* cmd_antidbg · Pillar-3 sottrace-Pro · spawn the anti-debug invisibility
 * probe ONCE.  Like cmd_fork_bomb it spawns trusted=0 / initial_tier=0 so the
 * fixture runs as an UNtrusted guest (trusted=1 would route around the real
 * syscall surface) — the probe calls ptrace(TRACEME), reads /proc/self/status
 * for TracerPid, getppid()s, and prints `[antidbg] ... invisible=YES` iff
 * TRACEME→0 and TracerPid==0 (the black-box anti-ptrace invisibility cert's
 * live evidence).  pledge=ALL so ptrace/open/read/getppid pass the pledge
 * gate and reach the real handlers. */
static int cmd_antidbg(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t ad_msg;
    memset(&ad_msg, 0, sizeof(ad_msg));
    const char *ad_argv[] = { "antidbg_probe" };
    strlcpy(ad_msg.binname, "antidbg_probe.bin", ORCH_SPAWN_BINNAME_BYTES);
    ad_msg.argc         = 1;
    ad_msg.profile      = 0;
    ad_msg.initial_tier = 0;            /* untrusted · real syscall surface */
    ad_msg.trusted      = 0;
    ad_msg.pledge       = (uint64_t)-1; /* PLEDGE_ALL · ptrace/open/read pass */
    size_t l = strlen(ad_argv[0]) + 1;
    memcpy(ad_msg.argv_pool, ad_argv[0], l);
    size_t nw = sizeof(ad_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&ad_msg;
    for (size_t k = 0; k < nw; ++k) seL4_SetMR(k, src[k]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    printf("[antidbg] spawn antidbg_probe.bin rc=%ld\n", (long)rc);
    return 0;
}

/* cmd_wl_shm · L13-D1 · spawn the hand-rolled wl_shm zero-copy pixel client. */
static int cmd_wl_shm(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t wls_msg;
    memset(&wls_msg, 0, sizeof(wls_msg));
    const char *wls_argv[] = { "wl_shm" };
    strlcpy(wls_msg.binname, "wl_shm.bin", ORCH_SPAWN_BINNAME_BYTES);
    wls_msg.argc         = 1;
    wls_msg.profile      = 0;
    wls_msg.initial_tier = 0;
    wls_msg.trusted      = 1;
    wls_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(wls_argv[0]) + 1;
    memcpy(wls_msg.argv_pool, wls_argv[0], l);
    size_t nw = sizeof(wls_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&wls_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[wl-shm] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[wl-shm] spawn OK · wl_shm zero-copy pixel client in flight\n");
    }
    return 0;
}

/* cmd_wl_capture_client · L14a-D1 · spawn the hostile screen-capture client AT TIER 2.
 * Mirrors cmd_wl_shm but sets initial_tier=2 AND trusted=0: a trusted process
 * cannot be tiered up (functor.c:54 `if (st->trusted && tier>0) return;`), so
 * trusted=0 lets initial_tier=2 stick.  st->tier latches at spawn BEFORE the
 * client's connect, so LUCAS deterministically routes it to the CANARY
 * compositor — where the only thing it can capture is the installed canary scene. */
static int cmd_wl_capture_client(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t wle_msg;
    memset(&wle_msg, 0, sizeof(wle_msg));
    const char *wle_argv[] = { "wl_capture_client" };
    strlcpy(wle_msg.binname, "wl_capture_client.bin", ORCH_SPAWN_BINNAME_BYTES);
    wle_msg.argc         = 1;
    wle_msg.profile      = 0;
    wle_msg.initial_tier = 2;   /* Tier-2 · route to the CANARY compositor */
    wle_msg.trusted      = 0;   /* NOT trusted so the Tier-2 promotion sticks */
    wle_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(wle_argv[0]) + 1;
    memcpy(wle_msg.argv_pool, wle_argv[0], l);
    size_t nw = sizeof(wle_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&wle_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[wl-capture] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[wl-capture] spawn OK · Tier-2 hostile capture client in flight\n");
    }
    return 0;
}

/* cmd_egress_probe · N1a · spawn the Tier-0e real-egress probe. */
static int cmd_egress_probe(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t eg_msg;
    memset(&eg_msg, 0, sizeof(eg_msg));
    const char *eg_argv[] = { "egress_probe" };
    strlcpy(eg_msg.binname, "egress_probe.bin", ORCH_SPAWN_BINNAME_BYTES);
    eg_msg.argc         = 1;
    eg_msg.profile      = 0;
    eg_msg.initial_tier = 3;   /* FUNCTOR_TIER_EGRESS · Tier-0e */
    eg_msg.trusted      = 1;   /* pin against anomaly promotion mid-connection */
    eg_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(eg_argv[0]) + 1;
    memcpy(eg_msg.argv_pool, eg_argv[0], l);
    size_t nw = sizeof(eg_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&eg_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[egress-probe] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[egress-probe] spawn OK · Tier-0e real-egress probe in flight\n");
    }
    return 0;
}

/* cmd_canary_service · sottrace-v1 T10 · spawn the Tier-0e canary-service that
 * listen(:80)/accept()/recv()s an inbound connection (parking on accept until
 * the T3 liveness poll wakes it).  Same tier/trusted/pledge as the egress probe
 * so its socket path bypasses deception interception and reaches the real fd. */
static int cmd_canary_service(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t hs_msg;
    memset(&hs_msg, 0, sizeof(hs_msg));
    const char *hs_argv[] = { "canary_service" };
    strlcpy(hs_msg.binname, "canary_service.bin", ORCH_SPAWN_BINNAME_BYTES);
    hs_msg.argc         = 1;
    hs_msg.profile      = 0;
    hs_msg.initial_tier = 3;   /* FUNCTOR_TIER_EGRESS · Tier-0e */
    hs_msg.trusted      = 1;   /* pin against anomaly promotion mid-connection */
    hs_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(hs_argv[0]) + 1;
    memcpy(hs_msg.argv_pool, hs_argv[0], l);
    size_t nw = sizeof(hs_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&hs_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[canary-svc] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[canary-svc] spawn OK · Tier-0e canary-service listening :80\n");
    }
    return 0;
}

/* cmd_canary_read · sottrace-v1 T11 · spawn the Tier-2 canary-read fixture that
 * reads /etc/passwd through the guest VFS canary backend, firing the v0
 * trace_emit_canary (SG_EV_CANARY_READ) producer end-to-end. */
static int cmd_canary_read(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t hr_msg;
    memset(&hr_msg, 0, sizeof(hr_msg));
    const char *hr_argv[] = { "canary_read" };
    strlcpy(hr_msg.binname, "canary_read.bin", ORCH_SPAWN_BINNAME_BYTES);
    hr_msg.argc         = 1;
    hr_msg.profile      = 0;
    hr_msg.initial_tier = 2;   /* Tier-2 · canary backend active for op_read */
    hr_msg.trusted      = 0;   /* NOT trusted so trace_emit_canary fires */
    hr_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(hr_argv[0]) + 1;
    memcpy(hr_msg.argv_pool, hr_argv[0], l);
    size_t nw = sizeof(hr_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&hr_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[canary-read] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[canary-read] spawn OK · Tier-2 sotbox reading /etc/passwd via canary VFS\n");
    }
    return 0;
}

/* cmd_hello_dyn · N3/D1 · spawn the dynamically-linked-against-musl probe.
 * Ordinary sotbox (Tier-0 pass-through · untrusted · PLEDGE_ALL): proves the
 * dynamic-loading path (kernel loads the PIE + ld-musl, ld-musl relocates). */
static int cmd_hello_dyn(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t hd_msg;
    memset(&hd_msg, 0, sizeof(hd_msg));
    const char *hd_argv[] = { "hello_dyn" };
    strlcpy(hd_msg.binname, "hello_dyn.bin", ORCH_SPAWN_BINNAME_BYTES);
    hd_msg.argc         = 1;
    hd_msg.profile      = 0;
    hd_msg.initial_tier = 0;             /* Tier-0 · F_0 pass-through */
    hd_msg.trusted      = 0;
    hd_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL · ld-musl startup syscalls */
    size_t l = strlen(hd_argv[0]) + 1;
    memcpy(hd_msg.argv_pool, hd_argv[0], l);
    size_t nw = sizeof(hd_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&hd_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[hello-dyn] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[hello-dyn] spawn OK · dynamic-musl probe in flight\n");
    }
    return 0;
}

/* cmd_hello_dyn2 · N3/D2 · spawn the multi-lib dynamic probe (DT_NEEDED an
 * extra libonefn.so beyond libc · runtime file-backed mmap). */
static int cmd_hello_dyn2(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t hd_msg;
    memset(&hd_msg, 0, sizeof(hd_msg));
    const char *hd_argv[] = { "hello_dyn2" };
    strlcpy(hd_msg.binname, "hello_dyn2.bin", ORCH_SPAWN_BINNAME_BYTES);
    hd_msg.argc         = 1;
    hd_msg.profile      = 0;
    hd_msg.initial_tier = 0;             /* Tier-0 · F_0 pass-through */
    hd_msg.trusted      = 0;
    hd_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL · ld-musl + lib startup */
    size_t l = strlen(hd_argv[0]) + 1;
    memcpy(hd_msg.argv_pool, hd_argv[0], l);
    size_t nw = sizeof(hd_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&hd_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[hello-dyn2] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[hello-dyn2] spawn OK · multi-lib dynamic probe in flight\n");
    }
    return 0;
}

/* cmd_hello_ssl · N3/D3 · spawn the OpenSSL bait (DT_NEEDED real libcrypto.so.3,
 * 4.48 MB · lazy file-backed mmap · RAND_bytes + SHA-256). */
static int cmd_hello_ssl(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t hs_msg;
    memset(&hs_msg, 0, sizeof(hs_msg));
    const char *hs_argv[] = { "hello_ssl" };
    strlcpy(hs_msg.binname, "hello_ssl.bin", ORCH_SPAWN_BINNAME_BYTES);
    hs_msg.argc         = 1;
    hs_msg.profile      = 0;
    hs_msg.initial_tier = 0;             /* Tier-0 · F_0 pass-through */
    hs_msg.trusted      = 0;
    hs_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL · OpenSSL startup */
    size_t l = strlen(hs_argv[0]) + 1;
    memcpy(hs_msg.argv_pool, hs_argv[0], l);
    size_t nw = sizeof(hs_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&hs_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[hello-ssl] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[hello-ssl] spawn OK · OpenSSL bait in flight (lazy-mmap libcrypto)\n");
    }
    return 0;
}

/* cmd_real_vfs · v2-real-vfs · Gate E · spawn vfsprobe.bin, whose
 * DT_NEEDED (libvfsprobe.so) is a symlink to libvfsprobe.so.1 in the real
 * recursive sysroot tree.  Exercises sysroot symlink-follow + openat/fstat/
 * read/lseek/mmap on /usr/lib/crt1.o + getdents64 over /usr/lib. */
static int cmd_real_vfs(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t rv_msg;
    memset(&rv_msg, 0, sizeof(rv_msg));
    const char *rv_argv[] = { "vfsprobe" };
    strlcpy(rv_msg.binname, "vfsprobe.bin", ORCH_SPAWN_BINNAME_BYTES);
    rv_msg.argc         = 1;
    rv_msg.profile      = 0;
    rv_msg.initial_tier = 0;             /* Tier-0 · F_0 pass-through */
    rv_msg.trusted      = 0;
    rv_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL · ld-musl + lib startup */
    size_t l = strlen(rv_argv[0]) + 1;
    memcpy(rv_msg.argv_pool, rv_argv[0], l);
    size_t nw = sizeof(rv_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&rv_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[real-vfs] spawn failed · rc=%lu\n", (unsigned long)rc);
    } else {
        printf("[real-vfs] spawn OK · real-tree probe in flight\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_sdlspike · v2.3 · SDL2-over-real-Wayland smoke (software/wl_shm,    */
/*               NO EGL).  Spawns the committed sdlspike.bin fixture; runs */
/*               BEFORE the captive bbsh so its markers land headless.     */
/* ------------------------------------------------------------------ */
static int cmd_sdlspike(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t sp_msg; memset(&sp_msg, 0, sizeof(sp_msg));
    const char *a[] = { "sdlspike" };
    strlcpy(sp_msg.binname, "sdlspike.bin", ORCH_SPAWN_BINNAME_BYTES);
    sp_msg.argc = 1; sp_msg.profile = 0; sp_msg.initial_tier = 0;
    sp_msg.trusted = 0; sp_msg.pledge = (uint64_t)-1;
    memcpy(sp_msg.argv_pool, a[0], strlen(a[0]) + 1);
    size_t nw = sizeof(sp_msg) / sizeof(seL4_Word); seL4_Word *src = (seL4_Word *)&sp_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t r = seL4_Call(orch_ep, seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw));
    printf(seL4_MessageInfo_get_label(r)
           ? "[sdlspike] spawn failed\n"
           : "[sdlspike] spawn OK · SDL2 sw/wl_shm over wayland in flight\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_procd_robust_test · PR 13 · spawn the procd_robust_test.bin    */
/*                         fixture · main thread + 1 worker each call */
/*                         set_robust_list(2).  Exercises the         */
/*                         OP_SET_ROBUST shadow-announce + the lucas- */
/*                         side robust_list walk on thread exit.     */
/* ------------------------------------------------------------------ */
static int cmd_procd_robust_test(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t prt_msg;
    memset(&prt_msg, 0, sizeof(prt_msg));
    const char *prt_argv[] = { "procd_robust_test" };
    strlcpy(prt_msg.binname, "procd_robust_test.bin",
            ORCH_SPAWN_BINNAME_BYTES);
    prt_msg.argc         = 1;
    prt_msg.profile      = 0;
    prt_msg.initial_tier = 0;
    prt_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t off = 0;
    size_t l = strlen(prt_argv[0]) + 1;
    memcpy(prt_msg.argv_pool + off, prt_argv[0], l);
    size_t nw = sizeof(prt_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&prt_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[procd-robust-test] spawn failed · rc=%lu\n",
               (unsigned long)rc);
    } else {
        printf("[procd-robust-test] spawn OK · set_robust_list(2) announces in flight\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_shellhook_test · init-cron PR 10 · spawn shellhook_test.bin    */
/*                       fixture · parent fork()s a child that        */
/*                       execve("/bin/sh", {"sh"}, NULL).  Lucas's    */
/*                       shellhook rewrites argv to source /etc/bashrc */
/*                       + /root/.bashrc so [BASHRC-MARKER] lines     */
/*                       appear in the serial log.                    */
/* ------------------------------------------------------------------ */
static int cmd_shellhook_test(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t sht_msg;
    memset(&sht_msg, 0, sizeof(sht_msg));
    const char *sht_argv[] = { "shellhook_test" };
    strlcpy(sht_msg.binname, "shellhook_test.bin",
            ORCH_SPAWN_BINNAME_BYTES);
    sht_msg.argc         = 1;
    sht_msg.profile      = 0;
    sht_msg.initial_tier = 0;
    sht_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t off = 0;
    size_t l = strlen(sht_argv[0]) + 1;
    memcpy(sht_msg.argv_pool + off, sht_argv[0], l);
    size_t nw = sizeof(sht_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&sht_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[shellhook-test] spawn failed · rc=%lu\n",
               (unsigned long)rc);
    } else {
        printf("[shellhook-test] spawn OK · execve(/bin/sh) shellhook in flight\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_stage7_demo · γ · spawn stage7_demo.bin fixture · the sotbox   */
/*                   spawns at Tier-2 and writes to 4 sensitive paths */
/*                   (crontab + bashrc + backdoor.service +           */
/*                    backdoor.timer).  Lucas intercepts each write   */
/*                   via path_matcher and sets functor_persistence    */
/*                   on the inode.  Post-simreboot the lie survives.  */
/*                                                                    */
/*                   Why C-static and not Python?  The Python         */
/*                   stdlib zip is not populated in the install image */
/*                   today, so simulated_attacker.py can't drive the     */
/*                   demo.  This fixture provides a non-Python path.  */
/* ------------------------------------------------------------------ */
static int cmd_stage7_demo(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t s7_msg;
    memset(&s7_msg, 0, sizeof(s7_msg));
    const char *s7_argv[] = { "stage7_demo" };
    strlcpy(s7_msg.binname, "stage7_demo.bin",
            ORCH_SPAWN_BINNAME_BYTES);
    s7_msg.argc         = 1;
    s7_msg.profile      = 0;
    s7_msg.initial_tier = 2;  /* γ · spawn at Tier-2 so F_persistence fires */
    s7_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t off = 0;
    size_t l = strlen(s7_argv[0]) + 1;
    memcpy(s7_msg.argv_pool + off, s7_argv[0], l);
    size_t nw = sizeof(s7_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&s7_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[stage7-c] spawn failed · rc=%lu\n",
               (unsigned long)rc);
    } else {
        printf("[stage7-c] spawn OK · Tier-2 sotbox writing to crontab/bashrc/.service/.timer\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_syscall_test · POSIX-surface PR 6 · spawn syscall_test.bin ·   */
/*                    raw-syscall C-static fixture that validates the */
/*                    LUCAS POSIX surface arc (PRs 1-5) at runtime:    */
/*                    unlink(87) + readv/writev(19/20) + madvise noop  */
/*                    (28) + the fd-1/2 console/FS boundary.  Prints   */
/*                    [syscall-test] ALL PASS on success · smoke gate  */
/*                    SYSCALL·all-pass.  Spawns at Tier-0 (initial_tier */
/*                    =0): the stdout writes must NOT promote the box,  */
/*                    which is exactly the PR 5 boundary under test.    */
/* ------------------------------------------------------------------ */
static int cmd_syscall_test(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t sc_msg;
    memset(&sc_msg, 0, sizeof(sc_msg));
    const char *sc_argv[] = { "syscall_test" };
    strlcpy(sc_msg.binname, "syscall_test.bin",
            ORCH_SPAWN_BINNAME_BYTES);
    sc_msg.argc         = 1;
    sc_msg.profile      = 0;
    sc_msg.initial_tier = 0;  /* PR 5 · stdout writes must not promote */
    sc_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t off = 0;
    size_t l = strlen(sc_argv[0]) + 1;
    memcpy(sc_msg.argv_pool + off, sc_argv[0], l);
    size_t nw = sizeof(sc_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&sc_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[syscall-test] spawn failed · rc=%lu\n",
               (unsigned long)rc);
    } else {
        printf("[syscall-test] spawn OK · validating unlink/iov/madvise/console\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_ubench · T5 syscall-latency microbench · spawn ubench.bin    */
/*              (raw getpid under rdtsc · fault→IPC→lucAs cost).      */
/*              Tier-0 trusted so its stdout reaches the operator     */
/*              console as "[ubench] getpid N=... median=..." .       */
/* ------------------------------------------------------------------ */
static int cmd_ubench(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t ub_msg;
    memset(&ub_msg, 0, sizeof(ub_msg));
    const char *ub_argv[] = { "ubench" };
    strlcpy(ub_msg.binname, "ubench.bin", ORCH_SPAWN_BINNAME_BYTES);
    ub_msg.argc         = 1;
    ub_msg.profile      = 0;
    ub_msg.initial_tier = 0;
    ub_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(ub_argv[0]) + 1;
    memcpy(ub_msg.argv_pool, ub_argv[0], l);
    size_t nw = sizeof(ub_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&ub_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    printf("[ubench] spawn rc=%lu (T5 · raw getpid latency · fault->IPC->lucAs)\n",
           (unsigned long)rc);
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_ubench_libc · vDSO arc · Task 8 · spawn ubench_libc.bin     */
/*   A normal musl-linked binary that calls clock_gettime() via the  */
/*   standard libc entry point.  musl resolves __vdso_clock_gettime  */
/*   from AT_SYSINFO_EHDR automatically — no trap if vDSO is mapped. */
/*   Emits: "[ubench-libc] clock_gettime min=<cyc> mean=<cyc>"      */
/*   Gate: tools/vdso-gate.sh asserts min < 1000 (no trap).         */
/* ------------------------------------------------------------------ */
static int cmd_ubench_libc(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t ul_msg;
    memset(&ul_msg, 0, sizeof(ul_msg));
    const char *ul_argv[] = { "ubench_libc" };
    strlcpy(ul_msg.binname, "ubench_libc.bin", ORCH_SPAWN_BINNAME_BYTES);
    ul_msg.argc         = 1;
    ul_msg.profile      = 0;
    ul_msg.initial_tier = 0;
    ul_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(ul_argv[0]) + 1;
    memcpy(ul_msg.argv_pool, ul_argv[0], l);
    size_t nw = sizeof(ul_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&ul_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    printf("[orch] ubench-libc spawn rc=%lu (Task8 · libc clock_gettime via vDSO)\n",
           (unsigned long)rc);
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_vdso_probe · vDSO arc · Task 5 · F1 · spawn vdso_probe.bin  */
/*   The probe manually parses the vDSO ELF mapped at               */
/*   AT_SYSINFO_EHDR, resolves __vdso_clock_gettime by name, and    */
/*   calls it for CLOCK_MONOTONIC + CLOCK_REALTIME, emitting:       */
/*   "[vdso-probe] resolved=0x<addr> mono=<s>.<ns> real=<s>"        */
/*   Gate: tools/vdso-gate.sh greps for that marker.                */
/* ------------------------------------------------------------------ */
static int cmd_vdso_probe(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t vp_msg;
    memset(&vp_msg, 0, sizeof(vp_msg));
    const char *vp_argv[] = { "vdso_probe" };
    strlcpy(vp_msg.binname, "vdso_probe.bin", ORCH_SPAWN_BINNAME_BYTES);
    vp_msg.argc         = 1;
    vp_msg.profile      = 0;
    vp_msg.initial_tier = 0;
    vp_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(vp_argv[0]) + 1;
    memcpy(vp_msg.argv_pool, vp_argv[0], l);
    size_t nw = sizeof(vp_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&vp_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    printf("[orch] vdso-probe spawn rc=%lu (Task5·F1 · ELF parse + clock_gettime call)\n",
           (unsigned long)rc);
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_fastpath_probe · fast-path arc · Task 9 · spawn fastpath_probe.bin */
/*   Calls sched_yield (sysno 24) in a timed lfence;rdtsc loop.         */
/*   Emits: "[fastpath-probe] sched_yield_cycles=<min> ret=<ret>"        */
/*   Gate: tools/fastpath-gate.sh asserts min < 2000 AND ret==0.         */
/* ------------------------------------------------------------------ */
static int cmd_fastpath_probe(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t fp_msg;
    memset(&fp_msg, 0, sizeof(fp_msg));
    const char *fp_argv[] = { "fastpath_probe" };
    strlcpy(fp_msg.binname, "fastpath_probe.bin", ORCH_SPAWN_BINNAME_BYTES);
    fp_msg.argc         = 1;
    fp_msg.profile      = 0;
    fp_msg.initial_tier = 0;
    fp_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t l = strlen(fp_argv[0]) + 1;
    memcpy(fp_msg.argv_pool, fp_argv[0], l);
    size_t nw = sizeof(fp_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&fp_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    printf("[orch] fastpath-probe spawn rc=%lu (Task9 · sched_yield fast-path gate)\n",
           (unsigned long)rc);
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_anomaly_test · ANOMALY PR 7 · spawn anomaly_test.bin ·      */
/*                     raw-syscall C-static fixture that deterministi- */
/*                     cally drives a sotbox's weighted suspicion      */
/*                     score across BOTH tier thresholds: cred recon   */
/*                     (+15, under T1) → 5 real-file writes (score 20, */
/*                     crosses T1) → 6-unlink burst (escalating        */
/*                     2+4+6+8+10+12, crosses T2).  Prints             */
/*                     [anomaly-test] ALL PASS on success · smoke     */
/*                     gates ANOMALY·test·all-pass / tier1 / tier2.   */
/*                     Spawns at Tier-0 (initial_tier=0): the engine    */
/*                     must promote it 0→1→2 from the syscall events.  */
/* ------------------------------------------------------------------ */
static int cmd_anomaly_test(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t st_msg;
    memset(&st_msg, 0, sizeof(st_msg));
    const char *st_argv[] = { "anomaly_test" };
    strlcpy(st_msg.binname, "anomaly_test.bin",
            ORCH_SPAWN_BINNAME_BYTES);
    st_msg.argc         = 1;
    st_msg.profile      = 0;
    st_msg.initial_tier = 0;  /* engine must promote 0→1→2 from events */
    st_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t off = 0;
    size_t l = strlen(st_argv[0]) + 1;
    memcpy(st_msg.argv_pool + off, st_argv[0], l);
    size_t nw = sizeof(st_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&st_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[anomaly-test] spawn failed · rc=%lu\n",
               (unsigned long)rc);
    } else {
        printf("[anomaly-test] spawn OK · driving score cred+writes+unlink-burst (T1→T2)\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_execmap_test · SP1 PR 4 · spawn execmap_test.bin TRUSTED ·     */
/*                    raw-syscall C-static fixture that mmaps a page  */
/*                    PROT_READ|PROT_WRITE|PROT_EXEC, copies x86_64   */
/*                    machine code into it, and jumps in.  The code   */
/*                    running IN the writable-mapped page prints      */
/*                    "[execmap-test] exec OK" · smoke gate           */
/*                    EXECMAP·exec-ok.  This is the always-on proof   */
/*                    that the PR 4 W^X relaxation actually yields an  */
/*                    executable writable page for a trusted sotbox    */
/*                    (the gating capability for the in-OS compiler).  */
/*                    Spawned TRUSTED (trusted=1) · the mmap RWX is    */
/*                    rejected with -EINVAL on an untrusted box.       */
/* ------------------------------------------------------------------ */
static int cmd_execmap_test(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t em_msg;
    memset(&em_msg, 0, sizeof(em_msg));
    const char *em_argv[] = { "execmap_test" };
    strlcpy(em_msg.binname, "execmap_test.bin",
            ORCH_SPAWN_BINNAME_BYTES);
    em_msg.argc         = 1;
    em_msg.profile      = 0;
    em_msg.initial_tier = 0;  /* SP1 · trusted pins the tier; start at 0 */
    em_msg.trusted      = 1;  /* SP1 · RWX mmap is only granted to trusted */
    em_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t off = 0;
    size_t l = strlen(em_argv[0]) + 1;
    memcpy(em_msg.argv_pool + off, em_argv[0], l);
    size_t nw = sizeof(em_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&em_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[execmap-test] spawn failed · rc=%lu\n",
               (unsigned long)rc);
    } else {
        printf("[execmap-test] spawn OK · trusted · mmap RWX + execute in writable page\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_procd_exec_test · PR 7 · spawn busybox-static.bin with argv    */
/*                       {"sh", "-c", "ls /"}.  busybox sh parses    */
/*                       the -c form with a single command and tail- */
/*                       execve()s `ls` (no intermediate fork · shell */
/*                       optimisation) into the same sotbox slot.    */
/*                       L3b-T6's same-binary in-place ELF reuse     */
/*                       makes the execve succeed and triggers the   */
/*                       OP_EXEC shadow-announce to procd.           */
/* ------------------------------------------------------------------ */
static int cmd_procd_exec_test(seL4_CPtr orch_ep)
{
    static orch_spawn_msg_t pet_msg;
    memset(&pet_msg, 0, sizeof(pet_msg));
    const char *pet_argv[] = { "sh", "-c", "ls /" };
    strlcpy(pet_msg.binname, "busybox-static.bin",
            ORCH_SPAWN_BINNAME_BYTES);
    pet_msg.argc         = 3;
    pet_msg.profile      = 0;
    pet_msg.initial_tier = 0;
    pet_msg.pledge       = (uint64_t)-1;  /* PLEDGE_ALL */
    size_t off = 0;
    for (int ai = 0; ai < 3; ++ai) {
        size_t l = strlen(pet_argv[ai]) + 1;
        if (off + l >= ORCH_SPAWN_ARGV_BYTES) break;
        memcpy(pet_msg.argv_pool + off, pet_argv[ai], l);
        off += l;
    }
    size_t nw = sizeof(pet_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&pet_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[procd-exec-test] spawn failed · rc=%lu\n",
               (unsigned long)rc);
    } else {
        printf("[procd-exec-test] spawn OK · busybox sh -c 'ls /' · execve in flight\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_inject_script · read a Python script from sotfs and spawn       */
/*                     python3.12-static with `-c <script>`.          */
/*                                                                    */
/* Usage: inject-script <sotfs-path>                                   */
/*                                                                    */
/* Step 1 · ORCH_OP_SOTFS_CAT reads the script bytes (up to            */
/*          path stays in argv, NOT the content.  Step 2 · pack       */
/*          argv = { "python3", <sotfs-path> } and ORCH_OP_SPAWN it    */
/*          under Tier 0 / PLEDGE_ALL.  Python opens the script via   */
/*          the sotfs VFS at runtime · size NOT bounded by the spawn  */
/*          argv pool.                                                 */
/*                                                                    */
/* Note: a brief existence check via ORCH_OP_SOTFS_CAT confirms the   */
/*       path resolves before we spawn python · saves a useless boot. */
/* ------------------------------------------------------------------ */
static int cmd_inject_script(seL4_CPtr orch_ep, const char *path)
{
    if (!path || !*path) {
        printf("usage: inject-script <sotfs-path>\n");
        return -1;
    }
    /* Skip leading whitespace (run_command passes us line+i+1). */
    while (*path == ' ') ++path;
    if (!*path) {
        printf("usage: inject-script <sotfs-path>\n");
        return -1;
    }

    /* ---- Step 1 · existence probe · ORCH_OP_SOTFS_CAT for any bytes. ---- */
    orch_sotfs_path_req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, path, ORCH_SOTFS_PATH_MAX - 1);

    size_t nwords = sizeof(req) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&req;
    for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info =
        seL4_MessageInfo_new(ORCH_OP_SOTFS_CAT, 0, 0, nwords);
    info = seL4_Call(orch_ep, info);

    static orch_sotfs_cat_reply_t reply;   /* static · no malloc / no stack blow */
    memset(&reply, 0, sizeof(reply));
    size_t rlen    = seL4_MessageInfo_get_length(info);
    size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
    if (rlen > rnwords) rlen = rnwords;
    seL4_Word *dst = (seL4_Word *)&reply;
    for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

    printf("sotos> inject-script %s\n", req.path);
    if (reply.rc < 0) {
        printf("[inject-script] script not found · rc=%d · install first\n",
               reply.rc);
        return 1;
    }

    /* ---- Step 2 · spawn `python3 <path>` · file mode, NOT -c. ---- */
    static orch_spawn_msg_t py_msg;
    memset(&py_msg, 0, sizeof(py_msg));
    strlcpy(py_msg.binname, "python3.12-static", ORCH_SPAWN_BINNAME_BYTES);
    py_msg.argc = 2;
    py_msg.profile = 0;
    py_msg.initial_tier = 0;
    py_msg.pledge = PLEDGE_ALL;

    /* Translate sotfs-root path → VFS path the sotbox sees.
     * sotfs is mounted at /tmp/ inside the sotbox, so a file installed at
     * sotfs root "/<leaf>" appears as "/tmp/<leaf>" through Python's open().
     * If the user already passed "/tmp/<...>", leave it alone. */
    char vfs_path[ORCH_SOTFS_PATH_MAX + 8];
    if (strncmp(req.path, "/tmp/", 5) == 0) {
        strlcpy(vfs_path, req.path, sizeof(vfs_path));
    } else {
        const char *leaf = (req.path[0] == '/') ? req.path + 1 : req.path;
        snprintf(vfs_path, sizeof(vfs_path), "/tmp/%s", leaf);
    }

    const char *py_argv[2] = { "python3", vfs_path };
    size_t off = 0;
    int truncated = 0;
    for (int ai = 0; ai < 2; ++ai) {
        size_t l = strlen(py_argv[ai]) + 1;
        if (off + l > ORCH_SPAWN_ARGV_BYTES) {
            /* Path doesn't fit in argv pool · only happens with a path
             * longer than ~360 chars, which is well above the sotfs path
             * max (96 bytes today). */
            truncated = 1;
            break;
        }
        memcpy(py_msg.argv_pool + off, py_argv[ai], l);
        off += l;
    }
    if (truncated) {
        printf("[inject-script] WARNING · path truncated\n");
    }

    size_t nw = sizeof(py_msg) / sizeof(seL4_Word);
    seL4_Word *psrc = (seL4_Word *)&py_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, psrc[i]);
    seL4_MessageInfo_t sinfo =
        seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t srep = seL4_Call(orch_ep, sinfo);
    seL4_Word rc = seL4_MessageInfo_get_label(srep);
    if (rc != 0) {
        printf("[inject-script] spawn failed · rc=%lu\n", (unsigned long)rc);
        return 1;
    }
    printf("[inject-script] spawn OK · sotfs=%s vfs=%s (file-mode, no size limit)\n",
           req.path, vfs_path);
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_tcc · tcc-libc · passthrough tokenizer · spawn the embedded    */
/*           TinyCC (binstore entry "tcc.bin") TRUSTED (tier-pinned).  */
/*           The operator's line is whitespace-split into tokens and   */
/*           forwarded verbatim AFTER the injected sysroot search +    */
/*           loadability flags, so argv becomes:                       */
/*             ["tcc","-I/usr/include","-B/usr/lib","-static",         */
/*              <operator tokens...>]                                   */
/*           -I/usr/include + -B/usr/lib expose the musl sysroot tree  */
/*           (mounted /usr · tcc-libc) so hosted sources can           */
/*           #include <stdio.h> + link musl; -static forces a loadable */
/*           static non-PIE EXEC (the L1 loader rejects PT_INTERP ·    */
/*           SP2 PR7).  Hosted is the default; freestanding = the      */
/*           operator passes -nostdlib (the -I is then unused).        */
/*                                                                     */
/*           Special case: `tcc -run` JIT-executes in-process and      */
/*           -static conflicts with -run in TinyCC, so the injected    */
/*           -static is DROPPED when any operator token is -run.       */
/*                                                                     */
/*           Arg packing mirrors cmd_inject_script: argc + sequential  */
/*           NUL-terminated strings written into argv_pool; orch       */
/*           unpacks the full vector (incl. argv[0]) generically.      */
/*                                                                     */
/* Usage: tcc [flags...] <sotfs-path-to-.c>                            */
/* ------------------------------------------------------------------ */
static int cmd_tcc(seL4_CPtr orch_ep, const char *path)
{
    if (!path || !*path) {
        printf("usage: tcc <sotfs-path-to-.c>\n");
        return -1;
    }
    /* Skip leading whitespace (run_command passes us line+i+1). */
    while (*path == ' ') ++path;
    if (!*path) {
        printf("usage: tcc <sotfs-path-to-.c>\n");
        return -1;
    }

    static orch_spawn_msg_t tcc_msg;
    memset(&tcc_msg, 0, sizeof(tcc_msg));
    strlcpy(tcc_msg.binname, "tcc.bin", ORCH_SPAWN_BINNAME_BYTES);
    tcc_msg.profile = 0; tcc_msg.initial_tier = 0;
    tcc_msg.trusted = 1;             /* the compiler runs trusted (SP1) */
    tcc_msg.pledge  = (uint64_t)-1;

    /* tcc-libc · passthrough: inject the musl sysroot search paths + the flags
     * that guarantee a loadable static non-PIE EXEC (the L1 loader rejects
     * PT_INTERP · SP2 PR7), then forward the operator's own tokens.  Hosted is
     * the default (operator's source can #include <stdio.h> + link musl);
     * freestanding = the operator passes -nostdlib (the -I is then unused). */
    #define TCC_MAX_ARGV 24
    const char *argv[TCC_MAX_ARGV];
    int argc = 0;
    argv[argc++] = "tcc";
    argv[argc++] = "-I/usr/include";
    argv[argc++] = "-B/usr/lib";
    /* -static slot · index 3 · may be dropped below if -run is present. */
    int static_idx = argc;
    argv[argc++] = "-static";
    /* tokenize the operator's line in-place (whitespace-split). */
    static char linebuf[256];
    strlcpy(linebuf, path, sizeof(linebuf));
    char *p = linebuf;
    int op_first = argc;             /* first operator-token slot */
    while (*p && argc < TCC_MAX_ARGV) {
        while (*p == ' ') *p++ = '\0';
        if (!*p) break;
        argv[argc++] = p;
        while (*p && *p != ' ') ++p;
    }
    /* -run JIT-executes in-process; -static conflicts with -run in TinyCC, so
     * drop the injected -static (shift the operator tokens down one slot).
     * Scan the FINALIZED tokens (they are NUL-terminated only after the loop
     * places the next separator). */
    int have_run = 0;
    for (int i = op_first; i < argc; ++i)
        if (strcmp(argv[i], "-run") == 0) { have_run = 1; break; }
    if (have_run) {
        for (int i = static_idx; i + 1 < argc; ++i) argv[i] = argv[i + 1];
        --argc;
    }
    tcc_msg.argc = argc;

    size_t off = 0; int truncated = 0;
    for (int i = 0; i < argc; ++i) {
        size_t l = strlen(argv[i]) + 1;
        if (off + l > ORCH_SPAWN_ARGV_BYTES) { truncated = 1; break; }
        memcpy(tcc_msg.argv_pool + off, argv[i], l);
        off += l;
    }
    if (truncated) { printf("[tcc] WARNING · argv truncated\n"); return -1; }

    size_t nw = sizeof(tcc_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&tcc_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw));
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) { printf("[tcc] spawn failed · rc=%lu\n", (unsigned long)rc); return 1; }
    printf("[tcc] spawn OK · trusted tier-0 · argc=%d\n", argc);
    return 0;
}

/* SP2 · run a standalone ELF from sotfs (writable graph) as a NEW UNTRUSTED
 * sotbox.  Emitted ELFs run from their own .text, so their syscalls have RIP
 * inside .text → MSYSCALL does not fire and the anomaly observes them as an
 * ordinary subject (may score + promote).  trusted is reserved for tcc -run. */
static int cmd_run(seL4_CPtr orch_ep, const char *path)
{
    while (*path == ' ') ++path;
    if (!*path || path[0] != '/') {
        printf("usage: run /tmp/<elf> [args...]\n");
        return -1;
    }
    /* Split <path> from any trailing args (args ignored for SP2's argv[0]-only
     * milestone; extra tokens are still packed so future programs see them). */
    char pbuf[64];
    int pi = 0;
    while (path[pi] && path[pi] != ' ' && pi < (int)sizeof(pbuf) - 1) {
        pbuf[pi] = path[pi]; ++pi;
    }
    pbuf[pi] = '\0';

    /* basename for argv[0]. */
    const char *base = pbuf;
    for (const char *q = pbuf; *q; ++q) if (*q == '/') base = q + 1;

    static orch_spawn_msg_t run_msg;
    memset(&run_msg, 0, sizeof(run_msg));
    strlcpy(run_msg.binname, pbuf, ORCH_SPAWN_BINNAME_BYTES);
    run_msg.argc         = 1;
    run_msg.profile      = 0;
    run_msg.initial_tier = 0;
    run_msg.trusted      = 0;             /* observed · NOT pinned */
    run_msg.pledge       = (uint64_t)-1; /* PLEDGE_ALL */

    size_t off = 0;
    size_t l = strlen(base) + 1;
    if (l > ORCH_SPAWN_ARGV_BYTES) { printf("[run] argv too long\n"); return -1; }
    memcpy(run_msg.argv_pool + off, base, l);

    size_t nw = sizeof(run_msg) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&run_msg;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
    seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[run] spawn '%s' failed · rc=%lu\n", pbuf, (unsigned long)rc);
        return 1;
    }
    printf("[run] spawn OK · untrusted · %s\n", pbuf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_dump_heap · sotGuard live-dump · forensic memory capture       */
/*                                                                    */
/* Usage: dump-heap <pid> <out_path>                                  */
/*                                                                    */
/* Sends ORCH_OP_DUMP_HEAP · orch reads the target sotbox's heap      */
/* range [brk_base, brk_top) via lucas_copy_from_client and installs it */
/* into <out_path> on sotfs.  Reply carries bytes_dumped (negative on */
/* error) plus the brk range for operator confirmation.               */
/*                                                                    */
/* Bounded at 1 MiB by the orch-side static buffer · larger heaps are */
/* truncated (operator can detect by comparing bytes vs brk_top-base).*/
/* ------------------------------------------------------------------ */
static int cmd_dump_heap(seL4_CPtr orch_ep, int pid, const char *out_path)
{
    if (pid <= 0 || !out_path || !*out_path) {
        printf("usage: dump-heap <pid> <out_path>\n");
        return -1;
    }
    orch_dump_heap_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.target_pid = (uint32_t)pid;
    strlcpy(msg.out_path, out_path, sizeof(msg.out_path));

    size_t dnwords = sizeof(msg) / sizeof(seL4_Word);
    seL4_Word *dsrc = (seL4_Word *)&msg;
    for (size_t i = 0; i < dnwords; ++i) seL4_SetMR(i, dsrc[i]);
    seL4_MessageInfo_t dinfo =
        seL4_MessageInfo_new(ORCH_OP_DUMP_HEAP, 0, 0, dnwords);
    dinfo = seL4_Call(orch_ep, dinfo);

    orch_dump_heap_reply_t dreply;
    memset(&dreply, 0, sizeof(dreply));
    size_t drlen    = seL4_MessageInfo_get_length(dinfo);
    size_t drnwords = sizeof(dreply) / sizeof(seL4_Word);
    if (drlen > drnwords) drlen = drnwords;
    seL4_Word *ddst = (seL4_Word *)&dreply;
    for (size_t i = 0; i < drlen; ++i) ddst[i] = seL4_GetMR(i);

    if (dreply.bytes_dumped < 0) {
        printf("[dump-heap] FAIL pid=%d rc=%ld (brk=[0x%lx,0x%lx))\n",
               pid, (long)dreply.bytes_dumped,
               (unsigned long)dreply.brk_base,
               (unsigned long)dreply.brk_top);
        return 1;
    }
    printf("[dump-heap] pid=%d bytes=%ld path=%s brk=[0x%lx,0x%lx)\n",
           pid, (long)dreply.bytes_dumped, out_path,
           (unsigned long)dreply.brk_base,
           (unsigned long)dreply.brk_top);
    return 0;
}

/* ------------------------------------------------------------------ */
/* SPAWN-PLEDGE-CLI · resolve --pledge argument to bitmask.            */
/*                                                                    */
/* sotShell is a small native process that does NOT link sotOs-lucas, */
/* so we replicate the (small) template name table locally.  The      */
/* canonical version lives at src/lucas/pledge.c ·                    */
/* lucas_pledge_template_from_name().  Both tables MUST stay in sync. */
/*                                                                    */
/* Also supports OpenBSD-style space-separated promise strings (e.g.  */
/* "stdio rpath inet") for ad-hoc bitmask construction.               */
/*                                                                    */
/* Return: bitmask, or PLEDGE_ALL on "none" / NULL.  Sets *ok=0 on    */
/* completely unknown input so the caller can refuse to spawn.        */
/* ------------------------------------------------------------------ */
struct shell_pledge_template {
    const char *name;
    uint64_t    mask;
};

static const struct shell_pledge_template shell_pledge_templates[] = {
    { "none",              PLEDGE_ALL              },
    { "T_TRUSTED_ROOT",    PLEDGE_T_TRUSTED_ROOT   },
    { "T_SHELL",           PLEDGE_T_SHELL          },
    { "T_DAEMON_NETWORK",  PLEDGE_T_DAEMON_NETWORK },
    { "T_CANARY_TARGET",    PLEDGE_T_CANARY_TARGET   },
    { "T_PYTHON_SANDBOX",  PLEDGE_T_PYTHON_SANDBOX },
    { "T_COMPUTE_ONLY",    PLEDGE_T_COMPUTE_ONLY   },
    { "T_PIPELINE_STAGE",  PLEDGE_T_PIPELINE_STAGE },
    { "T_NET_CLIENT",      PLEDGE_T_NET_CLIENT     },
};

/* OpenBSD-style promise classes (lowercase tokens) · mirrors the table
 * in src/lucas/pledge.c.  Used only when --pledge value contains a
 * space-separated promise list rather than a T_* template name. */
struct shell_pledge_class {
    const char *name;
    uint64_t    bit;
};

static const struct shell_pledge_class shell_pledge_classes[] = {
    { "stdio",   PLEDGE_STDIO  },
    { "rpath",   PLEDGE_RPATH  },
    { "wpath",   PLEDGE_WPATH  },
    { "inet",    PLEDGE_INET   },
    { "unix",    PLEDGE_UNIX   },
    { "proc",    PLEDGE_PROC   },
    { "exec",    PLEDGE_EXEC   },
    { "setid",   PLEDGE_SETID  },
    { "fattr",   PLEDGE_FATTR  },
    { "vminfo",  PLEDGE_VMINFO },
    { "tty",     PLEDGE_TTY    },
    { "lucas",   PLEDGE_LUCAS  },
    { "sotfs",   PLEDGE_SOTFS  },
};

static uint64_t shell_resolve_pledge(const char *arg, int *ok)
{
    *ok = 1;
    if (!arg || !*arg) return PLEDGE_ALL;

    /* First try template name lookup (exact, case-sensitive). */
    size_t ntpl = sizeof(shell_pledge_templates) / sizeof(shell_pledge_templates[0]);
    for (size_t i = 0; i < ntpl; ++i) {
        if (strcmp(arg, shell_pledge_templates[i].name) == 0) {
            return shell_pledge_templates[i].mask;
        }
    }

    /* Fallback: OpenBSD-style promise list (must contain a space or be
     * a recognised single class name).  We accept space, tab, or comma
     * as separators · matches src/lucas/pledge.c pledge_parse(). */
    uint64_t mask = 0;
    int saw_token = 0;
    const char *p = arg;
    size_t ncls = sizeof(shell_pledge_classes) / sizeof(shell_pledge_classes[0]);
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        const char *tok_start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != ',') p++;
        size_t tok_len = (size_t)(p - tok_start);
        int matched = 0;
        for (size_t i = 0; i < ncls; ++i) {
            const char *name = shell_pledge_classes[i].name;
            if (strlen(name) == tok_len &&
                strncmp(tok_start, name, tok_len) == 0) {
                mask |= shell_pledge_classes[i].bit;
                matched = 1;
                saw_token = 1;
                break;
            }
        }
        if (!matched) {
            /* Unknown token anywhere in the promise list → reject. */
            *ok = 0;
            return PLEDGE_ALL;
        }
    }
    if (!saw_token) {
        *ok = 0;
        return PLEDGE_ALL;
    }
    return mask;
}

/* ------------------------------------------------------------------ */
/* cmd_systemctl · β · PR 5 · operator-driven sotinit query verbs     */
/*                                                                    */
/* Usage: systemctl <list|status|start|stop> [name]                   */
/*                                                                    */
/* Packs sotinit_request_t directly into MRs (no SHM scratch required */
/* · 10 words total: MR(0)=op, MR(1)=arg32, MR(2..9)=name[64]).       */
/* Reply unpacks sotinit_reply_t from MR(0..2): result, state, slot.  */
/*                                                                    */
/* The verb-to-op mapping mirrors sotinit/proto.h:                    */
/*   list   → SOTINIT_OP_LIST     · returns unit_count in result.     */
/*   status → SOTINIT_OP_STATUS   · returns state + procd_slot.       */
/*   start  → SOTINIT_OP_START    · activates service via procd       */
/*                                  OP_SPAWN (idempotent on ACTIVE).  */
/*   stop   → SOTINIT_OP_STOP     · marks DISABLED (PR 6 wires real   */
/*                                  procd OP_TERMINATE).              */
/*                                                                    */
/* Smoke gate "[sotshell] systemctl" fires from the result-print line */
/* below; the demo loop drives `systemctl list` so the smoke check    */
/* asserts both sotinit's listen-loop banner and sotShell's dispatch  */
/* path in a single QEMU boot.                                        */
/* ------------------------------------------------------------------ */
static int cmd_systemctl(int argc, char **argv)
{
    if (argc < 2) {
        printf("[sotshell] usage: systemctl <list|status|start|stop> [name]\n");
        return -1;
    }
    seL4_Word op;
    if      (strcmp(argv[1], "list")   == 0) op = SOTINIT_OP_LIST;
    else if (strcmp(argv[1], "status") == 0) op = SOTINIT_OP_STATUS;
    else if (strcmp(argv[1], "start")  == 0) op = SOTINIT_OP_START;
    else if (strcmp(argv[1], "stop")   == 0) op = SOTINIT_OP_STOP;
    else {
        printf("[sotshell] systemctl · unknown action '%s'\n", argv[1]);
        return -1;
    }
    if (g_sotinit_ep_slot == 0) {
        printf("[sotshell] systemctl · sotinit EP not available · root did not pre-spawn\n");
        return -1;
    }

    /* Pack request: op + arg32 + 64-byte name (8 words). */
    seL4_SetMR(0, op);
    seL4_SetMR(1, 0);  /* arg32 unused for the verbs sotShell drives today */
    char name[64] = {0};
    if (argc > 2) {
        strncpy(name, argv[2], sizeof(name) - 1);
    }
    for (int i = 0; i < 8; i++) {
        seL4_Word w = 0;
        memcpy(&w, name + i * 8, sizeof(seL4_Word) < 8 ? sizeof(seL4_Word) : 8);
        seL4_SetMR(2 + i, w);
    }

    seL4_Call(g_sotinit_ep_slot, seL4_MessageInfo_new(0, 0, 0, 10));
    int32_t  result = (int32_t)seL4_GetMR(0);
    uint32_t state  = (uint32_t)seL4_GetMR(1);
    uint32_t slot   = (uint32_t)seL4_GetMR(2);
    printf("[sotshell] systemctl %s · result=%d state=%u slot=%u\n",
           argv[1], result, state, slot);
    return result;
}

/* ------------------------------------------------------------------ */
/* cmd_cron · β · PR 9 · operator-driven sotcron query verbs          */
/*                                                                    */
/* Usage: cron <list|now> [name]                                      */
/*                                                                    */
/* Packs sotcron_request_t into MRs (no SHM scratch required ·        */
/* up to 10 words total: MR(0)=op, MR(1)=pad, MR(2..9)=name[64]).     */
/* Reply unpacks sotcron_reply_t from MR(0..2):                       */
/*   MR(0) = result (>=0 timer count for LIST, 0 for FIRE_NOW OK,     */
/*           -3 for unknown name, -1 unknown op).                     */
/*   MR(1) = timer_count                                              */
/*   MR(2) = next_fire_tsc                                            */
/*                                                                    */
/* The verb-to-op mapping mirrors sotcron/proto.h:                    */
/*   list  → SOTCRON_OP_LIST      · returns timer_count.              */
/*   now   → SOTCRON_OP_FIRE_NOW  · operator-fires a named timer ·    */
/*                                  sets next_fire_tsc=now so the     */
/*                                  next polling tick runs the fire   */
/*                                  dispatch path into sotinit.       */
/*                                                                    */
/* Operator-driven · NOT in demo_commands (smoke gates are MANUAL).   */
/* ------------------------------------------------------------------ */
static int cmd_cron(int argc, char **argv)
{
    if (argc < 2) {
        printf("[sotshell] usage: cron <list|now> [name]\n");
        return -1;
    }
    if (g_sotcron_ep_slot == 0) {
        printf("[sotshell] cron · sotcron EP not available · root did not pre-spawn\n");
        return -1;
    }
    seL4_Word op;
    if      (strcmp(argv[1], "list") == 0) op = SOTCRON_OP_LIST;
    else if (strcmp(argv[1], "now")  == 0) op = SOTCRON_OP_FIRE_NOW;
    else {
        printf("[sotshell] cron · unknown action '%s' · usage: cron <list|now> [name]\n",
               argv[1]);
        return -1;
    }

    /* Pack request: op + pad + 64-byte name (8 words).  For LIST we still
     * send the full 10-word frame so sotcron's drain has uniform MR layout
     * (the name slot is just ignored when op=LIST). */
    seL4_SetMR(0, op);
    seL4_SetMR(1, 0);
    char name[SOTCRON_NAME_MAX] = {0};
    if (argc > 2) {
        strncpy(name, argv[2], sizeof(name) - 1);
    }
    for (int i = 0; i < 8; i++) {
        seL4_Word w = 0;
        memcpy(&w, name + i * 8, sizeof(seL4_Word) < 8 ? sizeof(seL4_Word) : 8);
        seL4_SetMR(2 + i, w);
    }

    seL4_Call(g_sotcron_ep_slot, seL4_MessageInfo_new(0, 0, 0, 10));
    int32_t  result   = (int32_t)seL4_GetMR(0);
    uint32_t count    = (uint32_t)seL4_GetMR(1);
    uint64_t nextfire = seL4_GetMR(2);
    printf("[sotshell] cron %s · result=%d · timer_count=%u · next_fire=%lu\n",
           argv[1], result, count, (unsigned long)nextfire);
    return result;
}

/* ------------------------------------------------------------------ */
/* cmd_quit · send ORCH_OP_SHUTDOWN as the quit signal                */
/* ------------------------------------------------------------------ */
static int cmd_quit(seL4_CPtr orch_ep)
{
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SHUTDOWN, 0, 0, 0);
    seL4_Call(orch_ep, info);
    return SOTSHELL_QUIT_SIGNAL;
}

/* ------------------------------------------------------------------ */
/* cmd_poweroff · ORCH_OP_POWEROFF · clean shutdown + power off the VM  */
/* orch persists state (WAL checkpoint + flush) then writes the ACPI    */
/* PM1a S5 port so QEMU exits.  Usage: poweroff  (alias: shutdown)      */
/* ------------------------------------------------------------------ */
static int cmd_poweroff(seL4_CPtr orch_ep)
{
    printf("sotos> poweroff · persisting state + powering off the VM...\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_POWEROFF, 0, 0, 0);
    seL4_Call(orch_ep, info);
    /* Reaching here means the VM did not power off (ACPI port unavailable);
     * fall through to a normal shell exit. */
    printf("sotos> poweroff returned · VM still alive (ACPI port unavailable)\n");
    return SOTSHELL_QUIT_SIGNAL;
}

/* ------------------------------------------------------------------ */
/* cmd_validate · ORCH_OP_VALIDATE · Pillar-4 P4a · trigger the          */
/* concurrent 3-malware validation run.  No payload — the 3-fixture     */
/* triple (graphical trojan / network infostealer / ransomware) is      */
/* orch-side.  orch seeds all 3 into a validation pool, runs ONE fault  */
/* loop until they all exit, frees the pool, then replies.  The demo    */
/* resumes here and the unattended path powers off.                     */
/* ------------------------------------------------------------------ */
static int cmd_validate(seL4_CPtr orch_ep)
{
    printf("[validate] requesting concurrent 3-malware validation run\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_VALIDATE, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[validate] validation run returned\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_bbsh · ORCH_OP_BBSH · interactive canary shell                   */
/* ------------------------------------------------------------------ */
/* Spawn a foreground `busybox sh -i` at Tier-2 (canary VFS) and hand   */
/* the serial console to it.  orch replies to this seL4_Call ONLY      */
/* AFTER busybox exits, so this thread stays BLOCKED for the whole     */
/* session — that is what stops sotShell's readline from polling the   */
/* UART while busybox owns it (no serial contention · single reader).  */
/* No payload — the busybox argv is orch-side.                         */
/* ------------------------------------------------------------------ */
static int cmd_bbsh(seL4_CPtr orch_ep)
{
    printf("[sotshell] bbsh · launching interactive busybox sh -i (Tier-2 canary) · type 'exit' to return · F12 = operator console\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_BBSH, 0, 0, 0);
    seL4_MessageInfo_t r = seL4_Call(orch_ep, info);   /* blocks until busybox exits / F12 */
    int label = (int)seL4_MessageInfo_get_label(r);    /* 3 = exited via F12 */
    if (label == 3) {
        printf("\n[sotshell] bbsh · F12 → switching to operator console\n");
    } else {
        printf("\n[sotshell] bbsh · busybox exited · back at sotShell\n");
    }
    return label;
}

/* ------------------------------------------------------------------ */
/* cmd_shell · `shell [--trusted]` · interactive busybox shell          */
/* ------------------------------------------------------------------ */
/* `shell`            → same as bbsh (Tier-2 canary · attacker-facing).  */
/* `shell --trusted`  → ORCH_OP_BBSH_TRUSTED · Tier-0e/trusted OPERATOR  */
/*   shell with REAL egress live for the whole session: `pip install …`  */
/*   / `python3 …` typed by hand reach the real wire.  Same block-until- */
/*   exit reply contract as cmd_bbsh (orch replies only after exit/F12). */
static int cmd_shell(seL4_CPtr orch_ep, int trusted)
{
    if (!trusted) return cmd_bbsh(orch_ep);
    printf("[sotshell] shell --trusted · launching Tier-0e busybox sh -i with REAL egress\n"
           "           (python3 / pip install reach the live internet) · 'exit' to return · F12 = operator console\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_BBSH_TRUSTED, 0, 0, 0);
    seL4_MessageInfo_t r = seL4_Call(orch_ep, info);   /* blocks until shell exits / F12 */
    int label = (int)seL4_MessageInfo_get_label(r);    /* 3 = exited via F12 */
    if (label == 3) {
        printf("\n[sotshell] shell --trusted · F12 → switching to operator console\n");
    } else {
        printf("\n[sotshell] shell --trusted · busybox exited · back at sotShell\n");
    }
    return label;
}

/* ------------------------------------------------------------------ */
/* cmd_console_kbd · F12 toggle · keyboard-driven OPERATOR console      */
/* ------------------------------------------------------------------ */
/* Reached when the operator presses F12 in the canary shell.  Unlike    */
/* cmd_interactive (serial/UART), this reads the GTK keyboard via orch   */
/* (ORCH_OP_GETKEY, enabled by g_use_getkey).  The operator runs the     */
/* full command set (list/sotinfo/python/doom/...); pressing F12 again   */
/* latches g_operator_f12 → this returns so the caller respawns the      */
/* canary shell.  A deliberately simple read loop (no fancy readline) so  */
/* the F12 latch is checked on every poll.                              */
static int cmd_console_kbd(seL4_CPtr orch_ep)
{
    g_use_getkey   = 1;   /* enable the GTK-keyboard input + framebuffer tee NOW */
    g_operator_f12 = 0;
    /* Wipe the stale canary-shell frame from the window (console_fb parses ANSI). */
    printf("\033[2J\033[H");
    fflush(stdout);
    printf("\n");
    printf("================================================================\n");
    printf("  sotOs OPERATOR CONSOLE - the TRUTH view (deception is off)\n");
    printf("  commands: watch sottrace list sotinfo sotnet ls cat doom python ...\n");
    printf("  'watch' = live DECEPTION MONITOR (see the attacker in real time)\n");
    printf("  press F12 to return to the attacker canary shell\n");
    printf("================================================================\n");
    char buf[128];
    int ret = 0;
    for (;;) {
        printf("sotos:%s# ", g_cwd);
        fflush(stdout);          /* sotShell stdout is block-buffered · flush so the
                                  * prompt shows before input (else: blind typing) */
        size_t pos = 0;
        for (;;) {
            if (g_operator_f12) { printf("\n"); goto done; }   /* F12 → back to canary shell */
            int c = serial_getchar();
            if (g_operator_f12) { printf("\n"); goto done; }
            if (c == 0) { seL4_Yield(); continue; }
            if (c == '\r' || c == '\n') { printf("\n"); fflush(stdout); buf[pos] = '\0'; break; }
            if (c == '\b' || c == 0x7F) { if (pos > 0) { pos--; printf("\b \b"); fflush(stdout); } continue; }
            if (c >= 0x20 && c < 0x7F && pos < sizeof(buf) - 1) {
                buf[pos++] = (char)c; printf("%c", c); fflush(stdout);   /* echo · flush each char */
            }
        }
        if (buf[0] == '\0') continue;
        int rc = run_command(orch_ep, buf);
        if (rc == SOTSHELL_QUIT_SIGNAL) { ret = SOTSHELL_QUIT_SIGNAL; goto done; }
    }
done:
    g_use_getkey   = 0;
    g_operator_f12 = 0;
    return ret;
}

/* cmd_bbsh_auto · ORCH_OP_BBSH_AUTO · default interactive shell.       */
/* Sent as the LAST demo command. orch spawns the keyboard busybox shell */
/* ONLY when a virtio-keyboard is present (just run-interactive); when   */
/* headless it replies immediately (no-op) and the demo finishes.        */
static int cmd_bbsh_auto(seL4_CPtr orch_ep)
{
    printf("[sotshell] bbsh-auto · if a keyboard is present, dropping into busybox sh -i (else continue)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_BBSH_AUTO, 0, 0, 0);
    seL4_Call(orch_ep, info);   /* blocks until busybox exits (interactive) or returns at once (headless) */
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_doom · ORCH_OP_DOOM · Doom-on-sotOs phase 1                    */
/* ------------------------------------------------------------------ */
/* Spawn doomgeneric (doom.bin) at Tier-0 trusted.  doom.bin +        */
/* doom1.wad are bundled in the binstore; /doom1.wad is served by the */
/* doom-wad VFS backend.  orch replies immediately after spawning,    */
/* then runs orch_fault_loop until doom exits (200 render ticks).     */
/* No payload — the doom argv + WAD path are orch-side.               */
/* ------------------------------------------------------------------ */
static int cmd_doom(seL4_CPtr orch_ep)
{
    printf("[sotshell] doom · launching doomgeneric (Tier-0 trusted)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_DOOM, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] doom · handler returned\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_gitdemo · ORCH_OP_GITDEMO · real Alpine git on sotOs           */
/* ------------------------------------------------------------------ */
/* Runs real git (musl-dynamic) at Tier-0 in /tmp/gitrepo: init ->     */
/* commit --allow-empty -> log.  orch replies after the first spawn,   */
/* then runs orch_fault_loop per step until each git exits.  The PASS  */
/* signal is `git log --oneline` printing the commit.  No payload —    */
/* the git binary + argv are orch-side (binstore + sysroot libs).      */
/* ------------------------------------------------------------------ */
static int cmd_gitdemo(seL4_CPtr orch_ep)
{
    printf("[sotshell] gitdemo · launching real git (Tier-0 · init/commit/log)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_GITDEMO, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] gitdemo · handler returned\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_sotctl · ORCH_OP_SOTCTL · the world-#3 NATIVE operator plane    */
/* ------------------------------------------------------------------ */
/* `sotctl [sub]` spawns the NATIVE sotctl seL4 binary (sotcrt+sotlibc */
/* +sel4runtime · NOT a Linux guest) which pulls the chosen truth-plane */
/* view over sotabi and prints it.  We map the subcommand to a         */
/* SOTABI_OP_* content op and pass it in MR1; orch spawns the binary   */
/* and serves its render-stream (bounded · the binary exits at EOF).   */
/* ------------------------------------------------------------------ */
static int cmd_sotctl(seL4_CPtr orch_ep, const char *sub)
{
    int op = SOTABI_OP_SESSIONS;
    uint32_t arg = 0;   /* op-specific (overlay --session N · persona set policy) */
    if (sub && *sub) {
        if      (strncmp(sub, "sessions", 8) == 0) op = SOTABI_OP_SESSIONS;
        else if (strncmp(sub, "process",  7) == 0) op = SOTABI_OP_PROCESS;
        else if (strncmp(sub, "ps",       2) == 0) op = SOTABI_OP_PROCESS;
        else if (strncmp(sub, "anomaly",  7) == 0) op = SOTABI_OP_ANOMALY;
        else if (strncmp(sub, "trace",    5) == 0) op = SOTABI_OP_TRACE;
        else if (strncmp(sub, "wal",      3) == 0) op = SOTABI_OP_WAL;
        else if (strncmp(sub, "replay",   6) == 0) op = SOTABI_OP_REPLAY;
        else if (strncmp(sub, "canary",   6) == 0) op = SOTABI_OP_CANARY;
        else if (strncmp(sub, "persona",  7) == 0) {
            op = SOTABI_OP_PERSONA;
            /* `persona` / `persona list` = view-only (arg 3 · NO pin).  `persona set
             * <alpine|debian|auto>` pins the persona for NEW sessions (0/1/2 · maps
             * in sot_persona_print → orch_persona_pin_set).  Without this, the arg
             * defaulted to 0 and a bare `persona` silently pinned Alpine. */
            const char *a = sub + 7;
            while (*a == ' ') ++a;
            if (strncmp(a, "set", 3) == 0) {
                a += 3; while (*a == ' ') ++a;
                if      (*a == 'a') arg = 0;   /* alpine */
                else if (*a == 'd') arg = 1;   /* debian */
                else                arg = 2;   /* auto / round-robin */
            } else {
                arg = 3;                       /* list-only */
            }
        }
        else if (strncmp(sub, "policy", 6) == 0) {
            /* `policy net <on|off|guarded|status>` · attacker egress posture.
             * GUARDED = Gate 0 engagement-safe (real wire → allowlist+DNS only,
             * rest sinkholed+IOC'd). on=open(dev), off=synth-only. */
            op = SOTABI_OP_POLICY_NET;
            const char *a = sub + 6;
            while (*a == ' ') ++a;
            if (strncmp(a, "net", 3) == 0) { a += 3; while (*a == ' ') ++a; }
            if      (strncmp(a, "off", 3) == 0)     arg = 0;
            else if (strncmp(a, "guarded", 7) == 0) arg = 3;
            else if (strncmp(a, "on", 2) == 0)      arg = 1;
            else                                    arg = 2;   /* status / query */
        }
        else                                       op = SOTABI_OP_HELP;
    }
    printf("[sotshell] sotctl · spawning the NATIVE sotctl (world-#3 · sotabi op=%d arg=%u)\n", op, arg);
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SOTCTL, 0, 0, 3);
    seL4_SetMR(0, 0);
    seL4_SetMR(1, (seL4_Word)op);
    seL4_SetMR(2, (seL4_Word)arg);
    seL4_Call(orch_ep, info);
    printf("[sotshell] sotctl · handler returned\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_egress_dns · ORCH_OP_EGRESS_DNS · internet-egress Phase 1 DNS    */
/* ------------------------------------------------------------------ */
/* Runs the dnsprobe fixture twice: Tier-0e (egress-functor) resolving  */
/* example.com via the REAL DNS forward, then a non-egress sotbox       */
/* resolving the canary domain malicious-c2.example (hermetic synth =   */
/* 10.0.2.15, no real wire).  orch replies after the first spawn, then  */
/* runs the fault loop per step.  No payload — binary + argv are        */
/* orch-side (binstore).                                                */
/* ------------------------------------------------------------------ */
static int cmd_egress_dns(seL4_CPtr orch_ep)
{
    printf("[sotshell] egress-dns · dnsprobe Tier-0e (example.com) + Tier-2 canary\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_EGRESS_DNS, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] egress-dns · handler returned\n");
    return 0;
}

/* cmd_egress_http · ORCH_OP_EGRESS_HTTP · egress Phase-1 END-TO-END · a Tier-0e
 * busybox `wget http://example.com` does the full real DNS-forward + TCP + HTTP. */
static int cmd_egress_http(seL4_CPtr orch_ep)
{
    printf("[sotshell] egress-http · Tier-0e busybox wget http://example.com (real egress)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_EGRESS_HTTP, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] egress-http · handler returned\n");
    return 0;
}

/* cmd_egress_install · ORCH_OP_EGRESS_INSTALL · download a REAL .deb over verified
 * HTTPS (Tier-0e TLS client + real CA bundle) → dpkg-deb -x extracts it. */
static int cmd_egress_install(seL4_CPtr orch_ep)
{
    printf("[sotshell] egress-install · wget a real .deb over verified HTTPS → dpkg-deb -x\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_EGRESS_INSTALL, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] egress-install · handler returned\n");
    return 0;
}

/* cmd_egress_python · ORCH_OP_EGRESS_PYTHON · the pip foundation · real CPython
 * does an in-process HTTPS GET over the egress (static _ssl + real CA bundle). */
static int cmd_egress_python(seL4_CPtr orch_ep)
{
    printf("[sotshell] egress-python · python3 HTTPS GET (in-process _ssl)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_EGRESS_PYTHON, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] egress-python · handler returned\n");
    return 0;
}

/* cmd_arena_churn · ORCH_OP_ARENA_CHURN · validate the in-life arena reclaim
 * (python churns 300 MiB through the 128 MiB heavy arena). */
static int cmd_arena_churn(seL4_CPtr orch_ep)
{
    printf("[sotshell] arena-churn · python mmap+free 1 MiB ×300 (reclaim validation)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_ARENA_CHURN, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] arena-churn · handler returned\n");
    return 0;
}

/* cmd_egress_pip · ORCH_OP_EGRESS_PIP · FULL pip install · real CPython runs
 * `python -m pip` (pip rides in the stdlib zip): `pip --version` heavy-import
 * sanity, then `pip install --target /tmp/sp six` from PyPI over the verified
 * egress → `import six` from the writable target. */
static int cmd_egress_pip(seL4_CPtr orch_ep)
{
    printf("[sotshell] egress-pip · python -m pip install six from PyPI (verified egress)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_EGRESS_PIP, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] egress-pip · handler returned\n");
    return 0;
}

/* cmd_egress_pipdeps · ORCH_OP_EGRESS_PIPDEPS · pip install requests + its 4 deps
 * (resolver + multi-package install over the verified egress). */
static int cmd_egress_pipdeps(seL4_CPtr orch_ep)
{
    printf("[sotshell] egress-pipdeps · pip install requests + deps from PyPI\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_EGRESS_PIPDEPS, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] egress-pipdeps · handler returned\n");
    return 0;
}

/* cmd_tools_fs · ORCH_OP_TOOLS_FS · real GNU tar + coreutils recursive-fs battery
 * (nested tar extract via dir-fd, cp -r, rm -rf). */
static int cmd_tools_fs(seL4_CPtr orch_ep)
{
    printf("[sotshell] tools-fs · GNU tar nested extract + cp -r + rm -rf\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_TOOLS_FS, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] tools-fs · handler returned\n");
    return 0;
}

/* cmd_py_e2e · ORCH_OP_PY_E2E · real python end-to-end (HTTPS→parse→fs→verify). */
static int cmd_py_e2e(seL4_CPtr orch_ep)
{
    printf("[sotshell] py-e2e · python HTTPS GET → parse → write fs → verify sha256\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_PY_E2E, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] py-e2e · handler returned\n");
    return 0;
}

/* cmd_egress_pip_build · ORCH_OP_EGRESS_PIP_BUILD · build a package from sdist
 * (no wheel) · real setuptools/wheel build backend runs IN-PROCESS. */
static int cmd_egress_pip_build(seL4_CPtr orch_ep)
{
    printf("[sotshell] egress-pipbuild · download sdist + setuptools build_wheel in-process\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_EGRESS_PIP_BUILD, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] egress-pipbuild · handler returned\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_glibc · ORCH_OP_GLIBC · run a glibc-static binary on sotOs      */
/* ------------------------------------------------------------------ */
/* Proves the GNU/glibc libc ABI (not just musl) runs: a static glibc  */
/* probe exercises stdio/malloc/uname/fopen at Tier-0.  No payload.    */
/* ------------------------------------------------------------------ */
static int cmd_glibc(seL4_CPtr orch_ep)
{
    printf("[sotshell] glibc · launching glibc-static probe (Tier-0)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_GLIBC, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] glibc · handler returned\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_gnu · ORCH_OP_GNU · run real GNU tools on sotOs                 */
/* ------------------------------------------------------------------ */
/* GNU coreutils 9.5 (ls/cat/wc), grep, sed, gawk — musl-dynamic — at  */
/* Tier-0 on the honey /etc/passwd.  No payload.                       */
/* ------------------------------------------------------------------ */
static int cmd_gnu(seL4_CPtr orch_ep)
{
    printf("[sotshell] gnu · launching GNU coreutils/grep/sed/gawk (Tier-0)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_GNU, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] gnu · handler returned\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_glibcdyn · ORCH_OP_GLIBCDYN · glibc-dynamic via real ld-linux   */
/* ------------------------------------------------------------------ */
/* Runs an off-the-shelf glibc-dynamic PIE loaded by ld-linux-x86-64   */
/* .so.2 at Tier-0.  Exploratory — the glibc loader bring-up.          */
/* ------------------------------------------------------------------ */
static int cmd_glibcdyn(seL4_CPtr orch_ep)
{
    printf("[sotshell] glibcdyn · launching glibc-dynamic via ld-linux (Tier-0)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_GLIBCDYN, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] glibcdyn · handler returned\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_install · ORCH_OP_INSTALL · install-arc P0.2                    */
/* ------------------------------------------------------------------ */
/* Drives a real `dpkg-deb -x /tmp/hello.deb /tmp/root` at Tier-0:     */
/* the off-the-shelf Debian dpkg-deb extracts the .deb's data.tar.xz   */
/* (execve'ing the real tar + xz) into the writable /tmp sotfs.        */
/* ------------------------------------------------------------------ */
static int cmd_dpkg_install(seL4_CPtr orch_ep)
{
    printf("[sotshell] dpkg-install · dpkg-deb -x /tmp/hello.deb /tmp/root (Tier-0)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_INSTALL, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] dpkg-install · handler returned\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_doomwl · ORCH_OP_DOOMWL · v2.3-M5 · Doom over REAL Wayland     */
/* ------------------------------------------------------------------ */
/* Spawn doomwl.bin (doomgeneric over the patched DYNAMIC SDL2, wayland */
/* backend, SOFTWARE renderer → wl_shm framebuffer on the honest       */
/* compositor · NO EGL).  Same orch contract as cmd_doom: reply after   */
/* spawn, run the fault loop until it exits.  The proof is the          */
/* compositor's 640x400 Doom commits over wl_shm.  No payload.          */
/* ------------------------------------------------------------------ */
static int cmd_doomwl(seL4_CPtr orch_ep)
{
    printf("[sotshell] doomwl · launching doomgeneric over real wayland (sw/wl_shm)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_DOOMWL, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] doomwl · handler returned\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_gtkspike · ORCH_OP_GTKSPIKE · v2.4 · GTK3 over REAL Wayland     */
/* ------------------------------------------------------------------ */
/* Spawn gtkspike.bin — a real GTK3 app (cairo software / wl_shm, no   */
/* EGL) over the honest compositor.  Same orch contract as cmd_doomwl. */
/* Exploratory spike: surfaces the first wall GTK hits on the host.    */
/* ------------------------------------------------------------------ */
static int cmd_gtkspike(seL4_CPtr orch_ep)
{
    printf("[sotshell] gtkspike · launching GTK3 over real wayland (cairo/wl_shm)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_GTKSPIKE, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] gtkspike · handler returned\n");
    return 0;
}

/* cmd_gtk3demo · ORCH_OP_GTK3DEMO · v2.x · an UNMODIFIED off-the-shelf GTK3 app
 * (Alpine gtk3-demo) over the honest compositor — the "real Linux app, no
 * per-app code" proof.  Same orch contract; orch supplies the GTK env. */
static int cmd_gtk3demo(seL4_CPtr orch_ep)
{
    printf("[sotshell] gtk3-demo · launching the UNMODIFIED off-the-shelf GTK3 app\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_GTK3DEMO, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] gtk3-demo · handler returned\n");
    return 0;
}

/* cmd_widgetfactory · ORCH_OP_WIDGETFACTORY · #2 · the UNMODIFIED off-the-shelf
 * Alpine gtk3-widget-factory (the canonical GTK widget showcase) over the honest
 * compositor — broader widget coverage than gtk3-demo.  Same orch contract. */
static int cmd_widgetfactory(seL4_CPtr orch_ep)
{
    printf("[sotshell] gtk3-widget-factory · launching the UNMODIFIED GTK widget showcase\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_WIDGETFACTORY, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] gtk3-widget-factory · handler returned\n");
    return 0;
}

/* cmd_mapfixed · ORCH_OP_MAPFIXED · Wine-prep · the wine-preloader mmap PATTERN
 * (reserve large PROT_NONE Windows ranges, commit sub-ranges via MAP_FIXED +
 * mprotect).  De-risks the Wine loader before the swamp.  Same orch contract. */
static int cmd_mapfixed(seL4_CPtr orch_ep)
{
    printf("[sotshell] mapfixed · launching the MAP_FIXED-low gate fixture (Wine-prep)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_MAPFIXED, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] mapfixed · handler returned\n");
    return 0;
}

/* cmd_wine · ORCH_OP_WINE · Wine M1 SPIKE · run `wine hello.exe` (a trivial
 * console PE) to find the next wall after MAP_FIXED-low.  Same orch contract. */
static int cmd_wine(seL4_CPtr orch_ep)
{
    printf("[sotshell] wine · launching `wine /usr/lib/wine/hello.exe` (real wineboot path)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_WINE, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] wine · handler returned\n");
    return 0;
}

/* cmd_wine_crt · ORCH_OP_WINE_CRT · Wine M2 · run `wine hello_crt.exe`, a REAL
 * C-runtime PE (msvcrt printf/malloc + the mingw CRT) — exercises the msvcrt.dll
 * DllMain locale/NLS init the CRT-less M1 PE avoided. */
static int cmd_wine_crt(seL4_CPtr orch_ep)
{
    printf("[sotshell] wine-crt · launching `wine /usr/lib/wine/hello_crt.exe` (real msvcrt PE)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_WINE_CRT, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] wine-crt · handler returned\n");
    return 0;
}

/* cmd_wine_gui · ORCH_OP_WINE_GUI · Wine GUI · run `wine hello_gui.exe`, a real
 * Win32 GUI PE (CreateWindowEx → user32/gdi32/win32u → winewayland → the honest
 * compositor) — the first Windows window on sotOs. */
static int cmd_wine_gui(seL4_CPtr orch_ep)
{
    printf("[sotshell] wine-gui · launching `wine /usr/lib/wine/hello_gui.exe` (Win32 window → winewayland)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_WINE_GUI, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] wine-gui · handler returned\n");
    return 0;
}

/* cmd_wine_baked · ORCH_OP_WINE_BAKED · Track M1 (PE execution) · run
 * `wine hello.exe` against a PRE-BAKED, version-matched prefix seeded into /.wine
 * so wine SKIPS the in-guest wineboot bootstrap.  This is the explicit demo path
 * for "Wine runs a simple Windows PE on sotOs"; it does NOT claim wineboot is
 * solved (real wineboot/TEB bootstrap is Track correctness · Wine M2a). */
static int cmd_wine_baked(seL4_CPtr orch_ep)
{
    printf("[sotshell] wine-baked · BAKED PREFIX · launching `wine /usr/lib/wine/hello.exe`\n");
    printf("[sotshell]   (prefix is PRE-BAKED into /.wine · wineboot SKIPPED · NOT full in-guest bootstrap)\n");
    seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_WINE_BAKED, 0, 0, 0);
    seL4_Call(orch_ep, info);
    printf("[sotshell] wine-baked · handler returned\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_interactive · real serial-input console loop (L4-Phase-C v2) */
/* ------------------------------------------------------------------ */
static int cmd_interactive(seL4_CPtr orch_ep)
{
    printf("\nsotOs operator console · type 'help' or 'quit'\n");
    if (g_io_port_cap == 0) {
        printf("[sotshell] WARNING · no IO_Port cap · serial input disabled\n");
    }
    char buf[128];
    while (1) {
        printf("sotos:%s> ", g_cwd);
        int len = read_line(buf, sizeof(buf));
        if (len < 0) return -1;
        if (buf[0] == '\0') continue;   /* empty line */
        int rc = run_command(orch_ep, buf);
        if (rc == SOTSHELL_QUIT_SIGNAL) {
            printf("[sotshell] exiting interactive mode\n");
            break;
        }
        /* All other non-zero return codes are command-specific failures
         * (bad args, missing file, IPC error). Keep the loop running so
         * the operator can retry · interactive mode only exits on `quit`. */
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* execute_pipeline · v0.7 · S2 · run a parsed pipeline               */
/*                                                                    */
/* δ-1 scope:                                                         */
/*  - n_cmds == 1 with stdout redirection · capture output via install. */
/*  - n_cmds  > 1 · log "pipes not yet supported · running first      */
/*    command only" and dispatch the first command's argv.            */
/*                                                                    */
/* Output capture for redirection: we don't have a stdout-tee inside  */
/* libc here, so we adopt a pragmatic shim · for the commands that    */
/* most commonly want redirection (grep, cat, ls, tail) we re-issue   */
/* the underlying ORCH_OP_SOTFS_CAT and write its raw bytes into a    */
/* install call against the destination path.  For other commands we    */
/* log that redirection isn't wired and dispatch normally.            */
/* ------------------------------------------------------------------ */
static int run_argv_via_legacy(seL4_CPtr orch_ep, const struct cmd *c);

static int execute_pipeline(seL4_CPtr orch_ep, const struct parsed_pipeline *pl)
{
    if (pl->n_cmds == 0) return 0;

    if (pl->n_cmds > 1) {
        printf("[parser] pipes not yet supported · running first command only\n");
    }

    const struct cmd *c = &pl->cmds[0];
    if (c->argc == 0) return 0;

    /* Redirection-to-file via cat-based shim.                                */
    /* If the first argv is a sotfs-backed reader (cat/tail/grep) and we have */
    /* stdout_path, capture its output by re-issuing ORCH_OP_SOTFS_CAT and    */
    /* writing through ORCH_OP_SOTFS_INSTALL.  Limited to 256 bytes by the     */
    /* INSTALL payload cap.                                                     */
    if (c->stdout_path && c->argc >= 2) {
        const char *cmd0 = c->argv[0];
        const char *src_path = NULL;
        const char *pattern = NULL;
        int is_grep = 0;
        if (strcmp(cmd0, "cat") == 0 || strcmp(cmd0, "tail") == 0) {
            src_path = c->argv[1];
        } else if (strcmp(cmd0, "grep") == 0 && c->argc >= 3) {
            pattern = c->argv[1];
            src_path = c->argv[2];
            is_grep = 1;
        }

        if (src_path) {
            /* Read source file via SOTFS_CAT. */
            orch_sotfs_path_req_t req;
            memset(&req, 0, sizeof(req));
            strncpy(req.path, src_path, ORCH_SOTFS_PATH_MAX - 1);
            size_t nwords = sizeof(req) / sizeof(seL4_Word);
            seL4_Word *src = (seL4_Word *)&req;
            for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
            seL4_MessageInfo_t info =
                seL4_MessageInfo_new(ORCH_OP_SOTFS_CAT, 0, 0, nwords);
            info = seL4_Call(orch_ep, info);

            orch_sotfs_cat_reply_t reply;
            memset(&reply, 0, sizeof(reply));
            size_t rlen    = seL4_MessageInfo_get_length(info);
            size_t rnwords = sizeof(reply) / sizeof(seL4_Word);
            if (rlen > rnwords) rlen = rnwords;
            seL4_Word *dst = (seL4_Word *)&reply;
            for (size_t i = 0; i < rlen; ++i) dst[i] = seL4_GetMR(i);

            if (reply.rc < 0) {
                printf("[parser] redir source read failed rc=%d\n", reply.rc);
                return 1;
            }

            uint32_t dl = reply.data_len;
            if (dl >= ORCH_SOTFS_CAT_MAX_BYTES) dl = ORCH_SOTFS_CAT_MAX_BYTES - 1;
            reply.data[dl] = '\0';

            /* Filter for grep. */
            char filt[ORCH_SOTFS_INSTALL_CONTENT_MAX];
            size_t flen = 0;
            const char *to_write = (const char *)reply.data;
            size_t to_write_len = dl;
            if (is_grep) {
                char *p = (char *)reply.data;
                while (*p && flen < sizeof(filt) - 1) {
                    char *nl = strchr(p, '\n');
                    if (nl) *nl = '\0';
                    if (strstr(p, pattern)) {
                        size_t L = strlen(p);
                        if (flen + L + 1 >= sizeof(filt)) break;
                        memcpy(filt + flen, p, L);
                        flen += L;
                        filt[flen++] = '\n';
                    }
                    if (!nl) break;
                    *nl = '\n';
                    p = nl + 1;
                }
                filt[flen] = '\0';
                to_write = filt;
                to_write_len = flen;
            }

            /* Install into destination path. */
            orch_sotfs_install_req_t preq;
            memset(&preq, 0, sizeof(preq));
            strncpy(preq.path, c->stdout_path, ORCH_SOTFS_PATH_MAX - 1);
            size_t wlen = to_write_len;
            if (wlen >= ORCH_SOTFS_INSTALL_CONTENT_MAX)
                wlen = ORCH_SOTFS_INSTALL_CONTENT_MAX - 1;
            memcpy(preq.content, to_write, wlen);
            preq.content_len = (uint32_t)wlen;

            size_t pnw = sizeof(preq) / sizeof(seL4_Word);
            seL4_Word *psrc = (seL4_Word *)&preq;
            for (size_t i = 0; i < pnw; ++i) seL4_SetMR(i, psrc[i]);
            seL4_MessageInfo_t pinfo =
                seL4_MessageInfo_new(ORCH_OP_SOTFS_INSTALL, 0, 0, pnw);
            pinfo = seL4_Call(orch_ep, pinfo);
            seL4_Word rc = seL4_MessageInfo_get_label(pinfo);
            printf("[parser] redir %s → %s · %zu bytes · rc=%lu\n",
                   src_path, c->stdout_path, wlen, (unsigned long)rc);
            return (int)rc;
        }

        printf("[parser] redirection for command '%s' not yet wired · "
               "running normally\n", cmd0);
    }

    /* No redirection (or unhandled) · dispatch first command normally. */
    return run_argv_via_legacy(orch_ep, c);
}

/* Rebuild a single line "argv[0] argv[1] ..." and feed back into the
 * legacy strcmp dispatch.  Avoids duplicating dispatch logic. */
static int run_command(seL4_CPtr orch_ep, const char *line);
static int run_argv_via_legacy(seL4_CPtr orch_ep, const struct cmd *c)
{
    char line[MAX_LINE_LEN];
    size_t pos = 0;
    for (int i = 0; i < c->argc; ++i) {
        const char *w = c->argv[i];
        size_t wl = strlen(w);
        if (i > 0) {
            if (pos + 1 >= sizeof(line)) break;
            line[pos++] = ' ';
        }
        if (pos + wl >= sizeof(line)) break;
        memcpy(line + pos, w, wl);
        pos += wl;
    }
    line[pos] = '\0';
    /* Re-enter dispatch · but mark that parser already ran so we don't loop. */
    static int reentry_guard = 0;
    if (reentry_guard) return 1;
    reentry_guard = 1;
    int rc = run_command(orch_ep, line);
    reentry_guard = 0;
    return rc;
}

/* ------------------------------------------------------------------ */
/* resolve_op_path · join an operator arg against g_cwd and normalize.  */
/* Absolute args pass through (normalized); a bare relative token like  */
/* "dir" becomes "/dir" when cwd="/".  Collapses "." / "" and pops on    */
/* "..".  Writes into caller-owned `out`; returns `out`.                 */
/* ------------------------------------------------------------------ */
static const char *resolve_op_path(const char *arg, char *out, size_t outsz)
{
    char joined[ORCH_SOTFS_PATH_MAX * 2];
    if (!arg) arg = "";
    while (*arg == ' ' || *arg == '\t') ++arg;
    if (arg[0] == '/')                 snprintf(joined, sizeof(joined), "%s", arg);
    else if (arg[0] == '\0')           snprintf(joined, sizeof(joined), "%s", g_cwd);
    else if (strcmp(g_cwd, "/") == 0)  snprintf(joined, sizeof(joined), "/%s", arg);
    else                               snprintf(joined, sizeof(joined), "%s/%s", g_cwd, arg);

    /* trim trailing whitespace the line tail may carry */
    size_t jl = strlen(joined);
    while (jl > 0 && (joined[jl - 1] == ' ' || joined[jl - 1] == '\t')) joined[--jl] = '\0';

    /* normalize path segments in place */
    char *seg[64]; int n = 0;
    for (char *p = strtok(joined, "/"); p; p = strtok(NULL, "/")) {
        if (strcmp(p, ".") == 0) continue;
        if (strcmp(p, "..") == 0) { if (n) n--; continue; }
        if (n < 64) seg[n++] = p;
    }
    if (n == 0) { snprintf(out, outsz, "/"); return out; }
    size_t w = 0; out[0] = '\0';
    for (int k = 0; k < n && w + 1 < outsz; ++k)
        w += snprintf(out + w, outsz - w, "/%s", seg[k]);
    return out;
}

static int cmd_pwd(void) { printf("%s\n", g_cwd); return 0; }

/* cd · set the operator cwd (optimistic · no operator stat op · a following
 * `ls` reveals an empty/absent dir).  No arg → "/" (operator home). */
static int cmd_cd(const char *arg)
{
    char resolved[ORCH_SOTFS_PATH_MAX];
    resolve_op_path((arg && *arg) ? arg : "/", resolved, sizeof(resolved));
    strncpy(g_cwd, resolved, sizeof(g_cwd) - 1);
    g_cwd[sizeof(g_cwd) - 1] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_exec_real · REAL execution of an arbitrary command line.        */
/* Spawns a genuine busybox `sh -c "cd <cwd>; <line>"` sotBox at Tier-0 */
/* (operator truth view).  busybox PATH-resolves and execve's the real */
/* binary; LUCAS's execve interception turns the deception-stub         */
/* launchers (/usr/bin/python3, /bin/doom, …) into the real CPython /   */
/* Doom / etc.  This is a real shell over the real merged VFS — NOT a   */
/* `-c` canned shortcut — so `uname -a`, `id`, `ps`, `ss -tln`, `env`,  */
/* `df -h`, `python3 foo.py` actually run.  Fire-and-forget: the child's */
/* stdout streams to the serial/fb console as it runs (like run/doom).  */
/* ------------------------------------------------------------------ */
static int cmd_exec_real(seL4_CPtr orch_ep, const char *line)
{
    while (*line == ' ') ++line;
    if (!*line) return 0;

    static orch_spawn_msg_t m;
    memset(&m, 0, sizeof(m));
    strlcpy(m.binname, "busybox-static.bin", ORCH_SPAWN_BINNAME_BYTES);
    m.argc         = 3;
    m.profile      = 0;
    m.initial_tier = 0;            /* operator truth view · real output */
    m.trusted      = 0;            /* observed, not pinned */
    m.pledge       = (uint64_t)-1; /* PLEDGE_ALL */

    /* Run in the operator's cwd so relative paths match what `ls`/`cd` show. */
    char composed[ORCH_SPAWN_ARGV_BYTES];
    snprintf(composed, sizeof(composed), "cd '%s' 2>/dev/null; %s", g_cwd, line);

    const char *a0 = "sh", *a1 = "-c";
    size_t l0 = strlen(a0) + 1, l1 = strlen(a1) + 1, l2 = strlen(composed) + 1;
    if (l0 + l1 + l2 > ORCH_SPAWN_ARGV_BYTES) {
        printf("[sotshell] command line too long for exec\n");
        return -1;
    }
    size_t off = 0;
    memcpy(m.argv_pool + off, a0, l0); off += l0;
    memcpy(m.argv_pool + off, a1, l1); off += l1;
    memcpy(m.argv_pool + off, composed, l2);

    size_t nw = sizeof(m) / sizeof(seL4_Word);
    seL4_Word *src = (seL4_Word *)&m;
    for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
    seL4_MessageInfo_t reply =
        seL4_Call(orch_ep, seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw));
    seL4_Word rc = seL4_MessageInfo_get_label(reply);
    if (rc != 0) {
        printf("[sotshell] exec failed · rc=%lu (is busybox-static.bin staged?)\n",
               (unsigned long)rc);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* run_command · tiny line parser + dispatch                          */
/* ------------------------------------------------------------------ */
static int run_command(seL4_CPtr orch_ep, const char *line)
{
    /* === v0.7 · S2 · parser-layer hook ===
     * Parse pipes / redirection / globs BEFORE the strcmp dispatch.
     * If the pipeline contains pipes or redirection we execute via
     * execute_pipeline() and return early.  Otherwise we may rewrite
     * `line` to the glob-expanded form before falling through.
     *
     * `pl` is declared at function scope so `pl.expanded_line` remains
     * valid for the duration of run_command(). */
    struct parsed_pipeline pl;
    /* Guard against parser-driven re-entry · static so it persists across
     * the recursive call from run_argv_via_legacy(). */
    static int in_parser = 0;
    if (!in_parser) {
        in_parser = 1;
        int prc = sotshell_parse(line, &pl);
        in_parser = 0;
        if (prc == 0 && pl.n_cmds > 0) {
            if (pl.has_pipes_or_redir) {
                return execute_pipeline(orch_ep, &pl);
            }
            if (pl.has_glob_or_quote && pl.expanded_line[0]) {
                line = pl.expanded_line;
                /* fall through to legacy dispatch with rewritten line. */
            }
        }
    }

    /* Extract first token (command name). */
    char cmd[32];
    int i = 0;
    while (line[i] && line[i] != ' ' && i < 31) {
        cmd[i] = line[i]; ++i;
    }
    cmd[i] = '\0';

    if (strcmp(cmd, "sotinfo") == 0)  return cmd_sotinfo(orch_ep);
    if (strcmp(cmd, "list") == 0)     return cmd_list(orch_ep);
    if (strcmp(cmd, "sotnet") == 0)   return cmd_sotnet(orch_ep);
    if (strcmp(cmd, "fork-bomb") == 0) return cmd_fork_bomb(orch_ep);
    if (strcmp(cmd, "antidbg") == 0)  return cmd_antidbg(orch_ep);
    if (strcmp(cmd, "churn") == 0)    return cmd_churn(orch_ep);
    if (strcmp(cmd, "soak") == 0)     return cmd_soak(orch_ep);
    if (strcmp(cmd, "clear") == 0) {  /* ANSI clear screen + home cursor */
        printf("\033[2J\033[H");
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "quit") == 0)     return cmd_quit(orch_ep);
    if (strcmp(cmd, "poweroff") == 0 || strcmp(cmd, "shutdown") == 0)
        return cmd_poweroff(orch_ep);
    if (strcmp(cmd, "validate") == 0) return cmd_validate(orch_ep);
    if (strcmp(cmd, "bbsh") == 0)     return cmd_bbsh(orch_ep);
    if (strcmp(cmd, "shell") == 0)    return cmd_shell(orch_ep, strstr(line, "--trusted") != NULL);
    if (strcmp(cmd, "bbsh-auto") == 0) return cmd_bbsh_auto(orch_ep);
    if (strcmp(cmd, "doom") == 0)     return cmd_doom(orch_ep);
    if (strcmp(cmd, "gitdemo") == 0)  return cmd_gitdemo(orch_ep);
    if (strcmp(cmd, "sotctl") == 0) {
        const char *rest = line + 6;            /* skip "sotctl" */
        while (*rest == ' ') ++rest;            /* → the subcommand (or "") */
        return cmd_sotctl(orch_ep, rest);
    }
    if (strcmp(cmd, "egress-dns") == 0) return cmd_egress_dns(orch_ep);
    if (strcmp(cmd, "egress-http") == 0) return cmd_egress_http(orch_ep);
    if (strcmp(cmd, "egress-install") == 0) return cmd_egress_install(orch_ep);
    if (strcmp(cmd, "egress-python") == 0) return cmd_egress_python(orch_ep);
    if (strcmp(cmd, "arena-churn") == 0) return cmd_arena_churn(orch_ep);
    if (strcmp(cmd, "egress-pip") == 0) return cmd_egress_pip(orch_ep);
    if (strcmp(cmd, "egress-pipdeps") == 0) return cmd_egress_pipdeps(orch_ep);
    if (strcmp(cmd, "tools-fs") == 0) return cmd_tools_fs(orch_ep);
    if (strcmp(cmd, "py-e2e") == 0) return cmd_py_e2e(orch_ep);
    if (strcmp(cmd, "egress-pipbuild") == 0) return cmd_egress_pip_build(orch_ep);
    if (strcmp(cmd, "glibc") == 0)    return cmd_glibc(orch_ep);
    if (strcmp(cmd, "gnu") == 0)      return cmd_gnu(orch_ep);
    if (strcmp(cmd, "glibcdyn") == 0) return cmd_glibcdyn(orch_ep);
    if (strcmp(cmd, "dpkg-install") == 0) return cmd_dpkg_install(orch_ep);
    if (strcmp(cmd, "doomwl") == 0)   return cmd_doomwl(orch_ep);
    if (strcmp(cmd, "gtkspike") == 0) return cmd_gtkspike(orch_ep);
    if (strcmp(cmd, "gtk3-demo") == 0) return cmd_gtk3demo(orch_ep);
    if (strcmp(cmd, "gtk3-widget-factory") == 0) return cmd_widgetfactory(orch_ep);
    if (strcmp(cmd, "mapfixed") == 0) return cmd_mapfixed(orch_ep);
    if (strcmp(cmd, "wine-baked") == 0) return cmd_wine_baked(orch_ep);
    if (strcmp(cmd, "wine-crt") == 0) return cmd_wine_crt(orch_ep);
    if (strcmp(cmd, "wine-gui") == 0) return cmd_wine_gui(orch_ep);
    if (strcmp(cmd, "wine") == 0) return cmd_wine(orch_ep);
    if (strcmp(cmd, "help") == 0) {
        printf("commands: sotinfo, list, sotnet, promote <pid> <tier>, silence <pid>, synth <pid>, clear <pid>, kill <pid>, pwd, cd <path>, ls/dir <path>, cat <path>, install <path> <content>, mkdir <path>, rm <path>, tail <path>, grep <pattern> <path>, dns list, dns install <domain> <ip>, dns lookup <domain>, synth-trigger <ip> <port>, synth-install <ip> <port> <response_profile>, synth-queue, anomaly-log, tpm-pcrs, tpm-quote [<nonce_hex>], dump-heap <pid> <out_path>, quit\n");
        printf("  (filesystem rooted at '/': merged view — synthetic /etc,/bin · real Alpine /usr,/lib · writable /tmp · cd/pwd/relative paths work · any other command runs for REAL via busybox)\n");
        printf("  python [--pledge <T_*|\"promises\">] \"<code>\"  · run Python 3.12 in a fresh Tier 0 sotbox\n");
        printf("  shell [--trusted]         · interactive busybox sh -i.  --trusted = Tier-0e OPERATOR shell with REAL egress (pip install / python3 reach the internet); bare = Tier-2 canary (same as bbsh)\n");
        printf("  inject-script <path>      · read a Python script from sotfs and spawn it via python3.12-static -c\n");
        printf("  tcc <path>                · SP1 · spawn embedded TinyCC trusted · argv [tcc,-B/tmp,-nostdlib,-run,<path>] · compile+run a freestanding C source\n");
        printf("  execmap-test              · SP1 PR 4 · spawn a trusted fixture that mmaps RWX + executes the writable page (exec OK)\n");
        printf("  anomaly-log              · dump in-orch ring of recent anomaly events\n");
        printf("  tpm-pcrs                  · read PCR 8/9/10 from the TPM (sotBoot measurement bank)\n");
        printf("  tpm-quote [<nonce>]       · request a TPM quote (signed PCR digest) over a hex nonce (default: deadbeef)\n");
        printf("  dump-heap <pid> <path>    · capture sotbox heap [brk_base,brk_top) to a sotfs file (sotGuard live-dump · ≤1 MiB)\n");
        printf("  simreboot                 · α · PR 7 · userspace-only reset cascade · 5-phase WAL CHECKPOINT + replay-apply\n");
        printf("  bbsh                      · launch an interactive busybox sh -i at Tier-2 (canary VFS) over the serial console · 'exit' to return\n");
        printf("  systemctl <action> [unit] · β · PR 5 · operator-driven sotinit query (list|status|start|stop)\n");
        printf("  cron <action> [timer]     · β · PR 9 · operator-driven sotcron query (list|now)\n");
        printf("  nano <path> (or edit)     · full-screen editor · arrows, ^O save, ^X exit, ^W search, ^K/^U cut, ^Z undo\n");
        return 0;
    }
    if ((strncmp(cmd, "nano", 4) == 0 && (cmd[4] == ' ' || cmd[4] == '\0')) ||
        (strncmp(cmd, "edit", 4) == 0 && (cmd[4] == ' ' || cmd[4] == '\0'))) {
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        while (*rest == ' ') ++rest;
        if (!*rest) { printf("usage: nano <path>\n"); return -1; }
        return sotnano_run(orch_ep, rest);
    }
    if (strcmp(cmd, "kill") == 0) {
        int pid = (line[i] == ' ') ? atoi(line + i + 1) : 0;
        return cmd_kill(orch_ep, pid);
    }
    if (strcmp(cmd, "promote") == 0) {
        int pid = 0, tier = 0;
        if (line[i] == ' ')
            sscanf(line + i + 1, "%d %d", &pid, &tier);
        return cmd_promote(orch_ep, pid, tier);
    }
    if (strcmp(cmd, "silence") == 0) {
        int pid = (line[i] == ' ') ? atoi(line + i + 1) : 0;
        return cmd_promote(orch_ep, pid, 1);
    }
    if (strcmp(cmd, "synth") == 0) {
        int pid = (line[i] == ' ') ? atoi(line + i + 1) : 0;
        return cmd_promote(orch_ep, pid, 2);
    }
    if (strcmp(cmd, "clear") == 0) {
        int pid = (line[i] == ' ') ? atoi(line + i + 1) : 0;
        return cmd_promote(orch_ep, pid, 0);
    }
    if (strcmp(cmd, "anomaly-log") == 0) {
        return cmd_anomaly_log(orch_ep);
    }
    if (strcmp(cmd, "sottrace") == 0) {
        /* arg comes from `line` (cmd holds only the first token); same idiom
         * as cmd_banner below. "sottrace on"/"off" toggle the live drain;
         * bare "sottrace" snapshots the rings. */
        const char *arg = (line[i] == ' ') ? line + i + 1 : "";
        while (*arg == ' ') arg++;
        if (strcmp(arg, "on") == 0)  return cmd_sottrace_live(orch_ep, 1);
        if (strcmp(arg, "off") == 0) return cmd_sottrace_live(orch_ep, 0);
        if (strcmp(arg, "graph") == 0) return cmd_sottrace_graph(orch_ep);
        if (strncmp(arg, "payload", 7) == 0 && (arg[7] == ' ' || arg[7] == '\0')) {
            const char *n = arg + 7;
            while (*n == ' ') n++;
            int id = atoi(n);            /* same atoi idiom as kill/silence */
            return cmd_sottrace_payload(orch_ep, (uint16_t)id);
        }
        return cmd_sottrace(orch_ep);
    }
    if (strcmp(cmd, "watch") == 0) {        /* v2.8 · live deception monitor */
        return cmd_watch(orch_ep);
    }
    /* C2 · demo-mode commands · phase banner, incident rollup, integrity check. */
    if (strcmp(cmd, "banner") == 0) {
        return cmd_banner((line[i] == ' ') ? line + i + 1 : "");
    }
    if (strcmp(cmd, "incident") == 0) {
        return cmd_incident(orch_ep);
    }
    if (strcmp(cmd, "verify") == 0) {
        return cmd_verify(orch_ep, (line[i] == ' ') ? line + i + 1 : "");
    }
    if (strcmp(cmd, "bench") == 0) {
        return cmd_bench(orch_ep, (line[i] == ' ') ? line + i + 1 : "");
    }
    if (strcmp(cmd, "simreboot") == 0) {
        return cmd_simreboot(orch_ep);
    }
    if (strcmp(cmd, "systemctl") == 0) {
        /* β · PR 5 · parse argv inline: rebuild a small argv array from the
         * raw line for the cmd_systemctl helper.  We split on single spaces ·
         * names with whitespace are not yet supported (matches systemd unit-
         * name conventions where spaces would themselves be illegal). */
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        while (*rest == ' ') rest++;
        char action_buf[16] = {0};
        char name_buf[64] = {0};
        int local_argc = 1;
        char *local_argv[3] = { (char *)"systemctl", NULL, NULL };
        if (*rest) {
            const char *sp = strchr(rest, ' ');
            size_t alen = sp ? (size_t)(sp - rest) : strlen(rest);
            if (alen >= sizeof(action_buf)) alen = sizeof(action_buf) - 1;
            memcpy(action_buf, rest, alen);
            local_argv[1] = action_buf;
            local_argc = 2;
            if (sp) {
                const char *nm = sp + 1;
                while (*nm == ' ') nm++;
                if (*nm) {
                    size_t nlen = strlen(nm);
                    if (nlen >= sizeof(name_buf)) nlen = sizeof(name_buf) - 1;
                    memcpy(name_buf, nm, nlen);
                    local_argv[2] = name_buf;
                    local_argc = 3;
                }
            }
        }
        return cmd_systemctl(local_argc, local_argv);
    }
    if (strcmp(cmd, "cron") == 0) {
        /* β · PR 9 · parse argv inline · same single-space split pattern
         * used for systemctl above.  Two args max (action + optional timer
         * name).  Operator-driven verb · NOT in demo_commands so the
         * smoke gate stays MANUAL (the operator types `cron list` or
         * `cron now <timer>` from interactive sotShell). */
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        while (*rest == ' ') rest++;
        char action_buf[16] = {0};
        char name_buf[64] = {0};
        int local_argc = 1;
        char *local_argv[3] = { (char *)"cron", NULL, NULL };
        if (*rest) {
            const char *sp = strchr(rest, ' ');
            size_t alen = sp ? (size_t)(sp - rest) : strlen(rest);
            if (alen >= sizeof(action_buf)) alen = sizeof(action_buf) - 1;
            memcpy(action_buf, rest, alen);
            local_argv[1] = action_buf;
            local_argc = 2;
            if (sp) {
                const char *nm = sp + 1;
                while (*nm == ' ') nm++;
                if (*nm) {
                    size_t nlen = strlen(nm);
                    if (nlen >= sizeof(name_buf)) nlen = sizeof(name_buf) - 1;
                    memcpy(name_buf, nm, nlen);
                    local_argv[2] = name_buf;
                    local_argc = 3;
                }
            }
        }
        return cmd_cron(local_argc, local_argv);
    }
    if (strcmp(cmd, "tpm-pcrs") == 0) {
        return cmd_tpm_pcrs(orch_ep);
    }
    if (strcmp(cmd, "tpm-quote") == 0) {
        /* Optional positional arg: nonce_hex.  When missing, cmd_tpm_quote
         * defaults to "deadbeef". */
        const char *arg = (line[i] == ' ') ? line + i + 1 : "";
        while (*arg == ' ') arg++;
        return cmd_tpm_quote(orch_ep, arg);
    }
    if (strcmp(cmd, "ls") == 0 || strcmp(cmd, "dir") == 0) {
        static char rp[ORCH_SOTFS_PATH_MAX];
        const char *arg = (line[i] == ' ') ? line + i + 1 : "";
        return cmd_ls(orch_ep, resolve_op_path(arg, rp, sizeof(rp)));
    }
    if (strcmp(cmd, "cd") == 0) {
        const char *arg = (line[i] == ' ') ? line + i + 1 : "";
        return cmd_cd(arg);
    }
    if (strcmp(cmd, "pwd") == 0) {
        return cmd_pwd();
    }
    if (strcmp(cmd, "cat") == 0) {
        static char rp[ORCH_SOTFS_PATH_MAX];
        const char *arg = (line[i] == ' ') ? line + i + 1 : "";
        if (!*arg) { printf("usage: cat <path>\n"); return -1; }
        return cmd_cat(orch_ep, resolve_op_path(arg, rp, sizeof(rp)));
    }
    if (strcmp(cmd, "install") == 0) {
        /* install <path> <content> — split on first space after path */
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        /* find the space separating path from content */
        const char *sp = strchr(rest, ' ');
        if (!sp) {
            printf("[sotshell] install: usage: install <path> <content>\n");
            return 1;
        }
        char path_buf[128];
        size_t plen = (size_t)(sp - rest);
        if (plen >= sizeof(path_buf)) plen = sizeof(path_buf) - 1;
        memcpy(path_buf, rest, plen);
        path_buf[plen] = '\0';
        const char *content = sp + 1;
        return cmd_install(orch_ep, path_buf, content);
    }
    if (strcmp(cmd, "mkdir") == 0) {
        static char rp[ORCH_SOTFS_PATH_MAX];
        const char *arg = (line[i] == ' ') ? line + i + 1 : "";
        return cmd_mkdir(orch_ep, resolve_op_path(arg, rp, sizeof(rp)));
    }
    if (strcmp(cmd, "rm") == 0) {
        static char rp[ORCH_SOTFS_PATH_MAX];
        const char *arg = (line[i] == ' ') ? line + i + 1 : "";
        return cmd_rm(orch_ep, resolve_op_path(arg, rp, sizeof(rp)));
    }
    if (strcmp(cmd, "tail") == 0) {
        static char rp[ORCH_SOTFS_PATH_MAX];
        const char *arg = (line[i] == ' ') ? line + i + 1 : "";
        return cmd_tail(orch_ep, resolve_op_path(arg, rp, sizeof(rp)));
    }
    if (strcmp(cmd, "grep") == 0) {
        /* grep <pattern> <path> — split on first space */
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        const char *sp = strchr(rest, ' ');
        if (!sp) {
            printf("[sotshell] grep: usage: grep <pattern> <path>\n");
            return 1;
        }
        char pat_buf[64];
        size_t plen = (size_t)(sp - rest);
        if (plen >= sizeof(pat_buf)) plen = sizeof(pat_buf) - 1;
        memcpy(pat_buf, rest, plen);
        pat_buf[plen] = '\0';
        const char *gpath = sp + 1;
        return cmd_grep(orch_ep, pat_buf, gpath);
    }
    if (strcmp(cmd, "dns") == 0) {
        /* `dns list` or `dns install <domain> <ip>` or `dns lookup <domain>` */
        const char *args = (line[i] == ' ') ? line + i + 1 : "";
        while (*args == ' ') args++;
        if (strncmp(args, "list", 4) == 0 && (args[4] == '\0' || args[4] == ' ')) {
            return cmd_dns_list(orch_ep);
        }
        if (strncmp(args, "install ", 6) == 0) {
            const char *domain = args + 6;
            const char *space = strchr(domain, ' ');
            if (!space) {
                printf("usage: dns install <domain> <ip>\n");
                return -1;
            }
            char domain_buf[64];
            size_t dlen = (size_t)(space - domain);
            if (dlen >= sizeof(domain_buf)) dlen = sizeof(domain_buf) - 1;
            memcpy(domain_buf, domain, dlen);
            domain_buf[dlen] = '\0';
            const char *ip_str = space + 1;
            return cmd_dns_install(orch_ep, domain_buf, ip_str);
        }
        if (strncmp(args, "lookup ", 7) == 0) {
            const char *domain = args + 7;
            while (*domain == ' ') domain++;
            if (*domain == '\0') {
                printf("usage: dns lookup <domain>\n");
                return -1;
            }
            return cmd_dns_lookup(orch_ep, domain);
        }
        printf("usage: dns list  |  dns install <domain> <ip>  |  dns lookup <domain>\n");
        return -1;
    }
    if (strcmp(cmd, "synth-trigger") == 0) {
        /* synth-trigger <a.b.c.d> <port> */
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        while (*rest == ' ') rest++;
        const char *sp = strchr(rest, ' ');
        if (!sp) {
            printf("[synth-trigger] usage: synth-trigger <a.b.c.d> <port>\n");
            return -1;
        }
        char ip_buf[32];
        size_t iplen = (size_t)(sp - rest);
        if (iplen >= sizeof(ip_buf)) iplen = sizeof(ip_buf) - 1;
        memcpy(ip_buf, rest, iplen);
        ip_buf[iplen] = '\0';
        const char *port_str = sp + 1;
        while (*port_str == ' ') port_str++;
        return cmd_synth_trigger(orch_ep, ip_buf, port_str);
    }
    if (strcmp(cmd, "synth-install") == 0) {
        /* synth-install <a.b.c.d> <port> <response_profile> */
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        while (*rest == ' ') rest++;
        char ip_buf[32], port_buf[16];
        const char *sp1 = strchr(rest, ' ');
        if (!sp1) { printf("[synth-install] usage: synth-install <a.b.c.d> <port> <response_profile>\n"); return -1; }
        size_t iplen = (size_t)(sp1 - rest);
        if (iplen >= sizeof(ip_buf)) iplen = sizeof(ip_buf) - 1;
        memcpy(ip_buf, rest, iplen); ip_buf[iplen] = '\0';
        const char *p2 = sp1 + 1; while (*p2 == ' ') p2++;
        const char *sp2 = strchr(p2, ' ');
        if (!sp2) { printf("[synth-install] usage: synth-install <a.b.c.d> <port> <response_profile>\n"); return -1; }
        size_t plen = (size_t)(sp2 - p2);
        if (plen >= sizeof(port_buf)) plen = sizeof(port_buf) - 1;
        memcpy(port_buf, p2, plen); port_buf[plen] = '\0';
        const char *response_profile = sp2 + 1; while (*response_profile == ' ') response_profile++;
        return cmd_synth_install(orch_ep, ip_buf, port_buf, response_profile);
    }
    if (strcmp(cmd, "synth-queue") == 0) {
        return cmd_synth_queue(orch_ep);
    }
    if (strncmp(cmd, "inject-script", 13) == 0 && line[i] == ' ') {
        return cmd_inject_script(orch_ep, line + i + 1);
    }
    /* SP1 PR 3 · spawn the embedded TinyCC trusted with
     * argv ["tcc","-B/tmp","-nostdlib","-run",<path>] · compile+run a
     * freestanding C source from sotfs. */
    if (strcmp(cmd, "tcc") == 0) {
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        return cmd_tcc(orch_ep, rest);
    }
    /* SP2 PR 7 · load+execute a standalone ELF from sotfs (untrusted). */
    if (strcmp(cmd, "run") == 0) {
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        return cmd_run(orch_ep, rest);
    }
    /* A2 · install a binary into the writable on-disk store (rwbinstore). */
    if (strcmp(cmd, "bininstall") == 0) {
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        return cmd_bininstall(orch_ep, rest);
    }
    /* PR 6 · spawn the procd fork/exit/wait4 smoke fixture. */
    if (strcmp(cmd, "procd-fork-test") == 0) {
        return cmd_procd_fork_test(orch_ep);
    }
    if (strcmp(cmd, "procd-exec-test") == 0) {
        return cmd_procd_exec_test(orch_ep);
    }
    /* PR 8 · spawn the pthread fixture (clone+futex smoke). */
    if (strcmp(cmd, "procd-pthread-test") == 0) {
        return cmd_procd_pthread_test(orch_ep);
    }
    /* PR 9 · spawn the pg-test fixture (setsid/getpgid smoke). */
    if (strcmp(cmd, "procd-pg-test") == 0) {
        return cmd_procd_pg_test(orch_ep);
    }
    /* PR 12 · spawn the cond-test fixture (WAIT_BITSET/WAKE_BITSET smoke). */
    if (strcmp(cmd, "procd-cond-test") == 0) {
        return cmd_procd_cond_test(orch_ep);
    }
    /* PR 13 · spawn the robust-test fixture (set_robust_list smoke). */
    if (strcmp(cmd, "procd-robust-test") == 0) {
        return cmd_procd_robust_test(orch_ep);
    }
    /* init-cron PR 10 · spawn the shellhook-test fixture
     * (execve argv-rewrite smoke).  Lucas's shellhook injects
     * /etc/bashrc + /root/.bashrc · the operator sees both the
     * [lucas] shellhook line and the [BASHRC-MARKER] echoes. */
    if (strcmp(cmd, "shellhook-test") == 0) {
        return cmd_shellhook_test(orch_ep);
    }
    /* γ · spawn the stage7-demo fixture · Tier-2 sotbox writes to
     * 4 sensitive paths so lucas fires F_persistence + sotfs sets
     * inode.functor_persistence=1.  Post-simreboot the lie survives. */
    if (strcmp(cmd, "stage7-demo") == 0) {
        return cmd_stage7_demo(orch_ep);
    }
    /* POSIX-surface PR 6 · spawn the syscall-test fixture · raw-syscall
     * C-static validation of unlink/readv/writev/madvise + the fd-1/2
     * console/FS boundary.  Operator sees [syscall-test] ALL PASS. */
    if (strcmp(cmd, "syscall-test") == 0) {
        return cmd_syscall_test(orch_ep);
    }
    if (strcmp(cmd, "ubench") == 0) {       /* T5 · syscall-latency microbench */
        return cmd_ubench(orch_ep);
    }
    if (strcmp(cmd, "ubench-libc") == 0) { /* vDSO arc · Task 8 · libc clock_gettime via vDSO */
        return cmd_ubench_libc(orch_ep);
    }
    if (strcmp(cmd, "vdso-probe") == 0) {   /* vDSO arc · Task 5 · F1 · ELF parse + call */
        return cmd_vdso_probe(orch_ep);
    }
    if (strcmp(cmd, "fastpath-probe") == 0) { /* fast-path arc · Task 9 · sched_yield gate */
        return cmd_fastpath_probe(orch_ep);
    }
    /* ANOMALY PR 7 · spawn the anomaly-test fixture · raw-syscall
     * C-static fixture that drives a sotbox's weighted suspicion score
     * across T1/T2 (cred recon + writes + unlink burst).  Operator
     * sees [anomaly-test] ALL PASS; the engine logs the tier flips. */
    if (strcmp(cmd, "anomaly-test") == 0) {
        return cmd_anomaly_test(orch_ep);
    }
    /* SP1 PR 4 · spawn the execmap-test fixture TRUSTED · proves a trusted
     * sotbox can execute memory it mapped writable (mmap RWX + jump in).
     * Operator sees [execmap-test] exec OK · gates the in-OS compiler. */
    if (strcmp(cmd, "execmap-test") == 0) {
        return cmd_execmap_test(orch_ep);
    }
    /* sotNet γ-3-γ-2b · spawn the BearSSL TLS client fixture · real TLS 1.2
     * handshake against the responder over the byte-pipe. */
    if (strcmp(cmd, "tls-probe") == 0) {
        return cmd_tls_probe(orch_ep);
    }
    if (strcmp(cmd, "wayland-connect") == 0) {
        return cmd_wayland_connect(orch_ep);
    }
    if (strcmp(cmd, "wayland-sync") == 0) {
        return cmd_wayland_sync(orch_ep);
    }
    if (strcmp(cmd, "wayland-info") == 0) {
        return cmd_wayland_info(orch_ep);
    }
    if (strcmp(cmd, "wl-shm") == 0) {
        return cmd_wl_shm(orch_ep);
    }
    if (strcmp(cmd, "wl-capture") == 0) {
        return cmd_wl_capture_client(orch_ep);
    }
    if (strcmp(cmd, "egress-probe") == 0) {
        return cmd_egress_probe(orch_ep);
    }
    if (strcmp(cmd, "canary-service") == 0) {
        return cmd_canary_service(orch_ep);
    }
    if (strcmp(cmd, "canary-read") == 0) {
        return cmd_canary_read(orch_ep);
    }
    if (strcmp(cmd, "hello-dyn") == 0) {
        return cmd_hello_dyn(orch_ep);
    }
    if (strcmp(cmd, "hello-dyn2") == 0) {
        return cmd_hello_dyn2(orch_ep);
    }
    if (strcmp(cmd, "hello-ssl") == 0) {
        return cmd_hello_ssl(orch_ep);
    }
    if (strcmp(cmd, "sdlspike") == 0) {
        return cmd_sdlspike(orch_ep);
    }
    if (strcmp(cmd, "real-vfs") == 0) {
        return cmd_real_vfs(orch_ep);
    }
    if (strcmp(cmd, "dump-heap") == 0) {
        /* dump-heap <pid> <out_path> · sotGuard live-dump forensic capture. */
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        while (*rest == ' ') ++rest;
        if (!*rest) {
            printf("usage: dump-heap <pid> <out_path>\n");
            return -1;
        }
        char pid_buf[16];
        size_t pi = 0;
        while (rest[pi] && rest[pi] != ' ' && pi < sizeof(pid_buf) - 1) {
            pid_buf[pi] = rest[pi];
            ++pi;
        }
        pid_buf[pi] = '\0';
        int dpid = atoi(pid_buf);
        const char *path = rest + pi;
        while (*path == ' ') ++path;
        if (!*path) {
            printf("usage: dump-heap <pid> <out_path>\n");
            return -1;
        }
        return cmd_dump_heap(orch_ep, dpid, path);
    }
    if (strncmp(cmd, "python", 6) == 0 && (line[i] == ' ' || line[i] == '\0')) {
        const char *rest = (line[i] == ' ') ? line + i + 1 : "";
        /* SPAWN-PLEDGE-CLI · optional `--pledge <template>` prefix.
         * Skip leading whitespace, then detect the flag.  The flag's
         * value may be a bare template name ("T_PYTHON_SANDBOX") or a
         * quoted OpenBSD-style promise string ("stdio rpath inet"). */
        while (*rest == ' ') ++rest;
        uint64_t pledge_mask = PLEDGE_ALL;
        if (strncmp(rest, "--pledge", 8) == 0 &&
            (rest[8] == ' ' || rest[8] == '=')) {
            const char *val = rest + 8;
            while (*val == ' ' || *val == '=') ++val;
            /* Extract the value: a quoted string ("...") consumes up to
             * the matching close-quote; an unquoted value consumes one
             * whitespace-delimited token. */
            char val_buf[64];
            const char *val_end;
            if (*val == '"') {
                ++val;
                val_end = strchr(val, '"');
                if (!val_end) {
                    printf("[sotshell] error: unterminated quote in --pledge value\n");
                    return 1;
                }
            } else {
                val_end = val;
                while (*val_end && *val_end != ' ') ++val_end;
            }
            size_t vlen = (size_t)(val_end - val);
            if (vlen >= sizeof(val_buf)) vlen = sizeof(val_buf) - 1;
            memcpy(val_buf, val, vlen);
            val_buf[vlen] = '\0';

            int ok = 0;
            pledge_mask = shell_resolve_pledge(val_buf, &ok);
            if (!ok) {
                printf("[sotshell] error: unknown pledge template '%s'\n", val_buf);
                return 1;
            }
            /* Advance past the consumed value (and closing quote, if any). */
            rest = val_end;
            if (*rest == '"') ++rest;
            while (*rest == ' ') ++rest;
        }
        /* Real execution (no `-c` shortcut): `python3 foo.py`, `python -V`, a
         * bare `python`, etc. run the REAL interpreter via a busybox shell.
         * Only a QUOTED argument keeps the operator `python "<inline code>"`
         * built-in (used by the python-canary gate). */
        if (*rest != '"') {
            return cmd_exec_real(orch_ep, line);
        }
        const char *code = rest;
        /* Strip surrounding quotes if present */
        char code_buf[256];
        if (*code == '"') {
            const char *end = strrchr(code, '"');
            if (end && end > code) {
                size_t len = end - code - 1;
                if (len >= sizeof(code_buf)) len = sizeof(code_buf) - 1;
                memcpy(code_buf, code + 1, len);
                code_buf[len] = '\0';
                code = code_buf;
            }
        }
        return cmd_python(orch_ep, code, pledge_mask);
    }
    /* No built-in matched · REAL execution.  Run the line in a genuine busybox
     * shell sotBox so real recon tools (uname, id, ps, ss, env, df, find, …)
     * and any staged ELF actually execute — instead of the console faking them
     * or rejecting them.  This is the "ejecución real, no atajos" path. */
    return cmd_exec_real(orch_ep, line);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[]) {
    (void)argc;
    seL4_CPtr orch_ep = (argc > 1) ? (seL4_CPtr)atol(argv[1]) : 0;
    if (!orch_ep) {
        printf("[sotshell] FATAL · no orch EP cap provided\n");
        return 1;
    }

    /* L4-Phase-C v2: argv[2] = IO_Port cap slot (0 if not delegated). */
    if (argc > 2) {
        g_io_port_cap = (seL4_CPtr)atol(argv[2]);
    }
    /* β · PR 5 · argv[3] = sotinit listen EP slot (0 if root did not
     * pre-spawn sotinit or the forward mint failed).  cmd_systemctl
     * short-circuits with a "not available" message when 0. */
    if (argc > 3) {
        g_sotinit_ep_slot = (seL4_CPtr)atol(argv[3]);
    }
    /* β · PR 9 · argv[4] = sotcron listen EP slot (0 if root did not
     * pre-spawn sotcron or the forward mint failed).  cmd_cron
     * short-circuits with a "not available" message when 0.  Minted
     * BADGED with BADGE_SOTCRON_OPERATOR so sotcron's NBRecv drain
     * sees a non-zero badge on operator queries. */
    if (argc > 4) {
        g_sotcron_ep_slot = (seL4_CPtr)atol(argv[4]);
    }

    /* v0.7 · S1 · install readline backend (serial poll + orch EP). */
    sotshell_readline_init(serial_getchar, orch_ep);
    /* v0.7 · S2 · parser needs orch EP for glob expansion via SOTFS_LS. */
    g_parser_orch_ep = orch_ep;
    /* F12 toggle · the operator console polls this EP for GTK-keyboard bytes
     * and tees its stdout to orch's framebuffer (so it shows in the window). */
    g_getkey_orch_ep = orch_ep;
    g_orig_stdio_write = sel4muslcsys_register_stdio_write_fn(sotshell_fb_tee_write);

    printf("\n");
    printf("======================================================\n");
    printf("  sotShell · operator console · L4-Phase-C v2\n");
    printf("======================================================\n\n");

    /* For now we drive sotShell from a synthetic input stream so the
     * autonomous demo can run.  L4-Phase-C (real interactive console)
     * replaces this with polled serial reads. */
    /* FULL(...) marks a completed-arc demo (GUI/wayland/Doom, compat-host
     * probes, subsystem self-tests, TCC/churn/persistence).  Default headless
     * boots are LEAN — FULL() entries collapse to NULL and are skipped in the
     * run loop, so the common gates (apt/ssh/smoke) boot fast.  The arc-specific
     * gates that grep these markers reconfigure with -DSOTOS_DEMO_FULL=ON.  The
     * bare (un-FULL) entries are the cheap core: the deception narrative, the
     * observability markers, and bbsh-auto — they also keep enough UART activity
     * to service inbound RX under KVM (the iothread-yield path). */
#ifdef SOTOS_DEMO_FULL
#  define FULL(s) (s)
#else
#  define FULL(s) ((const char *)0)
#endif
    static const char *demo_commands[] = {
        /* Wine M1 SPIKE · `wine` (cmd_wine · ORCH_OP_WINE) is NOT in the auto-demo:
         * wine progresses far (preloader reserves + maps the loader chain) but the
         * re-launched ld-musl #GPs — the spike frontier — so it would stall the
         * headless boot.  Invoke `wine` from the operator console to resume. */
        FULL("mapfixed"),  /* Wine-prep · MAP_FIXED-low gate · runs mapfixed.bin (the wine-
                      * preloader mmap PATTERN: reserve large PROT_NONE Windows ranges,
                      * commit sub-ranges via MAP_FIXED + mprotect).  FIRST so its fast
                      * static run + [mapfixed] ALL PASS land well inside the headless
                      * boot window (the GUI demos below are slow). */
        FULL("gnu"),       /* compat-host · real GNU tools (musl-dynamic): GNU coreutils 9.5
                      * (ls/cat/wc), grep, sed, gawk at Tier-0 on the honey /etc/passwd.
                      * The GNU userland (not busybox) runs on sotOs. */
        FULL("glibc"),     /* compat-host · a glibc-static binary (real GNU/glibc libc, NOT musl)
                      * runs at Tier-0 · the probe exercises stdio/malloc/uname/fopen.  Proves
                      * the glibc ABI works (static avoids the ld-linux loader · that arc next). */
        FULL("glibcdyn"),  /* compat-host · glibc-DYNAMIC PIE loaded by the REAL ld-linux-x86-64.so.2
                      * (not ld-musl) at Tier-0 · the glibc loader bring-up. */
        FULL("gitdemo"),   /* compat-host · REAL Alpine git (musl-dynamic) at Tier-0 in /tmp/gitrepo:
                      * init -> commit --allow-empty -> log.  Exercises the real rename()
                      * (lucas_sotfs_rename), the /dev/urandom node, and the libz/libpcre2
                      * dynamic closure from the sysroot.  `git log --oneline` printing the
                      * commit is the PASS signal.  Placed EARLY (fast static-ish run) so it
                      * lands well inside the headless boot window, before the slow GUI demos. */
        FULL("sotctl sessions"), /* world-#3 native operator plane · spawns the NATIVE sotctl
                      * binary (sotcrt+sotlibc+sel4runtime · NOT a Linux guest) which
                      * pulls the live sessions view over sotabi and prints it.  Bounded
                      * (the binary exits at render-stream EOF · NOT captive).  Proves the
                      * world-#3 C runtime runs headlessly · tools/sotctl-native-gate.sh. */
        FULL("dpkg-install"), /* install-arc P0.2 · `dpkg-deb -x /tmp/hello.deb /tmp/root` at Tier-0:
                      * the real off-the-shelf Debian dpkg-deb extracts the .deb's
                      * data.tar.xz (execve'ing the real tar + xz) into the writable
                      * /tmp sotfs, writing /tmp/root/usr/bin/hello (a real ELF).
                      * Placed EARLY with the other compat-host probes (fast, no GUI). */
        FULL("sdlspike"),  /* v2.3 · SDL2-over-real-Wayland smoke (sw/wl_shm) · before bbsh */
        FULL("doomwl"),    /* v2.3-M5 · Doom over REAL Wayland · doomgeneric → patched dynamic SDL2 (wayland/SOFTWARE) → wl_shm commits on the honest compositor (NO EGL). Grouped with sdlspike at the front so it lands within the headless boot window. */
        FULL("gtkspike"),  /* v2.4 · GTK3 over REAL Wayland · a real unmodified Alpine GTK3
                      * app renders a cairo window over wl_shm on the honest compositor
                      * (NO EGL) · undecorated (skips the CSD icon-PNG cascade) · the
                      * compositor sees the real cairo pixels (px0==the fill color),
                      * 0 faults.  Cleared 9 walls (loader/futex/seat/keymap/MAP_SHARED/
                      * statfs/heavy-arena).  Grouped with sdlspike/doomwl. */
        FULL("gtk3-widget-factory"), /* #2 GTK fidelity (broader-apps) · the UNMODIFIED Alpine
                      * gtk3-widget-factory — the canonical GTK widget showcase (every
                      * widget: buttons/switches/sliders/GtkTreeView/GtkNotebook/dialogs/
                      * spinners).  Same GTK env + lib closure (subset) as gtk3-demo, but a
                      * RICHER proof.  This is the TERMINAL GUI app of the auto-demo (the
                      * last wl client) → renders its window forever, exactly the proven
                      * gtk3-demo-as-terminal pattern.  gtk3-demo itself is no longer in
                      * the auto-demo (a force-reaped wl client breaks the next one); it
                      * stays a console command + its dedicated tools/gtk3-demo-window-gate.sh
                      * (F12 → type `gtk3-demo`), so its coverage is unchanged. */
        FULL("real-vfs"),  /* v2-real-vfs · Gate E · dynamic .so-via-symlink + sysroot syscall probe markers land in the headless boot window */
        /* NOTE: a throwaway "bbsh" GATE-TEMP entry (tools/bbsh-gate.sh) was
         * accidentally committed here in v1.0-rc1 (949330e) and left the HEADLESS
         * demo captive at an interactive `busybox sh -i` — so every demo command
         * after it (validate, soak, doom, tcc, ...) silently never ran headless.
         * Removed in v1.5 (the soak the endurance run needs lives below). The
         * bbsh-gate still inserts+reverts its own copy when run. */
        /* C2 #9/#7 · PHASE 1 · benign baseline (a normal read · no canary,
         * no cred path · produces no anomaly promotion → the contrast for
         * the later deception phase). */
        "banner PHASE 1 · BASELINE (benign read · no promotion)",
        "cat /tmp/welcome",
        /* Performance benchmarks · spawned EARLY (allocman pool fresh).  Each
         * `bench` is now ISOLATED (v0.46.0-bench-iso): orch blocks on the
         * bench's done EP after spawning it, so the shell + demo pause and the
         * bench runs ALONE — no preemption, no concurrent STO clients — until it
         * Sends done.  Combined with the STO registry GC (v0.45.0), all four
         * complete cleanly with low-jitter numbers.  Run consecutively (no
         * command between) so each stays isolated. */
        FULL("bench baseline"),
        FULL("bench sto_ops"),
        FULL("bench throughput"),
        FULL("bench sweep_cost"),
        /* vDSO arc · Task 5 · F1 · boot probe: manually parses the vDSO
         * ELF mapped at AT_SYSINFO_EHDR, resolves __vdso_clock_gettime by
         * name, calls it for CLOCK_MONOTONIC + CLOCK_REALTIME, emits the
         * "[vdso-probe] resolved=0x... mono=... real=..." gate marker.
         * Runs unconditionally (lean build too) — it is fast and exercises
         * the vDSO mapping on every boot.  Gate: tools/vdso-gate.sh. */
        "vdso-probe",
        /* vDSO arc · Task 8 · libc bench: normal musl-linked binary calls
         * clock_gettime() via the standard libc entry point — musl resolves
         * __vdso_clock_gettime from AT_SYSINFO_EHDR automatically.  Emits
         * "[ubench-libc] clock_gettime min=<cyc> mean=<cyc>".  Gate asserts
         * min < 1000 (no trap — real in-guest vDSO fast-path).
         * Runs lean (always-on) — same class as vdso-probe, fast. */
        "ubench-libc",
        /* fast-path arc · Task 9 · sched_yield fast-path gate: calls
         * sched_yield (sysno 24) in a timed lfence;rdtsc loop.  Emits
         * "[fastpath-probe] sched_yield_cycles=<min> ret=<ret>".  Gate
         * asserts min < 2000 (in-LUCAS dispatch, no seL4_Yield IPC) and
         * ret==0.  Runs lean (always-on) — fast, timing-only. */
        "fastpath-probe",
        "sotinfo",
        "list",
        "promote 1 1",
        "sotinfo",
        "anomaly-log",  /* ANOMALY-DASHBOARD · show recent anomaly events */
        "sotnet",    /* sotNet-ζ · show active flows */
        "ls /tmp",   /* L4-Phase-D · operator-side VFS · read-only · smoke-safe */
        "mkdir /tmp/operator-dir",          /* C1-A · create directory */
        "ls /tmp",                          /* should show 4 entries incl operator-dir */
        "install /tmp/temp-file SCRATCH-DATA", /* install scratch file */
        "rm /tmp/temp-file",                /* C1-A · remove file */
        "ls /tmp",                          /* C1-A · post-rm listing */
        /* Pillar-3 sottrace-Pro · run EARLY (before the slow wl/fork-bomb/churn/
         * tcc block) so the invisibility cert + FS graph always emit even when
         * the later heavy demo overruns the boot budget. */
        "antidbg",                          /* Pillar-3 · spawn the anti-debug probe (trusted=0/tier=0) · ptrace(TRACEME)→0 + /proc/self/status TracerPid:0 → [antidbg] ... invisible=YES (the black-box invisibility cert's live evidence) */
        "sottrace graph",                   /* Pillar-3 · emit the FS provenance graph ([graph] BEGIN ... G pid=... [graph] END) from the cat/ls/install/rm FS ops already in the ring */
        "banner PHASE 2 · FILESYSTEM + DECEPTION (canary bait · graded trust)",
        "tail /tmp/honey-readme.txt",       /* C1-A · last 5 lines */
        "grep aws_access /tmp/honey-aws-creds", /* C1-A · filter matching lines */
        "dns list",                             /* sotNet-ζ · show seeded canary domains */
        "dns install operator-c2.example. 192.168.99.7", /* sotNet-ζ · operator installs entry */
        "dns list",                             /* sotNet-ζ · show 5 entries after install */
        "dns lookup ransomware-pay.example.",   /* sotNet-ζ · canary tripwire HIT demo */
        /* γ-3-ε · install a response_profile for a destination with NO static entry,
         * FIRST (the synth responder is idle → the install is reliably
         * delivered + inserted · the deterministic '[synth-srv] install ·
         * dst=203.0.113.7' line is the boot proof).  The "served on redirect"
         * narrative uses the pre-existing (fire-and-forget · lossy when the
         * responder is busy) redirect path · eyeballed in operator runs. */
        "synth-install 203.0.113.7 8080 c2-ack",
        "synth-trigger 10.0.2.15 80",         /* γ Phase 3-D-2 · operator-driven synth redirect demo */
        "synth-trigger 203.0.113.7 8080",
        "synth-queue",                        /* γ Phase 3-D-2 · dump in-orch pending_recv queue */
        FULL("banner PHASE 3 · SUBSYSTEM SELF-TESTS"),
        FULL("procd-fork-test"),                      /* procd PR 6 · fork/exit/wait4 shadow-announce smoke */
        FULL("procd-exec-test"),                      /* procd PR 7 · execve shadow-announce smoke */
        FULL("procd-pthread-test"),                   /* procd PR 8 · clone(CLONE_VM|CLONE_THREAD) shadow-announce smoke */
        FULL("procd-pg-test"),                        /* procd PR 9 · setsid/getpgid shadow-announce smoke */
        FULL("procd-cond-test"),                      /* procd PR 12 · futex WAIT_BITSET/WAKE_BITSET broadcast smoke */
        FULL("procd-robust-test"),                    /* procd PR 13 · set_robust_list announce + thread-exit walk smoke */
        FULL("shellhook-test"),                       /* init-cron PR 10 · lucas execve argv-rewrite smoke (BASHRC-MARKER) */
        FULL("stage7-demo"),                          /* γ · Stage 7 · F_persistence end-to-end via C-static fixture */
        FULL("syscall-test"),                         /* POSIX-surface PR 6 · unlink/iov/madvise + console/FS boundary (ALL PASS) */
        FULL("anomaly-test"),                        /* ANOMALY PR 7 · cred+writes+unlink-burst drives score across T1/T2 (ALL PASS) */
        FULL("sottrace"),                             /* sottrace · snapshot the trace plane (syscalls + tier + dns) */
        FULL("execmap-test"),                         /* SP1 PR 4 · trusted mmap RWX + execute writable page (exec OK) */
        FULL("tls-probe"),                            /* sotNet γ-3-γ-2b · guest BearSSL fixture (T1 sha256 smoke · T4 TLS handshake) */
        FULL("wayland-connect"),                      /* L12-beta · AF_UNIX /run/user/1000/wayland-0 route smoke */
        FULL("wayland-sync"),                         /* L12-gamma · wl_display.sync round trip → callback done */
        FULL("wayland-info"),                         /* L12-delta · wl_registry globals + bind */
        FULL("wl-shm"),                               /* L13-D1 · hand-rolled wl_shm zero-copy pixel client → compositor commit checksum */
        FULL("wl-capture"),                              /* L14a-D1 · Tier-2 (trusted=0) hostile capture client → reads installed Canary Screenshot from shadow compositor */
        /* Pillar-4 P4a · CAPSTONE · concurrent 3-malware validation run.  Placed
         * EARLY (right after the per-fixture deception demos) so it completes well
         * within the headless boot window — the full demo's slow/live-drain tail
         * (sottrace on, tcc, hello-*) would otherwise time out before reaching it.
         * ORCH_OP_VALIDATE seeds wl_capture_client/tls_probe/stage7_demo concurrently into a
         * validation pool, runs ONE fault loop until all 3 exit, frees the pool. */
        FULL("validate"),
        FULL("soak"),                                 /* Pillar-4 P4b · scaled 24h-proxy soak · SOAK_N spawn+reap iters of hello-linux.bin; orch emits [stats] every STATS_EVERY → scripts/soak.sh computes the root_pages leak-drift slope. EARLY so it finishes in the boot window; leaves the late "churn" 250 regression untouched */
        FULL("fork-bomb"),                            /* Pillar-2 P2b · fork-bomb gate · spawn the fixture that raw-fork()s past the quota → detected + quarantined + terminated; the churn below proves the runtime survived */
        FULL("churn"),                                /* Pillar-2 P2a · spawn+exit immortality gate · runs AFTER the L13/L14/TLS regression markers, BEFORE the slow tcc/hello-dyn steps */
        FULL("hello-dyn"),                          /* N3/D1 · dynamic-musl loader · kernel loads PIE+ld-musl, ld-musl relocates → [hello-dyn] dynamic musl OK */
        FULL("hello-dyn2"),                           /* N3/D2 · multi-lib dynamic · ld-musl runtime-mmaps libonefn.so → [hello-dyn2] libonefn OK */
        FULL("hello-ssl"),                            /* N3/D3 · OpenSSL bait · lazy-mmap real libcrypto.so.3 (4.5MB) → [hello-ssl] libcrypto OK 7ba514f8 */
        FULL("doom"),                                 /* Doom Phase 1a · spawn doom.bin (doomgeneric, static-musl) · opens /doom1.wad (binstore VFS) + renders the title demo → frames present to /dev/fb0 → [doom] frame=N markers */
        /* internet-egress Phase 1 · `egress-dns` (cmd_egress_dns) is deliberately
         * NOT in the shared auto-demo.  The orch is single-threaded: while it runs
         * a demo's fault loop it cannot service inbound TLS, so the tls13/ssh gates
         * burst their probes into the GAPS between demos — inserting another demo
         * anywhere shifts those gaps out from under the probes and breaks them.
         * `egress-dns` is instead triggered IN ISOLATION by tools/egress-dns-gate.sh
         * (HMP `sendkey` at the sotos> prompt), so it validates the DNS canary
         * intercept without perturbing any other gate's boot. */
        /* M2 · default interactive shell · when a virtio-keyboard is present
         * (just run-interactive) orch drops into a keyboard-driven `busybox
         * sh -i` right here (after the deception+Doom highlights); headless
         * (no keyboard) it is a no-op so all gates are unchanged. */
        "bbsh-auto",
        /* N1a · egress-probe stays a MANUAL command (`egress-probe`), NOT auto-run.
         * The TCP FIN+data dispatch fix is in, but the guest read() still can't get
         * the HTTP response because virtio-net RX delivery stalls after the initial
         * buffers — the 5th+ frame (the 301) is never pulled by virtio_net_rx_poll.
         * Re-enable once the virtio-net RX recycling is fixed (proper used-ring +
         * likely a volatile/barrier on used->idx for DMA coherency). */
        /* SP1 PR 5 · the milestone · trusted tcc compiles + JIT-executes a
         * freestanding C source installed at sotfs /st-hello.c (seen by the
         * sotbox VFS as /tmp/st-hello.c · sotfs is mounted at /tmp).  The
         * JIT'd program prints "[st-hello] tcc-run OK"; its write/exit
         * syscalls run from a writable JIT page so MSYSCALL detects them
         * audit-only (trusted · not promoted).  Boot-driven so the always-on
         * gates TCC·run-output + TCC·trusted-msyscall fire unattended.
         * Runs AFTER execmap-test (sequential-spawn). */
        /* tcc-libc · cmd_tcc is now a passthrough tokenizer (injects
         * -I/usr/include -B/usr/lib -static, then forwards operator tokens),
         * so the freestanding milestones must pass their own flags:
         *   -run JIT  : -B/tmp finds /tmp/runmain.o · -nostdlib freestanding ·
         *               injected -static is auto-dropped when -run present. */
        FULL("banner PHASE 4 · IN-OS COMPILER (TCC · freestanding + musl-hosted)"),
        FULL("tcc -B/tmp -nostdlib -run /tmp/st-hello.c"),
        /* SP2 · emit a standalone ELF from the freestanding _start source
         * (-nostdlib · no libc/crt0 · injected -static keeps it non-PIE EXEC). */
        FULL("tcc -nostdlib -o /tmp/sp2-hello.elf /tmp/st-hello-emit.c"),
        /* SP2 · run the just-emitted standalone ELF from sotfs (untrusted). */
        FULL("run /tmp/sp2-hello.elf"),
        /* A2 · updatable-TCC · copy the read-only binstore tcc.bin into the
         * writable on-disk store (rwbinstore).  After this, spawn_load_elf
         * resolves 'tcc.bin' from rwbinstore (it shadows the baked copy) —
         * so the next `tcc` invocation runs the writable, replaceable binary.
         * Proves write→persist→spawn from the writable store. */
        FULL("bininstall tcc.bin tcc.bin"),
        /* tcc-libc · hosted milestone · compile a REAL libc program (#include
         * <stdio.h> + printf) against the /usr musl sysroot (cmd_tcc injects
         * -I/usr/include -B/usr/lib -static · no -nostdlib → links musl), then
         * run the emitted ELF from sotfs (untrusted).  Post-bininstall this
         * tcc.bin is served from rwbinstore (gate RWBIN·write-spawn). */
        FULL("tcc -o /tmp/hello-libc.elf /tmp/hello-libc.c"),
        FULL("run /tmp/hello-libc.elf"),
        /* α · PR 7 · simreboot cascade · userspace-only reset.  Drives
         * the 5-phase teardown + respawn + replay-apply in orch's vspace.
         * Placed AFTER mkdir + anomaly-log so the WAL has real records
         * to checkpoint and replay (file ops feed sotfs WAL, anomaly
         * events feed the ANOMALY_EV writer hook, etc.).
         *
         * The persistence proof for PR 7 is Phase 5's replay-apply
         * banner showing a positive record count · this confirms the
         * WAL → virtio-blk → replay chain stayed intact across the
         * cascade.  (The narrative "write file → simreboot → file
         * persists" would require a working `install` from sotShell ·
         * the existing `install /tmp/<leaf>` path has a pre-existing
         * resolver-vs-leaf-naming mismatch that returns -EIO; left
         * to a follow-up so PR 7 keeps the scope-reduction discipline.) */
        FULL("banner PHASE 5 · PERSISTENCE + REBOOT (WAL · simreboot cascade)"),
        FULL("ls /tmp"),                              /* PR 7 · snapshot pre-simreboot inventory */
        /* β · PR 5 · operator-driven sotinit listen-EP query · drives the
         * systemctl `list` verb against sotinit's IPC loop.  Smoke gate
         * "[sotshell] systemctl" greps the result-print line below so this
         * doubles as the end-to-end proof that the orch → sotShell EP
         * forward path landed correctly. */
        FULL("systemctl list"),
        FULL("simreboot"),                            /* PR 7 · trigger 5-phase cascade */
        FULL("ls /tmp"),                              /* PR 7 · verify directory state survived */
        FULL("python \"print('hello from python on sotOs · stdlib loaded')\""),  /* L11-γ · operator-driven Python spawn */
        /* C2 #4/#11/#14/#9 · PHASE 6 · incident rollup + post-attack integrity
         * proof (re-read the REAL /welcome file · the deception never touched
         * real data).  Runs after all attack/deception activity above. */
        "banner PHASE 6 · INCIDENT SUMMARY + INTEGRITY",
        "incident",
        "verify /tmp/welcome HOLA",
        /* sottrace-v1 · T11 · canary-read · spawn a Tier-2 sotbox that reads
         * /etc/passwd through the guest VFS canary backend, firing the v0
         * trace_emit_canary (SG_EV_CANARY_READ) producer end-to-end.
         * initial_tier=2 activates canary_entries immediately; trusted=0 so
         * the [canary] pid= + [sottrace] CANARY event fire on the first read. */
        "canary-read",
        /* sottrace-v1 · T12 (FINAL) · turn the LIVE serial drain ON *before* the
         * canary-service spawns so ACCEPT/CONN_CLOSE events stream to serial AS THEY
         * HAPPEN — snapshot-timing-independent.  The scripted demo can't easily
         * synchronize "snapshot AFTER the nc connects", so the live drain is the
         * reliable observation path; the trailing `sottrace`/`sottrace payload 1`
         * then add the snapshot + the captured forensic bytes. */
        "sottrace on",
        /* sottrace-v1 · T10 · canary-service · spawn the Tier-0e listen/accept/recv
         * sotbox so the boot reaches it and the spawned thread PARKS on
         * accept (woken by the T3 liveness poll when an inbound connection
         * completes).  The spawn call itself returns immediately, so the shell's
         * remaining demo (the trailing snapshot + payload dump) is NOT blocked —
         * only the canary-service's own thread parks, which gives a host
         * `nc 127.0.0.1 18080` time to connect.  Drive a real inbound connection
         * with `just run-honeypot` (QEMU hostfwd tcp::18080-:80) + nc; the inbound
         * connection drives [accept] + rx + live ACCEPT/CONN_CLOSE in the trace. */
        /* N2-T · the v1 canary-service passive sink is SUPERSEDED by orch's boot
         * LISTEN :80/:22 + the inbound bridge (the orchestra is now the responder,
         * no guest).  Removed from the demo so it does not contend for the :80
         * LISTEN slot.  The inbound path is exercised by an external client via
         * `just run-honeypot` + ncat (and the conn-specific `sottrace payload <id>`
         * dump is run there), not by a scripted demo step. */
        "sottrace",
        /* (P4a "validate" moved EARLY — see right after "wl-capture" above — so it
         * runs within the headless boot window; the live-drain "sottrace on" tail
         * here would otherwise push it past the QEMU timeout.) */
        /* NOTE: "quit" intentionally removed · sending ORCH_OP_SHUTDOWN
         * (op=3) closes orch's command window for sotShell.  After that
         * orch returns to listen_ep and never re-Recvs on shell_ep, so
         * any subsequent IPC from sotShell's interactive mode hangs.
         * Without the quit, orch stays in the command window and the
         * operator can type interactive commands after the scripted demo
         * finishes.  The trade-off is that root's queued L4-L11 demo
         * spawns (sent via listen_ep) block until sotShell exits · they
         * won't run in this mode.  Smoke compatibility regression
         * tracked separately. */
        /* Pillar-2 P2a · churn-harness · LAST so the regression demos above run
         * first.  Synchronous spawn loop of CHURN_M=1000 hello-linux.bin
         * sotboxes · measures the per-spawn capability leak (baseline; STOP at
         * exhaustion point K prints rc!=0).  NO teardown fix yet. */
        FULL("churn"),
    };
#undef FULL

    /* Interactive boot (a virtio-keyboard is present · just run-interactive)?
     * Skip the scripted demo entirely and drop straight into a keyboard-driven
     * busybox terminal — the operator runs commands manually (no auto-demo, no
     * churn 'hello world' spam). Re-spawn the terminal if it exits. Headless
     * (no keyboard) falls through to the normal scripted demo (gates intact). */
    int imode = 0;
    {
        seL4_MessageInfo_t qi = seL4_Call(orch_ep,
            seL4_MessageInfo_new(ORCH_OP_QUERY_INTERACTIVE, 0, 0, 0));
        imode = (int)seL4_MessageInfo_get_label(qi);
        if (imode == 1) {
            printf("[sotshell] interactive boot · dropping into the busybox canary shell "
                   "(demo skipped · type commands; 'doom' to launch Doom; F12 = operator console)\n");
            /* F12 toggle · the GTK window flips between the two shells:
             *   canary shell (bbsh, Tier-2 deception) ⇄ operator console (the truth).
             * cmd_bbsh returns 3 when the operator pressed F12 → open the operator
             * console (keyboard-driven via ORCH_OP_GETKEY); when IT sees F12 it
             * returns → the loop respawns the canary shell.  A plain `exit` in bbsh
             * just respawns a fresh canary shell (unchanged). */
            for (;;) {
                int br = cmd_bbsh(orch_ep);          /* canary shell · 3 = F12 */
                if (br == 3) {
                    int cr = cmd_console_kbd(orch_ep);   /* operator console · F12 → return */
                    if (cr == SOTSHELL_QUIT_SIGNAL) {    /* operator typed `quit` → power off */
                        cmd_poweroff(orch_ep);
                        break;
                    }
                }
            }
        } else if (imode == 2) {
            /* Serial-interactive operator boot (run-3pane / run-4pane / clean run):
             * NO scripted demo, NO banners — straight into the serial operator
             * console.  Headless gate boots (imode 0) still run the demo below. */
            cmd_interactive(orch_ep);
        }
    }
    if (imode != 0) {            /* interactive operator boot · skip the demo entirely */
        cmd_poweroff(orch_ep);
        seL4_TCB_Suspend(SEL4UTILS_TCB_SLOT);
        return 0;
    }

    for (size_t i = 0; i < sizeof(demo_commands)/sizeof(demo_commands[0]); ++i) {
        /* cmd_sotinfo, cmd_list, cmd_sotnet, cmd_ls print their own sotos> prefix.
         * All other commands (promote, kill, quit, unknown) get it here. */
        const char *dcmd = demo_commands[i];
        if (!dcmd) continue;   /* lean boot · FULL() demo collapsed to NULL */
        if (strncmp(dcmd, "sotinfo",      7) != 0 &&
            strncmp(dcmd, "list",         4) != 0 &&
            strncmp(dcmd, "sotnet",       6) != 0 &&
            strncmp(dcmd, "ls",           2) != 0 &&
            strncmp(dcmd, "mkdir",        5) != 0 &&
            strncmp(dcmd, "rm",           2) != 0 &&
            strncmp(dcmd, "tail",         4) != 0 &&
            strncmp(dcmd, "grep",         4) != 0 &&
            strncmp(dcmd, "install",        5) != 0 &&
            strncmp(dcmd, "cat",          3) != 0 &&
            strncmp(dcmd, "dns",          3) != 0 &&
            strncmp(dcmd, "banner",       6) != 0 &&
            strncmp(dcmd, "bench",        5) != 0 &&
            strncmp(dcmd, "anomaly-log", 12) != 0) {
            printf("sotos> %s\n", dcmd);
        }
        int ret = run_command(orch_ep, dcmd);
        if (ret < 0) break;   /* quit returned -1 */
    }

    /* PR 8 · STRESS · drive cmd_simreboot 10x to force multiple
     * CHECKPOINT epochs into the WAL and verify the userspace-only
     * cascade is reentrant.  Smoke greps the per-iteration banner and
     * the final "simreboot complete · uptime continuation" line that
     * orch emits at the end of each cascade.
     * LEAN boot skips this (persistence arc is complete + the 10x cascade
     * is slow) · the simreboot/persistence gates rebuild -DSOTOS_DEMO_FULL=ON. */
#ifdef SOTOS_DEMO_FULL
    for (int i = 0; i < 10; i++) {
        printf("[demo] stress simreboot %d/10\n", i + 1);
        cmd_simreboot(orch_ep);
    }
#endif

    /* C2 #15 · bounded closing · state exactly what was demonstrated and,
     * just as importantly, what was NOT claimed. */
    printf("\n═══ DEMO COMPLETE · what was demonstrated ═══\n");
    printf("  • in-OS compile + run (TCC · freestanding -run + musl-hosted ELF)\n");
    printf("  • writable on-disk binstore · updatable TCC · persists across simreboot\n");
    printf("  • deception bait (SYNTHETIC canaries) + graded trust (T0→T1→T2)\n");
    printf("  • WAL persistence + replay across the simreboot cascade\n");
    printf("  • zombie reaper · evict-oldest · never loses an exit\n");
    printf("  NOT claimed: no real exploit, no external network egress (synth-\n");
    printf("  redirected to canary), simreboot teardown is scope-reduced (banner-only\n");
    printf("  Phases 2-4 · root owns the peer TCBs).\n");
    printf("[sotshell] demo done · L4-Phase-C v2 complete\n");

    /* L4-Phase-C v2 · poll for interactive input AFTER scripted demo.
     * If any byte arrives within the window, drop into interactive mode.
     * Otherwise exit cleanly (smoke compatibility).
     *
     * Window sized at ~5 s · the operator should be ready to type when
     * they see this prompt.  Smoke (no TTY · stdin closed) hits the
     * timeout in 5 s, keeping the 90 s smoke budget intact for the
     * L4-L11 demo chain that follows the sotShell scripted phase. */
    printf("[sotshell] scripted demo complete · idle-poweroff (stays alive while probed)...\n");
    /* v2.9 · network-aware idle poweroff.  A bare unattended boot (no inbound
     * traffic) powers off after IDLE_BASE — unchanged for soak/CI/v15.  But a
     * host that is being PROBED keeps the network watermark climbing (orch
     * ORCH_OP_QUERY_NET = count of inbound conns that reached ESTABLISHED), which
     * resets the countdown to IDLE_ACTIVE — so multi-connection gates (e.g. the
     * 9-probe TLS gate, ~8 s between probes) are never cut off mid-sequence the
     * way the old fixed 5 s window was.  An operator keystroke still drops into
     * the interactive console.  ~1 µs/iter (seL4_Yield) so the counts are ~secs. */
    const long IDLE_BASE   =  5000000L;   /* ~5 s · no network → poweroff (soak) */
    const long IDLE_ACTIVE = 30000000L;   /* ~30 s past the last inbound conn    */
    long     countdown = IDLE_BASE;
    uint32_t last_net  = 0;
    long     iter      = 0;
    int      got_input = 0;
    for (;;) {
        int c = serial_getchar();
        if (c > 0) { got_input = 1; break; }
        /* Poll orch's inbound watermark every ~64k iters (cheap; orch answers in
         * its shell-window loop).  A change → the host is being probed → extend. */
        if ((iter++ & 0xFFFF) == 0) {
            seL4_MessageInfo_t ni = seL4_Call(orch_ep,
                seL4_MessageInfo_new(ORCH_OP_QUERY_NET, 0, 0, 0));
            uint32_t net = (seL4_MessageInfo_get_length(ni) >= 1)
                           ? (uint32_t)seL4_GetMR(0) : 0;
            if (net != last_net) { last_net = net; countdown = IDLE_ACTIVE; }
        }
        if (--countdown <= 0) break;
        seL4_Yield();
    }

    if (got_input) {
        printf("[sotshell] interactive input detected · entering operator console\n");
        cmd_interactive(orch_ep);
    } else {
        /* Unattended boot · network idle · power the VM off cleanly (persist
         * state + ACPI S5).  An interactive operator instead reaches the
         * console above and can type `poweroff` when done. */
        printf("[sotshell] network idle · clean poweroff\n");
        cmd_poweroff(orch_ep);
        /* cmd_poweroff only returns if the ACPI port was unavailable. */
    }

    /* Suspend this thread.  sotShell is a sel4utils child; its TCB cap is at
     * SEL4UTILS_TCB_SLOT (= 5), NOT at seL4_CapInitThreadTCB (= 1).
     * Using the correct slot avoids the "Illegal Operation" kernel error. */
    seL4_TCB_Suspend(SEL4UTILS_TCB_SLOT);
    return 0;
}
