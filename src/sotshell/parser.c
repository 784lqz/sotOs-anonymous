/*
 * sotOs · sotShell · v0.7 · S2 · parser layer implementation
 *
 * Tokenizer with quote-awareness + pipe/redirect detection +
 * glob expansion.  Returns a `parsed_pipeline` structure.
 *
 * Approach:
 *  1. tokenize() walks the input one byte at a time, peeling off
 *     tokens.  Quoted runs ('...' or "...") become a single token
 *     and never participate in operator detection.
 *  2. classify_token() identifies operators (|, >, >>, <, 2>).
 *  3. expand_glob_into_pool() rewrites a wildcard token into 1..N
 *     pooled tokens via glob_expand().
 *  4. assemble_cmds() walks the token list, splitting on '|' and
 *     consuming redirection operators.
 *  5. rebuild_expanded_line() composes a single-line representation
 *     for the legacy strcmp dispatch when no pipes/redir are present.
 *
 * Bounded.  No malloc.  No retry loops.
 */
#include "parser.h"
#include "glob.h"
#include <orch/proto.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* External orch EP set by sotshell main.c · used during glob expansion. */
extern seL4_CPtr g_parser_orch_ep;
seL4_CPtr g_parser_orch_ep = 0;

/* ------------------------------------------------------------------ */
/* Token kinds                                                         */
/* ------------------------------------------------------------------ */
enum tok_kind {
    TK_WORD = 0,
    TK_PIPE,       /* | */
    TK_REDIR_IN,   /* < */
    TK_REDIR_OUT,  /* > */
    TK_APPEND,     /* >> */
    TK_REDIR_ERR,  /* 2> · treated like > for δ-1 */
};

#define MAX_TOKENS 64

struct token {
    enum tok_kind kind;
    char *text;          /* for TK_WORD only · points into token_pool */
};

/* ------------------------------------------------------------------ */
/* pool_strdup — copy `s` (length `n`) into pool, return pointer.     */
/* Returns NULL on overflow.                                          */
/* ------------------------------------------------------------------ */
static char *pool_strdup(struct parsed_pipeline *p, const char *s, size_t n)
{
    if (p->token_pool_used + n + 1 > sizeof(p->token_pool)) return NULL;
    char *dst = p->token_pool + p->token_pool_used;
    memcpy(dst, s, n);
    dst[n] = '\0';
    p->token_pool_used += n + 1;
    return dst;
}

/* ------------------------------------------------------------------ */
/* tokenize — split `line` into operator + word tokens.               */
/* Quote-aware.  Returns number of tokens emitted, or -1 on error.    */
/* ------------------------------------------------------------------ */
static int tokenize(const char *line,
                    struct parsed_pipeline *pipeline,
                    struct token *toks, int max_toks,
                    int *had_quote_out)
{
    int n = 0;
    int had_quote = 0;
    const char *p = line;
    char buf[MAX_TOKEN_LEN];

    while (*p) {
        /* Skip whitespace. */
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        if (n >= max_toks) return -1;

        /* Operator: | */
        if (*p == '|') {
            toks[n].kind = TK_PIPE;
            toks[n].text = NULL;
            n++;
            p++;
            continue;
        }
        /* Operator: > or >> */
        if (*p == '>') {
            if (p[1] == '>') {
                toks[n].kind = TK_APPEND;
                p += 2;
            } else {
                toks[n].kind = TK_REDIR_OUT;
                p += 1;
            }
            toks[n].text = NULL;
            n++;
            continue;
        }
        /* Operator: < */
        if (*p == '<') {
            toks[n].kind = TK_REDIR_IN;
            toks[n].text = NULL;
            n++;
            p++;
            continue;
        }
        /* Operator: 2> · only when '2' is followed immediately by '>' */
        if (*p == '2' && p[1] == '>') {
            toks[n].kind = TK_REDIR_ERR;
            toks[n].text = NULL;
            n++;
            p += 2;
            continue;
        }

        /* Word token · accumulate until unquoted whitespace or operator. */
        size_t bp = 0;
        while (*p && bp < sizeof(buf) - 1) {
            char c = *p;
            if (c == ' ' || c == '\t') break;
            if (c == '|' || c == '<' || c == '>') break;
            if (c == '2' && p[1] == '>') break;

            if (c == '\'' || c == '"') {
                /* Quoted run: consume until matching quote. */
                char q = c;
                had_quote = 1;
                p++;   /* skip opening quote */
                while (*p && *p != q && bp < sizeof(buf) - 1) {
                    buf[bp++] = *p++;
                }
                if (*p == q) p++;   /* skip closing quote */
                continue;
            }

            buf[bp++] = c;
            p++;
        }
        buf[bp] = '\0';

        if (bp == 0) continue;   /* defensive · shouldn't happen */

        /* Glob expansion?  Only on words that contain * or ? AND were not
         * quoted in their entirety.  For δ-1 we apply glob if any wildcard
         * present (sufficient for the demo). */
        int has_wild = 0;
        for (size_t i = 0; i < bp; ++i) {
            if (buf[i] == '*' || buf[i] == '?') { has_wild = 1; break; }
        }

        if (has_wild && g_parser_orch_ep) {
            pipeline->has_glob_or_quote = 1;
            struct glob_result gr;
            /* Reuse the back of token_pool as scratch buf.  We won't grow it
             * here · glob_expand writes into its own buf which we then copy
             * into the pool. */
            char scratch[MAX_GLOB_EXPANSIONS * MAX_GLOB_PATH_LEN];
            int m = glob_expand(buf, g_parser_orch_ep, &gr,
                                scratch, sizeof(scratch));
            if (m > 0) {
                for (int i = 0; i < gr.n_matches; ++i) {
                    if (n >= max_toks) break;
                    char *t = pool_strdup(pipeline, gr.out_paths[i],
                                          strlen(gr.out_paths[i]));
                    if (!t) break;
                    toks[n].kind = TK_WORD;
                    toks[n].text = t;
                    n++;
                }
                continue;
            }
            /* fall through · keep literal token */
        }

        char *t = pool_strdup(pipeline, buf, bp);
        if (!t) return -1;
        toks[n].kind = TK_WORD;
        toks[n].text = t;
        n++;
    }

    if (had_quote_out) *had_quote_out = had_quote;
    return n;
}

/* ------------------------------------------------------------------ */
/* assemble_cmds — walk tokens, populate pipeline->cmds[].            */
/* Returns 0 on success, -1 on error.                                 */
/* ------------------------------------------------------------------ */
static int assemble_cmds(struct token *toks, int n_toks,
                         struct parsed_pipeline *pipeline)
{
    pipeline->n_cmds = 1;
    pipeline->cmds[0].argc = 0;
    pipeline->cmds[0].stdin_path = NULL;
    pipeline->cmds[0].stdout_path = NULL;
    pipeline->cmds[0].stdout_append = 0;

    int ci = 0;
    int i = 0;
    while (i < n_toks) {
        struct token *t = &toks[i];
        switch (t->kind) {
        case TK_WORD:
            if (pipeline->cmds[ci].argc >= MAX_ARGV - 1) return -1;
            pipeline->cmds[ci].argv[pipeline->cmds[ci].argc++] = t->text;
            pipeline->cmds[ci].argv[pipeline->cmds[ci].argc] = NULL;
            i++;
            break;
        case TK_PIPE:
            pipeline->has_pipes_or_redir = 1;
            if (ci + 1 >= MAX_PIPELINE_COMMANDS) return -1;
            ci++;
            pipeline->cmds[ci].argc = 0;
            pipeline->cmds[ci].stdin_path = NULL;
            pipeline->cmds[ci].stdout_path = NULL;
            pipeline->cmds[ci].stdout_append = 0;
            pipeline->n_cmds = ci + 1;
            i++;
            break;
        case TK_REDIR_IN:
            pipeline->has_pipes_or_redir = 1;
            if (i + 1 >= n_toks || toks[i+1].kind != TK_WORD) return -1;
            pipeline->cmds[ci].stdin_path = toks[i+1].text;
            i += 2;
            break;
        case TK_REDIR_OUT:
        case TK_REDIR_ERR:
            pipeline->has_pipes_or_redir = 1;
            if (i + 1 >= n_toks || toks[i+1].kind != TK_WORD) return -1;
            pipeline->cmds[ci].stdout_path = toks[i+1].text;
            pipeline->cmds[ci].stdout_append = 0;
            i += 2;
            break;
        case TK_APPEND:
            pipeline->has_pipes_or_redir = 1;
            if (i + 1 >= n_toks || toks[i+1].kind != TK_WORD) return -1;
            pipeline->cmds[ci].stdout_path = toks[i+1].text;
            pipeline->cmds[ci].stdout_append = 1;
            i += 2;
            break;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* rebuild_expanded_line — concat all argv tokens of cmd[0] with     */
/* single spaces.  Used to fall through to legacy dispatch when the   */
/* pipeline is just one command with no pipes/redir.                  */
/* ------------------------------------------------------------------ */
static void rebuild_expanded_line(struct parsed_pipeline *p)
{
    size_t pos = 0;
    for (int i = 0; i < p->cmds[0].argc; ++i) {
        const char *w = p->cmds[0].argv[i];
        size_t wlen = strlen(w);
        if (i > 0) {
            if (pos + 1 >= sizeof(p->expanded_line)) break;
            p->expanded_line[pos++] = ' ';
        }
        if (pos + wlen >= sizeof(p->expanded_line)) break;
        memcpy(p->expanded_line + pos, w, wlen);
        pos += wlen;
    }
    if (pos >= sizeof(p->expanded_line)) pos = sizeof(p->expanded_line) - 1;
    p->expanded_line[pos] = '\0';
}

/* ------------------------------------------------------------------ */
/* dbg_log_tokens — emit [parser] line with token summary             */
/* ------------------------------------------------------------------ */
static void dbg_log_tokens(struct token *toks, int n_toks,
                           struct parsed_pipeline *p)
{
    printf("[parser] tokens=[");
    for (int i = 0; i < n_toks; ++i) {
        if (i) printf(",");
        switch (toks[i].kind) {
        case TK_WORD:      printf("%s", toks[i].text); break;
        case TK_PIPE:      printf("|"); break;
        case TK_REDIR_IN:  printf("<"); break;
        case TK_REDIR_OUT: printf(">"); break;
        case TK_APPEND:    printf(">>"); break;
        case TK_REDIR_ERR: printf("2>"); break;
        }
    }
    printf("] n_cmds=%d", p->n_cmds);
    if (p->cmds[0].stdout_path) {
        printf(" redir_out=%s", p->cmds[0].stdout_path);
    }
    if (p->cmds[0].stdin_path) {
        printf(" redir_in=%s", p->cmds[0].stdin_path);
    }
    printf("\n");
}

/* ------------------------------------------------------------------ */
/* sotshell_parse — public API                                        */
/* ------------------------------------------------------------------ */
int sotshell_parse(const char *line, struct parsed_pipeline *out)
{
    if (!line || !out) return -1;
    memset(out, 0, sizeof(*out));

    struct token toks[MAX_TOKENS];
    int had_quote = 0;
    int n = tokenize(line, out, toks, MAX_TOKENS, &had_quote);
    if (n < 0) return -1;
    if (n == 0) {
        out->n_cmds = 0;
        out->expanded_line[0] = '\0';
        return 0;
    }
    if (had_quote) out->has_glob_or_quote = 1;

    if (assemble_cmds(toks, n, out) < 0) return -1;

    /* If pipeline is non-trivial OR an interesting feature was used, log. */
    if (out->has_pipes_or_redir || out->has_glob_or_quote) {
        dbg_log_tokens(toks, n, out);
    }

    rebuild_expanded_line(out);
    return 0;
}
