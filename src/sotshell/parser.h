/*
 * sotOs · sotShell · v0.7 · S2 · parser layer
 *
 * Tokenizer with quote-awareness + pipe/redirect detection +
 * glob expansion.  Returns a `parsed_pipeline` structure that
 * the dispatch layer can use to execute single-command or
 * piped commands with stdin/stdout redirection.
 *
 * For δ-1 the executor only handles single-command + redirection;
 * multi-command pipelines log a "not yet supported" line and run
 * the first command directly.
 *
 * Bounded: MAX_PIPELINE_COMMANDS, MAX_ARGV, MAX_GLOB_EXPANSIONS.
 * No malloc · all storage lives inside the parsed_pipeline struct.
 */
#ifndef SOTSHELL_PARSER_H
#define SOTSHELL_PARSER_H

#include <stddef.h>

#define MAX_PIPELINE_COMMANDS 4
#define MAX_ARGV              16
#define MAX_TOKEN_LEN         128
#define MAX_LINE_LEN          512

struct cmd {
    int   argc;
    char *argv[MAX_ARGV];          /* points into pipeline.token_pool */
    const char *stdin_path;        /* NULL if no redir */
    const char *stdout_path;       /* NULL if no redir */
    int   stdout_append;           /* 1 for >>, 0 for > */
};

struct parsed_pipeline {
    int n_cmds;
    struct cmd cmds[MAX_PIPELINE_COMMANDS];
    int has_pipes_or_redir;        /* 1 if pipeline non-trivial */
    int has_glob_or_quote;         /* 1 if any glob/quote was processed */

    /* Internal storage: tokens packed into pool, argv[] points into it. */
    char token_pool[MAX_LINE_LEN * 4];   /* room for glob expansions */
    size_t token_pool_used;

    /* Reconstructed expanded line (for falling through to legacy dispatch
     * when pipeline is single-command without pipes/redir). */
    char expanded_line[MAX_LINE_LEN];
};

/*
 * sotshell_parse — parse a raw input line into a pipeline structure.
 * Returns 0 on success, negative on error.  On success caller may
 * inspect `out->has_pipes_or_redir` and `out->n_cmds`.
 *
 * Tokenization rules:
 *  - Single quotes 'foo bar' or double quotes "foo bar" produce one token.
 *  - No variable expansion, no escape sequences.
 *  - Operators recognised: |, >, <, >>, 2> (2> is consumed but stderr is
 *    treated identically to stdout for δ-1).
 *  - Tokens containing * or ? are passed to glob_expand for expansion.
 */
int sotshell_parse(const char *line, struct parsed_pipeline *out);

#endif /* SOTSHELL_PARSER_H */
