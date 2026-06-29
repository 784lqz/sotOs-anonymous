# sotOs-procd-pg-test · PR 9 setsid/setpgid/getpgid smoke fixture

Tiny static x86_64 Linux binary that exercises the PR 9 OP_SETSID +
OP_SETPGID + OP_GETPGID shadow-announce path against the procd process
server.  The fixture forks once; the child then calls `getpgrp()`,
`setsid()`, `setpgid(0, 0)`, and `getpgid(0)` and writes a single-line
summary to stdout before exiting with 0 on success / 1 on loop failure.
The `setpgid(0, 0)` call is the no-op invariant check after setsid (the
child is already a group leader of a group named after its own pid),
present so the OP_SETPGID announce path fires alongside OP_SETSID.

## Why fork-first

A freshly procd-spawned slot has `pgid == fake_pid` (its own group
leader · inherited from `procd_handle_spawn`'s defaults).  Linux
`setsid()` returns EPERM in that state, mirrored 1:1 by
`procd_handle_setsid`.  `fork()` copies `pgid` from parent so the
child's `pgid` still equals the *parent's* `fake_pid` (procd's fork
inherits `parent->pgid`), which is distinct from the child's own
`fake_pid` · the child is no longer a pgrp leader and `setsid()`
succeeds, returning the child's `fake_pid` as the new `sid` + `pgid`.

## Smoke evidence

```
[orch] sotShell SPAWN 'procd_pg_test.bin' · 4552 bytes
[procd] setsid slot=N sid=N pgid=N
[procd] setpgid slot=N pgid=N (target_pid=0 caller_slot=N)
[pg-test] before_pgrp=<P> sid=<S> pgid=<S> ok=1
```

`scripts/smoke-procd.sh` greps for the `[procd] setsid slot=` line, the
`[procd] setpgid slot=` line, and the `[pg-test] before_pgrp=` line ·
three new PR 9 evidence markers.  `[procd] getpgid` is intentionally
not logged (the read-only path stays quiet); the resulting `pgid=` field
in the `[pg-test]` line carries that evidence instead.

## Rebuild

```bash
gcc -no-pie -nostdlib -static -Wl,--build-id=none -o procd_pg_test.bin pg_test.S
strip procd_pg_test.bin
```

Or via `make -f Makefile.fixture`.

## Why commit the binary

The fixture (~4.5 KiB stripped ET_EXEC) is committed so the seL4 CMake
build can embed it into orch's CPIO archive without requiring a host
gcc invocation during the cross-compile step.  Same pattern as
src/test/LucAs_hello, src/test/LucAs_fork_test, and
src/test/sotOs-procd-fork-test.

## Invocation paths

- Scripted: sotShell's `procd-pg-test` command (in the demo_commands
  array at sotshell/main.c) calls ORCH_OP_SPAWN with binname
  `procd_pg_test.bin`.
- Manual:  type `procd-pg-test` at the `sotos>` prompt once interactive
  mode kicks in (5-second window after the scripted demo finishes).
