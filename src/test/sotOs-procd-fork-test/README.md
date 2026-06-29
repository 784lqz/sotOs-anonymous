# sotOs-procd-fork-test · PR 6/7 fork/exit/wait4 smoke fixture

Tiny static x86_64 Linux binary that exercises the PR 6 OP_FORK + OP_EXIT
+ OP_WAIT shadow-announce path against the procd process server.  PR 7
dropped the PROCD_TAKEOVER_SPAWN gate · the announce path is now
unconditional, so this fixture's evidence lines always appear.

The parent forks once, the child writes `[fork-test] child alive\n` and
exits with status 42, the parent waits with `wait4(-1, NULL, 0, NULL)`,
then writes `[fork-test] parent reaped child\n` and exits 0.

## Smoke evidence

```
[orch] sotShell SPAWN 'procd_fork_test.bin' · 4568 bytes
[procd] fork slot=2 fake_pid=2 ppid=1 tier=0
[orch] procd fork announced child slot=2 fake_pid=2 (parent_slot=1)
[fork-test] child alive
[procd] exit slot=2 code=42 ppid=1
[procd] EV_SIGCHLD target=1 zombie_slot=2
[fork-test] parent reaped child
[procd] exit slot=1 code=0 ppid=0
```

scripts/smoke-procd.sh greps for the four PR 6 procd evidence lines
plus the PR 5 spawn announce/handler lines, the PR 7 exec announce line,
and the PR 4 ring marker/e2e lines for a 16/16 total · with PR 7 the
gate is gone, so the announce path is always active.

## Rebuild

```bash
gcc -no-pie -nostdlib -static -Wl,--build-id=none -o procd_fork_test.bin fork_test.S
strip procd_fork_test.bin
```

Or via `make -f Makefile.fixture`.

## Why commit the binary

The fixture (~4.5 KiB stripped ET_EXEC) is committed so the seL4 CMake
build can embed it into orch's CPIO archive without requiring a host
gcc invocation during the cross-compile step.  Same pattern as
src/test/LucAs_hello and src/test/LucAs_fork_test.

## Why a distinct basename

`fork_test.bin` is already taken by src/test/LucAs_fork_test.  CPIO
addressing uses the basename of each source path, so the PR 6 fixture
uses `procd_fork_test.bin` to coexist alongside the L3a fork demo in
the same orch CPIO archive.

## Invocation paths

- Scripted: sotShell's `procd-fork-test` command (in the demo_commands
  array at sotshell/main.c) calls ORCH_OP_SPAWN with binname
  `procd_fork_test.bin`.
- Manual:  type `procd-fork-test` at the `sotos>` prompt once interactive
  mode kicks in (5-second window after the scripted demo finishes).
