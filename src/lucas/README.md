# LucAs · Linux Unified Compatibility Abstraction Subsystem

L1 milestone: load and run a static Linux ELF that calls
`write(1, "hello world\n", ...) + exit_group(0)`.

For L1, sotOs-LucAs is a static library linked into root. The ELF
loader and per-client syscall companion run inline in the root task.
The orchestrator/multi-client split (own process, cap delegation)
arrives in L3+.

See `LucAs-killer-feature-design`
for the full architecture.
