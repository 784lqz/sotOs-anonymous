# TLC verification status

## STO.tla v2 (OCC core)

**Status: ✓ verified**

- Config: `Clients={c1,c2}, Objects={o1,o2}, MaxTx=3`
- Result: 5,438,083 states generated · 935,137 distinct states · depth 19 · 12s
- Invariants checked: `TypeOK`, `OnlyOwnerMutates`, `NoLostUpdate`
- No violations.

## STO.tla v3 (OCC + cap_ext)

**Status: partial · time-bounded exploration without violations**

- Attempted configs:
  | Config | Distinct states | Result |
  |---|---|---|
  | `MaxTx=2, MaxCaps=3, Objects={o1,o2}` | 54M+ (killed at 11min, queue still growing) | no violations seen |
  | `MaxTx=2, MaxCaps=2, Objects={o1,o2}` (with `InvocationsBounded` ≤ 5) | running >30min, killed | no violations seen |
  | `MaxTx=2, MaxCaps=2, Objects={o1}` (with `InvocationsBounded` ≤ 5) | running, killed | no violations seen |

- Invariants checked: above 3 plus `NoEffectsFromAborted`, `CommitOnlyVisibility`
- Constraint `InvocationsBounded == Len(invocations) <= 5` added because the `invocations` sequence grows unbounded with each `Invoke`/`InvokeFails`, producing an infinite state space.

## Honest caveat

TLC against v3 on this host machine does not terminate in reasonable wall time for any non-trivial configuration. The state space explosion comes from:

1. The `invocations` sequence is monotonically growing; every `Invoke` produces a new distinct state via `Append`.
2. `tx_phase` snapshots in each invocation entry add per-element variance.
3. Even bounded by `InvocationsBounded`, the interleavings of `Begin`/`Wrap`/`Invoke`/`Commit`/`Rollback` across 2 clients × 2 caps × 2 objects produce a deep state graph.

## What we can claim

- **v2 fully model-checked** at meaningful scale (1M distinct states).
- **v3 partially explored** at smaller scales without invariant violations.
- The early-development bug in the original `NoEffectsFromAborted` formulation (without `tx_phase` snapshot) was caught by TLC in **5 states**, demonstrating the spec is debuggable even at this scale.

## What we cannot claim

- **v3 is not exhaustively verified** under MaxTx=2/MaxCaps=2/Objects=2. The paper §7.1 should report this as "TLC explored N states without violations under bounded configurations" and not as "spec proven safe by TLC".

## Path forward

Options for closing this gap:

1. **TLA+ Proof System (TLAPS):** deductive proofs of the invariants, no model checking. Lifts the configuration limit. Effort: substantial.
2. **Refactor spec to bound `invocations`:** e.g. use a fixed-size circular buffer instead of an unbounded `Seq`. Loses some generality but makes TLC tractable.
3. **Simulation mode (`-simulate`):** random sampling instead of exhaustive. Faster but not a proof; useful for confidence-building.
4. **Better hardware:** TLC scales reasonably with cores + memory; a 64-core machine with 64 GB heap likely handles MaxCaps=3 in minutes.

The Isabelle/HOL path (prompt #5 / deepen-4) bypasses this entirely by doing deductive proofs.
