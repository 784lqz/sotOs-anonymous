# Isabelle proofs roadmap

## Status actual (post ciclo 4 / deepen-4)

- ✓ Isabelle 2025-2 installed and `sotOs` session defined.
- ✓ `STO_Abstract.thy`: HOL state machine reflecting TLA+ v3.
- ✓ `STO_Impl.thy`: manual specs for all key registry functions (init,
  begin, find, add_read, add_write, can_commit, commit, abort, wrap,
  wrapped_find, wrapped_invocable, sweep_wrapped, sweep_wrapped_by_mode)
  plus the `abstract` bridge.
- ✓ `STO_Refinement.thy`:
    - `abstract_init`: proved (no `sorry`)
    - `T2_begin_reduced`: proved (no `sorry`)
- ✗ T2 generalized (all actions, all reachable states).
- ✗ T3: composition with seL4 CDT proofs.

The `sotOs` Isabelle session builds clean in ~3 seconds.

## Próximos pasos en orden de criticidad

### 1. Extend T2 to other actions

We have `T2_begin_reduced`. The same pattern (witness state in the abstract,
prove action holds, prove abstraction equals witness) applies to:

- `T2_read_reduced`: a single `impl_add_read` after a fresh begin.
- `T2_write_reduced`: same with `impl_add_write`.
- `T2_wrap_reduced`: pattern for cap_ext.
- `T2_commit_reduced`: includes the sweep semantics.
- `T2_abort_reduced`: includes the all-modes sweep.

Costo estimado: 1-2 días por theorem with the established pattern.

### 2. Generalize T2 to a single step relation

  theorem T2_refinement:
    fixes r r' :: impl_registry
    assumes "impl_step r r'"   \<comment> \<open>any one of the impl_* functions\<close>
    shows "\<exists>s'. action_step (abstract r) s' \<and> abstract r' = s'"

Where `impl_step` unifies the impl_* functions under a single relation
and `action_step` does the same for the abstract actions.

Costo estimado: 1-2 semanas con los individual T2_* proved.

### 3. Set up l4v + obtain seL4 CDT theorems

For T3 we need the verified theorems about `seL4_CNode_Revoke` from
the l4v repository. Steps:

```bash
git clone https://github.com/seL4/l4v external/l4v
# l4v build is hours-long the first time. Pin to a commit matching
# external/kernel's commit if possible.
isabelle build -d external/l4v -d formal/isabelle sotOs
```

Costo estimado: 2-3 días for setup + version reconciliation.

### 4. Probar T3 (composition)

  theorem T3_composition:
    "no_effects_from_aborted (kernel_compose impl_state sel4_state)"

Done by unfolding kernel_compose, applying T2_refinement, and using
the seL4 CDT lemmas (specifically `Revoke_correct`).

Costo estimado: 2-4 semanas.

## Decisiones explícitas

- **Manual specs vs AutoCorres:** documented in ADR-0007.
- **Paper claim scope:** the paper §7 currently can claim "abstract spec
  in TLA+ verified up to bounded configurations + abstract-to-impl
  refinement for the initial step (`T2_begin_reduced`), with the full
  refinement and seL4 composition documented as in-progress." This is
  honest and falsifiable — what's done is done; what's not is named.

## Quick start for a contributor

```bash
cd formal/isabelle
isabelle build -d . sotOs               # ~3s, no sorries
isabelle jedit -d . -l sotOs STO_Refinement.thy  # interactive
```
