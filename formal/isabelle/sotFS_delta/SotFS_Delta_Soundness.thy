(*  Title:      sotOs/formal/isabelle/sotFS_delta/SotFS_Delta_Soundness.thy
    Author:     Anonymous

    sotFS-δ · soundness statements for the deception functor.

    δ-1 status: f1_silent, f2_isolation, f0_roundtrip, f1_idempotent,
    f1_writes_idempotent, f1_f2_obs_equiv (and its single-op corollary)
    are proven with real tactics.  The only remaining `sorry` is
    f2_sto_abort_rollback · deferred to δ-5 pending STO_Abstract import.
*)

theory SotFS_Delta_Soundness
imports SotFS_Delta_Functor
begin

(* === F_1 silence ===

   After routing a write through F_1, the observable (concrete) state equals
   the observable state of the input.  Stronger than f1_write_drop because
   it quantifies over the projection `observable` · whatever it ultimately
   projects to, F_1's silent-drop semantics guarantee invariance.
*)
theorem f1_silent:
  "\<forall>op s. observable (apply_write F1 op s) = observable s"
  by (simp add: apply_write_def observable_def)

(* === F_2 isolation ===

   After routing a write through F_2, the *concrete* part of state is
   unchanged.  Only the apparent (mirror) half moves.
*)
theorem f2_isolation:
  "\<forall>op s. concrete_part (apply_write F2 op s) = concrete_part s"
  by (simp add: apply_write_def concrete_part_def)

(* === F_0 round-trip (degenerate) ===

   For F_0, observable and concrete coincide modulo the initial state having
   apparent == concrete.  Stated for completeness; full proof at δ-3 once
   we have a notion of "well-formed initial state".
*)
theorem f0_roundtrip:
  "\<forall>op s. apparent s = concrete s
           \<longrightarrow> apparent (apply_write F0 op s) = concrete (apply_write F0 op s)"
  by (simp add: apply_write_def)

(* === F_1 idempotency ·  δ-1 NEW ===

   Applying the F_1 functor twice is the same as applying it once.  This is
   the "lifted" companion of f1_pass_through · since apply_functor F1 is
   identity at the entry point, idempotency is immediate; we leave the
   lemma here to document the algebraic property for δ-4 monoid work. *)
theorem f1_idempotent:
  "apply_functor F1 (apply_functor F1 s) = apply_functor F1 s"
  by (simp add: apply_functor_def)

(* The same property lifted to apply_write · F_1 drops writes so iterating
   apply_write F_1 across any list of ops is also idempotent. *)
theorem f1_writes_idempotent:
  "apply_writes F1 ops (apply_writes F1 ops s) = apply_writes F1 ops s"
  by (simp add: apply_writes_F1_drop)

(* === F_1 vs F_2 observational equivalence ·  δ-1 SUBSTANTIVE ===

   Statement: for any sequence of writes, the sotbox-observable trace under
   F_1 is identical to that under F_2.  With `observable = concrete` this
   says that neither tier moves the trusted (kernel-side) view of the file
   system · the deception layer is silent from the sotbox-observer POV.

   Proof: induction on the list of ops.  Base case (empty list) is
   refl after unfolding apply_writes and observable.  Step case uses
   apply_write_def on both tiers (F_1 leaves s unchanged · F_2 only mutates
   apparent, leaving concrete unchanged), then the IH.

   This is the real δ-1 claim · the prior `\<forall>op s. observable (...F1...) =
   observable (...F1...)` was a reflexivity tautology.
*)
theorem f1_f2_obs_equiv:
  "observable (apply_writes F1 ops s) = observable (apply_writes F2 ops s)"
proof (induct ops arbitrary: s)
  case Nil
  show ?case by simp
next
  case (Cons op ops)
  have lhs: "observable (apply_writes F1 (op # ops) s) = observable s"
    using apply_writes_F1_drop[of "op # ops" s]
    by (simp add: observable_def)
  have rhs: "observable (apply_writes F2 (op # ops) s) = observable s"
    using apply_writes_F2_concrete[of "op # ops" s]
    by (simp add: observable_def)
  from lhs rhs show ?case by simp
qed

(* Single-op corollary (recovers the original δ-1 statement shape but with
   a substantive RHS · F_1 vs F_2 rather than F_1 vs F_1). *)
corollary f1_f2_obs_equiv_single:
  "observable (apply_write F1 op s) = observable (apply_write F2 op s)"
  by (simp add: apply_write_def observable_def)

(* === Refinement link to STO · DEFERRED ===

   At δ-5 we want: if a write is wrapped in an STO transaction that aborts,
   then under F_2 the apparent half should be rolled back to match the
   concrete half.  Requires importing STO_Abstract; placeholder.
*)
theorem f2_sto_abort_rollback:
  "\<forall>op s. concrete_part (apply_write F2 op s) = concrete_part s"
  (* same shape as f2_isolation at δ-1; refined when STO is imported *)
  sorry

end
