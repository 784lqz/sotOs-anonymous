(*  Title:      sotOs/formal/isabelle/sotFS_delta/SotFS_Delta_Functor.thy
    Author:     Anonymous

    sotFS-δ · the deception functor F.

    F selects a tier (F_0 identity · F_1 ghost · F_2 mirror) and applies a
    state transformation accordingly.  At δ-1 we prove only the trivial
    identity lemma for F_0; F_1 and F_2 properties live in the Soundness
    theory with `sorry` placeholders.
*)

theory SotFS_Delta_Functor
imports SotFS_Delta_State
begin

(* === Tiers === *)

datatype tier = F0 | F1 | F2

(* === Functor application ===

   F_0 · identity · state unchanged.
   F_1 · ghost   · state unchanged (writes silently dropped at the
                    application layer; here apply_functor itself is identity,
                    so the *operation* must be intercepted before reaching
                    write_half · modelled in apply_write below).
   F_2 · mirror  · state unchanged at this entry point; mirror routing
                    happens in apply_write.
*)
definition apply_functor :: "tier \<Rightarrow> fs_state \<Rightarrow> fs_state" where
  "apply_functor t s =
     (case t of
        F0 \<Rightarrow> s
      | F1 \<Rightarrow> s
      | F2 \<Rightarrow> s)"

(* === apply_write ===

   The deception-aware write entry point.  Given a tier and an op:
     · F_0 routes the op to the concrete half.
     · F_1 drops the op (state unchanged).
     · F_2 routes the op to the apparent half only.
*)
definition apply_write :: "tier \<Rightarrow> fs_op \<Rightarrow> fs_state \<Rightarrow> fs_state" where
  "apply_write t op s =
     (case t of
        F0 \<Rightarrow> s\<lparr> concrete := write_half op (concrete s),
                  apparent := write_half op (apparent s) \<rparr>
      | F1 \<Rightarrow> s
      | F2 \<Rightarrow> s\<lparr> apparent := write_half op (apparent s) \<rparr>)"

(* === F_0 identity · provable trivially === *)

lemma f0_identity: "apply_functor F0 s = s"
  by (simp add: apply_functor_def)

lemma f1_pass_through: "apply_functor F1 s = s"
  by (simp add: apply_functor_def)

lemma f2_pass_through: "apply_functor F2 s = s"
  by (simp add: apply_functor_def)

(* F_1 drops writes · state literally unchanged. *)
lemma f1_write_drop: "apply_write F1 op s = s"
  by (simp add: apply_write_def)

(* === apply_writes ·  fold apply_write over a sequence of ops ===

   Needed for δ-1 substantive theorems that quantify over a *trace* of
   writes rather than a single op.  Defined by recursion on the op list. *)
fun apply_writes :: "tier \<Rightarrow> fs_op list \<Rightarrow> fs_state \<Rightarrow> fs_state" where
  "apply_writes t []       s = s"
| "apply_writes t (op # ops) s = apply_writes t ops (apply_write t op s)"

lemma apply_writes_F1_drop: "apply_writes F1 ops s = s"
  by (induct ops arbitrary: s) (simp_all add: f1_write_drop)

(* F_2 leaves the concrete half untouched for a single op. *)
lemma f2_concrete_unchanged: "concrete (apply_write F2 op s) = concrete s"
  by (simp add: apply_write_def)

(* F_2 leaves the concrete half untouched for any sequence of ops. *)
lemma apply_writes_F2_concrete: "concrete (apply_writes F2 ops s) = concrete s"
  by (induct ops arbitrary: s) (simp_all add: f2_concrete_unchanged)

end
