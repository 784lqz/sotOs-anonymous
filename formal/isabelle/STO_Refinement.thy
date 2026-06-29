(*  Title:      sotOs/formal/isabelle/STO_Refinement.thy
    Author:     Anonymous

    Refinement: the impl_* functions on impl_registry correspond to
    state transitions in the abstract machine, via the `abstract`
    bridge in STO_Impl.

    First milestone (T2_reduced): impl_init abstracts to init_state.
    Second milestone (T2_begin_reduced): impl_begin on impl_init
    produces the same state as action_begin on init_state.

    The general T2 (any impl_step ↔ action_step) and T3 (composition
    with seL4 CDT) are documented as future work in
    formal/isabelle/Roadmap.md.
*)

theory STO_Refinement
imports STO_Impl
begin

(* === Helper lemma · the empty registry abstracts to the initial state === *)

theorem abstract_init: "abstract impl_init = init_state"
  by (simp add: abstract_def impl_init_def init_state_def)

(* === T2 reduced (begin) ===
   Begin on the freshly initialized registry produces a state that
   matches action_begin from init_state under the abstraction bridge.

   Statement: for any client/badge c, if we run impl_begin on impl_init
   with that badge, then there exists a state s' related to init_state
   by action_begin c, and the abstraction of the resulting registry
   equals s'.
*)

theorem T2_begin_reduced:
  fixes badge :: nat
  assumes "(r', tx) = impl_begin impl_init badge"
  shows "\<exists>s'. action_begin badge init_state s' \<and> abstract r' = s'"
proof -
  define s' where
    "s' \<equiv> init_state\<lparr>
       txs := (txs init_state)(next_id init_state := PActive),
       owners := (owners init_state)(next_id init_state := Some badge),
       next_id := next_id init_state + 1
     \<rparr>"

  (* The witness state s' satisfies action_begin from init_state *)
  have action_holds: "action_begin badge init_state s'"
    by (simp add: action_begin_def s'_def Let_def init_state_def)

  (* The abstraction of r' equals s' *)
  have abs_eq: "abstract r' = s'"
  proof -
    from assms have r'_def: "r' = impl_init\<lparr>
        iactive := iactive impl_init @ [\<lparr>
          itx_id        = inext_tx_id impl_init,
          iowner_badge  = badge,
          iphase        = PActive,
          iread_set     = [],
          iwrite_set    = [],
          iwrapped_caps = []
        \<rparr>],
        inext_tx_id := inext_tx_id impl_init + 1
      \<rparr>"
      by (simp add: impl_begin_def Let_def split: prod.splits)

    show ?thesis
      using r'_def
      by (auto simp: abstract_def s'_def init_state_def impl_init_def
                     ext fun_eq_iff
               split: option.splits)
  qed

  from action_holds abs_eq show ?thesis by blast
qed

end
