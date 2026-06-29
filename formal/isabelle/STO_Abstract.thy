(*  Title:      sotOs/formal/isabelle/STO_Abstract.thy
    Author:     Anonymous

    Abstract state machine for Secure Transactional Objects.

    Reflects formal/tla/STO.tla v3 in HOL. The TLA+ spec defines temporal
    behavior; here we capture the state-transition structure as a relation,
    leaving temporal arguments (eventually, always) to meta-level reasoning
    or future TLAPS integration.
*)

theory STO_Abstract
imports Main
begin

(* === Types === *)

datatype tx_phase = PNone | PActive | PCommitted | PAborted

datatype cap_state = CFree | CLive | CRevoked

datatype cap_mode  = MCommitOnly | MActiveOk | MUnbound

type_synonym client_id = nat
type_synonym obj_id    = nat
type_synonym tx_id     = nat
type_synonym cap_id    = nat

(* === Invocation history record === *)

record invocation =
  inv_cap      :: cap_id
  inv_by       :: client_id
  inv_ok       :: bool
  inv_tx_phase :: tx_phase

(* === State === *)

record sto_state =
  txs        :: "tx_id \<Rightarrow> tx_phase"
  owners     :: "tx_id \<Rightarrow> client_id option"
  reads      :: "tx_id \<Rightarrow> obj_id set"
  writes     :: "tx_id \<Rightarrow> obj_id set"
  commit_log :: "(tx_id \<times> obj_id set) list"
  next_id    :: tx_id

  caps        :: "cap_id \<Rightarrow> cap_state"
  cap_obj     :: "cap_id \<Rightarrow> obj_id option"
  cap_tx      :: "cap_id \<Rightarrow> tx_id option"
  cap_mode    :: "cap_id \<Rightarrow> cap_mode"
  invocations :: "invocation list"
  next_cap    :: cap_id

(* === Initial state === *)

definition init_state :: sto_state where
  "init_state = \<lparr>
    txs         = (\<lambda>_. PNone),
    owners      = (\<lambda>_. None),
    reads       = (\<lambda>_. {}),
    writes      = (\<lambda>_. {}),
    commit_log  = [],
    next_id     = 1,
    caps        = (\<lambda>_. CFree),
    cap_obj     = (\<lambda>_. None),
    cap_tx      = (\<lambda>_. None),
    cap_mode    = (\<lambda>_. MUnbound),
    invocations = [],
    next_cap    = 1
  \<rparr>"

(* === Predicates over a single state === *)

definition committed_writes_after :: "sto_state \<Rightarrow> obj_id set list" where
  "committed_writes_after s = map snd (commit_log s)"

definition can_commit :: "sto_state \<Rightarrow> tx_id \<Rightarrow> bool" where
  "can_commit s t = (\<forall>ws \<in> set (committed_writes_after s). reads s t \<inter> ws = {})"

definition invocable :: "sto_state \<Rightarrow> cap_id \<Rightarrow> bool" where
  "invocable s k = (
     caps s k = CLive \<and>
     (case cap_tx s k of
        None \<Rightarrow> False
      | Some t \<Rightarrow>
          (cap_mode s k = MActiveOk \<and> txs s t = PActive) \<or>
          (cap_mode s k = MCommitOnly \<and> txs s t = PCommitted)))"

(* === Actions === *)

(* Begin: allocate the next tx slot as ACTIVE, owned by client c. *)
definition action_begin :: "client_id \<Rightarrow> sto_state \<Rightarrow> sto_state \<Rightarrow> bool" where
  "action_begin c s s' = (
    let t = next_id s in
      txs s'       = (txs s)(t := PActive) \<and>
      owners s'    = (owners s)(t := Some c) \<and>
      next_id s'   = next_id s + 1 \<and>
      reads s'     = reads s \<and>
      writes s'    = writes s \<and>
      commit_log s' = commit_log s \<and>
      caps s'      = caps s \<and>
      cap_obj s'   = cap_obj s \<and>
      cap_tx s'    = cap_tx s \<and>
      cap_mode s'  = cap_mode s \<and>
      invocations s' = invocations s \<and>
      next_cap s'  = next_cap s)"

definition action_read :: "client_id \<Rightarrow> tx_id \<Rightarrow> obj_id \<Rightarrow> sto_state \<Rightarrow> sto_state \<Rightarrow> bool" where
  "action_read c t oid s s' = (
    t < next_id s \<and>
    txs s t = PActive \<and>
    owners s t = Some c \<and>
    reads s' = (reads s)(t := reads s t \<union> {oid}) \<and>
    txs s' = txs s \<and>
    owners s' = owners s \<and>
    writes s' = writes s \<and>
    commit_log s' = commit_log s \<and>
    next_id s' = next_id s \<and>
    caps s' = caps s \<and>
    cap_obj s' = cap_obj s \<and>
    cap_tx s' = cap_tx s \<and>
    cap_mode s' = cap_mode s \<and>
    invocations s' = invocations s \<and>
    next_cap s' = next_cap s)"

definition action_write :: "client_id \<Rightarrow> tx_id \<Rightarrow> obj_id \<Rightarrow> sto_state \<Rightarrow> sto_state \<Rightarrow> bool" where
  "action_write c t oid s s' = (
    t < next_id s \<and>
    txs s t = PActive \<and>
    owners s t = Some c \<and>
    writes s' = (writes s)(t := writes s t \<union> {oid}) \<and>
    txs s' = txs s \<and>
    owners s' = owners s \<and>
    reads s' = reads s \<and>
    commit_log s' = commit_log s \<and>
    next_id s' = next_id s \<and>
    caps s' = caps s \<and>
    cap_obj s' = cap_obj s \<and>
    cap_tx s' = cap_tx s \<and>
    cap_mode s' = cap_mode s \<and>
    invocations s' = invocations s \<and>
    next_cap s' = next_cap s)"

definition action_wrap :: "client_id \<Rightarrow> tx_id \<Rightarrow> obj_id \<Rightarrow> cap_mode \<Rightarrow> sto_state \<Rightarrow> sto_state \<Rightarrow> bool" where
  "action_wrap c t oid m s s' = (
    let k = next_cap s in
      t < next_id s \<and>
      txs s t = PActive \<and>
      owners s t = Some c \<and>
      m \<in> {MCommitOnly, MActiveOk} \<and>
      caps s'     = (caps s)(k := CLive) \<and>
      cap_obj s'  = (cap_obj s)(k := Some oid) \<and>
      cap_tx s'   = (cap_tx s)(k := Some t) \<and>
      cap_mode s' = (cap_mode s)(k := m) \<and>
      next_cap s' = next_cap s + 1 \<and>
      txs s' = txs s \<and>
      owners s' = owners s \<and>
      reads s' = reads s \<and>
      writes s' = writes s \<and>
      commit_log s' = commit_log s \<and>
      next_id s' = next_id s \<and>
      invocations s' = invocations s)"

definition action_invoke :: "client_id \<Rightarrow> cap_id \<Rightarrow> sto_state \<Rightarrow> sto_state \<Rightarrow> bool" where
  "action_invoke c k s s' = (
    invocable s k \<and>
    (let phase = (case cap_tx s k of None \<Rightarrow> PNone | Some t \<Rightarrow> txs s t)
     in invocations s' = invocations s @ [
          \<lparr> inv_cap = k, inv_by = c, inv_ok = True, inv_tx_phase = phase \<rparr>]) \<and>
    txs s' = txs s \<and>
    owners s' = owners s \<and>
    reads s' = reads s \<and>
    writes s' = writes s \<and>
    commit_log s' = commit_log s \<and>
    next_id s' = next_id s \<and>
    caps s' = caps s \<and>
    cap_obj s' = cap_obj s \<and>
    cap_tx s' = cap_tx s \<and>
    cap_mode s' = cap_mode s \<and>
    next_cap s' = next_cap s)"

definition action_invoke_fails :: "client_id \<Rightarrow> cap_id \<Rightarrow> sto_state \<Rightarrow> sto_state \<Rightarrow> bool" where
  "action_invoke_fails c k s s' = (
    \<not> invocable s k \<and>
    k < next_cap s \<and>
    (let phase = (case cap_tx s k of None \<Rightarrow> PNone | Some t \<Rightarrow> txs s t)
     in invocations s' = invocations s @ [
          \<lparr> inv_cap = k, inv_by = c, inv_ok = False, inv_tx_phase = phase \<rparr>]) \<and>
    txs s' = txs s \<and>
    owners s' = owners s \<and>
    reads s' = reads s \<and>
    writes s' = writes s \<and>
    commit_log s' = commit_log s \<and>
    next_id s' = next_id s \<and>
    caps s' = caps s \<and>
    cap_obj s' = cap_obj s \<and>
    cap_tx s' = cap_tx s \<and>
    cap_mode s' = cap_mode s \<and>
    next_cap s' = next_cap s)"

(* RevokeFor as a state transformer · model of seL4_CNode_Revoke. *)
definition revoke_for :: "tx_id \<Rightarrow> sto_state \<Rightarrow> (cap_id \<Rightarrow> cap_state)" where
  "revoke_for t s = (\<lambda>k. if cap_tx s k = Some t \<and> caps s k = CLive
                          then CRevoked
                          else caps s k)"

definition action_commit :: "client_id \<Rightarrow> tx_id \<Rightarrow> sto_state \<Rightarrow> sto_state \<Rightarrow> bool" where
  "action_commit c t s s' = (
    t < next_id s \<and>
    txs s t = PActive \<and>
    owners s t = Some c \<and>
    can_commit s t \<and>
    txs s' = (txs s)(t := PCommitted) \<and>
    commit_log s' = commit_log s @ [(t, writes s t)] \<and>
    owners s' = owners s \<and>
    reads s' = reads s \<and>
    writes s' = writes s \<and>
    next_id s' = next_id s \<and>
    caps s' = caps s \<and>
    cap_obj s' = cap_obj s \<and>
    cap_tx s' = cap_tx s \<and>
    cap_mode s' = cap_mode s \<and>
    invocations s' = invocations s \<and>
    next_cap s' = next_cap s)"

definition action_abort_on_conflict :: "client_id \<Rightarrow> tx_id \<Rightarrow> sto_state \<Rightarrow> sto_state \<Rightarrow> bool" where
  "action_abort_on_conflict c t s s' = (
    t < next_id s \<and>
    txs s t = PActive \<and>
    owners s t = Some c \<and>
    \<not> can_commit s t \<and>
    txs s' = (txs s)(t := PAborted) \<and>
    caps s' = revoke_for t s \<and>
    owners s' = owners s \<and>
    reads s' = reads s \<and>
    writes s' = writes s \<and>
    commit_log s' = commit_log s \<and>
    next_id s' = next_id s \<and>
    cap_obj s' = cap_obj s \<and>
    cap_tx s' = cap_tx s \<and>
    cap_mode s' = cap_mode s \<and>
    invocations s' = invocations s \<and>
    next_cap s' = next_cap s)"

definition action_rollback :: "client_id \<Rightarrow> tx_id \<Rightarrow> sto_state \<Rightarrow> sto_state \<Rightarrow> bool" where
  "action_rollback c t s s' = (
    t < next_id s \<and>
    txs s t = PActive \<and>
    owners s t = Some c \<and>
    txs s' = (txs s)(t := PAborted) \<and>
    caps s' = revoke_for t s \<and>
    owners s' = owners s \<and>
    reads s' = reads s \<and>
    writes s' = writes s \<and>
    commit_log s' = commit_log s \<and>
    next_id s' = next_id s \<and>
    cap_obj s' = cap_obj s \<and>
    cap_tx s' = cap_tx s \<and>
    cap_mode s' = cap_mode s \<and>
    invocations s' = invocations s \<and>
    next_cap s' = next_cap s)"

(* === Invariants (lifted from TLA+) === *)

definition inv_only_owner_mutates :: "sto_state \<Rightarrow> bool" where
  "inv_only_owner_mutates s = (\<forall>t. txs s t \<noteq> PNone \<longrightarrow> (\<exists>c. owners s t = Some c))"

definition inv_no_lost_update :: "sto_state \<Rightarrow> bool" where
  "inv_no_lost_update s = (
    \<forall>i j. i < j \<and> j < length (commit_log s) \<longrightarrow>
      (let ti = fst (commit_log s ! i);
           wi = snd (commit_log s ! i);
           tj = fst (commit_log s ! j) in
       reads s tj \<inter> wi = {} \<or> tj = ti))"

definition inv_no_effects_from_aborted :: "sto_state \<Rightarrow> bool" where
  "inv_no_effects_from_aborted s = (
    \<forall>i \<in> set (invocations s). inv_ok i \<longrightarrow> inv_tx_phase i \<noteq> PAborted)"

definition inv_commit_only_visibility :: "sto_state \<Rightarrow> bool" where
  "inv_commit_only_visibility s = (
    \<forall>i \<in> set (invocations s).
      inv_ok i \<and> cap_mode s (inv_cap i) = MCommitOnly
      \<longrightarrow> inv_tx_phase i = PCommitted)"

end
