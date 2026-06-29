(*  Title:      sotOs/formal/isabelle/STO_Impl.thy
    Author:     Anonymous

    Manual specs of key C functions in src/sto/registry.c.
    Each function is modeled as a pure function on a record reflecting
    sto_registry_t. The correspondence between this and the actual C
    code is informal — auditable line by line by reading the headers
    + this theory side by side.

    See ADR-0007 for why we use manual specs instead of AutoCorres.
*)

theory STO_Impl
imports STO_Abstract
begin

(* === Implementation-side state === *)

record impl_transaction =
  itx_id        :: nat
  iowner_badge  :: nat
  iphase        :: tx_phase
  iread_set     :: "obj_id list"
  iwrite_set    :: "obj_id list"
  iwrapped_caps :: "cap_id list"

record impl_commit_entry =
  ice_tx_id     :: nat
  ice_write_set :: "obj_id list"

record impl_wrapped_cap =
  iwc_id      :: nat
  iwc_obj_id  :: nat
  iwc_tx_id   :: nat
  iwc_mode    :: cap_mode
  iwc_revoked :: bool

record impl_registry =
  iactive          :: "impl_transaction list"
  icommit_log      :: "impl_commit_entry list"
  inext_tx_id      :: nat
  iwrapped_pool    :: "impl_wrapped_cap list"
  inext_wrapped_id :: nat

(* === Function specs === *)

definition impl_init :: impl_registry where
  "impl_init = \<lparr>
    iactive          = [],
    icommit_log      = [],
    inext_tx_id      = 1,
    iwrapped_pool    = [],
    inext_wrapped_id = 1
  \<rparr>"

definition impl_begin :: "impl_registry \<Rightarrow> nat \<Rightarrow> (impl_registry \<times> impl_transaction)" where
  "impl_begin r badge =
    (let new_tx = \<lparr>
        itx_id        = inext_tx_id r,
        iowner_badge  = badge,
        iphase        = PActive,
        iread_set     = [],
        iwrite_set    = [],
        iwrapped_caps = []
      \<rparr>
     in
     (r\<lparr> iactive := iactive r @ [new_tx],
         inext_tx_id := inext_tx_id r + 1 \<rparr>, new_tx))"

definition impl_find :: "impl_registry \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> impl_transaction option" where
  "impl_find r tx_id badge =
    find (\<lambda>tx. itx_id tx = tx_id
             \<and> iowner_badge tx = badge
             \<and> iphase tx = PActive)
         (iactive r)"

definition impl_add_read :: "impl_transaction \<Rightarrow> obj_id \<Rightarrow> impl_transaction" where
  "impl_add_read tx oid =
    (if oid \<in> set (iread_set tx)
     then tx
     else tx\<lparr> iread_set := iread_set tx @ [oid] \<rparr>)"

definition impl_add_write :: "impl_transaction \<Rightarrow> obj_id \<Rightarrow> impl_transaction" where
  "impl_add_write tx oid =
    (if oid \<in> set (iwrite_set tx)
     then tx
     else tx\<lparr> iwrite_set := iwrite_set tx @ [oid] \<rparr>)"

definition impl_can_commit :: "impl_registry \<Rightarrow> impl_transaction \<Rightarrow> bool" where
  "impl_can_commit r tx =
    (\<forall>e \<in> set (icommit_log r). set (iread_set tx) \<inter> set (ice_write_set e) = {})"

definition impl_sweep_wrapped_by_mode ::
  "impl_registry \<Rightarrow> impl_transaction \<Rightarrow> cap_mode \<Rightarrow> impl_registry" where
  "impl_sweep_wrapped_by_mode r tx m =
    r\<lparr> iwrapped_pool := map (\<lambda>wc.
            if iwc_id wc \<in> set (iwrapped_caps tx) \<and> iwc_mode wc = m
            then wc\<lparr> iwc_revoked := True \<rparr>
            else wc)
          (iwrapped_pool r) \<rparr>"

definition impl_sweep_wrapped ::
  "impl_registry \<Rightarrow> impl_transaction \<Rightarrow> impl_registry" where
  "impl_sweep_wrapped r tx =
    r\<lparr> iwrapped_pool := map (\<lambda>wc.
            if iwc_id wc \<in> set (iwrapped_caps tx)
            then wc\<lparr> iwc_revoked := True \<rparr>
            else wc)
          (iwrapped_pool r) \<rparr>"

definition impl_commit :: "impl_registry \<Rightarrow> impl_transaction \<Rightarrow> impl_registry" where
  "impl_commit r tx =
    (let log_entry = \<lparr> ice_tx_id = itx_id tx, ice_write_set = iwrite_set tx \<rparr>;
         r1 = r\<lparr> icommit_log := icommit_log r @ [log_entry] \<rparr>;
         r2 = impl_sweep_wrapped_by_mode r1 tx MActiveOk
     in r2)"

definition impl_abort :: "impl_registry \<Rightarrow> impl_transaction \<Rightarrow> impl_registry" where
  "impl_abort r tx = impl_sweep_wrapped r tx"

definition impl_wrap ::
  "impl_registry \<Rightarrow> impl_transaction \<Rightarrow> obj_id \<Rightarrow> cap_mode
   \<Rightarrow> (impl_registry \<times> nat)" where
  "impl_wrap r tx oid mode =
    (let new_id = inext_wrapped_id r;
         new_wc = \<lparr> iwc_id      = new_id,
                    iwc_obj_id  = oid,
                    iwc_tx_id   = itx_id tx,
                    iwc_mode    = mode,
                    iwc_revoked = False \<rparr>
     in
     (r\<lparr> iwrapped_pool    := iwrapped_pool r @ [new_wc],
         inext_wrapped_id := inext_wrapped_id r + 1 \<rparr>, new_id))"

definition impl_wrapped_find ::
  "impl_registry \<Rightarrow> nat \<Rightarrow> impl_wrapped_cap option" where
  "impl_wrapped_find r wid =
    (case find (\<lambda>wc. iwc_id wc = wid) (iwrapped_pool r) of
       None \<Rightarrow> None
     | Some wc \<Rightarrow> if iwc_revoked wc then None else Some wc)"

definition impl_wrapped_invocable ::
  "impl_registry \<Rightarrow> impl_wrapped_cap \<Rightarrow> bool" where
  "impl_wrapped_invocable r wc =
    (\<not> iwc_revoked wc \<and>
     (case find (\<lambda>tx. itx_id tx = iwc_tx_id wc) (iactive r) of
        None \<Rightarrow> False
      | Some parent \<Rightarrow>
          (iwc_mode wc = MActiveOk
           \<and> (iphase parent = PActive \<or> iphase parent = PCommitted))
          \<or> (iwc_mode wc = MCommitOnly \<and> iphase parent = PCommitted)))"

(* === Bridge: from impl_registry to sto_state === *)

definition abstract :: "impl_registry \<Rightarrow> sto_state" where
  "abstract r = \<lparr>
    txs         = (\<lambda>t. case find (\<lambda>x. itx_id x = t) (iactive r) of
                          None \<Rightarrow> PNone
                        | Some tx \<Rightarrow> iphase tx),
    owners      = (\<lambda>t. case find (\<lambda>x. itx_id x = t) (iactive r) of
                          None \<Rightarrow> None
                        | Some tx \<Rightarrow> Some (iowner_badge tx)),
    reads       = (\<lambda>t. case find (\<lambda>x. itx_id x = t) (iactive r) of
                          None \<Rightarrow> {}
                        | Some tx \<Rightarrow> set (iread_set tx)),
    writes      = (\<lambda>t. case find (\<lambda>x. itx_id x = t) (iactive r) of
                          None \<Rightarrow> {}
                        | Some tx \<Rightarrow> set (iwrite_set tx)),
    commit_log  = map (\<lambda>e. (ice_tx_id e, set (ice_write_set e))) (icommit_log r),
    next_id     = inext_tx_id r,

    caps        = (\<lambda>k. case find (\<lambda>wc. iwc_id wc = k) (iwrapped_pool r) of
                          None \<Rightarrow> CFree
                        | Some wc \<Rightarrow> if iwc_revoked wc then CRevoked else CLive),
    cap_obj     = (\<lambda>k. case find (\<lambda>wc. iwc_id wc = k) (iwrapped_pool r) of
                          None \<Rightarrow> None
                        | Some wc \<Rightarrow> Some (iwc_obj_id wc)),
    cap_tx      = (\<lambda>k. case find (\<lambda>wc. iwc_id wc = k) (iwrapped_pool r) of
                          None \<Rightarrow> None
                        | Some wc \<Rightarrow> Some (iwc_tx_id wc)),
    cap_mode    = (\<lambda>k. case find (\<lambda>wc. iwc_id wc = k) (iwrapped_pool r) of
                          None \<Rightarrow> MUnbound
                        | Some wc \<Rightarrow> iwc_mode wc),
    invocations = [],
    next_cap    = inext_wrapped_id r
  \<rparr>"

end
