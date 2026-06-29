(*  Title:      sotOs/formal/isabelle/sotFS_delta/SotFS_Delta_State.thy
    Author:     Anonymous

    sotFS-δ · file-system state model.

    Shallow HOL embedding of a minimal file-system state: a pair of partial
    maps (inode_id ⇀ inode_meta) and (inode_id ⇀ content).  The split into
    "concrete" and "apparent" sub-records is exposed for the deception
    functor to manipulate at tiers F_1 (ghost · concrete frozen) and F_2
    (mirror · writes routed to apparent map).
*)

theory SotFS_Delta_State
imports Main
begin

(* === Primitive types === *)

type_synonym inode_id = nat
type_synonym uid_t    = nat
type_synonym gid_t    = nat
type_synonym mode_t   = nat
type_synonym size_t   = nat

(* File content modelled as a list of bytes; bytes are nat for simplicity. *)
type_synonym byte    = nat
type_synonym content = "byte list"

(* === Inode metadata === *)

record inode_meta =
  i_mode  :: mode_t
  i_uid   :: uid_t
  i_gid   :: gid_t
  i_size  :: size_t

(* === Concrete vs apparent state === *)

record fs_half =
  inodes  :: "inode_id \<rightharpoonup> inode_meta"
  content :: "inode_id \<rightharpoonup> content"

record fs_state =
  concrete :: fs_half
  apparent :: fs_half

(* === Constructors / projections === *)

definition empty_half :: fs_half where
  "empty_half = \<lparr> inodes = Map.empty, content = Map.empty \<rparr>"

definition empty_state :: fs_state where
  "empty_state = \<lparr> concrete = empty_half, apparent = empty_half \<rparr>"

definition concrete_part :: "fs_state \<Rightarrow> fs_half" where
  "concrete_part s = concrete s"

definition apparent_part :: "fs_state \<Rightarrow> fs_half" where
  "apparent_part s = apparent s"

(* === Operations (abstract) ===

   Writes are modelled as a partial state transformer.  We do NOT prove
   anything about their effect at δ-1; they're here so the functor can
   compose with them.  Concrete behaviour is left as an axiomatised
   transformer for δ-2 onwards.
*)

datatype fs_op =
    OpRead  inode_id
  | OpWrite inode_id content
  | OpUnlink inode_id
  | OpMkdir inode_id inode_meta

(* A write transformer: applied to a concrete half, returns a new half.
   Body is abstract; refined at δ-2. *)
definition write_half :: "fs_op \<Rightarrow> fs_half \<Rightarrow> fs_half" where
  "write_half op h =
     (case op of
        OpRead _      \<Rightarrow> h
      | OpWrite i c   \<Rightarrow> h\<lparr> content := (content h)(i \<mapsto> c) \<rparr>
      | OpUnlink i    \<Rightarrow> h\<lparr> inodes  := (inodes h)(i := None),
                            content := (content h)(i := None) \<rparr>
      | OpMkdir i m   \<Rightarrow> h\<lparr> inodes  := (inodes h)(i \<mapsto> m) \<rparr>)"

(* === Observation === *)

(* The sotbox-visible projection of state.
 *
 * δ-1 strengthening: `observable` is the *concrete* half, not the apparent
 * one.  Rationale: in deception theory the trusted sotbox observer sees the
 * real (concrete) file-system state, while the apparent half is the view
 * presented to potentially-deceived attackers.  Under this projection F_1
 * (silent-drop) and F_2 (mirror-only) are intended to be observationally
 * equivalent · neither moves the concrete half · which is the substantive
 * statement of f1_f2_obs_equiv at δ-1.  The earlier "= apparent" definition
 * trivialised the theorem because both sides of the equation referred to
 * the same F_1 result.  See SotFS_Delta_Soundness.thy for the proof.
 *)
definition observable :: "fs_state \<Rightarrow> fs_half" where
  "observable s = concrete s"

(* === Sanity lemmas === *)

lemma concrete_part_empty: "concrete_part empty_state = empty_half"
  by (simp add: concrete_part_def empty_state_def)

lemma apparent_part_empty: "apparent_part empty_state = empty_half"
  by (simp add: apparent_part_def empty_state_def)

lemma observable_empty: "observable empty_state = empty_half"
  by (simp add: observable_def empty_state_def)

end
