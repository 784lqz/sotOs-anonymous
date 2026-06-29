------------------------------ MODULE STO ------------------------------
(***************************************************************************)
(* sotOs · STO + cap_ext · v3                                              *)
(*                                                                          *)
(* Esta versión extiende v2 (OCC + NoLostUpdate) con capability extensions:*)
(* la operación Wrap deriva un cap nuevo desde un cap a un STO object,    *)
(* atado a una transacción. La invocabilidad del cap derivado depende de  *)
(* (a) el estado de la transacción, (b) el modo del wrap.                 *)
(*                                                                          *)
(* En abort, todos los caps derivados de la tx se revocan (modelo abstracto*)
(* del CDT de seL4: una operación atómica que invalida la subtree).       *)
(*                                                                          *)
(* Invariantes nuevas que probamos:                                        *)
(*   NoEffectsFromAborted: ningún cap derivado de una tx ABORTED es      *)
(*     invocable después del abort.                                       *)
(*   CommitOnlyVisibility: en modo COMMIT_ONLY, el cap no es invocable    *)
(*     mientras la tx está ACTIVE.                                        *)
(***************************************************************************)

EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS Clients, Objects, MaxTx, MaxCaps

ASSUME Cardinality(Clients) >= 1
ASSUME Cardinality(Objects) >= 1
ASSUME MaxTx >= 1
ASSUME MaxCaps >= 1

VARIABLES
    txs,          \* [1..MaxTx -> TxStates]
    owners,       \* [1..MaxTx -> Clients ∪ {NONE}]
    reads,        \* [1..MaxTx -> SUBSET Objects]
    writes,       \* [1..MaxTx -> SUBSET Objects]
    commit_log,   \* Seq of {tx, ws}
    next_id,
    \* New for cap_ext:
    caps,         \* [1..MaxCaps -> CapStates]   (FREE | LIVE | REVOKED)
    cap_obj,      \* [1..MaxCaps -> Objects ∪ {NONE}]
    cap_tx,       \* [1..MaxCaps -> 1..MaxTx ∪ {0}]    (0 = unbound)
    cap_mode,     \* [1..MaxCaps -> Modes]
    invocations,  \* Seq of {cap, by, ok}        (history for proofs)
    next_cap

vars == <<txs, owners, reads, writes, commit_log, next_id,
          caps, cap_obj, cap_tx, cap_mode, invocations, next_cap>>

TxStates  == {"NONE", "ACTIVE", "COMMITTED", "ABORTED"}
CapStates == {"FREE", "LIVE", "REVOKED"}
Modes     == {"COMMIT_ONLY", "ACTIVE_OK", "UNBOUND"}

TypeOK ==
    /\ txs        \in [1..MaxTx -> TxStates]
    /\ owners     \in [1..MaxTx -> Clients \cup {"NONE"}]
    /\ reads      \in [1..MaxTx -> SUBSET Objects]
    /\ writes     \in [1..MaxTx -> SUBSET Objects]
    /\ commit_log \in Seq([tx: 1..MaxTx, ws: SUBSET Objects])
    /\ next_id    \in 1..(MaxTx+1)
    /\ caps       \in [1..MaxCaps -> CapStates]
    /\ cap_obj    \in [1..MaxCaps -> Objects \cup {"NONE"}]
    /\ cap_tx     \in [1..MaxCaps -> 0..MaxTx]
    /\ cap_mode   \in [1..MaxCaps -> Modes]
    /\ invocations \in Seq([cap: 1..MaxCaps, by: Clients,
                            ok: BOOLEAN, tx_phase: TxStates])
    /\ next_cap   \in 1..(MaxCaps+1)

Init ==
    /\ txs         = [i \in 1..MaxTx   |-> "NONE"]
    /\ owners      = [i \in 1..MaxTx   |-> "NONE"]
    /\ reads       = [i \in 1..MaxTx   |-> {}]
    /\ writes      = [i \in 1..MaxTx   |-> {}]
    /\ commit_log  = <<>>
    /\ next_id     = 1
    /\ caps        = [i \in 1..MaxCaps |-> "FREE"]
    /\ cap_obj     = [i \in 1..MaxCaps |-> "NONE"]
    /\ cap_tx      = [i \in 1..MaxCaps |-> 0]
    /\ cap_mode    = [i \in 1..MaxCaps |-> "UNBOUND"]
    /\ invocations = <<>>
    /\ next_cap    = 1

(*** STO core actions (v2, unchanged) ***)

Begin(c) ==
    /\ next_id <= MaxTx
    /\ txs'    = [txs    EXCEPT ![next_id] = "ACTIVE"]
    /\ owners' = [owners EXCEPT ![next_id] = c]
    /\ next_id' = next_id + 1
    /\ UNCHANGED <<reads, writes, commit_log,
                   caps, cap_obj, cap_tx, cap_mode, invocations, next_cap>>

Read(c, t, o) ==
    /\ t < next_id
    /\ txs[t] = "ACTIVE"
    /\ owners[t] = c
    /\ reads' = [reads EXCEPT ![t] = @ \cup {o}]
    /\ UNCHANGED <<txs, owners, writes, commit_log, next_id,
                   caps, cap_obj, cap_tx, cap_mode, invocations, next_cap>>

Write(c, t, o) ==
    /\ t < next_id
    /\ txs[t] = "ACTIVE"
    /\ owners[t] = c
    /\ writes' = [writes EXCEPT ![t] = @ \cup {o}]
    /\ UNCHANGED <<txs, owners, reads, commit_log, next_id,
                   caps, cap_obj, cap_tx, cap_mode, invocations, next_cap>>

CommittedAfter(t) ==
    {commit_log[i].ws : i \in 1..Len(commit_log)}

CanCommit(t) ==
    \A ws \in CommittedAfter(t) : reads[t] \cap ws = {}

(*** cap_ext actions ***)

Wrap(c, t, o, m) ==
    /\ next_cap <= MaxCaps
    /\ t < next_id
    /\ txs[t] = "ACTIVE"
    /\ owners[t] = c
    /\ m \in {"COMMIT_ONLY", "ACTIVE_OK"}
    /\ caps'     = [caps     EXCEPT ![next_cap] = "LIVE"]
    /\ cap_obj'  = [cap_obj  EXCEPT ![next_cap] = o]
    /\ cap_tx'   = [cap_tx   EXCEPT ![next_cap] = t]
    /\ cap_mode' = [cap_mode EXCEPT ![next_cap] = m]
    /\ next_cap' = next_cap + 1
    /\ UNCHANGED <<txs, owners, reads, writes, commit_log, next_id, invocations>>

(* Predicate: is this cap currently invocable? *)
Invocable(k) ==
    /\ caps[k] = "LIVE"
    /\ \/ /\ cap_mode[k] = "ACTIVE_OK"
          /\ txs[cap_tx[k]] = "ACTIVE"
       \/ /\ cap_mode[k] = "COMMIT_ONLY"
          /\ txs[cap_tx[k]] = "COMMITTED"

(* Each invocation snapshots the tx phase at the moment it occurred.
 * Without this, NoEffectsFromAborted reads "txs[cap_tx[i.cap]] != ABORTED"
 * against the CURRENT state, which is trivially violated by any legitimate
 * Invoke during ACTIVE followed by Rollback. The snapshot captures
 * "was the tx in a valid state when this invocation happened?" — that
 * is the invariant we actually want to enforce. *)
Invoke(c, k) ==
    /\ Invocable(k)
    /\ invocations' = Append(invocations,
                              [cap |-> k, by |-> c, ok |-> TRUE,
                               tx_phase |-> txs[cap_tx[k]]])
    /\ UNCHANGED <<txs, owners, reads, writes, commit_log, next_id,
                   caps, cap_obj, cap_tx, cap_mode, next_cap>>

InvokeFails(c, k) ==
    /\ ~Invocable(k)
    /\ k < next_cap
    /\ invocations' = Append(invocations,
                              [cap |-> k, by |-> c, ok |-> FALSE,
                               tx_phase |-> txs[cap_tx[k]]])
    /\ UNCHANGED <<txs, owners, reads, writes, commit_log, next_id,
                   caps, cap_obj, cap_tx, cap_mode, next_cap>>

(* Sweep all caps belonging to tx t. Models seL4_CNode_Revoke on tx root. *)
RevokeFor(t) ==
    caps' = [k \in 1..MaxCaps |-> IF cap_tx[k] = t /\ caps[k] = "LIVE"
                                   THEN "REVOKED"
                                   ELSE caps[k]]

Commit(c, t) ==
    /\ t < next_id
    /\ txs[t] = "ACTIVE"
    /\ owners[t] = c
    /\ CanCommit(t)
    /\ txs'        = [txs EXCEPT ![t] = "COMMITTED"]
    /\ commit_log' = Append(commit_log, [tx |-> t, ws |-> writes[t]])
    /\ UNCHANGED <<owners, reads, writes, next_id,
                   caps, cap_obj, cap_tx, cap_mode, invocations, next_cap>>

AbortOnConflict(c, t) ==
    /\ t < next_id
    /\ txs[t] = "ACTIVE"
    /\ owners[t] = c
    /\ ~CanCommit(t)
    /\ txs' = [txs EXCEPT ![t] = "ABORTED"]
    /\ RevokeFor(t)
    /\ UNCHANGED <<owners, reads, writes, commit_log, next_id,
                   cap_obj, cap_tx, cap_mode, invocations, next_cap>>

Rollback(c, t) ==
    /\ t < next_id
    /\ txs[t] = "ACTIVE"
    /\ owners[t] = c
    /\ txs' = [txs EXCEPT ![t] = "ABORTED"]
    /\ RevokeFor(t)
    /\ UNCHANGED <<owners, reads, writes, commit_log, next_id,
                   cap_obj, cap_tx, cap_mode, invocations, next_cap>>

Next ==
    \E c \in Clients :
        \/ Begin(c)
        \/ \E t \in 1..MaxTx, o \in Objects : Read(c, t, o)
        \/ \E t \in 1..MaxTx, o \in Objects : Write(c, t, o)
        \/ \E t \in 1..MaxTx, o \in Objects, m \in {"COMMIT_ONLY", "ACTIVE_OK"} : Wrap(c, t, o, m)
        \/ \E k \in 1..MaxCaps : Invoke(c, k)
        \/ \E k \in 1..MaxCaps : InvokeFails(c, k)
        \/ \E t \in 1..MaxTx : Commit(c, t)
        \/ \E t \in 1..MaxTx : AbortOnConflict(c, t)
        \/ \E t \in 1..MaxTx : Rollback(c, t)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(*** Invariants ***)

OnlyOwnerMutates ==
    \A t \in 1..MaxTx :
        (txs[t] # "NONE") => (owners[t] \in Clients)

NoLostUpdate ==
    \A i, j \in 1..Len(commit_log) :
        (i < j) =>
            (reads[commit_log[j].tx] \cap commit_log[i].ws = {}
             \/ commit_log[j].tx # commit_log[i].tx)

(* Core cap_ext property: no successful invocation EVER occurred while *)
(* its parent tx was in ABORTED state. The snapshot tx_phase captures   *)
(* the tx's state at the moment of the invocation, so subsequent state  *)
(* transitions of the same tx do not retro-invalidate past invocations.*)
NoEffectsFromAborted ==
    \A i \in 1..Len(invocations) :
        invocations[i].ok = TRUE => invocations[i].tx_phase # "ABORTED"

(* In COMMIT_ONLY mode, no successful invocation occurred while tx was   *)
(* ACTIVE. The invocation must have happened with tx in COMMITTED phase. *)
CommitOnlyVisibility ==
    \A i \in 1..Len(invocations) :
        /\ invocations[i].ok = TRUE
        /\ cap_mode[invocations[i].cap] = "COMMIT_ONLY"
        => invocations[i].tx_phase = "COMMITTED"

(* TLC bound on invocations length. Without this, the state space is     *)
(* infinite because every Invoke appends a new distinct state. Bounding  *)
(* the trace makes exhaustive model checking tractable while still      *)
(* covering the interesting interleavings of cap_ext operations.        *)
InvocationsBounded == Len(invocations) <= 5

=============================================================================
