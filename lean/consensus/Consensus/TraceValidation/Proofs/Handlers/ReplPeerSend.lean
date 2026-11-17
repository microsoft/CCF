module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplSend
public import Consensus.TraceValidation.Proofs.Handlers.ReplPeers

@[expose] public section

/-!
# `send_append_entries` to one peer from its send frontier (not reviewed; `Replicate`)

From one past a peer's send index, `send_append_entries` sends ranges that each start at the
peer's send index and end within the ledger in one view. Any ghost predicate that each such
range keeps is kept by the whole call.
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation.Proofs.Life

variable {env : Env}

theorem tri_pin {α : Type} {x : M α} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop}
    (h : forall v0 o0, P v0 o0 -> Tri env (fun v o => v = v0 /\ o = o0) x Q)
    : Tri env P x Q :=
  fun c a c' e p r => h c.vars c.outbox p c a c' e ⟨rfl, rfl⟩ r

/-- What a range from the send frontier `p.sentIdx` to `e` requires of `e`. -/
def RangeOk (v : State) (p : Peer) (e : Nat) : Prop :=
  p.sentIdx <= e
  /\ e <= v.lastIdx
  /\ forall i, p.sentIdx < i -> i <= e -> v.viewAt i = v.viewAt e

/-- The range a peer's send leaves in its send index and outbox. -/
def rangeEnv (env : Env) (v : State) (to : NodeId) (p : Peer) (e : Nat)
    : CCF.Envelope NodeID Message :=
  ⟨
    env.names.id v.nodeId,
    env.names.id to,
    .appendEntriesRequest (rangeRequest env.names v (p.sentIdx + 1) e)
  ⟩

theorem peerSend_tri {to : NodeId} {ext : Bool} {G : State -> Outbox -> Prop}
    (base
      : forall v o,
          G v o
          -> ViewHyps v
              /\ v.isRetiredCommitted = false
              /\ (v.allOtherNodes.map Prod.fst).Nodup)
    (step
      : forall v o p e,
          G v o
          -> v.peer? to = some p
          -> RangeOk v p e
          -> G (v.setPeer to { p with sentIdx := e }) (o ++ [rangeEnv env v to p e]))
    {start : Nat}
    : Tri env
        (fun v o =>
          G v o
          /\ exists p,
              v.peer? to = some p /\ start = p.sentIdx + 1 /\ p.sentIdx <= v.lastIdx)
        (sendAppendEntries to start ext) fun _ => G := by
  refine send_tri (I := fun s v o => G v o /\ exists p, v.peer? to = some p
    /\ s = p.sentIdx + 1 /\ p.sentIdx <= v.lastIdx) (fun _ v o h => (base v o h.1).2.1)
    (fun s e => ?_)
  refine tri_pin fun v0 o0 pre => ?_
  obtain ⟨⟨g, p, found, rfl, pL⟩, ok⟩ := pre
  obtain ⟨vh, -, nd⟩ := base _ _ g
  have facts : RangeOk v0 p e := by
    unfold OkEnd at ok
    by_cases hL : p.sentIdx = v0.lastIdx
    · rw [hL, maxIdx_past vh] at ok
      simp only [gt_iff_lt, Nat.lt_add_one, ite_true] at ok
      subst ok
      exact ⟨Nat.le_of_eq hL, Nat.le_refl _, fun i h1 h2 => by omega⟩
    · obtain ⟨m1, m2, same⟩ := maxIdx_range vh (start := p.sentIdx + 1) (by omega) (by omega)
      have : Not (p.sentIdx + 1 > maxEnd v0 (p.sentIdx + 1)) := by omega
      simp only [this, ite_false] at ok
      exact ⟨by omega, by omega, fun i h1 h2 =>
        (same i (by omega) (by omega)).trans (same e (by omega) (by omega)).symm⟩
  refine Tri.conseq (tri_of_hoare (sendRange_spec (o0 := o0) found)) (fun _ _ h => h)
    (fun _ v o h => ?_)
  obtain ⟨rfl, rfl⟩ := h
  have g' := step _ _ _ _ g found facts
  refine ⟨fun _ => g', fun ne => ⟨g', { p with sentIdx := e }, ?_, ?_, ?_⟩⟩
  · rw [setPeer_lookup nd]
    simp
  · simp only [setPeer_lastIdx] at ne ⊢
    have := facts.2.1
    show min (e + 1) v0.lastIdx = e + 1
    omega
  · exact facts.2.1

end Consensus.TraceValidation.Proofs.Repl
