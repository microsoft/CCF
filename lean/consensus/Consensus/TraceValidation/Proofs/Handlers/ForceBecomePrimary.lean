module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.LifeHoare

@[expose] public section

/-!
# Obligation: `force_become_primary` (not reviewed)

The genesis node's untraced `force_become_primary`, opened by its `become_leader`. It starts
pristine (no ledger entry), so the clean part of the obligation is vacuous: `HoldSound` asks
for clean steps only from a non-pristine state. What remains is that the hold keeps the node
id (the machine checks `inv` at release). Throughout the hold the node has no ledger entry and nothing committed
(`ForceShape`), so `commit` never commits, `rollback` is never reached, and every state
change is the view bump, the leader role, and peer bookkeeping.
-/

namespace Consensus.TraceValidation.Proofs.Life

open Consensus.Model.Node (activeConfigurations eligiblePeers)
open Consensus.TraceValidation.Exec

/-- The genesis primary between the view bump and the end of `force_become_primary`. -/
def ForceShape (n : NodeId) (v : State) (_ : Outbox) : Prop :=
  v.nodeId = n
  /\ v.currentView = 2
  /\ v.lastIdx = 0
  /\ v.ledger.size = 0
  /\ v.commitIdx = 0
  /\ v.committable = []
  /\ v.views.size = 0
  /\ (v.leadership = .leader -> v.leaderId = some v.nodeId)

/-- One step of a `ForceShape` preservation proof. -/
macro "force_step" : tactic =>
  `(tactic|
    first
      | with_reducible exact pres_highest _
      | pres_step
      | (with_reducible refine Pres.setV (fun _ _ h => ?_)
         simpa [ForceShape, State.setPeer] using h)
      | (with_reducible refine Tri.send fun _ _ h => ?_; simpa [ForceShape] using h)
      | dsimp only)

variable {env : Env} {n : NodeId}

theorem force_commit (i : Nat) : Pres env (ForceShape n) (commit i) := by
  unfold commit
  refine Pres.getV_bind fun v o h => ?_
  obtain ⟨_, _, _, _, _, _⟩ := h
  dsimp only
  repeat' (first | (exfalso; omega) | force_step)

theorem force_updateCommitGo (fuel first : Nat) (nc : Option Nat)
    : Pres env (ForceShape n) (updateCommitGo first nc fuel) := by
  induction fuel generalizing first nc with
  | zero => unfold updateCommitGo; exact Pres.fail _
  | succ fuel ih =>
      unfold updateCommitGo
      repeat' (first | with_reducible exact ih _ _ | force_step)

theorem force_updateCommit : Pres env (ForceShape n) updateCommit := by
  unfold updateCommit
  repeat'
    first
      | with_reducible exact force_updateCommitGo _ _ _
      | with_reducible exact force_commit _
      | force_step

theorem force_sendRange (to : NodeId) (s e : Nat) (ext : Bool)
    : Pres env (ForceShape n) (sendAppendEntriesRange to s e ext) := by
  unfold sendAppendEntriesRange
  repeat' force_step

theorem force_sendLoop (to : NodeId) (ext : Bool) (fuel s : Nat) (b : Option Nat)
    : Pres env (ForceShape n) (sendAppendEntries.loop to ext fuel s b) := by
  induction fuel generalizing s b with
  | zero => unfold sendAppendEntries.loop; repeat' force_step
  | succ fuel ih =>
      rw [sendAppendEntries.loop]
      dsimp only
      repeat'
        first
          | with_reducible exact ih _ _
          | with_reducible exact force_sendRange _ _ _ _
          | force_step

theorem force_send (to : NodeId) (s : Nat) (ext : Bool)
    : Pres env (ForceShape n) (sendAppendEntries to s ext) := by
  unfold sendAppendEntries
  repeat' (first | with_reducible exact force_sendLoop _ _ _ _ _ | force_step)

theorem force_becomeLeader : Pres env (ForceShape n) becomeLeader := by
  unfold becomeLeader
  refine Pres.getV_bind fun v o h => ?_
  obtain ⟨_, _, _, _, _, _⟩ := h
  dsimp only
  repeat'
    first
      | (exfalso; omega)
      | with_reducible exact force_updateCommit
      | with_reducible exact force_send _ _ _
      | with_reducible exact pres_otherNodesSorted
      | (with_reducible refine Pres.setV fun _ _ h => ?_
         obtain ⟨h1, h2, h3, h4, h5, h6, h7, _⟩ := h
         exact ⟨h1, h2, h3, h4, h5, h6, h7, fun _ => rfl⟩)
      | force_step

/-- The pristine genesis node at view 0 with no role, as `inv` and the premises give it. -/
def ForceStart (n : NodeId) (v : State) (_ : Outbox) : Prop :=
  v.nodeId = n
  /\ v.currentView = 0
  /\ v.lastIdx = 0
  /\ v.ledger.size = 0
  /\ v.commitIdx = 0
  /\ v.committable = []
  /\ v.views.size = 0
  /\ v.leadership = .none

theorem force_hold : Tri env (ForceStart n) forceBecomePrimary fun _ => ForceShape n := by
  unfold forceBecomePrimary
  refine Tri.bind (Q := fun _ => ForceShape n) (Tri.setV fun v _ h => ?_) fun _ => ?_
  · obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩ := h
    exact ⟨h1, by simp [h2], h3, h4, h5, h6, h7, fun l => by simp [h8] at l⟩
  · exact Pres.bind force_becomeLeader fun _ => Pres.ite (fun _ => Pres.pure _) fun _ =>
      Pres.fail _

end Consensus.TraceValidation.Proofs.Life

namespace Consensus.TraceValidation.Proofs

open Consensus.TraceValidation.Exec (State)

theorem forceBecomePrimarySound (env : Env) : ForceBecomePrimarySound env := by
  intro node saved view0 none_ pristine_ actions c vars others cleanOthers _ _ invSaved _ _ ran
    _ finished _
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  have last : saved.lastIdx = 0 := by
    simp only [pristine, Bool.and_eq_true, beq_iff_eq] at pristine_
    exact pristine_.2
  have start : Life.ForceStart saved.nodeId saved [] := by
    simp only [inv, invChecks, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true]
      at invSaved
    obtain ⟨size, le, committable, _, _, views, _⟩ := invSaved
    simp only [beq_iff_eq, decide_eq_true_eq, last, view0] at size le committable views
    refine ⟨rfl, view0, last, size, by omega, ?_, by omega, none_⟩
    simpa [signaturesIn, last] using committable
  have shape := Life.Tri.run Life.force_hold start ran
  refine ⟨shape.1, fun clean notPristine _ _ => ?_⟩
  rw [pristine_] at notPristine
  cases notPristine

end Consensus.TraceValidation.Proofs
