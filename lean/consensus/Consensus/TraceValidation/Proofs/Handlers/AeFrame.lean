module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeHoare
public import Consensus.TraceValidation.Aft

@[expose] public section

/-!
# Helpers that leave the AppendEntries-relevant state alone (not reviewed)

`core v` collects the declared fields the AppendEntries proof tracks. `Frame env x`: on a
non-leader, `x` keeps `core` and sends nothing. Configuration hooks, peer bookkeeping and
retirement phases other than `retired_committed` are frames.
-/

namespace Consensus.TraceValidation.Proofs.Ae

open Consensus.Model.Node
open Consensus.TraceValidation.Exec

structure Core where
  nodeId : NodeId
  currentView : Nat
  votedFor : Option NodeId
  isNewFollower : Bool
  ledger : Array Exec.Entry
  lastIdx : Nat
  commitIdx : Nat
  committable : List Nat
  views : Array Nat
  leadership : Leadership
  leaderId : Option NodeId
  retiredCommittedIdx : Option Nat
  rcEntries : List (Nat × List NodeId)

def core (v : State) : Core :=
  ⟨
    v.nodeId,
    v.currentView,
    v.votedFor,
    v.isNewFollower,
    v.ledger,
    v.lastIdx,
    v.commitIdx,
    v.committable,
    v.views,
    v.leadership,
    v.leaderId,
    v.retiredCommittedIdx,
    v.rcEntries
  ⟩

def Frame {α : Type} (env : Env) (x : M α) : Prop :=
  forall (c0 : Core) (o0 : Outbox),
    c0.leadership ≠ .leader
    -> Hoare env (fun v o => core v = c0 /\ o = o0) x (fun _ v o => core v = c0 /\ o = o0)

namespace Frame
variable {env : Env}

theorem keeps {α : Type} {x : M α} (h : Spec.Keeps env x) : Frame env x :=
  fun _ _ _ => Hoare.keeps h fun _ _ _ p => p

theorem bind {α β : Type} {x : M α} {f : α -> M β} (hx : Frame env x)
    (hf : forall a, Frame env (f a))
    : Frame env (x >>= f) :=
  fun c0 o0 h => Hoare.bind (hx c0 o0 h) fun a => hf a c0 o0 h

theorem getV_bind {β : Type} {k : State -> M β}
    (hk : forall s, s.leadership ≠ .leader -> Frame env (k s))
    : Frame env (Exec.getV >>= k) := by
  intro c0 o0 h
  refine Hoare.getV_bind fun s => ?_
  by_cases hs : s.leadership ≠ .leader
  · exact Hoare.pre (hk s hs c0 o0 h) fun _ _ p => p.1
  · refine Hoare.false_pre fun v o ⟨⟨hc, _⟩, hv⟩ => ?_
    subst hv hc
    exact hs h

theorem ite {α : Type} {b : Prop} [Decidable b] {x y : M α} (hx : b -> Frame env x)
    (hy : Not b -> Frame env y)
    : Frame env (if b then x else y) := by
  by_cases h : b
  · simpa [h] using hx h
  · simpa [h] using hy h

theorem pure {α : Type} (a : α) : Frame env (Pure.pure a : M α) :=
  keeps (Spec.Keeps.pure a)

theorem fail {α : Type} (m : String) : Frame env (Exec.fail m : M α) :=
  fun _ _ _ => Hoare.fail m

theorem setV {f : State -> State}
    (hf : forall v, v.leadership ≠ .leader -> core (f v) = core v)
    : Frame env (Exec.setV f) := by
  intro c0 o0 h
  refine Hoare.setV f fun v o ⟨hc, ho⟩ => ⟨?_, ho⟩
  rw [hf v (by subst hc; exact h), hc]

theorem trace (fn : String) : Frame env (Exec.trace fn) := keeps (Spec.trace fn)

theorem emit (k : String) (j : Lean.Json) : Frame env (Exec.emit k j) :=
  keeps (Spec.emit k j)

theorem emitStr (k s : String) : Frame env (Exec.emitStr k s) := keeps (Spec.emitStr k s)

theorem emitNat (k : String) (n : Nat) : Frame env (Exec.emitNat k n) :=
  keeps (Spec.emitNat k n)

theorem curLoc : Frame env Exec.curLoc := keeps Spec.curLoc
theorem inNat (k : String) : Frame env (Exec.inNat k) := keeps (Spec.inNat k)
theorem use (k : String) : Frame env (Exec.use k) := keeps (Spec.use k)

theorem liftE {α : Type} (x : Except String α) : Frame env (Exec.liftE x) :=
  keeps (Spec.liftE x)

theorem forIn_list {α β : Type} (l : List α) (init : β) {f : α -> β -> M (ForInStep β)}
    (hf : forall a b, Frame env (f a b))
    : Frame env (forIn l init f) := by
  induction l generalizing init with
  | nil => exact pure init
  | cons a rest ih =>
      rw [List.forIn_cons]
      refine bind (hf a init) fun r => ?_
      cases r with
      | done b => exact pure b
      | yield b => exact ih b

theorem option {α β : Type} {o : Option α} {x : M β} {f : α -> M β} (hx : Frame env x)
    (hf : forall a, Frame env (f a))
    : Frame env
        (match o with
          | none => x
          | some a => f a) := by
  cases o
  · exact hx
  · exact hf _

end Frame

/-- Extension point: `Frame` lemmas for named helpers. -/
syntax "frame_ext" : tactic
macro_rules | `(tactic| frame_ext) => `(tactic| fail "no frame lemma")

/-- Decompose a handler into `Frame` rules. -/
macro "frame_tac" : tactic =>
  `(tactic| repeat' (first
    | with_reducible exact Consensus.TraceValidation.Proofs.Ae.Frame.pure _
    | with_reducible exact Consensus.TraceValidation.Proofs.Ae.Frame.fail _
    | with_reducible exact Consensus.TraceValidation.Proofs.Ae.Frame.trace _
    | with_reducible exact Consensus.TraceValidation.Proofs.Ae.Frame.emit _ _
    | with_reducible exact Consensus.TraceValidation.Proofs.Ae.Frame.emitStr _ _
    | with_reducible exact Consensus.TraceValidation.Proofs.Ae.Frame.emitNat _ _
    | with_reducible exact Consensus.TraceValidation.Proofs.Ae.Frame.curLoc
    | with_reducible exact Consensus.TraceValidation.Proofs.Ae.Frame.inNat _
    | with_reducible exact Consensus.TraceValidation.Proofs.Ae.Frame.use _
    | with_reducible exact Consensus.TraceValidation.Proofs.Ae.Frame.liftE _
    | with_reducible apply Consensus.TraceValidation.Proofs.Ae.Frame.getV_bind
    | with_reducible apply Consensus.TraceValidation.Proofs.Ae.Frame.bind
    | with_reducible apply Consensus.TraceValidation.Proofs.Ae.Frame.ite
    | with_reducible apply Consensus.TraceValidation.Proofs.Ae.Frame.forIn_list
    | with_reducible apply Consensus.TraceValidation.Proofs.Ae.Frame.option
    | ((with_reducible apply Consensus.TraceValidation.Proofs.Ae.Frame.setV); intro _ _;
        first
        | rfl
        | (simp only [Consensus.TraceValidation.Proofs.Ae.core,
            Consensus.TraceValidation.Exec.State.setPeer]; done))
    | frame_ext
    | (exfalso; simp_all; done)
    | (with_reducible intro)
    | dsimp only
    | with_reducible split))

theorem frame_startTicking (env : Env) : Frame env Exec.startTickingIfNecessary := by
  unfold Exec.startTickingIfNecessary
  refine Frame.setV fun v _ => ?_
  split <;> rfl

theorem frame_createAndRemove (env : Env) : Frame env Exec.createAndRemoveNodeState := by
  unfold Exec.createAndRemoveNodeState
  frame_tac

macro_rules | `(tactic| frame_ext) => `(tactic| exact frame_createAndRemove _)
macro_rules | `(tactic| frame_ext) => `(tactic| exact frame_startTicking _)

theorem frame_becomeRetired (env : Env) (idx : Nat) (phase : Phase)
    (h : phase ≠ .retiredCommitted)
    : Frame env (Exec.becomeRetired idx phase) := by
  unfold Exec.becomeRetired
  cases phase
  all_goals first | exact absurd rfl h | skip
  all_goals frame_tac

macro_rules | `(tactic| frame_ext) => `(tactic| exact frame_becomeRetired _ _ _ (by decide))

theorem frame_addConfiguration (env : Env) (idx : Option Nat) (nodes : Option Nodes)
    : Frame env (Exec.addConfiguration idx nodes) := by
  unfold Exec.addConfiguration
  frame_tac

end Consensus.TraceValidation.Proofs.Ae
