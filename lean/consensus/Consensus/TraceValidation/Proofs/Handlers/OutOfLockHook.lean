module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.LifeHoare

@[expose] public section

/-!
# Obligation: the out-of-lock `add_configuration` hook (not reviewed)

A joiner installing a snapshot runs the snapshot's configuration hooks outside the consensus
lock, before `init_as_backup`, with no role and at view 0. The hook only touches the
configuration bookkeeping (`configurations`, `all_other_nodes`, and the retirement fields
`retired`, `retirement_phase`, `retirement_idx`), and sends nothing since the node is not
primary (`OolShape`). `agrees` reads none of these fields of a node that is not primary, so
the clean state agrees before and after: the hold is matched by no clean step.
-/

namespace Consensus.TraceValidation.Proofs.Life

open Consensus.Model.Node (activeConfigurations eligiblePeers)
open Consensus.TraceValidation.Exec

/-- `s` with only its configuration bookkeeping changed, and nothing sent. -/
def OolShape (s : State) (v : State) (o : Outbox) : Prop :=
  o = []
  /\ exists configurations allOtherNodes retired retirementPhase retirementIdx,
      v
      = { s with configurations, allOtherNodes, retired, retirementPhase, retirementIdx }

/-- One step of an `OolShape` preservation proof. -/
macro "ool_step" : tactic =>
  `(tactic|
    first
      | pres_step
      | (with_reducible refine Pres.setV (fun _ _ h => ?_)
         obtain ⟨o, _, _, _, _, _, e⟩ := h
         subst e
         exact ⟨o, _, _, _, _, _, rfl⟩)
      | dsimp only)

variable {env : Env} {s : State}

theorem ool_becomeRetired (idx : Nat)
    : Pres env (OolShape s) (becomeRetired idx .ordered) := by
  unfold becomeRetired
  dsimp only
  repeat' ool_step

theorem ool_createAndRemoveNodeState (none_ : s.leadership = .none)
    : Pres env (OolShape s) createAndRemoveNodeState := by
  unfold createAndRemoveNodeState
  repeat'
    first
      | (exfalso; simp_all; done)
      | (with_reducible refine Pres.getV_bind fun _ _ h => ?_
         obtain ⟨_, _, _, _, _, _, e⟩ := h
         subst e)
      | ool_step

theorem ool_addConfiguration (none_ : s.leadership = .none) (idx? : Option Nat)
    (expected : Option Nodes)
    : Pres env (OolShape s) (addConfiguration idx? expected) := by
  unfold addConfiguration
  repeat'
    first
      | with_reducible exact ool_becomeRetired _
      | with_reducible exact ool_createAndRemoveNodeState none_
      | ool_step

theorem ool_hold (none_ : s.leadership = .none)
    : Pres env (OolShape s) outOfLockHook := by
  unfold outOfLockHook
  exact Tri.discard (ool_addConfiguration none_ none none)

end Consensus.TraceValidation.Proofs.Life

namespace Consensus.TraceValidation.Proofs

open CCF.Sections (LocalRun)
open Consensus.TraceValidation.Exec (State)

theorem outOfLockHookSound (env : Env) : OutOfLockHookSound env := by
  intro node saved none_ view0 actions c vars others cleanOthers _ _ _ _ _ ran _
    finished _
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  have start : Life.OolShape saved saved [] := ⟨rfl, _, _, _, _, _, rfl⟩
  obtain ⟨silent, cs, aon, r, rp, ri, shape⟩ := Life.Tri.run (Life.ool_hold none_) start ran
  rw [silent, shape]
  refine ⟨
    rfl,
    fun clean _ agreed unmatched =>
      ⟨[], clean, LocalRun.nil _, ?_, unmatched, by simp, by simp⟩
  ⟩
  simpa [agrees, abs, trackedPeers, none_] using agreed

end Consensus.TraceValidation.Proofs
