module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Obligation
public import Consensus.TraceValidation.Proofs.Monad

@[expose] public section

/-!
# Obligation: `drop_pending_to` (not reviewed)

The driver's `drop_pending_to` only traces: no state change and no sends, so its clean
counterpart is the empty run.
-/

namespace Consensus.TraceValidation.Proofs

open CCF.Sections (LocalRun)
open Consensus.TraceValidation.Exec (State Ctx Action)

theorem run_dropPendingTo {env : Env} {saved : State} {actions : List Action} {c : Ctx}
    (h : Exec.run env saved actions true Exec.dropPendingTo = .ok c)
    : c.vars = saved /\ c.outbox = [] := by
  cases actions with
  | nil => unfold_run [Exec.dropPendingTo] at h
  | cons a rest =>
      by_cases point : a.point = "drop_pending_to"
      · unfold_run [Exec.dropPendingTo, point] at h
        cases h
        exact ⟨rfl, rfl⟩
      · unfold_run [Exec.dropPendingTo, point] at h

theorem dropPendingToSound (env : Env) : DropPendingToSound env := by
  intro node saved actions c vars others cleanOthers _ _ _ _ _ ran _ finished _
  obtain ⟨keeps, silent⟩ := run_dropPendingTo ran
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  rw [keeps, silent]
  refine ⟨
    rfl,
    fun clean _ agreed unmatched =>
      ⟨[], clean, ?_, agreed, unmatched, by simp, by simp⟩
  ⟩
  exact LocalRun.nil _

end Consensus.TraceValidation.Proofs
