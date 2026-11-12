-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Proofs.Retention
public import Kv.Proofs.Capture

@[expose] public section

namespace Kv.Proofs.AdapterRetention

open Kv.Model
      hiding Store Tx advance compactStore rollbackStore tryApply step transitionSystem
open Kv.TraceValidation Kv.Properties Kv.Proofs.Correspondence Kv.Proofs.Retention

private theorem translated_attempt (w : World) (tid : Nat) (event : Event)
    (segment : AttemptEvent tid event)
    : ∀ action ∈ actions w event, AttemptAction tid action := by
  cases event <;> simp [AttemptEvent, actions, AttemptAction] at segment ⊢
  all_goals first
    | exact segment
    | intro action member
      rcases member with ⟨_, rfl⟩ | rfl <;> trivial

/-- Every accepted record preserves previously captured semantic views of a surviving attempt. -/
theorem step_kept (w next : World) (tid : Nat) (before : Tx) (r : Record)
    (live : find w.txs tid = some before) (segment : AttemptEvent tid r.event)
    (accepted : transitionSystem.step w r = some next)
    : ∃ after, find next.txs tid = some after ∧ Kept before.toTx after.toTx := by
  have projectedLive : find (project w).txs tid = some before.toTx := by
    simp only [project_tx, live, Option.map_some]
  obtain ⟨core, finalLive, kept⟩ :=
    run_retains (project w) (project next) tid before.toTx (actions w r.event)
      projectedLive (translated_attempt w tid r.event segment) (step_projects w next r accepted)
  obtain ⟨after, found, equal⟩ := project_tx_exists next tid core finalLive
  exact ⟨after, found, by simpa only [equal] using kept⟩

/-- Trace replay inherits semantic captured-view preservation, including metadata-only stutters. -/
theorem replay_kept (w final : World) (tid : Nat) (before : Tx) (rs : List Record)
    (live : find w.txs tid = some before) (segment : ∀ r ∈ rs, AttemptEvent tid r.event)
    (run : CCF.Execution.Run transitionSystem w rs final)
    : ∃ after, find final.txs tid = some after ∧ Kept before.toTx after.toTx := by
  induction rs generalizing w before with
  | nil =>
      cases run using @CCF.Execution.Run.casesOn transitionSystem
      exact ⟨before, live, ⟨rfl, fun _ h => h, fun _ _ h => ⟨h, rfl⟩⟩⟩
  | cons r rest ih =>
      cases run using @CCF.Execution.Run.casesOn transitionSystem with
      | @cons _ next _ _ _ transition tail =>
          obtain ⟨middle, middleLive, first⟩ :=
            step_kept w next tid before r live (segment r (List.mem_cons_self)) transition
          obtain ⟨after, finalLive, second⟩ :=
            ih next middle middleLive (fun a member => segment a (List.mem_cons_of_mem _ member)) tail
          exact ⟨after, finalLive, kept_trans first second⟩

end Kv.Proofs.AdapterRetention
