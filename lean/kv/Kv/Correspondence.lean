-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.TraceValidation.System
public import CCF.Execution

import Kv.Proofs.Correspondence

@[expose] public section

/-! Trace conformance: accepted replay exercises the semantic model and agrees with its outputs. -/

namespace Kv.Correspondence

open Kv.Model hiding Store Tx step transitionSystem
open Kv.TraceValidation

/-- Every accepted trace record exercises the semantic model or stutters for bookkeeping. -/
theorem step_projects
    : ∀ (w next : World) (r : Record),
        TraceValidation.transitionSystem.step w r = some next
        → CCF.Execution.Run Model.transitionSystem (project w) (actions w r.event)
            (project next) := by
  exact Proofs.Correspondence.step_projects

/-- Witness: a nonempty input creates a semantic store, rather than only recording scopes. -/
theorem step_projects_witness
    : ∃ (w next : World) (r : Record),
        TraceValidation.transitionSystem.step w r = some next
        ∧ actions w r.event ≠ [] := by
  exact Proofs.Correspondence.step_projects_witness

/-- Reported observations match the actual output of the translated semantic execution. -/
theorem step_reports
    : ∀ (w next : World) (r : Record),
        TraceValidation.transitionSystem.step w r = some next
        → ∃ output,
            executeActions (project w) (actions w r.event) = some (project next, output)
            ∧ reportedMatches r.event output = true := by
  exact Proofs.Correspondence.step_reports

/-- Witness: a read report is checked against the semantic absence result. -/
theorem step_reports_witness
    : ∃ (w next : World) (r : Record),
        TraceValidation.transitionSystem.step w r = some next
        ∧ r.event = .get 1 1 "m" "k" none false := by
  exact Proofs.Correspondence.step_reports_witness

/-- Accepted typed replay executes exactly the inputs translated along its own worlds. -/
theorem replay_projects
    : ∀ (w final : World) (records : List Record),
        replay w records = .ok final
        → ∃ inputs,
            semanticInputs w records = .ok inputs
            ∧ CCF.Execution.Run Model.transitionSystem (project w) inputs
                (project final) := by
  exact Proofs.Correspondence.replay_projects

/-- Witness: a nonempty typed replay has a semantic execution. -/
theorem replay_projects_witness
    : ∃ (w final : World) (records : List Record),
        replay w records = .ok final ∧ records ≠ [] := by
  exact Proofs.Correspondence.replay_projects_witness

/-- Trace-reachable projections are reachable by the executable semantic system. -/
theorem reachable_projects
    : ∀ w : World,
        TraceValidation.transitionSystem.Reachable w
        → Model.transitionSystem.Reachable (project w) := by
  exact Proofs.Correspondence.reachable_projects

/-- Witness: such a projection contains a live semantic store. -/
theorem reachable_projects_witness
    : ∃ (w : World) (sid : Nat) (s : Model.Store),
        TraceValidation.transitionSystem.Reachable w
        ∧ find (project w).stores sid = some s := by
  exact Proofs.Correspondence.reachable_projects_witness

end Kv.Correspondence
