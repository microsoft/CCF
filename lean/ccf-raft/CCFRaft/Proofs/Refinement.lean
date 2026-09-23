-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Refinement.Deliver

set_option autoImplicit false
set_option linter.unusedSectionVars false

/-!
# The network model refines the abstract model

Every reachable state of `Model.transitionSystem` corresponds to an abstract
state that satisfies the abstract inductive invariant. Each concrete step is
matched by abstract moves.
-/

namespace CCFRaft.Proofs.Refinement

open Shared Shared.MultiNodeTransitionSystem
open Model.Local (NodeState Bootstrap)
open Abstract.Invariant (SystemInductiveInvariant)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

/-- One concrete step is matched by abstract moves. -/
theorem simulate_step {nodes : List Node} {concrete next : Model.State Node TxId}
    {abstract : Abstract.Model.State Node TxId} {action : Model.Action Node TxId}
    (invariant : SystemInductiveInvariant abstract) (corr : Corr concrete abstract)
    (stepped : (Model.transitionSystem nodes).step concrete action = some next)
    : exists after, Moves abstract after /\ Corr next after := by
  cases action with
  | «local» node input =>
      obtain ⟨state, execute, found, acted, rfl⟩ := step_local stepped
      exact simulate_act invariant corr found acted
  | deliver envelope =>
      obtain ⟨member, state, execute, found, received, rfl⟩ := step_deliver stepped
      exact simulate_deliver corr member found received

theorem refines_initial {nodes : List Node} {concrete : Model.State Node TxId}
    (initialized : (Model.transitionSystem nodes).init concrete)
    : Refines concrete :=
  ⟨
    _,
    Abstract.ReconfigurationPreservation.initialSystemInductiveInvariant,
    corr_initial initialized
  ⟩

/-- A step from a refining state reaches a refining state. -/
theorem refines_step {nodes : List Node} {concrete next : Model.State Node TxId}
    {action : Model.Action Node TxId} (refines : Refines concrete)
    (stepped : (Model.transitionSystem nodes).step concrete action = some next)
    : Refines next := by
  obtain ⟨abstract, invariant, corr⟩ := refines
  obtain ⟨final, moves, related⟩ := simulate_step invariant corr stepped
  exact ⟨final, moves.preserves invariant, related⟩

theorem reachable_refines {nodes : List Node} {concrete : Model.State Node TxId}
    (reachable : (Model.transitionSystem nodes).Reachable concrete)
    : Refines concrete := by
  induction reachable with
  | initial initialized => exact refines_initial initialized
  | step _ stepped ih => exact refines_step ih stepped

end CCFRaft.Proofs.Refinement
