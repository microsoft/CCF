-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Refinement.Correspondence

set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

/-!
# Abstract moves

One concrete step is simulated by a finite sequence of abstract moves: enabled
abstract actions, and reorderings of one abstract destination queue. Every
move preserves the abstract invariant and extends every committed log.
-/

namespace CCFRaft.Proofs.Refinement

open Model.Local (NodeState Bootstrap)
open Abstract.Model (updateQueue)
open Abstract.Invariant (SystemInductiveInvariant)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

/-- Abstract moves that simulate one concrete step. -/
inductive Moves : Abstract.Model.State Node TxId -> Abstract.Model.State Node TxId -> Prop where
  | done (state : Abstract.Model.State Node TxId) : Moves state state
  | step {state final : Abstract.Model.State Node TxId} (action : Abstract.Model.Action Node TxId)
      (enabled : Abstract.Model.Enabled state action)
      (rest : Moves (Abstract.Model.next state action) final) : Moves state final
  | reorder {state final : Abstract.Model.State Node TxId} (destination : Node)
      (queue : List (Abstract.Model.Message Node TxId))
      (perm : queue.Perm (state.network destination))
      (rest : Moves { state with network := updateQueue state.network destination queue } final) :
      Moves state final

theorem Moves.single {state : Abstract.Model.State Node TxId} {action : Abstract.Model.Action Node TxId}
    (enabled : Abstract.Model.Enabled state action) :
    Moves state (Abstract.Model.next state action) :=
  .step action enabled (.done _)

theorem Moves.trans {first second third : Abstract.Model.State Node TxId}
    (head : Moves first second) (tail : Moves second third) : Moves first third := by
  induction head with
  | done => exact tail
  | step action enabled _ ih => exact .step action enabled (ih tail)
  | reorder destination queue perm _ ih => exact .reorder destination queue perm (ih tail)

/-- Moves preserve the invariant and never shorten or rewrite a committed log. -/
theorem Moves.preserves {first second : Abstract.Model.State Node TxId}
    (moves : Moves first second) (invariant : SystemInductiveInvariant first) :
    SystemInductiveInvariant second /\
      forall node, (first.nodes node).committedLog <+: (second.nodes node).committedLog := by
  induction moves with
  | done => exact ⟨invariant, fun _ => List.prefix_refl _⟩
  | @step state _ action enabled _ ih =>
      obtain ⟨final, extended⟩ :=
        ih (Abstract.ReconfigurationPreservation.systemInductiveInvariantPreserved
          state action invariant enabled)
      refine ⟨final, fun node => ?_⟩
      exact ((Abstract.ReconfigurationPreservation.systemInductiveInvariantSafety invariant
        ).committedLogAppendOnly action enabled node).trans (extended node)
  | @reorder state _ destination queue perm _ ih =>
      apply ih
      apply Abstract.ReconfigurationPreservation.pureNetworkDequeuePreservesSystemInductiveInvariant
        state _ invariant
      intro target message member
      by_cases same : target = destination
      · subst target
        simpa [updateQueue] using perm.subset (by simpa [updateQueue] using member)
      · simpa [updateQueue, same] using member

end CCFRaft.Proofs.Refinement
