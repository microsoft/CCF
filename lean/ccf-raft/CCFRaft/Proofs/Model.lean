-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Properties
import CCFRaft.Proofs.Refinement

set_option autoImplicit false

/-!
Election safety, and agreement of the committed logs in one state, for
`Model.transitionSystem`, from the refinement to the abstract model and the
abstract safety theorem.
-/

namespace CCFRaft.Proofs.Model

open Refinement
open CCFRaft.Model.Local (NodeState Bootstrap)
open Abstract.ReconfigurationPreservation (systemInductiveInvariantSafety)

theorem refines_of_trace {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId]
    [Bootstrap Node] {nodes : List Node} {trace : Properties.GlobalTrace Node TxId}
    {state : CCFRaft.Model.State Node TxId}
    (valid : trace.Valid (CCFRaft.Model.transitionSystem nodes))
    (member : state ∈ trace.states)
    : Refines state :=
  reachable_refines (valid.reachable member)

theorem election_safety : Properties.ElectionSafety := by
  intro Node TxId _ _ _ nodes trace state left right leftState rightState
    ⟨valid, member, leftMember, rightMember, leftLeader, rightLeader, sameTerm⟩
  obtain ⟨abstract, invariant, corr⟩ := refines_of_trace valid member
  apply (systemInductiveInvariantSafety invariant).electionSafety left right
  · rw [corr.nodes left leftState leftMember]
    exact leftLeader
  · rw [corr.nodes right rightState rightMember]
    exact rightLeader
  · rw [corr.nodes left leftState leftMember, corr.nodes right rightState rightMember]
    exact sameTerm

/-- Any two committed logs in one reachable state are prefix-comparable. -/
theorem committed_logs_prefix_here {Node TxId : Type} [DecidableEq Node]
    [DecidableEq TxId] [Bootstrap Node] {nodes : List Node}
    {state : CCFRaft.Model.State Node TxId}
    (reachable : (CCFRaft.Model.transitionSystem (TxId := TxId) nodes).Reachable state)
    {left right : Node} {leftState rightState : NodeState Node TxId}
    (leftMember : (left, leftState) ∈ state.nodes)
    (rightMember : (right, rightState) ∈ state.nodes)
    : leftState.committedLog <+: rightState.committedLog
      \/ rightState.committedLog <+: leftState.committedLog := by
  obtain ⟨abstract, invariant, corr⟩ := reachable_refines reachable
  have comparable := (systemInductiveInvariantSafety invariant).committedLogsPrefix left right
  rwa [corr.nodes left leftState leftMember, corr.nodes right rightState rightMember] at comparable

end CCFRaft.Proofs.Model
