-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Properties
import CCFRaft.Proofs.Refinement

set_option autoImplicit false

/-!
The safety properties of `Model.transitionSystem`, from the refinement to the
abstract model and the abstract safety theorem.
-/

namespace CCFRaft.Proofs.Model

open Refinement
open CCFRaft.Model.Local (NodeState Bootstrap)
open Abstract.ReconfigurationPreservation (systemInductiveInvariantSafety)

theorem refines_of_trace {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]
    {nodes : List Node} {trace : Properties.GlobalTrace Node TxId}
    {state : CCFRaft.Model.State Node TxId}
    (valid : trace.Valid (CCFRaft.Model.transitionSystem nodes)) (member : state ∈ trace.states) :
    Refines state :=
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

theorem committed_logs_prefix : Properties.CommittedLogsPrefix := by
  intro Node TxId _ _ _ nodes trace state left right leftState rightState
    ⟨valid, member, leftMember, rightMember⟩
  obtain ⟨abstract, invariant, corr⟩ := refines_of_trace valid member
  have comparable := (systemInductiveInvariantSafety invariant).committedLogsPrefix left right
  rwa [corr.nodes left leftState leftMember, corr.nodes right rightState rightMember] at comparable

theorem committed_frontier_is_signature : Properties.CommittedFrontierIsSignature := by
  intro Node TxId _ _ _ nodes trace state node nodeState ⟨valid, member, nodeMember, positive⟩
  obtain ⟨abstract, invariant, corr⟩ := refines_of_trace valid member
  have signature := (systemInductiveInvariantSafety invariant).committedFrontierIsSignature node
  rw [corr.nodes node nodeState nodeMember] at signature
  exact signature positive

theorem committed_log_append_only : Properties.CommittedLogAppendOnly := by
  intro Node TxId _ _ _ nodes trace step before after node beforeState afterState
    ⟨valid, first, second, beforeMember, afterMember⟩
  obtain ⟨action, stepped⟩ := valid.2 step before after first second
  have refines := refines_of_trace valid (List.mem_of_getElem? first)
  exact (refines_step refines stepped).2 node beforeState afterState beforeMember afterMember

end CCFRaft.Proofs.Model
