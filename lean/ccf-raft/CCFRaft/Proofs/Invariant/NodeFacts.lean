-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Ops
import CCFRaft.Proofs.Ledger

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

register_simp_attr concrete_effects

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Model.Local (
  BOOTSTRAP_TERM Bootstrap Configuration Entry EntryContent INITIAL_CONFIGURATION
    INITIAL_LEADER INITIAL_PRE_VOTE_STATUS MembershipState NodeState PreVoteStatus Role
    activeConfigurations activeNodeUnion allConfigurations allRetiredCommittedNodes
    becomeCandidateNodeState campaignEligible configurationsInLog configurationsInLogFrom
    currentConfiguration currentConfigurationAt entryAt? findHighestPossibleMatch
    hasConfigurationMajority highestActiveConfigurationWithNode implicitConfiguration
    initialNodeState isSignatureAt lastCommittableIndex lastCommittableTerm
    latestConfiguration maxCommittableIndex maxCommittableIndexUpTo maxCommittableTerm
    messageEntries refreshRetirementState retiredCommittedIndexFrom
    retiredCommittedIndexInLog retiredCommittedNodesUpTo retiredCommittedNodesUpToFrom
    retirementCommittableIndexInLog retirementCompletedNodes
    retirementIndexFromConfigurations retirementIndexInLog signatureIndexAfterFrom termAt
    updateIndex
  )
open CCFRaft.Proofs.Ledger

/-- Every valid bootstrap configuration contains its selected leader. -/
lemma initialLeader_mem_initialConfiguration
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : Bootstrap Node]
    : Membership.mem
        (INITIAL_CONFIGURATION (Node := Node))
        (INITIAL_LEADER (Node := Node)) :=
  bootstrap.leader_mem

variable {Node TxId : Type}
variable [DecidableEq Node]

/-- Reading the updated peer index returns the new value. -/
@[simp]
lemma updateIndex_same (indices : Node -> Nat) (node : Node) (value : Nat)
    : updateIndex indices node value node = value := by
  simp [updateIndex]

variable [Bootstrap Node] [DecidableEq TxId]

@[simp]
lemma refreshRetirementState_role (node : Node) (state : NodeState Node TxId)
    : (refreshRetirementState node state).role = state.role := by
  simp [refreshRetirementState]

@[simp]
lemma refreshRetirementState_currentTerm (node : Node) (state : NodeState Node TxId)
    : (refreshRetirementState node state).currentTerm = state.currentTerm := by
  simp [refreshRetirementState]

@[simp]
lemma refreshRetirementState_sentIndex (node : Node) (state : NodeState Node TxId)
    : (refreshRetirementState node state).sentIndex = state.sentIndex := by
  simp [refreshRetirementState]

@[simp]
lemma refreshRetirementState_matchIndex (node : Node) (state : NodeState Node TxId)
    : (refreshRetirementState node state).matchIndex = state.matchIndex := by
  simp [refreshRetirementState]

@[simp]
lemma refreshRetirementState_isNewFollower (node : Node) (state : NodeState Node TxId)
    : (refreshRetirementState node state).isNewFollower = state.isNewFollower := by
  simp [refreshRetirementState]

@[simp]
lemma refreshRetirementState_votedFor (node : Node) (state : NodeState Node TxId)
    : (refreshRetirementState node state).votedFor = state.votedFor := by
  simp [refreshRetirementState]

@[simp]
lemma refreshRetirementState_votesGranted (node : Node) (state : NodeState Node TxId)
    : (refreshRetirementState node state).votesGranted = state.votesGranted := by
  simp [refreshRetirementState]

@[simp]
lemma refreshRetirementState_preVotesGranted (node : Node) (state : NodeState Node TxId)
    : (refreshRetirementState node state).preVotesGranted = state.preVotesGranted := by
  simp [refreshRetirementState]

omit [Bootstrap Node] in
/-- Erasing a selected occurrence preserves membership of every remaining message. -/
lemma selectedSound
    {source : Node} {queue remaining : List (Model.Envelope Node TxId)}
    {selected : Model.Envelope Node TxId}
    (taken : Selected source queue selected remaining)
    : selected.source = source
      /\ selected ∈ queue
      /\ (forall message, message ∈ remaining -> message ∈ queue) := by
  obtain ⟨sourceEq, member, rfl⟩ := taken
  refine ⟨sourceEq, member, ?_⟩
  intro message present
  have remaining : message ∈ queue.erase selected := by
    simpa only [removeOne_eq_list_erase] using present
  exact List.mem_of_mem_erase remaining

end CCFRaft.Proofs.Invariant
