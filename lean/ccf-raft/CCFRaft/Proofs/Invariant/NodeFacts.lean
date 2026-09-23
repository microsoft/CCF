-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Ops
import CCFRaft.Proofs.Ledger

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

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

/-- Every valid bootstrap configuration is nonempty. -/
lemma initialConfiguration_nonempty
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : Bootstrap Node]
    : (INITIAL_CONFIGURATION (Node := Node)).Nonempty := by
  exact
    Exists.intro
      (INITIAL_LEADER (Node := Node))
      (initialLeader_mem_initialConfiguration (Node := Node))

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

/-- Reading the node just updated returns the new value. -/
@[simp]
lemma updateNode_same
    (nodes : (Node -> NodeState Node TxId))
    (node : Node)
    (value : NodeState Node TxId)
    : updateNode nodes node value node = value := by
  simp [updateNode]

/-- Reading another node after an update returns its old value. -/
@[simp]
lemma updateNode_of_ne
    (nodes : (Node -> NodeState Node TxId))
    (node candidate : Node)
    (value : NodeState Node TxId)
    (different : Not (candidate = node))
    : updateNode nodes node value candidate = nodes candidate := by
  simp [updateNode, different]

/-- Reading the updated peer index returns the new value. -/
@[simp]
lemma updateIndex_same (indices : Node -> Nat) (node : Node) (value : Nat)
    : updateIndex indices node value node = value := by
  simp [updateIndex]

/-- Updating one peer index leaves all other peer indices unchanged. -/
@[simp]
lemma updateIndex_of_ne
    (indices : Node -> Nat)
    (node candidate : Node)
    (value : Nat)
    (different : Not (candidate = node))
    : updateIndex indices node value candidate = indices candidate := by
  simp [updateIndex, different]

/-- Reading the replaced destination queue returns the new queue. -/
@[simp]
lemma updateQueue_same
    (network : Node -> List (Message Node TxId))
    (destination : Node)
    (queue : List (Message Node TxId))
    : updateQueue network destination queue destination = queue := by
  simp [updateQueue]

/-- Replacing one destination queue leaves other queues unchanged. -/
@[simp]
lemma updateQueue_of_ne
    (network : Node -> List (Message Node TxId))
    (destination candidate : Node)
    (queue : List (Message Node TxId))
    (different : Not (candidate = destination))
    : updateQueue network destination queue candidate = network candidate := by
  simp [updateQueue, different]

@[simp]
lemma protocolNodeState_idempotent (state : NodeState Node TxId)
    : protocolNodeState (protocolNodeState state) = protocolNodeState state := by
  simp [protocolNodeState]

@[simp]
lemma protocolNodeState_set_votedFor
    (state : NodeState Node TxId)
    (votedFor : Option Node)
    : protocolNodeState { state with votedFor }
      = { protocolNodeState state with votedFor } := by
  simp [protocolNodeState]

@[simp]
lemma protocolNodeState_set_sentIndex
    (state : NodeState Node TxId)
    (sentIndex : Node -> Nat)
    : protocolNodeState { state with sentIndex }
      = { protocolNodeState state with sentIndex } := by
  simp [protocolNodeState]

@[simp]
lemma protocolNodeState_idempotent_set_votedFor
    (state : NodeState Node TxId)
    (votedFor : Option Node)
    : protocolNodeState { protocolNodeState state with votedFor }
      = { protocolNodeState state with votedFor } := by
  simp [protocolNodeState]

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

@[simp]
lemma refreshRetirementState_idempotent (node : Node) (state : NodeState Node TxId)
    : refreshRetirementState node (refreshRetirementState node state)
      = refreshRetirementState node state := by
  have repeatOr (left right : Option Nat) :
      (left.or right).or right = left.or right := by
    cases left <;> cases right <;> rfl
  simp [refreshRetirementState, repeatOr]

@[simp]
lemma protocolNodeState_refreshRetirementState (node : Node) (state : NodeState Node TxId)
    : protocolNodeState (refreshRetirementState node state)
      = protocolNodeState state := by
  simp [protocolNodeState]

/-- Erasing a selected occurrence preserves membership of every remaining message. -/
lemma selectedSound
    {source : Node} {queue remaining : List (Message Node TxId)}
    {selected : Message Node TxId}
    (taken : Selected source queue selected remaining)
    : selected.source = source
      /\ selected ∈ queue
      /\ (forall message, message ∈ remaining -> message ∈ queue) := by
  obtain ⟨sourceEq, member, rfl⟩ := taken
  exact ⟨sourceEq, member, fun _ present => List.mem_of_mem_erase present⟩

end CCFRaft.Proofs.Invariant
