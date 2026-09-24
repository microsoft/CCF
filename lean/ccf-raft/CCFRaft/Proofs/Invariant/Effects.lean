-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.NodeFacts
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

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

@[view_effects]
def initializeConfigurationEffect (state : View Node TxId) (node : Node)
    : View Node TxId :=
  let nodeState := state.nodes node
  {
    state with
      nodes :=
        updateNode state.nodes node
          {
            nodeState with
              log :=
                [{
                  term := nodeState.currentTerm
                  content := .reconfiguration INITIAL_CONFIGURATION
                }]
          }
  }

@[view_effects]
def clientRequestEffect (state : View Node TxId) (node : Node) (txId : TxId)
    : View Node TxId :=
  let nodeState := state.nodes node
  let entry : Entry Node TxId :=
    {
      term := nodeState.currentTerm
      content := .transaction txId
    }
  let refreshed :=
    refreshRetirementState node { nodeState with log := nodeState.log ++ [entry] }
  { state with nodes := updateNode state.nodes node refreshed }

@[view_effects]
def changeConfigurationEffect (state : View Node TxId) (source : Node)
    (newConfiguration : Finset Node)
    : View Node TxId :=
  let sourceState := state.nodes source
  let previousConfiguration := (latestConfiguration sourceState).nodes
  let addedNodes := newConfiguration \ previousConfiguration
  let entry : Entry Node TxId :=
    {
      term := sourceState.currentTerm
      content := .reconfiguration newConfiguration
    }
  let appended := { sourceState with log := sourceState.log ++ [entry] }
  let nextSourceState :=
    refreshRetirementState source
      {
        appended with
          sentIndex :=
            fun peer =>
              if peer ∈ addedNodes then
                sourceState.log.length
              else
                sourceState.sentIndex peer
      }
  {
    state with
      nodes := updateNode state.nodes source nextSourceState
      hasJoined := state.hasJoined ∪ addedNodes
  }

@[view_effects]
def appendRetiredCommittedEffect (state : View Node TxId) (node : Node)
    : View Node TxId :=
  let nodeState := state.nodes node
  let pending := pendingRetiredCommittedNodes state node
  let entry : Entry Node TxId :=
    {
      term := nodeState.currentTerm
      content := .retiredCommitted pending
    }
  let refreshed :=
    refreshRetirementState node { nodeState with log := nodeState.log ++ [entry] }
  { state with nodes := updateNode state.nodes node refreshed }

@[view_effects]
def signCommittableMessagesEffect (state : View Node TxId) (node : Node)
    : View Node TxId :=
  let nodeState := state.nodes node
  let entry : Entry Node TxId :=
    {
      term := nodeState.currentTerm
      content := .signature
    }
  let refreshed :=
    refreshRetirementState node { nodeState with log := nodeState.log ++ [entry] }
  { state with nodes := updateNode state.nodes node refreshed }

@[view_effects]
def appendEntriesEffect (state : View Node TxId) (source : Node) (destination : Node)
    (batchEnd : Nat)
    : View Node TxId :=
  let sourceState := state.nodes source
  let request := makeAppendEntriesRequest state source destination batchEnd
  {
    state with
      nodes :=
        updateNode state.nodes source
          {
            sourceState with
              sentIndex :=
                updateIndex sourceState.sentIndex destination batchEnd
          }
      network := enqueue state.network (.appendEntriesRequest request)
  }

@[view_effects]
def advanceCommitIndexEffect (state : View Node TxId) (node : Node) : View Node TxId :=
  demoteRetiredCommitted (advanceCommitState state node) node

@[view_effects]
def timeoutEffect (state : View Node TxId) (node : Node) : View Node TxId :=
  becomeCandidateState state node

@[view_effects]
def becomePreVoteCandidateEffect (state : View Node TxId) (node : Node)
    : View Node TxId :=
  let nodeState := state.nodes node
  {
    state with
      nodes :=
        updateNode state.nodes node
          {
            nodeState with
              role := .preVoteCandidate
              preVotesGranted := {node}
          }
  }

@[view_effects]
def becomeCandidateEffect (state : View Node TxId) (node : Node) : View Node TxId :=
  becomeCandidateState state node

@[view_effects]
def requestVoteEffect (state : View Node TxId) (source : Node) (destination : Node)
    : View Node TxId :=
  let request := makeRequestVoteRequest state source destination
  { state with network := enqueue state.network (.requestVoteRequest request) }

@[view_effects]
def requestPreVoteEffect (state : View Node TxId) (source : Node) (destination : Node)
    : View Node TxId :=
  let request := makeRequestPreVote state source destination
  { state with network := enqueue state.network (.requestPreVote request) }

@[view_effects]
def checkQuorumEffect (state : View Node TxId) (node : Node) : View Node TxId :=
  stepDownState state node

@[view_effects]
def becomeLeaderEffect (state : View Node TxId) (node : Node) : View Node TxId :=
  let nodeState := state.nodes node
  let log := nodeState.log.take (maxCommittableIndex nodeState.log)
  let truncated := { nodeState with log }
  let nextNode :=
    refreshRetirementState node
      {
        truncated with
          role := .leader
          sentIndex := fun _ => log.length
          matchIndex := fun _ => 0
      }
  { state with nodes := updateNode state.nodes node nextNode }

@[view_effects]
def proposeVoteEffect (state : View Node TxId) (source : Node) (destination : Node)
    : View Node TxId :=
  let request := makeProposeVoteRequest state source destination
  { state with network := enqueue state.network (.proposeVoteRequest request) }

@[view_effects]
def advanceCommitIndexAndProposeVoteEffect (state : View Node TxId) (source : Node)
    (destination : Node)
    : View Node TxId :=
  let advanced := demoteRetiredCommitted (advanceCommitState state source) source
  let request := makeProposeVoteRequest state source destination
  { advanced with network := enqueue advanced.network (.proposeVoteRequest request) }

@[view_effects]
def observeTermEffect (state : View Node TxId) (destination : Node) (term : Nat)
    : View Node TxId :=
  {
    state with
      nodes :=
        updateNode state.nodes destination
          {
            state.nodes destination with
              role := .follower
              currentTerm := term
              votedFor := none
              isNewFollower := true
              preVotesGranted := ∅
          }
  }

end CCFRaft.Proofs.Invariant
