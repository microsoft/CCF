-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.NodeFacts
import CCFRaft.Proofs.Ledger

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Model.Local
open Concrete
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

@[concrete_effects]
def initializeConfigurationEffect (state : Model.State Node TxId) (node : Node)
    : Model.State Node TxId :=
  let nodeState := (nodeOf state) node
  {
    state with
      nodes :=
        replaceNode state.nodes node
          {
            nodeState with
              log :=
                [{
                  term := nodeState.currentTerm
                  content := .reconfiguration INITIAL_CONFIGURATION
                }]
          }
  }

@[concrete_effects]
def clientRequestEffect (state : Model.State Node TxId) (node : Node) (txId : TxId)
    : Model.State Node TxId :=
  let nodeState := (nodeOf state) node
  let entry : Entry Node TxId :=
    {
      term := nodeState.currentTerm
      content := .transaction txId
    }
  let refreshed :=
    refreshRetirementState node { nodeState with log := nodeState.log ++ [entry] }
  { state with nodes := replaceNode state.nodes node refreshed }

@[concrete_effects]
def changeConfigurationEffect (state : Model.State Node TxId) (source : Node)
    (newConfiguration : Finset Node)
    : Model.State Node TxId :=
  let sourceState := (nodeOf state) source
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
      nodes := replaceNode state.nodes source nextSourceState
  }

@[concrete_effects]
def appendRetiredCommittedEffect (state : Model.State Node TxId) (node : Node)
    : Model.State Node TxId :=
  let nodeState := (nodeOf state) node
  let pending := (nodeOf state node).retirementCompleted \ allRetiredCommittedNodes (nodeOf state node).log
  let entry : Entry Node TxId :=
    {
      term := nodeState.currentTerm
      content := .retiredCommitted pending
    }
  let refreshed :=
    refreshRetirementState node { nodeState with log := nodeState.log ++ [entry] }
  { state with nodes := replaceNode state.nodes node refreshed }

@[concrete_effects]
def signCommittableMessagesEffect (state : Model.State Node TxId) (node : Node)
    : Model.State Node TxId :=
  let nodeState := (nodeOf state) node
  let entry : Entry Node TxId :=
    {
      term := nodeState.currentTerm
      content := .signature
    }
  let refreshed :=
    refreshRetirementState node { nodeState with log := nodeState.log ++ [entry] }
  { state with nodes := replaceNode state.nodes node refreshed }

@[concrete_effects]
def appendEntriesEffect (state : Model.State Node TxId) (source : Node) (destination : Node)
    (batchEnd : Nat)
    : Model.State Node TxId :=
  let sourceState := (nodeOf state) source
  let request := appendRequestKey state source destination batchEnd
  {
    state with
      nodes :=
        replaceNode state.nodes source
          {
            sourceState with
              sentIndex :=
                updateIndex sourceState.sentIndex destination batchEnd
          }
      network := state.network ++ [appendRequestEnvelope request]
  }

@[concrete_effects]
def advanceCommitIndexEffect (state : Model.State Node TxId) (node : Node) : Model.State Node TxId :=
  demoteRetiredCommitted (advanceCommitState state node) node

@[concrete_effects]
def timeoutEffect (state : Model.State Node TxId) (node : Node) : Model.State Node TxId :=
  becomeCandidateState state node

@[concrete_effects]
def becomePreVoteCandidateEffect (state : Model.State Node TxId) (node : Node)
    : Model.State Node TxId :=
  let nodeState := (nodeOf state) node
  {
    state with
      nodes :=
        replaceNode state.nodes node
          {
            nodeState with
              role := .preVoteCandidate
              preVotesGranted := {node}
          }
  }

@[concrete_effects]
def becomeCandidateEffect (state : Model.State Node TxId) (node : Node) : Model.State Node TxId :=
  becomeCandidateState state node

@[concrete_effects]
def requestVoteEffect (state : Model.State Node TxId) (source : Node) (destination : Node)
    : Model.State Node TxId :=
  let request := voteRequestKey state source destination
  { state with network := state.network ++ [voteRequestEnvelope request] }

@[concrete_effects]
def requestPreVoteEffect (state : Model.State Node TxId) (source : Node) (destination : Node)
    : Model.State Node TxId :=
  let request := voteRequestKey state source destination
  { state with network := state.network ++ [preVoteRequestEnvelope request] }

@[concrete_effects]
def checkQuorumEffect (state : Model.State Node TxId) (node : Node) : Model.State Node TxId :=
  stepDownState state node

@[concrete_effects]
def becomeLeaderEffect (state : Model.State Node TxId) (node : Node) : Model.State Node TxId :=
  let nodeState := (nodeOf state) node
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
  { state with nodes := replaceNode state.nodes node nextNode }

@[concrete_effects]
def proposeVoteEffect (state : Model.State Node TxId) (source : Node) (destination : Node)
    : Model.State Node TxId :=
  let request := (source, destination, (nodeOf state source).currentTerm)
  { state with network := state.network ++ [proposeVoteEnvelope request] }

@[concrete_effects]
def advanceCommitIndexAndProposeVoteEffect (state : Model.State Node TxId) (source : Node)
    (destination : Node)
    : Model.State Node TxId :=
  let advanced := demoteRetiredCommitted (advanceCommitState state source) source
  let request := (source, destination, (nodeOf state source).currentTerm)
  { advanced with network := advanced.network ++ [proposeVoteEnvelope request] }

@[concrete_effects]
def observeTermEffect (state : Model.State Node TxId) (destination : Node) (term : Nat)
    : Model.State Node TxId :=
  { state with
    nodes := replaceNode state.nodes destination (updateTerm (nodeOf state destination) term) }

end CCFRaft.Proofs.Invariant
