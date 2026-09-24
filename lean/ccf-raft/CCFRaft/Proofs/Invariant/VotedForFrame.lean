-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Facts
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
variable [DecidableEq Node] [DecidableEq TxId]

private def withVotedFor
    (votedFor : Option Node)
    (result : NodeState Node TxId × AppendEntriesResponse Node)
    : NodeState Node TxId × AppendEntriesResponse Node :=
  ({ result.1 with votedFor := votedFor }, result.2)

omit [DecidableEq Node] [DecidableEq TxId] in
lemma rejectAppendEntriesRequest_votedFor
    (node : NodeState Node TxId)
    (votedFor : Option Node)
    (request : AppendEntriesRequest Node TxId)
    : rejectAppendEntriesRequest? { node with votedFor := votedFor } request
      = (rejectAppendEntriesRequest? node request).map (withVotedFor votedFor) := by
  unfold rejectAppendEntriesRequest?
  simp only [logOk]
  split_ifs <;> simp_all [failureResponse, withVotedFor]

lemma appendEntriesAlreadyDone_votedFor
    (node : NodeState Node TxId)
    (votedFor : Option Node)
    (request : AppendEntriesRequest Node TxId)
    : appendEntriesAlreadyDone? { node with votedFor := votedFor } request
      = (appendEntriesAlreadyDone? node request).map (withVotedFor votedFor) := by
  unfold appendEntriesAlreadyDone?
  simp only [alreadyDone]
  split_ifs <;>
    simp_all [
      committedFromLeader, successResponse, withVotedFor
    ]

omit [DecidableEq Node] [DecidableEq TxId] in
lemma conflictAppendEntriesRequest_votedFor
    (node : NodeState Node TxId)
    (votedFor : Option Node)
    (request : AppendEntriesRequest Node TxId)
    : conflictAppendEntriesRequest? { node with votedFor := votedFor } request
      = (conflictAppendEntriesRequest? node request).map
          fun next =>
            { next with votedFor := votedFor } := by
  unfold conflictAppendEntriesRequest?
  simp only [hasTermConflict, overlapLength]
  split_ifs <;> simp_all

variable [Bootstrap Node]

lemma noConflictAppendEntriesRequest_votedFor
    (node : NodeState Node TxId)
    (votedFor : Option Node)
    (request : AppendEntriesRequest Node TxId)
    : noConflictAppendEntriesRequest? { node with votedFor := votedFor } request
      = (noConflictAppendEntriesRequest? node request).map (withVotedFor votedFor) := by
  by_cases enabled : noConflictExtension node request
  · have changed : noConflictExtension { node with votedFor := votedFor } request :=
      enabled
    simp only [noConflictAppendEntriesRequest?, ite_eq_left enabled, ite_eq_left changed,
      Option.map_some]
    rfl
  · have changed : ¬noConflictExtension { node with votedFor := votedFor } request :=
      enabled
    simp only [noConflictAppendEntriesRequest?, ite_eq_right enabled, ite_eq_right changed,
      Option.map_none]

lemma acceptAppendEntriesRequest_votedFor
    (node : NodeState Node TxId)
    (votedFor : Option Node)
    (request : AppendEntriesRequest Node TxId)
    : acceptAppendEntriesRequest? { node with votedFor := votedFor } request
      = (acceptAppendEntriesRequest? node request).map (withVotedFor votedFor) := by
  unfold acceptAppendEntriesRequest?
  by_cases accepted :
      request.term = node.currentTerm /\
        node.role = .follower /\
        logOk node request /\
        request.prevLogIndex >= node.commitIndex
  · have acceptedChanged :
        request.term =
            ({ node with votedFor := votedFor } : NodeState Node TxId).currentTerm /\
          ({ node with votedFor := votedFor } : NodeState Node TxId).role =
            .follower /\
          logOk { node with votedFor := votedFor } request /\
          request.prevLogIndex >=
            ({ node with votedFor := votedFor } :
              NodeState Node TxId).commitIndex := by
      simpa [logOk] using accepted
    rw [ite_eq_left acceptedChanged, ite_eq_left accepted]
    rw [
      appendEntriesAlreadyDone_votedFor,
      noConflictAppendEntriesRequest_votedFor,
      conflictAppendEntriesRequest_votedFor
    ]
    cases appendEntriesAlreadyDone? node request <;>
      simp [withVotedFor]
    cases noConflictAppendEntriesRequest? node request <;> simp
    cases conflictResult : conflictAppendEntriesRequest? node request with
    | none => simp
    | some truncated =>
        have nestedAppend :=
          appendEntriesAlreadyDone_votedFor
            truncated votedFor request
        have nestedNoConflict :=
          noConflictAppendEntriesRequest_votedFor
            truncated votedFor request
        simp only [Option.map_some]
        rw [nestedAppend, nestedNoConflict]
        cases appendEntriesAlreadyDone? truncated request <;> simp
  · have rejectedChanged :
        Not (
          request.term =
              ({ node with votedFor := votedFor } :
                NodeState Node TxId).currentTerm /\
            ({ node with votedFor := votedFor } : NodeState Node TxId).role =
              .follower /\
            logOk { node with votedFor := votedFor } request /\
            request.prevLogIndex >=
              ({ node with votedFor := votedFor } :
                NodeState Node TxId).commitIndex) := by
      simpa [logOk] using accepted
    rw [ite_eq_right rejectedChanged, ite_eq_right accepted]
    rfl

lemma handleAppendEntriesRequest_votedFor
    (node : NodeState Node TxId)
    (votedFor : Option Node)
    (request : AppendEntriesRequest Node TxId)
    : handleAppendEntriesRequest? { node with votedFor := votedFor } request
      = (handleAppendEntriesRequest? node request).map (withVotedFor votedFor) := by
  unfold handleAppendEntriesRequest?
  rw [rejectAppendEntriesRequest_votedFor]
  cases rejectAppendEntriesRequest? node request
  · simp [acceptAppendEntriesRequest_votedFor]
  · simp

lemma canProduceAppendAckEventuallyAt_votedFor
    (node : NodeState Node TxId)
    (votedFor : Option Node)
    (request : AppendEntriesRequest Node TxId)
    (index : Nat)
    : canProduceAppendAckEventuallyAt { node with votedFor := votedFor } request index
      ↔ canProduceAppendAckEventuallyAt node request index := by
  unfold canProduceAppendAckEventuallyAt canProduceAppendAckAt
  rw [protocolNodeState_set_votedFor]
  rw [handleAppendEntriesRequest_votedFor]
  constructor <;> rintro (direct | future)
  · left
    rcases direct with ⟨nextNode, response, handled, success, covered⟩
    rw [Option.map_eq_some_iff] at handled
    rcases handled with ⟨result, oldHandled, resultEq⟩
    rcases result with ⟨oldNextNode, oldResponse⟩
    simp [withVotedFor] at resultEq
    rcases resultEq with ⟨_, rfl⟩
    exact ⟨oldNextNode, oldResponse, oldHandled, success, covered⟩
  · exact Or.inr future
  · left
    rcases direct with ⟨nextNode, response, handled, success, covered⟩
    refine ⟨{ nextNode with votedFor := votedFor }, response, ?_, success, covered⟩
    rw [Option.map_eq_some_iff]
    exact ⟨(nextNode, response), handled, rfl⟩
  · exact Or.inr future

end CCFRaft.Proofs.Invariant
