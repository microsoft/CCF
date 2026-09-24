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

open CCFRaft.Model.Local
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]

private def withVotedFor
    (votedFor : Option Node)
    (result : NodeState Node TxId × AppendEntriesResponse)
    : NodeState Node TxId × AppendEntriesResponse :=
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
variable (self : Node)

lemma noConflictAppendEntriesRequest_votedFor
    (node : NodeState Node TxId)
    (votedFor : Option Node)
    (request : AppendEntriesRequest Node TxId)
    : noConflictAppendEntriesRequest? self { node with votedFor := votedFor } request
      = (noConflictAppendEntriesRequest? self node request).map (withVotedFor votedFor) := by
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
    : acceptAppendEntriesRequest? self { node with votedFor := votedFor } request
      = (acceptAppendEntriesRequest? self node request).map (withVotedFor votedFor) := by
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
    cases noConflictAppendEntriesRequest? self node request <;> simp
    cases conflictResult : conflictAppendEntriesRequest? node request with
    | none => simp
    | some truncated =>
        have nestedAppend :=
          appendEntriesAlreadyDone_votedFor
            truncated votedFor request
        have nestedNoConflict :=
          noConflictAppendEntriesRequest_votedFor self
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
    (node : NodeState Node TxId) (votedFor : Option Node)
    (request : AppendEntriesRequest Node TxId)
    : handleAppendEntriesRequest? self { node with votedFor } request
      = (handleAppendEntriesRequest? self node request).map (withVotedFor votedFor) := by
  have core (input : NodeState Node TxId) :
      (match rejectAppendEntriesRequest? { input with votedFor } request with
      | some result => some result
      | none => acceptAppendEntriesRequest? self { input with votedFor } request)
      = (match rejectAppendEntriesRequest? input request with
        | some result => some result
        | none => acceptAppendEntriesRequest? self input request).map (withVotedFor votedFor) := by
    rw [rejectAppendEntriesRequest_votedFor]
    cases rejectAppendEntriesRequest? input request <;>
      simp [acceptAppendEntriesRequest_votedFor]
  unfold handleAppendEntriesRequest?
  by_cases stepping : request.term = node.currentTerm
      ∧ (node.role = .candidate ∨ node.role = .preVoteCandidate)
  · convert core { node with role := .follower, isNewFollower := true } using 1 <;>
      simp [stepping] <;> split <;> simp_all
  · convert core node using 1 <;> simp [stepping] <;> split <;> simp_all

lemma canProduceAppendAckEventuallyAt_votedFor
    (node : NodeState Node TxId)
    (votedFor : Option Node)
    (request : AppendRequestKey Node TxId)
    (index : Nat)
    : canProduceAppendAckEventuallyAt { node with votedFor := votedFor } request index
      ↔ canProduceAppendAckEventuallyAt node request index := by
  unfold canProduceAppendAckEventuallyAt canProduceAppendAckAt
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
