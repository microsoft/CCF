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

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId]

/-- The endpoint-annotated AppendEntries request carrying the envelope endpoints. -/
def annotateAppendRequest (request : Model.Local.AppendEntriesRequest Node TxId)
    (source destination : Node)
    : AppendEntriesRequest Node TxId where
  term := request.term
  prevLogIndex := request.prevLogIndex
  prevLogTerm := request.prevLogTerm
  entries := request.entries
  leaderCommit := request.leaderCommit
  source
  destination

/-- The endpoint-annotated AppendEntries response carrying the envelope endpoints. -/
def annotateAppendResponse (response : Model.Local.AppendEntriesResponse)
    (source destination : Node)
    : AppendEntriesResponse Node where
  term := response.term
  success := response.success
  lastLogIndex := response.lastLogIndex
  source
  destination

/-- The endpoint-annotated vote request carrying the envelope endpoints. -/
def annotateVoteRequest (request : Model.Local.RequestVoteRequest)
    (source destination : Node)
    : RequestVoteRequest Node where
  term := request.term
  lastCommittableTerm := request.lastCommittableTerm
  lastCommittableIndex := request.lastCommittableIndex
  source
  destination

/-- The endpoint-annotated vote response carrying the envelope endpoints. -/
def annotateVoteResponse (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : RequestVoteResponse Node where
  term := response.term
  voteGranted := response.voteGranted
  source
  destination

/-- The endpoint-annotated pre-vote request carrying the envelope endpoints. -/
def annotatePreVote (request : Model.Local.RequestVoteRequest) (source destination : Node)
    : RequestPreVote Node where
  term := request.term
  lastCommittableTerm := request.lastCommittableTerm
  lastCommittableIndex := request.lastCommittableIndex
  source
  destination

/-- The endpoint-annotated pre-vote response carrying the envelope endpoints. -/
def annotatePreVoteResponse (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : RequestPreVoteResponse Node where
  term := response.term
  voteGranted := response.voteGranted
  source
  destination

@[simp]
theorem annotateAppendResponse_source (response : Model.Local.AppendEntriesResponse)
    (source destination : Node)
    : (annotateAppendResponse response source destination).source = source :=
  rfl

@[simp]
theorem annotateAppendResponse_destination (response : Model.Local.AppendEntriesResponse)
    (source destination : Node)
    : (annotateAppendResponse response source destination).destination = destination :=
  rfl

@[simp]
theorem annotateVoteRequest_source (request : Model.Local.RequestVoteRequest)
    (source destination : Node)
    : (annotateVoteRequest request source destination).source = source :=
  rfl

@[simp]
theorem annotateVoteRequest_destination (request : Model.Local.RequestVoteRequest)
    (source destination : Node)
    : (annotateVoteRequest request source destination).destination = destination :=
  rfl

@[simp]
theorem annotateVoteResponse_source (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : (annotateVoteResponse response source destination).source = source :=
  rfl

@[simp]
theorem annotateVoteResponse_destination (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : (annotateVoteResponse response source destination).destination = destination :=
  rfl

@[simp]
theorem annotatePreVote_source (request : Model.Local.RequestVoteRequest)
    (source destination : Node)
    : (annotatePreVote request source destination).source = source :=
  rfl

@[simp]
theorem annotatePreVote_destination (request : Model.Local.RequestVoteRequest)
    (source destination : Node)
    : (annotatePreVote request source destination).destination = destination :=
  rfl

@[simp]
theorem annotatePreVoteResponse_source (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : (annotatePreVoteResponse response source destination).source = source :=
  rfl

@[simp]
theorem annotatePreVoteResponse_destination (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : (annotatePreVoteResponse response source destination).destination = destination :=
  rfl

variable [Bootstrap Node]

section AppendEntries

variable (state : NodeState Node TxId)
  (request : Model.Local.AppendEntriesRequest Node TxId)
  (source destination : Node)

/-- Map a local AppendEntries result to the endpoint-annotated one. -/
def annotateResult (source destination : Node)
    : NodeState Node TxId × Model.Local.AppendEntriesResponse
      -> NodeState Node TxId × AppendEntriesResponse Node
  | (next, response) => (next, annotateAppendResponse response destination source)

theorem failureResponse_eq
    : failureResponse state (annotateAppendRequest request source destination)
      = annotateAppendResponse (Model.Local.failureResponse state request) destination
          source := by
  unfold failureResponse Model.Local.failureResponse
  by_cases stale : request.term < state.currentTerm
  · simp [stale, annotateAppendRequest, annotateAppendResponse]
  by_cases first : request.prevLogIndex = 0
  · simp [stale, first, annotateAppendRequest, annotateAppendResponse]
  by_cases beyond : request.prevLogIndex > state.log.length
  · simp [stale, first, beyond, annotateAppendRequest, annotateAppendResponse]
  by_cases unknown : Model.Local.termAt state.log state.log.length = 0 <;>
    simp [stale, first, beyond, unknown, annotateAppendRequest, annotateAppendResponse]

@[simp]
theorem annotateAppendRequest_term
    : (annotateAppendRequest request source destination).term = request.term :=
  rfl

@[simp]
theorem annotateAppendRequest_prevLogIndex
    : (annotateAppendRequest request source destination).prevLogIndex
      = request.prevLogIndex :=
  rfl

@[simp]
theorem annotateAppendRequest_prevLogTerm
    : (annotateAppendRequest request source destination).prevLogTerm
      = request.prevLogTerm :=
  rfl

@[simp]
theorem annotateAppendRequest_entries
    : (annotateAppendRequest request source destination).entries = request.entries :=
  rfl

@[simp]
theorem annotateAppendRequest_leaderCommit
    : (annotateAppendRequest request source destination).leaderCommit
      = request.leaderCommit :=
  rfl

@[simp]
theorem annotateAppendRequest_source
    : (annotateAppendRequest request source destination).source = source :=
  rfl

@[simp]
theorem annotateAppendRequest_destination
    : (annotateAppendRequest request source destination).destination = destination :=
  rfl

theorem logOk_iff
    : logOk state (annotateAppendRequest request source destination)
      <-> Model.Local.logOk state request :=
  Iff.rfl

theorem alreadyDone_iff
    : alreadyDone state (annotateAppendRequest request source destination)
      <-> Model.Local.alreadyDone state request :=
  Iff.rfl

theorem hasTermConflict_iff
    : hasTermConflict state (annotateAppendRequest request source destination)
      <-> Model.Local.hasTermConflict state request :=
  Iff.rfl

theorem noConflictExtension_iff
    : noConflictExtension state (annotateAppendRequest request source destination)
      <-> Model.Local.noConflictExtension state request :=
  Iff.rfl

theorem reject_eq
    : rejectAppendEntriesRequest? state (annotateAppendRequest request source destination)
      = (Model.Local.rejectAppendEntriesRequest? state request).map
          (annotateResult source destination) := by
  unfold rejectAppendEntriesRequest? Model.Local.rejectAppendEntriesRequest?
  simp only [annotateAppendRequest_term, logOk_iff]
  split_ifs <;> simp [annotateResult, failureResponse_eq]

theorem alreadyDone_eq
    : appendEntriesAlreadyDone? state (annotateAppendRequest request source destination)
      = (Model.Local.appendEntriesAlreadyDone? state request).map
          (annotateResult source destination) := by
  unfold appendEntriesAlreadyDone? Model.Local.appendEntriesAlreadyDone?
  simp only [alreadyDone_iff]
  split_ifs <;> rfl

theorem conflict_eq
    : conflictAppendEntriesRequest? state
        (annotateAppendRequest request source destination)
      = Model.Local.conflictAppendEntriesRequest? state request := by
  unfold conflictAppendEntriesRequest? Model.Local.conflictAppendEntriesRequest?
  simp only [hasTermConflict_iff, annotateAppendRequest_prevLogIndex]

theorem noConflict_eq
    : noConflictAppendEntriesRequest? state
        (annotateAppendRequest request source destination)
      = (Model.Local.noConflictAppendEntriesRequest? destination state request).map
          (annotateResult source destination) := by
  unfold noConflictAppendEntriesRequest? Model.Local.noConflictAppendEntriesRequest?
  simp only [noConflictExtension_iff]
  split_ifs <;> rfl

theorem accept_eq
    : acceptAppendEntriesRequest? state (annotateAppendRequest request source destination)
      = (Model.Local.acceptAppendEntriesRequest? destination state request).map
          (annotateResult source destination) := by
  unfold acceptAppendEntriesRequest? Model.Local.acceptAppendEntriesRequest?
  simp only [logOk_iff, annotateAppendRequest_term, annotateAppendRequest_prevLogIndex]
  split_ifs
  · rw [alreadyDone_eq]
    cases Model.Local.appendEntriesAlreadyDone? state request with
    | some result => rfl
    | none =>
        simp only [Option.map_none]
        rw [noConflict_eq]
        cases Model.Local.noConflictAppendEntriesRequest? destination state request with
        | some result => rfl
        | none =>
            simp only [Option.map_none]
            rw [conflict_eq]
            cases Model.Local.conflictAppendEntriesRequest? state request with
            | none => rfl
            | some truncated =>
                simp only
                rw [alreadyDone_eq]
                cases Model.Local.appendEntriesAlreadyDone? truncated request with
                | some result => rfl
                | none => exact noConflict_eq truncated request source destination
  · rfl

/-- Without a same-term step-down, both handlers produce the same state and reply. -/
theorem handleAppendEntriesRequest_eq
    (noStepDown
      : Not
          (request.term = state.currentTerm
            /\ (state.role = .candidate \/ state.role = .preVoteCandidate)))
    : handleAppendEntriesRequest? state (annotateAppendRequest request source destination)
      = (Model.Local.handleAppendEntriesRequest? destination state request).map
          (annotateResult source destination) := by
  unfold handleAppendEntriesRequest? Model.Local.handleAppendEntriesRequest?
  rw [ite_eq_right_of_eq_false _ _ (eq_false noStepDown)]
  dsimp only
  rw [reject_eq]
  cases Model.Local.rejectAppendEntriesRequest? state request with
  | some result => rfl
  | none => exact accept_eq state request source destination

end AppendEntries

/-- The same-term step-down that precedes handling an AppendEntries request. -/
def stepDown (state : NodeState Node TxId)
    (request : Model.Local.AppendEntriesRequest Node TxId)
    : NodeState Node TxId :=
  if request.term = state.currentTerm
      /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
    { state with role := .follower, isNewFollower := true }
  else
    state

theorem stepDown_noStepDown (state : NodeState Node TxId)
    (request : Model.Local.AppendEntriesRequest Node TxId)
    : Not
        (request.term = (stepDown state request).currentTerm
          /\ ((stepDown state request).role = .candidate
              \/ (stepDown state request).role = .preVoteCandidate)) := by
  unfold stepDown
  split_ifs with stepped
  · simp
  · exact stepped

theorem handleAppendEntriesRequest_stepDown (self : Node) (state : NodeState Node TxId)
    (request : Model.Local.AppendEntriesRequest Node TxId)
    : Model.Local.handleAppendEntriesRequest? self state request
      = Model.Local.handleAppendEntriesRequest? self (stepDown state request)
          request := by
  conv_rhs => unfold Model.Local.handleAppendEntriesRequest?
  rw [ite_eq_right_of_eq_false _ _ (eq_false (stepDown_noStepDown state request))]
  rfl

theorem returnToFollower_eq (state : NodeState Node TxId)
    (request : Model.Local.AppendEntriesRequest Node TxId) (source destination : Node)
    : returnToFollowerState? state (annotateAppendRequest request source destination)
      = if request.term = state.currentTerm
            /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
          some (stepDown state request)
        else
          none := by
  unfold returnToFollowerState? stepDown
  simp only [annotateAppendRequest_term]
  by_cases stepped : request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) <;>
    simp [stepped]

theorem handleAppendEntriesResponse_eq (state : NodeState Node TxId)
    (response : Model.Local.AppendEntriesResponse) (source destination : Node)
    (bounded : state.role = .leader -> response.term <= state.currentTerm)
    : handleAppendEntriesResponse? state
        (annotateAppendResponse response source destination)
      = some (Model.Local.handleAppendEntriesResponse state source response) := by
  unfold handleAppendEntriesResponse? Model.Local.handleAppendEntriesResponse
  rcases response with ⟨term, success, lastLogIndex⟩
  simp only at bounded
  by_cases leader : state.role = .leader
  · have bound := bounded leader
    cases success
    · simp [leader, annotateAppendResponse]
    · by_cases same : term = state.currentTerm
      · simp [leader, same, annotateAppendResponse]
      · have stale : term < state.currentTerm := by omega
        simp [leader, same, stale, annotateAppendResponse]
  · simp [leader]

theorem handleRequestVoteRequest_eq (state : NodeState Node TxId)
    (request : Model.Local.RequestVoteRequest) (source destination : Node)
    (bounded : request.term <= state.currentTerm)
    : handleRequestVoteRequest? state (annotateVoteRequest request source destination)
      = some
          (
            (Model.Local.handleRequestVoteRequest state source request).1,
            annotateVoteResponse
              (Model.Local.handleRequestVoteRequest state source request).2 destination
              source
          ) := by
  unfold handleRequestVoteRequest? Model.Local.handleRequestVoteRequest
  have bound : (annotateVoteRequest request source destination).term <= state.currentTerm := bounded
  rw [ite_eq_left bound]
  rfl

theorem handleRequestPreVote_eq (state : NodeState Node TxId)
    (request : Model.Local.RequestVoteRequest) (source destination : Node)
    (bounded : request.term <= state.currentTerm)
    : handleRequestPreVote? state (annotatePreVote request source destination)
      = some
          (
            state,
            annotatePreVoteResponse (Model.Local.handleRequestPreVote state request)
              destination source
          ) := by
  unfold handleRequestPreVote? Model.Local.handleRequestPreVote
  have bound : (annotatePreVote request source destination).term <= state.currentTerm := bounded
  rw [ite_eq_left bound]
  rfl

theorem handleRequestVoteResponse_eq (state : NodeState Node TxId)
    (response : Model.Local.RequestVoteResponse) (source destination : Node)
    (bounded : response.term <= state.currentTerm)
    : handleRequestVoteResponse? state (annotateVoteResponse response source destination)
      = some (Model.Local.handleRequestVoteResponse state source response) := by
  unfold handleRequestVoteResponse? Model.Local.handleRequestVoteResponse
  rcases response with ⟨term, granted⟩
  by_cases stale : term < state.currentTerm
  · have different : Not (term = state.currentTerm) := by omega
    simp [annotateVoteResponse, stale, different]
  · have same : term = state.currentTerm := by simp only at bounded; omega
    by_cases candidate : state.role = .candidate <;> cases granted <;>
      simp [annotateVoteResponse, stale, same, candidate]

theorem handleRequestPreVoteResponse_eq (state : NodeState Node TxId)
    (response : Model.Local.RequestVoteResponse) (source destination : Node)
    (bounded : response.term <= state.currentTerm)
    : handleRequestPreVoteResponse? state
        (annotatePreVoteResponse response source destination)
      = some (Model.Local.handleRequestPreVoteResponse state source response) := by
  unfold handleRequestPreVoteResponse? Model.Local.handleRequestPreVoteResponse
  rcases response with ⟨term, granted⟩
  by_cases stale : term < state.currentTerm
  · have different : Not (term = state.currentTerm) := by omega
    simp [annotatePreVoteResponse, stale, different]
  · have same : term = state.currentTerm := by simp only at bounded; omega
    by_cases candidate : state.role = .preVoteCandidate <;> cases granted <;>
      simp [annotatePreVoteResponse, stale, same, candidate]

end CCFRaft.Proofs.Invariant
