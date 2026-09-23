-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Refinement.Internal

set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

/-!
# Message handlers in both models

The node-local handlers of `Model.Local` compute the same node state as the
abstract handlers. Abstract messages also carry their endpoints, which the
local handlers read from the envelope instead.
-/

namespace CCFRaft.Proofs.Refinement

open Model.Local (NodeState Bootstrap Role)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId]

/-- The abstract AppendEntries request carrying the envelope endpoints. -/
def absAppendRequest (request : Model.Local.AppendEntriesRequest Node TxId)
    (source destination : Node)
    : Abstract.Model.AppendEntriesRequest Node TxId where
  term := request.term
  prevLogIndex := request.prevLogIndex
  prevLogTerm := request.prevLogTerm
  entries := request.entries
  leaderCommit := request.leaderCommit
  source
  destination

/-- The abstract AppendEntries response carrying the envelope endpoints. -/
def absAppendResponse (response : Model.Local.AppendEntriesResponse)
    (source destination : Node)
    : Abstract.Model.AppendEntriesResponse Node where
  term := response.term
  success := response.success
  lastLogIndex := response.lastLogIndex
  source
  destination

/-- The abstract vote request carrying the envelope endpoints. -/
def absVoteRequest (request : Model.Local.RequestVoteRequest) (source destination : Node)
    : Abstract.Model.RequestVoteRequest Node where
  term := request.term
  lastCommittableTerm := request.lastCommittableTerm
  lastCommittableIndex := request.lastCommittableIndex
  source
  destination

/-- The abstract vote response carrying the envelope endpoints. -/
def absVoteResponse (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : Abstract.Model.RequestVoteResponse Node where
  term := response.term
  voteGranted := response.voteGranted
  source
  destination

/-- The abstract pre-vote request carrying the envelope endpoints. -/
def absPreVote (request : Model.Local.RequestVoteRequest) (source destination : Node)
    : Abstract.Model.RequestPreVote Node where
  term := request.term
  lastCommittableTerm := request.lastCommittableTerm
  lastCommittableIndex := request.lastCommittableIndex
  source
  destination

/-- The abstract pre-vote response carrying the envelope endpoints. -/
def absPreVoteResponse (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : Abstract.Model.RequestPreVoteResponse Node where
  term := response.term
  voteGranted := response.voteGranted
  source
  destination

@[simp]
theorem absAppendResponse_source (response : Model.Local.AppendEntriesResponse)
    (source destination : Node)
    : (absAppendResponse response source destination).source = source :=
  rfl

@[simp]
theorem absAppendResponse_destination (response : Model.Local.AppendEntriesResponse)
    (source destination : Node)
    : (absAppendResponse response source destination).destination = destination :=
  rfl

@[simp]
theorem absVoteRequest_source (request : Model.Local.RequestVoteRequest)
    (source destination : Node)
    : (absVoteRequest request source destination).source = source :=
  rfl

@[simp]
theorem absVoteRequest_destination (request : Model.Local.RequestVoteRequest)
    (source destination : Node)
    : (absVoteRequest request source destination).destination = destination :=
  rfl

@[simp]
theorem absVoteResponse_source (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : (absVoteResponse response source destination).source = source :=
  rfl

@[simp]
theorem absVoteResponse_destination (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : (absVoteResponse response source destination).destination = destination :=
  rfl

@[simp]
theorem absPreVote_source (request : Model.Local.RequestVoteRequest)
    (source destination : Node)
    : (absPreVote request source destination).source = source :=
  rfl

@[simp]
theorem absPreVote_destination (request : Model.Local.RequestVoteRequest)
    (source destination : Node)
    : (absPreVote request source destination).destination = destination :=
  rfl

@[simp]
theorem absPreVoteResponse_source (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : (absPreVoteResponse response source destination).source = source :=
  rfl

@[simp]
theorem absPreVoteResponse_destination (response : Model.Local.RequestVoteResponse)
    (source destination : Node)
    : (absPreVoteResponse response source destination).destination = destination :=
  rfl

variable [Bootstrap Node]

section AppendEntries

variable (state : NodeState Node TxId)
  (request : Model.Local.AppendEntriesRequest Node TxId)
  (source destination : Node)

/-- Map a local AppendEntries result to the abstract one. -/
def absResult (source destination : Node)
    : NodeState Node TxId × Model.Local.AppendEntriesResponse
      -> NodeState Node TxId × Abstract.Model.AppendEntriesResponse Node
  | (next, response) => (next, absAppendResponse response destination source)

theorem failureResponse_eq
    : Abstract.Model.failureResponse state (absAppendRequest request source destination)
      = absAppendResponse (Model.Local.failureResponse state request) destination
          source := by
  unfold Abstract.Model.failureResponse Model.Local.failureResponse
  by_cases stale : request.term < state.currentTerm
  · simp [stale, absAppendRequest, absAppendResponse]
  by_cases first : request.prevLogIndex = 0
  · simp [stale, first, absAppendRequest, absAppendResponse]
  by_cases beyond : request.prevLogIndex > state.log.length
  · simp [stale, first, beyond, absAppendRequest, absAppendResponse]
  by_cases unknown : Model.Local.termAt state.log state.log.length = 0 <;>
    simp [stale, first, beyond, unknown, absAppendRequest, absAppendResponse]

@[simp]
theorem absAppendRequest_term
    : (absAppendRequest request source destination).term = request.term :=
  rfl

@[simp]
theorem absAppendRequest_prevLogIndex
    : (absAppendRequest request source destination).prevLogIndex = request.prevLogIndex :=
  rfl

@[simp]
theorem absAppendRequest_prevLogTerm
    : (absAppendRequest request source destination).prevLogTerm = request.prevLogTerm :=
  rfl

@[simp]
theorem absAppendRequest_entries
    : (absAppendRequest request source destination).entries = request.entries :=
  rfl

@[simp]
theorem absAppendRequest_leaderCommit
    : (absAppendRequest request source destination).leaderCommit = request.leaderCommit :=
  rfl

@[simp]
theorem absAppendRequest_source
    : (absAppendRequest request source destination).source = source :=
  rfl

@[simp]
theorem absAppendRequest_destination
    : (absAppendRequest request source destination).destination = destination :=
  rfl

theorem logOk_iff
    : Abstract.Model.logOk state (absAppendRequest request source destination)
      <-> Model.Local.logOk state request :=
  Iff.rfl

theorem alreadyDone_iff
    : Abstract.Model.alreadyDone state (absAppendRequest request source destination)
      <-> Model.Local.alreadyDone state request :=
  Iff.rfl

theorem hasTermConflict_iff
    : Abstract.Model.hasTermConflict state (absAppendRequest request source destination)
      <-> Model.Local.hasTermConflict state request :=
  Iff.rfl

theorem noConflictExtension_iff
    : Abstract.Model.noConflictExtension state
        (absAppendRequest request source destination)
      <-> Model.Local.noConflictExtension state request :=
  Iff.rfl

theorem committedFromLeader_eq (log : List (Model.Local.Entry Node TxId))
    : Abstract.Model.committedFromLeader state
        (absAppendRequest request source destination) log
      = Model.Local.committedFromLeader state request log :=
  rfl

theorem reject_eq
    : Abstract.Model.rejectAppendEntriesRequest? state
        (absAppendRequest request source destination)
      = (Model.Local.rejectAppendEntriesRequest? state request).map
          (absResult source destination) := by
  unfold Abstract.Model.rejectAppendEntriesRequest? Model.Local.rejectAppendEntriesRequest?
  simp only [absAppendRequest_term, logOk_iff]
  split_ifs <;> simp [absResult, failureResponse_eq]

theorem alreadyDone_eq
    : Abstract.Model.appendEntriesAlreadyDone? state
        (absAppendRequest request source destination)
      = (Model.Local.appendEntriesAlreadyDone? state request).map
          (absResult source destination) := by
  unfold Abstract.Model.appendEntriesAlreadyDone? Model.Local.appendEntriesAlreadyDone?
  simp only [alreadyDone_iff]
  split_ifs <;> rfl

theorem conflict_eq
    : Abstract.Model.conflictAppendEntriesRequest? state
        (absAppendRequest request source destination)
      = Model.Local.conflictAppendEntriesRequest? state request := by
  unfold Abstract.Model.conflictAppendEntriesRequest? Model.Local.conflictAppendEntriesRequest?
  simp only [hasTermConflict_iff, absAppendRequest_prevLogIndex]

theorem noConflict_eq
    : Abstract.Model.noConflictAppendEntriesRequest? state
        (absAppendRequest request source destination)
      = (Model.Local.noConflictAppendEntriesRequest? destination state request).map
          (absResult source destination) := by
  unfold Abstract.Model.noConflictAppendEntriesRequest? Model.Local.noConflictAppendEntriesRequest?
  simp only [noConflictExtension_iff]
  split_ifs <;> rfl

theorem accept_eq
    : Abstract.Model.acceptAppendEntriesRequest? state
        (absAppendRequest request source destination)
      = (Model.Local.acceptAppendEntriesRequest? destination state request).map
          (absResult source destination) := by
  unfold Abstract.Model.acceptAppendEntriesRequest? Model.Local.acceptAppendEntriesRequest?
  simp only [logOk_iff, absAppendRequest_term, absAppendRequest_prevLogIndex]
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
    : Abstract.Model.handleAppendEntriesRequest? state
        (absAppendRequest request source destination)
      = (Model.Local.handleAppendEntriesRequest? destination state request).map
          (absResult source destination) := by
  unfold Abstract.Model.handleAppendEntriesRequest? Model.Local.handleAppendEntriesRequest?
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
    : Abstract.Model.returnToFollowerState? state
        (absAppendRequest request source destination)
      = if request.term = state.currentTerm
            /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
          some (stepDown state request)
        else
          none := by
  unfold Abstract.Model.returnToFollowerState? stepDown
  simp only [absAppendRequest_term]
  by_cases stepped : request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) <;>
    simp [stepped]

theorem handleAppendEntriesResponse_eq (state : NodeState Node TxId)
    (response : Model.Local.AppendEntriesResponse) (source destination : Node)
    (bounded : state.role = .leader -> response.term <= state.currentTerm)
    : Abstract.Model.handleAppendEntriesResponse? state
        (absAppendResponse response source destination)
      = some (Model.Local.handleAppendEntriesResponse state source response) := by
  unfold Abstract.Model.handleAppendEntriesResponse? Model.Local.handleAppendEntriesResponse
  rcases response with ⟨term, success, lastLogIndex⟩
  simp only at bounded
  by_cases leader : state.role = .leader
  · have bound := bounded leader
    cases success
    · simp [leader, absAppendResponse]
    · by_cases same : term = state.currentTerm
      · simp [leader, same, absAppendResponse]
      · have stale : term < state.currentTerm := by omega
        simp [leader, same, stale, absAppendResponse]
  · simp [leader]

theorem voteLogUpToDate_iff (state : NodeState Node TxId)
    (request : Model.Local.RequestVoteRequest) (source destination : Node)
    : Abstract.Model.voteLogUpToDate state (absVoteRequest request source destination)
      <-> Model.Local.voteLogUpToDate state request :=
  Iff.rfl

theorem handleRequestVoteRequest_eq (state : NodeState Node TxId)
    (request : Model.Local.RequestVoteRequest) (source destination : Node)
    (bounded : request.term <= state.currentTerm)
    : Abstract.Model.handleRequestVoteRequest? state
        (absVoteRequest request source destination)
      = some
          (
            (Model.Local.handleRequestVoteRequest state source request).1,
            absVoteResponse (Model.Local.handleRequestVoteRequest state source request).2
              destination source
          ) := by
  unfold Abstract.Model.handleRequestVoteRequest? Model.Local.handleRequestVoteRequest
  have bound : (absVoteRequest request source destination).term <= state.currentTerm := bounded
  rw [ite_eq_left bound]
  rfl

theorem handleRequestPreVote_eq (state : NodeState Node TxId)
    (request : Model.Local.RequestVoteRequest) (source destination : Node)
    (bounded : request.term <= state.currentTerm)
    : Abstract.Model.handleRequestPreVote? state (absPreVote request source destination)
      = some
          (
            state,
            absPreVoteResponse (Model.Local.handleRequestPreVote state request)
              destination source
          ) := by
  unfold Abstract.Model.handleRequestPreVote? Model.Local.handleRequestPreVote
  have bound : (absPreVote request source destination).term <= state.currentTerm := bounded
  rw [ite_eq_left bound]
  rfl

theorem handleRequestVoteResponse_eq (state : NodeState Node TxId)
    (response : Model.Local.RequestVoteResponse) (source destination : Node)
    (bounded : response.term <= state.currentTerm)
    : Abstract.Model.handleRequestVoteResponse? state
        (absVoteResponse response source destination)
      = some (Model.Local.handleRequestVoteResponse state source response) := by
  unfold Abstract.Model.handleRequestVoteResponse? Model.Local.handleRequestVoteResponse
  rcases response with ⟨term, granted⟩
  by_cases stale : term < state.currentTerm
  · have different : Not (term = state.currentTerm) := by omega
    simp [absVoteResponse, stale, different]
  · have same : term = state.currentTerm := by simp only at bounded; omega
    by_cases candidate : state.role = .candidate <;> cases granted <;>
      simp [absVoteResponse, stale, same, candidate]

theorem handleRequestPreVoteResponse_eq (state : NodeState Node TxId)
    (response : Model.Local.RequestVoteResponse) (source destination : Node)
    (bounded : response.term <= state.currentTerm)
    : Abstract.Model.handleRequestPreVoteResponse? state
        (absPreVoteResponse response source destination)
      = some (Model.Local.handleRequestPreVoteResponse state source response) := by
  unfold Abstract.Model.handleRequestPreVoteResponse? Model.Local.handleRequestPreVoteResponse
  rcases response with ⟨term, granted⟩
  by_cases stale : term < state.currentTerm
  · have different : Not (term = state.currentTerm) := by omega
    simp [absPreVoteResponse, stale, different]
  · have same : term = state.currentTerm := by simp only at bounded; omega
    by_cases candidate : state.role = .preVoteCandidate <;> cases granted <;>
      simp [absPreVoteResponse, stale, same, candidate]

end CCFRaft.Proofs.Refinement
