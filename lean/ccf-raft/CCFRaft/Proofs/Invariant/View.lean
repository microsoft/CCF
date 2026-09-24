-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Concrete
import Mathlib.Tactic

set_option autoImplicit false
set_option linter.unusedSectionVars false

/-!
# The global view of a network state

The safety invariant reads every node's state and every in-flight message by
destination. `view` computes that from a `Model.State`: node states come from
the node table, and each destination's queue lists the envelopes to it, with
their endpoints attached to the message. `joined` is a proof-only set of the
nodes that any configuration has named.
-/

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

/-- A replication request, as captured when the leader sends it. -/
structure AppendEntriesRequest (Node TxId : Type) where
  term : Nat
  prevLogIndex : Nat
  prevLogTerm : Nat
  entries : List (Entry Node TxId)
  leaderCommit : Nat
  source : Node
  destination : Node
deriving DecidableEq

/-- ACK or NACK returned after processing an AppendEntries request. -/
structure AppendEntriesResponse (Node : Type) where
  term : Nat
  success : Bool
  lastLogIndex : Nat
  source : Node
  destination : Node
deriving DecidableEq, Repr

/-! RequestVote messages carry the candidate's last committable position. -/

/-- Candidate log summary sent to a potential voter. -/
structure RequestVoteRequest (Node : Type) where
  term : Nat
  lastCommittableTerm : Nat
  lastCommittableIndex : Nat
  source : Node
  destination : Node
deriving DecidableEq, Repr

/-- A voter's reply, granting or rejecting a vote. -/
structure RequestVoteResponse (Node : Type) where
  term : Nat
  voteGranted : Bool
  source : Node
  destination : Node
deriving DecidableEq, Repr

/-- A pre-vote request, sent as its own message kind. -/
structure RequestPreVote (Node : Type) where
  term : Nat
  lastCommittableTerm : Nat
  lastCommittableIndex : Nat
  source : Node
  destination : Node
deriving DecidableEq, Repr

/-- A voter's reply, granting or rejecting a pre-vote. -/
structure RequestPreVoteResponse (Node : Type) where
  term : Nat
  voteGranted : Bool
  source : Node
  destination : Node
deriving DecidableEq, Repr

/-- A leader's same-term request that another replica start an election. -/
structure ProposeVoteRequest (Node : Type) where
  term : Nat
  source : Node
  destination : Node
deriving DecidableEq, Repr

/-- Network messages used by replication and elections. -/
inductive Message (Node TxId : Type) where
  /-- A leader-to-follower replication request. -/
  | appendEntriesRequest (request : AppendEntriesRequest Node TxId)
  /-- A follower-to-leader acknowledgement or rejection. -/
  | appendEntriesResponse (response : AppendEntriesResponse Node)
  /-- A candidate-to-voter RequestVote request. -/
  | requestVoteRequest (request : RequestVoteRequest Node)
  /-- A voter-to-candidate RequestVote response. -/
  | requestVoteResponse (response : RequestVoteResponse Node)
  /-- A pre-vote candidate-to-voter RequestPreVote request. -/
  | requestPreVote (request : RequestPreVote Node)
  /-- A voter-to-pre-vote-candidate RequestPreVote response. -/
  | requestPreVoteResponse (response : RequestPreVoteResponse Node)
  /-- A leader-to-replica request to begin an ordinary election. -/
  | proposeVoteRequest (request : ProposeVoteRequest Node)
deriving DecidableEq

variable {Node TxId : Type}

namespace Message

/-- Read the source ID of a message. -/
def source : Message Node TxId -> Node
  | .appendEntriesRequest request => request.source
  | .appendEntriesResponse response => response.source
  | .requestVoteRequest request => request.source
  | .requestVoteResponse response => response.source
  | .requestPreVote request => request.source
  | .requestPreVoteResponse response => response.source
  | .proposeVoteRequest request => request.source

/-- Read the destination ID of a message. -/
def destination : Message Node TxId -> Node
  | .appendEntriesRequest request => request.destination
  | .appendEntriesResponse response => response.destination
  | .requestVoteRequest request => request.destination
  | .requestVoteResponse response => response.destination
  | .requestPreVote request => request.destination
  | .requestPreVoteResponse response => response.destination
  | .proposeVoteRequest request => request.destination

/-- Read the term of a message. -/
def term : Message Node TxId -> Nat
  | .appendEntriesRequest request => request.term
  | .appendEntriesResponse response => response.term
  | .requestVoteRequest request => request.term
  | .requestVoteResponse response => response.term
  | .requestPreVote request => request.term
  | .requestPreVoteResponse response => response.term
  | .proposeVoteRequest request => request.term

/-- Whether a message is a pre-vote request or response. -/
def IsPreVote : Message Node TxId -> Prop
  | .requestPreVote _ => True
  | .requestPreVoteResponse _ => True
  | _ => False

/-- Whether a message carries no log, vote, or acknowledgement evidence. -/
def IsSafetyInert : Message Node TxId -> Prop
  | .requestPreVote _ => True
  | .requestPreVoteResponse _ => True
  | .proposeVoteRequest _ => True
  | _ => False

end Message

variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

/-- Check that a request's previous index and term match the follower log. -/
def logOk (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Prop :=
  request.prevLogIndex = 0
  \/ (request.prevLogIndex <= state.log.length
      /\ termAt state.log request.prevLogIndex = request.prevLogTerm)

/-- Check whether a heartbeat or all requested entry terms are already present. -/
def alreadyDone (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Prop :=
  request.entries = []
  \/ (request.prevLogIndex + request.entries.length <= state.log.length
      /\ ((state.log.drop request.prevLogIndex).take request.entries.length).map
            Entry.term
          = request.entries.map Entry.term)

/-- Number of request entries that overlap the follower's existing suffix. -/
def overlapLength (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Nat :=
  min request.entries.length (state.log.length - request.prevLogIndex)

/-- Detect a differing term in the overlapping part of a request. -/
def hasTermConflict
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Prop :=
  Not (request.entries = [])
  /\ Not
      (((state.log.drop request.prevLogIndex).take (overlapLength state request)).map
          Entry.term
        = (request.entries.take (overlapLength state request)).map Entry.term)

/-- Check that a request safely extends a matching follower prefix. -/
def noConflictExtension
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Prop :=
  Not (request.entries = [])
  /\ request.prevLogIndex <= state.log.length
  /\ state.log.length < request.prevLogIndex + request.entries.length
  /\ (state.log.drop request.prevLogIndex).take (state.log.length - request.prevLogIndex)
      = request.entries.take (state.log.length - request.prevLogIndex)

/-- Make the previous-entry consistency guard executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Decidable (logOk state request) := by
  unfold logOk
  infer_instance

/-- Make the already-applied request guard executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Decidable (alreadyDone state request) := by
  unfold alreadyDone
  infer_instance

/-- Make term-conflict detection executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Decidable (hasTermConflict state request) := by
  unfold hasTermConflict
  infer_instance

/-- Make no-conflict extension detection executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Decidable (noConflictExtension state request) := by
  unfold noConflictExtension
  infer_instance

/-- Advance the commit index to the latest signature the request covers. -/
def committedFromLeader
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId))
    : Nat :=
  max state.commitIndex
    (maxCommittableIndexUpTo newLog
      (min request.leaderCommit (request.prevLogIndex + request.entries.length)))

/-- Build the ACK for an applied request. -/
def successResponse
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (lastLogIndex : Nat)
    : AppendEntriesResponse Node where
  term := state.currentTerm
  success := true
  lastLogIndex
  source := request.destination
  destination := request.source

/-- Build the NACK for a stale or mismatched request. -/
def failureResponse
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : AppendEntriesResponse Node :=
  if request.term < state.currentTerm then
    {
      term := state.currentTerm
      success := false
      lastLogIndex := state.log.length
      source := request.destination
      destination := request.source
    }
  else
    let previousTerm :=
      if request.prevLogIndex = 0 then
        0
      else if request.prevLogIndex > state.log.length then
        0
      else
        termAt state.log state.log.length
    if previousTerm = 0 then
      {
        term := state.currentTerm
        success := false
        lastLogIndex := state.log.length
        source := request.destination
        destination := request.source
      }
    else
      let lastLogIndex :=
        findHighestPossibleMatch state.log request.prevLogIndex request.prevLogTerm
      {
        term := termAt state.log lastLogIndex
        success := false
        lastLogIndex
        source := request.destination
        destination := request.source
      }

/-- Reject stale-term requests or requests whose previous entry does not match. -/
def rejectAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if request.term < state.currentTerm
      \/ (request.term = state.currentTerm
          /\ state.role = .follower
          /\ Not (logOk state request)) then
    some (state, failureResponse state request)
  else
    none

/-- ACK a request whose entries are already present, and adopt its commit index. -/
def appendEntriesAlreadyDone?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if alreadyDone state request then
    let commitIndex := committedFromLeader state request state.log
    let nextState := { state with commitIndex }
    some
      (
        nextState,
        successResponse nextState request (request.prevLogIndex + request.entries.length)
      )
  else
    none

/-- Truncate a conflicting uncommitted suffix without consuming the request. -/
def conflictAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId) :=
  if hasTermConflict state request /\ state.isNewFollower then
    some
      {
        state with
          log := state.log.take request.prevLogIndex
          isNewFollower := false
      }
  else
    none

/-- Append a matching extension and return an ACK. -/
def noConflictAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if noConflictExtension state request then
    let newLog := state.log.take request.prevLogIndex ++ request.entries
    let commitIndex := committedFromLeader state request newLog
    -- Native receive runs commit callbacks at each newly applied signature.
    let firstRetirementCommit :=
      match retiredCommittedIndexInLog request.destination newLog with
      | none => commitIndex
      | some markerIndex =>
          match signatureIndexAfterFrom (max state.log.length markerIndex) 1 newLog with
          | none => commitIndex
          | some firstNewSignature => min commitIndex firstNewSignature
    let nextState :=
      refreshRetirementState request.destination
        { state with log := newLog, commitIndex := firstRetirementCommit }
    let nextState := { nextState with commitIndex }
    some (nextState, successResponse nextState request newLog.length)
  else
    none

/-- Apply an accepted request: already done, clean extension, or truncate and retry. -/
def acceptAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if request.term = state.currentTerm
      /\ state.role = .follower
      /\ logOk state request
      /\ request.prevLogIndex >= state.commitIndex then
    match appendEntriesAlreadyDone? state request with
    | some result => some result
    | none =>
        match noConflictAppendEntriesRequest? state request with
        | some result => some result
        | none =>
            match conflictAppendEntriesRequest? state request with
            | none => none
            | some truncated =>
                match appendEntriesAlreadyDone? truncated request with
                | some result => some result
                | none => noConflictAppendEntriesRequest? truncated request
  else
    none

/-- Reject a request when required, otherwise apply it. -/
def handleAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  match rejectAppendEntriesRequest? state request with
  | some result => some result
  | none => acceptAppendEntriesRequest? state request

/-- Compare a candidate log summary with a voter's local log. -/
def voteLogUpToDate (state : NodeState Node TxId) (request : RequestVoteRequest Node)
    : Prop :=
  request.lastCommittableTerm > maxCommittableTerm state.log
  \/ (request.lastCommittableTerm = maxCommittableTerm state.log
      /\ request.lastCommittableIndex >= maxCommittableIndex state.log)

instance (state : NodeState Node TxId) (request : RequestVoteRequest Node)
    : Decidable (voteLogUpToDate state request) := by
  unfold voteLogUpToDate
  infer_instance

/-- Read a RequestPreVote as a RequestVote request with the same fields. -/
def RequestPreVote.toRequestVoteRequest (request : RequestPreVote Node)
    : RequestVoteRequest Node where
  term := request.term
  lastCommittableTerm := request.lastCommittableTerm
  lastCommittableIndex := request.lastCommittableIndex
  source := request.source
  destination := request.destination

/-- Node state with the retirement metadata cleared. -/
def protocolNodeState (node : NodeState Node TxId) : NodeState Node TxId :=
  {
    node with
      membershipState := .active
      retirementIndex := none
      retirementCommittableIndex := none
      retiredCommittedIndex := none
  }

/-- Every node's state, every in-flight message by destination, and the joined nodes. -/
structure View (Node TxId : Type) where
  nodes : Node -> NodeState Node TxId
  network : Node -> List (Message Node TxId)
  hasJoined : Finset Node

/-- A node is allocated once some configuration has named it. -/
def View.allocated (state : View Node TxId) (node : Node) : Prop := node ∈ state.hasJoined

instance (state : View Node TxId) (node : Node) : Decidable (state.allocated node) :=
  inferInstanceAs (Decidable (node ∈ state.hasJoined))

/-- The message an envelope carries, with its endpoints attached. -/
def toMessage (envelope : Model.Envelope Node TxId) : Message Node TxId :=
  let source := envelope.source
  let destination := envelope.target
  match envelope.payload with
  | .appendEntriesRequest request =>
      .appendEntriesRequest
        {
          term := request.term
          prevLogIndex := request.prevLogIndex
          prevLogTerm := request.prevLogTerm
          entries := request.entries
          leaderCommit := request.leaderCommit
          source
          destination
        }
  | .appendEntriesResponse response =>
      .appendEntriesResponse
        {
          term := response.term
          success := response.success
          lastLogIndex := response.lastLogIndex
          source
          destination
        }
  | .requestVoteRequest request =>
      .requestVoteRequest
        {
          term := request.term
          lastCommittableTerm := request.lastCommittableTerm
          lastCommittableIndex := request.lastCommittableIndex
          source
          destination
        }
  | .requestVoteResponse response =>
      .requestVoteResponse
        {
          term := response.term, voteGranted := response.voteGranted, source, destination
        }
  | .requestPreVote request =>
      .requestPreVote
        {
          term := request.term
          lastCommittableTerm := request.lastCommittableTerm
          lastCommittableIndex := request.lastCommittableIndex
          source
          destination
        }
  | .requestPreVoteResponse response =>
      .requestPreVoteResponse
        {
          term := response.term, voteGranted := response.voteGranted, source, destination
        }
  | .proposeVoteRequest term => .proposeVoteRequest { term, source, destination }

/-- The global view of a network state with the given joined nodes. -/
def view (state : Model.State Node TxId) (joined : Finset Node) : View Node TxId where
  nodes node :=
    (Shared.MultiNodeTransitionSystem.nodeState state node).getD (initialNodeState node)
  network destination :=
    (state.network.filter fun envelope => envelope.target = destination).map toMessage
  hasJoined := joined

/-- Build a RequestVote message from the candidate's local state. -/
def makeRequestVoteRequest (state : View Node TxId) (source destination : Node)
    : RequestVoteRequest Node :=
  let sourceState := state.nodes source
  {
    term := sourceState.currentTerm
    lastCommittableTerm := lastCommittableTerm sourceState
    lastCommittableIndex := lastCommittableIndex sourceState
    source
    destination
  }

end CCFRaft.Proofs.Invariant
