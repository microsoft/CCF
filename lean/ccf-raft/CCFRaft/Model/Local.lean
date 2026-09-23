-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model.Node
import CCFRaft.Shared.Capabilities

set_option autoImplicit false

/-!
# One CCF Raft node

`step` runs one node on one event. It reads only that node's state and, for a
delivery, the message and its sender. It returns `none` for a disabled event.
For an enabled event it returns the next state and sends through the host's
`send` callback. The network composition is in `CCFRaft.Model`.

A message from a newer term first moves the node to that term as a follower,
then the node handles the message in the same step (`observeTerm`).
-/

namespace CCFRaft.Model.Local

open Shared (Capabilities Effect)

/-- A replication request, as captured when the leader sends it. -/
structure AppendEntriesRequest (Node TxId : Type) where
  term : Nat
  prevLogIndex : Nat
  prevLogTerm : Nat
  entries : List (Entry Node TxId)
  leaderCommit : Nat
deriving DecidableEq

/-- ACK or NACK returned after processing an AppendEntries request. -/
structure AppendEntriesResponse where
  term : Nat
  success : Bool
  lastLogIndex : Nat
deriving DecidableEq, Repr

/-- A candidate's last committable position, sent in a vote or pre-vote request. -/
structure RequestVoteRequest where
  term : Nat
  lastCommittableTerm : Nat
  lastCommittableIndex : Nat
deriving DecidableEq, Repr

/-- A voter's reply to a vote or pre-vote request. -/
structure RequestVoteResponse where
  term : Nat
  voteGranted : Bool
deriving DecidableEq, Repr

/-- Messages exchanged by replication and elections. The envelope carries the
source and destination. -/
inductive Message (Node TxId : Type) where
  /-- A leader-to-follower replication request. -/
  | appendEntriesRequest (request : AppendEntriesRequest Node TxId)
  /-- A follower-to-leader acknowledgement or rejection. -/
  | appendEntriesResponse (response : AppendEntriesResponse)
  /-- A candidate-to-voter RequestVote request. -/
  | requestVoteRequest (request : RequestVoteRequest)
  /-- A voter-to-candidate RequestVote response. -/
  | requestVoteResponse (response : RequestVoteResponse)
  /-- A pre-vote candidate-to-voter RequestPreVote request. -/
  | requestPreVote (request : RequestVoteRequest)
  /-- A voter-to-pre-vote-candidate RequestPreVote response. -/
  | requestPreVoteResponse (response : RequestVoteResponse)
  /-- A leader's same-term request that a replica start an election. -/
  | proposeVoteRequest (term : Nat)
deriving DecidableEq

/-- CCF Raft nodes emit no notifications. -/
abbrev Notification := Empty

variable {Node TxId : Type}

/-- The term a message carries. -/
def Message.term : Message Node TxId -> Nat
  | .appendEntriesRequest request => request.term
  | .appendEntriesResponse response => response.term
  | .requestVoteRequest request => request.term
  | .requestVoteResponse response => response.term
  | .requestPreVote request => request.term
  | .requestPreVoteResponse response => response.term
  | .proposeVoteRequest term => term

/-- The host capabilities lent to one node step. -/
abbrev Host (Node TxId : Type) := Capabilities Node (Message Node TxId) Notification

/-- The effect monad of one node step: it can only send messages. -/
abbrev NodeEffect (Node TxId : Type) := Effect Node (Message Node TxId) Notification

/-- Inputs a node acts on without receiving a message. -/
inductive Input (Node TxId : Type) where
  /-- Write the bootstrap configuration to the initial leader's empty log. -/
  | initializeConfiguration
  /-- Append a client transaction to a leader's log. -/
  | clientRequest (txId : TxId)
  /-- Append a new nonempty configuration to a leader's log. -/
  | changeConfiguration (newConfiguration : Finset Node)
  /-- Record completed retirements which are not durably represented yet. -/
  | appendRetiredCommitted
  /-- Append a signature over a leader's nonempty log. -/
  | signCommittableMessages
  /-- Send a single-term batch or an empty heartbeat. -/
  | appendEntries (destination : Node) (batchEnd : Nat)
  /-- Advance a leader to the commit index it can compute locally. -/
  | advanceCommitIndex
  /-- Start a next-term election when pre-vote is not enabled. -/
  | timeout
  /-- Start a pre-vote round without advancing the local term. -/
  | becomePreVoteCandidate
  /-- Convert a successful pre-vote round into a next-term election. -/
  | becomeCandidate
  /-- Send a RequestVote message to another node. -/
  | requestVote (destination : Node)
  /-- Send a RequestPreVote message to another node. -/
  | requestPreVote (destination : Node)
  /-- Step down as leader in the current term after a failed quorum check. -/
  | checkQuorum
  /-- Promote a candidate after its local vote set reaches a majority. -/
  | becomeLeader
  /-- Ask one plausible successor to start an ordinary election. -/
  | proposeVote (destination : Node)
  /-- Commit terminal retirement and propose a vote to a successor in one step. -/
  | advanceCommitIndexAndProposeVote (destination : Node)
deriving DecidableEq

/-- Everything a node can act on: an input, or a message from `source`. -/
inductive Event (Node TxId : Type) where
  | internal (input : Input Node TxId)
  | receive (source : Node) (message : Message Node TxId)

variable [DecidableEq Node] [DecidableEq TxId]

/-! ## Leader state -/

variable [Bootstrap Node]

/-- Nodes removed by committed configurations but not retired-committed yet. -/
def NodeState.retirementCompleted (state : NodeState Node TxId) : Finset Node :=
  retirementCompletedNodes state.log state.commitIndex

/--
A successor has maximal replication progress, with ties broken by membership
in the highest active configuration, matching CCF's successor nomination.
-/
def plausibleSuccessor (state : NodeState Node TxId) (self destination : Node) : Prop :=
  let candidates := (activeNodeUnion state).erase self
  destination ∈ candidates
  /\ ∀ candidate ∈ candidates,
      state.matchIndex candidate <= state.matchIndex destination
      /\ (state.matchIndex candidate = state.matchIndex destination
          -> highestActiveConfigurationWithNode state candidate
              <= highestActiveConfigurationWithNode state destination)

instance (state : NodeState Node TxId) (self destination : Node)
    : Decidable (plausibleSuccessor state self destination) := by
  unfold plausibleSuccessor
  infer_instance

/--
The conditions which let a node start an election: a passive or campaigning
role, membership it can campaign from, and no committed retirement.
-/
def candidateTransitionEnabled (state : NodeState Node TxId) (self : Node) : Prop :=
  (state.role = .follower \/ state.role = .preVoteCandidate \/ state.role = .candidate)
  /\ ((self ∈ activeNodeUnion state /\ campaignEligible self state)
      \/ self ∈ state.retirementCompleted)
  /\ Not (state.membershipState = .retiredCommitted)

instance (state : NodeState Node TxId) (self : Node)
    : Decidable (candidateTransitionEnabled state self) := by
  unfold candidateTransitionEnabled
  infer_instance

/-- Nodes which the leader locally knows to have reached an index. -/
def acknowledgingNodes (state : NodeState Node TxId) (self : Node) (index : Nat)
    : Finset Node :=
  (activeNodeUnion state).filter
    fun node =>
      node = self \/ state.matchIndex node >= index

/--
True when every active configuration starting at or before an index has a
majority which reached that index.
-/
def hasMajorityAt (state : NodeState Node TxId) (self : Node) (index : Nat) : Prop :=
  (activeConfigurations state).all
    fun configuration =>
      decide
        (configuration.index <= index
          -> hasConfigurationMajority (acknowledgingNodes state self index) configuration)

instance (state : NodeState Node TxId) (self : Node) (index : Nat)
    : Decidable (hasMajorityAt state self index) := by
  unfold hasMajorityAt
  infer_instance

/-- True when votes form a strict majority in every active configuration. -/
def hasElectionMajority (state : NodeState Node TxId) : Prop :=
  (activeConfigurations state).all
    fun configuration =>
      decide (hasConfigurationMajority state.votesGranted configuration)

instance (state : NodeState Node TxId) : Decidable (hasElectionMajority state) := by
  unfold hasElectionMajority
  infer_instance

/-- True when pre-votes form a strict majority in every active configuration. -/
def hasPreVoteMajority (state : NodeState Node TxId) : Prop :=
  (activeConfigurations state).all
    fun configuration =>
      decide (hasConfigurationMajority state.preVotesGranted configuration)

instance (state : NodeState Node TxId) : Decidable (hasPreVoteMajority state) := by
  unfold hasPreVoteMajority
  infer_instance

/-- Whether some active configuration contains a replica other than the node. -/
def hasOtherActiveReplica (state : NodeState Node TxId) (self : Node) : Prop :=
  (activeNodeUnion state).erase self |>.Nonempty

instance (state : NodeState Node TxId) (self : Node)
    : Decidable (hasOtherActiveReplica state self) := by
  unfold hasOtherActiveReplica
  infer_instance

/--
The highest current-term signature above the leader's commit index which a
majority has reached, or zero when there is none.
-/
def highestCommittableIndex (state : NodeState Node TxId) (self : Node) : Nat :=
  (List.range (state.log.length + 1)).foldl
    (fun best index =>
      if index > state.commitIndex
          /\ isSignatureAt state.log index = true
          /\ termAt state.log index = state.currentTerm
          /\ hasMajorityAt state self index then
        max best index
      else
        best)
    0

/-- Advance a leader's commit index and refresh its retirement metadata. -/
def advanceCommit (state : NodeState Node TxId) (self : Node) : NodeState Node TxId :=
  refreshRetirementState self
    { state with commitIndex := highestCommittableIndex state self }

/-- Whether advancing this leader's commit frontier completes its retirement. -/
def terminalRetirementCommit (state : NodeState Node TxId) (self : Node) : Prop :=
  (advanceCommit state self).membershipState = .retiredCommitted

instance (state : NodeState Node TxId) (self : Node)
    : Decidable (terminalRetirementCommit state self) := by
  unfold terminalRetirementCommit
  infer_instance

/--
Clear the role of a node whose retirement is committed, as CCF's
`become_retired(RetiredCommitted)` does.
-/
def demoteRetiredCommitted (state : NodeState Node TxId) : NodeState Node TxId :=
  if state.membershipState = .retiredCommitted then
    { state with role := .none }
  else
    state

/-- Append one current-term entry and refresh the retirement metadata. -/
def appendEntry (state : NodeState Node TxId) (self : Node)
    (content : EntryContent Node TxId)
    : NodeState Node TxId :=
  refreshRetirementState self
    { state with log := state.log ++ [{ term := state.currentTerm, content }] }

/-! ## Outgoing messages -/

/-- Build an AppendEntries request for one destination. -/
def makeAppendEntriesRequest (state : NodeState Node TxId) (destination : Node)
    (batchEnd : Nat)
    : AppendEntriesRequest Node TxId :=
  let previousIndex := state.sentIndex destination
  {
    term := state.currentTerm
    prevLogIndex := previousIndex
    prevLogTerm := termAt state.log previousIndex
    entries := messageEntries state.log previousIndex batchEnd
    leaderCommit := state.commitIndex
  }

/-- Build a vote or pre-vote request from the candidate's log. -/
def makeRequestVoteRequest (state : NodeState Node TxId) : RequestVoteRequest where
  term := state.currentTerm
  lastCommittableTerm := lastCommittableTerm state
  lastCommittableIndex := lastCommittableIndex state

/-! ## Handling AppendEntries -/

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
def hasTermConflict (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Prop :=
  Not (request.entries = [])
  /\ Not
      (((state.log.drop request.prevLogIndex).take (overlapLength state request)).map
          Entry.term
        = (request.entries.take (overlapLength state request)).map Entry.term)

/-- Check that a request safely extends a matching follower prefix. -/
def noConflictExtension (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Prop :=
  Not (request.entries = [])
  /\ request.prevLogIndex <= state.log.length
  /\ state.log.length < request.prevLogIndex + request.entries.length
  /\ (state.log.drop request.prevLogIndex).take (state.log.length - request.prevLogIndex)
      = request.entries.take (state.log.length - request.prevLogIndex)

instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Decidable (logOk state request) := by
  unfold logOk
  infer_instance

instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Decidable (alreadyDone state request) := by
  unfold alreadyDone
  infer_instance

instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Decidable (hasTermConflict state request) := by
  unfold hasTermConflict
  infer_instance

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
def successResponse (state : NodeState Node TxId) (lastLogIndex : Nat)
    : AppendEntriesResponse where
  term := state.currentTerm
  success := true
  lastLogIndex

/-- Build the NACK for a stale or mismatched request. -/
def failureResponse (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : AppendEntriesResponse :=
  if request.term < state.currentTerm then
    {
      term := state.currentTerm
      success := false
      lastLogIndex := state.log.length
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
      }
    else
      let lastLogIndex :=
        findHighestPossibleMatch state.log request.prevLogIndex request.prevLogTerm
      {
        term := termAt state.log lastLogIndex
        success := false
        lastLogIndex
      }

/-- Reject stale-term requests or requests whose previous entry does not match. -/
def rejectAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId × AppendEntriesResponse) :=
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
    : Option (NodeState Node TxId × AppendEntriesResponse) :=
  if alreadyDone state request then
    let commitIndex := committedFromLeader state request state.log
    let nextState := { state with commitIndex }
    some
      (
        nextState,
        successResponse nextState (request.prevLogIndex + request.entries.length)
      )
  else
    none

/-- Truncate a conflicting uncommitted suffix before retrying the request. -/
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
    (self : Node)
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId × AppendEntriesResponse) :=
  if noConflictExtension state request then
    let newLog := state.log.take request.prevLogIndex ++ request.entries
    let commitIndex := committedFromLeader state request newLog
    -- Native receive runs commit callbacks at each newly applied signature.
    let firstRetirementCommit :=
      match retiredCommittedIndexInLog self newLog with
      | none => commitIndex
      | some markerIndex =>
          match signatureIndexAfterFrom (max state.log.length markerIndex) 1 newLog with
          | none => commitIndex
          | some firstNewSignature => min commitIndex firstNewSignature
    let nextState :=
      refreshRetirementState self
        { state with log := newLog, commitIndex := firstRetirementCommit }
    let nextState := { nextState with commitIndex }
    some (nextState, successResponse nextState newLog.length)
  else
    none

/-- Apply an accepted request: already done, clean extension, or truncate and retry. -/
def acceptAppendEntriesRequest?
    (self : Node)
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId × AppendEntriesResponse) :=
  if request.term = state.currentTerm
      /\ state.role = .follower
      /\ logOk state request
      /\ request.prevLogIndex >= state.commitIndex then
    match appendEntriesAlreadyDone? state request with
    | some result => some result
    | none =>
        match noConflictAppendEntriesRequest? self state request with
        | some result => some result
        | none =>
            match conflictAppendEntriesRequest? state request with
            | none => none
            | some truncated =>
                match appendEntriesAlreadyDone? truncated request with
                | some result => some result
                | none => noConflictAppendEntriesRequest? self truncated request
  else
    none

/--
Reject a request when required, otherwise apply it. A same-term candidate or
pre-vote candidate first steps down to follower. `none` means the request
cannot be handled: it stays in the network.
-/
def handleAppendEntriesRequest?
    (self : Node)
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId × AppendEntriesResponse) :=
  let state :=
    if request.term = state.currentTerm
        /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
      { state with role := .follower, isNewFollower := true }
    else
      state
  match rejectAppendEntriesRequest? state request with
  | some result => some result
  | none => acceptAppendEntriesRequest? self state request

/-- Ignore replies after stepping down; otherwise update leader peer indices. -/
def handleAppendEntriesResponse
    (state : NodeState Node TxId)
    (source : Node)
    (response : AppendEntriesResponse)
    : NodeState Node TxId :=
  if state.role != .leader then
    state
  else if response.success then
    if response.term = state.currentTerm then
      {
        state with
          matchIndex :=
            updateIndex state.matchIndex source
              (max (state.matchIndex source) response.lastLogIndex)
      }
    else
      state
  else
    let possible := findHighestPossibleMatch state.log response.lastLogIndex response.term
    {
      state with
        sentIndex :=
          updateIndex state.sentIndex source
            (max (min possible (state.sentIndex source)) (state.matchIndex source))
    }

/-! ## Handling elections -/

/-- Compare a candidate log summary with a voter's local log. -/
def voteLogUpToDate (state : NodeState Node TxId) (request : RequestVoteRequest) : Prop :=
  request.lastCommittableTerm > maxCommittableTerm state.log
  \/ (request.lastCommittableTerm = maxCommittableTerm state.log
      /\ request.lastCommittableIndex >= maxCommittableIndex state.log)

instance (state : NodeState Node TxId) (request : RequestVoteRequest)
    : Decidable (voteLogUpToDate state request) := by
  unfold voteLogUpToDate
  infer_instance

/-- Grant a current-term vote to an up-to-date candidate, at most once per term. -/
def handleRequestVoteRequest
    (state : NodeState Node TxId)
    (source : Node)
    (request : RequestVoteRequest)
    : NodeState Node TxId × RequestVoteResponse :=
  let grant : Bool :=
    decide
      (request.term = state.currentTerm
        /\ voteLogUpToDate state request
        /\ (state.votedFor = none \/ state.votedFor = some source))
  (
    if grant then { state with votedFor := some source } else state,
    { term := state.currentTerm, voteGranted := grant }
  )

/-- Answer a pre-vote request without recording a vote. -/
def handleRequestPreVote (state : NodeState Node TxId) (request : RequestVoteRequest)
    : RequestVoteResponse where
  term := state.currentTerm
  voteGranted :=
    decide (request.term = state.currentTerm /\ voteLogUpToDate state request)

/-- Tally a current-term vote granted to a candidate. -/
def handleRequestVoteResponse
    (state : NodeState Node TxId)
    (source : Node)
    (response : RequestVoteResponse)
    : NodeState Node TxId :=
  if state.role = .candidate
      /\ response.term = state.currentTerm
      /\ response.voteGranted then
    { state with votesGranted := insert source state.votesGranted }
  else
    state

/-- Tally a current-term pre-vote without changing `votedFor`. -/
def handleRequestPreVoteResponse
    (state : NodeState Node TxId)
    (source : Node)
    (response : RequestVoteResponse)
    : NodeState Node TxId :=
  if state.role = .preVoteCandidate
      /\ response.term = state.currentTerm
      /\ response.voteGranted then
    { state with preVotesGranted := insert source state.preVotesGranted }
  else
    state

/-- Start an election on a same-term vote proposal when the node is eligible. -/
def handleProposeVoteRequest (state : NodeState Node TxId) (self : Node) (term : Nat)
    : NodeState Node TxId :=
  if term = state.currentTerm /\ candidateTransitionEnabled state self then
    becomeCandidateNodeState state self
  else
    state

/-- Move to a newer term as a follower that has not voted in it. -/
def updateTerm (state : NodeState Node TxId) (term : Nat) : NodeState Node TxId :=
  if state.currentTerm < term then
    {
      state with
        role := .follower
        currentTerm := term
        votedFor := none
        isNewFollower := true
        preVotesGranted := ∅
    }
  else
    state

/--
Adopt a newer term carried by a message before handling it. Vote proposals
never advance a term, and only a leader reads the term of an AppendEntries
response.
-/
def observeTerm (state : NodeState Node TxId) : Message Node TxId -> NodeState Node TxId
  | .proposeVoteRequest _ => state
  | .appendEntriesResponse response =>
      if state.role = .leader then updateTerm state response.term else state
  | message => updateTerm state message.term

/-! ## The step -/

/-- Handle one message from `source` after observing its term. -/
def receive
    (host : Host Node TxId)
    (self source : Node)
    (state : NodeState Node TxId)
    (message : Message Node TxId)
    : Option (NodeEffect Node TxId (NodeState Node TxId)) :=
  let state := observeTerm state message
  match message with
  | .appendEntriesRequest request => do
      let (next, response) <- handleAppendEntriesRequest? self state request
      pure do
        host.send (.appendEntriesResponse response) source
        return refreshRetirementState self next
  | .appendEntriesResponse response =>
      pure (pure (handleAppendEntriesResponse state source response))
  | .requestVoteRequest request =>
      let (next, response) := handleRequestVoteRequest state source request
      pure do
        host.send (.requestVoteResponse response) source
        return next
  | .requestVoteResponse response =>
      pure (pure (handleRequestVoteResponse state source response))
  | .requestPreVote request =>
      pure do
        host.send (.requestPreVoteResponse (handleRequestPreVote state request)) source
        return state
  | .requestPreVoteResponse response =>
      pure (pure (handleRequestPreVoteResponse state source response))
  | .proposeVoteRequest term =>
      pure (pure (handleProposeVoteRequest state self term))

/-- Act on one input. -/
def act (host : Host Node TxId) (self : Node) (state : NodeState Node TxId)
    : Input Node TxId -> Option (NodeEffect Node TxId (NodeState Node TxId))
  | .initializeConfiguration => do
      guard
        (self = INITIAL_LEADER
          /\ state.role = .leader
          /\ state.currentTerm = BOOTSTRAP_TERM
          /\ state.log = []
          /\ state.commitIndex = 0
          /\ state.membershipState = .active)
      pure
        (pure
          {
            state with
              log :=
                [{
                  term := state.currentTerm
                  content := .reconfiguration INITIAL_CONFIGURATION
                }]
          })
  | .clientRequest txId => do
      let next := appendEntry state self (.transaction txId)
      guard
        (state.role = .leader
          /\ Not (state.membershipState = .retiredCommitted)
          /\ Not (next.membershipState = .retiredCommitted))
      pure (pure next)
  | .changeConfiguration newConfiguration => do
      let previousConfiguration := (latestConfiguration state).nodes
      let addedNodes := newConfiguration \ previousConfiguration
      let appended := appendEntry state self (.reconfiguration newConfiguration)
      guard
        (state.role = .leader
          /\ Not (state.membershipState = .retiredCommitted)
          /\ newConfiguration.Nonempty
          /\ Not (newConfiguration = previousConfiguration)
          /\ Not (appended.membershipState = .retiredCommitted))
      -- New nodes are sent only future entries at first; they NACK if necessary.
      pure
        (pure
          {
            appended with
              sentIndex :=
                fun peer =>
                  if peer ∈ addedNodes then state.log.length else state.sentIndex peer
          })
  | .appendRetiredCommitted => do
      let pending := state.retirementCompleted \ allRetiredCommittedNodes state.log
      let next := appendEntry state self (.retiredCommitted pending)
      guard
        (state.role = .leader
          /\ Not (state.membershipState = .retiredCommitted)
          /\ pending.Nonempty
          /\ Not (next.membershipState = .retiredCommitted))
      pure (pure next)
  | .signCommittableMessages => do
      let next := appendEntry state self .signature
      guard
        (state.role = .leader
          /\ Not (state.membershipState = .retiredCommitted)
          /\ Not (state.log = [])
          /\ Not (next.membershipState = .retiredCommitted))
      pure (pure next)
  | .appendEntries destination batchEnd => do
      let sent := state.sentIndex destination
      guard
        (state.role = .leader
          /\ Not (self = destination)
          /\ (destination ∈ activeNodeUnion state
              \/ destination ∈ state.retirementCompleted)
          /\ sent <= batchEnd
          /\ batchEnd <= state.log.length
          /\ ((messageEntries state.log sent batchEnd).all
                fun entry =>
                  entry.term == termAt state.log batchEnd)
              = true
          /\ (Not (state.membershipState = .retiredCommitted) \/ sent < batchEnd))
      pure do
        host.send
          (.appendEntriesRequest (makeAppendEntriesRequest state destination batchEnd))
          destination
        return {
          state with
            sentIndex := updateIndex state.sentIndex destination batchEnd
        }
  | .advanceCommitIndex => do
      guard
        (state.role = .leader
          /\ state.commitIndex < highestCommittableIndex state self
          /\ Not (terminalRetirementCommit state self))
      pure (pure (demoteRetiredCommitted (advanceCommit state self)))
  | .timeout => do
      guard
        (candidateTransitionEnabled state self
          /\ Not (INITIAL_PRE_VOTE_STATUS self = .enabled))
      pure (pure (becomeCandidateNodeState state self))
  | .becomePreVoteCandidate => do
      guard
        (candidateTransitionEnabled state self /\ INITIAL_PRE_VOTE_STATUS self = .enabled)
      pure (pure { state with role := .preVoteCandidate, preVotesGranted := {self} })
  | .becomeCandidate => do
      guard
        (state.role = .preVoteCandidate
          /\ candidateTransitionEnabled state self
          /\ INITIAL_PRE_VOTE_STATUS self = .enabled
          /\ hasPreVoteMajority state)
      pure (pure (becomeCandidateNodeState state self))
  | .requestVote destination => do
      guard
        (state.role = .candidate
          /\ Not (self = destination)
          /\ destination ∈ activeNodeUnion state)
      pure do
        host.send (.requestVoteRequest (makeRequestVoteRequest state)) destination
        return state
  | .requestPreVote destination => do
      guard
        (state.role = .preVoteCandidate
          /\ Not (self = destination)
          /\ destination ∈ activeNodeUnion state)
      pure do
        host.send (.requestPreVote (makeRequestVoteRequest state)) destination
        return state
  | .checkQuorum => do
      guard (state.role = .leader /\ hasOtherActiveReplica state self)
      pure (pure { state with role := .follower, isNewFollower := true })
  | .becomeLeader => do
      let log := state.log.take (maxCommittableIndex state.log)
      let truncated := { state with log }
      guard
        (state.role = .candidate
          /\ Not (state.membershipState = .retiredCommitted)
          /\ hasElectionMajority state
          /\ Not
              ((refreshRetirementState self truncated).membershipState
                = .retiredCommitted))
      pure
        (pure
          (refreshRetirementState self
            {
              truncated with
                role := .leader
                sentIndex := fun _ => log.length
                matchIndex := fun _ => 0
            }))
  | .proposeVote destination => do
      guard (state.role = .leader /\ plausibleSuccessor state self destination)
      pure do
        host.send (.proposeVoteRequest state.currentTerm) destination
        return state
  | .advanceCommitIndexAndProposeVote destination => do
      guard
        (state.role = .leader
          /\ state.commitIndex < highestCommittableIndex state self
          /\ terminalRetirementCommit state self
          /\ plausibleSuccessor state self destination)
      pure do
        host.send (.proposeVoteRequest state.currentTerm) destination
        return demoteRetiredCommitted (advanceCommit state self)

/-- One step of node `self`: act on an input or handle a delivered message. -/
def step (host : Host Node TxId) (self : Node) (state : NodeState Node TxId)
    : Event Node TxId -> Option (NodeEffect Node TxId (NodeState Node TxId))
  | .internal input => act host self state input
  | .receive source message => receive host self source state message

end CCFRaft.Model.Local
