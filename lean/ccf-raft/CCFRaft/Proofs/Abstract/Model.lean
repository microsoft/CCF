-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model.Node
import CCFRaft.Proofs.Abstract.ExecutableTransitionSystem
import Mathlib.Data.Finmap

set_option autoImplicit false

/-!
# Abstract global-state model

The global-state CCF Raft model that `CCFRaft.Model` refines. The node
state and ledger functions are shared with `CCFRaft.Model.Local`.

Followers and candidates may start next-term elections repeatedly, and a message
may move another node directly across skipped terms. Handlers see only the
acting node's local state and an immutable message snapshot.
-/

namespace CCFRaft.Proofs.Abstract.Model

open CCFRaft.Model.Local (BOOTSTRAP_TERM Bootstrap Configuration Entry EntryContent INITIAL_CONFIGURATION INITIAL_LEADER INITIAL_PRE_VOTE_STATUS MembershipState NodeState PreVoteStatus Role activeConfigurations activeNodeUnion allConfigurations allRetiredCommittedNodes becomeCandidateNodeState campaignEligible configurationsInLog configurationsInLogFrom currentConfiguration currentConfigurationAt entryAt? findHighestPossibleMatch hasConfigurationMajority highestActiveConfigurationWithNode implicitConfiguration initialNodeState isSignatureAt lastCommittableIndex lastCommittableTerm latestConfiguration maxCommittableIndex maxCommittableIndexUpTo maxCommittableTerm messageEntries refreshRetirementState retiredCommittedIndexFrom retiredCommittedIndexInLog retiredCommittedNodesUpTo retiredCommittedNodesUpToFrom retirementCommittableIndexInLog retirementCompletedNodes retirementIndexFromConfigurations retirementIndexInLog signatureIndexAfterFrom termAt updateIndex)

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

namespace NodeState

end NodeState

/-- The fresh local state assigned when a configuration first adds a node. -/
def freshNodeState : NodeState Node TxId where
  role := .none
  currentTerm := 0
  log := []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := true
  votedFor := none
  votesGranted := ∅

/-- Finite storage for node-local protocol state. -/
structure NodeStore (Node TxId : Type) where
  entries : Finmap (fun _ : Node => NodeState Node TxId)

namespace NodeStore

variable [DecidableEq Node]

/-- Read a node's state, or `none` when the node is unallocated. -/
def node? (nodes : NodeStore Node TxId) (node : Node) :
    Option (NodeState Node TxId) :=
  nodes.entries.lookup node

/-- Read a node's state, using `freshNodeState` for an unallocated node. -/
def get (nodes : NodeStore Node TxId) (node : Node) :
    NodeState Node TxId :=
  (nodes.node? node).getD freshNodeState

instance : CoeFun (NodeStore Node TxId) (fun _ => Node -> NodeState Node TxId) where
  coe := get

/-- Whether storage has been allocated for a node identity. -/
def allocated (nodes : NodeStore Node TxId) (node : Node) : Prop :=
  nodes.node? node |>.isSome

instance (nodes : NodeStore Node TxId) (node : Node) :
    Decidable (nodes.allocated node) :=
  inferInstanceAs (Decidable (nodes.node? node |>.isSome))

/-- Insert or replace the state of one node. -/
def set
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    NodeStore Node TxId :=
  ⟨nodes.entries.insert node value⟩

/-- A store with no allocated node identities. -/
def empty : NodeStore Node TxId :=
  ⟨∅⟩

/-- Allocate a finite set of keys with values computed from each key. -/
def ofFinset
    (keys : Finset Node)
    (value : Node -> NodeState Node TxId) :
    NodeStore Node TxId :=
  let entries :=
    keys.1.map fun node => Sigma.mk node (value node)
  ⟨{
    entries
    nodupKeys := by
      rw [← Multiset.nodup_keys]
      simpa [entries, Multiset.keys] using keys.2
  }⟩

/-- Add fresh states for a finite set without replacing existing states. -/
def allocate
    (nodes : NodeStore Node TxId)
    (added : Finset Node) :
    NodeStore Node TxId :=
  ⟨nodes.entries ∪ (ofFinset added fun _ => freshNodeState).entries⟩

end NodeStore

/--
Global state: node states, message queues, submitted transaction IDs, and join
history.
-/
structure State (Node TxId : Type) where
  nodes : NodeStore Node TxId
  network : Node -> List (Message Node TxId)
  submittedTxIds : Finset TxId
  hasJoined : Finset Node
  preVoteStatus : Node -> PreVoteStatus := fun _ => .capable
  retirementCompleted : Node -> Finset Node := fun _ => ∅

variable [DecidableEq Node] [DecidableEq TxId]

/-- Read a node's state from the global state, or `none` when unallocated. -/
def State.node? (state : State Node TxId) (node : Node) :
    Option (NodeState Node TxId) :=
  state.nodes.node? node

/-- Whether the global state has allocated storage for a node identity. -/
def State.allocated (state : State Node TxId) (node : Node) : Prop :=
  state.nodes.allocated node

instance (state : State Node TxId) (node : Node) :
    Decidable (state.allocated node) :=
  inferInstanceAs (Decidable (state.nodes.allocated node))

/-- Replace the state of one node. -/
def updateNode
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    NodeStore Node TxId :=
  nodes.set node value

/-- Replace the message queue of one destination. -/
def updateQueue
    (network : Node -> List (Message Node TxId))
    (destination : Node)
    (queue : List (Message Node TxId)) :
    Node -> List (Message Node TxId) :=
  Function.update network destination queue

variable [Bootstrap Node]

/-- Allocate local states for exactly the bootstrap configuration. -/
def initialNodes : NodeStore Node TxId :=
  NodeStore.ofFinset INITIAL_CONFIGURATION initialNodeState

/--
The starting global state: bootstrap members allocated, empty queues, and no
submitted transactions.
-/
def initialState : State Node TxId where
  nodes := initialNodes
  network := fun _ => []
  submittedTxIds := ∅
  hasJoined := INITIAL_CONFIGURATION
  preVoteStatus := INITIAL_PRE_VOTE_STATUS
  retirementCompleted := fun _ => ∅

/--
A successor has maximal replication progress, with ties broken by membership
in the highest active configuration, matching CCF's successor nomination.
-/
def plausibleSuccessor
    (state : State Node TxId)
    (source destination : Node) : Prop :=
  let sourceState := state.nodes source
  let candidates := (activeNodeUnion sourceState).erase source
  destination ∈ candidates /\
    ∀ candidate ∈ candidates,
      sourceState.matchIndex candidate <=
          sourceState.matchIndex destination /\
        (sourceState.matchIndex candidate =
            sourceState.matchIndex destination ->
          highestActiveConfigurationWithNode sourceState candidate <=
            highestActiveConfigurationWithNode sourceState destination)

instance
    (state : State Node TxId)
    (source destination : Node) :
    Decidable (plausibleSuccessor state source destination) := by
  unfold plausibleSuccessor
  infer_instance

/-- Record the retirement-completed nodes one observer must still replicate to.
Compute the snapshot at update time, not at each later function application. -/
@[macro_inline]
def refreshRetirementCompleted
    (retirementCompleted : Node -> Finset Node)
    (observer : Node)
    (state : NodeState Node TxId) :
    Node -> Finset Node :=
  Function.update retirementCompleted observer
    (retirementCompletedNodes state.log state.commitIndex)

/--
The conditions which let a node start an election, checked when it handles a
vote proposal. The `timeout` and `becomePreVoteCandidate` guards repeat them.
-/
def candidateTransitionEnabled
    (state : State Node TxId)
    (node : Node) : Prop :=
  state.allocated node /\
    ((state.nodes node).role = .follower \/
      (state.nodes node).role = .preVoteCandidate \/
      (state.nodes node).role = .candidate) /\
    ((node ∈ activeNodeUnion (state.nodes node) /\
        campaignEligible node (state.nodes node)) \/
      node ∈ state.retirementCompleted node) /\
    Not ((state.nodes node).membershipState = .retiredCommitted)

instance
    (state : State Node TxId)
    (node : Node) :
    Decidable (candidateTransitionEnabled state node) := by
  unfold candidateTransitionEnabled
  infer_instance

/-- Append a message to its destination queue, even if an equal one is pending.
Inlining before closure conversion captures the queue once at send time. -/
@[macro_inline]
def enqueue
    (network : Node -> List (Message Node TxId))
    (message : Message Node TxId) :
    Node -> List (Message Node TxId) :=
  let destination := message.destination
  let queue := network destination
  updateQueue network destination (queue ++ [message])

/-- Take the first message from one sender, keeping the order of the others. -/
def takeFirstFrom
    (source : Node) :
    List (Message Node TxId) ->
      Option (Message Node TxId × List (Message Node TxId))
  | [] => none
  | message :: tail =>
      if message.source = source then
        some (message, tail)
      else
        match takeFirstFrom source tail with
        | none => none
        | some (selected, remaining) =>
            some (selected, message :: remaining)

/-- Take the zero-based nth message from one sender, keeping the others in order.
Matches Network.tla's OrderDropMessage, with an explicit selection witness. -/
def takeOccurrenceFrom
    (source : Node) :
    Nat -> List (Message Node TxId) ->
      Option (Message Node TxId × List (Message Node TxId))
  | _, [] => none
  | occurrence, message :: tail =>
      if message.source = source then
        match occurrence with
        | 0 => some (message, tail)
        | n + 1 => do
            let (selected, remaining) <- takeOccurrenceFrom source n tail
            pure (selected, message :: remaining)
      else do
        let (selected, remaining) <- takeOccurrenceFrom source occurrence tail
        pure (selected, message :: remaining)

/-- Check that a request's previous index and term match the follower log. -/
def logOk
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  request.prevLogIndex = 0 \/
    (request.prevLogIndex <= state.log.length /\
      termAt state.log request.prevLogIndex = request.prevLogTerm)

/-- Check whether a heartbeat or all requested entry terms are already present. -/
def alreadyDone
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  request.entries = [] \/
    (request.prevLogIndex + request.entries.length <= state.log.length /\
      ((state.log.drop request.prevLogIndex).take request.entries.length).map
          Entry.term =
        request.entries.map Entry.term)

/-- Number of request entries that overlap the follower's existing suffix. -/
def overlapLength
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Nat :=
  min request.entries.length
    (state.log.length - request.prevLogIndex)

/-- Detect a differing term in the overlapping part of a request. -/
def hasTermConflict
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  Not (request.entries = []) /\
    Not (
      ((state.log.drop request.prevLogIndex).take
          (overlapLength state request)).map Entry.term =
        (request.entries.take (overlapLength state request)).map Entry.term)

/-- Check that a request safely extends a matching follower prefix. -/
def noConflictExtension
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  Not (request.entries = []) /\
    request.prevLogIndex <= state.log.length /\
    state.log.length < request.prevLogIndex + request.entries.length /\
    (state.log.drop request.prevLogIndex).take
        (state.log.length - request.prevLogIndex) =
      request.entries.take (state.log.length - request.prevLogIndex)

/-- Make the previous-entry consistency guard executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (logOk state request) := by
  unfold logOk
  infer_instance

/-- Make the already-applied request guard executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (alreadyDone state request) := by
  unfold alreadyDone
  infer_instance

/-- Make term-conflict detection executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (hasTermConflict state request) := by
  unfold hasTermConflict
  infer_instance

/-- Make no-conflict extension detection executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (noConflictExtension state request) := by
  unfold noConflictExtension
  infer_instance

/-- Advance the commit index to the latest signature the request covers. -/
def committedFromLeader
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId)) : Nat :=
  max state.commitIndex
    (maxCommittableIndexUpTo newLog
      (min request.leaderCommit
        (request.prevLogIndex + request.entries.length)))

/-- Build the ACK for an applied request. -/
def successResponse
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (lastLogIndex : Nat) :
    AppendEntriesResponse Node where
  term := state.currentTerm
  success := true
  lastLogIndex
  source := request.destination
  destination := request.source

/-- Build the NACK for a stale or mismatched request. -/
def failureResponse
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    AppendEntriesResponse Node :=
  if request.term < state.currentTerm then
    { term := state.currentTerm
      success := false
      lastLogIndex := state.log.length
      source := request.destination
      destination := request.source }
  else
    let previousTerm :=
      if request.prevLogIndex = 0 then
        0
      else if request.prevLogIndex > state.log.length then
        0
      else
        termAt state.log state.log.length
    if previousTerm = 0 then
      { term := state.currentTerm
        success := false
        lastLogIndex := state.log.length
        source := request.destination
        destination := request.source }
    else
      let lastLogIndex :=
        findHighestPossibleMatch
          state.log request.prevLogIndex request.prevLogTerm
      { term := termAt state.log lastLogIndex
        success := false
        lastLogIndex
        source := request.destination
        destination := request.source }

/-- Reject stale-term requests or requests whose previous entry does not match. -/
def rejectAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if request.term < state.currentTerm \/
      (request.term = state.currentTerm /\
        state.role = .follower /\
        Not (logOk state request)) then
    some (state, failureResponse state request)
  else
    none

/-- ACK a request whose entries are already present, and adopt its commit index. -/
def appendEntriesAlreadyDone?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if alreadyDone state request then
    let commitIndex := committedFromLeader state request state.log
    let nextState := { state with commitIndex }
    some
      (nextState,
        successResponse nextState request
          (request.prevLogIndex + request.entries.length))
  else
    none

/-- Truncate a conflicting uncommitted suffix without consuming the request. -/
def conflictAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId) :=
  if hasTermConflict state request /\ state.isNewFollower then
    some
      { state with
        log := state.log.take request.prevLogIndex
        isNewFollower := false }
  else
    none

/-- Append a matching extension and return an ACK. -/
def noConflictAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
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
    let nextState := refreshRetirementState request.destination
      { state with log := newLog, commitIndex := firstRetirementCommit }
    let nextState := { nextState with commitIndex }
    some (nextState, successResponse nextState request newLog.length)
  else
    none

/-- Apply an accepted request: already done, clean extension, or truncate and retry. -/
def acceptAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if request.term = state.currentTerm /\
      state.role = .follower /\
      logOk state request /\
      request.prevLogIndex >= state.commitIndex then
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
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  match rejectAppendEntriesRequest? state request with
  | some result => some result
  | none => acceptAppendEntriesRequest? state request

/-- A same-term candidate steps down before retrying the unchanged request. -/
def returnToFollowerState?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId) :=
  if request.term = state.currentTerm /\
      (state.role = .candidate \/
        state.role = .preVoteCandidate) then
    some { state with role := .follower, isNewFollower := true }
  else
    none

/-- Ignore replies after stepping down; otherwise update leader peer indices. -/
def handleAppendEntriesResponse?
    (state : NodeState Node TxId)
    (response : AppendEntriesResponse Node) :
    Option (NodeState Node TxId) :=
  if state.role != .leader then
    some state
  else if response.success = true /\
      response.term = state.currentTerm then
    some
      { state with
        matchIndex :=
          updateIndex
            state.matchIndex
            response.source
            (max (state.matchIndex response.source) response.lastLogIndex) }
  else if response.success = false then
    let possible :=
      findHighestPossibleMatch state.log response.lastLogIndex response.term
    some
      { state with
        sentIndex :=
          updateIndex
            state.sentIndex
            response.source
            (max
              (min possible (state.sentIndex response.source))
              (state.matchIndex response.source)) }
  else if response.term < state.currentTerm then
    some state
  else
    none

/-- Compare a candidate log summary with a voter's local log. -/
def voteLogUpToDate
    (state : NodeState Node TxId)
    (request : RequestVoteRequest Node) : Prop :=
  request.lastCommittableTerm > maxCommittableTerm state.log \/
    (request.lastCommittableTerm = maxCommittableTerm state.log /\
      request.lastCommittableIndex >= maxCommittableIndex state.log)

instance (state : NodeState Node TxId) (request : RequestVoteRequest Node) :
    Decidable (voteLogUpToDate state request) := by
  unfold voteLogUpToDate
  infer_instance

/-- Read a RequestPreVote as a RequestVote request with the same fields. -/
def RequestPreVote.toRequestVoteRequest
    (request : RequestPreVote Node) :
    RequestVoteRequest Node where
  term := request.term
  lastCommittableTerm := request.lastCommittableTerm
  lastCommittableIndex := request.lastCommittableIndex
  source := request.source
  destination := request.destination

/-- Handle a current-term RequestVote request and construct the reply. -/
def handleRequestVoteRequest?
    (state : NodeState Node TxId)
    (request : RequestVoteRequest Node) :
    Option (NodeState Node TxId × RequestVoteResponse Node) :=
  if request.term <= state.currentTerm then
    let grant : Bool :=
      decide (
        request.term = state.currentTerm /\
          voteLogUpToDate state request /\
          (state.votedFor = none \/
            state.votedFor = some request.source))
    let nextState :=
      if grant then { state with votedFor := some request.source } else state
    some
      (nextState,
        { term := state.currentTerm
          voteGranted := grant
          source := request.destination
          destination := request.source })
  else
    none

/-- Handle a RequestPreVote request without recording a vote. -/
def handleRequestPreVote?
    (state : NodeState Node TxId)
    (request : RequestPreVote Node) :
    Option (NodeState Node TxId × RequestPreVoteResponse Node) :=
  let ordinaryRequest := request.toRequestVoteRequest
  if request.term <= state.currentTerm then
    let grant : Bool :=
      decide (
        request.term = state.currentTerm /\
          voteLogUpToDate state ordinaryRequest)
    some
      (state,
        { term := state.currentTerm
          voteGranted := grant
          source := request.destination
          destination := request.source })
  else
    none

/-- Tally or discard a RequestVote response at the candidate. -/
def handleRequestVoteResponse?
    (state : NodeState Node TxId)
    (response : RequestVoteResponse Node) :
    Option (NodeState Node TxId) :=
  if response.term < state.currentTerm then
    some state
  else if state.role != .candidate then
    some state
  else if response.term = state.currentTerm then
    if response.voteGranted then
      some
        { state with
          votesGranted := insert response.source state.votesGranted }
    else
      some state
  else
    none

/-- Tally or discard a RequestPreVote response without changing `votedFor`. -/
def handleRequestPreVoteResponse?
    (state : NodeState Node TxId)
    (response : RequestPreVoteResponse Node) :
    Option (NodeState Node TxId) :=
  if response.term < state.currentTerm then
    some state
  else if state.role != .preVoteCandidate then
    some state
  else if response.term = state.currentTerm then
    if response.voteGranted then
      some
        { state with
          preVotesGranted := insert response.source state.preVotesGranted }
    else
      some state
  else
    none

/-- Build a RequestVote message from the candidate's local state. -/
def makeRequestVoteRequest
    (state : State Node TxId)
    (source destination : Node) :
    RequestVoteRequest Node :=
  let sourceState := state.nodes source
  { term := sourceState.currentTerm
    lastCommittableTerm := lastCommittableTerm sourceState
    lastCommittableIndex := lastCommittableIndex sourceState
    source
    destination }

/-- Build a RequestPreVote message from the pre-vote candidate's local state. -/
def makeRequestPreVote
    (state : State Node TxId)
    (source destination : Node) :
    RequestPreVote Node :=
  let sourceState := state.nodes source
  { term := sourceState.currentTerm
    lastCommittableTerm := lastCommittableTerm sourceState
    lastCommittableIndex := lastCommittableIndex sourceState
    source
    destination }

/-- Build a vote proposal from the leader's local state. -/
def makeProposeVoteRequest
    (state : State Node TxId)
    (source destination : Node) :
    ProposeVoteRequest Node :=
  { term := (state.nodes source).currentTerm
    source
    destination }

/--
Start an election on a same-term vote proposal when the node is eligible, and
otherwise leave the node state unchanged.
-/
def handleProposeVoteRequest?
    (state : State Node TxId)
    (destination : Node)
    (request : ProposeVoteRequest Node) :
    Option (NodeState Node TxId) :=
  let nodeState := state.nodes destination
  if request.term = nodeState.currentTerm /\
      candidateTransitionEnabled state destination then
    some (becomeCandidateNodeState nodeState destination)
  else
    some nodeState

/-- Requests may introduce an unknown sender; responses require a known peer. -/
def messageSourceAllowed
    (state : State Node TxId)
    (message : Message Node TxId) : Prop :=
  match message with
  | .appendEntriesRequest _ => True
  | .requestVoteRequest _ => True
  | .requestPreVote _ => True
  | .appendEntriesResponse response => state.allocated response.source
  | .requestVoteResponse response => state.allocated response.source
  | .requestPreVoteResponse response => state.allocated response.source
  | .proposeVoteRequest _ => True

instance
    (state : State Node TxId)
    (message : Message Node TxId) :
    Decidable (messageSourceAllowed state message) := by
  cases message <;> simp only [messageSourceAllowed] <;> infer_instance

/--
The first queued message from a source with a newer term, ignoring vote
proposals, which never advance a term.
-/
def newerMessage?
    (state : State Node TxId)
    (source destination : Node) :
    Option (Message Node TxId) := do
  let (selected, _) <- takeFirstFrom source (state.network destination)
  match selected with
  | .proposeVoteRequest _ => none
  | _ =>
      if messageSourceAllowed state selected /\
          (state.nodes destination).currentTerm < selected.term then
        some selected
      else
        none

/-- Replace a destination queue with its remaining messages, then append a reply. -/
@[macro_inline]
def reply
    (network : Node -> List (Message Node TxId))
    (requestDestination : Node)
    (remaining : List (Message Node TxId))
    (response : AppendEntriesResponse Node) :
    Node -> List (Message Node TxId) :=
  enqueue
    (updateQueue network requestDestination remaining)
    (.appendEntriesResponse response)

/-- Process the first queued message from one sender at a destination. -/
def handleReceive?
    (state : State Node TxId)
    (source destination : Node) :
    Option (State Node TxId) :=
  match takeFirstFrom source (state.network destination) with
  | none => none
  | some (message, remaining) =>
      if message.destination != destination then
        none
      else
        match message with
        | .appendEntriesRequest request =>
            match returnToFollowerState? (state.nodes destination) request with
            | some nextNode =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode }
            | none =>
                match handleAppendEntriesRequest? (state.nodes destination) request with
                | none => none
                | some (nextNode, response) =>
                    let refreshedNode :=
                      refreshRetirementState destination nextNode
                    some
                      { state with
                        nodes :=
                          updateNode state.nodes destination refreshedNode
                        network :=
                          reply state.network destination remaining response
                        retirementCompleted :=
                          refreshRetirementCompleted
                            state.retirementCompleted destination refreshedNode }
        | .appendEntriesResponse response =>
            if state.allocated response.source then
              match
                handleAppendEntriesResponse? (state.nodes destination) response
              with
              | none => none
              | some nextNode =>
                  some
                    { state with
                      nodes := updateNode state.nodes destination nextNode
                      network :=
                        updateQueue state.network destination remaining }
            else
              some
                { state with
                  network :=
                    updateQueue state.network destination remaining }
        | .requestVoteRequest request =>
            match handleRequestVoteRequest? (state.nodes destination) request with
            | none => none
            | some (nextNode, response) =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode
                    network :=
                      enqueue
                        (updateQueue state.network destination remaining)
                        (.requestVoteResponse response) }
        | .requestVoteResponse response =>
            if state.allocated response.source then
              match
                handleRequestVoteResponse? (state.nodes destination) response
              with
              | none => none
              | some nextNode =>
                  some
                    { state with
                      nodes := updateNode state.nodes destination nextNode
                      network :=
                        updateQueue state.network destination remaining }
            else
              some
                { state with
                  network :=
                    updateQueue state.network destination remaining }
        | .requestPreVote request =>
            match
              handleRequestPreVote?
                (state.nodes destination)
                request
            with
            | none => none
            | some (nextNode, response) =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode
                    network :=
                      enqueue
                        (updateQueue state.network destination remaining)
                        (.requestPreVoteResponse response) }
        | .requestPreVoteResponse response =>
            if state.allocated response.source then
              match
                handleRequestPreVoteResponse?
                  (state.nodes destination)
                  response
              with
              | none => none
              | some nextNode =>
                  some
                    { state with
                      nodes := updateNode state.nodes destination nextNode
                      network :=
                        updateQueue state.network destination remaining }
            else
              some
                { state with
                  network :=
                    updateQueue state.network destination remaining }
        | .proposeVoteRequest request =>
            match handleProposeVoteRequest? state destination request with
            | none => none
            | some nextNode =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode
                    network :=
                      updateQueue state.network destination remaining }

/-- Build an AppendEntries request from the leader's state for one destination. -/
def makeAppendEntriesRequest
    (state : State Node TxId)
    (source destination : Node)
    (batchEnd : Nat) :
    AppendEntriesRequest Node TxId :=
  let sourceState := state.nodes source
  let previousIndex := sourceState.sentIndex destination
  { term := sourceState.currentTerm
    prevLogIndex := previousIndex
    prevLogTerm := termAt sourceState.log previousIndex
    entries := messageEntries sourceState.log previousIndex batchEnd
    leaderCommit := sourceState.commitIndex
    source
    destination }

/-- Nodes which the leader locally knows to have reached an index. -/
def acknowledgingNodes
    (state : State Node TxId)
    (leader : Node)
    (index : Nat) :
    Finset Node :=
  (activeNodeUnion (state.nodes leader)).filter fun node =>
    node = leader \/
      (state.nodes leader).matchIndex node >= index

/--
True when every active configuration starting at or before an index has a
majority which reached that index.
-/
def hasMajorityAt
    (state : State Node TxId)
    (leader : Node)
    (index : Nat) : Prop :=
  (activeConfigurations (state.nodes leader)).all fun configuration =>
    decide (
      configuration.index <= index ->
        hasConfigurationMajority
          (acknowledgingNodes state leader index)
          configuration)

/-- Make the replication majority check executable. -/
instance (state : State Node TxId) (leader : Node) (index : Nat) :
    Decidable (hasMajorityAt state leader index) := by
  unfold hasMajorityAt
  infer_instance

/-- True when votes form a strict majority in every active configuration. -/
def hasElectionMajority
    (state : State Node TxId)
    (candidate : Node) : Prop :=
  (activeConfigurations (state.nodes candidate)).all fun configuration =>
    decide (
      hasConfigurationMajority
        (state.nodes candidate).votesGranted
        configuration)

instance (state : State Node TxId) (candidate : Node) :
    Decidable (hasElectionMajority state candidate) := by
  unfold hasElectionMajority
  infer_instance

/-- True when pre-votes form a strict majority in every active configuration. -/
def hasPreVoteMajority
    (state : State Node TxId)
    (candidate : Node) : Prop :=
  (activeConfigurations (state.nodes candidate)).all fun configuration =>
    decide (
      hasConfigurationMajority
        (state.nodes candidate).preVotesGranted
        configuration)

instance (state : State Node TxId) (candidate : Node) :
    Decidable (hasPreVoteMajority state candidate) := by
  unfold hasPreVoteMajority
  infer_instance

/-- Whether some active configuration contains a replica other than the node. -/
def hasOtherActiveReplica
    (state : State Node TxId)
    (node : Node) : Prop :=
  (activeNodeUnion (state.nodes node)).erase node |>.Nonempty

instance (state : State Node TxId) (node : Node) :
    Decidable (hasOtherActiveReplica state node) := by
  unfold hasOtherActiveReplica
  infer_instance

/-- Completed retirements not yet represented in a leader's log. -/
def pendingRetiredCommittedNodes
    (state : State Node TxId)
    (leader : Node) :
    Finset Node :=
  state.retirementCompleted leader \
    allRetiredCommittedNodes (state.nodes leader).log

/--
The highest current-term signature above the leader's commit index which a
majority has reached, or zero when there is none.
-/
def highestCommittableIndex
    (state : State Node TxId)
    (leader : Node) : Nat :=
  let leaderState := state.nodes leader
  (List.range (leaderState.log.length + 1)).foldl
    (fun best index =>
      if index > leaderState.commitIndex /\
          isSignatureAt leaderState.log index = true /\
          termAt leaderState.log index = leaderState.currentTerm /\
          hasMajorityAt state leader index then
        max best index
      else
        best)
    0

/-- Whether advancing this leader's commit frontier completes its retirement. -/
def terminalRetirementCommit
    (state : State Node TxId)
    (node : Node) : Prop :=
  let nodeState := state.nodes node
  (refreshRetirementState node
    { nodeState with
      commitIndex := highestCommittableIndex state node }).membershipState =
        .retiredCommitted

instance
    (state : State Node TxId)
    (node : Node) :
    Decidable (terminalRetirementCommit state node) := by
  unfold terminalRetirementCommit
  infer_instance

/-- One protocol step, with an explicit argument for every nondeterministic choice. -/
inductive Action (Node TxId : Type) where
  /-- Write the bootstrap configuration to the initial leader's empty log. -/
  | initializeConfiguration (node : Node)
  /-- Submit a fresh external transaction to a node. -/
  | clientRequest (node : Node) (txId : TxId)
  /-- Append a new nonempty configuration to a leader's log. -/
  | changeConfiguration (source : Node) (newConfiguration : Finset Node)
  /-- Record completed retirements which are not durably represented yet. -/
  | appendRetiredCommitted (node : Node)
  /-- Append a signature over a leader's nonempty log. -/
  | signCommittableMessages (node : Node)
  /-- Send a single-term batch or an empty heartbeat. -/
  | appendEntries (source destination : Node) (batchEnd : Nat)
  /-- Process the first queued message from one sender. -/
  | receive (source destination : Node)
  /-- Drop the nth message from one sender, keeping the others in order. -/
  | drop (source destination : Node) (occurrence : Nat)
  /-- Advance a leader to the commit index it can compute locally. -/
  | advanceCommitIndex (node : Node)
  /-- Start a next-term election when pre-vote is not enabled. -/
  | timeout (node : Node)
  /-- Start a pre-vote round without advancing the local term. -/
  | becomePreVoteCandidate (node : Node)
  /-- Convert a successful pre-vote round into a next-term election. -/
  | becomeCandidate (node : Node)
  /-- Send a RequestVote message from a candidate to another node. -/
  | requestVote (source destination : Node)
  /-- Send a RequestPreVote message to another node. -/
  | requestPreVote (source destination : Node)
  /-- Step down as leader in the current term after a failed quorum check. -/
  | checkQuorum (node : Node)
  /-- Observe a newer message term without consuming the message. -/
  | updateTerm (source destination : Node)
  /-- Promote a candidate after its local vote set reaches a majority. -/
  | becomeLeader (node : Node)
  /-- Ask one plausible successor to start an ordinary election. -/
  | proposeVote (source destination : Node)
  /-- Commit terminal retirement and propose a vote to a successor in one step. -/
  | advanceCommitIndexAndProposeVote (source destination : Node)
  deriving DecidableEq

/-- Apply `becomeCandidateNodeState` to one node of the global state. -/
@[simp]
def becomeCandidateState
    (state : State Node TxId)
    (node : Node) :
    State Node TxId :=
  let nodeState := state.nodes node
  { state with
    nodes :=
      updateNode state.nodes node
        (becomeCandidateNodeState nodeState node) }

/-- Advance a node's commit index and refresh its retirement metadata. -/
def advanceCommitState
    (state : State Node TxId)
    (node : Node) :
    State Node TxId :=
  let nodeState := state.nodes node
  let refreshed :=
    refreshRetirementState node
      { nodeState with
        commitIndex := highestCommittableIndex state node }
  { state with
    nodes := updateNode state.nodes node refreshed
    retirementCompleted :=
      refreshRetirementCompleted state.retirementCompleted node refreshed }

/-- Demote one node to follower without changing its term. -/
def stepDownState
    (state : State Node TxId)
    (node : Node) :
    State Node TxId :=
  let nodeState := state.nodes node
  { state with
    nodes :=
      updateNode state.nodes node
        { nodeState with role := .follower, isNewFollower := true } }

/--
Clear the role of a node whose retirement is committed, as CCF's
`become_retired(RetiredCommitted)` does.
-/
def demoteRetiredCommitted
    (state : State Node TxId)
    (node : Node) :
    State Node TxId :=
  let nodeState := state.nodes node
  if nodeState.membershipState = .retiredCommitted then
    { state with
      nodes := updateNode state.nodes node { nodeState with role := .none } }
  else
    state

/-- An action's guard and total update, including when the guard is false. -/
structure ActionDefinition (Node TxId : Type) where
  enabled : Prop
  next : State Node TxId

/-- Define each action's guard beside its state update. -/
@[reducible]
def definition
    (state : State Node TxId) :
    Action Node TxId -> ActionDefinition Node TxId
  | .initializeConfiguration node =>
      let nodeState := state.nodes node
      { enabled :=
          node = INITIAL_LEADER /\
            state.allocated node /\
            nodeState.role = .leader /\
            nodeState.currentTerm = BOOTSTRAP_TERM /\
            nodeState.log = [] /\
            nodeState.commitIndex = 0 /\
            nodeState.membershipState = .active
        next :=
          { state with
            nodes := updateNode state.nodes node
              { nodeState with
                log := [{ term := nodeState.currentTerm
                          content := .reconfiguration INITIAL_CONFIGURATION }] } } }
  | .clientRequest node txId =>
      let nodeState := state.nodes node
      let entry : Entry Node TxId :=
        { term := nodeState.currentTerm
          content := .transaction txId }
      let refreshed :=
        refreshRetirementState node
          { nodeState with log := nodeState.log ++ [entry] }
      { enabled :=
          state.allocated node /\
            nodeState.role = .leader /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            Not (refreshed.membershipState = .retiredCommitted)
        next :=
          { state with
            nodes := updateNode state.nodes node refreshed
            submittedTxIds := insert txId state.submittedTxIds
            retirementCompleted :=
              refreshRetirementCompleted state.retirementCompleted node refreshed } }
  | .changeConfiguration source newConfiguration =>
      let sourceState := state.nodes source
      let previousConfiguration := (latestConfiguration sourceState).nodes
      let addedNodes := newConfiguration \ previousConfiguration
      let entry : Entry Node TxId :=
        { term := sourceState.currentTerm
          content := .reconfiguration newConfiguration }
      let appended := { sourceState with log := sourceState.log ++ [entry] }
      { enabled :=
          state.allocated source /\
            sourceState.role = .leader /\
            Not (sourceState.membershipState = .retiredCommitted) /\
            newConfiguration.Nonempty /\
            Not (newConfiguration = previousConfiguration) /\
            Not (
              (refreshRetirementState source appended).membershipState =
                .retiredCommitted)
        next :=
          let nextSourceState :=
            refreshRetirementState source
              { appended with
                sentIndex := fun peer =>
                  if peer ∈ addedNodes then
                    sourceState.log.length
                  else
                    sourceState.sentIndex peer }
          { state with
            nodes := updateNode (state.nodes.allocate addedNodes) source nextSourceState
            hasJoined := state.hasJoined ∪ addedNodes
            retirementCompleted :=
              refreshRetirementCompleted
                state.retirementCompleted source nextSourceState } }
  | .appendRetiredCommitted node =>
      let nodeState := state.nodes node
      let pending := pendingRetiredCommittedNodes state node
      let entry : Entry Node TxId :=
        { term := nodeState.currentTerm
          content := .retiredCommitted pending }
      let refreshed :=
        refreshRetirementState node
          { nodeState with log := nodeState.log ++ [entry] }
      { enabled :=
          state.allocated node /\
            nodeState.role = .leader /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            pending.Nonempty /\
            Not (refreshed.membershipState = .retiredCommitted)
        next :=
          { state with
            nodes := updateNode state.nodes node refreshed
            retirementCompleted :=
              refreshRetirementCompleted state.retirementCompleted node refreshed } }
  | .signCommittableMessages node =>
      let nodeState := state.nodes node
      let entry : Entry Node TxId :=
        { term := nodeState.currentTerm
          content := .signature }
      let refreshed :=
        refreshRetirementState node
          { nodeState with log := nodeState.log ++ [entry] }
      { enabled :=
          state.allocated node /\
            nodeState.role = .leader /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            Not (nodeState.log = []) /\
            Not (refreshed.membershipState = .retiredCommitted)
        next :=
          { state with
            nodes := updateNode state.nodes node refreshed
            retirementCompleted :=
              refreshRetirementCompleted state.retirementCompleted node refreshed } }
  | .appendEntries source destination batchEnd =>
      let sourceState := state.nodes source
      { enabled :=
          state.allocated source /\
            state.allocated destination /\
            sourceState.role = .leader /\
            Not (source = destination) /\
            (destination ∈ activeNodeUnion sourceState \/
              destination ∈ state.retirementCompleted source) /\
            sourceState.sentIndex destination <= batchEnd /\
            batchEnd <= sourceState.log.length /\
            ((messageEntries sourceState.log
              (sourceState.sentIndex destination) batchEnd).all fun entry =>
                entry.term == termAt sourceState.log batchEnd) = true /\
            (Not (sourceState.membershipState = .retiredCommitted) \/
              sourceState.sentIndex destination < batchEnd)
        next :=
          let request := makeAppendEntriesRequest state source destination batchEnd
          { state with
            nodes :=
              updateNode state.nodes source
                { sourceState with
                  sentIndex :=
                    updateIndex sourceState.sentIndex destination batchEnd }
            network := enqueue state.network (.appendEntriesRequest request) } }
  | .receive source destination =>
      let result := handleReceive? state source destination
      { enabled := state.allocated destination /\ result.isSome
        next := result.getD state }
  | .drop source destination occurrence =>
      let result := takeOccurrenceFrom source occurrence (state.network destination)
      { enabled := result.isSome
        next :=
          match result with
          | none => state
          | some (_, remaining) =>
              { state with network := updateQueue state.network destination remaining } }
  | .advanceCommitIndex node =>
      { enabled :=
          state.allocated node /\
            (state.nodes node).role = .leader /\
            (state.nodes node).commitIndex < highestCommittableIndex state node /\
            Not (terminalRetirementCommit state node)
        next := demoteRetiredCommitted (advanceCommitState state node) node }
  | .timeout node =>
      let nodeState := state.nodes node
      { enabled :=
          state.allocated node /\
            (nodeState.role = .follower \/
              nodeState.role = .preVoteCandidate \/
              nodeState.role = .candidate) /\
            ((node ∈ activeNodeUnion nodeState /\ campaignEligible node nodeState) \/
              node ∈ state.retirementCompleted node) /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            Not (state.preVoteStatus node = .enabled)
        next := becomeCandidateState state node }
  | .becomePreVoteCandidate node =>
      let nodeState := state.nodes node
      { enabled :=
          state.allocated node /\
            (nodeState.role = .follower \/
              nodeState.role = .preVoteCandidate \/
              nodeState.role = .candidate) /\
            ((node ∈ activeNodeUnion nodeState /\ campaignEligible node nodeState) \/
              node ∈ state.retirementCompleted node) /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            state.preVoteStatus node = .enabled
        next :=
          { state with
            nodes :=
              updateNode state.nodes node
                { nodeState with
                  role := .preVoteCandidate
                  preVotesGranted := {node} } } }
  | .becomeCandidate node =>
      let nodeState := state.nodes node
      { enabled :=
          state.allocated node /\
            nodeState.role = .preVoteCandidate /\
            ((node ∈ activeNodeUnion nodeState /\ campaignEligible node nodeState) \/
              node ∈ state.retirementCompleted node) /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            state.preVoteStatus node = .enabled /\
            hasPreVoteMajority state node
        next := becomeCandidateState state node }
  | .requestVote source destination =>
      { enabled :=
          state.allocated source /\
            state.allocated destination /\
            (state.nodes source).role = .candidate /\
            Not (source = destination) /\
            destination ∈ activeNodeUnion (state.nodes source)
        next :=
          let request := makeRequestVoteRequest state source destination
          { state with network := enqueue state.network (.requestVoteRequest request) } }
  | .requestPreVote source destination =>
      { enabled :=
          state.allocated source /\
            state.allocated destination /\
            (state.nodes source).role = .preVoteCandidate /\
            Not (source = destination) /\
            destination ∈ activeNodeUnion (state.nodes source)
        next :=
          let request := makeRequestPreVote state source destination
          { state with network := enqueue state.network (.requestPreVote request) } }
  | .checkQuorum node =>
      { enabled :=
          state.allocated node /\
            (state.nodes node).role = .leader /\
            hasOtherActiveReplica state node
        next := stepDownState state node }
  | .updateTerm source destination =>
      let result := newerMessage? state source destination
      { enabled := state.allocated destination /\ result.isSome
        next :=
          match result with
          | none => state
          | some selected =>
              let nodeState := state.nodes destination
              { state with
                nodes :=
                  updateNode state.nodes destination
                    { nodeState with
                      role :=
                        if nodeState.role = .follower then
                          .follower
                        else
                          .follower
                      currentTerm := selected.term
                      votedFor := none
                      isNewFollower := true
                      preVotesGranted := ∅ } } }
  | .becomeLeader node =>
      let nodeState := state.nodes node
      let log := nodeState.log.take (maxCommittableIndex nodeState.log)
      let truncated := { nodeState with log }
      { enabled :=
          state.allocated node /\
            nodeState.role = .candidate /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            hasElectionMajority state node /\
            Not (
              (refreshRetirementState node truncated).membershipState =
                .retiredCommitted)
        next :=
          let nextNode :=
            refreshRetirementState node
              { truncated with
                role := .leader
                sentIndex := fun _ => log.length
                matchIndex := fun _ => 0 }
          { state with
            nodes := updateNode state.nodes node nextNode
            retirementCompleted :=
              refreshRetirementCompleted state.retirementCompleted node nextNode } }
  | .proposeVote source destination =>
      { enabled :=
          state.allocated source /\
            state.allocated destination /\
            (state.nodes source).role = .leader /\
            plausibleSuccessor state source destination
        next :=
          let request := makeProposeVoteRequest state source destination
          { state with network := enqueue state.network (.proposeVoteRequest request) } }
  | .advanceCommitIndexAndProposeVote source destination =>
      { enabled :=
          state.allocated source /\
            state.allocated destination /\
            (state.nodes source).role = .leader /\
            (state.nodes source).commitIndex < highestCommittableIndex state source /\
            terminalRetirementCommit state source /\
            plausibleSuccessor state source destination
        next :=
          let advanced :=
            demoteRetiredCommitted (advanceCommitState state source) source
          let request := makeProposeVoteRequest state source destination
          { advanced with
            network := enqueue advanced.network (.proposeVoteRequest request) } }

def Enabled (state : State Node TxId) (action : Action Node TxId) : Prop :=
  (definition state action).enabled

-- Unfold only the guard projection to derive its decision procedure.
instance (state : State Node TxId) (action : Action Node TxId) :
    Decidable (Enabled state action) := by
  cases action <;> dsimp [Enabled, definition] <;> infer_instance

def next (state : State Node TxId) (action : Action Node TxId) : State Node TxId :=
  (definition state action).next

def system : ExecutableTransitionSystem where
  State := State Node TxId
  Action := Action Node TxId
  initial := initialState
  Enabled
  enabledDecidable := fun _ _ => inferInstance
  next

/-- Apply actions in order, returning `none` when one of them is disabled. -/
def runActions
    (state : State Node TxId) :
    List (Action Node TxId) -> Option (State Node TxId)
  | [] => some state
  | action :: actions => do
      let nextState <- system.applyAction state action
      runActions nextState actions

/-- States reachable from `initialState` through enabled actions. -/
abbrev Reachable :=
  (system (Node := Node) (TxId := TxId)).Reachable

end CCFRaft.Proofs.Abstract.Model
