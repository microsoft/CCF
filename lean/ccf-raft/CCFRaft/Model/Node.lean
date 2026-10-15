module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model.ClusterConfig
public import CCFRaft.Model.Messages
public import CCFRaft.Model.NodeState
public import CCF.Capabilities
public import Mathlib.Data.Finset.Sort
public import Mathlib.Order.Prod.Lex.Basic

@[expose] public section

/-!
# Local node steps

How one node reacts to an event, over the state in `NodeState.lean`. `step` is
the entry point: `act` handles an `Input`, and `receive` handles a `Message`
after `observeTerm` applies CCF's message-specific term rules.

A step may send messages through `caps`. A failed `guard` means the event is
disabled: the step has no effect and a received message stays in flight.
-/

namespace CCFRaft.Model.Node

open CCF (Capabilities Effect)

abbrev Caps (Node TxId : Type) := Capabilities Node (Message Node TxId) Notification

abbrev NodeEffect (Node TxId : Type) := Effect Node (Message Node TxId) Notification

variable {Node TxId : Type}

inductive TimeoutKind where
  | election
  | checkQuorum
deriving DecidableEq

inductive Input (Node TxId : Type) where
  | append (entries : List (EntryContent Node TxId))
  /-- Starts at the peer's send frontier -/
  | sendEntries (destination : Node) (endIndex : Nat)
  | timeout (kind : TimeoutKind)
  | nominateSuccessor
deriving DecidableEq

inductive Event (Node TxId : Type) where
  | internal (input : Input Node TxId)
  | receive (source : Node) (message : Message Node TxId)

variable [DecidableEq Node] [DecidableEq TxId]

/-! ## Leader state -/

/--
Approximates `all_other_nodes`; unlike CCF, peers lost on rollback are not retained.
-/
def eligiblePeers (config : InitialConfig Node) (state : NodeState Node TxId)
    (self : Node)
    : Finset Node :=
  (state.activeMembers config ∪ state.retirementCompletedNodes config).erase self

/-- Maximize replication progress, latest active membership, then node ID. -/
def findSuccessor [LinearOrder Node] (config : InitialConfig Node)
    (state : NodeState Node TxId) (self : Node)
    : Option Node :=
  let configurations := state.activeConfigurations config
  let rank node :=
    toLex (state.matchIndex node, toLex (latestMembershipIndex configurations node, node))
  let peers := (eligiblePeers config state self).sort
  peers.foldl
    (fun best candidate =>
      match best with
      | none => some candidate
      | some selected =>
          if rank selected < rank candidate then
            some candidate
          else
            best)
    none

def nominateSuccessor [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (state : NodeState Node TxId) (self : Node)
    : NodeEffect Node TxId Unit := do
  if let some successor := findSuccessor config state self then
    caps.send (.proposeVoteRequest state.currentTerm) successor

abbrev canStartElection (config : InitialConfig Node)
    (state : NodeState Node TxId) (self : Node)
    : Prop :=
  (state.role = .follower \/ state.role = .preVoteCandidate \/ state.role = .candidate)
  /\ (self ∈ configurationMembers (state.signedActiveConfigurations config)
      \/ self ∈ state.retirementCompletedNodes config)
  /\ Not (state.isRetiredCommitted config self)

/--
The highest current-term signature above the leader's commit index which a
majority of every active configuration has reached, or zero when there is none.
-/
def highestCommittableIndex (config : InitialConfig Node)
    (state : NodeState Node TxId) (self : Node)
    : Nat :=
  let replicatedBy index :=
    (state.activeMembers config).filter
      fun node => node = self \/ state.matchIndex node >= index
  (List.range (state.log.length + 1)).foldl
    (fun highest index =>
      if index > state.commitIndex
          /\ isSignatureAt state.log index = true
          /\ termAt state.log index = state.currentTerm
          /\ hasQuorum (state.activeConfigurations config) (replicatedBy index) then
        max highest index
      else
        highest)
    0

/--
Record a chosen commit index, preserving the first frontier covering this node's
retirement record.
-/
def NodeState.recordCommit (node : Node) (state : NodeState Node TxId) (commitIndex : Nat)
    : NodeState Node TxId :=
  {
    state with
      commitIndex
      retiredCommittedIndex :=
        state.retiredCommittedIndex.orElse
          fun _ =>
            if node ∈ retiredCommittedNodes (state.log.take commitIndex) then
              some commitIndex
            else
              none
  }

/--
Retirement nominates using the precommit peer and configuration view, before
discarding old configurations and clearing the outgoing leader's role.
-/
def advanceCommit [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (state : NodeState Node TxId) (self : Node)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let commitIndex := highestCommittableIndex config state self
  if commitIndex <= state.commitIndex then
    return state
  else
    let preCommitState := state
    let state := state.recordCommit self commitIndex
    if state.isRetiredCommitted config self then
      if preCommitState.role = .leader then
        nominateSuccessor config caps preCommitState self
      return { state with role := .none, leaderKnown := false }
    else
      return state

/-! ## Outgoing messages -/

def makeAppendEntriesRequest (state : NodeState Node TxId) (destination : Node)
    (endIndex : Nat)
    : AppendEntriesRequest Node TxId :=
  let previousIndex := state.sentIndex destination
  {
    term := state.currentTerm
    prevLogIndex := previousIndex
    prevLogTerm := termAt state.log previousIndex
    entries := messageEntries state.log previousIndex endIndex
    leaderCommit := state.commitIndex
  }

def makeRequestVoteRequest (state : NodeState Node TxId) : RequestVoteRequest where
  term := state.currentTerm
  lastCommittableTerm := lastCommittableTerm state
  lastCommittableIndex := lastCommittableIndex state

/-! ## Appending entries -/

/--
CCF runs hooks before appending the entry: new-peer heartbeats use the
pre-append log length.
-/
def appendEntry [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (self : Node) (state : NodeState Node TxId)
    (content : EntryContent Node TxId)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  if content.isSignature then
    guard (Not (state.log = []))
  let metadata := content.metadata
  if metadata.retiredCommitted.Nonempty then
    guard
      (metadata.retiredCommitted
        ⊆ state.retirementCompletedNodes config \ retiredCommittedNodes state.log)
  let state <- do
    match metadata.configuration with
    | none => pure state
    | some nodes => do
        let previousConfiguration :=
          latestConfigurationMembers (configurationHistory config state.log)
        guard (nodes.Nonempty /\ Not (nodes = previousConfiguration))
        let addedPeers := (nodes \ eligiblePeers config state self).erase self
        let state : NodeState Node TxId :=
          {
            state with
              sentIndex :=
                fun peer =>
                  if peer ∈ addedPeers then state.log.length else state.sentIndex peer
          }
        for peer in addedPeers.sort do
          caps.send
            (.appendEntriesRequest (makeAppendEntriesRequest state peer state.log.length))
            peer
        pure state
  return { state with log := state.log ++ [{ term := state.currentTerm, content }] }

def appendBatch [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (self : Node) (state : NodeState Node TxId)
    (entries : List (EntryContent Node TxId))
    : NodeEffect Node TxId (NodeState Node TxId) := do
  guard
    (state.role = .leader
      /\ Not (state.isRetiredCommitted config self)
      /\ Not (entries = []))
  let state <- entries.foldlM (appendEntry config caps self) state
  advanceCommit config caps state self

def sendEntries (config : InitialConfig Node) (caps : Caps Node TxId) (self : Node)
    (state : NodeState Node TxId) (destination : Node) (endIndex : Nat)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let previousIndex := state.sentIndex destination
  guard
    (state.role = .leader
      /\ destination ∈ eligiblePeers config state self
      /\ previousIndex <= endIndex
      /\ endIndex <= state.log.length
      /\ ((messageEntries state.log previousIndex endIndex).all
            fun entry =>
              entry.term == termAt state.log endIndex)
          = true
      /\ (Not (state.isRetiredCommitted config self) \/ previousIndex < endIndex))
  caps.send
    (.appendEntriesRequest (makeAppendEntriesRequest state destination endIndex))
    destination
  return { state with sentIndex := Function.update state.sentIndex destination endIndex }

/-! ## Handling AppendEntries -/

/-- The highest local index whose term could match a rejected request. -/
def findHighestPossibleMatch (log : List (Entry Node TxId)) (index term : Nat) : Nat :=
  (List.range (min index log.length + 1)).foldl
    (fun best candidate =>
      if candidate > 0 /\ termAt log candidate <= term then
        max best candidate
      else
        best)
    0

abbrev appendEntryMatchesLog (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Prop :=
  request.prevLogIndex = 0
  \/ (request.prevLogIndex <= state.log.length
      /\ termAt state.log request.prevLogIndex = request.prevLogTerm)

abbrev hasTermConflict (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Prop :=
  ((state.log.drop request.prevLogIndex).zip request.entries).any
    fun (existing, incoming) => existing.term != incoming.term

def handleAppendEntiresFromLeader
    (self : Node)
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : NodeState Node TxId × AppendEntriesResponse :=
  let commitLimit :=
    min request.leaderCommit (request.prevLogIndex + request.entries.length)
  let commitIfPossible (state : NodeState Node TxId) :=
    state.recordCommit self
      (max state.commitIndex (maxCommittableIndexUpTo state.log commitLimit))
  let state :=
    (request.entries.drop (state.log.length - request.prevLogIndex)).foldl
      (fun state entry =>
        let state := { state with log := state.log ++ [entry] }
        if entry.content.isSignature then commitIfPossible state else state)
      state
  let state := commitIfPossible state
  (
    state,
    {
      term := state.currentTerm
      success := true
      lastLogIndex := request.prevLogIndex + request.entries.length
    }
  )

def handleAppendEntriesRequest
    (caps : Caps Node TxId)
    (self source : Node)
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let state :=
    if request.term = state.currentTerm
        /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
      { state with role := .follower, isNewFollower := true }
    else
      state
  if request.term < state.currentTerm \/ Not (appendEntryMatchesLog state request) then
    if request.term < state.currentTerm \/ termAt state.log request.prevLogIndex = 0 then
      caps.send
        (.appendEntriesResponse
          {
            term := state.currentTerm, success := false, lastLogIndex := state.log.length
          })
        source
    else
      let lastLogIndex :=
        findHighestPossibleMatch state.log request.prevLogIndex request.prevLogTerm
      caps.send
        (.appendEntriesResponse
          { term := termAt state.log lastLogIndex, success := false, lastLogIndex })
        source
    return state
  else
    let state := { state with leaderKnown := true }
    let conflict := hasTermConflict state request
    if request.prevLogIndex < state.commitIndex \/ (conflict /\ !state.isNewFollower) then
      return state
    else
      let state :=
        if conflict then
          {
            state with
              log := state.log.take request.prevLogIndex, isNewFollower := false
          }
        else
          state
      let (state, response) := handleAppendEntiresFromLeader self state request
      caps.send (.appendEntriesResponse response) source
      return state

def handleAppendEntriesResponse [LinearOrder Node]
    (config : InitialConfig Node)
    (caps : Caps Node TxId)
    (self : Node)
    (state : NodeState Node TxId)
    (source : Node)
    (response : AppendEntriesResponse)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  if state.role != .leader then
    return state
  else if response.success then
    if response.term = state.currentTerm then
      let state :=
        {
          state with
            matchIndex :=
              Function.update state.matchIndex source
                (max (state.matchIndex source) response.lastLogIndex)
        }
      advanceCommit config caps state self
    else
      return state
  else
    -- A mismatch NACK carries a log term, so older-term retry hints still apply.
    let retryIndex :=
      findHighestPossibleMatch state.log response.lastLogIndex response.term
    return {
      state with
        sentIndex :=
          Function.update state.sentIndex source
            (max (min retryIndex (state.sentIndex source)) (state.matchIndex source))
    }

/-! ## Handling elections -/

abbrev voteLogUpToDate (state : NodeState Node TxId) (request : RequestVoteRequest)
    : Prop :=
  request.lastCommittableTerm > maxCommittableTerm state.log
  \/ (request.lastCommittableTerm = maxCommittableTerm state.log
      /\ request.lastCommittableIndex >= maxCommittableIndex state.log)

def handleRequestVoteRequest
    (caps : Caps Node TxId)
    (state : NodeState Node TxId)
    (source : Node)
    (request : RequestVoteRequest)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let voteGranted : Bool :=
    decide
      (request.term = state.currentTerm
        /\ voteLogUpToDate state request
        /\ !state.leaderKnown
        /\ (state.votedFor = none \/ state.votedFor = some source))
  caps.send (.requestVoteResponse { term := state.currentTerm, voteGranted }) source
  return if voteGranted then { state with votedFor := some source } else state

def handleRequestPreVote
    (caps : Caps Node TxId)
    (state : NodeState Node TxId)
    (source : Node)
    (request : RequestVoteRequest)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let voteGranted :=
    decide (request.term = state.currentTerm /\ voteLogUpToDate state request)
  caps.send (.requestPreVoteResponse { term := state.currentTerm, voteGranted }) source
  return state

/--
CCF keeps the unsigned suffix at startup.
-/
def leaderState (state : NodeState Node TxId) : NodeState Node TxId :=
  let log :=
    if state.commitIndex > 0 then
      state.log.take (lastCommittableIndex state)
    else
      state.log
  {
    state with
      role := .leader
      log
      leaderKnown := true
      sentIndex := fun _ => log.length
      matchIndex := fun _ => 0
  }

def becomeLeader [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (self : Node) (state : NodeState Node TxId)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let state := leaderState state
  let state <- advanceCommit config caps state self
  for peer in (eligiblePeers config state self).sort do
    caps.send
      (.appendEntriesRequest (makeAppendEntriesRequest state peer state.log.length))
      peer
  return state

def electIfQuorum [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (self : Node) (state : NodeState Node TxId)
    : NodeEffect Node TxId (NodeState Node TxId) :=
  if state.role = .candidate
      /\ hasQuorum (state.activeConfigurations config) state.votesGranted
      /\ Not (state.isRetiredCommitted config self) then
    becomeLeader config caps self state
  else
    pure state

def broadcastToOthers [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (self : Node) (state : NodeState Node TxId)
    (message : Message Node TxId)
    : NodeEffect Node TxId Unit := do
  for destination in ((state.activeMembers config).erase self).sort do
    caps.send message destination

/--
The self-vote can promote to leader before the vote-request loop.
-/
def becomeCandidate [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (state : NodeState Node TxId) (self : Node)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let state : NodeState Node TxId :=
    {
      state with
        role := .candidate
        currentTerm := state.currentTerm + 1
        votedFor := some self
        leaderKnown := false
        votesGranted := {self}
        preVotesGranted := ∅
    }
  let candidateState := state
  let state <- electIfQuorum config caps self state
  broadcastToOthers config caps self candidateState
    (.requestVoteRequest (makeRequestVoteRequest candidateState))
  return state

/--
The self-vote can synchronously start a regular election.
-/
def becomePreVoteCandidate [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (state : NodeState Node TxId) (self : Node)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let state : NodeState Node TxId :=
    {
      state with
        role := .preVoteCandidate, leaderKnown := false, preVotesGranted := {self}
    }
  if hasQuorum (state.activeConfigurations config) state.preVotesGranted then
    becomeCandidate config caps state self
  else
    broadcastToOthers config caps self state
      (.requestPreVote (makeRequestVoteRequest state))
    return state

def startElection [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (state : NodeState Node TxId)
    (self : Node)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  guard (canStartElection config state self)
  if config.preVoteStatus self = .enabled then
    becomePreVoteCandidate config caps state self
  else
    becomeCandidate config caps state self

def handleRequestVoteResponse [LinearOrder Node]
    (config : InitialConfig Node)
    (caps : Caps Node TxId)
    (self : Node)
    (state : NodeState Node TxId)
    (source : Node)
    (response : RequestVoteResponse)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  if state.role = .candidate
      /\ response.term = state.currentTerm
      /\ response.voteGranted then
    let state := { state with votesGranted := insert source state.votesGranted }
    electIfQuorum config caps self state
  else
    return state

def handleRequestPreVoteResponse [LinearOrder Node]
    (config : InitialConfig Node)
    (caps : Caps Node TxId)
    (self : Node)
    (state : NodeState Node TxId)
    (source : Node)
    (response : RequestVoteResponse)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  if state.role = .preVoteCandidate
      /\ response.term = state.currentTerm
      /\ response.voteGranted then
    let state := { state with preVotesGranted := insert source state.preVotesGranted }
    if hasQuorum (state.activeConfigurations config) state.preVotesGranted then
      becomeCandidate config caps state self
    else
      return state
  else
    return state

def checkQuorum (config : InitialConfig Node) (state : NodeState Node TxId) (self : Node)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  guard (state.role = .leader /\ ((state.activeMembers config).erase self).Nonempty)
  return { state with role := .follower, leaderKnown := false }

def handleProposeVoteRequest [LinearOrder Node]
    (config : InitialConfig Node)
    (caps : Caps Node TxId)
    (state : NodeState Node TxId)
    (self : Node)
    (term : Nat)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  if term = state.currentTerm /\ canStartElection config state self then
    becomeCandidate config caps state self
  else
    return state

def updateTerm (state : NodeState Node TxId) (term : Nat) : NodeState Node TxId :=
  if state.currentTerm < term then
    {
      state with
        role := .follower
        currentTerm := term
        votedFor := none
        leaderKnown := false
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

def receive [LinearOrder Node]
    (config : InitialConfig Node)
    (caps : Caps Node TxId)
    (self source : Node)
    (state : NodeState Node TxId)
    (message : Message Node TxId)
    : NodeEffect Node TxId (NodeState Node TxId) :=
  let state := observeTerm state message
  match message with
  | .appendEntriesRequest request =>
      handleAppendEntriesRequest caps self source state request
  | .appendEntriesResponse response =>
      handleAppendEntriesResponse config caps self state source response
  | .requestVoteRequest request =>
      handleRequestVoteRequest caps state source request
  | .requestVoteResponse response =>
      handleRequestVoteResponse config caps self state source response
  | .requestPreVote request =>
      handleRequestPreVote caps state source request
  | .requestPreVoteResponse response =>
      handleRequestPreVoteResponse config caps self state source response
  | .proposeVoteRequest term =>
      handleProposeVoteRequest config caps state self term

def act [LinearOrder Node] (config : InitialConfig Node) (caps : Caps Node TxId)
    (self : Node) (state : NodeState Node TxId)
    : Input Node TxId -> NodeEffect Node TxId (NodeState Node TxId)
  | .append entries => appendBatch config caps self state entries
  | .sendEntries destination endIndex =>
      sendEntries config caps self state destination endIndex
  | .timeout .election => startElection config caps state self
  | .timeout .checkQuorum => checkQuorum config state self
  | .nominateSuccessor => do
      guard (state.role = .leader)
      nominateSuccessor config caps state self
      return state

def step [LinearOrder Node] (config : InitialConfig Node) (caps : Caps Node TxId)
    (self : Node) (state : NodeState Node TxId)
    : Event Node TxId -> NodeEffect Node TxId (NodeState Node TxId)
  | .internal input => act config caps self state input
  | .receive source message => receive config caps self source state message

end CCFRaft.Model.Node
