module

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

abbrev Caps := Capabilities NodeID Message Notification

abbrev NodeEffect := Effect NodeID Message Notification

inductive TimeoutKind where
  | election
  | checkQuorum
deriving DecidableEq

inductive Input where
  | append (entries : List EntryContent)
  /-- Starts at the peer's send frontier -/
  | sendEntries (destination : NodeID) (endIndex : Nat)
  | timeout (kind : TimeoutKind)
  | nominateSuccessor
deriving DecidableEq

inductive Event where
  | internal (input : Input)
  | receive (source : NodeID) (message : Message)

/-! ## Primary state -/

/--
Approximates `all_other_nodes`; unlike CCF, peers lost on rollback are not retained.
-/
def eligiblePeers (state : NodeState) (self : NodeID) : Finset NodeID :=
  (state.activeMembers ∪ state.retirementCompletedNodes).erase self

/-- Maximize replication progress, latest active membership, then node ID. -/
def findSuccessor (state : NodeState) (self : NodeID) : Option NodeID :=
  let configurations := state.activeConfigurations
  let rank node :=
    toLex (state.matchIndex node, toLex (latestMembershipIndex configurations node, node))
  let peers := (eligiblePeers state self).sort
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

def nominateSuccessor (caps : Caps) (state : NodeState) (self : NodeID)
    : NodeEffect NodeState := do
  guard (state.role = .primary)
  if let some successor := findSuccessor state self then
    caps.send (.proposeRequestVoteRequest state.currentTerm) successor
  return state

abbrev canStartElection (state : NodeState) (self : NodeID) : Prop :=
  (state.role = .follower \/ state.role = .preVoteCandidate \/ state.role = .candidate)
  /\ (self ∈ configurationMembers state.signedActiveConfigurations
      \/ self ∈ state.retirementCompletedNodes)
  /\ Not (state.isRetiredCommitted self)

/--
The highest current-term signature above the primary's commit index which a
majority of every active configuration at or before that signature has reached,
or zero when there is none.
-/
def highestCommittableIndex (state : NodeState) (self : NodeID) : Nat :=
  let replicatedBy index :=
    state.activeMembers.filter fun node => node = self \/ state.matchIndex node >= index
  (List.range (state.log.length + 1)).foldl
    (fun highest index =>
      if index > state.commitIndex
          /\ isSignatureAt state.log index = true
          /\ termAt state.log index = state.currentTerm
          /\ hasQuorum
              (state.activeConfigurations.filter
                fun configuration => configuration.index <= index)
              (replicatedBy index) then
        max highest index
      else
        highest)
    0

/--
Record a chosen commit index, latching the original transaction index once this
node's retirement confirmation commits and clearing its role and primary knowledge.
-/
def NodeState.recordCommit (node : NodeID) (state : NodeState) (commitIndex : Nat)
    : NodeState :=
  let previouslyConfirmed := state.retiredCommittedIndex.isSome
  let state :=
    {
      state with
        commitIndex
        retiredCommittedIndex :=
          state.retiredCommittedIndex.orElse
            fun _ =>
              firstLogIndexAfter (state.log.take commitIndex) 0
                fun content => decide (node ∈ content.metadata.retirementConfirmations)
    }
  if !previouslyConfirmed /\ state.isRetiredCommitted node then
    { state with role := .none, primaryKnown := false }
  else
    state

/--
Retirement nominates using the precommit peer and configuration view, before
discarding old configurations and clearing the outgoing primary's role.
-/
def advanceCommit (caps : Caps) (state : NodeState) (self : NodeID)
    : NodeEffect NodeState := do
  let commitIndex := highestCommittableIndex state self
  if commitIndex <= state.commitIndex then
    return state
  else
    let preCommitState := state
    let state := state.recordCommit self commitIndex
    if state.isRetiredCommitted self then
      if preCommitState.role = .primary then
        let _ ← nominateSuccessor caps preCommitState self
      return state
    else
      return state

/-! ## Outgoing messages -/

def makeAppendEntriesRequest (state : NodeState) (destination : NodeID) (endIndex : Nat)
    : AppendEntriesRequest :=
  let previousIndex := state.sentIndex destination
  {
    term := state.currentTerm
    prevLogIndex := previousIndex
    prevLogTerm := termAt state.log previousIndex
    entries := messageEntries state.log previousIndex endIndex
    primaryCommit := state.commitIndex
  }

def makeRequestVoteRequest (state : NodeState) : RequestVoteRequest where
  term := state.currentTerm
  lastCommittableTerm := lastCommittableTerm state
  lastCommittableIndex := lastCommittableIndex state

/-! ## Appending entries -/

/--
CCF runs hooks before appending the entry: new-peer heartbeats use the
pre-append log length.
-/
def appendEntry (caps : Caps) (self : NodeID) (state : NodeState) (content : EntryContent)
    : NodeEffect NodeState := do
  if content.isSignature then
    guard (Not (state.log = []))
  let metadata := content.metadata
  if metadata.retirementConfirmations.Nonempty then
    guard
      (metadata.retirementConfirmations
        ⊆ state.retirementCompletedNodes \ retiredCommittedNodes state.log)
  let state <- do
    match metadata.configuration with
    | none => pure state
    | some nodes => do
        let history := configurationHistory state.log
        let previousConfiguration := latestConfigurationMembers history
        guard (nodes.Nonempty /\ Not (nodes = previousConfiguration))
        -- CCF deletes, and so lets rejoin, only nodes whose `retired_committed`
        -- status is globally committed (`delete_retired_committed_node`).
        let rejoining := (nodes ∩ configurationMembers history) \ previousConfiguration
        guard
          (rejoining
            ⊆ retiredCommittedNodes state.committedLog ∩ retiredCommittedNodes state.log)
        let addedPeers := (nodes \ eligiblePeers state self).erase self
        let state : NodeState :=
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

def appendBatch (caps : Caps) (self : NodeID) (state : NodeState)
    (entries : List EntryContent)
    : NodeEffect NodeState := do
  guard
    (state.role = .primary /\ Not (state.isRetiredCommitted self) /\ Not (entries = []))
  let state <- entries.foldlM (appendEntry caps self) state
  advanceCommit caps state self

def sendEntries (caps : Caps) (self : NodeID)
    (state : NodeState) (destination : NodeID) (endIndex : Nat)
    : NodeEffect NodeState := do
  let previousIndex := state.sentIndex destination
  guard
    (state.role = .primary
      /\ destination ∈ eligiblePeers state self
      /\ previousIndex <= endIndex
      /\ endIndex <= state.log.length
      /\ ((messageEntries state.log previousIndex endIndex).all
            fun entry =>
              entry.term == termAt state.log endIndex)
          = true
      /\ (Not (state.isRetiredCommitted self) \/ previousIndex + 1 < endIndex))
  caps.send
    (.appendEntriesRequest (makeAppendEntriesRequest state destination endIndex))
    destination
  return { state with sentIndex := Function.update state.sentIndex destination endIndex }

/-! ## Handling AppendEntries -/

/-- The highest local index whose term could match a rejected request. -/
def findHighestPossibleMatch (log : List Entry) (index term : Nat) : Nat :=
  (List.range (min index log.length + 1)).foldl
    (fun best candidate =>
      if candidate > 0 /\ termAt log candidate <= term then
        max best candidate
      else
        best)
    0

abbrev appendEntryMatchesLog (state : NodeState) (request : AppendEntriesRequest)
    : Prop :=
  request.prevLogIndex <= state.log.length
  /\ termAt state.log request.prevLogIndex = request.prevLogTerm

/-- One-based index of the first overlapping entry with a different term. -/
def firstTermConflictIndex (state : NodeState) (request : AppendEntriesRequest)
    : Option Nat :=
  let overlapping := (state.log.drop request.prevLogIndex).zip request.entries
  let conflict :=
    (overlapping.zipIdx (request.prevLogIndex + 1)).find?
      fun ((existing, incoming), _) => existing.term != incoming.term
  conflict.map Prod.snd

def handleAppendEntiresFromPrimary
    (self : NodeID)
    (state : NodeState)
    (request : AppendEntriesRequest)
    : NodeState × AppendEntriesResponse :=
  let commitLimit :=
    min request.primaryCommit (request.prevLogIndex + request.entries.length)
  let commitIfPossible (state : NodeState) :=
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

/-- Reset election bookkeeping like C++'s `become_aware_of_new_term`, even in the same term. -/
def becomeAwareOfNewTerm (state : NodeState) (term : Nat) : NodeState :=
  {
    state with
      role := .follower
      currentTerm := term
      votedFor := if state.currentTerm = term then state.votedFor else none
      primaryKnown := false
      isNewFollower := true
      votesGranted := ∅
      preVotesGranted := ∅
  }

def handleAppendEntriesRequest
    (caps : Caps)
    (self source : NodeID)
    (state : NodeState)
    (request : AppendEntriesRequest)
    : NodeEffect NodeState := do
  let state :=
    if request.term = state.currentTerm
        /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
      becomeAwareOfNewTerm state request.term
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
    let state := { state with primaryKnown := true }
    let conflictIndex := firstTermConflictIndex state request
    if request.prevLogIndex < state.commitIndex
        \/ (conflictIndex.isSome /\ !state.isNewFollower) then
      return state
    else
      let state :=
        match conflictIndex with
        | none => state
        | some index =>
            { state with log := state.log.take (index - 1), isNewFollower := false }
      let (state, response) := handleAppendEntiresFromPrimary self state request
      caps.send (.appendEntriesResponse response) source
      return state

def handleAppendEntriesResponse
    (caps : Caps)
    (self : NodeID)
    (state : NodeState)
    (source : NodeID)
    (response : AppendEntriesResponse)
    : NodeEffect NodeState := do
  if state.role != .primary then
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
      advanceCommit caps state self
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

abbrev voteLogUpToDate (state : NodeState) (request : RequestVoteRequest) : Prop :=
  request.lastCommittableTerm > maxCommittableTerm state.log
  \/ (request.lastCommittableTerm = maxCommittableTerm state.log
      /\ request.lastCommittableIndex >= maxCommittableIndex state.log)

def handleRequestVoteRequest
    (caps : Caps)
    (state : NodeState)
    (source : NodeID)
    (request : RequestVoteRequest)
    : NodeEffect NodeState := do
  let voteGranted : Bool :=
    decide
      (request.term = state.currentTerm
        /\ voteLogUpToDate state request
        /\ !state.primaryKnown
        /\ (state.votedFor = none \/ state.votedFor = some source))
  caps.send (.requestVoteResponse { term := state.currentTerm, voteGranted }) source
  return if voteGranted then { state with votedFor := some source } else state

def handleRequestPreVoteRequest
    (caps : Caps)
    (state : NodeState)
    (source : NodeID)
    (request : RequestVoteRequest)
    : NodeEffect NodeState := do
  let voteGranted :=
    decide (request.term = state.currentTerm /\ voteLogUpToDate state request)
  caps.send (.requestPreVoteResponse { term := state.currentTerm, voteGranted }) source
  return state

/--
CCF keeps the unsigned suffix at startup.
-/
def primaryState (state : NodeState) : NodeState :=
  let log :=
    if state.commitIndex > 0 then
      state.log.take (lastCommittableIndex state)
    else
      state.log
  {
    state with
      role := .primary
      log
      primaryKnown := true
      sentIndex := fun _ => log.length
      matchIndex := fun _ => 0
  }

def becomePrimary (caps : Caps) (self : NodeID) (state : NodeState)
    : NodeEffect NodeState := do
  let state := primaryState state
  let state <- advanceCommit caps state self
  for peer in (eligiblePeers state self).sort do
    caps.send
      (.appendEntriesRequest (makeAppendEntriesRequest state peer state.log.length))
      peer
  return state

def electIfQuorum (caps : Caps) (self : NodeID) (state : NodeState)
    : NodeEffect NodeState :=
  if state.role = .candidate
      /\ hasQuorum state.activeConfigurations state.votesGranted
      /\ Not (state.isRetiredCommitted self) then
    becomePrimary caps self state
  else
    pure state

def broadcastToOthers (caps : Caps) (self : NodeID) (state : NodeState)
    (message : Message)
    : NodeEffect Unit := do
  for destination in (state.activeMembers.erase self).sort do
    caps.send message destination

/--
The self-vote can promote to primary before the vote-request loop.
-/
def becomeCandidate (caps : Caps) (state : NodeState) (self : NodeID)
    : NodeEffect NodeState := do
  let state : NodeState :=
    {
      state with
        role := .candidate
        currentTerm := state.currentTerm + 1
        votedFor := some self
        primaryKnown := false
        votesGranted := {self}
        preVotesGranted := ∅
    }
  let candidateState := state
  let state <- electIfQuorum caps self state
  broadcastToOthers caps self candidateState
    (.requestVoteRequest (makeRequestVoteRequest candidateState))
  return state

/--
The self-vote can synchronously start a regular election.
-/
def becomePreVoteCandidate (caps : Caps) (state : NodeState) (self : NodeID)
    : NodeEffect NodeState := do
  let state : NodeState :=
    {
      state with
        role := .preVoteCandidate, primaryKnown := false, preVotesGranted := {self}
    }
  if hasQuorum state.activeConfigurations state.preVotesGranted then
    becomeCandidate caps state self
  else
    broadcastToOthers caps self state
      (.requestPreVoteRequest (makeRequestVoteRequest state))
    return state

def startElection (caps : Caps) (state : NodeState) (self : NodeID)
    : NodeEffect NodeState := do
  guard (canStartElection state self)
  becomePreVoteCandidate caps state self

def handleRequestVoteResponse
    (caps : Caps)
    (self : NodeID)
    (state : NodeState)
    (source : NodeID)
    (response : RequestVoteResponse)
    : NodeEffect NodeState := do
  if state.role = .candidate
      /\ response.term = state.currentTerm
      /\ response.voteGranted then
    let state := { state with votesGranted := insert source state.votesGranted }
    electIfQuorum caps self state
  else
    return state

def handleRequestPreVoteResponse
    (caps : Caps)
    (self : NodeID)
    (state : NodeState)
    (source : NodeID)
    (response : RequestVoteResponse)
    : NodeEffect NodeState := do
  if state.role = .preVoteCandidate
      /\ response.term = state.currentTerm
      /\ response.voteGranted then
    let state := { state with preVotesGranted := insert source state.preVotesGranted }
    if hasQuorum state.activeConfigurations state.preVotesGranted then
      becomeCandidate caps state self
    else
      return state
  else
    return state

def checkQuorum (state : NodeState) (self : NodeID) : NodeEffect NodeState := do
  guard (state.role = .primary /\ (state.activeMembers.erase self).Nonempty)
  return { state with role := .follower, primaryKnown := false }

def handleProposeRequestVoteRequest
    (caps : Caps)
    (state : NodeState)
    (self : NodeID)
    (term : Nat)
    : NodeEffect NodeState := do
  if term = state.currentTerm /\ canStartElection state self then
    becomeCandidate caps state self
  else
    return state

def updateTerm (state : NodeState) (term : Nat) : NodeState :=
  if state.currentTerm < term then
    becomeAwareOfNewTerm state term
  else
    state

/--
Adopt a newer term carried by a message before handling it. Vote proposals
never advance a term, and only a primary reads the term of an AppendEntries
response.
-/
def observeTerm (state : NodeState) : Message -> NodeState
  | .proposeRequestVoteRequest _ => state
  | .appendEntriesResponse response =>
      if state.role = .primary then updateTerm state response.term else state
  | message => updateTerm state message.term

/-! ## The step -/

def receive (caps : Caps) (self source : NodeID) (state : NodeState) (message : Message)
    : NodeEffect NodeState :=
  let requiresKnownPeer : Bool :=
    match message with
    | .appendEntriesResponse _ | .requestVoteResponse _ | .requestPreVoteResponse _ =>
        true
    | _ => false
  if requiresKnownPeer /\ source ∉ eligiblePeers state self then
    pure state
  else
    let state := observeTerm state message
    match message with
    | .appendEntriesRequest request =>
        handleAppendEntriesRequest caps self source state request
    | .appendEntriesResponse response =>
        handleAppendEntriesResponse caps self state source response
    | .requestVoteRequest request =>
        handleRequestVoteRequest caps state source request
    | .requestVoteResponse response =>
        handleRequestVoteResponse caps self state source response
    | .requestPreVoteRequest request =>
        handleRequestPreVoteRequest caps state source request
    | .requestPreVoteResponse response =>
        handleRequestPreVoteResponse caps self state source response
    | .proposeRequestVoteRequest term =>
        handleProposeRequestVoteRequest caps state self term

def act (caps : Caps) (self : NodeID) (state : NodeState) : Input -> NodeEffect NodeState
  | .append entries => appendBatch caps self state entries
  | .sendEntries destination endIndex =>
      sendEntries caps self state destination endIndex
  | .timeout .election => startElection caps state self
  | .timeout .checkQuorum => checkQuorum state self
  | .nominateSuccessor => nominateSuccessor caps state self

def step (caps : Caps) (self : NodeID) (state : NodeState) : Event -> NodeEffect NodeState
  | .internal input => act caps self state input
  | .receive source message => receive caps self source state message

end CCFRaft.Model.Node
