-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model.ClusterConfig
import CCFRaft.Model.Messages
import CCFRaft.Model.NodeState
import CCFRaft.Shared.Capabilities
import Mathlib.Data.Finset.Sort

/-!
# Local node steps

How one node reacts to an event, over the state in `NodeState.lean`. `step` is
the entry point: `act` handles an `Input`, and `receive` handles a `Message`
after `observeTerm` adopts any newer term it carries.

A step may send messages through `caps`. A failed `guard` means the event is
disabled: the step has no effect and a received message stays in flight.
-/

namespace CCFRaft.Model.Local

open Shared (Capabilities Effect)

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
  | nominateSuccessor (destination : Node)
deriving DecidableEq

inductive Event (Node TxId : Type) where
  | internal (input : Input Node TxId)
  | receive (source : Node) (message : Message Node TxId)

variable [DecidableEq Node] [DecidableEq TxId]

/-! ## Leader state -/

abbrev hasQuorum (configurations : List (Configuration Node)) (voters : Finset Node)
    : Prop :=
  configurations.all
    fun configuration =>
      decide (hasConfigurationMajority voters configuration)

/--
Approximates `all_other_nodes`; unlike CCF, peers lost on rollback are not retained.
-/
def eligiblePeers (config : InitialConfig Node) (state : NodeState Node TxId)
    (self : Node)
    : Finset Node :=
  (state.activeMembers config ∪ state.retirementCompleted config).erase self

abbrev candidateTransitionEnabled (config : InitialConfig Node)
    (state : NodeState Node TxId) (self : Node)
    : Prop :=
  (state.role = .follower \/ state.role = .preVoteCandidate \/ state.role = .candidate)
  /\ ((self ∈ state.activeMembers config /\ campaignEligible config self state)
      \/ self ∈ state.retirementCompleted config)
  /\ Not (state.membershipState = .retiredCommitted)

/--
The highest current-term signature above the leader's commit index which a
majority of every active configuration has reached, or zero when there is none.
-/
def highestCommittableIndex (config : InitialConfig Node)
    (state : NodeState Node TxId) (self : Node)
    : Nat :=
  let reached index :=
    (state.activeMembers config).filter
      fun node => node = self \/ state.matchIndex node >= index
  (List.range (state.log.length + 1)).foldl
    (fun best index =>
      if index > state.commitIndex
          /\ isSignatureAt state.log index = true
          /\ termAt state.log index = state.currentTerm
          /\ hasQuorum (state.activeConfigurations config) (reached index) then
        max best index
      else
        best)
    0

/--
Retirement saves the outgoing leader's nomination permission before discarding
committed configurations. Sending the nomination is a separate local event.
-/
def advanceCommit [LinearOrder Node] (config : InitialConfig Node)
    (_caps : Caps Node TxId) (state : NodeState Node TxId) (self : Node)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let target := highestCommittableIndex config state self
  if target <= state.commitIndex then
    return state
  else
    let next := refreshRetirementState config self { state with commitIndex := target }
    if next.membershipState = .retiredCommitted then
      return {
        next with
          role := .none
          leaderKnown := false
          pendingRetirementNomination :=
            if state.role = .leader then
              some (state.currentTerm, eligiblePeers config state self)
            else
              none
      }
    else
      return next

def advanceCommitIfAlone [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (state : NodeState Node TxId) (self : Node)
    : NodeEffect Node TxId (NodeState Node TxId) :=
  if ((state.activeMembers config).erase self).Nonempty then
    pure state
  else
    advanceCommit config caps state self

/-! ## Outgoing messages -/

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

def makeRequestVoteRequest (state : NodeState Node TxId) : RequestVoteRequest where
  term := state.currentTerm
  lastCommittableTerm := lastCommittableTerm state
  lastCommittableIndex := lastCommittableIndex state

/-! ## Appending entries -/

/--
CCF runs hooks before appending the entry: new-peer heartbeats use the
pre-append log length.
-/
def applyTransactionEffect [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (self : Node) (txId : TxId)
    (done : List (TransactionEffect Node)) (state : NodeState Node TxId)
    (effect : TransactionEffect Node)
    : NodeEffect Node TxId (NodeState Node TxId) :=
  -- Later hooks see earlier effects without advancing the append frontier.
  let view : NodeState Node TxId :=
    {
      state with
        log :=
          if done = [] then
            state.log
          else
            state.log
            ++ [{ term := state.currentTerm, content := .transaction txId done }]
    }
  match effect with
  | .reconfiguration nodes => do
      let previousConfiguration :=
        (configurationHistory config view.log).foldl
          (fun _ configuration => configuration.nodes) config.configuration
      guard (nodes.Nonempty /\ Not (nodes = previousConfiguration))
      let addedNodes := (nodes \ eligiblePeers config view self).erase self
      let next : NodeState Node TxId :=
        {
          state with
            sentIndex :=
              fun peer =>
                if peer ∈ addedNodes then state.log.length else state.sentIndex peer
        }
      (addedNodes.sort).forM
        fun peer =>
          caps.send
            (.appendEntriesRequest (makeAppendEntriesRequest next peer state.log.length))
            peer
      return next
  | .retiredCommitted nodes => do
      let pending := view.retirementCompleted config \ retiredCommittedNodes view.log
      guard (nodes.Nonempty /\ nodes ⊆ pending)
      return state

def appendEntry [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (self : Node) (state : NodeState Node TxId)
    (content : EntryContent Node TxId)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let state <- match content with
                | .transaction txId effects => do
                    let (state, _) <- effects.foldlM
                                        (fun (state, done) effect => do
                                          let state <- applyTransactionEffect config caps
                                                        self txId done state effect
                                          return (state, done ++ [effect]))
                                        (state, [])
                    pure state
                | .signature => do
                    guard (Not (state.log = []))
                    pure state
  return refreshRetirementState config self
    { state with log := state.log ++ [{ term := state.currentTerm, content }] }

def appendBatch [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (self : Node) (state : NodeState Node TxId)
    (entries : List (EntryContent Node TxId))
    : NodeEffect Node TxId (NodeState Node TxId) := do
  guard
    (state.role = .leader
      /\ Not (state.membershipState = .retiredCommitted)
      /\ Not (entries = []))
  let appended <- entries.foldlM (appendEntry config caps self) state
  advanceCommitIfAlone config caps appended self

def sendEntries (config : InitialConfig Node) (caps : Caps Node TxId) (self : Node)
    (state : NodeState Node TxId) (destination : Node) (endIndex : Nat)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let sent := state.sentIndex destination
  guard
    (state.role = .leader
      /\ destination ∈ eligiblePeers config state self
      /\ sent <= endIndex
      /\ endIndex <= state.log.length
      /\ ((messageEntries state.log sent endIndex).all
            fun entry =>
              entry.term == termAt state.log endIndex)
          = true
      /\ (Not (state.membershipState = .retiredCommitted) \/ sent < endIndex))
  caps.send
    (.appendEntriesRequest (makeAppendEntriesRequest state destination endIndex))
    destination
  return { state with sentIndex := Function.update state.sentIndex destination endIndex }

/-! ## Handling AppendEntries -/

abbrev logOk (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Prop :=
  request.prevLogIndex = 0
  \/ (request.prevLogIndex <= state.log.length
      /\ termAt state.log request.prevLogIndex = request.prevLogTerm)

abbrev hasTermConflict (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Prop :=
  ((state.log.drop request.prevLogIndex).zip request.entries).any
    fun (existing, incoming) => existing.term != incoming.term

def committedFromLeader
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId))
    : Nat :=
  max state.commitIndex
    (maxCommittableIndexUpTo newLog
      (min request.leaderCommit (request.prevLogIndex + request.entries.length)))

def appendEntriesNack
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : AppendEntriesResponse :=
  if request.term < state.currentTerm \/ termAt state.log request.prevLogIndex = 0 then
    { term := state.currentTerm, success := false, lastLogIndex := state.log.length }
  else
    let lastLogIndex :=
      findHighestPossibleMatch state.log request.prevLogIndex request.prevLogTerm
    { term := termAt state.log lastLogIndex, success := false, lastLogIndex }

def appendEntriesFromLeader
    (config : InitialConfig Node)
    (self : Node)
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : NodeState Node TxId × AppendEntriesResponse :=
  let newLog :=
    state.log ++ request.entries.drop (state.log.length - request.prevLogIndex)
  let commitIndex := committedFromLeader state request newLog
  -- Native receive runs commit callbacks at each newly applied signature.
  let firstRetirementCommit :=
    match
        firstLogIndexAfter newLog 0
          (fun content =>
            content.effects.any
              fun effect =>
                match effect with
                | .retiredCommitted nodes => decide (self ∈ nodes)
                | .reconfiguration _ => false)
    with
    | none => commitIndex
    | some markerIndex =>
        match firstLogIndexAfter newLog (max state.log.length markerIndex)
                (fun content => decide (content = .signature)) with
        | none => commitIndex
        | some firstNewSignature => min commitIndex firstNewSignature
  let nextState :=
    refreshRetirementState config self
      { state with log := newLog, commitIndex := firstRetirementCommit }
  (
    { nextState with commitIndex },
    {
      term := nextState.currentTerm
      success := true
      lastLogIndex := request.prevLogIndex + request.entries.length
    }
  )

def handleAppendEntriesRequest
    (config : InitialConfig Node)
    (caps : Caps Node TxId)
    (self source : Node)
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  if request.term < state.currentTerm then
    caps.send (.appendEntriesResponse (appendEntriesNack state request)) source
    return refreshRetirementState config self state
  else
    let state :=
      if request.term = state.currentTerm
          /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true }
      else
        state
    if Not (logOk state request) then
      caps.send (.appendEntriesResponse (appendEntriesNack state request)) source
      return refreshRetirementState config self state
    else
      let state := { state with leaderKnown := true }
      if request.prevLogIndex < state.commitIndex
          \/ (hasTermConflict state request /\ !state.isNewFollower) then
        return refreshRetirementState config self state
      else
        let state :=
          if hasTermConflict state request then
            {
              state with
                log := state.log.take request.prevLogIndex, isNewFollower := false
            }
          else
            state
        let (next, response) := appendEntriesFromLeader config self state request
        caps.send (.appendEntriesResponse response) source
        return refreshRetirementState config self next

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
      advanceCommit config caps
        {
          state with
            matchIndex :=
              Function.update state.matchIndex source
                (max (state.matchIndex source) response.lastLogIndex)
        }
        self
    else
      return state
  else
    let possible := findHighestPossibleMatch state.log response.lastLogIndex response.term
    return {
      state with
        sentIndex :=
          Function.update state.sentIndex source
            (max (min possible (state.sentIndex source)) (state.matchIndex source))
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
  let grant : Bool :=
    decide
      (request.term = state.currentTerm
        /\ voteLogUpToDate state request
        /\ !state.leaderKnown
        /\ (state.votedFor = none \/ state.votedFor = some source))
  caps.send
    (.requestVoteResponse { term := state.currentTerm, voteGranted := grant }) source
  return if grant then { state with votedFor := some source } else state

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
def leaderState (config : InitialConfig Node) (self : Node) (state : NodeState Node TxId)
    : NodeState Node TxId :=
  let log :=
    if state.commitIndex > 0 then
      state.log.take (lastCommittableIndex state)
    else
      state.log
  refreshRetirementState config self
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
  let leader <- advanceCommitIfAlone config caps (leaderState config self state) self
  ((eligiblePeers config leader self).sort).forM
    fun peer =>
      caps.send
        (.appendEntriesRequest (makeAppendEntriesRequest leader peer leader.log.length))
        peer
  return leader

def electIfQuorum [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (self : Node) (state : NodeState Node TxId)
    : NodeEffect Node TxId (NodeState Node TxId) :=
  if state.role = .candidate
      /\ hasQuorum (state.activeConfigurations config) state.votesGranted
      /\ Not (state.membershipState = .retiredCommitted) then
    becomeLeader config caps self state
  else
    pure state

def broadcastToOthers [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (self : Node) (state : NodeState Node TxId)
    (message : Message Node TxId)
    : NodeEffect Node TxId Unit :=
  (((state.activeMembers config).erase self).sort).forM
    fun destination =>
      caps.send message destination

/--
The self-vote can promote to leader before the vote-request loop.
-/
def becomeCandidate [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (state : NodeState Node TxId) (self : Node)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let candidate : NodeState Node TxId :=
    {
      state with
        role := .candidate
        currentTerm := state.currentTerm + 1
        votedFor := some self
        leaderKnown := false
        votesGranted := {self}
        preVotesGranted := ∅
    }
  let next <- electIfQuorum config caps self candidate
  broadcastToOthers config caps self candidate
    (.requestVoteRequest (makeRequestVoteRequest candidate))
  return next

/--
The self-vote can synchronously start a regular election.
-/
def becomePreVoteCandidate [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (state : NodeState Node TxId) (self : Node)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let preVoteCandidate : NodeState Node TxId :=
    {
      state with
        role := .preVoteCandidate, leaderKnown := false, preVotesGranted := {self}
    }
  if hasQuorum (preVoteCandidate.activeConfigurations config)
      preVoteCandidate.preVotesGranted then
    becomeCandidate config caps preVoteCandidate self
  else
    broadcastToOthers config caps self preVoteCandidate
      (.requestPreVote (makeRequestVoteRequest preVoteCandidate))
    return preVoteCandidate

def startElection [LinearOrder Node] (config : InitialConfig Node)
    (caps : Caps Node TxId) (state : NodeState Node TxId)
    (self : Node)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  guard (candidateTransitionEnabled config state self)
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
    electIfQuorum config caps self
      { state with votesGranted := insert source state.votesGranted }
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
  if term = state.currentTerm /\ candidateTransitionEnabled config state self then
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
      handleAppendEntriesRequest config caps self source state request
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
  | .nominateSuccessor destination => do
      guard (destination ≠ self)
      let term ←
        if state.role = .leader then do
          guard (destination ∈ eligiblePeers config state self)
          pure state.currentTerm
        else do
          guard (state.role = .none /\ state.membershipState = .retiredCommitted)
          let some (term, peers) := state.pendingRetirementNomination | failure
          guard (destination ∈ peers)
          pure term
      caps.send (.proposeVoteRequest term) destination
      return { state with pendingRetirementNomination := none }

def step [LinearOrder Node] (config : InitialConfig Node) (caps : Caps Node TxId)
    (self : Node) (state : NodeState Node TxId)
    : Event Node TxId -> NodeEffect Node TxId (NodeState Node TxId)
  | .internal (.nominateSuccessor destination) =>
      act config caps self state (.nominateSuccessor destination)
  | .internal input =>
      act config caps self { state with pendingRetirementNomination := none } input
  | .receive source message =>
      receive config caps self source { state with pendingRetirementNomination := none }
        message

end CCFRaft.Model.Local
