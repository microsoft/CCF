-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model.Messages

/-!
# Local node steps

How one node reacts to an event, over the state in `Node.lean`. `step` is the
entry point: `act` handles an `Input`, and `receive` handles a `Message` after
`observeTerm` adopts any newer term it carries.

A step may send messages through `caps`. A failed `guard` means the event is
disabled: the step has no effect and a received message stays in flight.
-/

namespace CCFRaft.Model.Local

variable {Node TxId : Type}

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

/-- True when voters form a strict majority in every supplied configuration. -/
abbrev hasQuorum (configurations : List (Configuration Node)) (voters : Finset Node)
    : Prop :=
  configurations.all
    fun configuration =>
      decide (hasConfigurationMajority voters configuration)

/--
A successor has maximal replication progress, with ties broken by membership
in the highest active configuration, matching CCF's successor nomination.
-/
abbrev plausibleSuccessor (config : InitialConfig Node) (state : NodeState Node TxId)
    (self destination : Node)
    : Prop :=
  let configurations := state.activeConfigurations config
  let candidates := (state.activeMembers config).erase self
  let latestMembershipIndex node :=
    configurations.foldl
      (fun highest configuration =>
        if node ∈ configuration.nodes then max highest configuration.index else highest)
      0
  destination ∈ candidates
  /\ ∀ candidate ∈ candidates,
      state.matchIndex candidate <= state.matchIndex destination
      /\ (state.matchIndex candidate = state.matchIndex destination
          -> latestMembershipIndex candidate <= latestMembershipIndex destination)

/--
The conditions which let a node start an election: a passive or campaigning
role, membership it can campaign from, and no committed retirement.
-/
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
Advance a leader's commit index and refresh its retirement metadata. A node
whose retirement is now committed clears its role and known leader, as CCF's
`become_retired(RetiredCommitted)` does.
-/
def advanceCommit (config : InitialConfig Node)
    (state : NodeState Node TxId) (self : Node)
    : NodeState Node TxId :=
  let next :=
    refreshRetirementState config self
      { state with commitIndex := highestCommittableIndex config state self }
  if next.membershipState = .retiredCommitted then
    { next with role := .none, leaderKnown := false }
  else
    next

/--
Append one current-term entry to a leader's log and refresh its retirement
metadata. Disabled for a retired-committed node.
-/
def leaderAppend (config : InitialConfig Node) (state : NodeState Node TxId)
    (self : Node) (content : EntryContent Node TxId)
    : NodeEffect Node TxId (NodeState Node TxId) := do
  let next :=
    refreshRetirementState config self
      { state with log := state.log ++ [{ term := state.currentTerm, content }] }
  guard (state.role = .leader /\ Not (state.membershipState = .retiredCommitted))
  pure next

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
abbrev logOk (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Prop :=
  request.prevLogIndex = 0
  \/ (request.prevLogIndex <= state.log.length
      /\ termAt state.log request.prevLogIndex = request.prevLogTerm)

/--
Detect a log position covered by both the follower's log and the request where
the two disagree. As in CCF, only terms are compared, not entry contents.
-/
abbrev hasTermConflict (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Prop :=
  ((state.log.drop request.prevLogIndex).zip request.entries).any
    fun (existing, incoming) => existing.term != incoming.term

/-- Advance the commit index to the latest signature the request covers. -/
def committedFromLeader
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId))
    : Nat :=
  max state.commitIndex
    (maxCommittableIndexUpTo newLog
      (min request.leaderCommit (request.prevLogIndex + request.entries.length)))

/--
The NACK for a stale-term request or a mismatched previous entry. It reports
the follower's term and log length, unless the follower holds the previous
index with a different term; then it reports the highest index that could
still match the leader's log, and that index's term.
-/
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

/--
Apply a request that agrees with the follower's log on every position both
cover: append the entries past the end of the log, adopt the leader's commit
index, and ACK up to the end of the request.
-/
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
            match content with
            | .retiredCommitted nodes => decide (self ∈ nodes)
            | _ => false)
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

/--
Handle an AppendEntries request, returning the new state and the response to
send, if any. A same-term candidate or pre-vote candidate first steps down to
follower. Stale-term requests and requests whose previous entry does not match
are NACKed. Otherwise the sender becomes the known leader, and the request is
dropped without a response if it starts before the commit index, or if it
conflicts with the log of a node that may no longer roll back. A new follower
instead truncates a conflicting suffix, then the entries are applied.
-/
def handleAppendEntriesRequest
    (config : InitialConfig Node)
    (self : Node)
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : NodeState Node TxId × Option AppendEntriesResponse :=
  let state :=
    if request.term = state.currentTerm
        /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
      { state with role := .follower, isNewFollower := true }
    else
      state
  if request.term < state.currentTerm \/ Not (logOk state request) then
    (state, some (appendEntriesNack state request))
  else
    let state := { state with leaderKnown := true }
    if request.prevLogIndex < state.commitIndex
        \/ (hasTermConflict state request /\ !state.isNewFollower) then
      (state, none)
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
      (next, some response)

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
            Function.update state.matchIndex source
              (max (state.matchIndex source) response.lastLogIndex)
      }
    else
      state
  else
    let possible := findHighestPossibleMatch state.log response.lastLogIndex response.term
    {
      state with
        sentIndex :=
          Function.update state.sentIndex source
            (max (min possible (state.sentIndex source)) (state.matchIndex source))
    }

/-! ## Handling elections -/

/-- Compare a candidate log summary with a voter's local log. -/
abbrev voteLogUpToDate (state : NodeState Node TxId) (request : RequestVoteRequest)
    : Prop :=
  request.lastCommittableTerm > maxCommittableTerm state.log
  \/ (request.lastCommittableTerm = maxCommittableTerm state.log
      /\ request.lastCommittableIndex >= maxCommittableIndex state.log)

/--
Grant a current-term vote to an up-to-date candidate, at most once per term
and only while no leader is known in that term.
-/
def handleRequestVoteRequest
    (state : NodeState Node TxId)
    (source : Node)
    (request : RequestVoteRequest)
    : NodeState Node TxId × RequestVoteResponse :=
  let grant : Bool :=
    decide
      (request.term = state.currentTerm
        /\ voteLogUpToDate state request
        /\ !state.leaderKnown
        /\ (state.votedFor = none \/ state.votedFor = some source))
  (
    if grant then { state with votedFor := some source } else state,
    { term := state.currentTerm, voteGranted := grant }
  )

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

/-- Move to a newer term as a follower that has not voted or seen a leader in it. -/
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

/-- Handle one message from `source` after observing its term. -/
def receive
    (config : InitialConfig Node)
    (caps : Caps Node TxId)
    (self source : Node)
    (state : NodeState Node TxId)
    (message : Message Node TxId)
    : NodeEffect Node TxId (NodeState Node TxId) :=
  let state := observeTerm state message
  match message with
  | .appendEntriesRequest request => do
      let (next, response) := handleAppendEntriesRequest config self state request
      if let some response := response then
        caps.send (.appendEntriesResponse response) source
      return refreshRetirementState config self next
  | .appendEntriesResponse response =>
      return handleAppendEntriesResponse state source response
  | .requestVoteRequest request => do
      let (next, response) := handleRequestVoteRequest state source request
      caps.send (.requestVoteResponse response) source
      return next
  | .requestVoteResponse response =>
      return handleRequestVoteResponse state source response
  | .requestPreVote request => do
      -- Answer without recording a vote.
      let voteGranted :=
        decide (request.term = state.currentTerm /\ voteLogUpToDate state request)
      caps.send (.requestPreVoteResponse { term := state.currentTerm, voteGranted })
        source
      return state
  | .requestPreVoteResponse response =>
      return handleRequestPreVoteResponse state source response
  | .proposeVoteRequest term =>
      -- Start an election on a same-term proposal when the node is eligible.
      if term = state.currentTerm /\ candidateTransitionEnabled config state self then
        return becomeCandidateNodeState state self
      else
        return state

/-- Act on one input. -/
def act (config : InitialConfig Node) (caps : Caps Node TxId) (self : Node)
    (state : NodeState Node TxId)
    : Input Node TxId -> NodeEffect Node TxId (NodeState Node TxId)
  | .initializeConfiguration => do
      guard
        (self = config.leader
          /\ state.role = .leader
          /\ state.currentTerm = BOOTSTRAP_TERM
          /\ state.log = []
          /\ state.commitIndex = 0
          /\ state.membershipState = .active)
      return {
        state with
          log :=
            [{
              term := state.currentTerm
              content := .reconfiguration config.configuration
            }]
      }
  | .clientRequest txId => leaderAppend config state self (.transaction txId)
  | .changeConfiguration newConfiguration => do
      let previousConfiguration :=
        (configurationHistory config state.log).foldl
          (fun _ configuration => configuration.nodes) config.configuration
      let addedNodes := newConfiguration \ previousConfiguration
      guard (newConfiguration.Nonempty /\ Not (newConfiguration = previousConfiguration))
      let appended <- leaderAppend config state self (.reconfiguration newConfiguration)
      -- New nodes are sent only future entries at first; they NACK if necessary.
      return {
        appended with
          sentIndex :=
            fun peer =>
              if peer ∈ addedNodes then state.log.length else state.sentIndex peer
      }
  | .appendRetiredCommitted => do
      let pending := state.retirementCompleted config \ retiredCommittedNodes state.log
      guard pending.Nonempty
      leaderAppend config state self (.retiredCommitted pending)
  | .signCommittableMessages => do
      guard (Not (state.log = []))
      leaderAppend config state self .signature
  | .appendEntries destination batchEnd => do
      let sent := state.sentIndex destination
      guard
        (state.role = .leader
          /\ Not (self = destination)
          /\ (destination ∈ state.activeMembers config
              \/ destination ∈ state.retirementCompleted config)
          /\ sent <= batchEnd
          /\ batchEnd <= state.log.length
          /\ ((messageEntries state.log sent batchEnd).all
                fun entry =>
                  entry.term == termAt state.log batchEnd)
              = true
          /\ (Not (state.membershipState = .retiredCommitted) \/ sent < batchEnd))
      caps.send
        (.appendEntriesRequest (makeAppendEntriesRequest state destination batchEnd))
        destination
      return {
        state with
          sentIndex := Function.update state.sentIndex destination batchEnd
      }
  | .advanceCommitIndex => do
      guard
        (state.role = .leader
          /\ state.commitIndex < highestCommittableIndex config state self
          /\ Not ((advanceCommit config state self).membershipState = .retiredCommitted))
      return advanceCommit config state self
  | .timeout => do
      guard
        (candidateTransitionEnabled config state self
          /\ Not (config.preVoteStatus self = .enabled))
      return becomeCandidateNodeState state self
  | .becomePreVoteCandidate => do
      guard
        (candidateTransitionEnabled config state self
          /\ config.preVoteStatus self = .enabled)
      return {
        state with
          role := .preVoteCandidate, leaderKnown := false, preVotesGranted := {self}
      }
  | .becomeCandidate => do
      guard
        (state.role = .preVoteCandidate
          /\ hasQuorum (state.activeConfigurations config) state.preVotesGranted)
      return becomeCandidateNodeState state self
  | .requestVote destination => do
      guard
        (state.role = .candidate
          /\ Not (self = destination)
          /\ destination ∈ state.activeMembers config)
      caps.send (.requestVoteRequest (makeRequestVoteRequest state)) destination
      return state
  | .requestPreVote destination => do
      guard
        (state.role = .preVoteCandidate
          /\ Not (self = destination)
          /\ destination ∈ state.activeMembers config)
      caps.send (.requestPreVote (makeRequestVoteRequest state)) destination
      return state
  | .checkQuorum => do
      guard (state.role = .leader /\ ((state.activeMembers config).erase self).Nonempty)
      return { state with role := .follower, leaderKnown := false }
  | .becomeLeader => do
      guard
        (state.role = .candidate
          /\ Not (state.membershipState = .retiredCommitted)
          /\ hasQuorum (state.activeConfigurations config) state.votesGranted)
      -- Drop the unsigned suffix, except at startup, as CCF does.
      let log :=
        if state.commitIndex > 0 then
          state.log.take (lastCommittableIndex state)
        else
          state.log
      return refreshRetirementState config self
        {
          state with
            role := .leader
            log
            leaderKnown := true
            sentIndex := fun _ => log.length
            matchIndex := fun _ => 0
        }
  | .proposeVote destination => do
      guard (state.role = .leader /\ plausibleSuccessor config state self destination)
      caps.send (.proposeVoteRequest state.currentTerm) destination
      return state
  | .advanceCommitIndexAndProposeVote destination => do
      guard
        (state.role = .leader
          /\ state.commitIndex < highestCommittableIndex config state self
          /\ (advanceCommit config state self).membershipState = .retiredCommitted
          /\ plausibleSuccessor config state self destination)
      caps.send (.proposeVoteRequest state.currentTerm) destination
      return advanceCommit config state self

/-- One step of node `self`: act on an input or handle a delivered message. -/
def step (config : InitialConfig Node) (caps : Caps Node TxId) (self : Node)
    (state : NodeState Node TxId)
    : Event Node TxId -> NodeEffect Node TxId (NodeState Node TxId)
  | .internal input => act config caps self state input
  | .receive source message => receive config caps self source state message

end CCFRaft.Model.Local
