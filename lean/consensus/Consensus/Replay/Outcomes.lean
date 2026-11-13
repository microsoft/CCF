module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Model

public section

/-!
# Outcomes of model steps

An outcome names one thing which a node's step does: a branch of a handler in
`Model/Node.lean`, or an effect which several handlers share, such as a commit.
Replay collects the outcomes of the actions it runs, so that what the traces of the
implementation exercise can be compared with what the model allows.
A step may show several outcomes.
-/

namespace Consensus.Replay

open Model.Node
open CCF (Finset)
open CCF.MultiNodeTransitionSystem (nodeState)

inductive Outcome where
  -- `appendBatch`
  /-- A transaction which changes neither membership nor retirement is appended. -/
  | appendTransaction
  | appendSignature
  | appendConfiguration
  /-- The peers which a configuration adds are sent a heartbeat as it is appended. -/
  | appendConfigurationToNewPeers
  | appendRetirementConfirmation
  | appendSeveralEntries
  /-- A batch sends entries before its commit check. -/
  | appendFlushes
  -- `sendEntries`
  | sendEntries
  | sendHeartbeat
  /-- The destination has been removed, and its retirement is not confirmed yet. -/
  | sendToRemovedPeer
  -- `startElection`
  | electionStarted
  /-- A node which is already campaigning times out again. -/
  | electionRetried
  /-- The node is a quorum by itself, and becomes primary at once. -/
  | electionWonWithoutPeers
  /-- The node is in no signed active configuration, and campaigns as a removed node. -/
  | electionByRemovedNode
  -- `checkQuorum`, `nominateSuccessor` and `initAsBackup`
  | checkQuorumStepsDown
  | nominationSent
  | nominationWithoutSuccessor
  | joinEmpty
  | joinFromSnapshot
  -- `handleAppendEntriesRequest`
  /-- Rejected: the request is from an earlier term. -/
  | appendEntriesStaleTerm
  /-- Rejected: the log ends before the previous index. -/
  | appendEntriesMissingPrevious
  /-- Rejected with a hint: the entry at the previous index has another term. -/
  | appendEntriesMismatchedPrevious
  /-- Ignored: the previous index is below the commit index. -/
  | appendEntriesBelowCommit
  /-- Ignored: an entry conflicts, and the node may not roll back. -/
  | appendEntriesConflictIgnored
  /-- A conflicting suffix is rolled back. -/
  | appendEntriesTruncates
  | appendEntriesAppends
  /-- Accepted: every entry is already in the log. -/
  | appendEntriesDuplicate
  | appendEntriesHeartbeat
  /-- A candidate learns of the primary of its own term. -/
  | appendEntriesDemotesCandidate
  /-- The commit index of the follower advances. -/
  | appendEntriesCommits
  -- `handleAppendEntriesResponse`
  | appendEntriesResponseFromUnknownPeer
  | appendEntriesResponseToNonPrimary
  | ackAdvancesMatch
  /-- An acknowledgement at the match index, as for a heartbeat. -/
  | ackRepeated
  /-- An acknowledgement below the match index, which arrives late. -/
  | ackBelowMatch
  /-- Ignored: an acknowledgement from an earlier term. -/
  | ackFromOtherTerm
  /-- A rejection moves the send index back. -/
  | nackRewinds
  | nackWithoutRewind
  -- `handleRequestVoteRequest`
  | voteGranted
  | voteRefusedStaleTerm
  /-- Refused only because the log of the candidate is behind. -/
  | voteRefusedLog
  /-- Refused only because the voter knows a primary in this term. -/
  | voteRefusedPrimaryKnown
  /-- Refused only because the voter voted for another candidate. -/
  | voteRefusedAlreadyVoted
  | voteRefusedSeveralReasons
  -- `handleRequestPreVoteRequest`
  | preVoteGranted
  | preVoteRefusedStaleTerm
  | preVoteRefusedLog
  -- `handleRequestVoteResponse`
  | voteResponseFromUnknownPeer
  | voteResponseFromOtherTerm
  /-- Ignored: the node gave up its candidacy, and campaigns again in the same term. -/
  | voteResponseToPreVoteCandidate
  /-- Ignored: the node is no longer campaigning. -/
  | voteResponseToNonCandidate
  | voteResponseRefusal
  | voteResponseCounted
  | voteResponseElects
  -- `handleRequestPreVoteResponse`
  | preVoteResponseFromUnknownPeer
  | preVoteResponseFromOtherTerm
  /-- Ignored: the node is a candidate already, and a pre-vote is not a vote. -/
  | preVoteResponseToCandidate
  /-- Ignored: the node is no longer campaigning. -/
  | preVoteResponseToNonCandidate
  | preVoteResponseRefusal
  | preVoteResponseCounted
  | preVoteResponseStartsElection
  -- `handleProposeRequestVoteRequest`
  | proposalAccepted
  | proposalFromOtherTerm
  /-- Ignored: the node may not start an election. -/
  | proposalIneligible
  -- `observeTerm`
  | higherTermAdopted
  | higherTermDeposesPrimary
  -- `becomePrimary`
  /-- The new primary drops the entries after its last signature. -/
  | electedTruncatesSuffix
  /-- The election needed a quorum of several active configurations. -/
  | electedWithJointQuorum
  -- `advanceCommit`
  | primaryCommits
  /-- The commit needed a quorum of several active configurations. -/
  | commitWithJointQuorum
  /-- The commit stops before a pending configuration. -/
  | commitBelowPendingConfiguration
  /-- A quorum holds a signature of an earlier term, which stays uncommitted. -/
  | commitDeferredForOldTerm
  -- `NodeState.retirement`
  | retirementOrdered
  | retirementSigned
  | retirementCompleted
  | retirementCommitted
  /-- A primary nominates a successor as its retirement is confirmed. -/
  | retirementCommitNominates
  /-- The signature after the removal of the node is rolled back, but not the removal. -/
  | retirementSignatureRolledBack
  /-- The removal of the node is rolled back. -/
  | retirementRolledBack
deriving DecidableEq, Repr

namespace Outcome

/-- Every outcome, in the order of declaration. -/
def all : List Outcome :=
  [
    .appendTransaction,
    .appendSignature,
    .appendConfiguration,
    .appendConfigurationToNewPeers,
    .appendRetirementConfirmation,
    .appendSeveralEntries,
    .appendFlushes,
    .sendEntries,
    .sendHeartbeat,
    .sendToRemovedPeer,
    .electionStarted,
    .electionRetried,
    .electionWonWithoutPeers,
    .electionByRemovedNode,
    .checkQuorumStepsDown,
    .nominationSent,
    .nominationWithoutSuccessor,
    .joinEmpty,
    .joinFromSnapshot,
    .appendEntriesStaleTerm,
    .appendEntriesMissingPrevious,
    .appendEntriesMismatchedPrevious,
    .appendEntriesBelowCommit,
    .appendEntriesConflictIgnored,
    .appendEntriesTruncates,
    .appendEntriesAppends,
    .appendEntriesDuplicate,
    .appendEntriesHeartbeat,
    .appendEntriesDemotesCandidate,
    .appendEntriesCommits,
    .appendEntriesResponseFromUnknownPeer,
    .appendEntriesResponseToNonPrimary,
    .ackAdvancesMatch,
    .ackRepeated,
    .ackBelowMatch,
    .ackFromOtherTerm,
    .nackRewinds,
    .nackWithoutRewind,
    .voteGranted,
    .voteRefusedStaleTerm,
    .voteRefusedLog,
    .voteRefusedPrimaryKnown,
    .voteRefusedAlreadyVoted,
    .voteRefusedSeveralReasons,
    .preVoteGranted,
    .preVoteRefusedStaleTerm,
    .preVoteRefusedLog,
    .voteResponseFromUnknownPeer,
    .voteResponseFromOtherTerm,
    .voteResponseToPreVoteCandidate,
    .voteResponseToNonCandidate,
    .voteResponseRefusal,
    .voteResponseCounted,
    .voteResponseElects,
    .preVoteResponseFromUnknownPeer,
    .preVoteResponseFromOtherTerm,
    .preVoteResponseToCandidate,
    .preVoteResponseToNonCandidate,
    .preVoteResponseRefusal,
    .preVoteResponseCounted,
    .preVoteResponseStartsElection,
    .proposalAccepted,
    .proposalFromOtherTerm,
    .proposalIneligible,
    .higherTermAdopted,
    .higherTermDeposesPrimary,
    .electedTruncatesSuffix,
    .electedWithJointQuorum,
    .primaryCommits,
    .commitWithJointQuorum,
    .commitBelowPendingConfiguration,
    .commitDeferredForOldTerm,
    .retirementOrdered,
    .retirementSigned,
    .retirementCompleted,
    .retirementCommitted,
    .retirementCommitNominates,
    .retirementSignatureRolledBack,
    .retirementRolledBack
  ]

/-- A report lists `all`, so it must not omit an outcome. -/
theorem mem_all (outcome : Outcome) : outcome ∈ all := by
  cases outcome <;> decide

/-- The name of the constructor. -/
def name (outcome : Outcome) : String :=
  ((reprStr outcome).splitOn ".").getLastD ""

end Outcome

private abbrev LocalStep :=
  CCF.MultiNodeTransitionSystem.LocalStep NodeID NodeState Event Message Notification

/-- The step which the acting node takes for `action`, unless it disables the action. -/
private def localStep (state : Model.State) (action : Model.Action)
    : Option LocalStep := do
  let (node, event) :=
    match action with
    | .local node input => (node, Event.internal input)
    | .deliver envelope =>
        (envelope.target, Event.receive envelope.source envelope.payload)
  let before ← nodeState state node
  let (after, effects) ← (step (CCF.Capabilities.record node) node before event).run {}
  return { node, before, action := event, after, effects }

private def tag (condition : Prop) [Decidable condition] (outcome : Outcome)
    : List Outcome :=
  if condition then [outcome] else []

private def either (condition : Prop) [Decidable condition] (yes no : Outcome)
    : List Outcome :=
  [if condition then yes else no]

private def sent (s : LocalStep) : List Message :=
  s.effects.outgoing.map (·.payload)

/-! ## Local inputs -/

private def appendOutcomes (s : LocalStep) (entries : List AppendEntryInput)
    : List Outcome :=
  let any (property : EntryContent → Bool) :=
    entries.any fun entry => property entry.content
  let plain (content : EntryContent) : Bool :=
    !content.isSignature && content.metadata == {}
  let confirms (content : EntryContent) : Bool :=
    decide content.metadata.retirementConfirmations.Nonempty
  let peers := eligiblePeers s.before s.node
  let toNewPeer (envelope : Model.Envelope) : Bool :=
    envelope.payload matches .appendEntriesRequest _ && decide (envelope.target ∉ peers)
  tag (any plain) .appendTransaction
  ++ tag (any (·.isSignature)) .appendSignature
  ++ tag (any (·.metadata.configuration.isSome)) .appendConfiguration
  ++ tag (s.effects.outgoing.any toNewPeer) .appendConfigurationToNewPeers
  ++ tag (any confirms) .appendRetirementConfirmation
  ++ tag (entries.length > 1) .appendSeveralEntries
  ++ tag (entries.any (!·.flushes.isEmpty)) .appendFlushes

private def sendOutcomes (s : LocalStep) (destination endIndex : Nat) : List Outcome :=
  let entries := messageEntries s.before.log (s.before.sentIndex destination) endIndex
  either entries.isEmpty .sendHeartbeat .sendEntries
  ++ tag (destination ∉ s.before.activeMembers) .sendToRemovedPeer

private def electionOutcomes (s : LocalStep) : List Outcome :=
  either (s.before.role = .follower) .electionStarted .electionRetried
  ++ tag (s.after.role = .primary) .electionWonWithoutPeers
  ++ tag (s.node ∉ configurationMembers s.before.signedActiveConfigurations)
      .electionByRemovedNode

/-! ## Handling AppendEntries -/

/-- `state` is the receiver after `observeTerm`, wherever a handler takes it. -/
private def appendEntriesRequestOutcomes (s : LocalStep) (state : NodeState)
    (request : AppendEntriesRequest)
    : List Outcome :=
  let response :=
    (sent s).findSome?
      fun
      | .appendEntriesResponse response => some response
      | _ => none
  let result : Outcome :=
    match response with
    | none =>
        if request.prevLogIndex < state.commitIndex then
          .appendEntriesBelowCommit
        else
          .appendEntriesConflictIgnored
    | some response =>
        if !response.success then
          if request.term < state.currentTerm then
            .appendEntriesStaleTerm
          else if termAt state.log request.prevLogIndex = 0 then
            .appendEntriesMissingPrevious
          else
            .appendEntriesMismatchedPrevious
        else if !state.log.isPrefixOf s.after.log then
          .appendEntriesTruncates
        else if state.log.length < s.after.log.length then
          .appendEntriesAppends
        else if request.entries.isEmpty then
          .appendEntriesHeartbeat
        else
          .appendEntriesDuplicate
  [result]
  ++ tag
      (request.term = state.currentTerm
        /\ (state.role = .candidate \/ state.role = .preVoteCandidate))
      .appendEntriesDemotesCandidate
  ++ tag (s.before.commitIndex < s.after.commitIndex) .appendEntriesCommits

/--
Whether a quorum holds a signature of an earlier term above the commit index, which
`highestCommittableIndex` does not commit.
-/
private def deferredForOldTerm (self : NodeID) (state : NodeState) : Bool :=
  let replicatedBy index :=
    state.activeMembers.filter fun node => node = self \/ state.matchIndex node >= index
  (List.range (state.log.length + 1)).any
    fun index =>
      decide
        (index > state.commitIndex
          /\ isSignatureAt state.log index = true
          /\ termAt state.log index ≠ state.currentTerm
          /\ hasQuorum
              (state.activeConfigurations.filter
                fun configuration => configuration.index <= index)
              (replicatedBy index))

private def appendEntriesResponseOutcomes (s : LocalStep) (state : NodeState)
    (source : NodeID) (response : AppendEntriesResponse)
    : List Outcome :=
  let rewinds := decide (s.after.sentIndex source < state.sentIndex source)
  let matched := state.matchIndex source
  if state.role ≠ .primary then
    [.appendEntriesResponseToNonPrimary]
  else if !response.success then
    either rewinds .nackRewinds .nackWithoutRewind
  else if response.term ≠ state.currentTerm then
    [.ackFromOtherTerm]
  else if response.lastLogIndex < matched then
    [.ackBelowMatch]
  else if response.lastLogIndex = matched then
    [.ackRepeated]
  else
    .ackAdvancesMatch :: tag (deferredForOldTerm s.node s.after) .commitDeferredForOldTerm

/-! ## Handling elections -/

private def voteRequestOutcomes (s : LocalStep) (state : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : List Outcome :=
  let granted :=
    (sent s).any
      fun
      | .requestVoteResponse response => response.voteGranted
      | _ => false
  if granted then
    [.voteGranted]
  else if request.term ≠ state.currentTerm then
    [.voteRefusedStaleTerm]
  else
    let reasons :=
      tag (Not (voteLogUpToDate state request)) .voteRefusedLog
      ++ tag state.primaryKnown .voteRefusedPrimaryKnown
      ++ tag (Not (state.votedFor = none \/ state.votedFor = some source))
          .voteRefusedAlreadyVoted
    match reasons with
    | [reason] => [reason]
    | _ => [.voteRefusedSeveralReasons]

private def preVoteRequestOutcomes (s : LocalStep) (state : NodeState)
    (request : RequestVoteRequest)
    : List Outcome :=
  let granted :=
    (sent s).any
      fun
      | .requestPreVoteResponse response => response.voteGranted
      | _ => false
  if granted then
    [.preVoteGranted]
  else if request.term ≠ state.currentTerm then
    [.preVoteRefusedStaleTerm]
  else
    [.preVoteRefusedLog]

/--
A response with the term of the node leaves `observeTerm` without effect, so the
state before the step decides.
-/
private def voteResponseOutcomes (s : LocalStep) (response : RequestVoteResponse)
    : List Outcome :=
  if response.term ≠ s.before.currentTerm then
    [.voteResponseFromOtherTerm]
  else if s.before.role = .preVoteCandidate then
    [.voteResponseToPreVoteCandidate]
  else if s.before.role ≠ .candidate then
    [.voteResponseToNonCandidate]
  else if !response.voteGranted then
    [.voteResponseRefusal]
  else if s.after.role = .primary then
    [.voteResponseElects]
  else
    [.voteResponseCounted]

private def preVoteResponseOutcomes (s : LocalStep) (response : RequestVoteResponse)
    : List Outcome :=
  if response.term ≠ s.before.currentTerm then
    [.preVoteResponseFromOtherTerm]
  else if s.before.role = .candidate then
    [.preVoteResponseToCandidate]
  else if s.before.role ≠ .preVoteCandidate then
    [.preVoteResponseToNonCandidate]
  else if !response.voteGranted then
    [.preVoteResponseRefusal]
  else if s.after.role = .preVoteCandidate then
    [.preVoteResponseCounted]
  else
    [.preVoteResponseStartsElection]

/-- An accepted proposal starts an election, which increments the term. -/
private def proposalOutcomes (s : LocalStep) (term : Nat) : List Outcome :=
  if term ≠ s.before.currentTerm then
    [.proposalFromOtherTerm]
  else if s.after.currentTerm = s.before.currentTerm then
    [.proposalIneligible]
  else
    [.proposalAccepted]

private def receiveOutcomes (s : LocalStep) (source : NodeID) (message : Message)
    : List Outcome :=
  let unknownPeer : Option Outcome :=
    if source ∈ eligiblePeers s.before s.node then
      none
    else
      match message with
      | .appendEntriesResponse _ => some .appendEntriesResponseFromUnknownPeer
      | .requestVoteResponse _ => some .voteResponseFromUnknownPeer
      | .requestPreVoteResponse _ => some .preVoteResponseFromUnknownPeer
      | _ => none
  if let some outcome := unknownPeer then
    [outcome]
  else
    let state := observeTerm s.before message
    let handled :=
      match message with
      | .appendEntriesRequest request => appendEntriesRequestOutcomes s state request
      | .appendEntriesResponse response =>
          appendEntriesResponseOutcomes s state source response
      | .requestVoteRequest request => voteRequestOutcomes s state source request
      | .requestVoteResponse response => voteResponseOutcomes s response
      | .requestPreVoteRequest request => preVoteRequestOutcomes s state request
      | .requestPreVoteResponse response => preVoteResponseOutcomes s response
      | .proposeRequestVoteRequest term => proposalOutcomes s term
    let higherTerm := s.before.currentTerm < state.currentTerm
    handled
    ++ tag (higherTerm /\ s.before.role ≠ .primary) .higherTermAdopted
    ++ tag (higherTerm /\ s.before.role = .primary) .higherTermDeposesPrimary

/-! ## Effects shared by handlers -/

private def electedOutcomes (s : LocalStep) : List Outcome :=
  if s.before.role ≠ .primary /\ s.after.role = .primary then
    tag (s.after.log.length < s.before.log.length) .electedTruncatesSuffix
    ++ tag (s.before.activeConfigurations.length > 1) .electedWithJointQuorum
  else
    []

/--
A follower commits only in `handleAppendEntriesRequest`, and a joiner starts committed.
As in `highestCommittableIndex`, a commit needs a quorum of each configuration which is
active at the previous commit index and at or below the new one.
-/
private def commitOutcomes (s : LocalStep) : List Outcome :=
  let asPrimary : Bool :=
    decide (s.before.role = .primary \/ s.after.role = .primary)
    && !(s.action matches .receive _ (.appendEntriesRequest _))
  if asPrimary /\ s.before.commitIndex < s.after.commitIndex then
    let active := activeConfigurations s.after.log s.before.commitIndex
    let reached :=
      active.filter fun configuration => configuration.index <= s.after.commitIndex
    [.primaryCommits]
    ++ tag (reached.length > 1) .commitWithJointQuorum
    ++ tag (reached.length < active.length) .commitBelowPendingConfiguration
  else
    []

private def retirementOutcomes (s : LocalStep) : List Outcome :=
  let before := (s.before.retirement s.node).phase
  let after := (s.after.retirement s.node).phase
  if before = after then
    []
  else
    match after with
    | .noRetirementObserved => [.retirementRolledBack]
    | .retirementOrdered =>
        either (before = .retirementSigned) .retirementSignatureRolledBack
          .retirementOrdered
    | .retirementSigned => [.retirementSigned]
    | .retirementCompleted => [.retirementCompleted]
    | .retiredCommitted =>
        [.retirementCommitted]
        ++ tag
            (s.before.role = .primary
              /\ (sent s).any (· matches .proposeRequestVoteRequest _))
            .retirementCommitNominates

/-! ## The step -/

/-- What the step of the acting node shows; nothing if the node disables `action`. -/
def outcomes (state : Model.State) (action : Model.Action) : List Outcome :=
  match localStep state action with
  | none => []
  | some s =>
      let handled :=
        match s.action with
        | .internal (.append entries) => appendOutcomes s entries
        | .internal (.sendEntries destination endIndex) =>
            sendOutcomes s destination endIndex
        | .internal (.timeout .election) => electionOutcomes s
        | .internal (.timeout .checkQuorum) => [.checkQuorumStepsDown]
        | .internal .nominateSuccessor =>
            either s.effects.outgoing.isEmpty .nominationWithoutSuccessor .nominationSent
        | .internal (.initAsBackup entries) =>
            either entries.isEmpty .joinEmpty .joinFromSnapshot
        | .receive source message => receiveOutcomes s source message
      handled ++ electedOutcomes s ++ commitOutcomes s ++ retirementOutcomes s

/--
A Markdown table of the steps and traces which show each outcome, with the first such
trace, followed by the outcomes which no trace shows.
-/
def report (traces : Array (String × Array Outcome)) : String :=
  let rows :=
    Outcome.all.map
      fun outcome =>
        let showing := traces.filter fun (_, shown) => shown.contains outcome
        let steps := traces.foldl (fun total (_, shown) => total + shown.count outcome) 0
        (outcome.name, steps, showing.size, (showing[0]?.map Prod.fst).getD "")
  let missing := (rows.filter fun (_, steps, _) => steps == 0).map (·.1)
  let lines :=
    ["| Outcome | Steps | Traces | First trace |", "| --- | ---: | ---: | --- |"]
    ++ rows.map
        (fun (name, steps, count, first) => s!"| {name} | {steps} | {count} | {first} |")
    ++ [
      "",
      s!"Traces: {traces.size}. Outcomes shown: {rows.length - missing.length} of {rows.length}."
    ]
    ++ if missing.isEmpty then [] else ["", s!"Not shown: {", ".intercalate missing}."]
  "\n".intercalate lines

end Consensus.Replay
