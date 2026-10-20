module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import CCFRaft.Model

public import CCFRaft.Model
public import CCFRaft.Tests.AppendTransactions
public import Mathlib.Data.Finset.Range

public section

namespace CCFRaft.Tests.CanonicalTests

open CCFRaft CCFRaft.Model.Node
open CCFRaft.Model (ModelConfig initialNodeState BOOTSTRAP_TERM)
open CCF.MultiNodeTransitionSystem (nodeState)

private def modelConfig : ModelConfig where
  configuration := Finset.range 5
  primary := ⟨0, by decide⟩

private abbrev State := Model.State
private abbrev Envelope := Model.Envelope

private def allNodes : List NodeID := List.range 15

private def system := Model.transitionSystem modelConfig allNodes

private def initial : State :=
  { nodes := allNodes.map fun node => (node, initialNodeState modelConfig node) }

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do
    throw (IO.userError message)

example (left right : NodeID) (leftMatch rightMatch leftIndex rightIndex : Nat)
    : (toLex (leftMatch, toLex (leftIndex, left))
        < toLex (rightMatch, toLex (rightIndex, right)))
      <-> (leftMatch < rightMatch
            \/ (leftMatch = rightMatch
                /\ (leftIndex < rightIndex
                    \/ (leftIndex = rightIndex /\ left < right)))) := by
  simp only [Prod.Lex.toLex_lt_toLex]

private def configurationQueries : IO Unit := do
  let empty : List Entry := []
  let initialHistory := configurationHistory empty
  check (initialHistory.isEmpty && configurationMembers initialHistory == ∅)
    "an empty log must not know any configuration or membership"
  check (latestConfigurationMembers ([] : List Configuration) == ∅)
    "an empty configuration list must have no latest members"
  check (latestConfigurationMembers initialHistory == ∅)
    "an empty log must have no latest membership"
  check (!decide (hasQuorum [] modelConfig.configuration))
    "votes must not form a quorum without a locally known configuration"
  let log : List Entry :=
    [
      {
        term := 1,
        content := .transaction 10 { configuration := some modelConfig.configuration }
      },
      { term := 1, content := .transaction 101 { configuration := some {0, 1} } },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 102 { configuration := some {1, 5} } },
      { term := 1, content := .transaction 103 { configuration := some {5} } },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 109 { retirementConfirmations := {0} } }
    ]
  check ((configurationHistory log).map (·.index) == [1, 2, 4, 5])
    "configuration indices must count intervening nonconfiguration entries"
  for (length, expected)
      in [
        (0, ∅),
        (1, modelConfig.configuration),
        (2, {0, 1}),
        (3, {0, 1}),
        (4, {1, 5}),
        (5, {5}),
        (7, {5})
      ] do
    check
      (latestConfigurationMembers (configurationHistory (log.take length)) == expected)
      s!"wrong latest membership in prefix {length}"
  for (commitIndex, expected)
      in [
        (0, [1, 2, 4, 5]),
        (1, [1, 2, 4, 5]),
        (2, [2, 4, 5]),
        (3, [2, 4, 5]),
        (4, [4, 5]),
        (5, [5]),
        (7, [5]),
        (10, [5])
      ] do
    check
      ((activeConfigurations log commitIndex).map (·.index) == expected)
      s!"wrong active configuration indices at commit index {commitIndex}"
  check
    (configurationMembers (activeConfigurations log 4) == {1, 5})
    "active membership must include pending configurations but exclude obsolete ones"
  for (length, commitIndex, expected)
      in [
        (0, 0, []),
        (1, 0, []),
        (2, 0, []),
        (3, 0, [1, 2]),
        (4, 0, [1, 2]),
        (5, 0, [1, 2]),
        (6, 0, [1, 2, 4, 5]),
        (5, 3, [2]),
        (6, 3, [2, 4, 5]),
        (6, 6, [5])
      ] do
    let state : NodeState :=
      {
        (initialNodeState modelConfig 0 : NodeState) with
          log := log.take length
          commitIndex
      }
    check
      (state.signedActiveConfigurations.map (·.index) == expected)
      s!"wrong signed active configurations at length {length}, commit {commitIndex}"
  for length in List.range (log.length + 1) do
    for commitIndex in List.range (length + 1) do
      for node in allNodes do
        for role in [Role.none, .follower, .preVoteCandidate, .candidate, .primary] do
          let state : NodeState :=
            {
              (initialNodeState modelConfig node : NodeState) with
                log := log.take length
                commitIndex
                role
            }
          let signedMembership :=
            state.activeConfigurations.any
              fun configuration =>
                decide
                  (node ∈ configuration.nodes
                    /\ configuration.index <= maxCommittableIndex state.log)
          let expected :=
            decide
              ((role = .follower \/ role = .preVoteCandidate \/ role = .candidate)
                /\ ((node ∈ state.activeMembers /\ signedMembership = true)
                    \/ node ∈ state.retirementCompletedNodes)
                /\ Not ((state.retirement node).phase = .retiredCommitted))
          check (decide (canStartElection state node) == expected)
            s!"election eligibility changed at length {length}, commit {commitIndex}"
  let tied : NodeState :=
    { (initialNodeState modelConfig 0 : NodeState) with log, commitIndex := 4 }
  check (decide ((5 : NodeID) ∈ eligiblePeers tied 0))
    "latest active membership must make a peer eligible for nomination"
  check (decide ((1 : NodeID) ∈ eligiblePeers tied 0))
    "older active membership must remain eligible for nomination"
  check (!decide ((0 : NodeID) ∈ eligiblePeers tied 0)) "a node cannot nominate itself"
  let ahead := { tied with matchIndex := Function.update tied.matchIndex 1 8 }
  check (eligiblePeers ahead 0 == eligiblePeers tied 0)
    "replication ranking must not restrict nomination eligibility"
  check (retirementIndexInLog (0 : NodeID) log == some 4)
    "retirement must start at the first removal after membership"
  check (retirementIndexInLog (5 : NodeID) log == none)
    "absence before joining must not count as retirement"
  for (commitIndex, expected)
      in [
        (0, (∅ : Finset NodeID)),
        (2, {2, 3, 4}),
        (4, {0, 2, 3, 4}),
        (5, {0, 1, 2, 3, 4}),
        (6, {0, 1, 2, 3, 4}),
        (7, {1, 2, 3, 4})
      ] do
    let state : NodeState :=
      { (initialNodeState modelConfig 0 : NodeState) with log, commitIndex }
    check (state.retirementCompletedNodes == expected)
      s!"wrong completed retirements at commit index {commitIndex}"
  let rejoined :=
    log
    ++ [{ term := 1, content := .transaction 104 { configuration := some {0, 1, 5} } }]
  check (retirementIndexInLog (0 : NodeID) rejoined == some 4)
    "rejoining must not change the first removal index"
  let rejoinedState : NodeState :=
    {
      (initialNodeState modelConfig 0 : NodeState) with
        log := rejoined
        commitIndex := 8
    }
  check (rejoinedState.retirementCompletedNodes == {2, 3, 4})
    "current members must not appear among completed retirements"
  let combined : List Entry :=
    [
      {
        term := 1,
        content :=
          .transaction 200 { configuration := some {1}, retirementConfirmations := {0} }
      },
      { term := 1, content := .signature }
    ]
  check ((configurationHistory combined).map (·.index) == [1])
    "a transaction must record at most one configuration at its log index"
  check (latestConfigurationMembers (configurationHistory combined) == {1})
    "the latest membership must be the transaction's resulting configuration"
  check
    ((activeConfigurations combined 0).map (·.nodes) == [{1}])
    "a transaction must add only its resulting configuration to active membership"
  check
    ((activeConfigurations combined 2).map (·.nodes) == [{1}])
    "committing a transaction must supersede the earlier configuration"
  check (retiredCommittedNodes combined == {0})
    "retirement metadata must coexist with a configuration at the same log index"
  check
    ((configurationHistory (combined.take 0)).isEmpty
      && retiredCommittedNodes (combined.take 0) == ∅)
    "rolling back a transaction must remove both metadata fields from log queries"
  let combinedState : NodeState :=
    { (initialNodeState modelConfig 0 : NodeState) with log := combined }
  check
    (combinedState.signedActiveConfigurations.map (·.nodes) == [{1}])
    "a signature must cover the transaction's pending configuration"
  let unsigned := { combinedState with log := combined.take 1 }
  check
    (unsigned.signedActiveConfigurations.isEmpty)
    "rolling back a signature must exclude unsigned pending configurations"
  let committed := { combinedState with commitIndex := 2 }
  check
    (committed.signedActiveConfigurations.map (·.nodes) == [{1}])
    "signed active configurations must exclude superseded configurations"
  for history in [log, rejoined, combined] do
    for length in List.range (history.length + 1) do
      for commitIndex in List.range (history.length + 3) do
        let state : NodeState :=
          { combinedState with log := history.take length, commitIndex }
        let committedHistory :=
          (configurationHistory state.log).filter
            fun configuration => configuration.index <= commitIndex
        let expected :=
          ((configurationMembers committedHistory
              \ latestConfigurationMembers committedHistory)
            \ retiredCommittedNodes state.committedLog).filter
            fun node =>
              (retirementIndexInLog node state.committedLog).isSome
        check (state.retirementCompletedNodes == expected)
          s!"completed retirements changed at length {length}, commit {commitIndex}"

private def retirementQueries : IO Unit := do
  for node in [(0 : NodeID), 6] do
    let state : NodeState := initialNodeState modelConfig node
    check ((state.retirement node).phase == .noRetirementObserved)
      "no observed retirement must cover both initial members and never-joined nodes"
    let state := { state with retiredCommittedIndex := some 0 }
    check (!decide (state.isRetiredCommitted node))
      "a retirement commit latch without a membership removal must not imply retirement"
  let log : List Entry :=
    [
      {
        term := 1,
        content := .transaction 100 { configuration := some modelConfig.configuration }
      },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 105 { configuration := some {1, 5} } },
      { term := 1, content := .transaction 3 {} },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 110 { retirementConfirmations := {0} } },
      { term := 1, content := .transaction 111 { retirementConfirmations := {1, 5} } },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 112 { retirementConfirmations := {0, 6} } }
    ]
  for entry in log do
    check (entry.content.isSignature == decide (entry.content = .signature))
      "signature classification must agree with the entry constructor"
  check
    ((firstLogIndexAfter ([] : List Entry) 0 EntryContent.isSignature).isNone)
    "an empty log must have no matching index"
  for afterIndex in List.range (log.length + 3) do
    let expected := if afterIndex < log.length then some (afterIndex + 1) else none
    check (firstLogIndexAfter log afterIndex (fun _ => true) == expected)
      s!"wrong one-based index after {afterIndex}"
  for (afterIndex, expected)
      in [
        (0, some 2),
        (1, some 2),
        (2, some 5),
        (4, some 5),
        (5, some 8),
        (8, none),
        (99, none)
      ] do
    check (firstLogIndexAfter log afterIndex EntryContent.isSignature == expected)
      s!"wrong first signature after {afterIndex}"
  let namesNode :=
    fun (content : EntryContent) =>
      decide ((0 : NodeID) ∈ content.metadata.retirementConfirmations)
  check (firstLogIndexAfter log 0 namesNode == some 6)
    "retirement lookup must select the first record naming the node"
  check (firstLogIndexAfter log 6 namesNode == some 9)
    "retirement lookup must exclude the supplied lower bound"
  let combined : List Entry :=
    [{
      term := 1
      content :=
        .transaction 113
          { configuration := some {0, 1}, retirementConfirmations := {0, 5} }
    }]
  check (retiredCommittedNodes combined == {0, 5})
    "retirement lookup must read the full recorded set alongside configuration metadata"
  for (length, expected)
      in [
        (0, (∅ : Finset NodeID)),
        (5, ∅),
        (6, {0}),
        (7, {0, 1, 5}),
        (8, {0, 1, 5}),
        (9, {0, 1, 5, 6}),
        (99, {0, 1, 5, 6})
      ] do
    check (retiredCommittedNodes (log.take length) == expected)
      s!"wrong recorded retirements in prefix {length}"
  for (length, commitIndex, phase)
      in [
        (2, 0, MembershipState.noRetirementObserved),
        (3, 0, .retirementOrdered),
        (4, 0, .retirementOrdered),
        (5, 0, .retirementSigned),
        (6, 5, .retirementCompleted),
        (7, 5, .retirementCompleted),
        (8, 8, .retiredCommitted)
      ] do
    let state :=
      NodeState.recordCommit (0 : NodeID)
        {
          (initialNodeState modelConfig 0 : NodeState) with
            log := log.take length
            commitIndex
        } commitIndex
    let retirement := state.retirement (0 : NodeID)
    check (retirement.phase == phase)
      s!"wrong retirement phase at length {length}, commit {commitIndex}"
    check
      (decide (state.isRetiredCommitted 0) == (phase == .retiredCommitted))
      "retired-committed classification must use the derived membership phase"
    check (retirement.index == if length < 3 then none else some 3)
      "retirement metadata must use the first membership removal"
    check (retirement.committableIndex == if length < 5 then none else some 5)
      "the signature before removal must not make retirement committable"
    check (state.retiredCommittedIndex == if commitIndex < 6 then none else some 6)
      "only committed confirmations may set the retirement transaction index"
  let rejoined :=
    log ++ [{ term := 1, content := .transaction 106 { configuration := some {0, 1} } }]
  let state : NodeState :=
    { (initialNodeState modelConfig 0 : NodeState) with log := log.take 5 }
  check ((state.retirement 0).phase == .retirementSigned)
    "a signature after removal must make retirement signed"
  let state := { state with log := state.log.take 3 }
  check ((state.retirement 0).phase == .retirementOrdered)
    "rolling back the signature must immediately restore ordered retirement"
  let state := { state with log := state.log.take 2 }
  check ((state.retirement 0).phase == .noRetirementObserved)
    "rolling back removal must clear the observed retirement"
  check (retirementIndexInLog (0 : NodeID) rejoined == some 3)
    "rejoining must preserve the first retirement index"
  check (retirementIndexInLog (5 : NodeID) rejoined == some 10)
    "a later join must precede the first retirement of a fresh node"
  check ((retirementIndexInLog (6 : NodeID) log).isNone)
    "a retirement record alone must not imply prior membership"

private def get (state : State) (node : NodeID) : NodeState :=
  (nodeState state node).getD (initialNodeState modelConfig node)

/-- Pending envelopes from `source` to `destination`, oldest first. -/
private def pending (state : State) (source destination : NodeID) : List Envelope :=
  state.network.filter
    fun envelope =>
      envelope.source == source && envelope.target == destination

private def apply (state : State) (action : Model.Action) : IO State :=
  match system.step state action with
  | some after => do
      check
        (allNodes.all
          fun node =>
            decide ((get state node).committedLog <+: (get after node).committedLog))
        "canonical action rolled back or rewrote a committed prefix"
      pure after
  | none => throw (IO.userError "expected canonical action to be enabled")

/-- Deliver the oldest pending envelope from `source` to `destination`. -/
private def receive (state : State) (source destination : NodeID) : IO State := do
  let some envelope := (pending state source destination).head?
  | throw (IO.userError "no pending envelope to receive")
  apply state (.deliver envelope)

private def ledgerLocalStartup : IO Unit := do
  let source : NodeID := 0
  let primary := get initial source
  check
    (primary.activeMembers == modelConfig.configuration
      && primary.signedActiveConfigurations.isEmpty)
    "the primary must know only its unsigned genesis configuration"
  for destination in ([1, 6] : List NodeID) do
    let fresh := get initial destination
    check
      (fresh.log.isEmpty
        && fresh.activeConfigurations.isEmpty
        && fresh.activeMembers == ∅
        && fresh.retirementCompletedNodes == ∅
        && !decide (canStartElection fresh destination))
      "empty-ledger nodes must not know membership or be eligible to campaign"
    check (system.step initial (.local destination (.timeout .election))).isNone
      "an empty-ledger election timeout must be disabled"
    let nomination : Envelope :=
      {
        source,
        target := destination,
        payload := .proposeRequestVoteRequest fresh.currentTerm
      }
    let nominated ← apply { initial with network := [nomination] } (.deliver nomination)
    check
      (nominated.network.isEmpty
        && (get nominated destination).role == fresh.role
        && (get nominated destination).currentTerm == fresh.currentTerm)
      "a same-term nomination must not enable an unconfigured node"
    let mut state := initial
    if destination == 6 then
      state ←
        apply state
          (.local source
            (.append
              [.transaction 400
                { configuration := some (modelConfig.configuration ∪ {destination}) }]))
      state ← receive state source destination
      state ← receive state destination source
    let unsignedLength := (get state source).log.length
    state ← apply state (.local source (.sendEntries destination unsignedLength))
    state ← receive state source destination
    state ← receive state destination source
    let configured := get state destination
    check
      (configured.log == (get state source).log
        && decide (destination ∈ configured.activeMembers)
        && configured.signedActiveConfigurations.isEmpty
        && !decide (canStartElection configured destination))
      "replication must install unsigned membership without enabling an election"
    state ← apply state (.local source (.append [.signature]))
    state ← apply state (.local source (.sendEntries destination (unsignedLength + 1)))
    state ← receive state source destination
    let configured := get state destination
    check
      (decide (canStartElection configured destination)
        && configured.role == .follower
        && state.nodes.map Prod.fst == initial.nodes.map Prod.fst)
      "a covering signature must enable campaigning without changing network population"
    state ← apply state (.local destination (.timeout .election))
    check
      ((get state destination).role == .preVoteCandidate
        && (get state destination).currentTerm == BOOTSTRAP_TERM)
      "a configured node must start pre-vote through its ordinary local step"
    let rolledBack := { configured with log := [] }
    check
      (rolledBack.activeMembers == ∅
        && rolledBack.signedActiveConfigurations.isEmpty
        && !decide (canStartElection rolledBack destination))
      "removing the local ledger must remove configuration knowledge"
  let unconfigured :=
    {
      primary with
        role := .candidate
        log :=
          [
            { term := BOOTSTRAP_TERM, content := .transaction 401 {} },
            { term := BOOTSTRAP_TERM, content := .signature }
          ]
        votesGranted := modelConfig.configuration
    }
  check (highestCommittableIndex unconfigured source == 0)
    "a signature without a configuration must not commit by a vacuous quorum"
  let some (unelected, effects) :=
    (electIfQuorum (CCF.Capabilities.record source) source unconfigured).run {}
  | throw (IO.userError "an unconfigured quorum check must be an enabled no-op")
  check (unelected.role == .candidate && effects.outgoing.isEmpty)
    "an unconfigured candidate must not promote by a vacuous quorum"

private def bootstrapAndNoMatchingPrefixTerms : IO Unit := do
  let source : NodeID := 0
  let destination : NodeID := 1
  let future : NodeID := 5
  check
    (BOOTSTRAP_TERM == 2
      && (get initial source).currentTerm == BOOTSTRAP_TERM
      && (get initial destination).currentTerm == BOOTSTRAP_TERM)
    "bootstrap primary and follower must start at implementation term 2"
  check
    ((get initial future).currentTerm == 0 && decide ((get initial future).role = .none))
    "nodes outside the bootstrap configuration must start fresh at term 0"
  check
    ((get initial source).log
        == [{
              term := BOOTSTRAP_TERM
              content :=
                .transaction 0 { configuration := some modelConfig.configuration }
            }]
      && (get initial destination).log.isEmpty
      && (get initial source).commitIndex == 0)
    "only the bootstrap primary starts with the configuration entry"
  let follower :=
    {
      get initial destination with
        log := [{ term := BOOTSTRAP_TERM, content := .transaction 1 {} }]
    }
  let request : AppendEntriesRequest :=
    {
      term := BOOTSTRAP_TERM
      prevLogIndex := 1
      prevLogTerm := 1
      entries := []
      primaryCommit := 0
    }
  check
    (findHighestPossibleMatch follower.log request.prevLogIndex request.prevLogTerm == 0)
    "conflicting prefix must have no possible matching index"
  let some (after, effects) :=
    (handleAppendEntriesRequest (CCF.Capabilities.record destination)
      destination source follower request).run
      {}
  | throw (IO.userError "conflicting prefix did not produce a response")
  let some { payload := .appendEntriesResponse response, .. } := effects.outgoing.head?
  | throw (IO.userError "conflicting prefix did not produce an AppendEntries response")
  check (!response.success && response.lastLogIndex == 0 && response.term == 0)
    "no matching prefix must produce a NACK with index 0 and term 0"
  check (after.currentTerm == BOOTSTRAP_TERM && after.log == follower.log)
    "no matching prefix NACK must preserve the follower's term and log"

private def nominationSelection : IO Unit := do
  let primary : NodeID := 0
  let caps :=
    CCF.Capabilities.record (Message := Message) (Notification := Notification) primary
  let before : NodeState :=
    {
      (initialNodeState modelConfig primary : NodeState) with
        log :=
          (initialNodeState modelConfig primary).log
          ++ [
            {
              term := BOOTSTRAP_TERM,
              content := .transaction 201 { configuration := some {1, 2} }
            },
            { term := BOOTSTRAP_TERM, content := .signature },
            {
              term := BOOTSTRAP_TERM,
              content := .transaction 202 { retirementConfirmations := {0, 3, 4} }
            },
            { term := BOOTSTRAP_TERM, content := .signature }
          ]
        matchIndex := fun _ => 5
    }
  let nominate state := (step caps primary state (.internal .nominateSuccessor)).run {}
  check (findSuccessor before primary == some 2)
    "latest active membership must outrank a larger node ID; full ties choose the highest ID"
  let ahead := { before with matchIndex := Function.update before.matchIndex 4 9 }
  check (findSuccessor ahead primary == some 4)
    "replication progress must outrank configuration membership"
  check (nominate { before with role := .follower }).isNone "a follower must not nominate"
  let some (nominated, outputs) := nominate ahead
  | throw (IO.userError "primary nomination must be enabled")
  check (nominated.log == ahead.log && nominated.commitIndex == ahead.commitIndex)
    "standalone nomination must preserve the primary's ledger state"
  check (outputs.outgoing.length == 1)
    "a primary nomination must send exactly one packet when an eligible peer exists"
  let some envelope := outputs.outgoing.head?
  | throw (IO.userError "nomination packet is missing")
  check
    (envelope.source == primary
      && envelope.target == 4
      && envelope.payload == .proposeRequestVoteRequest BOOTSTRAP_TERM)
    "standalone nomination must use the internally selected destination and current term"
  let some (retired, effects) := (advanceCommit caps ahead primary).run {}
  | throw (IO.userError "retirement commit must be enabled")
  check
    (retired.commitIndex == 5
      && retired.retiredCommittedIndex == some 4
      && retired.role == .none
      && !retired.primaryKnown
      && decide (retired.isRetiredCommitted primary))
    "retirement commit must record the transaction index and clear the primary role"
  check (!decide ((4 : NodeID) ∈ eligiblePeers retired primary))
    "retirement must prune the old peer after the atomic nomination"
  check (effects.outgoing.length == 1)
    "retirement commit must send exactly one nested nomination"
  let some envelope := effects.outgoing.head?
  | throw (IO.userError "retirement nomination packet is missing")
  check
    (envelope.source == primary
      && envelope.target == 4
      && envelope.payload == .proposeRequestVoteRequest BOOTSTRAP_TERM)
    "retirement nomination must use the precommit peer view and term"
  check (nominate retired).isNone "retired nonprimaries must not nominate after commit"
  let solo : ModelConfig := { configuration := {primary}, primary := ⟨primary, by simp⟩ }
  let alone : NodeState := initialNodeState solo primary
  check (findSuccessor alone primary == none)
    "a node must not nominate itself when no eligible peer exists"
  let some (_, soloEffects) :=
    (step caps primary alone (.internal .nominateSuccessor)).run {}
  | throw (IO.userError "a lone primary nomination must be an enabled no-op")
  check soloEffects.outgoing.isEmpty "a lone primary must not send a nomination"
  let numericConfig : ModelConfig :=
    { configuration := {0, 20, 2}, primary := ⟨0, by decide⟩ }
  let numeric := initialNodeState numericConfig 0
  check (findSuccessor numeric 0 == some 20)
    "node IDs must be unbounded natural numbers, ordered numerically"

private def appendCommitTriggers : IO Unit := do
  let primary : NodeID := 0
  let caps :=
    CCF.Capabilities.record (Message := Message) (Notification := Notification) primary
  let state : NodeState :=
    {
      (initialNodeState modelConfig primary : NodeState) with
        log :=
          [
            {
              term := BOOTSTRAP_TERM,
              content :=
                .transaction 301 { configuration := some modelConfig.configuration }
            },
            { term := BOOTSTRAP_TERM, content := .signature }
          ]
        commitIndex := 2
        matchIndex := fun _ => 2
    }
  let some (state, _) :=
    (appendBatch caps primary state [.signature]).run {}
  | throw (IO.userError "multinode append must be enabled")
  check (state.log.length == 3 && state.commitIndex == 2)
    "previous acknowledgements must not commit a newly appended signature"
  let appendedState := state
  let some (state, _) :=
    (handleAppendEntriesResponse caps primary state 1
      { term := BOOTSTRAP_TERM, success := true, lastLogIndex := 3 }).run
      {}
  | throw (IO.userError "first acknowledgement must be enabled")
  check (state.commitIndex == 2)
    "one other acknowledgement must not commit without the five-node majority"
  let some (state, _) :=
    (handleAppendEntriesResponse caps primary state 2
      { term := BOOTSTRAP_TERM, success := true, lastLogIndex := 3 }).run
      {}
  | throw (IO.userError "quorum acknowledgement must be enabled")
  check (state.commitIndex == 3)
    "the current-term signature must commit when its acknowledgements reach a quorum"
  let state := { appendedState with matchIndex := fun _ => 3, role := .candidate }
  let some (state, _) := (becomePrimary caps primary state).run {}
  | throw (IO.userError "primary promotion must be enabled")
  check (state.commitIndex == 2 && state.matchIndex 1 == 0)
    "promotion must reset stale peer progress before attempting commit"

private def commitQuorumAtSignature : IO Unit := do
  let primary : NodeID := 0
  let caps := CCF.Capabilities.record primary
  let config : ModelConfig :=
    { configuration := {0, 1, 2}, primary := ⟨primary, by decide⟩ }
  let state := initialNodeState config primary
  let some (state, _) := (appendBatch caps primary state [.signature]).run {}
  | throw (IO.userError "the old configuration's signature must append")
  let some (state, _) :=
    (appendBatch caps primary state
      [.transaction 302 { configuration := some {0, 1, 2, 3, 4} }, .signature]).run
      {}
  | throw (IO.userError "the pending configuration and its signature must append")
  let some (state, _) :=
    (handleAppendEntriesResponse caps primary state 1
      { term := BOOTSTRAP_TERM, success := true, lastLogIndex := 4 }).run
      {}
  | throw (IO.userError "the old-configuration quorum acknowledgement must be enabled")
  check (state.commitIndex == 2)
    "a later pending configuration must not block an earlier signature's quorum"
  check (highestCommittableIndex state primary == 0)
    "the signature after the new configuration must require its majority too"
  check (!decide (hasQuorum state.activeConfigurations {primary, 1}))
    "elections must still require a majority in every active configuration"
  let some (state, _) :=
    (handleAppendEntriesResponse caps primary state 3
      { term := BOOTSTRAP_TERM, success := true, lastLogIndex := 4 }).run
      {}
  | throw (IO.userError "the new-configuration quorum acknowledgement must be enabled")
  check (state.commitIndex == 4)
    "both configuration majorities must commit the later signature"
  check (state.activeConfigurations.map (·.index) == [3])
    "committing the new configuration must discard the obsolete quorum requirement"

private def nominationTerms : IO Unit := do
  let source : NodeID := 0
  let destination : NodeID := 1
  let configured ← apply initial (.local source (.append [.signature]))
  let configured ← apply configured (.local source (.sendEntries destination 2))
  let configured ← receive configured source destination
  let configured ← receive configured destination source
  for term in [0, 1, BOOTSTRAP_TERM + 1] do
    let nomination : Envelope :=
      { source, target := destination, payload := .proposeRequestVoteRequest term }
    let state := { configured with network := [nomination] }
    let after ← apply state (.deliver nomination)
    check after.network.isEmpty s!"nomination term {term}: message was not consumed"
    check ((get after destination).currentTerm == (get state destination).currentTerm)
      s!"nomination term {term}: current term changed"
    check (decide ((get after destination).role = (get state destination).role))
      s!"nomination term {term}: role changed"
  let nomination : Envelope :=
    {
      source, target := destination, payload := .proposeRequestVoteRequest BOOTSTRAP_TERM
    }
  let after ← apply { configured with network := [nomination] } (.deliver nomination)
  check (decide ((get after destination).role = .candidate))
    "same-term nomination: eligible follower did not become candidate"
  check ((get after destination).currentTerm == BOOTSTRAP_TERM + 1)
    "same-term nomination: election did not increment the term"
  let vote : Envelope :=
    {
      source,
      target := destination
      payload :=
        .requestVoteRequest
          {
            makeRequestVoteRequest (get configured source) with
              term := BOOTSTRAP_TERM + 1
          }
    }
  let after ← apply { configured with network := [vote] } (.deliver vote)
  check ((get after destination).currentTerm == BOOTSTRAP_TERM + 1)
    "newer vote request: current term did not advance"
  check (decide ((get after destination).votedFor = some source))
    "newer vote request: the vote was not granted in the new term"
  let some { payload := .requestVoteResponse response, .. } := after.network.head?
  | throw (IO.userError "newer vote request: no vote response")
  check (response.voteGranted && response.term == BOOTSTRAP_TERM + 1)
    "newer vote request: the response does not grant the vote in the new term"

private def appendEntriesResponseTerms : IO Unit := do
  let primary : NodeID := 0
  let follower : NodeID := 1
  let response : AppendEntriesResponse :=
    { term := 5, success := false, lastLogIndex := 0 }
  let toFollower : Envelope :=
    { source := primary, target := follower, payload := .appendEntriesResponse response }
  let after ← apply { initial with network := [toFollower] } (.deliver toFollower)
  check ((get after follower).currentTerm == BOOTSTRAP_TERM && after.network.isEmpty)
    "a non-primary must ignore an AppendEntries response, including its term"
  let toPrimary : Envelope :=
    { source := follower, target := primary, payload := .appendEntriesResponse response }
  let after ← apply { initial with network := [toPrimary] } (.deliver toPrimary)
  check
    ((get after primary).currentTerm == 5
      && decide ((get after primary).role = .follower))
    "a primary must adopt a newer AppendEntries response term as a follower"

example (caps : Caps) (self source : NodeID) (state : NodeState)
    (response : AppendEntriesResponse) (unknown : source ∉ eligiblePeers state self)
    : Model.Node.receive caps self source state (.appendEntriesResponse response)
      = pure state := by
  simp [Model.Node.receive, unknown]

example (caps : Caps) (self source : NodeID) (state : NodeState)
    (response : RequestVoteResponse) (unknown : source ∉ eligiblePeers state self)
    : Model.Node.receive caps self source state (.requestVoteResponse response)
      = pure state := by
  simp [Model.Node.receive, unknown]

example (caps : Caps) (self source : NodeID) (state : NodeState)
    (response : RequestVoteResponse) (unknown : source ∉ eligiblePeers state self)
    : Model.Node.receive caps self source state (.requestPreVoteResponse response)
      = pure state := by
  simp [Model.Node.receive, unknown]

private def appendEntriesZeroPrefix : IO Unit := do
  for node in [0, 1] do
    let state := initialNodeState modelConfig node
    for previousTerm in [0, 1, BOOTSTRAP_TERM] do
      let request : AppendEntriesRequest :=
        {
          term := BOOTSTRAP_TERM
          prevLogIndex := 0
          prevLogTerm := previousTerm
          entries := []
          primaryCommit := 0
        }
      check (decide (appendEntryMatchesLog state request) == (previousTerm == 0))
        "index zero must match only previous term zero, regardless of the local log"
      let some (received, effects) :=
        (Model.Node.receive (CCF.Capabilities.record node) node 10 state
          (.appendEntriesRequest request)).run
          {}
      | throw (IO.userError "a zero-prefix request must remain receivable")
      let some { payload := .appendEntriesResponse response, .. } :=
        effects.outgoing.head?
      | throw (IO.userError "a zero-prefix request must receive a response")
      check
        (effects.outgoing.length == 1
          && response.success == (previousTerm == 0)
          && received.log == state.log
          && received.commitIndex == state.commitIndex)
        "a nonzero previous term at index zero must be rejected without changing the log"

private def retiredSendBoundary : IO Unit := do
  let self : NodeID := 0
  let state : NodeState :=
    {
      (initialNodeState modelConfig self) with
        log :=
          [
            {
              term := BOOTSTRAP_TERM,
              content := .transaction 0 { configuration := some {0, 1} }
            },
            {
              term := BOOTSTRAP_TERM,
              content := .transaction 1 { configuration := some {1} }
            },
            { term := BOOTSTRAP_TERM, content := .signature },
            {
              term := BOOTSTRAP_TERM,
              content := .transaction 2 { retirementConfirmations := {0} }
            },
            { term := BOOTSTRAP_TERM, content := .signature }
          ]
        commitIndex := 5
        sentIndex := fun _ => 3
    }
  for retired in [false, true] do
    let state := { state with retiredCommittedIndex := if retired then some 4 else none }
    check (decide (state.isRetiredCommitted self) == retired)
      "the send-boundary fixture must distinguish final retirement"
    for endIndex in [3, 4, 5] do
      let result :=
        (sendEntries (CCF.Capabilities.record self) self state 1 endIndex).run {}
      let shouldSend := !retired || endIndex > 4
      check (result.isSome == shouldSend)
        "final retirement must suppress both empty and single-entry ranges, like C++"
      if let some (received, effects) := result then
        let some { payload := .appendEntriesRequest request, .. } :=
          effects.outgoing.head?
        | throw (IO.userError "an enabled range must send AppendEntries")
        check
          (effects.outgoing.length == 1
            && request.entries.length == endIndex - 3
            && received.sentIndex 1 == endIndex)
          "an allowed range must send all selected entries and update the frontier"

private def responseAdmission : IO Unit := do
  let self : NodeID := 0
  for role in [Role.follower, .preVoteCandidate, .candidate, .primary] do
    for source in [1, 10] do
      for term in [1, BOOTSTRAP_TERM, BOOTSTRAP_TERM + 1] do
        let state : NodeState :=
          {
            (initialNodeState modelConfig self) with
              role
              votedFor := some self
              primaryKnown := true
              votesGranted := {self}
              preVotesGranted := {self}
          }
        let messages : List Message :=
          [
            .appendEntriesResponse { term, success := false, lastLogIndex := 0 },
            .requestVoteResponse { term, voteGranted := false },
            .requestPreVoteResponse { term, voteGranted := false }
          ]
        for message in messages do
          let some (received, effects) :=
            (Model.Node.receive (CCF.Capabilities.record self) self source state
              message).run
              {}
          | throw (IO.userError "a discarded response must not disable receipt")
          let readsTerm :=
            source == 1
            && (match message with
                | .appendEntriesResponse _ => role == .primary
                | _ => true)
          let advancesTerm := readsTerm && term > state.currentTerm
          check
            (received.currentTerm
                == (if readsTerm then max term state.currentTerm else state.currentTerm)
              && received.role == (if advancesTerm then .follower else role)
              && received.votedFor == (if advancesTerm then none else state.votedFor)
              && received.primaryKnown
                  == (if advancesTerm then false else state.primaryKnown)
              && received.votesGranted == (if advancesTerm then ∅ else state.votesGranted)
              && received.preVotesGranted
                  == (if advancesTerm then ∅ else state.preVotesGranted)
              && received.log == state.log
              && received.commitIndex == state.commitIndex
              && effects.outgoing.isEmpty)
            "response admission must precede term adoption without filtering known peers"
  let state := initialNodeState modelConfig self
  let vote : RequestVoteRequest :=
    { term := state.currentTerm + 1, lastCommittableTerm := 0, lastCommittableIndex := 0 }
  let requests : List Message :=
    [
      .appendEntriesRequest
        {
          term := vote.term,
          prevLogIndex := 0,
          prevLogTerm := 0,
          entries := [],
          primaryCommit := 0
        },
      .requestVoteRequest vote,
      .requestPreVoteRequest vote
    ]
  for request in requests do
    let some (received, effects) :=
      (Model.Node.receive (CCF.Capabilities.record self) self 10 state request).run {}
    | throw (IO.userError "an unknown sender's request must remain receivable")
    check (received.currentTerm == vote.term && effects.outgoing.length == 1)
      "unknown requests must still advance the term and receive a response"
  let state : NodeState :=
    {
      state with
        log :=
          state.log
          ++ [
            {
              term := state.currentTerm,
              content := .transaction 1 { configuration := some {self} }
            },
            { term := state.currentTerm, content := .signature }
          ]
        commitIndex := 3
    }
  check (decide (1 ∉ state.activeMembers /\ 1 ∈ state.retirementCompletedNodes))
    "response admission fixture must distinguish completed retirement from active membership"
  for response
      in [
        Message.appendEntriesResponse
          { term := vote.term, success := false, lastLogIndex := 0 },
        .requestVoteResponse { term := vote.term, voteGranted := false },
        .requestPreVoteResponse { term := vote.term, voteGranted := false }
      ] do
    let some (received, _) :=
      (Model.Node.receive (CCF.Capabilities.record self) self 1 state response).run {}
    | throw (IO.userError "a completed-retirement peer response must remain receivable")
    check (received.currentTerm == vote.term)
      "response admission must not be restricted to active configuration members"

private def batches : IO Unit := do
  let source : NodeID := 0
  let destination : NodeID := 1
  check (system.step initial (.local source (.append []))).isNone
    "an empty append batch must be disabled"
  check (system.step initial (.local destination (.append [.signature]))).isNone
    "a follower must not append"
  let written ←
    apply initial
      (.local source (.append [.transaction 1 {}, .transaction 2 {}, .signature]))
  check ((get written source).log.length == 4)
    s!"an append batch must append every entry in one step (length {(get written source).log.length})"
  check (system.step written (.local source (.sendEntries destination 5))).isNone
    "batch past the log must be disabled"
  let sent ← apply written (.local source (.sendEntries destination 4))
  check ((pending sent source destination).length == 1)
    "a batch must produce exactly one packet"
  let some { payload := .appendEntriesRequest packet, .. } := sent.network.head?
  | throw (IO.userError "batch did not produce AppendEntries")
  check (packet.entries.length == 4 && packet.prevLogIndex == 0)
    "batch did not snapshot the full requested range"
  let heartbeat ← apply sent (.local source (.sendEntries destination 4))
  let some { payload := .appendEntriesRequest empty, .. } := heartbeat.network.getLast?
  | throw (IO.userError "heartbeat did not produce AppendEntries")
  check (empty.entries.isEmpty && empty.prevLogIndex == 4)
    "heartbeat must be one empty packet at the sent frontier"
  check (system.step sent (.local source (.sendEntries destination 2))).isNone
    "batch cannot move the sent frontier backwards"
  let delivered ← receive sent source destination
  check ((get delivered destination).log.length == 4)
    "receiving a batch must apply all entries atomically"
  let mixedNode :=
    {
      get written source with
        log :=
          [
            { term := 1, content := .transaction 1 {} },
            { term := 2, content := .transaction 2 {} }
          ]
    }
  let mixed :=
    {
      written with
        nodes :=
          written.nodes.map
            fun (entry : NodeID × NodeState) =>
              if entry.1 == source then (source, mixedNode) else entry
    }
  check (system.step mixed (.local source (.sendEntries destination 2))).isNone
    "native AppendEntries batches cannot span terms"

private def overlappingAppendEntries : IO Unit := do
  let node : NodeID := 1
  let matching : Entry := { term := 4, content := .transaction 3 {} }
  let replacement : Entry := { term := 4, content := .transaction 40 {} }
  let before : NodeState :=
    {
      (initialNodeState modelConfig node : NodeState) with
        currentTerm := 6
        log :=
          [
            { term := 2, content := .transaction 1 {} },
            { term := 2, content := .signature },
            matching,
            { term := 5, content := .transaction 4 {} },
            { term := 5, content := .signature }
          ]
        commitIndex := 2
        isNewFollower := true
    }
  let request : AppendEntriesRequest :=
    {
      term := 6
      prevLogIndex := 2
      prevLogTerm := 2
      entries := [{ matching with content := .transaction 30 {} }, replacement]
      primaryCommit := 2
    }
  for (entries, expectedIndex)
      in [
        ([], none),
        ([matching], none),
        (request.entries, some 4),
        ([{ matching with term := 6 }, { replacement with term := 6 }], some 3),
        ([matching, { replacement with term := 6 }], some 4)
      ] do
    check (firstTermConflictIndex before { request with entries } == expectedIndex)
      "term-conflict lookup must return the first conflicting one-based index"
  let fromStart := { request with prevLogIndex := 0, prevLogTerm := 0 }
  check (firstTermConflictIndex before fromStart == some 1)
    "term-conflict lookup must count the first log entry as index one"
  let extension : AppendEntriesRequest :=
    { request with prevLogIndex := 5, prevLogTerm := 5, entries := [replacement] }
  check (firstTermConflictIndex before extension == none)
    "an entry beyond the local log is an extension, not a conflict"
  for isNewFollower in [true, false] do
    let state := { before with isNewFollower }
    let matchingRequest := { request with entries := [matching] }
    let some (after, effects) :=
      (handleAppendEntriesRequest (CCF.Capabilities.record node)
        node 0 state matchingRequest).run
        {}
    | throw (IO.userError "a matching batch must be handled")
    check
      (after.log == before.log
        && after.isNewFollower == isNewFollower
        && effects.outgoing.length == 1)
      "a matching batch must retain the local suffix and new-follower status"
  for isNewFollower in [true, false] do
    let state := { before with isNewFollower }
    let some (after, effects) :=
      (handleAppendEntriesRequest (CCF.Capabilities.record node) node 0 state request).run
        {}
    | throw (IO.userError "an overlapping batch must be handled")
    if isNewFollower then
      check (after.log == before.log.take 3 ++ [replacement])
        "rollback must retain term-matching entries, not replace them with incoming payloads"
      check (after.commitIndex == 2 && !after.isNewFollower)
        "conflict resolution must preserve commitment and consume new-follower status"
      let some { payload := .appendEntriesResponse response, .. } :=
        effects.outgoing.head?
      | throw (IO.userError "conflict resolution must acknowledge the batch")
      check
        (effects.outgoing.length == 1 && response.success && response.lastLogIndex == 4)
        "conflict resolution must acknowledge the request's end index"
    else
      check
        (after.log == before.log && after.commitIndex == 2 && effects.outgoing.isEmpty)
        "an established follower must ignore conflicting entries without rollback"
  let committed := { before with commitIndex := 5 }
  let some (after, effects) :=
    (handleAppendEntriesRequest (CCF.Capabilities.record node)
      node 0 committed request).run
      {}
  | throw (IO.userError "a batch preceding commitment must be handled")
  check
    (after.log == committed.log
      && after.commitIndex == 5
      && after.isNewFollower
      && effects.outgoing.isEmpty)
    "an overlapping batch must not roll back a committed prefix"

private def reorderedDelivery : IO Unit := do
  let source : NodeID := 0
  let destination : NodeID := 1
  let state ← apply initial (.local source (.append [.transaction 1 {}]))
  let state ← apply state (.local source (.append [.signature]))
  let state ← apply state (.local source (.sendEntries destination 2))
  let state ← apply state (.local source (.sendEntries destination 2))
  let some heartbeat := (pending state source destination)[1]?
  | throw (IO.userError "missing second AppendEntries")
  let beforeDeliveryState := state
  let state ← apply state (.deliver heartbeat)
  check
    ((pending state source destination).length == 1
      && (get state destination).log.isEmpty)
    "a later envelope may be delivered first, leaving the earlier one pending"
  let some { payload := .appendEntriesResponse response, .. } :=
    (pending state destination source).head?
  | throw (IO.userError "reordered heartbeat did not produce a response")
  check (!response.success && response.lastLogIndex == 0)
    "a heartbeat past the follower log must be NACKed"
  check
    (system.step beforeDeliveryState
      (.deliver { heartbeat with target := source })).isNone
    "an envelope that is not pending cannot be delivered"

private def singleNodePreVote : IO Unit := do
  let config : ModelConfig := { configuration := {0}, primary := ⟨0, by decide⟩ }
  let some (state, _) :=
    (appendBatch (CCF.Capabilities.record 0) 0 (initialNodeState config 0)
      [.signature]).run
      {}
  | throw (IO.userError "a single-node primary must sign its initial configuration")
  let state := { state with role := .follower, primaryKnown := false }
  let some (elected, effects) :=
    (step (CCF.Capabilities.record 0) 0 state (.internal (.timeout .election))).run {}
  | throw (IO.userError "a single-node election must be enabled")
  check
    (decide (elected.role = .primary)
      && elected.currentTerm == BOOTSTRAP_TERM + 1
      && elected.votedFor == some 0
      && elected.votesGranted == {0}
      && elected.preVotesGranted == ∅
      && effects.outgoing.isEmpty)
    "self pre-vote and vote quorums must elect a single node without messages"

private def committedPrefixSurvivesTruncation : IO Unit := do
  let original : NodeID := 0
  let successor : NodeID := 1
  let second : NodeID := 2
  let mut state := initial
  state ← apply state (.local original (.append [.signature]))
  for peer in [successor, second] do
    state ← apply state (.local original (.sendEntries peer 2))
    state ← receive state original peer
    state ← receive state peer original
  let committed := (get state original).committedLog
  check (committed.length == 2) "truncation test requires a nonempty committed prefix"
  state ← apply state (.local original (.append [.transaction 10 {}]))
  state ← apply state (.local original (.sendEntries successor 3))
  state ← receive state original successor
  state ← receive state successor original
  check ((get state successor).commitIndex == 2 && (get state successor).log.length == 3)
    "successor must have a committed prefix and an uncommitted suffix"
  state ← apply state (.local successor (.timeout .election))
  check
    (decide ((get state successor).role = .preVoteCandidate)
      && (get state successor).currentTerm == BOOTSTRAP_TERM)
    "an election timeout must start pre-vote without advancing the term"
  for voter in [original, second] do
    state ← receive state successor voter
    state ← receive state voter successor
  check
    (decide ((get state successor).role = .candidate)
      && (get state successor).currentTerm == BOOTSTRAP_TERM + 1)
    "a pre-vote quorum must start the regular election and advance the term once"
  for voter in [original, second] do
    state ← receive state successor voter
    state ← receive state voter successor
  check (decide ((get state successor).role = .primary))
    "a vote quorum must promote the candidate inside the receive"
  check
    ((get state successor).log == committed
      && (get state successor).committedLog == committed)
    "promotion must truncate only the uncommitted suffix"
  -- Promotion sends an empty heartbeat to every peer inside the receive.
  for peer in [original, second] do
    state ← receive state successor peer
    state ← receive state peer successor
  state ← apply state (.local successor (.append [.transaction 20 {}]))
  state ← apply state (.local successor (.append [.signature]))
  for peer in [original, second] do
    state ← apply state (.local successor (.sendEntries peer 4))
    state ← receive state successor peer
    state ← receive state peer successor
  check
    ((get state original).committedLog == committed
      && entryAt? (get state original).log 3
          == some { term := BOOTSTRAP_TERM + 1, content := .transaction 20 {} })
    "conflict resolution must replace the uncommitted entry, not the committed prefix"
  state ← apply state (.local successor (.sendEntries original 4))
  state ← receive state successor original
  check
    ((get state original).commitIndex == 4
      && decide (committed <+: (get state original).committedLog))
    "the retained prefix must extend when the replacement suffix commits"

private def committedPrimaryCanHeartbeatBehindCommit : IO Unit := do
  let source : NodeID := 0
  let laggard : NodeID := 3
  let mut state := initial
  state ← apply state (.local source (.append [.signature]))
  for peer in ([1, 2] : List NodeID) do
    state ← apply state (.local source (.sendEntries peer 2))
    state ← receive state source peer
    state ← receive state peer source
  check ((get state source).commitIndex == 2)
    "primary should have quorum-committed the bootstrap signature"
  state ← apply state (.local source (.sendEntries laggard 0))
  let some { payload := .appendEntriesRequest heartbeat, .. } :=
    (pending state source laggard).head?
  | throw (IO.userError "missing lagging heartbeat")
  check
    (heartbeat.entries.isEmpty
      && heartbeat.prevLogIndex == 0
      && heartbeat.primaryCommit == 2)
    "empty heartbeat may advertise a commit beyond its verified frontier"
  state ← receive state source laggard
  check ((get state laggard).commitIndex == 0)
    "a lagging heartbeat must not commit an unverified prefix"

private def networkSnapshots : IO Unit := do
  let started ← IO.monoMsNow
  let source : NodeID := 0
  let left : NodeID := 1
  let right : NodeID := 2
  let count := 64
  let mut state := initial
  for _ in [:count] do
    state ← apply state (.local source (.sendEntries left 0))
    state ← apply state (.local source (.sendEntries right 0))
  check
    ((pending state source left).length == count
      && (pending state source right).length == count
      && state.network.length == 2 * count)
    "alternating sends changed queue multiplicity"
  for _ in [:count] do
    state ← receive state source left
    state ← receive state source right
  check
    ((pending state left source).length == count
      && (pending state right source).length == count
      && state.network.length == 2 * count)
    "alternating replies changed queue multiplicity"
  for _ in [:count] do
    state ← receive state left source
    state ← receive state right source
  check (state.network.isEmpty && initial.network.isEmpty)
    "network snapshots were not independent"
  check ((← IO.monoMsNow) - started < 5000)
    "network snapshot regression: 384 simple transitions took over five seconds"

private def repliesAfterStepDown : IO Unit := do
  let source : NodeID := 0
  let destination : NodeID := 1
  let mut state := initial
  state ← apply state (.local source (.append [.signature]))
  state ← apply state (.local source (.sendEntries destination 2))
  state ← receive state source destination
  state ← receive state destination source
  for transaction in [:6] do
    state ← apply state (.local source (.append [.transaction transaction {}]))
  state ← apply state (.local source (.sendEntries destination 8))
  state ← apply state (.local source (.sendEntries destination 8))
  let sent := state
  state ← apply state (.local destination (.timeout .election))
  for voter in ([2, 3] : List NodeID) do
    state ← receive state destination voter
    state ← receive state voter destination
  state ← receive state destination source
  state ← receive state source destination
  state ← receive state source destination
  -- The pre-vote quorum queued the regular vote request before either NACK.
  state ← receive state destination source
  check (decide ((get state source).role = .follower))
    "newer-term vote request did not demote the old primary"
  for remaining in [1, 0] do
    state ← receive state destination source
    check
      ((get state source).sentIndex destination == 8
        && (get state source).matchIndex destination == 2
        && (get state source).log.length == 8
        && (pending state destination source).length == remaining)
      "late NACK changed a non-primary's cursor or was not consumed exactly once"
  let some heartbeat := (pending sent source destination)[1]?
  | throw (IO.userError "missing heartbeat")
  let mut primary ← apply sent (.deliver heartbeat)
  primary ← receive primary destination source
  check
    (decide ((get primary source).role = .primary)
      && (get primary source).sentIndex destination == 2
      && (get primary source).matchIndex destination == 2)
    "current primary must still rewind its sent cursor after a NACK"

private def retirementConfirmationIndices : IO Unit := do
  let node : NodeID := 0
  let survivor : NodeID := 1
  let log : List Entry :=
    [
      {
        term := 1, content := .transaction 107 { configuration := some {node, survivor} }
      },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 108 { configuration := some {survivor} } },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 113 { retirementConfirmations := {node} } },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 7 {} },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 9 {} },
      { term := 1, content := .signature }
    ]
  let before : NodeState :=
    {
      (initialNodeState modelConfig node : NodeState) with
        role := .follower
        currentTerm := 1
        log := log.take 5
        commitIndex := 4
        primaryKnown := true
    }
  check ((before.recordCommit node 4).retiredCommittedIndex.isNone)
    "an uncommitted retirement confirmation must not set the transaction index"
  let state := ({ before with log := log.take 8 } : NodeState).recordCommit node 8
  check (state.retiredCommittedIndex == some 5)
    "retirement must record the confirmation transaction index, not a signature frontier"
  let state := ({ state with log } : NodeState).recordCommit node 10
  check (state.retiredCommittedIndex == some 5)
    "later commits must preserve the confirmation transaction index"
  for (
        oldLength,
        previousIndex,
        endIndex,
        primaryCommit,
        expectedCommit,
        expectedRetirement
      )
      in [
        (4, 4, 8, 8, 8, some 5),
        (5, 5, 8, 8, 8, some 5),
        (6, 6, 8, 8, 8, some 5),
        (5, 5, 10, 10, 10, some 5),
        (6, 6, 10, 10, 10, some 5),
        (8, 8, 10, 10, 10, some 5),
        (5, 5, 5, 8, 4, none),
        (6, 6, 6, 8, 6, some 5),
        (8, 8, 8, 8, 8, some 5),
        (6, 6, 7, 8, 6, some 5),
        (5, 5, 8, 7, 6, some 5),
        (6, 6, 8, 7, 6, some 5),
        (5, 5, 10, 5, 4, none),
        (5, 5, 10, 3, 4, none),
        (6, 4, 8, 8, 8, some 5),
        (8, 4, 10, 10, 10, some 5),
        (8, 5, 6, 10, 6, some 5)
      ] do
    let state := { before with log := log.take oldLength }
    let request : AppendEntriesRequest :=
      {
        term := 1
        prevLogIndex := previousIndex
        prevLogTerm := 1
        entries := (log.take endIndex).drop previousIndex
        primaryCommit
      }
    let some (received, effects) :=
      (handleAppendEntriesRequest (CCF.Capabilities.record node)
        node node state request).run
        {}
    | throw (IO.userError "retirement batch was not answered")
    let some { payload := .appendEntriesResponse response, .. } := effects.outgoing.head?
    | throw (IO.userError "retirement batch did not produce an AppendEntries response")
    check
      (effects.outgoing.length == 1
        && response.success
        && response.term == state.currentTerm
        && response.lastLogIndex == endIndex)
      "a received batch must produce one acknowledgement for the original request"
    check (received.log == log.take (max oldLength endIndex))
      "received entries must extend only the missing suffix"
    check
      (received.commitIndex == expectedCommit
        && received.retiredCommittedIndex == expectedRetirement)
      s!"batch from {oldLength}, previous {previousIndex}, end {endIndex}, commit {primaryCommit}: wrong commit or confirmation index"
    if expectedRetirement.isSome then
      check (received.role == .none && !received.primaryKnown)
        "committing a follower's retirement confirmation must clear role and primary knowledge"
    else
      check (received.role == .follower && received.primaryKnown)
        "an uncommitted retirement confirmation must not clear role or primary knowledge"
    let some (voted, voteEffects) :=
      (Model.Node.receive (CCF.Capabilities.record node) node survivor received
        (.requestVoteRequest (makeRequestVoteRequest received))).run
        {}
    | throw (IO.userError "a retired follower must still handle vote requests")
    let some { payload := .requestVoteResponse vote, .. } := voteEffects.outgoing.head?
    | throw (IO.userError "the follower must answer the vote request")
    check
      (voteEffects.outgoing.length == 1
        && vote.voteGranted == expectedRetirement.isSome
        && voted.votedFor == if expectedRetirement.isSome then some survivor else none)
      "the same-term vote must use primary knowledge after the retirement commit hook"
    if expectedRetirement.isSome then
      let heartbeat : AppendEntriesRequest :=
        {
          term := received.currentTerm + 1
          prevLogIndex := received.log.length
          prevLogTerm := termAt received.log received.log.length
          entries := []
          primaryCommit := received.commitIndex
        }
      let some (later, _) :=
        (Model.Node.receive (CCF.Capabilities.record node) node survivor received
          (.appendEntriesRequest heartbeat)).run
          {}
      | throw (IO.userError "a retired node must still handle higher-term AppendEntries")
      check
        (later.role == .follower
          && later.primaryKnown
          && later.currentTerm == heartbeat.term
          && later.retiredCommittedIndex == expectedRetirement)
        "final retirement must clear role once, not force later states to remain role-less"

private def appendEntriesStepDown : IO Unit := do
  for role in [Role.none, .follower, .preVoteCandidate, .candidate, .primary] do
    for term in [5, 6, 7] do
      for prefixMatches in [false, true] do
        let state : NodeState :=
          {
            (initialNodeState modelConfig 1) with
              role
              currentTerm := 6
              votedFor := some 1
              primaryKnown := true
              votesGranted := {1, 2}
              preVotesGranted := {1, 3}
              isNewFollower := false
          }
        let request : AppendEntriesRequest :=
          {
            term
            prevLogIndex := if prefixMatches then 0 else 1
            prevLogTerm := 0
            entries := []
            primaryCommit := 0
          }
        let some (received, effects) :=
          (Model.Node.receive (CCF.Capabilities.record 1) 1 0 state
            (.appendEntriesRequest request)).run
            {}
        | throw (IO.userError "AppendEntries step-down must not disable receipt")
        let stepsDown :=
          term > state.currentTerm
          || (term == state.currentTerm
              && (role == .candidate || role == .preVoteCandidate))
        check
          (received.role == (if stepsDown then .follower else role)
            && received.currentTerm == max term state.currentTerm
            && received.votedFor == (if term > state.currentTerm then none else some 1)
            && received.votesGranted == (if stepsDown then ∅ else state.votesGranted)
            && received.preVotesGranted
                == (if stepsDown then ∅ else state.preVotesGranted)
            && received.isNewFollower == stepsDown
            && received.primaryKnown
                == (if term >= state.currentTerm && prefixMatches then
                      true
                    else
                      !stepsDown))
          s!"AppendEntries step-down state mismatch: term {term}, prefix {prefixMatches}"
        check (received.log == state.log && received.commitIndex == state.commitIndex)
          "an empty AppendEntries must preserve the empty log and commit index"
        let some { payload := .appendEntriesResponse response, .. } :=
          effects.outgoing.head?
        | throw (IO.userError "AppendEntries step-down must send a response")
        check
          (effects.outgoing.length == 1
            && response.term == received.currentTerm
            && response.success == (term >= state.currentTerm && prefixMatches)
            && response.lastLogIndex == 0)
          "AppendEntries step-down must still send the expected ACK or NACK"

/-- Runs the canonical CCF Raft behavior checks. -/
def run : IO Unit := do
  configurationQueries
  retirementQueries
  ledgerLocalStartup
  bootstrapAndNoMatchingPrefixTerms
  nominationSelection
  appendCommitTriggers
  commitQuorumAtSignature
  nominationTerms
  appendEntriesResponseTerms
  responseAdmission
  appendEntriesZeroPrefix
  retiredSendBoundary
  batches
  overlappingAppendEntries
  reorderedDelivery
  singleNodePreVote
  committedPrimaryCanHeartbeatBehindCommit
  committedPrefixSurvivesTruncation
  networkSnapshots
  repliesAfterStepDown
  retirementConfirmationIndices
  appendEntriesStepDown
  IO.println "Canonical behavior checks passed."

#eval run

end CCFRaft.Tests.CanonicalTests
