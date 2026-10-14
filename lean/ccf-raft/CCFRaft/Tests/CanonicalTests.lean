-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Replay
import CCFRaft.Tests.AppendTransactions
import Mathlib.Data.Fintype.Basic

open CCFRaft CCFRaft.Model.Local
open CCFRaft.Shared.MultiNodeTransitionSystem (nodeState)

private abbrev Node := Fin 15

private def initialConfig : InitialConfig Node where
  configuration := Finset.univ.filter fun node => node.val < 5
  leader := ⟨0, by decide⟩
  leader_mem := by decide

private abbrev State := Model.State Node Nat
private abbrev Envelope := Model.Envelope Node Nat

private def allNodes : List Node := List.finRange 15

private def system := Model.transitionSystem initialConfig (TxId := Nat) allNodes

private def initial : State :=
  {
    nodes := allNodes.map fun node => (node, initialNodeState initialConfig node)
    active := allNodes
  }

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do
    throw (IO.userError message)

private def configurationQueries : IO Unit := do
  let empty : List (Entry Node Nat) := []
  let initialHistory := configurationHistory initialConfig empty
  check (initialHistory.map (·.index) == [0])
    "an empty log must retain the initial configuration at index zero"
  check (configurationMembers initialHistory == initialConfig.configuration)
    "initial membership must not depend on a reconfiguration entry"
  let log : List (Entry Node Nat) :=
    [
      { term := 1, content := .transaction 10 [] },
      { term := 1, content := .transaction 101 [.reconfiguration {0, 1}] },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 102 [.reconfiguration {1, 5}] },
      { term := 1, content := .transaction 103 [.reconfiguration {5}] },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 109 [.retiredCommitted {0}] }
    ]
  check ((configurationHistory initialConfig log).map (·.index) == [0, 2, 4, 5])
    "configuration indices must count intervening nonconfiguration entries"
  for (commitIndex, expected)
      in [
        (0, [0, 2, 4, 5]),
        (1, [0, 2, 4, 5]),
        (2, [2, 4, 5]),
        (3, [2, 4, 5]),
        (4, [4, 5]),
        (5, [5]),
        (7, [5]),
        (10, [5])
      ] do
    check
      ((activeConfigurations initialConfig log commitIndex).map (·.index) == expected)
      s!"wrong active configuration indices at commit index {commitIndex}"
  check
    (configurationMembers (activeConfigurations initialConfig log 4) == {1, 5})
    "active membership must include pending configurations but exclude obsolete ones"
  let tied : NodeState Node Nat :=
    { (initialNodeState initialConfig 0 : NodeState Node Nat) with log, commitIndex := 4 }
  check (decide ((5 : Node) ∈ eligiblePeers initialConfig tied 0))
    "latest active membership must make a peer eligible for nomination"
  check (decide ((1 : Node) ∈ eligiblePeers initialConfig tied 0))
    "older active membership must remain eligible for nomination"
  check (!decide ((0 : Node) ∈ eligiblePeers initialConfig tied 0))
    "a node cannot nominate itself"
  let ahead := { tied with matchIndex := Function.update tied.matchIndex 1 8 }
  check (eligiblePeers initialConfig ahead 0 == eligiblePeers initialConfig tied 0)
    "replication ranking must not restrict nomination eligibility"
  check (retirementIndexInLog initialConfig (0 : Node) log == some 4)
    "retirement must start at the first removal after membership"
  check (retirementIndexInLog initialConfig (5 : Node) log == none)
    "absence before joining must not count as retirement"
  for (commitIndex, expected)
      in [
        (0, (∅ : Finset Node)),
        (2, {2, 3, 4}),
        (4, {0, 2, 3, 4}),
        (5, {0, 1, 2, 3, 4}),
        (6, {0, 1, 2, 3, 4}),
        (7, {1, 2, 3, 4})
      ] do
    let state : NodeState Node Nat :=
      { (initialNodeState initialConfig 0 : NodeState Node Nat) with log, commitIndex }
    check (state.retirementCompleted initialConfig == expected)
      s!"wrong completed retirements at commit index {commitIndex}"
  let rejoined :=
    log ++ [{ term := 1, content := .transaction 104 [.reconfiguration {0, 1, 5}] }]
  check (retirementIndexInLog initialConfig (0 : Node) rejoined == some 4)
    "rejoining must not change the first removal index"
  let rejoinedState : NodeState Node Nat :=
    {
      (initialNodeState initialConfig 0 : NodeState Node Nat) with
        log := rejoined
        commitIndex := 8
    }
  check (rejoinedState.retirementCompleted initialConfig == {2, 3, 4})
    "current members must not appear among completed retirements"
  -- Effects of one transaction share its index and keep their order.
  let combined : List (Entry Node Nat) :=
    [
      {
        term := 1,
        content := .transaction 200 [.reconfiguration {0, 1}, .reconfiguration {1}]
      },
      { term := 1, content := .signature }
    ]
  check ((configurationHistory initialConfig combined).map (·.index) == [0, 1, 1])
    "configuration effects of one transaction must share its index"
  check
    ((activeConfigurations initialConfig combined 0).map (·.nodes)
      == [initialConfig.configuration, {0, 1}, {1}])
    "uncommitted configuration effects must all be active, in effect order"
  check
    ((activeConfigurations initialConfig combined 2).map (·.nodes) == [{1}])
    "committing a transaction must retain only its last configuration effect"

private def retirementQueries : IO Unit := do
  let log : List (Entry Node Nat) :=
    [
      { term := 1, content := .signature },
      { term := 1, content := .transaction 105 [.reconfiguration {1, 5}] },
      { term := 1, content := .transaction 3 [] },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 110 [.retiredCommitted {0}] },
      { term := 1, content := .transaction 111 [.retiredCommitted {1, 5}] },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 112 [.retiredCommitted {0, 6}] }
    ]
  let isSignature :=
    fun (content : EntryContent Node Nat) => decide (content = .signature)
  check ((firstLogIndexAfter ([] : List (Entry Node Nat)) 0 isSignature).isNone)
    "an empty log must have no matching index"
  for afterIndex in List.range (log.length + 3) do
    let expected := if afterIndex < log.length then some (afterIndex + 1) else none
    check (firstLogIndexAfter log afterIndex (fun _ => true) == expected)
      s!"wrong one-based index after {afterIndex}"
  for (afterIndex, expected)
      in [(0, some 1), (1, some 4), (2, some 4), (4, some 7), (7, none), (99, none)] do
    check (firstLogIndexAfter log afterIndex isSignature == expected)
      s!"wrong first signature after {afterIndex}"
  let namesNode :=
    fun (content : EntryContent Node Nat) =>
      content.effects.any
        fun effect =>
          match effect with
          | .retiredCommitted nodes => decide ((0 : Node) ∈ nodes)
          | .reconfiguration _ => false
  check (firstLogIndexAfter log 0 namesNode == some 5)
    "retirement lookup must select the first record naming the node"
  check (firstLogIndexAfter log 5 namesNode == some 8)
    "retirement lookup must exclude the supplied lower bound"
  for (length, expected)
      in [
        (0, (∅ : Finset Node)),
        (4, ∅),
        (5, {0}),
        (6, {0, 1, 5}),
        (7, {0, 1, 5}),
        (8, {0, 1, 5, 6}),
        (99, {0, 1, 5, 6})
      ] do
    check (retiredCommittedNodes (log.take length) == expected)
      s!"wrong recorded retirements in prefix {length}"
  for (length, commitIndex, phase)
      in [
        (1, 0, MembershipState.active),
        (2, 0, .retirementOrdered),
        (3, 0, .retirementOrdered),
        (4, 0, .retirementSigned),
        (5, 4, .retirementCompleted),
        (6, 4, .retirementCompleted),
        (7, 7, .retiredCommitted)
      ] do
    let state :=
      refreshRetirementState initialConfig (0 : Node)
        {
          (initialNodeState initialConfig 0 : NodeState Node Nat) with
            log := log.take length
            commitIndex
        }
    check (state.membershipState == phase)
      s!"wrong retirement phase at length {length}, commit {commitIndex}"
    check (state.retirementIndex == if length < 2 then none else some 2)
      "retirement metadata must use the first membership removal"
    check (state.retirementCommittableIndex == if length < 4 then none else some 4)
      "the signature before removal must not make retirement committable"
    check (state.retiredCommittedIndex == if commitIndex < 5 then none else some 7)
      "uncommitted records must not set the retirement commit frontier"
  let rejoined :=
    log ++ [{ term := 1, content := .transaction 106 [.reconfiguration {0, 1}] }]
  check (retirementIndexInLog initialConfig (0 : Node) rejoined == some 2)
    "rejoining must preserve the first retirement index"
  check (retirementIndexInLog initialConfig (5 : Node) rejoined == some 9)
    "a later join must precede the first retirement of a fresh node"
  check ((retirementIndexInLog initialConfig (6 : Node) log).isNone)
    "a retirement record alone must not imply prior membership"

private def get (state : State) (node : Node) : NodeState Node Nat :=
  (nodeState state node).getD (initialNodeState initialConfig node)

/-- Pending envelopes from `source` to `destination`, oldest first. -/
private def pending (state : State) (source destination : Node) : List Envelope :=
  state.network.filter
    fun envelope =>
      envelope.source == source && envelope.target == destination

private def apply (state : State) (action : Model.Action Node Nat) : IO State :=
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
private def receive (state : State) (source destination : Node) : IO State := do
  let some envelope := (pending state source destination).head?
  | throw (IO.userError "no pending envelope to receive")
  apply state (.deliver envelope)

private def bootstrapAndNoMatchingPrefixTerms : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  let future : Node := ⟨5, by decide⟩
  check
    (BOOTSTRAP_TERM == 2
      && (get initial source).currentTerm == BOOTSTRAP_TERM
      && (get initial destination).currentTerm == BOOTSTRAP_TERM)
    "bootstrap leader and follower must start at implementation term 2"
  check
    ((get initial future).currentTerm == 0 && decide ((get initial future).role = .none))
    "nodes outside the bootstrap configuration must start fresh at term 0"
  check
    ((get initial source).log
        == [{
              term := BOOTSTRAP_TERM
              content :=
                .transaction default [.reconfiguration initialConfig.configuration]
            }]
      && (get initial destination).log.isEmpty
      && (get initial source).commitIndex == 0)
    "only the bootstrap leader starts with the configuration entry"
  let follower :=
    {
      get initial destination with
        log := [{ term := BOOTSTRAP_TERM, content := .transaction 1 [] }]
    }
  let request : AppendEntriesRequest Node Nat :=
    {
      term := BOOTSTRAP_TERM
      prevLogIndex := 1
      prevLogTerm := 1
      entries := []
      leaderCommit := 0
    }
  check
    (findHighestPossibleMatch follower.log request.prevLogIndex request.prevLogTerm == 0)
    "conflicting prefix must have no possible matching index"
  let some (after, effects) :=
    (handleAppendEntriesRequest initialConfig (Shared.Capabilities.record destination)
      destination source follower request).run
      {}
  | throw (IO.userError "conflicting prefix did not produce a response")
  let some { payload := .appendEntriesResponse response, .. } := effects.outgoing.head?
  | throw (IO.userError "conflicting prefix did not produce an AppendEntries response")
  check (!response.success && response.lastLogIndex == 0 && response.term == 0)
    "no matching prefix must produce a NACK with index 0 and term 0"
  check (after.currentTerm == BOOTSTRAP_TERM && after.log == follower.log)
    "no matching prefix NACK must preserve the follower's term and log"

private def nominationPermissions : IO Unit := do
  let leader : Node := 0
  let caps :=
    Shared.Capabilities.record (Message := Message Node Nat)
      (Notification := Notification) leader
  let before : NodeState Node Nat :=
    {
      (initialNodeState initialConfig leader : NodeState Node Nat) with
        log :=
          [
            {
              term := BOOTSTRAP_TERM,
              content := .transaction 201 [.reconfiguration {1, 2}]
            },
            { term := BOOTSTRAP_TERM, content := .signature },
            {
              term := BOOTSTRAP_TERM,
              content := .transaction 202 [.retiredCommitted {0, 3, 4}]
            },
            { term := BOOTSTRAP_TERM, content := .signature }
          ]
        matchIndex := fun _ => 4
    }
  let nominate state destination :=
    (step initialConfig caps leader state
      (.internal (.nominateSuccessor destination))).run
      {}
  -- Eligible destinations are not ranked by progress.
  let uneven := { before with matchIndex := Function.update before.matchIndex 1 0 }
  check (nominate uneven 1).isSome
    "a leader must be allowed to nominate an eligible peer with lower replication progress"
  check (nominate before leader).isNone "self nomination must be disabled"
  check (nominate before 5).isNone "nomination of an ineligible peer must be disabled"
  check (nominate { before with role := .follower } 1).isNone
    "a follower must not nominate"
  let some (retired, effects) := (advanceCommit initialConfig caps before leader).run {}
  | throw (IO.userError "retirement commit must be enabled")
  check
    (retired.commitIndex == 4
      && retired.role == .none
      && retired.membershipState == .retiredCommitted)
    "retirement commit must still clear leadership and advance the commit frontier"
  check effects.outgoing.isEmpty "retirement commit must not send an implicit nomination"
  check (!decide ((3 : Node) ∈ eligiblePeers initialConfig retired leader))
    "retirement must prune the old peer before the nomination event"
  check (retired.pendingRetirementNomination == some (BOOTSTRAP_TERM, {1, 2, 3, 4}))
    "retirement must capture the old eligible-peer view and term"
  let some (nominated, outputs) := nominate retired 3
  | throw
      (IO.userError "outgoing retiring leader must nominate using its precommit peers")
  check (outputs.outgoing.length == 1)
    "an explicit retirement nomination must send exactly one packet"
  let some envelope := outputs.outgoing.head?
  | throw (IO.userError "nomination packet is missing")
  check
    (envelope.source == leader
      && envelope.target == 3
      && envelope.payload == .proposeVoteRequest BOOTSTRAP_TERM)
    "retirement nomination must use the selected destination and captured term"
  check nominated.pendingRetirementNomination.isNone
    "retirement nomination must consume the pending permission"
  check (nominate nominated 1).isNone
    "a retired node must not reuse nomination permission"
  check (nominate { retired with pendingRetirementNomination := none } 1).isNone
    "arbitrary retired nonleaders must not nominate"
  check (nominate retired leader).isNone
    "pending retirement permission must not allow self nomination"
  check (nominate retired 5).isNone
    "pending retirement permission must reject destinations outside the captured peers"
  let some (expired, _) :=
    (step initialConfig caps leader retired (.receive 1 (.proposeVoteRequest 0))).run {}
  | throw (IO.userError "an ignored proposal must remain enabled")
  check (nominate expired 1).isNone
    "another local event must expire retirement nomination permission"

private def nominationTerms : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  for term in [0, 1, BOOTSTRAP_TERM + 1] do
    let nomination : Envelope :=
      { source, target := destination, payload := .proposeVoteRequest term }
    let state := { initial with network := [nomination] }
    let after ← apply state (.deliver nomination)
    check after.network.isEmpty s!"nomination term {term}: message was not consumed"
    check ((get after destination).currentTerm == (get state destination).currentTerm)
      s!"nomination term {term}: current term changed"
    check (decide ((get after destination).role = (get state destination).role))
      s!"nomination term {term}: role changed"
  let nomination : Envelope :=
    { source, target := destination, payload := .proposeVoteRequest BOOTSTRAP_TERM }
  let after ← apply { initial with network := [nomination] } (.deliver nomination)
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
          { makeRequestVoteRequest (get initial source) with term := BOOTSTRAP_TERM + 1 }
    }
  let after ← apply { initial with network := [vote] } (.deliver vote)
  check ((get after destination).currentTerm == BOOTSTRAP_TERM + 1)
    "newer vote request: current term did not advance"
  check (decide ((get after destination).votedFor = some source))
    "newer vote request: the vote was not granted in the new term"
  let some { payload := .requestVoteResponse response, .. } := after.network.head?
  | throw (IO.userError "newer vote request: no vote response")
  check (response.voteGranted && response.term == BOOTSTRAP_TERM + 1)
    "newer vote request: the response does not grant the vote in the new term"

private def appendEntriesResponseTerms : IO Unit := do
  let leader : Node := ⟨0, by decide⟩
  let follower : Node := ⟨1, by decide⟩
  let response : AppendEntriesResponse :=
    { term := 5, success := false, lastLogIndex := 0 }
  let toFollower : Envelope :=
    { source := leader, target := follower, payload := .appendEntriesResponse response }
  let after ← apply { initial with network := [toFollower] } (.deliver toFollower)
  check ((get after follower).currentTerm == BOOTSTRAP_TERM && after.network.isEmpty)
    "a non-leader must ignore an AppendEntries response, including its term"
  let toLeader : Envelope :=
    { source := follower, target := leader, payload := .appendEntriesResponse response }
  let after ← apply { initial with network := [toLeader] } (.deliver toLeader)
  check
    ((get after leader).currentTerm == 5 && decide ((get after leader).role = .follower))
    "a leader must adopt a newer AppendEntries response term as a follower"

private def batches : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  check (system.step initial (.local source (.append []))).isNone
    "an empty append batch must be disabled"
  check (system.step initial (.local destination (.append [.signature]))).isNone
    "a follower must not append"
  let written ←
    apply initial
      (.local source (.append [.transaction 1 [], .transaction 2 [], .signature]))
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
            { term := 1, content := .transaction 1 [] },
            { term := 2, content := .transaction 2 [] }
          ]
    }
  let mixed :=
    {
      written with
        nodes :=
          written.nodes.map
            fun (entry : Node × NodeState Node Nat) =>
              if entry.1 == source then (source, mixedNode) else entry
    }
  check (system.step mixed (.local source (.sendEntries destination 2))).isNone
    "native AppendEntries batches cannot span terms"

private def reorderedDelivery : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  let written ← apply initial (.local source (.append [.transaction 1 []]))
  let written ← apply written (.local source (.append [.signature]))
  let sent ← apply written (.local source (.sendEntries destination 2))
  let sent ← apply sent (.local source (.sendEntries destination 2))
  let some heartbeat := (pending sent source destination)[1]?
  | throw (IO.userError "missing second AppendEntries")
  let after ← apply sent (.deliver heartbeat)
  check
    ((pending after source destination).length == 1
      && (get after destination).log.isEmpty)
    "a later envelope may be delivered first, leaving the earlier one pending"
  let some { payload := .appendEntriesResponse response, .. } :=
    (pending after destination source).head?
  | throw (IO.userError "reordered heartbeat did not produce a response")
  check (!response.success && response.lastLogIndex == 0)
    "a heartbeat past the follower log must be NACKed"
  check (system.step sent (.deliver { heartbeat with target := source })).isNone
    "an envelope that is not pending cannot be delivered"

private def committedPrefixSurvivesTruncation : IO Unit := do
  let original : Node := ⟨0, by decide⟩
  let successor : Node := ⟨1, by decide⟩
  let second : Node := ⟨2, by decide⟩
  let mut state := initial
  state ← apply state (.local original (.append [.signature]))
  for peer in [successor, second] do
    state ← apply state (.local original (.sendEntries peer 2))
    state ← receive state original peer
    state ← receive state peer original
  let committed := (get state original).committedLog
  check (committed.length == 2) "truncation test requires a nonempty committed prefix"
  state ← apply state (.local original (.append [.transaction 10 []]))
  state ← apply state (.local original (.sendEntries successor 3))
  state ← receive state original successor
  state ← receive state successor original
  check ((get state successor).commitIndex == 2 && (get state successor).log.length == 3)
    "successor must have a committed prefix and an uncommitted suffix"
  -- The timeout sends every vote request; the second granted vote promotes.
  state ← apply state (.local successor (.timeout .election))
  for voter in [original, second] do
    state ← receive state successor voter
    state ← receive state voter successor
  check (decide ((get state successor).role = .leader))
    "a vote quorum must promote the candidate inside the receive"
  check
    ((get state successor).log == committed
      && (get state successor).committedLog == committed)
    "promotion must truncate only the uncommitted suffix"
  -- Promotion sends an empty heartbeat to every peer inside the receive.
  for peer in [original, second] do
    state ← receive state successor peer
    state ← receive state peer successor
  state ← apply state (.local successor (.append [.transaction 20 []]))
  state ← apply state (.local successor (.append [.signature]))
  for peer in [original, second] do
    state ← apply state (.local successor (.sendEntries peer 4))
    state ← receive state successor peer
    state ← receive state peer successor
  check
    ((get state original).committedLog == committed
      && entryAt? (get state original).log 3
          == some { term := BOOTSTRAP_TERM + 1, content := .transaction 20 [] })
    "conflict resolution must replace the uncommitted entry, not the committed prefix"
  state ← apply state (.local successor (.sendEntries original 4))
  state ← receive state successor original
  check
    ((get state original).commitIndex == 4
      && decide (committed <+: (get state original).committedLog))
    "the retained prefix must extend when the replacement suffix commits"

private def committedLeaderCanHeartbeatBehindCommit : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let laggard : Node := ⟨3, by decide⟩
  let mut state := initial
  state ← apply state (.local source (.append [.signature]))
  for peer in ([⟨1, by decide⟩, ⟨2, by decide⟩] : List Node) do
    state ← apply state (.local source (.sendEntries peer 2))
    state ← receive state source peer
    state ← receive state peer source
  check ((get state source).commitIndex == 2)
    "leader should have quorum-committed the bootstrap signature"
  state ← apply state (.local source (.sendEntries laggard 0))
  let some { payload := .appendEntriesRequest heartbeat, .. } :=
    (pending state source laggard).head?
  | throw (IO.userError "missing lagging heartbeat")
  check
    (heartbeat.entries.isEmpty
      && heartbeat.prevLogIndex == 0
      && heartbeat.leaderCommit == 2)
    "empty heartbeat may advertise a commit beyond its verified frontier"
  state ← receive state source laggard
  check ((get state laggard).commitIndex == 0)
    "a lagging heartbeat must not commit an unverified prefix"

private def networkSnapshots : IO Unit := do
  let started ← IO.monoMsNow
  let source : Node := ⟨0, by decide⟩
  let left : Node := ⟨1, by decide⟩
  let right : Node := ⟨2, by decide⟩
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
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  let mut state := initial
  for transaction in [:6] do
    state ← apply state (.local source (.append [.transaction transaction []]))
  state ← apply state (.local source (.sendEntries destination 6))
  state ← apply state (.local source (.sendEntries destination 6))
  let sent := state
  state ← apply state (.local destination (.timeout .election))
  state ← receive state source destination
  state ← receive state source destination
  -- The timeout queued its vote request before either NACK.
  state ← receive state destination source
  check (decide ((get state source).role = .follower))
    "newer-term vote request did not demote the old leader"
  for remaining in [1, 0] do
    state ← receive state destination source
    check
      ((get state source).sentIndex destination == 6
        && (get state source).matchIndex destination == 0
        && (get state source).log.length == 7
        && (pending state destination source).length == remaining)
      "late NACK changed a non-leader's cursor or was not consumed exactly once"
  let some heartbeat := (pending sent source destination)[1]?
  | throw (IO.userError "missing heartbeat")
  let mut leader ← apply sent (.deliver heartbeat)
  leader ← receive leader destination source
  check
    (decide ((get leader source).role = .leader)
      && (get leader source).sentIndex destination == 0
      && (get leader source).matchIndex destination == 0)
    "current leader must still rewind its sent cursor after a NACK"

private def parseJson (input : String) : IO Lean.Json :=
  match Lean.Json.parse input with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

private def replayDocument (rawInstructions : List String) : IO Lean.Json := do
  let bootstrap ← parseJson r#"{
    "configuration":["alpha","beta"], "leader":"alpha",
    "pre_vote_enabled":{"alpha":false,"beta":false,"future":true}
  }"#
  let origin ← parseJson r#"[{"file":"captured trace.ndjson","line":17,"rule":"unit"}]"#
  let instructions ←
    rawInstructions.mapM
      fun input => do
        let value ← parseJson input
        match value.getObj? with
        | .error error => throw (IO.userError error)
        | .ok fields =>
            return Lean.Json.mkObj (("origin", origin) :: fields.toList)
  return Lean.Json.mkObj
    [
      ("schema", Lean.toJson "ccfraft-replay/v4"),
      ("bootstrap", bootstrap),
      ("instructions", Lean.toJson instructions)
    ]

private def expectReplayError (instructions : List String) (expected : String)
    : IO Unit := do
  match CCFRaft.Replay.replay (← replayDocument instructions) with
  | .ok _ => throw (IO.userError s!"replay unexpectedly accepted {expected}")
  | .error error =>
      check (error.contains expected) s!"expected '{expected}', got '{error}'"
      check (error.contains "captured trace.ndjson:17 [unit]")
        "replay failure lost source provenance"

private def jsonReplay : IO Unit := do
  let obsolete :=
    (← replayDocument []).setObjVal! "schema" (Lean.toJson "ccfraft-replay/v1")
  match CCFRaft.Replay.replay obsolete with
  | .ok _ => throw (IO.userError "accepted obsolete erased-index schema")
  | .error error =>
      check (error.contains "v1 is unsupported: v4 requires physical ledger indices")
        error
  let updateTerm :=
    (← replayDocument []).setObjVal! "schema" (Lean.toJson "ccfraft-replay/v2")
  match CCFRaft.Replay.replay updateTerm with
  | .ok _ => throw (IO.userError "accepted a schema with separate updateTerm actions")
  | .error error => check (error.contains "v2 is unsupported") error
  match CCFRaft.Replay.replay (← replayDocument []) with
  | .ok _ => throw (IO.userError "accepted an empty replay")
  | .error error => check (error.contains "instructions must not be empty") error
  let initialSteps :=
    [
      r#"{"kind":"observation","observation":"state","node":"future","fields":{"role":"none","currentTerm":0,"preVoteEnabled":true}}"#,
      r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"transaction","transaction":"tx-1","effects":[]}]}"#,
      r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"signature"}]}"#,
      r#"{"kind":"action","action":"sendEntries","source":"alpha","destination":"beta","endIndex":3}"#
    ]
  let packet :=
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","term":2,"prev_idx":0,"prev_term":0,"idx":3,"term_of_idx":2,"leader_commit_idx":0,"contains_new_view":false}}"#
  let receive :=
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#
  let complete :=
    initialSteps
    ++ [
      packet,
      receive,
      r#"{"kind":"observation","observation":"state","node":"beta","fields":{"role":"follower","logLength":3,"commitIndex":0}}"#,
      r#"{"kind":"observation","observation":"message","source":"beta","destination":"alpha","packet":{"msg":"raft_append_entries_response","term":2,"success":"OK","last_log_idx":3}}"#,
      r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
      r#"{"kind":"observation","observation":"state","node":"alpha","peer":"beta","fields":{"commitIndex":3,"sentIndex":3,"matchIndex":3}}"#
    ]
  match CCFRaft.Replay.replay (← replayDocument complete) with
  | .error error => throw (IO.userError error)
  | .ok result =>
      check
        (result.instructions == complete.length
          && result.actions == 5
          && result.observations == 5)
        "replayer did not consume every instruction"
  expectReplayError
    (initialSteps
      ++ [
        r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"logLength":99}}"#,
        r#"{"kind":"garbage"}"#
      ])
    "instruction 5"
  expectReplayError [receive] "disabled canonical action 'receive'"
  expectReplayError
    [r#"{"kind":"action","action":"append","node":"beta","entries":[{"kind":"transaction","transaction":"tx","effects":[]}]}"#]
    "disabled canonical action 'append'"
  expectReplayError
    [r#"{"kind":"action","action":"timeout","node":"missing","timeout":"election"}"#]
    "undeclared node"
  expectReplayError
    [r#"{"kind":"action","action":"sendEntries","source":"alpha","destination":"beta","endIndex":-1}"#]
    "instruction 1"
  expectReplayError [r#"{"kind":"action","action":"invented","node":"alpha"}"#]
    "unsupported action"
  expectReplayError
    [r#"{"kind":"action","action":"timeout","node":"beta","timeout":"election","ignored":true}"#]
    "unsupported field"
  expectReplayError
    [r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"unknown":0}}"#]
    "unsupported observation field"
  expectReplayError
    [r#"{"kind":"observation","observation":"entry","node":"alpha","index":0,"fields":{"kind":"signature"}}"#]
    "log entry index must be positive"
  expectReplayError
    [r#"{"kind":"observation","observation":"entry","node":"alpha","index":2,"fields":{"kind":"signature"}}"#]
    "has no log entry at index 2"
  expectReplayError
    (initialSteps
      ++ [r#"{"kind":"observation","observation":"entry","node":"alpha","index":1,"fields":{"kind":"signature"}}"#])
    "kind: observed"
  expectReplayError
    (initialSteps
      ++ [r#"{"kind":"observation","observation":"entry","node":"alpha","index":2,"fields":{"committed":true}}"#])
    "committed: observed true, canonical false"
  expectReplayError
    (initialSteps
      ++ [r#"{"kind":"observation","observation":"entry","node":"alpha","index":2,"fields":{"unknown":0}}"#])
    "unsupported observation field"
  expectReplayError
    (initialSteps
      ++ [r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","idx":1}}"#])
    "idx: observed 1, canonical 3"
  expectReplayError
    (initialSteps
      ++ [r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","unknown":0}}"#])
    "unsupported observation field"
  expectReplayError
    (initialSteps
      ++ [
        r#"{"kind":"action","action":"drop","source":"alpha","destination":"beta"}"#,
        packet
      ])
    "no pending packet"
  let sentTwice :=
    initialSteps
    ++ [r#"{"kind":"action","action":"sendEntries","source":"alpha","destination":"beta","endIndex":3}"#]
  let latest ←
    replayDocument
      (sentTwice
        ++ [
          r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","selection":"last","packet":{"msg":"raft_append_entries","prev_idx":3,"idx":3}}"#,
          r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","occurrence":1,"packet":{"msg":"raft_append_entries","prev_idx":3,"idx":3}}"#,
          packet
        ])
  match CCFRaft.Replay.replay latest with
  | .ok result => check (result.instructions == 8) "incomplete packet selection replay"
  | .error error => throw (IO.userError error)
  expectReplayError
    (sentTwice
      ++ [r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","prev_idx":3}}"#])
    "prev_idx: observed 3, canonical 0"
  expectReplayError
    (sentTwice
      ++ [r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","selection":"last","occurrence":1,"packet":{"msg":"raft_append_entries"}}"#])
    "cannot specify both selection and occurrence"
  expectReplayError
    (sentTwice
      ++ [r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","selection":"any","packet":{"msg":"raft_append_entries"}}"#])
    "unsupported message selection"
  let reconfiguration ←
    replayDocument
      [
        r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"transaction","transaction":"cfg-1","effects":[{"kind":"configuration","configuration":["alpha","beta","future"]}]}]}"#,
        r#"{"kind":"observation","observation":"state","node":"future","fields":{"role":"none","currentTerm":0}}"#,
        r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"signature"}]}"#,
        r#"{"kind":"action","action":"receive","source":"alpha","destination":"future"}"#,
        r#"{"kind":"action","action":"receive","source":"future","destination":"alpha"}"#,
        r#"{"kind":"action","action":"sendEntries","source":"alpha","destination":"future","endIndex":3}"#,
        r#"{"kind":"action","action":"receive","source":"alpha","destination":"future"}"#,
        r#"{"kind":"action","action":"timeout","node":"future","timeout":"election"}"#,
        r#"{"kind":"observation","observation":"state","node":"future","fields":{"role":"preVoteCandidate","currentTerm":2,"logLength":3}}"#
      ]
  match CCFRaft.Replay.replay reconfiguration with
  | .ok result => check (result.instructions == 9) "incomplete reconfiguration replay"
  | .error error => throw (IO.userError error)
  let noOrigin :=
    (← replayDocument [receive]).setObjVal! "instructions"
      (.arr #[Lean.Json.mkObj [("kind", Lean.toJson "action"), ("origin", .arr #[])]])
  match CCFRaft.Replay.replay noOrigin with
  | .ok _ => throw (IO.userError "accepted empty origin")
  | .error error =>
      check (error.contains "instruction 1: invalid origin") error
  let malformed ←
    parseJson
      r#"{
    "schema":"ccfraft-replay/v4",
    "bootstrap":{"configuration":["alpha"],"leader":"outsider","pre_vote_enabled":{"alpha":false}},
    "instructions":[]
  }"#
  match CCFRaft.Replay.replay malformed with
  | .ok _ => throw (IO.userError "accepted bootstrap leader outside configuration")
  | .error error => check (error.contains "not in the configuration") error

private def bootstrapPrefix : IO Unit := do
  let document ←
    replayDocument
      [
        r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"logLength":1,"committableIndices":[],"configurations":[{"index":1,"nodes":["alpha"]}]}}"#,
        r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"signature"}]}"#,
        r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"commitIndex":2,"committableIndices":[]}}"#,
        r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"transaction","transaction":"cfg-1","effects":[{"kind":"configuration","configuration":["alpha","beta"]}]}]}"#,
        r#"{"kind":"observation","observation":"state","node":"alpha","peer":"beta","fields":{"logLength":3,"commitIndex":2,"committableIndices":[],"sentIndex":2,"configurations":[{"index":1,"nodes":["alpha"]},{"index":3,"nodes":["alpha","beta"]}]}}"#,
        r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","prev_idx":2,"idx":2,"prev_term":2,"term_of_idx":2,"leader_commit_idx":2}}"#,
        r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
        r#"{"kind":"observation","observation":"message","source":"beta","destination":"alpha","packet":{"msg":"raft_append_entries_response","success":"FAIL","last_log_idx":0,"term":2}}"#,
        r#"{"kind":"observation","observation":"state","node":"beta","fields":{"role":"follower","currentTerm":2,"logLength":0,"commitIndex":0}}"#,
        r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
        r#"{"kind":"action","action":"sendEntries","source":"alpha","destination":"beta","endIndex":3}"#,
        r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
        r#"{"kind":"observation","observation":"state","node":"beta","fields":{"logLength":3,"commitIndex":2,"committableIndices":[],"configurations":[{"index":1,"nodes":["alpha"]},{"index":3,"nodes":["alpha","beta"]}]}}"#
      ]
  let bootstrap ←
    parseJson
      r#"{"configuration":["alpha"],"leader":"alpha","pre_vote_enabled":{"alpha":false,"beta":false}}"#
  match CCFRaft.Replay.replay (document.setObjVal! "bootstrap" bootstrap) with
  | .ok result => check (result.instructions == 13) "incomplete bootstrap prefix replay"
  | .error error => throw (IO.userError error)
  let startup ←
    replayDocument
      [
        r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"signature"}]}"#,
        r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"logLength":2,"commitIndex":2}}"#,
        r#"{"kind":"observation","observation":"entry","node":"alpha","index":1,"fields":{"kind":"transaction","transaction":"","effects":[{"kind":"configuration","configuration":["alpha"]}],"configurations":[["alpha"]],"term":2,"committed":true}}"#,
        r#"{"kind":"observation","observation":"entry","node":"alpha","index":2,"fields":{"kind":"signature","committed":true}}"#,
        r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"signature"}]}"#,
        r#"{"kind":"observation","observation":"entry","node":"alpha","index":3,"fields":{"kind":"signature","committed":true}}"#,
        r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"logLength":3,"commitIndex":3,"committableIndices":[]}}"#
      ]
  match CCFRaft.Replay.replay (startup.setObjVal! "bootstrap" bootstrap) with
  | .ok result => check (result.instructions == 7) "incomplete physical startup replay"
  | .error error => throw (IO.userError error)
  expectReplayError
    [r#"{"kind":"action","action":"initializeConfiguration","node":"alpha"}"# ]
    "unsupported action 'initializeConfiguration'"

private def terminalRetirementRole : IO Unit := do
  let document ←
    replayDocument
      [
        r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"signature"}]}"#,
        r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"transaction","transaction":"cfg-1","effects":[{"kind":"configuration","configuration":["beta"]}]}]}"#,
        r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"signature"}]}"#,
        r#"{"kind":"action","action":"sendEntries","source":"alpha","destination":"beta","endIndex":4}"#,
        r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
        r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
        r#"{"kind":"action","action":"sendEntries","source":"alpha","destination":"beta","endIndex":4}"#,
        r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
        r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
        r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
        r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
        r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"role":"leader","membershipState":"retirementCompleted","commitIndex":4}}"#,
        r#"{"kind":"action","action":"sendEntries","source":"alpha","destination":"beta","endIndex":4}"#,
        r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
        r#"{"kind":"action","action":"append","node":"alpha","entries":[{"kind":"transaction","transaction":"retire-1","effects":[{"kind":"retiredCommitted","nodes":["alpha"]}]},{"kind":"signature"}]}"#,
        r#"{"kind":"action","action":"sendEntries","source":"alpha","destination":"beta","endIndex":6}"#,
        r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
        r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
        r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"role":"none","membershipState":"retiredCommitted","currentTerm":2,"commitIndex":6,"retiredCommittedIndex":6}}"#,
        r#"{"kind":"action","action":"nominateSuccessor","node":"alpha","destination":"beta"}"#,
        r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_propose_request_vote","term":2}}"#,
        r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
        r#"{"kind":"observation","observation":"state","node":"beta","fields":{"role":"leader","currentTerm":3}}"#
      ]
  let bootstrap ←
    parseJson
      r#"{"configuration":["alpha"],"leader":"alpha","pre_vote_enabled":{"alpha":false,"beta":false}}"#
  match CCFRaft.Replay.replay (document.setObjVal! "bootstrap" bootstrap) with
  | .ok result =>
      check (result.instructions == 23) "incomplete terminal retirement replay"
  | .error error => throw (IO.userError error)

private def retirementCommitFrontiers : IO Unit := do
  let node : Node := ⟨0, by decide⟩
  let survivor : Node := ⟨1, by decide⟩
  let log : List (Entry Node Nat) :=
    [
      { term := 1, content := .transaction 107 [.reconfiguration {node, survivor}] },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 108 [.reconfiguration {survivor}] },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 113 [.retiredCommitted {node}] },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 7 [] },
      { term := 1, content := .signature },
      { term := 1, content := .transaction 9 [] },
      { term := 1, content := .signature }
    ]
  let before : NodeState Node Nat :=
    refreshRetirementState initialConfig node
      {
        (initialNodeState initialConfig node : NodeState Node Nat) with
          role := .follower
          currentTerm := 1
          log := log.take 5
          commitIndex := 4
      }
  check (before.retiredCommittedIndex.isNone)
    "an uncommitted retirement marker must not set the commit frontier"
  let jumped :=
    refreshRetirementState initialConfig node
      { before with log := log.take 8, commitIndex := 8 }
  check (jumped.retiredCommittedIndex == some 8)
    "commit frontier must not be the marker index or marker index plus one"
  let later :=
    refreshRetirementState initialConfig node { jumped with log, commitIndex := 10 }
  check (later.retiredCommittedIndex == some 8)
    "later commits must preserve the first covering retirement frontier"
  for (oldLength, expected) in [(5, 6), (6, 8)] do
    let state := { before with log := log.take oldLength }
    let request : AppendEntriesRequest Node Nat :=
      {
        term := 1
        prevLogIndex := oldLength
        prevLogTerm := 1
        entries := (log.take 8).drop oldLength
        leaderCommit := 8
      }
    let some (received, effects) :=
      (handleAppendEntriesRequest initialConfig (Shared.Capabilities.record node)
        node node state request).run
        {}
    | throw (IO.userError "retirement batch was not answered")
    let some { payload := .appendEntriesResponse response, .. } := effects.outgoing.head?
    | throw (IO.userError "retirement batch did not produce an AppendEntries response")
    check response.success "retirement batch was rejected"
    let received := refreshRetirementState initialConfig node received
    check (received.commitIndex == 8 && received.retiredCommittedIndex == some expected)
      s!"batch from {oldLength}: wrong first covering retirement commit"

def main : IO Unit := do
  configurationQueries
  retirementQueries
  bootstrapAndNoMatchingPrefixTerms
  nominationPermissions
  nominationTerms
  appendEntriesResponseTerms
  batches
  reorderedDelivery
  committedLeaderCanHeartbeatBehindCommit
  committedPrefixSurvivesTruncation
  networkSnapshots
  repliesAfterStepDown
  jsonReplay
  bootstrapPrefix
  terminalRetirementRole
  retirementCommitFrontiers
  IO.println "Canonical behavior checks passed."
