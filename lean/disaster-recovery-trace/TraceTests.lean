import DisasterRecoveryTrace.Protocol.Trace

open DisasterRecovery.Protocol.Model
open DisasterRecoveryTrace.Protocol.Trace

private def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def baseEvent
    (locations : List Location)
    (node : Location)
    (sequence : Nat)
    (kind : Kind) : TraceEvent := {
  instanceId := "trace-tests"
  expectedLocations := locations
  node
  sequence
  kind
  attempt := none
  messageId := none
  causedBy := none
  source := none
  txid := none
  batch := none
  pre := none
  post := none
  openKind := none
  send := none
}

private def startEvent
    (locations : List Location)
    (node : Location) : TraceEvent := {
  baseEvent locations node 0 .start with
  pre := some .gossiping
  post := some .gossiping
}

private def sendEvent
    (locations : List Location)
    (sequence : Nat)
    (messageId description : String)
    (phase : Phase)
    (batch : Nat := sequence) : TraceEvent := {
  baseEvent locations "A" sequence .send with
  messageId := some messageId
  pre := some phase
  post := some phase
  txid := if description.startsWith "gossip:" then
    some { view := 1, seqno := 1 }
  else
    none
  batch := some batch
  send := some description
}

private def gossipEvent
    (locations : List Location)
    (sequence : Nat)
    (messageId cause : String)
    (post : Phase) : TraceEvent := {
  baseEvent locations "A" sequence .gossipAccepted with
  attempt := some sequence
  messageId := some messageId
  causedBy := some cause
  source := some "A"
  txid := some { view := 1, seqno := 1 }
  pre := some .gossiping
  post := some post
}

private def voteEvent
    (locations : List Location)
    (sequence : Nat)
    (messageId cause : String)
    (post : Phase) : TraceEvent := {
  baseEvent locations "A" sequence .voteAccepted with
  attempt := some sequence
  messageId := some messageId
  causedBy := some cause
  source := some "A"
  pre := some .voting
  post := some post
}

private def timeoutEvent
    (locations : List Location)
    (sequence : Nat)
    (pre post : Phase) : TraceEvent := {
  baseEvent locations "A" sequence .timeout with
  attempt := some sequence
  pre := some pre
  post := some post
}

private def openEvent
    (locations : List Location)
    (sequence : Nat)
    (kind : OpenKind) : TraceEvent := {
  baseEvent locations "A" sequence .open with
  attempt := some sequence
  pre := some .opening
  post := some .opening
  openKind := some kind
}

private def completeEvent
    (locations : List Location)
    (sequence : Nat) : TraceEvent := {
  baseEvent locations "A" sequence .complete with
  attempt := some sequence
  pre := some .open
  post := some .open
}

private def lifecycleEvent
    (locations : List Location)
    (node : Location)
    (sequence attempt : Nat)
    (kind : Kind) : TraceEvent := {
  baseEvent locations node sequence kind with
  attempt := some attempt
  txid := if kind == .aborted then none else
    some { view := 1, seqno := sequence }
}

private def validationSucceeds (events : List TraceEvent) : Bool :=
  match validate events with
  | .ok () => true
  | .error _ => false

private def failedAt (events : List TraceEvent) (expectedPrefix : Nat) : Bool :=
  match validate events with
  | .error failure => failure.prefixLength == expectedPrefix
  | .ok () => false

private def replayFailedAt (events : List TraceEvent) (expectedPrefix : Nat) : Bool :=
  match replay events with
  | .error failure => failure.prefixLength == expectedPrefix
  | .ok _ => false

private def parseFails (value : String) : Bool :=
  match parseEvent value with
  | .error _ => true
  | .ok _ => false

private def quorumTrace : List TraceEvent :=
  let locations := ["A"]
  [
    startEvent locations "A",
    sendEvent locations 1 "send-gossip" "gossip:A" .gossiping,
    { gossipEvent locations 2 "receive-gossip" "send-gossip" .voting with
      attempt := some 0 },
    lifecycleEvent locations "A" 3 0 .globallyCommitted,
    sendEvent locations 4 "send-vote" "vote:A" .voting,
    sendEvent locations 5 "send-voting-gossip" "gossip:A" .voting 4,
    { voteEvent locations 6 "receive-vote" "send-vote" .opening with
      attempt := some 1 },
    { openEvent locations 7 .quorum with attempt := some 1 },
    lifecycleEvent locations "A" 8 1 .globallyCommitted,
    { timeoutEvent locations 9 .opening .opening with attempt := some 2 },
    lifecycleEvent locations "A" 10 2 .globallyCommitted,
    { timeoutEvent locations 11 .opening .opening with attempt := some 3 },
    lifecycleEvent locations "A" 12 3 .globallyCommitted,
    { timeoutEvent locations 13 .opening .open with attempt := some 4 },
    { completeEvent locations 14 with attempt := some 4 },
    lifecycleEvent locations "A" 15 4 .globallyCommitted
  ]

private def eventJson (event : TraceEvent) : Lean.Json :=
  let kind := match event.kind with
    | .start => "start"
    | .send => "send"
    | .gossipAccepted => "gossip_accepted"
    | .voteAccepted => "vote_accepted"
    | .iAmOpenAccepted => "iamopen_accepted"
    | .timeout => "timeout"
    | .open => "open"
    | .joinRestart => "join_restart"
    | .complete => "complete"
    | .locallyCommitted => "locally_committed"
    | .globallyCommitted => "globally_committed"
    | .rolledBack => "rolled_back"
    | .aborted => "aborted"
  Lean.Json.mkObj ([
    ("instance", Lean.toJson event.instanceId),
    ("expected_locations", Lean.toJson event.expectedLocations),
    ("node", Lean.toJson event.node),
    ("sequence", Lean.toJson event.sequence),
    ("kind", Lean.toJson kind)
  ] ++
    (event.attempt.toList.map fun value => ("attempt", Lean.toJson value)) ++
    (event.messageId.toList.map fun value => ("message_id", Lean.toJson value)) ++
    (event.causedBy.toList.map fun value => ("caused_by", Lean.toJson value)) ++
    (event.source.toList.map fun value => ("source", Lean.toJson value)) ++
    (event.txid.toList.flatMap fun value =>
      [("view", Lean.toJson value.view), ("seqno", Lean.toJson value.seqno)]) ++
    (event.batch.toList.map fun value => ("batch", Lean.toJson value)) ++
    (event.pre.toList.map fun value => ("pre", Lean.toJson (phaseName value))) ++
    (event.post.toList.map fun value => ("post", Lean.toJson (phaseName value))) ++
    (event.openKind.toList.map fun value => ("open_kind", Lean.toJson (openKindName value))) ++
    (event.send.toList.map fun value => ("send", Lean.toJson value)))

private def textLog (events : List TraceEvent) : String :=
  String.join (events.map fun event => s!"[info] RDP_TRACE {(eventJson event).compress}\n")

private def jsonLog (events : List TraceEvent) : String :=
  String.join (events.map fun event =>
    (Lean.Json.mkObj [("msg", Lean.toJson s!"RDP_TRACE {(eventJson event).compress}")]).compress
      ++ "\n")

private def located (events : List TraceEvent) : List LocatedEvent :=
  events.zipIdx.map fun (event, index) => { path := "test.out", line := index + 1, event }

private def expectInvalid (result : Except LogError α) (message : String) : IO Unit := do
  match result with
  | .error (.invalid _) => pure ()
  | _ => throw (IO.userError message)

private def expectIncomplete (result : Except LogError α) (message : String) : IO Unit := do
  match result with
  | .error (.incomplete _) => pure ()
  | _ => throw (IO.userError message)

private def accepted [BEq α] (result : Except LogError α) (expected : α) : Bool :=
  match result with
  | .ok value => value == expected
  | .error _ => false

private def phaseAt (active : ActiveReplay) (node : Location) : Option Phase :=
  (active.system.nodes.find? fun entry => entry.1 == node).map
    (fun entry => entry.2.phase)

private def activeState (state : ReplayState) : IO ActiveReplay :=
  match state.active with
  | some active => pure active
  | none => throw (IO.userError "replay did not create active state")

private def validateTextLogs (logs : List (String × String)) (scenario : Scenario) :
    Except LogError Nat :=
  validateLogs (logs.map fun (path, text) => (path, text.toUTF8)) scenario

private def checkLogs : IO Unit := do
  let scenario : Scenario := { participatingNodes := 1, openKind := .quorum }
  let logs := [("node.out", textLog quorumTrace)]
  expect (accepted (validateTextLogs logs scenario) quorumTrace.length)
    "raw text quorum log was rejected"
  expect
    (accepted
      (validateTextLogs [("node.out", "unrelated\n{\"msg\":42}\n\n" ++ jsonLog quorumTrace)] scenario)
      quorumTrace.length)
    "JSON envelope quorum log was rejected"
  expect
    (accepted (validateTextLogs [("node.out", textLog quorumTrace.reverse)] scenario)
      quorumTrace.length)
    "per-node sequences were not used to order records"
  expect
    (accepted (validateTextLogs [("node.out", (textLog quorumTrace).replace "\n" "\r\n")] scenario)
      quorumTrace.length)
    "CRLF log was rejected"

  let first := quorumTrace.head!
  let escaped := quorumTrace.map fun event =>
    { event with instanceId := "escaped \"quote\" \\ slash RDP_TRACE value" }
  expect
    (accepted (validateTextLogs [("node.out", jsonLog escaped)] scenario) escaped.length)
    "escaped JSON message or embedded marker was misparsed"
  expectInvalid (extractLog "bad.out" "noise\nRDP_TRACE {broken}\n")
    "malformed marked record was ignored"
  expectInvalid (extractLog "bad.out" s!"RDP_TRACE {(eventJson first).compress} junk\n")
    "trailing garbage after an event was ignored"
  match extractLog "bad.out" "noise\nRDP_TRACE {broken}\n" with
  | .error (.invalid message) =>
      expect (message.startsWith "bad.out:2:") "raw source location was lost"
  | _ => throw (IO.userError "malformed input accepted")
  expectIncomplete (validateTextLogs [] scenario) "empty trace was accepted"
  expectIncomplete (validateTextLogs [("node.out", textLog (quorumTrace.take 6))] scenario)
    "unobserved committed effect was accepted"
  expectIncomplete (validateTextLogs [("node.out", textLog quorumTrace.dropLast)] scenario)
    "missing completion was accepted"
  expectIncomplete
    (validateTextLogs [("node.out", textLog quorumTrace ++ "RDP_TRACE {")] scenario)
    "unterminated record after completion was accepted"
  expectIncomplete
    (validateTextLogs logs { scenario with participatingNodes := 2 })
    "absent participating node was accepted"
  expectInvalid (validateTextLogs logs { scenario with participatingNodes := 0 })
    "zero participating nodes was accepted"
  expectInvalid (validateTextLogs logs { scenario with openKind := .failover })
    "wrong scenario open kind was accepted"
  expectInvalid
    (validateTextLogs [("node.out", textLog (quorumTrace ++ [first]))] scenario)
    "duplicate node sequence was accepted"
  expectIncomplete
    (linearize (located [first, { first with sequence := 2, kind := .timeout }]))
    "sequence gap was accepted"
  expectInvalid
    (linearize (located [first, { first with sequence := 1, instanceId := "other" }]))
    "recovery identity change was accepted"
  expectInvalid
    (linearize (located [
      { first with messageId := some "duplicate" },
      { first with sequence := 1, messageId := some "duplicate" }
    ]))
    "duplicate message ID was accepted"
  expectIncomplete
    (linearize (located [first, gossipEvent ["A"] 1 "receive" "missing" .voting]))
    "unresolved cause was accepted"
  expectInvalid
    (linearize (located [
      { first with messageId := some "not-a-send" },
      gossipEvent ["A"] 1 "receive" "not-a-send" .voting
    ]))
    "receive used a non-send cause"
  expectInvalid
    (validateTextLogs [("node.out", textLog (quorumTrace.map fun event =>
      if event.sequence == 2 then { event with post := some .open } else event))] scenario)
    "invalid replay transition was treated as incomplete input"
  let partialUTF8 := (textLog quorumTrace).toUTF8.push 0xc3
  expectIncomplete (validateLogs [("node.out", partialUTF8)] scenario)
    "partial UTF-8 write was accepted or treated as malformed"
  expectInvalid (validateLogs [("node.out", partialUTF8.push 10)] scenario)
    "malformed UTF-8 in a complete line was accepted"

  let discarded := quorumTrace ++ [
    { timeoutEvent ["A"] 16 .opening .opening with attempt := some 5 },
    { openEvent ["A"] 17 .failover with attempt := some 5 },
    lifecycleEvent ["A"] "A" 18 5 .rolledBack
  ]
  expect
    (accepted (validateTextLogs [("node.out", textLog discarded)] scenario)
      discarded.length)
    "discarded records changed scenario validation or raw event count"
  let rolledBackCompletion :=
    quorumTrace.dropLast ++ [lifecycleEvent ["A"] "A" 15 4 .rolledBack]
  expectIncomplete
    (validateTextLogs [("node.out", textLog rolledBackCompletion)] scenario)
    "speculative terminal evidence was treated as committed"

  let locations := ["A", "B"]
  let aStart := startEvent locations "A"
  let bStart := startEvent locations "B"
  let aReceive := {
    gossipEvent locations 1 "receive-a" "send-b" .gossiping with source := some "B" }
  let bReceive := {
    gossipEvent locations 1 "receive-b" "send-a" .gossiping with node := "B" }
  let aSend := sendEvent locations 2 "send-a" "gossip:B" .gossiping
  let bSend := { sendEvent locations 2 "send-b" "gossip:A" .gossiping with node := "B" }
  expectInvalid (linearize (located [aStart, aReceive, aSend, bStart, bReceive, bSend]))
    "causal cycle was accepted"
  let causal := [aStart, aReceive, bStart, { bSend with sequence := 1 }]
  match linearize (located causal) with
  | .ok records =>
      expect
        (records.map (fun record => (record.event.node, record.event.sequence)) ==
          [("A", 0), ("B", 0), ("B", 1), ("A", 1)])
        "cross-node cause did not precede its receive"
  | .error error => throw (IO.userError s!"causal trace rejected: {repr error}")
  match linearize (located causal), linearize (located causal.reverse) with
  | .ok forward, .ok backward =>
      expect (forward.map LocatedEvent.event == backward.map LocatedEvent.event)
        "ordering depends on log argument order"
  | _, _ => throw (IO.userError "causal ordering failed")

private def checkAttempts : IO Unit := do
  let locations := ["A"]
  let start := startEvent locations "A"
  let send := sendEvent locations 1 "send-gossip" "gossip:A" .gossiping
  let receive := {
    gossipEvent locations 2 "receive-gossip" "send-gossip" .voting with
    attempt := some 0
  }
  let committed := lifecycleEvent locations "A" 3 0 .globallyCommitted

  match replay [start, send, receive] with
  | .ok state =>
      let active <- activeState state
      expect (phaseAt active "A" == some .gossiping)
        "speculative event changed canonical state before commit"
      expect active.consumedSendIds.isEmpty
        "speculative receive consumed its send before commit"
  | .error failure =>
      throw (IO.userError s!"buffered attempt was rejected: {repr failure}")

  match replay [start, send, receive, committed] with
  | .ok state =>
      let active <- activeState state
      expect (phaseAt active "A" == some .voting)
        "globally committed attempt was not applied"
      expect (active.consumedSendIds == ["send-gossip"])
        "globally committed receive did not consume its send"
  | .error failure =>
      throw (IO.userError s!"committed attempt was rejected: {repr failure}")

  let earlyVote :=
    sendEvent locations 3 "early-vote" "vote:A" .voting
  let earlyGossip :=
    sendEvent locations 4 "early-gossip" "gossip:A" .voting 3
  let delayedCommit :=
    lifecycleEvent locations "A" 5 0 .globallyCommitted
  match replay [
    start,
    send,
    receive,
    earlyVote,
    earlyGossip,
    delayedCommit
  ] with
  | .ok state =>
      let active <- activeState state
      expect (phaseAt active "A" == some .voting)
        "delayed lifecycle did not commit after speculative-state sends"
      expect (active.sends.length == 3)
        "immediate sends before lifecycle were not retained"
  | .error failure =>
      throw (IO.userError s!"pre-lifecycle send was rejected: {repr failure}")

  let delayedRollback :=
    lifecycleEvent locations "A" 5 0 .rolledBack
  match replay [
    start,
    send,
    receive,
    earlyVote,
    earlyGossip,
    delayedRollback
  ] with
  | .ok state =>
      let active <- activeState state
      expect (phaseAt active "A" == some .gossiping)
        "rolled-back local projection changed canonical state"
      expect (active.sends.length == 3)
        "rollback discarded sends emitted from a local projection"
      expect active.pendingSendBatches.isEmpty
        "completed pre-rollback send batch remained pending"
  | .error failure =>
      throw (IO.userError s!"pre-rollback sends were rejected: {repr failure}")

  for lifecycle in [.globallyCommitted, .rolledBack] do
    let resolution := lifecycleEvent locations "A" 3 0 lifecycle
    let lateVote :=
      sendEvent locations 4 s!"late-vote-{repr lifecycle}" "vote:A" .voting
    let lateGossip :=
      sendEvent locations 5 s!"late-gossip-{repr lifecycle}" "gossip:A" .voting 4
    match replay [start, send, receive, resolution, lateVote, lateGossip] with
    | .ok state =>
        let active <- activeState state
        let expectedPhase := if lifecycle == .globallyCommitted then
          Phase.voting
        else
          Phase.gossiping
        expect (phaseAt active "A" == some expectedPhase)
          "post-lifecycle send changed canonical state"
        expect (active.sends.length == 3)
          "first post-lifecycle send lost its prepared local projection"
        expect active.pendingSendBatches.isEmpty
          "post-lifecycle send batch did not finish"
    | .error failure =>
        throw (IO.userError
          s!"first send after {repr lifecycle} was rejected: {repr failure}")
  let abort := {
    lifecycleEvent locations "A" 3 0 .aborted with txid := none
  }
  expect
    (replayFailedAt [
      start,
      send,
      receive,
      abort,
      sendEvent locations 4 "aborted-vote" "vote:A" .voting
    ] 5)
    "aborted attempt justified a later send"
  expect
    (replayFailedAt [
      start,
      send,
      receive,
      earlyVote,
      earlyGossip,
      { abort with sequence := 5 }
    ] 6)
    "aborted attempt justified earlier speculative sends"
  let localCommit :=
    lifecycleEvent locations "A" 5 0 .locallyCommitted
  match parseEvent (eventJson localCommit).compress with
  | .ok parsed =>
      expect (parsed.kind == .locallyCommitted)
        "local commit event kind did not parse"
  | .error message =>
      throw (IO.userError s!"local commit event did not parse: {message}")
  match replay [
    start,
    send,
    receive,
    earlyVote,
    earlyGossip,
    localCommit
  ] with
  | .ok state =>
      let active <- activeState state
      expect active.sendProofs.isEmpty
        "local commit did not justify earlier speculative sends"
  | .error failure =>
      throw (IO.userError
        s!"local commit did not resolve speculative sends: {repr failure}")
  expect
    (replayFailedAt [
      start,
      send,
      receive,
      { localCommit with sequence := 3 },
      { abort with sequence := 4 }
    ] 5)
    "locally committed attempt was later aborted"

  let tx0 : TxID := { view := 1, seqno := 10 }
  let tx1 : TxID := { view := 1, seqno := 11 }
  let local0 := {
    lifecycleEvent locations "A" 3 0 .locallyCommitted with txid := some tx0
  }
  let local1 := {
    lifecycleEvent locations "A" 8 1 .locallyCommitted with txid := some tx1
  }
  let outOfOrderFinals := [
    start,
    send,
    receive,
    local0,
    sendEvent locations 4 "ordered-vote" "vote:A" .voting,
    sendEvent locations 5 "ordered-gossip" "gossip:A" .voting 4,
    { voteEvent locations 6 "ordered-receive" "ordered-vote" .opening with
      attempt := some 1 },
    { openEvent locations 7 .quorum with attempt := some 1 },
    local1,
    { lifecycleEvent locations "A" 9 1 .globallyCommitted with txid := some tx1 },
    { lifecycleEvent locations "A" 10 0 .globallyCommitted with txid := some tx0 }
  ]
  match replay outOfOrderFinals with
  | .ok state =>
      let active <- activeState state
      expect (phaseAt active "A" == some .opening)
        "out-of-order final callbacks changed transaction order"
      expect active.pendingCommits.isEmpty
        "out-of-order final callbacks were not drained"
  | .error failure =>
      throw (IO.userError
        s!"out-of-order final callbacks were rejected: {repr failure}")

  let repeatedLocations := ["A", "B"]
  let repeatedStart := startEvent repeatedLocations "A"
  let repeatedGossipA := {
    sendEvent repeatedLocations 1 "repeated-gossip-a" "gossip:A" .gossiping with
      txid := some { view := 2, seqno := 1 }
  }
  let repeatedGossipB :=
    sendEvent repeatedLocations 2 "repeated-gossip-b" "gossip:B" .gossiping 1
  let repeatedReceiveA := {
    gossipEvent repeatedLocations 3 "repeated-receive-a" "repeated-gossip-a"
      .gossiping with
        attempt := some 0
        txid := repeatedGossipA.txid
  }
  let repeatedGossipTimeout := {
    timeoutEvent repeatedLocations 5 .gossiping .voting with
      attempt := some 1
  }
  let repeatedVote :=
    sendEvent repeatedLocations 7 "repeated-vote" "vote:A" .voting
  let concurrentVote :=
    sendEvent repeatedLocations 8 "concurrent-vote" "vote:A" .voting
  let repeatedVoteReceive := {
    voteEvent repeatedLocations 13 "repeated-vote-receive" "repeated-vote"
      .voting with
        attempt := some 2
  }
  let repeatedVoteTxid : TxID := { view := 2, seqno := 30 }
  let repeatedTimeoutTxid : TxID := { view := 2, seqno := 31 }
  let repeatedTrace := [
    repeatedStart,
    repeatedGossipA,
    repeatedGossipB,
    repeatedReceiveA,
    lifecycleEvent repeatedLocations "A" 4 0 .globallyCommitted,
    repeatedGossipTimeout,
    lifecycleEvent repeatedLocations "A" 6 1 .globallyCommitted,
    repeatedVote,
    concurrentVote,
    sendEvent repeatedLocations 9 "repeated-voting-gossip-a" "gossip:A" .voting 7,
    sendEvent repeatedLocations 10 "concurrent-voting-gossip-a" "gossip:A" .voting 8,
    sendEvent repeatedLocations 11 "repeated-voting-gossip-b" "gossip:B" .voting 7,
    sendEvent repeatedLocations 12 "concurrent-voting-gossip-b" "gossip:B" .voting 8,
    repeatedVoteReceive,
    { lifecycleEvent repeatedLocations "A" 14 2 .locallyCommitted with
      txid := some repeatedVoteTxid },
    { timeoutEvent repeatedLocations 15 .voting .opening with attempt := some 3 },
    { openEvent repeatedLocations 16 .failover with attempt := some 3 },
    { lifecycleEvent repeatedLocations "A" 17 3 .locallyCommitted with
      txid := some repeatedTimeoutTxid },
    { lifecycleEvent repeatedLocations "A" 18 3 .globallyCommitted with
      txid := some repeatedTimeoutTxid },
    sendEvent repeatedLocations 19 "first-pending-iamopen" "iamopen:B" .opening,
    sendEvent repeatedLocations 20 "second-pending-iamopen" "iamopen:B" .opening,
    { lifecycleEvent repeatedLocations "A" 21 2 .globallyCommitted with
      txid := some repeatedVoteTxid }
  ]
  match replay repeatedTrace with
  | .ok state =>
      let active <- activeState state
      expect (phaseAt active "A" == some .opening)
        "repeated sends changed out-of-order canonical replay"
      expect active.pendingCommits.isEmpty
        "lower final callback did not release the pending commit"
      expect active.pendingSendBatches.isEmpty
        "repeated pending-state send batch remained incomplete"
  | .error failure =>
      throw (IO.userError
        s!"repeated sends from a pending commit were rejected: {repr failure}")

  expect
    (replayFailedAt [
      start,
      send,
      receive,
      local0,
      { lifecycleEvent locations "A" 4 0 .globallyCommitted with
        txid := some tx1 }
    ] 5)
    "final lifecycle accepted a TxID different from its local commit"

  let reuseLocations := ["A", "B"]
  let reuseStart := startEvent reuseLocations "A"
  let firstGossipA :=
    sendEvent reuseLocations 1 "first-gossip-a" "gossip:A" .gossiping
  let firstGossipB :=
    sendEvent reuseLocations 2 "first-gossip-b" "gossip:B" .gossiping 1
  let firstReceive := {
    gossipEvent reuseLocations 3 "first-receive" "first-gossip-a" .gossiping with
      attempt := some 0
  }
  let reusedTxid : TxID := { view := 2, seqno := 20 }
  let firstLocal := {
    lifecycleEvent reuseLocations "A" 4 0 .locallyCommitted with
      txid := some reusedTxid
  }
  let secondGossipA :=
    sendEvent reuseLocations 6 "second-gossip-a" "gossip:A" .gossiping
  let secondGossipB :=
    sendEvent reuseLocations 7 "second-gossip-b" "gossip:B" .gossiping 6
  let duplicateReceive := {
    gossipEvent reuseLocations 8 "duplicate-receive" "second-gossip-a"
      .gossiping with
        attempt := some 1
  }
  let duplicateLocal := {
    lifecycleEvent reuseLocations "A" 9 1 .locallyCommitted with
      txid := some reusedTxid
  }
  match replay [
    reuseStart,
    firstGossipA,
    firstGossipB,
    firstReceive,
    firstLocal,
    { lifecycleEvent reuseLocations "A" 5 0 .globallyCommitted with
      txid := some reusedTxid },
    secondGossipA,
    secondGossipB,
    duplicateReceive,
    duplicateLocal,
    { lifecycleEvent reuseLocations "A" 10 1 .globallyCommitted with
      txid := some reusedTxid }
  ] with
  | .ok state =>
      let active <- activeState state
      expect (active.committedRecords.length == 2)
        "read-only attempts did not retain a reused TxID"
      expect active.pendingCommits.isEmpty
        "equal-TxID attempts were not ordered by attempt"
  | .error failure =>
      throw (IO.userError
        s!"read-only attempts sharing a TxID were rejected: {repr failure}")
  match validate [
    reuseStart,
    firstGossipA,
    firstGossipB,
    firstReceive,
    firstLocal
  ] with
  | .error failure =>
      expect
        (failure.message ==
          "trace ended with locally committed attempts awaiting final status")
        "unresolved local commit reported the wrong failure"
  | .ok () =>
      throw (IO.userError "unresolved local commit passed terminal validation")

  let completedVote :=
    sendEvent locations 4 "completed-vote" "vote:A" .voting
  let completedGossip :=
    sendEvent locations 5 "completed-gossip" "gossip:A" .voting 4
  let committedOpeningVote := {
    voteEvent locations 6 "committed-opening-vote" "completed-vote" .opening with
    attempt := some 1
  }
  let committedOpening := {
    openEvent locations 7 .quorum with attempt := some 1
  }
  let committedOpeningLifecycle :=
    lifecycleEvent locations "A" 8 1 .globallyCommitted
  let postCommitVote :=
    sendEvent locations 9 "post-commit-vote" "vote:A" .voting
  let postCommitGossip :=
    sendEvent locations 10 "post-commit-gossip" "gossip:A" .voting 9
  match replay [
    start,
    send,
    receive,
    committed,
    completedVote,
    completedGossip,
    committedOpeningVote,
    committedOpening,
    committedOpeningLifecycle,
    postCommitVote,
    postCommitGossip
  ] with
  | .ok state =>
      let active <- activeState state
      expect (phaseAt active "A" == some .opening)
        "post-commit prepared batch changed canonical state"
      expect active.pendingSendBatches.isEmpty
        "post-commit prepared batch did not finish"
  | .error failure =>
      throw (IO.userError
        s!"first send after state-changing commit was rejected: {repr failure}")

  let rollback := lifecycleEvent locations "A" 3 0 .rolledBack
  let canonicalAfterRollback :=
    sendEvent locations 4 "canonical-after-rollback" "gossip:A" .gossiping
  let staleAfterChoice :=
    sendEvent locations 5 "stale-after-choice" "vote:A" .voting
  match replay [
    start,
    send,
    receive,
    rollback,
    canonicalAfterRollback,
    staleAfterChoice,
    sendEvent locations 6 "stale-after-choice-gossip" "gossip:A" .voting 5
  ] with
  | .ok state =>
      let active <- activeState state
      expect (phaseAt active "A" == some .gossiping)
        "delayed rolled-back batch changed canonical state"
      expect active.pendingSendBatches.isEmpty
        "delayed rolled-back batch did not finish"
  | .error failure =>
      throw (IO.userError
        s!"delayed rolled-back batch was rejected: {repr failure}")

  let votingSend :=
    sendEvent locations 4 "send-vote" "vote:A" .voting
  let openingVote := {
    voteEvent locations 5 "receive-vote" "send-vote" .opening with
    attempt := some 1
  }
  let opening := { openEvent locations 6 .quorum with attempt := some 1 }
  let openingCommit :=
    lifecycleEvent locations "A" 7 1 .globallyCommitted
  let remainingSend :=
    sendEvent locations 8 "send-voting-gossip" "gossip:A" .voting 4
  match replay [
    start,
    send,
    receive,
    committed,
    votingSend,
    openingVote,
    opening,
    openingCommit,
    remainingSend
  ] with
  | .ok state =>
      let active <- activeState state
      expect (phaseAt active "A" == some .opening)
        "interleaved lifecycle was not applied"
      expect active.pendingSendBatches.isEmpty
        "lifecycle interleaving broke an immediate send batch"
  | .error failure =>
      throw (IO.userError s!"interleaved send batch was rejected: {repr failure}")
  match replay [
    start,
    send,
    receive,
    committed,
    votingSend,
    openingVote,
    opening,
    openingCommit,
    remainingSend,
    sendEvent locations 9 "delayed-vote" "vote:A" .voting,
    sendEvent locations 10 "delayed-gossip" "gossip:A" .voting 9
  ] with
  | .ok state =>
      let active <- activeState state
      expect (phaseAt active "A" == some .opening)
        "delayed pre-commit batch changed canonical state"
      expect active.pendingSendBatches.isEmpty
        "delayed pre-commit batch did not finish"
  | .error failure =>
      throw (IO.userError
        s!"delayed pre-commit batch was rejected: {repr failure}")

  for lifecycle in [.rolledBack, .aborted] do
    let discarded := if lifecycle == .aborted then
      { lifecycleEvent locations "A" 3 0 lifecycle with txid := none }
    else
      lifecycleEvent locations "A" 3 0 lifecycle
    let retry := {
      gossipEvent locations 4 "receive-retry" "send-gossip" .voting with
      attempt := some 1
    }
    let retryCommit := lifecycleEvent locations "A" 5 1 .globallyCommitted
    match replay [start, send, receive, discarded, retry, retryCommit] with
    | .ok state =>
        let active <- activeState state
        expect (phaseAt active "A" == some .voting)
          "discarded attempt changed canonical state"
        expect (active.consumedSendIds == ["send-gossip"])
          "discarded attempt consumed a send needed by its committed retry"
    | .error failure =>
        throw (IO.userError s!"discarded attempt retry failed: {repr failure}")

  let unresolved := quorumTrace ++ [
    { timeoutEvent locations 16 .open .open with attempt := some 5 }
  ]
  expect (validationSucceeds unresolved)
    "unresolved end-of-log attempt was rejected"

  expect
    (replayFailedAt
      [start, lifecycleEvent locations "A" 1 99 .globallyCommitted] 2)
    "lifecycle for an unknown attempt was accepted"
  let aborted := {
    lifecycleEvent locations "A" 2 0 .aborted with txid := none
  }
  expect
    (replayFailedAt [
      start,
      { timeoutEvent locations 1 .gossiping .gossiping with attempt := some 0 },
      aborted,
      { aborted with sequence := 3 }
    ] 4)
    "second lifecycle for a resolved attempt was accepted"
  expect
    (replayFailedAt [
      start,
      { timeoutEvent locations 1 .gossiping .gossiping with attempt := some 0 },
      { timeoutEvent locations 2 .gossiping .gossiping with attempt := some 0 }
    ] 3)
    "duplicate active attempt key was accepted"
  expect
    (replayFailedAt [
      start,
      { timeoutEvent locations 1 .gossiping .gossiping with attempt := some 0 },
      { timeoutEvent locations 2 .gossiping .gossiping with attempt := some 1 },
      { timeoutEvent locations 3 .gossiping .gossiping with attempt := some 0 }
    ] 4)
    "closed active attempt key was reused"
  expect
    (replayFailedAt [
      start,
      { openEvent locations 1 .quorum with attempt := some 0 }
    ] 2)
    "correlated event without a transaction attempt was accepted"

  expect
    (replayFailedAt [
      start,
      { timeoutEvent locations 1 .gossiping .gossiping with attempt := none }
    ] 2)
    "attempt-less speculative event was accepted"
  expect
    (replayFailedAt [{ start with attempt := some 0 }] 1)
    "attempt on start was accepted"
  expect
    (replayFailedAt [start, { send with attempt := some 0 }] 2)
    "attempt on send was accepted"
  expect
    (replayFailedAt [start, { send with batch := none }] 2)
    "send without a batch was accepted"
  expect
    (replayFailedAt [{ start with batch := some 0 }] 1)
    "batch on a non-send event was accepted"
  expect
    (replayFailedAt [
      start,
      send,
      { sendEvent locations 2 "reused-batch" "gossip:A" .gossiping with
        batch := send.batch }
    ] 3)
    "completed send batch was reused"

  let lifecycle := lifecycleEvent locations "A" 1 0 .globallyCommitted
  expect
    (replayFailedAt [start, { lifecycle with attempt := none }] 2)
    "attempt-less lifecycle was accepted"
  expect
    (replayFailedAt [start, { lifecycle with txid := none }] 2)
    "transaction lifecycle without TxID was accepted"
  expect
    (replayFailedAt [start, {
      lifecycleEvent locations "A" 1 0 .locallyCommitted with txid := none
    }] 2)
    "local commit without TxID was accepted"
  expect
    (replayFailedAt [start, {
      lifecycleEvent locations "A" 1 0 .aborted with
      txid := some { view := 1, seqno := 1 }
    }] 2)
    "aborted lifecycle with TxID was accepted"
  expect
    (replayFailedAt [start, { lifecycle with
      pre := some .gossiping
      post := some .gossiping
    }] 2)
    "lifecycle with pre/post was accepted"

  let rolled := lifecycleEvent locations "A" 3 0 .rolledBack
  let duplicateReceive := {
    gossipEvent locations 4 "receive-gossip" "send-gossip" .voting with
    attempt := some 1
  }
  expect
    (replayFailedAt [start, send, receive, rolled, duplicateReceive] 5)
    "discarded receive message_id was allowed to repeat"

private def failoverTrace : List TraceEvent :=
  let locations := ["A", "B"]
  [
    startEvent locations "A",
    sendEvent locations 1 "gossip-a" "gossip:A" .gossiping,
    sendEvent locations 2 "gossip-b" "gossip:B" .gossiping 1,
    { gossipEvent locations 3 "receive-gossip" "gossip-a" .gossiping with
      attempt := some 0 },
    lifecycleEvent locations "A" 4 0 .globallyCommitted,
    { timeoutEvent locations 5 .gossiping .voting with attempt := some 1 },
    lifecycleEvent locations "A" 6 1 .globallyCommitted,
    sendEvent locations 7 "vote-a" "vote:A" .voting,
    sendEvent locations 8 "voting-gossip-a" "gossip:A" .voting 7,
    sendEvent locations 9 "voting-gossip-b" "gossip:B" .voting 7,
    { voteEvent locations 10 "receive-vote" "vote-a" .voting with
      attempt := some 2 },
    lifecycleEvent locations "A" 11 2 .globallyCommitted,
    { timeoutEvent locations 12 .voting .opening with attempt := some 3 },
    { openEvent locations 13 .failover with attempt := some 3 },
    lifecycleEvent locations "A" 14 3 .globallyCommitted,
    { timeoutEvent locations 15 .opening .open with attempt := some 4 },
    { completeEvent locations 16 with attempt := some 4 },
    lifecycleEvent locations "A" 17 4 .globallyCommitted
  ]

private def checkMultiNodeLogs : IO Unit := do
  let locations := ["A", "B"]
  let opener := failoverTrace.take 15 ++ [
    sendEvent locations 15 "send-open-b" "iamopen:B" .opening,
    sendEvent locations 16 "send-open-b-duplicate" "iamopen:B" .opening,
    { timeoutEvent locations 17 .opening .open with attempt := some 4 },
    { completeEvent locations 18 with attempt := some 4 },
    lifecycleEvent locations "A" 19 4 .globallyCommitted
  ]
  let joiner := [
    startEvent locations "B",
    { baseEvent locations "B" 1 .iAmOpenAccepted with
      attempt := some 0
      messageId := some "receive-open-b"
      causedBy := some "send-open-b"
      source := some "A"
      pre := some .gossiping
      post := some .joining },
    { baseEvent locations "B" 2 .joinRestart with
      attempt := some 0
      pre := some .joining
      post := some .joining },
    lifecycleEvent locations "B" 3 0 .globallyCommitted,
    { baseEvent locations "B" 4 .iAmOpenAccepted with
      attempt := some 1
      messageId := some "receive-open-b-duplicate"
      causedBy := some "send-open-b-duplicate"
      source := some "A"
      pre := some .joining
      post := some .joining },
    lifecycleEvent locations "B" 5 1 .globallyCommitted,
    { baseEvent locations "B" 6 .timeout with
      attempt := some 2
      pre := some .joining
      post := some .joining },
    lifecycleEvent locations "B" 7 2 .globallyCommitted
  ]
  let logs := [("b.out", jsonLog joiner), ("a.out", textLog opener)]
  let scenario : Scenario := { participatingNodes := 2, openKind := .failover }
  expect (accepted (validateTextLogs logs scenario) (opener.length + joiner.length))
    "producer-shaped duplicate IAmOpen or Joining timeout was rejected"
  expect (accepted (validateTextLogs logs.reverse scenario) (opener.length + joiner.length))
    "log path order changed distributed validation"
  expectIncomplete
    (validateTextLogs [("b.out", jsonLog (joiner.take 3)), ("a.out", textLog opener)] scenario)
    "unterminated joiner was accepted"
  expectInvalid (validateTextLogs logs { scenario with participatingNodes := 1 })
    "extra participating node was accepted"

private def checkLogCLI : IO Unit := do
  let directory := System.FilePath.mk ".lake/trace-checks"
  IO.FS.createDirAll directory
  let path := directory / "node log.out"
  let validator := ".lake/build/bin/trace-validator"
  let run := fun (kind : String) (timeout : String) => IO.Process.output {
    cmd := validator
    args := #["--logs", "1", kind, timeout, path.toString]
  }
  IO.FS.writeFile path (textLog quorumTrace)
  let accepted <- run "QUORUM" "0"
  expect (accepted.exitCode == 0) s!"raw log CLI failed: {accepted.stderr}"
  IO.FS.writeFile path (jsonLog failoverTrace)
  let failover <- run "FAILOVER" "0"
  expect (failover.exitCode == 0) s!"failover log CLI failed: {failover.stderr}"
  let wrongKind <- run "QUORUM" "0"
  expect (wrongKind.exitCode == 1) "CLI accepted wrong scenario"
  IO.FS.writeFile path (textLog quorumTrace.dropLast)
  let incomplete <- run "QUORUM" "0"
  expect (incomplete.exitCode == 1) "CLI accepted missing completion"
  let child <- IO.Process.spawn {
    cmd := validator
    args := #["--logs", "1", "QUORUM", "2000", path.toString]
    stdout := .piped
    stderr := .piped
  }
  IO.sleep 100
  IO.FS.withFile path .append fun handle =>
    handle.putStr (textLog [quorumTrace.getLast!])
  let code <- child.wait
  let error <- child.stderr.readToEnd
  expect (code == 0) s!"CLI did not wait for appended completion: {error}"
  IO.FS.writeFile path "RDP_TRACE {broken}\n"
  let before <- IO.monoMsNow
  let invalid <- run "QUORUM" "30000"
  expect (invalid.exitCode == 1) "CLI accepted malformed trace JSON"
  expect ((← IO.monoMsNow) - before < 5000) "CLI retried malformed input"
  let missing <- IO.Process.output {
    cmd := validator
    args := #["--logs", "1", "QUORUM", "0", (directory / "missing").toString]
  }
  expect (missing.exitCode != 0) "CLI ignored unreadable log"
  for args in [
      #["--logs", "0", "QUORUM", "0", path.toString],
      #["--logs", "1", "WRONG", "0", path.toString],
      #["--logs", "1", "QUORUM", "-1", path.toString],
      #["--logs", "1", "QUORUM", "0"]] do
    let badArgs <- IO.Process.output { cmd := validator, args }
    expect (badArgs.exitCode == 2) "CLI accepted invalid arguments"
  IO.FS.writeFile path (String.join (quorumTrace.map fun event =>
    (eventJson event).compress ++ "\n"))
  let ndjson <- IO.Process.output { cmd := validator, args := #[path.toString] }
  expect (ndjson.exitCode == 0) "existing ordered NDJSON interface was broken"
  IO.FS.removeFile path

def main : IO UInt32 := do
  checkLogs
  checkMultiNodeLogs
  checkLogCLI
  checkAttempts
  expect (validationSucceeds quorumTrace) "complete quorum trace was rejected"

  let locations := ["A", "B"]
  expect
    (failedAt [startEvent locations "A", startEvent locations "B"] 2)
    "incomplete multi-node trace was accepted"
  expect
    (failedAt [startEvent locations "A"] 1)
    "incomplete single-node trace was accepted"
  expect
    (failedAt [startEvent locations "A", startEvent locations "A"] 2)
    "duplicate start was accepted"
  expect
    (failedAt [startEvent ["A", "A"] "A"] 1)
    "duplicate expected locations were accepted"
  expect
    (failedAt [{ startEvent ["A"] "A" with instanceId := "" }] 1)
    "empty recovery instance was accepted"

  let single := ["A"]
  let start := startEvent single "A"
  let gossipSend := sendEvent single 1 "send-gossip" "gossip:A" .gossiping
  let missingCause := {
    gossipEvent single 2 "receive-gossip" "missing" .voting with
    causedBy := none
  }
  expect
    (failedAt [start, gossipSend, missingCause] 3)
    "receive without caused_by was accepted"

  let wrongClass := {
    voteEvent single 2 "receive-vote" "send-gossip" .voting with
    pre := some .gossiping
  }
  expect
    (failedAt [start, gossipSend, wrongClass] 3)
    "vote consumed a gossip send"

  let wrongTxid := {
    gossipEvent single 2 "receive-gossip" "send-gossip" .voting with
    txid := some { view := 9, seqno := 9 }
  }
  expect
    (failedAt [start, gossipSend, wrongTxid] 3)
    "gossip received a different TxID than its send"

  let wrongPost := {
    gossipEvent single 2 "receive-gossip" "send-gossip" .open with
    attempt := some 0
  }
  expect
    (failedAt [
      start,
      gossipSend,
      wrongPost,
      lifecycleEvent single "A" 3 0 .globallyCommitted
    ] 4)
    "invalid gossip post-state was accepted"

  let received := {
    gossipEvent single 2 "receive-gossip" "send-gossip" .voting with
    attempt := some 0
  }
  let reusedCause := {
    gossipEvent single 4 "receive-gossip-again" "send-gossip" .voting with
    attempt := some 1
    pre := some .voting
  }
  expect
    (failedAt [
      start,
      gossipSend,
      received,
      lifecycleEvent single "A" 3 0 .globallyCommitted,
      reusedCause,
      lifecycleEvent single "A" 5 1 .globallyCommitted
    ] 6)
    "one send caused multiple receives"

  let badSend := sendEvent single 1 "send-vote" "vote:A" .gossiping
  expect
    (failedAt [start, badSend] 2)
    "Voting send was accepted while Gossiping"

  let abortedTimeout := {
    timeoutEvent single 1 .gossiping .gossiping with attempt := some 0
  }
  expect
    (failedAt [
      start,
      abortedTimeout,
      lifecycleEvent single "A" 2 0 .globallyCommitted
    ] 3)
    "committed empty-gossip timeout was accepted"

  let throughVote := quorumTrace.take 7
  expect
    (failedAt (throughVote ++ [
      { openEvent single 7 .quorum with attempt := some 1 },
      { openEvent single 8 .quorum with attempt := some 1 },
      lifecycleEvent single "A" 9 1 .globallyCommitted
    ]) 10)
    "one opening transition produced multiple open observations"
  expect
    (failedAt (quorumTrace.take 7 ++ [
      lifecycleEvent single "A" 7 1 .globallyCommitted
    ]) 8)
    "trace with an unobserved opening effect was accepted"

  let rejectedJson :=
    "{\"instance\":\"x\",\"expected_locations\":[\"A\"],"
      ++ "\"node\":\"A\",\"sequence\":0,\"kind\":\"gossip_rejected\","
      ++ "\"pre\":\"GOSSIPING\",\"post\":\"GOSSIPING\"}"
  expect (parseFails rejectedJson)
    "unused rejection event remains in the trace format"

  let lifecycleJson :=
    "{\"instance\":\"x\",\"expected_locations\":[\"A\"],"
      ++ "\"node\":\"A\",\"sequence\":1,\"kind\":\"globally_committed\","
      ++ "\"attempt\":7,\"view\":2,\"seqno\":3}"
  match parseEvent lifecycleJson with
  | .ok event =>
      expect
        (event.kind == .globallyCommitted && event.attempt == some 7 &&
          event.txid == some { view := 2, seqno := 3 })
        "lifecycle fields were not parsed"
  | .error message =>
      throw (IO.userError s!"valid lifecycle JSON was rejected: {message}")

  IO.println "all raw log, CLI, and strict trace replay checks passed"
  pure 0
