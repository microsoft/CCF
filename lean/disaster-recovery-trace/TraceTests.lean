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
  version := contractVersion
  instanceId := "trace-tests"
  expectedLocations := locations
  node
  sequence
  kind
  messageId := none
  causedBy := none
  source := none
  txid := none
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
    (phase : Phase) : TraceEvent := {
  baseEvent locations "A" sequence .send with
  messageId := some messageId
  pre := some phase
  post := some phase
  txid := if description.startsWith "gossip:" then
    some { view := 1, seqno := 1 }
  else
    none
  send := some description
}

private def gossipEvent
    (locations : List Location)
    (sequence : Nat)
    (messageId cause : String)
    (post : Phase) : TraceEvent := {
  baseEvent locations "A" sequence .gossipAccepted with
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
  pre := some pre
  post := some post
}

private def openEvent
    (locations : List Location)
    (sequence : Nat)
    (kind : OpenKind) : TraceEvent := {
  baseEvent locations "A" sequence .open with
  pre := some .opening
  post := some .opening
  openKind := some kind
}

private def completeEvent
    (locations : List Location)
    (sequence : Nat) : TraceEvent := {
  baseEvent locations "A" sequence .complete with
  pre := some .open
  post := some .open
}

private def validationSucceeds (events : List TraceEvent) : Bool :=
  match validate events with
  | .ok () => true
  | .error _ => false

private def failedAt (events : List TraceEvent) (expectedPrefix : Nat) : Bool :=
  match validate events with
  | .error failure => failure.prefixLength == expectedPrefix
  | .ok () => false

private def parseFails (value : String) : Bool :=
  match parseEvent value with
  | .error _ => true
  | .ok _ => false

private def quorumTrace : List TraceEvent :=
  let locations := ["A"]
  [
    startEvent locations "A",
    sendEvent locations 1 "send-gossip" "gossip:A" .gossiping,
    gossipEvent locations 2 "receive-gossip" "send-gossip" .voting,
    sendEvent locations 3 "send-vote" "vote:A" .voting,
    sendEvent locations 4 "send-voting-gossip" "gossip:A" .voting,
    voteEvent locations 5 "receive-vote" "send-vote" .opening,
    openEvent locations 6 .quorum,
    timeoutEvent locations 7 .opening .opening,
    timeoutEvent locations 8 .opening .opening,
    timeoutEvent locations 9 .opening .open,
    completeEvent locations 10
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
  Lean.Json.mkObj ([
    ("version", Lean.toJson event.version),
    ("instance", Lean.toJson event.instanceId),
    ("expected_locations", Lean.toJson event.expectedLocations),
    ("node", Lean.toJson event.node),
    ("sequence", Lean.toJson event.sequence),
    ("kind", Lean.toJson kind)
  ] ++
    (event.messageId.toList.map fun value => ("message_id", Lean.toJson value)) ++
    (event.causedBy.toList.map fun value => ("caused_by", Lean.toJson value)) ++
    (event.source.toList.map fun value => ("source", Lean.toJson value)) ++
    (event.txid.toList.flatMap fun value =>
      [("view", Lean.toJson value.view), ("seqno", Lean.toJson value.seqno)]) ++
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

private def failoverTrace : List TraceEvent :=
  let locations := ["A", "B"]
  [
    startEvent locations "A",
    sendEvent locations 1 "gossip-a" "gossip:A" .gossiping,
    sendEvent locations 2 "gossip-b" "gossip:B" .gossiping,
    gossipEvent locations 3 "receive-gossip" "gossip-a" .gossiping,
    timeoutEvent locations 4 .gossiping .voting,
    sendEvent locations 5 "vote-a" "vote:A" .voting,
    sendEvent locations 6 "voting-gossip-a" "gossip:A" .voting,
    sendEvent locations 7 "voting-gossip-b" "gossip:B" .voting,
    voteEvent locations 8 "receive-vote" "vote-a" .voting,
    timeoutEvent locations 9 .voting .opening,
    openEvent locations 10 .failover,
    timeoutEvent locations 11 .opening .open,
    completeEvent locations 12
  ]

private def checkMultiNodeLogs : IO Unit := do
  let locations := ["A", "B"]
  let opener := failoverTrace.take 11 ++ [
    sendEvent locations 11 "send-open-b" "iamopen:B" .opening,
    timeoutEvent locations 12 .opening .open,
    completeEvent locations 13
  ]
  let joiner := [
    startEvent locations "B",
    { baseEvent locations "B" 1 .iAmOpenAccepted with
      messageId := some "receive-open-b"
      causedBy := some "send-open-b"
      source := some "A"
      pre := some .gossiping
      post := some .joining },
    { baseEvent locations "B" 2 .joinRestart with
      pre := some .joining
      post := some .joining }
  ]
  let logs := [("b.out", jsonLog joiner), ("a.out", textLog opener)]
  let scenario : Scenario := { participatingNodes := 2, openKind := .failover }
  expect (accepted (validateTextLogs logs scenario) (opener.length + joiner.length))
    "distributed opener/joiner logs were rejected"
  expect (accepted (validateTextLogs logs.reverse scenario) (opener.length + joiner.length))
    "log path order changed distributed validation"
  expectIncomplete
    (validateTextLogs [("b.out", jsonLog joiner.dropLast), ("a.out", textLog opener)] scenario)
    "unterminated joiner was accepted"
  expectInvalid (validateTextLogs logs { scenario with participatingNodes := 1 })
    "extra participating node was accepted"

private def checkLogCLI : IO Unit := do
  IO.FS.withTempDir fun directory => do
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

def main : IO UInt32 := do
  checkLogs
  checkMultiNodeLogs
  checkLogCLI
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

  let wrongPost := gossipEvent single 2 "receive-gossip" "send-gossip" .open
  expect
    (failedAt [start, gossipSend, wrongPost] 3)
    "invalid gossip post-state was accepted"

  let received := gossipEvent single 2 "receive-gossip" "send-gossip" .voting
  let reusedCause := {
    voteEvent single 3 "receive-vote" "send-gossip" .voting with
    pre := some .voting
  }
  expect
    (failedAt [start, gossipSend, received, reusedCause] 4)
    "one send caused multiple receives"

  let badSend := sendEvent single 1 "send-vote" "vote:A" .gossiping
  expect
    (failedAt [start, badSend] 2)
    "Voting send was accepted while Gossiping"

  let abortedTimeout := timeoutEvent single 1 .gossiping .gossiping
  expect
    (failedAt [start, abortedTimeout] 2)
    "aborted empty-gossip timeout was accepted"

  let throughOpen := quorumTrace.take 7
  expect
    (failedAt (throughOpen ++ [openEvent single 7 .quorum]) 8)
    "one opening transition produced multiple open observations"
  expect
    (failedAt (quorumTrace.take 6) 6)
    "trace with an unobserved opening effect was accepted"

  let rejectedJson :=
    "{\"version\":\"ccf.recovery_decision_protocol.trace/1\","
      ++ "\"instance\":\"x\",\"expected_locations\":[\"A\"],"
      ++ "\"node\":\"A\",\"sequence\":0,\"kind\":\"gossip_rejected\","
      ++ "\"pre\":\"GOSSIPING\",\"post\":\"GOSSIPING\"}"
  expect (parseFails rejectedJson)
    "unused rejection event remains in the strict v1 format"

  IO.println "all raw log, CLI, and strict trace replay checks passed"
  pure 0
