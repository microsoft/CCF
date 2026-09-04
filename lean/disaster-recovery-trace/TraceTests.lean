import DisasterRecoveryTrace.Protocol.Trace

open DisasterRecovery.Protocol
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

def main : IO UInt32 := do
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

  IO.println "all strict trace replay checks passed"
  pure 0
