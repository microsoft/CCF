import DisasterRecovery.Protocol.Trace

open DisasterRecovery.Protocol
open DisasterRecovery.Protocol.Trace

private def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def baseEvent
    (locations : List Location)
    (node : Location)
    (sequence : Nat)
    (kind : DisasterRecovery.Protocol.Trace.Kind) :
    DisasterRecovery.Protocol.Trace.TraceEvent := {
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
    (node : Location) : DisasterRecovery.Protocol.Trace.TraceEvent := {
  baseEvent locations node 0 .start with
  pre := some .gossiping
  post := some .gossiping
}

private def validationFailedAt
    (events : List DisasterRecovery.Protocol.Trace.TraceEvent)
    (expectedPrefix : Nat) : Bool :=
  match validate events with
  | .error failure => failure.prefixLength == expectedPrefix
  | .ok _ => false

def main : IO UInt32 := do
  let locations := ["A", "B"]
  match validate [startEvent locations "A", startEvent locations "B"] with
  | .ok 1 => pure ()
  | result =>
      throw (IO.userError s!"multi-node starts were not accepted: {repr result}")

  match validate [startEvent locations "A"] with
  | .ok 1 => pure ()
  | result =>
      throw (IO.userError s!"unavailable configured node was required to start: {repr result}")

  expect
    (validationFailedAt
      [startEvent locations "A", startEvent locations "A"] 2)
    "duplicate start was not rejected at the second event"

  expect
    (validationFailedAt
      [startEvent ["A", "A"] "A"] 1)
    "duplicate expected_locations were not rejected"

  expect
    (validationFailedAt
      [{ startEvent ["A"] "A" with instanceId := "" }] 1)
    "empty recovery instance was not rejected"

  expect
    (validationFailedAt
      [{ baseEvent ["A"] "A" 0 .start with post := some .gossiping }] 1)
    "missing required start pre-state was not rejected"

  let single := ["A"]
  let start := startEvent single "A"
  let retry := {
    baseEvent single "A" 1 .retry with
    pre := some .gossiping
    post := some .gossiping
  }
  let send := {
    baseEvent single "A" 2 .send with
    messageId := some "send-1"
    pre := some .gossiping
    post := some .gossiping
    send := some "gossip:A"
  }
  let wrongCause := {
    baseEvent single "A" 3 .voteAccepted with
    messageId := some "receive-1"
    causedBy := some "send-1"
    source := some "A"
    pre := some .gossiping
    post := some .gossiping
  }
  expect
    (validationFailedAt [start, retry, send, wrongCause] 4)
    "caused_by accepted a send with the wrong message class"

  let duplicateId := {
    baseEvent single "A" 3 .gossipAccepted with
    messageId := some "send-1"
    source := some "A"
    txid := some { view := 1, seqno := 1 }
    pre := some .gossiping
    post := some .voting
  }
  expect
    (validationFailedAt [start, retry, send, duplicateId] 4)
    "duplicate message_id was not rejected"

  let received := {
    baseEvent single "A" 3 .gossipAccepted with
    messageId := some "receive-1"
    causedBy := some "send-1"
    source := some "A"
    txid := some { view := 1, seqno := 1 }
    pre := some .gossiping
    post := some .voting
  }
  let reusedCause := {
    baseEvent single "A" 4 .gossipRejected with
    messageId := some "receive-2"
    causedBy := some "send-1"
    source := some "A"
    txid := some { view := 1, seqno := 1 }
    pre := some .voting
    post := some .voting
  }
  expect
    (validationFailedAt [start, retry, send, received, reusedCause] 5)
    "a send was accepted as the cause of multiple receives"

  let openingVote := {
    baseEvent single "A" 4 .voteAccepted with
    messageId := some "opening-vote"
    source := some "A"
    pre := some .voting
    post := some .opening
  }
  let openedOnce := {
    baseEvent single "A" 5 .open with
    pre := some .opening
    post := some .opening
    openKind := some .quorum
  }
  let openedTwice := {
    openedOnce with sequence := 6
  }
  expect
    (validationFailedAt
      [start, retry, send, received, openingVote, openedOnce, openedTwice] 7)
    "one opening transition produced multiple committed open observations"

  let hiddenReceive := {
    baseEvent single "A" 1 .gossipAccepted with
    messageId := some "receive-hidden"
    causedBy := some "hidden-send"
    source := some "A"
    txid := some { view := 1, seqno := 1 }
    pre := some .gossiping
    post := some .voting
  }
  let lateHiddenSend := {
    baseEvent single "A" 2 .send with
    messageId := some "hidden-send"
    pre := some .voting
    post := some .voting
    send := some "gossip:A"
  }
  expect
    (validationFailedAt [start, hiddenReceive, lateHiddenSend] 3)
    "a hidden causal send ID was accepted later in the trace"

  let selfCaused := {
    hiddenReceive with
    messageId := some "same-id"
    causedBy := some "same-id"
  }
  expect
    (validationFailedAt [start, selfCaused] 2)
    "one observation was accepted as both a send and its receive"

  let abortedTimeout := {
    baseEvent single "A" 1 .timeout with
    pre := some .gossiping
    post := some .gossiping
  }
  expect
    (validationFailedAt [start, abortedTimeout] 2)
    "an aborted empty-gossip timeout was accepted as committed"

  let beforeSourceStart := {
    baseEvent locations "A" 1 .gossipAccepted with
    messageId := some "receive-before-start"
    causedBy := some "hidden-before-start"
    source := some "B"
    txid := some { view := 1, seqno := 1 }
    pre := some .gossiping
    post := some .gossiping
  }
  expect
    (validationFailedAt
      [startEvent locations "A", beforeSourceStart, startEvent locations "B"] 2)
    "a hidden send originated before its source node started"

  let impossibleVote := {
    baseEvent locations "A" 1 .voteAccepted with
    messageId := some "impossible-vote"
    source := some "B"
    pre := some .gossiping
    post := some .gossiping
  }
  expect
    (validationFailedAt
      [startEvent locations "A", startEvent locations "B", impossibleVote] 3)
    "an accepted receive bypassed hidden-send feasibility"

  let externalVote := {
    baseEvent single "A" 1 .voteAccepted with
    messageId := some "external-vote"
    source := some "OUTSIDE"
    pre := some .gossiping
    post := some .gossiping
  }
  match validate [start, externalVote] with
  | .ok 1 => pure ()
  | result =>
      throw (IO.userError s!"external accepted input was rejected: {repr result}")

  let emptySource := {
    baseEvent single "A" 1 .gossipAccepted with
    messageId := some "empty-source"
    source := some ""
    txid := some { view := 1, seqno := 1 }
    pre := some .gossiping
    post := some .voting
  }
  expect
    (validationFailedAt [start, emptySource] 2)
    "an empty receive source was accepted"

  let aGossipA := {
    baseEvent locations "A" 1 .gossipAccepted with
    messageId := some "a-gossip-a"
    source := some "A"
    txid := some { view := 2, seqno := 1 }
    pre := some .gossiping
    post := some .gossiping
  }
  let aGossipB := {
    baseEvent locations "A" 2 .gossipAccepted with
    messageId := some "a-gossip-b"
    source := some "B"
    txid := some { view := 1, seqno := 1 }
    pre := some .gossiping
    post := some .voting
  }
  let bGossipA := {
    baseEvent locations "B" 1 .gossipAccepted with
    messageId := some "b-gossip-a"
    source := some "A"
    txid := some { view := 2, seqno := 1 }
    pre := some .gossiping
    post := some .gossiping
  }
  let bGossipB := {
    baseEvent locations "B" 2 .gossipAccepted with
    messageId := some "b-gossip-b"
    source := some "B"
    txid := some { view := 1, seqno := 1 }
    pre := some .gossiping
    post := some .voting
  }
  let aVoteA := {
    baseEvent locations "A" 3 .voteAccepted with
    messageId := some "a-vote-a"
    source := some "A"
    pre := some .voting
    post := some .voting
  }
  let aVoteB := {
    baseEvent locations "A" 4 .voteAccepted with
    messageId := some "a-vote-b"
    source := some "B"
    pre := some .voting
    post := some .opening
  }
  let delayedGossip := {
    baseEvent locations "B" 3 .gossipRejected with
    messageId := some "b-delayed-gossip"
    causedBy := some "hidden-delayed-gossip"
    source := some "A"
    txid := some { view := 2, seqno := 1 }
    pre := some .voting
    post := some .voting
  }
  let delayedTrace := [
    startEvent locations "A",
    startEvent locations "B",
    aGossipA,
    aGossipB,
    bGossipA,
    bGossipB,
    aVoteA,
    aVoteB,
    delayedGossip
  ]
  match validate delayedTrace with
  | .ok 1 => pure ()
  | result =>
      throw (IO.userError s!"delayed hidden send was rejected: {repr result}")

  let failoverGossipA := {
    baseEvent locations "A" 1 .gossipAccepted with
    messageId := some "failover-gossip-a"
    source := some "A"
    txid := some { view := 1, seqno := 1 }
    pre := some .gossiping
    post := some .gossiping
  }
  let failoverTimeoutA1 := {
    baseEvent locations "A" 2 .timeout with
    pre := some .gossiping
    post := some .voting
  }
  let failoverVoteA := {
    baseEvent locations "A" 3 .voteAccepted with
    messageId := some "failover-vote-a"
    source := some "A"
    pre := some .voting
    post := some .voting
  }
  let failoverTimeoutA2 := {
    baseEvent locations "A" 4 .timeout with
    pre := some .voting
    post := some .opening
  }
  let failoverGossipB := {
    baseEvent locations "B" 1 .gossipAccepted with
    messageId := some "failover-gossip-b"
    source := some "B"
    txid := some { view := 1, seqno := 1 }
    pre := some .gossiping
    post := some .gossiping
  }
  let failoverTimeoutB1 := {
    baseEvent locations "B" 2 .timeout with
    pre := some .gossiping
    post := some .voting
  }
  let failoverVoteB := {
    baseEvent locations "B" 3 .voteAccepted with
    messageId := some "failover-vote-b"
    source := some "B"
    pre := some .voting
    post := some .voting
  }
  let failoverTimeoutB2 := {
    baseEvent locations "B" 4 .timeout with
    pre := some .voting
    post := some .opening
  }
  let openA := {
    baseEvent locations "A" 5 .open with
    pre := some .opening
    post := some .opening
    openKind := some .failover
  }
  let duplicateOpenA := { openA with sequence := 6 }
  let twoFailovers := [
    startEvent locations "A",
    startEvent locations "B",
    failoverGossipA,
    failoverTimeoutA1,
    failoverVoteA,
    failoverTimeoutA2,
    failoverGossipB,
    failoverTimeoutB1,
    failoverVoteB,
    failoverTimeoutB2,
    openA,
    duplicateOpenA
  ]
  expect
    (validationFailedAt twoFailovers 12)
    "node A consumed node B's pending open effect"

  IO.println "all trace contract checks passed"
  pure 0
