import DisasterRecovery.Protocol.Refinement
import DisasterRecovery.Protocol.Temporal
import DisasterRecovery.Protocol.Trace

open DisasterRecovery.Protocol

private def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def eventsFor (config : Config) : List Event :=
  let messages := config.expectedLocations.flatMap fun source =>
    [
      .receiveGossip source { view := 0, seqno := source.length } .accepted,
      .receiveGossip source { view := 0, seqno := source.length } .rejected,
      .receiveVote source .accepted,
      .receiveVote source .rejected,
      .receiveIAmOpen source .accepted,
      .receiveIAmOpen source .rejected
    ]
  messages ++ [.timeout, .retry]

private def invariant (state : NodeState) : Bool :=
  let chosenReady :=
    if state.phase == .voting then state.chosen.isSome else true
  let openingKind :=
    if state.phase == .opening || state.phase == .open then
      state.openKind.isSome
    else
      true
  let restartOnlyJoining :=
    if state.restartRequested then state.phase == .joining else true
  chosenReady && openingKind && restartOnlyJoining

private def enumerate (config : Config) (location : Location) : IO (Prod Nat Nat) := do
  let initial := initialNode location
  let mut states := #[initial]
  let mut seen : Std.HashMap String Nat := {}
  seen := seen.insert (stateKey initial) 0
  let mut cursor := 0
  let mut edges := 0
  while cursor < states.size do
    let state := states[cursor]!
    expect (invariant state) s!"canonical invariant failed: {stateKey state}"
    for event in eventsFor config do
      let next := (step config state event).state
      edges := edges + 1
      let key := stateKey next
      if !seen.contains key then
        seen := seen.insert key states.size
        states := states.push next
    cursor := cursor + 1
  pure (states.size, edges)

def main : IO UInt32 := do
  let config : Config := {
    instanceId := "canonical-tests"
    expectedLocations := ["A", "B"]
  }
  expect config.isValid "canonical test configuration is invalid"
  expect
    (!({ instanceId := "invalid", expectedLocations := ["A", "A"] } :
      Config).isValid)
    "duplicate expected locations were accepted"
  expect (voteQuorum config == 2) "two-node strict majority must be two"

  let initial := initialNode "A"
  expect initial.gossips.isEmpty "canonical C++ state must start without gossip"

  let first := step config initial
    (.receiveGossip "A" { view := 1, seqno := 10 } .accepted)
  expect (first.state.phase == .gossiping) "one of two gossips advanced early"
  let duplicate := step config first.state
    (.receiveGossip "A" { view := 99, seqno := 99 } .accepted)
  expect (duplicate.state == first.state)
    "duplicate gossip source changed its recorded TxID"
  let second := step config first.state
    (.receiveGossip "B" { view := 2, seqno := 1 } .accepted)
  expect (second.state.phase == .voting) "all expected gossips did not advance"
  expect (second.state.chosen == some "B") "full TxID maximum was not chosen"

  let tiedA := step config initial
    (.receiveGossip "A" { view := 2, seqno := 1 } .accepted)
  let tiedB := step config tiedA.state
    (.receiveGossip "B" { view := 2, seqno := 1 } .accepted)
  expect (tiedB.state.chosen == some "B")
    "location name did not break an equal TxID tie lexicographically"

  let frozen := step config second.state
    (.receiveGossip "C" { view := 9, seqno := 9 } .accepted)
  expect (!frozen.accepted && frozen.state == second.state)
    "gossip did not freeze after choosing a node"

  let oneVote := step config second.state (.receiveVote "A" .accepted)
  expect (oneVote.state.phase == .voting) "even-node quorum used legacy threshold"
  let twoVotes := step config oneVote.state (.receiveVote "B" .accepted)
  expect (twoVotes.state.phase == .opening) "strict voting quorum did not open"
  expect (twoVotes.state.openKind == some .quorum) "quorum path mislabeled"

  let emptyVoting := {
    initial with
    phase := .voting
    timeoutState := .voting
    chosen := some "A"
  }
  let noVotes := step config emptyVoting .timeout
  expect (noVotes.state == emptyVoting)
    "aligned voting timeout with zero votes advanced"

  let oneVoteWaiting := { emptyVoting with votes := ["A"] }
  let failover := step config oneVoteWaiting .timeout
  expect (failover.state.phase == .opening) "failover vote did not open"
  expect (failover.state.openKind == some .failover) "failover path mislabeled"

  let opening := {
    twoVotes.state with
    timeoutState := .opening
  }
  let complete := step config opening .timeout
  expect (complete.state.phase == .open) "Opening timeout did not reach Open"

  let joining := step config initial
    (.receiveIAmOpen "B" .accepted)
  expect (joining.state.phase == .joining && joining.state.restartRequested)
    "IAmOpen did not request joining restart"

  let retry := step config second.state .retry
  expect
    (retry.effects ==
      [.sendVote "B", .sendGossip "A", .sendGossip "B"])
    "Voting retry did not send vote before continuing gossip"

  let unexpectedConfig : Config := {
    instanceId := "unexpected"
    expectedLocations := ["A"]
  }
  let unexpected := step unexpectedConfig (initialNode "A")
    (.receiveGossip "OUTSIDE" { view := 1, seqno := 1 } .accepted)
  expect (unexpected.state.phase == .voting)
    "model no longer exposes C++ acceptance of unexpected validated locations"

  let (oneStates, oneEdges) <- enumerate
    { instanceId := "n1", expectedLocations := ["A"] } "A"
  let (twoStates, twoEdges) <- enumerate config "A"
  IO.println s!"canonical n=1: {oneStates} states, {oneEdges} event edges"
  IO.println s!"canonical n=2: {twoStates} states, {twoEdges} event edges"
  IO.println "all canonical semantic and proof checks passed"
  pure 0
