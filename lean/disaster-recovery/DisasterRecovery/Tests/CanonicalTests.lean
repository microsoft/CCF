import DisasterRecovery.Model
import DisasterRecovery.Tests.Network

open DisasterRecovery
open Shared
open DisasterRecovery.Model.Local

example (config : Config) (location : Location) :
    (transitionSystem config location).Reachable (initialNode location) :=
  .initial rfl

example (config : Model.Config) (active : List Location)
    (valid : config.Valid)
    (nodup : active.Nodup)
    (configured :
      forall node, node ∈ active -> node ∈ config.protocol.expectedLocations) :
    Model.Reachable config (Model.initial config active) := by
  apply TransitionSystem.Reachable.initial
  refine ⟨valid, valid.2.1, ?_, nodup, configured, rfl, ?_⟩
  · simp [Model.initial, List.map_map, Function.comp_def]
  · intro entry member
    rcases List.mem_map.mp member with ⟨node, _, rfl⟩
    rfl

private def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def requireSome (value : Option α) (message : String) : IO α :=
  match value with
  | some result => pure result
  | none => throw (IO.userError message)

private def runLocal (config : Config) (state : NodeState) (event : Event) : IO Result :=
  requireSome (transition config state event) s!"disabled local event: {repr event}"

private def runGlobal (config : Model.Config) (state : Model.State)
    (action : Model.Action) : IO Model.State :=
  requireSome (Model.next config state action) s!"disabled global action: {repr action}"

private def deliverMessage (config : Model.Config) (state : Model.State)
    (source target : Location) (payload : Message) : IO Model.State := do
  let envelope <- requireSome
    (state.network.find? fun message =>
      message.source == source && message.target == target && message.payload == payload)
    s!"missing message from {source} to {target}: {repr payload}"
  runGlobal config state (.deliver envelope)

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

private def enumerate (config : Config) (location : Location) : IO (Nat × Nat) := do
  let machine := transitionSystem config location
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
      edges := edges + 1
      match machine.step state event with
      | none => pure ()
      | some next =>
          let key := stateKey next
          if !seen.contains key then
            seen := seen.insert key states.size
            states := states.push next
    cursor := cursor + 1
  pure (states.size, edges)

def main : IO UInt32 := do
  Tests.Network.run
  let config : Config := {
    instanceId := "canonical-tests"
    expectedLocations := ["A", "B"]
  }
  expect config.isValid "canonical test configuration is invalid"
  expect
    (!({ instanceId := "invalid", expectedLocations := ["A", "A"] } : Config).isValid)
    "duplicate expected locations were accepted"
  expect (voteQuorum config == 2) "two-node strict majority must be two"
  let initial := initialNode "A"
  let machine := transitionSystem config "A"
  expect initial.gossips.isEmpty "canonical C++ state must start without gossip"
  expect ((machine.step initial .timeout).isNone) "empty-gossip timeout must be disabled"
  expect
    (machine.step initial (.receiveGossip "A" { view := 1, seqno := 10 } .rejected) ==
      some initial)
    "rejected validation must be an enabled ignored receive"

  let first <- runLocal config initial
    (.receiveGossip "A" { view := 1, seqno := 10 } .accepted)
  expect (first.state.phase == .gossiping) "one of two gossips advanced early"
  let duplicate <- runLocal config first.state
    (.receiveGossip "A" { view := 99, seqno := 99 } .accepted)
  expect (duplicate.state == first.state) "duplicate gossip changed its recorded TxID"
  let second <- runLocal config first.state
    (.receiveGossip "B" { view := 2, seqno := 1 } .accepted)
  expect (second.state.phase == .voting) "all expected gossips did not advance"
  expect (second.state.chosen == some "B") "full TxID maximum was not chosen"
  let tiedA <- runLocal config initial
    (.receiveGossip "A" { view := 2, seqno := 1 } .accepted)
  let tiedB <- runLocal config tiedA.state
    (.receiveGossip "B" { view := 2, seqno := 1 } .accepted)
  expect (tiedB.state.chosen == some "B") "location did not break a TxID tie"
  let frozen <- runLocal config second.state
    (.receiveGossip "C" { view := 9, seqno := 9 } .accepted)
  expect
    (frozen.state == second.state && frozen.effects == [.rejected "gossip-frozen"])
    "frozen gossip did not leave state unchanged with a rejection diagnostic"

  let oneVote <- runLocal config second.state (.receiveVote "A" .accepted)
  expect (oneVote.state.phase == .voting) "even-node quorum used legacy threshold"
  let twoVotes <- runLocal config oneVote.state (.receiveVote "B" .accepted)
  expect (twoVotes.state.phase == .opening) "strict voting quorum did not open"
  expect (twoVotes.state.openKind == some .quorum) "quorum path mislabeled"
  let emptyVoting := {
    initial with phase := .voting, timeoutState := .voting, chosen := some "A"
  }
  expect (machine.step emptyVoting .timeout == some emptyVoting)
    "zero-vote timeout must be an enabled stutter"
  let failover <- runLocal config { emptyVoting with votes := ["A"] } .timeout
  expect (failover.state.phase == .opening && failover.state.openKind == some .failover)
    "failover timeout did not open"
  let opening := { twoVotes.state with timeoutState := .opening }
  let complete <- runLocal config opening .timeout
  expect (complete.state.phase == .open && complete.effects == [.completed])
    "opening timeout did not emit completion"
  let completedRetry <- runLocal config complete.state .retry
  expect completedRetry.effects.isEmpty "retry replayed a preceding completion effect"
  let ignoredOpen <- runLocal config opening (.receiveIAmOpen "B" .accepted)
  expect
    (ignoredOpen.state == opening &&
      ignoredOpen.effects == [.rejected "already-opening-or-open"])
    "opening must ignore IAmOpen with a rejection diagnostic"
  let misaligned := { opening with timeoutState := .voting }
  expect
    (machine.step misaligned .timeout == some { misaligned with timeoutState := .opening })
    "misaligned timeout must advance only the timeout lane"
  let joining <- runLocal config initial (.receiveIAmOpen "B" .accepted)
  expect (joining.state.phase == .joining && joining.state.restartRequested)
    "IAmOpen did not request joining restart"
  let retry <- runLocal config second.state .retry
  expect (retry.effects == [.sendVote "B", .sendGossip "A", .sendGossip "B"])
    "voting retry did not send vote before continuing gossip"
  expect
    (messages { view := 1, seqno := 10 } retry.effects ==
      [("B", .vote), ("A", .gossip { view := 1, seqno := 10 }),
        ("B", .gossip { view := 1, seqno := 10 })])
    "local send effects were not converted to complete messages"

  let globalConfig : Model.Config := {
    protocol := config
    recovered := [("A", { view := 1, seqno := 10 }), ("B", { view := 2, seqno := 1 })]
  }
  let globalInitial := Model.initial globalConfig ["A", "B"]
  expect ((Model.next globalConfig globalInitial (.local "A" .timeout)).isNone)
    "global empty-gossip timeout must remain disabled"
  expect ((Model.next globalConfig globalInitial (.local "C" .retry)).isNone)
    "inactive nodes must not send messages"
  let sent <- runGlobal globalConfig globalInitial (.local "A" .retry)
  expect (sent.network.length == 2 && sent.nodes == globalInitial.nodes)
    "retry must enqueue messages without changing node state"
  let message <- requireSome
    (sent.network.find? fun envelope => envelope.target == "A") "self-gossip missing"
  let delivered <- runGlobal globalConfig sent (.deliver message)
  expect (delivered.network.length == 1) "delivery did not consume one envelope"
  expect
    (Model.nodeState delivered "A" ==
      some { initial with gossips := [("A", { view := 1, seqno := 10 })] })
    "global delivery did not apply local receive"
  expect (Model.nodeState delivered "B" == Model.nodeState sent "B")
    "delivery changed another node"

  let envelope : Model.Envelope := {
    source := "B", target := "A", payload := .gossip { view := 2, seqno := 1 }
  }
  expect ((Model.next globalConfig globalInitial (.deliver envelope)).isNone)
    "delivery accepted a message absent from the network"
  let beforeDelivery := {
    globalInitial with
    nodes := [("A", second.state), ("B", initialNode "B")]
    network := [envelope, envelope]
  }
  let ignored <- runGlobal globalConfig beforeDelivery (.deliver envelope)
  expect (ignored.network == [envelope] && ignored.nodes == beforeDelivery.nodes)
    "ignored delivery must consume one occurrence without changing node state"
  let ignoredAgain <- runGlobal globalConfig ignored (.deliver envelope)
  expect (ignoredAgain.network.isEmpty && ignoredAgain.nodes == ignored.nodes)
    "second ignored delivery did not consume the remaining occurrence"
  let toInactive := Model.initial globalConfig ["A"]
  let inactiveSent <- runGlobal globalConfig toInactive (.local "A" .retry)
  let inactiveMessage <- requireSome
    (inactiveSent.network.find? fun env => env.target == "B") "inactive gossip missing"
  expect ((Model.next globalConfig inactiveSent (.deliver inactiveMessage)).isNone)
    "an inactive destination accepted a delivery"

  let sentA <- runGlobal globalConfig globalInitial (.local "A" .retry)
  let sentBoth <- runGlobal globalConfig sentA (.local "B" .retry)
  let gossipAA <- deliverMessage globalConfig sentBoth "A" "A"
    (.gossip { view := 1, seqno := 10 })
  let gossipBA <- deliverMessage globalConfig gossipAA "B" "A"
    (.gossip { view := 2, seqno := 1 })
  let gossipAB <- deliverMessage globalConfig gossipBA "A" "B"
    (.gossip { view := 1, seqno := 10 })
  let gossipBB <- deliverMessage globalConfig gossipAB "B" "B"
    (.gossip { view := 2, seqno := 1 })
  let voteA <- runGlobal globalConfig gossipBB (.local "A" .retry)
  let voteBoth <- runGlobal globalConfig voteA (.local "B" .retry)
  let receivedA <- deliverMessage globalConfig voteBoth "A" "B" .vote
  let receivedBoth <- deliverMessage globalConfig receivedA "B" "B" .vote
  let opener <- requireSome (Model.nodeState receivedBoth "B") "opener disappeared"
  expect (opener.phase == .opening && opener.openKind == some .quorum)
    "global strict-majority votes did not open the selected node"
  let advertised <- runGlobal globalConfig receivedBoth (.local "B" .retry)
  let joined <- deliverMessage globalConfig advertised "B" "A" .iAmOpen
  let joiner <- requireSome (Model.nodeState joined "A") "joiner disappeared"
  expect (joiner.phase == .joining && joiner.chosen == some "B" && joiner.restartRequested)
    "global IAmOpen did not request the selected restart"
  let timeout1 <- runGlobal globalConfig joined (.local "B" .timeout)
  let timeout2 <- runGlobal globalConfig timeout1 (.local "B" .timeout)
  let timeout3 <- runGlobal globalConfig timeout2 (.local "B" .timeout)
  let opened <- requireSome (Model.nodeState timeout3 "B") "opened node disappeared"
  expect (opened.phase == .open) "global timeout lane did not complete opening"
  expect ((Model.next globalConfig timeout3 (.local "B" .retry)).isNone)
    "completed node kept sending retries"

  let singleConfig : Model.Config := {
    protocol := { instanceId := "different-snapshots", expectedLocations := ["A"] }
    recovered := [("A", { view := 1, seqno := 10 })]
  }
  let singleInitial := Model.initial singleConfig ["A"]
  let singleSend1 <- runGlobal singleConfig singleInitial (.local "A" .retry)
  let singleSend2 <- runGlobal singleConfig singleSend1 (.local "A" .retry)
  let singleReceived <- deliverMessage singleConfig singleSend2 "A" "A"
    (.gossip { view := 1, seqno := 10 })
  let singleVoting <- runGlobal singleConfig singleReceived (.local "A" .retry)
  let sameMessage : Model.Envelope := {
    source := "A", target := "A", payload := .gossip { view := 1, seqno := 10 }
  }
  expect
    (singleVoting.network ==
      [sameMessage, { source := "A", target := "A", payload := .vote }, sameMessage])
    "messages sent from different local states acquired ghost metadata"
  let singleIgnored <- runGlobal singleConfig singleVoting (.deliver sameMessage)
  expect
    (singleIgnored.network ==
      [{ source := "A", target := "A", payload := .vote }, sameMessage])
    "delivery did not consume the first matching occurrence"

  let unexpectedConfig : Config := {
    instanceId := "unexpected", expectedLocations := ["A"]
  }
  let unexpected <- runLocal unexpectedConfig (initialNode "A")
    (.receiveGossip "OUTSIDE" { view := 1, seqno := 1 } .accepted)
  expect (unexpected.state.phase == .voting)
    "model no longer exposes C++ acceptance of unexpected validated locations"
  let (oneStates, oneEdges) <- enumerate
    { instanceId := "n1", expectedLocations := ["A"] } "A"
  let (twoStates, twoEdges) <- enumerate config "A"
  expect (oneStates == 21 && oneEdges == 168 && twoStates == 151 && twoEdges == 2114)
    "canonical exploration changed its reachable states or event coverage"
  IO.println s!"canonical n=1: {oneStates} states, {oneEdges} event edges"
  IO.println s!"canonical n=2: {twoStates} states, {twoEdges} event edges"
  IO.println "all canonical semantic checks passed"
  pure 0
