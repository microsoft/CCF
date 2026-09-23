import DisasterRecovery.Tests.Initial
import DisasterRecovery.Tests.Network

open DisasterRecovery
open Shared
open DisasterRecovery.Model.Local

private def localMachine (config : Config) (recovered : TxID) (location : Location) :
    TransitionSystem NodeState Event where
  init := fun state => state = initialNode location
  step := fun state event =>
    (step (Capabilities.record location) config recovered state event).map
      (fun execute => (execute.run {}).1)

example (config : Config) (recovered : TxID) (location : Location) :
    (localMachine config recovered location).Reachable (initialNode location) :=
  .initial rfl

private def stepConfig : Model.Config := {
  protocol := { instanceId := "local-step-tests", expectedLocations := ["A"] }
  recovered := [("A", { view := 1, seqno := 10 })]
}

private def frozenStep : MultiNodeTransitionSystem.LocalStep Location NodeState Event Message Notification := {
  node := "A"
  before := { location := "A", chosen := some "B" }
  action := .receiveGossip "OUTSIDE" { view := 9, seqno := 99 } .accepted
  after := { location := "A", chosen := some "B" }
  effects := { notifications := [.rejected "gossip-frozen"] }
}

example : (Model.protocol stepConfig).ValidStep frozenStep := ⟨_, rfl, rfl⟩

example : ¬ (Model.protocol stepConfig).ValidStep { frozenStep with effects := {} } := by
  rintro ⟨execute, enabled, result⟩
  cases enabled
  cases result

example (config : Model.Config) (active : List Location)
    (valid : config.Valid)
    (nodup : active.Nodup)
    (configured :
      forall node, node ∈ active -> node ∈ config.protocol.expectedLocations) :
    (Model.transitionSystem config).Reachable (Tests.initial config active) := by
  apply TransitionSystem.Reachable.initial
  refine ⟨valid, valid.2.1, ?_, nodup, configured, rfl, ?_⟩
  · simp [Tests.initial, List.map_map, Function.comp_def]
  · intro entry member
    rcases List.mem_map.mp member with ⟨node, _, rfl⟩
    rfl

private def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def requireSome (value : Option α) (message : String) : IO α :=
  match value with
  | some result => pure result
  | none => throw (IO.userError message)

private def runLocal (config : Config) (state : NodeState) (event : Event) :
    IO (NodeState × Outputs Location Message Notification) :=
  requireSome
    ((step (Capabilities.record state.location) config { view := 1, seqno := 10 } state event).map
      (fun execute => execute.run {}))
    s!"disabled local event: {repr event}"

private def runGlobal (config : Model.Config) (state : Model.State)
    (action : Model.Action) : IO Model.State :=
  requireSome ((Model.transitionSystem config).step state action) s!"disabled global action: {repr action}"

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

private def phaseName : Phase -> String
  | .gossiping => "GOSSIPING"
  | .voting => "VOTING"
  | .opening => "OPENING"
  | .joining => "JOINING"
  | .open => "OPEN"

private def openKindName : OpenKind -> String
  | .quorum => "QUORUM"
  | .failover => "FAILOVER"

private def stateKey (state : NodeState) : String :=
  let gossips := String.intercalate "," (state.gossips.map fun entry =>
    s!"{entry.1}@{entry.2.view}.{entry.2.seqno}")
  let votes := String.intercalate "," state.votes
  let chosen := state.chosen.getD "-"
  let kind := state.openKind.map openKindName |>.getD "-"
  s!"{state.location}|{phaseName state.phase}|{phaseName state.timeoutState}|g={gossips}|v={votes}|c={chosen}|k={kind}|r={state.restartRequested}"

private def enumerate (config : Config) (location : Location) : IO (Nat × Nat) := do
  let recovered : TxID := { view := 0, seqno := 0 }
  let machine := localMachine config recovered location
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
      let emitted := step (Capabilities.record location) config recovered state event
      if let some execute := emitted then
        let (after, effects) := execute.run {}
        let pending : Outputs Location Message Notification := {
          outgoing := [{ source := location, target := location, payload := .vote }]
          notifications := [.rejected "existing-notification"]
        }
        let (afterPending, accumulated) := execute.run pending
        expect (afterPending == after &&
            accumulated.outgoing == pending.outgoing ++ effects.outgoing &&
            accumulated.notifications == pending.notifications ++ effects.notifications)
          s!"pending outputs changed local execution: {repr event}"
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
  let machine := localMachine config { view := 1, seqno := 10 } "A"
  expect initial.gossips.isEmpty "canonical C++ state must start without gossip"
  expect ((machine.step initial .timeout).isNone) "empty-gossip timeout must be disabled"
  expect
    (machine.step initial (.receiveGossip "A" { view := 1, seqno := 10 } .rejected) ==
      some initial)
    "rejected validation must be an enabled ignored receive"

  let first <- runLocal config initial
    (.receiveGossip "A" { view := 1, seqno := 10 } .accepted)
  expect (first.1.phase == .gossiping) "one of two gossips advanced early"
  let duplicate <- runLocal config first.1
    (.receiveGossip "A" { view := 99, seqno := 99 } .accepted)
  expect (duplicate.1 == first.1) "duplicate gossip changed its recorded TxID"
  let second <- runLocal config first.1
    (.receiveGossip "B" { view := 2, seqno := 1 } .accepted)
  expect (second.1.phase == .voting) "all expected gossips did not advance"
  expect (second.1.chosen == some "B") "full TxID maximum was not chosen"
  let tiedA <- runLocal config initial
    (.receiveGossip "A" { view := 2, seqno := 1 } .accepted)
  let tiedB <- runLocal config tiedA.1
    (.receiveGossip "B" { view := 2, seqno := 1 } .accepted)
  expect (tiedB.1.chosen == some "B") "location did not break a TxID tie"
  let frozen <- runLocal config second.1
    (.receiveGossip "C" { view := 9, seqno := 9 } .accepted)
  expect
    (frozen.1 == second.1 && frozen.2.notifications == [.rejected "gossip-frozen"])
    "frozen gossip did not leave state unchanged with a rejection diagnostic"
  expect frozen.2.outgoing.isEmpty "gossip rejection generated a network reply"
  for event in [
      Event.receiveGossip "B" { view := 9, seqno := 99 } .rejected,
      .receiveVote "B" .rejected,
      .receiveIAmOpen "B" .rejected] do
    let (after, effects) <- runLocal config second.1 event
    expect (after == second.1 && effects.outgoing.isEmpty &&
        effects.notifications == [.rejected "quote-or-certificate"])
      "validation rejection changed state, sent a reply, or recorded the wrong notification"

  let oneVote <- runLocal config second.1 (.receiveVote "A" .accepted)
  expect (oneVote.1.phase == .voting) "even-node quorum used legacy threshold"
  let twoVotes <- runLocal config oneVote.1 (.receiveVote "B" .accepted)
  expect (twoVotes.1.phase == .opening) "strict voting quorum did not open"
  expect (twoVotes.1.openKind == some .quorum) "quorum path mislabeled"
  expect (twoVotes.2.notifications == [.opening .quorum] && twoVotes.2.outgoing.isEmpty)
    "quorum opening failed to notify without sending"
  let emptyVoting := {
    initial with phase := .voting, timeoutState := .voting, chosen := some "A"
  }
  expect (machine.step emptyVoting .timeout == some emptyVoting)
    "zero-vote timeout must be an enabled stutter"
  let failover <- runLocal config { emptyVoting with votes := ["A"] } .timeout
  expect (failover.1.phase == .opening && failover.1.openKind == some .failover)
    "failover timeout did not open"
  expect (failover.2.notifications == [.opening .failover] && failover.2.outgoing.isEmpty)
    "failover opening failed to notify without sending"
  let opening := { twoVotes.1 with timeoutState := .opening }
  let complete <- runLocal config opening .timeout
  expect (complete.1.phase == .open && complete.2.notifications == [.completed])
    "opening timeout did not emit completion"
  expect ((machine.step complete.1 .retry).isNone)
    "standalone completed retry must be disabled, matching the network step"
  let ignoredOpen <- runLocal config opening (.receiveIAmOpen "B" .accepted)
  expect
    (ignoredOpen.1 == opening &&
      ignoredOpen.2.notifications == [.rejected "already-opening-or-open"])
    "opening must ignore IAmOpen with a rejection diagnostic"
  let misaligned := { opening with timeoutState := .voting }
  expect
    (machine.step misaligned .timeout == some { misaligned with timeoutState := .opening })
    "misaligned timeout must advance only the timeout lane"
  let joining <- runLocal config initial (.receiveIAmOpen "B" .accepted)
  expect (joining.1.phase == .joining && joining.1.restartRequested)
    "IAmOpen did not request joining restart"
  expect (joining.2.notifications == [.restart "B"] && joining.2.outgoing.isEmpty)
    "joining failed to record the selected restart notification"
  let globalConfig : Model.Config := {
    protocol := config
    recovered := [("A", { view := 1, seqno := 10 }), ("B", { view := 2, seqno := 1 })]
  }
  let retry (config : Model.Config) (state : NodeState) :
      Option (NodeState × List Model.Envelope) := do
    let recovered <- Model.recoveredTxID config "A"
    let execute <- step (Capabilities.record "A") config.protocol recovered state .retry
    let (after, effects) := execute.run {}
    pure (after, effects.outgoing)
  let (retried, outgoing) <- requireSome
    (retry globalConfig second.1)
    "voting retry was disabled"
  expect (retried == second.1 &&
      outgoing == [
        { source := "A", target := "B", payload := .vote },
        { source := "A", target := "A", payload := .gossip { view := 1, seqno := 10 } },
        { source := "A", target := "B", payload := .gossip { view := 1, seqno := 10 } }])
    "voting retry did not send vote before continuing gossip"
  expect
    ((retry globalConfig complete.1).isNone)
    "completed retry must be disabled without sending or replaying completion"
  let gossip : List Model.Envelope := [
    { source := "A", target := "A", payload := .gossip { view := 1, seqno := 10 } },
    { source := "A", target := "B", payload := .gossip { view := 1, seqno := 10 } }
  ]
  let retryCases : List (NodeState × Option (List Model.Envelope)) := [
    (initial, some gossip),
    ({ initial with chosen := some "B" }, some gossip),
    ({ initial with phase := .voting }, some gossip),
    ({ initial with phase := .opening },
      some [{ source := "A", target := "B", payload := .iAmOpen }]),
    ({ initial with phase := .joining }, none),
    ({ initial with phase := .open }, none)
  ]
  for (before, expected) in retryCases do
    expect
      (retry globalConfig before ==
        expected.map (fun sent => (before, sent)))
      s!"direct retry sends differ in {repr before.phase}"
  let noPeers := { globalConfig with protocol := { config with expectedLocations := [] } }
  expect ((retry noPeers initial).isNone)
    "empty gossip retry must be disabled"
  expect
    (retry noPeers second.1 ==
      some (second.1, [{ source := "A", target := "B", payload := .vote }]))
    "a vote-only retry must remain enabled"
  expect
    ((retry noPeers { initial with phase := .opening }).isNone)
    "opening retry without recipients must be disabled"
  let globalInitial := Tests.initial globalConfig ["A", "B"]
  expect (((Model.transitionSystem globalConfig).step globalInitial (.local "A" .timeout)).isNone)
    "global empty-gossip timeout must remain disabled"
  expect (((Model.transitionSystem globalConfig).step globalInitial (.local "C" .retry)).isNone)
    "inactive nodes must not send messages"
  let sent <- runGlobal globalConfig globalInitial (.local "A" .retry)
  expect (sent.network.length == 2 && sent.nodes == globalInitial.nodes)
    "retry must enqueue messages without changing node state"
  let message <- requireSome
    (sent.network.find? fun envelope => envelope.target == "A") "self-gossip missing"
  let delivered <- runGlobal globalConfig sent (.deliver message)
  expect (delivered.network.length == 1) "delivery did not consume one envelope"
  expect
    (MultiNodeTransitionSystem.nodeState delivered "A" ==
      some { initial with gossips := [("A", { view := 1, seqno := 10 })] })
    "global delivery did not apply local receive"
  expect (MultiNodeTransitionSystem.nodeState delivered "B" == MultiNodeTransitionSystem.nodeState sent "B")
    "delivery changed another node"

  let envelope : Model.Envelope := {
    source := "B", target := "A", payload := .gossip { view := 2, seqno := 1 }
  }
  expect (((Model.transitionSystem globalConfig).step globalInitial (.deliver envelope)).isNone)
    "delivery accepted a message absent from the network"
  let beforeDelivery := {
    globalInitial with
    nodes := [("A", second.1), ("B", initialNode "B")]
    network := [envelope, envelope]
  }
  let ignored <- runGlobal globalConfig beforeDelivery (.deliver envelope)
  expect (ignored.network == [envelope] && ignored.nodes == beforeDelivery.nodes)
    "ignored delivery must consume one occurrence without changing node state"
  let ignoredAgain <- runGlobal globalConfig ignored (.deliver envelope)
  expect (ignoredAgain.network.isEmpty && ignoredAgain.nodes == ignored.nodes)
    "second ignored delivery did not consume the remaining occurrence"
  let toInactive := Tests.initial globalConfig ["A"]
  let inactiveSent <- runGlobal globalConfig toInactive (.local "A" .retry)
  let inactiveMessage <- requireSome
    (inactiveSent.network.find? fun env => env.target == "B") "inactive gossip missing"
  expect (((Model.transitionSystem globalConfig).step inactiveSent (.deliver inactiveMessage)).isNone)
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
  let opener <- requireSome (MultiNodeTransitionSystem.nodeState receivedBoth "B") "opener disappeared"
  expect (opener.phase == .opening && opener.openKind == some .quorum)
    "global strict-majority votes did not open the selected node"
  let advertised <- runGlobal globalConfig receivedBoth (.local "B" .retry)
  let joined <- deliverMessage globalConfig advertised "B" "A" .iAmOpen
  let joiner <- requireSome (MultiNodeTransitionSystem.nodeState joined "A") "joiner disappeared"
  expect (joiner.phase == .joining && joiner.chosen == some "B" && joiner.restartRequested)
    "global IAmOpen did not request the selected restart"
  let timeout1 <- runGlobal globalConfig joined (.local "B" .timeout)
  let timeout2 <- runGlobal globalConfig timeout1 (.local "B" .timeout)
  let timeout3 <- runGlobal globalConfig timeout2 (.local "B" .timeout)
  let opened <- requireSome (MultiNodeTransitionSystem.nodeState timeout3 "B") "opened node disappeared"
  expect (opened.phase == .open) "global timeout lane did not complete opening"
  expect (((Model.transitionSystem globalConfig).step timeout3 (.local "B" .retry)).isNone)
    "completed node kept sending retries"

  let singleConfig : Model.Config := {
    protocol := { instanceId := "different-snapshots", expectedLocations := ["A"] }
    recovered := [("A", { view := 1, seqno := 10 })]
  }
  let singleInitial := Tests.initial singleConfig ["A"]
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
  expect (unexpected.1.phase == .voting)
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
