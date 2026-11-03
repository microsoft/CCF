module

meta import CCFRaft.Model

public import CCFRaft.Model

public section

namespace CCFRaft.Tests.CanonicalTraces

open CCFRaft CCFRaft.Model.Node
open CCFRaft.Model (initialNodeState BOOTSTRAP_TERM)
open CCF.MultiNodeTransitionSystem (nodeState)

private inductive Action where
  | local (node : NodeID) (input : Input)
  /-- Deliver the oldest pending message along this directed link. -/
  | deliver (source target : NodeID)

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do
    throw (IO.userError message)

private def get (state : Model.State) (node : NodeID) : IO NodeState :=
  match nodeState state node with
  | some state => pure state
  | none => throw (IO.userError s!"missing node {node}")

private def initialState (configuration : Finset NodeID) (nodes : List NodeID)
    : Model.State :=
  { nodes := nodes.map fun node => (node, initialNodeState configuration node) }

private def checkLedger (name : String) (state : Model.State) (node : NodeID)
    (expected : List Entry) (commitIndex : Nat)
    : IO Unit := do
  let localState ← get state node
  check
    (localState.log == expected
      && localState.commitIndex == commitIndex
      && localState.committedLog == expected.take commitIndex)
    s!"{name}: node {node} has the wrong ledger or committed prefix"

private def runTrace (name : String) (configuration : Finset NodeID)
    (nodes : List NodeID) (start : Model.State) (actions : List Action)
    : IO Model.State := do
  let system := Model.transitionSystem configuration nodes
  let mut state := start
  check (decide (configuration.Nonempty /\ nodes.Nodup))
    s!"{name}: initial membership must be nonempty and node IDs unique"
  for (action, index) in actions.zipIdx do
    let description :=
      match action with
      | .local node _ => s!"local action on node {node}"
      | .deliver source target => s!"delivery {source} -> {target}"
    let context := s!"{name}, action {index + 1} ({description})"
    let action : Model.Action ←
      match action with
      | .local node input => pure (.local node input)
      | .deliver source target =>
          match state.network.find?
                  fun envelope =>
                    envelope.source == source && envelope.target == target with
          | some envelope => pure (.deliver envelope)
          | none => throw (IO.userError s!"{context}: no pending message")
    match system.step state action with
    | some after => state := after
    | none => throw (IO.userError s!"{context}: disabled action")
  return state

private def clientRequestCommits : IO Unit := do
  let configuration : Finset NodeID := {0, 1, 2}
  let nodes := [0, 1, 2]
  let state ←
    runTrace "client request commits" configuration nodes
      (initialState configuration nodes)
      [
        .local 0 (.append [{ content := .transaction 10 {} }]),
        .local 0 (.append [{ content := .signature }]),
        .local 0 (.sendEntries 1 [3]),
        .deliver 0 1,
        .deliver 1 0,
        .local 0 (.sendEntries 2 [3]),
        .deliver 0 2,
        .deliver 2 0,
        .local 0 (.sendEntries 1 [3]),
        .deliver 0 1,
        .deliver 1 0
      ]
  let expected : List Entry :=
    [
      {
        term := BOOTSTRAP_TERM,
        content := .transaction 0 { configuration := some configuration }
      },
      { term := BOOTSTRAP_TERM, content := .transaction 10 {} },
      { term := BOOTSTRAP_TERM, content := .signature }
    ]
  for node in nodes do
    let localState ← get state node
    check (localState.log == expected && localState.committedLog == expected)
      s!"client request commits: node {node} must commit the exact requested ledger"
    check
      (localState.currentTerm == BOOTSTRAP_TERM
        && localState.role == (if node == 0 then .primary else .follower))
      s!"client request commits: node {node} has the wrong term or role"
  check state.network.isEmpty "client request commits: undelivered messages remain"

private def reconfigureElectAndCommit : IO Unit := do
  let nodes := [0, 1, 2]
  let expected : List Entry :=
    [
      { term := BOOTSTRAP_TERM, content := .transaction 0 { configuration := some {0} } },
      { term := BOOTSTRAP_TERM, content := .transaction 10 {} },
      { term := BOOTSTRAP_TERM, content := .signature },
      {
        term := BOOTSTRAP_TERM,
        content := .transaction 20 { configuration := some {0, 1, 2} }
      },
      { term := BOOTSTRAP_TERM, content := .signature }
    ]
  let state ←
    runTrace "reconfiguration before delivery" {0} nodes (initialState {0} nodes)
      [
        .local 0 (.append [{ content := .transaction 10 {} }]),
        .local 0 (.append [{ content := .signature }]),
        .local 0
          (.append [{ content := .transaction 20 { configuration := some {0, 1, 2} } }]),
        .local 0 (.append [{ content := .signature }])
      ]
  checkLedger "reconfiguration before delivery" state 0 expected 3
  for node in [1, 2] do
    checkLedger "reconfiguration before delivery" state node [] 0

  -- New-peer heartbeats start at the old ledger end; NACKs enable full replication.
  let state ←
    runTrace "initial setup delivery" {0} nodes state
      [.deliver 0 1, .deliver 1 0, .deliver 0 2, .deliver 2 0]
  checkLedger "initial setup delivery" state 0 expected 3
  for node in [1, 2] do
    checkLedger "initial setup delivery" state node [] 0

  let state ←
    runTrace "replication" {0} nodes state
      [
        .local 0 (.sendEntries 1 [5]),
        .local 0 (.sendEntries 2 [5]),
        .deliver 0 1,
        .deliver 1 0,
        .deliver 0 2,
        .deliver 2 0
      ]
  checkLedger "replication" state 0 expected 5
  for node in [1, 2] do
    checkLedger "replication" state node expected 3

  let state ←
    runTrace "commit notification" {0} nodes state
      [
        .local 0 (.sendEntries 1 [5]),
        .deliver 0 1,
        .deliver 1 0,
        .local 0 (.sendEntries 2 [5]),
        .deliver 0 2,
        .deliver 2 0
      ]
  for node in nodes do
    checkLedger "commit notification" state node expected 5

  -- Node 1 wins pre-vote and the election with node 0's vote.
  let state ←
    runTrace "election" {0} nodes state
      [
        .local 1 (.timeout .election),
        .deliver 1 0,
        .deliver 0 1,
        .deliver 1 0,
        .deliver 0 1,
        -- Drain node 2's queued election requests before its promotion heartbeat.
        .deliver 1 2,
        .deliver 2 1,
        .deliver 1 2,
        .deliver 2 1,
        .deliver 1 2,
        .deliver 2 1,
        .deliver 1 0,
        .deliver 0 1
      ]
  for node in nodes do
    checkLedger "election" state node expected 5
    let localState ← get state node
    check
      (localState.currentTerm == BOOTSTRAP_TERM + 1
        && localState.role == (if node == 1 then .primary else .follower))
      s!"election: node {node} has the wrong term or role"

  let state ←
    runTrace "new primary client request" {0} nodes state
      [
        .local 1 (.append [{ content := .transaction 30 {} }]),
        .local 1 (.append [{ content := .signature }]),
        .local 1 (.sendEntries 0 [7]),
        .deliver 1 0,
        .deliver 0 1,
        .local 1 (.sendEntries 2 [7]),
        .deliver 1 2,
        .deliver 2 1,
        .local 1 (.sendEntries 0 [7]),
        .deliver 1 0,
        .deliver 0 1
      ]
  let expected :=
    expected
    ++ [
      { term := BOOTSTRAP_TERM + 1, content := .transaction 30 {} },
      { term := BOOTSTRAP_TERM + 1, content := .signature }
    ]
  for node in nodes do
    checkLedger "new primary client request" state node expected 7
    let localState ← get state node
    check
      (localState.currentTerm == BOOTSTRAP_TERM + 1
        && localState.role == (if node == 1 then .primary else .follower)
        && localState.activeMembers == {0, 1, 2})
      s!"reconfigure, elect and commit: node {node} has the wrong term, role or membership"
  check state.network.isEmpty "reconfigure, elect and commit: undelivered messages remain"

private def sendPassAlignment : IO Unit := do
  let configuration : Finset NodeID := {0, 1, 2}
  let system := Model.transitionSystem configuration [0, 1, 2]
  let oldLog : List Entry :=
    [
      { term := 2, content := .transaction 0 { configuration := some configuration } },
      { term := 2, content := .signature },
      { term := 2, content := .transaction 1 {} },
      { term := 2, content := .signature },
      { term := 2, content := .transaction 2 {} },
      { term := 2, content := .signature }
    ]
  let leader : NodeState :=
    {
      initialNodeState configuration 1 with
        role := .primary
        currentTerm := 3
        log :=
          oldLog
          ++ [
            { term := 3, content := .transaction 3 {} },
            { term := 3, content := .signature }
          ]
        commitIndex := 4
        sentIndex := fun _ => 4
    }
  let nack : Model.Envelope :=
    {
      source := 2
      target := 1
      payload := .appendEntriesResponse { term := 3, success := false, lastLogIndex := 4 }
    }
  let state : Model.State := { nodes := [(1, leader)], network := [nack] }
  for ends in [[], [6], [8], [6, 6, 8], [6, 9]] do
    check (system.step state (.local 1 (.sendEntries 2 ends))).isNone
      s!"send pass: accepted incomplete, mixed-term or invalid batches {ends}"
  let some sent := system.step state (.local 1 (.sendEntries 2 [6, 8]))
  | throw (IO.userError "send pass: complete term-bounded pass was disabled")
  check ((← get sent 1).sentIndex 2 == 8)
    "send pass: frontier did not advance to the log end"
  let packets := sent.network.filter fun envelope => envelope.source == 1
  check
    (packets.map (·.payload)
      == [
        .appendEntriesRequest (makeAppendEntriesRequest leader 4 6),
        .appendEntriesRequest (makeAppendEntriesRequest leader 6 8)
      ])
    "send pass: batches were not queued together with contiguous headers"
  let some rewound := system.step sent (.deliver nack)
  | throw (IO.userError "send pass: delayed NACK was disabled")
  check
    ((← get rewound 1).sentIndex 2 == 4 && rewound.network == packets)
    "send pass: delayed NACK did not rewind after both batches were queued"

  let beforeAppend := { leader with log := leader.log.take 7 }
  let state : Model.State := { nodes := [(1, beforeAppend)] }
  let flush (ends : List Nat) : Model.Action :=
    .local 1 (.append [{ content := .signature, flushes := [(2, ends)] }])
  check (system.step state (flush [6])).isNone
    "send pass: append accepted an incomplete flush"
  let some flushed := system.step state (flush [6, 8])
  | throw (IO.userError "send pass: complete append flush was disabled")
  check
    ((← get flushed 1).sentIndex 2 == 8
      && flushed.network.map (·.payload) == packets.map (·.payload))
    "send pass: append flush did not preserve the atomic pass or precommit headers"

private def rejoinAlignment : IO Unit := do
  let configuration : Finset NodeID := {0, 1}
  let log : List Entry :=
    [
      { term := 2, content := .transaction 0 { configuration := some configuration } },
      { term := 2, content := .signature },
      { term := 2, content := .transaction 1 { configuration := some {0} } },
      { term := 2, content := .signature },
      { term := 2, content := .transaction 2 { retirementConfirmations := {1} } },
      { term := 2, content := .signature }
    ]
  let leader := { initialNodeState configuration 0 with log, commitIndex := 4 }
  let system := Model.transitionSystem configuration [0, 1]
  let rejoin : Model.Action :=
    .local 0
      (.append [{ content := .transaction 3 { configuration := some configuration } }])
  check (system.step { nodes := [(0, leader)] } rejoin).isNone
    "rejoin: accepted an uncommitted retirement confirmation"
  let leader := { leader with commitIndex := 6 }
  let some rejoined := system.step { nodes := [(0, leader)] } rejoin
  | throw (IO.userError "rejoin: committed retirement did not permit rejoining")
  check (retiredCommittedNodes (← get rejoined 0).log == ∅)
    "rejoin: fresh node record retained its old retirement confirmation"
  let removed ←
    runTrace "remove rejoined node" configuration [0, 1] rejoined
      [.local 0 (.append [{ content := .transaction 4 { configuration := some {0} } }])]
  check (system.step removed rejoin).isNone
    "rejoin: reused a confirmation from before an uncommitted re-addition"

/-- Runs action traces and checks their ledgers and append-time packet emissions. -/
def run : IO Unit := do
  clientRequestCommits
  reconfigureElectAndCommit
  sendPassAlignment
  rejoinAlignment
  IO.println "Canonical action traces passed."

#eval run

end CCFRaft.Tests.CanonicalTraces
