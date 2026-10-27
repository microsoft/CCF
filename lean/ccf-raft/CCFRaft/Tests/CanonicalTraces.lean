module

meta import CCFRaft.Properties.Liveness.Assumptions.Window

public import CCFRaft.Model

import CCFRaft.Properties.Liveness.Assumptions.Window

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

private def checkReconfiguration (name : String) (state : Model.State) (node : NodeID)
    (expected : Bool)
    : IO Unit := do
  let localState ← get state node
  check (decide (Liveness.ReconfigurationSettled localState) == expected)
    s!"{name}: node {node} has the wrong reconfiguration-settlement status"

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
        .local 0 (.append [.transaction 10 {}]),
        .local 0 (.append [.signature]),
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
        .local 0 (.append [.transaction 10 {}]),
        .local 0 (.append [.signature]),
        .local 0 (.append [.transaction 20 { configuration := some {0, 1, 2} }]),
        .local 0 (.append [.signature])
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

  -- Node 2 times out first, so it knows no primary and grants node 1's pre-vote.
  -- Node 0, the primary, and node 1 while it still knows the primary, refuse
  -- pre-votes. Node 1 then wins the election with node 0's vote.
  let state ←
    runTrace "election" {0} nodes state
      [
        .local 2 (.timeout .election),
        .deliver 2 0,
        .deliver 2 1,
        .deliver 0 2,
        .deliver 1 2,
        .local 1 (.timeout .election),
        .deliver 1 2,
        .deliver 2 1,
        .deliver 1 0,
        .deliver 1 0,
        .deliver 0 1,
        .deliver 0 1,
        -- Drain node 1's queued vote request before its promotion heartbeat.
        .deliver 1 2,
        .deliver 1 2,
        .deliver 2 1,
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
        .local 1 (.append [.transaction 30 {}]),
        .local 1 (.append [.signature]),
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

private def retirementFinishesAtLeader : IO Unit := do
  let configuration : Finset NodeID := {0, 1}
  let nodes := [0, 1]
  let state := initialState configuration nodes
  checkReconfiguration "initial configuration" state 0 true
  let state ←
    runTrace "initial signature" configuration nodes state
      [
        .local 0 (.append [.signature]),
        .local 0 (.sendEntries 1 [2]),
        .deliver 0 1,
        .deliver 1 0
      ]
  let state ←
    runTrace "pending removal" configuration nodes state
      [.local 0 (.append [.transaction 20 { configuration := some {0} }, .signature])]
  checkReconfiguration "pending removal" state 0 false
  let state ←
    runTrace "removal acknowledgement after later signature" configuration nodes state
      [
        .local 0 (.sendEntries 1 [4]),
        .deliver 0 1,
        .local 0 (.append [.transaction 30 {}, .signature]),
        .deliver 1 0
      ]
  let leader ← get state 0
  check
    (leader.commitIndex == 4
      && maxCommittableIndex leader.log == 6
      && leader.activeConfigurations.length == 1)
    "retirement: expected one active configuration and a stranded later signature"
  checkReconfiguration "removal awaiting confirmation" state 0 false
  let state ←
    runTrace "append retirement confirmation" configuration nodes state
      [.local 0 (.append [.transaction 40 { retirementConfirmations := {1} }])]
  let leader ← get state 0
  check (leader.commitIndex == 6 && retiredCommittedNodes leader.log == {1})
    "retirement: appending confirmation must rerun the scan without committing itself"
  checkReconfiguration "uncommitted confirmation" state 0 false
  let state ←
    runTrace "commit retirement confirmation" configuration nodes state
      [.local 0 (.append [.signature])]
  let leader ← get state 0
  check (leader.commitIndex == 8) "retirement: confirmation signature must commit"
  checkReconfiguration "committed confirmation" state 0 true
  checkReconfiguration "follower has not learned completion" state 1 false

/-- Runs initialized action traces and checks their ledgers at each stage. -/
def run : IO Unit := do
  clientRequestCommits
  reconfigureElectAndCommit
  retirementFinishesAtLeader
  IO.println "Canonical action traces passed."

#eval run

end CCFRaft.Tests.CanonicalTraces
