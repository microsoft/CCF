module

meta import CCFRaft.Model

public import CCFRaft.Model

public section

namespace CCFRaft.Tests.CanonicalTests

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

private def runTrace (name : String) (configuration : Finset NodeID)
    (nodes : List NodeID) (actions : List Action)
    : IO Model.State := do
  let system := Model.transitionSystem configuration nodes
  let mut state : Model.State :=
    { nodes := nodes.map fun node => (node, initialNodeState configuration node) }
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
      [
        .local 0 (.append [.transaction 10 {}]),
        .local 0 (.append [.signature]),
        .local 0 (.sendEntries 1 3),
        .deliver 0 1,
        .deliver 1 0,
        .local 0 (.sendEntries 2 3),
        .deliver 0 2,
        .deliver 2 0,
        .local 0 (.sendEntries 1 3),
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
  let state ←
    runTrace "reconfigure, elect and commit" {0} nodes
      [
        .local 0 (.append [.transaction 10 {}]),
        .local 0 (.append [.signature]),
        .local 0 (.append [.transaction 20 { configuration := some {0, 1, 2} }]),
        .local 0 (.append [.signature]),
        -- New-peer heartbeats start at the old ledger end; NACKs enable full replication.
        .deliver 0 1,
        .deliver 1 0,
        .deliver 0 2,
        .deliver 2 0,
        .local 0 (.sendEntries 1 5),
        .deliver 0 1,
        .deliver 1 0,
        .local 0 (.sendEntries 2 5),
        .deliver 0 2,
        .deliver 2 0,
        .local 0 (.sendEntries 1 5),
        .deliver 0 1,
        .deliver 1 0,
        -- Node 1 wins pre-vote and the election with node 0's vote.
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
        .deliver 0 1,
        .local 1 (.append [.transaction 30 {}]),
        .local 1 (.append [.signature]),
        .local 1 (.sendEntries 0 7),
        .deliver 1 0,
        .deliver 0 1,
        .local 1 (.sendEntries 2 7),
        .deliver 1 2,
        .deliver 2 1,
        .local 1 (.sendEntries 0 7),
        .deliver 1 0,
        .deliver 0 1
      ]
  let expected : List Entry :=
    [
      { term := BOOTSTRAP_TERM, content := .transaction 0 { configuration := some {0} } },
      { term := BOOTSTRAP_TERM, content := .transaction 10 {} },
      { term := BOOTSTRAP_TERM, content := .signature },
      {
        term := BOOTSTRAP_TERM,
        content := .transaction 20 { configuration := some {0, 1, 2} }
      },
      { term := BOOTSTRAP_TERM, content := .signature },
      { term := BOOTSTRAP_TERM + 1, content := .transaction 30 {} },
      { term := BOOTSTRAP_TERM + 1, content := .signature }
    ]
  for node in nodes do
    let localState ← get state node
    check (localState.log == expected && localState.committedLog == expected)
      s!"reconfigure, elect and commit: node {node} must commit both requests and the reconfiguration in order"
    check
      (localState.currentTerm == BOOTSTRAP_TERM + 1
        && localState.role == (if node == 1 then .primary else .follower)
        && localState.activeMembers == {0, 1, 2})
      s!"reconfigure, elect and commit: node {node} has the wrong term, role or membership"
  check state.network.isEmpty "reconfigure, elect and commit: undelivered messages remain"

/-- Runs initialized action traces and checks their final ledgers. -/
def run : IO Unit := do
  clientRequestCommits
  reconfigureElectAndCommit
  IO.println "Canonical action traces passed."

#eval run

end CCFRaft.Tests.CanonicalTests
