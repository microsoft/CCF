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
        .local 0 (.append [
          { content := .transaction 20 { configuration := some {0, 1, 2} } }
        ]),
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
        .local 0 (.sendEntries 1 5),
        .local 0 (.sendEntries 2 5),
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
        .local 0 (.sendEntries 1 5),
        .deliver 0 1,
        .deliver 1 0,
        .local 0 (.sendEntries 2 5),
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

private def appendFlushes : IO Unit := do
  let append := fun state entries =>
    (act (CCF.Capabilities.record 0) 0 state (.append entries)).run {}
  let packets := fun (outputs : CCF.Outputs NodeID Message Notification) =>
    outputs.outgoing.map fun envelope =>
      match envelope.payload with
      | .appendEntriesRequest request =>
          some (envelope.target, request.prevLogIndex, request.entries.length,
            request.primaryCommit)
      | _ => none

  let some (configured, outputs) := append (initialNodeState {0} 0)
      [{
        content := .transaction 1 { configuration := some {0, 1} }
        flushes := [(1, 2)]
      }]
    | throw (IO.userError "configuration append with flush is disabled")
  check
    (configured.log.length == 2 && configured.sentIndex 1 == 2
      && packets outputs == [some (1, 1, 0, 0), some (1, 1, 1, 0)])
    "configuration heartbeat must precede the flush of the new entry"

  let retained := {
    initialNodeState {0, 1} 0 with
    log := [
      { term := BOOTSTRAP_TERM, content := .transaction 0 { configuration := some {0, 1} } },
      { term := BOOTSTRAP_TERM, content := .transaction 1 { configuration := some {0} } },
      { term := BOOTSTRAP_TERM, content := .signature }
    ]
    commitIndex := 3
    sentIndex := fun _ => 3
    matchIndex := fun _ => 3
  }
  check (retained.activeMembers == {0} && eligiblePeers retained 0 == {1})
    "expected singleton active membership with a retained retired peer"
  let some (committed, outputs) := append retained
      [{ content := .signature, flushes := [(1, 4)] }]
    | throw (IO.userError "signature append with pre-commit flush is disabled")
  check
    (committed.commitIndex == 4 && packets outputs == [some (1, 3, 1, 3)])
    "flush must carry the old commit index before the append self-commits"

  let initial := initialNodeState {0, 1} 0
  let some (batched, outputs) := append initial [
      { content := .transaction 1 {}, flushes := [(1, 2)] },
      { content := .transaction 2 {}, flushes := [(1, 3)] }
    ]
    | throw (IO.userError "per-entry flushes are disabled")
  check
    (batched.log.length == 3 && batched.sentIndex 1 == 3
      && packets outputs == [some (1, 0, 2, 0), some (1, 2, 1, 0)])
    "each entry must flush before appending the next entry"
  for flushes in [[(1, 3)], [(2, 2)], [(1, 2), (1, 1)], [(1, 2), (2, 2)]] do
    check (append initial [{ content := .transaction 1 {}, flushes }]).isNone
      "invalid flush choices must disable the entire append"

  let mixed := {
    initial with
    log := [
      { term := 1, content := .transaction 0 { configuration := some {0, 1} } },
      { term := 1, content := .transaction 1 {} },
      { term := BOOTSTRAP_TERM, content := .transaction 2 {} }
    ]
  }
  check (append mixed [{ content := .transaction 3 {}, flushes := [(1, 4)] }]).isNone
    "a flush packet must not span terms"
  let some (_, outputs) := append mixed
      [{ content := .transaction 3 {}, flushes := [(1, 2), (1, 4)] }]
    | throw (IO.userError "term-bounded flush is disabled")
  check (packets outputs == [some (1, 0, 2, 0), some (1, 2, 2, 0)])
    "flush must preserve the chosen packet boundaries"

/-- Runs action traces and checks their ledgers and append-time packet emissions. -/
def run : IO Unit := do
  clientRequestCommits
  reconfigureElectAndCommit
  appendFlushes
  IO.println "Canonical action traces passed."

#eval run

end CCFRaft.Tests.CanonicalTraces
