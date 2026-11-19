-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import Consensus.Replay.Interpreter
import Scenarios

/-!
Runs the consensus scenarios on the Lean model of the protocol, without the implementation.

`CftDriver` declares each command of a scenario as the C function `cft_*`, which
`driver.cpp` implements by calling the implementation. This module implements each command
on the model, as `model_cft_*`, and `shim.c` defines `cft_*` to call it. A program which
links them, and not `driver.cpp`, runs the scenarios on the model alone.

The model does not say when a timer fires, when a primary sends, or which message is
delivered next: those are inputs to it. This module decides them as the scenario driver
and `cft.h` do, with a clock for each node, the queue of each sender, and the connections
between nodes.
-/

open Lean (Json toJson)
open Consensus Consensus.Model.Node
open CCF (Finset)
open CCF.MultiNodeTransitionSystem (nodeState removeOne)
open CftDriver (Text scenarios)

namespace ModelDriver

abbrev Envelope := Model.Envelope

/-- The request timeout of a scenario node, in milliseconds, after which a primary sends. -/
private def requestTimeout : Nat := 10

/-- The election timeout of a scenario node, in milliseconds. -/
private def electionTimeout : Nat := 100

/-- The model, and what the scenario driver and `cft.h` keep beside it. -/
structure Driver where
  /-- The node which `startNode` created. -/
  first : Option NodeID := none
  state : Model.State := { nodes := [] }
  /-- Milliseconds since the timer of each node restarted. -/
  elapsed : NodeID → Nat := fun _ => 0
  /-- For a primary, milliseconds since each peer acknowledged it. -/
  sinceAck : NodeID → NodeID → Nat := fun _ _ => 0
  /-- The pairs of nodes of which the first can send to the second. -/
  connections : List (NodeID × NodeID) := []
  nextRequest : Nat := 1
  commands : Nat := 0
  /-- What the command which is running has done to the model. -/
  actions : Array Json := #[]
  /-- The trace: a record of each command which has run. -/
  records : Array Json := #[]

instance : Inhabited Driver :=
  ⟨{}⟩

initialize driver : IO.Ref Driver ← IO.mkRef {}

private def fail {α : Type} (message : String) : IO α :=
  throw (IO.userError message)

/-! ## Nodes -/

/-- The longest name of a node, in bytes. -/
private def nameBytes : Nat := 16

/--
The model identifies a node by a number, and orders nodes by it, where the implementation
orders them by name. The number of a node is its name, read in base 256 and padded to
`nameBytes`, which keeps the order of the names.
-/
private def nodeId (name : Text) : IO NodeID := do
  let bytes := name.text.toUTF8.toList
  if bytes.isEmpty || bytes.length > nameBytes || bytes.contains 0 then
    fail s!"The name of node '{name.text}' must have 1 to {nameBytes} bytes"
  return (bytes ++ List.replicate (nameBytes - bytes.length) 0).foldl
    (fun id (byte : UInt8) => id * 256 + byte.toNat)
    0

private def nodeName (node : NodeID) : String :=
  let bytes :=
    (List.range nameBytes).map
      fun place => (node / 256 ^ (nameBytes - 1 - place) % 256).toUInt8
  String.fromUTF8! ⟨(bytes.takeWhile (· != 0)).toArray⟩

/-- The nodes, in the order of their names. -/
private def nodeIds : IO (List NodeID) :=
  return (← driver.get).state.nodes.map (·.1)

private def get (node : NodeID) : IO NodeState := do
  match nodeState (← driver.get).state node with
  | some state => pure state
  | none => fail s!"Node {nodeName node} does not exist"

private def leadership (state : NodeState) : String :=
  match state.role with
  | .none => "None"
  | .follower => "Follower"
  | .preVoteCandidate => "PreVoteCandidate"
  | .candidate => "Candidate"
  | .primary => "Leader"

/-- Whether `node` has not seen its retirement. -/
private def isActive (node : NodeID) (state : NodeState) : Bool :=
  (state.retirement node).phase == .noRetirementObserved

private def retirementPhase (node : NodeID) (state : NodeState) : Option String :=
  match (state.retirement node).phase with
  | .noRetirementObserved => none
  | .retirementOrdered => some "Ordered"
  | .retirementSigned => some "Signed"
  | .retirementCompleted => some "Completed"
  | .retiredCommitted => some "RetiredCommitted"

/-! ## Trace -/

/-- The state of a node, with the names which the trace of the implementation gives it. -/
private def stateJson (node : NodeID) (state : NodeState) : Json :=
  Json.mkObj
    ([
        ("node_id", toJson (nodeName node)),
        ("current_view", toJson state.currentTerm),
        ("last_idx", toJson state.log.length),
        ("commit_idx", toJson state.commitIndex),
        ("leadership_state", toJson (leadership state)),
        ("membership_state", toJson (if isActive node state then "Active" else "Retired"))
      ]
      ++ (retirementPhase node state).toList.map
          fun phase => ("retirement_phase", toJson phase))

/-- A model action, with its message as the trace of the implementation gives a packet. -/
private def actionFields : Model.Action → List (String × Json)
  | .local node input =>
      ("node_id", toJson (nodeName node))
      :: match input with
          | .append entries => [("action", "append"), ("entries", toJson entries.length)]
          | .sendEntries destination endIndex =>
              [
                ("action", "sendEntries"),
                ("to_node_id", toJson (nodeName destination)),
                ("idx", toJson endIndex)
              ]
          | .timeout .election => [("action", "timeout"), ("kind", "election")]
          | .timeout .checkQuorum => [("action", "timeout"), ("kind", "checkQuorum")]
          | .nominateSuccessor => [("action", "nominateSuccessor")]
          | .initAsBackup _ => [("action", "initAsBackup")]
  | .deliver envelope =>
      [
        ("node_id", toJson (nodeName envelope.target)),
        ("action", "receive"),
        ("from_node_id", toJson (nodeName envelope.source)),
        ("packet", Replay.messageJson envelope.payload)
      ]

private def record (fields : List (String × Json)) : IO Unit :=
  driver.modify fun d => { d with actions := d.actions.push (Json.mkObj fields) }

/-! ## Timers -/

private def restart (node : NodeID) : IO Unit :=
  driver.modify
    fun d =>
      { d with elapsed := fun other => if other == node then 0 else d.elapsed other }

private def acknowledged (node : NodeID) (peer? : Option NodeID) : IO Unit :=
  driver.modify
    fun d =>
      {
        d with
          sinceAck :=
            fun primary peer =>
              if primary == node && peer?.all (· == peer) then
                0
              else
                d.sinceAck primary peer
      }

/--
Restart the timers which `cft.h` restarts when `node` goes from `pre` to `post` by `action`,
which sent `sent`.
-/
private def updateTimers (node : NodeID) (pre post : NodeState) (action : Model.Action)
    (sent : List Envelope)
    : IO Unit := do
  -- become_pre_vote_candidate, become_candidate, become_leader and become_follower
  if pre.role != post.role || pre.currentTerm != post.currentTerm then
    restart node
    acknowledged node none
  match action with
  | .local _ (.timeout .election) => restart node
  | .local .. => pure ()
  | .deliver envelope =>
      match envelope.payload with
      | .appendEntriesRequest request =>
          -- The sender is the primary of this term, and the logs agree before the entries
          if request.term >= pre.currentTerm
              && request.prevLogIndex <= pre.log.length
              && termAt pre.log request.prevLogIndex == request.prevLogTerm then
            restart node
      | .requestVoteRequest _ =>
          let granted :=
            sent.any
              fun reply =>
                match reply.payload with
                | .requestVoteResponse response => response.voteGranted
                | _ => false
          if granted then
            restart node
      | .appendEntriesResponse _ =>
          if pre.role == .primary
              && decide (envelope.source ∈ eligiblePeers pre node) then
            acknowledged node (some envelope.source)
      | _ => pure ()

/-! ## Model steps -/

/-- Take a step of the model, and record it. `false` if the model does not allow it. -/
private def step? (action : Model.Action) : IO Bool := do
  let d ← driver.get
  let some first := d.first | fail "No node has started"
  let node :=
    match action with
    | .local node _ => node
    | .deliver envelope => envelope.target
  let some pre := nodeState d.state node | fail s!"Node {nodeName node} does not exist"
  match Model.networkStep ({first} : Finset NodeID) d.state action with
  | none =>
      record (actionFields action ++ [("allowed", toJson false)])
      return false
  | some after =>
      let some post := nodeState after node | fail s!"Node {nodeName node} does not exist"
      let kept :=
        match action with
        | .local .. => d.state.network.length
        | .deliver _ => d.state.network.length - 1
      let sent := after.network.drop kept
      driver.set { d with state := after }
      record
        (actionFields action
          ++ [(
                "sent",
                toJson
                  (sent.map
                    fun envelope =>
                      Json.mkObj
                        [
                          ("to_node_id", toJson (nodeName envelope.target)),
                          ("packet", Replay.messageJson envelope.payload)
                        ])
              )])
      updateTimers node pre post action sent
      return true

/-! ## Messages -/

/-- The undelivered messages of `source`, oldest first. -/
private def queue (source : NodeID) : IO (List Envelope) :=
  return (← driver.get).state.network.filter (·.source == source)

/-- Lose a message: it is no longer undelivered. -/
private def lose (envelope : Envelope) : IO Unit := do
  record
    [
      ("node_id", toJson (nodeName envelope.source)),
      ("action", "lose"),
      ("to_node_id", toJson (nodeName envelope.target)),
      ("packet", Replay.messageJson envelope.payload)
    ]
  driver.modify
    fun d =>
      { d with state := { d.state with network := removeOne envelope d.state.network } }

private def connect (first second : NodeID) : IO Unit :=
  driver.modify
    fun d =>
      {
        d with
          connections :=
            [(first, second), (second, first)].foldl
              (fun pairs pair => if pairs.contains pair then pairs else pair :: pairs)
              d.connections
      }

private def disconnect (first second : NodeID) : IO Unit :=
  driver.modify
    fun d =>
      {
        d with
          connections :=
            d.connections.filter
              fun pair => pair != (first, second) && pair != (second, first)
      }

/--
Deliver a message, and say whether it was. It is lost if its sender and target are not
connected. So is an AppendEntries whose sender no longer holds its entries: the scenario
driver reads them from the ledger of the sender when it delivers the message.
-/
private def dispatch (envelope : Envelope) : IO Bool := do
  let connected := (← driver.get).connections.contains (envelope.source, envelope.target)
  let held ←
    match envelope.payload with
    | .appendEntriesRequest request =>
        pure
          (decide
            (request.prevLogIndex + request.entries.length
              <= (← get envelope.source).log.length))
    | _ => pure true
  if connected && held then
    if ← step? (.deliver envelope) then
      return true
  lose envelope
  return false

/-- Deliver the undelivered messages of `source`, until `limit` of them are, if given. -/
private def dispatchQueue (source : NodeID) (limit : Option Nat := none) : IO Unit := do
  let mut delivered := 0
  for envelope in ← queue source do
    if limit.any (delivered >= ·) then
      break
    if ← dispatch envelope then
      delivered := delivered + 1

/-- Deliver the messages which are undelivered now, and not those sent in reply. -/
private def dispatchAllOnce : IO Unit := do
  let counts ← (← nodeIds).mapM fun node => return (node, (← queue node).length)
  for (node, count) in counts do
    dispatchQueue node (some count)

private def dispatchAll : IO Unit := do
  for _ in [0:5] do
    if (← driver.get).state.network.isEmpty then
      break
    dispatchAllOnce

/-- Reorder the undelivered messages of `source` at random, as the scenario driver does. -/
private def shuffle (source : NodeID) : IO Unit := do
  let mut pending := (← queue source).toArray
  for last in (List.range pending.size).reverse do
    pending := pending.swapIfInBounds last (← IO.rand 0 last)
  driver.modify
    fun d =>
      {
        d with
          state :=
            {
              d.state with
                network := d.state.network.filter (·.source != source) ++ pending.toList
            }
      }

/-! ## Time -/

/-- The last index of the entries which follow `start` in its term. -/
private def endOfTerm (log : List Entry) (start : Nat) : Nat :=
  let term := termAt log start
  start + ((log.drop start).takeWhile (·.term == term)).length

/-- Send to `peer` what `node` has not sent it, a term at a time, as `send_append_entries`. -/
private partial def sendEntriesTo (node peer : NodeID) : IO Unit := do
  let state ← get node
  let last := state.log.length
  let start := state.sentIndex peer + 1
  let stop := if start > last then last else endOfTerm state.log start
  if (← step? (.local node (.sendEntries peer stop))) && stop != last then
    sendEntriesTo node peer

/-- Advance the clock of `node`, as `periodic` in `cft.h`. -/
private def periodic (node : NodeID) (ms : Nat) : IO Unit := do
  let state ← get node
  driver.modify
    fun d =>
      { d with elapsed := fun other => d.elapsed other + if other == node then ms else 0 }
  let elapsed := (← driver.get).elapsed node
  if state.role == .primary then
    if elapsed >= requestTimeout then
      restart node
      for peer in (eligiblePeers state node).sort do
        sendEntriesTo node peer
    driver.modify
      fun d =>
        {
          d with
            sinceAck :=
              fun primary peer =>
                d.sinceAck primary peer + if primary == node then ms else 0
        }
    let d ← driver.get
    let live (configuration : Configuration) : Nat :=
      (configuration.nodes.sort.filter
        fun member => member == node || d.sinceAck node member < electionTimeout).length
    -- A primary steps down unless a majority of each configuration has acknowledged it
    unless (← get node).activeConfigurations.all
            fun configuration => live configuration >= configuration.nodes.card / 2 + 1 do
      discard <| step? (.local node (.timeout .checkQuorum))
  else if elapsed >= electionTimeout && !decide (state.isRetiredCommitted node) then
    discard <| step? (.local node (.timeout .election))

/-! ## Replication -/

/-- The primary in the highest term, with that term. -/
private def latestPrimary : IO (Option (Nat × NodeID)) :=
  return (← driver.get).state.nodes.foldl
    (fun best (node, state) =>
      let candidate := (state.currentTerm, node)
      if state.role == .primary && best.all (decide <| Prod.lexLt · candidate) then
        some candidate
      else
        best)
    none

/-- The primary in `term`, or in the highest term for `latest`, which may have none. -/
private def findPrimary (term : Text) : IO (Option NodeID) := do
  if term.text == "latest" then
    return (← latestPrimary).map (·.2)
  let primary :=
    (← driver.get).state.nodes.find?
      fun (_, state) => state.role == .primary && toString state.currentTerm == term.text
  match primary with
  | some (node, _) => return some node
  | none => fail s!"Found no primary in term {term.text}"

private def transaction (metadata : TransactionMetadata := {}) : IO EntryContent := do
  let request := (← driver.get).nextRequest
  driver.modify fun d => { d with nextRequest := request + 1 }
  return .transaction request metadata

/-- Append `contents` in one batch on the primary in `term`, if there is one. -/
private def append (term : Text) (contents : List EntryContent) : IO Unit := do
  let some primary ← findPrimary term | return
  unless ← step? (.local primary (.append (contents.map fun content => { content }))) do
    fail s!"The model does not let node {nodeName primary} append these entries"

/-! ## Membership -/

/-- Create a node which has joined, with an empty ledger, connected to no other. -/
private def addNode (node : NodeID) : IO Unit := do
  let d ← driver.get
  let some first := d.first | fail "No node has started"
  if (nodeState d.state node).isSome then
    fail s!"Node {nodeName node} already exists"
  let fresh := (node, Model.initialNodeState ({first} : Finset NodeID) node)
  let (before, after) := d.state.nodes.partition (·.1 < node)
  driver.set { d with state := { d.state with nodes := before ++ fresh :: after } }
  unless ← step? (.local node (.initAsBackup [])) do
    fail s!"The model does not let node {nodeName node} join"
  restart node

/--
Create `joining`, connected to every other node, and replicate the configuration of every
node but `out`.
-/
private def reconfigure (term : Text) (joining out : List NodeID) : IO Unit := do
  for node in joining do
    addNode node
  for node in joining do
    for other in ← nodeIds do
      if other != node then
        connect other node
  let members := (← nodeIds).filter (!out.contains ·)
  append term [← transaction { configuration := some (Finset.ofList members) }]

/-! ## Assertions -/

/-- A detail of `node`, as the scenario driver gives it to an assertion. -/
private def detail (node : NodeID) (name : String) : IO String := do
  let state ← get node
  match name with
  | "leadership_state" => return leadership state
  | "current_view" => return toString state.currentTerm
  | "membership_state" => return if isActive node state then "Active" else "Retired"
  | "retirement_phase" => return (retirementPhase node state).getD "null"
  | _ => fail s!"The model has no detail {name}"

/-- Why `nodes` are not in sync with the first of them, if they are not. -/
private def discrepancy (nodes : List NodeID) : IO (Option String) := do
  let target :: others := nodes | return none
  let expected ← get target
  for node in others do
    let state ← get node
    let differs (what : String) (actual wanted : Nat) :=
      s!"{what} {actual} of node {nodeName node} doesn't match {wanted} on {nodeName target}"
    if state.currentTerm != expected.currentTerm then
      return some (differs "Term" state.currentTerm expected.currentTerm)
    if state.log.length != expected.log.length then
      return some (differs "Last index" state.log.length expected.log.length)
    if state.log != expected.log then
      return some
        s!"An entry of node {nodeName node} doesn't match that on {nodeName target}"
    if state.commitIndex != expected.commitIndex then
      return some (differs "Commit index" state.commitIndex expected.commitIndex)
  return none

/-- The commit index of `node` must be held by a majority of each configuration before it. -/
private def checkCommitSafety (node : NodeID) : IO Unit := do
  let d ← driver.get
  let state ← get node
  let holds (other : NodeID) : Bool :=
    (nodeState d.state other).any
      fun otherState => otherState.log.take state.commitIndex == state.committedLog
  for configuration in state.activeConfigurations do
    if configuration.index <= state.commitIndex
        && (configuration.nodes.sort.filter holds).length
            < configuration.nodes.card / 2 + 1 then
      fail s!"Node ({nodeName node}) at unsafe commit idx ({state.commitIndex})"

/--
Sign on the primary in the highest term, connect the nodes which have not retired, and
have that primary send until they are in sync.
-/
private def loopUntilSync : IO Unit := do
  let some (term, primary) ← latestPrimary
  | fail "Can't currently loop until sync, no primary"
  let active ← (← nodeIds).filterM fun node => return isActive node (← get node)
  append (toString term : String) [.signature]
  for node in active do
    for other in ← nodeIds do
      if other != node then
        connect node other
  for _ in [0:20] do
    periodic primary 10
    dispatchAll
    if (← discrepancy active).isNone then
      return
  fail
    s!"Failed to reach state sync after 20 loop iterations: {(← discrepancy active).getD ""}"

/-! ## Commands -/

/--
Run a command: record it, with what it did to the model and the state in which it leaves
each node, and name it if it fails. The commit index of every node must then be safe,
which the scenario driver does not check after a command which only reads.
-/
private def command (name : String) (run : IO Unit) (reads : Bool := false)
    : IO Unit := do
  driver.modify fun d => { d with commands := d.commands + 1, actions := #[] }
  let problem ←
    try
      run
      unless reads do
        for node in ← nodeIds do
          checkCommitSafety node
      pure none
    catch error =>
      pure (some s!"Step {(← driver.get).commands} ({name}) failed: {error}")
  let d ← driver.get
  let fields :=
    [
      ("cmd", toJson name),
      ("actions", Json.arr d.actions),
      (
        "nodes",
        Json.arr (d.state.nodes.map fun (node, state) => stateJson node state).toArray
      )
    ]
    ++ problem.toList.map fun error => ("error", toJson error)
  driver.set { d with records := d.records.push (Json.mkObj fields) }
  if let some error := problem then
    fail error

/-- The text of a command, as the scenario driver records it. -/
private def text (name : String) (arguments : List String) : String :=
  ",".intercalate (name :: arguments)

private def texts (items : List Text) : List String :=
  items.map (·.text)

@[export model_cft_start_node]
def startNode (node : Text) : IO Unit :=
  command (text "start_node" [node.text]) do
    let id ← nodeId node
    if (← driver.get).first.isSome then
      fail "Start node already exists"
    driver.modify
      fun d =>
        {
          d with
            first := some id
            state := { nodes := [(id, Model.initialNodeState ({id} : Finset NodeID) id)] }
        }

@[export model_cft_trust_node]
def trustNode (term node : Text) : IO Unit :=
  command (text "trust_node" [term.text, node.text]) do
    reconfigure term [← nodeId node] []

@[export model_cft_trust_nodes]
def trustNodes (term : Text) (nodes : List Text) : IO Unit :=
  command (text "trust_nodes" (term.text :: texts nodes)) do
    reconfigure term (← nodes.mapM nodeId) []

@[export model_cft_swap_node]
def swapNode (term retire trust : Text) : IO Unit :=
  command (text "swap_node" [term.text, retire.text, trust.text]) do
    reconfigure term [← nodeId trust] [← nodeId retire]

@[export model_cft_swap_nodes]
def swapNodes (term : Text) (retire trust : List Text) : IO Unit :=
  let changes :=
    (if retire.isEmpty then [] else "out" :: texts retire)
    ++ if trust.isEmpty then [] else "in" :: texts trust
  command (text "swap_nodes" (term.text :: changes)) do
    reconfigure term (← trust.mapM nodeId) (← retire.mapM nodeId)

@[export model_cft_cleanup_nodes]
def cleanupNodes (term : Text) (nodes : List Text) : IO Unit :=
  command (text "cleanup_nodes" (term.text :: texts nodes)) do
    let retired ← nodes.mapM nodeId
    for node in retired do
      discard <| get node
    append term [← transaction { retirementConfirmations := Finset.ofList retired }]

@[export model_cft_nominate_successor]
def nominateSuccessor (node : Text) : IO Unit :=
  command (text "nominate_successor" [node.text]) do
    let id ← nodeId node
    discard <| get id
    discard <| step? (.local id .nominateSuccessor)

@[export model_cft_nodes]
def nodes (ids : List Text) : IO Unit :=
  command (text "nodes" (texts ids)) do
    fail "The model has no network without a primary: start it with start_node"

@[export model_cft_create_new_node]
def createNewNode (node : Text) : IO Unit :=
  command (text "create_new_node" [node.text]) do addNode (← nodeId node)

@[export model_cft_replicate_new_configuration]
def replicateNewConfiguration (term : Text) (nodes : List Text) : IO Unit :=
  command (text "replicate_new_configuration" (term.text :: texts nodes)) do
    let members ← nodes.mapM nodeId
    for node in members do
      unless (← nodeIds).contains node do
        addNode node
    append term [← transaction { configuration := some (Finset.ofList members) }]

@[export model_cft_replicate]
def replicate (term : Text) (entries : List Text) : IO Unit :=
  command (text "replicate" (term.text :: texts entries)) do
    append term
      (← entries.mapM
          fun entry => if entry.text == "$" then pure .signature else transaction)

@[export model_cft_periodic_one]
def periodicOne (node : Text) (ms : UInt64) : IO Unit :=
  command (text "periodic_one" [node.text, toString ms]) do
    periodic (← nodeId node) ms.toNat

@[export model_cft_periodic_all]
def periodicAll (ms : UInt64) : IO Unit :=
  command (text "periodic_all" [toString ms]) do
    for node in ← nodeIds do
      periodic node ms.toNat

@[export model_cft_connect]
def connectCommand (first second : Text) : IO Unit :=
  command (text "connect" [first.text, second.text]) do
    connect (← nodeId first) (← nodeId second)

@[export model_cft_disconnect]
def disconnectCommand (first second : Text) : IO Unit :=
  command (text "disconnect" [first.text, second.text]) do
    disconnect (← nodeId first) (← nodeId second)

@[export model_cft_disconnect_node]
def disconnectNode (node : Text) : IO Unit :=
  command (text "disconnect_node" [node.text]) do
    let id ← nodeId node
    for other in ← nodeIds do
      disconnect id other

@[export model_cft_reconnect]
def reconnect (first second : Text) : IO Unit :=
  command (text "reconnect" [first.text, second.text]) do
    connect (← nodeId first) (← nodeId second)

@[export model_cft_reconnect_node]
def reconnectNode (node : Text) : IO Unit :=
  command (text "reconnect_node" [node.text]) do
    let id ← nodeId node
    for other in ← nodeIds do
      if other != id then
        connect id other

@[export model_cft_dispatch_one]
def dispatchOne (node : Text) : IO Unit :=
  command (text "dispatch_one" [node.text]) do
    let id ← nodeId node
    discard <| get id
    dispatchQueue id

@[export model_cft_dispatch_single]
def dispatchSingle (source target : Text) : IO Unit :=
  command (text "dispatch_single" [source.text, target.text]) do
    let source ← nodeId source
    let target ← nodeId target
    discard <| get source
    if let some envelope := (← queue source).find? (·.target == target) then
      discard <| dispatch envelope

@[export model_cft_dispatch_all_once]
def dispatchAllOnceCommand : IO Unit :=
  command "dispatch_all_once" dispatchAllOnce

@[export model_cft_dispatch_all]
def dispatchAllCommand : IO Unit :=
  command "dispatch_all" dispatchAll

@[export model_cft_drop_pending]
def dropPending (node : Text) : IO Unit :=
  command (text "drop_pending" [node.text]) do
    for envelope in ← queue (← nodeId node) do
      lose envelope

@[export model_cft_drop_pending_to]
def dropPendingTo (source target : Text) : IO Unit :=
  command (text "drop_pending_to" [source.text, target.text]) do
    let target ← nodeId target
    for envelope in ← queue (← nodeId source) do
      if envelope.target == target then
        lose envelope

@[export model_cft_shuffle_one]
def shuffleOne (node : Text) : IO Unit :=
  command (text "shuffle_one" [node.text]) do shuffle (← nodeId node)

@[export model_cft_shuffle_all]
def shuffleAll : IO Unit :=
  command "shuffle_all" do
    for node in ← nodeIds do
      shuffle node

/-! The scenario driver prints for these commands. The model driver records every command. -/

@[export model_cft_state_one]
def stateOne (node : Text) : IO Unit :=
  command (text "state_one" [node.text]) (pure ()) (reads := true)

@[export model_cft_state_all]
def stateAll : IO Unit :=
  command "state_all" (pure ()) (reads := true)

@[export model_cft_summarise_log]
def summariseLog (node : Text) : IO Unit :=
  command (text "summarise_log" [node.text]) (pure ()) (reads := true)

@[export model_cft_summarise_logs_all]
def summariseLogsAll : IO Unit :=
  command "summarise_logs_all" (pure ()) (reads := true)

@[export model_cft_summarise_messages]
def summariseMessages (source target : Text) : IO Unit :=
  command (text "summarise_messages" [source.text, target.text]) (pure ())

@[export model_cft_assert_state_sync]
def assertStateSync : IO Unit :=
  command "assert_state_sync" (reads := true) do
    if let some reason ← discrepancy (← nodeIds) then
      fail s!"States not in sync: {reason}"

@[export model_cft_assert_commit_safety]
def assertCommitSafety (node : Text) : IO Unit :=
  command (text "assert_commit_safety" [node.text]) do checkCommitSafety (← nodeId node)

@[export model_cft_assert_commit_idx]
def assertCommitIdx (node : Text) (idx : UInt64) : IO Unit :=
  command (text "assert_commit_idx" [node.text, toString idx]) (reads := true) do
    let actual := (← get (← nodeId node)).commitIndex
    unless actual == idx.toNat do
      fail s!"Node {node.text} not at expected commit idx ({idx}) : {actual}"

@[export model_cft_assert_detail]
def assertDetail (node : Text) (name : String) (expected : Text) : IO Unit :=
  command (text "assert_detail" [node.text, name, expected.text]) do
    let actual ← detail (← nodeId node) name
    unless actual == expected.text do
      fail s!"Node {node.text} {name} is not as expected: {actual} != {expected.text}"

@[export model_cft_assert_not_detail]
def assertNotDetail (node : Text) (name : String) (unexpected : Text) : IO Unit :=
  command (text "assert_!detail" [node.text, name, unexpected.text]) do
    let actual ← detail (← nodeId node) name
    if actual == unexpected.text then
      fail s!"Node {node.text} {name} is not as expected: {actual} == {unexpected.text}"

@[export model_cft_assert_config]
def assertConfig (node : Text) (idx : UInt64) (nodes : List Text) : IO Unit :=
  command (text "assert_config" (node.text :: toString idx :: texts nodes)) do
    let expected := Finset.ofList (← nodes.mapM nodeId)
    match (← get (← nodeId node)).activeConfigurations.find? (·.index == idx.toNat) with
    | none => fail s!"Node {node.text} does not have a configuration at idx {idx}"
    | some configuration =>
        unless configuration.nodes == expected do
          fail
            s!"Node {node.text} configuration at idx {idx} ({configuration.nodes.sort.map nodeName}) does not match expected ({texts nodes})"

@[export model_cft_assert_absent_config]
def assertAbsentConfig (node : Text) (idx : UInt64) : IO Unit :=
  command (text "assert_absent_config" [node.text, toString idx]) do
    if (← get (← nodeId node)).activeConfigurations.any (·.index == idx.toNat) then
      fail s!"Node {node.text} has unexpected configuration at idx {idx}"

@[export model_cft_assert_last_txid]
def assertLastTxid (node : Text) (txid : String) : IO Unit :=
  command (text "assert_last_txid" [node.text, txid]) (reads := true) do
    let state ← get (← nodeId node)
    let actual := s!"{termAt state.log state.log.length}.{state.log.length}"
    unless actual == txid do
      fail s!"Node {node.text} lastTxID is not as expected: {actual} != {txid}"

@[export model_cft_loop_until_sync]
def loopUntilSyncCommand : IO Unit :=
  command "loop_until_sync" loopUntilSync

/-! `CftDriver.run` starts the scenario driver before a scenario, and stops it after. -/

/-- Forget the last run. The model driver exports no trace to a collector. -/
@[export model_cft_start]
def start (_fluentd : List String) : IO Unit :=
  driver.set {}

/-- Confirm that the network can still make progress, as the scenario driver does. -/
@[export model_cft_finish]
def finish : IO Unit :=
  command "finish" loopUntilSync

/--
Run a scenario on the model, and write its trace to `file`, if given: a line for each
command. Give what went wrong, if anything did.
-/
def run (steps : IO Unit) (file : Option System.FilePath) : IO (Option String) := do
  start []
  let problem ←
    try
      steps
      finish
      pure none
    catch error =>
      pure (some (toString error))
  if let some file := file then
    IO.FS.writeFile file
      (String.join ((← driver.get).records.toList.map (·.compress ++ "\n")))
  return problem

end ModelDriver

/--
Run the scenario named by the first argument on the model, and write its trace to the file
named by the second, if given. With `--all`, run every scenario, and write the trace of
each to the directory named by the second argument, if given.
-/
def main (args : List String) : IO UInt32 := do
  let registered := (← scenarios.get).reverse
  match args with
  | ["--all"] | ["--all", _] =>
      let directory := args[1]?.map System.FilePath.mk
      if let some directory := directory then
        IO.FS.createDirAll directory
      let mut failed := 0
      for (name, steps) in registered do
        match ← ModelDriver.run steps (directory.map (· / s!"{name}.ndjson")) with
        | none => IO.println s!"{name}: ok"
        | some problem =>
            failed := failed + 1
            IO.println s!"{name}: FAILED\n{problem}"
      IO.println s!"{registered.length} scenarios, {failed} failed"
      return if failed == 0 && !registered.isEmpty then 0 else 1
  | [name] | [name, _] =>
      let some steps := registered.lookup name
      | do
        IO.eprintln s!"Unknown scenario '{name}'"
        return 2
      match ← ModelDriver.run steps (args[1]?.map System.FilePath.mk) with
      | none =>
          IO.println s!"{name}: ok"
          return 0
      | some problem =>
          IO.eprintln s!"{name}: {problem}"
          return 1
  | _ =>
      IO.eprintln "usage: cft_model_driver SCENARIO [TRACE] | --all [DIRECTORY]"
      return 2
