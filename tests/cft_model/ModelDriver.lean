-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import Consensus.Model
import Scenarios
import Std.Time

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

It writes a trace of what the model does, in the records which the implementation traces:
a step of the model is one call of `cft.h`, which traces several events as it goes.
-/

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

/-- The bytes of entries which a primary of `cft.h` replicates before it sends them. -/
private def sizeLimit : Nat := 20000

/-! ## JSON -/

/--
JSON whose objects keep the order of their fields, so that a record is written as the
scenario test writes that of the implementation.
-/
inductive Value where
  | number (value : Nat)
  | text (value : String)
  | flag (value : Bool)
  | list (items : List Value)
  | object (fields : List (String × Value))

/-- A string as Python writes it in JSON: other than printable ASCII is escaped. -/
private def quote (text : String) : String :=
  let unit (code : Nat) : String :=
    let digits := String.ofList (Nat.toDigits 16 code)
    "\\u" ++ "".pushn '0' (4 - digits.length) ++ digits
  let escape (c : Char) : String :=
    if c == '"' then
      "\\\""
    else if c == '\\' then
      "\\\\"
    else if c == '\n' then
      "\\n"
    else if c == '\r' then
      "\\r"
    else if c == '\t' then
      "\\t"
    else if c.toNat == 8 then
      "\\b"
    else if c.toNat == 12 then
      "\\f"
    else if 32 <= c.toNat && c.toNat <= 126 then
      c.toString
    else if c.toNat < 65536 then
      unit c.toNat
    else
      -- A surrogate pair
      unit (55296 + (c.toNat - 65536) / 1024) ++ unit (56320 + (c.toNat - 65536) % 1024)
  "\"" ++ String.join (text.toList.map escape) ++ "\""

/-- A value on one line, with the separators of Python, or without spaces if `compact`. -/
partial def Value.render (value : Value) (compact : Bool := false) : String :=
  let (item, field) := if compact then (",", ":") else (", ", ": ")
  match value with
  | .number value => toString value
  | .text value => quote value
  | .flag value => if value then "true" else "false"
  | .list items => "[" ++ item.intercalate (items.map (render · compact)) ++ "]"
  | .object fields =>
      "{"
      ++ item.intercalate
          (fields.map fun (key, value) => quote key ++ field ++ value.render compact)
      ++ "}"

/-! ## Driver -/

/-- What `cft.h` keeps to decide how many entries a primary sends in one message. -/
structure Batching where
  /-- The entries which the node has replicated since it last sent before the end of a batch. -/
  count : Nat := 0
  /-- The bytes of those entries. -/
  size : Nat := 0
  /-- A hundred times the moving average of the entries which fit in `sizeLimit`. -/
  window : Nat := 0
  /-- The most entries of one message. -/
  limit : Nat := 20

/-- As `update_batch_size` in `cft.h`. -/
private def Batching.resized (batching : Batching) : Batching :=
  let average := if batching.count == 0 then sizeLimit else batching.size / batching.count
  let fit := if average == 0 then sizeLimit / 2 else sizeLimit / average
  let window := batching.window - batching.window / 100 + fit
  { batching with window, limit := max (window / 100) 1 }

/-- The model, and what the scenario driver and `cft.h` keep beside it. -/
structure Driver where
  /-- The node which `startNode` created. -/
  first : Option NodeID := none
  state : Model.State := { nodes := [] }
  /-- Milliseconds since the timer of each node restarted. -/
  elapsed : NodeID → Nat := fun _ => 0
  /-- For a primary, milliseconds since each peer acknowledged it. -/
  sinceAck : NodeID → NodeID → Nat := fun _ _ => 0
  batching : NodeID → Batching := fun _ => {}
  /-- The pairs of nodes of which the first can send to the second. -/
  connections : List (NodeID × NodeID) := []
  nextRequest : Nat := 1
  commands : Nat := 0
  /-- The messages sent by the step which is being traced, whose events are not yet written. -/
  outbox : List Envelope := []
  /-- The trace: the `msg` of each record. -/
  records : Array Value := #[]

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

private def named (node : NodeID) : Value :=
  .text (nodeName node)

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

private def retirementPhase (node : NodeID) (state : NodeState) : Option String :=
  match (state.retirement node).phase with
  | .noRetirementObserved => none
  | .retirementOrdered => some "Ordered"
  | .retirementSigned => some "Signed"
  | .retirementCompleted => some "Completed"
  | .retiredCommitted => some "RetiredCommitted"

/-- Whether `node` has not seen its retirement. -/
private def isActive (node : NodeID) (state : NodeState) : Bool :=
  (retirementPhase node state).isNone

/-! ## Trace -/

/-- The state of a node, as the implementation traces it. -/
structure Snapshot where
  node : NodeID
  view : Nat
  last : Nat
  commit : Nat
  leadership : String
  /-- The phase of its retirement, once it has seen it. -/
  phase : Option String
  retirementIdx : Option Nat
  retirementCommittableIdx : Option Nat
  retiredCommittedIdx : Option Nat
  /-- The first of the signatures after its commit index, and the last if there is another. -/
  committable : List Nat
deriving BEq

private def snapshot (node : NodeID) (state : NodeState) : Snapshot :=
  let retirement := state.retirement node
  let signatures :=
    (state.log.zipIdx 1).filterMap
      fun (entry, index) =>
        if index > state.commitIndex && entry.content.isSignature then
          some index
        else
          none
  {
    node
    view := state.currentTerm
    last := state.log.length
    commit := state.commitIndex
    leadership := leadership state
    phase := retirementPhase node state
    retirementIdx := retirement.index
    retirementCommittableIdx := retirement.committableIndex
    retiredCommittedIdx := state.retiredCommittedIndex
    committable :=
      match signatures with
      | [] => []
      | first :: rest => first :: rest.getLast?.toList
  }

private def Snapshot.value (shown : Snapshot) : Value :=
  let index (key : String) (value : Option Nat) : List (String × Value) :=
    value.toList.map fun value => (key, .number value)
  .object
    ([
        ("node_id", named shown.node),
        ("current_view", .number shown.view),
        ("last_idx", .number shown.last),
        ("commit_idx", .number shown.commit),
        ("leadership_state", .text shown.leadership),
        ("membership_state", .text (if shown.phase.isSome then "Retired" else "Active"))
      ]
      ++ shown.phase.toList.map (fun phase => ("retirement_phase", .text phase))
      ++ index "retirement_idx" shown.retirementIdx
      ++ index "retirement_committable_idx" shown.retirementCommittableIdx
      ++ index "retired_committed_idx" shown.retiredCommittedIdx
      ++ [("committable_indices", .list (shown.committable.map .number))])

private def nodesValue (nodes : Finset NodeID) : Value :=
  .object (nodes.sort.map fun node => (nodeName node, .object [("address", .text ":")]))

/-- The configurations which a node has not yet replaced by a committed one. -/
private def configurations (state : NodeState) : String × Value :=
  (
    "configurations",
    .list
      (state.activeConfigurations.map
        fun configuration =>
          .object
            [
              ("idx", .number configuration.index),
              ("nodes", nodesValue configuration.nodes),
              ("rid", .number configuration.index)
            ])
  )

/-- The fields of `add_configuration`, for the configuration `members` at `index`. -/
private def added (state : NodeState) (index : Nat) (members : Finset NodeID)
    : List (String × Value) :=
  [
    configurations state,
    ("idx", .number index),
    ("nodes", nodesValue members),
    ("rid", .number index)
  ]

/-- A message, as the implementation traces its packet. -/
private def packet : Message → Value
  | .appendEntriesRequest request =>
      .object
        [
          ("msg", .text "append_entries"),
          ("idx", .number (request.prevLogIndex + request.entries.length)),
          ("prev_idx", .number request.prevLogIndex),
          ("term", .number request.term),
          ("prev_term", .number request.prevLogTerm),
          ("leader_commit_idx", .number request.primaryCommit),
          (
            "term_of_idx",
            .number (request.entries.getLast?.map Entry.term |>.getD request.prevLogTerm)
          ),
          ("contains_new_view", .flag false)
        ]
  | .appendEntriesResponse response =>
      .object
        [
          ("msg", .text "append_entries_response"),
          ("term", .number response.term),
          ("last_log_idx", .number response.lastLogIndex),
          ("success", .text (if response.success then "OK" else "FAIL"))
        ]
  | .requestVoteRequest request => vote "request_vote" request
  | .requestPreVoteRequest request => vote "request_pre_vote" request
  | .requestVoteResponse response => voted "request_vote_response" response
  | .requestPreVoteResponse response => voted "request_pre_vote_response" response
  | .proposeRequestVoteRequest term =>
      .object [("msg", .text "propose_request_vote"), ("term", .number term)]
where
  vote (msg : String) (request : RequestVoteRequest) : Value :=
    .object
      [
        ("msg", .text msg),
        ("term", .number request.term),
        ("last_committable_idx", .number request.lastCommittableIndex),
        ("term_of_last_committable_idx", .number request.lastCommittableTerm)
      ]
  voted (msg : String) (response : RequestVoteResponse) : Value :=
    .object
      [
        ("msg", .text msg),
        ("term", .number response.term),
        ("vote_granted", .flag response.voteGranted)
      ]

private def write (msg : Value) : IO Unit :=
  driver.modify fun d => { d with records := d.records.push msg }

/-- Write an event: what `function` of the implementation traces. -/
private def event (function : String) (fields : List (String × Value)) : IO Unit :=
  write (.object (("function", .text function) :: fields))

/-- Write an event with the state of `node`. -/
private def stateEvent (function : String) (node : NodeID) (state : NodeState)
    (fields : List (String × Value) := [])
    : IO Unit :=
  event function (("state", (snapshot node state).value) :: fields)

/-- The next message sent by the step which is being traced, if `kind` holds of it. -/
private def nextSent (kind : Message → Bool := fun _ => true) : IO (Option Envelope) :=
  return (← driver.get).outbox.head?.filter (kind ·.payload)

/-- Write the event for the next message which the step sent, from a node shown as `shown`. -/
private def sentEvent (function : String) (shown : Snapshot)
    (fields : List (String × Value) := [])
    : IO Unit := do
  let envelope :: rest := (← driver.get).outbox
  | fail s!"The model sent no message to trace as {function}"
  driver.modify fun d => { d with outbox := rest }
  event function
    ([
        ("state", shown.value),
        ("packet", packet envelope.payload),
        ("to_node_id", named envelope.target)
      ]
      ++ fields)

private def isEntries : Message → Bool
  | .appendEntriesRequest _ => true
  | _ => false

private def isVoteRequest : Message → Bool
  | .requestVoteRequest _ => true
  | _ => false

private def isPreVoteRequest : Message → Bool
  | .requestPreVoteRequest _ => true
  | _ => false

private def isNomination : Message → Bool
  | .proposeRequestVoteRequest _ => true
  | _ => false

/--
`send_append_entries`, for the next message which the step sent, and the state of its
sender after. `shown` is how `cft.h` traces the sender, and `shownSent` the index which it
holds as sent before, if they are not those of the model.
-/
private def entriesSent (node : NodeID) (state : NodeState)
    (shown : Option Snapshot := none) (shownSent : Option Nat := none)
    : IO NodeState := do
  let some envelope ← nextSent isEntries
  | fail s!"The model sent no entries to trace for node {nodeName node}"
  let .appendEntriesRequest request := envelope.payload | return state
  let peer := envelope.target
  sentEvent "send_append_entries" (shown.getD (snapshot node state))
    [
      ("match_idx", .number (state.matchIndex peer)),
      ("sent_idx", .number (shownSent.getD (state.sentIndex peer)))
    ]
  return {
    state with
      sentIndex :=
        CCF.Function.update state.sentIndex peer
          (request.prevLogIndex + request.entries.length)
  }

/--
`commit`: `node` commits up to `index`, if that is after its commit index, and its state
after. A primary whose retirement is then committed nominates its successor: `cft.h` does
so while it is still primary, before it records the phase of its retirement.
-/
private def committed (node : NodeID) (state : NodeState) (index : Nat)
    : IO NodeState := do
  if index <= state.commitIndex then
    return state
  stateEvent "commit" node state [("idx", .number index), configurations state]
  let after := state.recordCommit node index
  if state.role == .primary then
    if let some envelope ← nextSent isNomination then
      let shown :=
        { snapshot node after with leadership := "Leader", phase := some "Completed" }
      event "step_down_and_nominate_successor"
        [
          ("state", shown.value),
          configurations state,
          ("to_node_id", named envelope.target)
        ]
      sentEvent "send_propose_request_vote" shown
  return after

/--
`become_leader`, and what `cft.h` does at once as primary: commit, if the node needs no
other to do so, and send to each peer.
-/
private def becameLeader (node : NodeID) (state : NodeState) : IO NodeState := do
  let mut leader := primaryState state
  stateEvent "become_leader" node leader [configurations leader]
  leader ← committed node leader (highestCommittableIndex leader node)
  while (← nextSent isEntries).isSome do
    leader ← entriesSent node leader
  return leader

/--
`become_candidate`, which elects a node at once if its own vote is a quorum, and asks the
others for theirs.
-/
private def becameCandidate (node : NodeID) (state : NodeState) : IO NodeState := do
  let candidate : NodeState :=
    {
      state with
        role := .candidate
        currentTerm := state.currentTerm + 1
        votedFor := some node
        primaryKnown := false
        votesGranted := {node}
        preVotesGranted := ∅
    }
  stateEvent "become_candidate" node candidate [configurations candidate]
  let mut state := candidate
  if hasQuorum candidate.activeConfigurations candidate.votesGranted
      ∧ Not (candidate.isRetiredCommitted node) then
    state ← becameLeader node candidate
  while (← nextSent isVoteRequest).isSome do
    sentEvent "send_request_vote" (snapshot node state)
  return state

/-- An election timeout: `become_pre_vote_candidate`, and the requests for a pre-vote. -/
private def timedOut (node : NodeID) (pre : NodeState) : IO NodeState := do
  let state : NodeState :=
    {
      pre with
        role := .preVoteCandidate, primaryKnown := false, preVotesGranted := {node}
    }
  stateEvent "become_pre_vote_candidate" node state [configurations state]
  if hasQuorum state.activeConfigurations state.preVotesGranted then
    becameCandidate node state
  else
    while (← nextSent isPreVoteRequest).isSome do
      sentEvent "send_request_vote" (snapshot node state)
    return state

/--
`replicate`: a primary appends `entries` in one batch, each with whether `cft.h` then sends
what it has not sent, before the end of the batch.
-/
private def replicated (node : NodeID) (pre : NodeState)
    (entries : List (AppendEntryInput × Bool))
    : IO NodeState := do
  stateEvent "replicate" node pre
  let mut state := pre
  for (entry, flushed) in entries do
    let index := state.log.length + 1
    let metadata := entry.content.metadata
    stateEvent "replicate_entry" node state
      [
        ("view", .number state.currentTerm),
        ("seqno", .number index),
        ("globally_committable", .flag entry.content.isSignature)
      ]
    for retired in metadata.retirementConfirmations.sort do
      event "retired_committed_tx"
        [
          ("node_id", named node),
          ("seqno", .number index),
          ("retired_node_id", named retired)
        ]
    let appended : NodeState :=
      {
        state with
          log := state.log ++ [{ term := state.currentTerm, content := entry.content }]
      }
    if let some members := metadata.configuration then
      stateEvent "add_configuration" node state (added state index members)
      -- cft.h has seen the configuration, which may retire the node, before it holds the entry.
      -- It takes a node which the configuration adds to hold the entry, and sends it none.
      let shown := { snapshot node appended with last := state.log.length }
      for peer in ((members \ eligiblePeers state node).erase node).sort do
        state :=
          {
            state with
              sentIndex := CCF.Function.update state.sentIndex peer state.log.length
          }
        state ← entriesSent node state (shown := some shown) (shownSent := some index)
    state := { appended with sentIndex := state.sentIndex }
    -- cft.h traces that it sends, even if it has no peer to send to
    if flushed then
      stateEvent "batch_flush" node state
      for _ in entry.flushes do
        state ← entriesSent node state
  committed node state (highestCommittableIndex state node)

/-- The events of `node` receiving `message` from `source`, and its state after. -/
private def received (node source : NodeID) (message : Message) (pre : NodeState)
    : IO NodeState := do
  let receive (function : String) (fields : List (String × Value) := []) : IO Unit :=
    stateEvent function node pre
      ([("packet", packet message), ("from_node_id", named source)] ++ fields)
  -- become_aware_of_new_term
  let follow (term : Nat) : IO NodeState := do
    let state := becomeAwareOfNewTerm pre term
    stateEvent "become_follower" node state [configurations state]
    return state
  let known := decide (source ∈ eligiblePeers pre node)
  match message with
  | .appendEntriesRequest request =>
      receive "recv_append_entries"
      let mut state := pre
      if pre.currentTerm < request.term
          || (pre.currentTerm == request.term
              && (pre.role == .candidate || pre.role == .preVoteCandidate)) then
        state ← follow request.term
      -- Without a response, cft.h ignored the message
      let some response ← nextSent | return state
      let accepted :=
        match response.payload with
        | .appendEntriesResponse response => response.success
        | _ => false
      if accepted then
        if let some index := firstTermConflictIndex state request then
          state :=
            { state with log := state.log.take (index - 1), isNewFollower := false }
        let limit :=
          min request.primaryCommit (request.prevLogIndex + request.entries.length)
        let commit (state : NodeState) : IO NodeState :=
          committed node state
            (max state.commitIndex (maxCommittableIndexUpTo state.log limit))
        for entry in request.entries.drop (state.log.length - request.prevLogIndex) do
          stateEvent "execute_append_entries_sync" node state
            [("from_node_id", named source)]
          let before := state
          let index := state.log.length + 1
          state := { state with log := state.log ++ [entry] }
          for retired in entry.content.metadata.retirementConfirmations.sort do
            event "retired_committed_tx"
              [
                ("node_id", named node),
                ("seqno", .number index),
                ("retired_node_id", named retired)
              ]
          if let some members := entry.content.metadata.configuration then
            -- cft.h holds the entry before it sees the configuration in it
            event "add_configuration"
              (("state", ({ snapshot node before with last := index }).value)
                :: added before index members)
          if entry.content.isSignature then
            state ← commit state
        state ← commit state
      sentEvent "send_append_entries_response" (snapshot node state)
      return state
  | .appendEntriesResponse response =>
      -- cft.h ignores the response of a node which it does not know, before it traces it
      unless known do
        return pre
      receive "recv_append_entries_response"
        [
          ("match_idx", .number (pre.matchIndex source)),
          ("sent_idx", .number (pre.sentIndex source))
        ]
      if pre.role != .primary then
        return pre
      if pre.currentTerm < response.term then
        follow response.term
      else if response.success && response.term == pre.currentTerm then
        let state :=
          {
            pre with
              matchIndex :=
                CCF.Function.update pre.matchIndex source
                  (max (pre.matchIndex source) response.lastLogIndex)
          }
        committed node state (highestCommittableIndex state node)
      else
        return pre
  | .requestVoteRequest request | .requestPreVoteRequest request =>
      receive "recv_request_vote"
      let state ← if pre.currentTerm < request.term then follow request.term else pure pre
      sentEvent "send_request_vote_response" (snapshot node state)
      return state
  | .requestVoteResponse response =>
      receive "recv_request_vote_response"
      if !known then
        return pre
      else if pre.currentTerm < response.term then
        follow response.term
      else if
        pre.role == .candidate
        && response.term == pre.currentTerm
        && response.voteGranted then
        let state := { pre with votesGranted := insert source pre.votesGranted }
        if hasQuorum state.activeConfigurations state.votesGranted
            ∧ Not (state.isRetiredCommitted node) then
          becameLeader node state
        else
          return state
      else
        return pre
  | .requestPreVoteResponse response =>
      receive "recv_request_vote_response"
      if !known then
        return pre
      else if pre.currentTerm < response.term then
        follow response.term
      else if
        pre.role == .preVoteCandidate
        && response.term == pre.currentTerm
        && response.voteGranted then
        let state := { pre with preVotesGranted := insert source pre.preVotesGranted }
        if hasQuorum state.activeConfigurations state.preVotesGranted then
          becameCandidate node state
        else
          return state
      else
        return pre
  | .proposeRequestVoteRequest term =>
      receive "recv_propose_request_vote"
      if term = pre.currentTerm ∧ canStartElection pre node then
        becameCandidate node pre
      else
        return pre

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

/--
Take a step of the model, and write the events which the implementation traces for it:
`events` does, from the state of the node before the step, and gives its state after.
`false` if the model does not allow the step, which then writes nothing.
-/
private def perform (action : Model.Action)
    (events : NodeState → NodeState → IO NodeState)
    : IO Bool := do
  let d ← driver.get
  let some first := d.first | fail "No node has started"
  let node :=
    match action with
    | .local node _ => node
    | .deliver envelope => envelope.target
  let some pre := nodeState d.state node | fail s!"Node {nodeName node} does not exist"
  let some after := Model.networkStep ({first} : Finset NodeID) d.state action
  | return false
  let some post := nodeState after node | fail s!"Node {nodeName node} does not exist"
  let kept :=
    match action with
    | .local .. => d.state.network.length
    | .deliver _ => d.state.network.length - 1
  let sent := after.network.drop kept
  driver.set { d with state := after, outbox := sent }
  let traced ← events pre post
  -- The events are those of the step: they show each message sent, and end in its state
  unless (← driver.get).outbox.isEmpty && snapshot node traced == snapshot node post do
    fail
      s!"The events traced for a step of node {nodeName node} are not those of the model"
  updateTimers node pre post action sent
  return true

/-! ## Messages -/

/-- The undelivered messages of `source`, oldest first. -/
private def queue (source : NodeID) : IO (List Envelope) :=
  return (← driver.get).state.network.filter (·.source == source)

/-- Lose a message: it is no longer undelivered. -/
private def lose (envelope : Envelope) : IO Unit := do
  stateEvent "drop_pending_to" envelope.source (← get envelope.source)
    [
      ("from_node_id", named envelope.source),
      ("to_node_id", named envelope.target),
      ("packet", packet envelope.payload)
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
    let events (pre _post : NodeState) : IO NodeState :=
      received envelope.target envelope.source envelope.payload pre
    if ← perform (.deliver envelope) events then
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

/--
The last index of each message in which a primary with `log` sends a peer the entries
after `sent`, as `send_append_entries` in `cft.h`: at most `limit` entries, of one term.
A primary with no entry to send sends one message without any.
-/
private def ranges (log : List Entry) (sent limit : Nat) : List Nat :=
  go (log.length + 1) sent
where
  go : Nat → Nat → List Nat
    | 0, _ => []
    | fuel + 1, sent =>
        let start := sent + 1
        let stop :=
          if start > log.length then
            log.length
          else
            min (start + limit - 1) (endOfTerm log start)
        if stop == log.length then [stop] else stop :: go fuel stop

/-- Advance the clock of `node`, as `periodic` in `cft.h`. -/
private def periodic (node : NodeID) (ms : Nat) : IO Unit := do
  let state ← get node
  stateEvent "tick" node state
  driver.modify
    fun d =>
      { d with elapsed := fun other => d.elapsed other + if other == node then ms else 0 }
  let elapsed := (← driver.get).elapsed node
  if state.role == .primary then
    if elapsed >= requestTimeout then
      restart node
      driver.modify
        fun d =>
          {
            d with
              batching := CCF.Function.update d.batching node (d.batching node).resized
          }
      let limit := ((← driver.get).batching node).limit
      for peer in (eligiblePeers state node).sort do
        for stop in ranges state.log (state.sentIndex peer) limit do
          let events (pre _post : NodeState) : IO NodeState := entriesSent node pre
          unless ← perform (.local node (.sendEntries peer stop)) events do
            break
    -- cft.h counts the time since a peer acknowledged from when it first knows that peer
    let peers := eligiblePeers state node
    driver.modify
      fun d =>
        {
          d with
            sinceAck :=
              fun primary peer =>
                d.sinceAck primary peer
                + if primary == node && decide (peer ∈ peers) then ms else 0
        }
    let d ← driver.get
    let live (configuration : Configuration) : Nat :=
      (configuration.nodes.sort.filter
        fun member => member == node || d.sinceAck node member < electionTimeout).length
    -- A primary steps down unless a majority of each configuration has acknowledged it
    unless (← get node).activeConfigurations.all
            fun configuration => live configuration >= configuration.nodes.card / 2 + 1 do
      let events (_pre post : NodeState) : IO NodeState := do
        stateEvent "become_follower" node post [configurations post]
        return post
      discard <| perform (.local node (.timeout .checkQuorum)) events
  else if elapsed >= electionTimeout && !decide (state.isRetiredCommitted node) then
    let events (pre _post : NodeState) : IO NodeState := timedOut node pre
    discard <| perform (.local node (.timeout .election)) events

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

/-- An entry to replicate, with the bytes which the scenario driver replicates for it. -/
abbrev Replicated := EntryContent × Nat

/--
The bytes which the scenario driver replicates for an entry of `kind` whose data has
`bytes`: JSON which names the kind, and holds the data in base64.
-/
private def entryBytes (kind : String) (bytes : Nat) : Nat :=
  21 + kind.utf8ByteSize + 4 * ((bytes + 2) / 3)

/--
The bytes of `text` in the JSON which the scenario driver replicates, without its quotes:
a quote, a backslash and a control character are escaped, and the rest is UTF-8.
-/
private def escapedBytes (text : String) : Nat :=
  let bytes (c : Char) : Nat :=
    if c == '"' || c == '\\' then
      2
    else if c == '\n' || c == '\r' || c == '\t' || c.toNat == 8 || c.toNat == 12 then
      2
    else if c.toNat < 32 then
      -- As \u00XX
      6
    else
      c.utf8Size
  (text.toList.map bytes).sum

/-- The bytes of the JSON in which the scenario driver replicates `nodes`, with their addresses. -/
private def nodesBytes (nodes : List NodeID) : Nat :=
  2 + (nodes.length - 1) + (nodes.map fun node => escapedBytes (nodeName node) + 18).sum

/-- A number for a transaction, which no other has. -/
private def newRequest : IO Nat := do
  let request := (← driver.get).nextRequest
  driver.modify fun d => { d with nextRequest := request + 1 }
  return request

private def signed : Replicated :=
  (.signature, entryBytes "raw" "signature".utf8ByteSize)

private def transaction (data : String) : IO Replicated :=
  return (.transaction (← newRequest) {}, entryBytes "raw" data.utf8ByteSize)

private def reconfiguration (members : List NodeID) : IO Replicated :=
  return (
    .transaction (← newRequest) { configuration := some (Finset.ofList members) },
    entryBytes "reconfiguration" (nodesBytes members)
  )

private def retirement (retired : List NodeID) : IO Replicated :=
  return (
    .transaction (← newRequest) { retirementConfirmations := Finset.ofList retired },
    entryBytes "retired_committed" (nodesBytes retired)
  )

/--
Append `entries` in one batch on the primary in `term`, if there is one. As `cft.h`, the
primary sends what it has not sent once the entries which it has replicated reach
`sizeLimit`, and not only at its next tick. A batch of no entries is traced, and appends
nothing.
-/
private def append (term : Text) (entries : List Replicated) : IO Unit := do
  let some primary ← findPrimary term | return
  let state ← get primary
  if entries.isEmpty then
    -- cft.h traces a call which replicates nothing, where the model appends at least one entry
    if decide (state.isRetiredCommitted primary) then
      fail s!"The model does not let node {nodeName primary} append these entries"
    stateEvent "replicate" primary state
    return
  let mut batching := (← driver.get).batching primary
  let mut log := state.log
  let mut sent := state.sentIndex
  let mut inputs : Array (AppendEntryInput × Bool) := #[]
  for (content, size) in entries do
    let before : NodeState := { state with log }
    if let some members := content.metadata.configuration then
      for peer in ((members \ eligiblePeers before primary).erase primary).sort do
        sent := CCF.Function.update sent peer log.length
    log := log ++ [{ term := state.currentTerm, content }]
    batching :=
      { batching with count := batching.count + 1, size := batching.size + size }
    let mut flushes : List (NodeID × Nat) := []
    let flushed := batching.size >= sizeLimit
    if flushed then
      batching := { batching.resized with count := 0, size := 0 }
      for peer in (eligiblePeers { state with log } primary).sort do
        let stops := ranges log (sent peer) batching.limit
        flushes := flushes ++ stops.map (peer, ·)
        sent := CCF.Function.update sent peer log.length
    inputs := inputs.push ({ content, flushes }, flushed)
  driver.modify
    fun d => { d with batching := CCF.Function.update d.batching primary batching }
  let events (pre _post : NodeState) : IO NodeState :=
    replicated primary pre inputs.toList
  unless ← perform (.local primary (.append (inputs.toList.map (·.1)))) events do
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
  let events (pre post : NodeState) : IO NodeState := do
    stateEvent "init_as_backup" node pre [("seqno", .number 0), ("view", .number 0)]
    stateEvent "become_follower" node post [configurations post]
    return post
  unless ← perform (.local node (.initAsBackup [])) events do
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
  append term [← reconfiguration ((← nodeIds).filter (!out.contains ·))]

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
Sign on the primary in the highest term, connect the nodes which have not retired and which
that primary knows, and have it send until they are in sync. It sends nothing to a node
which it does not know.
-/
private def loopUntilSync : IO Unit := do
  let some (term, primary) ← latestPrimary
  | fail "Can't currently loop until sync, no primary"
  let known := eligiblePeers (← get primary) primary
  let active ←
    (← nodeIds).filterM
      fun node =>
        return isActive node (← get node) && (node == primary || decide (node ∈ known))
  append (toString term : String) [signed]
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
Run a command: record it, as the scenario driver does, and name it if it fails. The commit
index of every node must then be safe, which the scenario driver does not check after a
command which only reads.
-/
private def command {α : Type} (name : String) (run : IO α) (reads : Bool := false)
    : IO α := do
  driver.modify fun d => { d with commands := d.commands + 1 }
  write (.object [("cmd", .text name)])
  try
    let result ← run
    unless reads do
      for node in ← nodeIds do
        checkCommitSafety node
    return result
  catch error =>
    fail s!"Step {(← driver.get).commands} ({name}) failed: {error}"

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
    let state := Model.initialNodeState ({id} : Finset NodeID) id
    let size := entryBytes "reconfiguration" (nodesBytes [id])
    driver.modify
      fun d =>
        {
          d with
            first := some id
            state := { nodes := [(id, state)] }
            batching := CCF.Function.update d.batching id { count := 1, size }
        }
    -- The model starts with the node as primary of its own configuration, which cft.h replicates
    let empty := { state with log := [] }
    stateEvent "become_leader" id empty [configurations empty]
    stateEvent "replicate" id empty
    stateEvent "replicate_entry" id empty
      [
        ("view", .number state.currentTerm),
        ("seqno", .number 1),
        ("globally_committable", .flag false)
      ]
    stateEvent "add_configuration" id empty (added empty 1 {id})

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
    append term [← retirement retired]

@[export model_cft_nominate_successor]
def nominateSuccessor (node : Text) : IO Unit :=
  command (text "nominate_successor" [node.text]) do
    let id ← nodeId node
    stateEvent "nomination" id (← get id)
    let events (pre _post : NodeState) : IO NodeState := do
      if let some envelope ← nextSent isNomination then
        stateEvent "step_down_and_nominate_successor" id pre
          [configurations pre, ("to_node_id", named envelope.target)]
        sentEvent "send_propose_request_vote" (snapshot id pre)
      return pre
    discard <| perform (.local id .nominateSuccessor) events

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
    append term [← reconfiguration members]

@[export model_cft_replicate]
def replicate (term : Text) (entries : List Text) : IO Unit :=
  command (text "replicate" (term.text :: texts entries)) do
    append term
      (← entries.mapM
          fun entry => if entry.text == "$" then pure signed else transaction entry.text)

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

/-- Each message as the scenario driver writes it: the packet of the trace, without spaces. -/
@[export model_cft_pending_messages]
def pendingMessages (source target : Text) : IO (Array String) :=
  command (text "pending_messages" [source.text, target.text]) (reads := true) do
    let source ← nodeId source
    let target ← nodeId target
    discard <| get source
    let pending := (← queue source).filter (·.target == target)
    return pending.toArray.map
      fun envelope =>
        (packet envelope.payload).render (compact := true)

@[export model_cft_dispatch_all_once]
def dispatchAllOnceCommand : IO Unit :=
  command "dispatch_all_once" dispatchAllOnce

@[export model_cft_dispatch_all]
def dispatchAllCommand : IO Unit :=
  command "dispatch_all" dispatchAll

@[export model_cft_drop_pending]
def dropPending (node : Text) : IO Unit :=
  command (text "drop_pending" [node.text]) do
    let pending ← queue (← nodeId node)
    -- The scenario driver drops the messages to each node in turn
    for target in ← nodeIds do
      for envelope in pending do
        if envelope.target == target then
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

@[export model_cft_assert_view]
def assertView (node : Text) (idx : UInt64) (view : UInt64) : IO Unit :=
  command (text "assert_view" [node.text, toString idx, toString view]) (reads := true) do
    let state ← get (← nodeId node)
    let actual := termAt state.log idx.toNat
    unless actual == view.toNat do
      fail s!"Node {node.text} view at idx {idx} is not as expected: {actual} != {view}"

@[export model_cft_loop_until_sync]
def loopUntilSyncCommand : IO Unit :=
  command "loop_until_sync" loopUntilSync

/-! `CftDriver.run` starts the scenario driver before a scenario, and stops it after. -/

/-- Forget the last run. The model driver exports no trace to a collector. -/
@[export model_cft_start]
def start (_fluentd : List String) : IO Unit :=
  driver.set {}

/--
Confirm that the network can still make progress, as the scenario driver does after a
scenario, which is not a command of the trace.
-/
@[export model_cft_finish]
def finish : IO Unit :=
  loopUntilSync

/-- The process, as the implementation identifies it in each record: by its ID and the time. -/
private def processId : IO String := do
  let now ← Std.Time.Timestamp.now
  return s!"{← IO.Process.getPID}-{now.toNanosecondsSinceUnixEpoch.val}"

/--
Run a scenario on the model, and write its trace to `file`, if given: a record on each line,
numbered from 0 as those of the implementation. Give what went wrong, if anything did.
-/
def run (steps : IO Unit) (process : String) (file : Option System.FilePath)
    : IO (Option String) := do
  start []
  let problem ←
    try
      steps
      finish
      pure none
    catch error =>
      pure (some (toString error))
  if let some file := file then
    let line (msg : Value) (sequence : Nat) : String :=
      (Value.object
        [("pid", .text process), ("m_ts", .number sequence), ("msg", msg)]).render
      ++ "\n"
    IO.FS.writeFile file
      (String.join
        ((← driver.get).records.toList.zipIdx.map
          fun (msg, sequence) => line msg sequence))
  return problem

end ModelDriver

/--
Run the scenario named by the first argument on the model, and write its trace to the file
named by the second, if given. With `--all`, run every scenario, and write the trace of
each to the directory named by the second argument, if given.
-/
def main (args : List String) : IO UInt32 := do
  let registered := (← scenarios.get).reverse
  let process ← ModelDriver.processId
  match args with
  | ["--all"] | ["--all", _] =>
      let directory := args[1]?.map System.FilePath.mk
      if let some directory := directory then
        IO.FS.createDirAll directory
      let mut failed := 0
      for (name, steps) in registered do
        match ← ModelDriver.run steps process (directory.map (· / s!"{name}.ndjson")) with
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
      match ← ModelDriver.run steps process (args[1]?.map System.FilePath.mk) with
      | none =>
          IO.println s!"{name}: ok"
          return 0
      | some problem =>
          IO.eprintln s!"{name}: {problem}"
          return 1
  | _ =>
      IO.eprintln "usage: cft_model_driver SCENARIO [TRACE] | --all [DIRECTORY]"
      return 2
