module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model
public import Lean.Data.Json
public import Mathlib.Data.String.Basic

public section

namespace CCFRaft.Replay

open Lean Model.Node
open CCF.MultiNodeTransitionSystem (nodeState removeOne)

abbrev Envelope := Model.Envelope

/-- Source evidence and the named rule which uses it. -/
structure Origin where
  file : String
  line : Nat
  rule : String
deriving Inhabited

def Origin.label (origin : Origin) : String :=
  s!"{origin.file}:{origin.line} [{origin.rule}]"

/-- Bootstrap and every driver-created node, including nodes with no events yet. -/
structure Header where
  bootstrap : Finset NodeID
  declared : List String
  requests : List String := [""]

def Header.nodeId (header : Header) (node : String) : Except String NodeID := do
  let some index := header.declared.findIdx? (· == node)
  | throw s!"undeclared node '{node}'"
  return index

def Header.initial (header : Header) : Model.State :=
  {
    nodes :=
      (List.range header.declared.length).map
        fun node =>
          (node, Model.initialNodeState header.bootstrap node)
  }

inductive Step where
  | local (node : String) (input : Input)
  | receive (source destination : String) (packet : Json)
  | drop (source destination : String)

def Step.name : Step → String
  | .local _ (.append _) => "append"
  | .local _ (.sendEntries ..) => "sendEntries"
  | .local _ (.timeout _) => "timeout"
  | .local _ .nominateSuccessor => "nominateSuccessor"
  | .receive .. => "receive"
  | .drop .. => "drop"

inductive PacketSelection where
  | latest
  | head

structure ReplayState where
  state : Model.State
  dropped : List Envelope := []

/-- Direct model actions and read-only checks; there is no replay wire schema. -/
inductive Instruction where
  | action (step : Step) (origin : Origin)
  | observe (check : ReplayState → Except String Unit) (origin : Origin)

def Instruction.origin : Instruction → Origin
  | .action _ origin
  | .observe _ origin => origin

/--
Dropped copies remain undelivered model envelopes, excluded with multiplicity.
-/
def ReplayState.live (replay : ReplayState) : List Envelope :=
  replay.dropped.foldl (fun network envelope => removeOne envelope network)
    replay.state.network

def ReplayState.pending (replay : ReplayState) (source destination : NodeID)
    : List Envelope :=
  replay.live.filter
    fun envelope => envelope.source == source && envelope.target == destination

private def roleName : Role → String
  | .none => "none"
  | .follower => "follower"
  | .preVoteCandidate => "preVoteCandidate"
  | .candidate => "candidate"
  | .primary => "leader"

private def membershipName : MembershipState → String
  | .noRetirementObserved => "active"
  | .retirementOrdered => "retirementOrdered"
  | .retirementSigned => "retirementSigned"
  | .retirementCompleted => "retirementCompleted"
  | .retiredCommitted => "retiredCommitted"

private def checkFields (expected actual : Json) : Except String Unit := do
  let observed := (← expected.getObj?).toList
  if observed.isEmpty then throw "observation must contain at least one field"
  for (key, expectedValue) in observed do
    let actualValue ←
      (actual.getObjVal? key).mapError fun _ => s!"unsupported observation field '{key}'"
    unless expectedValue == actualValue do
      throw s!"{key}: observed {expectedValue.compress}, model {actualValue.compress}"

private def lookup (header : Header) (replay : ReplayState) (node : String)
    : Except String NodeState := do
  let nodeId ← header.nodeId node
  let some state := nodeState replay.state nodeId
  | throw s!"node '{node}' is not in the network"
  return state

private def members (header : Header) (nodes : Finset NodeID) : Json :=
  toJson
    ((header.declared.zipIdx).filterMap
      fun (name, index) =>
        if index ∈ nodes then some name else none)

private def observeNodeState (header : Header) (node : String) (state : NodeState)
    (peer : Option String) (expected : Json)
    : Except String Unit := do
  let self ← header.nodeId node
  let retirement := state.retirement self
  let configurations :=
    (activeConfigurations state.log state.commitIndex).filterMap
      fun configuration =>
        if configuration.index == 0 then
          none
        else
          some
            (Json.mkObj
              [
                ("index", toJson configuration.index),
                ("nodes", members header configuration.nodes)
              ])
  let mut fields :=
    [
      ("role", toJson (roleName state.role)),
      ("currentTerm", toJson state.currentTerm),
      ("logLength", toJson state.log.length),
      ("commitIndex", toJson state.commitIndex),
      ("configurations", toJson configurations),
      ("membershipState", toJson (membershipName retirement.phase)),
      ("retirementIndex", toJson retirement.index),
      ("retirementCommittableIndex", toJson retirement.committableIndex),
      ("retiredCommittedIndex", toJson state.retiredCommittedIndex)
    ]
  if let some peer := peer then
    let peer ← header.nodeId peer
    fields :=
      fields
      ++ [
        ("sentIndex", toJson (state.sentIndex peer)),
        ("matchIndex", toJson (state.matchIndex peer))
      ]
  checkFields expected (Json.mkObj fields)

/-- Capture stable identities, not the bootstrap membership finalized after reduction. -/
def observeState (header : Header) (node : String) (peer : Option String)
    (expected : Json) (replay : ReplayState)
    : Except String Unit := do
  observeNodeState header node (← lookup header replay node) peer expected

/-- Read the final log at an independently checked old commit frontier. -/
def observeBeforeCommit (header : Header) (node : String) (frontier : Nat)
    (expected : Json) (replay : ReplayState)
    : Except String Unit := do
  let state ← lookup header replay node
  unless frontier < state.commitIndex do
    throw "pre-commit frontier must precede final commitIndex"
  let self ← header.nodeId node
  let confirmation :=
    firstLogIndexAfter (state.log.take frontier) 0
      fun content => decide (self ∈ content.metadata.retirementConfirmations)
  -- Commit does not change the log. This view is only observed, never executed.
  let view :=
    { state with commitIndex := frontier, retiredCommittedIndex := confirmation }
  observeNodeState header node view none expected

def observeEntry (header : Header) (node : String) (index : Nat)
    (expected : Json) (replay : ReplayState)
    : Except String Unit := do
  if index == 0 then throw "log entry index must be positive"
  let state ← lookup header replay node
  let some entry := entryAt? state.log index
  | throw s!"node '{node}' has no log entry at index {index}"
  let content ←
    match entry.content with
    | .transaction transaction metadata => do
        let some request := header.requests[transaction]?
        | throw s!"unknown model request identifier {transaction}"
        pure
          [
            ("kind", toJson "transaction"),
            ("transaction", toJson request),
            ("retiredCommitted", members header metadata.retirementConfirmations),
            (
              "configurations",
              toJson (metadata.configuration.toList.map (members header))
            )
          ]
    | .signature => pure [("kind", toJson "signature")]
  checkFields expected
    (Json.mkObj
      ([
          ("term", toJson entry.term),
          ("committed", toJson (decide (index <= state.commitIndex)))
        ]
        ++ content))

/-- Physical packet coordinates; lower-term NACK hints are not election terms. -/
def messageJson (message : Model.Node.Message) : Json :=
  let fields :=
    match message with
    | .appendEntriesRequest request =>
        [
          ("msg", toJson "raft_append_entries"),
          ("prev_idx", toJson request.prevLogIndex),
          ("prev_term", toJson request.prevLogTerm),
          ("idx", toJson (request.prevLogIndex + request.entries.length)),
          ("leader_commit_idx", toJson request.primaryCommit),
          (
            "term_of_idx",
            toJson (request.entries.getLast?.map Entry.term |>.getD request.prevLogTerm)
          ),
          ("contains_new_view", toJson false)
        ]
    | .appendEntriesResponse response =>
        [
          ("msg", toJson "raft_append_entries_response"),
          ("success", toJson (if response.success then "OK" else "FAIL")),
          ("last_log_idx", toJson response.lastLogIndex)
        ]
    | .requestVoteRequest request =>
        [
          ("msg", toJson "raft_request_vote"),
          ("last_committable_idx", toJson request.lastCommittableIndex),
          ("term_of_last_committable_idx", toJson request.lastCommittableTerm)
        ]
    | .requestPreVoteRequest request =>
        [
          ("msg", toJson "raft_request_pre_vote"),
          ("last_committable_idx", toJson request.lastCommittableIndex),
          ("term_of_last_committable_idx", toJson request.lastCommittableTerm)
        ]
    | .requestVoteResponse response =>
        [
          ("msg", toJson "raft_request_vote_response"),
          ("vote_granted", toJson response.voteGranted)
        ]
    | .requestPreVoteResponse response =>
        [
          ("msg", toJson "raft_request_pre_vote_response"),
          ("vote_granted", toJson response.voteGranted)
        ]
    | .proposeRequestVoteRequest _ => [("msg", toJson "raft_propose_request_vote")]
  Json.mkObj (("term", toJson message.term) :: fields)

private def selectPacket (state : ReplayState) (source destination : NodeID)
    (packet : Json) (selection : PacketSelection)
    : Except String Envelope := do
  let pending := state.pending source destination
  let some first := pending.head?
  | throw s!"no pending packet from '{source}' to '{destination}'"
  let envelope ←
    match selection with
    | .head => pure first
    | .latest => pure (pending.getLast?.getD first)
  checkFields packet (messageJson envelope.payload)
  return envelope

/-- Sends select the latest packet; explicit drops check the head before excluding it. -/
def observeMessage (header : Header) (source destination : String) (packet : Json)
    (selection : PacketSelection) (replay : ReplayState)
    : Except String Unit := do
  let source ← header.nodeId source
  let destination ← header.nodeId destination
  let _ ← selectPacket replay source destination packet selection
  pure ()

private def runStep (header : Header) (replay : ReplayState) (step : Step)
    : Except String ReplayState := do
  let system :=
    Model.transitionSystem header.bootstrap (List.range header.declared.length)
  match step with
  | .local node input =>
      let node ← header.nodeId node
      match input with
      | .sendEntries destination _ =>
          unless destination < header.declared.length do
            throw s!"undeclared model node {destination}"
      | .append entries =>
          for entry in entries do
            if let .transaction request _ := entry then
              unless request > 0 && request < header.requests.length do
                throw s!"undeclared or reserved model request {request}"
            let metadata := entry.metadata
            for member
                in metadata.configuration.getD ∅ ∪ metadata.retirementConfirmations
                    |>.sort do
              unless member < header.declared.length do
                throw s!"undeclared model node {member}"
      | _ => pure ()
      let some state := system.step replay.state (.local node input)
      | throw s!"disabled model action '{step.name}'"
      return { replay with state }
  | .receive source destination packet =>
      let source ← header.nodeId source
      let destination ← header.nodeId destination
      let envelope ← selectPacket replay source destination packet .head
      let some state := system.step replay.state (.deliver envelope)
      | throw "disabled model action 'receive'"
      return { replay with state }
  | .drop source destination =>
      let source ← header.nodeId source
      let destination ← header.nodeId destination
      let some envelope := (replay.pending source destination).head?
      | throw s!"no pending packet from '{source}' to '{destination}'"
      return { replay with dropped := replay.dropped ++ [envelope] }

/-- Observations never change model state or repair a disabled action. -/
def runInstruction (header : Header) (state : ReplayState) (instruction : Instruction)
    : Except String ReplayState := do
  match instruction with
  | .action step _ => runStep header state step
  | .observe check _ =>
      check state
      return state

structure Result where
  instructions : Nat
  actions : Nat
  observations : Nat
deriving Repr, BEq

def Result.json (result : Result) : Json :=
  Json.mkObj
    [
      ("status", toJson "ok"),
      ("instructions", toJson result.instructions),
      ("actions", toJson result.actions),
      ("observations", toJson result.observations)
    ]

def replay (header : Header) (instructions : Array Instruction)
    : Except String Result := do
  unless !header.declared.isEmpty
          && header.declared.all (!·.isEmpty)
          && header.declared.eraseDups == header.declared do
    throw "declared nodes must be nonempty and distinct"
  unless header.declared == header.declared.mergeSort do
    throw "declared nodes must be sorted lexically"
  unless header.bootstrap.Nonempty do
    throw "initial membership must be nonempty"
  for node in header.bootstrap.sort do
    unless node < header.declared.length do
      throw s!"undeclared model node {node}"
  unless header.requests.head? == some "" && (header.requests.drop 1).all (!·.isEmpty) do
    throw "request identifiers must reserve zero for genesis"
  unless header.requests.eraseDups == header.requests do
    throw "request identifiers must be distinct"
  if instructions.isEmpty then throw "replay instructions must not be empty"
  let mut state : ReplayState := { state := header.initial }
  let mut actions := 0
  for instruction in instructions, index in [:instructions.size] do
    state ←
      (runInstruction header state instruction).mapError
        fun error =>
          s!"instruction {index + 1} at {instruction.origin.label}: {error}"
    if let .action .. := instruction then actions := actions + 1
  return {
    instructions := instructions.size,
    actions,
    observations := instructions.size - actions
  }

end CCFRaft.Replay
