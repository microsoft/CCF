module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model
public import Lean.Data.Json

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
      header.declared.mapIdx
        fun node _ =>
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
def ReplayState.pending (replay : ReplayState) (source destination : NodeID)
    : List Envelope :=
  (replay.dropped.foldl (fun network envelope => removeOne envelope network)
    replay.state.network).filter
    fun envelope => envelope.source == source && envelope.target == destination

/-- Object keys and array indices are distinct observation path components. -/
inductive JsonPathPart where
  | field (key : String)
  | index (position : Nat)
deriving BEq, Repr

abbrev JsonPath := List JsonPathPart

def JsonPath.label (path : JsonPath) : String :=
  "$"
  ++ String.join
      (path.map
        fun
        | .field key => s!"[{(toJson key).compress}]"
        | .index position => s!"[{position}]")

private def checkValue {α : Type} [ToJson α] (actual : α) (expected : Json)
    : Except String Unit := do
  let actual := toJson actual
  unless expected == actual do
    throw s!"observed {expected.compress}, model {actual.compress}"

/-- A registered checker owns its whole value; otherwise descend and reject unknown paths. -/
partial def checkJsonPaths (resolve : JsonPath → Option (Json → Except String Unit))
    (expected : Json)
    : Except String Unit := do
  if (← expected.getObj?).isEmpty then
    throw "observation must contain at least one field"
  visit [] expected
where
  visit (path : JsonPath) (value : Json) : Except String Unit := do
    if let some check := resolve path then
      (check value).mapError (fun error => s!"{path.label}: {error}")
    else
      let unsupported := s!"unsupported observation field '{path.label}'"
      match value with
      | .obj fields =>
          if fields.isEmpty then throw unsupported
          for (key, child) in fields.toList do
            visit (path ++ [.field key]) child
      | .arr values =>
          if values.isEmpty then throw unsupported
          for child in values, position in [:values.size] do
            visit (path ++ [.index position]) child
      | _ => throw unsupported

private def checkFields (expected actual : Json) : Except String Unit :=
  checkJsonPaths
    (fun
      | [.field key] => (actual.getObjVal? key).toOption.map checkValue
      | _ => none)
    expected

private def lookup (header : Header) (replay : ReplayState) (node : String)
    : Except String NodeState := do
  let nodeId ← header.nodeId node
  let some state := nodeState replay.state nodeId
  | throw s!"node '{node}' is not in the network"
  return state

private def members (header : Header) (nodes : Finset NodeID) : List String :=
  (header.declared.zipIdx).filterMap
    fun (name, index) =>
      if index ∈ nodes then some name else none

private def observeNodeState (header : Header) (node : String) (state : NodeState)
    (peer : Option String) (expected : Json)
    : Except String Unit := do
  let self ← header.nodeId node
  let peer ← peer.mapM header.nodeId
  checkJsonPaths
    (fun
      | [.field "leadership_state"] =>
          some
            (checkValue
              (match state.role with
                | .none => "None"
                | .follower => "Follower"
                | .preVoteCandidate => "PreVoteCandidate"
                | .candidate => "Candidate"
                | .primary => "Leader"))
      | [.field "current_view"] => some (checkValue state.currentTerm)
      | [.field "last_idx"] => some (checkValue state.log.length)
      | [.field "commit_idx"] => some (checkValue state.commitIndex)
      | [.field "committable_indices"] =>
          some
            (checkValue
              ((state.log.zipIdx 1).filterMap
                fun (entry, index) =>
                  if index > state.commitIndex && entry.content.isSignature then
                    some index
                  else
                    none))
      | [.field "configurations"] =>
          some
            fun value => do
              let observed ←
                (← value.getArr?).toList.mapM
                  fun configuration => do
                    let index ← configuration.getObjValAs? Nat "idx"
                    let nodes ← configuration.getObjVal? "nodes" >>= Json.getObj?
                    return (index, (nodes.toList.map Prod.fst).mergeSort)
              let actual :=
                (activeConfigurations state.log state.commitIndex).filterMap
                  fun configuration =>
                    if configuration.index == 0 then
                      none
                    else
                      some (configuration.index, members header configuration.nodes)
              checkValue actual (toJson observed)
      | [.field "membership_state"] =>
          some
            (checkValue
              (if (state.retirement self).phase == .noRetirementObserved then
                  "Active"
                else
                  "Retired"))
      | [.field "retirement_phase"] =>
          some
            (checkValue
              (match (state.retirement self).phase with
                | .noRetirementObserved => none
                | .retirementOrdered => some "Ordered"
                | .retirementSigned => some "Signed"
                | .retirementCompleted => some "Completed"
                | .retiredCommitted => some "RetiredCommitted"))
      | [.field "retirement_idx"] => some (checkValue (state.retirement self).index)
      | [.field "retirement_committable_idx"] =>
          some (checkValue (state.retirement self).committableIndex)
      | [.field "retired_committed_idx"] => some (checkValue state.retiredCommittedIndex)
      | [.field "sent_idx"] => peer.map fun peer => checkValue (state.sentIndex peer)
      | [.field "match_idx"] => peer.map fun peer => checkValue (state.matchIndex peer)
      | _ => none)
    expected

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
            (
              "retiredCommitted",
              toJson (members header metadata.retirementConfirmations)
            ),
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
  let some envelope :=
    match selection with
    | .head => pending.head?
    | .latest => pending.getLast?
  | throw s!"no pending packet from '{source}' to '{destination}'"
  checkFields packet (messageJson envelope.payload)
  return envelope

/-- Sends select the latest packet; explicit drops check the head before excluding it. -/
def observeMessage (header : Header) (source destination : String) (packet : Json)
    (selection : PacketSelection) (replay : ReplayState)
    : Except String Unit := do
  let source ← header.nodeId source
  let destination ← header.nodeId destination
  discard (selectPacket replay source destination packet selection)

/-- Observations never change model state or repair a disabled action. -/
def runInstruction (header : Header) (replay : ReplayState) (instruction : Instruction)
    : Except String ReplayState := do
  let system :=
    Model.transitionSystem header.bootstrap (List.range header.declared.length)
  match instruction with
  | .observe check _ =>
      check replay
      return replay
  | .action (step@(.local node input)) _ =>
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
  | .action (.receive source destination packet) _ =>
      let source ← header.nodeId source
      let destination ← header.nodeId destination
      let envelope ← selectPacket replay source destination packet .head
      let some state := system.step replay.state (.deliver envelope)
      | throw "disabled model action 'receive'"
      return { replay with state }
  | .action (.drop source destination) _ =>
      let source ← header.nodeId source
      let destination ← header.nodeId destination
      let some envelope := (replay.pending source destination).head?
      | throw s!"no pending packet from '{source}' to '{destination}'"
      return { replay with dropped := replay.dropped ++ [envelope] }

structure Result where
  instructions : Nat
  actions : Nat
  observations : Nat
deriving Repr, BEq

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
