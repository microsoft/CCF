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

/-- Bootstrap and nodes identified by native events or configurations. -/
structure Header where
  bootstrap : Finset NodeID
  declared : List String

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

structure ReplayState where
  state : Model.State
  dropped : List Envelope := []

/-- Direct model actions and boundary snapshots; there is no replay wire schema. -/
inductive Instruction where
  | action (step : Step) (origin : Origin)
  | observeNodeState (node : String) (expected : Json) (origin : Origin)

def Instruction.origin : Instruction → Origin
  | .action _ origin
  | .observeNodeState _ _ origin => origin

/--
Dropped copies remain undelivered model envelopes, excluded with multiplicity.
-/
def ReplayState.pending (replay : ReplayState) (source destination : NodeID)
    : List Envelope :=
  (replay.dropped.foldl (fun network envelope => removeOne envelope network)
    replay.state.network).filter
    fun envelope => envelope.source == source && envelope.target == destination

private def checkValue {α : Type} [ToJson α] (actual : α) (expected : Json)
    : Except String Unit := do
  let actual := toJson actual
  unless expected == actual do
    throw s!"observed {expected.compress}, model {actual.compress}"

private def checkFields (resolve : String → Option (Json → Except String Unit))
    (expected : Json)
    : Except String Unit := do
  let fields ← expected.getObj?
  if fields.isEmpty then
    throw "observation must contain at least one field"
  for (key, value) in fields.toList do
    let path := s!"$[{(toJson key).compress}]"
    let some check := resolve key
    | throw s!"unsupported observation field '{path}'"
    (check value).mapError (fun error => s!"{path}: {error}")

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

/-- Compare an action-boundary snapshot with the current model node. -/
def observeState (header : Header) (node : String) (expected : Json)
    (replay : ReplayState)
    : Except String Unit := do
  let state ← lookup header replay node
  let self ← header.nodeId node
  checkFields
    (fun
      | "node_id" => some (checkValue node)
      | "leadership_state" =>
          some
            (checkValue
              (match state.role with
                | .none => "None"
                | .follower => "Follower"
                | .preVoteCandidate => "PreVoteCandidate"
                | .candidate => "Candidate"
                | .primary => "Leader"))
      | "current_view" => some (checkValue state.currentTerm)
      | "last_idx" => some (checkValue state.log.length)
      | "commit_idx" => some (checkValue state.commitIndex)
      | "committable_indices" =>
          let indices :=
            (state.log.zipIdx 1).filterMap
              fun (entry, index) =>
                if index > state.commitIndex && entry.content.isSignature then
                  some index
                else
                  none
          -- Native telemetry records only the first and last cache entries.
          some
            (checkValue
              (match indices with
                | [] => []
                | first :: rest => first :: rest.getLast?.toList))
      | "configurations" =>
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
      | "membership_state" =>
          some
            (checkValue
              (if (state.retirement self).phase == .noRetirementObserved then
                  "Active"
                else
                  "Retired"))
      | "retirement_phase" =>
          some
            (checkValue
              (match (state.retirement self).phase with
                | .noRetirementObserved => none
                | .retirementOrdered => some "Ordered"
                | .retirementSigned => some "Signed"
                | .retirementCompleted => some "Completed"
                | .retiredCommitted => some "RetiredCommitted"))
      | "retirement_idx" => some (checkValue (state.retirement self).index)
      | "retirement_committable_idx" =>
          some (checkValue (state.retirement self).committableIndex)
      | "retired_committed_idx" => some (checkValue state.retiredCommittedIndex)
      | _ => none)
    expected

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
    (packet : Json)
    : Except String Envelope := do
  let some envelope := (state.pending source destination).head?
  | throw s!"no pending packet from '{source}' to '{destination}'"
  let actual := messageJson envelope.payload
  checkFields (fun key => (actual.getObjVal? key).toOption.map checkValue) packet
  return envelope

/-- Observations never change model state or repair a disabled action. -/
def runInstruction (header : Header) (replay : ReplayState) (instruction : Instruction)
    : Except String ReplayState := do
  let system :=
    Model.transitionSystem header.bootstrap (List.range header.declared.length)
  match instruction with
  | .observeNodeState node expected _ =>
      observeState header node expected replay
      return replay
  | .action (step@(.local node input)) _ =>
      let node ← header.nodeId node
      match input with
      | .sendEntries destination _ =>
          unless destination < header.declared.length do
            throw s!"undeclared model node {destination}"
      | .append entries =>
          for entry in entries do
            let metadata := entry.content.metadata
            for member
                in metadata.configuration.getD ∅ ∪ metadata.retirementConfirmations
                    |>.sort do
              unless member < header.declared.length do
                throw s!"undeclared model node {member}"
            for (destination, _) in entry.flushes do
              unless destination < header.declared.length do
                throw s!"undeclared model node {destination}"
      | _ => pure ()
      let some state := system.step replay.state (.local node input)
      | throw s!"disabled model action '{step.name}'"
      return { replay with state }
  | .action (.receive source destination packet) _ =>
      let source ← header.nodeId source
      let destination ← header.nodeId destination
      let envelope ← selectPacket replay source destination packet
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
