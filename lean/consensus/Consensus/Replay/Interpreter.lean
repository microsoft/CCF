module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Model
public import Lean.Data.Json

public section

namespace Consensus.Replay

open Lean Model.Node
open CCF (Finset)
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
  /-- Initialize from a node's committed prefix ending at `index` in term `view`. -/
  | initAsBackup (node : String) (index view : Nat)

def Step.name : Step → String
  | .local _ (.append _) => "append"
  | .local _ (.sendEntries ..) => "sendEntries"
  | .local _ (.timeout _) => "timeout"
  | .local _ .nominateSuccessor => "nominateSuccessor"
  | .local _ (.initAsBackup _) | .initAsBackup .. => "initAsBackup"
  | .receive .. => "receive"

structure ReplayState where
  state : Model.State
  /-- Envelopes queued by actions since the last send observation. -/
  queued : List Envelope := []

/-- A traced native send, or the proposal a nomination implies. -/
structure NativeSend where
  target : String
  packet : Json
  origin : Origin

/-- Direct model actions and boundary snapshots; there is no replay wire schema. -/
inductive Instruction where
  | action (step : Step) (origin : Origin)
  | observeNodeState (node : String) (expected : Json) (origin : Origin)
  /-- The envelopes queued since the last send observation must equal `sends`, as a multiset. -/
  | observeSends (sends : Array NativeSend) (origin : Origin)

def Instruction.origin : Instruction → Origin
  | .action _ origin
  | .observeNodeState _ _ origin
  | .observeSends _ origin => origin

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
          ("msg", toJson "append_entries"),
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
          ("msg", toJson "append_entries_response"),
          ("success", toJson (if response.success then "OK" else "FAIL")),
          ("last_log_idx", toJson response.lastLogIndex)
        ]
    | .requestVoteRequest request =>
        [
          ("msg", toJson "request_vote"),
          ("last_committable_idx", toJson request.lastCommittableIndex),
          ("term_of_last_committable_idx", toJson request.lastCommittableTerm)
        ]
    | .requestPreVoteRequest request =>
        [
          ("msg", toJson "request_pre_vote"),
          ("last_committable_idx", toJson request.lastCommittableIndex),
          ("term_of_last_committable_idx", toJson request.lastCommittableTerm)
        ]
    | .requestVoteResponse response =>
        [
          ("msg", toJson "request_vote_response"),
          ("vote_granted", toJson response.voteGranted)
        ]
    | .requestPreVoteResponse response =>
        [
          ("msg", toJson "request_pre_vote_response"),
          ("vote_granted", toJson response.voteGranted)
        ]
    | .proposeRequestVoteRequest _ => [("msg", toJson "propose_request_vote")]
  Json.mkObj (("term", toJson message.term) :: fields)

/-- A native packet matches when it has exactly the fields the model renders, with equal values. -/
private def checkPacket (packet : Json) (message : Model.Node.Message)
    : Except String Unit := do
  let actual := messageJson message
  checkFields (fun key => (actual.getObjVal? key).toOption.map checkValue) packet
  let missing :=
    (← actual.getObj?).toList.map Prod.fst
    |>.filter fun key => !(packet.getObjVal? key).isOk
  unless missing.isEmpty do
    throw s!"packet lacks fields {missing}"

/-- The first matching envelope, else the first with the same `msg`, to diagnose a mismatch. -/
private def closest (packet : Json) (envelopes : List Envelope) : Option Envelope :=
  envelopes.find? (fun envelope => (checkPacket packet envelope.payload).isOk)
  <|> envelopes.find?
        fun envelope =>
          ((messageJson envelope.payload).getObjVal? "msg").toOption
          == (packet.getObjVal? "msg").toOption

/-- Deliver any matching queued envelope; loss is non-delivery. -/
private def selectPacket (replay : ReplayState) (source destination : NodeID)
    (packet : Json)
    : Except String Envelope := do
  let pending :=
    replay.state.network.filter
      fun envelope => envelope.source == source && envelope.target == destination
  let some envelope := closest packet pending <|> pending.head?
  | throw s!"no pending packet from '{source}' to '{destination}'"
  checkPacket packet envelope.payload
  unless pending.all
          fun other =>
            !(checkPacket packet other.payload).isOk
            || other.payload == envelope.payload do
    throw
      s!"ambiguous delivery from '{source}' to '{destination}': matching packets differ in model payload"
  return envelope

/-- Run one model action, recording the envelopes it queues. -/
private def ReplayState.run (replay : ReplayState) (header : Header)
    (action : Model.Action) (name : String)
    : Except String ReplayState := do
  let some state := Model.networkStep header.bootstrap replay.state action
  | throw s!"disabled model action '{name}'"
  -- A step appends the acting node's sends to the network left after any delivery.
  let pending := replay.state.network.length - if action matches .deliver _ then 1 else 0
  return { state, queued := replay.queued ++ state.network.drop pending }

/-- Observations never change model state or repair a disabled action. -/
def runInstruction (header : Header) (replay : ReplayState) (instruction : Instruction)
    : Except String ReplayState := do
  match instruction with
  | .observeNodeState node expected _ =>
      observeState header node expected replay
      return replay
  | .observeSends sends _ =>
      let mut queued := replay.queued
      for send in sends do
        let context := s!"{send.origin.label}: send to '{send.target}'"
        let target ← (header.nodeId send.target).mapError (s!"{context}: " ++ ·)
        let some envelope := closest send.packet (queued.filter (·.target == target))
        | throw s!"{context}: not queued by the model: {send.packet.compress}"
        (checkPacket send.packet envelope.payload).mapError (s!"{context}: " ++ ·)
        queued := removeOne envelope queued
      if let some envelope := queued.head? then
        let target := header.declared[envelope.target]?.getD (toString envelope.target)
        throw
          s!"model queued {(messageJson envelope.payload).compress} to '{target}' with no native send"
      return { replay with queued := [] }
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
      replay.run header (.local node input) step.name
  | .action (.receive source destination packet) _ =>
      let source ← header.nodeId source
      let destination ← header.nodeId destination
      let envelope ← selectPacket replay source destination packet
      replay.run header (.deliver envelope) "receive"
  | .action (step@(.initAsBackup node index view)) _ =>
      let joiner ← header.nodeId node
      -- Committed prefixes in a reachable state are comparable, so any such node will do.
      let some (_, source) :=
        replay.state.nodes.find?
          fun (_, state) =>
            index <= state.commitIndex
            && (index == 0 || isSignatureAt state.log index)
            && termAt state.log index == view
      | throw s!"no node has a committed signature at {index} in term {view}"
      replay.run header (.local joiner (.initAsBackup (source.log.take index))) step.name

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

end Consensus.Replay
