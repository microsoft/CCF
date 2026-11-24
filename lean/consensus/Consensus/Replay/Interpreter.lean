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
  | observeSends (sends : List NativeSend) (origin : Origin)

def Instruction.origin : Instruction → Origin
  | .action _ origin
  | .observeNodeState _ _ origin
  | .observeSends _ origin => origin

/--
A head event and its follow-on events on the same node: one hold of the node's consensus
lock.
-/
structure Group where
  /-- The node whose lock hold this is. -/
  node : String
  /-- Index of the head event among its node's events. -/
  start : Nat
  /-- `m_ts` of the head event: where the group starts in its process's order. -/
  m_ts : Nat
  /-- `ts` of the head event, when the trace records it. -/
  ts : Option Nat
  /-- What the group's rule emitted, run with no other group's actions in between. -/
  instructions : Array Instruction

/-- Where the group starts, with its rule. -/
def Group.label (group : Group) : String :=
  (group.instructions[0]?.map (·.origin.label)).getD ""

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

private def pendingBetween (replay : ReplayState) (source destination : NodeID)
    : List Envelope :=
  replay.state.network.filter
    fun envelope => envelope.source == source && envelope.target == destination

/-- Why no queued envelope renders `packet`, diffing the closest in rendered order. -/
private def missing (header : Header) (pending : List Envelope)
    (source destination : NodeID) (packet : Json)
    : String :=
  let name (node : NodeID) := header.declared[node]?.getD (toString node)
  let sorted :=
    (pending.map fun envelope => ((messageJson envelope.payload).compress, envelope))
    |>.mergeSort fun a b => a.1 ≤ b.1
  let pending := sorted.map Prod.snd
  match closest packet pending <|> pending.head? with
  | none => s!"no pending packet from '{name source}' to '{name destination}'"
  | some envelope =>
      let queued := s!"queued from '{name source}': {sorted.map Prod.fst}"
      match checkPacket packet envelope.payload with
      | .error error => s!"{error}; {queued}"
      | .ok _ => queued

/-- Deliver any matching queued envelope; loss is non-delivery. -/
private def selectPacket (replay : ReplayState) (source destination : NodeID)
    (packet : Json)
    : Except String Envelope := do
  let pending := pendingBetween replay source destination
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

/-- A node whose committed prefix has a signature at `index` in term `view`. -/
private def initSource (replay : ReplayState) (index view : Nat)
    : Except String NodeState := do
  -- Committed prefixes in a reachable state are comparable, so any such node will do.
  let some (_, source) :=
    replay.state.nodes.find?
      fun (_, state) =>
        index <= state.commitIndex
        && (index == 0 || isSignatureAt state.log index)
        && termAt state.log index == view
  | throw s!"no node has a committed signature at {index} in term {view}"
  return source

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
      let source ← initSource replay index view
      replay.run header (.local joiner (.initAsBackup (source.log.take index))) step.name

/--
Why a step must wait: a receive has no matching queued packet, or an initialization has no
committed source. Both only become enabled as other nodes act. Other steps are local to a
node changed only by its own groups, so a disabled one fails when its group runs.
The reason is built only on demand: a waiting group is retried after every other group.
-/
private def Step.waiting (header : Header) (replay : ReplayState)
    : Step → Except String (Option (Unit → String))
  | .receive source destination packet => do
      let source ← header.nodeId source
      let destination ← header.nodeId destination
      let pending := pendingBetween replay source destination
      if pending.any fun envelope => (checkPacket packet envelope.payload).isOk then
        return none
      return some fun _ => missing header pending source destination packet
  | .initAsBackup _ index view =>
      match initSource replay index view with
      | .ok _ => return none
      | .error reason => return some fun _ => reason
  | .local .. => pure none

/-- Why a group must wait before its first action, located at that action. -/
private def Group.waiting (header : Header) (replay : ReplayState) (group : Group)
    : Except String (Option (Unit → String)) := do
  let some (.action step origin) := group.instructions.find? (· matches .action ..)
  | return none
  let located := (s!"{origin.label}: " ++ ·)
  return (located ∘ ·) <$> (← (step.waiting header replay).mapError located)

/-- Run a group's instructions with no other group's actions between them. -/
private def runGroup (header : Header) (replay : ReplayState) (group : Group)
    : Except String ReplayState :=
  group.instructions.foldlM
    (fun replay instruction =>
      (runInstruction header replay instruction).mapError
        (s!"{instruction.origin.label}: " ++ ·))
    replay

structure Result where
  /-- Groups run of each node, fewer than it has only if replay is lenient. -/
  ran : Array Nat
  actions : Nat
  observations : Nat
deriving Repr, BEq

/-- Where a group natively sends `packet` to `destination`. -/
private def Group.send? (group : Group) (destination : String) (packet : Json)
    : Option Origin :=
  group.instructions.findSome?
    fun
    | .observeSends sends _ =>
        (sends.find? fun send => send.target == destination && send.packet == packet).map
          (·.origin)
    | _ => none

/--
Explain a replay in which every node's next group waits. A receive whose sender does not
send its packet in the rest of the trace can never run; the other groups wait for another
node.
-/
private def stuck (rest : Array Group) (blocked : Array (Group × (Unit → String)))
    : String :=
  let (never, waits) :=
    blocked.toList.partitionMap
      fun (group, reason) =>
        let waiting := s!"node '{group.node}' waits at {reason ()}"
        match group.instructions.find? (· matches .action ..) with
        | some (.action (.receive source destination packet) _) =>
            let sender := rest.filter (·.node == source)
            match sender.findSome? (·.send? destination packet) with
            | none => .inl s!"{waiting}; '{source}' sends no such packet later"
            | some origin =>
                .inr s!"{waiting}; '{source}' sends it later at {origin.label}"
        | _ => .inr waiting
  let list (title : String) (lines : List String) :=
    if lines.isEmpty then "" else s!"\n{title}:\n  {"\n  ".intercalate lines}"
  "no enabled group"
  ++ list "can never run" never
  ++ list "waiting for another node" waits

/--
Run each node's groups in order, recording the groups run, ending with any that failed.
The enabled group with the earliest wall-clock time runs, then by node; without wall-clock
times `m_ts` stands in, which is the order of execution within a process and otherwise only
makes diagnostics reproducible, as counters of different processes are not comparable.
A group's node changes only through its own groups, other nodes only add packets it may
receive, and a committed prefix stays committed, so the verdict does not depend on which
enabled group runs.
If `lenient`, replay ends without failing once no group may run.
-/
def schedule (header : Header) (queues : Array (Array Group)) (lenient := false)
    : ExceptT String (StateM (Array Group)) Result := do
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
  let total := queues.foldl (· + ·.size) 0
  if total == 0 then throw "replay groups must not be empty"
  let key (group : Group) := group.ts.getD group.m_ts
  let mut state : ReplayState := { state := header.initial }
  let mut next := Array.replicate queues.size 0
  for _ in [:total] do
    let heads :=
      (queues.zipIdx.filterMap
        fun (groups, queue) => (·, queue) <$> groups[next[queue]!]?)
      |>.qsort fun (a, i) (b, j) => key a < key b || (key a == key b && i < j)
    let mut chosen := none
    let mut blocked := #[]
    for (group, queue) in heads do
      match ← ofExcept (group.waiting header state) with
      | none =>
          chosen := some (group, queue)
          break
      | some reason => blocked := blocked.push (group, reason)
    let some (group, queue) := chosen
    |
      if lenient then
        break
      let rest := queues.zipIdx.flatMap fun (groups, queue) => groups.extract next[queue]!
      throw (stuck rest blocked)
    modify (·.push group)
    state ← ofExcept (runGroup header state group)
    next := next.modify queue (· + 1)
  let instructions :=
    queues.zipIdx.flatMap
      fun (groups, queue) => (groups.extract 0 next[queue]!).flatMap (·.instructions)
  let actions := (instructions.filter (· matches .action ..)).size
  return { ran := next, actions, observations := instructions.size - actions }

end Consensus.Replay
