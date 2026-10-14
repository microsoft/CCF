-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model
import CCFRaft.Model.ClusterConfig
import CCFRaft.Model.Node
import CCFRaft.Model.Messages
import CCFRaft.Model.NodeState
import Lean.Data.Json
import Mathlib.Data.String.Basic

/-!
Replays reduced `raft_driver` executions through `Model.transitionSystem`.
Every declared node is in the network from the start. A `receive` delivers the
oldest pending envelope from its source to its destination, which is the order
`raft_driver` delivers in. A `drop` does not step the model: the envelope stays
in the network and the replay never delivers it.
-/

namespace CCFRaft.Replay

open Lean Model.Node
open Shared (Envelope)
open Shared.MultiNodeTransitionSystem (nodeState removeOne)

abbrev Envelope := Model.Envelope String String

structure ReplayState where
  state : Model.State String String
  dropped : List Envelope := []

/-- Pending envelopes the recorded run has not dropped, oldest first. Equal
envelopes are interchangeable, so removing any equal copy suffices. -/
def ReplayState.live (replay : ReplayState) : List Envelope :=
  replay.dropped.foldl (fun network envelope => removeOne envelope network)
    replay.state.network

def ReplayState.pending (replay : ReplayState) (source destination : String)
    : List Envelope :=
  replay.live.filter
    fun envelope => envelope.source == source && envelope.target == destination

private def objectFields (value : Json) : Except String (List (String × Json)) := do
  return (← value.getObj?).toList

private def keys (value : Json) (allowed : List String) : Except String Unit := do
  for (key, _) in ← objectFields value do
    unless key ∈ allowed do
      throw s!"unsupported field '{key}'"

private def field (value : Json) (key : String) : Except String Json :=
  (value.getObjVal? key).mapError fun error => s!"{key}: {error}"

private def text (value : Json) : Except String String := do
  let result ← value.getStr?
  if result.isEmpty then throw "expected a nonempty string"
  return result

private def stringField (value : Json) (key : String) : Except String String := do
  text (← field value key)

private def natField (value : Json) (key : String) : Except String Nat := do
  (← field value key).getNat?

private def optionalField (value : Json) (key : String)
    : Except String (Option Json) := do
  return (← objectFields value).lookup key

private def occurrence (value : Json) : Except String Nat := do
  match ← optionalField value "occurrence" with
  | none => return 0
  | some index => index.getNat?

private def nodeList (value : Json) : Except String (List String) := do
  let nodes ← (← value.getArr?).toList.mapM text
  if nodes.isEmpty then throw "configuration must not be empty"
  unless nodes.toFinset.card == nodes.length do
    throw "configuration contains duplicate node identifiers"
  return nodes

structure Header where
  bootstrap : InitialConfig String
  declared : List String

def Header.initial (header : Header) : Model.State String String :=
  {
    nodes :=
      header.declared.map fun node => (node, initialNodeState header.bootstrap node)
    active := header.declared
  }

private def parseHeader (value : Json) : Except String Header := do
  keys value ["configuration", "leader", "pre_vote_enabled"]
  let configuredNodes ← nodeList (← field value "configuration")
  let configuration := configuredNodes.toFinset
  let leader ← stringField value "leader"
  let modes ← objectFields (← field value "pre_vote_enabled")
  let modes ←
    modes.mapM
      fun (node, enabled) => do
        let node ← text (.str node)
        let enabled ← enabled.getBool?
        return (node, enabled)
  let declared := modes.map Prod.fst
  for node in configuredNodes do
    unless node ∈ declared do
      throw s!"bootstrap node '{node}' has no pre_vote_enabled declaration"
  if member : leader ∈ configuration then
    return {
      declared
      bootstrap :=
        {
          configuration
          leader
          leader_mem := member
          preVoteStatus :=
            fun node =>
              if modes.lookup node == some true then .enabled else .capable
        }
    }
  else
    throw s!"bootstrap leader '{leader}' is not in the configuration"

private def nodeField (header : Header) (value : Json) (key : String)
    : Except String String := do
  let node ← stringField value key
  unless node ∈ header.declared do
    throw s!"{key}: undeclared node '{node}'"
  return node

inductive Step where
  | local (node : String) (input : Input String String)
  | receive (source destination : String)
  | drop (source destination : String) (occurrence : Nat)

private def declaredNodes (header : Header) (value : Json) (key : String)
    : Except String (Finset String) := do
  let nodes ← nodeList (← field value key)
  for node in nodes do
    unless node ∈ header.declared do
      throw s!"{key}: undeclared node '{node}'"
  return nodes.toFinset

private def parseEffect (header : Header) (value : Json)
    : Except String (TransactionEffect String) := do
  match ← stringField value "kind" with
  | "configuration" =>
      keys value ["kind", "configuration"]
      return .reconfiguration (← declaredNodes header value "configuration")
  | "retiredCommitted" =>
      keys value ["kind", "nodes"]
      return .retiredCommitted (← declaredNodes header value "nodes")
  | kind => throw s!"unsupported transaction effect '{kind}'"

private def parseEntry (header : Header) (value : Json)
    : Except String (EntryContent String String) := do
  match ← stringField value "kind" with
  | "transaction" =>
      keys value ["kind", "transaction", "effects"]
      let effects ← (← field value "effects").getArr?
      return .transaction (← stringField value "transaction")
        (← effects.toList.mapM (parseEffect header))
  | "signature" =>
      keys value ["kind"]
      return .signature
  | kind => throw s!"unsupported entry kind '{kind}'"

private def parseAction (header : Header) (value : Json) : Except String Step := do
  let name ← stringField value "action"
  let base := ["kind", "action", "origin"]
  match name with
  | "append" =>
      keys value (base ++ ["node", "entries"])
      let entries ← (← field value "entries").getArr?
      if entries.isEmpty then throw "entries must not be empty"
      return .local (← nodeField header value "node")
        (.append (← entries.toList.mapM (parseEntry header)))
  | "sendEntries" =>
      keys value (base ++ ["source", "destination", "endIndex"])
      return .local (← nodeField header value "source")
        (.sendEntries (← nodeField header value "destination")
          (← natField value "endIndex"))
  | "drop" =>
      keys value (base ++ ["source", "destination", "occurrence"])
      return .drop (← nodeField header value "source")
        (← nodeField header value "destination") (← occurrence value)
  | "receive" =>
      keys value (base ++ ["source", "destination"])
      return .receive (← nodeField header value "source")
        (← nodeField header value "destination")
  | "timeout" =>
      keys value (base ++ ["node", "timeout"])
      let node ← nodeField header value "node"
      match ← stringField value "timeout" with
      | "election" => return .local node (.timeout .election)
      | "checkQuorum" => return .local node (.timeout .checkQuorum)
      | kind => throw s!"unsupported timeout '{kind}'"
  | "nominateSuccessor" =>
      keys value (base ++ ["node"])
      return .local (← nodeField header value "node") .nominateSuccessor
  | _ => throw s!"unsupported action '{name}'"

/-- Receive consumes the oldest live envelope; drop only excludes it from replay. -/
private def runStep (header : Header) (replay : ReplayState) (step : Step) (name : String)
    : Except String ReplayState := do
  let system := Model.transitionSystem (TxId := String) header.bootstrap header.declared
  match step with
  | .local node input =>
      match system.step replay.state (.local node input) with
      | some state => return { replay with state }
      | none => throw s!"disabled canonical action '{name}'"
  | .receive source destination =>
      let some envelope := (replay.pending source destination).head?
      | throw
          s!"disabled canonical action '{name}': no pending packet from '{source}' to '{destination}'"
      match system.step replay.state (.deliver envelope) with
      | some state => return { replay with state }
      | none => throw s!"disabled canonical action '{name}'"
  | .drop source destination index =>
      let some envelope := (replay.pending source destination)[index]?
      | throw
          s!"no pending packet from '{source}' to '{destination}' at occurrence {index}"
      return { replay with dropped := replay.dropped ++ [envelope] }

private def roleName : Role → String
  | .none => "none"
  | .follower => "follower"
  | .preVoteCandidate => "preVoteCandidate"
  | .candidate => "candidate"
  | .leader => "leader"

private def membershipName : MembershipState → String
  | .active => "active"
  | .retirementOrdered => "retirementOrdered"
  | .retirementSigned => "retirementSigned"
  | .retirementCompleted => "retirementCompleted"
  | .retiredCommitted => "retiredCommitted"

private def checkFields (expected actual : Json) : Except String Unit := do
  let observed ← objectFields expected
  if observed.isEmpty then throw "observation must contain at least one field"
  for (key, expectedValue) in observed do
    let actualValue ←
      (field actual key).mapError
        fun _ =>
          s!"unsupported observation field '{key}'"
    unless expectedValue == actualValue do
      throw s!"{key}: observed {expectedValue.compress}, canonical {actualValue.compress}"

private def lookup (replay : ReplayState) (node : String)
    : Except String (NodeState String String) :=
  match nodeState replay.state node with
  | some state => pure state
  | none => throw s!"node '{node}' is not in the network"

private def observeState (header : Header) (replay : ReplayState) (value : Json)
    : Except String Unit := do
  keys value ["kind", "observation", "origin", "node", "peer", "fields"]
  let node ← nodeField header value "node"
  let nodeState ← lookup replay node
  let retirement := nodeState.retirement header.bootstrap node
  let committableIndices :=
    (List.range' 1 nodeState.log.length).filter
      fun index =>
        index > nodeState.commitIndex && isSignatureAt nodeState.log index
  let configurations :=
    (activeConfigurations header.bootstrap nodeState.log nodeState.commitIndex).filterMap
      fun configuration =>
        if configuration.index == 0 then
          none
        else
          some
            (Json.mkObj
              [
                ("index", toJson configuration.index),
                (
                  "nodes",
                  toJson
                    (header.declared.filter fun member => member ∈ configuration.nodes)
                )
              ])
  let mut fields :=
    [
      ("role", toJson (roleName nodeState.role)),
      ("currentTerm", toJson nodeState.currentTerm),
      ("logLength", toJson nodeState.log.length),
      ("commitIndex", toJson nodeState.commitIndex),
      ("committableIndices", toJson committableIndices),
      ("configurations", toJson configurations),
      ("membershipState", toJson (membershipName retirement.phase)),
      ("retirementIndex", toJson retirement.index),
      ("retirementCommittableIndex", toJson retirement.committableIndex),
      ("retiredCommittedIndex", toJson nodeState.retiredCommittedIndex),
      ("preVoteEnabled", toJson (decide (header.bootstrap.preVoteStatus node = .enabled)))
    ]
  if (← optionalField value "peer").isSome then
    let peer ← nodeField header value "peer"
    fields :=
      fields
      ++ [
        ("sentIndex", toJson (nodeState.sentIndex peer)),
        ("matchIndex", toJson (nodeState.matchIndex peer))
      ]
  checkFields (← field value "fields") (Json.mkObj fields)

private def observeEntry (header : Header) (replay : ReplayState) (value : Json)
    : Except String Unit := do
  keys value ["kind", "observation", "origin", "node", "index", "fields"]
  let node ← nodeField header value "node"
  let index ← natField value "index"
  if index == 0 then throw "log entry index must be positive"
  let nodeState ← lookup replay node
  let some entry := entryAt? nodeState.log index
  | throw s!"node '{node}' has no log entry at index {index}"
  let members (nodes : Finset String) :=
    toJson (header.declared.filter fun member => member ∈ nodes)
  let contentFields :=
    match entry.content with
    | .transaction transaction effects =>
        [
          ("kind", toJson "transaction"),
          ("transaction", toJson transaction),
          (
            "effects",
            Json.arr
              (effects.map
                fun effect =>
                  match effect with
                  | .reconfiguration configuration =>
                      Json.mkObj
                        [
                          ("kind", toJson "configuration"),
                          ("configuration", members configuration)
                        ]
                  | .retiredCommitted nodes =>
                      Json.mkObj
                        [
                          ("kind", toJson "retiredCommitted"),
                          ("nodes", members nodes)
                        ]).toArray
          ),
          (
            "configurations",
            Json.arr ((entryConfigurations entry.content).map members).toArray
          )
        ]
    | .signature => [("kind", toJson "signature")]
  let fields :=
    [
      ("term", toJson entry.term),
      ("committed", toJson (decide (index <= nodeState.commitIndex)))
    ]
    ++ contentFields
  checkFields (← field value "fields") (Json.mkObj fields)

/-- `contains_new_view` is initialized false in raft_types.h and never set. -/
def messageJson (message : Message String String) : Json :=
  let fields :=
    match message with
    | .appendEntriesRequest request =>
        [
          ("msg", toJson "raft_append_entries"),
          ("prev_idx", toJson request.prevLogIndex),
          ("prev_term", toJson request.prevLogTerm),
          ("idx", toJson (request.prevLogIndex + request.entries.length)),
          ("leader_commit_idx", toJson request.leaderCommit),
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
    | .requestPreVote request =>
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
    | .proposeVoteRequest _ =>
        [("msg", toJson "raft_propose_request_vote")]
  Json.mkObj (("term", toJson message.term) :: fields)

private def observeMessage (header : Header) (replay : ReplayState) (value : Json)
    : Except String Unit := do
  keys value
    [
      "kind",
      "observation",
      "origin",
      "source",
      "destination",
      "packet",
      "occurrence",
      "selection"
    ]
  let source ← nodeField header value "source"
  let destination ← nodeField header value "destination"
  let pending := replay.pending source destination
  let index ←
    match ← optionalField value "selection" with
    | none => occurrence value
    | some selection => do
        if (← optionalField value "occurrence").isSome then
          throw "message observation cannot specify both selection and occurrence"
        match ← text selection with
        | "first" => pure 0
        | "last" => pure pending.length.pred
        | name => throw s!"unsupported message selection '{name}'"
  let some envelope := pending[index]?
  | throw s!"no pending packet from '{source}' to '{destination}' at occurrence {index}"
  let message := envelope.payload
  let packet ← field value "packet"
  let _ ← stringField packet "msg"
  checkFields packet (messageJson message)

private def originLabel (value : Json) : Except String String := do
  let origins ← (← field value "origin").getArr?
  if origins.isEmpty then throw "origin must not be empty"
  let labels ←
    origins.toList.mapM
      fun origin => do
        let file ← stringField origin "file"
        let line ← natField origin "line"
        if line == 0 then throw "origin line must be positive"
        let rule ← stringField origin "rule"
        return s!"{file}:{line} [{rule}]"
  return String.intercalate ", " labels

structure Result where
  instructions : Nat
  actions : Nat
  observations : Nat
deriving Repr

/-- Replay in input order. Later malformed instructions cannot hide an earlier
guard failure or discrepancy. Observations never update protocol state. -/
def replay (document : Json) : Except String Result := do
  keys document ["schema", "bootstrap", "instructions"]
  let schema ← stringField document "schema"
  if schema == "ccfraft-replay/v1" then
    throw "ccfraft-replay/v1 is unsupported: v4 requires physical ledger indices"
  if schema == "ccfraft-replay/v2" then
    throw
      "ccfraft-replay/v2 is unsupported: v4 receives adopt newer terms without updateTerm"
  if schema == "ccfraft-replay/v3" then
    throw "ccfraft-replay/v3 is unsupported: v4 requires deterministic successor ranking"
  unless schema == "ccfraft-replay/v4" do
    throw s!"unsupported replay schema '{schema}'"
  let header ←
    (parseHeader (← field document "bootstrap")).mapError
      fun error => s!"bootstrap: {error}"
  let instructions ← (← field document "instructions").getArr?
  if instructions.isEmpty then
    throw "replay instructions must not be empty"
  let mut state : ReplayState := { state := header.initial }
  let mut actions := 0
  let mut observations := 0
  for index in [:instructions.size] do
    let instruction := instructions[index]!
    let label ←
      (originLabel instruction).mapError
        fun error => s!"instruction {index + 1}: invalid origin: {error}"
    let step : Except String (ReplayState × Bool) := do
      match ← stringField instruction "kind" with
      | "action" =>
          let step ← parseAction header instruction
          return (← runStep header state step (← stringField instruction "action"), true)
      | "observation" =>
          match ← stringField instruction "observation" with
          | "state" => observeState header state instruction
          | "message" => observeMessage header state instruction
          | "entry" => observeEntry header state instruction
          | name => throw s!"unsupported observation '{name}'"
          return (state, false)
      | kind => throw s!"unsupported instruction kind '{kind}'"
    let (nextState, isAction) ←
      step.mapError fun error => s!"instruction {index + 1} at {label}: {error}"
    state := nextState
    if isAction then actions := actions + 1 else observations := observations + 1
  return { instructions := instructions.size, actions, observations }

end CCFRaft.Replay
