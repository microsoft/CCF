-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Protocol.Model
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Replay

open Lean Protocol.Model

abbrev ReplayState := State String String

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

private def optionalField (value : Json) (key : String) : Except String (Option Json) := do
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
  bootstrap : Bootstrap String
  declared : List String

private def parseHeader (value : Json) : Except String Header := do
  keys value ["configuration", "leader", "pre_vote_enabled"]
  let configuredNodes ← nodeList (← field value "configuration")
  let configuration := configuredNodes.toFinset
  let leader ← stringField value "leader"
  let modes ← objectFields (← field value "pre_vote_enabled")
  let modes ← modes.mapM fun (node, enabled) => do
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
      bootstrap := {
        configuration
        leader
        leader_mem := member
        preVoteStatus := fun node =>
          if modes.lookup node == some true then .enabled else .capable
      }
    }
  else
    throw s!"bootstrap leader '{leader}' is not in the configuration"

private def nodeField (header : Header) (value : Json) (key : String) :
    Except String String := do
  let node ← stringField value key
  unless node ∈ header.declared do
    throw s!"{key}: undeclared node '{node}'"
  return node

private def parseAction (header : Header) (value : Json) :
    Except String (Action String String) := do
  let name ← stringField value "action"
  let base := ["kind", "action", "origin"]
  match name with
  | "clientRequest" =>
      keys value (base ++ ["node", "transaction"])
      return .clientRequest (← nodeField header value "node")
        (← stringField value "transaction")
  | "changeConfiguration" =>
      keys value (base ++ ["source", "configuration"])
      let nodes ← nodeList (← field value "configuration")
      for node in nodes do
        unless node ∈ header.declared do
          throw s!"configuration: undeclared node '{node}'"
      return .changeConfiguration (← nodeField header value "source") nodes.toFinset
  | "appendEntries" =>
      keys value (base ++ ["source", "destination", "batchEnd"])
      return .appendEntries (← nodeField header value "source")
        (← nodeField header value "destination") (← natField value "batchEnd")
  | "drop" =>
      keys value (base ++ ["source", "destination", "occurrence"])
      return .drop (← nodeField header value "source")
        (← nodeField header value "destination") (← occurrence value)
  | "receive" | "updateTerm" | "requestVote" | "requestPreVote" | "proposeVote"
      | "advanceCommitIndexAndProposeVote" =>
      keys value (base ++ ["source", "destination"])
      let source ← nodeField header value "source"
      let destination ← nodeField header value "destination"
      match name with
      | "receive" => return .receive source destination
      | "updateTerm" => return .updateTerm source destination
      | "requestVote" => return .requestVote source destination
      | "requestPreVote" => return .requestPreVote source destination
      | "proposeVote" => return .proposeVote source destination
      | _ => return .advanceCommitIndexAndProposeVote source destination
  | "initializeConfiguration" | "appendRetiredCommitted" | "signCommittableMessages" | "advanceCommitIndex"
      | "timeout" | "becomePreVoteCandidate" | "becomeCandidate" | "checkQuorum"
      | "becomeLeader" =>
      keys value (base ++ ["node"])
      let node ← nodeField header value "node"
      match name with
      | "initializeConfiguration" => return .initializeConfiguration node
      | "appendRetiredCommitted" => return .appendRetiredCommitted node
      | "signCommittableMessages" => return .signCommittableMessages node
      | "advanceCommitIndex" => return .advanceCommitIndex node
      | "timeout" => return .timeout node
      | "becomePreVoteCandidate" => return .becomePreVoteCandidate node
      | "becomeCandidate" => return .becomeCandidate node
      | "checkQuorum" => return .checkQuorum node
      | _ => return .becomeLeader node
  | _ => throw s!"unsupported action '{name}'"

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
    let actualValue ← (field actual key).mapError fun _ =>
      s!"unsupported observation field '{key}'"
    unless expectedValue == actualValue do
      throw s!"{key}: observed {expectedValue.compress}, canonical {actualValue.compress}"

private def observeState (header : Header) (state : ReplayState) (value : Json) :
    Except String Unit := do
  keys value ["kind", "observation", "origin", "node", "peer", "fields"]
  let node ← nodeField header value "node"
  let _ : Bootstrap String := header.bootstrap
  let nodeState := state.nodes node
  let committableIndices := (List.range' 1 nodeState.log.length).filter fun index =>
    index > nodeState.commitIndex && isSignatureAt nodeState.log index
  let configurations := (activeConfigurations nodeState).filterMap fun configuration =>
    if configuration.index == 0 then none else some (Json.mkObj [
      ("index", toJson configuration.index),
      ("nodes", toJson (header.declared.filter fun member => member ∈ configuration.nodes))])
  let mut fields := [
    ("role", toJson (roleName nodeState.role)),
    ("currentTerm", toJson nodeState.currentTerm),
    ("logLength", toJson nodeState.log.length),
    ("commitIndex", toJson nodeState.commitIndex),
    ("committableIndices", toJson committableIndices),
    ("configurations", toJson configurations),
    ("allocated", toJson (decide (state.allocated node))),
    ("membershipState", toJson (membershipName nodeState.membershipState)),
    ("retirementIndex", toJson nodeState.retirementIndex),
    ("retirementCommittableIndex", toJson nodeState.retirementCommittableIndex),
    ("retiredCommittedIndex", toJson nodeState.retiredCommittedIndex),
    ("preVoteEnabled", toJson (decide (state.preVoteStatus node = .enabled)))]
  if (← optionalField value "peer").isSome then
    let peer ← nodeField header value "peer"
    fields := fields ++ [
      ("sentIndex", toJson (nodeState.sentIndex peer)),
      ("matchIndex", toJson (nodeState.matchIndex peer))]
  checkFields (← field value "fields") (Json.mkObj fields)

private def observeEntry (header : Header) (state : ReplayState) (value : Json) :
    Except String Unit := do
  keys value ["kind", "observation", "origin", "node", "index", "fields"]
  let node ← nodeField header value "node"
  let index ← natField value "index"
  if index == 0 then throw "log entry index must be positive"
  let nodeState := state.nodes node
  let some entry := entryAt? nodeState.log index
    | throw s!"node '{node}' has no log entry at index {index}"
  let contentFields := match entry.content with
    | .transaction transaction =>
        [("kind", toJson "transaction"), ("transaction", toJson transaction)]
    | .signature => [("kind", toJson "signature")]
    | .reconfiguration configuration =>
        [("kind", toJson "configuration"),
         ("configuration", toJson (header.declared.filter fun member => member ∈ configuration))]
    | .retiredCommitted nodes =>
        [("kind", toJson "retiredCommitted"),
         ("nodes", toJson (header.declared.filter fun member => member ∈ nodes))]
  let fields := [
    ("term", toJson entry.term),
    ("committed", toJson (decide (index <= nodeState.commitIndex)))] ++ contentFields
  checkFields (← field value "fields") (Json.mkObj fields)

/-- Only modeled packet fields, plus the fixed unused compatibility bit.
`contains_new_view` is initialized false in raft_types.h and never set. -/
def messageJson (message : Message String String) : Json :=
  let fields := match message with
    | .appendEntriesRequest request =>
        [("msg", toJson "raft_append_entries"),
         ("prev_idx", toJson request.prevLogIndex),
         ("prev_term", toJson request.prevLogTerm),
         ("idx", toJson (request.prevLogIndex + request.entries.length)),
         ("leader_commit_idx", toJson request.leaderCommit),
         ("term_of_idx", toJson
           (request.entries.getLast?.map Entry.term |>.getD request.prevLogTerm)),
         ("contains_new_view", toJson false)]
    | .appendEntriesResponse response =>
        [("msg", toJson "raft_append_entries_response"),
         ("success", toJson (if response.success then "OK" else "FAIL")),
         ("last_log_idx", toJson response.lastLogIndex)]
    | .requestVoteRequest request =>
        [("msg", toJson "raft_request_vote"),
         ("last_committable_idx", toJson request.lastCommittableIndex),
         ("term_of_last_committable_idx", toJson request.lastCommittableTerm)]
    | .requestPreVote request =>
        [("msg", toJson "raft_request_pre_vote"),
         ("last_committable_idx", toJson request.lastCommittableIndex),
         ("term_of_last_committable_idx", toJson request.lastCommittableTerm)]
    | .requestVoteResponse response =>
        [("msg", toJson "raft_request_vote_response"),
         ("vote_granted", toJson response.voteGranted)]
    | .requestPreVoteResponse response =>
        [("msg", toJson "raft_request_pre_vote_response"),
         ("vote_granted", toJson response.voteGranted)]
    | .proposeVoteRequest _ =>
        [("msg", toJson "raft_propose_request_vote")]
  Json.mkObj (("term", toJson message.term) :: fields)

private def observeMessage (header : Header) (state : ReplayState) (value : Json) :
    Except String Unit := do
  keys value ["kind", "observation", "origin", "source", "destination", "packet", "occurrence", "selection"]
  let source ← nodeField header value "source"
  let destination ← nodeField header value "destination"
  let index ← match ← optionalField value "selection" with
    | none => occurrence value
    | some selection => do
        if (← optionalField value "occurrence").isSome then
          throw "message observation cannot specify both selection and occurrence"
        match ← text selection with
        | "first" => pure 0
        | "last" => pure ((state.network destination).filter
            (fun message => message.source == source)).length.pred
        | name => throw s!"unsupported message selection '{name}'"
  let some (message, _) := takeOccurrenceFrom source index (state.network destination)
    | throw s!"no pending packet from '{source}' to '{destination}' at occurrence {index}"
  unless message.destination == destination do
    throw "pending packet has an inconsistent destination"
  let packet ← field value "packet"
  let _ ← stringField packet "msg"
  checkFields packet (messageJson message)

private def originLabel (value : Json) : Except String String := do
  let origins ← (← field value "origin").getArr?
  if origins.isEmpty then throw "origin must not be empty"
  let labels ← origins.toList.mapM fun origin => do
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
    throw "ccfraft-replay/v1 is unsupported: v2 requires physical ledger indices"
  unless schema == "ccfraft-replay/v2" do
    throw s!"unsupported replay schema '{schema}'"
  let header ← (parseHeader (← field document "bootstrap")).mapError
    fun error => s!"bootstrap: {error}"
  let instructions ← (← field document "instructions").getArr?
  if instructions.isEmpty then
    throw "replay instructions must not be empty"
  let _ : Bootstrap String := header.bootstrap
  let mut state : ReplayState := initialState
  let mut actions := 0
  let mut observations := 0
  for index in [:instructions.size] do
    let instruction := instructions[index]!
    let label ← (originLabel instruction).mapError
      fun error => s!"instruction {index + 1}: invalid origin: {error}"
    let step : Except String (ReplayState × Bool) := do
      match ← stringField instruction "kind" with
      | "action" =>
          let action ← parseAction header instruction
          match system.applyAction state action with
          | some nextState => return (nextState, true)
          | none => throw s!"disabled canonical action '{← stringField instruction "action"}'"
      | "observation" =>
          match ← stringField instruction "observation" with
          | "state" => observeState header state instruction
          | "message" => observeMessage header state instruction
          | "entry" => observeEntry header state instruction
          | name => throw s!"unsupported observation '{name}'"
          return (state, false)
      | kind => throw s!"unsupported instruction kind '{kind}'"
    let (nextState, isAction) ← step.mapError
      fun error => s!"instruction {index + 1} at {label}: {error}"
    state := nextState
    if isAction then actions := actions + 1 else observations := observations + 1
  return { instructions := instructions.size, actions, observations }

end CCFRaft.Replay
