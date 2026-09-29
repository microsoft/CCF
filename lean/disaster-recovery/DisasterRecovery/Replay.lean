import DisasterRecovery.Model
import Lean.Data.Json

set_option autoImplicit false

/-!
Replays reduced recovery-decision-protocol executions through
`Model.transitionSystem`. Every expected location is in the network from the
start, and the participants are its active nodes. Actions must be enabled, and
observations compare selected fields of a node's state, or the messages and
notifications of the node's latest action, with the model.
-/

namespace DisasterRecovery.Replay

open Lean Model.Local
open Shared (Capabilities Outputs)
open Shared.MultiNodeTransitionSystem (nodeState)

/-- `Config.isValid` requires an instance identifier, which traces do not carry. -/
def instanceId : String :=
  "recovery-trace"

/-- The recovered TxID of a location that sent no gossip, which no step reads. -/
def unusedTxID : TxID :=
  { view := 0, seqno := 0 }

abbrev LocalOutputs :=
  Outputs Location Message Notification

/-- The log record, and the reduction rule, that an instruction comes from. -/
structure Origin where
  file : String
  line : Nat
  rule : String

/-- Fields of a node's state that a record shows. Absent fields are not compared. -/
structure StateFields where
  phase : Option Phase := none
  timeoutState : Option Phase := none
  gossips : Option (List (Location × TxID)) := none
  votes : Option (List Location) := none
  chosen : Option Location := none
  openKind : Option OpenKind := none
  restartRequested : Option Bool := none

inductive Instruction where
  /-- A model action, which must be enabled. -/
  | action (action : Model.Action) (origins : List Origin)
  /-- Fields of a node's state. -/
  | state (node : Location) (fields : StateFields) (origins : List Origin)
  /-- The messages and notifications of the latest action, which ran on `node`. -/
  | outputs (node : Location) (sent : List (Location × Message))
    (notifications : List Notification) (origins : List Origin)

def Instruction.origins : Instruction → List Origin
  | .action _ origins
  | .state _ _ origins
  | .outputs _ _ _ origins => origins

structure Header where
  config : Model.Config
  participants : List Location

/-- The expected locations, the participants, and the TxIDs they gossiped. -/
def Header.make (expected participants : List Location)
    (recovered : List (Location × TxID))
    : Header :=
  {
    config :=
      {
        protocol := { instanceId, expectedLocations := expected }
        recovered :=
          expected.map fun node => (node, (recovered.lookup node).getD unusedTxID)
      }
    participants
  }

/-- Every expected location in its initial state. Only participants act. -/
def Header.initial (header : Header) : Model.State :=
  {
    nodes :=
      header.config.protocol.expectedLocations.map fun node => (node, initialNode node)
    active := header.participants
  }

def phaseName : Phase → String
  | .gossiping => "gossiping"
  | .voting => "voting"
  | .opening => "opening"
  | .joining => "joining"
  | .open => "open"

def openKindName : OpenKind → String
  | .quorum => "quorum"
  | .failover => "failover"

private def txidJson (value : TxID) : Json :=
  Json.mkObj [("view", toJson value.view), ("seqno", toJson value.seqno)]

private def messageJson : Message → Json
  | .gossip value => Json.mkObj [("kind", toJson "gossip"), ("txid", txidJson value)]
  | .vote => Json.mkObj [("kind", toJson "vote")]
  | .iAmOpen => Json.mkObj [("kind", toJson "iAmOpen")]

private def notificationJson : Notification → Json
  | .opening kind =>
      Json.mkObj [("kind", toJson "opening"), ("openKind", toJson (openKindName kind))]
  | .restart chosen => Json.mkObj [("kind", toJson "restart"), ("chosen", toJson chosen)]
  | .completed => Json.mkObj [("kind", toJson "completed")]
  | .rejected reason =>
      Json.mkObj [("kind", toJson "rejected"), ("reason", toJson reason)]

private def gossipsJson (gossips : List (Location × TxID)) : Json :=
  Json.mkObj (gossips.map fun (location, value) => (location, txidJson value))

private def sentJson (sent : List (Location × Message)) : Json :=
  toJson
    (sent.map
      fun (destination, message) =>
        Json.mkObj
          [("destination", toJson destination), ("message", messageJson message)])

private def optionJson {α : Type} (render : α → Json) : Option α → Json
  | some value => render value
  | none => Json.null

/-- The node an action runs on, and the local event it runs. -/
private def localEvent (config : Model.Config) : Model.Action → Location × Event
  | .local node input => (node, (Model.protocol config).internal input)
  | .deliver envelope =>
      (envelope.target, (Model.protocol config).receive envelope.source envelope.payload)

private def actionName : Model.Action → String
  | .local _ .retry => "retry"
  | .local _ .timeout => "timeout"
  | .deliver _ => "receive"

/--
Runs one action. The network state does not keep notifications, so, as the
properties do, re-run the node's local step to recover its outputs.
-/
private def runAction (config : Model.Config) (state : Model.State)
    (action : Model.Action)
    : Except String (Model.State × Location × LocalOutputs) := do
  let some next := (Model.transitionSystem config).step state action
  | throw s!"disabled model action '{actionName action}'"
  let (node, event) := localEvent config action
  let some before := nodeState state node
  | throw s!"node '{node}' is not in the network"
  let some execute :=
    (Model.protocol config).step (Capabilities.record node) node before event
  | throw s!"disabled model action '{actionName action}'"
  return (next, node, (Id.run (execute.run {})).2)

private def check {α : Type} [BEq α] (key : String) (render : α → Json)
    (observed : Option α) (model : α)
    : Except String Unit :=
  match observed with
  | some value =>
      if value == model then
        pure ()
      else
        throw
          s!"{key}: observed {(render value).compress}, model {(render model).compress}"
  | none => pure ()

private def checkState (fields : StateFields) (state : NodeState)
    : Except String Unit := do
  check "phase" (toJson ∘ phaseName) fields.phase state.phase
  check "timeoutState" (toJson ∘ phaseName) fields.timeoutState state.timeoutState
  check "gossips" gossipsJson fields.gossips
    (state.gossips.mergeSort fun left right => left.1 <= right.1)
  check "votes" toJson fields.votes (state.votes.mergeSort (· <= ·))
  check "chosen" (optionJson toJson) (fields.chosen.map some) state.chosen
  check "openKind" (optionJson (toJson ∘ openKindName)) (fields.openKind.map some)
    state.openKind
  check "restartRequested" toJson fields.restartRequested state.restartRequested

structure ReplayState where
  state : Model.State
  /-- The node and outputs of the latest action. -/
  latest : Option (Location × LocalOutputs) := none

private def execute (config : Model.Config) (current : ReplayState)
    : Instruction → Except String ReplayState
  | .action action _ => do
      let (state, node, outputs) ← runAction config current.state action
      return { state, latest := some (node, outputs) }
  | .state node fields _ => do
      let some state := nodeState current.state node
      | throw s!"node '{node}' is not in the network"
      checkState fields state
      return current
  | .outputs node sent notifications _ => do
      let some (latest, outputs) := current.latest
      | throw "no action precedes this outputs observation"
      unless latest == node do
        throw s!"the latest action ran on '{latest}', not '{node}'"
      check "sent" sentJson (some sent)
        (outputs.outgoing.map fun envelope => (envelope.target, envelope.payload))
      check "notifications" (fun values => toJson (values.map notificationJson))
        (some notifications) outputs.notifications
      return current

private def label (origins : List Origin) : String :=
  ", ".intercalate
    (origins.map fun origin => s!"{origin.file}:{origin.line} [{origin.rule}]")

structure Result where
  actions : Nat
  observations : Nat

/-- Replays the instructions in order. Observations never update protocol state. -/
def replay (header : Header) (instructions : Array Instruction)
    : Except String Result := do
  unless header.config.protocol.isValid do
    throw "expected locations must be nonempty, without empty names"
  let mut current : ReplayState := { state := header.initial }
  let mut actions := 0
  for instruction in instructions, index in [:instructions.size] do
    current ←
      (execute header.config current instruction).mapError
        fun error => s!"instruction {index + 1} at {label instruction.origins}: {error}"
    if let .action .. := instruction then
      actions := actions + 1
  return { actions, observations := instructions.size - actions }

end DisasterRecovery.Replay
