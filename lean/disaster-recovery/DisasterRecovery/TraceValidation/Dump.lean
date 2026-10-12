import DisasterRecovery.TraceValidation.Reduction

set_option autoImplicit false

/-!
Writes a replay as JSON for the trace viewer in `replayer/viewer`, which only
lays it out. Every fact the viewer shows is computed here, by the replayer and
the model: the model state after each instruction, the actions that each state
enables, the queued copy that each delivery removed and the send that queued it,
and the result of each check, with the observed and model values when one fails.
-/

namespace DisasterRecovery.TraceValidation.Dump

open Lean Model.Local
open Shared (Capabilities)
open Shared.MultiNodeTransitionSystem (nodeState removeOne)

instance : ToJson TxID where
  toJson txid := .str s!"{txid.view}.{txid.seqno}"

deriving instance ToJson for Phase, OpenKind, NodeState, Origin

/-- A message in the records' terms: its `message`, and the `txid` of a gossip. -/
private def messageJson : Message → Json
  | .gossip txid => json% {message: "gossip", txid: $txid}
  | .vote => json% {message: "vote"}
  | .iAmOpen => json% {message: "iamopen"}

instance : ToJson Model.Envelope where
  toJson e :=
    (json% {source: $(e.source), target: $(e.target)}).mergeObj (messageJson e.payload)

instance : ToJson Notification where
  toJson
    | .opening kind => json% {kind: "opening", openKind: $kind}
    | .restart chosen => json% {kind: "restart", chosen: $chosen}
    | .completed => json% {kind: "completed"}
    | .rejected reason => json% {kind: "rejected", reason: $reason}

instance : ToJson Model.Action where
  toJson
    | .local node .retry => json% {kind: "retry", node: $node}
    | .local node .timeout => json% {kind: "timeout", node: $node}
    | .deliver envelope => (json% {kind: "deliver"}).mergeObj (toJson envelope)

private def sentJson (sent : List (Location × Message)) : Json :=
  toJson
    (sent.map
      fun (target, message) => (json% {target: $target}).mergeObj (messageJson message))

private def outputsJson (node : Location) (outputs : LocalOutputs) : Json :=
  let sent := outputs.outgoing.map fun envelope => (envelope.target, envelope.payload)
  json% {node: $node, sent: $(sentJson sent), notifications: $(outputs.notifications)}

/--
One field that a state observation shows: its `NodeState` name, its observed
value, an observation of that field alone, and the model's value of it.
-/
private structure Field where
  key : String
  observed : Json
  alone : StateFields
  model : NodeState → Json

private def field {α : Type} [ToJson α] (key : String) (value : Option α)
    (alone : α → StateFields) (model : NodeState → Json)
    : Option Field :=
  value.map fun value => { key, observed := toJson value, alone := alone value, model }

private def splitFields (fields : StateFields) : List Field :=
  List.reduceOption
    [
      field "phase" fields.phase ({ phase := some · }) (toJson ·.phase),
      field "timeoutState" fields.timeoutState ({ timeoutState := some · })
        (toJson ·.timeoutState),
      field "chosen" fields.chosen ({ chosen := some · }) (toJson ·.chosen),
      field "openKind" fields.openKind ({ openKind := some · }) (toJson ·.openKind),
      field "restartRequested" fields.restartRequested ({ restartRequested := some · })
        (toJson ·.restartRequested)
    ]

/-- The node an action runs on. -/
private def actionNode : Model.Action → Location
  | .local node _ => node
  | .deliver envelope => envelope.target

private def describe : Instruction → Json
  | .action action origins =>
      json% {kind: "action", node: $(actionNode action), action: $action, origins: $origins}
  | .state node fields origins =>
      let shown :=
        Json.mkObj ((splitFields fields).map fun field => (field.key, field.observed))
      json% {kind: "state", node: $node, fields: $shown, origins: $origins}
  | .outputs node sent notifications origins =>
      json% {
        kind: "outputs", node: $node, sent: $(sentJson sent), notifications: $notifications,
        origins: $origins
      }

/--
A copy of a message in the model's network, the instruction of the action that
sent it, its position among that action's sends, and the send record that the
outputs observation after that action matched it with.
-/
structure Copy where
  envelope : Model.Envelope
  sentBy : Nat
  position : Nat
  record : Option Origin := none

/-- The network tells copies apart only by their envelopes. -/
instance : BEq Copy where
  beq left right := left.envelope == right.envelope

/-- A model state, the actions it enables, and who sent each queued copy, in network order. -/
private def stateJson (config : Model.Config) (state : Model.State) (copies : List Copy)
    : Json :=
  let enabled (action : Model.Action) : Bool :=
    ((Model.transitionSystem config).step state action).isSome
  let groups : Array (Model.Envelope × Array Nat) :=
    copies.foldl (init := #[])
      fun groups copy =>
        match groups.findIdx? (·.1 == copy.envelope) with
        | some index =>
            groups.modify index
              fun (envelope, senders) => (envelope, senders.push copy.sentBy)
        | none => groups.push (copy.envelope, #[copy.sentBy])
  let nodes :=
    state.nodes.map
      fun (node, value) =>
        json% {
          node: $node, state: $value, retry: $(enabled (.local node .retry)),
          timeout: $(enabled (.local node .timeout))
        }
  let network :=
    groups.map
      fun (envelope, senders) =>
        json% {
          envelope: $envelope, count: $(senders.size),
          deliverable: $(enabled (.deliver envelope)), sentBy: $senders
        }
  json% {nodes: $nodes, active: $(state.active), network: $network}

/-- Which of the model network's guards a disabled action fails. -/
private def guards (config : Model.Config) (state : Model.State) (action : Model.Action)
    : Json :=
  let node := actionNode action
  let (event, queued) :=
    match action with
    | .local _ input => ((Model.protocol config).internal input, none)
    | .deliver envelope =>
        (
          (Model.protocol config).receive envelope.source envelope.payload,
          some (state.network.contains envelope)
        )
  let before := nodeState state node
  let localStep :=
    before.bind
      fun before =>
        (Model.protocol config).step (Capabilities.record node) node before event
  let holding :=
    json% {
      active: $(state.active.contains node), known: $(before.isSome),
      localStep: $(localStep.isSome)
    }
  match queued with
  | some queued => holding.mergeObj (json% {queued: $queued})
  | none => holding

private def check (key : String) (observed model : Json)
    (result : Except String ReplayState)
    : Json :=
  let error : Option String :=
    match result with
    | .ok _ => none
    | .error error => some error
  json% {key: $key, observed: $observed, model: $model, error: $error}

/--
What a failed instruction compared, each observed field or list checked alone
by the replayer, or the guards of a disabled action.
-/
private def diagnose (config : Model.Config) (current : ReplayState) : Instruction → Json
  | .state node fields origins =>
      let model := nodeState current.state node
      let checks :=
        (splitFields fields).map
          fun field =>
            check field.key field.observed ((model.map field.model).getD .null)
              (runInstruction config current (.state node field.alone origins))
      json% {checks: $checks, model: $model}
  | .outputs node sent notifications origins =>
      match current.latest with
      | none => Json.mkObj []
      | some (latest, outputs) =>
          let modelSent :=
            outputs.outgoing.map fun envelope => (envelope.target, envelope.payload)
          -- Each list is checked with the model's value for the other one.
          let checks :=
            [
              check "sent" (sentJson sent) (sentJson modelSent)
                (runInstruction config current
                  (.outputs node sent outputs.notifications origins)),
              check "notifications" (toJson notifications) (toJson outputs.notifications)
                (runInstruction config current
                  (.outputs node modelSent notifications origins))
            ]
          json% {checks: $checks, model: $(outputsJson latest outputs)}
  | .action action _ => json% {guards: $(guards config current.state action)}

/--
Replays the instructions as `replay` does, and returns each model state, from
the initial one, and each instruction with what it did. The copies beside the
model's network show which send each delivery takes: a delivery removes the copy
that the model's `removeOne` removes, and the copies must match the network
after every action.
-/
private def walk (header : Header) (instructions : Array Instruction)
    : Except String (Array Json × Array Json) := do
  let config := header.config
  let mut current : ReplayState := { state := header.initial }
  let mut copies : List Copy := []
  let mut latest : Option Nat := none
  let mut states := #[stateJson config current.state copies]
  let mut steps := #[]
  let mut failed := !config.protocol.isValid
  for instruction in instructions, index in [:instructions.size] do
    let described := describe instruction
    if failed then
      steps := steps.push (described.mergeObj (json% {status: "skipped"}))
      continue
    match runInstruction config current instruction with
    | .error error =>
        failed := true
        let failure := json% {status: "failed", error: $error, state: $(states.size - 1)}
        steps :=
          steps.push
            ((described.mergeObj failure).mergeObj (diagnose config current instruction))
    | .ok next =>
        let mut did := json% {status: "ok"}
        match instruction with
        | .action action _ =>
            let (consumed, kept) :=
              match action with
              | .deliver envelope =>
                  (
                    copies.find? fun (copy : Copy) => copy.envelope == envelope,
                    removeOne ({ envelope, sentBy := 0, position := 0 } : Copy) copies
                  )
              | .local .. => (none, copies)
            let (node, outputs) := next.latest.getD (actionNode action, {})
            copies :=
              kept
              ++ outputs.outgoing.zipIdx.map
                  fun (envelope, position) =>
                    ({ envelope, sentBy := index, position } : Copy)
            unless copies.map Copy.envelope == next.state.network do
              throw
                s!"instruction {index + 1}: the copies differ from the model's network"
            states := states.push (stateJson config next.state copies)
            latest := some index
            let took :=
              consumed.map
                fun (copy : Copy) =>
                  json% {sentBy: $(copy.sentBy), position: $(copy.position), record: $(copy.record)}
            did :=
              did.mergeObj (json% {outputs: $(outputsJson node outputs), consumed: $took})
        | .outputs _ sent _ origins =>
            -- The observation matched the latest action's sends to these records, in order.
            if origins.length == sent.length then
              copies :=
                copies.map
                  fun copy =>
                    if latest == some copy.sentBy then
                      { copy with record := origins[copy.position]? }
                    else
                      copy
        | .state .. => pure ()
        current := next
        steps :=
          steps.push
            ((described.mergeObj did).mergeObj (json% {state: $(states.size - 1)}))
  return (states, steps)

private def outcome (stage message : String) (result : Option Result) : Json :=
  let ended := json% {stage: $stage, ok: $(stage == "done"), message: $message}
  match result with
  | some result =>
      ended.mergeObj
        (json% {actions: $(result.actions), observations: $(result.observations)})
  | none => ended

/-- A run's scenario, logs and records, and what the reduction and replay made of them. -/
def dump (scenario : Scenario) (logs : List System.FilePath) (records : Array Record)
    (reduced : Except String Reduced)
    : Except String Json := do
  let records :=
    records.map
      fun record =>
        json% {file: $(record.file), line: $(record.line), value: $(record.value)}
  let common :=
    json% {
      format: 1,
      scenario: {participants: $(scenario.participants)},
      logs: $(logs.map (·.toString)),
      records: $records
    }
  match reduced with
  | .error message =>
      return common.mergeObj (json% {outcome: $(outcome "reduce" message none)})
  | .ok reduced =>
      let header := reduced.header
      let (states, steps) ← walk header reduced.instructions
      let result :=
        match replay header reduced.instructions with
        | .error message => outcome "replay" message none
        | .ok result =>
            match reduced.scenario with
            | some failure => outcome "scenario" failure (some result)
            | none => outcome "done" "" (some result)
      let expected := header.config.protocol.expectedLocations
      return common.mergeObj
        (json% {
            header: {
              expectedLocations: $expected, participants: $(header.participants),
              recovered: $(header.config.recovered)
            },
            states: $states,
            instructions: $steps,
            outcome: $result
          })

/--
Writes the dump of a run to `path`. It reads the logs again after the reduction,
so a log that is still growing may show records that the reduction did not see.
-/
def write (path : System.FilePath) (scenario : Scenario) (logs : List System.FilePath)
    (reduced : Except String Reduced)
    : IO Unit := do
  let records :=
    match ← readLogs logs with
    | .ok records => records
    | .error _ => #[]
  match dump scenario logs records reduced with
  | .ok json => IO.FS.writeFile path json.compress
  | .error message => throw (IO.userError s!"cannot dump the replay: {message}")

end DisasterRecovery.TraceValidation.Dump
