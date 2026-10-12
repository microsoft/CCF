import DisasterRecovery.Proofs.ExecutionLocal

/-! Proof-only execution with send snapshots and terminal-effect histories. -/

namespace DisasterRecovery.Proofs.Execution.Global

open Shared (TransitionSystem)
open Local

/-- The model configuration used unchanged by the instrumented execution. -/
abbrev Config := Model.Config

/-- The model's well-formedness condition on configuration and recovered IDs. -/
abbrev Config.Valid (config : Config) := Model.Config.Valid config

/-- The recovered transaction ID that a location advertises in its gossips. -/
def recoveredTxID (config : Config) (source : Location) : Option TxID :=
  (config.recovered.find? fun entry => entry.1 == source).map Prod.snd

/-- An uninstrumented recovery message carried by a proof-level envelope. -/
abbrev Payload := DisasterRecovery.Model.Local.Message

/-- A model message augmented with the sender's local state at emission. -/
structure Envelope where
  /-- The location that emitted the message. -/
  source : Location
  /-- The destination location. -/
  target : Location
  /-- The protocol message without its routing information. -/
  payload : Payload
  /-- The local-state snapshot justifying the send. -/
  sourceState : NodeState
deriving Repr, BEq, ReflBEq, LawfulBEq

/-- A historical opening notification and the state that produced it. -/
structure Opening where
  /-- The location that began opening. -/
  node : Location
  /-- The evidence under which the location began opening. -/
  kind : OpenKind
  /-- The local state after the opening transition. -/
  state : NodeState
deriving Repr, BEq

/-- Global execution state with ghost histories of sends and terminal notifications. -/
structure State where
  /-- The current local states of all configured nodes. -/
  system : SystemState
  /-- Locations permitted to execute protocol actions. -/
  active : List Location
  /-- Instrumented messages still awaiting delivery. -/
  network : List Envelope := []
  /-- Every message emitted so far, including delivered messages. -/
  sent : List Envelope := []
  /-- Opening notifications with their supporting snapshots, newest first. -/
  openings : List Opening := []
  /-- Locations that requested a restart, newest first. -/
  restarts : List Location := []
  /-- Locations that completed recovery, newest first. -/
  completed : List Location := []
deriving Repr, BEq

/-- One instrumented global retry, message delivery, or timeout. -/
inductive Action where
  /-- Emit a location's current retry messages with their source-state snapshots. -/
  | retry (source : Location)
  /-- Deliver one queued instrumented envelope to its target. -/
  | deliver (envelope : Envelope)
  /-- Fire a timeout at the target location. -/
  | timeout (target : Location)
deriving Repr, BEq

/-- Look up a location's current local state in the instrumented node table. -/
def nodeState (state : State) (node : Location) : Option NodeState :=
  (state.system.nodes.find? fun entry => entry.1 == node).map Prod.snd

/-- Convert a send effect to an envelope with its source-state evidence. -/
def messageForEffect (config : Config) (source : Location) (sourceState : NodeState)
    : Effect -> Option Envelope
  | .sendGossip target => do
      let txid <- recoveredTxID config source
      pure { source, target, payload := .gossip txid, sourceState }
  | .sendVote target =>
      some { source, target, payload := .vote, sourceState }
  | .sendIAmOpen target =>
      some { source, target, payload := .iAmOpen, sourceState }
  | _ => none

/-- The instrumented envelopes emitted by a retry from the supplied local state. -/
def retryMessages (config : Config) (source : Location) (sourceState : NodeState)
    : List Envelope :=
  (step config.protocol sourceState .retry).effects.filterMap
    (messageForEffect config source sourceState)

/-- The envelope is justified by a retry from a snapshot with the correct source identity. -/
def Envelope.Valid (config : Config) (envelope : Envelope) : Prop :=
  envelope.sourceState.location = envelope.source
  /\ envelope ∈ retryMessages config envelope.source envelope.sourceState

/-- Translate a queued envelope into an authenticated local receive event. -/
def eventFor (envelope : Envelope) : Event :=
  match envelope.payload with
  | .gossip txid => .receiveGossip envelope.source txid .accepted
  | .vote => .receiveVote envelope.source .accepted
  | .iAmOpen => .receiveIAmOpen envelope.source .accepted

/-- Consume only the first matching occurrence, preserving other message copies. -/
def removeOne [BEq α] (value : α) : List α -> List α
  | [] => []
  | head :: tail =>
      if head == value then tail else head :: removeOne value tail

/-- Prepend a terminal notification to its ghost history, leaving other effects alone. -/
def recordEffect (node : Location) (nodeState : NodeState) (state : State)
    : Effect -> State
  | .opening kind =>
      { state with openings := { node, kind, state := nodeState } :: state.openings }
  | .restart _ =>
      { state with restarts := node :: state.restarts }
  | .completed =>
      { state with completed := node :: state.completed }
  | _ => state

/-- Record the terminal notifications of a completed local step. -/
def recordEffects
    (node : Location)
    (nodeState : NodeState)
    (effects : List Effect)
    (state : State)
    : State :=
  effects.foldl (recordEffect node nodeState) state

/-- Start with initial local states, the supplied active nodes, and empty histories. -/
def initial (config : Config) (active : List Location) : State :=
  {
    system := initialSystem config.protocol
    active
  }

/-- Execute one enabled global action and update the corresponding ghost histories. -/
def next (config : Config) (state : State) : Action -> Option State
  | .retry source => do
      guard (state.active.contains source)
      let sourceState <- nodeState state source
      let messages := retryMessages config source sourceState
      guard (!messages.isEmpty)
      pure
        {
          state with
            network := state.network ++ messages
            sent := state.sent ++ messages
        }
  | .deliver envelope => do
      guard (state.network.contains envelope)
      guard (state.active.contains envelope.target)
      let (system, output) <- systemStep config.protocol state.system envelope.target
                                (eventFor envelope)
      let delivered :=
        {
          state with
            system
            network := removeOne envelope state.network
        }
      pure (recordEffects envelope.target output.state output.effects delivered)
  | .timeout target => do
      guard (state.active.contains target)
      let (system, output) <- systemStep config.protocol state.system target .timeout
      guard output.accepted
      pure (recordEffects target output.state output.effects { state with system })

/-- The instrumented system with valid configuration and duplicate-free active locations. -/
def transitionSystem (config : Config) : TransitionSystem State Action where
  init :=
    fun state =>
      exists active : List Location,
        config.Valid
        /\ active.Nodup
        /\ (forall node, node ∈ active -> node ∈ config.protocol.expectedLocations)
        /\ state = initial config active
  step := next config

/-- States obtainable by finite enabled executions of the instrumented system. -/
abbrev Reachable (config : Config) : State -> Prop :=
  (transitionSystem config).Reachable

end DisasterRecovery.Proofs.Execution.Global
