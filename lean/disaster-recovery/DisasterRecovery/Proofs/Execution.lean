import DisasterRecovery.Proofs.ExecutionLocal

/-! Proof-only execution with send snapshots and terminal-effect histories. -/

namespace DisasterRecovery.Proofs.Execution.Global

open Shared (TransitionSystem)
open Local

@[inherit_doc Model.Config]
abbrev Config := Model.Config

@[inherit_doc Model.Config.Valid]
abbrev Config.Valid (config : Config) := Model.Config.Valid config

@[inherit_doc Model.recoveredTxID]
def recoveredTxID (config : Config) (source : Location) : Option TxID :=
  (config.recovered.find? fun entry => entry.1 == source).map Prod.snd

@[inherit_doc DisasterRecovery.Model.Local.Message]
abbrev Payload := DisasterRecovery.Model.Local.Message

/-- A queued message decorated with the sender's state at emission time. -/
structure Envelope where
  /-- The node that emitted the message. -/
  source : Location
  /-- The node to which the message is addressed. -/
  target : Location
  /-- The recovery message content. -/
  payload : Payload
  /-- The sender's local state when the message was emitted. -/
  sourceState : NodeState
deriving Repr, BEq, ReflBEq, LawfulBEq

/-- A recorded opening notification and the local state that produced it. -/
structure Opening where
  /-- The node that started opening. -/
  node : Location
  /-- Whether the opening was by quorum or failover. -/
  kind : OpenKind
  /-- The node's state after the step that emitted the notification. -/
  state : NodeState
deriving Repr, BEq

/-- The network decorated with send snapshots and terminal-notification histories. -/
structure State where
  /-- Current local states of the configured nodes. -/
  system : SystemState
  /-- Nodes permitted to take steps. -/
  active : List Location
  /-- Messages still queued for delivery. -/
  network : List Envelope := []
  /-- All messages emitted so far, retaining their send-time snapshots. -/
  sent : List Envelope := []
  /-- Recorded openings, newest first. -/
  openings : List Opening := []
  /-- Nodes that requested a restart, newest first. -/
  restarts : List Location := []
  /-- Nodes that completed opening, newest first. -/
  completed : List Location := []
deriving Repr, BEq

/-- A retry, delivery, or timeout in the decorated network. -/
inductive Action where
  | retry (source : Location)
  | deliver (envelope : Envelope)
  | timeout (target : Location)
deriving Repr, BEq

/-- Looks up a node's current state in the decorated network. -/
def nodeState (state : State) (node : Location) : Option NodeState :=
  (state.system.nodes.find? fun entry => entry.1 == node).map Prod.snd

/-- Decorates a send effect with its sender and send-time state; ignores notifications. -/
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

/-- The decorated messages emitted by a node's retry. -/
def retryMessages (config : Config) (source : Location) (sourceState : NodeState)
    : List Envelope :=
  (step config.protocol sourceState .retry).effects.filterMap
    (messageForEffect config source sourceState)

/-- The envelope was emitted by a retry of the node identified in its snapshot. -/
def Envelope.Valid (config : Config) (envelope : Envelope) : Prop :=
  envelope.sourceState.location = envelope.source
  /\ envelope ∈ retryMessages config envelope.source envelope.sourceState

/-- The accepted receive event corresponding to a decorated envelope. -/
def eventFor (envelope : Envelope) : Event :=
  match envelope.payload with
  | .gossip txid => .receiveGossip envelope.source txid .accepted
  | .vote => .receiveVote envelope.source .accepted
  | .iAmOpen => .receiveIAmOpen envelope.source .accepted

/-- Removes one queued copy of a value, preserving any other identical copies. -/
def removeOne [BEq α] (value : α) : List α -> List α
  | [] => []
  | head :: tail =>
      if head == value then tail else head :: removeOne value tail

/-- Adds a terminal notification to its proof-only history. -/
def recordEffect (node : Location) (nodeState : NodeState) (state : State)
    : Effect -> State
  | .opening kind =>
      { state with openings := { node, kind, state := nodeState } :: state.openings }
  | .restart _ =>
      { state with restarts := node :: state.restarts }
  | .completed =>
      { state with completed := node :: state.completed }
  | _ => state

/-- Records terminal notifications from a step in emission order. -/
def recordEffects
    (node : Location)
    (nodeState : NodeState)
    (effects : List Effect)
    (state : State)
    : State :=
  effects.foldl (recordEffect node nodeState) state

/-- Initializes the local states and active set with empty queues and histories. -/
def initial (config : Config) (active : List Location) : State :=
  {
    system := initialSystem config.protocol
    active
  }

/-- Executes a decorated network action and updates its proof-only histories. -/
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

/-- The decorated execution system with valid configurations and active-node subsets. -/
def transitionSystem (config : Config) : TransitionSystem State Action where
  init :=
    fun state =>
      exists active : List Location,
        config.Valid
        /\ active.Nodup
        /\ (forall node, node ∈ active -> node ∈ config.protocol.expectedLocations)
        /\ state = initial config active
  step := next config

/-- States reachable by enabled actions in the decorated execution system. -/
abbrev Reachable (config : Config) : State -> Prop :=
  (transitionSystem config).Reachable

end DisasterRecovery.Proofs.Execution.Global
