import DisasterRecovery.Protocol.Model

namespace DisasterRecovery.Protocol.Global

structure Config where
  protocol : Protocol.Config
  recovered : List (Prod Location TxID)
deriving Repr, BEq

def Config.Valid (config : Config) : Prop :=
  config.protocol.isValid = true /\
    config.recovered.map Prod.fst = config.protocol.expectedLocations

def recoveredTxID (config : Config) (source : Location) : Option TxID :=
  (config.recovered.find? fun entry => entry.1 == source).map Prod.snd

inductive Payload where
  | gossip (txid : TxID)
  | vote
  | iAmOpen
deriving Repr, BEq

structure Envelope where
  source : Location
  target : Location
  payload : Payload
  sourceState : NodeState
deriving Repr, BEq

structure Opening where
  node : Location
  kind : OpenKind
deriving Repr, BEq

structure State where
  system : SystemState
  active : List Location
  network : List Envelope := []
  sent : List Envelope := []
  openings : List Opening := []
  restarts : List Location := []
  completed : List Location := []
deriving Repr, BEq

inductive Action where
  | retry (source : Location)
  | deliver (envelope : Envelope)
  | timeout (target : Location)
deriving Repr, BEq

def nodeState (state : State) (node : Location) : Option NodeState :=
  (state.system.nodes.find? fun entry => entry.1 == node).map Prod.snd

def messageForEffect
    (config : Config)
    (source : Location)
    (sourceState : NodeState) : Effect -> Option Envelope
  | .sendGossip target => do
      let txid <- recoveredTxID config source
      pure { source, target, payload := .gossip txid, sourceState }
  | .sendVote target =>
      some { source, target, payload := .vote, sourceState }
  | .sendIAmOpen target =>
      some { source, target, payload := .iAmOpen, sourceState }
  | _ => none

def retryMessages
    (config : Config)
    (source : Location)
    (sourceState : NodeState) : List Envelope :=
  (step config.protocol sourceState .retry).effects.filterMap
    (messageForEffect config source sourceState)

def Envelope.Valid (config : Config) (envelope : Envelope) : Prop :=
  envelope.sourceState.location = envelope.source /\
    envelope ∈ retryMessages config envelope.source envelope.sourceState

def eventFor (envelope : Envelope) : Event :=
  match envelope.payload with
  | .gossip txid => .receiveGossip envelope.source txid .accepted
  | .vote => .receiveVote envelope.source .accepted
  | .iAmOpen => .receiveIAmOpen envelope.source .accepted

def removeOne [BEq α] (value : α) : List α -> List α
  | [] => []
  | head :: tail =>
      if head == value then tail else head :: removeOne value tail

def recordEffect (node : Location) (state : State) : Effect -> State
  | .opening kind =>
      { state with openings := { node, kind } :: state.openings }
  | .restart _ =>
      { state with restarts := node :: state.restarts }
  | .completed =>
      { state with completed := node :: state.completed }
  | _ => state

def recordEffects
    (node : Location)
    (effects : List Effect)
    (state : State) : State :=
  effects.foldl (recordEffect node) state

def initial (config : Config) (active : List Location) : State := {
  system := initialSystem config.protocol
  active
}

def next (config : Config) (state : State) : Action -> Option State
  | .retry source => do
      guard (state.active.contains source)
      let sourceState <- nodeState state source
      let messages := retryMessages config source sourceState
      guard (!messages.isEmpty)
      pure {
        state with
        network := state.network ++ messages
        sent := state.sent ++ messages
      }
  | .deliver envelope => do
      guard (state.network.contains envelope)
      guard (state.active.contains envelope.target)
      let (system, output) <-
        systemStep config.protocol state.system envelope.target
          (eventFor envelope)
      let delivered := {
        state with
        system
        network := removeOne envelope state.network
      }
      pure (recordEffects envelope.target output.effects delivered)
  | .timeout target => do
      guard (state.active.contains target)
      let (system, output) <-
        systemStep config.protocol state.system target .timeout
      guard output.accepted
      pure (recordEffects target output.effects { state with system })

inductive Reachable (config : Config) : State -> Prop where
  | initial
      (active : List Location)
      (nodup : active.Nodup)
      (configured :
        forall node, node ∈ active ->
          node ∈ config.protocol.expectedLocations) :
      Reachable config (Global.initial config active)
  | step
      {state nextState : State}
      {action : Action}
      (reachable : Reachable config state)
      (transition : next config state action = some nextState) :
      Reachable config nextState

end DisasterRecovery.Protocol.Global
