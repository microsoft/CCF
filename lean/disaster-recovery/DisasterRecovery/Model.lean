import DisasterRecovery.Shared.Global
import DisasterRecovery.Model.Local

namespace DisasterRecovery.Model

open Shared
open DisasterRecovery.Model.Local

structure Config where
  protocol : DisasterRecovery.Model.Local.Config
  recovered : List (Location × TxID)
deriving Repr, BEq

def Config.Valid (config : Config) : Prop :=
  config.protocol.isValid = true /\
    config.protocol.expectedLocations.Nodup /\
    config.recovered.map Prod.fst = config.protocol.expectedLocations

def recoveredTxID (config : Config) (source : Location) : Option TxID :=
  (config.recovered.find? fun entry => entry.1 == source).map Prod.snd

inductive Input where
  | retry
  | timeout
deriving Repr, BEq

abbrev Envelope := Global.Envelope Location Message
abbrev State := Global.State Location NodeState Message
abbrev Action := Global.Action Location Message Input

def protocol (config : Config) :
    Global.Protocol Location NodeState Event Message Input where
  init node state := state = initialNode node
  step host source state action := do
    let recovered <- recoveredTxID config source
    DisasterRecovery.Model.Local.step host config.protocol recovered state action
  receive := DisasterRecovery.Model.Local.receive
  internal
    | .retry => .retry
    | .timeout => .timeout

def transitionSystem (config : Config) : TransitionSystem State Action :=
  let network := Global.lift config.protocol.expectedLocations (protocol config)
  { network with init := fun state => config.Valid /\ network.init state }

def initial (config : Config) (active : List Location) : State := {
  nodes := config.protocol.expectedLocations.map fun node => (node, initialNode node)
  active
}

def next (config : Config) : State -> Action -> Option State :=
  (transitionSystem config).step

abbrev nodeState (state : State) (node : Location) : Option NodeState :=
  Global.nodeState state node

abbrev Reachable (config : Config) : State -> Prop :=
  (transitionSystem config).Reachable

end DisasterRecovery.Model
