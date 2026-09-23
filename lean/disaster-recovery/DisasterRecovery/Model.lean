import DisasterRecovery.Shared.MultiNodeTransitionSystem
import DisasterRecovery.Model.GlobalHelper

namespace DisasterRecovery.Model

open Shared
open DisasterRecovery.Model.Local

structure Config where
  protocol : DisasterRecovery.Model.Local.Config
  recovered : List (Location × TxID)
deriving Repr, BEq

def Config.Valid (config : Config) : Prop :=
  config.protocol.isValid = true
  /\ config.protocol.expectedLocations.Nodup
  /\ config.recovered.map Prod.fst = config.protocol.expectedLocations

def recoveredTxID (config : Config) (source : Location) : Option TxID :=
  (config.recovered.find? fun entry => entry.1 == source).map Prod.snd

inductive Input where
  | retry
  | timeout
deriving Repr, BEq

abbrev Envelope := Shared.Envelope Location Message
abbrev State := MultiNodeTransitionSystem.State Location NodeState Message
abbrev Action := MultiNodeTransitionSystem.Action Location Message Input

def protocol (config : Config)
    : MultiNodeTransitionSystem.Protocol Location NodeState Event Message Notification Input where
  init node state := state = initialNode node
  step host source state action := do
    let recovered <- recoveredTxID config source
    DisasterRecovery.Model.Local.step host config.protocol recovered state action
  receive := GlobalHelper.receive
  internal
    | .retry => .retry
    | .timeout => .timeout

def transitionSystem (config : Config) : TransitionSystem State Action :=
  let network := MultiNodeTransitionSystem.lift config.protocol.expectedLocations (protocol config)
  { network with init := fun state => config.Valid /\ network.init state }

end DisasterRecovery.Model
