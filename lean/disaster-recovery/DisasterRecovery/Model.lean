import DisasterRecovery.Shared.MultiNodeTransitionSystem
import DisasterRecovery.Model.Local

namespace DisasterRecovery.Model

open Shared
open DisasterRecovery.Model.Local

/-- The local protocol configuration and one recovered ledger per expected location. -/
structure Config where
  /-- Parameters shared by every node's local protocol. -/
  protocol : DisasterRecovery.Model.Local.Config
  /-- Recovered ledger tips, in expected-location order. -/
  recovered : List (Location × TxID)
deriving Repr, BEq

/-- The protocol is valid and recovered ledgers cover its distinct expected locations. -/
def Config.Valid (config : Config) : Prop :=
  config.protocol.isValid = true
  /\ config.protocol.expectedLocations.Nodup
  /\ config.recovered.map Prod.fst = config.protocol.expectedLocations

/-- Looks up the recovered ledger tip of a configured node. -/
def recoveredTxID (config : Config) (source : Location) : Option TxID :=
  (config.recovered.find? fun entry => entry.1 == source).map Prod.snd

/-- Inputs a node can receive without a network delivery. -/
inductive Input where
  | retry
  | timeout
deriving Repr, BEq

/-- A recovery protocol message in flight. -/
abbrev Envelope := Shared.Envelope Location Message

/-- The local states, active nodes, and queued recovery messages. -/
abbrev State := MultiNodeTransitionSystem.State Location NodeState Message

/-- A local retry or timeout, or one queued message delivery. -/
abbrev Action := MultiNodeTransitionSystem.Action Location Message Input

/-- Converts a delivered message into an accepted local receive event. -/
def receive (source : Location) : Message -> Event
  | .gossip txid => .receiveGossip source txid .accepted
  | .vote => .receiveVote source .accepted
  | .iAmOpen => .receiveIAmOpen source .accepted

/-- Supplies the local recovery protocol to the shared network composition. -/
def protocol (config : Config)
    : MultiNodeTransitionSystem.Protocol Location NodeState Event Message Notification
        Input where
  init node state := state = initialNode node
  step host source state action := do
    let recovered <- recoveredTxID config source
    DisasterRecovery.Model.Local.step host config.protocol recovered state action
  receive := receive
  internal
    | .retry => .retry
    | .timeout => .timeout

/-- Composes the nodes and requires a valid configuration in every initial state. -/
def transitionSystem (config : Config) : TransitionSystem State Action :=
  let network :=
    MultiNodeTransitionSystem.lift config.protocol.expectedLocations (protocol config)
  { network with init := fun state => config.Valid /\ network.init state }

end DisasterRecovery.Model
