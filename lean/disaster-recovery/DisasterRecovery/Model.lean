import DisasterRecovery.Shared.MultiNodeTransitionSystem
import DisasterRecovery.Model.Local

namespace DisasterRecovery.Model

open Shared
open DisasterRecovery.Model.Local

/-- Recovery configuration together with each location's recovered transaction ID. -/
structure Config where
  /-- The common local-protocol configuration. -/
  protocol : DisasterRecovery.Model.Local.Config
  /-- Recovered transaction IDs, in configured location order. -/
  recovered : List (Location × TxID)
deriving Repr, BEq

/-- The local configuration is valid and has exactly one recovered ID per location. -/
def Config.Valid (config : Config) : Prop :=
  config.protocol.isValid = true
  /\ config.protocol.expectedLocations.Nodup
  /\ config.recovered.map Prod.fst = config.protocol.expectedLocations

/-- Look up the transaction ID advertised by a location's gossip retries. -/
def recoveredTxID (config : Config) (source : Location) : Option TxID :=
  (config.recovered.find? fun entry => entry.1 == source).map Prod.snd

/-- External inputs supplied to a node without delivering a network message. -/
inductive Input where
  /-- Request retransmission of the messages for the node's current phase. -/
  | retry
  /-- Fire the next timeout in the node's timeout schedule. -/
  | timeout
deriving Repr, BEq

/-- A recovery-protocol message together with its source and target locations. -/
abbrev Envelope := Shared.Envelope Location Message

/-- All local recovery states and the messages awaiting delivery. -/
abbrev State := MultiNodeTransitionSystem.State Location NodeState Message

/-- A local retry or timeout, or delivery of a queued recovery message. -/
abbrev Action := MultiNodeTransitionSystem.Action Location Message Input

/-- Translate a network delivery into an authenticated local receive event. -/
def receive (source : Location) : Message -> Event
  | .gossip txid => .receiveGossip source txid .accepted
  | .vote => .receiveVote source .accepted
  | .iAmOpen => .receiveIAmOpen source .accepted

/-- Instantiate the local recovery protocol for the shared network model. -/
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

/-- The message-passing recovery system, restricted to valid initial configurations. -/
def transitionSystem (config : Config) : TransitionSystem State Action :=
  let network :=
    MultiNodeTransitionSystem.lift config.protocol.expectedLocations (protocol config)
  { network with init := fun state => config.Valid /\ network.init state }

end DisasterRecovery.Model
