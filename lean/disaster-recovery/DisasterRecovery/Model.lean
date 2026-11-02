module

public import CCF.MultiNodeTransitionSystem
public import DisasterRecovery.Model.Local

@[expose] public section

namespace DisasterRecovery.Model

open CCF
open DisasterRecovery.Model.Local

/-- The local protocol configuration and one recovered ledger per expected location. -/
structure Config where
  /-- Parameters shared by every node's local protocol. -/
  protocol : DisasterRecovery.Model.Local.Config
  /-- Recovered ledger tips, in expected-location order. -/
  recovered : List (Location × TxID)
deriving Repr, BEq

/-- Valid recovery parameters and recovered ledgers. -/
def Config.Valid (config : Config) : Prop :=
  config.protocol.isValid = true
  /\ config.protocol.expectedLocations.Nodup
  /\ config.recovered.map Prod.fst = config.protocol.expectedLocations

/-- Looks up the recovered ledger tip of a configured node. -/
def recoveredTxID (config : Config) (source : Location) : Option TxID :=
  (config.recovered.find? fun entry => entry.1 == source).map Prod.snd

/-- Inputs a node can receive without a network delivery. -/
inductive Input where
  /-- Request retransmission of the messages for the node's current phase. -/
  | retry
  /-- Fire the next timeout in the node's timeout schedule. -/
  | timeout
deriving Repr, BEq

/-- A recovery protocol message in flight. -/
abbrev Envelope := CCF.Envelope Location Message

/-- The local states and queued recovery messages. -/
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
    let recovered <- liftM (recoveredTxID config source)
    DisasterRecovery.Model.Local.step host config.protocol recovered state action
  receive := receive
  internal
    | .retry => .retry
    | .timeout => .timeout

/-- Composes recovery nodes.
Initial states include every expected location but may also contain unused nodes. -/
abbrev transitionSystem (config : Config) : TransitionSystem :=
  let network := MultiNodeTransitionSystem.lift (protocol config)
  {
    network with
      init :=
        fun state =>
          config.Valid
          /\ (forall node,
                node ∈ config.protocol.expectedLocations
                -> node ∈ state.nodes.map Prod.fst)
          /\ network.init state
  }

end DisasterRecovery.Model
