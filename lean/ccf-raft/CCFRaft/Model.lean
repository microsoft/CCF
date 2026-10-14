module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model.ClusterConfig
public import CCFRaft.Model.Node
public import CCFRaft.Model.Messages
public import CCFRaft.Model.NodeState
public import CCF.MultiNodeTransitionSystem

@[expose] public section

/-!
# CCF Raft network

Composes `Node.step` into a network. Deliveries may select any queued envelope;
an envelope never delivered models message loss.
-/

namespace CCFRaft.Model

open CCF
open Node

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId]

abbrev Envelope (Node TxId : Type) := CCF.Envelope Node (Message Node TxId)

abbrev State (Node TxId : Type) :=
  MultiNodeTransitionSystem.State Node (NodeState Node TxId) (Message Node TxId)

abbrev Action (Node TxId : Type) :=
  MultiNodeTransitionSystem.Action Node (Message Node TxId) (Input Node TxId)

def protocol [LinearOrder Node] [Inhabited TxId] (config : InitialConfig Node)
    : MultiNodeTransitionSystem.Protocol
        Node (NodeState Node TxId) (Event Node TxId) (Message Node TxId) Notification
        (Input Node TxId) where
  init node state := state = initialNodeState config node
  step := CCFRaft.Model.Node.step config
  receive := .receive
  internal := .internal

/-- The network of `nodes`. Initial membership, the initial leader, and
pre-vote modes are supplied explicitly by `config`. -/
def transitionSystem [LinearOrder Node] [Inhabited TxId]
    (config : InitialConfig Node) (nodes : List Node)
    : TransitionSystem (State Node TxId) (Action Node TxId) :=
  MultiNodeTransitionSystem.lift nodes (protocol config)

end CCFRaft.Model
