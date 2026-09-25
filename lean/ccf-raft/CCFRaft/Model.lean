-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model.Local
import CCFRaft.Shared.MultiNodeTransitionSystem

set_option autoImplicit false

/-!
# CCF Raft network

Composes copies of `Local.step` with `MultiNodeTransitionSystem`. Every node in
`nodes` starts in `initialNodeState`: bootstrap members at `BOOTSTRAP_TERM`,
and every other node as a fresh replica with term 0 and an empty log. A
delivery may consume any queued envelope, so messages can be reordered. An
envelope that is never delivered models a dropped message.
-/

namespace CCFRaft.Model

open Shared
open Local

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

abbrev Envelope (Node TxId : Type) := Shared.Envelope Node (Message Node TxId)

abbrev State (Node TxId : Type) :=
  MultiNodeTransitionSystem.State Node (NodeState Node TxId) (Message Node TxId)

abbrev Action (Node TxId : Type) :=
  MultiNodeTransitionSystem.Action Node (Message Node TxId) (Input Node TxId)

def protocol
    : MultiNodeTransitionSystem.Protocol
        Node (NodeState Node TxId) (Event Node TxId) (Message Node TxId) Notification
        (Input Node TxId) where
  init node state := state = initialNodeState node
  step := Local.step
  receive := .receive
  internal := .internal

/-- The network of `nodes`. Bootstrap membership, the initial leader, and
pre-vote modes come from the `Bootstrap` instance. -/
def transitionSystem (nodes : List Node)
    : TransitionSystem (State Node TxId) (Action Node TxId) :=
  MultiNodeTransitionSystem.lift nodes protocol

end CCFRaft.Model
