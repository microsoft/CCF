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

abbrev Envelope := CCF.Envelope NodeID Message

abbrev State :=
  MultiNodeTransitionSystem.State NodeID NodeState Message

abbrev Action :=
  MultiNodeTransitionSystem.Action NodeID Message Input

/-- Initialization only; nodes learn subsequent membership from their own logs. -/
structure ModelConfig where
  configuration : Finset NodeID
  primary : configuration

/-- The term of the initial primary, matching CCF's forced-primary startup. -/
def BOOTSTRAP_TERM : Nat := 2

/-- Only the initial primary starts with the unsigned configuration transaction. -/
def initialNodeState (config : ModelConfig) (node : NodeID) : NodeState where
  role :=
    if node = config.primary then
      .primary
    else if node ∈ config.configuration then
      .follower
    else
      .none
  currentTerm := if node ∈ config.configuration then BOOTSTRAP_TERM else 0
  log :=
    if node = config.primary then
      [{
        term := BOOTSTRAP_TERM
        content := .transaction 0 { configuration := some config.configuration }
      }]
    else
      []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := false
  votedFor := none
  primaryKnown := node = config.primary
  votesGranted := ∅

def protocol (config : ModelConfig)
    : MultiNodeTransitionSystem.Protocol
        NodeID NodeState Event Message Notification
        Input where
  init node state := state = initialNodeState config node
  step := CCFRaft.Model.Node.step
  receive := .receive
  internal := .internal

/-- The network of `nodes`, with initial membership and primary supplied by `config`. -/
def transitionSystem (config : ModelConfig) (nodes : List NodeID)
    : TransitionSystem State Action :=
  MultiNodeTransitionSystem.lift nodes (protocol config)

end CCFRaft.Model
