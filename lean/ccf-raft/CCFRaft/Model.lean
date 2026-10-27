module

public import CCFRaft.Model.ClusterConfig
public import CCFRaft.Model.Node
public import CCFRaft.Model.Messages
public import CCFRaft.Model.NodeState
public import CCF.MultiNodeTransitionSystem
public import Mathlib.Data.Finset.Max

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

/-- The term of the initial primary, matching CCF's forced-primary startup. -/
def BOOTSTRAP_TERM : Nat := 2

/-- The smallest initial member is primary and holds the unsigned configuration. -/
def initialNodeState (initialConfiguration : Finset NodeID) (node : NodeID) : NodeState :=
  let primary := initialConfiguration.min = (node : WithTop NodeID)
  {
    role :=
      if primary then
        .primary
      else if node ∈ initialConfiguration then
        .follower
      else
        .none
    currentTerm := if node ∈ initialConfiguration then BOOTSTRAP_TERM else 0
    log :=
      if primary then
        [{
          term := BOOTSTRAP_TERM
          content := .transaction 0 { configuration := some initialConfiguration }
        }]
      else
        []
    commitIndex := 0
    sentIndex := fun _ => 0
    matchIndex := fun _ => 0
    isNewFollower := false
    votedFor := none
    primaryKnown := primary
    votesGranted := ∅
  }

def protocol (initialConfiguration : Finset NodeID)
    : MultiNodeTransitionSystem.Protocol
        NodeID NodeState Event Message Notification
        Input where
  init node state := state = initialNodeState initialConfiguration node
  step := CCFRaft.Model.Node.step
  receive := .receive
  internal := .internal

/-- The network of `nodes`, initialized from a nonempty membership configuration. -/
abbrev transitionSystem (initialConfiguration : Finset NodeID) (nodes : List NodeID)
    : TransitionSystem :=
  let system := MultiNodeTransitionSystem.lift (protocol initialConfiguration)
  {
    system with
      init :=
        fun state =>
          initialConfiguration.Nonempty
          /\ state.nodes.map Prod.fst = nodes
          /\ system.init state
  }

end CCFRaft.Model
