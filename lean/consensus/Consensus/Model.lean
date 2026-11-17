module

public import Consensus.Model.ClusterConfig
public import Consensus.Model.Node
public import Consensus.Model.Messages
public import Consensus.Model.NodeState
public import CCF.MultiNodeTransitionSystem

@[expose] public section

/-!
# CCF consensus protocol network

Composes `Node.step` into a network. Deliveries may select any queued envelope;
an envelope never delivered models message loss.
-/

namespace Consensus.Model

open CCF
open Node

abbrev Envelope := CCF.Envelope NodeID Message

abbrev State :=
  MultiNodeTransitionSystem.State NodeID NodeState Message

abbrev Action :=
  MultiNodeTransitionSystem.Action NodeID Message Input

/-- The term of the initial primary, matching CCF's forced-primary startup. -/
def BOOTSTRAP_TERM : Nat := 2

/--
Production starts with one voting node. The model also permits multi-node initial
configurations, which the consensus testing infrastructure can construct.
The smallest initial member is primary and holds the unsigned configuration.
-/
def initialNodeState (initialConfiguration : Finset NodeID) (node : NodeID) : NodeState :=
  let primary := initialConfiguration.min? = some node
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
  step := Consensus.Model.Node.step
  receive := .receive
  internal := .internal

/--
Whether some node has `entries` as a committed ledger prefix; a fresh joiner has
committed only the empty prefix. Crashes are not modeled, so the prefix keeps its history.
-/
def committedPrefixOf (state : State) (entries : List Entry) : Bool :=
  state.nodes.any
    fun (_, other) =>
      entries.length <= other.commitIndex && other.log.take entries.length == entries

/-- A network step; a node initializes only from a committed prefix. -/
def networkStep (initialConfiguration : Finset NodeID) (state : State) (action : Action)
    : Option State :=
  match action with
  | .local _ (.initAsBackup entries) =>
      if committedPrefixOf state entries then
        MultiNodeTransitionSystem.next (protocol initialConfiguration) state action
      else
        none
  | _ => MultiNodeTransitionSystem.next (protocol initialConfiguration) state action

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
      step := networkStep initialConfiguration
  }

end Consensus.Model
