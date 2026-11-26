module

public import Consensus.Model
public import Consensus.Properties.Bootstrap
public import Consensus.Properties.Config
public import CCF.Execution

import Consensus.Proofs.Direct
import Consensus.Proofs.Deadlock
import Consensus.Proofs.SafetyInvariant
import Consensus.Proofs.Witnesses

@[expose] public section

/-!
Safety theorems about the CCF consensus protocol model, each paired with a witness lemma
exhibiting satisfaction of that theorem's preconditions.
-/

namespace Consensus.Properties

open CCF (Finset)

abbrev Behaviour (config : Finset Model.Node.NodeID) (nodes : List Model.Node.NodeID) :=
  CCF.Execution.Behaviour (Model.transitionSystem config nodes)

open Model.Node

/-- Any two committed logs in a valid behaviour are prefix-comparable: those of
any two nodes, in any two states of the behaviour. -/
theorem committed_logs_prefix
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (behaviour : Behaviour config nodes),
      forall (stateA stateB : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (stateA ∈ behaviour
          /\ stateB ∈ behaviour
          /\ (left, leftState) ∈ stateA.nodes
          /\ (right, rightState) ∈ stateB.nodes)
        -> leftState.committedLog <+: rightState.committedLog
            \/ rightState.committedLog <+: leftState.committedLog := by
  exact Proofs.CommittedLogs.committed_logs_prefix

/-- Witness: every valid initial membership admits a behaviour and node states
satisfying the committed-log theorem's preconditions with nonempty committed logs. -/
theorem committed_logs_prefix_witness
    : forall (config : ValidConfig),
        exists (nodes : List NodeID) (behaviour : Behaviour config nodes),
        exists (stateA stateB : Model.State),
        exists (left right : NodeID) (leftState rightState : NodeState),
          stateA ∈ behaviour
          /\ stateB ∈ behaviour
          /\ (left, leftState) ∈ stateA.nodes
          /\ (right, rightState) ∈ stateB.nodes
          /\ leftState.committedLog ≠ []
          /\ rightState.committedLog ≠ [] := by
  exact Proofs.Witnesses.committed_logs_prefix_witness

/-- A successful network step from a state with unique node IDs preserves each
node's committed prefix. -/
theorem single_node_committed_log_monotonic
    : forall (config : Finset NodeID) (nodes : List NodeID),
      forall (pre post : Model.State),
      forall (nodeId : NodeID) (nodePre nodePost : NodeState),
      forall (action : Model.Action),
        ((pre.nodes.map Prod.fst).Nodup
          /\ (Model.transitionSystem config nodes).step pre action = some post
          /\ (nodeId, nodePre) ∈ pre.nodes
          /\ (nodeId, nodePost) ∈ post.nodes)
        -> nodePre.committedLog <+: nodePost.committedLog := by
  exact Proofs.Direct.single_node_committed_log_monotonic

/-- Witness: every valid initial membership admits a successful step from a
state with unique node IDs that strictly extends a node's nonempty committed log. -/
theorem single_node_committed_log_monotonic_witness
    : forall (config : ValidConfig),
        exists (nodes : List NodeID),
        exists (pre post : Model.State),
        exists (nodeId : NodeID) (nodePre nodePost : NodeState),
        exists (action : Model.Action),
          (pre.nodes.map Prod.fst).Nodup
          /\ (Model.transitionSystem config nodes).step pre action = some post
          /\ (nodeId, nodePre) ∈ pre.nodes
          /\ (nodeId, nodePost) ∈ post.nodes
          /\ nodePre.committedLog ≠ []
          /\ nodePre.committedLog.length < nodePost.committedLog.length := by
  exact Proofs.Witnesses.single_node_committed_log_monotonic_witness

/-- No two distinct nodes are primary in the same term. -/
theorem election_safety
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (behaviour : Behaviour config nodes)
              (state : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (state ∈ behaviour
          /\ (left, leftState) ∈ state.nodes
          /\ (right, rightState) ∈ state.nodes
          /\ leftState.role = .primary
          /\ rightState.role = .primary
          /\ leftState.currentTerm = rightState.currentTerm)
        -> left = right := by
  exact Proofs.Election.election_safety

/-- Witness: every valid initial membership admits a behaviour and primary states
satisfying the election-safety theorem's preconditions. -/
theorem election_safety_witness
    : forall (config : ValidConfig),
        exists
        (nodes : List NodeID) (behaviour : Behaviour config nodes) (state : Model.State),
        exists (left right : NodeID) (leftState rightState : NodeState),
          state ∈ behaviour
          /\ (left, leftState) ∈ state.nodes
          /\ (right, rightState) ∈ state.nodes
          /\ leftState.role = .primary
          /\ rightState.role = .primary
          /\ leftState.currentTerm = rightState.currentTerm := by
  exact Proofs.Witnesses.election_safety_witness

/-- Every positive commit index points to a signature entry. -/
theorem committed_frontier_is_signature
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (behaviour : Behaviour config nodes)
              (state : Model.State),
      forall (node : NodeID) (nodeState : NodeState),
        (state ∈ behaviour
          /\ (node, nodeState) ∈ state.nodes
          /\ 0 < nodeState.commitIndex)
        -> isSignatureAt nodeState.log nodeState.commitIndex = true := by
  exact Proofs.Direct.committed_frontier_is_signature

/-- Witness: every valid initial membership admits a valid behaviour with a positive
commit index. -/
theorem committed_frontier_is_signature_witness
    : forall (config : ValidConfig),
        exists
        (nodes : List NodeID) (behaviour : Behaviour config nodes) (state : Model.State),
        exists (node : NodeID) (nodeState : NodeState),
          state ∈ behaviour
          /\ (node, nodeState) ∈ state.nodes
          /\ 0 < nodeState.commitIndex := by
  exact Proofs.Witnesses.committed_frontier_is_signature_witness

/-- Once bootstrapping completes, which takes a node committing a signature, every
reachable state has an enabled action. -/
theorem deadlock_free_after_bootstrap
    : forall (config : Finset NodeID) (nodes : List NodeID),
        ({
              Model.transitionSystem config nodes with
                init :=
                  fun state =>
                    (Model.transitionSystem config nodes).Reachable state
                    /\ Bootstrapped state
            }
          : CCF.TransitionSystem).DeadlockFree := by
  exact Proofs.Deadlock.deadlock_free_after_bootstrap

/-- Witness: every valid configuration completes bootstrapping. -/
theorem deadlock_free_after_bootstrap_witness
    : forall (config : ValidConfig),
        exists (nodes : List NodeID) (state : Model.State),
          (Model.transitionSystem config nodes).Reachable state
          /\ Bootstrapped state := by
  exact Proofs.Witnesses.deadlock_free_after_bootstrap_witness

end Consensus.Properties
