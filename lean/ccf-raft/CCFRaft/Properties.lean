module

public import CCFRaft.Model
public import CCF.Execution
public import CCF.WitnessedTheorem

import CCFRaft.Proofs.CommittedLogs
import CCFRaft.Proofs.Direct.CommitFrontier
import CCFRaft.Proofs.Election
import CCFRaft.Proofs.Witnesses

@[expose] public section

/-!
Safety theorems about the CCF-Raft model, each paired with a witness lemma
or bundled with a witness proof exhibiting an execution relevant to that property.
-/

namespace CCFRaft.Properties

abbrev GlobalTrace := CCF.Execution.Trace Model.State

open Model.Node

/-- Any two committed logs in a valid trace are prefix-comparable: those of
any two nodes, in any two states of the trace. -/
theorem committed_logs_prefix
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace),
      forall (stateA stateB : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ stateA ∈ trace
          /\ stateB ∈ trace
          /\ (left, leftState) ∈ stateA.nodes
          /\ (right, rightState) ∈ stateB.nodes)
        -> leftState.committedLog <+: rightState.committedLog
            \/ rightState.committedLog <+: leftState.committedLog := by
  exact Proofs.CommittedLogs.committed_logs_prefix

/-- Witness: a valid trace has two states in which two distinct nodes have
nonempty committed logs. -/
lemma committed_logs_prefix_witness
    : exists (config : Finset NodeID),
    exists (nodes : List NodeID) (trace : GlobalTrace),
    exists (stateA stateB : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ stateA ∈ trace
      /\ stateB ∈ trace
      /\ (left, leftState) ∈ stateA.nodes
      /\ (right, rightState) ∈ stateB.nodes
      /\ left ≠ right
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

/-- Witness: a successful step from a state with unique node IDs strictly extends
one node's nonempty committed log. -/
lemma single_node_committed_log_monotonic_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
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

/-- A trace state and two node states for election safety. -/
structure ElectionSafetyContext where
  config : Finset NodeID
  nodes : List NodeID
  trace : GlobalTrace
  state : Model.State
  left : NodeID
  right : NodeID
  leftState : NodeState
  rightState : NodeState

/-- No two distinct nodes are primary in the same term. -/
theorem election_safety
    : CCF.WitnessedTheorem
        (requires :=
          fun c : ElectionSafetyContext =>
            c.trace.Valid (Model.transitionSystem c.config c.nodes)
            /\ c.state ∈ c.trace
            /\ (c.left, c.leftState) ∈ c.state.nodes
            /\ (c.right, c.rightState) ∈ c.state.nodes
            /\ c.leftState.role = .primary
            /\ c.rightState.role = .primary)

        (ensures :=
          fun c =>
            c.leftState.currentTerm = c.rightState.currentTerm -> c.left = c.right)

        (witness_satisfies := fun c => c.left ≠ c.right) where

  proof := by intro c; exact Proofs.Election.election_safety

  witness_proof := by
    exact Proofs.Witnesses.election_safety_witness ElectionSafetyContext.mk
      (by intros; assumption)

/-- A trace state and a node state for the committed-frontier property. -/
structure CommitFrontierContext where
  config : Finset NodeID
  nodes : List NodeID
  trace : GlobalTrace
  state : Model.State
  node : NodeID
  nodeState : NodeState

/-- Every positive commit index points to a signature entry. -/
theorem committed_frontier_is_signature
    : CCF.WitnessedTheorem
        (requires :=
          fun c : CommitFrontierContext =>
            c.trace.Valid (Model.transitionSystem c.config c.nodes)
            /\ c.state ∈ c.trace
            /\ (c.node, c.nodeState) ∈ c.state.nodes
            /\ 0 < c.nodeState.commitIndex)

        (ensures :=
          fun c =>
            isSignatureAt c.nodeState.log c.nodeState.commitIndex = true) where

  proof := by intro c; exact Proofs.Direct.committed_frontier_is_signature

  witness_proof := by
    exact Proofs.Witnesses.committed_frontier_is_signature_witness
      CommitFrontierContext.mk (by intros; assumption)

end CCFRaft.Properties
