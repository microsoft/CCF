module

public import Consensus.Model
public import CCF.Execution
public import CCF.Witnessed

import Consensus.Proofs.Claims
import Consensus.Proofs.SafetyInvariant
import Consensus.Proofs.Witnesses

@[expose] public section

/-!
Safety theorems about the CCF consensus protocol model, each with a witness exhibiting a
nontrivial execution relevant to that property.
A claim stated with `witnessed% forall xs, { pre := p, post := q, witness := w }` is both
`forall xs, p -> q` and the witness `exists xs, p /\ w`.
-/

namespace Consensus.Properties

open CCF (Finset)

abbrev GlobalTrace (config : Finset Model.Node.NodeID) (nodes : List Model.Node.NodeID) :=
  CCF.Execution.Trace (Model.transitionSystem config nodes)

open Model.Node

/-- Any two committed logs in a valid trace are prefix-comparable: those of
any two nodes, in any two states of the trace.
Witness: a valid trace has two states in which two distinct nodes have nonempty committed
logs. -/
theorem committed_logs_prefix
    : witnessed% forall (config : Finset NodeID) (nodes : List NodeID)
                        (trace : GlobalTrace config nodes) (stateA stateB : Model.State)
                        (left right : NodeID) (leftState rightState : NodeState),
                  {
                    pre :=
                      stateA ∈ trace
                      /\ stateB ∈ trace
                      /\ (left, leftState) ∈ stateA.nodes
                      /\ (right, rightState) ∈ stateB.nodes
                    post :=
                      leftState.committedLog <+: rightState.committedLog
                      \/ rightState.committedLog <+: leftState.committedLog
                    witness :=
                      left ≠ right
                      /\ leftState.committedLog ≠ []
                      /\ rightState.committedLog ≠ []
                  } := by
  exact Proofs.Claims.committed_logs_prefix

/-- A successful network step from a state with unique node IDs preserves each
node's committed prefix.
Witness: such a step strictly extends one node's nonempty committed log. -/
theorem single_node_committed_log_monotonic
    : witnessed% forall (config : Finset NodeID) (nodes : List NodeID)
                        (before after : Model.State) (nodeId : NodeID)
                        (nodeBefore nodeAfter : NodeState) (action : Model.Action),
                  {
                    pre :=
                      (before.nodes.map Prod.fst).Nodup
                      /\ (Model.transitionSystem config nodes).step before action
                          = some after
                      /\ (nodeId, nodeBefore) ∈ before.nodes
                      /\ (nodeId, nodeAfter) ∈ after.nodes
                    post := nodeBefore.committedLog <+: nodeAfter.committedLog
                    witness :=
                      nodeBefore.committedLog ≠ []
                      /\ nodeBefore.committedLog.length < nodeAfter.committedLog.length
                  } := by
  exact Proofs.Claims.single_node_committed_log_monotonic

/-- No two distinct nodes are primary in the same term. -/
theorem election_safety
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace config nodes)
              (state : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (state ∈ trace
          /\ (left, leftState) ∈ state.nodes
          /\ (right, rightState) ∈ state.nodes
          /\ leftState.role = .primary
          /\ rightState.role = .primary
          /\ leftState.currentTerm = rightState.currentTerm)
        -> left = right := by
  exact Proofs.Election.election_safety

/-- Witness: a valid trace has a state in which two nodes are primaries. -/
theorem election_safety_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace : GlobalTrace config nodes) (state : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      state ∈ trace
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes
      /\ leftState.role = .primary
      /\ rightState.role = .primary
      /\ left ≠ right := by
  exact Proofs.Witnesses.election_safety_witness

/-- Every positive commit index points to a signature entry.
Witness: a valid trace has a state with a positive commit index. -/
theorem committed_frontier_is_signature
    : witnessed% forall (config : Finset NodeID) (nodes : List NodeID)
                        (trace : GlobalTrace config nodes) (state : Model.State)
                        (node : NodeID) (nodeState : NodeState),
                  {
                    pre :=
                      state ∈ trace
                      /\ (node, nodeState) ∈ state.nodes
                      /\ 0 < nodeState.commitIndex
                    post := isSignatureAt nodeState.log nodeState.commitIndex = true
                  } := by
  exact Proofs.Claims.committed_frontier_is_signature

end Consensus.Properties
