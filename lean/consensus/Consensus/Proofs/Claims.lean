module

public import Consensus.Model
public import CCF.Execution
public import CCF.Witnessed

import Consensus.Proofs.Direct
import Consensus.Proofs.SafetyInvariant
import Consensus.Proofs.Witnesses

@[expose] public section

/-!
The witnessed claims of `Consensus/Properties.lean`, each assembled from its safety theorem and
its witness.
`Properties.lean` restates each claim and refers to its proof here.
-/

namespace Consensus.Proofs.Claims

open CCF (Finset)

/-- A finite or infinite execution of the network, as in `Properties.lean`. -/
abbrev GlobalTrace (config : Finset Model.Node.NodeID) (nodes : List Model.Node.NodeID) :=
  CCF.Execution.Trace (Model.transitionSystem config nodes)

open Model.Node

/-- The claim `committed_logs_prefix` of `Properties.lean`. -/
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
                  } :=
  ⟨
    Proofs.CommittedLogs.committed_logs_prefix,
    Proofs.Witnesses.committed_logs_prefix_witness
  ⟩

/-- The claim `single_node_committed_log_monotonic` of `Properties.lean`. -/
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
                  } :=
  ⟨
    Proofs.Direct.single_node_committed_log_monotonic,
    Proofs.Witnesses.single_node_committed_log_monotonic_witness
  ⟩

/-- The claim `committed_frontier_is_signature` of `Properties.lean`. -/
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
                  } :=
  ⟨
    Proofs.Direct.committed_frontier_is_signature,
    Proofs.Witnesses.committed_frontier_is_signature_witness
  ⟩

end Consensus.Proofs.Claims
