module

public import Consensus.Model

import Mathlib.Tactic.Lemma

@[expose] public section

namespace Consensus.Proofs.Deadlock

open Model.Node

theorem deadlock_free
    : forall (node : NodeID) (nodes : List NodeID),
        node ∈ nodes -> (Model.transitionSystem {node} nodes).DeadlockFree := by
  -- Unsigned reconfiguration followed by CheckQuorum permits a reachable deadlock.
  sorry

lemma deadlock_free_witness
    : exists (node : NodeID) (nodes : List NodeID) (state : Model.State),
        node ∈ nodes /\ (Model.transitionSystem {node} nodes).init state := by
  refine ⟨0, [0], { nodes := [(0, Model.initialNodeState {0} 0)] }, by simp, ?_⟩
  simp [Model.protocol]

end Consensus.Proofs.Deadlock
