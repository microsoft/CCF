module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.ProofTLA.Safety.Commit

@[expose] public section

/-!
Same-state comparability of committed logs, for `PropertiesTLA.log_inv`.
Every reachable state heads an `Exec` history whose invariant makes any two
committed logs comparable.
-/

namespace CCFRaft.ProofTLA

open Model.Node

theorem log_inv
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (state : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        ((Model.transitionSystem config nodes).Reachable state
          /\ (left, leftState) ∈ state.nodes
          /\ (right, rightState) ∈ state.nodes)
        -> leftState.committedLog <+: rightState.committedLog
            \/ rightState.committedLog <+: leftState.committedLog := by
  intro config _ _ _ _ _ _ ⟨reachable, leftMember, rightMember⟩
  let _ : Initial := ⟨config⟩
  obtain ⟨history, exec⟩ := Safety.exec_of_reachable reachable
  exact Safety.committed_logs_comparable exec leftMember rightMember

end CCFRaft.ProofTLA
