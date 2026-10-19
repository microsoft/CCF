module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.ProofTLA.Safety.Commit

@[expose] public section

/-!
Same-state comparability of committed logs, for `PropertiesTLA.spec_logInv`.
Every reachable state heads an `Exec` history whose invariant makes any two
committed logs comparable.
-/

namespace CCFRaft.ProofTLA

open Model.Node

theorem logInv (config : Model.ModelConfig) {nodes : List NodeID} {state : Model.State}
    (reachable : (Model.transitionSystem config nodes).Reachable state)
    {i j : NodeID}
    {si sj : NodeState} (iMember : (i, si) ∈ state.nodes)
    (jMember : (j, sj) ∈ state.nodes)
    : si.committedLog <+: sj.committedLog \/ sj.committedLog <+: si.committedLog := by
  let _ : Model.ModelConfig := config
  obtain ⟨history, exec⟩ := Safety.exec_of_reachable reachable
  exact Safety.committed_logs_comparable exec iMember jMember

end CCFRaft.ProofTLA
