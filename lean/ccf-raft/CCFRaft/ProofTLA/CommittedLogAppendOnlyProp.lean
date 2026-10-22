module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.ProofTLA.Direct.AppendOnly

@[expose] public section

/-!
Per-step growth of each node's committed log, for
`PropertiesTLA.committed_log_append_only_prop`.
-/

namespace CCFRaft.ProofTLA

open Model.Node

theorem committed_log_append_only_prop
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (before after : Model.State) (action : Model.Action),
      forall (node : NodeID) (nodeBefore nodeAfter : NodeState),
        ((Model.transitionSystem config nodes).Reachable before
          /\ (Model.transitionSystem config nodes).step before action = some after
          /\ (node, nodeBefore) ∈ before.nodes
          /\ (node, nodeAfter) ∈ after.nodes)
        -> nodeBefore.committedLog <+: nodeAfter.committedLog := by
  intro config _ _ _ _ _ _ _ ⟨reachable, stepped, beforeMember, afterMember⟩
  let _ : Initial := ⟨config⟩
  exact Direct.committed_log_step (Direct.keys_nodup reachable) stepped beforeMember afterMember

end CCFRaft.ProofTLA
