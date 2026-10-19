module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.ProofTLA.Direct.AppendOnly

@[expose] public section

/-!
Per-step growth of each node's committed log, for
`PropertiesTLA.spec_committedLogAppendOnlyProp`.
-/

namespace CCFRaft.ProofTLA

open Model.Node

/-- `CommittedLogAppendOnlyProp` for one step from a reachable state and one node. -/
theorem committedLog_step (config : Model.ModelConfig) {nodes : List NodeID}
    {before after : Model.State} {action : Model.Action}
    (reachable : (Model.transitionSystem config nodes).Reachable before)
    (stepped : (Model.transitionSystem config nodes).step before action = some after)
    {i : NodeID} {bi ai : NodeState} (beforeMember : (i, bi) ∈ before.nodes)
    (afterMember : (i, ai) ∈ after.nodes)
    : bi.committedLog <+: ai.committedLog := by
  let _ : Model.ModelConfig := config
  exact Direct.committed_log_step (Direct.keys_nodup reachable) stepped beforeMember afterMember

end CCFRaft.ProofTLA
