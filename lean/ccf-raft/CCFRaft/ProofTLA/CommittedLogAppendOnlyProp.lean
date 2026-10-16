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

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId]
  [LinearOrder Node]

/-- `CommittedLogAppendOnlyProp` for one step from a reachable state and one node. -/
theorem committedLog_step (config : InitialConfig Node) {nodes : List Node}
    {before after : Model.State Node TxId} {action : Model.Action Node TxId}
    (reachable : (Model.transitionSystem config nodes).Reachable before)
    (stepped : (Model.transitionSystem config nodes).step before action = some after)
    {i : Node} {bi ai : NodeState Node TxId} (beforeMember : (i, bi) ∈ before.nodes)
    (afterMember : (i, ai) ∈ after.nodes)
    : bi.committedLog <+: ai.committedLog := by
  let _ : InitialConfig Node := config
  exact Direct.committed_log_step (Direct.keys_nodup reachable) stepped beforeMember afterMember

end CCFRaft.ProofTLA
