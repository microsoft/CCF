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

/-- `CommittedLogAppendOnlyProp` for one step of a valid trace and one node. -/
theorem committedLog_step (config : InitialConfig Node) {nodes : List Node}
    {trace : CCF.Execution.Trace (Model.State Node TxId)}
    (valid : trace.Valid (Model.transitionSystem config nodes)) {k : Nat}
    {before after : Model.State Node TxId} (atBefore : trace.states[k]? = some before)
    (atAfter : trace.states[k + 1]? = some after) {i : Node}
    {bi ai : NodeState Node TxId} (beforeMember : (i, bi) ∈ before.nodes)
    (afterMember : (i, ai) ∈ after.nodes)
    : bi.committedLog <+: ai.committedLog := by
  let _ : InitialConfig Node := config
  obtain ⟨action, stepped⟩ := valid.2 k before after atBefore atAfter
  exact Direct.committed_log_step
    (Direct.keys_nodup (valid.reachable (List.mem_of_getElem? atBefore))) stepped
    beforeMember afterMember

end CCFRaft.ProofTLA
