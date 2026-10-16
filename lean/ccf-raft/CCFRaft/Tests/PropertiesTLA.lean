module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.PropertiesTLA

@[expose] public section

/-!
Checks that the `PropertiesTLA` statements line up with the TLA+ definitions they restate.
-/

namespace CCFRaft.Tests.PropertiesTLA

open Model.Node ProofTLA

section Execution

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId]
  [LinearOrder Node]

/-- `Servers`: every state of a valid trace holds each configured node exactly once. -/
theorem servers (config : InitialConfig Node) {nodes : List Node}
    {trace : PropertiesTLA.GlobalTrace Node TxId}
    (valid : trace.Valid (Model.transitionSystem config nodes))
    {state : Model.State Node TxId} (member : state ∈ trace.states)
    : state.nodes.map Prod.fst = nodes /\ nodes.Nodup := by
  let _ : InitialConfig Node := config
  refine ⟨?_, ?_⟩
  · have reachable := valid.reachable member
    clear member
    induction reachable with
    | initial initialized => exact initialized.2.1
    | @step before after action _ stepped ih =>
        cases action with
        | «local» actor input =>
            obtain ⟨_, _, _, _, _, rfl⟩ := Concrete.step_local stepped
            simpa [Concrete.replaceNode_keys] using ih
        | deliver envelope =>
            obtain ⟨_, _, _, _, _, _, rfl⟩ := Concrete.step_deliver stepped
            simpa [Concrete.replaceNode_keys] using ih
  · obtain ⟨initial, _, initialized⟩ := valid.1
    exact initialized.1

/-- `committedLog` is ccfraft.tla's `Committed(i)`, `SubSeq(log[i], 1, commitIndex[i])`:
`take` never truncates at the log's end, since the commit index lies within the log. -/
theorem committed_length (config : InitialConfig Node) {nodes : List Node}
    {trace : PropertiesTLA.GlobalTrace Node TxId}
    (valid : trace.Valid (Model.transitionSystem config nodes))
    {state : Model.State Node TxId} (member : state ∈ trace.states) {i : Node}
    {s : NodeState Node TxId} (listed : (i, s) ∈ state.nodes)
    : s.committedLog.length = s.commitIndex := by
  let _ : InitialConfig Node := config
  have frontier := Direct.commitFrontier_invariant.reachable (valid.reachable member) i s listed
  simpa [NodeState.committedLog] using frontier.1

end Execution

end CCFRaft.Tests.PropertiesTLA
