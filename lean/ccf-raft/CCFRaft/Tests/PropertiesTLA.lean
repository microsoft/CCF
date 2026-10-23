module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.ProofTLA.Concrete
public import CCFRaft.ProofTLA.Direct.AppendOnly
public import CCFRaft.PropertiesTLA

@[expose] public section

/-!
Checks that the `PropertiesTLA` statements line up with the TLA+ definitions they restate.
-/

namespace CCFRaft.Tests.PropertiesTLA

open Model.Node ProofTLA

section Execution

/-- `Servers`: every reachable state holds each configured node exactly once. -/
theorem servers (config : Finset NodeID) {nodes : List NodeID}
    {state : Model.State}
    (reachable : (Model.transitionSystem config nodes).Reachable state)
    : state.nodes.map Prod.fst = nodes /\ nodes.Nodup := by
  let _ : Initial := ⟨config⟩
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (Model.transitionSystem config nodes) with
  | initial initialized => exact ⟨initialized.2.1, initialized.2.1 ▸ initialized.2.2.1⟩
  | @step before after action _ stepped ih =>
      cases action with
      | «local» actor input =>
          obtain ⟨_, _, _, _, _, rfl⟩ := Concrete.step_local stepped
          simpa [Concrete.replaceNode_keys] using ih
      | deliver envelope =>
          obtain ⟨_, _, _, _, _, _, rfl⟩ := Concrete.step_deliver stepped
          simpa [Concrete.replaceNode_keys] using ih

/-- `committedLog` is ccfraft.tla's `Committed(i)`, `SubSeq(log[i], 1, commitIndex[i])`:
`take` never truncates at the log's end, since the commit index lies within the log. -/
theorem committed_length (config : Finset NodeID) {nodes : List NodeID}
    {state : Model.State}
    (reachable : (Model.transitionSystem config nodes).Reachable state) {i : NodeID}
    {s : NodeState} (listed : (i, s) ∈ state.nodes)
    : s.committedLog.length = s.commitIndex := by
  let _ : Initial := ⟨config⟩
  have frontier := Direct.commitFrontier_invariant.reachable reachable i s listed
  simpa [NodeState.committedLog] using frontier.1

/-- `[]LogInv` over behaviours: the reachable-state claim covers every state of every
valid finite or infinite trace. -/
theorem log_inv_trace (config : Finset NodeID) {nodes : List NodeID}
    {trace : CCF.Execution.Trace Model.State}
    (valid : trace.Valid (Model.transitionSystem config nodes)) {state : Model.State}
    (member : state ∈ trace) {left right : NodeID} {leftState rightState : NodeState}
    (leftMember : (left, leftState) ∈ state.nodes)
    (rightMember : (right, rightState) ∈ state.nodes)
    : leftState.committedLog <+: rightState.committedLog
      \/ rightState.committedLog <+: leftState.committedLog :=
  PropertiesTLA.log_inv config nodes state left right leftState rightState
    ⟨valid.reachable member, leftMember, rightMember⟩

/-- `[][A]_vars` over behaviours: the step claim covers each adjacent pair of states of
every valid finite or infinite trace. -/
theorem committed_log_append_only_prop_trace (config : Finset NodeID)
    {nodes : List NodeID} {trace : CCF.Execution.Trace Model.State}
    (valid : trace.Valid (Model.transitionSystem config nodes)) {index : Nat}
    {before after : Model.State} (present : trace.get? index = some before)
    (next : trace.get? (index + 1) = some after) {node : NodeID}
    {nodeBefore nodeAfter : NodeState} (beforeMember : (node, nodeBefore) ∈ before.nodes)
    (afterMember : (node, nodeAfter) ∈ after.nodes)
    : nodeBefore.committedLog <+: nodeAfter.committedLog := by
  obtain ⟨action, stepped⟩ := valid.2 index before after present next
  exact PropertiesTLA.committed_log_append_only_prop config nodes before after action node
    nodeBefore nodeAfter
    ⟨valid.reachable (Stream'.Seq.get?_mem present), stepped, beforeMember, afterMember⟩

end Execution

end CCFRaft.Tests.PropertiesTLA
