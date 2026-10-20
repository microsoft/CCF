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

/-- `Servers`: every reachable state holds each configured node exactly once. -/
theorem servers (config : Model.ModelConfig) {nodes : List NodeID}
    {state : Model.State}
    (reachable : (Model.transitionSystem config nodes).Reachable state)
    : state.nodes.map Prod.fst = nodes /\ nodes.Nodup := by
  let _ : Model.ModelConfig := config
  induction reachable with
  | initial initialized => exact ⟨initialized.1, initialized.1 ▸ initialized.2.1⟩
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
theorem committed_length (config : Model.ModelConfig) {nodes : List NodeID}
    {state : Model.State}
    (reachable : (Model.transitionSystem config nodes).Reachable state) {i : NodeID}
    {s : NodeState} (listed : (i, s) ∈ state.nodes)
    : s.committedLog.length = s.commitIndex := by
  let _ : Model.ModelConfig := config
  have frontier := Direct.commitFrontier_invariant.reachable reachable i s listed
  simpa [NodeState.committedLog] using frontier.1

end Execution

end CCFRaft.Tests.PropertiesTLA
