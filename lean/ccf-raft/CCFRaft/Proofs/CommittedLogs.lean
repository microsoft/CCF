module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Proofs.Direct.AppendOnly
public import CCFRaft.Proofs.Safety.Commit

@[expose] public section

/-!
Committed logs anywhere in a trace are prefix-comparable. Carry the earlier
state's node forward to the later state, where its committed log has only
grown, then compare the two nodes' committed logs in that one state.
-/

namespace CCFRaft.Proofs.CommittedLogs

open CCFRaft.Proofs.Config

theorem committed_logs_prefix_of_le [Config.InitialConfiguration]
    {nodes : List Model.Node.NodeID} {trace : CCF.Execution.Trace Model.State}
    (valid : trace.Valid (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes))
    {earlierIndex laterIndex : Nat} {earlier later : Model.State}
    {earlierNode laterNode : Model.Node.NodeID}
    {earlierState laterState : Model.Node.NodeState}
    (ordered : earlierIndex <= laterIndex)
    (earlierFound : trace.get? earlierIndex = some earlier)
    (laterFound : trace.get? laterIndex = some later)
    (earlierMember : (earlierNode, earlierState) ∈ earlier.nodes)
    (laterMember : (laterNode, laterState) ∈ later.nodes)
    : earlierState.committedLog <+: laterState.committedLog
      \/ laterState.committedLog <+: earlierState.committedLog := by
  obtain ⟨carried, carriedMember, grown⟩ :=
    Direct.committed_log_later valid earlierFound earlierMember (laterIndex - earlierIndex)
      later (by rwa [Nat.add_sub_cancel' ordered])
  obtain ⟨history, exec⟩ :=
    Safety.exec_of_reachable (valid.reachable (Stream'.Seq.get?_mem laterFound))
  rcases Safety.committed_logs_comparable exec carriedMember laterMember with
    carriedFirst | laterFirst
  · exact Or.inl (grown.trans carriedFirst)
  · exact List.prefix_or_prefix_of_prefix grown laterFirst

end CCFRaft.Proofs.CommittedLogs
