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

open Model.Node

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

theorem committed_logs_prefix
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : CCF.Execution.Trace Model.State),
      forall (first second : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ first ∈ trace
          /\ second ∈ trace
          /\ (left, leftState) ∈ first.nodes
          /\ (right, rightState) ∈ second.nodes)
        -> leftState.committedLog <+: rightState.committedLog
            \/ rightState.committedLog <+: leftState.committedLog := by
  intro config nodes trace first second left right leftState rightState
    ⟨valid, firstMember, secondMember, leftMember, rightMember⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  obtain ⟨firstIndex, firstFound⟩ := Stream'.Seq.mem_iff_exists_get?.mp firstMember
  obtain ⟨secondIndex, secondFound⟩ := Stream'.Seq.mem_iff_exists_get?.mp secondMember
  rcases Nat.le_total firstIndex secondIndex with ordered | ordered
  · exact Proofs.CommittedLogs.committed_logs_prefix_of_le valid ordered
      firstFound.symm secondFound.symm leftMember rightMember
  · exact (Proofs.CommittedLogs.committed_logs_prefix_of_le valid ordered
      secondFound.symm firstFound.symm rightMember leftMember).symm

end CCFRaft.Proofs.CommittedLogs
