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

theorem committed_logs_prefix : Properties.CommittedLogsPrefix := by
  intro config nodes trace first second left right leftState rightState
    ⟨valid, firstMember, secondMember, leftMember, rightMember⟩
  let _ : Config.InitialConfiguration := ⟨config⟩
  obtain ⟨firstIndex, firstFound⟩ := Stream'.Seq.mem_iff_exists_get?.mp firstMember
  obtain ⟨secondIndex, secondFound⟩ := Stream'.Seq.mem_iff_exists_get?.mp secondMember
  /- Move the node of the earlier state to the later state, then compare there. -/
  have across : forall {earlierIndex laterIndex : Nat} {earlier later : Model.State}
      {earlierNode laterNode : Model.Node.NodeID}
      {earlierState laterState : Model.Node.NodeState},
      earlierIndex <= laterIndex
      -> trace.get? earlierIndex = some earlier
      -> trace.get? laterIndex = some later
      -> (earlierNode, earlierState) ∈ earlier.nodes
      -> (laterNode, laterState) ∈ later.nodes
      -> earlierState.committedLog <+: laterState.committedLog
          \/ laterState.committedLog <+: earlierState.committedLog := by
    intro earlierIndex laterIndex earlier later earlierNode laterNode earlierState laterState
      ordered earlierFound laterFound earlierMember laterMember
    obtain ⟨carried, carriedMember, grown⟩ :=
      Direct.committed_log_later valid earlierFound earlierMember (laterIndex - earlierIndex)
        later (by rwa [Nat.add_sub_cancel' ordered])
    obtain ⟨history, exec⟩ :=
      Safety.exec_of_reachable (valid.reachable (Stream'.Seq.get?_mem laterFound))
    rcases Safety.committed_logs_comparable exec carriedMember laterMember with
      carriedFirst | laterFirst
    · exact Or.inl (grown.trans carriedFirst)
    · exact List.prefix_or_prefix_of_prefix grown laterFirst
  rcases Nat.le_total firstIndex secondIndex with ordered | ordered
  · exact across ordered firstFound.symm secondFound.symm leftMember rightMember
  · exact (across ordered secondFound.symm firstFound.symm rightMember leftMember).symm

end CCFRaft.Proofs.CommittedLogs
