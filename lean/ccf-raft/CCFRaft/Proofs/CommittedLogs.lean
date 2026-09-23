-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Direct.AppendOnly
import CCFRaft.Proofs.Invariant.Reachable

set_option autoImplicit false

/-!
Committed logs anywhere in a trace are prefix-comparable. Carry the earlier
state's node forward to the later state, where its committed log has only
grown, then compare the two nodes' committed logs in that one state.
-/

namespace CCFRaft.Proofs.CommittedLogs

theorem committed_logs_prefix : Properties.CommittedLogsPrefix := by
  intro Node TxId _ _ _ nodes trace first second left right leftState rightState
    ⟨valid, firstMember, secondMember, leftMember, rightMember⟩
  obtain ⟨firstIndex, atFirst⟩ := List.mem_iff_getElem?.mp firstMember
  obtain ⟨secondIndex, atSecond⟩ := List.mem_iff_getElem?.mp secondMember
  /- Move the node of the earlier state to the later state, then compare there. -/
  have across : forall {earlierIndex laterIndex : Nat} {earlier later}
      {earlierNode laterNode : Node} {earlierState laterState : Model.Local.NodeState Node TxId},
      earlierIndex <= laterIndex
      -> trace.states[earlierIndex]? = some earlier
      -> trace.states[laterIndex]? = some later
      -> (earlierNode, earlierState) ∈ earlier.nodes
      -> (laterNode, laterState) ∈ later.nodes
      -> earlierState.committedLog <+: laterState.committedLog
          \/ laterState.committedLog <+: earlierState.committedLog := by
    intro earlierIndex laterIndex earlier later earlierNode laterNode earlierState laterState
      ordered atEarlier atLater earlierMember laterMember
    obtain ⟨carried, carriedMember, grown⟩ :=
      Direct.committed_log_later valid atEarlier earlierMember (laterIndex - earlierIndex) later
        (by rwa [Nat.add_sub_cancel' ordered])
    have reachable := valid.reachable (List.mem_of_getElem? atLater)
    rcases Invariant.inv_committedLogsPrefix (Invariant.reachable_inv reachable)
        (Direct.keys_nodup reachable) carriedMember laterMember with
      carriedFirst | laterFirst
    · exact Or.inl (grown.trans carriedFirst)
    · exact List.prefix_or_prefix_of_prefix grown laterFirst
  rcases Nat.le_total firstIndex secondIndex with ordered | ordered
  · exact across ordered atFirst atSecond leftMember rightMember
  · exact (across ordered atSecond atFirst rightMember leftMember).symm

end CCFRaft.Proofs.CommittedLogs
