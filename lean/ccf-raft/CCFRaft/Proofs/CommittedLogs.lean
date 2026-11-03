module

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
    {nodes : List Model.Node.NodeID}
    {trace
      : CCF.Execution.Trace (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes)}
    {earlierIndex laterIndex : Nat} {earlier later : Model.State}
    {earlierNode laterNode : Model.Node.NodeID}
    {earlierState laterState : Model.Node.NodeState}
    (ordered : earlierIndex <= laterIndex)
    (earlierFound : trace.stateAt earlierIndex = some earlier)
    (laterFound : trace.stateAt laterIndex = some later)
    (earlierMember : (earlierNode, earlierState) ∈ earlier.nodes)
    (laterMember : (laterNode, laterState) ∈ later.nodes)
    : earlierState.committedLog <+: laterState.committedLog
      \/ laterState.committedLog <+: earlierState.committedLog := by
  obtain ⟨carried, carriedMember, grown⟩ :=
    Direct.committed_log_later earlierFound earlierMember (laterIndex - earlierIndex)
      later (by rwa [Nat.add_sub_cancel' ordered])
  obtain ⟨history, exec⟩ :=
    Safety.exec_of_reachable (trace.reachable (CCF.Execution.Trace.stateAt_mem laterFound))
  rcases Safety.committed_logs_comparable exec carriedMember laterMember with
    carriedFirst | laterFirst
  · exact Or.inl (grown.trans carriedFirst)
  · exact List.prefix_or_prefix_of_prefix grown laterFirst

theorem committed_logs_prefix
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID)
              (trace : CCF.Execution.Trace (Model.transitionSystem config nodes)),
      forall (stateA stateB : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (stateA ∈ trace
          /\ stateB ∈ trace
          /\ (left, leftState) ∈ stateA.nodes
          /\ (right, rightState) ∈ stateB.nodes)
        -> leftState.committedLog <+: rightState.committedLog
            \/ rightState.committedLog <+: leftState.committedLog := by
  intro config nodes trace stateA stateB left right leftState rightState
    ⟨memberA, memberB, leftMember, rightMember⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  obtain ⟨indexA, foundA⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp memberA
  obtain ⟨indexB, foundB⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp memberB
  rcases Nat.le_total indexA indexB with ordered | ordered
  · exact Proofs.CommittedLogs.committed_logs_prefix_of_le ordered
      foundA.symm foundB.symm leftMember rightMember
  · exact (Proofs.CommittedLogs.committed_logs_prefix_of_le ordered
      foundB.symm foundA.symm rightMember leftMember).symm

end CCFRaft.Proofs.CommittedLogs
