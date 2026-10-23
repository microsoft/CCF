module

public import CCFRaft.Proofs.Safety.Commit

@[expose] public section

namespace CCFRaft.Proofs.Election

open Model.Node

theorem primary_eq_of_reachable [Config.InitialConfiguration]
    {nodes : List Model.Node.NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    {left right : Model.Node.NodeID} {leftState rightState : Model.Node.NodeState}
    (leftMember : (left, leftState) ∈ state.nodes)
    (rightMember : (right, rightState) ∈ state.nodes)
    (leftLeader : leftState.role = .primary) (rightLeader : rightState.role = .primary)
    (sameTerm : leftState.currentTerm = rightState.currentTerm)
    : left = right := by
  obtain ⟨history, _, inv⟩ := Safety.inv_of_reachable reachable
  have leftLed := inv.leader_led left leftState leftMember leftLeader
  rw [sameTerm] at leftLed
  exact inv.election_safety left right _ leftLed
    (inv.leader_led right rightState rightMember rightLeader)

theorem election_safety
    {config : Finset NodeID} {nodes : List NodeID}
    {trace : CCF.Execution.Trace Model.State} {state : Model.State}
    {left right : NodeID} {leftState rightState : NodeState}
    : (trace.Valid (Model.transitionSystem config nodes)
        /\ state ∈ trace
        /\ (left, leftState) ∈ state.nodes
        /\ (right, rightState) ∈ state.nodes
        /\ leftState.role = .primary
        /\ rightState.role = .primary)
      -> leftState.currentTerm = rightState.currentTerm
      -> left = right := by
  intro ⟨valid, member, leftMember, rightMember, leftLeader, rightLeader⟩ sameTerm
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact Proofs.Election.primary_eq_of_reachable (valid.reachable member)
    leftMember rightMember leftLeader rightLeader sameTerm

end CCFRaft.Proofs.Election
