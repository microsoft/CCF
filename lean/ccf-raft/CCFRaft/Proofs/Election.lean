module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Proofs.Safety.Commit

@[expose] public section

namespace CCFRaft.Proofs.Election

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

end CCFRaft.Proofs.Election
