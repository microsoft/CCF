module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Properties
public import CCFRaft.Proofs.Safety.Commit

@[expose] public section

namespace CCFRaft.Proofs.Election

theorem election_safety : Properties.ElectionSafety := by
  intro config nodes trace state left right leftState rightState
    ⟨valid, member, leftMember, rightMember, leftLeader, rightLeader, sameTerm⟩
  let _ : Config.InitialConfiguration := ⟨config⟩
  obtain ⟨history, _, inv⟩ := Safety.inv_of_reachable (valid.reachable member)
  have leftLed := inv.leader_led left leftState leftMember leftLeader
  rw [sameTerm] at leftLed
  exact inv.election_safety left right _ leftLed
    (inv.leader_led right rightState rightMember rightLeader)

end CCFRaft.Proofs.Election
