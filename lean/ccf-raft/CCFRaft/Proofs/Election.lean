module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Properties
public import CCFRaft.Proofs.Invariant.Reachable
public import CCFRaft.Proofs.Invariant.Safety

@[expose] public section

namespace CCFRaft.Proofs.Election

theorem election_safety : Properties.ElectionSafety := by
  intro Node TxId _ _ config nodes trace state left right leftState rightState
    ⟨valid, member, leftMember, rightMember, leftLeader, rightLeader, sameTerm⟩
  let _ : Model.Node.InitialConfig Node := config
  have reachable := valid.reachable member
  exact Invariant.inv_electionSafety (Invariant.reachable_inv reachable)
    leftMember rightMember leftLeader rightLeader sameTerm

end CCFRaft.Proofs.Election
