-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Properties
import CCFRaft.Proofs.Invariant.Reachable
import CCFRaft.Proofs.Invariant.Safety

namespace CCFRaft.Proofs.Election

theorem election_safety : Properties.ElectionSafety := by
  intro Node TxId _ _ config nodes trace state left right leftState rightState
    ⟨valid, member, leftMember, rightMember, leftLeader, rightLeader, sameTerm⟩
  let _ : Model.Local.InitialConfig Node := config
  have reachable := valid.reachable member
  exact Invariant.inv_electionSafety (Invariant.reachable_inv reachable)
    leftMember rightMember leftLeader rightLeader sameTerm

end CCFRaft.Proofs.Election
