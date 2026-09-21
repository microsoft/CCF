import DisasterRecovery.Properties
import DisasterRecovery.Proofs.Local
import DisasterRecovery.Proofs.Model

namespace DisasterRecovery.Proof

theorem gossip_freezes_after_choice : Properties.GossipFreezesAfterChoice :=
  Proofs.Local.gossip_freezes_after_choice

theorem rejected_gossip_stutters : Properties.RejectedGossipStutters :=
  Proofs.Local.rejected_gossip_stutters

theorem quorum_advance_opens : Properties.QuorumAdvanceOpens :=
  Proofs.Local.quorum_advance_opens

theorem aligned_opening_timeout_completes : Properties.AlignedOpeningTimeoutCompletes :=
  Proofs.Local.aligned_opening_timeout_completes

theorem reachable_well_formed : Properties.ReachableWellFormed :=
  Proofs.Model.reachable_well_formed

theorem reachable_quorum_invariant : Properties.ReachableQuorumInvariant :=
  Proofs.Model.reachable_quorum_invariant

theorem quorum_opener_unique : Properties.QuorumOpenerUnique :=
  Proofs.Model.quorum_opener_unique

theorem quorum_history_opener_unique : Properties.QuorumHistoryOpenerUnique :=
  Proofs.Model.quorum_history_opener_unique

theorem full_gossip_selection_preserves_commit : Properties.FullGossipSelectionPreservesCommit :=
  Proofs.Model.full_gossip_selection_preserves_commit

theorem quorum_open_preserves_commit : Properties.QuorumOpenPreservesCommit :=
  Proofs.Model.quorum_open_preserves_commit

end DisasterRecovery.Proof
