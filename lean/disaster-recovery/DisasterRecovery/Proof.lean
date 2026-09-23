import DisasterRecovery.Properties
import DisasterRecovery.Proofs.Local
import DisasterRecovery.Proofs.Model
import DisasterRecovery.Proofs.Witnesses

namespace DisasterRecovery.Proof

theorem gossip_freezes_after_choice : Properties.GossipFreezesAfterChoice :=
  Proofs.Local.gossip_freezes_after_choice

theorem rejected_gossip_stutters : Properties.RejectedGossipStutters :=
  Proofs.Local.rejected_gossip_stutters

theorem quorum_advance_opens : Properties.QuorumAdvanceOpens :=
  Proofs.Local.quorum_step_opens

theorem aligned_opening_timeout_completes : Properties.AlignedOpeningTimeoutCompletes :=
  Proofs.Local.aligned_opening_timeout_completes

theorem quorum_opener_unique : Properties.QuorumOpenerUnique :=
  Proofs.Model.quorum_opener_unique

theorem full_gossip_preserves_commit : Properties.FullGossipPreservesCommit :=
  Proofs.Model.full_gossip_preserves_commit

theorem quorum_open_preserves_commit : Properties.QuorumOpenPreservesCommit :=
  Proofs.Model.quorum_open_preserves_commit

theorem gossip_freezes_after_choice_witness : Properties.GossipFreezesAfterChoiceWitness :=
  Proofs.Witnesses.gossip_freezes_after_choice_witness

theorem rejected_gossip_stutters_witness : Properties.RejectedGossipStuttersWitness :=
  Proofs.Witnesses.rejected_gossip_stutters_witness

theorem quorum_advance_opens_witness : Properties.QuorumAdvanceOpensWitness :=
  Proofs.Witnesses.quorum_advance_opens_witness

theorem aligned_opening_timeout_completes_witness
    : Properties.AlignedOpeningTimeoutCompletesWitness :=
  Proofs.Witnesses.aligned_opening_timeout_completes_witness

theorem quorum_opener_unique_witness : Properties.QuorumOpenerUniqueWitness :=
  Proofs.Witnesses.quorum_opener_unique_witness

theorem quorum_open_preserves_commit_witness : Properties.QuorumOpenPreservesCommitWitness :=
  Proofs.Witnesses.quorum_open_preserves_commit_witness

theorem full_gossip_preserves_commit_witness : Properties.FullGossipPreservesCommitWitness :=
  Proofs.Witnesses.full_gossip_preserves_commit_witness

end DisasterRecovery.Proof
