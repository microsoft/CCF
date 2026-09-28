import DisasterRecovery.Properties
import DisasterRecovery.Proofs.History
import DisasterRecovery.Proofs.Gossip

namespace DisasterRecovery.Proofs.Model

lemma quorum_opener_unique : Properties.QuorumOpenerUnique := by
  rintro config trace firstStep secondStep firstOpener secondOpener ⟨valid, first, second⟩
  obtain ⟨_, _, ghost, _, _, _, linked⟩ := History.history_correspondence trace valid
  obtain ⟨firstState, firstMember, firstThreshold⟩ :=
    Gossip.quorum_notification_final_votes valid linked first
  obtain ⟨secondState, secondMember, secondThreshold⟩ :=
    Gossip.quorum_notification_final_votes valid linked second
  exact Observed.current_quorum_unique_of_thresholds linked.reachable
    (firstOpener, firstState) (secondOpener, secondState)
    firstMember secondMember firstThreshold secondThreshold

lemma quorum_open_preserves_commit : Properties.QuorumOpenPreservesCommit :=
  Gossip.quorum_open_preserves_commit

lemma full_gossip_preserves_commit : Properties.FullGossipPreservesCommit :=
  Gossip.full_gossip_preserves_commit

end DisasterRecovery.Proofs.Model
