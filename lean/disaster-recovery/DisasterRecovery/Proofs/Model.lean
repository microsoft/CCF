module

public import DisasterRecovery.Properties
public import DisasterRecovery.Proofs.History
public import DisasterRecovery.Proofs.Gossip

@[expose] public section

namespace DisasterRecovery.Proofs.Model

lemma quorum_opener_unique : Properties.QuorumOpenerUnique := by
  rintro config trace firstStep secondStep firstOpener secondOpener ⟨valid, first, second⟩
  obtain ⟨ghost, linked⟩ :=
    History.history_correspondence trace valid (firstStep + secondStep + 1)
  obtain ⟨firstState, firstMember, firstThreshold⟩ :=
    Gossip.quorum_notification_final_votes valid linked (by omega) first
  obtain ⟨secondState, secondMember, secondThreshold⟩ :=
    Gossip.quorum_notification_final_votes valid linked (by omega) second
  exact Observed.current_quorum_unique_of_thresholds linked.reachable
    (firstOpener, firstState) (secondOpener, secondState)
    firstMember secondMember firstThreshold secondThreshold

lemma quorum_open_preserves_commit : Properties.QuorumOpenPreservesCommit :=
  Gossip.quorum_open_preserves_commit

lemma full_gossip_preserves_commit : Properties.FullGossipPreservesCommit :=
  Gossip.full_gossip_preserves_commit

end DisasterRecovery.Proofs.Model
