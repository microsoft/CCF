import DisasterRecovery.Properties
import DisasterRecovery.Proofs.History
import DisasterRecovery.Proofs.Gossip

namespace DisasterRecovery.Proofs.Model

lemma full_gossip_selection_preserves_commit : Properties.FullGossipSelectionPreservesCommit := by
  intro config history opener committed valid full durable
  obtain ⟨ghost, linked⟩ := History.history_correspondence history valid
  obtain ⟨edge, output, member, observed, sent, complete⟩ := full
  have ghostFull : Predicates.FullGossipSelection config ghost opener :=
    ⟨{ source := output.node, target := opener, payload := .vote, sourceState := output.before },
      linked.output_sent member observed sent, rfl, rfl, complete⟩
  exact Committed.full_gossip_selection_preserves_commit linked.reachable ghostFull durable

lemma quorum_opener_unique : Properties.QuorumOpenerUnique := by
  intro config history valid firstEdge secondEdge members
    firstOutput secondOutput observed firstEffect secondEffect
  obtain ⟨firstMember, secondMember⟩ := members
  obtain ⟨firstObserved, secondObserved⟩ := observed
  obtain ⟨ghost, linked⟩ := History.history_correspondence history valid
  have same := Quorum.quorum_opener_unique linked.reachable
    ⟨_, linked.openings firstEdge firstMember firstOutput firstObserved .quorum firstEffect,
      rfl, rfl⟩
    ⟨_, linked.openings secondEdge secondMember secondOutput secondObserved .quorum secondEffect,
      rfl, rfl⟩
  exact firstObserved.1.trans (same.trans secondObserved.1.symm)

lemma quorum_open_preserves_commit : Properties.QuorumOpenPreservesCommit :=
  Gossip.quorum_open_preserves_commit

end DisasterRecovery.Proofs.Model
