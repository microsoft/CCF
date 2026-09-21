import DisasterRecovery.Properties
import DisasterRecovery.Proofs.History
import DisasterRecovery.Proofs.Observed

namespace DisasterRecovery.Proofs.Model

open DisasterRecovery.Model.Local
open Properties.Helpers

theorem reachable_history {config : DisasterRecovery.Model.Config}
    {state : DisasterRecovery.Model.State}
    (reachable : DisasterRecovery.Model.Reachable config state) :
    Nonempty (Properties.History.History config state) := by
  induction reachable with
  | initial initialized => exact ⟨⟨_, [], initialized, .nil _⟩⟩
  | @step before after action reachable transition ih =>
      obtain ⟨history⟩ := ih
      exact ⟨⟨history.initial,
        history.steps ++ [{ before, action, after }],
        history.initialized, history.valid.append (.cons transition (.nil _))⟩⟩

lemma reachable_well_formed {config : DisasterRecovery.Model.Config}
    {state : DisasterRecovery.Model.State}
    (reachable : DisasterRecovery.Model.Reachable config state) :
    WellFormed config state := by
  obtain ⟨execution, ghostReachable, projection⟩ := Lifting.model_reachable_lifts reachable
  have wf := Invariants.reachable_well_formed ghostReachable
  subst state
  refine {
    nodeKeys := wf.nodeKeys
    nodeKeysNodup := wf.nodeKeysNodup
    nodeLocations := wf.nodeLocations
    activeNodup := wf.activeNodup
    activeConfigured := wf.activeConfigured
    networkSourceActive := ?_
    history := History.history_well_formed
  }
  intro envelope member
  rcases List.mem_map.mp member with ⟨sent, pending, rfl⟩
  exact wf.sentSourceActive sent (wf.networkSent sent pending)

lemma reachable_quorum_invariant {config : DisasterRecovery.Model.Config}
    {state : DisasterRecovery.Model.State}
    (reachable : DisasterRecovery.Model.Reachable config state) :
    QuorumInvariant config state := by
  obtain ⟨execution, ghostReachable, projection⟩ := Lifting.model_reachable_lifts reachable
  have wf := Invariants.reachable_well_formed ghostReachable
  have invariant := Quorum.reachable_quorum_invariant ghostReachable
  subst state
  refine {
    votesNodup := invariant.votesNodup
    votesConfigured := ?_
    quorumThreshold := Observed.reachable_quorum_thresholds ghostReachable
    history := History.history_quorum_invariant
  }
  intro entry member voter vote
  obtain ⟨sent, sentMember, source, _, _⟩ := invariant.votesSent entry member voter vote
  exact wf.activeConfigured voter
    (by simpa [source] using wf.sentSourceActive sent sentMember)

lemma quorum_opener_unique {config : DisasterRecovery.Model.Config}
    {state : DisasterRecovery.Model.State} {first second : Location}
    (reachable : DisasterRecovery.Model.Reachable config state)
    (firstOpened : QuorumOpened state first)
    (secondOpened : QuorumOpened state second) :
    first = second := by
  obtain ⟨execution, ghostReachable, projection⟩ := Lifting.model_reachable_lifts reachable
  rcases firstOpened with ⟨firstState, firstMember, firstKind⟩
  rcases secondOpened with ⟨secondState, secondMember, secondKind⟩
  subst state
  exact Observed.current_quorum_unique ghostReachable
    (first, firstState) (second, secondState) firstMember secondMember firstKind secondKind

lemma full_gossip_selection_preserves_commit
    {config : DisasterRecovery.Model.Config} {state : DisasterRecovery.Model.State}
    {opener : Location} {committed : TxID}
    (history : Properties.History.History config state)
    (full : Properties.History.FullGossipSelection history opener)
    (durable : DurableCommit config committed) :
    exists recovered,
      DisasterRecovery.Model.recoveredTxID config opener = some recovered /\
      TxID.EarlierThan committed recovered := by
  obtain ⟨ghost, linked⟩ := History.history_correspondence history
  obtain ⟨voter, sourceState, sent, complete⟩ := full
  have ghostFull : Predicates.FullGossipSelection config ghost opener :=
    ⟨{ source := voter, target := opener, payload := .vote, sourceState },
      (linked.sent _).mpr sent, rfl, rfl, complete⟩
  exact Committed.full_gossip_selection_preserves_commit linked.reachable ghostFull durable

lemma quorum_history_opener_unique
    {config : DisasterRecovery.Model.Config} {state : DisasterRecovery.Model.State}
    {first second : Location}
    (history : Properties.History.History config state)
    (firstOpened : Properties.History.QuorumOpened history first)
    (secondOpened : Properties.History.QuorumOpened history second) :
    first = second := by
  obtain ⟨ghost, linked⟩ := History.history_correspondence history
  obtain ⟨firstEdge, firstMember, firstNode, firstOutput, firstObserved, firstEffect⟩ := firstOpened
  obtain ⟨secondEdge, secondMember, secondNode, secondOutput, secondObserved, secondEffect⟩ := secondOpened
  exact Quorum.quorum_opener_unique linked.reachable
    ⟨_, linked.openings firstEdge firstMember firstOutput firstObserved .quorum firstEffect,
      firstNode, rfl⟩
    ⟨_, linked.openings secondEdge secondMember secondOutput secondObserved .quorum secondEffect,
      secondNode, rfl⟩

lemma quorum_open_preserves_commit : Properties.QuorumOpenPreservesCommit := by
  intro config state opener committed history _opened full durable
  exact full_gossip_selection_preserves_commit history full durable

end DisasterRecovery.Proofs.Model
