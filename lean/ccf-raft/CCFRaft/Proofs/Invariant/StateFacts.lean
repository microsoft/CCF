-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Safety
import CCFRaft.Proofs.Invariant.NodeFacts
import CCFRaft.Proofs.Ledger

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Model.Local (
  BOOTSTRAP_TERM Bootstrap Configuration Entry EntryContent INITIAL_CONFIGURATION
    INITIAL_LEADER INITIAL_PRE_VOTE_STATUS MembershipState NodeState PreVoteStatus Role
    activeConfigurations activeNodeUnion allConfigurations allRetiredCommittedNodes
    becomeCandidateNodeState campaignEligible configurationsInLog configurationsInLogFrom
    currentConfiguration currentConfigurationAt entryAt? findHighestPossibleMatch
    hasConfigurationMajority highestActiveConfigurationWithNode implicitConfiguration
    initialNodeState isSignatureAt lastCommittableIndex lastCommittableTerm
    latestConfiguration maxCommittableIndex maxCommittableIndexUpTo maxCommittableTerm
    messageEntries refreshRetirementState retiredCommittedIndexFrom
    retiredCommittedIndexInLog retiredCommittedNodesUpTo retiredCommittedNodesUpToFrom
    retirementCommittableIndexInLog retirementCompletedNodes
    retirementIndexFromConfigurations retirementIndexInLog signatureIndexAfterFrom termAt
    updateIndex
  )
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

open Shared Shared.MultiNodeTransitionSystem Concrete

theorem mem_foldl_union {P : Configuration Node -> Prop} [DecidablePred P]
    (configurations : List (Configuration Node)) (init : Finset Node) (member : Node)
    (found
      : member
        ∈ configurations.foldl
            (fun nodes configuration =>
              if P configuration then nodes ∪ configuration.nodes else nodes)
            init)
    : member ∈ init
      \/ ∃ configuration ∈ configurations, member ∈ configuration.nodes := by
  induction configurations generalizing init with
  | nil => exact Or.inl found
  | cons head tail ih =>
      rcases ih _ found with inner | ⟨configuration, listed, inside⟩
      · by_cases chosen : P head
        · simp only [chosen, ite_true, Finset.mem_union] at inner
          rcases inner with old | here
          · exact Or.inl old
          · exact Or.inr ⟨head, by simp, here⟩
        · simp only [chosen, ite_false] at inner
          exact Or.inl inner
      · exact Or.inr ⟨configuration, by simp [listed], inside⟩

theorem retirementCompletedNodes_configured {log : List (Entry Node TxId)}
    {commitIndex : Nat} {member : Node}
    (found : member ∈ retirementCompletedNodes log commitIndex)
    : ∃ configuration ∈ allConfigurations log, member ∈ configuration.nodes := by
  unfold retirementCompletedNodes at found
  simp only [Finset.mem_filter, Finset.mem_sdiff] at found
  rcases mem_foldl_union _ _ _ found.1.1.1 with empty | configured
  · simp at empty
  · exact configured

theorem initialNodeState_of_not_mem {node : Node} (absent : node ∉ INITIAL_CONFIGURATION)
    : (initialNodeState node : NodeState Node TxId) = freshNodeState := by
  have notLeader : Not (node = INITIAL_LEADER) := by
    rintro rfl
    exact absent (Bootstrap.leader_mem)
  simp [initialNodeState, freshNodeState, absent, notLeader]

theorem observeTerm_eq_updateTerm (state : NodeState Node TxId)
    (message : Model.Local.Message Node TxId)
    : Model.Local.observeTerm state message = state
      \/ (Model.Local.observeTerm state message
            = Model.Local.updateTerm state message.term
          /\ state.currentTerm < message.term
          /\ (forall term, Not (message = .proposeVoteRequest term))
          /\ (forall response,
                message = .appendEntriesResponse response -> state.role = .leader)) := by
  have update : forall term, Model.Local.updateTerm state term = state \/
      (state.currentTerm < term) := by
    intro term
    unfold Model.Local.updateTerm
    split_ifs with newer
    · exact Or.inr newer
    · exact Or.inl rfl
  cases message
  case proposeVoteRequest term => exact Or.inl rfl
  case appendEntriesResponse response =>
    by_cases leader : state.role = .leader
    · rcases update response.term with same | newer
      · left
        simp [Model.Local.observeTerm, leader, same]
      · right
        refine ⟨by simp [Model.Local.observeTerm, leader, Model.Local.Message.term], newer,
          by simp, fun _ _ => leader⟩
    · left
      simp [Model.Local.observeTerm, leader]
  case appendEntriesRequest payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestVoteRequest payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestVoteResponse payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestPreVote payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestPreVoteResponse payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩

theorem StateInvariant.joinedCarriers {state : Model.State Node TxId}
    {joined : Finset Node} (invariant : StateInvariant state joined)
    : JoinedCarrierFacts (joined := joined) state := by
  obtain ⟨_, _, _, _, _, _, facts⟩ := invariant.safety
  exact facts.joinedCarriers

theorem StateInvariant.joined_of_role {state : Model.State Node TxId}
    {joined : Finset Node} (invariant : StateInvariant state joined) {node : Node}
    (active : (nodeOf state node).role ≠ .none)
    : node ∈ joined := by
  by_contra absent
  have outside : node ∉ INITIAL_CONFIGURATION := fun member => absent (invariant.initialJoined member)
  rw [invariant.unjoined node absent, initialNodeState_of_not_mem outside] at active
  exact active rfl

theorem StateInvariant.activeJoined {state : Model.State Node TxId} {joined : Finset Node}
    (invariant : StateInvariant state joined) {node member : Node}
    (active : member ∈ activeNodeUnion (nodeOf state node))
    : member ∈ joined :=
  invariant.joinedCarriers.activeNodes node active

theorem StateInvariant.retiredJoined {state : Model.State Node TxId}
    {joined : Finset Node} (invariant : StateInvariant state joined) {node member : Node}
    (retired : member ∈ (nodeOf state node).retirementCompleted)
    : member ∈ joined := by
  obtain ⟨configuration, listed, member⟩ := retirementCompletedNodes_configured retired
  exact invariant.joinedCarriers.configurationNodes node configuration listed member

theorem StateInvariant.update {state : Model.State Node TxId} {joined : Finset Node}
    (invariant : StateInvariant state joined)
    {node : Node} {value : NodeState Node TxId}
    {network : List (Model.Envelope Node TxId)} {joined' : Finset Node}
    (nodeJoined : node ∈ joined) (mono : joined ⊆ joined')
    (safety
      : SystemInductiveInvariant (joined := joined')
          { state with nodes := replaceNode state.nodes node value, network })
    (endpoints
      : forall envelope,
          envelope ∈ network -> envelope.source ∈ joined' /\ envelope.target ∈ joined')
    : StateInvariant
        { state with nodes := replaceNode state.nodes node value, network } joined' where
  safety := safety
  distinct := by simpa [replaceNode_keys] using invariant.distinct
  initialJoined := Finset.Subset.trans invariant.initialJoined mono
  unjoined := by
    intro member absent
    have different : member ≠ node := by
      rintro rfl
      exact absent (mono nodeJoined)
    change nodeOf { state with nodes := replaceNode state.nodes node value } member = _
    rw [nodeOf_replaceNode_other state node member value different]
    exact invariant.unjoined member (fun old => absent (mono old))
  endpoints := endpoints

theorem StateInvariant.sentEndpoints {state : Model.State Node TxId}
    {joined joined' : Finset Node} (invariant : StateInvariant state joined)
    (mono : joined ⊆ joined') {sends : List (Model.Envelope Node TxId)}
    (sent
      : forall envelope,
          envelope ∈ sends -> envelope.source ∈ joined' /\ envelope.target ∈ joined')
    : forall envelope,
        envelope ∈ state.network ++ sends
        -> envelope.source ∈ joined' /\ envelope.target ∈ joined' := by
  intro envelope member
  rcases List.mem_append.mp member with old | outgoing
  · obtain ⟨source, target⟩ := invariant.endpoints envelope old
    exact ⟨mono source, mono target⟩
  · exact sent envelope outgoing

theorem StateInvariant.erasedEndpoints {state : Model.State Node TxId}
    {joined : Finset Node} (invariant : StateInvariant state joined)
    (selected : Model.Envelope Node TxId)
    : forall envelope,
        envelope ∈ removeOne selected state.network
        -> envelope.source ∈ joined /\ envelope.target ∈ joined := by
  intro envelope member
  rw [removeOne_eq_list_erase] at member
  exact invariant.endpoints envelope (List.mem_of_mem_erase member)

end CCFRaft.Proofs.Invariant
