-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Local
import CCFRaft.Proofs.Invariant.StateFacts
import CCFRaft.Proofs.Direct.CommitFrontier

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open Shared Concrete
open Model.Local

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]


@[simp]
theorem replaceNode_twice (nodes : List (Node × NodeState Node TxId)) (node : Node)
    (first second : NodeState Node TxId)
    : replaceNode (replaceNode nodes node first) node second = replaceNode nodes node second := by
  unfold replaceNode
  rw [List.map_map]
  apply List.map_congr_left
  intro entry _
  by_cases same : entry.1 = node <;> simp [same]

theorem advanced_eq (state : Model.State Node TxId) (node : Node)
    (present : node ∈ state.nodes.map Prod.fst)
    : demoteRetiredCommitted (advanceCommitState state node) node
      = { state with
        nodes := replaceNode state.nodes node
          (Model.Local.demoteRetiredCommitted (Model.Local.advanceCommit (nodeOf state node) node)) } := by
  simp only [demoteRetiredCommitted, advanceCommitState, nodeOf_replaceNode, present, ite_true,
    replaceNode_twice]

theorem refresh_sentIndex (node : Node) (value : NodeState Node TxId)
    (sentIndex : Node -> Nat)
    : { refreshRetirementState node value with sentIndex }
      = refreshRetirementState node { value with sentIndex } :=
  rfl

set_option hygiene false in
macro "extract_guard" : tactic =>
  `(tactic| (
    simp only [Model.Local.act, guard, bind, Option.bind] at acted
    split at acted
    · simp at acted
    rename_i _ _ _ condition
    have enabled := guard_holds condition
    have acted := Option.some.inj acted
    subst acted
    simp only [Direct.run_pure, Direct.run_send, List.nil_append,
      List.append_nil]))

/-- Preserve the invariant under the node update and sends of an internal input. -/
theorem act_preserves {state : Model.State Node TxId} {joinedNodes : Finset Node} (invariant : StateInvariant state joinedNodes)
    {node : Node}
    (present : node ∈ state.nodes.map Prod.fst) {input : Model.Local.Input Node TxId}
    {execute : Model.Local.NodeEffect Node TxId (NodeState Node TxId)}
    (acted
      : Model.Local.act (Capabilities.record node) node ((nodeOf state) node) input
        = some execute)
    : ∃ joined,
        StateInvariant
          { state with
            nodes := replaceNode state.nodes node (execute.run {}).1
            network := state.network ++ (execute.run {}).2.outgoing } joined := by
  cases input with
  | initializeConfiguration =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.2.1]; decide)
      refine ⟨
        joinedNodes,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState]
        using initializeConfigurationPreservesSystemInductiveInvariant
          state node (present := present) invariant.safety ⟨enabled.1, joined, enabled.2⟩
  | clientRequest txId =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        joinedNodes,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState, Model.Local.appendEntry]
        using clientRequestPreservesSystemInductiveInvariant state node (present := present) txId
          invariant.safety ⟨joined, enabled⟩
  | changeConfiguration configuration =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      let added := configuration \ (latestConfiguration ((nodeOf state) node)).nodes
      refine ⟨joinedNodes ∪ added,
        invariant.update joined Finset.subset_union_left ?_ ?_⟩
      · simpa only [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState, Model.Local.appendEntry, added, refresh_sentIndex]
          using changeConfigurationPreservesSystemInductiveInvariant state node (present := present)
            configuration invariant.safety ⟨joined, enabled⟩
      · intro message member
        obtain ⟨source, target⟩ := invariant.endpoints message member
        exact ⟨Finset.mem_union_left _ source, Finset.mem_union_left _ target⟩
  | appendRetiredCommitted =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        joinedNodes,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState, Model.Local.appendEntry, allRetiredCommittedNodes]
        using appendRetiredCommittedPreservesSystemInductiveInvariant state node (present := present)
          invariant.safety ⟨joined, enabled⟩
  | signCommittableMessages =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        joinedNodes,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState, Model.Local.appendEntry]
        using signCommittableMessagesPreservesSystemInductiveInvariant state node (present := present)
          invariant.safety ⟨joined, enabled⟩
  | appendEntries destination batchEnd =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      have target : destination ∈ joinedNodes := by
        rcases enabled.2.2.1 with active | retired
        · exact invariant.activeJoined active
        · exact invariant.retiredJoined retired
      refine ⟨joinedNodes, invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.sentEndpoints (Finset.Subset.refl _) ?_)⟩
      · simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState,
          appendRequestKey, Model.Local.makeAppendEntriesRequest] using appendEntriesPreservesSystemInductiveInvariant
            state node (present := present) destination batchEnd invariant.safety ⟨joined, target, enabled⟩
      · intro envelope member
        simp only [List.mem_singleton] at member
        subst envelope
        exact ⟨joined, target⟩
  | advanceCommitIndex =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        joinedNodes,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState, advanced_eq state node present]
        using advanceCommitPreservesSystemInductiveInvariant state node (present := present) invariant.distinct invariant.safety
          ⟨joined, enabled⟩
  | timeout =>
      extract_guard
      obtain ⟨eligible, capable⟩ := enabled
      have joined := invariant.joined_of_role (node := node) (by
        rcases eligible.1 with role | role | role <;> rw [role] <;> decide)
      refine ⟨
        joinedNodes,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState]
        using timeoutPreservesSystemInductiveInvariant state node (present := present) invariant.safety
          ⟨joined, eligible.1, eligible.2.1, eligible.2.2, capable⟩
  | becomePreVoteCandidate =>
      extract_guard
      obtain ⟨eligible, capable⟩ := enabled
      have joined := invariant.joined_of_role (node := node) (by
        rcases eligible.1 with role | role | role <;> rw [role] <;> decide)
      refine ⟨
        joinedNodes,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState]
        using becomePreVoteCandidatePreservesSystemInductiveInvariant state node (present := present)
          invariant.safety ⟨joined, eligible.1, eligible.2.1, eligible.2.2, capable⟩
  | becomeCandidate =>
      extract_guard
      obtain ⟨role, eligible, capable, majority⟩ := enabled
      have joined := invariant.joined_of_role (node := node) (by rw [role]; decide)
      refine ⟨
        joinedNodes,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState]
        using becomeCandidatePreservesSystemInductiveInvariant state node (present := present) invariant.safety
          ⟨joined, role, eligible.2.1, eligible.2.2, capable, majority⟩
  | requestVote destination =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      have target := invariant.activeJoined enabled.2.2
      refine ⟨joinedNodes, invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.sentEndpoints (Finset.Subset.refl _) ?_)⟩
      · simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState,
          voteRequestKey, Model.Local.makeRequestVoteRequest] using requestVotePreservesSystemInductiveInvariant
            state node destination invariant.safety ⟨joined, target, enabled⟩
      · intro envelope member
        simp only [List.mem_singleton] at member
        subst envelope
        exact ⟨joined, target⟩
  | requestPreVote destination =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      have target := invariant.activeJoined enabled.2.2
      refine ⟨joinedNodes, invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.sentEndpoints (Finset.Subset.refl _) ?_)⟩
      · simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState,
          voteRequestKey, Model.Local.makeRequestVoteRequest] using requestPreVotePreservesSystemInductiveInvariant
            state node destination invariant.safety ⟨joined, target, enabled⟩
      · intro envelope member
        simp only [List.mem_singleton] at member
        subst envelope
        exact ⟨joined, target⟩
  | checkQuorum =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        joinedNodes,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState, stepDownState]
        using checkQuorumPreservesSystemInductiveInvariant state node (present := present) invariant.safety
          ⟨joined, enabled⟩
  | becomeLeader =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        joinedNodes,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState]
        using becomeLeaderPreservesSystemInductiveInvariant state node (present := present) invariant.safety
          ⟨joined, enabled⟩
  | proposeVote destination =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      have target := invariant.activeJoined (Finset.mem_of_mem_erase enabled.2.1)
      refine ⟨joinedNodes, invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.sentEndpoints (Finset.Subset.refl _) ?_)⟩
      · simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState]
          using proposeVotePreservesSystemInductiveInvariant state node destination
            invariant.safety ⟨joined, target, enabled⟩
      · intro envelope member
        simp only [List.mem_singleton] at member
        subst envelope
        exact ⟨joined, target⟩
  | advanceCommitIndexAndProposeVote destination =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      have target := invariant.activeJoined (Finset.mem_of_mem_erase enabled.2.2.2.1)
      refine ⟨joinedNodes, invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.sentEndpoints (Finset.Subset.refl _) ?_)⟩
      · simpa [concrete_effects, leaderAppendJoined, replaceNode_nodeOf state node invariant.distinct, becomeCandidateState, advanced_eq state node present]
          using advanceCommitAndProposeVotePreservesSystemInductiveInvariant state node (present := present)
            destination invariant.distinct invariant.safety ⟨joined, target, enabled⟩
      · intro envelope member
        simp only [List.mem_singleton] at member
        subst envelope
        exact ⟨joined, target⟩

end CCFRaft.Proofs.Invariant
