-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Local
import CCFRaft.Proofs.Invariant.ViewFacts
import CCFRaft.Proofs.Direct.CommitFrontier

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open Shared Concrete
open Model.Local (
  Bootstrap NodeState Entry Role refreshRetirementState activeNodeUnion
    INITIAL_CONFIGURATION INITIAL_LEADER INITIAL_PRE_VOTE_STATUS BOOTSTRAP_TERM
    latestConfiguration implicitConfiguration updateIndex
  )

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

@[simp]
theorem updateNode_self (nodes : Node -> NodeState Node TxId) (node : Node)
    : updateNode nodes node (nodes node) = nodes := by
  simp [updateNode]

theorem append_messagesAt_singleton (network : Node -> List (Message Node TxId))
    (envelope : Model.Envelope Node TxId)
    : (fun destination => network destination ++ messagesAt [envelope] destination)
      = enqueue network (toMessage envelope) :=
  funext fun destination => (enqueue_toMessage network envelope destination).symm

theorem refresh_sentIndex (node : Node) (value : NodeState Node TxId)
    (sentIndex : Node -> Nat)
    : { refreshRetirementState node value with sentIndex }
      = refreshRetirementState node { value with sentIndex } :=
  rfl

theorem advanceCommit_eq (state : View Node TxId) (node : Node)
    : refreshRetirementState node
        { state.nodes node with commitIndex := highestCommittableIndex state node }
      = Model.Local.advanceCommit (state.nodes node) node :=
  rfl

theorem advanced_eq (state : View Node TxId) (node : Node)
    : demoteRetiredCommitted (advanceCommitState state node) node
      = {
        state with
          nodes :=
            updateNode state.nodes node
              (Model.Local.demoteRetiredCommitted
                (Model.Local.advanceCommit (state.nodes node) node))
      } := by
  simp only [demoteRetiredCommitted, advanceCommitState, advanceCommit_eq,
    updateNode_same, Model.Local.demoteRetiredCommitted]
  split_ifs <;> simp [updateNode]

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
      messagesAt_nil, List.append_nil]))

/-- Preserve the invariant under the node update and sends of an internal input. -/
theorem act_preserves {state : View Node TxId} (invariant : ViewInvariant state)
    {node : Node} {input : Model.Local.Input Node TxId}
    {execute : Model.Local.NodeEffect Node TxId (NodeState Node TxId)}
    (acted
      : Model.Local.act (Capabilities.record node) node (state.nodes node) input
        = some execute)
    : ∃ joined,
        ViewInvariant
          {
            nodes := updateNode state.nodes node (execute.run {}).1
            network :=
              fun destination =>
                state.network destination
                ++ messagesAt (execute.run {}).2.outgoing destination
            hasJoined := joined
          } := by
  cases input with
  | initializeConfiguration =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.2.1]; decide)
      refine ⟨
        state.hasJoined,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [view_effects]
        using initializeConfigurationPreservesSystemInductiveInvariant
          state node invariant.safety ⟨enabled.1, joined, enabled.2⟩
  | clientRequest txId =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        state.hasJoined,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [view_effects, Model.Local.appendEntry]
        using clientRequestPreservesSystemInductiveInvariant state node txId
          invariant.safety ⟨joined, enabled⟩
  | changeConfiguration configuration =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      let added := configuration \ (latestConfiguration (state.nodes node)).nodes
      refine ⟨state.hasJoined ∪ added,
        invariant.update joined Finset.subset_union_left ?_ ?_⟩
      · simpa only [view_effects, Model.Local.appendEntry, added, refresh_sentIndex]
          using changeConfigurationPreservesSystemInductiveInvariant state node
            configuration invariant.safety ⟨joined, enabled⟩
      · intro destination message member
        obtain ⟨source, target⟩ := invariant.endpoints destination message member
        exact ⟨Finset.mem_union_left _ source, Finset.mem_union_left _ target⟩
  | appendRetiredCommitted =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        state.hasJoined,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [view_effects, Model.Local.appendEntry, pendingRetiredCommittedNodes]
        using appendRetiredCommittedPreservesSystemInductiveInvariant state node
          invariant.safety ⟨joined, enabled⟩
  | signCommittableMessages =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        state.hasJoined,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [view_effects, Model.Local.appendEntry]
        using signCommittableMessagesPreservesSystemInductiveInvariant state node
          invariant.safety ⟨joined, enabled⟩
  | appendEntries destination batchEnd =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      have target : destination ∈ state.hasJoined := by
        rcases enabled.2.2.1 with active | retired
        · exact invariant.activeJoined active
        · exact invariant.retiredJoined retired
      refine ⟨state.hasJoined, invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.sentEndpoints (Finset.Subset.refl _) ?_)⟩
      · simpa [append_messagesAt_singleton, view_effects,
          makeAppendEntriesRequest, Model.Local.makeAppendEntriesRequest,
          toMessage] using appendEntriesPreservesSystemInductiveInvariant
            state node destination batchEnd invariant.safety ⟨joined, target, enabled⟩
      · intro envelope member
        simp only [List.mem_singleton] at member
        subst envelope
        exact ⟨joined, target⟩
  | advanceCommitIndex =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        state.hasJoined,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [view_effects, advanced_eq]
        using advanceCommitPreservesSystemInductiveInvariant state node invariant.safety
          ⟨joined, enabled⟩
  | timeout =>
      extract_guard
      obtain ⟨eligible, capable⟩ := enabled
      have joined := invariant.joined_of_role (node := node) (by
        rcases eligible.1 with role | role | role <;> rw [role] <;> decide)
      refine ⟨
        state.hasJoined,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [view_effects]
        using timeoutPreservesSystemInductiveInvariant state node invariant.safety
          ⟨joined, eligible.1, eligible.2.1, eligible.2.2, capable⟩
  | becomePreVoteCandidate =>
      extract_guard
      obtain ⟨eligible, capable⟩ := enabled
      have joined := invariant.joined_of_role (node := node) (by
        rcases eligible.1 with role | role | role <;> rw [role] <;> decide)
      refine ⟨
        state.hasJoined,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [view_effects]
        using becomePreVoteCandidatePreservesSystemInductiveInvariant state node
          invariant.safety ⟨joined, eligible.1, eligible.2.1, eligible.2.2, capable⟩
  | becomeCandidate =>
      extract_guard
      obtain ⟨role, eligible, capable, majority⟩ := enabled
      have joined := invariant.joined_of_role (node := node) (by rw [role]; decide)
      refine ⟨
        state.hasJoined,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [view_effects]
        using becomeCandidatePreservesSystemInductiveInvariant state node invariant.safety
          ⟨joined, role, eligible.2.1, eligible.2.2, capable, majority⟩
  | requestVote destination =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      have target := invariant.activeJoined enabled.2.2
      refine ⟨state.hasJoined, invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.sentEndpoints (Finset.Subset.refl _) ?_)⟩
      · simpa [append_messagesAt_singleton, view_effects,
          makeRequestVoteRequest, Model.Local.makeRequestVoteRequest,
          toMessage] using requestVotePreservesSystemInductiveInvariant
            state node destination invariant.safety ⟨joined, target, enabled⟩
      · intro envelope member
        simp only [List.mem_singleton] at member
        subst envelope
        exact ⟨joined, target⟩
  | requestPreVote destination =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      have target := invariant.activeJoined enabled.2.2
      refine ⟨state.hasJoined, invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.sentEndpoints (Finset.Subset.refl _) ?_)⟩
      · simpa [append_messagesAt_singleton, view_effects,
          makeRequestPreVote, Model.Local.makeRequestVoteRequest,
          toMessage] using requestPreVotePreservesSystemInductiveInvariant
            state node destination invariant.safety ⟨joined, target, enabled⟩
      · intro envelope member
        simp only [List.mem_singleton] at member
        subst envelope
        exact ⟨joined, target⟩
  | checkQuorum =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        state.hasJoined,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [view_effects, stepDownState]
        using checkQuorumPreservesSystemInductiveInvariant state node invariant.safety
          ⟨joined, enabled⟩
  | becomeLeader =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      refine ⟨
        state.hasJoined,
        invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
      ⟩
      simpa [view_effects]
        using becomeLeaderPreservesSystemInductiveInvariant state node invariant.safety
          ⟨joined, enabled⟩
  | proposeVote destination =>
      extract_guard
      have joined := invariant.joined_of_role (node := node) (by rw [enabled.1]; decide)
      have target := invariant.activeJoined (Finset.mem_of_mem_erase enabled.2.1)
      refine ⟨state.hasJoined, invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.sentEndpoints (Finset.Subset.refl _) ?_)⟩
      · simpa [append_messagesAt_singleton, view_effects, makeProposeVoteRequest,
          toMessage]
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
      refine ⟨state.hasJoined, invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.sentEndpoints (Finset.Subset.refl _) ?_)⟩
      · simpa [append_messagesAt_singleton, view_effects, advanced_eq,
          makeProposeVoteRequest, toMessage]
          using advanceCommitAndProposeVotePreservesSystemInductiveInvariant state node
            destination invariant.safety ⟨joined, target, enabled⟩
      · intro envelope member
        simp only [List.mem_singleton] at member
        subst envelope
        exact ⟨joined, target⟩

end CCFRaft.Proofs.Invariant
