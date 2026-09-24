-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.VoteRequest
import CCFRaft.Proofs.Ledger

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Model.Local
open Concrete
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable {joinedNodes : Finset Node}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

attribute [local simp] Shared.Envelope.target ConfigurationCoverageWitness.sharedPrefix

lemma pureNetworkDequeuePreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (network : List (Model.Envelope Node TxId))
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (networkSubset
      : forall destination message,
          (message ∈ network /\ message.target = destination) -> (message ∈ state.network /\ message.target = destination))
    : SystemInductiveInvariant (joined := joinedNodes) { state with network } := by
  let after : Model.State Node TxId := { state with network }
  have effectiveElectionSubset :
      forall candidate,
        effectiveElectionVoters (joined := joinedNodes) after candidate ⊆
          effectiveElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate voter member
    simp only [
      effectiveElectionVoters, Finset.mem_filter
    ] at member ⊢
    rcases member with ⟨joined, processed | queued⟩
    · exact ⟨joined, Or.inl processed⟩
    · rcases queued with
        ⟨response, queued, granted, term, source, destination⟩
      exact ⟨
        joined,
        Or.inr
          ⟨
            response,
            networkSubset candidate (voteResponseEnvelope response) queued,
            granted,
            term,
            source,
            destination
          ⟩
      ⟩
  change SystemInductiveInvariant (joined := joinedNodes) after
  apply
    networkFramePreservesSystemInductiveInvariant state after invariant rfl
        (fun _ => rfl)
        (fun destination message member =>
          Or.inl (networkSubset destination message member))
  · intro _ _ responseHistory _ _ _ _ leader index peer member
    simp only [effectiveAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, self | matched | queued⟩
    · exact ⟨joined, Or.inl self⟩
    · exact ⟨joined, Or.inr (Or.inl matched)⟩
    · rcases queued with
        ⟨response, queued, success, term, source, destination,
          acknowledged, covered⟩
      exact ⟨
        joined,
        Or.inr
          (Or.inr
            ⟨
              response,
              networkSubset leader (appendResponseEnvelope response) queued,
              success,
              term,
              source,
              destination,
              acknowledged,
              covered
            ⟩)
      ⟩
  · intro candidate _ majority
    rw [hasEffectiveElectionMajority, List.all_eq_true] at majority ⊢
    intro configuration active
    apply decide_eq_true
    exact
      hasConfigurationMajority_mono
        (effectiveElectionSubset candidate)
        (of_decide_eq_true (majority configuration active))
  · intro candidate voter _ member
    exact effectiveElectionSubset candidate member


lemma receiveRequestPreVotePreservesSystemInductiveInvariant
    (state : Model.State Node TxId) (source destination : Node)
    (request : RequestVoteRequest) (remaining : List (Model.Envelope Node TxId))
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (taken : Selected source state.network (preVoteRequestEnvelope (source, destination, request)) remaining)
    : SystemInductiveInvariant (joined := joinedNodes)
        { state with network := remaining ++ [preVoteResponseEnvelope
            (destination, source, handleRequestPreVote (nodeOf state destination) request)] } := by
  apply safetyInertNetworkChangePreservesSystemInductiveInvariant state { state with network := remaining ++ [preVoteResponseEnvelope
      (destination, source, handleRequestPreVote (nodeOf state destination) request)] } invariant rfl (fun _ => rfl)
  intro target envelope member
  rcases List.mem_append.mp member.1 with old | reply_
  · exact Or.inl ⟨(selectedSound taken).2.2 _ old, member.2⟩
  · obtain rfl := List.mem_singleton.mp reply_
    exact Or.inr ⟨by simp [IsSafetyInert], member.2,
      invariantCurrentTermsValid invariant destination⟩

lemma receiveRequestPreVoteResponsePreservesSystemInductiveInvariant
    (state : Model.State Node TxId) (source destination : Node)
    {present : destination ∈ state.nodes.map Prod.fst}
    (response : RequestVoteResponse) (remaining : List (Model.Envelope Node TxId))
    (nextNode : NodeState Node TxId)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (taken : Selected source state.network
      (preVoteResponseEnvelope (source, destination, response)) remaining)
    (handled : handleRequestPreVoteResponse (nodeOf state destination) source response = nextNode)
    : SystemInductiveInvariant (joined := joinedNodes)
        { state with nodes := replaceNode state.nodes destination nextNode, network := remaining } := by
  let middle : Model.State Node TxId :=
    { state with nodes := replaceNode state.nodes destination nextNode }
  have post := handleRequestPreVoteResponsePreserves handled
  have preserved : SystemInductiveInvariant (joined := joinedNodes) middle := by
    apply retirementMetadataFramePreservesSystemInductiveInvariant state middle invariant rfl rfl
    all_goals
      intro node
      by_cases same : node = destination
      · subst node
        simpa only [middle, nodeOf_replaceNode, present, ite_true] using
          (by first | exact post.roleUnchanged | exact post.currentTermUnchanged
                    | exact post.logUnchanged | exact post.commitIndexUnchanged
                    | exact post.sentIndexUnchanged | exact post.matchIndexUnchanged
                    | exact post.votedForUnchanged | exact post.votesGrantedUnchanged
                    | exact post.isNewFollowerUnchanged)
      · simp [middle, same]
  exact pureNetworkDequeuePreservesSystemInductiveInvariant middle remaining preserved
    (fun _ envelope member => ⟨(selectedSound taken).2.2 envelope member.1, member.2⟩)

lemma receiveProposeVoteRequestPreservesSystemInductiveInvariant
    (state : Model.State Node TxId) (source destination : Node)
    {present : destination ∈ state.nodes.map Prod.fst}
    (distinct : (state.nodes.map Prod.fst).Nodup)
    (term : Nat) (remaining : List (Model.Envelope Node TxId))
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (joined : destination ∈ joinedNodes)
    (taken : Selected source state.network (proposeVoteEnvelope (source, destination, term)) remaining)
    : SystemInductiveInvariant (joined := joinedNodes)
        { state with
          nodes := replaceNode state.nodes destination
            (handleProposeVoteRequest (nodeOf state destination) destination term)
          network := remaining } := by
  rcases handleProposeVoteRequestCases (nodeOf state destination) destination term with same | changed
  · rw [same, replaceNode_nodeOf state destination distinct]
    exact pureNetworkDequeuePreservesSystemInductiveInvariant state remaining invariant
      (fun _ envelope member => ⟨(selectedSound taken).2.2 envelope member.1, member.2⟩)
  · rw [changed.2.2]
    have preserved := candidateTransitionPreservesSystemInductiveInvariant
      state destination (present := present) invariant ⟨joined, changed.2.1.1⟩
    exact pureNetworkDequeuePreservesSystemInductiveInvariant
      (becomeCandidateState state destination) remaining preserved
      (fun _ envelope member => ⟨(selectedSound taken).2.2 envelope member.1, member.2⟩)

end CCFRaft.Proofs.Invariant
