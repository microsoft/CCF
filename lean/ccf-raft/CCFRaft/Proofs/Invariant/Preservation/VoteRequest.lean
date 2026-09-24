-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.AppendRequest
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

/-- Receiving a RequestVote request preserves the full arbitrary-term invariant. -/
lemma receiveRequestVoteRequestPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (source destination : Node)
    {present : destination ∈ state.nodes.map Prod.fst}
    (distinct : (state.nodes.map Prod.fst).Nodup)
    (request : VoteRequestKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (nextNode : NodeState Node TxId)
    (response : VoteResponseKey Node)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (_destinationAllocated : destination ∈ joinedNodes)
    (addressed : request.2.1 = destination)
    (taken
      : Selected source state.network (voteRequestEnvelope request)
          remaining)
    (responseSource : response.1 = request.2.1)
    (responseDestination : response.2.1 = request.1)
    (handled
      : handleRequestVoteRequest ((nodeOf state) destination) request.1 request.2.2
        = (nextNode, response.2.2))
    : SystemInductiveInvariant (joined := joinedNodes)
        {
          state with
            nodes := replaceNode state.nodes destination nextNode
            network :=
              enqueue
                (remaining)
                (voteResponseEnvelope response)
        } := by
  let post := handleRequestVoteRequestLocalPost responseSource responseDestination handled
  let enqueued : Model.State Node TxId :=
    { state with
      nodes := replaceNode state.nodes destination nextNode
      network :=
        enqueue state.network (voteResponseEnvelope response) }
  let after : Model.State Node TxId :=
    { state with
      nodes := replaceNode state.nodes destination nextNode
      network :=
        enqueue
          (remaining)
          (voteResponseEnvelope response) }
  have enqueuedInvariant : SystemInductiveInvariant (joined := joinedNodes) enqueued := by
    by_cases granted : response.2.2.voteGranted = true
    · simpa [enqueued]
        using enqueueGrantedVoteResponsePreservesSystemInductiveInvariant (present := present)
          state source destination request nextNode response remaining
          invariant addressed taken responseSource responseDestination handled granted
    · have rejected : response.2.2.voteGranted = false := by
        exact Bool.eq_false_of_not_eq_true granted
      have nextEq := post.rejectedState rejected
      have nodesEq :
          replaceNode state.nodes destination nextNode = state.nodes := by
        rw [nextEq]
        exact replaceNode_nodeOf state destination distinct
      simpa [enqueued, nodesEq]
        using enqueueRejectedVoteResponsePreservesSystemInductiveInvariant
          state response invariant rejected
          (by
            rw [post.responseSource]
            exact
              systemVoteRequestDestinationJoined
                state invariant destination request
                  ⟨(selectedSound taken).2.1, addressed⟩)
          (by
            rw [post.responseTerm]
            exact invariantCurrentTermsValid invariant destination)
  have roleEq :
      forall node,
        ((nodeOf after) node).role = ((nodeOf enqueued) node).role := by
    intro node
    rfl
  have termEq :
      forall node,
        ((nodeOf after) node).currentTerm =
          ((nodeOf enqueued) node).currentTerm := by
    intro node
    rfl
  have logEq :
      forall node,
        ((nodeOf after) node).log = ((nodeOf enqueued) node).log := by
    intro node
    rfl
  have commitEq :
      forall node,
        ((nodeOf after) node).commitIndex =
          ((nodeOf enqueued) node).commitIndex := by
    intro node
    rfl
  have networkSubset :
      forall queuedDestination message,
        (message ∈ after.network /\ message.target = queuedDestination) ->
          (message ∈ enqueued.network /\ message.target = queuedDestination) := by
    intro queuedDestination message member
    rcases
        memEnqueue
          (remaining)
          (voteResponseEnvelope response)
          message queuedDestination
          (by simpa [after] using member) with
      old | new
    · have oldMember :
          (message ∈ state.network /\ message.target = queuedDestination) := by
        exact ⟨(selectedSound taken).2.2 _ old.1, old.2⟩
      simpa [enqueued]
        using memEnqueueNoDupOfMem
          state.network (voteResponseEnvelope response)
          message queuedDestination oldMember
    · rcases new with ⟨destinationEq, messageEq⟩
      subst queuedDestination
      subst message
      simp [enqueued, enqueue]
  have voteResponseEq :
      forall queuedDestination queuedResponse,
        (voteResponseEnvelope queuedResponse ∈ after.network /\ queuedResponse.2.1 = queuedDestination) ↔
          (voteResponseEnvelope queuedResponse ∈ enqueued.network /\ queuedResponse.2.1 = queuedDestination) := by
    intro queuedDestination queuedResponse
    constructor
    · intro member
      rcases
          voteResponseMemAfterVoteRequestReceive
            state.network source destination request response
              queuedResponse remaining taken queuedDestination
              (by simpa [after] using member) with
        old | new
      · simpa [enqueued]
          using memEnqueueNoDupOfMem
            state.network (voteResponseEnvelope response)
            (voteResponseEnvelope queuedResponse)
            queuedDestination old
      · rcases new with ⟨destinationEq, responseEq⟩
        subst queuedDestination
        subst queuedResponse
        simp [enqueued, enqueue]
    · intro member
      rcases
          memEnqueue
            state.network (voteResponseEnvelope response)
              (voteResponseEnvelope queuedResponse)
              queuedDestination
              (by simpa [enqueued] using member) with
        old | new
      · simpa [after]
          using oldVoteResponseMemAfterVoteRequestReceive
            state.network source destination request response
            queuedResponse remaining taken queuedDestination old
      · simp only [voteResponseEnvelope.injEq] at new
        rcases new with ⟨destinationEq, responseEq⟩
        subst queuedDestination
        subst queuedResponse
        simp [after, enqueue]
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters (joined := joinedNodes) after candidate =
          effectiveElectionVoters (joined := joinedNodes) enqueued candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, support⟩
      refine ⟨joined, ?_⟩
      rcases support with processed | queued
      · exact Or.inl processed
      · right
        rcases queued with
          ⟨queuedResponse, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact ⟨
          queuedResponse,
          (voteResponseEq candidate queuedResponse).mp member,
          granted,
          responseTerm,
          responseSource,
          responseDestination
        ⟩
    · rintro ⟨joined, support⟩
      refine ⟨joined, ?_⟩
      rcases support with processed | queued
      · exact Or.inl processed
      · right
        rcases queued with
          ⟨queuedResponse, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact ⟨
          queuedResponse,
          (voteResponseEq candidate queuedResponse).mpr member,
          granted,
          responseTerm,
          responseSource,
          responseDestination
        ⟩
  have effectiveAckersEq :
      forall
        (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
        leader index,
        effectiveAckers (joined := joinedNodes) after responseHistory leader index =
          effectiveAckers (joined := joinedNodes) enqueued responseHistory leader index := by
    intro responseHistory leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter]
    constructor
    · rintro ⟨joined, support⟩
      refine ⟨joined, ?_⟩
      rcases support with self | matched | queued
      · exact Or.inl self
      · exact Or.inr (Or.inl matched)
      · right
        right
        rcases queued with
          ⟨queuedResponse, member, success, responseTerm,
            responseSource, responseDestination, lastIndex, covered⟩
        exact ⟨
          queuedResponse,
          networkSubset leader (appendResponseEnvelope queuedResponse) member,
          success,
          responseTerm,
          responseSource,
          responseDestination,
          lastIndex,
          covered
        ⟩
    · rintro ⟨joined, support⟩
      refine ⟨joined, ?_⟩
      rcases support with self | matched | queued
      · exact Or.inl self
      · exact Or.inr (Or.inl matched)
      · right
        right
        rcases queued with
          ⟨queuedResponse, member, success, responseTerm,
            responseSource, responseDestination, lastIndex, covered⟩
        have oldMember :
            (appendResponseEnvelope queuedResponse ∈ state.network /\ queuedResponse.2.1 = leader) := by
          rcases
              memEnqueue
                state.network (voteResponseEnvelope response)
                  (appendResponseEnvelope queuedResponse)
                  leader (by simpa [enqueued] using member) with
            old | new
          · exact old
          · simp at new
        have afterMember :
            (appendResponseEnvelope queuedResponse ∈ after.network /\ queuedResponse.2.1 = leader) := by
          rw [show
            after.network =
              enqueue
                (remaining)
                (voteResponseEnvelope response) by rfl]
          exact (appendResponseMemAfterVoteRequestReceive
                  state.network source destination request response remaining
                  taken leader queuedResponse).mpr
            oldMember
        exact ⟨
          queuedResponse,
          afterMember,
          success,
          responseTerm,
          responseSource,
          responseDestination,
          lastIndex,
          covered
        ⟩
  change SystemInductiveInvariant (joined := joinedNodes) after
  apply networkFramePreservesSystemInductiveInvariant enqueued after enqueuedInvariant (by simp [after, enqueued])
    (fun _ => rfl)
    (fun destination message member =>
      Or.inl (networkSubset destination message member))
  · intro _ _ actualResponseHistory _ _ _ _ leader index
    exact Finset.subset_of_eq
      (effectiveAckersEq actualResponseHistory leader index)
  · intro candidate role majority
    unfold hasEffectiveElectionMajority at majority ⊢
    rw [effectiveElectionVotersEq] at majority
    exact majority
  · intro candidate voter active member
    rw [effectiveElectionVotersEq] at member
    exact member

end CCFRaft.Proofs.Invariant
