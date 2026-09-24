-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.AppendRequest
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

attribute [local simp] Message.destination ConfigurationCoverageWitness.sharedPrefix

/-- Receiving a RequestVote request preserves the full arbitrary-term invariant. -/
lemma receiveRequestVoteRequestPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (source destination : Node)
    (request : RequestVoteRequest Node)
    (remaining : List (Message Node TxId))
    (nextNode : NodeState Node TxId)
    (response : RequestVoteResponse Node)
    (invariant : SystemInductiveInvariant state)
    (_destinationAllocated : state.allocated destination)
    (taken
      : Selected source (state.network destination) (.requestVoteRequest request)
          remaining)
    (handled
      : handleRequestVoteRequest? (state.nodes destination) request
        = some (nextNode, response))
    : SystemInductiveInvariant
        {
          state with
            nodes := updateNode state.nodes destination nextNode
            network :=
              enqueue
                (updateQueue state.network destination remaining)
                (.requestVoteResponse response)
        } := by
  let post := handleRequestVoteRequestLocalPost handled
  let enqueued : View Node TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network :=
        enqueue state.network (.requestVoteResponse response) }
  let after : View Node TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network :=
        enqueue
          (updateQueue state.network destination remaining)
          (.requestVoteResponse response) }
  have enqueuedInvariant : SystemInductiveInvariant enqueued := by
    by_cases granted : response.voteGranted = true
    · simpa [enqueued]
        using enqueueGrantedVoteResponsePreservesSystemInductiveInvariant
          state source destination request nextNode response remaining
          invariant taken handled granted
    · have rejected : response.voteGranted = false := by
        exact Bool.eq_false_of_not_eq_true granted
      have nextEq := post.rejectedState rejected
      have nodesEq :
          updateNode state.nodes destination nextNode = state.nodes := by
        rw [nextEq]
        exact (by simp [updateNode])
      simpa [enqueued, nodesEq]
        using enqueueRejectedVoteResponsePreservesSystemInductiveInvariant
          state response invariant rejected
          (by
            rw [post.responseSource]
            exact
              systemVoteRequestDestinationJoined
                state invariant destination request
                  (selectedSound taken).2.1)
          (by
            rw [post.responseTerm]
            exact invariantCurrentTermsValid invariant destination)
  have roleEq :
      forall node,
        (after.nodes node).role = (enqueued.nodes node).role := by
    intro node
    rfl
  have termEq :
      forall node,
        (after.nodes node).currentTerm =
          (enqueued.nodes node).currentTerm := by
    intro node
    rfl
  have logEq :
      forall node,
        (after.nodes node).log = (enqueued.nodes node).log := by
    intro node
    rfl
  have commitEq :
      forall node,
        (after.nodes node).commitIndex =
          (enqueued.nodes node).commitIndex := by
    intro node
    rfl
  have networkSubset :
      forall queuedDestination message,
        message ∈ after.network queuedDestination ->
          message ∈ enqueued.network queuedDestination := by
    intro queuedDestination message member
    rcases
        memEnqueue
          (updateQueue state.network destination remaining)
          (.requestVoteResponse response)
          message queuedDestination
          (by simpa [after] using member) with
      old | new
    · have oldMember :
          message ∈ state.network queuedDestination := by
        by_cases same : queuedDestination = destination
        · subst queuedDestination
          have retained : message ∈ remaining := by simpa [updateQueue] using old
          exact (selectedSound taken).2.2 message retained
        · simpa [updateQueue, Function.update, same] using old
      simpa [enqueued]
        using memEnqueueNoDupOfMem
          state.network (.requestVoteResponse response)
          message queuedDestination oldMember
    · rcases new with ⟨destinationEq, messageEq⟩
      subst queuedDestination
      subst message
      simpa [enqueued]
        using memEnqueueNoDupSelf state.network (.requestVoteResponse response)
  have voteResponseEq :
      forall queuedDestination queuedResponse,
        Message.requestVoteResponse queuedResponse ∈
            after.network queuedDestination ↔
          Message.requestVoteResponse queuedResponse ∈
            enqueued.network queuedDestination := by
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
            state.network (.requestVoteResponse response)
            (.requestVoteResponse queuedResponse)
            queuedDestination old
      · rcases new with ⟨destinationEq, responseEq⟩
        subst queuedDestination
        subst queuedResponse
        simpa [enqueued]
          using memEnqueueNoDupSelf state.network (.requestVoteResponse response)
    · intro member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse)
              queuedDestination
              (by simpa [enqueued] using member) with
        old | new
      · simpa [after]
          using oldVoteResponseMemAfterVoteRequestReceive
            state.network source destination request response
            queuedResponse remaining taken queuedDestination old
      · simp only [Message.requestVoteResponse.injEq] at new
        rcases new with ⟨destinationEq, responseEq⟩
        subst queuedDestination
        subst queuedResponse
        simpa [after]
          using memEnqueueNoDupSelf
            (updateQueue state.network destination remaining)
            (.requestVoteResponse response)
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters after candidate =
          effectiveElectionVoters enqueued candidate := by
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
        (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
        leader index,
        effectiveAckers after responseHistory leader index =
          effectiveAckers enqueued responseHistory leader index := by
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
          networkSubset leader (.appendEntriesResponse queuedResponse) member,
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
            Message.appendEntriesResponse queuedResponse ∈
              state.network leader := by
          rcases
              memEnqueue
                state.network (.requestVoteResponse response)
                  (.appendEntriesResponse queuedResponse)
                  leader (by simpa [enqueued] using member) with
            old | new
          · exact old
          · simp at new
        have afterMember :
            Message.appendEntriesResponse queuedResponse ∈
              after.network leader := by
          rw [show
            after.network =
              enqueue
                (updateQueue state.network destination remaining)
                (.requestVoteResponse response) by rfl]
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
  change SystemInductiveInvariant after
  apply networkFramePreservesSystemInductiveInvariant
    enqueued after enqueuedInvariant
    (by simp [after, enqueued]) (fun _ => Iff.rfl)
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
