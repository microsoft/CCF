-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.ReceiveFrames
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

/-- Enqueuing a rejected vote response is inert for all safety evidence. -/
lemma enqueueRejectedVoteResponsePreservesSystemInductiveInvariant
    (state : View Node TxId)
    (response : RequestVoteResponse Node)
    (invariant : SystemInductiveInvariant state)
    (rejected : response.voteGranted = false)
    (responseSourceJoined : response.source ∈ state.hasJoined)
    (responseTermValid : TermNumberValid response.term)
    : SystemInductiveInvariant
        {
          state with
            network :=
              enqueue state.network (.requestVoteResponse response)
        } := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafety with
    ⟨owners, canonicalHistory, elections, activations,
      nodeEvidence, requestEvidence, ownership, electionFacts,
      configurationFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, activationVoteHistory,
      ackerElectionFacts,
      ackerActivationFacts,
      electionQueuedFacts, activationProgress, activationQuorums,
      evidenceFacts, prospectiveFacts, activationEvidence,
      activationCanonical, activationElections, configurationActivations⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  let after : View Node TxId :=
    { state with
      network :=
        enqueue state.network (.requestVoteResponse response) }
  have appendRequestEq :
      forall destination request,
        Message.appendEntriesRequest request ∈ after.network destination ↔
          Message.appendEntriesRequest request ∈
            state.network destination := by
    intro destination request
    constructor
    · intro member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.appendEntriesRequest request) destination
              (by simpa [after] using member) with
        old | new
      · exact old
      · simp at new
    · intro member
      simpa [after]
        using memEnqueueNoDupOfMem
          state.network (.requestVoteResponse response)
          (.appendEntriesRequest request) destination member
  have appendResponseEq :
      forall destination queuedResponse,
        Message.appendEntriesResponse queuedResponse ∈
            after.network destination ↔
          Message.appendEntriesResponse queuedResponse ∈
            state.network destination := by
    intro destination queuedResponse
    constructor
    · intro member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.appendEntriesResponse queuedResponse) destination
              (by simpa [after] using member) with
        old | new
      · exact old
      · simp at new
    · intro member
      simpa [after]
        using memEnqueueNoDupOfMem
          state.network (.requestVoteResponse response)
          (.appendEntriesResponse queuedResponse) destination member
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers after responseHistory leader index =
          effectiveAckers state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter]
    apply and_congr (by simp [after])
    constructor <;> rintro (self | matched | queued)
    · exact Or.inl self
    · exact Or.inr (Or.inl matched)
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      exact ⟨
        queuedResponse,
        (appendResponseEq leader queuedResponse).mp member,
        success,
        responseTerm,
        responseSource,
        responseDestination,
        lastIndex,
        covered
      ⟩
    · exact Or.inl self
    · exact Or.inr (Or.inl matched)
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      exact ⟨
        queuedResponse,
        (appendResponseEq leader queuedResponse).mpr member,
        success,
        responseTerm,
        responseSource,
        responseDestination,
        lastIndex,
        covered
      ⟩
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters after candidate =
          effectiveElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    apply and_congr (by simp [after])
    constructor
    · rintro (processed | queued)
      · exact Or.inl processed
      · right
        rcases queued with
          ⟨queuedResponse, member, granted, responseTerm,
            responseSource, responseDestination⟩
        rcases
            memEnqueue
              state.network (.requestVoteResponse response)
                (.requestVoteResponse queuedResponse) candidate
                (by simpa [after] using member) with
          old | new
        · exact ⟨
            queuedResponse,
            old,
            granted,
            responseTerm,
            responseSource,
            responseDestination
          ⟩
        · simp only [Message.requestVoteResponse.injEq] at new
          have same : queuedResponse = response := new.2
          subst queuedResponse
          rw [rejected] at granted
          contradiction
    · rintro (processed | queued)
      · exact Or.inl processed
      · right
        rcases queued with
          ⟨queuedResponse, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact ⟨
          queuedResponse,
          by
            simpa [after]
              using memEnqueueNoDupOfMem
                state.network (.requestVoteResponse response)
                (.requestVoteResponse queuedResponse)
                candidate member,
          granted,
          responseTerm,
          responseSource,
          responseDestination
        ⟩
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt after responseHistory leader index ↔
          hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader index
    unfold hasEffectiveMajorityAt
    rw [effectiveAckersEq]
  have effectiveElectionMajorityEq :
      forall candidate,
        hasEffectiveElectionMajority after candidate ↔
          hasEffectiveElectionMajority state candidate := by
    intro candidate
    unfold hasEffectiveElectionMajority
    rw [effectiveElectionVotersEq]
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters after candidate =
          potentialElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter,
      effectiveElectionVotersEq
    ]
    apply and_congr (by simp [after])
    change (voter ∈ effectiveElectionVoters state candidate
            \/ currentlyEligibleElectionVoter state candidate voter)
    ↔ (voter ∈ effectiveElectionVoters state candidate
        \/ currentlyEligibleElectionVoter state candidate voter)
    rfl
  have potentialElectionMajorityEq :
      forall candidate,
        hasPotentialElectionMajority after candidate ↔
          hasPotentialElectionMajority state candidate := by
    intro candidate
    unfold hasPotentialElectionMajority
    rw [potentialElectionVotersEq]
  have queuedAppendReserveEq :
      forall leader peer index,
        queuedAppendReserve after appendHistory leader peer index ↔
          queuedAppendReserve state appendHistory leader peer index := by
    intro leader peer index
    constructor
    · rintro ⟨request, member, requestSource, requestDestination,
               requestTerm, producible, covered⟩
      exact ⟨
        request,
        (appendRequestEq peer request).mp member,
        requestSource,
        requestDestination,
        by simpa [after] using requestTerm,
        by simpa [after] using producible,
        by simpa [after] using covered
      ⟩
    · rintro ⟨request, member, requestSource, requestDestination,
               requestTerm, producible, covered⟩
      exact ⟨
        request,
        (appendRequestEq peer request).mpr member,
        requestSource,
        requestDestination,
        by simpa [after] using requestTerm,
        by simpa [after] using producible,
        by simpa [after] using covered
      ⟩
  have potentialAckersEq :
      forall leader index,
        potentialAckers after appendHistory responseHistory leader index =
          potentialAckers
            state appendHistory responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      potentialAckers, Finset.mem_filter,
      effectiveAckersEq, queuedAppendReserveEq
    ]
    simp [after]
  have potentialMajorityEq :
      forall leader index,
        hasPotentialMajorityAt
            after appendHistory responseHistory leader index ↔
          hasPotentialMajorityAt
            state appendHistory responseHistory leader index := by
    intro leader index
    unfold hasPotentialMajorityAt
    rw [potentialAckersEq]
  have temporalFacts :=
    ackerTemporalFrameSameLogs
      state after votes votes responseHistory voteVoterHistory elections
        ackerCurrentFacts ackerVoteFacts ackerElectionFacts
        (fun leader role => by simpa [after] using role)
        (fun leader _ => by simp [after])
        (fun leader => by simp [after])
        (fun leader index voter _ _ member => by
          rw [effectiveAckersEq] at member
          exact member)
        (fun node => Nat.le_of_eq (by simp [after]))
        (fun _ _ _ voted _ => voted)
  have ackerActivationAfter :
      AckerActivationHistory
        after responseHistory elections activations := by
    apply
      ackerActivationFrameSameLogs
        state after responseHistory elections elections activations
          ackerActivationFacts
    · intro leader role
      simpa [after] using role
    · intro leader role
      simp [after]
    · intro leader
      simp [after]
    · intro leader index supporter role current member
      rw [effectiveAckersEq] at member
      exact member
    · intro term record stored
      exact stored
  refine ⟨
    votes,
    appendHistory,
    responseHistory,
    voteRequestHistory,
    voteCandidateHistory,
    voteVoterHistory,
    ?_
  ⟩
  constructor
  · exact facts.commitIndicesBounded
  · exact facts.currentTermsPositive
  · exact facts.entriesDoNotExceedCurrentTerm
  · exact facts.candidatesSelfVote
  · exact facts.leadersHaveElectionWitness
  · exact facts.leaderProgressBounded
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      simpa [after] using facts.voteHistory.current voter
    · intro voter term future
      exact
        facts.voteHistory.future voter term
          (by simpa [after] using future)
    · intro candidate voter active member
      exact
        facts.voteHistory.counted candidate voter
          (by simpa [after] using active)
          (by simpa [after] using member)
  · constructor
    · intro destination message member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              message destination
              (by simpa [after] using member) with
        old | new
      · exact facts.networkHistory.addressed destination message old
      · exact (congrArg Message.destination new.2).trans new.1.symm
    · intro destination request member
      exact
        facts.networkHistory.appendRequest
          destination request (appendRequestEq destination request |>.mp member)
    · intro destination queuedResponse member
      exact
        facts.networkHistory.appendResponse
          destination queuedResponse
            ((appendResponseEq destination queuedResponse).mp member)
    · intro destination request member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.requestVoteRequest request) destination
              (by simpa [after] using member) with
        old | new
      · exact facts.networkHistory.voteRequest destination request old
      · simp at new
    · intro destination queuedResponse member granted
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse) destination
              (by simpa [after] using member) with
        old | new
      · exact
          facts.networkHistory.voteResponse
            destination queuedResponse old granted
      · simp only [Message.requestVoteResponse.injEq] at new
        have same : queuedResponse = response := new.2
        rw [same, rejected] at granted
        contradiction
  have evidenceAfter :
      CommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
        state after appendHistory nodeEvidence requestEvidence
          evidenceFacts
          (fun _ => rfl) (fun _ => rfl)
    · intro node
      exact le_rfl
    · intro destination request member
      exact (appendRequestEq destination request).mp member
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state after appendHistory appendHistory
          nodeEvidence nodeEvidence requestEvidence requestEvidence
          elections prospectiveFacts
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state after appendHistory nodeEvidence requestEvidence
            (fun _ => rfl) (fun _ => rfl)
            (fun destination request member =>
              (appendRequestEq destination request).mp member)
            known
    · intro member
      exact prefixRefl (state.nodes member).log
    · intro evidence supportedPrefix destination request known
        queued sameTerm
      exact Or.inl
        ⟨(appendRequestEq destination request).mp queued, rfl⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      have oldRelaxed :
          member ∈ relaxedElectionVoters state candidate := by
        simp only [
          relaxedElectionVoters, Finset.mem_filter] at relaxed ⊢
        rcases relaxed with ⟨joined, effective | eligible⟩
        · exact ⟨
            by simpa [after] using joined,
            Or.inl
              (by
                rw [effectiveElectionVotersEq] at effective
                exact effective)
          ⟩
        · exact ⟨by simpa [after] using joined, Or.inr eligible⟩
      exact Or.inl
        ⟨role, newer, entriesBefore,
          oldRelaxed,
          prefixRefl (state.nodes candidate).log⟩
  have configurationFactsAfter :
      ElectionConfigurationFacts after elections activations := by
    apply
      electionConfigurationFrame
        state after elections activations activations configurationFacts
    · intro _ _ stored
      exact stored
    · apply
        activationSupporterCurrentHistoryFrame
          state after elections elections activations
            configurationFacts.supporterCurrentHistory
      · intro node
        simp [after]
      · intro node
        simp [after]
      · intro _ _ stored
        exact stored
    · intro candidate role majority
      exact ⟨
        by simpa [after] using role,
        by simp [after],
        (effectiveElectionMajorityEq candidate).mp majority
      ⟩
    · intro candidate configuration role active
      simpa [after] using active
    · intro candidate role entry member
      simpa [after]
        using configurationFacts.candidateEntriesBeforeTerm
          candidate
          (by simpa [after] using role)
          entry
          (by simpa [after] using member)
  have activationQuorumsAfter :
      ActivationQuorumFacts
        after appendHistory responseHistory elections activations := by
    constructor
    · exact activationQuorums.history
    · intro leader index role current signature potential
        term record recorded newer
      have old :=
        activationQuorums.recordBridge
          leader index
          (by simpa [after] using role)
          (by simpa [after] using current)
          (by simpa [after] using signature)
          ((potentialMajorityEq leader index).mp potential)
          term record recorded
          (by simpa [after] using newer)
      simpa [after] using old
    · intro leader index role current signature potential
        candidate candidateRole candidateMajority newer
      have old :=
        activationQuorums.candidateBridge
          leader index
          (by simpa [after] using role)
          (by simpa [after] using current)
          (by simpa [after] using signature)
          ((potentialMajorityEq leader index).mp potential)
          candidate
          (by simpa [after] using candidateRole)
          ((potentialElectionMajorityEq candidate).mp candidateMajority)
          (by simpa [after] using newer)
      simpa [after] using old
    · intro leader index role current signature majority node
      have old :=
        activationQuorums.committedBridge
          leader index
          (by simpa [after] using role)
          (by simpa [after] using current)
          (by simpa [after] using signature)
          ((effectiveMajorityEq leader index).mp majority)
          node
      simpa [after] using old
    · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
        right rightIndex rightRole rightCurrent rightSignature rightMajority
      have old :=
        activationQuorums.potentialBridge
          left leftIndex
          (by simpa [after] using leftRole)
          (by simpa [after] using leftCurrent)
          (by simpa [after] using leftSignature)
          ((effectiveMajorityEq left leftIndex).mp leftMajority)
          right rightIndex
          (by simpa [after] using rightRole)
          (by simpa [after] using rightCurrent)
          (by simpa [after] using rightSignature)
          ((effectiveMajorityEq right rightIndex).mp rightMajority)
      simpa [after] using old
    · intro activationIndex activation queuedDestination queuedRequest
        stored queued sameTerm
      exact
        activationQuorums.queuedComparable
          activationIndex activation queuedDestination queuedRequest
          stored
          ((appendRequestEq queuedDestination queuedRequest).mp queued)
          sameTerm
    · exact
        committedConfigurationCoverageFrame
          activationQuorums.committedCoverage
          (fun _ => rfl) (fun _ => rfl) (fun _ => le_rfl)
    · apply
        queuedConfigurationCoverageFrame
          activationQuorums.queuedCoverage
          (afterAppendHistory := appendHistory)
      · intro queuedDestination queuedRequest queued
        exact (appendRequestEq queuedDestination queuedRequest).mp queued
      · intro _
        rfl
  have activationProgressAfter :
      ActivationSupporterProgress after activations := by
    apply
      activationSupporterProgressFrame
        state after activations activationProgress
    intro node
    simp [after]
  have activationEvidenceAfter :
      ActivationEvidenceFacts
        after appendHistory responseHistory nodeEvidence requestEvidence
          elections activations := by
    apply
      activationEvidenceFrame
        state after
        appendHistory appendHistory responseHistory responseHistory
        nodeEvidence nodeEvidence
        requestEvidence requestEvidence elections elections activations
        activationEvidence
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state after appendHistory nodeEvidence requestEvidence
            (fun node => by simp [after])
            (fun node => by
              simp [after, NodeState.committedLog])
            (fun destination request member =>
              (appendRequestEq destination request).mp member)
            known
    · intro candidate role majority
      exact ⟨
        by simpa [after] using role,
        (potentialElectionMajorityEq candidate).mp majority
      ⟩
    · intro candidate role
      simp [after]
    · intro candidate role
      simp [after]
    · intro candidate configuration role active
      simpa [after] using active
  have configurationActivationsAfter :
      ConfigurationCoverageFacts after activations := by
    apply configurationCoverageFrameNodesEq configurationActivations
    rfl
  · refine ⟨
      owners,
      canonicalHistory,
      elections,
      activations,
      nodeEvidence,
      requestEvidence,
      ?_,
      ?_,
      configurationFactsAfter,
      ?_,
      ?_,
      ?_,
      activationVoteHistory,
      ?_,
      ackerActivationAfter,
      ?_,
      activationProgressAfter,
      activationQuorumsAfter,
      evidenceAfter,
      prospectiveAfter,
      activationEvidenceAfter,
      activationCanonical,
      activationElections,
      configurationActivationsAfter
    ⟩
    · constructor
      · exact ownership.bootstrap
      · intro leader role
        exact ownership.activeLeader leader (by simpa [after] using role)
      · intro node index entry found
        exact
          ownership.logEntryAgreement node index entry
            (by simpa [after] using found)
      · intro destination request member index entry found
        exact
          ownership.queuedHistoryEntryAgreement
            destination request
              ((appendRequestEq destination request).mp member)
              index entry found
      · exact ownership.activeLeaderHistory
      · exact ownership.canonicalEntryOwner
      · exact ownership.canonicalMonoLog
      · exact ownership.ownerProgress
      · intro destination request member
        exact
          ownership.queuedAppendMetadata
            destination request
              ((appendRequestEq destination request).mp member)
      · intro destination request member sameTerm leaderRole
        exact
          ownership.queuedActiveSourceHistory
            destination request
              ((appendRequestEq destination request).mp member)
              sameTerm leaderRole
    · exact
        electionHistoryFrame
          state after votes votes canonicalHistory canonicalHistory
            owners elections electionFacts
            (fun _ _ _ _ _ => rfl)
            (fun term => prefixRefl (canonicalHistory term))
            (fun _ canonical => canonical)
    · intro candidate voter active member
      exact
        voteCanonicalFacts candidate voter active
          (by rw [effectiveElectionVotersEq] at member; exact member)
    · exact temporalFacts.1
    · exact temporalFacts.2.1
    · exact temporalFacts.2.2
    · intro destination request member record recorded
      exact
        electionQueuedFacts destination request
          ((appendRequestEq destination request).mp member)
          record recorded
  · intro candidate voter active member
    exact
      facts.grantedVoteSnapshots candidate voter active
        (by rw [effectiveElectionVotersEq] at member; exact member)
  · exact ⟨
      ackHistory,
      processedAckHistoryFrame
        state after ackHistory ackFacts
        (fun _ => rfl) (fun _ => rfl)
        (fun _ => rfl) (fun _ _ => rfl)
    ⟩
  · constructor
    · exact facts.joinedCarriers.activeNodes
    · exact facts.joinedCarriers.configurationNodes
    · exact facts.joinedCarriers.grantedVotes
    · intro destination request member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.requestVoteRequest request) destination
              (by simpa [after] using member) with
        old | new
      · exact
          facts.joinedCarriers.voteRequestDestinations
            destination request old
      · simp at new
    · intro destination request member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.appendEntriesRequest request) destination
              (by simpa [after] using member) with
        old | new
      · exact
          facts.joinedCarriers.appendRequestDestinations
            destination request old
      · simp at new
    · intro destination request member configuration configured peer inNodes
      have old :
          Message.appendEntriesRequest request ∈
            state.network destination := by
        rcases
            memEnqueue
              state.network (.requestVoteResponse response)
                (.appendEntriesRequest request) destination
                (by simpa [after] using member) with
          old | new
        · exact old
        · simp at new
      exact
        facts.joinedCarriers.appendRequestConfigurations
          destination request old configuration configured inNodes
    · intro destination queuedResponse member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse) destination
              (by simpa [after] using member) with
        old | new
      · exact
          facts.joinedCarriers.voteResponseSources
            destination queuedResponse old
      · simp only [Message.requestVoteResponse.injEq] at new
        simpa [new.2] using responseSourceJoined
    · constructor
      · exact facts.joinedCarriers.runtimeNodes.activeRoles
      · exact facts.joinedCarriers.runtimeNodes.positiveMatches
      · intro destination queuedResponse member
        rcases
            memEnqueue
              state.network (.requestVoteResponse response)
                (.appendEntriesResponse queuedResponse) destination
                (by simpa [after] using member) with
          old | new
        · exact
            facts.joinedCarriers.runtimeNodes.appendResponses
              destination queuedResponse old
        · simp at new
      · exact facts.joinedCarriers.runtimeNodes.nonemptyLogs
  · exact
      AllocatedNodesExactlyJoined.frame
        facts.allocatedNodesExactlyJoined (fun _ => Iff.rfl) rfl
  · exact facts.currentTermsValid
  · exact networkTermsValidEnqueue facts.networkTermsValid responseTermValid

end CCFRaft.Proofs.Invariant
