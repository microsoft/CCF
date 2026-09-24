-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.LeaderAppend
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

/-- Sending a vote request changes only the network and its proof snapshot. -/
lemma requestVotePreservesSystemInductiveInvariant
    (state : View Node TxId)
    (source destination : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : (state.allocated source
          /\ state.allocated destination
          /\ (state.nodes source).role = .candidate
          /\ Not (source = destination)
          /\ destination ∈ activeNodeUnion (state.nodes source)))
    : SystemInductiveInvariant (requestVoteEffect state source destination) := by
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
  have activationVoteHistoryAfter :
      ActivationVoteHistory
        votes voteVoterHistory elections activations := by
    apply
      activationVoteHistoryFrame
        votes votes voteVoterHistory voteVoterHistory
          elections activations activationVoteHistory
    · intro _ _ _ _ _ _ _ voted _ _
      exact voted
    · intro _ _ _ _ retained
      exact retained
  have candidatesAboveBootstrap :=
    invariantFactsCandidatesAboveBootstrap facts
  let request := makeRequestVoteRequest state source destination
  let voteRequestSnapshot :=
    (state.nodes source).log.take
      (maxCommittableIndex (state.nodes source).log)
  let newVoteRequestHistory :=
    Function.update voteRequestHistory request voteRequestSnapshot
  have sourceLastIndex :
      lastCommittableIndex (state.nodes source) =
        maxCommittableIndex (state.nodes source).log :=
    lastCommittableIndex_eq_maxCommittableIndex
      (state.nodes source)
      (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
        facts source)
  have sourceLastTerm :
      lastCommittableTerm (state.nodes source) =
        maxCommittableTerm (state.nodes source).log :=
    lastCommittableTerm_eq_maxCommittableTerm
      (state.nodes source)
      (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
        facts source)
  have snapshotLength :
      voteRequestSnapshot.length =
        maxCommittableIndex (state.nodes source).log := by
    simp [
      voteRequestSnapshot,
      Nat.min_eq_left
        (maxCommittableIndexBounded (state.nodes source).log)
    ]
  have snapshotTerm :
      termAt voteRequestSnapshot voteRequestSnapshot.length =
        maxCommittableTerm (state.nodes source).log := by
    rw [snapshotLength]
    exact (termAtTakeOfLe
            (log := (state.nodes source).log)
            (index := maxCommittableIndex (state.nodes source).log)
            (count := maxCommittableIndex (state.nodes source).log)
            le_rfl).trans
      rfl
  have snapshotCommittable :
      maxCommittableIndex voteRequestSnapshot =
        voteRequestSnapshot.length := by
    rw [snapshotLength]
    exact maxCommittableIndexTakeMax (state.nodes source).log
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers
            (requestVoteEffect state source destination)
            responseHistory leader index =
          effectiveAckers state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter]
    constructor
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨by simpa [view_effects, view_effects] using joined, Or.inl self⟩
      · exact ⟨
          by simpa [view_effects, view_effects] using joined,
          Or.inr
            (Or.inl (by simpa [view_effects, view_effects] using matched))
        ⟩
      · refine ⟨
          by simpa [view_effects, view_effects] using joined,
          Or.inr (Or.inr ?_)
        ⟩
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        have oldMember :
            Message.appendEntriesResponse response ∈
              state.network leader := by
          rcases
              memEnqueue
                state.network (.requestVoteRequest request)
                  (.appendEntriesResponse response) leader
                  (by simpa [view_effects, view_effects, request] using member) with
            old | new
          · exact old
          · simp at new
        exact ⟨
          response,
          oldMember,
          success,
          by simpa [view_effects, view_effects] using term,
          sourceEq,
          destinationEq,
          lastIndex,
          by simpa [view_effects, view_effects] using covered
        ⟩
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨by simpa [view_effects, view_effects] using joined, Or.inl self⟩
      · exact ⟨
          by simpa [view_effects, view_effects] using joined,
          Or.inr
            (Or.inl (by simpa [view_effects, view_effects] using matched))
        ⟩
      · refine ⟨by simpa [view_effects, view_effects] using joined, Or.inr (Or.inr ?_)⟩
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        refine ⟨
          response,
          ?_,
          success,
          by simpa [view_effects, view_effects] using term,
          sourceEq,
          destinationEq,
          lastIndex,
          by simpa [view_effects, view_effects] using covered
        ⟩
        simpa [view_effects, view_effects, request]
          using memEnqueueNoDupOfMem
            state.network (.requestVoteRequest request)
            (.appendEntriesResponse response) leader member
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt
            (requestVoteEffect state source destination)
            responseHistory leader index ↔
          hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader index
    unfold hasEffectiveMajorityAt
    rw [effectiveAckersEq]
    rfl
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters
            (requestVoteEffect state source destination) candidate =
          effectiveElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [view_effects, view_effects] using joined,
          Or.inl (by simpa [view_effects, view_effects] using processed)
        ⟩
      · refine ⟨
          by simpa [view_effects, view_effects] using joined,
          Or.inr ?_
        ⟩
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        have oldMember :
            Message.requestVoteResponse response ∈
              state.network candidate := by
          rcases
              memEnqueue
                state.network (.requestVoteRequest request)
                  (.requestVoteResponse response) candidate
                  (by simpa [view_effects, view_effects, request] using member) with
            old | new
          · exact old
          · simp at new
        exact ⟨
          response,
          oldMember,
          granted,
          by simpa [view_effects, view_effects] using responseTerm,
          responseSource,
          responseDestination
        ⟩
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [view_effects, view_effects] using joined,
          Or.inl (by simpa [view_effects, view_effects] using processed)
        ⟩
      · refine ⟨by simpa [view_effects, view_effects] using joined, Or.inr ?_⟩
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        refine ⟨
          response,
          ?_,
          granted,
          by simpa [view_effects, view_effects] using responseTerm,
          responseSource,
          responseDestination
        ⟩
        simpa [view_effects, view_effects, request]
          using memEnqueueNoDupOfMem
            state.network (.requestVoteRequest request)
            (.requestVoteResponse response) candidate member
  have effectiveElectionMajorityEq :
      forall candidate,
        hasEffectiveElectionMajority
            (requestVoteEffect state source destination) candidate ↔
          hasEffectiveElectionMajority state candidate := by
    intro candidate
    unfold hasEffectiveElectionMajority
    rw [effectiveElectionVotersEq]
    rfl
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters
            (requestVoteEffect state source destination) candidate =
          potentialElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨by simpa [view_effects, view_effects] using joined, Or.inl (by
          rw [effectiveElectionVotersEq] at effective
          exact effective)⟩
      · exact ⟨by simpa [view_effects, view_effects] using joined, Or.inr (by
          simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          view_effects, view_effects,
          voteLogUpToDate
          ] using eligible)⟩
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨by simpa [view_effects, view_effects] using joined, Or.inl (by
          rw [effectiveElectionVotersEq]
          exact effective)⟩
      · exact ⟨by simpa [view_effects, view_effects] using joined, Or.inr (by
          simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          view_effects, view_effects,
          voteLogUpToDate
          ] using eligible)⟩
  have potentialElectionMajorityEq :
      forall candidate,
        hasPotentialElectionMajority
            (requestVoteEffect state source destination) candidate ↔
          hasPotentialElectionMajority state candidate := by
    intro candidate
    unfold hasPotentialElectionMajority
    rw [potentialElectionVotersEq]
    rfl
  have queuedAppendReserveEq :
      forall leader peer index,
        queuedAppendReserve
            (requestVoteEffect state source destination)
            appendHistory leader peer index ↔
          queuedAppendReserve state appendHistory leader peer index := by
    intro leader peer index
    constructor
    · rintro ⟨queuedRequest, member, requestSource, requestDestination,
               requestTerm, producible, covered⟩
      have oldMember :
          Message.appendEntriesRequest queuedRequest ∈
            state.network peer := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest) peer
                (by simpa [view_effects, view_effects] using member) with
          old | new
        · exact old
        · simp at new
      exact ⟨
        queuedRequest,
        oldMember,
        requestSource,
        requestDestination,
        by simpa [view_effects, view_effects] using requestTerm,
        by simpa [view_effects, view_effects] using producible,
        by simpa [view_effects, view_effects] using covered
      ⟩
    · rintro ⟨queuedRequest, member, requestSource, requestDestination,
               requestTerm, producible, covered⟩
      exact ⟨
        queuedRequest,
        by
          simpa [view_effects, view_effects, request]
            using memEnqueueNoDupOfMem
              state.network (.requestVoteRequest request)
              (.appendEntriesRequest queuedRequest) peer member,
        requestSource,
        requestDestination,
        by simpa [view_effects, view_effects] using requestTerm,
        by simpa [view_effects, view_effects] using producible,
        by simpa [view_effects, view_effects] using covered
      ⟩
  have potentialAckersEq :
      forall leader index,
        potentialAckers
            (requestVoteEffect state source destination)
            appendHistory responseHistory leader index =
          potentialAckers
            state appendHistory responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      potentialAckers, Finset.mem_filter,
      effectiveAckersEq, queuedAppendReserveEq
    ]
    simp [view_effects, view_effects]
  have potentialMajorityEq :
      forall leader index,
        hasPotentialMajorityAt
            (requestVoteEffect state source destination)
            appendHistory responseHistory leader index ↔
          hasPotentialMajorityAt
            state appendHistory responseHistory leader index := by
    intro leader index
    unfold hasPotentialMajorityAt
    rw [potentialAckersEq]
    rfl
  have temporalFacts :=
    ackerTemporalFrameSameLogs state
      (requestVoteEffect state source destination)
      votes votes responseHistory voteVoterHistory elections
      ackerCurrentFacts ackerVoteFacts ackerElectionFacts
      (fun leader role => by
        simpa [view_effects, view_effects] using role)
      (fun leader _ => by simp [view_effects, view_effects])
      (fun leader => by simp [view_effects, view_effects])
      (fun leader index voter _ _ member => by
        rw [effectiveAckersEq] at member
        exact member)
      (fun node => Nat.le_of_eq (by simp [view_effects, view_effects]))
      (fun _ _ _ voted _ => voted)
  have ackerActivationAfter :
      AckerActivationHistory
        (requestVoteEffect state source destination)
        responseHistory elections activations := by
    apply
      ackerActivationFrameSameLogs
        state (requestVoteEffect state source destination)
          responseHistory elections elections activations
          ackerActivationFacts
    · intro leader role
      simpa [view_effects, view_effects] using role
    · intro leader role
      simp [view_effects, view_effects]
    · intro leader
      simp [view_effects, view_effects]
    · intro leader index supporter role current member
      rw [effectiveAckersEq] at member
      exact member
    · intro term record stored
      exact stored
  refine ⟨
    votes,
    appendHistory,
    responseHistory,
    newVoteRequestHistory,
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
      simpa [view_effects, view_effects] using facts.voteHistory.current voter
    · intro voter term future
      apply facts.voteHistory.future voter term
      simpa [view_effects, view_effects] using future
    · intro candidate voter active member
      apply facts.voteHistory.counted candidate voter
      · simpa [view_effects, view_effects] using active
      · simpa [view_effects, view_effects] using member
  · constructor
    · intro queuedDestination message member
      rcases
          memEnqueue
            state.network (.requestVoteRequest request)
              message queuedDestination
              (by simpa [view_effects, view_effects, request] using member) with
        old | new
      · exact facts.networkHistory.addressed queuedDestination message old
      · rcases new with ⟨destinationEq, messageEq⟩
        subst message
        simpa [request, makeRequestVoteRequest] using destinationEq.symm
    · intro queuedDestination queuedRequest member
      have old :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest) queuedDestination
                (by simpa [view_effects, view_effects, request] using member) with
          old | new
        · exact old
        · simp at new
      exact facts.networkHistory.appendRequest
        queuedDestination queuedRequest old
    · intro queuedDestination response member
      have old :
          Message.appendEntriesResponse response ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesResponse response) queuedDestination
                (by simpa [view_effects, view_effects, request] using member) with
          old | new
        · exact old
        · simp at new
      exact
        facts.networkHistory.appendResponse
          queuedDestination response old
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueue
            state.network (.requestVoteRequest request)
              (.requestVoteRequest queuedRequest) queuedDestination
              (by simpa [view_effects, view_effects, request] using member) with
        old | new
      · have oldFacts :=
          facts.networkHistory.voteRequest
            queuedDestination queuedRequest old
        by_cases sameRequest : queuedRequest = request
        · subst queuedRequest
          refine ⟨
            by simp [
                newVoteRequestHistory,
                request, makeRequestVoteRequest,
                sourceLastIndex, snapshotLength
              ],
            by simp [
                newVoteRequestHistory,
                request, makeRequestVoteRequest,
                sourceLastTerm, snapshotTerm
              ],
            by simpa [
                newVoteRequestHistory, Function.update
              ] using snapshotCommittable,
            candidatesAboveBootstrap source enabled.2.2.1,
            by
              simp [request, makeRequestVoteRequest, view_effects, view_effects],
            ?_
          ⟩
          intro _ _
          simpa [newVoteRequestHistory, Function.update, voteRequestSnapshot, request,
            makeRequestVoteRequest, view_effects]
            using List.take_prefix
              (maxCommittableIndex (state.nodes source).log)
              (state.nodes source).log
        · simpa [
            newVoteRequestHistory, Function.update, sameRequest, view_effects
          ] using oldFacts
      · rcases new with ⟨destinationEq, messageEq⟩
        simp only [Message.requestVoteRequest.injEq] at messageEq
        subst queuedRequest
        refine ⟨
          by simp [
              newVoteRequestHistory,
              request, makeRequestVoteRequest,
              sourceLastIndex, snapshotLength
            ],
          by simp [
              newVoteRequestHistory,
              request, makeRequestVoteRequest,
              sourceLastTerm, snapshotTerm
            ],
          by simpa [
              newVoteRequestHistory, Function.update
            ] using snapshotCommittable,
          candidatesAboveBootstrap source enabled.2.2.1,
          by
            simp [request, makeRequestVoteRequest, view_effects, view_effects],
          ?_
        ⟩
        intro _ _
        simpa [newVoteRequestHistory, Function.update, voteRequestSnapshot, request,
          makeRequestVoteRequest, view_effects]
          using List.take_prefix
            (maxCommittableIndex (state.nodes source).log)
            (state.nodes source).log
    · intro queuedDestination response member granted
      have old :
          Message.requestVoteResponse response ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.requestVoteResponse response) queuedDestination
                (by simpa [view_effects, view_effects, request] using member) with
          old | new
        · exact old
        · simp at new
      rcases
          facts.networkHistory.voteResponse
            queuedDestination response old granted with
        ⟨termBound, recorded, upToDate⟩
      exact ⟨
        by simpa [view_effects, view_effects] using termBound,
        recorded,
        by simpa [voteLogUpToDate] using upToDate
      ⟩
  have evidenceAfter :
        CommitEvidenceFacts
          (requestVoteEffect state source destination)
          appendHistory nodeEvidence requestEvidence := by
      apply
        commitEvidenceFrame
        state (requestVoteEffect state source destination)
          appendHistory nodeEvidence requestEvidence evidenceFacts
      · intro node
        simp [view_effects, view_effects]
      · intro node
        simp [view_effects, view_effects, NodeState.committedLog]
      · intro node
        simp [view_effects, view_effects]
      · intro queuedDestination queuedRequest member
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [view_effects, view_effects] using member) with
          old | new
        · exact old
        · simp at new
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        (requestVoteEffect state source destination)
        appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state (requestVoteEffect state source destination)
        appendHistory appendHistory
        nodeEvidence nodeEvidence requestEvidence requestEvidence
          elections prospectiveFacts
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state (requestVoteEffect state source destination)
            appendHistory
            nodeEvidence requestEvidence
            (fun node => by simp [view_effects, view_effects])
            (fun node => by
              simp [view_effects, view_effects, NodeState.committedLog])
            (fun queuedDestination queuedRequest member => by
              rcases
                  memEnqueue
                    state.network (.requestVoteRequest request)
                      (.appendEntriesRequest queuedRequest)
                      queuedDestination
                      (by simpa [view_effects, view_effects] using member) with
                old | new
              · exact old
              · simp at new)
            known
    · intro member
      simp [view_effects, view_effects]
    · intro evidence supportedPrefix queuedDestination queuedRequest
        known queued sameTerm
      rcases
          memEnqueue
            state.network (.requestVoteRequest request)
              (.appendEntriesRequest queuedRequest)
              queuedDestination
              (by simpa [view_effects, view_effects] using queued) with
        old | new
      · exact Or.inl ⟨old, rfl⟩
      · simp at new
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      left
      refine ⟨
        by simpa [view_effects, view_effects] using role,
        by simpa [view_effects, view_effects] using newer,
        ?_,
        ?_,
        by simp [view_effects, view_effects]
      ⟩
      · intro entry entryMember
        simpa [view_effects, view_effects]
          using entriesBefore entry
            (by simpa [view_effects, view_effects] using entryMember)
      · simp only [
          relaxedElectionVoters, Finset.mem_filter] at relaxed ⊢
        rcases relaxed with ⟨joined, effective | upToDate⟩
        · rw [effectiveElectionVotersEq] at effective
          exact ⟨
            by simpa [view_effects, view_effects] using joined,
            Or.inl effective
          ⟩
        · exact ⟨
            by simpa [view_effects, view_effects] using joined,
            Or.inr
              (by
                simpa [makeRequestVoteRequest, view_effects, view_effects,
                  voteLogUpToDate]
                  using upToDate)
          ⟩
  have configurationFactsAfter :
      ElectionConfigurationFacts
        (requestVoteEffect state source destination)
        elections activations := by
    apply
      electionConfigurationFrame
        state (requestVoteEffect state source destination)
        elections activations activations configurationFacts
    · intro _ _ stored
      exact stored
    · apply
        activationSupporterCurrentHistoryFrame
          state (requestVoteEffect state source destination)
          elections elections activations
          configurationFacts.supporterCurrentHistory
      · intro candidate
        simp [view_effects, view_effects]
      · intro candidate
        simp [view_effects, view_effects]
      · intro _ _ stored
        exact stored
    · intro candidate role majority
      exact ⟨
        by simpa [view_effects, view_effects] using role,
        by simp [view_effects, view_effects],
        (effectiveElectionMajorityEq candidate).mp majority
      ⟩
    · intro candidate configuration role active
      simpa [view_effects, view_effects] using active
    · intro candidate role entry member
      simpa [view_effects, view_effects]
        using configurationFacts.candidateEntriesBeforeTerm
          candidate
          (by simpa [view_effects, view_effects] using role)
          entry
          (by simpa [view_effects, view_effects] using member)
  have activationQuorumsAfter :
      ActivationQuorumFacts
        (requestVoteEffect state source destination)
        appendHistory responseHistory elections activations := by
    constructor
    · exact activationQuorums.history
    · intro leader index role current signature potential
        term record recorded newer
      have old :=
        activationQuorums.recordBridge
          leader index
          (by simpa [view_effects, view_effects] using role)
          (by simpa [view_effects, view_effects] using current)
          (by simpa [view_effects, view_effects] using signature)
          ((potentialMajorityEq leader index).mp potential)
          term record recorded
          (by simpa [view_effects, view_effects] using newer)
      simpa [view_effects, view_effects] using old
    · intro leader index role current signature potential
        candidate candidateRole candidateMajority newer
      have old :=
        activationQuorums.candidateBridge
          leader index
          (by simpa [view_effects, view_effects] using role)
          (by simpa [view_effects, view_effects] using current)
          (by simpa [view_effects, view_effects] using signature)
          ((potentialMajorityEq leader index).mp potential)
          candidate
          (by simpa [view_effects, view_effects] using candidateRole)
          ((potentialElectionMajorityEq candidate).mp candidateMajority)
          (by simpa [view_effects, view_effects] using newer)
      simpa [view_effects, view_effects] using old
    · intro leader index role current signature majority node
      have old :=
        activationQuorums.committedBridge
          leader index
          (by simpa [view_effects, view_effects] using role)
          (by simpa [view_effects, view_effects] using current)
          (by simpa [view_effects, view_effects] using signature)
          ((effectiveMajorityEq leader index).mp majority)
          node
      simpa [view_effects, view_effects] using old
    · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
        right rightIndex rightRole rightCurrent rightSignature rightMajority
      have old :=
        activationQuorums.potentialBridge
          left leftIndex
          (by simpa [view_effects, view_effects] using leftRole)
          (by simpa [view_effects, view_effects] using leftCurrent)
          (by simpa [view_effects, view_effects] using leftSignature)
          ((effectiveMajorityEq left leftIndex).mp leftMajority)
          right rightIndex
          (by simpa [view_effects, view_effects] using rightRole)
          (by simpa [view_effects, view_effects] using rightCurrent)
          (by simpa [view_effects, view_effects] using rightSignature)
          ((effectiveMajorityEq right rightIndex).mp rightMajority)
      simpa [view_effects, view_effects] using old
    · intro activationIndex activation queuedDestination queuedRequest
        stored queued sameTerm
      have oldQueued :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [view_effects, view_effects] using queued) with
          old | new
        · exact old
        · simp at new
      exact
        activationQuorums.queuedComparable
          activationIndex activation queuedDestination queuedRequest
          stored
          oldQueued
          sameTerm
    · exact
        committedConfigurationCoverageFrame
          activationQuorums.committedCoverage
          (fun node => by simp [view_effects, view_effects])
          (fun node => by simp [view_effects, view_effects])
          (fun node => by simp [view_effects, view_effects])
    · apply
        queuedConfigurationCoverageFrame
          activationQuorums.queuedCoverage
          (afterAppendHistory := appendHistory)
      · intro queuedDestination queuedRequest queued
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [view_effects, view_effects] using queued) with
          old | new
        · exact old
        · simp at new
      · intro _
        rfl
  have activationProgressAfter :
      ActivationSupporterProgress
        (requestVoteEffect state source destination)
        activations := by
    apply
      activationSupporterProgressFrame
        state (requestVoteEffect state source destination)
          activations activationProgress
    intro candidate
    simp [view_effects, view_effects]
  have activationEvidenceAfter :
      ActivationEvidenceFacts
        (requestVoteEffect state source destination)
        appendHistory responseHistory nodeEvidence requestEvidence
          elections activations := by
    apply
      activationEvidenceFrame
        state (requestVoteEffect state source destination)
        appendHistory appendHistory responseHistory responseHistory
        nodeEvidence nodeEvidence
        requestEvidence requestEvidence elections elections activations
        activationEvidence
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state (requestVoteEffect state source destination)
          appendHistory nodeEvidence requestEvidence
          (fun node => by simp [view_effects, view_effects])
          (fun node => by
            simp [view_effects, view_effects, NodeState.committedLog])
          (fun queuedDestination queuedRequest member => by
            rcases
                memEnqueue
                  state.network (.requestVoteRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects, view_effects] using member) with
              old | new
            · exact old
            · simp at new)
          known
    · intro candidate role majority
      exact ⟨
        by simpa [view_effects, view_effects] using role,
        (potentialElectionMajorityEq candidate).mp majority
      ⟩
    · intro candidate role
      simp [view_effects, view_effects]
    · intro candidate role
      simp [view_effects, view_effects]
    · intro candidate configuration role active
      simpa [view_effects, view_effects] using active
  have configurationActivationsAfter :
      ConfigurationCoverageFacts
        (requestVoteEffect state source destination) activations := by
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
      activationVoteHistoryAfter,
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
    constructor
    · exact ownership.bootstrap
    · intro leader role
      exact
        ownership.activeLeader leader
          (by simpa [view_effects, view_effects] using role)
    · intro node index entry found
      exact
        ownership.logEntryAgreement node index entry
          (by simpa [view_effects, view_effects] using found)
    · intro queuedDestination queuedRequest member index entry found
      have oldMember :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [view_effects, view_effects] using member) with
          old | new
        · exact old
        · simp at new
      exact
        ownership.queuedHistoryEntryAgreement
          queuedDestination queuedRequest oldMember index entry found
    · intro leader role
      exact
        ownership.activeLeaderHistory leader
          (by simpa [view_effects, view_effects] using role)
    · exact ownership.canonicalEntryOwner
    · exact ownership.canonicalMonoLog
    · intro term owner owned
      simpa [view_effects, view_effects] using ownership.ownerProgress term owner owned
    · intro queuedDestination queuedRequest member
      have oldMember :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [view_effects, view_effects] using member) with
          old | new
        · exact old
        · simp at new
      exact
        ownership.queuedAppendMetadata
          queuedDestination queuedRequest oldMember
    · intro queuedDestination queuedRequest member sameTerm leaderRole
      have oldMember :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [view_effects, view_effects] using member) with
          old | new
        · exact old
        · simp at new
      exact
        ownership.queuedActiveSourceHistory
          queuedDestination queuedRequest oldMember
            (by simpa [view_effects, view_effects] using sameTerm)
            (by simpa [view_effects, view_effects] using leaderRole)
    · apply
        electionHistoryFrame
          state (requestVoteEffect state source destination)
            votes votes canonicalHistory canonicalHistory
            owners elections electionFacts
      · intros
        rfl
      · intro term
        exact prefixRefl (canonicalHistory term)
      · intro history canonical
        exact canonical
    · apply
        grantedVoteCanonicalFrame
          state (requestVoteEffect state source destination)
            canonicalHistory canonicalHistory
            voteCandidateHistory voteVoterHistory voteCanonicalFacts
            (fun candidate _ => by simp [view_effects, view_effects])
      · intro candidate active
        simpa [view_effects, view_effects] using active
      · intro candidate voter _ member
        rw [effectiveElectionVotersEq] at member
        exact member
      · intro history canonical
        exact canonical
    · exact temporalFacts.1
    · exact temporalFacts.2.1
    · exact temporalFacts.2.2
    · intro queuedDestination queuedRequest queued record recorded
      have oldMember :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest)
                queuedDestination
                (by simpa [view_effects, view_effects] using queued) with
          old | new
        · exact old
        · simp at new
      exact
        electionQueuedFacts
          queuedDestination queuedRequest oldMember record recorded
  · intro candidate voter active member
    have oldActive :
        (state.nodes candidate).role = .candidate \/
          (state.nodes candidate).role = .leader := by
      simpa [view_effects, view_effects] using active
    have oldMember :
        voter ∈ effectiveElectionVoters state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    simpa [view_effects, view_effects]
      using facts.grantedVoteSnapshots candidate voter oldActive oldMember
  · refine ⟨ackHistory, ?_⟩
    constructor
    · intro leader role peer zero
      exact
        ackFacts.zero leader
          (by simpa [view_effects, view_effects] using role)
          peer (by simpa [view_effects, view_effects] using zero)
    · intro leader role peer positive
      rcases
          ackFacts.positive leader
            (by simpa [view_effects, view_effects] using role)
            peer (by simpa [view_effects, view_effects] using positive) with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      exact ⟨
        snapshot,
        stored,
        by simpa [view_effects, view_effects] using snapshotTerm,
        by simpa [view_effects, view_effects] using snapshotIndex,
        historyBound,
        by simpa [view_effects, view_effects] using agreed
      ⟩
  · constructor
    · intro node peer member
      simpa [view_effects, view_effects]
        using facts.joinedCarriers.activeNodes node member
    · intro node configuration member peer inNodes
      exact
        facts.joinedCarriers.configurationNodes node configuration
          (by simpa [view_effects, view_effects] using member)
          (by simpa [view_effects, view_effects] using inNodes)
    · intro node peer member
      simpa [view_effects, view_effects]
        using facts.joinedCarriers.grantedVotes node member
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueue
            state.network (.requestVoteRequest request)
              (.requestVoteRequest queuedRequest) queuedDestination
              (by simpa [view_effects, view_effects, request] using member) with
        old | new
      · exact
          facts.joinedCarriers.voteRequestDestinations
            queuedDestination queuedRequest old
      · rcases new with ⟨destinationEq, requestEq⟩
        simp at requestEq
        subst queuedRequest
        rw [destinationEq]
        exact
          facts.joinedCarriers.activeNodes source enabled.2.2.2.2
    · intro queuedDestination queuedRequest member
      have old :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest) queuedDestination
                (by simpa [view_effects, view_effects, request] using member) with
          old | new
        · exact old
        · simp at new
      exact
        facts.joinedCarriers.appendRequestDestinations
          queuedDestination queuedRequest old
    · intro queuedDestination queuedRequest member configuration configured
        peer inNodes
      have old :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.appendEntriesRequest queuedRequest) queuedDestination
                (by simpa [view_effects, view_effects, request] using member) with
          old | new
        · exact old
        · simp at new
      exact
        facts.joinedCarriers.appendRequestConfigurations
          queuedDestination queuedRequest old configuration configured
            inNodes
    · intro queuedDestination response member
      have old :
          Message.requestVoteResponse response ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteRequest request)
                (.requestVoteResponse response) queuedDestination
                (by simpa [view_effects, view_effects, request] using member) with
          old | new
        · exact old
        · simp at new
      simpa [view_effects, view_effects]
        using facts.joinedCarriers.voteResponseSources queuedDestination response old
    · constructor
      · intro node active
        simpa [view_effects, view_effects]
          using facts.joinedCarriers.runtimeNodes.activeRoles node
            (by simpa [view_effects, view_effects] using active)
      · intro leader peer positive
        simpa [view_effects, view_effects]
          using facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
            (by simpa [view_effects, view_effects] using positive)
      · intro queuedDestination response member
        have old :
            Message.appendEntriesResponse response ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.requestVoteRequest request)
                  (.appendEntriesResponse response) queuedDestination
                  (by simpa [view_effects, view_effects, request] using member) with
            old | new
          · exact old
          · simp at new
        simpa [view_effects, view_effects]
          using facts.joinedCarriers.runtimeNodes.appendResponses
            queuedDestination response old
      · intro node nonempty
        simpa [view_effects, view_effects]
          using facts.joinedCarriers.runtimeNodes.nonemptyLogs node
            (by simpa [view_effects, view_effects] using nonempty)
  · exact
      AllocatedNodesExactlyJoined.frame
        facts.allocatedNodesExactlyJoined
        (fun _ => Iff.rfl)
        rfl

  · exact facts.currentTermsValid
  · simpa only [NetworkTermsValid, view_effects, view_effects]
      using (networkTermsValidEnqueue
              (message := .requestVoteRequest request)
              facts.networkTermsValid (facts.currentTermsValid source))

end CCFRaft.Proofs.Invariant
