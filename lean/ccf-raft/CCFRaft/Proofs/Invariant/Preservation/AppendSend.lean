-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.VoteSend
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

/-- A request built by an enabled arbitrary-term leader snapshots its log. -/
lemma madeAppendRequestSupport
    (state : View Node TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (commitBounded : CommitIndicesBounded state)
    (_progress : LeaderProgressBounded state)
    (enabled
      : (state.allocated source
          /\ state.allocated destination
          /\ (state.nodes source).role = .leader
          /\ Not (source = destination)
          /\ (destination ∈ activeNodeUnion (state.nodes source)
              \/ destination ∈ (state.nodes source).retirementCompleted)
          /\ (state.nodes source).sentIndex destination <= batchEnd
          /\ batchEnd <= (state.nodes source).log.length
          /\ ((messageEntries (state.nodes source).log
                ((state.nodes source).sentIndex destination) batchEnd).all
                fun entry => entry.term == termAt (state.nodes source).log batchEnd)
              = true
          /\ (Not ((state.nodes source).membershipState = .retiredCommitted)
              \/ (state.nodes source).sentIndex destination < batchEnd)))
    : let request := makeAppendEntriesRequest state source destination batchEnd
      RequestSnapshots (state.nodes source).log request
      /\ request.leaderCommit <= (state.nodes source).log.length
      /\ RequestCommitStillPresent state (state.nodes source).log request := by
  rcases enabled with
    ⟨_sourceAllocated, _destinationAllocated, _leaderRole, _different,
      _destinationActive, previousBeforeEnd, endWithin, _singleTerm, _sendAllowed⟩
  let previousIndex := (state.nodes source).sentIndex destination
  have entriesLength :
      (messageEntries
        (state.nodes source).log previousIndex batchEnd).length =
          batchEnd - previousIndex :=
    messageEntriesLength
      (state.nodes source).log previousBeforeEnd endWithin
  dsimp [previousIndex] at *
  refine ⟨?_, ?_, ?_⟩
  · unfold RequestSnapshots
    simp only [makeAppendEntriesRequest]
    refine ⟨?_, by simp, ?_⟩
    · rw [entriesLength]
      omega
    · rw [entriesLength]
      have sumEq :
          (state.nodes source).sentIndex destination +
              (batchEnd - (state.nodes source).sentIndex destination) =
            batchEnd := by
        omega
      simpa [messageEntries, sumEq]
        using (List.take_add
                (l := (state.nodes source).log)
                (i := (state.nodes source).sentIndex destination)
                (j := batchEnd - (state.nodes source).sentIndex destination))
  · simpa [makeAppendEntriesRequest] using commitBounded source
  · unfold RequestCommitStillPresent
    simp only [makeAppendEntriesRequest]
    exact prefixRefl _

/-- Sending AppendEntries updates one cursor and enqueues one snapshot. -/
lemma appendEntriesPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : (state.allocated source
          /\ state.allocated destination
          /\ (state.nodes source).role = .leader
          /\ Not (source = destination)
          /\ (destination ∈ activeNodeUnion (state.nodes source)
              \/ destination ∈ (state.nodes source).retirementCompleted)
          /\ (state.nodes source).sentIndex destination <= batchEnd
          /\ batchEnd <= (state.nodes source).log.length
          /\ ((messageEntries (state.nodes source).log
                ((state.nodes source).sentIndex destination) batchEnd).all
                fun entry => entry.term == termAt (state.nodes source).log batchEnd)
              = true
          /\ (Not ((state.nodes source).membershipState = .retiredCommitted)
              \/ (state.nodes source).sentIndex destination < batchEnd)))
    : SystemInductiveInvariant
        (appendEntriesEffect state source destination batchEnd) := by
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
  let request := makeAppendEntriesRequest state source destination batchEnd
  let newAppendHistory :=
    Function.update appendHistory request (state.nodes source).log
  let newRequestEvidence : RequestCommitEvidence Node TxId :=
    Function.update
      requestEvidence request (nodeEvidence source)
  have requestSupport :=
    madeAppendRequestSupport
      state source destination batchEnd
        facts.commitIndicesBounded facts.leaderProgressBounded enabled
  have roleEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).role =
          (state.nodes node).role := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        view_effects, updateNode, nodeEq
      ]
  have currentTermEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        view_effects, updateNode, nodeEq
      ]
  have logEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).log =
          (state.nodes node).log := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        view_effects, updateNode, nodeEq
      ]
  have commitIndexEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).commitIndex =
          (state.nodes node).commitIndex := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        view_effects, updateNode, nodeEq
      ]
  have lastIndexEq :
      forall node,
        lastCommittableIndex
            ((appendEntriesEffect state source destination batchEnd).nodes node) =
          lastCommittableIndex (state.nodes node) := by
    intro node
    exact lastCommittableIndexFrame (logEq node) (commitIndexEq node)
  have lastTermEq :
      forall node,
        lastCommittableTerm
            ((appendEntriesEffect state source destination batchEnd).nodes node) =
          lastCommittableTerm (state.nodes node) := by
    intro node
    exact lastCommittableTermFrame (logEq node) (commitIndexEq node)
  have votedForEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).votedFor =
          (state.nodes node).votedFor := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        view_effects, updateNode, nodeEq
      ]
  have votesGrantedEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).votesGranted =
          (state.nodes node).votesGranted := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        view_effects, updateNode, nodeEq
      ]
  have matchEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).matchIndex =
          (state.nodes node).matchIndex := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        view_effects, updateNode, nodeEq
      ]
  have committedEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).committedLog =
          (state.nodes node).committedLog := by
    intro node
    simp [NodeState.committedLog, commitIndexEq, logEq]
  have activeConfigurationsEq :
      forall node,
        activeConfigurations
            ((appendEntriesEffect state source destination batchEnd).nodes node) =
          activeConfigurations (state.nodes node) := by
    intro node
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitIndexEq]
  have currentConfigurationEq :
      forall node,
        currentConfiguration
            ((appendEntriesEffect state source destination batchEnd).nodes node) =
          currentConfiguration (state.nodes node) := by
    intro node
    unfold currentConfiguration
    rw [logEq, commitIndexEq]
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers
            (appendEntriesEffect state source destination batchEnd)
            responseHistory leader index =
          effectiveAckers state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter]
    constructor
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨by simpa [view_effects] using joined, Or.inl self⟩
      · exact ⟨
          by simpa [view_effects] using joined,
          Or.inr (Or.inl (by simpa [matchEq] using matched))
        ⟩
      · refine ⟨
          by simpa [view_effects] using joined,
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
                state.network (.appendEntriesRequest request)
                  (.appendEntriesResponse response) leader
                  (by simpa [view_effects, request] using member) with
            old | new
          · exact old
          · simp at new
        exact ⟨
          response,
          oldMember,
          success,
          by simpa [currentTermEq] using term,
          sourceEq,
          destinationEq,
          lastIndex,
          by simpa [logEq] using covered
        ⟩
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨by simpa [view_effects] using joined, Or.inl self⟩
      · exact ⟨
          by simpa [view_effects] using joined,
          Or.inr (Or.inl (by simpa [matchEq] using matched))
        ⟩
      · refine ⟨by simpa [view_effects] using joined, Or.inr (Or.inr ?_)⟩
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        refine ⟨
          response,
          ?_,
          success,
          by simpa [currentTermEq] using term,
          sourceEq,
          destinationEq,
          lastIndex,
          by simpa [logEq] using covered
        ⟩
        simpa [view_effects, request]
          using memEnqueueNoDupOfMem
            state.network (.appendEntriesRequest request)
            (.appendEntriesResponse response) leader member
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt
            (appendEntriesEffect state source destination batchEnd)
            responseHistory leader index ↔
          hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader index
    unfold hasEffectiveMajorityAt
    rw [activeConfigurationsEq, effectiveAckersEq]
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters
            (appendEntriesEffect state source destination batchEnd)
            candidate =
          effectiveElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [view_effects] using joined,
          Or.inl (by simpa [votesGrantedEq] using processed)
        ⟩
      · refine ⟨
          by simpa [view_effects] using joined,
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
                state.network (.appendEntriesRequest request)
                  (.requestVoteResponse response) candidate
                  (by simpa [view_effects, request] using member) with
            old | new
          · exact old
          · simp at new
        exact ⟨
          response,
          oldMember,
          granted,
          by simpa [currentTermEq] using responseTerm,
          responseSource,
          responseDestination
        ⟩
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [view_effects] using joined,
          Or.inl (by simpa [votesGrantedEq] using processed)
        ⟩
      · refine ⟨by simpa [view_effects] using joined, Or.inr ?_⟩
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        refine ⟨
          response,
          ?_,
          granted,
          by simpa [currentTermEq] using responseTerm,
          responseSource,
          responseDestination
        ⟩
        simpa [view_effects, request]
          using memEnqueueNoDupOfMem
            state.network (.appendEntriesRequest request)
            (.requestVoteResponse response) candidate member
  have effectiveElectionMajorityEq :
      forall candidate,
        hasEffectiveElectionMajority
            (appendEntriesEffect state source destination batchEnd)
            candidate ↔
          hasEffectiveElectionMajority state candidate := by
    intro candidate
    simp only [
      hasEffectiveElectionMajority,
      effectiveElectionVotersEq,
      activeConfigurationsEq
    ]
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters
            (appendEntriesEffect state source destination batchEnd)
            candidate =
          potentialElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨by simpa [view_effects] using joined, Or.inl (by
          rw [effectiveElectionVotersEq] at effective
          exact effective)⟩
      · exact ⟨by simpa [view_effects] using joined, Or.inr (by
          simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          currentTermEq, logEq, commitIndexEq, votedForEq,
          lastCommittableIndexFrame
            (logEq candidate) (commitIndexEq candidate),
          lastCommittableTermFrame
            (logEq candidate) (commitIndexEq candidate),
          voteLogUpToDate
          ] using eligible)⟩
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨by simpa [view_effects] using joined, Or.inl (by
          rw [effectiveElectionVotersEq]
          exact effective)⟩
      · exact ⟨by simpa [view_effects] using joined, Or.inr (by
          simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          currentTermEq, logEq, commitIndexEq, votedForEq,
          lastCommittableIndexFrame
            (logEq candidate) (commitIndexEq candidate),
          lastCommittableTermFrame
            (logEq candidate) (commitIndexEq candidate),
          voteLogUpToDate
          ] using eligible)⟩
  have potentialElectionMajorityEq :
      forall candidate,
        hasPotentialElectionMajority
            (appendEntriesEffect state source destination batchEnd)
            candidate ↔
          hasPotentialElectionMajority state candidate := by
    intro candidate
    simp only [
      hasPotentialElectionMajority,
      potentialElectionVotersEq,
      activeConfigurationsEq
    ]
  have requestSupportAfter :
      RequestSnapshots (state.nodes source).log request /\
        request.leaderCommit <= (state.nodes source).log.length /\
        RequestCommitStillPresent
          (appendEntriesEffect state source destination batchEnd)
          (state.nodes source).log request := by
    refine ⟨requestSupport.1, requestSupport.2.1, ?_⟩
    unfold RequestCommitStillPresent at requestSupport ⊢
    rw [committedEq]
    exact requestSupport.2.2
  have temporalFacts :=
    ackerTemporalFrameSameLogs
      state (appendEntriesEffect state source destination batchEnd)
        votes votes responseHistory voteVoterHistory elections
        ackerCurrentFacts ackerVoteFacts ackerElectionFacts
        (fun leader role => by simpa [roleEq] using role)
        (fun leader _ => currentTermEq leader)
        logEq
        (fun leader index voter _ _ member => by
          rw [effectiveAckersEq] at member
          exact member)
        (fun node => Nat.le_of_eq (currentTermEq node).symm)
        (fun _ _ _ voted _ => voted)
  have ackerActivationAfter :
      AckerActivationHistory
        (appendEntriesEffect state source destination batchEnd)
        responseHistory elections activations := by
    apply
      ackerActivationFrameSameLogs
        state (appendEntriesEffect state source destination batchEnd)
          responseHistory elections elections activations
          ackerActivationFacts
    · intro leader role
      simpa [roleEq] using role
    · intro leader role
      exact currentTermEq leader
    · exact logEq
    · intro leader index supporter role current member
      rw [effectiveAckersEq] at member
      exact member
    · intro term record stored
      exact stored
  refine ⟨
    votes,
    newAppendHistory,
    responseHistory,
    voteRequestHistory,
    voteCandidateHistory,
    voteVoterHistory,
    ?_
  ⟩
  constructor
  · intro node
    rw [commitIndexEq, logEq]
    exact facts.commitIndicesBounded node
  · intro node participating
    rw [currentTermEq]
    apply facts.currentTermsPositive node
    intro none
    apply participating
    simpa [roleEq] using none
  · intro node entry member
    rw [logEq] at member
    rw [currentTermEq]
    exact facts.entriesDoNotExceedCurrentTerm node entry member
  · intro node role
    rw [roleEq] at role
    rw [votedForEq, votesGrantedEq]
    exact facts.candidatesSelfVote node role
  · intro leader role
    rw [roleEq] at role
    have old := facts.leadersHaveElectionWitness leader role
    rw [currentTermEq]
    rcases old with bootstrap | majority
    · exact Or.inl bootstrap
    · exact Or.inr (by
        simpa [logEq, votesGrantedEq] using majority)
  · intro leader role peer
    have oldRole :
        (state.nodes leader).role = .leader := by
      by_cases leaderEq : leader = source <;>
        simpa [
          view_effects, updateNode,
          Function.update, leaderEq
        ] using role
    have oldProgress := facts.leaderProgressBounded leader oldRole peer
    by_cases leaderEq : leader = source
    · subst leader
      constructor
      · by_cases peerEq : peer = destination
        · subst peer
          simp [
            view_effects, updateIndex,
            Function.update
          ]
          exact enabled.2.2.2.2.2.2.1
        · simpa [
            view_effects, updateIndex,
            Function.update, peerEq
          ] using oldProgress.1
      · simpa [view_effects] using oldProgress.2
    · simpa [
        view_effects, updateNode,
        Function.update, leaderEq
      ] using oldProgress
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [currentTermEq, votedForEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      apply facts.voteHistory.future voter term
      rw [currentTermEq] at future
      exact future
    · intro candidate voter active member
      rw [currentTermEq]
      apply facts.voteHistory.counted candidate voter
      · rw [roleEq] at active
        exact active
      · rw [votesGrantedEq] at member
        exact member
  · constructor
    · intro queuedDestination message member
      rcases
          memEnqueue
            state.network (.appendEntriesRequest request)
              message queuedDestination
              (by simpa [view_effects, request] using member) with
        old | new
      · exact facts.networkHistory.addressed queuedDestination message old
      · rcases new with ⟨destinationEq, messageEq⟩
        subst message
        simpa [request, makeAppendEntriesRequest] using destinationEq.symm
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueue
            state.network (.appendEntriesRequest request)
              (.appendEntriesRequest queuedRequest) queuedDestination
              (by simpa [view_effects, request] using member) with
        old | new
      · by_cases sameRequest : queuedRequest = request
        · subst queuedRequest
          simpa [
            newAppendHistory, Function.update, request
          ] using requestSupportAfter
        · have oldFacts :=
            facts.networkHistory.appendRequest
              queuedDestination queuedRequest old
          have historyEq :
              newAppendHistory queuedRequest =
                appendHistory queuedRequest := by
            simp [newAppendHistory, sameRequest]
          rw [historyEq]
          refine ⟨oldFacts.1, oldFacts.2.1, ?_⟩
          unfold RequestCommitStillPresent at oldFacts ⊢
          rw [committedEq]
          exact oldFacts.2.2
      · rcases new with ⟨destinationEq, messageEq⟩
        simp only [Message.appendEntriesRequest.injEq] at messageEq
        subst queuedRequest
        simpa [
          newAppendHistory, Function.update, request
        ] using requestSupportAfter
    · intro queuedDestination response member
      have old :
          Message.appendEntriesResponse response ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.appendEntriesRequest request)
                (.appendEntriesResponse response) queuedDestination
                (by simpa [view_effects, request] using member) with
          old | new
        · exact old
        · simp at new
      intro success
      rcases
          facts.networkHistory.appendResponse queuedDestination response old
            success with
        ⟨lengthBound, termBound, supported⟩
      refine ⟨lengthBound, by simpa [currentTermEq] using termBound, ?_⟩
      intro sameTerm
      rcases supported (by simpa [currentTermEq] using sameTerm) with
        active | follower | preVoteCandidate
      · exact Or.inl
          ⟨by simpa [roleEq] using active.1,
            by simpa [logEq] using active.2⟩
      · exact Or.inr (Or.inl (by simpa [roleEq] using follower))
      · exact
          Or.inr (Or.inr (by simpa [roleEq] using preVoteCandidate))
    · intro queuedDestination voteRequest member
      have old :
          Message.requestVoteRequest voteRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.appendEntriesRequest request)
                (.requestVoteRequest voteRequest) queuedDestination
                (by simpa [view_effects, request] using member) with
          old | new
        · exact old
        · simp at new
      rcases
          facts.networkHistory.voteRequest
            queuedDestination voteRequest old with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      exact ⟨
        lastIndex,
        lastTerm,
        maxIndex,
        aboveBootstrap,
        by simpa [currentTermEq] using termBound,
        fun sameTerm active => by
          have oldSameTerm :
              voteRequest.term =
                (state.nodes voteRequest.source).currentTerm := by
            simpa [currentTermEq] using sameTerm
          have oldActive :
              (state.nodes voteRequest.source).role = .candidate \/
                (state.nodes voteRequest.source).role = .leader := by
            simpa [roleEq] using active
          simpa [logEq] using activePrefix oldSameTerm oldActive
      ⟩
    · intro queuedDestination response member granted
      have old :
          Message.requestVoteResponse response ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.appendEntriesRequest request)
                (.requestVoteResponse response) queuedDestination
                (by simpa [view_effects, request] using member) with
          old | new
        · exact old
        · simp at new
      rcases
          facts.networkHistory.voteResponse
            queuedDestination response old granted with
        ⟨termBound, recorded, upToDate⟩
      exact ⟨
        by simpa [currentTermEq] using termBound,
        recorded,
        by simpa [voteLogUpToDate] using upToDate
      ⟩
  have evidenceAfter :
      CommitEvidenceFacts
        (appendEntriesEffect state source destination batchEnd)
        newAppendHistory nodeEvidence newRequestEvidence := by
    constructor
    · intro node positive
      have oldPositive :
          0 < (state.nodes node).commitIndex := by
        rw [commitIndexEq] at positive
        exact positive
      rcases evidenceFacts.nodePositive node oldPositive with
        ⟨evidence, stored, valid, lengthEq, termBound⟩
      exact ⟨
        evidence,
        stored,
        by simpa [committedEq] using valid,
        by simpa [commitIndexEq] using lengthEq,
        by simpa [currentTermEq] using termBound
      ⟩
    · intro queuedDestination queuedRequest member positive
      by_cases sameRequest : queuedRequest = request
      · subst queuedRequest
        have sourcePositive :
            0 < (state.nodes source).commitIndex := by
          simpa [request, makeAppendEntriesRequest] using positive
        rcases
            evidenceFacts.nodePositive source sourcePositive with
          ⟨evidence, stored, valid, lengthEq, termBound⟩
        refine ⟨
          evidence,
          by simpa [
              newRequestEvidence, Function.update
            ] using stored,
          ?_,
          ?_,
          ?_
        ⟩
        · simpa [
            newAppendHistory, Function.update,
            request, makeAppendEntriesRequest,
            NodeState.committedLog
          ] using valid
        · simpa [request, makeAppendEntriesRequest] using lengthEq
        · simpa [request, makeAppendEntriesRequest] using termBound
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects] using member) with
            old | new
          · exact old
          · simp at new
            exact False.elim (sameRequest new.2)
        rcases
            evidenceFacts.requestPositive
              queuedDestination queuedRequest oldMember positive with
          ⟨evidence, stored, valid, lengthEq, termBound⟩
        exact ⟨
          evidence,
          by simpa [
              newRequestEvidence, Function.update, sameRequest
            ] using stored,
          by simpa [
              newAppendHistory, Function.update, sameRequest
            ] using valid,
          lengthEq,
          termBound
        ⟩
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        (appendEntriesEffect state source destination batchEnd)
        newAppendHistory nodeEvidence newRequestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state (appendEntriesEffect state source destination batchEnd)
          appendHistory newAppendHistory
          nodeEvidence nodeEvidence
          requestEvidence newRequestEvidence elections prospectiveFacts
    · intro evidence supportedPrefix known
      rcases known with nodeKnown | requestKnown
      · rcases nodeKnown with
          ⟨node, positive, stored, prefixEq⟩
        exact Or.inl
          ⟨node,
            by simpa [commitIndexEq] using positive,
            stored,
            by simpa [committedEq] using prefixEq⟩
      · rcases requestKnown with
          ⟨queuedDestination, queuedRequest, member,
            positive, stored, prefixEq⟩
        by_cases sameRequest : queuedRequest = request
        · subst queuedRequest
          have sourcePositive :
              0 < (state.nodes source).commitIndex := by
            simpa [request, makeAppendEntriesRequest] using positive
          have sourceStored :
              nodeEvidence source = some evidence := by
            simpa [newRequestEvidence, Function.update] using stored
          exact Or.inl
            ⟨
              source,
              sourcePositive,
              sourceStored,
              by simpa [
                  newAppendHistory, Function.update,
                  request, makeAppendEntriesRequest,
                  NodeState.committedLog
                ] using prefixEq
            ⟩
        · have oldMember :
              Message.appendEntriesRequest queuedRequest ∈
                state.network queuedDestination := by
            rcases
                memEnqueue
                  state.network (.appendEntriesRequest request)
                    (.appendEntriesRequest queuedRequest)
                    queuedDestination
                    (by simpa [view_effects] using member) with
              old | new
            · exact old
            · simp at new
              exact False.elim (sameRequest new.2)
          exact Or.inr
            ⟨queuedDestination, queuedRequest, oldMember,
              positive,
              by simpa [
                newRequestEvidence, Function.update, sameRequest
              ] using stored,
              by simpa [
                newAppendHistory, Function.update, sameRequest
              ] using prefixEq⟩
    · intro member
      simp [logEq]
    · intro evidence supportedPrefix queuedDestination queuedRequest
        known queued sameTerm
      by_cases sameRequest : queuedRequest = request
      · subst queuedRequest
        right
        right
        have oldKnown :
            KnownCommitEvidence
              state appendHistory nodeEvidence requestEvidence
                evidence supportedPrefix := by
          rcases known with nodeKnown | requestKnown
          · rcases nodeKnown with
              ⟨node, positive, stored, prefixEq⟩
            exact Or.inl
              ⟨node,
                by simpa [commitIndexEq] using positive,
                stored,
                by simpa [committedEq] using prefixEq⟩
          · rcases requestKnown with
              ⟨knownDestination, knownRequest, queuedMember,
                positive, stored, prefixEq⟩
            by_cases knownRequestEq : knownRequest = request
            · subst knownRequest
              have sourcePositive :
                  0 < (state.nodes source).commitIndex := by
                simpa [request, makeAppendEntriesRequest] using positive
              have sourceStored :
                  nodeEvidence source = some evidence := by
                simpa [newRequestEvidence, Function.update] using stored
              exact Or.inl
                ⟨
                  source,
                  sourcePositive,
                  sourceStored,
                  by simpa [
                      newAppendHistory, Function.update,
                      request, makeAppendEntriesRequest,
                      NodeState.committedLog
                    ] using prefixEq
                ⟩
            · have oldMember :
                  Message.appendEntriesRequest knownRequest ∈
                    state.network knownDestination := by
                rcases
                    memEnqueue
                      state.network (.appendEntriesRequest request)
                        (.appendEntriesRequest knownRequest)
                        knownDestination
                        (by simpa [view_effects] using
                          queuedMember) with
                  old | new
                · exact old
                · simp at new
                  exact False.elim (knownRequestEq new.2)
              exact Or.inr
                ⟨knownDestination, knownRequest, oldMember,
                  positive,
                  by simpa [
                    newRequestEvidence, Function.update,
                    knownRequestEq
                  ] using stored,
                  by simpa [
                    newAppendHistory, Function.update,
                    knownRequestEq
                  ] using prefixEq⟩
        rcases
            knownCommitEvidenceValid evidenceFacts oldKnown with
          ⟨_, _, _, _, _, ackMajority, _, _⟩
        rcases configurationMajorityNonempty ackMajority with
          ⟨member, _authorityMember, ackMember⟩
        have leaderCovered :=
          knownCommitEvidenceActiveLeaderContainsFrontier
            ownership electionFacts evidenceFacts prospectiveFacts
            oldKnown enabled.2.2.1
            (by simpa [request, makeAppendEntriesRequest] using Nat.le_of_eq sameTerm)
            ackMember
        simpa [newAppendHistory, Function.update, request, makeAppendEntriesRequest]
          using leaderCovered
      · left
        have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects] using queued) with
            old | new
          · exact old
          · simp at new
            exact False.elim (sameRequest new.2)
        exact ⟨
          oldMember,
          by simp [
              newAppendHistory, sameRequest
            ]
        ⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      left
      refine ⟨
        by simpa [roleEq] using role,
        by simpa [currentTermEq] using newer,
        ?_,
        ?_,
        by simp [logEq]
      ⟩
      · intro entry entryMember
        simpa [currentTermEq]
          using entriesBefore entry (by simpa [logEq] using entryMember)
      · simp only [
          relaxedElectionVoters, Finset.mem_filter] at relaxed ⊢
        rcases relaxed with ⟨joined, effective | upToDate⟩
        · rw [effectiveElectionVotersEq] at effective
          exact ⟨
            by simpa [view_effects] using joined,
            Or.inl effective
          ⟩
        · exact ⟨
            by simpa [view_effects] using joined,
            Or.inr
              (by
                simpa [makeRequestVoteRequest, currentTermEq, logEq, lastIndexEq,
                  lastTermEq, voteLogUpToDate]
                  using upToDate)
          ⟩
  have configurationFactsAfter :
      ElectionConfigurationFacts
        (appendEntriesEffect state source destination batchEnd)
        elections activations := by
    apply
      electionConfigurationFrame
        state (appendEntriesEffect state source destination batchEnd)
        elections activations activations configurationFacts
    · intro _ _ stored
      exact stored
    · apply
        activationSupporterCurrentHistoryFrame
          state (appendEntriesEffect state source destination batchEnd)
          elections elections activations
          configurationFacts.supporterCurrentHistory
      · intro candidate
        rw [logEq]
      · intro candidate
        exact Nat.le_of_eq (currentTermEq candidate).symm
      · intro _ _ stored
        exact stored
    · intro candidate role majority
      exact ⟨
        by simpa [roleEq] using role,
        by simp [currentTermEq],
        (effectiveElectionMajorityEq candidate).mp majority
      ⟩
    · intro candidate configuration role active
      simpa [activeConfigurationsEq] using active
    · intro candidate role entry member
      simpa [currentTermEq]
        using configurationFacts.candidateEntriesBeforeTerm
          candidate
          (by simpa [roleEq] using role)
          entry
          (by simpa [logEq] using member)
  have activationProgressAfter :
      ActivationSupporterProgress
        (appendEntriesEffect state source destination batchEnd)
        activations := by
    apply
      activationSupporterProgressFrame
        state (appendEntriesEffect state source destination batchEnd)
          activations activationProgress
    intro candidate
    rw [currentTermEq]
  have ownershipAfter :
      TermOwnershipFacts
        (appendEntriesEffect state source destination batchEnd)
        votes newAppendHistory canonicalHistory owners := by
    apply
      termOwnershipFrame
        state (appendEntriesEffect state source destination batchEnd)
          appendHistory newAppendHistory votes canonicalHistory owners
          ownership
    · intro leader role
      simpa [roleEq] using role
    · intro owner role
      simpa [roleEq] using role
    · exact currentTermEq
    · exact logEq
    · intro queuedDestination queuedRequest member index entry found
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        have sourceFound :
            entryAt? (state.nodes source).log index = some entry := by
          simpa [newAppendHistory, Function.update] using found
        rcases
            ownership.logEntryAgreement
              source index entry sourceFound with
          ⟨canonicalFound, agreed⟩
        exact ⟨canonicalFound, by simpa [newAppendHistory, Function.update] using agreed⟩
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects] using member) with
            old | new
          · exact old
          · simp only [Message.appendEntriesRequest.injEq] at new
            exact False.elim (requestEq new.2)
        have oldFound :
            entryAt? (appendHistory queuedRequest) index = some entry := by
          simpa [newAppendHistory, Function.update, requestEq] using found
        rcases
            ownership.queuedHistoryEntryAgreement
              queuedDestination queuedRequest oldMember
                index entry oldFound with
          ⟨canonicalFound, agreed⟩
        exact ⟨
          canonicalFound,
          by simpa [
              newAppendHistory, Function.update, requestEq
            ] using agreed
        ⟩
    · intro queuedDestination queuedRequest member
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        refine ⟨?_, ?_, ?_⟩
        · simpa [request, makeAppendEntriesRequest] using enabled.2.2.2.1
        · simpa [request, makeAppendEntriesRequest]
            using ownership.activeLeader source enabled.2.2.1
        · intro entry entryMember
          have sourceMember :
              entry ∈ (state.nodes source).log := by
            simpa [newAppendHistory, Function.update] using entryMember
          simpa [request, makeAppendEntriesRequest]
            using facts.entriesDoNotExceedCurrentTerm source entry sourceMember
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects] using member) with
            old | new
          · exact old
          · simp only [Message.appendEntriesRequest.injEq] at new
            exact False.elim (requestEq new.2)
        rcases
            ownership.queuedAppendMetadata
              queuedDestination queuedRequest oldMember with
          ⟨different, owned, bounded⟩
        exact ⟨
          different,
          owned,
          by simpa [
              newAppendHistory, Function.update, requestEq
            ] using bounded
        ⟩
    · intro queuedDestination queuedRequest member sameTerm leaderRole
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        have requestSource : request.source = source := by
          simp [request, makeAppendEntriesRequest]
        have historyEq :
            newAppendHistory request = (state.nodes source).log := by
          simp [newAppendHistory]
        rw [historyEq, requestSource, logEq]
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects] using member) with
            old | new
          · exact old
          · simp only [Message.appendEntriesRequest.injEq] at new
            exact False.elim (requestEq new.2)
        have oldPrefix :=
          ownership.queuedActiveSourceHistory
            queuedDestination queuedRequest oldMember
              (by simpa [currentTermEq] using sameTerm)
              (by simpa [roleEq] using leaderRole)
        simpa [
          newAppendHistory, Function.update, requestEq, logEq
        ] using oldPrefix
  have voteFactsAfter :
      VoteHistoryFacts
        (appendEntriesEffect state source destination batchEnd) votes := by
    constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [currentTermEq, votedForEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      apply facts.voteHistory.future voter term
      simpa [currentTermEq] using future
    · intro candidate voter active member
      rw [currentTermEq]
      apply facts.voteHistory.counted candidate voter
      · simpa [roleEq] using active
      · simpa [votesGrantedEq] using member
  have electionFactsAfter :
      ElectionHistoryFacts
        (appendEntriesEffect state source destination batchEnd)
        votes canonicalHistory owners elections := by
    apply
      electionHistoryFrame
        state (appendEntriesEffect state source destination batchEnd)
          votes votes canonicalHistory canonicalHistory
          owners elections electionFacts
    · intros
      rfl
    · intro term
      exact prefixRefl (canonicalHistory term)
    · intro history canonical
      exact canonical
  have configurationActivationsForBridge :
      ConfigurationCoverageFacts
        (appendEntriesEffect state source destination batchEnd)
        activations := by
    apply
      configurationCoverageFrame
        configurationActivations currentConfigurationEq
        (fun node => by rw [currentTermEq])
        (fun node => by rw [commitIndexEq])
        (fun node frontier _ => by rw [logEq])
    · intro node witness role
      simpa [currentTermEq]
        using witness.candidateTermStrict (by simpa [roleEq] using role)
  have activationQuorumsAfter :
      ActivationQuorumFacts
        (appendEntriesEffect state source destination batchEnd)
        newAppendHistory responseHistory elections activations := by
    constructor
    · exact activationQuorums.history
    · intro bridgeSource bridgeIndex role current signature
        bridgePotential term record recorded later
      exact Or.inl
        (potentialPrefixInElectionRecordsFromActivationHistory
          (by
            intro candidate participating
            rw [currentTermEq]
            apply facts.currentTermsPositive candidate
            intro none
            apply participating
            simpa [roleEq] using none)
          (by
            intro candidate entry member
            rw [logEq] at member
            rw [currentTermEq]
            exact
              facts.entriesDoNotExceedCurrentTerm
                candidate entry member)
          voteFactsAfter ownershipAfter electionFactsAfter
          configurationFactsAfter activationQuorums.history
          activationProgressAfter ackerActivationAfter
          temporalFacts.2.2 activationCanonical activationElections
          configurationActivationsForBridge evidenceAfter prospectiveAfter
          role current signature bridgePotential
          term record recorded later)
    · intro bridgeSource bridgeIndex role current signature
        bridgePotential candidate candidateRole candidateMajority later
      have oldRole : (state.nodes bridgeSource).role = .leader := by
        simpa [roleEq] using role
      have oldCurrent :
          termAt (state.nodes bridgeSource).log bridgeIndex =
            (state.nodes bridgeSource).currentTerm := by
        simpa [logEq, currentTermEq] using current
      have oldSignature :
          isSignatureAt (state.nodes bridgeSource).log bridgeIndex = true := by
        simpa [logEq] using signature
      have oldCandidateRole :
          (state.nodes candidate).role = .candidate := by
        simpa [roleEq] using candidateRole
      have oldCandidateMajority :
          hasPotentialElectionMajority state candidate :=
        (potentialElectionMajorityEq candidate).mp candidateMajority
      by_cases oldPotential :
          hasPotentialMajorityAt
            state appendHistory responseHistory bridgeSource bridgeIndex
      · rcases
            activationQuorums.candidateBridge
              bridgeSource bridgeIndex oldRole oldCurrent oldSignature
              oldPotential candidate oldCandidateRole oldCandidateMajority
              (by simpa [currentTermEq] using later) with
          direct | shared
        · exact Or.inl (by simpa [logEq] using direct)
        · right
          rcases shared with
            ⟨configuration, sourceActive, governs, candidateActive⟩
          exact ⟨
            configuration,
            by simpa [activeConfigurationsEq] using sourceActive,
            governs,
            by simpa [activeConfigurationsEq] using candidateActive
          ⟩
      · by_cases bridgeCommitted :
            bridgeIndex <= (state.nodes bridgeSource).commitIndex
        · have bridgeIndexPositive : 0 < bridgeIndex := by
            rcases isSignatureAtTrue oldSignature with
              ⟨entry, found, _⟩
            have nonzero : Not (bridgeIndex = 0) := by
              intro zero
              rw [zero] at found
              simp [entryAt?] at found
            exact Nat.pos_of_ne_zero nonzero
          have commitPositive :
              0 < (state.nodes bridgeSource).commitIndex := by omega
          rcases evidenceFacts.nodePositive bridgeSource commitPositive with
            ⟨evidence, stored, _valid, _lengthEq, termBound⟩
          have known :
              KnownCommitEvidence
                state appendHistory nodeEvidence requestEvidence
                  evidence (state.nodes bridgeSource).committedLog :=
            Or.inl ⟨bridgeSource, commitPositive, stored, rfl⟩
          have committedInCandidate :=
            prospectiveKnownEffectiveWinnerCompleteness
              facts.entriesDoNotExceedCurrentTerm
              (invariantFactsCandidatesAboveBootstrap facts)
              facts.voteHistory facts.grantedVoteSnapshots
              ownership electionFacts configurationFacts
              evidenceFacts prospectiveFacts activationEvidence
              known oldCandidateRole oldCandidateMajority
              (termBound.trans_lt
                (by simpa [currentTermEq] using later))
          have sourceBound :
              bridgeIndex <= (state.nodes bridgeSource).log.length := by
            rcases isSignatureAtTrue oldSignature with
              ⟨entry, found, _⟩
            exact entryAtSomeIndexBound found
          have sourceInCommitted :
              (state.nodes bridgeSource).log.take bridgeIndex <+:
                (state.nodes bridgeSource).committedLog := by
            unfold NodeState.committedLog
            rw [List.prefix_take_iff]
            exact ⟨
              List.take_prefix bridgeIndex _,
              by
                simp [
                  List.length_take,
                  Nat.min_eq_left sourceBound
                ]
                exact bridgeCommitted
            ⟩
          exact Or.inl
            (by simpa [logEq] using sourceInCommitted.trans committedInCandidate)
        let sourceConfiguration :=
          currentConfiguration (state.nodes bridgeSource)
        let candidateConfiguration :=
          currentConfiguration (state.nodes candidate)
        have sourceActive :
            sourceConfiguration ∈
              activeConfigurations (state.nodes bridgeSource) :=
          currentConfiguration_mem_activeConfigurations _
        have sourceGoverns :
            sourceConfiguration.index <= bridgeIndex := by
          have currentBound :=
            currentConfiguration_index_le_commitIndex
              (state.nodes bridgeSource)
          dsimp [sourceConfiguration]
          omega
        by_cases candidateBefore :
            candidateConfiguration.index <= sourceConfiguration.index
        · by_cases sameIndex :
              candidateConfiguration.index = sourceConfiguration.index
          · have sameConfiguration :
                candidateConfiguration = sourceConfiguration := by
              by_cases zero : sourceConfiguration.index = 0
              · have sourceImplicit :
                    sourceConfiguration = implicitConfiguration := by
                  apply
                    allConfigurations_index_unique
                      (TxId := TxId)
                      (state.nodes bridgeSource).log
                  · exact currentConfiguration_mem_allConfigurations _
                  · simp [allConfigurations, implicitConfiguration]
                  · simpa [implicitConfiguration] using zero
                have candidateImplicit :
                    candidateConfiguration = implicitConfiguration := by
                  apply
                    allConfigurations_index_unique
                      (TxId := TxId)
                      (state.nodes candidate).log
                  · exact currentConfiguration_mem_allConfigurations _
                  · simp [allConfigurations, implicitConfiguration]
                  · simp [sameIndex, zero, implicitConfiguration]
                exact candidateImplicit.trans sourceImplicit.symm
              · have sourcePositive : 0 < sourceConfiguration.index :=
                  Nat.pos_of_ne_zero zero
                have candidatePositive :
                    0 < candidateConfiguration.index := by omega
                exact
                  configurationCoverageCurrentIndexUnique
                    activationQuorums.history configurationActivations
                    (by simpa [candidateConfiguration] using candidatePositive)
                    (by simpa [sourceConfiguration] using sourcePositive)
                    (by simpa [
                      candidateConfiguration, sourceConfiguration
                    ] using sameIndex)
            right
            exact ⟨
              sourceConfiguration,
              by simpa [activeConfigurationsEq] using sourceActive,
              sourceGoverns,
              by
                rw [activeConfigurationsEq]
                rw [← sameConfiguration]
                exact
                  currentConfiguration_mem_activeConfigurations
                    (state.nodes candidate)
            ⟩
          · have sourcePositive : 0 < sourceConfiguration.index := by
              have candidateNonnegative :
                  0 <= candidateConfiguration.index := Nat.zero_le _
              omega
            have commitPositive :
                0 < (state.nodes bridgeSource).commitIndex :=
              sourcePositive.trans_le
                (currentConfiguration_index_le_commitIndex
                  (state.nodes bridgeSource))
            rcases evidenceFacts.nodePositive bridgeSource commitPositive with
              ⟨evidence, stored, _valid, _lengthEq, termBound⟩
            have known :
                KnownCommitEvidence
                  state appendHistory nodeEvidence requestEvidence
                    evidence (state.nodes bridgeSource).committedLog :=
              Or.inl ⟨bridgeSource, commitPositive, stored, rfl⟩
            have committedInCandidate :=
              prospectiveKnownEffectiveWinnerCompleteness
                facts.entriesDoNotExceedCurrentTerm
                (invariantFactsCandidatesAboveBootstrap facts)
                facts.voteHistory facts.grantedVoteSnapshots
                ownership electionFacts configurationFacts
                evidenceFacts prospectiveFacts activationEvidence
                known oldCandidateRole oldCandidateMajority
                (termBound.trans_lt
                  (by simpa [currentTermEq] using later))
            have sourceKnownCommitted :
                sourceConfiguration ∈
                  allConfigurations
                    (state.nodes bridgeSource).committedLog := by
              unfold NodeState.committedLog
              apply
                allConfigurations_mem_take_of_index_le
                  (state.nodes bridgeSource).log
                  (state.nodes bridgeSource).commitIndex
              · exact facts.commitIndicesBounded bridgeSource
              · exact currentConfiguration_mem_allConfigurations _
              · exact currentConfiguration_index_le_commitIndex _
            have sourceKnownCandidate :
                sourceConfiguration ∈
                  allConfigurations (state.nodes candidate).log :=
              memOfPrefix
                (allConfigurations_mono_prefix committedInCandidate)
                sourceKnownCommitted
            right
            exact ⟨
              sourceConfiguration,
              by simpa [activeConfigurationsEq] using sourceActive,
              sourceGoverns,
              by
                rw [activeConfigurationsEq]
                simpa [
                  activeConfigurations, candidateConfiguration
                ] using And.intro
                  sourceKnownCandidate candidateBefore
            ⟩
        · have sourceBeforeCandidate :
              sourceConfiguration.index < candidateConfiguration.index := by
            omega
          have candidatePositive : 0 < candidateConfiguration.index :=
            lt_of_le_of_lt (Nat.zero_le _) sourceBeforeCandidate
          rcases
              configurationActivations candidate candidatePositive with
            ⟨candidateCoverage⟩
          let candidateActivation := candidateCoverage.activation
          have candidateStored :
              activations candidateCoverage.activationIndex =
                some candidateActivation :=
            candidateCoverage.stored
          have candidateActivationPrefix :
              candidateCoverage.sharedPrefix <+:
                (state.nodes candidate).log := by
            rw [candidateCoverage.sharedPrefix_eq_nodeLogTake]
            exact List.take_prefix _ _
          have activationTermBeforeCandidate :
              candidateActivation.activationTerm <
                (state.nodes candidate).currentTerm :=
            candidateCoverage.activationTerm_lt_candidateTerm oldCandidateRole
          have candidateEventInCandidate :
              candidateActivation.history.take
                  candidateActivation.activationFrontier <+:
                (state.nodes candidate).log := by
            exact (activationPrefixInPotentialCandidateByCoverageAuthorityChain
                    (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts)
                    facts.entriesDoNotExceedCurrentTerm
                    facts.grantedVoteSnapshots voteCanonicalFacts
                    ownership electionFacts activationQuorums.history
                    configurationFacts.supporterCurrentHistory
                    activationVoteHistory activationCanonical
                    activationElections configurationActivations
                    oldCandidateRole oldCandidateMajority
                    candidateActivation.newConfiguration.index
                    candidateCoverage.activationIndex candidateActivation
                    rfl candidateStored activationTermBeforeCandidate).trans
              (List.take_prefix
                (maxCommittableIndex (state.nodes candidate).log)
                (state.nodes candidate).log)
          by_cases sourceBeforeActivation :
              (state.nodes bridgeSource).currentTerm <
                candidateActivation.activationTerm
          · rcases
                electionFacts.ownerRecorded
                  candidateActivation.activationTerm
                  candidateActivation.leader
                  (activationCanonical.termOwner
                    candidateCoverage.activationIndex candidateActivation
                      candidateStored) with
              bootstrap | activationElection
            · rw [bootstrap.1] at sourceBeforeActivation
              have positive :=
                facts.currentTermsPositive bridgeSource (by
                  rw [oldRole]; decide)
              omega
            · rcases activationElection with
                ⟨activationRecord, activationRecorded, leaderEq⟩
              have sourceInElection :=
                potentialPrefixInElectionRecordsFromActivationHistory
                  (by
                    intro node participating
                    rw [currentTermEq]
                    apply facts.currentTermsPositive node
                    intro none
                    apply participating
                    simpa [roleEq] using none)
                  (by
                    intro node entry member
                    rw [logEq] at member
                    rw [currentTermEq]
                    exact facts.entriesDoNotExceedCurrentTerm
                      node entry member)
                  voteFactsAfter ownershipAfter electionFactsAfter
                  configurationFactsAfter activationQuorums.history
                  activationProgressAfter ackerActivationAfter
                  temporalFacts.2.2 activationCanonical
                  activationElections configurationActivationsForBridge
                  evidenceAfter prospectiveAfter
                  role current signature bridgePotential
                  candidateActivation.activationTerm activationRecord
                  activationRecorded
                  (by simpa [currentTermEq] using sourceBeforeActivation)
              have sourceInActivation :=
                electionPromotionPrefixInActivation
                  electionFacts activationQuorums.history
                  activationCanonical candidateStored
                  (by simpa [leaderEq] using activationRecorded)
                  (by simpa [logEq] using sourceInElection)
              have activationInCandidate :
                  candidateActivation.history.take
                      candidateActivation.activationFrontier <+:
                    (state.nodes candidate).log :=
                candidateEventInCandidate
              exact Or.inl
                (by simpa [logEq] using
                  sourceInActivation.trans activationInCandidate)
          · have activationBeforeSource :
                candidateActivation.activationTerm <=
                  (state.nodes bridgeSource).currentTerm := by
              omega
            by_cases sameTerm :
                candidateActivation.activationTerm =
                  (state.nodes bridgeSource).currentTerm
            · have activationCanonicalEq :
                  candidateActivation.history.take
                      candidateActivation.activationFrontier =
                    (state.nodes bridgeSource).log.take
                      candidateActivation.activationFrontier := by
                calc
                  candidateActivation.history.take candidateActivation.activationFrontier
                      = (canonicalHistory candidateActivation.activationTerm).take
                          candidateActivation.activationFrontier :=
                    activationCanonical.activationFrontierCanonical
                      candidateCoverage.activationIndex candidateActivation
                      candidateStored
                  _ = (state.nodes bridgeSource).log.take
                        candidateActivation.activationFrontier := by
                    rw [sameTerm,
                      ownership.activeLeaderHistory bridgeSource oldRole]
              by_cases indexBefore :
                  bridgeIndex <= candidateActivation.activationFrontier
              · left
                have sourceInActivation :
                    (state.nodes bridgeSource).log.take bridgeIndex <+:
                      candidateActivation.history.take
                        candidateActivation.activationFrontier := by
                  rw [activationCanonicalEq]
                  rw [List.prefix_take_iff]
                  exact ⟨
                    List.take_prefix bridgeIndex (state.nodes bridgeSource).log,
                    by
                      simp only [List.length_take]
                      have sourceBound :
                          bridgeIndex <=
                            (state.nodes bridgeSource).log.length := by
                        rcases isSignatureAtTrue oldSignature with
                          ⟨entry, found, _⟩
                        exact entryAtSomeIndexBound found
                      simp [Nat.min_eq_left sourceBound, indexBefore]
                  ⟩
                simpa [logEq] using sourceInActivation.trans candidateEventInCandidate
              · right
                have candidateGoverns :
                    candidateConfiguration.index <= bridgeIndex := by
                  exact
                    candidateCoverage.configurationIndexBound.trans
                      (candidateCoverage.sharedFrontier_le_activationFrontier.trans
                        (Nat.lt_of_not_ge indexBefore).le)
                have candidateKnownSource :
                    candidateConfiguration ∈
                      allConfigurations (state.nodes bridgeSource).log := by
                  have activationPrefixSource :
                      candidateActivation.history.take
                          candidateActivation.activationFrontier <+:
                        (state.nodes bridgeSource).log := by
                    calc
                      candidateActivation.history.take
                            candidateActivation.activationFrontier
                          = (state.nodes bridgeSource).log.take
                              candidateActivation.activationFrontier :=
                        activationCanonicalEq
                      _ <+: (state.nodes bridgeSource).log :=
                        List.take_prefix _ _
                  apply
                    memOfPrefix
                      (allConfigurations_mono_prefix activationPrefixSource)
                  apply
                    memOfPrefix
                      (allConfigurations_mono_prefix
                        candidateCoverage.sharedPrefix_prefix_activationPrefix)
                  simpa [candidateConfiguration]
                    using candidateCoverage.configuration_mem_activationHistoryTake
                      activationQuorums.history
                exact ⟨
                  candidateConfiguration,
                  by
                    rw [activeConfigurationsEq]
                    simpa [
                      activeConfigurations, sourceConfiguration
                    ] using And.intro
                      candidateKnownSource sourceBeforeCandidate.le,
                  candidateGoverns,
                  by
                    simpa [activeConfigurationsEq]
                      using currentConfiguration_mem_activeConfigurations
                        (state.nodes candidate)
                ⟩
            · have strict :
                  candidateActivation.activationTerm <
                    (state.nodes bridgeSource).currentTerm := by
                omega
              rcases
                  electionFacts.ownerRecorded
                    (state.nodes bridgeSource).currentTerm bridgeSource
                    (ownership.activeLeader bridgeSource oldRole) with
                bootstrap | sourceElection
              · rw [bootstrap.1] at strict
                have positive :=
                  activationQuorums.history.termPositive
                    candidateCoverage.activationIndex candidateActivation
                      candidateStored
                omega
              · rcases sourceElection with
                  ⟨sourceRecord, sourceRecorded, sourceLeader⟩
                have activationInSource :=
                  (activationPrefixInLaterElection
                    activationElections candidateStored
                      sourceRecorded strict).trans
                    ((electionFacts.promotionCanonical
                      (state.nodes bridgeSource).currentTerm
                      sourceRecord sourceRecorded).trans
                      (by rw [
                        ownership.activeLeaderHistory
                          bridgeSource oldRole
                      ]))
                have candidateKnownSource
                    : candidateConfiguration
                      ∈ allConfigurations (state.nodes bridgeSource).log :=
                  memOfPrefix
                    (allConfigurations_mono_prefix activationInSource)
                    (by
                      apply
                        memOfPrefix
                          (allConfigurations_mono_prefix
                            candidateCoverage.sharedPrefix_prefix_activationPrefix)
                      simpa [candidateConfiguration]
                        using candidateCoverage.configuration_mem_activationHistoryTake
                          activationQuorums.history)
                have frontierBeforeIndex :
                    candidateActivation.activationFrontier < bridgeIndex := by
                  rcases isSignatureAtTrue oldSignature with
                    ⟨sourceEntry, sourceFound, _⟩
                  rcases isSignatureAtTrue
                      (activationQuorums.history.valid
                        candidateCoverage.activationIndex candidateActivation
                          candidateStored).2.2.2.2.2.1 with
                    ⟨activationEntry, activationFound, _⟩
                  have activationFoundSource :=
                    entryAt_of_prefix activationInSource (by
                      rw [entryAtTake_of_le le_rfl]
                      exact activationFound)
                  have sourceEntryTerm :
                      sourceEntry.term =
                        (state.nodes bridgeSource).currentTerm := by
                    simpa [termAt, sourceFound] using oldCurrent
                  have activationEntryTerm :
                      activationEntry.term =
                        candidateActivation.activationTerm := by
                    have activationTerm :=
                      (activationQuorums.history.supporterAcks
                        candidateCoverage.activationIndex candidateActivation
                          candidateStored).1
                    simpa [termAt, activationFound] using activationTerm
                  by_contra notBefore
                  have indexLe :
                      bridgeIndex <=
                        candidateActivation.activationFrontier := by omega
                  by_cases equal :
                      bridgeIndex =
                        candidateActivation.activationFrontier
                  · have sameEntry : sourceEntry = activationEntry :=
                      Option.some.inj
                        (sourceFound.symm.trans
                          (by simpa [equal] using activationFoundSource))
                    rw [sameEntry, activationEntryTerm] at sourceEntryTerm
                    omega
                  · have monotone :=
                      (canonicalHistoriesMonoLog ownership)
                        bridgeSource bridgeIndex
                        candidateActivation.activationFrontier
                        sourceEntry activationEntry (by omega)
                        sourceFound activationFoundSource
                    rw [sourceEntryTerm, activationEntryTerm] at monotone
                    omega
                right
                exact ⟨
                  candidateConfiguration,
                  by
                    rw [activeConfigurationsEq]
                    simpa [
                      activeConfigurations, sourceConfiguration
                    ] using And.intro
                      candidateKnownSource sourceBeforeCandidate.le,
                  by
                    have indexBound :
                        candidateConfiguration.index <=
                          candidateActivation.activationFrontier := by
                      exact
                        candidateCoverage.configurationIndexBound.trans
                          candidateCoverage.sharedFrontier_le_activationFrontier
                    exact indexBound.trans frontierBeforeIndex.le,
                  by
                    simpa [activeConfigurationsEq]
                      using currentConfiguration_mem_activeConfigurations
                        (state.nodes candidate)
                ⟩
    · intro bridgeSource bridgeIndex role current signature majority node
      rcases
          activationQuorums.committedBridge
            bridgeSource bridgeIndex
              (by simpa [roleEq] using role)
              (by simpa [logEq, currentTermEq] using current)
              (by simpa [logEq] using signature)
              ((effectiveMajorityEq bridgeSource bridgeIndex).mp majority)
              node with
        direct | direct | shared
      · exact Or.inl (by simpa [logEq, committedEq] using direct)
      · exact Or.inr (Or.inl
          (by simpa [logEq, committedEq] using direct))
      · right
        right
        rcases shared with
          ⟨configuration, active, governs, configurationEq⟩
        exact ⟨
          configuration,
          by simpa [activeConfigurationsEq] using active,
          governs,
          by simpa [currentConfigurationEq] using configurationEq
        ⟩
    · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
        right rightIndex rightRole rightCurrent rightSignature rightMajority
      rcases
          activationQuorums.potentialBridge
            left leftIndex
              (by simpa [roleEq] using leftRole)
              (by simpa [logEq, currentTermEq] using leftCurrent)
              (by simpa [logEq] using leftSignature)
              ((effectiveMajorityEq left leftIndex).mp leftMajority)
            right rightIndex
              (by simpa [roleEq] using rightRole)
              (by simpa [logEq, currentTermEq] using rightCurrent)
              (by simpa [logEq] using rightSignature)
              ((effectiveMajorityEq right rightIndex).mp rightMajority) with
        direct | direct | shared
      · exact Or.inl (by simpa [logEq] using direct)
      · exact Or.inr (Or.inl (by simpa [logEq] using direct))
      · right
        right
        rcases shared with
          ⟨configuration, leftActive, leftGoverns,
            rightActive, rightGoverns⟩
        exact ⟨
          configuration,
          by simpa [activeConfigurationsEq] using leftActive,
          leftGoverns,
          by simpa [activeConfigurationsEq] using rightActive,
          rightGoverns
        ⟩
    · intro activationIndex activation queuedDestination queuedRequest
        stored queued sameTerm
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        left
        have canonicalPrefix :
            activation.history.take activation.activationFrontier <+:
              (state.nodes source).log := by
          rw [
            activationCanonical.activationFrontierCanonical
              activationIndex activation stored,
            ← sameTerm,
            show request.term =
                (state.nodes source).currentTerm by
              simp [request, makeAppendEntriesRequest],
            ownership.activeLeaderHistory source enabled.2.2.1
          ]
          exact
            List.take_prefix
              activation.activationFrontier
              (state.nodes source).log
        simpa [newAppendHistory] using canonicalPrefix
      · have oldQueued :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects] using queued) with
            old | new
          · exact old
          · simp only [Message.appendEntriesRequest.injEq] at new
            exact False.elim (requestEq new.2)
        simpa [newAppendHistory, Function.update, requestEq]
          using activationQuorums.queuedComparable
            activationIndex activation queuedDestination queuedRequest
            stored oldQueued sameTerm
    · exact
        committedConfigurationCoverageFrame
          activationQuorums.committedCoverage
          logEq commitIndexEq
          (fun node => Nat.le_of_eq (currentTermEq node).symm)
    · intro queuedDestination queuedRequest queued frontier within
        positive signature
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        have sourceCoverage :
            Nonempty
              (ConfigurationFrontierCoverageWitness
                activations (state.nodes source).log frontier
                  (state.nodes source).currentTerm) := by
          apply
            activationQuorums.committedCoverage source frontier
          · simpa [request, makeAppendEntriesRequest]
              using within.trans (Nat.min_le_left _ _)
          · simpa [
              newAppendHistory, Function.update,
              request, makeAppendEntriesRequest
            ] using positive
          · simpa [
              newAppendHistory, Function.update,
              request, makeAppendEntriesRequest
            ] using signature
        simpa [newAppendHistory, Function.update, request, makeAppendEntriesRequest]
          using sourceCoverage
      · have oldQueued :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects] using queued) with
            old | new
          · exact old
          · simp only [Message.appendEntriesRequest.injEq] at new
            exact False.elim (requestEq new.2)
        rcases
            activationQuorums.queuedCoverage
              queuedDestination queuedRequest oldQueued frontier within
                (by simpa [
                  newAppendHistory, Function.update, requestEq
                ] using positive)
                (by simpa [
                  newAppendHistory, Function.update, requestEq
                ] using signature) with
          ⟨witness⟩
        exact ⟨by simpa [
          newAppendHistory, Function.update, requestEq
        ] using witness⟩
  have configurationActivationsAfter :
      ConfigurationCoverageFacts
        (appendEntriesEffect state source destination batchEnd)
        activations := by
    exact configurationActivationsForBridge
  have activationEvidenceAfter :
      ActivationEvidenceFacts
        (appendEntriesEffect state source destination batchEnd)
        newAppendHistory responseHistory nodeEvidence newRequestEvidence
          elections activations := by
    apply
      activationEvidenceFrame
        state (appendEntriesEffect state source destination batchEnd)
          appendHistory newAppendHistory responseHistory responseHistory
          nodeEvidence nodeEvidence
          requestEvidence newRequestEvidence elections elections activations
          activationEvidence
    · intro evidence supportedPrefix known
      rcases known with nodeKnown | requestKnown
      · rcases nodeKnown with
          ⟨node, positive, stored, prefixEq⟩
        exact Or.inl
          ⟨node,
            by simpa [commitIndexEq] using positive,
            stored,
            by simpa [committedEq] using prefixEq⟩
      · rcases requestKnown with
          ⟨queuedDestination, queuedRequest, member,
            positive, stored, prefixEq⟩
        by_cases sameRequest : queuedRequest = request
        · subst queuedRequest
          have sourcePositive :
              0 < (state.nodes source).commitIndex := by
            simpa [request, makeAppendEntriesRequest] using positive
          have sourceStored :
              nodeEvidence source = some evidence := by
            simpa [newRequestEvidence, Function.update] using stored
          exact Or.inl
            ⟨
              source,
              sourcePositive,
              sourceStored,
              by simpa [
                  newAppendHistory, Function.update,
                  request, makeAppendEntriesRequest,
                  NodeState.committedLog
                ] using prefixEq
            ⟩
        · have oldMember :
              Message.appendEntriesRequest queuedRequest ∈
                state.network queuedDestination := by
            rcases
                memEnqueue
                  state.network (.appendEntriesRequest request)
                    (.appendEntriesRequest queuedRequest)
                    queuedDestination
                    (by simpa [view_effects] using member) with
              old | new
            · exact old
            · simp at new
              exact False.elim (sameRequest new.2)
          exact Or.inr
            ⟨queuedDestination, queuedRequest, oldMember,
              positive,
              by simpa [
                newRequestEvidence, Function.update, sameRequest
              ] using stored,
              by simpa [
                newAppendHistory, Function.update, sameRequest
              ] using prefixEq⟩
    · intro candidate role majority
      exact ⟨
        by simpa [roleEq] using role,
        (potentialElectionMajorityEq candidate).mp majority
      ⟩
    · intro candidate role
      exact currentTermEq candidate
    · intro candidate role
      rw [logEq]
    · intro candidate configuration role active
      simpa [activeConfigurationsEq] using active
  · refine ⟨
      owners,
      canonicalHistory,
      elections,
      activations,
      nodeEvidence,
      newRequestEvidence,
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
      rw [currentTermEq]
      exact ownership.activeLeader leader
        (by simpa [roleEq] using role)
    · intro node index entry found
      rcases
          ownership.logEntryAgreement node index entry
            (by simpa [logEq] using found) with
        ⟨canonicalFound, agreed⟩
      exact ⟨canonicalFound, by simpa [logEq] using agreed⟩
    · intro queuedDestination queuedRequest member index entry found
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        have sourceFound :
            entryAt? (state.nodes source).log index = some entry := by
          simpa [newAppendHistory, Function.update] using found
        rcases
            ownership.logEntryAgreement source index entry sourceFound with
          ⟨canonicalFound, agreed⟩
        exact ⟨
          canonicalFound,
          by simpa [
              newAppendHistory, Function.update
            ] using agreed
        ⟩
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects] using member) with
            old | new
          · exact old
          · simp only [Message.appendEntriesRequest.injEq] at new
            exact False.elim (requestEq new.2)
        have oldFound :
            entryAt? (appendHistory queuedRequest) index = some entry := by
          simpa [newAppendHistory, Function.update, requestEq] using found
        rcases
            ownership.queuedHistoryEntryAgreement
              queuedDestination queuedRequest oldMember index entry oldFound with
          ⟨canonicalFound, agreed⟩
        exact ⟨
          canonicalFound,
          by simpa [
              newAppendHistory, Function.update, requestEq
            ] using agreed
        ⟩
    · intro leader role
      rw [currentTermEq]
      have oldRole : (state.nodes leader).role = .leader := by simpa [roleEq] using role
      simpa [logEq] using ownership.activeLeaderHistory leader oldRole
    · exact ownership.canonicalEntryOwner
    · exact ownership.canonicalMonoLog
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bound, oldLeader⟩
      constructor
      · simpa [currentTermEq] using bound
      · intro same
        have oldSame :
            term = (state.nodes owner).currentTerm := by
          simpa [currentTermEq] using same
        simpa [roleEq] using oldLeader oldSame
    · intro queuedDestination queuedRequest member
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        refine ⟨?_, ?_, ?_⟩
        · simpa [request, makeAppendEntriesRequest] using enabled.2.2.2.1
        · simpa [request, makeAppendEntriesRequest]
            using ownership.activeLeader source enabled.2.2.1
        · intro entry entryMember
          have sourceMember :
              entry ∈ (state.nodes source).log := by
            simpa [newAppendHistory, Function.update] using entryMember
          simpa [request, makeAppendEntriesRequest]
            using facts.entriesDoNotExceedCurrentTerm source entry sourceMember
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects] using member) with
            old | new
          · exact old
          · simp only [Message.appendEntriesRequest.injEq] at new
            exact False.elim (requestEq new.2)
        rcases
            ownership.queuedAppendMetadata
              queuedDestination queuedRequest oldMember with
          ⟨different, owned, bounded⟩
        exact ⟨
          different,
          owned,
          by simpa [
              newAppendHistory, Function.update, requestEq
            ] using bounded
        ⟩
    · intro queuedDestination queuedRequest member sameTerm leaderRole
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        have requestSource : request.source = source := by
          simp [request, makeAppendEntriesRequest]
        have historyEq :
            newAppendHistory request = (state.nodes source).log := by
          simp [newAppendHistory]
        rw [historyEq, requestSource, logEq]
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects] using member) with
            old | new
          · exact old
          · simp only [Message.appendEntriesRequest.injEq] at new
            exact False.elim (requestEq new.2)
        have oldPrefix :=
          ownership.queuedActiveSourceHistory
            queuedDestination queuedRequest oldMember
              (by simpa [currentTermEq] using sameTerm)
              (by simpa [roleEq] using leaderRole)
        simpa [
          newAppendHistory, Function.update, requestEq, logEq
        ] using oldPrefix
    · apply
        electionHistoryFrame
          state (appendEntriesEffect state source destination batchEnd)
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
          state (appendEntriesEffect state source destination batchEnd)
            canonicalHistory canonicalHistory
            voteCandidateHistory voteVoterHistory voteCanonicalFacts
            (fun candidate _ => currentTermEq candidate)
      · intro candidate active
        simpa [roleEq] using active
      · intro candidate voter _ member
        rw [effectiveElectionVotersEq] at member
        exact member
      · intro history canonical
        exact canonical
    · exact temporalFacts.1
    · exact temporalFacts.2.1
    · exact temporalFacts.2.2
    · intro queuedDestination queuedRequest queued record recorded
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        have promotionPrefix :=
          electionFacts.promotionCanonical
            request.term record recorded
        have activeHistory :=
          ownership.activeLeaderHistory source enabled.2.2.1
        simpa [
          newAppendHistory, Function.update,
          request, makeAppendEntriesRequest,
          activeHistory
        ] using promotionPrefix
      · have oldMember :
            Message.appendEntriesRequest queuedRequest ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesRequest queuedRequest)
                  queuedDestination
                  (by simpa [view_effects] using queued) with
            old | new
          · exact old
          · simp at new
            exact False.elim (requestEq new.2)
        simpa [newAppendHistory, Function.update, requestEq]
          using electionQueuedFacts
            queuedDestination queuedRequest oldMember record recorded
  · intro candidate voter active member
    rw [currentTermEq candidate, currentTermEq voter]
    rw [roleEq] at active
    have oldMember :
        voter ∈ effectiveElectionVoters state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    simpa [voteLogUpToDate, logEq]
      using facts.grantedVoteSnapshots candidate voter active oldMember
  · refine ⟨ackHistory, ?_⟩
    constructor
    · intro leader role peer zero
      exact
        ackFacts.zero leader
          (by simpa [roleEq] using role)
          peer (by simpa [matchEq] using zero)
    · intro leader role peer positive
      rcases
          ackFacts.positive leader
            (by simpa [roleEq] using role)
            peer (by simpa [matchEq] using positive) with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      exact ⟨
        snapshot,
        stored,
        by simpa [currentTermEq] using snapshotTerm,
        by simpa [matchEq] using snapshotIndex,
        historyBound,
        by simpa [logEq] using agreed
      ⟩
  · constructor
    · intro node peer member
      simpa [view_effects]
        using facts.joinedCarriers.activeNodes node
          (by simpa [activeNodeUnion, activeConfigurationsEq] using member)
    · intro node configuration member peer inNodes
      simpa [view_effects]
        using facts.joinedCarriers.configurationNodes node configuration
          (by simpa [logEq] using member)
          (by simpa [view_effects] using inNodes)
    · intro node peer member
      simpa [view_effects]
        using facts.joinedCarriers.grantedVotes node
          (by simpa [votesGrantedEq] using member)
    · intro queuedDestination queuedRequest member
      have old :
          Message.requestVoteRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.appendEntriesRequest request)
                (.requestVoteRequest queuedRequest) queuedDestination
                (by simpa [view_effects] using member) with
          old | new
        · exact old
        · simp at new
      simpa [view_effects]
        using facts.joinedCarriers.voteRequestDestinations
          queuedDestination queuedRequest old
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueue
            state.network (.appendEntriesRequest request)
              (.appendEntriesRequest queuedRequest) queuedDestination
              (by simpa [view_effects] using member) with
        old | new
      · exact
          facts.joinedCarriers.appendRequestDestinations
            queuedDestination queuedRequest old
      · rcases new with ⟨destinationEq, requestEq⟩
        simp at requestEq
        subst queuedRequest
        rw [destinationEq]
        exact (facts.allocatedNodesExactlyJoined destination).mp enabled.2.1
    · intro queuedDestination queuedRequest member configuration configured
        peer inNodes
      rcases
          memEnqueue
            state.network (.appendEntriesRequest request)
              (.appendEntriesRequest queuedRequest) queuedDestination
              (by simpa [view_effects] using member) with
        old | new
      · exact
          facts.joinedCarriers.appendRequestConfigurations
            queuedDestination queuedRequest old configuration configured
              inNodes
      · rcases new with ⟨destinationEq, requestEq⟩
        subst queuedDestination
        simp at requestEq
        subst queuedRequest
        apply
          allConfigurations_suffix_nodes_carried
            ((state.nodes source).log.take
            ((state.nodes source).sentIndex destination))
            ((state.nodes source).log.drop
            ((state.nodes source).sentIndex destination))
            state.hasJoined
            (by
              simpa [List.take_append_drop] using
                facts.joinedCarriers.configurationNodes source)
            configuration ?_ inNodes
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix
                (batchEnd -
                  (state.nodes source).sentIndex destination)
                ((state.nodes source).log.drop
                  ((state.nodes source).sentIndex destination))))
        simpa [
          request, makeAppendEntriesRequest, messageEntries
        ] using configured
    · intro queuedDestination response member
      have old :
          Message.requestVoteResponse response ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.appendEntriesRequest request)
                (.requestVoteResponse response) queuedDestination
                (by simpa [view_effects] using member) with
          old | new
        · exact old
        · simp at new
      simpa [view_effects]
        using facts.joinedCarriers.voteResponseSources queuedDestination response old
    · constructor
      · intro node active
        simpa [view_effects]
          using facts.joinedCarriers.runtimeNodes.activeRoles node
            (by simpa [roleEq] using active)
      · intro leader peer positive
        simpa [view_effects]
          using facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
            (by simpa [matchEq] using positive)
      · intro queuedDestination response member
        have old :
            Message.appendEntriesResponse response ∈
              state.network queuedDestination := by
          rcases
              memEnqueue
                state.network (.appendEntriesRequest request)
                  (.appendEntriesResponse response) queuedDestination
                  (by simpa [view_effects] using member) with
            old | new
          · exact old
          · simp at new
        simpa [view_effects]
          using facts.joinedCarriers.runtimeNodes.appendResponses
            queuedDestination response old
      · intro node nonempty
        simpa [view_effects]
          using facts.joinedCarriers.runtimeNodes.nonemptyLogs node
            (by simpa [logEq] using nonempty)
  · exact fun _ => Iff.rfl
  · intro candidate
    simpa only [currentTermEq] using facts.currentTermsValid candidate
  · simpa only [NetworkTermsValid, view_effects]
      using (networkTermsValidEnqueue
              (message := .appendEntriesRequest request)
              facts.networkTermsValid (facts.currentTermsValid source))

end CCFRaft.Proofs.Invariant
