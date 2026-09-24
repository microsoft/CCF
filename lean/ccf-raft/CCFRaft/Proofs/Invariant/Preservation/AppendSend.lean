-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.VoteSend
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

/-- A request built by an enabled arbitrary-term leader snapshots its log. -/
lemma madeAppendRequestSupport
    (state : Model.State Node TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (commitBounded : CommitIndicesBounded state)
    (_progress : LeaderProgressBounded state)
    (enabled
      : (source ∈ joinedNodes
          /\ destination ∈ joinedNodes
          /\ ((nodeOf state) source).role = .leader
          /\ Not (source = destination)
          /\ (destination ∈ activeNodeUnion ((nodeOf state) source)
              \/ destination ∈ ((nodeOf state) source).retirementCompleted)
          /\ ((nodeOf state) source).sentIndex destination <= batchEnd
          /\ batchEnd <= ((nodeOf state) source).log.length
          /\ ((messageEntries ((nodeOf state) source).log
                (((nodeOf state) source).sentIndex destination) batchEnd).all
                fun entry => entry.term == termAt ((nodeOf state) source).log batchEnd)
              = true
          /\ (Not (((nodeOf state) source).membershipState = .retiredCommitted)
              \/ ((nodeOf state) source).sentIndex destination < batchEnd)))
    : let request := appendRequestKey state source destination batchEnd
      RequestSnapshots ((nodeOf state) source).log request
      /\ request.2.2.leaderCommit <= ((nodeOf state) source).log.length
      /\ RequestCommitStillPresent state ((nodeOf state) source).log request := by
  rcases enabled with
    ⟨_sourceAllocated, _destinationAllocated, _leaderRole, _different,
      _destinationActive, previousBeforeEnd, endWithin, _singleTerm, _sendAllowed⟩
  let previousIndex := ((nodeOf state) source).sentIndex destination
  have entriesLength :
      (messageEntries
        ((nodeOf state) source).log previousIndex batchEnd).length =
          batchEnd - previousIndex :=
    messageEntriesLength
      ((nodeOf state) source).log previousBeforeEnd endWithin
  dsimp [previousIndex] at *
  refine ⟨?_, ?_, ?_⟩
  · unfold RequestSnapshots
    simp only [appendRequestKey, Model.Local.makeAppendEntriesRequest]
    refine ⟨?_, by simp, ?_⟩
    · rw [entriesLength]
      omega
    · rw [entriesLength]
      have sumEq :
          ((nodeOf state) source).sentIndex destination +
              (batchEnd - ((nodeOf state) source).sentIndex destination) =
            batchEnd := by
        omega
      simpa [messageEntries, sumEq]
        using (List.take_add
                (l := ((nodeOf state) source).log)
                (i := ((nodeOf state) source).sentIndex destination)
                (j := batchEnd - ((nodeOf state) source).sentIndex destination))
  · simpa [appendRequestKey, Model.Local.makeAppendEntriesRequest] using commitBounded source
  · unfold RequestCommitStillPresent
    simp only [appendRequestKey, Model.Local.makeAppendEntriesRequest]
    exact prefixRefl _

/-- Sending AppendEntries updates one cursor and enqueues one snapshot. -/
lemma appendEntriesPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (source destination : Node)
    {present : source ∈ state.nodes.map Prod.fst}
    (batchEnd : Nat)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : (source ∈ joinedNodes
          /\ destination ∈ joinedNodes
          /\ ((nodeOf state) source).role = .leader
          /\ Not (source = destination)
          /\ (destination ∈ activeNodeUnion ((nodeOf state) source)
              \/ destination ∈ ((nodeOf state) source).retirementCompleted)
          /\ ((nodeOf state) source).sentIndex destination <= batchEnd
          /\ batchEnd <= ((nodeOf state) source).log.length
          /\ ((messageEntries ((nodeOf state) source).log
                (((nodeOf state) source).sentIndex destination) batchEnd).all
                fun entry => entry.term == termAt ((nodeOf state) source).log batchEnd)
              = true
          /\ (Not (((nodeOf state) source).membershipState = .retiredCommitted)
              \/ ((nodeOf state) source).sentIndex destination < batchEnd)))
    : SystemInductiveInvariant (joined := joinedNodes)
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
  let request := appendRequestKey state source destination batchEnd
  let newAppendHistory :=
    Function.update appendHistory request ((nodeOf state) source).log
  let newRequestEvidence : RequestCommitEvidence Node TxId :=
    Function.update
      requestEvidence request (nodeEvidence source)
  have requestSupport :=
    madeAppendRequestSupport
      state source destination batchEnd
        facts.commitIndicesBounded facts.leaderProgressBounded enabled
  have roleEq :
      forall node,
        ((nodeOf (appendEntriesEffect state source destination batchEnd)) node).role =
          ((nodeOf state) node).role := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        concrete_effects, present, nodeOf_replaceNode, nodeEq
      ]
  have currentTermEq :
      forall node,
        ((nodeOf (appendEntriesEffect state source destination batchEnd)) node).currentTerm =
          ((nodeOf state) node).currentTerm := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        concrete_effects, present, nodeOf_replaceNode, nodeEq
      ]
  have logEq :
      forall node,
        ((nodeOf (appendEntriesEffect state source destination batchEnd)) node).log =
          ((nodeOf state) node).log := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        concrete_effects, present, nodeOf_replaceNode, nodeEq
      ]
  have commitIndexEq :
      forall node,
        ((nodeOf (appendEntriesEffect state source destination batchEnd)) node).commitIndex =
          ((nodeOf state) node).commitIndex := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        concrete_effects, present, nodeOf_replaceNode, nodeEq
      ]
  have lastIndexEq :
      forall node,
        lastCommittableIndex
            ((nodeOf (appendEntriesEffect state source destination batchEnd)) node) =
          lastCommittableIndex ((nodeOf state) node) := by
    intro node
    exact lastCommittableIndexFrame (logEq node) (commitIndexEq node)
  have lastTermEq :
      forall node,
        lastCommittableTerm
            ((nodeOf (appendEntriesEffect state source destination batchEnd)) node) =
          lastCommittableTerm ((nodeOf state) node) := by
    intro node
    exact lastCommittableTermFrame (logEq node) (commitIndexEq node)
  have votedForEq :
      forall node,
        ((nodeOf (appendEntriesEffect state source destination batchEnd)) node).votedFor =
          ((nodeOf state) node).votedFor := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        concrete_effects, present, nodeOf_replaceNode, nodeEq
      ]
  have votesGrantedEq :
      forall node,
        ((nodeOf (appendEntriesEffect state source destination batchEnd)) node).votesGranted =
          ((nodeOf state) node).votesGranted := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        concrete_effects, present, nodeOf_replaceNode, nodeEq
      ]
  have matchEq :
      forall node,
        ((nodeOf (appendEntriesEffect state source destination batchEnd)) node).matchIndex =
          ((nodeOf state) node).matchIndex := by
    intro node
    by_cases nodeEq : node = source <;>
      simp [
        concrete_effects, present, nodeOf_replaceNode, nodeEq
      ]
  have committedEq :
      forall node,
        ((nodeOf (appendEntriesEffect state source destination batchEnd)) node).committedLog =
          ((nodeOf state) node).committedLog := by
    intro node
    simp [NodeState.committedLog, commitIndexEq, logEq]
  have activeConfigurationsEq :
      forall node,
        activeConfigurations
            ((nodeOf (appendEntriesEffect state source destination batchEnd)) node) =
          activeConfigurations ((nodeOf state) node) := by
    intro node
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitIndexEq]
  have currentConfigurationEq :
      forall node,
        currentConfiguration
            ((nodeOf (appendEntriesEffect state source destination batchEnd)) node) =
          currentConfiguration ((nodeOf state) node) := by
    intro node
    unfold currentConfiguration
    rw [logEq, commitIndexEq]
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers (joined := joinedNodes)
            (appendEntriesEffect state source destination batchEnd)
            responseHistory leader index =
          effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter]
    constructor
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨by simpa [concrete_effects, present] using joined, Or.inl self⟩
      · exact ⟨
          by simpa [concrete_effects, present] using joined,
          Or.inr (Or.inl (by simpa [matchEq] using matched))
        ⟩
      · refine ⟨
          by simpa [concrete_effects, present] using joined,
          Or.inr (Or.inr ?_)
        ⟩
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        have oldMember :
            (appendResponseEnvelope response ∈ state.network /\ response.2.1 = leader) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendResponseEnvelope response) leader
                  (by simpa [concrete_effects, present, request] using member) with
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
      · exact ⟨by simpa [concrete_effects, present] using joined, Or.inl self⟩
      · exact ⟨
          by simpa [concrete_effects, present] using joined,
          Or.inr (Or.inl (by simpa [matchEq] using matched))
        ⟩
      · refine ⟨by simpa [concrete_effects, present] using joined, Or.inr (Or.inr ?_)⟩
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
        simpa [concrete_effects, present, request]
          using memEnqueueNoDupOfMem
            state.network (appendRequestEnvelope request)
            (appendResponseEnvelope response) leader member
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt (joined := joinedNodes)
            (appendEntriesEffect state source destination batchEnd)
            responseHistory leader index ↔
          hasEffectiveMajorityAt (joined := joinedNodes) state responseHistory leader index := by
    intro leader index
    unfold hasEffectiveMajorityAt
    rw [activeConfigurationsEq, effectiveAckersEq]
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters (joined := joinedNodes)
            (appendEntriesEffect state source destination batchEnd)
            candidate =
          effectiveElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [concrete_effects, present] using joined,
          Or.inl (by simpa [votesGrantedEq] using processed)
        ⟩
      · refine ⟨
          by simpa [concrete_effects, present] using joined,
          Or.inr ?_
        ⟩
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        have oldMember :
            (voteResponseEnvelope response ∈ state.network /\ response.2.1 = candidate) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (voteResponseEnvelope response) candidate
                  (by simpa [concrete_effects, present, request] using member) with
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
          by simpa [concrete_effects, present] using joined,
          Or.inl (by simpa [votesGrantedEq] using processed)
        ⟩
      · refine ⟨by simpa [concrete_effects, present] using joined, Or.inr ?_⟩
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
        simpa [concrete_effects, present, request]
          using memEnqueueNoDupOfMem
            state.network (appendRequestEnvelope request)
            (voteResponseEnvelope response) candidate member
  have effectiveElectionMajorityEq :
      forall candidate,
        hasEffectiveElectionMajority (joined := joinedNodes)
            (appendEntriesEffect state source destination batchEnd)
            candidate ↔
          hasEffectiveElectionMajority (joined := joinedNodes) state candidate := by
    intro candidate
    simp only [
      hasEffectiveElectionMajority,
      effectiveElectionVotersEq,
      activeConfigurationsEq
    ]
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters (joined := joinedNodes)
            (appendEntriesEffect state source destination batchEnd)
            candidate =
          potentialElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨by simpa [concrete_effects, present] using joined, Or.inl (by
          rw [effectiveElectionVotersEq] at effective
          exact effective)⟩
      · exact ⟨by simpa [concrete_effects, present] using joined, Or.inr (by
          simpa [
          currentlyEligibleElectionVoter,
          voteRequestKey, Model.Local.makeRequestVoteRequest,
          currentTermEq, logEq, commitIndexEq, votedForEq,
          lastCommittableIndexFrame
            (logEq candidate) (commitIndexEq candidate),
          lastCommittableTermFrame
            (logEq candidate) (commitIndexEq candidate),
          voteLogUpToDate
          ] using eligible)⟩
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨by simpa [concrete_effects, present] using joined, Or.inl (by
          rw [effectiveElectionVotersEq]
          exact effective)⟩
      · exact ⟨by simpa [concrete_effects, present] using joined, Or.inr (by
          simpa [
          currentlyEligibleElectionVoter,
          voteRequestKey, Model.Local.makeRequestVoteRequest,
          currentTermEq, logEq, commitIndexEq, votedForEq,
          lastCommittableIndexFrame
            (logEq candidate) (commitIndexEq candidate),
          lastCommittableTermFrame
            (logEq candidate) (commitIndexEq candidate),
          voteLogUpToDate
          ] using eligible)⟩
  have potentialElectionMajorityEq :
      forall candidate,
        hasPotentialElectionMajority (joined := joinedNodes)
            (appendEntriesEffect state source destination batchEnd)
            candidate ↔
          hasPotentialElectionMajority (joined := joinedNodes) state candidate := by
    intro candidate
    simp only [
      hasPotentialElectionMajority,
      potentialElectionVotersEq,
      activeConfigurationsEq
    ]
  have requestSupportAfter :
      RequestSnapshots ((nodeOf state) source).log request /\
        request.2.2.leaderCommit <= ((nodeOf state) source).log.length /\
        RequestCommitStillPresent
          (appendEntriesEffect state source destination batchEnd)
          ((nodeOf state) source).log request := by
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
      AckerActivationHistory (joined := joinedNodes)
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
        ((nodeOf state) leader).role = .leader := by
      by_cases leaderEq : leader = source <;>
        simpa [
          concrete_effects, present, nodeOf_replaceNode,
          Function.update, leaderEq
        ] using role
    have oldProgress := facts.leaderProgressBounded leader oldRole peer
    by_cases leaderEq : leader = source
    · subst leader
      constructor
      · by_cases peerEq : peer = destination
        · subst peer
          simp [
            concrete_effects, present, updateIndex,
            Function.update
          ]
          exact enabled.2.2.2.2.2.2.1
        · simpa [
            concrete_effects, present, updateIndex,
            Function.update, peerEq
          ] using oldProgress.1
      · simpa [concrete_effects, present] using oldProgress.2
    · simpa [
        concrete_effects, present, nodeOf_replaceNode,
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
            state.network (appendRequestEnvelope request)
              message queuedDestination
              (by simpa [concrete_effects, present, request] using member) with
        old | new
      · exact facts.networkHistory.addressed queuedDestination message old
      · rcases new with ⟨destinationEq, messageEq⟩
        subst message
        simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest] using destinationEq.symm
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueue
            state.network (appendRequestEnvelope request)
              (appendRequestEnvelope queuedRequest) queuedDestination
              (by simpa [concrete_effects, present, request] using member) with
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
        simp only [appendRequestEnvelope.injEq] at messageEq
        subst queuedRequest
        simpa [
          newAppendHistory, Function.update, request
        ] using requestSupportAfter
    · intro queuedDestination response member
      have old :
          (appendResponseEnvelope response ∈ state.network /\ response.2.1 = queuedDestination) := by
        rcases
            memEnqueue
              state.network (appendRequestEnvelope request)
                (appendResponseEnvelope response) queuedDestination
                (by simpa [concrete_effects, present, request] using member) with
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
          (voteRequestEnvelope voteRequest ∈ state.network /\ voteRequest.2.1 = queuedDestination) := by
        rcases
            memEnqueue
              state.network (appendRequestEnvelope request)
                (voteRequestEnvelope voteRequest) queuedDestination
                (by simpa [concrete_effects, present, request] using member) with
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
              voteRequest.2.2.term =
                ((nodeOf state) voteRequest.1).currentTerm := by
            simpa [currentTermEq] using sameTerm
          have oldActive :
              ((nodeOf state) voteRequest.1).role = .candidate \/
                ((nodeOf state) voteRequest.1).role = .leader := by
            simpa [roleEq] using active
          simpa [logEq] using activePrefix oldSameTerm oldActive
      ⟩
    · intro queuedDestination response member granted
      have old :
          (voteResponseEnvelope response ∈ state.network /\ response.2.1 = queuedDestination) := by
        rcases
            memEnqueue
              state.network (appendRequestEnvelope request)
                (voteResponseEnvelope response) queuedDestination
                (by simpa [concrete_effects, present, request] using member) with
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
          0 < ((nodeOf state) node).commitIndex := by
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
            0 < ((nodeOf state) source).commitIndex := by
          simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest] using positive
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
            request, appendRequestKey, Model.Local.makeAppendEntriesRequest,
            NodeState.committedLog
          ] using valid
        · simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest] using lengthEq
        · simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest] using termBound
      · have oldMember :
            (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendRequestEnvelope queuedRequest)
                  queuedDestination
                  (by simpa [concrete_effects, present] using member) with
            old | new
          · exact old
          · simp only [appendRequestEnvelope.injEq] at new
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
      ProspectiveCommitEvidenceFacts (joined := joinedNodes)
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
              0 < ((nodeOf state) source).commitIndex := by
            simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest] using positive
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
                  request, appendRequestKey, Model.Local.makeAppendEntriesRequest,
                  NodeState.committedLog
                ] using prefixEq
            ⟩
        · have oldMember :
              (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
            rcases
                memEnqueue
                  state.network (appendRequestEnvelope request)
                    (appendRequestEnvelope queuedRequest)
                    queuedDestination
                    (by simpa [concrete_effects, present] using member) with
              old | new
            · exact old
            · simp only [appendRequestEnvelope.injEq] at new
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
                  0 < ((nodeOf state) source).commitIndex := by
                simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest] using positive
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
                      request, appendRequestKey, Model.Local.makeAppendEntriesRequest,
                      NodeState.committedLog
                    ] using prefixEq
                ⟩
            · have oldMember :
                  (appendRequestEnvelope knownRequest ∈ state.network /\ knownRequest.2.1 = knownDestination) := by
                rcases
                    memEnqueue
                      state.network (appendRequestEnvelope request)
                        (appendRequestEnvelope knownRequest)
                        knownDestination
                        (by simpa [concrete_effects, present] using
                          queuedMember) with
                  old | new
                · exact old
                · simp only [appendRequestEnvelope.injEq] at new
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
            (by simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest] using Nat.le_of_eq sameTerm)
            ackMember
        simpa [newAppendHistory, Function.update, request, appendRequestKey, Model.Local.makeAppendEntriesRequest]
          using leaderCovered
      · left
        have oldMember :
            (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendRequestEnvelope queuedRequest)
                  queuedDestination
                  (by simpa [concrete_effects, present] using queued) with
            old | new
          · exact old
          · simp only [appendRequestEnvelope.injEq] at new
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
            by simpa [concrete_effects, present] using joined,
            Or.inl effective
          ⟩
        · exact ⟨
            by simpa [concrete_effects, present] using joined,
            Or.inr
              (by
                simpa [voteRequestKey, Model.Local.makeRequestVoteRequest, currentTermEq, logEq, lastIndexEq,
                  lastTermEq, voteLogUpToDate]
                  using upToDate)
          ⟩
  have configurationFactsAfter :
      ElectionConfigurationFacts (joined := joinedNodes)
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
            entryAt? ((nodeOf state) source).log index = some entry := by
          simpa [newAppendHistory, Function.update] using found
        rcases
            ownership.logEntryAgreement
              source index entry sourceFound with
          ⟨canonicalFound, agreed⟩
        exact ⟨canonicalFound, by simpa [newAppendHistory, Function.update] using agreed⟩
      · have oldMember :
            (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendRequestEnvelope queuedRequest)
                  queuedDestination
                  (by simpa [concrete_effects, present] using member) with
            old | new
          · exact old
          · simp only [appendRequestEnvelope.injEq] at new
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
        · simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest] using enabled.2.2.2.1
        · simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest]
            using ownership.activeLeader source enabled.2.2.1
        · intro entry entryMember
          have sourceMember :
              entry ∈ ((nodeOf state) source).log := by
            simpa [newAppendHistory, Function.update] using entryMember
          simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest]
            using facts.entriesDoNotExceedCurrentTerm source entry sourceMember
      · have oldMember :
            (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendRequestEnvelope queuedRequest)
                  queuedDestination
                  (by simpa [concrete_effects, present] using member) with
            old | new
          · exact old
          · simp only [appendRequestEnvelope.injEq] at new
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
        have requestSource : request.1 = source := by
          simp [request, appendRequestKey, Model.Local.makeAppendEntriesRequest]
        have historyEq :
            newAppendHistory request = ((nodeOf state) source).log := by
          simp [newAppendHistory]
        rw [historyEq, requestSource, logEq]
      · have oldMember :
            (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendRequestEnvelope queuedRequest)
                  queuedDestination
                  (by simpa [concrete_effects, present] using member) with
            old | new
          · exact old
          · simp only [appendRequestEnvelope.injEq] at new
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
      ActivationQuorumFacts (joined := joinedNodes)
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
      have oldRole : ((nodeOf state) bridgeSource).role = .leader := by
        simpa [roleEq] using role
      have oldCurrent :
          termAt ((nodeOf state) bridgeSource).log bridgeIndex =
            ((nodeOf state) bridgeSource).currentTerm := by
        simpa [logEq, currentTermEq] using current
      have oldSignature :
          isSignatureAt ((nodeOf state) bridgeSource).log bridgeIndex = true := by
        simpa [logEq] using signature
      have oldCandidateRole :
          ((nodeOf state) candidate).role = .candidate := by
        simpa [roleEq] using candidateRole
      have oldCandidateMajority :
          hasPotentialElectionMajority (joined := joinedNodes) state candidate :=
        (potentialElectionMajorityEq candidate).mp candidateMajority
      by_cases oldPotential :
          hasPotentialMajorityAt (joined := joinedNodes)
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
            bridgeIndex <= ((nodeOf state) bridgeSource).commitIndex
        · have bridgeIndexPositive : 0 < bridgeIndex := by
            rcases isSignatureAtTrue oldSignature with
              ⟨entry, found, _⟩
            have nonzero : Not (bridgeIndex = 0) := by
              intro zero
              rw [zero] at found
              simp [entryAt?] at found
            exact Nat.pos_of_ne_zero nonzero
          have commitPositive :
              0 < ((nodeOf state) bridgeSource).commitIndex := by omega
          rcases evidenceFacts.nodePositive bridgeSource commitPositive with
            ⟨evidence, stored, _valid, _lengthEq, termBound⟩
          have known :
              KnownCommitEvidence
                state appendHistory nodeEvidence requestEvidence
                  evidence ((nodeOf state) bridgeSource).committedLog :=
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
              bridgeIndex <= ((nodeOf state) bridgeSource).log.length := by
            rcases isSignatureAtTrue oldSignature with
              ⟨entry, found, _⟩
            exact entryAtSomeIndexBound found
          have sourceInCommitted :
              ((nodeOf state) bridgeSource).log.take bridgeIndex <+:
                ((nodeOf state) bridgeSource).committedLog := by
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
          currentConfiguration ((nodeOf state) bridgeSource)
        let candidateConfiguration :=
          currentConfiguration ((nodeOf state) candidate)
        have sourceActive :
            sourceConfiguration ∈
              activeConfigurations ((nodeOf state) bridgeSource) :=
          currentConfiguration_mem_activeConfigurations _
        have sourceGoverns :
            sourceConfiguration.index <= bridgeIndex := by
          have currentBound :=
            currentConfiguration_index_le_commitIndex
              ((nodeOf state) bridgeSource)
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
                      ((nodeOf state) bridgeSource).log
                  · exact currentConfiguration_mem_allConfigurations _
                  · simp [allConfigurations, implicitConfiguration]
                  · simpa [implicitConfiguration] using zero
                have candidateImplicit :
                    candidateConfiguration = implicitConfiguration := by
                  apply
                    allConfigurations_index_unique
                      (TxId := TxId)
                      ((nodeOf state) candidate).log
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
                    ((nodeOf state) candidate)
            ⟩
          · have sourcePositive : 0 < sourceConfiguration.index := by
              have candidateNonnegative :
                  0 <= candidateConfiguration.index := Nat.zero_le _
              omega
            have commitPositive :
                0 < ((nodeOf state) bridgeSource).commitIndex :=
              sourcePositive.trans_le
                (currentConfiguration_index_le_commitIndex
                  ((nodeOf state) bridgeSource))
            rcases evidenceFacts.nodePositive bridgeSource commitPositive with
              ⟨evidence, stored, _valid, _lengthEq, termBound⟩
            have known :
                KnownCommitEvidence
                  state appendHistory nodeEvidence requestEvidence
                    evidence ((nodeOf state) bridgeSource).committedLog :=
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
                    ((nodeOf state) bridgeSource).committedLog := by
              unfold NodeState.committedLog
              apply
                allConfigurations_mem_take_of_index_le
                  ((nodeOf state) bridgeSource).log
                  ((nodeOf state) bridgeSource).commitIndex
              · exact facts.commitIndicesBounded bridgeSource
              · exact currentConfiguration_mem_allConfigurations _
              · exact currentConfiguration_index_le_commitIndex _
            have sourceKnownCandidate :
                sourceConfiguration ∈
                  allConfigurations ((nodeOf state) candidate).log :=
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
                ((nodeOf state) candidate).log := by
            rw [candidateCoverage.sharedPrefix_eq_nodeLogTake]
            exact List.take_prefix _ _
          have activationTermBeforeCandidate :
              candidateActivation.activationTerm <
                ((nodeOf state) candidate).currentTerm :=
            candidateCoverage.activationTerm_lt_candidateTerm oldCandidateRole
          have candidateEventInCandidate :
              candidateActivation.history.take
                  candidateActivation.activationFrontier <+:
                ((nodeOf state) candidate).log := by
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
                (maxCommittableIndex ((nodeOf state) candidate).log)
                ((nodeOf state) candidate).log)
          by_cases sourceBeforeActivation :
              ((nodeOf state) bridgeSource).currentTerm <
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
                    ((nodeOf state) candidate).log :=
                candidateEventInCandidate
              exact Or.inl
                (by simpa [logEq] using
                  sourceInActivation.trans activationInCandidate)
          · have activationBeforeSource :
                candidateActivation.activationTerm <=
                  ((nodeOf state) bridgeSource).currentTerm := by
              omega
            by_cases sameTerm :
                candidateActivation.activationTerm =
                  ((nodeOf state) bridgeSource).currentTerm
            · have activationCanonicalEq :
                  candidateActivation.history.take
                      candidateActivation.activationFrontier =
                    ((nodeOf state) bridgeSource).log.take
                      candidateActivation.activationFrontier := by
                calc
                  candidateActivation.history.take candidateActivation.activationFrontier
                      = (canonicalHistory candidateActivation.activationTerm).take
                          candidateActivation.activationFrontier :=
                    activationCanonical.activationFrontierCanonical
                      candidateCoverage.activationIndex candidateActivation
                      candidateStored
                  _ = ((nodeOf state) bridgeSource).log.take
                        candidateActivation.activationFrontier := by
                    rw [sameTerm,
                      ownership.activeLeaderHistory bridgeSource oldRole]
              by_cases indexBefore :
                  bridgeIndex <= candidateActivation.activationFrontier
              · left
                have sourceInActivation :
                    ((nodeOf state) bridgeSource).log.take bridgeIndex <+:
                      candidateActivation.history.take
                        candidateActivation.activationFrontier := by
                  rw [activationCanonicalEq]
                  rw [List.prefix_take_iff]
                  exact ⟨
                    List.take_prefix bridgeIndex ((nodeOf state) bridgeSource).log,
                    by
                      simp only [List.length_take]
                      have sourceBound :
                          bridgeIndex <=
                            ((nodeOf state) bridgeSource).log.length := by
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
                      allConfigurations ((nodeOf state) bridgeSource).log := by
                  have activationPrefixSource :
                      candidateActivation.history.take
                          candidateActivation.activationFrontier <+:
                        ((nodeOf state) bridgeSource).log := by
                    calc
                      candidateActivation.history.take
                            candidateActivation.activationFrontier
                          = ((nodeOf state) bridgeSource).log.take
                              candidateActivation.activationFrontier :=
                        activationCanonicalEq
                      _ <+: ((nodeOf state) bridgeSource).log :=
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
                        ((nodeOf state) candidate)
                ⟩
            · have strict :
                  candidateActivation.activationTerm <
                    ((nodeOf state) bridgeSource).currentTerm := by
                omega
              rcases
                  electionFacts.ownerRecorded
                    ((nodeOf state) bridgeSource).currentTerm bridgeSource
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
                      ((nodeOf state) bridgeSource).currentTerm
                      sourceRecord sourceRecorded).trans
                      (by rw [
                        ownership.activeLeaderHistory
                          bridgeSource oldRole
                      ]))
                have candidateKnownSource
                    : candidateConfiguration
                      ∈ allConfigurations ((nodeOf state) bridgeSource).log :=
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
                        ((nodeOf state) bridgeSource).currentTerm := by
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
                        ((nodeOf state) candidate)
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
              ((nodeOf state) source).log := by
          rw [
            activationCanonical.activationFrontierCanonical
              activationIndex activation stored,
            ← sameTerm,
            show request.2.2.term =
                ((nodeOf state) source).currentTerm by
              simp [request, appendRequestKey, Model.Local.makeAppendEntriesRequest],
            ownership.activeLeaderHistory source enabled.2.2.1
          ]
          exact
            List.take_prefix
              activation.activationFrontier
              ((nodeOf state) source).log
        simpa [newAppendHistory] using canonicalPrefix
      · have oldQueued :
            (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendRequestEnvelope queuedRequest)
                  queuedDestination
                  (by simpa [concrete_effects, present] using queued) with
            old | new
          · exact old
          · simp only [appendRequestEnvelope.injEq] at new
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
                activations ((nodeOf state) source).log frontier
                  ((nodeOf state) source).currentTerm) := by
          apply
            activationQuorums.committedCoverage source frontier
          · simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest]
              using within.trans (Nat.min_le_left _ _)
          · simpa [
              newAppendHistory, Function.update,
              request, appendRequestKey, Model.Local.makeAppendEntriesRequest
            ] using positive
          · simpa [
              newAppendHistory, Function.update,
              request, appendRequestKey, Model.Local.makeAppendEntriesRequest
            ] using signature
        simpa [newAppendHistory, Function.update, request, appendRequestKey, Model.Local.makeAppendEntriesRequest]
          using sourceCoverage
      · have oldQueued :
            (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendRequestEnvelope queuedRequest)
                  queuedDestination
                  (by simpa [concrete_effects, present] using queued) with
            old | new
          · exact old
          · simp only [appendRequestEnvelope.injEq] at new
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
      ActivationEvidenceFacts (joined := joinedNodes)
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
              0 < ((nodeOf state) source).commitIndex := by
            simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest] using positive
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
                  request, appendRequestKey, Model.Local.makeAppendEntriesRequest,
                  NodeState.committedLog
                ] using prefixEq
            ⟩
        · have oldMember :
              (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
            rcases
                memEnqueue
                  state.network (appendRequestEnvelope request)
                    (appendRequestEnvelope queuedRequest)
                    queuedDestination
                    (by simpa [concrete_effects, present] using member) with
              old | new
            · exact old
            · simp only [appendRequestEnvelope.injEq] at new
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
            entryAt? ((nodeOf state) source).log index = some entry := by
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
            (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendRequestEnvelope queuedRequest)
                  queuedDestination
                  (by simpa [concrete_effects, present] using member) with
            old | new
          · exact old
          · simp only [appendRequestEnvelope.injEq] at new
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
      have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
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
            term = ((nodeOf state) owner).currentTerm := by
          simpa [currentTermEq] using same
        simpa [roleEq] using oldLeader oldSame
    · intro queuedDestination queuedRequest member
      by_cases requestEq : queuedRequest = request
      · subst queuedRequest
        refine ⟨?_, ?_, ?_⟩
        · simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest] using enabled.2.2.2.1
        · simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest]
            using ownership.activeLeader source enabled.2.2.1
        · intro entry entryMember
          have sourceMember :
              entry ∈ ((nodeOf state) source).log := by
            simpa [newAppendHistory, Function.update] using entryMember
          simpa [request, appendRequestKey, Model.Local.makeAppendEntriesRequest]
            using facts.entriesDoNotExceedCurrentTerm source entry sourceMember
      · have oldMember :
            (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendRequestEnvelope queuedRequest)
                  queuedDestination
                  (by simpa [concrete_effects, present] using member) with
            old | new
          · exact old
          · simp only [appendRequestEnvelope.injEq] at new
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
        have requestSource : request.1 = source := by
          simp [request, appendRequestKey, Model.Local.makeAppendEntriesRequest]
        have historyEq :
            newAppendHistory request = ((nodeOf state) source).log := by
          simp [newAppendHistory]
        rw [historyEq, requestSource, logEq]
      · have oldMember :
            (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendRequestEnvelope queuedRequest)
                  queuedDestination
                  (by simpa [concrete_effects, present] using member) with
            old | new
          · exact old
          · simp only [appendRequestEnvelope.injEq] at new
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
            request.2.2.term record recorded
        have activeHistory :=
          ownership.activeLeaderHistory source enabled.2.2.1
        simpa [
          newAppendHistory, Function.update,
          request, appendRequestKey, Model.Local.makeAppendEntriesRequest,
          activeHistory
        ] using promotionPrefix
      · have oldMember :
            (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendRequestEnvelope queuedRequest)
                  queuedDestination
                  (by simpa [concrete_effects, present] using queued) with
            old | new
          · exact old
          · simp only [appendRequestEnvelope.injEq] at new
            exact False.elim (requestEq new.2)
        simpa [newAppendHistory, Function.update, requestEq]
          using electionQueuedFacts
            queuedDestination queuedRequest oldMember record recorded
  · intro candidate voter active member
    rw [currentTermEq candidate, currentTermEq voter]
    rw [roleEq] at active
    have oldMember :
        voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
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
      simpa [concrete_effects, present]
        using facts.joinedCarriers.activeNodes node
          (by simpa [activeNodeUnion, activeConfigurationsEq] using member)
    · intro node configuration member peer inNodes
      simpa [concrete_effects, present]
        using facts.joinedCarriers.configurationNodes node configuration
          (by simpa [logEq] using member)
          (by simpa [concrete_effects, present] using inNodes)
    · intro node peer member
      simpa [concrete_effects, present]
        using facts.joinedCarriers.grantedVotes node
          (by simpa [votesGrantedEq] using member)
    · intro queuedDestination queuedRequest member
      have old :
          (voteRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
        rcases
            memEnqueue
              state.network (appendRequestEnvelope request)
                (voteRequestEnvelope queuedRequest) queuedDestination
                (by simpa [concrete_effects, present] using member) with
          old | new
        · exact old
        · simp at new
      simpa [concrete_effects, present]
        using facts.joinedCarriers.voteRequestDestinations
          queuedDestination queuedRequest old
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueue
            state.network (appendRequestEnvelope request)
              (appendRequestEnvelope queuedRequest) queuedDestination
              (by simpa [concrete_effects, present] using member) with
        old | new
      · exact
          facts.joinedCarriers.appendRequestDestinations
            queuedDestination queuedRequest old
      · rcases new with ⟨destinationEq, requestEq⟩
        simp only [appendRequestEnvelope.injEq] at requestEq
        subst queuedRequest
        rw [destinationEq]
        exact (facts.allocatedNodesExactlyJoined destination).mp enabled.2.1
    · intro queuedDestination queuedRequest member configuration configured
        peer inNodes
      rcases
          memEnqueue
            state.network (appendRequestEnvelope request)
              (appendRequestEnvelope queuedRequest) queuedDestination
              (by simpa [concrete_effects, present] using member) with
        old | new
      · exact
          facts.joinedCarriers.appendRequestConfigurations
            queuedDestination queuedRequest old configuration configured
              inNodes
      · rcases new with ⟨destinationEq, requestEq⟩
        subst queuedDestination
        simp only [appendRequestEnvelope.injEq] at requestEq
        subst queuedRequest
        apply
          allConfigurations_suffix_nodes_carried
            (((nodeOf state) source).log.take
            (((nodeOf state) source).sentIndex destination))
            (((nodeOf state) source).log.drop
            (((nodeOf state) source).sentIndex destination))
            joinedNodes
            (by
              simpa [List.take_append_drop] using
                facts.joinedCarriers.configurationNodes source)
            configuration ?_ inNodes
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix
                (batchEnd -
                  ((nodeOf state) source).sentIndex destination)
                (((nodeOf state) source).log.drop
                  (((nodeOf state) source).sentIndex destination))))
        simpa [
          request, appendRequestKey, Model.Local.makeAppendEntriesRequest, messageEntries
        ] using configured
    · intro queuedDestination response member
      have old :
          (voteResponseEnvelope response ∈ state.network /\ response.2.1 = queuedDestination) := by
        rcases
            memEnqueue
              state.network (appendRequestEnvelope request)
                (voteResponseEnvelope response) queuedDestination
                (by simpa [concrete_effects, present] using member) with
          old | new
        · exact old
        · simp at new
      simpa [concrete_effects, present]
        using facts.joinedCarriers.voteResponseSources queuedDestination response old
    · constructor
      · intro node active
        simpa [concrete_effects, present]
          using facts.joinedCarriers.runtimeNodes.activeRoles node
            (by simpa [roleEq] using active)
      · intro leader peer positive
        simpa [concrete_effects, present]
          using facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
            (by simpa [matchEq] using positive)
      · intro queuedDestination response member
        have old :
            (appendResponseEnvelope response ∈ state.network /\ response.2.1 = queuedDestination) := by
          rcases
              memEnqueue
                state.network (appendRequestEnvelope request)
                  (appendResponseEnvelope response) queuedDestination
                  (by simpa [concrete_effects, present] using member) with
            old | new
          · exact old
          · simp at new
        simpa [concrete_effects, present]
          using facts.joinedCarriers.runtimeNodes.appendResponses
            queuedDestination response old
      · intro node nonempty
        simpa [concrete_effects, present]
          using facts.joinedCarriers.runtimeNodes.nonemptyLogs node
            (by simpa [logEq] using nonempty)
  · exact fun _ => Iff.rfl
  · intro candidate
    simpa only [currentTermEq] using facts.currentTermsValid candidate
  · simpa only [NetworkTermsValid, concrete_effects, present]
      using (networkTermsValidEnqueue
              (message := appendRequestEnvelope request)
              facts.networkTermsValid (facts.currentTermsValid source))

end CCFRaft.Proofs.Invariant
