-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.StepDown
import CCFRaft.Proofs.Ledger
import CCFRaft.Proofs.Invariant.AckFacts

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Model.Local
open Concrete
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable {joinedNodes joinedNext : Finset Node}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

attribute [local simp] Shared.Envelope.target ConfigurationCoverageWitness.sharedPrefix

/-- Dequeuing a non-vote message leaves latent election voters unchanged. -/
lemma effectiveElectionVotersAfterAppendResponse
    (state after : Model.State Node TxId)
    (response : AppendResponseKey Node) (remaining : List (Model.Envelope Node TxId))
    (taken : Selected response.1 state.network (appendResponseEnvelope response) remaining)
    (networkEq : after.network = remaining)
    (hasJoinedEq : joinedNext = joinedNodes)
    (termEq : forall node, (nodeOf after node).currentTerm = (nodeOf state node).currentTerm)
    (votesEq : forall node, (nodeOf after node).votesGranted = (nodeOf state node).votesGranted)
    : forall candidate,
        effectiveElectionVoters (joined := joinedNext) after candidate
        = effectiveElectionVoters (joined := joinedNodes) state candidate := by
  classical
  subst joinedNext
  have voteMember (vote : VoteResponseKey Node) :
      (voteResponseEnvelope vote ∈ remaining) ↔
        (voteResponseEnvelope vote ∈ state.network) := by
    constructor
    · exact (selectedSound taken).2.2 _
    · intro old
      rcases memSelectedOrRemaining taken old with same | retained
      · simp [appendResponseEnvelope, voteResponseEnvelope] at same
      · exact retained
  intro candidate
  ext voter
  simp only [effectiveElectionVoters, Finset.mem_filter]
  simp only [queuedGrantedVote, votesEq, termEq, networkEq, voteMember]

/-- Frame changes which cannot create leaders retain processed ACK history. -/
lemma processedAckHistoryFrameBack
    (state after : Model.State Node TxId)
    (history : ProcessedAckHistory Node TxId)
    (facts : ProcessedAckHistoryFacts state history)
    (leaderBack
      : forall node,
          ((nodeOf after) node).role = .leader -> ((nodeOf state) node).role = .leader)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf state) node).log)
    (matchEq
      : forall leader peer,
          ((nodeOf after) leader).matchIndex peer = ((nodeOf state) leader).matchIndex peer)
    : ProcessedAckHistoryFacts after history := by
  constructor
  · intro leader role peer zero
    exact
      facts.zero leader
        (leaderBack leader role)
        peer (by simpa [matchEq] using zero)
  · intro leader role peer positive
    rcases
        facts.positive leader
          (leaderBack leader role)
          peer (by simpa [matchEq] using positive) with
      ⟨snapshot, stored, snapshotTerm, snapshotIndex,
        historyBound, agreed⟩
    exact ⟨
      snapshot,
      stored,
      by simpa [termEq] using snapshotTerm,
      by simpa [matchEq] using snapshotIndex,
      historyBound,
      by simpa [logEq] using agreed
    ⟩

/-- Frame changes preserving leader role, term, log, and match retain ACK history. -/
lemma processedAckHistoryFrame
    (state after : Model.State Node TxId)
    (history : ProcessedAckHistory Node TxId)
    (facts : ProcessedAckHistoryFacts state history)
    (roleEq : forall node, ((nodeOf after) node).role = ((nodeOf state) node).role)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf state) node).log)
    (matchEq
      : forall leader peer,
          ((nodeOf after) leader).matchIndex peer = ((nodeOf state) leader).matchIndex peer)
    : ProcessedAckHistoryFacts after history :=
  processedAckHistoryFrameBack
    state after history facts
    (fun node role => by simpa [roleEq] using role)
    termEq logEq matchEq

/--
A replication-cursor update preserves the invariant once its effects on
effective acknowledgement and election evidence are supplied.
-/
lemma roleAndNetworkFramePreservesSystemInductiveInvariant
    (state after : Model.State Node TxId)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (hasJoinedEq : joinedNext = joinedNodes)
    (allocatedEq : forall node, node ∈ joinedNext <-> node ∈ joinedNodes)
    (joinedCarriersAfter : JoinedCarrierFacts (joined := joinedNext) after)
    (participatingBack
      : forall node,
          Not (((nodeOf after) node).role = .none) -> Not (((nodeOf state) node).role = .none))
    (candidateBack
      : forall node,
          ((nodeOf after) node).role = .candidate -> ((nodeOf state) node).role = .candidate)
    (leaderBack
      : forall node,
          ((nodeOf after) node).role = .leader -> ((nodeOf state) node).role = .leader)
    (ownerRoleForward
      : forall owner,
          (((nodeOf state) owner).role = .leader
            \/ ((nodeOf state) owner).role = .follower
            \/ ((nodeOf state) owner).role = .preVoteCandidate
            \/ ((nodeOf state) owner).role = .none)
          -> (((nodeOf after) owner).role = .leader
              \/ ((nodeOf after) owner).role = .follower
              \/ ((nodeOf after) owner).role = .preVoteCandidate
              \/ ((nodeOf after) owner).role = .none))
    (passiveRoleForward
      : forall node,
          (((nodeOf state) node).role = .follower
            \/ ((nodeOf state) node).role = .preVoteCandidate
            \/ ((nodeOf state) node).role = .none)
          -> (((nodeOf after) node).role = .follower
              \/ ((nodeOf after) node).role = .preVoteCandidate
              \/ ((nodeOf after) node).role = .none))
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf state) node).log)
    (commitEq
      : forall node, ((nodeOf after) node).commitIndex = ((nodeOf state) node).commitIndex)
    (candidatesSelfVoteAfter : CandidatesSelfVote after)
    (leadersHaveElectionWitnessAfter : LeadersHaveElectionWitness after)
    (voteHistoryAfter
      : forall (votes : VoteHistory Node)
                (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
                (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
                (voteRequestHistory : VoteRequestKey Node -> List (Entry Node TxId))
                (voteCandidateHistory voteVoterHistory
                  : VoteResponseKey Node -> List (Entry Node TxId)),
          InvariantFacts (joined := joinedNodes)
            state votes appendHistory responseHistory
            voteRequestHistory voteCandidateHistory voteVoterHistory
          -> VoteHistoryFacts after votes)
    (processedAckHistoryAfter
      : forall (votes : VoteHistory Node)
                (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
                (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
                (voteRequestHistory : VoteRequestKey Node -> List (Entry Node TxId))
                (voteCandidateHistory voteVoterHistory
                  : VoteResponseKey Node -> List (Entry Node TxId)),
          InvariantFacts (joined := joinedNodes)
            state votes appendHistory responseHistory
            voteRequestHistory voteCandidateHistory voteVoterHistory
          -> Exists fun history => ProcessedAckHistoryFacts after history)
    (networkFrame
      : forall destination message,
          (message ∈ after.network /\ message.target = destination)
          -> (message ∈ state.network /\ message.target = destination)
              \/ (IsSafetyInert message.payload
                  /\ message.target = destination
                  /\ TermNumberValid message.payload.term))
    (progressAfter : LeaderProgressBounded after)
    (effectiveAckersSubsetAfter
      : forall (votes : VoteHistory Node)
                (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
                (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
                (voteRequestHistory : VoteRequestKey Node -> List (Entry Node TxId))
                (voteCandidateHistory voteVoterHistory
                  : VoteResponseKey Node -> List (Entry Node TxId)),
          InvariantFacts (joined := joinedNodes)
            state votes appendHistory responseHistory
            voteRequestHistory voteCandidateHistory voteVoterHistory
          -> forall leader index,
              effectiveAckers (joined := joinedNext) after responseHistory leader index
              ⊆ effectiveAckers (joined := joinedNodes) state responseHistory leader index)
    (potentialAckersSubsetAfter
      : forall (votes : VoteHistory Node)
                (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
                (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
                (voteRequestHistory : VoteRequestKey Node -> List (Entry Node TxId))
                (voteCandidateHistory voteVoterHistory
                  : VoteResponseKey Node -> List (Entry Node TxId)),
          InvariantFacts (joined := joinedNodes)
            state votes appendHistory responseHistory
            voteRequestHistory voteCandidateHistory voteVoterHistory
          -> forall leader index,
              potentialAckers (joined := joinedNext) after appendHistory responseHistory leader index
              ⊆ potentialAckers (joined := joinedNodes) state appendHistory responseHistory leader index)
    (effectiveElectionMajorityBack
      : forall candidate,
          ((nodeOf after) candidate).role = .candidate
          -> hasEffectiveElectionMajority (joined := joinedNext) after candidate
          -> hasEffectiveElectionMajority (joined := joinedNodes) state candidate)
    (potentialElectionMajorityBack
      : forall candidate,
          ((nodeOf after) candidate).role = .candidate
          -> hasPotentialElectionMajority (joined := joinedNext) after candidate
          -> hasPotentialElectionMajority (joined := joinedNodes) state candidate)
    (effectiveElectionMemberBack
      : forall candidate voter,
          (((nodeOf after) candidate).role = .candidate
            \/ ((nodeOf after) candidate).role = .leader)
          -> voter ∈ effectiveElectionVoters (joined := joinedNext) after candidate
          -> voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate)
    : SystemInductiveInvariant (joined := joinedNext) after := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafety with
    ⟨owners, canonicalHistory, elections, activations,
      nodeEvidence, requestEvidence, ownership, electionFacts,
      configurationFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, activationVoteHistory,
      ackerElectionFacts, ackerActivationFacts,
      electionQueuedFacts, activationProgress, activationQuorums,
      evidenceFacts, prospectiveFacts, activationEvidence,
      activationCanonical, activationElections, configurationActivations⟩
  have activeRoleBack :
      forall node,
        (((nodeOf after) node).role = .candidate \/
          ((nodeOf after) node).role = .leader) ->
        (((nodeOf state) node).role = .candidate \/
          ((nodeOf state) node).role = .leader) := by
    intro node active
    rcases active with candidate | leader
    · exact Or.inl (candidateBack node candidate)
    · exact Or.inr (leaderBack node leader)
  have appendRequestSubset :
      forall destination request,
        (appendRequestEnvelope request ∈ after.network /\ request.2.1 = destination) ->
          (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination) := by
    intro destination request member
    rcases networkFrame destination _ member with old | inert
    · exact old
    · simp [IsSafetyInert] at inert
  have appendResponseSubset :
      forall destination response,
        (appendResponseEnvelope response ∈ after.network /\ response.2.1 = destination) ->
          (appendResponseEnvelope response ∈ state.network /\ response.2.1 = destination) := by
    intro destination response member
    rcases networkFrame destination _ member with old | inert
    · exact old
    · simp [IsSafetyInert] at inert
  have voteRequestSubset :
      forall destination request,
        (voteRequestEnvelope request ∈ after.network /\ request.2.1 = destination) ->
          (voteRequestEnvelope request ∈ state.network /\ request.2.1 = destination) := by
    intro destination request member
    rcases networkFrame destination _ member with old | inert
    · exact old
    · simp [IsSafetyInert] at inert
  have voteResponseSubset :
      forall destination response,
        (voteResponseEnvelope response ∈ after.network /\ response.2.1 = destination) ->
          (voteResponseEnvelope response ∈ state.network /\ response.2.1 = destination) := by
    intro destination response member
    rcases networkFrame destination _ member with old | inert
    · exact old
    · simp [IsSafetyInert] at inert
  have committedEq :
      forall node,
        ((nodeOf after) node).committedLog =
          ((nodeOf state) node).committedLog := by
    intro node
    simp [NodeState.committedLog, commitEq, logEq]
  have activeConfigurationsEq :
      forall node,
        activeConfigurations ((nodeOf after) node) =
          activeConfigurations ((nodeOf state) node) := by
    intro node
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have lastIndexEq :
      forall node,
        lastCommittableIndex ((nodeOf after) node) =
          lastCommittableIndex ((nodeOf state) node) := by
    intro node
    exact lastCommittableIndexFrame (logEq node) (commitEq node)
  have lastTermEq :
      forall node,
        lastCommittableTerm ((nodeOf after) node) =
          lastCommittableTerm ((nodeOf state) node) := by
    intro node
    exact lastCommittableTermFrame (logEq node) (commitEq node)
  have effectiveMajorityBack :
      forall leader index,
        hasEffectiveMajorityAt (joined := joinedNext) after responseHistory leader index ->
          hasEffectiveMajorityAt (joined := joinedNodes) state responseHistory leader index := by
    intro leader index majority
    rw [hasEffectiveMajorityAt, List.all_eq_true] at majority ⊢
    intro configuration active
    apply decide_eq_true
    intro governs
    have afterActive :
        configuration ∈ activeConfigurations ((nodeOf after) leader) := by
      simpa [activeConfigurationsEq] using active
    exact
      hasConfigurationMajority_mono
        (effectiveAckersSubsetAfter
          votes appendHistory responseHistory voteRequestHistory
            voteCandidateHistory voteVoterHistory facts leader index)
        ((of_decide_eq_true
          (majority configuration afterActive)) governs)
  have potentialAckersSubset :
      forall leader index,
        potentialAckers (joined := joinedNext) after appendHistory responseHistory leader index ⊆
          potentialAckers (joined := joinedNodes) state appendHistory responseHistory leader index := by
    exact
      potentialAckersSubsetAfter
        votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory facts
  have potentialMajorityBack :
      forall leader index,
        hasPotentialMajorityAt (joined := joinedNext)
            after appendHistory responseHistory leader index ->
          hasPotentialMajorityAt (joined := joinedNodes)
            state appendHistory responseHistory leader index := by
    intro leader index majority
    rw [hasPotentialMajorityAt, List.all_eq_true] at majority ⊢
    intro configuration active
    apply decide_eq_true
    intro governs
    have afterActive :
        configuration ∈ activeConfigurations ((nodeOf after) leader) := by
      simpa [activeConfigurationsEq] using active
    exact
      hasConfigurationMajority_mono
        (potentialAckersSubset leader index)
        ((of_decide_eq_true
          (majority configuration afterActive)) governs)
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
  · intro node
    rw [commitEq, logEq]
    exact facts.commitIndicesBounded node
  · intro node active
    rw [termEq]
    exact
      facts.currentTermsPositive node
        (participatingBack node active)
  · intro node entry member
    rw [logEq] at member
    rw [termEq]
    exact facts.entriesDoNotExceedCurrentTerm node entry member
  · exact candidatesSelfVoteAfter
  · exact leadersHaveElectionWitnessAfter
  · exact progressAfter
  · exact
      voteHistoryAfter
        votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory facts
  · constructor
    · intro destination message member
      rcases networkFrame destination message member with old | inert
      · exact facts.networkHistory.addressed destination message old
      · exact inert.2.1
    · intro destination request member
      rcases
          facts.networkHistory.appendRequest
            destination request
              (appendRequestSubset destination request member) with
        ⟨snapshot, commitBound, present⟩
      exact ⟨
        snapshot,
        commitBound,
        by simpa [RequestCommitStillPresent, committedEq] using present
      ⟩
    · intro destination response member success
      have oldMember := appendResponseSubset destination response member
      rcases
          facts.networkHistory.appendResponse destination response oldMember
            success with
        ⟨lengthBound, termBound, supported⟩
      refine ⟨lengthBound, by simpa [termEq] using termBound, ?_⟩
      intro sameTerm
      rcases supported (by simpa [termEq] using sameTerm) with
        active | follower | preVoteCandidate
      · rcases
            ownerRoleForward response.2.1 (Or.inl active.1) with
          afterLeader | afterFollower | afterPreVoteCandidate
        · exact Or.inl
            ⟨afterLeader, by simpa [logEq] using active.2⟩
        · exact Or.inr (Or.inl afterFollower)
        · exact Or.inr (Or.inr afterPreVoteCandidate)
      · rcases
            passiveRoleForward response.2.1 (Or.inl follower) with
          afterFollower | afterPreVoteCandidate
        · exact Or.inr (Or.inl afterFollower)
        · exact Or.inr (Or.inr afterPreVoteCandidate)
      · rcases
            passiveRoleForward
              response.2.1 (Or.inr preVoteCandidate) with
          afterFollower | afterPreVoteCandidate
        · exact Or.inr (Or.inl afterFollower)
        · exact Or.inr (Or.inr afterPreVoteCandidate)
    · intro destination request member
      rcases
          facts.networkHistory.voteRequest destination request
            (voteRequestSubset destination request member) with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      exact ⟨
        lastIndex,
        lastTerm,
        maxIndex,
        aboveBootstrap,
        by simpa [termEq] using termBound,
        fun sameTerm active => by
          have oldSameTerm :
              request.2.2.term =
                ((nodeOf state) request.1).currentTerm := by
            simpa [termEq] using sameTerm
          have oldActive :
              ((nodeOf state) request.1).role = .candidate \/
                ((nodeOf state) request.1).role = .leader := by
            exact activeRoleBack request.1 active
          simpa [logEq] using activePrefix oldSameTerm oldActive
      ⟩
    · intro destination response member granted
      rcases
          facts.networkHistory.voteResponse destination response
            (voteResponseSubset destination response member)
            granted with
        ⟨termBound, recorded, upToDate⟩
      exact ⟨
        by simpa [termEq] using termBound,
        recorded,
        by simpa [voteLogUpToDate] using upToDate
      ⟩
  have evidenceAfter :
      CommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
        state after appendHistory
          nodeEvidence requestEvidence evidenceFacts
          commitEq committedEq
    · intro node
      exact Nat.le_of_eq (termEq node).symm
    · intro destination request member
      exact appendRequestSubset destination request member
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts (joined := joinedNext)
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
            commitEq committedEq
            (fun destination request member =>
              appendRequestSubset destination request member)
            known
    · intro member
      simp [logEq]
    · intro evidence supportedPrefix destination request known
        queued sameTerm
      left
      exact ⟨appendRequestSubset destination request queued, rfl⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      have oldRole :
          ((nodeOf state) candidate).role = .candidate := by
        exact candidateBack candidate role
      have oldRelaxed :
          member ∈ relaxedElectionVoters (joined := joinedNodes) state candidate := by
        simp only [
          relaxedElectionVoters, Finset.mem_filter] at relaxed ⊢
        rcases relaxed with ⟨joined, effective | eligible⟩
        · exact ⟨
            by simpa [hasJoinedEq] using joined,
            Or.inl (effectiveElectionMemberBack candidate member (Or.inl role) effective)
          ⟩
        · exact ⟨
            by simpa [hasJoinedEq] using joined,
            Or.inr
              (by
                simpa [voteRequestKey, Model.Local.makeRequestVoteRequest, termEq, logEq, lastIndexEq, lastTermEq,
                  voteLogUpToDate]
                  using eligible)
          ⟩
      left
      exact ⟨
        oldRole,
        by simpa [termEq] using newer,
        by
          intro entry entryMember
          simpa [termEq] using entriesBefore entry (by simpa [logEq] using entryMember),
        oldRelaxed,
        by simp [logEq]
      ⟩
  · have temporalFacts :=
      ackerTemporalFrameSameLogs
        state after votes votes responseHistory voteVoterHistory elections
          ackerCurrentFacts ackerVoteFacts ackerElectionFacts
          (fun leader role => leaderBack leader role)
          (fun leader _ => termEq leader)
          logEq
          (fun leader index voter _ _ member =>
            effectiveAckersSubsetAfter
              votes appendHistory responseHistory voteRequestHistory
                voteCandidateHistory voteVoterHistory facts leader index member)
          (fun node => Nat.le_of_eq (termEq node).symm)
          (fun _ _ _ voted _ => voted)
    have ownershipAfter :
        TermOwnershipFacts
          after votes appendHistory canonicalHistory owners := by
      apply
        termOwnershipFrame
          state after appendHistory appendHistory votes canonicalHistory
          owners ownership
      · intro leader role
        exact leaderBack leader role
      · intro owner role
        exact ownerRoleForward owner role
      · exact termEq
      · exact logEq
      · intro destination request member index entry found
        exact
          ownership.queuedHistoryEntryAgreement
            destination request
            (appendRequestSubset destination request member)
            index entry found
      · intro destination request member
        exact
          ownership.queuedAppendMetadata destination request
            (appendRequestSubset destination request member)
      · intro destination request member sameTerm leaderRole
        simpa [logEq]
          using ownership.queuedActiveSourceHistory destination request
            (appendRequestSubset destination request member)
            (by simpa [termEq] using sameTerm)
            (leaderBack request.1 leaderRole)
    have electionFactsAfter :
        ElectionHistoryFacts after votes canonicalHistory owners elections := by
      apply
        electionHistoryFrame
          state after votes votes canonicalHistory canonicalHistory
          owners elections electionFacts
      · intros
        rfl
      · intro term
        exact prefixRefl (canonicalHistory term)
      · intro history canonical
        exact canonical
    have voteCanonicalAfter :
        GrantedVoteCanonicalSnapshots (joined := joinedNext)
          after canonicalHistory voteCandidateHistory voteVoterHistory := by
      apply
        grantedVoteCanonicalFrame
          state after canonicalHistory canonicalHistory
          voteCandidateHistory voteVoterHistory voteCanonicalFacts
          (fun candidate _ => termEq candidate)
      · intro candidate active
        exact activeRoleBack candidate active
      · intro candidate voter active member
        exact effectiveElectionMemberBack candidate voter active member
      · intro history canonical
        exact canonical
    have supporterCurrentAfter :
        ActivationSupporterCurrentHistory after elections activations := by
      apply
        activationSupporterCurrentHistoryFrame
          state after elections elections activations
          configurationFacts.supporterCurrentHistory
      · intro node
        simp [logEq]
      · intro node
        exact Nat.le_of_eq (termEq node).symm
      · intro term record stored
        exact stored
    have configurationFactsAfter :
        ElectionConfigurationFacts (joined := joinedNext) after elections activations := by
      apply
        electionConfigurationFrame
          state after elections activations activations configurationFacts
      · intro _ _ stored
        exact stored
      · exact supporterCurrentAfter
      · intro candidate role majority
        exact ⟨
          candidateBack candidate role,
          termEq candidate,
          effectiveElectionMajorityBack candidate role majority
        ⟩
      · intro candidate configuration role active
        simpa [activeConfigurationsEq] using active
      · intro candidate role entry member
        simpa [termEq]
          using configurationFacts.candidateEntriesBeforeTerm
            candidate
            (candidateBack candidate role)
            entry
            (by simpa [logEq] using member)
    have activationVoteHistoryAfter :
        ActivationVoteHistory
          votes voteVoterHistory elections activations :=
      activationVoteHistory
    have ackerActivationAfter :
        AckerActivationHistory (joined := joinedNext)
          after responseHistory elections activations := by
      apply
        ackerActivationFrameSameLogs
          state after responseHistory elections elections activations
          ackerActivationFacts
      · intro source role
        exact leaderBack source role
      · intro source _
        exact termEq source
      · exact logEq
      · intro source index supporter role current member
        exact
          effectiveAckersSubsetAfter
            votes appendHistory responseHistory voteRequestHistory
              voteCandidateHistory voteVoterHistory facts source index member
      · intro term record stored
        exact stored
    have activationProgressAfter :
        ActivationSupporterProgress after activations := by
      apply
        activationSupporterProgressFrame
          state after activations activationProgress
      intro node
      exact Nat.le_of_eq (termEq node).symm
    have configurationActivationsAfter :
        ConfigurationCoverageFacts after activations := by
      apply
        configurationCoverageFrame configurationActivations
      · intro node
        unfold currentConfiguration
        rw [logEq, commitEq]
      · intro node
        exact Nat.le_of_eq (termEq node).symm
      · exact commitEq
      · intro node frontier _
        rw [logEq]
      · intro candidate witness role
        rw [termEq]
        exact witness.candidateTermStrict (candidateBack candidate role)
    have activationQuorumsAfter :
        ActivationQuorumFacts (joined := joinedNext)
          after appendHistory responseHistory elections activations := by
      constructor
      · exact activationQuorums.history
      · intro source index role current signature potential
          term record recorded later
        rcases
            activationQuorums.recordBridge
              source index
              (leaderBack source role)
              (by simpa [logEq, termEq] using current)
              (by simpa [logEq] using signature)
              (potentialMajorityBack source index potential)
              term record recorded
              (by simpa [termEq] using later) with
          direct | shared
        · exact Or.inl (by simpa [logEq] using direct)
        · exact Or.inr
            (by simpa [activeConfigurationsEq] using shared)
      · intro source index role current signature potential
          candidate candidateRole candidateMajority later
        rcases
            activationQuorums.candidateBridge
              source index
              (leaderBack source role)
              (by simpa [logEq, termEq] using current)
              (by simpa [logEq] using signature)
              (potentialMajorityBack source index potential)
              candidate
              (candidateBack candidate candidateRole)
              (potentialElectionMajorityBack
                candidate candidateRole candidateMajority)
              (by simpa [termEq] using later) with
          direct | shared
        · exact Or.inl (by simpa [logEq] using direct)
        · exact Or.inr
            (by simpa [activeConfigurationsEq] using shared)
      · intro source index role current signature majority node
        simpa [termEq, logEq, commitEq, NodeState.committedLog, activeConfigurationsEq,
          currentConfiguration]
          using activationQuorums.committedBridge
            source index
            (leaderBack source role)
            (by simpa [logEq, termEq] using current)
            (by simpa [logEq] using signature)
            (effectiveMajorityBack source index majority)
            node
      · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
          right rightIndex rightRole rightCurrent rightSignature rightMajority
        simpa [termEq, logEq, activeConfigurationsEq]
          using activationQuorums.potentialBridge
            left leftIndex
            (leaderBack left leftRole)
            (by simpa [logEq, termEq] using leftCurrent)
            (by simpa [logEq] using leftSignature)
            (effectiveMajorityBack left leftIndex leftMajority)
            right rightIndex
            (leaderBack right rightRole)
            (by simpa [logEq, termEq] using rightCurrent)
            (by simpa [logEq] using rightSignature)
            (effectiveMajorityBack right rightIndex rightMajority)
      · intro activationIndex activation queuedDestination queuedRequest
          stored queued sameTerm
        exact
          activationQuorums.queuedComparable
            activationIndex activation queuedDestination queuedRequest
            stored
            (appendRequestSubset queuedDestination queuedRequest queued)
            sameTerm
      · exact
          committedConfigurationCoverageFrame
            activationQuorums.committedCoverage logEq commitEq
            (fun node => Nat.le_of_eq (termEq node).symm)
      · apply
          queuedConfigurationCoverageFrame
            activationQuorums.queuedCoverage
            (afterAppendHistory := appendHistory)
        · intro queuedDestination queuedRequest queued
          exact appendRequestSubset queuedDestination queuedRequest queued
        · intro _
          rfl
    have activationEvidenceAfter :
        ActivationEvidenceFacts (joined := joinedNext)
          after appendHistory responseHistory nodeEvidence requestEvidence
          elections activations := by
      apply
        activationEvidenceFrame
          state after appendHistory appendHistory
          responseHistory responseHistory
          nodeEvidence nodeEvidence requestEvidence requestEvidence
          elections elections activations activationEvidence
      · intro evidence supportedPrefix known
        exact
          knownCommitEvidenceFrameBack
            state after appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member =>
              appendRequestSubset destination request member)
            known
      · intro candidate role majority
        exact ⟨
          candidateBack candidate role,
          potentialElectionMajorityBack candidate role majority
        ⟩
      · intro candidate role
        simp [termEq]
      · intro candidate _
        simp [logEq]
      · intro candidate configuration _ active
        simpa [activeConfigurationsEq] using active
    exact ⟨
      owners,
      canonicalHistory,
      elections,
      activations,
      nodeEvidence,
      requestEvidence,
      ownershipAfter,
      electionFactsAfter,
      configurationFactsAfter,
      voteCanonicalAfter,
      temporalFacts.1,
      temporalFacts.2.1,
      activationVoteHistory,
      temporalFacts.2.2,
      ackerActivationAfter,
      (by
        intro destination request member record recorded
        exact
          electionQueuedFacts destination request
            (appendRequestSubset destination request member)
            record recorded),
      activationProgressAfter,
      activationQuorumsAfter,
      evidenceAfter,
      prospectiveAfter,
      activationEvidenceAfter,
      activationCanonical,
      activationElections,
      configurationActivationsAfter
    ⟩
  · intro candidate voter active member
    have afterActive := active
    rw [termEq candidate, termEq voter]
    have oldActive := activeRoleBack candidate active
    have oldMember :
        voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate :=
      effectiveElectionMemberBack candidate voter afterActive member
    simpa [voteLogUpToDate, logEq]
      using facts.grantedVoteSnapshots candidate voter oldActive oldMember
  · exact
      processedAckHistoryAfter
        votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory facts
  · exact joinedCarriersAfter
  · exact
      AllocatedNodesExactlyJoined.frame
        facts.allocatedNodesExactlyJoined allocatedEq hasJoinedEq
  · intro node
    simpa only [termEq] using facts.currentTermsValid node
  · intro destination message member
    rcases networkFrame destination message member with old | added
    · exact facts.networkTermsValid destination message old
    · exact added.2.2

/--
Pure response dequeue preserves the invariant when every node record is
unchanged and the remaining effective evidence is accounted for.
-/
lemma networkFramePreservesSystemInductiveInvariant
    (state after : Model.State Node TxId)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (hasJoinedEq : joinedNext = joinedNodes)
    (allocatedEq : forall node, node ∈ joinedNext <-> node ∈ joinedNodes)
    (nodeStateEq : forall node, (nodeOf after) node = (nodeOf state) node)
    (networkFrame
      : forall destination message,
          (message ∈ after.network /\ message.target = destination)
          -> (message ∈ state.network /\ message.target = destination)
              \/ (IsSafetyInert message.payload
                  /\ message.target = destination
                  /\ TermNumberValid message.payload.term))
    (effectiveAckersSubsetAfter
      : forall (votes : VoteHistory Node)
                (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
                (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
                (voteRequestHistory : VoteRequestKey Node -> List (Entry Node TxId))
                (voteCandidateHistory voteVoterHistory
                  : VoteResponseKey Node -> List (Entry Node TxId)),
          InvariantFacts (joined := joinedNodes)
            state votes appendHistory responseHistory
            voteRequestHistory voteCandidateHistory voteVoterHistory
          -> forall leader index,
              effectiveAckers (joined := joinedNext) after responseHistory leader index
              ⊆ effectiveAckers (joined := joinedNodes) state responseHistory leader index)
    (effectiveElectionMajorityBack
      : forall candidate,
          ((nodeOf after) candidate).role = .candidate
          -> hasEffectiveElectionMajority (joined := joinedNext) after candidate
          -> hasEffectiveElectionMajority (joined := joinedNodes) state candidate)
    (effectiveElectionMemberBack
      : forall candidate voter,
          (((nodeOf after) candidate).role = .candidate
            \/ ((nodeOf after) candidate).role = .leader)
          -> voter ∈ effectiveElectionVoters (joined := joinedNext) after candidate
          -> voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate)
    : SystemInductiveInvariant (joined := joinedNext) after := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have packed :
      SystemInductiveInvariant (joined := joinedNodes) state :=
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have nodesEq : (nodeOf after) = (nodeOf state) :=
    funext nodeStateEq
  have appendRequestSubset :
      forall destination request,
        (appendRequestEnvelope request ∈ after.network /\ request.2.1 = destination) ->
          (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination) := by
    intro destination request member
    rcases networkFrame destination _ member with old | inert
    · exact old
    · simp [IsSafetyInert] at inert
  have appendResponseSubset :
      forall destination response,
        (appendResponseEnvelope response ∈ after.network /\ response.2.1 = destination) ->
          (appendResponseEnvelope response ∈ state.network /\ response.2.1 = destination) := by
    intro destination response member
    rcases networkFrame destination _ member with old | inert
    · exact old
    · simp [IsSafetyInert] at inert
  have voteRequestSubset :
      forall destination request,
        (voteRequestEnvelope request ∈ after.network /\ request.2.1 = destination) ->
          (voteRequestEnvelope request ∈ state.network /\ request.2.1 = destination) := by
    intro destination request member
    rcases networkFrame destination _ member with old | inert
    · exact old
    · simp [IsSafetyInert] at inert
  have voteResponseSubset :
      forall destination response,
        (voteResponseEnvelope response ∈ after.network /\ response.2.1 = destination) ->
          (voteResponseEnvelope response ∈ state.network /\ response.2.1 = destination) := by
    intro destination response member
    rcases networkFrame destination _ member with old | inert
    · exact old
    · simp [IsSafetyInert] at inert
  apply roleAndNetworkFramePreservesSystemInductiveInvariant
    state after packed hasJoinedEq allocatedEq
    (by
      constructor
      · intro node peer member
        rw [hasJoinedEq]
        exact
          facts.joinedCarriers.activeNodes node
            (by simpa [nodesEq] using member)
      · intro node configuration member peer inNodes
        rw [hasJoinedEq]
        exact
          facts.joinedCarriers.configurationNodes node configuration
            (by simpa [nodesEq] using member)
            (by simpa [nodesEq] using inNodes)
      · intro node peer member
        rw [hasJoinedEq]
        exact
          facts.joinedCarriers.grantedVotes node
            (by simpa [nodesEq] using member)
      · intro destination request member
        rw [hasJoinedEq]
        exact
          facts.joinedCarriers.voteRequestDestinations
            destination request
            (voteRequestSubset destination request member)
      · intro destination request member
        rw [hasJoinedEq]
        exact
          facts.joinedCarriers.appendRequestDestinations
            destination request
            (appendRequestSubset destination request member)
      · intro destination request member configuration configured
          peer inNodes
        rw [hasJoinedEq]
        exact
          facts.joinedCarriers.appendRequestConfigurations
            destination request
            (appendRequestSubset destination request member)
            configuration configured inNodes
      · intro destination response member
        rw [hasJoinedEq]
        exact
          facts.joinedCarriers.voteResponseSources
            destination response
            (voteResponseSubset destination response member)
      · constructor
        · intro node active
          rw [hasJoinedEq]
          exact
            facts.joinedCarriers.runtimeNodes.activeRoles node
              (by simpa [nodesEq] using active)
        · intro leader peer positive
          rw [hasJoinedEq]
          exact
            facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
              (by simpa [nodesEq] using positive)
        · intro destination response member
          rw [hasJoinedEq]
          exact
            facts.joinedCarriers.runtimeNodes.appendResponses
              destination response
                (appendResponseSubset destination response member)
        · intro node nonempty
          rw [hasJoinedEq]
          exact
            facts.joinedCarriers.runtimeNodes.nonemptyLogs node
              (by simpa [nodesEq] using nonempty))
    (fun node participating => by
      simpa [nodesEq] using participating)
    (fun node role => by simpa [nodesEq] using role)
    (fun node role => by simpa [nodesEq] using role)
    (fun node role => by simpa [nodesEq] using role)
    (fun node role => by simpa [nodesEq] using role)
    (fun node => by rw [nodesEq])
    (fun node => by rw [nodesEq])
    (fun node => by rw [nodesEq])
  · intro node role
    simpa [nodesEq] using facts.candidatesSelfVote node (by simpa [nodesEq] using role)
  · intro node role
    have oldRole : ((nodeOf state) node).role = .leader := by simpa [nodesEq] using role
    rcases facts.leadersHaveElectionWitness node oldRole with
      bootstrap | majority
    · exact Or.inl
        ⟨bootstrap.1, by simpa [nodesEq] using bootstrap.2⟩
    · exact Or.inr (by simpa [nodesEq] using majority)
  · intro _ _ _ _ _ _ actualFacts
    constructor
    · exact actualFacts.voteHistory.bootstrapEmpty
    · intro voter
      simpa [nodesEq] using actualFacts.voteHistory.current voter
    · intro voter term future
      exact
        actualFacts.voteHistory.future voter term
          (by simpa [nodesEq] using future)
    · intro candidate voter active member
      simpa [nodesEq]
        using actualFacts.voteHistory.counted candidate voter
          (by simpa [nodesEq] using active)
          (by simpa [nodesEq] using member)
  · intro _ _ _ _ _ _ actualFacts
    rcases actualFacts.processedAckHistory with
      ⟨history, historyFacts⟩
    exact ⟨
      history,
      processedAckHistoryFrame
        state after history historyFacts
        (fun node => by rw [nodesEq])
        (fun node => by rw [nodesEq])
        (fun node => by rw [nodesEq])
        (fun leader peer => by rw [nodesEq])
    ⟩
  · exact networkFrame
  · intro leader role peer
    simpa [nodesEq]
      using facts.leaderProgressBounded leader (by simpa [nodesEq] using role) peer
  · exact effectiveAckersSubsetAfter
  · intro actualVotes actualAppendHistory actualResponseHistory
        actualVoteRequestHistory actualVoteCandidateHistory
        actualVoteVoterHistory actualFacts leader index peer member
    simp only [
      potentialAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | reserve⟩
    · refine ⟨by simpa [hasJoinedEq] using joined, Or.inl ?_⟩
      exact
        effectiveAckersSubsetAfter
          actualVotes actualAppendHistory actualResponseHistory
            actualVoteRequestHistory actualVoteCandidateHistory
            actualVoteVoterHistory actualFacts leader index effective
    · refine ⟨by simpa [hasJoinedEq] using joined, Or.inr ?_⟩
      unfold queuedAppendReserve at reserve ⊢
      rcases reserve with
        ⟨request, queued, sourceEq, destinationEq,
          requestTerm, producible, covered⟩
      exact ⟨
        request,
        appendRequestSubset peer request queued,
        sourceEq,
        destinationEq,
        by simpa [nodesEq] using requestTerm,
        by simpa [nodesEq] using producible,
        by simpa [nodesEq] using covered
      ⟩
  · exact effectiveElectionMajorityBack
  · intro candidate role majority
    rw [hasPotentialElectionMajority, List.all_eq_true] at majority ⊢
    intro configuration active
    apply decide_eq_true
    have afterActive :
        configuration ∈ activeConfigurations ((nodeOf after) candidate) := by
      simpa [nodesEq] using active
    apply
      hasConfigurationMajority_mono
        (smaller := potentialElectionVoters (joined := joinedNext) after candidate)
        (larger := potentialElectionVoters (joined := joinedNodes) state candidate)
        ?_
        (of_decide_eq_true (majority configuration afterActive))
    intro voter member
    simp only [
      potentialElectionVoters, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | eligible⟩
    · exact ⟨
        by simpa [hasJoinedEq] using joined,
        Or.inl
          (effectiveElectionMemberBack candidate voter
            (by simpa [nodesEq] using Or.inl role) effective)
      ⟩
    · refine ⟨by simpa [hasJoinedEq] using joined, Or.inr ?_⟩
      unfold currentlyEligibleElectionVoter at eligible ⊢
      simpa [voteRequestKey, Model.Local.makeRequestVoteRequest, nodesEq] using eligible
  · exact effectiveElectionMemberBack

/--
Adding, removing, or replacing only safety-inert election-control packets
preserves the invariant when every node record is unchanged.
-/
lemma safetyInertNetworkChangePreservesSystemInductiveInvariant
    (state after : Model.State Node TxId)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (hasJoinedEq : joinedNext = joinedNodes)
    (allocatedEq : forall node, node ∈ joinedNext <-> node ∈ joinedNodes)
    (nodeStateEq : forall node, (nodeOf after) node = (nodeOf state) node)
    (networkFrame
      : forall destination message,
          (message ∈ after.network /\ message.target = destination)
          -> (message ∈ state.network /\ message.target = destination)
              \/ (IsSafetyInert message.payload
                  /\ message.target = destination
                  /\ TermNumberValid message.payload.term))
    : SystemInductiveInvariant (joined := joinedNext) after := by
  have appendResponseSubset :
      forall destination response,
        (appendResponseEnvelope response ∈ after.network /\ response.2.1 = destination) ->
          (appendResponseEnvelope response ∈ state.network /\ response.2.1 = destination) := by
    intro destination response member
    rcases networkFrame destination _ member with old | inert
    · exact old
    · simp [IsSafetyInert] at inert
  have voteResponseSubset :
      forall destination response,
        (voteResponseEnvelope response ∈ after.network /\ response.2.1 = destination) ->
          (voteResponseEnvelope response ∈ state.network /\ response.2.1 = destination) := by
    intro destination response member
    rcases networkFrame destination _ member with old | inert
    · exact old
    · simp [IsSafetyInert] at inert
  have effectiveElectionSubset :
      forall candidate,
        effectiveElectionVoters (joined := joinedNext) after candidate ⊆
          effectiveElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate voter member
    simp only [
      effectiveElectionVoters, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, processed | queued⟩
    · exact ⟨
        by simpa [hasJoinedEq] using joined,
        Or.inl (by simpa [nodeStateEq] using processed)
      ⟩
    · rcases queued with
        ⟨response, queued, granted, responseTerm,
          responseSource, responseDestination⟩
      exact ⟨
        by simpa [hasJoinedEq] using joined,
        Or.inr
          ⟨
            response,
            voteResponseSubset candidate response queued,
            granted,
            by simpa [nodeStateEq] using responseTerm,
            responseSource,
            responseDestination
          ⟩
      ⟩
  apply
    networkFramePreservesSystemInductiveInvariant
      state after invariant hasJoinedEq allocatedEq nodeStateEq networkFrame
  · intro _ _ responseHistory _ _ _ _ leader index peer member
    simp only [
      effectiveAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, self | matched | queued⟩
    · exact ⟨by simpa [hasJoinedEq] using joined, Or.inl self⟩
    · exact ⟨
        by simpa [hasJoinedEq] using joined,
        Or.inr (Or.inl (by simpa [nodeStateEq] using matched))
      ⟩
    · rcases queued with
        ⟨response, queued, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      exact ⟨
        by simpa [hasJoinedEq] using joined,
        Or.inr
          (Or.inr
            ⟨
              response,
              appendResponseSubset leader response queued,
              success,
              by simpa [nodeStateEq] using responseTerm,
              responseSource,
              responseDestination,
              lastIndex,
              by simpa [nodeStateEq] using covered
            ⟩)
      ⟩
  · intro candidate _ majority
    rw [hasEffectiveElectionMajority, List.all_eq_true] at majority ⊢
    intro configuration active
    apply decide_eq_true
    exact
      hasConfigurationMajority_mono
        (effectiveElectionSubset candidate)
        (of_decide_eq_true
          (majority configuration
            (by simpa [nodeStateEq] using active)))
  · intro candidate voter _ member
    exact effectiveElectionSubset candidate member

/-- Sending RequestPreVote adds only a safety-inert pre-vote packet. -/
lemma requestPreVotePreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (source destination : Node)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (_enabled
      : (source ∈ joinedNodes
          /\ destination ∈ joinedNodes
          /\ ((nodeOf state) source).role = .preVoteCandidate
          /\ Not (source = destination)
          /\ destination ∈ activeNodeUnion ((nodeOf state) source)))
    : SystemInductiveInvariant (joined := joinedNodes) (requestPreVoteEffect state source destination) := by
  let request := voteRequestKey state source destination
  let after := requestPreVoteEffect state source destination
  change SystemInductiveInvariant (joined := joinedNodes) after
  apply
    safetyInertNetworkChangePreservesSystemInductiveInvariant
      state after invariant rfl (fun _ => Iff.rfl) (fun _ => rfl)
  intro queuedDestination message member
  rcases
      memEnqueue
        state.network (preVoteRequestEnvelope request)
          message queuedDestination
          (by simpa [after, concrete_effects, request] using member) with
    old | new
  · exact Or.inl old
  · rcases new with ⟨destinationEq, messageEq⟩
    subst queuedDestination
    subst message
    exact Or.inr
      ⟨by simp [IsSafetyInert], rfl,
        invariantCurrentTermsValid invariant source⟩

/-- Enqueuing a proposal packet changes no consensus-safety evidence. -/
lemma enqueueProposeVoteRequestPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (request : Node × Node × Nat)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (requestTermValid : TermNumberValid request.2.2)
    : SystemInductiveInvariant (joined := joinedNodes)
        {
          state with
            network :=
              enqueue state.network (proposeVoteEnvelope request)
        } := by
  let after : Model.State Node TxId :=
    { state with
      network :=
        enqueue state.network (proposeVoteEnvelope request) }
  change SystemInductiveInvariant (joined := joinedNodes) after
  apply
    safetyInertNetworkChangePreservesSystemInductiveInvariant
      state after invariant rfl (fun _ => Iff.rfl) (fun _ => rfl)
  intro queuedDestination message member
  rcases
      memEnqueue
        state.network (proposeVoteEnvelope request)
          message queuedDestination
          (by simpa [after] using member) with
    old | new
  · exact Or.inl old
  · rcases new with ⟨destinationEq, messageEq⟩
    subst queuedDestination
    subst message
    exact Or.inr ⟨by simp [IsSafetyInert], rfl, requestTermValid⟩

/-- Sending a successor proposal preserves the safety invariant. -/
lemma proposeVotePreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (source destination : Node)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (_enabled
      : (source ∈ joinedNodes
          /\ destination ∈ joinedNodes
          /\ ((nodeOf state) source).role = .leader
          /\ plausibleSuccessor (nodeOf state source) source destination))
    : SystemInductiveInvariant (joined := joinedNodes) (proposeVoteEffect state source destination) := by
  simpa [concrete_effects]
    using enqueueProposeVoteRequestPreservesSystemInductiveInvariant
      state ((source, destination, (nodeOf state source).currentTerm)) invariant
      (invariantCurrentTermsValid invariant source)

/-- Replication cursors and queued ACK evidence determine effective ACKers. -/
lemma effectiveAckersFrame
    (state after : Model.State Node TxId)
    (networkEq : after.network = state.network)
    (hasJoinedEq : joinedNext = joinedNodes)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf state) node).log)
    (matchEq
      : forall leader peer,
          ((nodeOf after) leader).matchIndex peer = ((nodeOf state) leader).matchIndex peer)
    : forall (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
              leader index,
        effectiveAckers (joined := joinedNext) after responseHistory leader index
        = effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
  intro responseHistory leader index
  ext peer
  simp only [
    effectiveAckers, Finset.mem_filter]
  apply and_congr
  · simp only [hasJoinedEq]
  · constructor <;> rintro (self | matched | queued)
    · exact Or.inl self
    · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
    · right
      right
      rcases queued with
        ⟨response, member, success, responseTerm, sourceEq,
          destinationEq, lastIndex, covered⟩
      exact ⟨
        response,
        by simpa [networkEq] using member,
        success,
        by simpa [termEq] using responseTerm,
        sourceEq,
        destinationEq,
        lastIndex,
        by simpa [logEq] using covered
      ⟩
    · exact Or.inl self
    · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
    · right
      right
      rcases queued with
        ⟨response, member, success, responseTerm, sourceEq,
          destinationEq, lastIndex, covered⟩
      exact ⟨
        response,
        by simpa [networkEq] using member,
        success,
        by simpa [termEq] using responseTerm,
        sourceEq,
        destinationEq,
        lastIndex,
        by simpa [logEq] using covered
      ⟩

/-- Vote sets and queued grants determine effective election voters. -/
lemma effectiveElectionVotersFrame
    (state after : Model.State Node TxId)
    (networkEq : after.network = state.network)
    (hasJoinedEq : joinedNext = joinedNodes)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (votesEq
      : forall node, ((nodeOf after) node).votesGranted = ((nodeOf state) node).votesGranted)
    : forall candidate,
        effectiveElectionVoters (joined := joinedNext) after candidate
        = effectiveElectionVoters (joined := joinedNodes) state candidate := by
  intro candidate
  ext voter
  simp only [
    effectiveElectionVoters, Finset.mem_filter]
  apply and_congr
  · simp only [hasJoinedEq]
  · constructor <;> rintro (processed | queued)
    · exact Or.inl (by simpa [votesEq] using processed)
    · right
      rcases queued with
        ⟨response, member, granted, responseTerm,
          responseSource, responseDestination⟩
      exact ⟨
        response,
        by simpa [networkEq] using member,
        granted,
        by simpa [termEq] using responseTerm,
        responseSource,
        responseDestination
      ⟩
    · exact Or.inl (by simpa [votesEq] using processed)
    · right
      rcases queued with
        ⟨response, member, granted, responseTerm,
          responseSource, responseDestination⟩
      exact ⟨
        response,
        by simpa [networkEq] using member,
        granted,
        by simpa [termEq] using responseTerm,
        responseSource,
        responseDestination
      ⟩

/-- Retirement metadata and observer bookkeeping are safety-inert. -/
lemma retirementMetadataFramePreservesSystemInductiveInvariant
    (state after : Model.State Node TxId)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (hasJoinedEq : joinedNext = joinedNodes)
    (allocatedEq : forall node, node ∈ joinedNext <-> node ∈ joinedNodes)
    (networkEq : after.network = state.network)
    (roleEq : forall node, ((nodeOf after) node).role = ((nodeOf state) node).role)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf state) node).log)
    (commitEq
      : forall node, ((nodeOf after) node).commitIndex = ((nodeOf state) node).commitIndex)
    (sentEq : forall node, ((nodeOf after) node).sentIndex = ((nodeOf state) node).sentIndex)
    (matchEq : forall node, ((nodeOf after) node).matchIndex = ((nodeOf state) node).matchIndex)
    (votedEq : forall node, ((nodeOf after) node).votedFor = ((nodeOf state) node).votedFor)
    (votesEq
      : forall node, ((nodeOf after) node).votesGranted = ((nodeOf state) node).votesGranted)
    (followerEq : forall node,
      (nodeOf after node).isNewFollower = (nodeOf state node).isNewFollower)
    : SystemInductiveInvariant (joined := joinedNext) after := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have activeConfigurationsEq :
      forall node,
        activeConfigurations ((nodeOf after) node) =
          activeConfigurations ((nodeOf state) node) := by
    intro node
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have effectiveAckersEq :
      forall actualResponseHistory leader index,
        effectiveAckers (joined := joinedNext) after actualResponseHistory leader index =
          effectiveAckers (joined := joinedNodes) state actualResponseHistory leader index :=
    effectiveAckersFrame
      state after networkEq hasJoinedEq termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters (joined := joinedNext) after candidate =
          effectiveElectionVoters (joined := joinedNodes) state candidate :=
    effectiveElectionVotersFrame
      state after networkEq hasJoinedEq termEq votesEq
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters (joined := joinedNext) after candidate =
          potentialElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨
          by simpa [hasJoinedEq] using joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq] at effective
              exact effective)
        ⟩
      · exact ⟨
          by simpa [hasJoinedEq] using joined,
          Or.inr
            (by
              simpa [currentlyEligibleElectionVoter, voteRequestKey, Model.Local.makeRequestVoteRequest, termEq,
                logEq, commitEq, votedEq,
                lastCommittableIndexFrame
                  (logEq candidate) (commitEq candidate),
                lastCommittableTermFrame
                  (logEq candidate) (commitEq candidate), voteLogUpToDate]
                using eligible)
        ⟩
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨
          by simpa [hasJoinedEq] using joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq]
              exact effective)
        ⟩
      · exact ⟨
          by simpa [hasJoinedEq] using joined,
          Or.inr
            (by
              simpa [currentlyEligibleElectionVoter, voteRequestKey, Model.Local.makeRequestVoteRequest, termEq,
                logEq, commitEq, votedEq,
                lastCommittableIndexFrame
                  (logEq candidate) (commitEq candidate),
                lastCommittableTermFrame
                  (logEq candidate) (commitEq candidate), voteLogUpToDate]
                using eligible)
        ⟩
  have joinedCarriersAfter : JoinedCarrierFacts (joined := joinedNext) after := by
    apply
      joinedCarrierFactsFrame
        state after facts.joinedCarriers hasJoinedEq
          (fun node configuration active => by
            simpa [activeConfigurationsEq] using active)
          (fun node configuration member => by
            simpa [logEq] using member)
          (fun node peer member => by simpa [votesEq] using member)
          (fun node active => by
            rw [hasJoinedEq]
            exact
              facts.joinedCarriers.runtimeNodes.activeRoles node
                (by simpa [roleEq] using active))
          (fun leader peer positive => by
            rw [hasJoinedEq]
            exact
              facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
                (by simpa [matchEq] using positive))
          (fun node nonempty => by
            rw [hasJoinedEq]
            exact
              facts.joinedCarriers.runtimeNodes.nonemptyLogs node
                (by simpa [logEq] using nonempty))
          (fun destination message member => by
            simpa [networkEq] using member)
  have candidatesSelfVoteAfter : CandidatesSelfVote after := by
    intro candidate role
    rcases
        facts.candidatesSelfVote candidate
          (by simpa [roleEq] using role) with
      ⟨voted, counted⟩
    exact ⟨by simpa [votedEq] using voted, by simpa [votesEq] using counted⟩
  have leadersHaveElectionWitnessAfter :
      LeadersHaveElectionWitness after := by
    intro leader role
    rcases
        facts.leadersHaveElectionWitness leader
          (by simpa [roleEq] using role) with
      bootstrap | majority
    · exact Or.inl
        ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
    · exact Or.inr (by simpa [logEq, votesEq] using majority)
  apply
    roleAndNetworkFramePreservesSystemInductiveInvariant
      state after
        ⟨votes, appendHistory, responseHistory,
          voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
        hasJoinedEq allocatedEq joinedCarriersAfter
        (fun node active => by simpa [roleEq] using active)
        (fun node role => by simpa [roleEq] using role)
        (fun node role => by simpa [roleEq] using role)
        (fun node role => by simpa [roleEq] using role)
        (fun node role => by simpa [roleEq] using role)
        termEq logEq commitEq
        candidatesSelfVoteAfter leadersHaveElectionWitnessAfter
  · intro _ _ _ _ _ _ actualFacts
    constructor
    · exact actualFacts.voteHistory.bootstrapEmpty
    · intro voter
      simpa [termEq, votedEq] using actualFacts.voteHistory.current voter
    · intro voter term future
      exact
        actualFacts.voteHistory.future voter term
          (by simpa [termEq] using future)
    · intro candidate voter active member
      rw [termEq]
      exact
        actualFacts.voteHistory.counted candidate voter
          (by simpa [roleEq] using active)
          (by simpa [votesEq] using member)
  · intro _ _ _ _ _ _ actualFacts
    rcases actualFacts.processedAckHistory with
      ⟨history, historyFacts⟩
    exact ⟨
      history,
      processedAckHistoryFrame
        state after history historyFacts roleEq termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
    ⟩
  · intro destination message member
    exact Or.inl (by simpa [networkEq] using member)
  · intro leader role peer
    simpa [sentEq, matchEq, logEq]
      using facts.leaderProgressBounded leader (by simpa [roleEq] using role) peer
  · intro _ _ actualResponseHistory _ _ _ _ leader index
    exact Finset.subset_of_eq
      (effectiveAckersEq actualResponseHistory leader index)
  · intro _ actualAppendHistory actualResponseHistory
      _ _ _ _ leader index peer member
    simp only [
      potentialAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | reserve⟩
    · exact ⟨
        by simpa [hasJoinedEq] using joined,
        Or.inl
          (by
            rw [effectiveAckersEq actualResponseHistory leader index]
              at effective
            exact effective)
      ⟩
    · rcases reserve with
        ⟨request, queued, sourceEq, destinationEq,
          requestTerm, producible, covered⟩
      exact ⟨
        by simpa [hasJoinedEq] using joined,
        Or.inr
          ⟨
            request,
            by simpa [networkEq] using queued,
            sourceEq,
            destinationEq,
            by simpa [termEq] using requestTerm,
            by
              rcases producible with direct | future
              · left
                exact (canProduceAppendAckAt_frame (roleEq peer) (termEq peer)
                  (logEq peer) (commitEq peer) (followerEq peer) request index).mp direct
              · exact Or.inr
                  ⟨by simpa [termEq] using future.1, future.2⟩,
            by simpa [logEq] using covered
          ⟩
      ⟩
  · intro candidate _ majority
    unfold hasEffectiveElectionMajority at majority ⊢
    simpa [activeConfigurationsEq, effectiveElectionVotersEq] using majority
  · intro candidate _ majority
    unfold hasPotentialElectionMajority at majority ⊢
    simpa [activeConfigurationsEq, potentialElectionVotersEq] using majority
  · intro candidate voter _ member
    simpa [effectiveElectionVotersEq] using member

end CCFRaft.Proofs.Invariant
