-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Quorums
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

/--
Future voter closure transfers any canonically owned signed prefix from one
current supporter into the unchanged candidate log.
-/
lemma futureElectionMemberContainsSignedPrefix
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (committedSignature : CommittedFrontierIsSignature state)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    {evidence : CommitEvidence Node TxId}
    (frontierBound : evidence.commitFrontier <= evidence.history.length)
    (frontierTerm : termAt evidence.history evidence.commitFrontier = evidence.commitTerm)
    (frontierPositive : 0 < evidence.commitFrontier)
    (frontierSignature : isSignatureAt evidence.history evidence.commitFrontier = true)
    (commitTermPositive : BOOTSTRAP_TERM <= evidence.commitTerm)
    (electionClosure
      : forall term record,
          elections term = some record
          -> evidence.commitTerm < term
          -> evidence.history.take evidence.commitFrontier <+: record.promotionLog)
    {candidate member : Node}
    {targetTerm : Nat}
    (memberCovered
      : evidence.history.take evidence.commitFrontier <+: (state.nodes member).log)
    (future : member ∈ futureElectionVoters state candidate targetTerm)
    : evidence.history.take evidence.commitFrontier <+: (state.nodes candidate).log := by
  let evidencePrefix :=
    evidence.history.take evidence.commitFrontier
  have prefixLength :
      evidencePrefix.length = evidence.commitFrontier := by
    simp only [evidencePrefix, List.length_take]
    rw [Nat.min_eq_left frontierBound]
  rcases
      entryAtSomeOfPositiveBound frontierPositive frontierBound with
    ⟨frontierEntry, historyFound⟩
  have frontierEntryTerm :
      frontierEntry.term = evidence.commitTerm := by
    simpa [termAt, historyFound] using frontierTerm
  have prefixFound :
      entryAt? evidencePrefix evidence.commitFrontier =
        some frontierEntry := by
    rw [entryAtTake_of_le le_rfl]
    exact historyFound
  have memberFound :
      entryAt? (state.nodes member).log evidence.commitFrontier =
        some frontierEntry :=
    entryAt_of_prefix memberCovered prefixFound
  rcases
      ownership.logEntryAgreement
        member evidence.commitFrontier frontierEntry memberFound with
    ⟨canonicalCommitFound, memberAgreed⟩
  have prefixCanonical :
      evidencePrefix =
        (canonicalHistory evidence.commitTerm).take
          evidence.commitFrontier := by
    calc
      evidencePrefix = (state.nodes member).log.take evidence.commitFrontier := by
        have covered := prefixEqTake memberCovered
        rw [prefixLength] at covered
        exact covered.symm
      _ = (canonicalHistory frontierEntry.term).take evidence.commitFrontier :=
        memberAgreed
      _ = (canonicalHistory evidence.commitTerm).take evidence.commitFrontier := by
        rw [frontierEntryTerm]
  have prefixLastTerm :
      termAt evidencePrefix evidencePrefix.length =
        evidence.commitTerm := by
    rw [prefixLength]
    simpa [termAt, prefixFound] using frontierEntryTerm
  have evidenceSignature :
      isSignatureAt evidence.history evidence.commitFrontier = true :=
    frontierSignature
  have prefixSignature :
      isSignatureAt evidencePrefix evidence.commitFrontier = true := by
    exact isSignatureAt_take_of_le le_rfl evidenceSignature
  have memberSignature :
      isSignatureAt
        (state.nodes member).log evidence.commitFrontier = true :=
    isSignatureAt_of_prefix memberCovered prefixSignature
  have memberFrontierBound :
      evidence.commitFrontier <=
        maxCommittableIndex (state.nodes member).log :=
    signatureIndex_le_maxCommittableIndex memberSignature
  have memberCommittablePositive :
      0 < maxCommittableIndex (state.nodes member).log := by
    omega
  rcases
      isSignatureAtTrue
        (maxCommittableIndexPositiveIsSignature
          memberCommittablePositive) with
    ⟨memberEntry, memberEntryFound, _⟩
  have memberEntryTerm :
      maxCommittableTerm (state.nodes member).log =
        memberEntry.term := by
    simp [maxCommittableTerm, termAt, memberEntryFound]
  have memberLastTerm :
      evidence.commitTerm <=
        maxCommittableTerm (state.nodes member).log := by
    have entryOrder :
        frontierEntry.term <= memberEntry.term := by
      by_cases sameIndex :
          evidence.commitFrontier =
            maxCommittableIndex (state.nodes member).log
      · rw [sameIndex] at memberFound
        exact (congrArg Entry.term
                (Option.some.inj (memberFound.symm.trans memberEntryFound))).le
      · exact (canonicalHistoriesMonoLog ownership) member
          evidence.commitFrontier
          (maxCommittableIndex (state.nodes member).log)
          frontierEntry memberEntry
          (lt_of_le_of_ne memberFrontierBound sameIndex)
          memberFound memberEntryFound
    calc
      evidence.commitTerm = frontierEntry.term := frontierEntryTerm.symm
      _ <= memberEntry.term := entryOrder
      _ = maxCommittableTerm (state.nodes member).log :=
        memberEntryTerm.symm
  simp only [
    futureElectionVoters, Finset.mem_filter] at future
  rcases future with ⟨_joined, self | supporter⟩
  · subst member
    exact memberCovered
  · rcases supporter with ⟨_, upToDate⟩
    have commitPositive := commitTermPositive
    have candidateLastIndex :
        lastCommittableIndex (state.nodes candidate) =
          maxCommittableIndex (state.nodes candidate).log :=
      lastCommittableIndex_eq_maxCommittableIndex
        (state.nodes candidate) (committedSignature candidate)
    have candidateLastTermEq :
        lastCommittableTerm (state.nodes candidate) =
          maxCommittableTerm (state.nodes candidate).log :=
      lastCommittableTerm_eq_maxCommittableTerm
        (state.nodes candidate) (committedSignature candidate)
    unfold voteLogUpToDate at upToDate
    simp only [makeRequestVoteRequest] at upToDate
    rw [candidateLastIndex, candidateLastTermEq] at upToDate
    have candidateLastTerm :
        evidence.commitTerm <=
          maxCommittableTerm (state.nodes candidate).log := by
      rcases upToDate with newer | same
      · omega
      · omega
    have candidateTermPositive :
        0 < maxCommittableTerm (state.nodes candidate).log := by
      have commitTermPositive :
          0 < evidence.commitTerm := by
        exact positiveOfBootstrapTermLe commitPositive
      omega
    have candidateIndexPositive :
        0 < maxCommittableIndex (state.nodes candidate).log := by
      apply Nat.pos_of_ne_zero
      intro zero
      simp [
        maxCommittableTerm, zero, termAt, entryAt?
      ] at candidateTermPositive
    rcases
        isSignatureAtTrue
          (maxCommittableIndexPositiveIsSignature
            candidateIndexPositive) with
      ⟨candidateEntry, candidateFound, _⟩
    have candidateEntryLast :
        candidateEntry.term =
          maxCommittableTerm (state.nodes candidate).log := by
      simp [maxCommittableTerm, termAt, candidateFound]
    rcases
        ownership.logEntryAgreement
          candidate (maxCommittableIndex (state.nodes candidate).log)
            candidateEntry candidateFound with
      ⟨candidateCanonicalFound, candidateAgreed⟩
    by_cases sameCommit :
        candidateEntry.term = evidence.commitTerm
    · have candidateLengthBound :
          evidence.commitFrontier <=
            maxCommittableIndex (state.nodes candidate).log := by
        rcases upToDate with newer | same
        · rw [← candidateEntryLast, sameCommit] at newer
          omega
        · have memberLength := memberFrontierBound
          omega
      rw [List.prefix_iff_eq_take]
      calc
        evidencePrefix
            = (canonicalHistory evidence.commitTerm).take evidence.commitFrontier :=
          prefixCanonical
        _ = ((canonicalHistory candidateEntry.term).take
              (maxCommittableIndex (state.nodes candidate).log)).take
              evidence.commitFrontier := by
          rw [sameCommit]
          simp [List.take_take, Nat.min_eq_left candidateLengthBound]
        _ = ((state.nodes candidate).log.take
              (maxCommittableIndex (state.nodes candidate).log)).take
              evidence.commitFrontier := by
          rw [← candidateAgreed]
        _ = (state.nodes candidate).log.take evidence.commitFrontier := by
          simp [List.take_take, Nat.min_eq_left candidateLengthBound]
        _ = (state.nodes candidate).log.take evidencePrefix.length := by
          rw [prefixLength]
    · have commitStrict :
          evidence.commitTerm < candidateEntry.term := by
        rw [candidateEntryLast] at sameCommit
        omega
      rcases
          ownership.canonicalEntryOwner
            candidateEntry.term
              (maxCommittableIndex (state.nodes candidate).log)
              candidateEntry candidateCanonicalFound with
        ⟨owner, owned⟩
      rcases
          electionFacts.ownerRecorded
            candidateEntry.term owner owned with
        bootstrap | recorded
      · rw [bootstrap.1] at commitStrict
        omega
      · rcases recorded with
          ⟨record, recordStored, _⟩
        have closure :=
          electionClosure
            candidateEntry.term record recordStored commitStrict
        have prefixInCanonical :
            evidencePrefix <+:
              canonicalHistory candidateEntry.term :=
          closure.trans
            (electionFacts.promotionCanonical
              candidateEntry.term record recordStored)
        have canonicalPrefixFound :
            entryAt?
                (canonicalHistory candidateEntry.term)
                evidence.commitFrontier =
              some frontierEntry :=
          entryAt_of_prefix prefixInCanonical prefixFound
        have lengthStrict :
            evidence.commitFrontier <
              maxCommittableIndex (state.nodes candidate).log := by
          by_contra notStrict
          have reverse :
              maxCommittableIndex (state.nodes candidate).log <=
                evidence.commitFrontier := by omega
          by_cases equal :
              maxCommittableIndex (state.nodes candidate).log =
                evidence.commitFrontier
          · rw [equal] at candidateCanonicalFound
            have entryEq :
                candidateEntry = frontierEntry :=
              Option.some.inj
                (candidateCanonicalFound.symm.trans canonicalPrefixFound)
            rw [entryEq, frontierEntryTerm] at commitStrict
            omega
          · have order :
              maxCommittableIndex (state.nodes candidate).log <
                  evidence.commitFrontier := by omega
            have termOrder :=
              ownership.canonicalMonoLog candidateEntry.term
              (maxCommittableIndex (state.nodes candidate).log)
                evidence.commitFrontier
                candidateEntry frontierEntry order
                candidateCanonicalFound canonicalPrefixFound
            rw [frontierEntryTerm] at termOrder
            omega
        rw [List.prefix_iff_eq_take]
        calc
          evidencePrefix
              = (canonicalHistory candidateEntry.term).take evidence.commitFrontier := by
            have covered := prefixEqTake prefixInCanonical
            simpa [prefixLength] using covered.symm
          _ = ((canonicalHistory candidateEntry.term).take
                (maxCommittableIndex (state.nodes candidate).log)).take
                evidence.commitFrontier := by
            simp [
              List.take_take,
              Nat.min_eq_left lengthStrict.le
            ]
          _ = ((state.nodes candidate).log.take
                (maxCommittableIndex (state.nodes candidate).log)).take
                evidence.commitFrontier := by
            rw [← candidateAgreed]
          _ = (state.nodes candidate).log.take evidence.commitFrontier := by
            simp [
              List.take_take,
              Nat.min_eq_left lengthStrict.le
            ]
          _ = (state.nodes candidate).log.take evidencePrefix.length := by
            rw [prefixLength]

/-- Commit-evidence specialization of signed-prefix future-voter closure. -/
lemma prospectiveCommitFutureMemberCore
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (committedSignature : CommittedFrontierIsSignature state)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (commitTermPositive
      : forall evidence supportedPrefix,
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix
          -> BOOTSTRAP_TERM <= evidence.commitTerm)
    (electionClosure
      : forall evidence supportedPrefix,
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix
          -> forall term record,
              elections term = some record
              -> evidence.commitTerm < term
              -> evidence.history.take evidence.commitFrontier <+: record.promotionLog)
    (currentMember
      : forall evidence supportedPrefix,
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix
          -> forall member,
              member ∈ evidence.ackQuorum
              -> evidence.history.take evidence.commitFrontier
                  <+: (state.nodes member).log)
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (known
      : KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {candidate member : Node}
    {targetTerm : Nat}
    (ackMember : member ∈ evidence.ackQuorum)
    (future : member ∈ futureElectionVoters state candidate targetTerm)
    : evidence.history.take evidence.commitFrontier <+: (state.nodes candidate).log := by
  have valid := knownCommitEvidenceValid evidenceFacts known
  have supportedPositive :=
    knownCommitEvidenceSupportedLengthPositive evidenceFacts known
  apply
    futureElectionMemberContainsSignedPrefix
      ownership committedSignature electionFacts
      valid.1 valid.2.1
      (supportedPositive.trans_le valid.2.2.1)
      valid.2.2.2.2.2.2.1
      (commitTermPositive evidence supportedPrefix known)
      (fun term record recorded newer =>
        electionClosure
          evidence supportedPrefix known term record recorded newer)
      (currentMember
        evidence supportedPrefix known member ackMember)
      future

omit [DecidableEq TxId] [Bootstrap Node] in
/-- Frozen activation closure rules out every recorded current-log handoff. -/
lemma activationSupporterContainsCurrentPrefix
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (currentHistory : ActivationSupporterCurrentHistory state elections activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    (stored : activations activationIndex = some activation)
    {supporter : Node}
    (member : supporter ∈ activation.jointSupporters)
    : activation.history.take activation.activationFrontier
      <+: (state.nodes supporter).log := by
  rcases currentHistory
      activationIndex activation stored supporter member with
    retained | bad
  · exact retained
  · rcases bad with
      ⟨badTerm, badRecord, later, _bounded, badStored, missing⟩
    exact False.elim
      (missing
        (activationPrefixInLaterElection
          activationElections stored badStored later))

/--
One future voter from an activation quorum transfers the signed activation
prefix into the unchanged timeout candidate log.
-/
lemma activationSupporterFutureCandidateContainsPrefix
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (committedSignature : CommittedFrontierIsSignature state)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (currentHistory : ActivationSupporterCurrentHistory state elections activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    (stored : activations activationIndex = some activation)
    {candidate supporter : Node}
    {targetTerm : Nat}
    (member : supporter ∈ activation.jointSupporters)
    (future : supporter ∈ futureElectionVoters state candidate targetTerm)
    : activation.history.take activation.activationFrontier
      <+: (state.nodes candidate).log := by
  let evidence : CommitEvidence Node TxId :=
    { commitTerm := activation.activationTerm
      history := activation.history
      commitFrontier := activation.activationFrontier
      supportedLength := 0
      authority := activation.newConfiguration
      ackQuorum := activation.jointSupporters }
  have valid := historyFacts.valid activationIndex activation stored
  have frontierTerm :=
    (historyFacts.supporterAcks
      activationIndex activation stored).1
  have frontierPositive : 0 < activation.activationFrontier := by
    exact Nat.zero_lt_of_lt valid.1
  have covered :=
    activationSupporterContainsCurrentPrefix
      currentHistory activationElections stored member
  simpa [evidence]
    using (futureElectionMemberContainsSignedPrefix
            ownership committedSignature electionFacts
            (evidence := evidence)
            (by simpa [evidence] using valid.2.1)
            (by simpa [evidence] using frontierTerm)
            (by simpa [evidence] using frontierPositive)
            (by simpa [evidence] using valid.2.2.2.2.2.1)
            (by
              simpa [evidence]
                using historyFacts.termPositive activationIndex activation stored)
            (fun term record recorded later => by
              simpa [evidence]
                using activationPrefixInLaterElection
                  activationElections stored recorded
                  (by simpa [evidence] using later))
            (by simpa [evidence] using covered)
            future)

/--
A future election quorum intersecting one activation-governing quorum carries
that activation into the unchanged candidate log.
-/
lemma activationPrefixInFutureCandidateOfGoverningConfiguration
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (committedSignature : CommittedFrontierIsSignature state)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (currentHistory : ActivationSupporterCurrentHistory state elections activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    (stored : activations activationIndex = some activation)
    {candidate : Node}
    {targetTerm : Nat}
    {ballotActive : List (Configuration Node)}
    (futureMajority : hasFutureElectionMajority state candidate targetTerm ballotActive)
    {configuration : Configuration Node}
    (governing : configuration ∈ activation.governingActive)
    (candidateActive : configuration ∈ ballotActive)
    : activation.history.take activation.activationFrontier
      <+: (state.nodes candidate).log := by
  have activationMajority :=
    (historyFacts.valid
      activationIndex activation stored).2.2.2.2.2.2.2.2
      configuration governing
  have candidateMajority :=
    futureElectionMajorityAtConfiguration
      futureMajority candidateActive
  rcases
      configurationMajoritiesIntersect
        activationMajority candidateMajority with
    ⟨supporter, _configurationMember, activationMember, futureMember⟩
  exact
    activationSupporterFutureCandidateContainsPrefix
      ownership committedSignature electionFacts historyFacts
      currentHistory activationElections stored
      activationMember futureMember

/--
A potential election quorum intersecting one activation-governing quorum
carries that activation into the candidate's promotion prefix.
-/
lemma activationPrefixInPotentialCandidatePromotionOfGoverningConfiguration
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (committedSignature : CommittedFrontierIsSignature state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (canonicalSnapshots
      : GrantedVoteCanonicalSnapshots
          state canonicalHistory voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (currentHistory : ActivationSupporterCurrentHistory state elections activations)
    (voteHistory : ActivationVoteHistory votes voteVoterHistory elections activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    (stored : activations activationIndex = some activation)
    {candidate : Node}
    (candidateRole : (state.nodes candidate).role = .candidate)
    (candidateMajority : hasPotentialElectionMajority state candidate)
    (activationBeforeCandidate
      : activation.activationTerm < (state.nodes candidate).currentTerm)
    {configuration : Configuration Node}
    (governing : configuration ∈ activation.governingActive)
    (candidateActive : configuration ∈ activeConfigurations (state.nodes candidate))
    : activation.history.take activation.activationFrontier
      <+: (state.nodes candidate).log.take
            (maxCommittableIndex (state.nodes candidate).log) := by
  have valid := historyFacts.valid activationIndex activation stored
  have activationMajority :=
    valid.2.2.2.2.2.2.2.2 configuration governing
  have candidateConfigurationMajority :=
    potentialElectionMajorityAtConfiguration
      candidateMajority candidateActive
  rcases
      configurationMajoritiesIntersect
        activationMajority candidateConfigurationMajority with
    ⟨supporter, _configurationMember, activationMember, candidateMember⟩
  by_cases supporterEq : supporter = candidate
  · subst supporter
    apply
      signatureEndedPrefixOfMaxTake
        (activationSupporterContainsCurrentPrefix
          currentHistory activationElections stored activationMember)
    exact signatureAtTakeLength valid.2.2.2.2.2.1
  · simp only [
      potentialElectionVoters, Finset.mem_filter] at candidateMember
    rcases candidateMember with ⟨_joined, materialised | eligible⟩
    · have snapshot :=
        snapshots candidate supporter
          (Or.inl candidateRole) materialised
      have recordedVote := snapshot.1
      rcases snapshot.2 with self | voteSnapshot
      · exact False.elim (supporterEq self)
      · have voterPrefix :
          activation.history.take activation.activationFrontier <+:
            voteVoterHistory
              (grantedVoteKey
                supporter (state.nodes candidate).currentTerm candidate) := by
          rcases
              voteHistory
                activationIndex activation supporter
                (state.nodes candidate).currentTerm candidate
                stored activationMember recordedVote supporterEq
                activationBeforeCandidate with
            retained | bad
          · exact retained
          · rcases bad with
              ⟨badTerm, badRecord, later, _bounded, badStored, missing⟩
            exact False.elim
              (missing
                (activationPrefixInLaterElection
                  activationElections stored badStored later))
        rcases
            canonicalSnapshots candidate supporter
              (Or.inl candidateRole) materialised with
          self | canonicalSnapshot
        · exact False.elim (supporterEq self)
        · let response :=
            grantedVoteKey
              supporter (state.nodes candidate).currentTerm candidate
          have candidateEntrySafe :
              forall entry,
                entry ∈ voteCandidateHistory response ->
                  entry.term < (state.nodes candidate).currentTerm \/
                    (entry.term = (state.nodes candidate).currentTerm /\
                      forall record,
                        elections (state.nodes candidate).currentTerm =
                            some record ->
                          activation.history.take
                              activation.activationFrontier <+:
                            record.promotionLog) := by
            intro entry member
            have currentMember :
                entry ∈ (state.nodes candidate).log :=
              memOfPrefix voteSnapshot.1 member
            have bounded := entriesBounded candidate entry currentMember
            by_cases same :
                entry.term = (state.nodes candidate).currentTerm
            · exact Or.inr
                ⟨same, fun record recorded =>
                  activationPrefixInLaterElection
                    activationElections stored recorded
                    activationBeforeCandidate⟩
            · exact Or.inl (by omega)
          apply
            candidateSnapshotContainsSupportedPrefix
              (targetTerm := (state.nodes candidate).currentTerm)
              (historyFacts.termPositive activationIndex activation stored)
              ownership electionFacts
              (historyFacts.supporterAcks
                activationIndex activation stored).1
              valid.2.2.2.2.2.1
              voterPrefix
              (committablePrefixOfMaxTake
                voteSnapshot.1 voteSnapshot.2.1)
              canonicalSnapshot.1
              canonicalSnapshot.2.2.1
              canonicalSnapshot.2.2.2
              candidateEntrySafe
          · simpa [
              response, voteLogUpToDate, maxCommittableTerm,
              voteSnapshot.2.1, voteSnapshot.2.2.1
            ] using voteSnapshot.2.2.2.2
          · intro earlierTerm earlierRecord later _ recorded
            exact
              activationPrefixInLaterElection
                activationElections stored recorded later
    · have voterPrefix :
          activation.history.take activation.activationFrontier <+:
            (state.nodes supporter).log := by
        rcases
            currentHistory
              activationIndex activation stored supporter activationMember with
          retained | bad
        · exact retained
        · rcases bad with
            ⟨badTerm, badRecord, later, _bounded, badStored, missing⟩
          exact False.elim
            (missing
              (activationPrefixInLaterElection
                activationElections stored badStored later))
      have candidateEntrySafe :
          forall entry,
            entry ∈ (state.nodes candidate).log ->
              entry.term < (state.nodes candidate).currentTerm \/
                (entry.term = (state.nodes candidate).currentTerm /\
                  forall record,
                    elections (state.nodes candidate).currentTerm =
                        some record ->
                      activation.history.take
                          activation.activationFrontier <+:
                        record.promotionLog) := by
        intro entry member
        have bounded := entriesBounded candidate entry member
        by_cases same :
            entry.term = (state.nodes candidate).currentTerm
        · exact Or.inr
            ⟨same, fun record recorded =>
              activationPrefixInLaterElection
                activationElections stored recorded
                activationBeforeCandidate⟩
        · exact Or.inl (by omega)
      apply signatureEndedPrefixOfMaxTake
      · apply
          candidateSnapshotContainsSupportedPrefix
            (targetTerm := (state.nodes candidate).currentTerm)
            (historyFacts.termPositive activationIndex activation stored)
            ownership electionFacts
            (historyFacts.supporterAcks
              activationIndex activation stored).1
            valid.2.2.2.2.2.1
            voterPrefix
            (prefixRefl (state.nodes candidate).log)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement
                candidate entryIndex entry found)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement
                supporter entryIndex entry found)
            ((canonicalHistoriesMonoLog ownership) supporter)
            candidateEntrySafe
        · simpa [
              currentlyEligibleElectionVoter,
              makeRequestVoteRequest,
              lastCommittableIndex_eq_maxCommittableIndex
                (state.nodes candidate) (committedSignature candidate),
              lastCommittableTerm_eq_maxCommittableTerm
                (state.nodes candidate) (committedSignature candidate),
              voteLogUpToDate
            ] using eligible.2.1
        · intro earlierTerm earlierRecord later _ recorded
          exact
            activationPrefixInLaterElection
              activationElections stored recorded later
      · exact signatureAtTakeLength valid.2.2.2.2.2.1

/-- Every activation moves to a configuration with a strictly larger index. -/
lemma activationOldConfigurationIndexLtNew
    {activations : ActivationHistory Node TxId}
    (historyFacts : ActivationHistoryFacts activations)
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    (stored : activations activationIndex = some activation)
    : activation.oldConfiguration.index < activation.newConfiguration.index := by
  have valid := historyFacts.valid activationIndex activation stored
  have newGoverning :
      activation.newConfiguration ∈ activation.governingActive :=
    valid.2.2.2.2.2.2.2.1
  rw [valid.2.2.2.2.2.2.1] at newGoverning
  have newKnown :
      activation.newConfiguration ∈
        allConfigurations activation.history :=
    (List.mem_filter.mp newGoverning).1
  let priorNode : NodeState Node TxId :=
    { log := activation.history
      commitIndex := activation.priorCommitIndex
      currentTerm := 0
      role := .none
      votedFor := none
      votesGranted := ∅
      sentIndex := fun _ => 0
      matchIndex := fun _ => 0
      isNewFollower := false }
  have oldKnown :
      activation.oldConfiguration ∈
        allConfigurations activation.history := by
    have known := currentConfiguration_mem_allConfigurations priorNode
    simpa [
      priorNode, currentConfiguration,
      valid.2.2.1
    ] using known
  have oldLeNew :
      activation.oldConfiguration.index <=
        activation.newConfiguration.index :=
    (of_decide_eq_true (List.mem_filter.mp newGoverning).2).1
  have differentIndex :
      activation.oldConfiguration.index ≠
        activation.newConfiguration.index := by
    intro same
    apply valid.2.2.2.2.1
    exact
      allConfigurations_index_unique
        (TxId := TxId) activation.history
        oldKnown newKnown same
  exact lt_of_le_of_ne oldLeNew differentIndex

/--
Every configuration governed by an activation is no later than the
activation's resulting configuration.
-/
lemma activationGoverningConfigurationIndexLeNew
    {activations : ActivationHistory Node TxId}
    (historyFacts : ActivationHistoryFacts activations)
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    (stored : activations activationIndex = some activation)
    {configuration : Configuration Node}
    (governing : configuration ∈ activation.governingActive)
    : configuration.index <= activation.newConfiguration.index := by
  have valid := historyFacts.valid activationIndex activation stored
  have governingParts :
      configuration ∈ allConfigurations activation.history /\
        activation.oldConfiguration.index <= configuration.index /\
        configuration.index <= activation.activationFrontier := by
    rw [valid.2.2.2.2.2.2.1] at governing
    exact ⟨
      (List.mem_filter.mp governing).1,
      of_decide_eq_true (List.mem_filter.mp governing).2
    ⟩
  let activationNode : NodeState Node TxId :=
    { log := activation.history
      commitIndex := activation.activationFrontier
      currentTerm := 0
      role := .none
      votedFor := none
      votesGranted := ∅
      sentIndex := fun _ => 0
      matchIndex := fun _ => 0
      isNewFollower := false }
  have ordered :=
    configuration_index_le_currentConfiguration
      activationNode configuration
      (by simpa [activationNode] using governingParts.1)
      (by simpa [activationNode] using governingParts.2.2)
  simpa [activationNode, currentConfiguration, valid.2.2.2.1] using ordered

omit [DecidableEq TxId] in
/-- A covered current-configuration prefix precedes every higher activation. -/
lemma currentCoveragePrefixInHigherActivation
    {state : View Node TxId}
    {activations : ActivationHistory Node TxId}
    (coverage : ConfigurationCoverageFacts state activations)
    {node : Node}
    {higherIndex : ActivationKey Node}
    {higher : ActivationRecord Node TxId}
    (higherStored : activations higherIndex = some higher)
    (currentPositive : 0 < (currentConfiguration (state.nodes node)).index)
    (indexOrder
      : (currentConfiguration (state.nodes node)).index < higher.newConfiguration.index)
    : Exists
        fun witness : ConfigurationCoverageWitness state activations node =>
          witness.sharedPrefix <+: higher.history.take higher.activationFrontier := by
  rcases coverage node currentPositive with ⟨witness⟩
  exact ⟨witness, witness.sharedPrefix_prefix_higherAuthority higherStored indexOrder⟩

omit [DecidableEq TxId] in
/-- Every lower activation prefix precedes a covered current configuration. -/
lemma lowerActivationPrefixInCurrentCoverage
    {state : View Node TxId}
    {activations : ActivationHistory Node TxId}
    (coverage : ConfigurationCoverageFacts state activations)
    {node : Node}
    {lowerIndex : ActivationKey Node}
    {lower : ActivationRecord Node TxId}
    (lowerStored : activations lowerIndex = some lower)
    (currentPositive : 0 < (currentConfiguration (state.nodes node)).index)
    (indexOrder
      : lower.newConfiguration.index < (currentConfiguration (state.nodes node)).index)
    : Exists
        fun witness : ConfigurationCoverageWitness state activations node =>
          lower.history.take lower.activationFrontier <+: witness.sharedPrefix := by
  rcases coverage node currentPositive with ⟨witness⟩
  exact ⟨witness, witness.lowerAuthority_prefix_sharedPrefix lowerStored indexOrder⟩

/--
Prefix inclusion between two signed activation frontiers orders their terms.
-/
lemma activationTermLeOfPrefix
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {activations : ActivationHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (historyFacts : ActivationHistoryFacts activations)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    {earlierIndex laterIndex : ActivationKey Node}
    {earlier later : ActivationRecord Node TxId}
    (earlierStored : activations earlierIndex = some earlier)
    (laterStored : activations laterIndex = some later)
    (isPrefix
      : earlier.history.take earlier.activationFrontier
        <+: later.history.take later.activationFrontier)
    : earlier.activationTerm <= later.activationTerm := by
  have earlierValid := historyFacts.valid earlierIndex earlier earlierStored
  have laterValid := historyFacts.valid laterIndex later laterStored
  have earlierLength :
      (earlier.history.take earlier.activationFrontier).length =
        earlier.activationFrontier := by
    simp [Nat.min_eq_left earlierValid.2.1]
  have laterLength :
      (later.history.take later.activationFrontier).length =
        later.activationFrontier := by
    simp [Nat.min_eq_left laterValid.2.1]
  have earlierTermAt :
      termAt
          (earlier.history.take earlier.activationFrontier)
          (earlier.history.take earlier.activationFrontier).length =
        earlier.activationTerm := by
    rw [earlierLength, termAtTakeOfLe le_rfl]
    exact (historyFacts.supporterAcks
      earlierIndex earlier earlierStored).1
  have laterTermAt :
      termAt
          (later.history.take later.activationFrontier)
          (later.history.take later.activationFrontier).length =
        later.activationTerm := by
    rw [laterLength, termAtTakeOfLe le_rfl]
    exact (historyFacts.supporterAcks
      laterIndex later laterStored).1
  have laterMono :
      MonoHistory
        (later.history.take later.activationFrontier) :=
    canonicalSnapshotMono ownership
      (historyCanonicalOfPrefix
        (activationCanonical.recordCanonical
          laterIndex later laterStored)
        (List.take_prefix later.activationFrontier later.history))
  have ordered :=
    termAtLastMonotoneOfPrefix isPrefix laterMono
  rw [earlierTermAt, laterTermAt] at ordered
  exact ordered

/--
Canonical term histories and frozen elections compare two ordered activation
prefixes directly when the lower activation is not on the higher authority's
immediate prior chain.
-/
lemma activationPrefixInHigherActivationCore
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (_ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    {lowerIndex higherIndex : ActivationKey Node}
    {lower higher : ActivationRecord Node TxId}
    (lowerStored : activations lowerIndex = some lower)
    (higherStored : activations higherIndex = some higher)
    (indexOrder : lower.newConfiguration.index < higher.newConfiguration.index)
    : lower.history.take lower.activationFrontier
      <+: higher.history.take higher.activationFrontier := by
  let lowerPrefix :=
    lower.history.take lower.activationFrontier
  let higherPrefix :=
    higher.history.take higher.activationFrontier
  have lowerValid := historyFacts.valid lowerIndex lower lowerStored
  have higherValid := historyFacts.valid higherIndex higher higherStored
  have higherConfigurationKnown :
      higher.newConfiguration ∈ allConfigurations higherPrefix := by
    simpa [higherPrefix] using activationNewConfigurationKnown historyFacts higherStored
  have higherPrefixNotLower :
      Not (higherPrefix <+: lowerPrefix) := by
    intro reverse
    have higherKnownLowerPrefix :
        higher.newConfiguration ∈ allConfigurations lowerPrefix :=
      memOfPrefix
        (allConfigurations_mono_prefix reverse)
        higherConfigurationKnown
    have higherKnownLowerHistory :
        higher.newConfiguration ∈ allConfigurations lower.history :=
      memOfPrefix
        (allConfigurations_mono_prefix
          (List.take_prefix lower.activationFrontier lower.history))
        (by simpa [lowerPrefix] using higherKnownLowerPrefix)
    have higherIndexBound :
        higher.newConfiguration.index <= lower.activationFrontier := by
      rw [allConfigurations] at higherKnownLowerPrefix
      rcases List.mem_cons.mp higherKnownLowerPrefix with
        implicit | physical
      · rw [implicit] at indexOrder
        simp [implicitConfiguration] at indexOrder
      · have bounded :=
          (configurationsInLog_index_bounds
            (TxId := TxId) lowerPrefix physical).2
        simpa [
          lowerPrefix, List.length_take,
          Nat.min_eq_left lowerValid.2.1
        ] using bounded
    let lowerNode : NodeState Node TxId :=
      { state.nodes INITIAL_LEADER with
        log := lower.history
        commitIndex := lower.activationFrontier }
    have maximal :=
      configuration_index_le_currentConfiguration
        lowerNode higher.newConfiguration
        (by simpa [lowerNode] using higherKnownLowerHistory)
        (by simpa [lowerNode] using higherIndexBound)
    have lowerCurrent :
        currentConfiguration lowerNode = lower.newConfiguration := by
      simpa [lowerNode, currentConfiguration] using lowerValid.2.2.2.1.symm
    rw [lowerCurrent] at maximal
    omega
  rcases Nat.lt_trichotomy
      lower.activationTerm higher.activationTerm with
    lowerBefore | sameTerm | higherBefore
  · rcases
        electionFacts.ownerRecorded
          higher.activationTerm higher.leader
          (activationCanonical.termOwner
            higherIndex higher higherStored) with
      bootstrap | recorded
    · rw [bootstrap.1] at lowerBefore
      have lowerPositive :=
        historyFacts.termPositive lowerIndex lower lowerStored
      omega
    · rcases recorded with
        ⟨record, recordStored, recordLeader⟩
      have lowerInPromotion :=
        activationPrefixInLaterElection
          activationElections lowerStored recordStored lowerBefore
      simpa [lowerPrefix, higherPrefix]
        using electionPromotionPrefixInActivationCore
          electionFacts historyFacts activationCanonical
          higherStored
          (by simpa [recordLeader] using recordStored)
          lowerInPromotion
  · have lowerCanonical :=
      activationCanonical.activationFrontierCanonical
        lowerIndex lower lowerStored
    have higherCanonical :=
      activationCanonical.activationFrontierCanonical
        higherIndex higher higherStored
    by_cases frontierOrder :
        higher.activationFrontier <= lower.activationFrontier
    · have higherInLower : higherPrefix <+: lowerPrefix := by
        dsimp [lowerPrefix, higherPrefix]
        rw [lowerCanonical, higherCanonical, sameTerm]
        rw [List.prefix_take_iff]
        exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans frontierOrder⟩
      exact False.elim (higherPrefixNotLower higherInLower)
    · rw [lowerCanonical, higherCanonical, sameTerm]
      rw [List.prefix_take_iff]
      exact ⟨
        List.take_prefix _ _,
        (List.length_take_le _ _).trans (Nat.le_of_not_ge frontierOrder)
      ⟩
  · rcases
        electionFacts.ownerRecorded
          lower.activationTerm lower.leader
          (activationCanonical.termOwner
            lowerIndex lower lowerStored) with
      bootstrap | recorded
    · rw [bootstrap.1] at higherBefore
      have higherPositive :=
        historyFacts.termPositive higherIndex higher higherStored
      omega
    · rcases recorded with
        ⟨record, recordStored, recordLeader⟩
      have higherInPromotion :=
        activationPrefixInLaterElection
          activationElections higherStored recordStored higherBefore
      have higherInLower :=
        electionPromotionPrefixInActivationCore
          electionFacts historyFacts activationCanonical
          lowerStored
          (by simpa [recordLeader] using recordStored)
          higherInPromotion
      exact False.elim
        (higherPrefixNotLower
          (by
            simpa [higherPrefix, lowerPrefix] using higherInLower))

/--
Follow prior activation authorities until the lower activation is reached.
When an activation skips over the lower authority, compare the two immutable
activation prefixes directly.
-/
lemma activationPrefixInHigherActivationByAuthorityChain
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    {lowerIndex : ActivationKey Node}
    {lower : ActivationRecord Node TxId}
    (lowerStored : activations lowerIndex = some lower)
    : forall configurationIndex higherIndex higher,
        higher.newConfiguration.index = configurationIndex
        -> activations higherIndex = some higher
        -> lower.newConfiguration.index < higher.newConfiguration.index
        -> lower.history.take lower.activationFrontier
            <+: higher.history.take higher.activationFrontier := by
  intro configurationIndex
  induction configurationIndex using Nat.strong_induction_on with
  | h configurationIndex inductionHypothesis =>
      intro higherIndex higher indexEq higherStored indexOrder
      have higherOldBeforeNew :=
        activationOldConfigurationIndexLtNew historyFacts higherStored
      by_cases lowerAtOrBeforeOld :
          lower.newConfiguration.index <=
            higher.oldConfiguration.index
      · have lowerPositive :
            0 < lower.newConfiguration.index := by
          have lowerOldBeforeNew :=
            activationOldConfigurationIndexLtNew historyFacts lowerStored
          omega
        have oldPositive :
            0 < higher.oldConfiguration.index := by
          omega
        obtain ⟨priorIndex, prior, priorFacts⟩ :=
          historyFacts.priorActivation
            higherIndex higher higherStored oldPositive
        have priorStored := priorFacts.1
        have priorBeforeHigher := priorFacts.2.1
        have oldGoverning := priorFacts.2.2.1
        have priorPrefix := priorFacts.2.2.2
        have priorInHigher :
            prior.history.take prior.activationFrontier <+:
              higher.history.take higher.activationFrontier :=
          priorPrefix
        have oldAtOrBeforePrior :
            higher.oldConfiguration.index <=
              prior.newConfiguration.index :=
          activationGoverningConfigurationIndexLeNew
            historyFacts priorStored oldGoverning
        rcases
            lt_or_eq_of_le
              (lowerAtOrBeforeOld.trans oldAtOrBeforePrior) with
          lowerBeforePrior | lowerEqPriorIndex
        · have priorBeforeConfigurationIndex :
              prior.newConfiguration.index < configurationIndex := by
            simpa [indexEq] using priorBeforeHigher
          exact (inductionHypothesis
                  prior.newConfiguration.index
                  priorBeforeConfigurationIndex
                  priorIndex
                  prior
                  rfl
                  priorStored lowerBeforePrior).trans
            priorInHigher
        · exact
            activationPrefixInHigherActivationCore
              ownership electionFacts historyFacts activationCanonical
              activationElections lowerStored higherStored indexOrder
      · exact
          activationPrefixInHigherActivationCore
            ownership electionFacts historyFacts activationCanonical
            activationElections lowerStored higherStored indexOrder

/-- Every lower-index activation prefix occurs in a higher activation. -/
lemma activationPrefixInHigherActivation
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    {lowerIndex higherIndex : ActivationKey Node}
    {lower higher : ActivationRecord Node TxId}
    (lowerStored : activations lowerIndex = some lower)
    (higherStored : activations higherIndex = some higher)
    (indexOrder : lower.newConfiguration.index < higher.newConfiguration.index)
    : lower.history.take lower.activationFrontier
      <+: higher.history.take higher.activationFrontier :=
  activationPrefixInHigherActivationByAuthorityChain
    ownership electionFacts historyFacts activationCanonical
    activationElections lowerStored
    higher.newConfiguration.index higherIndex higher rfl
    higherStored indexOrder

/--
Follow frozen prior authorities until the source authority governs an
activation, then transfer the source's acknowledged signed prefix through the
remaining activation chain.
-/
lemma acknowledgedPrefixInActivationByAuthorityChain
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationHistory
      : AckerActivationHistory state responseHistory elections activations)
    {source : Node}
    {index : Nat}
    {configuration : Configuration Node}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (sourceMajority
      : hasConfigurationMajority
          (effectiveAckers state responseHistory source index)
          configuration)
    (sourceActive : configuration ∈ activeConfigurations (state.nodes source))
    (configurationGoverns : configuration.index <= index)
    : forall configurationIndex activationIndex activation,
        activation.newConfiguration.index = configurationIndex
        -> activations activationIndex = some activation
        -> configuration.index < activation.newConfiguration.index
        -> (state.nodes source).currentTerm < activation.activationTerm
        -> (forall earlierTerm earlierRecord,
              (state.nodes source).currentTerm < earlierTerm
              -> earlierTerm <= activation.activationTerm
              -> elections earlierTerm = some earlierRecord
              -> (state.nodes source).log.take index <+: earlierRecord.promotionLog)
        -> (state.nodes source).log.take index
            <+: activation.history.take activation.activationFrontier := by
  intro configurationIndex
  induction configurationIndex using Nat.strong_induction_on with
  | h configurationIndex inductionHypothesis =>
      intro activationIndex activation indexEq stored authorityBefore later
          earlierSafe
      have directThroughElection :
          (state.nodes source).log.take index <+:
            activation.history.take activation.activationFrontier := by
        rcases
            electionFacts.ownerRecorded
              activation.activationTerm activation.leader
              (activationCanonical.termOwner
                activationIndex activation stored) with
          bootstrap | elected
        · have sourcePositive :=
            termsPositive source (by rw [sourceRole]; decide)
          rw [bootstrap.1] at later
          omega
        · rcases elected with ⟨record, recorded, _recordLeader⟩
          exact
            electionPromotionPrefixInActivation
              electionFacts historyFacts activationCanonical
              stored recorded
              (earlierSafe
                activation.activationTerm record later le_rfl recorded)
      by_cases governing :
          configuration ∈ activation.governingActive
      · exact
          acknowledgedPrefixInActivation
            ownership historyFacts activationCanonical activationHistory
            sourceRole currentEntry currentSignature sourceMajority
            sourceActive configurationGoverns stored governing later
            earlierSafe
      · have oldBeforeNew :=
          activationOldConfigurationIndexLtNew historyFacts stored
        by_cases sourceBeforeOld :
            configuration.index < activation.oldConfiguration.index
        · have oldPositive : 0 < activation.oldConfiguration.index := by
            omega
          obtain ⟨priorIndex, prior, priorFacts⟩ :=
            historyFacts.priorActivation
              activationIndex activation stored oldPositive
          have priorStored := priorFacts.1
          have priorBeforeActivation := priorFacts.2.1
          have oldGoverning := priorFacts.2.2.1
          have priorPrefix := priorFacts.2.2.2
          have priorInActivation :
              prior.history.take prior.activationFrontier <+:
                activation.history.take activation.activationFrontier :=
            priorPrefix
          by_cases priorLater :
              (state.nodes source).currentTerm < prior.activationTerm
          · have priorTermBound :
                prior.activationTerm <= activation.activationTerm :=
              activationTermLeOfPrefix
                ownership historyFacts activationCanonical
                priorStored stored priorInActivation
            have sourceInPrior :
                (state.nodes source).log.take index <+:
                  prior.history.take prior.activationFrontier := by
              have oldAtOrBeforePrior :
                  activation.oldConfiguration.index <=
                    prior.newConfiguration.index :=
                activationGoverningConfigurationIndexLeNew
                  historyFacts priorStored oldGoverning
              apply
                inductionHypothesis prior.newConfiguration.index
                  (by simpa [indexEq] using priorBeforeActivation)
                  priorIndex
                  prior
                  rfl
                  priorStored
                  (sourceBeforeOld.trans_le oldAtOrBeforePrior)
                  priorLater
              intro earlierTerm earlierRecord above bounded recorded
              exact
                earlierSafe earlierTerm earlierRecord above
                  (bounded.trans priorTermBound) recorded
            exact sourceInPrior.trans priorInActivation
          · exact directThroughElection
        · exact directThroughElection

/--
Follow frozen prior authorities until one governing configuration is active
for the candidate, then use the supplied transfer callback.
-/
lemma activationPrefixInTargetByAuthorityChainCore
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (_ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (_electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (_activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (_activationElections : ActivationElectionFacts votes elections activations)
    {candidate : Node}
    {targetHistory : List (Entry Node TxId)}
    {Eligible : ActivationRecord Node TxId -> Prop}
    (targetPrefix : targetHistory <+: (state.nodes candidate).log)
    (priorEligible
      : forall activationIndex activation priorIndex prior,
          activations activationIndex = some activation
          -> activations priorIndex = some prior
          -> activation.oldConfiguration ∈ prior.governingActive
          -> prior.history.take prior.activationFrontier
              <+: activation.history.take activation.activationFrontier
          -> Eligible activation
          -> Eligible prior)
    (sharedConfiguration
      : forall activationIndex activation,
          activations activationIndex = some activation
          -> Eligible activation
          -> forall configuration,
              configuration ∈ activation.governingActive
              -> configuration ∈ activeConfigurations (state.nodes candidate)
              -> activation.history.take activation.activationFrontier <+: targetHistory)
    (candidateKnownInActivation
      : forall activationIndex activation,
          activations activationIndex = some activation
          -> (currentConfiguration (state.nodes candidate)).index
              < activation.newConfiguration.index
          -> currentConfiguration (state.nodes candidate)
              ∈ allConfigurations activation.history)
    : forall configurationIndex activationIndex activation,
        activation.newConfiguration.index = configurationIndex
        -> activations activationIndex = some activation
        -> Eligible activation
        -> (currentConfiguration (state.nodes candidate)).index
            < activation.newConfiguration.index
        -> activation.history.take activation.activationFrontier <+: targetHistory := by
  intro configurationIndex
  induction configurationIndex using Nat.strong_induction_on with
  | h configurationIndex inductionHypothesis =>
      intro activationIndex activation indexEq stored eligible candidateBefore
      have valid := historyFacts.valid activationIndex activation stored
      have newGoverning :
          activation.newConfiguration ∈ activation.governingActive :=
        valid.2.2.2.2.2.2.2.1
      have newWithin :
          activation.newConfiguration.index <=
            activation.activationFrontier := by
        rw [valid.2.2.2.2.2.2.1] at newGoverning
        exact (of_decide_eq_true (List.mem_filter.mp newGoverning).2).2
      have oldKnownActivation :
          activation.oldConfiguration ∈
            allConfigurations activation.history := by
        let priorNode : NodeState Node TxId :=
          { state.nodes candidate with
            log := activation.history
            commitIndex := activation.priorCommitIndex }
        have known :=
          currentConfiguration_mem_allConfigurations priorNode
        simpa [
          priorNode, currentConfiguration,
          valid.2.2.1
        ] using known
      have newKnownActivation :
          activation.newConfiguration ∈
            allConfigurations activation.history := by
        rw [valid.2.2.2.2.2.2.1] at newGoverning
        exact (List.mem_filter.mp newGoverning).1
      have oldBeforeNew :
          activation.oldConfiguration.index <
            activation.newConfiguration.index := by
        have oldLeNew :
            activation.oldConfiguration.index <=
              activation.newConfiguration.index := by
          rw [valid.2.2.2.2.2.2.1] at newGoverning
          exact (of_decide_eq_true (List.mem_filter.mp newGoverning).2).1
        have differentIndex :
            activation.oldConfiguration.index ≠
              activation.newConfiguration.index := by
          intro same
          apply valid.2.2.2.2.1
          exact
            allConfigurations_index_unique
              (TxId := TxId) activation.history
              oldKnownActivation newKnownActivation same
        exact lt_of_le_of_ne oldLeNew differentIndex
      by_cases oldBeforeCandidate :
          activation.oldConfiguration.index <=
            (currentConfiguration (state.nodes candidate)).index
      · let candidateConfiguration :=
          currentConfiguration (state.nodes candidate)
        have candidateKnown :
            candidateConfiguration ∈
              allConfigurations activation.history := by
          exact
            candidateKnownInActivation
              activationIndex activation stored candidateBefore
        have candidateGoverning :
            candidateConfiguration ∈ activation.governingActive := by
          rw [valid.2.2.2.2.2.2.1]
          simp only [List.mem_filter]
          refine ⟨candidateKnown, decide_eq_true ?_⟩
          exact ⟨
            by simpa [candidateConfiguration] using oldBeforeCandidate,
            by simpa [candidateConfiguration] using candidateBefore.le.trans newWithin
          ⟩
        have candidateActive :
            candidateConfiguration ∈
              activeConfigurations (state.nodes candidate) := by
          simpa [candidateConfiguration]
            using currentConfiguration_mem_activeConfigurations (state.nodes candidate)
        exact
          sharedConfiguration
            activationIndex activation stored eligible
            candidateConfiguration candidateGoverning candidateActive
      · have candidateBeforeOld :
            (currentConfiguration (state.nodes candidate)).index <
              activation.oldConfiguration.index := by
          omega
        have oldPositive : 0 < activation.oldConfiguration.index := by
          omega
        obtain ⟨priorIndex, prior, priorFacts⟩ :=
          historyFacts.priorActivation
            activationIndex activation stored oldPositive
        have priorStored := priorFacts.1
        have priorBeforeActivation := priorFacts.2.1
        have oldCovered := priorFacts.2.2.1
        have priorPrefix := priorFacts.2.2.2
        have priorCovered :
            prior.history.take prior.activationFrontier <+:
              targetHistory := by
          have oldAtOrBeforePrior :
              activation.oldConfiguration.index <=
                prior.newConfiguration.index :=
            activationGoverningConfigurationIndexLeNew
              historyFacts priorStored oldCovered
          apply
            inductionHypothesis prior.newConfiguration.index
              (by simpa [indexEq] using priorBeforeActivation)
              priorIndex
              prior
              rfl
              priorStored
              (priorEligible
                activationIndex activation priorIndex prior stored
                  priorStored oldCovered priorPrefix eligible)
          exact candidateBeforeOld.trans_le oldAtOrBeforePrior
        have oldKnownCandidate :
            activation.oldConfiguration ∈
              allConfigurations (state.nodes candidate).log := by
          have priorValid :=
            historyFacts.valid priorIndex prior priorStored
          have oldCoveredParts :
              activation.oldConfiguration ∈
                  allConfigurations prior.history /\
                activation.oldConfiguration.index <=
                  prior.activationFrontier := by
            rw [priorValid.2.2.2.2.2.2.1] at oldCovered
            exact ⟨
              (List.mem_filter.mp oldCovered).1,
              (of_decide_eq_true (List.mem_filter.mp oldCovered).2).2
            ⟩
          exact
            memOfPrefix
              (allConfigurations_mono_prefix
                (priorCovered.trans targetPrefix))
              (allConfigurations_mem_take_of_index_le
                prior.history prior.activationFrontier
                priorValid.2.1 oldCoveredParts.1 oldCoveredParts.2)
        have oldActiveCandidate :
            activation.oldConfiguration ∈
              activeConfigurations (state.nodes candidate) := by
          simpa [activeConfigurations]
            using And.intro oldKnownCandidate candidateBeforeOld.le
        have oldCommitted :
            activation.oldConfiguration.index <=
              activation.priorCommitIndex := by
          let priorNode : NodeState Node TxId :=
            { state.nodes candidate with
              log := activation.history
              commitIndex := activation.priorCommitIndex }
          have bound :=
            currentConfiguration_index_le_commitIndex priorNode
          simpa [
            priorNode, currentConfiguration,
            valid.2.2.1
          ] using bound
        have oldGoverning :
            activation.oldConfiguration ∈
              activation.governingActive := by
          rw [valid.2.2.2.2.2.2.1]
          simp only [List.mem_filter]
          refine ⟨oldKnownActivation, decide_eq_true ?_⟩
          exact ⟨le_rfl, oldCommitted.trans (Nat.le_of_lt valid.1)⟩
        exact
          sharedConfiguration
            activationIndex activation stored eligible
            activation.oldConfiguration oldGoverning oldActiveCandidate

/-- Coverage facts instantiate the same authority-chain core. -/
lemma activationPrefixInTargetByCoverageAuthorityChain
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    (coverage : ConfigurationCoverageFacts state activations)
    {candidate : Node}
    {targetHistory : List (Entry Node TxId)}
    {Eligible : ActivationRecord Node TxId -> Prop}
    (targetPrefix : targetHistory <+: (state.nodes candidate).log)
    (priorEligible
      : forall activationIndex activation priorIndex prior,
          activations activationIndex = some activation
          -> activations priorIndex = some prior
          -> activation.oldConfiguration ∈ prior.governingActive
          -> prior.history.take prior.activationFrontier
              <+: activation.history.take activation.activationFrontier
          -> Eligible activation
          -> Eligible prior)
    (sharedConfiguration
      : forall activationIndex activation,
          activations activationIndex = some activation
          -> Eligible activation
          -> forall configuration,
              configuration ∈ activation.governingActive
              -> configuration ∈ activeConfigurations (state.nodes candidate)
              -> activation.history.take activation.activationFrontier <+: targetHistory)
    : forall configurationIndex activationIndex activation,
        activation.newConfiguration.index = configurationIndex
        -> activations activationIndex = some activation
        -> Eligible activation
        -> (currentConfiguration (state.nodes candidate)).index
            < activation.newConfiguration.index
        -> activation.history.take activation.activationFrontier <+: targetHistory := by
  apply
    activationPrefixInTargetByAuthorityChainCore
      ownership electionFacts historyFacts activationCanonical
      activationElections targetPrefix priorEligible sharedConfiguration
  intro activationIndex activation stored candidateBefore
  let candidateConfiguration := currentConfiguration (state.nodes candidate)
  by_cases candidateZero : candidateConfiguration.index = 0
  · have candidateImplicit :
        candidateConfiguration = implicitConfiguration := by
      apply
        allConfigurations_index_unique
          (TxId := TxId) (state.nodes candidate).log
      · exact currentConfiguration_mem_allConfigurations _
      · simp [allConfigurations, implicitConfiguration]
      · simpa [implicitConfiguration] using candidateZero
    simp [candidateConfiguration, candidateImplicit, allConfigurations]
  · rcases coverage candidate
        (by simpa [candidateConfiguration] using
          Nat.pos_of_ne_zero candidateZero) with
      ⟨witness⟩
    have sharedInActivation :=
      witness.sharedPrefix_prefix_higherAuthority stored
        (by simpa [candidateConfiguration] using candidateBefore)
    exact
      memOfPrefix
        (allConfigurations_mono_prefix
          (sharedInActivation.trans
            (List.take_prefix
              activation.activationFrontier activation.history)))
        (by simpa [candidateConfiguration] using
          witness.configuration_mem_activationHistoryTake historyFacts)

/-- Coverage-native authority traversal for a future election quorum. -/
lemma activationPrefixInFutureCandidateByCoverageAuthorityChain
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (committedSignature : CommittedFrontierIsSignature state)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (currentHistory : ActivationSupporterCurrentHistory state elections activations)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    (coverage : ConfigurationCoverageFacts state activations)
    {candidate : Node}
    {targetTerm : Nat}
    {ballotActive : List (Configuration Node)}
    (futureMajority : hasFutureElectionMajority state candidate targetTerm ballotActive)
    (ballotActiveEq : ballotActive = activeConfigurations (state.nodes candidate))
    : forall configurationIndex activationIndex activation,
        activation.newConfiguration.index = configurationIndex
        -> activations activationIndex = some activation
        -> (currentConfiguration (state.nodes candidate)).index
            < activation.newConfiguration.index
        -> activation.history.take activation.activationFrontier
            <+: (state.nodes candidate).log := by
  intro configurationIndex activationIndex activation indexEq stored
      candidateBefore
  apply activationPrefixInTargetByCoverageAuthorityChain
    ownership electionFacts historyFacts activationCanonical
    activationElections coverage
    (targetHistory := (state.nodes candidate).log)
    (Eligible := fun _ => True)
    (prefixRefl (state.nodes candidate).log)
    (by
      intro _ _ _ _ _ _ _ _ _
      trivial)
    (by
      intro innerIndex innerActivation innerStored _
          configuration governing candidateActive
      apply
        activationPrefixInFutureCandidateOfGoverningConfiguration
          ownership committedSignature electionFacts historyFacts
          currentHistory activationElections innerStored
          futureMajority governing
      simpa [ballotActiveEq] using candidateActive)
    configurationIndex activationIndex activation indexEq stored trivial candidateBefore

/-- Coverage-native activation transfer into a potential candidate. -/
lemma activationPrefixInPotentialCandidateByCoverageAuthorityChain
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (committedSignature : CommittedFrontierIsSignature state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (canonicalSnapshots
      : GrantedVoteCanonicalSnapshots
          state canonicalHistory voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (currentHistory : ActivationSupporterCurrentHistory state elections activations)
    (voteHistory : ActivationVoteHistory votes voteVoterHistory elections activations)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    (coverage : ConfigurationCoverageFacts state activations)
    {candidate : Node}
    (candidateRole : (state.nodes candidate).role = .candidate)
    (candidateMajority : hasPotentialElectionMajority state candidate)
    : forall configurationIndex activationIndex activation,
        activation.newConfiguration.index = configurationIndex
        -> activations activationIndex = some activation
        -> activation.activationTerm < (state.nodes candidate).currentTerm
        -> activation.history.take activation.activationFrontier
            <+: (state.nodes candidate).log.take
                  (maxCommittableIndex (state.nodes candidate).log) := by
  intro configurationIndex activationIndex activation indexEq stored
      activationBeforeCandidate
  let candidateConfiguration :=
    currentConfiguration (state.nodes candidate)
  have sharedInMax
      (witness : ConfigurationCoverageWitness state activations candidate) :
      witness.sharedPrefix <+:
        (state.nodes candidate).log.take
          (maxCommittableIndex (state.nodes candidate).log) := by
    rw [witness.sharedPrefix_eq_nodeLogTake]
    rw [List.prefix_take_iff]
    exact ⟨
      List.take_prefix _ _,
      (List.length_take_le _ _).trans
        (witness.sharedFrontier_le_commitIndex.trans
          (commitIndex_le_maxCommittableIndex
            (state.nodes candidate) (committedSignature candidate)))
    ⟩
  rcases Nat.lt_trichotomy
      activation.newConfiguration.index candidateConfiguration.index with
    activationBefore | sameIndex | candidateBefore
  · have candidatePositive : 0 < candidateConfiguration.index := by
      have activationPositive :=
        activationOldConfigurationIndexLtNew historyFacts stored
      omega
    rcases coverage candidate
        (by simpa [candidateConfiguration] using candidatePositive) with
      ⟨witness⟩
    exact (witness.lowerAuthority_prefix_sharedPrefix
            stored (by simpa [candidateConfiguration] using activationBefore)).trans
      (sharedInMax witness)
  · have activationPositive :
        0 < activation.newConfiguration.index := by
      have advances :=
        activationOldConfigurationIndexLtNew historyFacts stored
      omega
    have candidatePositive : 0 < candidateConfiguration.index := by
      simpa [sameIndex] using activationPositive
    rcases coverage candidate
        (by simpa [candidateConfiguration] using candidatePositive) with
      ⟨witness⟩
    have configurationEq :
        activation.newConfiguration = candidateConfiguration := by
      simpa [candidateConfiguration]
        using witness.sameAuthority_configurationEq
          stored (by simpa [candidateConfiguration] using sameIndex)
    apply
      activationPrefixInPotentialCandidatePromotionOfGoverningConfiguration
        committedSignature entriesBounded snapshots canonicalSnapshots
        ownership electionFacts historyFacts currentHistory voteHistory
        activationElections stored candidateRole candidateMajority
        activationBeforeCandidate
    · exact (historyFacts.valid activationIndex activation stored).2.2.2.2.2.2.2.1
    · simpa [candidateConfiguration, configurationEq]
        using currentConfiguration_mem_activeConfigurations (state.nodes candidate)
  · apply
      activationPrefixInTargetByCoverageAuthorityChain
        ownership electionFacts historyFacts activationCanonical
        activationElections coverage
        (targetHistory :=
          (state.nodes candidate).log.take
            (maxCommittableIndex (state.nodes candidate).log))
        (Eligible := fun record =>
          record.activationTerm < (state.nodes candidate).currentTerm)
        (List.take_prefix
          (maxCommittableIndex (state.nodes candidate).log)
          (state.nodes candidate).log)
        (by
          intro innerIndex innerActivation _priorIndex prior
              innerStored priorStored _oldCovered priorPrefix innerBefore
          have priorActivationPrefix :
              prior.history.take prior.activationFrontier <+:
                innerActivation.history.take
                  innerActivation.activationFrontier :=
            priorPrefix
          exact
            (activationTermLeOfPrefix
              ownership historyFacts activationCanonical
              priorStored innerStored priorActivationPrefix).trans_lt
                innerBefore)
        (by
          intro innerIndex innerActivation innerStored innerBefore
              configuration governing candidateActive
          exact
            activationPrefixInPotentialCandidatePromotionOfGoverningConfiguration
              committedSignature entriesBounded snapshots
              canonicalSnapshots ownership electionFacts historyFacts
              currentHistory voteHistory activationElections innerStored
              candidateRole candidateMajority innerBefore
              governing candidateActive)
        configurationIndex activationIndex activation indexEq stored
        activationBeforeCandidate
        (by simpa [candidateConfiguration] using candidateBefore)

/-- Coverage-native same-term potential candidates share one configuration. -/
lemma potentialCandidatesSharedConfigurationCoverage
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (committedSignature : CommittedFrontierIsSignature state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (canonicalSnapshots
      : GrantedVoteCanonicalSnapshots
          state canonicalHistory voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (currentHistory : ActivationSupporterCurrentHistory state elections activations)
    (voteHistory : ActivationVoteHistory votes voteVoterHistory elections activations)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    (coverage : ConfigurationCoverageFacts state activations)
    {left right : Node}
    (leftRole : (state.nodes left).role = .candidate)
    (rightRole : (state.nodes right).role = .candidate)
    (sameTerm : (state.nodes left).currentTerm = (state.nodes right).currentTerm)
    (leftPotential : hasPotentialElectionMajority state left)
    (rightPotential : hasPotentialElectionMajority state right)
    : Exists
        fun configuration =>
          configuration ∈ activeConfigurations (state.nodes left)
          /\ configuration ∈ activeConfigurations (state.nodes right) := by
  let leftConfiguration := currentConfiguration (state.nodes left)
  let rightConfiguration := currentConfiguration (state.nodes right)
  have leftActive :
      leftConfiguration ∈ activeConfigurations (state.nodes left) := by
    simpa [leftConfiguration]
      using currentConfiguration_mem_activeConfigurations (state.nodes left)
  have rightActive :
      rightConfiguration ∈ activeConfigurations (state.nodes right) := by
    simpa [rightConfiguration]
      using currentConfiguration_mem_activeConfigurations (state.nodes right)
  rcases Nat.lt_trichotomy
      leftConfiguration.index rightConfiguration.index with
    leftBefore | sameIndex | rightBefore
  · have rightPositive : 0 < rightConfiguration.index := by omega
    rcases coverage right
        (by simpa [rightConfiguration] using rightPositive) with
      ⟨rightWitness⟩
    have eventInLeft :=
      activationPrefixInPotentialCandidateByCoverageAuthorityChain
        committedSignature entriesBounded snapshots canonicalSnapshots
        ownership electionFacts historyFacts currentHistory voteHistory
        activationCanonical activationElections coverage
        leftRole leftPotential
        rightWitness.activation.newConfiguration.index
        rightWitness.activationIndex rightWitness.activation rfl
        rightWitness.stored
        (by simpa [sameTerm] using rightWitness.activationTerm_lt_candidateTerm rightRole)
    have rightKnownEvent :
        rightConfiguration ∈
          allConfigurations
            (rightWitness.activation.history.take
              rightWitness.activation.activationFrontier) := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            (rightWitness.sharedPrefix_prefix_activationPrefix))
      simpa [rightConfiguration]
        using rightWitness.configuration_mem_activationHistoryTake historyFacts
    have rightKnownLeft :
        rightConfiguration ∈ allConfigurations (state.nodes left).log := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            (eventInLeft.trans
              (List.take_prefix
                (maxCommittableIndex (state.nodes left).log)
                (state.nodes left).log)))
      exact rightKnownEvent
    exact ⟨
      rightConfiguration,
      by
        simpa [activeConfigurations, leftConfiguration]
          using And.intro rightKnownLeft leftBefore.le,
      rightActive
    ⟩
  · by_cases zero : leftConfiguration.index = 0
    · have rightZero : rightConfiguration.index = 0 := by simpa [sameIndex] using zero
      have leftImplicit : leftConfiguration = implicitConfiguration := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) (state.nodes left).log
        · simpa [leftConfiguration]
            using currentConfiguration_mem_allConfigurations (state.nodes left)
        · simp [allConfigurations, implicitConfiguration]
        · simpa [implicitConfiguration] using zero
      have rightImplicit : rightConfiguration = implicitConfiguration := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) (state.nodes right).log
        · simpa [rightConfiguration]
            using currentConfiguration_mem_allConfigurations (state.nodes right)
        · simp [allConfigurations, implicitConfiguration]
        · simpa [implicitConfiguration] using rightZero
      exact ⟨
        leftConfiguration,
        leftActive,
        by simpa [leftImplicit, rightImplicit] using rightActive
      ⟩
    · have leftPositive : 0 < leftConfiguration.index :=
        Nat.pos_of_ne_zero zero
      have rightPositive : 0 < rightConfiguration.index := by
        simpa [sameIndex] using leftPositive
      have sameConfiguration :=
        configurationCoverageCurrentIndexUnique
          historyFacts coverage
          (by simpa [leftConfiguration] using leftPositive)
          (by simpa [rightConfiguration] using rightPositive)
          (by simpa [leftConfiguration, rightConfiguration] using sameIndex)
      exact ⟨
        leftConfiguration,
        leftActive,
        by simpa [
            leftConfiguration, rightConfiguration, sameConfiguration
          ] using rightActive
      ⟩
  · have leftPositive : 0 < leftConfiguration.index := by omega
    rcases coverage left
        (by simpa [leftConfiguration] using leftPositive) with
      ⟨leftWitness⟩
    have eventInRight :=
      activationPrefixInPotentialCandidateByCoverageAuthorityChain
        committedSignature entriesBounded snapshots canonicalSnapshots
        ownership electionFacts historyFacts currentHistory voteHistory
        activationCanonical activationElections coverage
        rightRole rightPotential
        leftWitness.activation.newConfiguration.index
        leftWitness.activationIndex leftWitness.activation rfl
        leftWitness.stored
        (by simpa [sameTerm] using leftWitness.activationTerm_lt_candidateTerm leftRole)
    have leftKnownEvent :
        leftConfiguration ∈
          allConfigurations
            (leftWitness.activation.history.take
              leftWitness.activation.activationFrontier) := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            (leftWitness.sharedPrefix_prefix_activationPrefix))
      simpa [leftConfiguration]
        using leftWitness.configuration_mem_activationHistoryTake historyFacts
    have leftKnownRight :
        leftConfiguration ∈ allConfigurations (state.nodes right).log := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            (eventInRight.trans
              (List.take_prefix
                (maxCommittableIndex (state.nodes right).log)
                (state.nodes right).log)))
      exact leftKnownEvent
    exact ⟨
      leftConfiguration,
      leftActive,
      by
        simpa [activeConfigurations, rightConfiguration]
          using And.intro leftKnownRight rightBefore.le
    ⟩

/-- Coverage-native frozen ballot and potential candidate sharing. -/
lemma potentialCandidateElectionRecordSharedConfigurationCoverage
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (committedSignature : CommittedFrontierIsSignature state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (canonicalSnapshots
      : GrantedVoteCanonicalSnapshots
          state canonicalHistory voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
    (historyFacts : ActivationHistoryFacts activations)
    (currentHistory : ActivationSupporterCurrentHistory state elections activations)
    (voteHistory : ActivationVoteHistory votes voteVoterHistory elections activations)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    (coverage : ConfigurationCoverageFacts state activations)
    {term : Nat}
    {record : ElectionRecord Node TxId}
    (recorded : elections term = some record)
    {candidate : Node}
    (candidateRole : (state.nodes candidate).role = .candidate)
    (sameTerm : (state.nodes candidate).currentTerm = term)
    (candidateMajority : hasPotentialElectionMajority state candidate)
    : Exists
        fun configuration =>
          configuration ∈ record.ballotActive
          /\ configuration ∈ activeConfigurations (state.nodes candidate) := by
  let candidateConfiguration := currentConfiguration (state.nodes candidate)
  let ballotConfiguration :=
    currentConfigurationAt record.ballotLog record.ballotCommitIndex
  have candidateActive :
      candidateConfiguration ∈
        activeConfigurations (state.nodes candidate) := by
    simpa [candidateConfiguration]
      using currentConfiguration_mem_activeConfigurations (state.nodes candidate)
  have ballotActive : ballotConfiguration ∈ record.ballotActive := by
    simpa [ballotConfiguration]
      using configurationFacts.ballotCurrentAuthorityActive term record recorded
  have ballotCommitPrefixPromotion :
      record.ballotLog.take record.ballotCommitIndex <+:
        record.promotionLog := by
    rw [
      electionFacts.promotionFromBallot term record recorded,
      List.prefix_take_iff
    ]
    exact ⟨
      List.take_prefix record.ballotCommitIndex record.ballotLog,
      by
        simp only [List.length_take]
        have commitBound :=
          (configurationFacts.ballotCommittedFrontierSignature
            term record recorded).1
        omega
    ⟩
  have activationBeforeBallot
      {activationIndex : ActivationKey Node}
      {activation : ActivationRecord Node TxId}
      (stored : activations activationIndex = some activation)
      (retained :
        activation.history.take activation.activationFrontier <+:
          record.ballotLog.take record.ballotCommitIndex) :
      activation.activationTerm < term := by
    have valid := historyFacts.valid activationIndex activation stored
    rcases isSignatureAtTrue valid.2.2.2.2.2.1 with
      ⟨entry, found, _⟩
    have entryTerm : entry.term = activation.activationTerm := by
      simpa [termAt, found]
        using (historyFacts.supporterAcks activationIndex activation stored).1
    have foundInTake :
        entryAt?
            (activation.history.take activation.activationFrontier)
            activation.activationFrontier =
          some entry := by
      rw [entryAtTake_of_le le_rfl]
      exact found
    have foundInPromotion :
        entryAt? record.promotionLog activation.activationFrontier =
          some entry :=
      entryAt_of_prefix
        (retained.trans ballotCommitPrefixPromotion) foundInTake
    have before :=
      electionFacts.promotionEntriesBeforeTerm
        term record recorded entry (entryAtSomeMember foundInPromotion)
    simpa [entryTerm] using before
  rcases Nat.lt_trichotomy
      candidateConfiguration.index ballotConfiguration.index with
    candidateBefore | sameIndex | ballotBefore
  · have ballotPositive : 0 < ballotConfiguration.index := by omega
    rcases
        configurationFacts.ballotCurrentAuthorityActivation
          term record recorded
          (by simpa [ballotConfiguration] using ballotPositive) with
      ⟨activationIndex, activation, stored, ballotGoverning,
        activationBeforeTerm, _ballotBound, _historyAgreement⟩
    have activationInCandidate :=
      activationPrefixInPotentialCandidateByCoverageAuthorityChain
        committedSignature entriesBounded snapshots canonicalSnapshots
        ownership electionFacts historyFacts currentHistory voteHistory
        activationCanonical activationElections coverage
        candidateRole candidateMajority
        activation.newConfiguration.index activationIndex activation
        rfl
        stored
        (by simpa [sameTerm] using activationBeforeTerm)
    have ballotKnownCandidate :
        ballotConfiguration ∈ allConfigurations (state.nodes candidate).log := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            (activationInCandidate.trans
              (List.take_prefix
                (maxCommittableIndex (state.nodes candidate).log)
                (state.nodes candidate).log)))
      have valid := historyFacts.valid activationIndex activation stored
      have governing := ballotGoverning
      rw [valid.2.2.2.2.2.2.1] at governing
      exact
        allConfigurations_mem_take_of_index_le
          activation.history activation.activationFrontier valid.2.1
          (List.mem_filter.mp governing).1
          (of_decide_eq_true (List.mem_filter.mp governing).2).2
    exact ⟨
      ballotConfiguration,
      ballotActive,
      by
        simpa [activeConfigurations, candidateConfiguration]
          using And.intro ballotKnownCandidate candidateBefore.le
    ⟩
  · by_cases zero : candidateConfiguration.index = 0
    · have candidateImplicit :
          candidateConfiguration = implicitConfiguration := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) (state.nodes candidate).log
        · simpa [candidateConfiguration]
            using currentConfiguration_mem_allConfigurations (state.nodes candidate)
        · simp [allConfigurations, implicitConfiguration]
        · simpa [implicitConfiguration] using zero
      have ballotZero : ballotConfiguration.index = 0 := by simpa [sameIndex] using zero
      have ballotImplicit :
          ballotConfiguration = implicitConfiguration := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) record.ballotLog
        · simpa [ballotConfiguration, currentConfiguration]
            using currentConfiguration_mem_allConfigurations
              {
                (state.nodes candidate) with
                  log := record.ballotLog
                  commitIndex := record.ballotCommitIndex
              }
        · simp [allConfigurations, implicitConfiguration]
        · simpa [implicitConfiguration] using ballotZero
      exact ⟨
        ballotConfiguration,
        ballotActive,
        by
          simpa [candidateConfiguration, candidateImplicit, ballotImplicit]
            using candidateActive
      ⟩
    · have candidatePositive : 0 < candidateConfiguration.index :=
        Nat.pos_of_ne_zero zero
      rcases coverage candidate
          (by simpa [candidateConfiguration] using candidatePositive) with
        ⟨witness⟩
      have ballotPositive : 0 < ballotConfiguration.index := by
        simpa [sameIndex] using candidatePositive
      rcases
          configurationFacts.ballotCurrentAuthorityActivation
            term record recorded
            (by simpa [ballotConfiguration] using ballotPositive) with
        ⟨ballotActivationIndex, ballotActivation, ballotStored,
          ballotGoverning, _activationBeforeTerm,
          _ballotBound, _historyAgreement⟩
      have ballotGoverningRecord := ballotGoverning
      have ballotKnownActivation :
          ballotConfiguration ∈
            allConfigurations ballotActivation.history := by
        have valid :=
          historyFacts.valid
            ballotActivationIndex ballotActivation ballotStored
        rw [valid.2.2.2.2.2.2.1] at ballotGoverning
        exact (List.mem_filter.mp ballotGoverning).1
      have candidateAtOrBeforeActivation :
          candidateConfiguration.index <=
            ballotActivation.newConfiguration.index := by
        have ballotAtOrBefore :=
          activationGoverningConfigurationIndexLeNew
            historyFacts ballotStored ballotGoverningRecord
        simpa [
          candidateConfiguration, ballotConfiguration, sameIndex
        ] using ballotAtOrBefore
      have candidateKnownActivation :
          candidateConfiguration ∈
            allConfigurations ballotActivation.history := by
        rcases lt_or_eq_of_le candidateAtOrBeforeActivation with
          strict | equal
        · apply memOfPrefix
            (allConfigurations_mono_prefix
              ((witness.sharedPrefix_prefix_higherAuthority
                  ballotStored
                  (by simpa [candidateConfiguration] using strict)).trans
                (List.take_prefix
                  ballotActivation.activationFrontier
                  ballotActivation.history)))
          simpa [candidateConfiguration]
            using ConfigurationCoverageWitness.configuration_mem_activationHistoryTake
              historyFacts witness
        · have sameConfiguration :=
            witness.sameAuthority_configurationEq
              ballotStored
              (by simpa [candidateConfiguration] using equal.symm)
          simpa [sameConfiguration]
            using memOfPrefix
              (allConfigurations_mono_prefix
                (List.take_prefix
                  ballotActivation.activationFrontier
                  ballotActivation.history))
              (activationNewConfigurationKnown historyFacts ballotStored)
      have sameConfiguration :
          candidateConfiguration = ballotConfiguration := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) ballotActivation.history
            candidateKnownActivation ballotKnownActivation
        simpa [candidateConfiguration, ballotConfiguration] using sameIndex
      exact ⟨
        ballotConfiguration,
        ballotActive,
        by simpa [sameConfiguration] using candidateActive
      ⟩
  · have candidatePositive : 0 < candidateConfiguration.index := by omega
    rcases coverage candidate
        (by simpa [candidateConfiguration] using candidatePositive) with
      ⟨witness⟩
    have eventInPromotion :=
      activationPrefixInLaterElection
        activationElections witness.stored recorded
        (by simpa [sameTerm] using witness.activationTerm_lt_candidateTerm candidateRole)
    have candidateKnownEvent :
        candidateConfiguration ∈
          allConfigurations
            (witness.activation.history.take
              witness.activation.activationFrontier) := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            witness.sharedPrefix_prefix_activationPrefix)
      simpa [candidateConfiguration]
        using witness.configuration_mem_activationHistoryTake historyFacts
    have candidateKnownBallot :
        candidateConfiguration ∈ allConfigurations record.ballotLog := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            (eventInPromotion.trans
              (by
                rw [electionFacts.promotionFromBallot term record recorded]
                exact List.take_prefix _ _)))
      exact candidateKnownEvent
    exact ⟨
      candidateConfiguration,
      electionConfigurationActiveOfKnown
        electionFacts recorded candidateKnownBallot ballotBefore.le,
      candidateActive
    ⟩

/--
Transfer a potential source prefix to an unchanged higher-term candidate
across an UpdateTerm frame. Disjoint current configurations are connected by
their causally ordered activation records.
-/
lemma activationPrefixInEffectiveCandidateByAuthorityChain
    {after : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (afterTermsPositive : CurrentTermsPositive after)
    (afterCommittedSignature : CommittedFrontierIsSignature after)
    (afterEntriesBounded : EntriesDoNotExceedCurrentTerm after)
    (afterVoteFacts : VoteHistoryFacts after votes)
    (afterSnapshots
      : GrantedVoteSnapshots after votes voteCandidateHistory voteVoterHistory)
    (afterCanonicalSnapshots
      : GrantedVoteCanonicalSnapshots
          after canonicalHistory voteCandidateHistory voteVoterHistory)
    (afterOwnership
      : TermOwnershipFacts after votes appendHistory canonicalHistory owners)
    (afterElectionFacts
      : ElectionHistoryFacts after votes canonicalHistory owners elections)
    (afterConfigurationFacts : ElectionConfigurationFacts after elections activations)
    (historyFacts : ActivationHistoryFacts activations)
    (afterCurrentHistory : ActivationSupporterCurrentHistory after elections activations)
    (activationVoteHistory
      : ActivationVoteHistory votes voteVoterHistory elections activations)
    (afterActivationProgress : ActivationSupporterProgress after activations)
    (afterAckerActivation
      : AckerActivationHistory after responseHistory elections activations)
    (afterAckerElection : AckerElectionHistory after responseHistory elections)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    (coverage : ConfigurationCoverageFacts after activations)
    (afterEvidence : CommitEvidenceFacts after appendHistory nodeEvidence requestEvidence)
    (afterProspective
      : ProspectiveCommitEvidenceFacts
          after appendHistory nodeEvidence requestEvidence elections)
    {source candidate : Node}
    {index : Nat}
    (sourceRole : (after.nodes source).role = .leader)
    (currentEntry
      : termAt (after.nodes source).log index = (after.nodes source).currentTerm)
    (currentSignature : isSignatureAt (after.nodes source).log index = true)
    (potential : hasPotentialMajorityAt after appendHistory responseHistory source index)
    (candidateRole : (after.nodes candidate).role = .candidate)
    (candidateMajority : hasPotentialElectionMajority after candidate)
    (newer : (after.nodes source).currentTerm < (after.nodes candidate).currentTerm)
    (directOfShared
      : forall configuration,
          configuration ∈ activeConfigurations (after.nodes source)
          -> configuration.index <= index
          -> configuration ∈ activeConfigurations (after.nodes candidate)
          -> (after.nodes source).log.take index <+: (after.nodes candidate).log)
    : (after.nodes source).log.take index <+: (after.nodes candidate).log := by
  let sourceConfiguration :=
    currentConfiguration (after.nodes source)
  let candidateConfiguration :=
    currentConfiguration (after.nodes candidate)
  have sourceActive :
      sourceConfiguration ∈
        activeConfigurations (after.nodes source) := by
    simpa [sourceConfiguration]
      using currentConfiguration_mem_activeConfigurations (after.nodes source)
  have candidateActive :
      candidateConfiguration ∈
        activeConfigurations (after.nodes candidate) := by
    simpa [candidateConfiguration]
      using currentConfiguration_mem_activeConfigurations (after.nodes candidate)
  have activationInCandidate
      {activationIndex : ActivationKey Node}
      {activation : ActivationRecord Node TxId}
      (stored : activations activationIndex = some activation)
      (activationBefore :
        activation.activationTerm <
          (after.nodes candidate).currentTerm) :
      activation.history.take activation.activationFrontier <+:
        (after.nodes candidate).log.take
          (maxCommittableIndex (after.nodes candidate).log) := by
    exact
      activationPrefixInPotentialCandidateByCoverageAuthorityChain
        afterCommittedSignature afterEntriesBounded afterSnapshots
        afterCanonicalSnapshots afterOwnership afterElectionFacts
        historyFacts afterCurrentHistory activationVoteHistory
        activationCanonical activationElections coverage
        candidateRole candidateMajority
        activation.newConfiguration.index activationIndex activation
        rfl stored activationBefore
  have sourceKnownInLaterActivation :
      forall activationIndex activation,
        activations activationIndex = some activation ->
        sourceConfiguration.index < activation.newConfiguration.index ->
          sourceConfiguration ∈ allConfigurations activation.history := by
    intro activationIndex activation stored order
    by_cases sourceZero : sourceConfiguration.index = 0
    · have sourceImplicit :
          sourceConfiguration = implicitConfiguration := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) (after.nodes source).log
        · simpa [sourceConfiguration]
            using currentConfiguration_mem_allConfigurations (after.nodes source)
        · simp [allConfigurations, implicitConfiguration]
        · simpa [implicitConfiguration] using sourceZero
      simp [sourceImplicit, allConfigurations]
    · rcases coverage source
          (by simpa [sourceConfiguration] using
            Nat.pos_of_ne_zero sourceZero) with
        ⟨sourceWitness⟩
      have sourceKnownShared :=
        sourceWitness.configuration_mem_activationHistoryTake historyFacts
      have sharedInActivation :=
        sourceWitness.sharedPrefix_prefix_higherAuthority stored
          (by simpa [sourceConfiguration] using order)
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            (sharedInActivation.trans
              (List.take_prefix
                activation.activationFrontier activation.history)))
      simpa [
        sourceConfiguration,
        ConfigurationCoverageWitness.sharedPrefix,
        ConfigurationCoverageWitness.sharedFrontier
      ] using sourceKnownShared
  have sourceInLaterActivation :
      forall configurationIndex activationIndex activation,
        activation.newConfiguration.index = configurationIndex ->
        activations activationIndex = some activation ->
        sourceConfiguration.index <= index ->
        sourceConfiguration.index < activation.newConfiguration.index ->
        (after.nodes source).currentTerm < activation.activationTerm ->
          (after.nodes source).log.take index <+:
            activation.history.take activation.activationFrontier := by
    intro configurationIndex
    induction configurationIndex using Nat.strong_induction_on with
    | h configurationIndex inductionHypothesis =>
        intro activationIndex activation indexEq stored sourceGoverns
            configurationBefore activationLater
        have valid := historyFacts.valid activationIndex activation stored
        have earlierSafe :
            forall earlierTerm earlierRecord,
              (after.nodes source).currentTerm < earlierTerm ->
              earlierTerm <= activation.activationTerm ->
              elections earlierTerm = some earlierRecord ->
                (after.nodes source).log.take index <+:
                  earlierRecord.promotionLog := by
          intro earlierTerm earlierRecord above _ recorded
          exact
            potentialPrefixInElectionRecordsFromActivationHistory
              afterTermsPositive afterEntriesBounded afterVoteFacts
              afterOwnership afterElectionFacts afterConfigurationFacts
              historyFacts afterActivationProgress afterAckerActivation
              afterAckerElection activationCanonical activationElections
              coverage afterEvidence afterProspective
              sourceRole currentEntry currentSignature potential
              earlierTerm earlierRecord recorded above
        have directThroughElection :
            (after.nodes source).log.take index <+:
              activation.history.take activation.activationFrontier := by
          rcases
              afterElectionFacts.ownerRecorded
                activation.activationTerm activation.leader
                (activationCanonical.termOwner
                  activationIndex activation stored) with
            bootstrap | elected
          · have sourcePositive :=
              afterTermsPositive source (by rw [sourceRole]; decide)
            rw [bootstrap.1] at activationLater
            omega
          · rcases elected with
              ⟨record, recorded, recordLeader⟩
            exact
              electionPromotionPrefixInActivation
                afterElectionFacts historyFacts activationCanonical
                stored (by simpa [recordLeader] using recorded)
                (earlierSafe
                  activation.activationTerm record activationLater le_rfl
                  recorded)
        have oldBeforeNew :=
          activationOldConfigurationIndexLtNew historyFacts stored
        by_cases sourceBeforeOld :
            sourceConfiguration.index <
              activation.oldConfiguration.index
        · have oldPositive : 0 < activation.oldConfiguration.index := by
            omega
          obtain ⟨priorIndex, prior, priorFacts⟩ :=
            historyFacts.priorActivation
              activationIndex activation stored oldPositive
          have priorStored := priorFacts.1
          have priorBeforeActivation := priorFacts.2.1
          have oldCovered := priorFacts.2.2.1
          have priorPrefix := priorFacts.2.2.2
          have priorInActivation :
              prior.history.take prior.activationFrontier <+:
                activation.history.take activation.activationFrontier :=
            priorPrefix
          by_cases priorLater :
              (after.nodes source).currentTerm <
                prior.activationTerm
          · have sourceInPrior :
                (after.nodes source).log.take index <+:
                  prior.history.take prior.activationFrontier := by
              have oldAtOrBeforePrior :
                  activation.oldConfiguration.index <=
                    prior.newConfiguration.index :=
                activationGoverningConfigurationIndexLeNew
                  historyFacts priorStored oldCovered
              apply
                inductionHypothesis prior.newConfiguration.index
                  (by simpa [indexEq] using priorBeforeActivation)
                  priorIndex prior
                  rfl
                  priorStored sourceGoverns
                  (sourceBeforeOld.trans_le oldAtOrBeforePrior)
                  priorLater
            exact sourceInPrior.trans priorInActivation
          · exact directThroughElection
        · have sourceKnown :=
            sourceKnownInLaterActivation
              activationIndex activation stored configurationBefore
          have newGoverning :
              activation.newConfiguration ∈ activation.governingActive :=
            valid.2.2.2.2.2.2.2.1
          rw [valid.2.2.2.2.2.2.1] at newGoverning
          have newWithin :
              activation.newConfiguration.index <=
                activation.activationFrontier :=
            (of_decide_eq_true
              (List.mem_filter.mp newGoverning).2).2
          have sourceGoverning :
              sourceConfiguration ∈ activation.governingActive := by
            rw [valid.2.2.2.2.2.2.1]
            simp only [List.mem_filter]
            refine ⟨sourceKnown, decide_eq_true ?_⟩
            exact ⟨by omega, configurationBefore.le.trans newWithin⟩
          exact
            potentialPrefixInActivation
              afterOwnership historyFacts activationCanonical
              afterActivationProgress afterAckerActivation
              sourceRole currentEntry currentSignature potential
              sourceActive sourceGoverns
              stored sourceGoverning activationLater earlierSafe
  rcases Nat.lt_trichotomy
      sourceConfiguration.index candidateConfiguration.index with
    sourceBeforeCandidate | sameIndex | candidateBeforeSource
  · have candidatePositive : 0 < candidateConfiguration.index := by
      omega
    rcases coverage candidate
        (by simpa [candidateConfiguration] using candidatePositive) with
      ⟨candidateWitness⟩
    have candidateEventInCandidate :
        candidateWitness.activation.history.take
            candidateWitness.activation.activationFrontier <+:
          (after.nodes candidate).log := by
      exact (activationPrefixInPotentialCandidatePromotionOfGoverningConfiguration
              afterCommittedSignature afterEntriesBounded afterSnapshots
              afterCanonicalSnapshots afterOwnership afterElectionFacts
              historyFacts afterCurrentHistory activationVoteHistory
              activationElections candidateWitness.stored
              candidateRole candidateMajority
              (candidateWitness.activationTerm_lt_candidateTerm candidateRole)
              candidateWitness.configurationCovered candidateActive).trans
        (List.take_prefix
          (maxCommittableIndex (after.nodes candidate).log)
          (after.nodes candidate).log)
    by_cases sourceGoverns : sourceConfiguration.index <= index
    · rcases Nat.lt_trichotomy
          (after.nodes source).currentTerm
          candidateWitness.activation.activationTerm with
        sourceBeforeActivation | sameTerm | activationBeforeSource
      · exact (sourceInLaterActivation
                candidateWitness.activation.newConfiguration.index
                candidateWitness.activationIndex candidateWitness.activation
                rfl candidateWitness.stored sourceGoverns
                (sourceBeforeCandidate.trans_le
                  (candidateWitness.configurationIndex_le_activationConfiguration
                    historyFacts))
                sourceBeforeActivation).trans
          candidateEventInCandidate
      · have activationInSource :
            candidateWitness.activation.history.take
                candidateWitness.activation.activationFrontier <+:
              (after.nodes source).log := by
          rw [
            activationCanonical.activationFrontierCanonical
              candidateWitness.activationIndex candidateWitness.activation
                candidateWitness.stored,
            ← sameTerm,
            afterOwnership.activeLeaderHistory source sourceRole
          ]
          exact List.take_prefix _ _
        by_cases candidateGoverns : candidateConfiguration.index <= index
        · have candidateKnownSource :
              candidateConfiguration ∈
                allConfigurations (after.nodes source).log := by
            apply
              memOfPrefix
                (allConfigurations_mono_prefix activationInSource)
            apply
              memOfPrefix
                (allConfigurations_mono_prefix
                  candidateWitness.sharedPrefix_prefix_activationPrefix)
            simpa [candidateConfiguration]
              using candidateWitness.configuration_mem_activationHistoryTake historyFacts
          exact directOfShared candidateConfiguration
            (by
              simpa [activeConfigurations, sourceConfiguration]
                using And.intro candidateKnownSource sourceBeforeCandidate.le)
            candidateGoverns candidateActive
        · have activationLength :
              (candidateWitness.activation.history.take
                candidateWitness.activation.activationFrontier).length =
                  candidateWitness.activation.activationFrontier := by
            simp [Nat.min_eq_left
              (historyFacts.valid
                candidateWitness.activationIndex candidateWitness.activation
                candidateWitness.stored).2.1]
          have exactTake := prefixEqTake activationInSource
          have exactFrontierTake :
              (after.nodes source).log.take
                  candidateWitness.activation.activationFrontier =
                candidateWitness.activation.history.take
                  candidateWitness.activation.activationFrontier := by
            simpa [activationLength] using exactTake
          have sourceInActivation :
              (after.nodes source).log.take index <+:
                candidateWitness.activation.history.take
                  candidateWitness.activation.activationFrontier := by
            rw [← exactFrontierTake]
            rw [List.prefix_take_iff]
            exact ⟨
              List.take_prefix _ _,
              (List.length_take_le _ _).trans
                (by
                  have candidateWithin :=
                    candidateWitness.configurationIndexBound.trans
                      candidateWitness.sharedFrontier_le_activationFrontier
                  have candidateWithin' :
                      candidateConfiguration.index <=
                        candidateWitness.activation.activationFrontier := by
                    simpa [candidateConfiguration] using candidateWithin
                  exact (Nat.le_of_lt (Nat.lt_of_not_ge candidateGoverns)).trans
                    candidateWithin')
            ⟩
          exact sourceInActivation.trans candidateEventInCandidate
      · have activationInSource :
            candidateWitness.activation.history.take
                candidateWitness.activation.activationFrontier <+:
              (after.nodes source).log := by
          rcases
              afterElectionFacts.ownerRecorded
                (after.nodes source).currentTerm source
                (afterOwnership.activeLeader source sourceRole) with
            bootstrap | elected
          · have activationPositive :=
              historyFacts.termPositive
                candidateWitness.activationIndex candidateWitness.activation
                  candidateWitness.stored
            rw [bootstrap.1] at activationBeforeSource
            omega
          · rcases elected with
              ⟨record, recorded, _recordLeader⟩
            exact (activationPrefixInLaterElection
                    activationElections candidateWitness.stored recorded
                    activationBeforeSource).trans
              ((afterElectionFacts.promotionCanonical
                  (after.nodes source).currentTerm record recorded).trans
                (by rw [
                    afterOwnership.activeLeaderHistory source sourceRole
                  ]))
        by_cases candidateGoverns : candidateConfiguration.index <= index
        · have candidateKnownSource :
              candidateConfiguration ∈
                allConfigurations (after.nodes source).log := by
            apply
              memOfPrefix
                (allConfigurations_mono_prefix activationInSource)
            apply
              memOfPrefix
                (allConfigurations_mono_prefix
                  candidateWitness.sharedPrefix_prefix_activationPrefix)
            simpa [candidateConfiguration]
              using candidateWitness.configuration_mem_activationHistoryTake historyFacts
          exact directOfShared candidateConfiguration
            (by
              simpa [activeConfigurations, sourceConfiguration]
                using And.intro candidateKnownSource sourceBeforeCandidate.le)
            candidateGoverns candidateActive
        · have activationLength :
              (candidateWitness.activation.history.take
                candidateWitness.activation.activationFrontier).length =
                  candidateWitness.activation.activationFrontier := by
            simp [Nat.min_eq_left
              (historyFacts.valid
                candidateWitness.activationIndex candidateWitness.activation
                candidateWitness.stored).2.1]
          have exactTake := prefixEqTake activationInSource
          have exactFrontierTake :
              (after.nodes source).log.take
                  candidateWitness.activation.activationFrontier =
                candidateWitness.activation.history.take
                  candidateWitness.activation.activationFrontier := by
            simpa [activationLength] using exactTake
          have sourceInActivation :
              (after.nodes source).log.take index <+:
                candidateWitness.activation.history.take
                  candidateWitness.activation.activationFrontier := by
            rw [← exactFrontierTake]
            rw [List.prefix_take_iff]
            exact ⟨
              List.take_prefix _ _,
              (List.length_take_le _ _).trans
                (by
                  have candidateWithin :=
                    candidateWitness.configurationIndexBound.trans
                      candidateWitness.sharedFrontier_le_activationFrontier
                  have candidateWithin' :
                      candidateConfiguration.index <=
                        candidateWitness.activation.activationFrontier := by
                    simpa [candidateConfiguration] using candidateWithin
                  exact (Nat.le_of_lt (Nat.lt_of_not_ge candidateGoverns)).trans
                    candidateWithin')
            ⟩
          exact sourceInActivation.trans candidateEventInCandidate
    · have sourcePositive : 0 < sourceConfiguration.index := by
        omega
      rcases coverage source
          (by simpa [sourceConfiguration] using sourcePositive) with
        ⟨sourceWitness⟩
      have sourceInShared :
          (after.nodes source).log.take index <+:
            sourceWitness.sharedPrefix := by
        rw [sourceWitness.sharedPrefix_eq_nodeLogTake]
        rw [List.prefix_take_iff]
        exact ⟨
          List.take_prefix _ _,
          (List.length_take_le _ _).trans
            (by
              have sourceWithin :
                  sourceConfiguration.index <=
                    sourceWitness.sharedFrontier := by
                simpa [sourceConfiguration, ConfigurationCoverageWitness.sharedFrontier]
                  using sourceWitness.configurationIndexBound
              omega)
        ⟩
      have sharedInCandidateEvent :=
        sourceWitness.sharedPrefix_prefix_higherAuthority
          candidateWitness.stored
          (sourceBeforeCandidate.trans_le
            (candidateWitness.configurationIndex_le_activationConfiguration
              historyFacts))
      exact
        sourceInShared.trans
          (sharedInCandidateEvent.trans candidateEventInCandidate)
  · by_cases sourceZero : sourceConfiguration.index = 0
    · have sourceImplicit :
          sourceConfiguration = implicitConfiguration := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) (after.nodes source).log
        · simpa [sourceConfiguration]
            using currentConfiguration_mem_allConfigurations (after.nodes source)
        · simp [allConfigurations, implicitConfiguration]
        · simpa [implicitConfiguration] using sourceZero
      have candidateZero : candidateConfiguration.index = 0 := by
        simpa [sameIndex] using sourceZero
      have candidateImplicit :
          candidateConfiguration = implicitConfiguration := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) (after.nodes candidate).log
        · simpa [candidateConfiguration]
            using currentConfiguration_mem_allConfigurations (after.nodes candidate)
        · simp [allConfigurations, implicitConfiguration]
        · simpa [implicitConfiguration] using candidateZero
      exact directOfShared sourceConfiguration sourceActive
        (by
          omega)
        (by simpa [sourceImplicit, candidateImplicit] using candidateActive)
    · have sourcePositive : 0 < sourceConfiguration.index :=
        Nat.pos_of_ne_zero sourceZero
      rcases coverage source
          (by simpa [sourceConfiguration] using sourcePositive) with
        ⟨sourceWitness⟩
      have sourceEventInCandidate :=
        activationInCandidate sourceWitness.stored
          (sourceWitness.activationTerm_le_currentTerm.trans_lt newer)
      by_cases indexWithin : index <= sourceWitness.sharedFrontier
      · have sourceInShared :
            (after.nodes source).log.take index <+:
              sourceWitness.sharedPrefix := by
          rw [sourceWitness.sharedPrefix_eq_nodeLogTake]
          rw [List.prefix_take_iff]
          exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans indexWithin⟩
        exact
          sourceInShared.trans
            (sourceWitness.sharedPrefix_prefix_activationPrefix.trans
              (sourceEventInCandidate.trans
                (List.take_prefix
                  (maxCommittableIndex (after.nodes candidate).log)
                  (after.nodes candidate).log)))
      · have sourceKnownCandidate :
            sourceConfiguration ∈
              allConfigurations (after.nodes candidate).log := by
          apply
            memOfPrefix
              (allConfigurations_mono_prefix
                (sourceEventInCandidate.trans
                  (List.take_prefix
                    (maxCommittableIndex (after.nodes candidate).log)
                    (after.nodes candidate).log)))
          apply
            memOfPrefix
              (allConfigurations_mono_prefix
                sourceWitness.sharedPrefix_prefix_activationPrefix)
          simpa [sourceConfiguration]
            using sourceWitness.configuration_mem_activationHistoryTake historyFacts
        exact directOfShared sourceConfiguration sourceActive
          (sourceWitness.configurationIndexBound.trans (Nat.lt_of_not_ge indexWithin).le)
          (by
            simpa [activeConfigurations, candidateConfiguration]
              using And.intro sourceKnownCandidate (by simpa [
                  sourceConfiguration, candidateConfiguration
                ] using sameIndex.symm.le))
  · have sourcePositive : 0 < sourceConfiguration.index := by
      omega
    rcases coverage source
        (by simpa [sourceConfiguration] using sourcePositive) with
      ⟨sourceWitness⟩
    have sourceEventInCandidate :=
      activationInCandidate sourceWitness.stored
        (sourceWitness.activationTerm_le_currentTerm.trans_lt newer)
    by_cases indexWithin : index <= sourceWitness.sharedFrontier
    · have sourceInShared :
          (after.nodes source).log.take index <+:
            sourceWitness.sharedPrefix := by
        rw [sourceWitness.sharedPrefix_eq_nodeLogTake]
        rw [List.prefix_take_iff]
        exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans indexWithin⟩
      exact
        sourceInShared.trans
          (sourceWitness.sharedPrefix_prefix_activationPrefix.trans
            (sourceEventInCandidate.trans
              (List.take_prefix
                (maxCommittableIndex (after.nodes candidate).log)
                (after.nodes candidate).log)))
    · have sourceKnownCandidate :
          sourceConfiguration ∈
            allConfigurations (after.nodes candidate).log := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (sourceEventInCandidate.trans
                (List.take_prefix
                  (maxCommittableIndex (after.nodes candidate).log)
                  (after.nodes candidate).log)))
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              sourceWitness.sharedPrefix_prefix_activationPrefix)
        simpa [sourceConfiguration]
          using sourceWitness.configuration_mem_activationHistoryTake historyFacts
      exact directOfShared sourceConfiguration sourceActive
        (sourceWitness.configurationIndexBound.trans (Nat.lt_of_not_ge indexWithin).le)
        (by
          simpa [activeConfigurations, candidateConfiguration]
            using And.intro sourceKnownCandidate candidateBeforeSource.le)

/-- Coverage-native frozen ballot and future election sharing. -/
lemma futureElectionRecordSharedConfigurationCoverage
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (committedSignature : CommittedFrontierIsSignature state)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
    (historyFacts : ActivationHistoryFacts activations)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    (coverage : ConfigurationCoverageFacts state activations)
    {term : Nat}
    {record : ElectionRecord Node TxId}
    (recorded : elections term = some record)
    {candidate : Node}
    (candidateBefore : (state.nodes candidate).currentTerm < term)
    (futureMajority
      : hasFutureElectionMajority
          state candidate term
          (activeConfigurations (state.nodes candidate)))
    : Exists
        fun configuration =>
          configuration ∈ record.ballotActive
          /\ configuration ∈ activeConfigurations (state.nodes candidate) := by
  let ballotConfiguration :=
    currentConfigurationAt record.ballotLog record.ballotCommitIndex
  let candidateConfiguration := currentConfiguration (state.nodes candidate)
  have ballotActive :
      ballotConfiguration ∈ record.ballotActive := by
    simpa [ballotConfiguration]
      using configurationFacts.ballotCurrentAuthorityActive term record recorded
  have candidateActive :
      candidateConfiguration ∈
        activeConfigurations (state.nodes candidate) := by
    simpa [candidateConfiguration]
      using currentConfiguration_mem_activeConfigurations (state.nodes candidate)
  rcases Nat.lt_trichotomy
      ballotConfiguration.index candidateConfiguration.index with
    ballotBefore | sameIndex | candidateBeforeBallot
  · have candidatePositive : 0 < candidateConfiguration.index := by omega
    rcases coverage candidate
        (by simpa [candidateConfiguration] using candidatePositive) with
      ⟨witness⟩
    have eventInPromotion :=
      activationPrefixInLaterElection
        activationElections witness.stored recorded
        (witness.activationTerm_le_currentTerm.trans_lt candidateBefore)
    have candidateKnownEvent :
        candidateConfiguration ∈
          allConfigurations
            (witness.activation.history.take
              witness.activation.activationFrontier) := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            witness.sharedPrefix_prefix_activationPrefix)
      simpa [candidateConfiguration]
        using witness.configuration_mem_activationHistoryTake historyFacts
    have candidateKnownBallot :
        candidateConfiguration ∈ allConfigurations record.ballotLog := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            (eventInPromotion.trans
              (by
                rw [electionFacts.promotionFromBallot term record recorded]
                exact List.take_prefix _ _)))
      exact candidateKnownEvent
    exact ⟨
      candidateConfiguration,
      electionConfigurationActiveOfKnown
        electionFacts recorded candidateKnownBallot ballotBefore.le,
      candidateActive
    ⟩
  · by_cases zero : candidateConfiguration.index = 0
    · have candidateImplicit :
          candidateConfiguration = implicitConfiguration := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) (state.nodes candidate).log
        · simpa [candidateConfiguration]
            using currentConfiguration_mem_allConfigurations (state.nodes candidate)
        · simp [allConfigurations, implicitConfiguration]
        · simpa [implicitConfiguration] using zero
      have ballotZero : ballotConfiguration.index = 0 := by simpa [sameIndex] using zero
      have ballotImplicit :
          ballotConfiguration = implicitConfiguration := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) record.ballotLog
        · simpa [ballotConfiguration, currentConfiguration]
            using currentConfiguration_mem_allConfigurations
              {
                (state.nodes candidate) with
                  log := record.ballotLog
                  commitIndex := record.ballotCommitIndex
              }
        · simp [allConfigurations, implicitConfiguration]
        · simpa [implicitConfiguration] using ballotZero
      exact ⟨
        ballotConfiguration,
        ballotActive,
        by
          simpa [candidateConfiguration, candidateImplicit, ballotImplicit]
            using candidateActive
      ⟩
    · have candidatePositive : 0 < candidateConfiguration.index :=
        Nat.pos_of_ne_zero zero
      rcases coverage candidate
          (by simpa [candidateConfiguration] using candidatePositive) with
        ⟨witness⟩
      have ballotPositive : 0 < ballotConfiguration.index := by
        simpa [sameIndex] using candidatePositive
      rcases
          configurationFacts.ballotCurrentAuthorityActivation
            term record recorded
            (by simpa [ballotConfiguration] using ballotPositive) with
        ⟨ballotActivationIndex, ballotActivation, ballotStored,
          ballotGoverning, _activationBeforeTerm,
          _ballotBound, _historyAgreement⟩
      have ballotGoverningRecord := ballotGoverning
      have ballotKnownActivation :
          ballotConfiguration ∈
            allConfigurations ballotActivation.history := by
        have valid :=
          historyFacts.valid
            ballotActivationIndex ballotActivation ballotStored
        rw [valid.2.2.2.2.2.2.1] at ballotGoverning
        exact (List.mem_filter.mp ballotGoverning).1
      have candidateAtOrBeforeActivation :
          candidateConfiguration.index <=
            ballotActivation.newConfiguration.index := by
        have ballotAtOrBefore :=
          activationGoverningConfigurationIndexLeNew
            historyFacts ballotStored ballotGoverningRecord
        simpa [
          candidateConfiguration, ballotConfiguration, sameIndex
        ] using ballotAtOrBefore
      have candidateKnownActivation :
          candidateConfiguration ∈
            allConfigurations ballotActivation.history := by
        rcases lt_or_eq_of_le candidateAtOrBeforeActivation with
          strict | equal
        · apply memOfPrefix
            (allConfigurations_mono_prefix
              ((witness.sharedPrefix_prefix_higherAuthority
                  ballotStored
                  (by simpa [candidateConfiguration] using strict)).trans
                (List.take_prefix
                  ballotActivation.activationFrontier
                  ballotActivation.history)))
          simpa [candidateConfiguration]
            using ConfigurationCoverageWitness.configuration_mem_activationHistoryTake
              historyFacts witness
        · have sameConfiguration :=
            witness.sameAuthority_configurationEq
              ballotStored
              (by simpa [candidateConfiguration] using equal.symm)
          simpa [sameConfiguration]
            using memOfPrefix
              (allConfigurations_mono_prefix
                (List.take_prefix
                  ballotActivation.activationFrontier
                  ballotActivation.history))
              (activationNewConfigurationKnown historyFacts ballotStored)
      have sameConfiguration :
          candidateConfiguration = ballotConfiguration := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) ballotActivation.history
            candidateKnownActivation ballotKnownActivation
        simpa [candidateConfiguration, ballotConfiguration] using sameIndex.symm
      exact ⟨
        ballotConfiguration,
        ballotActive,
        by simpa [sameConfiguration] using candidateActive
      ⟩
  · have ballotPositive : 0 < ballotConfiguration.index := by omega
    rcases
        configurationFacts.ballotCurrentAuthorityActivation
          term record recorded
          (by simpa [ballotConfiguration] using ballotPositive) with
      ⟨ballotActivationIndex, ballotActivation, ballotStored,
        ballotGoverning, _activationBeforeTerm,
        _ballotBound, _historyAgreement⟩
    have ballotActivationInCandidate :=
      activationPrefixInFutureCandidateByCoverageAuthorityChain
        committedSignature ownership electionFacts historyFacts
        configurationFacts.supporterCurrentHistory
        activationCanonical activationElections coverage
        futureMajority rfl
        ballotActivation.newConfiguration.index ballotActivationIndex
        ballotActivation
        rfl
        ballotStored
        (candidateBeforeBallot.trans_le
          (activationGoverningConfigurationIndexLeNew
            historyFacts ballotStored ballotGoverning))
    have ballotKnownCandidate :
        ballotConfiguration ∈ allConfigurations (state.nodes candidate).log :=
      memOfPrefix
        (allConfigurations_mono_prefix ballotActivationInCandidate)
        (by
          have valid :=
            historyFacts.valid
              ballotActivationIndex ballotActivation ballotStored
          have governing := ballotGoverning
          rw [valid.2.2.2.2.2.2.1] at governing
          exact
            allConfigurations_mem_take_of_index_le
              ballotActivation.history
              ballotActivation.activationFrontier valid.2.1
              (List.mem_filter.mp governing).1
              (of_decide_eq_true
                (List.mem_filter.mp governing).2).2)
    exact ⟨
      ballotConfiguration,
      ballotActive,
      by
        simpa [activeConfigurations, candidateConfiguration]
          using And.intro ballotKnownCandidate candidateBeforeBallot.le
    ⟩

/--
Future voter closure specialized to the fields stored in prospective commit
evidence.
-/
lemma prospectiveCommitFutureMember
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (committedSignature : CommittedFrontierIsSignature state)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts
      : ProspectiveCommitEvidenceFacts
          state appendHistory nodeEvidence requestEvidence elections)
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (known
      : KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {candidate member : Node}
    {targetTerm : Nat}
    (_candidateBefore : (state.nodes candidate).currentTerm < targetTerm)
    (ackMember : member ∈ evidence.ackQuorum)
    (future : member ∈ futureElectionVoters state candidate targetTerm)
    : evidence.history.take evidence.commitFrontier <+: (state.nodes candidate).log :=
  prospectiveCommitFutureMemberCore
    ownership committedSignature electionFacts evidenceFacts
    prospectiveFacts.commitTermPositive
    prospectiveFacts.electionClosure
    prospectiveFacts.currentMember
    known ackMember future

/-- Under a support quorum, every materialised ACKer's current log contains the prefix. -/
lemma effectiveAckerContainsPotentialPrefix
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (currentHistory : AckerCurrentHistory state responseHistory elections)
    (electedHistory : AckerElectionHistory state responseHistory elections)
    (activationQuorums
      : ActivationQuorumFacts state appendHistory responseHistory elections activations)
    {source voter : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (effective : voter ∈ effectiveAckers state responseHistory source index)
    : (state.nodes source).log.take index <+: (state.nodes voter).log := by
  rcases
      currentHistory source index sourceRole currentEntry currentSignature
        voter effective with
    retained | bad
  · exact retained
  · rcases bad with
      ⟨badTerm, badRecord, above, _, recorded, missing⟩
    exact False.elim
      (missing
        (potentialPrefixInElectionRecords
          termsPositive voteFacts ownership electionFacts electedHistory
            activationQuorums
            sourceRole currentEntry currentSignature potential
            badTerm badRecord recorded above))

omit [Bootstrap Node] in
lemma effectiveAckerContainsPrefixOfEarlierSafe
    {state : View Node TxId}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {elections : ElectionHistory Node TxId}
    (currentHistory : AckerCurrentHistory state responseHistory elections)
    {source voter : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (effective : voter ∈ effectiveAckers state responseHistory source index)
    (earlierSafe
      : forall term record,
          (state.nodes source).currentTerm < term
          -> elections term = some record
          -> (state.nodes source).log.take index <+: record.promotionLog)
    : (state.nodes source).log.take index <+: (state.nodes voter).log := by
  rcases
      currentHistory source index sourceRole currentEntry currentSignature
        voter effective with
    retained | bad
  · exact retained
  · rcases bad with
      ⟨badTerm, badRecord, above, _, recorded, missing⟩
    exact False.elim
      (missing (earlierSafe badTerm badRecord above recorded))

/--
One materialised ACKer which is either an existing voter or currently regards
the candidate log as up to date transfers the acknowledged prefix.
-/
lemma effectiveAckerRelaxedCandidateContainsPotentialPrefix
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (committedSignature : CommittedFrontierIsSignature state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (canonicalSnapshots
      : GrantedVoteCanonicalSnapshots
          state canonicalHistory voteCandidateHistory voteVoterHistory)
    (currentHistory : AckerCurrentHistory state responseHistory elections)
    (voteHistory
      : AckerVoteHistory state votes responseHistory voteVoterHistory elections)
    (electedHistory : AckerElectionHistory state responseHistory elections)
    (activationQuorums
      : ActivationQuorumFacts state appendHistory responseHistory elections activations)
    {source candidate voter : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (candidateRole : (state.nodes candidate).role = .candidate)
    (newer : (state.nodes source).currentTerm < (state.nodes candidate).currentTerm)
    (candidateEntriesBefore
      : forall entry,
          entry ∈ (state.nodes candidate).log
          -> entry.term < (state.nodes candidate).currentTerm)
    (effective : voter ∈ effectiveAckers state responseHistory source index)
    (relaxed : voter ∈ relaxedElectionVoters state candidate)
    : (state.nodes source).log.take index <+: (state.nodes candidate).log := by
  have earlierSafe :
      forall earlierTerm earlierRecord,
        (state.nodes source).currentTerm < earlierTerm ->
        earlierTerm < (state.nodes candidate).currentTerm ->
        elections earlierTerm = some earlierRecord ->
          (state.nodes source).log.take index <+:
            earlierRecord.promotionLog := by
    intro earlierTerm earlierRecord above _ recorded
    exact
      potentialPrefixInElectionRecords
        termsPositive voteFacts ownership electionFacts electedHistory
          activationQuorums
          sourceRole currentEntry currentSignature potential
          earlierTerm earlierRecord recorded above
  by_cases voterEq : voter = candidate
  · subst voter
    exact
      effectiveAckerContainsPotentialPrefix
        termsPositive voteFacts ownership electionFacts
          currentHistory electedHistory activationQuorums
          sourceRole currentEntry currentSignature potential effective
  · simp only [
      relaxedElectionVoters, Finset.mem_filter] at relaxed
    rcases relaxed with ⟨_joined, materialised | upToDate⟩
    · have snapshot :=
        snapshots candidate voter
          (Or.inl candidateRole) materialised
      have recordedVote := snapshot.1
      have voterPrefix :
          (state.nodes source).log.take index <+:
            voteVoterHistory
              (grantedVoteKey
                voter (state.nodes candidate).currentTerm candidate) := by
        rcases
            voteHistory source index sourceRole currentEntry currentSignature
              voter (state.nodes candidate).currentTerm candidate
              effective recordedVote voterEq newer with
          retained | bad
        · exact retained
        · rcases bad with
            ⟨badTerm, badRecord, above, _, recorded, missing⟩
          exact False.elim
            (missing
              (potentialPrefixInElectionRecords
                termsPositive voteFacts ownership electionFacts electedHistory
                  activationQuorums
                  sourceRole currentEntry currentSignature potential
                  badTerm badRecord recorded above))
      rcases snapshot.2 with self | voteSnapshot
      · exact False.elim (voterEq self)
      · rcases
          canonicalSnapshots candidate voter
            (Or.inl candidateRole) materialised with
        self | canonicalSnapshot
        · exact False.elim (voterEq self)
        · let response :=
            grantedVoteKey
              voter (state.nodes candidate).currentTerm candidate
          apply
            candidateSnapshotContainsProspectivePrefix
              (termsPositive source (by rw [sourceRole]; decide))
              ownership electionFacts
                currentEntry currentSignature voterPrefix voteSnapshot.1
                canonicalSnapshot.1
                canonicalSnapshot.2.2.1
                canonicalSnapshot.2.2.2
                (fun entry member =>
                  Or.inl
                    (candidateEntriesBefore entry
                      (memOfPrefix voteSnapshot.1 member)))
          · simpa [
              response, voteLogUpToDate, maxCommittableTerm,
              voteSnapshot.2.1, voteSnapshot.2.2.1
            ] using voteSnapshot.2.2.2.2
          · exact earlierSafe
    · have voterPrefix :=
        effectiveAckerContainsPotentialPrefix
          termsPositive voteFacts ownership electionFacts
            currentHistory electedHistory activationQuorums
            sourceRole currentEntry currentSignature potential effective
      apply
        candidateSnapshotContainsProspectivePrefix
          (targetTerm := (state.nodes candidate).currentTerm)
          (termsPositive source (by rw [sourceRole]; decide))
          ownership electionFacts
            currentEntry currentSignature voterPrefix
            (prefixRefl (state.nodes candidate).log)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement
                candidate entryIndex entry found)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement voter entryIndex entry found)
            ((canonicalHistoriesMonoLog ownership) voter)
            (fun entry member =>
              Or.inl (candidateEntriesBefore entry member))
      · simpa [
          relaxedElectionVoters,
          makeRequestVoteRequest,
          lastCommittableIndex_eq_maxCommittableIndex
            (state.nodes candidate) (committedSignature candidate),
          lastCommittableTerm_eq_maxCommittableTerm
            (state.nodes candidate) (committedSignature candidate),
          voteLogUpToDate
        ] using upToDate.2
      · exact earlierSafe

lemma effectiveAckerRelaxedCandidateContainsPrefixOfEarlierSafe
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (committedSignature : CommittedFrontierIsSignature state)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (canonicalSnapshots
      : GrantedVoteCanonicalSnapshots
          state canonicalHistory voteCandidateHistory voteVoterHistory)
    (currentHistory : AckerCurrentHistory state responseHistory elections)
    (voteHistory
      : AckerVoteHistory state votes responseHistory voteVoterHistory elections)
    {source candidate voter : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (candidateRole : (state.nodes candidate).role = .candidate)
    (newer : (state.nodes source).currentTerm < (state.nodes candidate).currentTerm)
    (candidateEntriesBefore
      : forall entry,
          entry ∈ (state.nodes candidate).log
          -> entry.term < (state.nodes candidate).currentTerm)
    (effective : voter ∈ effectiveAckers state responseHistory source index)
    (relaxed : voter ∈ relaxedElectionVoters state candidate)
    (earlierSafe
      : forall term record,
          (state.nodes source).currentTerm < term
          -> elections term = some record
          -> (state.nodes source).log.take index <+: record.promotionLog)
    : (state.nodes source).log.take index <+: (state.nodes candidate).log := by
  by_cases voterEq : voter = candidate
  · subst voter
    exact
      effectiveAckerContainsPrefixOfEarlierSafe
        currentHistory sourceRole currentEntry currentSignature effective
        earlierSafe
  · simp only [
      relaxedElectionVoters, Finset.mem_filter] at relaxed
    rcases relaxed with ⟨_joined, materialised | upToDate⟩
    · have snapshot :=
        snapshots candidate voter (Or.inl candidateRole) materialised
      have recordedVote := snapshot.1
      have voterPrefix :
          (state.nodes source).log.take index <+:
            voteVoterHistory
              (grantedVoteKey
                voter (state.nodes candidate).currentTerm candidate) := by
        rcases
            voteHistory source index sourceRole currentEntry currentSignature
              voter (state.nodes candidate).currentTerm candidate
              effective recordedVote voterEq newer with
          retained | bad
        · exact retained
        · rcases bad with
            ⟨badTerm, badRecord, above, _, recorded, missing⟩
          exact False.elim
            (missing (earlierSafe badTerm badRecord above recorded))
      rcases snapshot.2 with self | voteSnapshot
      · exact False.elim (voterEq self)
      · rcases
          canonicalSnapshots candidate voter
            (Or.inl candidateRole) materialised with
        self | canonicalSnapshot
        · exact False.elim (voterEq self)
        · let response :=
            grantedVoteKey
              voter (state.nodes candidate).currentTerm candidate
          apply
            candidateSnapshotContainsProspectivePrefix
              (termsPositive source (by rw [sourceRole]; decide))
              ownership electionFacts
                currentEntry currentSignature voterPrefix voteSnapshot.1
                canonicalSnapshot.1
                canonicalSnapshot.2.2.1
                canonicalSnapshot.2.2.2
                (fun entry member =>
                  Or.inl
                    (candidateEntriesBefore entry
                      (memOfPrefix voteSnapshot.1 member)))
          · simpa [
              response, voteLogUpToDate, maxCommittableTerm,
              voteSnapshot.2.1, voteSnapshot.2.2.1
            ] using voteSnapshot.2.2.2.2
          · intro term record above _ recorded
            exact earlierSafe term record above recorded
    · have voterPrefix :=
        effectiveAckerContainsPrefixOfEarlierSafe
          currentHistory sourceRole currentEntry currentSignature effective
          earlierSafe
      apply
        candidateSnapshotContainsProspectivePrefix
          (targetTerm := (state.nodes candidate).currentTerm)
          (termsPositive source (by rw [sourceRole]; decide))
          ownership electionFacts
            currentEntry currentSignature voterPrefix
            (prefixRefl (state.nodes candidate).log)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement
                candidate entryIndex entry found)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement voter entryIndex entry found)
            ((canonicalHistoriesMonoLog ownership) voter)
            (fun entry member =>
              Or.inl (candidateEntriesBefore entry member))
      · simpa [
          relaxedElectionVoters,
          makeRequestVoteRequest,
          lastCommittableIndex_eq_maxCommittableIndex
            (state.nodes candidate) (committedSignature candidate),
          lastCommittableTerm_eq_maxCommittableTerm
            (state.nodes candidate) (committedSignature candidate),
          voteLogUpToDate
        ] using upToDate.2
      · intro term record above _ recorded
        exact earlierSafe term record above recorded

/--
One materialised ACKer whose current log would support a strictly later
election transfers the acknowledged prefix to that unchanged candidate log.
-/
lemma effectiveAckerFutureCandidateContainsPotentialPrefix
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (committedSignature : CommittedFrontierIsSignature state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (currentHistory : AckerCurrentHistory state responseHistory elections)
    (electedHistory : AckerElectionHistory state responseHistory elections)
    (activationQuorums
      : ActivationQuorumFacts state appendHistory responseHistory elections activations)
    {source candidate voter : Node}
    {index targetTerm : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (_sourceBefore : (state.nodes source).currentTerm < targetTerm)
    (candidateBefore : (state.nodes candidate).currentTerm < targetTerm)
    (effective : voter ∈ effectiveAckers state responseHistory source index)
    (future : voter ∈ futureElectionVoters state candidate targetTerm)
    : (state.nodes source).log.take index <+: (state.nodes candidate).log := by
  have voterPrefix :=
    effectiveAckerContainsPotentialPrefix
      termsPositive voteFacts ownership electionFacts
        currentHistory electedHistory activationQuorums
        sourceRole currentEntry currentSignature potential effective
  by_cases voterEq : voter = candidate
  · subst voter
    exact voterPrefix
  · simp only [
      futureElectionVoters, Finset.mem_filter] at future
    rcases future with ⟨_joined, self | supporter⟩
    · exact False.elim (voterEq self)
    · have earlierSafe :
          forall earlierTerm earlierRecord,
            (state.nodes source).currentTerm < earlierTerm ->
            earlierTerm < targetTerm ->
            elections earlierTerm = some earlierRecord ->
              (state.nodes source).log.take index <+:
                earlierRecord.promotionLog := by
        intro earlierTerm earlierRecord above _ recorded
        exact
          potentialPrefixInElectionRecords
            termsPositive voteFacts ownership electionFacts electedHistory
              activationQuorums
              sourceRole currentEntry currentSignature potential
              earlierTerm earlierRecord recorded above
      apply
        candidateSnapshotContainsProspectivePrefix
          (targetTerm := targetTerm)
          (termsPositive source (by rw [sourceRole]; decide))
          ownership electionFacts
            currentEntry currentSignature voterPrefix
            (prefixRefl (state.nodes candidate).log)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement
                candidate entryIndex entry found)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement voter entryIndex entry found)
            ((canonicalHistoriesMonoLog ownership) voter)
            (candidateEntrySafe := fun entry member =>
              Or.inl (by
                have bounded := entriesBounded candidate entry member
                omega))
      · simpa [
          futureElectionVoters,
          makeRequestVoteRequest,
          lastCommittableIndex_eq_maxCommittableIndex
            (state.nodes candidate) (committedSignature candidate),
          lastCommittableTerm_eq_maxCommittableTerm
            (state.nodes candidate) (committedSignature candidate),
          voteLogUpToDate
        ] using supporter.2
      · exact earlierSafe

/--
A future election quorum on a live evidence authority carries that evidence
into the unchanged candidate log.
-/
lemma prospectiveCommitFutureCandidateOfSharedAuthority
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (committedSignature : CommittedFrontierIsSignature state)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts
      : ProspectiveCommitEvidenceFacts
          state appendHistory nodeEvidence requestEvidence elections)
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (known
      : KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {candidate : Node}
    {targetTerm : Nat}
    {ballotActive : List (Configuration Node)}
    (candidateBefore : (state.nodes candidate).currentTerm < targetTerm)
    (futureMajority : hasFutureElectionMajority state candidate targetTerm ballotActive)
    (authorityActive : evidence.authority ∈ ballotActive)
    : evidence.history.take evidence.commitFrontier <+: (state.nodes candidate).log := by
  have valid := knownCommitEvidenceValid evidenceFacts known
  have electionMajority :=
    futureElectionMajorityAtConfiguration
      futureMajority authorityActive
  rcases
      configurationMajoritiesIntersect
        valid.2.2.2.2.2.1 electionMajority with
    ⟨member, _authorityMember, ackMember, futureMember⟩
  exact
    prospectiveCommitFutureMember
      ownership committedSignature electionFacts evidenceFacts
        prospectiveFacts known candidateBefore ackMember futureMember

/--
On one shared governing configuration, a timeout election intersects a
potential replication quorum in a materialised ACK and transfers its prefix to
the unchanged candidate log.
-/
lemma potentialPrefixInFutureCandidateOfSharedConfiguration
    {state after : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (committedSignature : CommittedFrontierIsSignature state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (currentHistory : AckerCurrentHistory state responseHistory elections)
    (electedHistory : AckerElectionHistory state responseHistory elections)
    (activationQuorums
      : ActivationQuorumFacts state appendHistory responseHistory elections activations)
    {source candidate : Node}
    {index targetTerm : Nat}
    {configuration : Configuration Node}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt after appendHistory responseHistory source index)
    (potentialBack
      : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (sourceConfigurationActive
      : configuration ∈ activeConfigurations (after.nodes source))
    (configurationGoverns : configuration.index <= index)
    (candidateMajority : hasPotentialElectionMajority after candidate)
    (candidateConfigurationActive
      : configuration ∈ activeConfigurations (after.nodes candidate))
    (sourceBefore : (state.nodes source).currentTerm < targetTerm)
    (candidateBefore : (state.nodes candidate).currentTerm < targetTerm)
    (_sourceLogEq : (after.nodes source).log = (state.nodes source).log)
    (sourceTermEq : (after.nodes source).currentTerm = (state.nodes source).currentTerm)
    (effectiveBack
      : forall voter,
          voter ∈ effectiveAckers after responseHistory source index
          -> voter ∈ effectiveAckers state responseHistory source index)
    (electionSubset
      : potentialElectionVoters after candidate
        ⊆ futureElectionVoters state candidate targetTerm)
    (potentialVoterTerm
      : forall voter,
          voter ∈ potentialElectionVoters after candidate
          -> (after.nodes voter).currentTerm = targetTerm)
    : (state.nodes source).log.take index <+: (state.nodes candidate).log := by
  have sourceMajority :=
    potentialMajorityAtConfiguration
      potential sourceConfigurationActive configurationGoverns
  have candidateConfigurationMajority :=
    potentialElectionMajorityAtConfiguration
      candidateMajority candidateConfigurationActive
  rcases
      configurationMajoritiesIntersect
        sourceMajority candidateConfigurationMajority with
    ⟨voter, _configurationMember, potentialMember, electionMember⟩
  have effective :
      voter ∈ effectiveAckers state responseHistory source index := by
    simp only [
      potentialAckers, Finset.mem_filter] at potentialMember
    rcases potentialMember with ⟨_joined, materialised | reserve⟩
    · exact effectiveBack voter materialised
    · have reserveTerm :=
        queuedAppendReservePeerTerm reserve
      have voterTerm := potentialVoterTerm voter electionMember
      omega
  have future :
      voter ∈ futureElectionVoters state candidate targetTerm := by
    exact electionSubset electionMember
  exact
    effectiveAckerFutureCandidateContainsPotentialPrefix
      termsPositive committedSignature entriesBounded voteFacts ownership
        electionFacts currentHistory electedHistory activationQuorums
        sourceRole currentEntry currentSignature
        potentialBack
        sourceBefore candidateBefore effective future

/-- Temporal quorum evidence derives compatibility with every committed log. -/
lemma derivePotentialCommitSafe
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (quorumLog : QuorumLog state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (currentHistory : AckerCurrentHistory state responseHistory elections)
    (electedHistory : AckerElectionHistory state responseHistory elections)
    (activationQuorums
      : ActivationQuorumFacts state appendHistory responseHistory elections activations)
    : PotentialCommitSafe state responseHistory := by
  intro source index role current signature majority committed
  have potential :=
    effectiveMajorityImpliesPotential
      state appendHistory responseHistory source index majority
  rcases
      activationQuorums.committedBridge
        source index role current signature majority committed with
    direct | direct | shared
  · exact Or.inl direct
  · exact Or.inr direct
  · rcases shared with
      ⟨configuration, sourceActive, governs, configurationEq⟩
    have sourceMajority :=
      effectiveMajorityAtConfiguration
        majority sourceActive governs
    rcases
        quorumLog committed configuration configurationEq
          (effectiveAckers state responseHistory source index)
          sourceMajority with
      ⟨voter, _configurationMember, effective, committedPrefix⟩
    have sourcePrefix :=
      effectiveAckerContainsPotentialPrefix
        termsPositive voteFacts ownership electionFacts
          currentHistory electedHistory activationQuorums
          role current signature potential effective
    exact prefixesComparable sourcePrefix committedPrefix

/-- Temporal quorum evidence derives higher-winner containment. -/
lemma derivePotentialCommitElectionSafe
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (committedSignature : CommittedFrontierIsSignature state)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (voteFacts : VoteHistoryFacts state votes)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (canonicalSnapshots
      : GrantedVoteCanonicalSnapshots
          state canonicalHistory voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
    (currentHistory : AckerCurrentHistory state responseHistory elections)
    (voteHistory
      : AckerVoteHistory state votes responseHistory voteVoterHistory elections)
    (electedHistory : AckerElectionHistory state responseHistory elections)
    (activationQuorums
      : ActivationQuorumFacts state appendHistory responseHistory elections activations)
    : PotentialCommitElectionSafe state responseHistory := by
  intro source index role current signature majority winner active newer
  have potential :=
    effectiveMajorityImpliesPotential
      state appendHistory responseHistory source index majority
  rcases active with leader | candidate
  · exact
      potentialPrefixInHigherLeader
        termsPositive voteFacts ownership electionFacts electedHistory
          activationQuorums role current signature potential leader newer
  · exact
      potentialPrefixInHigherCandidate
        termsPositive committedSignature candidatesAbove entriesBounded
          voteFacts snapshots canonicalSnapshots
            ownership electionFacts configurationFacts currentHistory
            voteHistory electedHistory activationQuorums
          role current signature potential candidate.1
            (effectiveElectionMajorityImpliesPotential
              state winner candidate.2)
            newer

/-- Temporal quorum evidence makes any two potential prefixes comparable. -/
lemma derivePotentialCommitsComparable
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (currentHistory : AckerCurrentHistory state responseHistory elections)
    (electedHistory : AckerElectionHistory state responseHistory elections)
    (activationQuorums
      : ActivationQuorumFacts state appendHistory responseHistory elections activations)
    : PotentialCommitsComparable state responseHistory := by
  intro left leftIndex leftRole leftCurrent leftSignature leftMajority
      right rightIndex rightRole rightCurrent rightSignature rightMajority
  have leftPotential :=
    effectiveMajorityImpliesPotential
      state appendHistory responseHistory left leftIndex leftMajority
  have rightPotential :=
    effectiveMajorityImpliesPotential
      state appendHistory responseHistory right rightIndex rightMajority
  rcases
      activationQuorums.potentialBridge
        left leftIndex leftRole leftCurrent leftSignature leftMajority
        right rightIndex rightRole rightCurrent rightSignature rightMajority with
    direct | direct | shared
  · exact Or.inl direct
  · exact Or.inr direct
  · rcases shared with
      ⟨configuration, leftActive, leftGoverns,
        rightActive, rightGoverns⟩
    have leftConfigurationMajority :=
      effectiveMajorityAtConfiguration
        leftMajority leftActive leftGoverns
    have rightConfigurationMajority :=
      effectiveMajorityAtConfiguration
        rightMajority rightActive rightGoverns
    rcases
        configurationMajoritiesIntersect
          leftConfigurationMajority rightConfigurationMajority with
      ⟨voter, _configurationMember, leftMember, rightMember⟩
    have leftPrefix :=
      effectiveAckerContainsPotentialPrefix
        termsPositive voteFacts ownership electionFacts
          currentHistory electedHistory activationQuorums
          leftRole leftCurrent leftSignature leftPotential leftMember
    have rightPrefix :=
      effectiveAckerContainsPotentialPrefix
        termsPositive voteFacts ownership electionFacts
          currentHistory electedHistory activationQuorums
          rightRole rightCurrent rightSignature rightPotential rightMember
    exact prefixesComparable leftPrefix rightPrefix

/-- A successful selected request is exactly the reserve its reply materialises. -/
lemma successfulAppendRequestIsReserve
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    {destination : Node}
    {request : AppendEntriesRequest Node TxId}
    {nextNode : NodeState Node TxId}
    {response : AppendEntriesResponse Node}
    (member : Message.appendEntriesRequest request ∈ state.network destination)
    (requestDestination : request.destination = destination)
    (sourceRole : (state.nodes request.source).role = .leader)
    (requestTerm : request.term = (state.nodes request.source).currentTerm)
    (handled
      : handleAppendEntriesRequest? (state.nodes destination) request
        = some (nextNode, response))
    (success : response.success = true)
    : queuedAppendReserve
        state appendHistory request.source destination
        response.lastLogIndex := by
  rcases handleAppendEntriesRequest_protocolNodeState_some handled with
    ⟨projectedAfter, projectedHandled, _⟩
  refine ⟨
    request,
    member,
    rfl,
    requestDestination,
    requestTerm,
    Or.inl ⟨projectedAfter, response, projectedHandled, success, le_rfl⟩,
    ?_
  ⟩
  exact
    ownership.queuedActiveSourceHistory
      destination request member requestTerm sourceRole

/-- Frame an immutable election history across monotone local changes. -/
lemma electionHistoryFrame
    (state after : View Node TxId)
    (votes afterVotes : VoteHistory Node)
    (canonicalHistory afterCanonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (elections : ElectionHistory Node TxId)
    (facts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (votesPreserved
      : forall term record voter,
          elections term = some record
          -> voter ∈ record.supporters
          -> afterVotes voter term = votes voter term)
    (canonicalMonotone
      : forall term, canonicalHistory term <+: afterCanonicalHistory term)
    (canonicalFrame
      : forall history,
          HistoryCanonical canonicalHistory history
          -> HistoryCanonical afterCanonicalHistory history)
    : ElectionHistoryFacts after afterVotes afterCanonicalHistory owners elections := by
  constructor
  · exact facts.recordOwned
  · exact facts.ownerRecorded
  · exact facts.majority
  · intro term record voter recorded member
    rw [votesPreserved term record voter recorded member]
    exact facts.voted term record voter recorded member
  · intro term record recorded
    exact facts.ballotConfigurations term record recorded
  · exact facts.promotionFromBallot
  · intro term record recorded
    exact (facts.promotionCanonical term record recorded).trans (canonicalMonotone term)
  · exact facts.promotionCommittable
  · exact facts.promotionEntriesBeforeTerm
  · exact facts.candidatePrefix
  · intro term record voter recorded member
    exact
      canonicalFrame _
        (facts.candidateCanonical term record voter recorded member)
  · exact facts.candidateCommittable
  · intro term record voter recorded member
    exact
      canonicalFrame _
        (facts.voterCanonical term record voter recorded member)
  · exact facts.voterCommittable
  · intro term record voter recorded member
    simpa [voteLogUpToDate] using facts.upToDate term record voter recorded member
  · exact facts.termAboveBootstrap

omit [DecidableEq TxId] in
/-- A current node log is canonical under term ownership. -/
lemma nodeLogCanonical
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (node : Node)
    : HistoryCanonical canonicalHistory (state.nodes node).log := by
  intro index entry found
  exact ownership.logEntryAgreement node index entry found

omit [DecidableEq TxId] [Bootstrap Node] in
/-- Frame active vote snapshots across role/evidence restriction and canonical extension. -/
lemma grantedVoteCanonicalFrame
    (state after : View Node TxId)
    (canonicalHistory afterCanonicalHistory : Nat -> List (Entry Node TxId))
    (voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId))
    (facts
      : GrantedVoteCanonicalSnapshots
          state canonicalHistory
          voteCandidateHistory voteVoterHistory)
    (termEq
      : forall candidate,
          ((after.nodes candidate).role = .candidate
            \/ (after.nodes candidate).role = .leader)
          -> (after.nodes candidate).currentTerm = (state.nodes candidate).currentTerm)
    (activeBack
      : forall candidate,
          ((after.nodes candidate).role = .candidate
            \/ (after.nodes candidate).role = .leader)
          -> ((state.nodes candidate).role = .candidate
              \/ (state.nodes candidate).role = .leader))
    (memberBack
      : forall candidate voter,
          ((after.nodes candidate).role = .candidate
            \/ (after.nodes candidate).role = .leader)
          -> voter ∈ effectiveElectionVoters after candidate
          -> voter ∈ effectiveElectionVoters state candidate)
    (canonicalFrame
      : forall history,
          HistoryCanonical canonicalHistory history
          -> HistoryCanonical afterCanonicalHistory history)
    : GrantedVoteCanonicalSnapshots
        after afterCanonicalHistory
        voteCandidateHistory voteVoterHistory := by
  intro candidate voter active member
  rcases
      facts candidate voter
        (activeBack candidate active)
        (memberBack candidate voter active member) with
    self | snapshots
  · exact Or.inl self
  · right
    simpa [termEq candidate active]
      using And.intro
        (canonicalFrame _ snapshots.1)
        (And.intro snapshots.2.1
          (And.intro (canonicalFrame _ snapshots.2.2.1) snapshots.2.2.2))

omit [Bootstrap Node] in
/-- Frame all ACK/election temporal relations when node logs are unchanged. -/
lemma ackerTemporalFrameSameLogs
    (state after : View Node TxId)
    (votes afterVotes : VoteHistory Node)
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (voteVoterHistory : RequestVoteResponse Node -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    (currentFacts : AckerCurrentHistory state responseHistory elections)
    (voteFacts : AckerVoteHistory state votes responseHistory voteVoterHistory elections)
    (electionFacts : AckerElectionHistory state responseHistory elections)
    (roleBack
      : forall source,
          (after.nodes source).role = .leader -> (state.nodes source).role = .leader)
    (sourceTermEq
      : forall source,
          (after.nodes source).role = .leader
          -> (after.nodes source).currentTerm = (state.nodes source).currentTerm)
    (logEq : forall node, (after.nodes node).log = (state.nodes node).log)
    (effectiveBack
      : forall source index voter,
          (after.nodes source).role = .leader
          -> termAt (after.nodes source).log index = (after.nodes source).currentTerm
          -> voter ∈ effectiveAckers after responseHistory source index
          -> voter ∈ effectiveAckers state responseHistory source index)
    (termMonotone
      : forall node, (state.nodes node).currentTerm <= (after.nodes node).currentTerm)
    (voteBack
      : forall voter voteTerm candidate,
          afterVotes voter voteTerm = some candidate
          -> Not (voter = candidate)
          -> votes voter voteTerm = some candidate)
    : AckerCurrentHistory after responseHistory elections
      /\ AckerVoteHistory after afterVotes responseHistory voteVoterHistory elections
      /\ AckerElectionHistory after responseHistory elections := by
  have prefixEq :
      forall source index,
        (after.nodes source).log.take index =
          (state.nodes source).log.take index := by
    intro source index
    rw [logEq]
  constructor
  · intro source index role current signature voter effective
    have oldRole := roleBack source role
    have oldTerm :
        (after.nodes source).currentTerm =
          (state.nodes source).currentTerm :=
      sourceTermEq source role
    have oldCurrent :
        termAt (state.nodes source).log index =
          (state.nodes source).currentTerm := by
      simpa [logEq, oldTerm] using current
    have oldSignature :
        isSignatureAt (state.nodes source).log index = true := by
      simpa [logEq] using signature
    rcases
        currentFacts source index oldRole oldCurrent oldSignature voter
          (effectiveBack source index voter role current effective) with
      retained | bad
    · exact Or.inl (by simpa [logEq, prefixEq] using retained)
    · right
      rcases bad with
        ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
      exact ⟨
        badTerm,
        badRecord,
        by simpa [oldTerm] using above,
        Nat.le_trans bounded (termMonotone voter),
        recorded,
        by simpa [prefixEq] using missing
      ⟩
  · constructor
    · intro source index role current signature
        voter voteTerm candidate effective voted different newer
      have oldRole := roleBack source role
      have oldTerm :
          (after.nodes source).currentTerm =
            (state.nodes source).currentTerm :=
        sourceTermEq source role
      have oldCurrent :
          termAt (state.nodes source).log index =
            (state.nodes source).currentTerm := by
        simpa [logEq, oldTerm] using current
      have oldSignature :
          isSignatureAt (state.nodes source).log index = true := by
        simpa [logEq] using signature
      have oldEffective :=
        effectiveBack source index voter role current effective
      have oldVoted := voteBack voter voteTerm candidate voted different
      have oldNewer :
          (state.nodes source).currentTerm < voteTerm := by
        simpa [oldTerm] using newer
      rcases
          voteFacts source index oldRole oldCurrent oldSignature
            voter voteTerm candidate oldEffective oldVoted different oldNewer with
        retained | bad
      · exact Or.inl (by simpa [prefixEq] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
        exact ⟨
          badTerm,
          badRecord,
          by simpa [oldTerm] using above,
          bounded,
          recorded,
          by simpa [prefixEq] using missing
        ⟩
    · intro source index role current signature term record voter
        recorded member effective newer
      have oldRole := roleBack source role
      have oldTerm :
          (after.nodes source).currentTerm =
            (state.nodes source).currentTerm :=
        sourceTermEq source role
      have oldCurrent :
          termAt (state.nodes source).log index =
            (state.nodes source).currentTerm := by
        simpa [logEq, oldTerm] using current
      have oldSignature :
          isSignatureAt (state.nodes source).log index = true := by
        simpa [logEq] using signature
      have oldEffective :=
        effectiveBack source index voter role current effective
      have oldNewer :
          (state.nodes source).currentTerm < term := by
        simpa [oldTerm] using newer
      rcases
          electionFacts source index oldRole oldCurrent oldSignature
            term record voter recorded member oldEffective oldNewer with
        retained | bad
      · exact Or.inl (by simpa [prefixEq] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, below, badRecorded, missing⟩
        exact ⟨
          badTerm,
          badRecord,
          by simpa [oldTerm] using above,
          below,
          badRecorded,
          by simpa [prefixEq] using missing
        ⟩

omit [Bootstrap Node] in
/-- Frame ACK-to-activation chronology when source logs are unchanged. -/
lemma ackerActivationFrameSameLogs
    (state after : View Node TxId)
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (elections afterElections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    (facts : AckerActivationHistory state responseHistory elections activations)
    (roleBack
      : forall source,
          (after.nodes source).role = .leader -> (state.nodes source).role = .leader)
    (sourceTermEq
      : forall source,
          (after.nodes source).role = .leader
          -> (after.nodes source).currentTerm = (state.nodes source).currentTerm)
    (logEq : forall node, (after.nodes node).log = (state.nodes node).log)
    (effectiveBack
      : forall source index supporter,
          (after.nodes source).role = .leader
          -> termAt (after.nodes source).log index = (after.nodes source).currentTerm
          -> supporter ∈ effectiveAckers after responseHistory source index
          -> supporter ∈ effectiveAckers state responseHistory source index)
    (electionPreserved
      : forall term record,
          elections term = some record -> afterElections term = some record)
    : AckerActivationHistory after responseHistory afterElections activations := by
  intro source index role current signature
      activationIndex activation configuration supporter
      activationStored governing activationSupporter effective later
  have oldRole := roleBack source role
  have termEq := sourceTermEq source role
  have oldCurrent :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm := by
    simpa [logEq, termEq] using current
  have oldSignature :
      isSignatureAt (state.nodes source).log index = true := by
    simpa [logEq] using signature
  have oldEffective :=
    effectiveBack source index supporter role current effective
  have oldLater :
      (state.nodes source).currentTerm <
        activation.activationTerm := by
    simpa [termEq] using later
  rcases
      facts source index oldRole oldCurrent oldSignature
        activationIndex activation configuration supporter
        activationStored governing activationSupporter oldEffective oldLater with
    retained | bad
  · exact Or.inl (by simpa [logEq] using retained)
  · right
    rcases bad with
      ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
    exact ⟨
      badTerm,
      badRecord,
      by simpa [termEq] using above,
      bounded,
      electionPreserved badTerm badRecord recorded,
      by simpa [logEq] using missing
    ⟩

/-- Any request which can still acknowledge an index carries entries through it. -/
lemma canProduceAppendAckAt_index_le_requestEnd
    {node : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {index : Nat}
    (producible : canProduceAppendAckAt node request index)
    : index <= request.prevLogIndex + request.entries.length := by
  rcases producible with
    ⟨nextNode, response, handled, success, acknowledged⟩
  have exactIndex :=
    (handleAppendEntriesRequestLocalPost handled).successfulIndexExact
      success
  omega

/-- Every direct or prepared reserve is bounded by its immutable request tail. -/
lemma canProduceAppendAckEventuallyAt_index_le_requestEnd
    {node : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {index : Nat}
    (producible : canProduceAppendAckEventuallyAt node request index)
    : index <= request.prevLogIndex + request.entries.length := by
  rcases producible with direct | prepared
  · exact canProduceAppendAckAt_index_le_requestEnd direct
  · exact prepared.2

/-- Only a follower can directly produce a successful ACK. -/
lemma canProduceAppendAckAt_role
    {node : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {index : Nat}
    (producible : canProduceAppendAckAt node request index)
    : node.role = .follower := by
  rcases producible with
    ⟨nextNode, response, handled, success, _⟩
  unfold handleAppendEntriesRequest? at handled
  split at handled
  · rename_i rejectedState rejectedResponse rejected
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · have pairEq :=
        (Option.some.inj rejected).trans (Option.some.inj handled)
      have responseEq := congrArg Prod.snd pairEq
      dsimp at responseEq
      subst response
      have failed :=
        (failureResponseMetadata (protocolNodeState node) request).2.2
      rw [failed] at success
      contradiction
    · contradiction
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · rename_i accepted
      simpa [protocolNodeState] using accepted.2.1
    · contradiction

omit [DecidableEq TxId] [Bootstrap Node] in
/-- FIFO enqueue never removes an existing queued message. -/
lemma memEnqueueNoDupOfMem
    (network : Node -> List (Message Node TxId))
    (newMessage message : Message Node TxId)
    (destination : Node)
    (member : message ∈ network destination)
    : message ∈ enqueue network newMessage destination := by
  unfold enqueue
  by_cases destinationEq : destination = newMessage.destination
  · subst destination
    simp only [updateQueue, Function.update_self, List.mem_append, List.mem_singleton]
    exact Or.inl member
  · simpa only [updateQueue, Function.update_of_ne destinationEq] using member

/--
Sending AppendEntries can add only the request destination to a potential
support set. The new support is tied to the exact source-log snapshot and
cannot acknowledge beyond the immutable request tail.
-/
lemma appendEntriesPotentialAckerDelta
    (state : View Node TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
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
    {leader peer : Node}
    {index : Nat}
    (member
      : peer
        ∈ potentialAckers
            (appendEntriesEffect state source destination batchEnd)
            (Function.update appendHistory
              (makeAppendEntriesRequest state source destination batchEnd)
              (state.nodes source).log)
            responseHistory leader index)
    : peer ∈ potentialAckers state appendHistory responseHistory leader index
      \/ (leader = source
          /\ peer = destination
          /\ index
              <= (makeAppendEntriesRequest state source destination batchEnd).prevLogIndex
                  + (makeAppendEntriesRequest
                      state source destination batchEnd).entries.length
          /\ (Function.update appendHistory
                (makeAppendEntriesRequest state source destination batchEnd)
                (state.nodes source).log)
                (makeAppendEntriesRequest state source destination batchEnd)
              = (state.nodes source).log
          /\ (makeAppendEntriesRequest state source destination batchEnd).term
              = (state.nodes source).currentTerm) := by
  let request :=
    makeAppendEntriesRequest state source destination batchEnd
  let newAppendHistory :=
    Function.update appendHistory request (state.nodes source).log
  have currentTermEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases same : node = source <;>
      simp [view_effects, view_effects, updateNode, same]
  have logEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).log =
          (state.nodes node).log := by
    intro node
    by_cases same : node = source <;>
      simp [view_effects, view_effects, updateNode, same]
  have matchEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).matchIndex =
          (state.nodes node).matchIndex := by
    intro node
    by_cases same : node = source <;>
      simp [view_effects, view_effects, updateNode, same]
  simp only [
    potentialAckers, Finset.mem_filter] at member ⊢
  rcases member with ⟨joined, effective | reserve⟩
  · left
    refine ⟨joined, ?_⟩
    left
    simp only [
      effectiveAckers, Finset.mem_filter] at effective ⊢
    rcases effective with ⟨_effectiveJoined, self | matched | queued⟩
    · exact ⟨joined, Or.inl self⟩
    · exact ⟨joined, Or.inr (Or.inl (by simpa [matchEq] using matched))⟩
    · refine ⟨joined, Or.inr (Or.inr ?_)⟩
      rcases queued with
        ⟨response, queued, success, term, responseSource,
          responseDestination, acknowledged, covered⟩
      have oldQueued :
          Message.appendEntriesResponse response ∈
            state.network leader := by
        rcases
            memEnqueue
              state.network (.appendEntriesRequest request)
                (.appendEntriesResponse response) leader
                (by simpa [view_effects, view_effects, request] using queued) with
          old | new
        · exact old
        · simp at new
      exact ⟨
        response,
        oldQueued,
        success,
        by simpa [currentTermEq] using term,
        responseSource,
        responseDestination,
        acknowledged,
        by simpa [logEq] using covered
      ⟩
  · rcases reserve with
      ⟨queuedRequest, queued, requestSource, requestDestination,
        requestTerm, producible, covered⟩
    by_cases sameRequest : queuedRequest = request
    · subst queuedRequest
      right
      have leaderEq : leader = source := by
        simpa [request, makeAppendEntriesRequest] using requestSource.symm
      have peerEq : peer = destination := by
        simpa [request, makeAppendEntriesRequest] using requestDestination.symm
      exact ⟨
        leaderEq,
        peerEq,
        canProduceAppendAckEventuallyAt_index_le_requestEnd producible,
        by simp [],
        by simp [ makeAppendEntriesRequest]
      ⟩
    · left
      refine ⟨joined, Or.inr ?_⟩
      have requestDestinationEq := requestDestination
      have oldProducible :
          canProduceAppendAckEventuallyAt
            (state.nodes peer) queuedRequest index := by
        rcases producible with direct | future
        · by_cases peerEq : peer = source
          · have destinationEq :
                queuedRequest.destination = source :=
              requestDestinationEq.trans peerEq
            have follower := canProduceAppendAckAt_role direct
            have leaderRole :
                ((appendEntriesEffect state source destination batchEnd).nodes
                  source).role = .leader := by
              simpa [view_effects, view_effects] using enabled.2.2.1
            rw [peerEq, leaderRole] at follower
            contradiction
          · exact Or.inl (by
              simpa [
                view_effects, view_effects, updateNode,
                Function.update, peerEq
              ] using direct)
        · exact Or.inr (by simpa [currentTermEq] using future)
      have oldQueued :
          Message.appendEntriesRequest queuedRequest ∈
            state.network peer := by
        rcases
            memEnqueue
              state.network (.appendEntriesRequest request)
                (.appendEntriesRequest queuedRequest) peer
                (by simpa [view_effects, view_effects, request] using queued) with
          old | new
        · exact old
        · simp at new
          exact False.elim (sameRequest new.2)
      exact ⟨
        queuedRequest,
        oldQueued,
        requestSource,
        requestDestination,
        by simpa [currentTermEq] using requestTerm,
        oldProducible,
        by simpa [
            newAppendHistory, request, Function.update, sameRequest,
            logEq
          ] using covered
      ⟩

/-- Existing potential AppendEntries support survives a send action. -/
lemma appendEntriesPotentialAckersMonotone
    (state : View Node TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
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
    (leader : Node)
    (index : Nat)
    : potentialAckers state appendHistory responseHistory leader index
      ⊆ potentialAckers
          (appendEntriesEffect state source destination batchEnd)
          (Function.update appendHistory
            (makeAppendEntriesRequest state source destination batchEnd)
            (state.nodes source).log)
          responseHistory leader index := by
  let request :=
    makeAppendEntriesRequest state source destination batchEnd
  let newAppendHistory :=
    Function.update appendHistory request (state.nodes source).log
  have currentTermEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases same : node = source <;>
      simp [view_effects, view_effects, updateNode, same]
  have logEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).log =
          (state.nodes node).log := by
    intro node
    by_cases same : node = source <;>
      simp [view_effects, view_effects, updateNode, same]
  have matchEq :
      forall node,
        ((appendEntriesEffect state source destination batchEnd).nodes node).matchIndex =
          (state.nodes node).matchIndex := by
    intro node
    by_cases same : node = source <;>
      simp [view_effects, view_effects, updateNode, same]
  intro peer member
  simp only [
    potentialAckers, Finset.mem_filter] at member ⊢
  rcases member with ⟨joined, effective | reserve⟩
  · refine ⟨by simpa [view_effects, view_effects] using joined, ?_⟩
    left
    simp only [
      effectiveAckers, Finset.mem_filter] at effective ⊢
    rcases effective with ⟨_effectiveJoined, self | matched | queued⟩
    · exact ⟨by simpa [view_effects, view_effects] using joined, Or.inl self⟩
    · exact ⟨
        by simpa [view_effects, view_effects] using joined,
        Or.inr (Or.inl (by simpa [matchEq] using matched))
      ⟩
    · refine ⟨
        by simpa [view_effects, view_effects] using joined,
        Or.inr (Or.inr ?_)
      ⟩
      rcases queued with
        ⟨response, queued, success, term, responseSource,
          responseDestination, acknowledged, covered⟩
      exact ⟨
        response,
        by
          simpa [view_effects, view_effects, request]
            using memEnqueueNoDupOfMem
              state.network (.appendEntriesRequest request)
              (.appendEntriesResponse response) leader queued,
        success,
        by simpa [currentTermEq] using term,
        responseSource,
        responseDestination,
        acknowledged,
        by simpa [logEq] using covered
      ⟩
  · refine ⟨by simpa [view_effects, view_effects] using joined, ?_⟩
    right
    rcases reserve with
      ⟨queuedRequest, queued, requestSource, requestDestination,
        requestTerm, producible, covered⟩
    have requestDestinationEq := requestDestination
    have newProducible :
        canProduceAppendAckEventuallyAt
          ((appendEntriesEffect state source destination batchEnd).nodes peer)
          queuedRequest index := by
      rcases producible with direct | future
      · by_cases peerEq : peer = source
        · have destinationEq :
              queuedRequest.destination = source :=
            requestDestinationEq.trans peerEq
          have follower := canProduceAppendAckAt_role direct
          rw [peerEq, enabled.2.2.1] at follower
          contradiction
        · exact Or.inl (by
            simpa [
              view_effects, view_effects, updateNode,
              Function.update, peerEq
            ] using direct)
      · exact Or.inr (by simpa [currentTermEq] using future)
    refine ⟨
      queuedRequest,
      by
        simpa [view_effects, view_effects, request]
          using memEnqueueNoDupOfMem
            state.network (.appendEntriesRequest request)
            (.appendEntriesRequest queuedRequest) peer queued,
      requestSource,
      requestDestination,
      by simpa [currentTermEq] using requestTerm,
      newProducible,
      ?_
    ⟩
    by_cases sameRequest : queuedRequest = request
    · subst queuedRequest
      have leaderEq : leader = source := by
        simpa [request, makeAppendEntriesRequest] using requestSource.symm
      subst leader
      have requestSourceEq : request.source = source := by
        simp [request, makeAppendEntriesRequest]
      change (Function.update appendHistory request (state.nodes source).log) request
      <+: ((appendEntriesEffect state source destination batchEnd).nodes
            request.source).log
      simp only [Function.update_self]
      rw [logEq, requestSourceEq]
    · simpa [
        newAppendHistory, request, Function.update, sameRequest,
        logEq
      ] using covered

/--
Configuration-qualified send delta: a new potential majority is either an old
majority, or the destination is its unique essential new supporter.
-/
lemma appendEntriesPotentialMajorityDeltaAtConfiguration
    (state : View Node TxId)
    (source destination : Node)
    (batchEnd : Nat)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
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
    (leader : Node)
    (index : Nat)
    (configuration : Configuration Node)
    (afterMajority
      : hasConfigurationMajority
          (potentialAckers
            (appendEntriesEffect state source destination batchEnd)
            (Function.update appendHistory
              (makeAppendEntriesRequest state source destination batchEnd)
              (state.nodes source).log)
            responseHistory leader index)
          configuration)
    : hasConfigurationMajority
        (potentialAckers state appendHistory responseHistory leader index)
        configuration
      \/ (leader = source
          /\ destination ∈ configuration.nodes
          /\ destination
              ∈ potentialAckers
                  (appendEntriesEffect state source destination batchEnd)
                  (Function.update appendHistory
                    (makeAppendEntriesRequest state source destination batchEnd)
                    (state.nodes source).log)
                  responseHistory leader index
          /\ destination
              ∉ potentialAckers state appendHistory responseHistory leader index
          /\ potentialAckers
                (appendEntriesEffect state source destination batchEnd)
                (Function.update appendHistory
                  (makeAppendEntriesRequest state source destination batchEnd)
                  (state.nodes source).log)
                responseHistory leader index
              = insert destination
                  (potentialAckers state appendHistory responseHistory leader index)
          /\ ((potentialAckers
                  (appendEntriesEffect state source destination batchEnd)
                  (Function.update appendHistory
                    (makeAppendEntriesRequest state source destination batchEnd)
                    (state.nodes source).log)
                  responseHistory leader index)
                ∩ configuration.nodes).card
              = ((potentialAckers state appendHistory responseHistory leader index)
                  ∩ configuration.nodes).card
                + 1
          /\ Not
              (hasConfigurationMajority
                ((potentialAckers
                    (appendEntriesEffect state source destination batchEnd)
                    (Function.update appendHistory
                      (makeAppendEntriesRequest state source destination batchEnd)
                      (state.nodes source).log)
                    responseHistory leader index).erase
                  destination)
                configuration)) := by
  let before :=
    potentialAckers
      state appendHistory responseHistory leader index
  let after :=
    potentialAckers
      (appendEntriesEffect state source destination batchEnd)
      (Function.update appendHistory
        (makeAppendEntriesRequest state source destination batchEnd)
        (state.nodes source).log)
      responseHistory leader index
  by_cases oldMajority :
      hasConfigurationMajority before configuration
  · exact Or.inl oldMajority
  · have beforeSubset : before ⊆ after := by
      exact
        appendEntriesPotentialAckersMonotone
          state source destination batchEnd appendHistory responseHistory
            enabled leader index
    have afterSubset : after ⊆ insert destination before := by
      intro peer member
      rcases
          appendEntriesPotentialAckerDelta
            state source destination batchEnd appendHistory responseHistory
              enabled member with
        old | added
      · exact Finset.mem_insert_of_mem old
      · simp [added.2.1]
    rcases
        configurationMajorityOneNodeDelta
          beforeSubset afterSubset afterMajority oldMajority with
      ⟨configurationMember, afterMember, beforeMissing,
        afterEq, cardEq, essential⟩
    have leaderEq : leader = source := by
      rcases
          appendEntriesPotentialAckerDelta
            state source destination batchEnd appendHistory responseHistory
              enabled afterMember with
        old | added
      · exact False.elim (beforeMissing old)
      · exact added.1
    exact
      Or.inr
        ⟨leaderEq, configurationMember, afterMember, beforeMissing,
          afterEq, cardEq, essential⟩

/-- A queued reserve cannot acknowledge beyond its immutable leader history. -/
lemma queuedAppendReserve_index_le_leaderLog
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    (requestFacts
      : forall destination request,
          Message.appendEntriesRequest request ∈ state.network destination
          -> RequestSnapshots (appendHistory request) request)
    {leader peer : Node}
    {index : Nat}
    (reserve : queuedAppendReserve state appendHistory leader peer index)
    : index <= (state.nodes leader).log.length := by
  rcases reserve with
    ⟨request, queued, _source, requestDestination, _term,
      producible, covered⟩
  have requestBound :=
    (requestFacts peer request
      (by simpa [requestDestination] using queued)).1
  have acknowledged :=
    canProduceAppendAckEventuallyAt_index_le_requestEnd producible
  have historyBound := covered.length_le
  omega

omit [DecidableEq TxId] [Bootstrap Node] in
/--
An active leader has no effective quorum beyond its log: processed cursors are
bounded, while queued ACKs carry a bounded history prefix of that same log.
-/
lemma effectiveAckersBeyondLeaderLog
    {state : View Node TxId}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    (progress : LeaderProgressBounded state)
    (responseSafe
      : forall destination response,
          Message.appendEntriesResponse response ∈ state.network destination
          -> SuccessfulResponseSnapshot state (responseHistory response) response)
    {leader : Node}
    (role : (state.nodes leader).role = .leader)
    {index : Nat}
    (beyond : (state.nodes leader).log.length < index)
    {peer : Node}
    (member : peer ∈ effectiveAckers state responseHistory leader index)
    : peer = leader := by
  simp only [
    effectiveAckers, Finset.mem_filter] at member
  rcases member with ⟨_joined, self | matched | queued⟩
  · exact self
  · have bounded := (progress leader role peer).2
    omega
  · rcases queued with
      ⟨response, queued, success, _, _, _, _, covered⟩
    have responseBound := (responseSafe leader response queued success).1
    have historyBound := covered.length_le
    omega

/--
At an index beyond an active leader's current log, neither a processed/queued
ACK nor a queued request reserve can contribute. Only the leader's self-ACK
remains.
-/
lemma potentialAckersBeyondLeaderLog
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {voteRequestHistory : RequestVoteRequest Node -> List (Entry Node TxId)}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    (progress : LeaderProgressBounded state)
    (networkFacts
      : NetworkHistoryFacts
          state appendHistory responseHistory
          voteRequestHistory voteCandidateHistory voteVoterHistory votes)
    {leader : Node}
    (role : (state.nodes leader).role = .leader)
    {index : Nat}
    (beyond : (state.nodes leader).log.length < index)
    {peer : Node}
    (member : peer ∈ potentialAckers state appendHistory responseHistory leader index)
    : peer = leader := by
  simp only [
    potentialAckers, Finset.mem_filter] at member
  rcases member with ⟨_joined, effective | reserve⟩
  · exact
      effectiveAckersBeyondLeaderLog
        progress networkFacts.appendResponse role beyond effective
  · have bounded :=
      queuedAppendReserve_index_le_leaderLog
        (fun destination request queued =>
          (networkFacts.appendRequest destination request queued).1)
        reserve
    omega

omit [Bootstrap Node] in
/-- Enqueue-with-deduplication contains the message being enqueued. -/
lemma memEnqueueNoDupSelf
    (network : Node -> List (Message Node TxId))
    (message : Message Node TxId)
    : message ∈ enqueue network message message.destination := by
  unfold enqueue
  by_cases duplicate : message ∈ network message.destination
  · simp []
  · simp [ updateQueue]

omit [Bootstrap Node] in
lemma memSelectedOrRemaining
    {source : Node} {queue remaining : List (Message Node TxId)}
    {selected message : Message Node TxId}
    (taken : Selected source queue selected remaining) (member : message ∈ queue)
    : message = selected ∨ message ∈ remaining := by
  by_cases same : message = selected
  · exact Or.inl same
  · exact Or.inr (taken.2.2 ▸ (List.mem_erase_of_ne same).mpr member)

end CCFRaft.Proofs.Invariant
