-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Frames
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

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- A successful one-based lookup identifies an entry in the underlying log. -/
lemma entryAtSomeMember
    {log : List (Entry Node TxId)}
    {index : Nat}
    {entry : Entry Node TxId}
    (found : entryAt? log index = some entry)
    : entry ∈ log := by
  unfold entryAt? at found
  split at found
  · simp at found
  · rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, valueEq⟩
    have member : log[index - 1] ∈ log :=
      List.getElem_mem within
    rw [valueEq] at member
    exact member

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Membership exposes a positive one-based lookup. -/
lemma memberEntryAt
    {log : List (Entry Node TxId)}
    {entry : Entry Node TxId}
    (member : entry ∈ log)
    : Exists fun index => entryAt? log index = some entry := by
  rcases List.mem_iff_get.mp member with ⟨index, found⟩
  refine ⟨index.val + 1, ?_⟩
  unfold entryAt?
  simp only [Nat.add_eq_zero_iff, one_ne_zero, and_false, ↓reduceIte]
  rw [List.getElem?_eq_some_iff]
  exact ⟨by omega, by simpa using found⟩

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Every positive in-bounds one-based index has a concrete entry. -/
lemma entryAtSomeOfPositiveBound
    {log : List (Entry Node TxId)}
    {index : Nat}
    (positive : 0 < index)
    (within : index <= log.length)
    : Exists fun entry => entryAt? log index = some entry := by
  refine ⟨log[index - 1], ?_⟩
  unfold entryAt?
  simp only [positive.ne', ↓reduceIte]
  rw [List.getElem?_eq_some_iff]
  exact ⟨by omega, rfl⟩

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Taking beyond a one-based lookup leaves that lookup unchanged. -/
lemma entryAtTake_of_le
    {log : List (Entry Node TxId)}
    {index count : Nat}
    (within : index <= count)
    : entryAt? (log.take count) index = entryAt? log index := by
  by_cases zero : index = 0
  · simp [entryAt?, zero]
  · unfold entryAt?
    simp only [zero, ↓reduceIte]
    rw [List.getElem?_take]
    split
    · rfl
    · omega

lemma knownEvidenceFrontierCanonical
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
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
    : evidence.history.take evidence.commitFrontier
      = (canonicalHistory evidence.commitTerm).take evidence.commitFrontier := by
  have valid := knownCommitEvidenceValid evidenceFacts known
  have supportedPositive :=
    knownCommitEvidenceSupportedLengthPositive evidenceFacts known
  have frontierPositive : 0 < evidence.commitFrontier :=
    supportedPositive.trans_le valid.2.2.1
  rcases
      entryAtSomeOfPositiveBound frontierPositive valid.1 with
    ⟨frontierEntry, historyFound⟩
  have frontierEntryTerm :
      frontierEntry.term = evidence.commitTerm := by
    simpa [termAt, historyFound] using valid.2.1
  rcases
      configurationMajorityNonempty valid.2.2.2.2.2.1 with
    ⟨member, _authorityMember, ackMember⟩
  have memberCovered :=
    prospectiveFacts.currentMember
      evidence supportedPrefix known member ackMember
  have prefixLength :
      (evidence.history.take evidence.commitFrontier).length =
        evidence.commitFrontier := by
    simp [Nat.min_eq_left valid.1]
  have prefixFound :
      entryAt?
          (evidence.history.take evidence.commitFrontier)
          evidence.commitFrontier =
        some frontierEntry := by
    rw [entryAtTake_of_le le_rfl]
    exact historyFound
  have memberFound :
      entryAt? (state.nodes member).log evidence.commitFrontier =
        some frontierEntry :=
    entryAt_of_prefix memberCovered prefixFound
  have memberAgreed :=
    (ownership.logEntryAgreement
      member evidence.commitFrontier frontierEntry memberFound).2
  calc
    evidence.history.take evidence.commitFrontier
        = (state.nodes member).log.take evidence.commitFrontier := by
      have covered := prefixEqTake memberCovered
      rw [prefixLength] at covered
      exact covered.symm
    _ = (canonicalHistory frontierEntry.term).take evidence.commitFrontier :=
      memberAgreed
    _ = (canonicalHistory evidence.commitTerm).take evidence.commitFrontier := by
      rw [frontierEntryTerm]

omit [Bootstrap Node] in
/-- Every effective ACK supporter has advanced to at least the ACKed term. -/
lemma effectiveAckerCurrentTermBound
    {state : View Node TxId}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {elections : ElectionHistory Node TxId}
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (currentHistory : AckerCurrentHistory state responseHistory elections)
    {leader supporter : Node}
    {frontier : Nat}
    (leaderRole : (state.nodes leader).role = .leader)
    (frontierTerm
      : termAt (state.nodes leader).log frontier = (state.nodes leader).currentTerm)
    (frontierSignature : isSignatureAt (state.nodes leader).log frontier = true)
    (member : supporter ∈ effectiveAckers state responseHistory leader frontier)
    : (state.nodes leader).currentTerm <= (state.nodes supporter).currentTerm := by
  rcases
      currentHistory leader frontier leaderRole frontierTerm
        frontierSignature supporter member with
    retained | bad
  · rcases isSignatureAtTrue frontierSignature with
      ⟨entry, found, _signature⟩
    have entryTerm :
        entry.term = (state.nodes leader).currentTerm := by
      simpa [termAt, found] using frontierTerm
    have prefixFound :
        entryAt?
            ((state.nodes leader).log.take frontier)
            frontier =
          some entry := by
      rw [entryAtTake_of_le le_rfl]
      exact found
    have supporterFound :=
      entryAt_of_prefix retained prefixFound
    simpa [entryTerm]
      using entriesBounded supporter entry (entryAtSomeMember supporterFound)
  · rcases bad with
      ⟨badTerm, _record, above, bounded, _recorded, _missing⟩
    exact (Nat.le_of_lt above).trans bounded

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Taking beyond an index leaves its term lookup unchanged. -/
lemma termAtTakeOfLe
    {log : List (Entry Node TxId)}
    {index count : Nat}
    (within : index <= count)
    : termAt (log.take count) index = termAt log index := by
  unfold termAt
  rw [entryAtTake_of_le within]

omit [Bootstrap Node] in
/-- Taking through the latest signature retains exactly that committable index. -/
lemma maxCommittableIndexTakeMax (log : List (Entry Node TxId))
    : maxCommittableIndex (log.take (maxCommittableIndex log))
      = maxCommittableIndex log := by
  by_cases zero : maxCommittableIndex log = 0
  · rw [zero]
    rfl
  apply Nat.le_antisymm
  · exact (maxCommittableIndexBounded (log.take (maxCommittableIndex log))).trans
      (by simp)
  · exact
      signatureIndex_le_maxCommittableIndex
        (isSignatureAt_take_of_le le_rfl
          (maxCommittableIndexPositiveIsSignature
            (Nat.pos_of_ne_zero zero)))

omit [Bootstrap Node] in
/-- Taking through the latest signature retains its committable term. -/
lemma maxCommittableTermTakeMax (log : List (Entry Node TxId))
    : maxCommittableTerm (log.take (maxCommittableIndex log))
      = maxCommittableTerm log := by
  unfold maxCommittableTerm
  rw [maxCommittableIndexTakeMax]
  exact termAtTakeOfLe le_rfl

omit [Bootstrap Node] in
/-- An exact committable snapshot lies inside the larger log's signature prefix. -/
lemma committablePrefixOfMaxTake
    {snapshot log : List (Entry Node TxId)}
    (isPrefix : snapshot <+: log)
    (snapshotCommittable : maxCommittableIndex snapshot = snapshot.length)
    : snapshot <+: log.take (maxCommittableIndex log) := by
  have lengthBound :
      snapshot.length <= maxCommittableIndex log := by
    rw [← snapshotCommittable]
    exact maxCommittableIndex_le_of_prefix isPrefix
  rw [List.prefix_iff_eq_take]
  calc
    snapshot = log.take snapshot.length := (prefixEqTake isPrefix).symm
    _ = (log.take (maxCommittableIndex log)).take snapshot.length := by
      simp [List.take_take, Nat.min_eq_left lengthBound]

omit [Bootstrap Node] in
/-- A prefix ending in a signature lies inside the larger log's signature prefix. -/
lemma signatureEndedPrefixOfMaxTake
    {snapshot log : List (Entry Node TxId)}
    (isPrefix : snapshot <+: log)
    (signature : isSignatureAt snapshot snapshot.length = true)
    : snapshot <+: log.take (maxCommittableIndex log) := by
  apply committablePrefixOfMaxTake isPrefix
  apply Nat.le_antisymm
  · exact maxCommittableIndexBounded snapshot
  · exact signatureIndex_le_maxCommittableIndex signature

omit [Bootstrap Node] in
/-- Taking through a known signature produces a prefix ending at that signature. -/
lemma signatureAtTakeLength
    {log : List (Entry Node TxId)}
    {index : Nat}
    (signature : isSignatureAt log index = true)
    : isSignatureAt (log.take index) (log.take index).length = true := by
  have indexBound : index <= log.length := by
    rcases isSignatureAtTrue signature with ⟨entry, found, _⟩
    exact entryAtSomeIndexBound found
  simpa [List.length_take, Nat.min_eq_left indexBound]
    using isSignatureAt_take_of_le le_rfl signature

omit [DecidableEq TxId] in
/-- Extract one governing configuration's processed replication majority. -/
lemma majorityAtConfiguration
    {state : View Node TxId}
    {leader : Node}
    {index : Nat}
    (majority : hasMajorityAt state leader index)
    {configuration : Configuration Node}
    (active : configuration ∈ activeConfigurations (state.nodes leader))
    (governs : configuration.index <= index)
    : hasConfigurationMajority (acknowledgingNodes state leader index) configuration := by
  rw [hasMajorityAt, List.all_eq_true] at majority
  exact (of_decide_eq_true (majority configuration active)) governs

omit [DecidableEq TxId] in
/-- Extract one governing configuration's effective replication majority. -/
lemma effectiveMajorityAtConfiguration
    {state : View Node TxId}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {leader : Node}
    {index : Nat}
    (majority : hasEffectiveMajorityAt state responseHistory leader index)
    {configuration : Configuration Node}
    (active : configuration ∈ activeConfigurations (state.nodes leader))
    (governs : configuration.index <= index)
    : hasConfigurationMajority
        (effectiveAckers state responseHistory leader index)
        configuration := by
  rw [hasEffectiveMajorityAt, List.all_eq_true] at majority
  exact (of_decide_eq_true (majority configuration active)) governs

/-- Extract one active configuration's potential replication majority. -/
lemma potentialMajorityAtConfiguration
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {leader : Node}
    {index : Nat}
    (majority : hasPotentialMajorityAt state appendHistory responseHistory leader index)
    {configuration : Configuration Node}
    (active : configuration ∈ activeConfigurations (state.nodes leader))
    (governs : configuration.index <= index)
    : hasConfigurationMajority
        (potentialAckers state appendHistory responseHistory leader index)
        configuration := by
  rw [hasPotentialMajorityAt, List.all_eq_true] at majority
  exact (of_decide_eq_true (majority configuration active)) governs

omit [DecidableEq TxId] in
/-- Extract one active configuration's processed election majority. -/
lemma electionMajorityAtConfiguration
    {state : View Node TxId}
    {candidate : Node}
    (majority : hasElectionMajority state candidate)
    {configuration : Configuration Node}
    (active : configuration ∈ activeConfigurations (state.nodes candidate))
    : hasConfigurationMajority (state.nodes candidate).votesGranted configuration := by
  rw [hasElectionMajority, List.all_eq_true] at majority
  exact of_decide_eq_true (majority configuration active)

omit [DecidableEq TxId] in
/-- Extract one active configuration's effective election majority. -/
lemma effectiveElectionMajorityAtConfiguration
    {state : View Node TxId}
    {candidate : Node}
    (majority : hasEffectiveElectionMajority state candidate)
    {configuration : Configuration Node}
    (active : configuration ∈ activeConfigurations (state.nodes candidate))
    : hasConfigurationMajority
        (effectiveElectionVoters state candidate)
        configuration := by
  rw [hasEffectiveElectionMajority, List.all_eq_true] at majority
  exact of_decide_eq_true (majority configuration active)

/-- Extract one active configuration's potential election majority. -/
lemma potentialElectionMajorityAtConfiguration
    {state : View Node TxId}
    {candidate : Node}
    (majority : hasPotentialElectionMajority state candidate)
    {configuration : Configuration Node}
    (active : configuration ∈ activeConfigurations (state.nodes candidate))
    : hasConfigurationMajority
        (potentialElectionVoters state candidate)
        configuration := by
  rw [hasPotentialElectionMajority, List.all_eq_true] at majority
  exact of_decide_eq_true (majority configuration active)

/-- Materialised election support is included in potential election support. -/
lemma effectiveElectionMajorityIsPotential
    (state : View Node TxId)
    (candidate : Node)
    (majority : hasEffectiveElectionMajority state candidate)
    : hasPotentialElectionMajority state candidate := by
  rw [
    hasEffectiveElectionMajority, List.all_eq_true
  ] at majority
  rw [hasPotentialElectionMajority, List.all_eq_true]
  intro configuration active
  apply decide_eq_true
  have effectiveMajority :
      hasConfigurationMajority
        (effectiveElectionVoters state candidate)
        configuration :=
    of_decide_eq_true (majority configuration active)
  apply
    hasConfigurationMajority_mono
      (configuration := configuration)
      (smaller := effectiveElectionVoters state candidate)
      (larger := potentialElectionVoters state candidate)
      _ effectiveMajority
  intro voter member
  have joined : voter ∈ state.hasJoined := by
    have unpacked :
        voter ∈ state.hasJoined /\
          (voter ∈ (state.nodes candidate).votesGranted \/
            queuedGrantedVote state candidate voter) := by
      simpa [effectiveElectionVoters] using member
    exact unpacked.1
  simpa [potentialElectionVoters] using And.intro joined (Or.inl member)

/--
A potential election majority lifts to a frozen future ballot whenever every
potential voter is a future voter and the ballot configurations are unchanged.
-/
lemma potentialElectionMajorityImpliesFuture
    {state after : View Node TxId}
    {candidate : Node}
    {targetTerm : Nat}
    {ballotActive : List (Configuration Node)}
    (subset
      : potentialElectionVoters after candidate
        ⊆ futureElectionVoters state candidate targetTerm)
    (active : ballotActive = activeConfigurations (after.nodes candidate))
    (majority : hasPotentialElectionMajority after candidate)
    : hasFutureElectionMajority state candidate targetTerm ballotActive := by
  rw [hasPotentialElectionMajority, List.all_eq_true] at majority
  rw [hasFutureElectionMajority, List.all_eq_true]
  intro configuration ballotMember
  apply decide_eq_true
  have afterMember :
      configuration ∈
        activeConfigurations (after.nodes candidate) := by
    simpa [active] using ballotMember
  exact
    hasConfigurationMajority_mono subset
      (of_decide_eq_true (majority configuration afterMember))

omit [Bootstrap Node] in
/-- Extract one frozen ballot configuration's future election majority. -/
lemma futureElectionMajorityAtConfiguration
    {state : View Node TxId}
    {candidate : Node}
    {targetTerm : Nat}
    {ballotActive : List (Configuration Node)}
    (majority : hasFutureElectionMajority state candidate targetTerm ballotActive)
    {configuration : Configuration Node}
    (active : configuration ∈ ballotActive)
    : hasConfigurationMajority
        (futureElectionVoters state candidate targetTerm)
        configuration := by
  rw [hasFutureElectionMajority, List.all_eq_true] at majority
  exact of_decide_eq_true (majority configuration active)

/-- Every prefix supported by valid evidence lies inside its ACK frontier. -/
lemma validEvidenceSupportedPrefixFrontier
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (valid : evidence.Valid supportedPrefix)
    : supportedPrefix <+: evidence.history.take evidence.commitFrontier := by
  rcases valid with
    ⟨_, _, supportedBound, supportedEq, _⟩
  rw [← supportedEq, List.prefix_take_iff]
  exact ⟨
    List.take_prefix evidence.supportedLength evidence.history,
    Nat.le_trans
      (List.length_take_le evidence.supportedLength evidence.history)
      supportedBound
  ⟩

/--
Ballot ancestry puts a known evidence frontier in every active leader whose
term is not older than the commit term.  At the same term, one ACK member
identifies the shared canonical history.  At a higher term, ownership exposes
the leader's election record, whose promotion log contains the frontier by
`electionClosure` and is the ancestor of the active leader history.
-/
lemma knownCommitEvidenceActiveLeaderContainsFrontier
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
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
    {leader member : Node}
    (leaderRole : (state.nodes leader).role = .leader)
    (termRelation : evidence.commitTerm <= (state.nodes leader).currentTerm)
    (ackMember : member ∈ evidence.ackQuorum)
    : evidence.history.take evidence.commitFrontier <+: (state.nodes leader).log := by
  let evidencePrefix :=
    evidence.history.take evidence.commitFrontier
  have valid := knownCommitEvidenceValid evidenceFacts known
  have supportedPositive :=
    knownCommitEvidenceSupportedLengthPositive evidenceFacts known
  have frontierPositive : 0 < evidence.commitFrontier := by
    have supportedBound := valid.2.2.1
    omega
  have prefixLength :
      evidencePrefix.length = evidence.commitFrontier := by
    simp only [evidencePrefix, List.length_take]
    rw [Nat.min_eq_left valid.1]
  rcases
      entryAtSomeOfPositiveBound frontierPositive valid.1 with
    ⟨frontierEntry, historyFound⟩
  have frontierEntryTerm :
      frontierEntry.term = evidence.commitTerm := by
    simpa [termAt, historyFound] using valid.2.1
  have prefixFound :
      entryAt? evidencePrefix evidence.commitFrontier =
        some frontierEntry := by
    rw [entryAtTake_of_le le_rfl]
    exact historyFound
  have memberCovered :=
    prospectiveFacts.currentMember
      evidence supportedPrefix known member ackMember
  have memberFound :
      entryAt? (state.nodes member).log evidence.commitFrontier =
        some frontierEntry :=
    entryAt_of_prefix memberCovered prefixFound
  rcases
      ownership.logEntryAgreement
        member evidence.commitFrontier frontierEntry memberFound with
    ⟨_canonicalFound, memberAgreed⟩
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
  by_cases newer :
      evidence.commitTerm < (state.nodes leader).currentTerm
  · have owned :=
      ownership.activeLeader leader leaderRole
    rcases
        electionFacts.ownerRecorded
          (state.nodes leader).currentTerm leader owned with
      bootstrap | recorded
    · rw [bootstrap.1] at newer
      have positive :=
        prospectiveFacts.commitTermPositive
          evidence supportedPrefix known
      omega
    · rcases recorded with
        ⟨record, recordStored, _recordLeader⟩
      have promotionPrefix :=
        prospectiveFacts.electionClosure
          evidence supportedPrefix known
            (state.nodes leader).currentTerm record
            recordStored newer
      have canonicalPrefix :=
        promotionPrefix.trans
          (electionFacts.promotionCanonical
            (state.nodes leader).currentTerm record recordStored)
      rw [ownership.activeLeaderHistory leader leaderRole] at canonicalPrefix
      exact canonicalPrefix
  · have sameTerm :
        evidence.commitTerm =
          (state.nodes leader).currentTerm := by
      omega
    rw [List.prefix_iff_eq_take]
    calc
      evidencePrefix
          = (canonicalHistory evidence.commitTerm).take evidence.commitFrontier :=
        prefixCanonical
      _ = (state.nodes leader).log.take evidence.commitFrontier := by
        rw [sameTerm, ownership.activeLeaderHistory leader leaderRole]
      _ = (state.nodes leader).log.take evidencePrefix.length := by
        rw [prefixLength]

/--
Ballot ancestry also derives containment for a higher-term queued
AppendEntries history.  Queued metadata identifies the term owner, the frozen
election record inherits the evidence frontier through `electionClosure`, and
`ElectionQueuedHistoryFacts` carries that promotion ancestry into the queued
history.  Equal terms remain governed by `sameTermQueuedComparable`.
-/
lemma knownCommitEvidenceQueuedAppendContainsFrontier
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (electionQueuedFacts : ElectionQueuedHistoryFacts state appendHistory elections)
    (prospectiveFacts
      : ProspectiveCommitEvidenceFacts
          state appendHistory nodeEvidence requestEvidence elections)
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (known
      : KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {destination : Node}
    {request : AppendEntriesRequest Node TxId}
    (queued : Message.appendEntriesRequest request ∈ state.network destination)
    (newer : evidence.commitTerm < request.term)
    : evidence.history.take evidence.commitFrontier <+: appendHistory request := by
  rcases ownership.queuedAppendMetadata destination request queued with
    ⟨_distinct, owned, _entriesBounded⟩
  rcases
      electionFacts.ownerRecorded request.term request.source owned with
    bootstrap | recorded
  · rw [bootstrap.1] at newer
    have positive :=
      prospectiveFacts.commitTermPositive
        evidence supportedPrefix known
    omega
  · rcases recorded with
      ⟨record, recordStored, _recordLeader⟩
    exact (prospectiveFacts.electionClosure
            evidence supportedPrefix known request.term record
            recordStored newer).trans
      (electionQueuedFacts destination request queued record recordStored)

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Classify a successful lookup after appending one entry. -/
lemma entryAtAppendSingleton
    {log : List (Entry Node TxId)}
    {newEntry foundEntry : Entry Node TxId}
    {index : Nat}
    (found : entryAt? (log ++ [newEntry]) index = some foundEntry)
    : ((index <= log.length /\ entryAt? log index = some foundEntry)
        \/ (index = log.length + 1 /\ foundEntry = newEntry)) := by
  have positive : 0 < index := by
    by_contra notPositive
    have zero : index = 0 := Nat.eq_zero_of_not_pos notPositive
    subst index
    simp [entryAt?] at found
  unfold entryAt? at found
  simp only [positive.ne', ↓reduceIte] at found
  by_cases oldIndex : index - 1 < log.length
  · left
    constructor
    · omega
    · unfold entryAt?
      simp only [positive.ne', ↓reduceIte]
      simpa [List.getElem?_append_left oldIndex] using found
  · right
    have appendedIndex : index - 1 = log.length := by
      have within :
          index - 1 < (log ++ [newEntry]).length := by
        rw [List.getElem?_eq_some_iff] at found
        exact found.1
      simp at within
      omega
    constructor
    · omega
    · rw [List.getElem?_append_right (by omega)] at found
      simp [appendedIndex] at found
      exact found.symm

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Appending a suffix does not change a one-based lookup inside the base. -/
lemma entryAtAppend_of_le_length
    {base suffix : List (Entry Node TxId)}
    {index : Nat}
    (within : index <= base.length)
    : entryAt? (base ++ suffix) index = entryAt? base index := by
  unfold entryAt?
  split
  · rfl
  · rw [List.getElem?_append_left]
    omega

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- A lookup after an appended base is the corresponding suffix lookup. -/
lemma entryAtAppend_right
    {base suffix : List (Entry Node TxId)}
    {index : Nat}
    (afterBase : base.length < index)
    : entryAt? (base ++ suffix) index = entryAt? suffix (index - base.length) := by
  have positive : 0 < index := by omega
  have suffixPositive : 0 < index - base.length := by omega
  unfold entryAt?
  simp only [
    positive.ne', suffixPositive.ne', ↓reduceIte
  ]
  rw [List.getElem?_append_right (by omega)]
  congr 1
  omega

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Dropping and bounding a slice preserves lookups represented in it. -/
lemma entryAtDropTake
    {log : List (Entry Node TxId)}
    {previous index count : Nat}
    (afterPrevious : previous < index)
    (withinSlice : index <= previous + count)
    : entryAt? ((log.drop previous).take count) (index - previous)
      = entryAt? log index := by
  have positive : 0 < index := by omega
  have slicePositive : 0 < index - previous := by omega
  unfold entryAt?
  simp only [
    positive.ne', slicePositive.ne', ↓reduceIte
  ]
  rw [List.getElem?_take]
  split
  · rw [List.getElem?_drop]
    congr 1
    omega
  · rename_i outside
    exact False.elim (outside (by omega))

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Equal term projections give equal terms at matching successful lookups. -/
lemma entryTermsEqualOfMappedTerms
    {left right : List (Entry Node TxId)}
    {index : Nat}
    {leftEntry rightEntry : Entry Node TxId}
    (terms : left.map Entry.term = right.map Entry.term)
    (leftFound : entryAt? left index = some leftEntry)
    (rightFound : entryAt? right index = some rightEntry)
    : leftEntry.term = rightEntry.term := by
  have positive : 0 < index := by
    by_contra notPositive
    have zero : index = 0 := Nat.eq_zero_of_not_pos notPositive
    subst index
    simp [entryAt?] at leftFound
  have pointwise :=
    congrArg (fun values => values[index - 1]?) terms
  unfold entryAt? at leftFound rightFound
  simp only [positive.ne', ↓reduceIte] at leftFound rightFound
  simpa [List.getElem?_map, leftFound, rightFound] using pointwise

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Appending a suffix does not change the term inside the base. -/
lemma termAtAppend_of_le_length
    {base suffix : List (Entry Node TxId)}
    {index : Nat}
    (within : index <= base.length)
    : termAt (base ++ suffix) index = termAt base index := by
  unfold termAt
  rw [entryAtAppend_of_le_length within]

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- A positive term lookup exposes the underlying entry. -/
lemma termAtPositiveEntry
    {log : List (Entry Node TxId)}
    {index : Nat}
    (positive : 0 < termAt log index)
    : Exists
        fun entry =>
          entryAt? log index = some entry /\ entry.term = termAt log index := by
  unfold termAt at positive ⊢
  cases found : entryAt? log index with
  | none =>
      simp [found] at positive
  | some entry =>
      exact ⟨entry, by simp [], by simp []⟩

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Canonical snapshots with the same final term are ordered by final index. -/
lemma canonicalHistoriesPrefixOfSameLastTerm
    (canonicalHistory : Nat -> List (Entry Node TxId))
    {left right : List (Entry Node TxId)}
    (leftCanonical : HistoryCanonical canonicalHistory left)
    (rightCanonical : HistoryCanonical canonicalHistory right)
    (leftNonempty : Not (left = []))
    (lengthLe : left.length <= right.length)
    (lastTermEq : termAt left left.length = termAt right right.length)
    : left <+: right := by
  have leftPositive : 0 < left.length :=
    List.length_pos_iff_ne_nil.mpr leftNonempty
  have rightPositive : 0 < right.length := by omega
  rcases
      entryAtSomeOfPositiveBound leftPositive le_rfl with
    ⟨leftEntry, leftFound⟩
  rcases
      entryAtSomeOfPositiveBound rightPositive le_rfl with
    ⟨rightEntry, rightFound⟩
  rcases leftCanonical left.length leftEntry leftFound with
    ⟨leftCanonicalFound, leftAgreed⟩
  rcases rightCanonical right.length rightEntry rightFound with
    ⟨rightCanonicalFound, rightAgreed⟩
  have entryTermEq : leftEntry.term = rightEntry.term := by
    simpa [termAt, leftFound, rightFound] using lastTermEq
  have leftEq :
      left =
        (canonicalHistory leftEntry.term).take left.length := by
    simpa using leftAgreed
  have rightEq :
      right =
        (canonicalHistory rightEntry.term).take right.length := by
    simpa using rightAgreed
  calc
    left = (canonicalHistory leftEntry.term).take left.length :=
      leftEq
    _ = (canonicalHistory rightEntry.term).take left.length := by
      rw [entryTermEq]
    _ <+: (canonicalHistory rightEntry.term).take right.length := by
      rw [List.prefix_take_iff]
      exact ⟨
        List.take_prefix left.length _,
        Nat.le_trans (List.length_take_le _ _) lengthLe
      ⟩
    _ = right := rightEq.symm

/--
When a handled AppendEntries request advances commit, the corrected
request-end bound and canonical history agreement identify the exact learned
committed prefix.
-/
lemma handledAppendRequestAdvancedCommittedHistory
    (state : View Node TxId)
    (votes : VoteHistory Node)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse Node)
    (requestMember : Message.appendEntriesRequest request ∈ state.network destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (oldCommitBound
      : (state.nodes destination).commitIndex <= (state.nodes destination).log.length)
    (handled
      : handleAppendEntriesRequest? (state.nodes destination) request
        = some (nextNode, response))
    (advanced : (state.nodes destination).commitIndex < nextNode.commitIndex)
    : nextNode.committedLog = (appendHistory request).take nextNode.commitIndex := by
  let post :=
    handleAppendEntriesRequestLocalPost handled
  have succeeded : response.success = true :=
    post.commitAdvancedSuccessful advanced
  have nextBound : nextNode.commitIndex <= nextNode.log.length :=
    post.commitIndexBounded oldCommitBound
  have withinEnd :
      nextNode.commitIndex <=
        request.prevLogIndex + request.entries.length := by
    rcases le_max_iff.mp post.commitRequestEndBound with old | learned
    · omega
    · exact learned
  have nextPositive : 0 < nextNode.commitIndex := by omega
  have previousBound :
      request.prevLogIndex <= (state.nodes destination).log.length := by
    rcases post.successfulLogOk succeeded with zero | present
    · omega
    · exact present.1
  have historyPreviousBound :
      request.prevLogIndex <= (appendHistory request).length := by
    exact Nat.le_trans (Nat.le_add_right _ _) snapshot.1
  have previousAgreement :
      (state.nodes destination).log.take request.prevLogIndex =
        (appendHistory request).take request.prevLogIndex := by
    by_cases zero : request.prevLogIndex = 0
    · simp [zero]
    · have previousPositive : 0 < request.prevLogIndex := by omega
      rcases
          entryAtSomeOfPositiveBound previousPositive previousBound with
        ⟨nodeEntry, nodeFound⟩
      rcases
          entryAtSomeOfPositiveBound
            previousPositive historyPreviousBound with
        ⟨historyEntry, historyFound⟩
      have nodeTerm :
          nodeEntry.term = request.prevLogTerm := by
        rcases post.successfulLogOk succeeded with impossible | present
        · exact False.elim (zero impossible)
        · simpa [termAt, nodeFound] using present.2
      have historyTerm :
          historyEntry.term = request.prevLogTerm := by
        simpa [termAt, historyFound] using snapshot.2.1.symm
      rcases
          ownership.logEntryAgreement
            destination request.prevLogIndex nodeEntry nodeFound with
        ⟨_, nodeAgreed⟩
      rcases
          ownership.queuedHistoryEntryAgreement
            destination request requestMember
              request.prevLogIndex historyEntry historyFound with
        ⟨_, historyAgreed⟩
      calc
        (state.nodes destination).log.take request.prevLogIndex
            = (canonicalHistory nodeEntry.term).take request.prevLogIndex :=
          nodeAgreed
        _ = (canonicalHistory historyEntry.term).take request.prevLogIndex := by
          rw [nodeTerm, historyTerm]
        _ = (appendHistory request).take request.prevLogIndex :=
          historyAgreed.symm
  have nextPreviousAgreement :
      nextNode.log.take request.prevLogIndex =
        (appendHistory request).take request.prevLogIndex := by
    have nextOldPrevious :
        nextNode.log.take request.prevLogIndex =
          (state.nodes destination).log.take request.prevLogIndex := by
      rcases post.logShape with same | truncated | extended
      · rw [same]
      · rw [truncated]
        simp
      · rw [extended]
        simp [List.length_take, previousBound]
    exact nextOldPrevious.trans previousAgreement
  have takeAgreement :
      nextNode.log.take nextNode.commitIndex =
        (appendHistory request).take nextNode.commitIndex := by
    by_cases withinPrevious :
        nextNode.commitIndex <= request.prevLogIndex
    · calc
        nextNode.log.take nextNode.commitIndex =
            (nextNode.log.take request.prevLogIndex).take
              nextNode.commitIndex := by
                simp [List.take_take, Nat.min_eq_left withinPrevious]
        _ =
            ((appendHistory request).take request.prevLogIndex).take
              nextNode.commitIndex := by
                rw [nextPreviousAgreement]
        _ = (appendHistory request).take nextNode.commitIndex := by
              simp [List.take_take, Nat.min_eq_left withinPrevious]
    · have afterPrevious :
          request.prevLogIndex < nextNode.commitIndex := by omega
      rcases post.logShape with same | truncated | extended
      · have nodeFound :
            Exists fun entry =>
              entryAt? (state.nodes destination).log
                nextNode.commitIndex = some entry := by
          rw [same] at nextBound
          exact
            entryAtSomeOfPositiveBound nextPositive
              nextBound
        rcases nodeFound with ⟨nodeEntry, nodeFound⟩
        rcases
            entryAtSomeOfPositiveBound nextPositive
              (Nat.le_trans withinEnd snapshot.1) with
          ⟨historyEntry, historyFound⟩
        have offsetPositive :
            0 < nextNode.commitIndex - request.prevLogIndex := by omega
        have requestFound :
            entryAt? request.entries
                (nextNode.commitIndex - request.prevLogIndex) =
              some historyEntry := by
          have inTaken :
              entryAt?
                  ((appendHistory request).take
                    (request.prevLogIndex + request.entries.length))
                  nextNode.commitIndex =
                some historyEntry := by
            rw [entryAtTake_of_le withinEnd]
            exact historyFound
          rw [snapshot.2.2] at inTaken
          have previousLength :
              ((appendHistory request).take request.prevLogIndex).length =
                request.prevLogIndex := by
            simp [List.length_take, historyPreviousBound]
          rw [
            entryAtAppend_right
              (base := (appendHistory request).take request.prevLogIndex)
              (suffix := request.entries)
              (by simpa [previousLength] using afterPrevious),
            previousLength
          ] at inTaken
          exact inTaken
        have localSliceFound :
            entryAt?
                (((state.nodes destination).log.drop request.prevLogIndex).take
                  request.entries.length)
                (nextNode.commitIndex - request.prevLogIndex) =
              some nodeEntry := by
          rw [entryAtDropTake afterPrevious withinEnd]
          exact nodeFound
        have sameTerm :
            nodeEntry.term = historyEntry.term :=
          entryTermsEqualOfMappedTerms
            (post.successfulUnchangedEntryTerms succeeded same)
            localSliceFound requestFound
        rcases
            ownership.logEntryAgreement
              destination nextNode.commitIndex nodeEntry nodeFound with
          ⟨_, nodeAgreed⟩
        rcases
            ownership.queuedHistoryEntryAgreement
              destination request requestMember
                nextNode.commitIndex historyEntry historyFound with
          ⟨_, historyAgreed⟩
        rw [same]
        calc
          (state.nodes destination).log.take nextNode.commitIndex
              = (canonicalHistory nodeEntry.term).take nextNode.commitIndex :=
            nodeAgreed
          _ = (canonicalHistory historyEntry.term).take nextNode.commitIndex := by
            rw [sameTerm]
          _ = (appendHistory request).take nextNode.commitIndex :=
            historyAgreed.symm
      · have truncatedLength :
            nextNode.log.length <= request.prevLogIndex := by
          rw [truncated]
          simp
        omega
      · rw [extended]
        calc
          ((state.nodes destination).log.take request.prevLogIndex
                ++ request.entries).take
                nextNode.commitIndex
              = ((appendHistory request).take request.prevLogIndex
                  ++ request.entries).take
                  nextNode.commitIndex := by
            rw [previousAgreement]
          _ = ((appendHistory request).take
                (request.prevLogIndex + request.entries.length)).take
                nextNode.commitIndex := by
            rw [snapshot.2.2]
          _ = (appendHistory request).take nextNode.commitIndex := by
            simp [List.take_take, Nat.min_eq_left withinEnd]
  simpa [NodeState.committedLog] using takeAgreement

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- A shared prefix covering the complete request makes the request already
present in the destination log. -/
lemma appendRequestAlreadyDoneOfSharedPrefix
    {before : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {history sharedPrefix : List (Entry Node TxId)}
    (snapshot : RequestSnapshots history request)
    (beforePrefix : sharedPrefix <+: before.log)
    (historyPrefix : sharedPrefix <+: history)
    (covers : request.prevLogIndex + request.entries.length <= sharedPrefix.length)
    : alreadyDone before request := by
  right
  constructor
  · exact Nat.le_trans covers beforePrefix.length_le
  · have beforeTake :
        before.log.take
            (request.prevLogIndex + request.entries.length) =
          history.take
            (request.prevLogIndex + request.entries.length) := by
      calc
        before.log.take (request.prevLogIndex + request.entries.length)
            = sharedPrefix.take (request.prevLogIndex + request.entries.length) :=
          (takeEqOfPrefix beforePrefix covers).symm
        _ = history.take (request.prevLogIndex + request.entries.length) :=
          takeEqOfPrefix historyPrefix covers
    have exactEntries :
        (before.log.drop request.prevLogIndex).take
            request.entries.length =
          request.entries := by
      have dropped :=
        congrArg (List.drop request.prevLogIndex) beforeTake
      rw [snapshot.2.2] at dropped
      have previousBound :
          request.prevLogIndex <= history.length := by
        exact Nat.le_trans
          (Nat.le_add_right _ _) snapshot.1
      simpa [
        List.drop_take,
        List.length_take,
        previousBound
      ] using dropped
    rw [exactEntries]

/-- A successful handler cannot shorten a prefix shared by the destination
and the immutable request history. -/
lemma successfulAppendRequestSharedPrefixLength
    {before nextNode : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : AppendEntriesResponse Node}
    {history sharedPrefix : List (Entry Node TxId)}
    (snapshot : RequestSnapshots history request)
    (beforePrefix : sharedPrefix <+: before.log)
    (historyPrefix : sharedPrefix <+: history)
    (handled : handleAppendEntriesRequest? before request = some (nextNode, response))
    (success : response.success = true)
    : sharedPrefix.length <= nextNode.log.length := by
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
      have failed := (failureResponseMetadata before request).2.2
      rw [failed] at success
      contradiction
    · simp_all
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · split at handled
      · rename_i alreadyState alreadyResponse alreadyResult
        unfold appendEntriesAlreadyDone? at alreadyResult
        split at alreadyResult
        · have pairEq :=
            (Option.some.inj alreadyResult).trans
              (Option.some.inj handled)
          have nextEq := congrArg Prod.fst pairEq
          dsimp at nextEq
          subst nextNode
          simpa using beforePrefix.length_le
        · contradiction
      · split at handled
        · rename_i extendedState extendedResponse extensionResult
          unfold noConflictAppendEntriesRequest? at extensionResult
          split at extensionResult
          · rename_i extension
            have pairEq :=
              (Option.some.inj extensionResult).trans
                (Option.some.inj handled)
            have nextEq := congrArg Prod.fst pairEq
            dsimp at nextEq
            subst nextNode
            rcases extension with ⟨_, _, shorter, _⟩
            have prefixBound : sharedPrefix.length <
                request.prevLogIndex + request.entries.length :=
              lt_of_le_of_lt beforePrefix.length_le shorter
            simp only [refreshRetirementState_log, List.length_append, List.length_take]
            omega
          · contradiction
        · split at handled
          · contradiction
          · rename_i truncated conflictResult
            unfold conflictAppendEntriesRequest? at conflictResult
            split at conflictResult
            · rename_i conflict
              have truncatedEq := Option.some.inj conflictResult
              subst truncated
              split at handled
              · rename_i alreadyState alreadyResponse alreadyResult
                unfold appendEntriesAlreadyDone? at alreadyResult
                split at alreadyResult
                · rcases conflict.1.1 with nonempty
                  rename_i already
                  rcases already with empty | bounded
                  · exact False.elim (nonempty empty)
                  · have entriesPositive :
                        0 < request.entries.length :=
                      List.length_pos_iff_ne_nil.mpr nonempty
                    have endBeforePrevious :
                        request.prevLogIndex +
                            request.entries.length <=
                          request.prevLogIndex := by
                      exact Nat.le_trans bounded.1 (List.length_take_le _ _)
                    omega
                · contradiction
              · unfold noConflictAppendEntriesRequest? at handled
                split at handled
                · have pairEq :=
                    Option.some.inj handled
                  have nextEq := congrArg Prod.fst pairEq
                  dsimp at nextEq
                  subst nextNode
                  have prefixBound :
                      sharedPrefix.length <=
                        request.prevLogIndex + request.entries.length := by
                    by_contra notBounded
                    have already :=
                      appendRequestAlreadyDoneOfSharedPrefix
                        snapshot beforePrefix historyPrefix
                          (by omega)
                    have impossible :=
                      ‹appendEntriesAlreadyDone? before request = none›
                    simp [appendEntriesAlreadyDone?, already] at impossible
                  have previousBound :
                      request.prevLogIndex <= before.log.length := by
                    rcases
                        ‹request.term = before.currentTerm /\
                          before.role = .follower /\
                          logOk before request /\
                          request.prevLogIndex >= before.commitIndex›.2.2.1 with
                      zero | present
                    · omega
                    · exact present.1
                  simpa [
                    List.length_append,
                    List.length_take,
                    previousBound
                  ] using prefixBound
                · contradiction
            · contradiction
    · contradiction

/-- Successful handling retains every prefix shared by the old destination log
and the immutable queued request history. -/
lemma handledAppendRequestRetainsSharedPrefix
    (state : View Node TxId)
    (votes : VoteHistory Node)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse Node)
    (requestMember : Message.appendEntriesRequest request ∈ state.network destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled
      : handleAppendEntriesRequest? (state.nodes destination) request
        = some (nextNode, response))
    (success : response.success = true)
    {sharedPrefix : List (Entry Node TxId)}
    (beforePrefix : sharedPrefix <+: (state.nodes destination).log)
    (historyPrefix : sharedPrefix <+: appendHistory request)
    : sharedPrefix <+: nextNode.log := by
  let post :=
    handleAppendEntriesRequestLocalPost handled
  have prefixBound :
      sharedPrefix.length <= nextNode.log.length :=
    successfulAppendRequestSharedPrefixLength
      snapshot beforePrefix historyPrefix handled success
  have previousBound :
      request.prevLogIndex <= (state.nodes destination).log.length := by
    rcases post.successfulLogOk success with zero | present
    · omega
    · exact present.1
  have historyPreviousBound :
      request.prevLogIndex <= (appendHistory request).length := by
    exact Nat.le_trans (Nat.le_add_right _ _) snapshot.1
  have previousAgreement :
      (state.nodes destination).log.take request.prevLogIndex =
        (appendHistory request).take request.prevLogIndex := by
    by_cases zero : request.prevLogIndex = 0
    · simp [zero]
    · have previousPositive : 0 < request.prevLogIndex := by omega
      rcases
          entryAtSomeOfPositiveBound previousPositive previousBound with
        ⟨nodeEntry, nodeFound⟩
      rcases
          entryAtSomeOfPositiveBound
            previousPositive historyPreviousBound with
        ⟨historyEntry, historyFound⟩
      have nodeTerm :
          nodeEntry.term = request.prevLogTerm := by
        rcases post.successfulLogOk success with impossible | present
        · exact False.elim (zero impossible)
        · simpa [termAt, nodeFound] using present.2
      have historyTerm :
          historyEntry.term = request.prevLogTerm := by
        simpa [termAt, historyFound] using snapshot.2.1.symm
      rcases
          ownership.logEntryAgreement
            destination request.prevLogIndex nodeEntry nodeFound with
        ⟨_, nodeAgreed⟩
      rcases
          ownership.queuedHistoryEntryAgreement
            destination request requestMember
              request.prevLogIndex historyEntry historyFound with
        ⟨_, historyAgreed⟩
      calc
        (state.nodes destination).log.take request.prevLogIndex
            = (canonicalHistory nodeEntry.term).take request.prevLogIndex :=
          nodeAgreed
        _ = (canonicalHistory historyEntry.term).take request.prevLogIndex := by
          rw [nodeTerm, historyTerm]
        _ = (appendHistory request).take request.prevLogIndex :=
          historyAgreed.symm
  rcases post.logShape with same | truncated | extended
  · simpa [same] using beforePrefix
  · rw [truncated]
    have withinPrevious : sharedPrefix.length <= request.prevLogIndex := by
      rw [truncated] at prefixBound
      simpa [List.length_take, previousBound] using prefixBound
    rw [List.prefix_take_iff]
    exact ⟨beforePrefix, withinPrevious⟩
  · have fullAgreement :
        nextNode.log =
          (appendHistory request).take
            (request.prevLogIndex + request.entries.length) := by
      calc
        nextNode.log
            = (state.nodes destination).log.take request.prevLogIndex
              ++ request.entries :=
          extended
        _ = (appendHistory request).take request.prevLogIndex ++ request.entries := by
          rw [previousAgreement]
        _ = (appendHistory request).take
              (request.prevLogIndex + request.entries.length) :=
          snapshot.2.2.symm
    rw [fullAgreement, List.prefix_take_iff]
    constructor
    · exact historyPrefix
    · simpa [fullAgreement, List.length_take, snapshot.1] using prefixBound

/-- If the receive path did not step down a candidate, handling an
AppendEntries request leaves every active node unchanged. -/
lemma handleAppendEntriesRequestActiveUnchanged
    {before nextNode : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : AppendEntriesResponse Node}
    (notStepped : returnToFollowerState? before request = none)
    (handled : handleAppendEntriesRequest? before request = some (nextNode, response))
    (active : before.role = .candidate \/ before.role = .leader)
    : nextNode = before := by
  rcases active with candidate | leader
  · let post := handleAppendEntriesRequestLocalPost handled
    by_cases succeeded : response.success = true
    · have sameTerm := post.successfulCurrentTerm succeeded
      unfold returnToFollowerState? at notStepped
      simp [sameTerm, candidate] at notStepped
    · have failed : response.success = false :=
        Bool.eq_false_of_not_eq_true succeeded
      exact post.failedStateUnchanged failed
  · exact
      handleAppendEntriesRequestLeaderUnchanged
        leader handled

/-- Every successful response acknowledges an index present in the resulting
destination log. -/
lemma successfulAppendResponseIndexWithinLog
    {before nextNode : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : AppendEntriesResponse Node}
    (handled : handleAppendEntriesRequest? before request = some (nextNode, response))
    (success : response.success = true)
    : response.lastLogIndex <= nextNode.log.length := by
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
      have failed := (failureResponseMetadata before request).2.2
      rw [failed] at success
      contradiction
    · contradiction
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · split at handled
      · rename_i alreadyState alreadyResponse alreadyResult
        unfold appendEntriesAlreadyDone? at alreadyResult
        split at alreadyResult
        · rename_i already
          have pairEq :=
            (Option.some.inj alreadyResult).trans
              (Option.some.inj handled)
          have nextEq := congrArg Prod.fst pairEq
          have responseEq := congrArg Prod.snd pairEq
          dsimp at nextEq responseEq
          subst nextNode
          subst response
          simp only [successResponse]
          rcases already with empty | represented
          · have previousBound :
                request.prevLogIndex <= before.log.length := by
              rcases
                  ‹request.term = before.currentTerm /\
                    before.role = .follower /\
                    logOk before request /\
                    request.prevLogIndex >= before.commitIndex›.2.2.1 with
                zero | present
              · omega
              · exact present.1
            simp [empty]
            exact previousBound
          · exact represented.1
        · contradiction
      · split at handled
        · rename_i extendedState extendedResponse extensionResult
          unfold noConflictAppendEntriesRequest? at extensionResult
          split at extensionResult
          · rename_i extension
            have pairEq :=
              (Option.some.inj extensionResult).trans
                (Option.some.inj handled)
            have nextEq := congrArg Prod.fst pairEq
            have responseEq := congrArg Prod.snd pairEq
            dsimp at nextEq responseEq
            subst nextNode
            subst response
            simp [
              successResponse,
              List.length_take,
              extension.2.1
            ]
          · contradiction
        · split at handled
          · contradiction
          · rename_i truncated conflictResult
            unfold conflictAppendEntriesRequest? at conflictResult
            split at conflictResult
            · have truncatedEq := Option.some.inj conflictResult
              subst truncated
              split at handled
              · rename_i alreadyState alreadyResponse alreadyResult
                unfold appendEntriesAlreadyDone? at alreadyResult
                split at alreadyResult
                · rename_i already
                  have pairEq :=
                    (Option.some.inj alreadyResult).trans
                      (Option.some.inj handled)
                  have nextEq := congrArg Prod.fst pairEq
                  have responseEq := congrArg Prod.snd pairEq
                  dsimp at nextEq responseEq
                  subst nextNode
                  subst response
                  simp only [successResponse]
                  rcases already with empty | represented
                  · exact False.elim
                      (‹hasTermConflict before request /\
                        before.isNewFollower = true›.1.1 empty)
                  · exact represented.1
                · contradiction
              · unfold noConflictAppendEntriesRequest? at handled
                split at handled
                · rename_i extension
                  have pairEq := Option.some.inj handled
                  have nextEq := congrArg Prod.fst pairEq
                  have responseEq := congrArg Prod.snd pairEq
                  dsimp at nextEq responseEq
                  subst nextNode
                  subst response
                  simp [
                    successResponse,
                    List.length_take]
                · contradiction
            · contradiction
    · contradiction

/-- A successful request already represented in the destination log leaves
that log unchanged. -/
lemma successfulAlreadyDoneAppendLogUnchanged
    {before nextNode : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : AppendEntriesResponse Node}
    (already : alreadyDone before request)
    (handled : handleAppendEntriesRequest? before request = some (nextNode, response))
    (success : response.success = true)
    : nextNode.log = before.log := by
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
      have failed := (failureResponseMetadata before request).2.2
      rw [failed] at success
      contradiction
    · contradiction
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · split at handled
      · rename_i alreadyState alreadyResponse alreadyResult
        unfold appendEntriesAlreadyDone? at alreadyResult
        simp [already] at alreadyResult
        have pairEq :=
          alreadyResult.trans (Option.some.inj handled)
        have nextEq := congrArg Prod.fst pairEq
        simpa using (congrArg NodeState.log nextEq).symm
      · rename_i noAlready
        unfold appendEntriesAlreadyDone? at noAlready
        simp [already] at noAlready
    · contradiction

/-- A successful selected request materialises the corresponding source-log
prefix in the destination log. -/
lemma handledAppendRequestAcknowledgesSourcePrefix
    (state : View Node TxId)
    (votes : VoteHistory Node)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse Node)
    (requestMember : Message.appendEntriesRequest request ∈ state.network destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled
      : handleAppendEntriesRequest? (state.nodes destination) request
        = some (nextNode, response))
    (success : response.success = true)
    (sourceRole : (state.nodes request.source).role = .leader)
    (requestTerm : request.term = (state.nodes request.source).currentTerm)
    {index : Nat}
    (acknowledged : index <= response.lastLogIndex)
    : (state.nodes request.source).log.take index <+: nextNode.log := by
  let post := handleAppendEntriesRequestLocalPost handled
  have withinEnd :
      index <= request.prevLogIndex + request.entries.length := by
    exact Nat.le_trans acknowledged (post.successfulIndexBound success)
  have historyBound : index <= (appendHistory request).length :=
    Nat.le_trans withinEnd snapshot.1
  have sourceHistory :=
    ownership.queuedActiveSourceHistory
      destination request requestMember requestTerm sourceRole
  have sourceTake :
      (state.nodes request.source).log.take index =
        (appendHistory request).take index :=
    (takeEqOfPrefix sourceHistory historyBound).symm
  have nextBound : index <= nextNode.log.length :=
    Nat.le_trans acknowledged
      (successfulAppendResponseIndexWithinLog handled success)
  have previousBound :
      request.prevLogIndex <= (state.nodes destination).log.length := by
    rcases post.successfulLogOk success with zero | present
    · omega
    · exact present.1
  have historyPreviousBound :
      request.prevLogIndex <= (appendHistory request).length := by
    exact Nat.le_trans (Nat.le_add_right _ _) snapshot.1
  have previousAgreement :
      (state.nodes destination).log.take request.prevLogIndex =
        (appendHistory request).take request.prevLogIndex := by
    by_cases zero : request.prevLogIndex = 0
    · simp [zero]
    · have previousPositive : 0 < request.prevLogIndex := by omega
      rcases
          entryAtSomeOfPositiveBound previousPositive previousBound with
        ⟨nodeEntry, nodeFound⟩
      rcases
          entryAtSomeOfPositiveBound
            previousPositive historyPreviousBound with
        ⟨historyEntry, historyFound⟩
      have nodeTerm :
          nodeEntry.term = request.prevLogTerm := by
        rcases post.successfulLogOk success with impossible | present
        · exact False.elim (zero impossible)
        · simpa [termAt, nodeFound] using present.2
      have historyTerm :
          historyEntry.term = request.prevLogTerm := by
        simpa [termAt, historyFound] using snapshot.2.1.symm
      rcases
          ownership.logEntryAgreement
            destination request.prevLogIndex nodeEntry nodeFound with
        ⟨_, nodeAgreed⟩
      rcases
          ownership.queuedHistoryEntryAgreement
            destination request requestMember
              request.prevLogIndex historyEntry historyFound with
        ⟨_, historyAgreed⟩
      calc
        (state.nodes destination).log.take request.prevLogIndex
            = (canonicalHistory nodeEntry.term).take request.prevLogIndex :=
          nodeAgreed
        _ = (canonicalHistory historyEntry.term).take request.prevLogIndex := by
          rw [nodeTerm, historyTerm]
        _ = (appendHistory request).take request.prevLogIndex :=
          historyAgreed.symm
  have nextPreviousAgreement :
      nextNode.log.take request.prevLogIndex =
        (appendHistory request).take request.prevLogIndex := by
    have nextOldPrevious :
        nextNode.log.take request.prevLogIndex =
          (state.nodes destination).log.take request.prevLogIndex := by
      rcases post.logShape with same | truncated | extended
      · rw [same]
      · rw [truncated]
        simp
      · rw [extended]
        simp [List.length_take, previousBound]
    exact nextOldPrevious.trans previousAgreement
  have takeAgreement :
      nextNode.log.take index =
        (appendHistory request).take index := by
    by_cases withinPrevious : index <= request.prevLogIndex
    · calc
        nextNode.log.take index =
            (nextNode.log.take request.prevLogIndex).take index := by
          simp [List.take_take, Nat.min_eq_left withinPrevious]
        _ =
            ((appendHistory request).take request.prevLogIndex).take
              index := by rw [nextPreviousAgreement]
        _ = (appendHistory request).take index := by
          simp [List.take_take, Nat.min_eq_left withinPrevious]
    · have afterPrevious : request.prevLogIndex < index := by omega
      have indexPositive : 0 < index := by omega
      rcases post.logShape with same | truncated | extended
      · have nodeFound :
            Exists fun entry =>
              entryAt? (state.nodes destination).log index = some entry := by
          rw [same] at nextBound
          exact entryAtSomeOfPositiveBound indexPositive nextBound
        rcases nodeFound with ⟨nodeEntry, nodeFound⟩
        rcases
            entryAtSomeOfPositiveBound indexPositive historyBound with
          ⟨historyEntry, historyFound⟩
        have requestFound :
            entryAt? request.entries
                (index - request.prevLogIndex) =
              some historyEntry := by
          have inTaken :
              entryAt?
                  ((appendHistory request).take
                    (request.prevLogIndex + request.entries.length))
                  index =
                some historyEntry := by
            rw [entryAtTake_of_le withinEnd]
            exact historyFound
          rw [snapshot.2.2] at inTaken
          have previousLength :
              ((appendHistory request).take request.prevLogIndex).length =
                request.prevLogIndex := by
            simp [List.length_take, historyPreviousBound]
          rw [
            entryAtAppend_right
              (base := (appendHistory request).take request.prevLogIndex)
              (suffix := request.entries)
              (by simpa [previousLength] using afterPrevious),
            previousLength
          ] at inTaken
          exact inTaken
        have localSliceFound :
            entryAt?
                (((state.nodes destination).log.drop
                    request.prevLogIndex).take request.entries.length)
                (index - request.prevLogIndex) =
              some nodeEntry := by
          rw [entryAtDropTake afterPrevious withinEnd]
          exact nodeFound
        have sameTerm :
            nodeEntry.term = historyEntry.term :=
          entryTermsEqualOfMappedTerms
            (post.successfulUnchangedEntryTerms success same)
            localSliceFound requestFound
        rcases
            ownership.logEntryAgreement
              destination index nodeEntry nodeFound with
          ⟨_, nodeAgreed⟩
        rcases
            ownership.queuedHistoryEntryAgreement
              destination request requestMember
                index historyEntry historyFound with
          ⟨_, historyAgreed⟩
        rw [same]
        calc
          (state.nodes destination).log.take index
              = (canonicalHistory nodeEntry.term).take index :=
            nodeAgreed
          _ = (canonicalHistory historyEntry.term).take index := by
            rw [sameTerm]
          _ = (appendHistory request).take index :=
            historyAgreed.symm
      · have truncatedLength :
            nextNode.log.length <= request.prevLogIndex := by
          rw [truncated]
          exact List.length_take_le _ _
        omega
      · rw [extended]
        calc
          ((state.nodes destination).log.take request.prevLogIndex
                ++ request.entries).take
                index
              = ((appendHistory request).take request.prevLogIndex
                  ++ request.entries).take
                  index := by
            rw [previousAgreement]
          _ = ((appendHistory request).take
                (request.prevLogIndex + request.entries.length)).take
                index := by
            rw [snapshot.2.2]
          _ = (appendHistory request).take index := by
            simp [List.take_take, Nat.min_eq_left withinEnd]
  rw [List.prefix_iff_eq_take]
  have sourceBound :
      index <= (state.nodes request.source).log.length :=
    Nat.le_trans historyBound sourceHistory.length_le
  simp only [List.length_take, Nat.min_eq_left sourceBound]
  exact sourceTake.trans takeAgreement.symm

/-- A handled request leaves every destination entry on its owned canonical
history, including entries copied from an immutable queued snapshot. -/
lemma handledAppendRequestCanonicalAgreement
    (state : View Node TxId)
    (votes : VoteHistory Node)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse Node)
    (requestMember : Message.appendEntriesRequest request ∈ state.network destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled
      : handleAppendEntriesRequest? (state.nodes destination) request
        = some (nextNode, response))
    : forall index entry,
        entryAt? nextNode.log index = some entry
        -> entryAt? (canonicalHistory entry.term) index = some entry
            /\ nextNode.log.take index = (canonicalHistory entry.term).take index := by
  let post :=
    handleAppendEntriesRequestLocalPost handled
  intro index entry found
  by_cases succeeded : response.success = true
  · have previousBound :
        request.prevLogIndex <= (state.nodes destination).log.length := by
      rcases post.successfulLogOk succeeded with zero | present
      · omega
      · exact present.1
    have historyPreviousBound :
        request.prevLogIndex <= (appendHistory request).length := by
      exact Nat.le_trans (Nat.le_add_right _ _) snapshot.1
    have previousAgreement :
        (state.nodes destination).log.take request.prevLogIndex =
          (appendHistory request).take request.prevLogIndex := by
      by_cases zero : request.prevLogIndex = 0
      · simp [zero]
      · have previousPositive : 0 < request.prevLogIndex := by omega
        rcases
            entryAtSomeOfPositiveBound previousPositive previousBound with
          ⟨nodeEntry, nodeFound⟩
        rcases
            entryAtSomeOfPositiveBound
              previousPositive historyPreviousBound with
          ⟨historyEntry, historyFound⟩
        have nodeTerm :
            nodeEntry.term = request.prevLogTerm := by
          rcases post.successfulLogOk succeeded with impossible | present
          · exact False.elim (zero impossible)
          · simpa [termAt, nodeFound] using present.2
        have historyTerm :
            historyEntry.term = request.prevLogTerm := by
          simpa [termAt, historyFound] using snapshot.2.1.symm
        rcases
            ownership.logEntryAgreement
              destination request.prevLogIndex nodeEntry nodeFound with
          ⟨_, nodeAgreed⟩
        rcases
            ownership.queuedHistoryEntryAgreement
              destination request requestMember
                request.prevLogIndex historyEntry historyFound with
          ⟨_, historyAgreed⟩
        calc
          (state.nodes destination).log.take request.prevLogIndex
              = (canonicalHistory nodeEntry.term).take request.prevLogIndex :=
            nodeAgreed
          _ = (canonicalHistory historyEntry.term).take request.prevLogIndex := by
            rw [nodeTerm, historyTerm]
          _ = (appendHistory request).take request.prevLogIndex :=
            historyAgreed.symm
    rcases post.logShape with same | truncated | extended
    · rw [same] at found ⊢
      exact
        ownership.logEntryAgreement destination index entry found
    · have indexBound : index <= request.prevLogIndex := by
        have within := entryAtSomeIndexBound found
        rw [truncated] at within
        simp at within
        exact within.1
      have oldFound :
          entryAt? (state.nodes destination).log index = some entry := by
        rw [← entryAtTake_of_le indexBound]
        simpa [truncated] using found
      rcases
          ownership.logEntryAgreement
            destination index entry oldFound with
        ⟨canonicalFound, agreed⟩
      exact ⟨
        canonicalFound,
        by
          rw [truncated]
          simpa [
            List.take_take, Nat.min_eq_left indexBound
          ] using agreed
      ⟩
    · have fullAgreement :
          nextNode.log =
            (appendHistory request).take
              (request.prevLogIndex + request.entries.length) := by
        calc
          nextNode.log
              = (state.nodes destination).log.take request.prevLogIndex
                ++ request.entries :=
            extended
          _ = (appendHistory request).take request.prevLogIndex ++ request.entries := by
            rw [previousAgreement]
          _ = (appendHistory request).take
                (request.prevLogIndex + request.entries.length) :=
            snapshot.2.2.symm
      have indexBound :
          index <= request.prevLogIndex + request.entries.length := by
        have within := entryAtSomeIndexBound found
        rw [fullAgreement] at within
        simpa [List.length_take, snapshot.1] using within
      have historyFound :
          entryAt? (appendHistory request) index = some entry := by
        rw [fullAgreement, entryAtTake_of_le indexBound] at found
        exact found
      rcases
          ownership.queuedHistoryEntryAgreement
            destination request requestMember index entry historyFound with
        ⟨canonicalFound, agreed⟩
      exact ⟨
        canonicalFound,
        by
          rw [fullAgreement]
          simpa [
            List.take_take, Nat.min_eq_left indexBound
          ] using agreed
      ⟩
  · have failed : response.success = false := by
      cases value : response.success
      · rfl
      · exact False.elim (succeeded value)
    have unchanged := post.failedStateUnchanged failed
    subst nextNode
    exact ownership.logEntryAgreement destination index entry found

omit [DecidableEq TxId] in
/-- Canonical history monotonicity transfers to every represented node log. -/
lemma canonicalHistoriesMonoLog
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    : MonoLog state := by
  intro node earlier later earlierEntry laterEntry order
      earlierFound laterFound
  rcases
      ownership.logEntryAgreement node later laterEntry laterFound with
    ⟨canonicalLater, agreed⟩
  have earlierInNodeTake :
      entryAt? ((state.nodes node).log.take later) earlier =
        some earlierEntry := by
    rw [entryAtTake_of_le order.le]
    exact earlierFound
  have earlierInCanonicalTake :
      entryAt? ((canonicalHistory laterEntry.term).take later) earlier =
        some earlierEntry := by
    rw [← agreed]
    exact earlierInNodeTake
  have earlierInCanonical :
      entryAt? (canonicalHistory laterEntry.term) earlier =
        some earlierEntry := by
    rw [← entryAtTake_of_le order.le]
    exact earlierInCanonicalTake
  exact
    ownership.canonicalMonoLog laterEntry.term
      earlier later earlierEntry laterEntry order
        earlierInCanonical canonicalLater

omit [DecidableEq TxId] in
/--
Canonical agreement locates a local log entry in its canonical history, whose
entry-owner fact then supplies the term owner.
-/
lemma termOwnershipLogEntryOwner
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    {node : Node}
    {entry : Entry Node TxId}
    (member : entry ∈ (state.nodes node).log)
    : Exists fun owner => owners entry.term = some owner := by
  rcases memberEntryAt member with ⟨index, found⟩
  rcases ownership.logEntryAgreement node index entry found with
    ⟨canonicalFound, _⟩
  exact
    ownership.canonicalEntryOwner
      entry.term index entry canonicalFound

/--
An owned term is either the bootstrap term or has the strict majority recorded
by its immutable election record.
-/
lemma electionHistoryOwnerProvenance
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    {term : Nat}
    {owner : Node}
    (owned : owners term = some owner)
    : ((term = BOOTSTRAP_TERM /\ owner = INITIAL_LEADER)
        \/ Exists
            fun record =>
              elections term = some record /\ record.leader = owner) :=
  electionFacts.ownerRecorded term owner owned

lemma nodeLogTermNumberValid
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (node : Node)
    (index : Nat)
    : TermNumberValid (termAt (state.nodes node).log index) := by
  by_cases zero : termAt (state.nodes node).log index = 0
  · exact Or.inl zero
  · rcases termAtPositiveEntry (Nat.pos_of_ne_zero zero) with
      ⟨entry, found, entryTerm⟩
    rcases termOwnershipLogEntryOwner ownership (entryAtSomeMember found) with
      ⟨owner, owned⟩
    right
    rw [← entryTerm]
    rcases electionFacts.ownerRecorded entry.term owner owned with
      bootstrap | elected
    · exact bootstrap.1.ge
    · rcases elected with ⟨record, recorded, _⟩
      exact (electionFacts.termAboveBootstrap entry.term record recorded).le

/--
Canonical agreement for a frozen voter log transfers canonical monotonicity
to that exact election-record snapshot.
-/
lemma electionHistoryVoterMono
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    {term : Nat}
    {record : ElectionRecord Node TxId}
    {voter : Node}
    (recorded : elections term = some record)
    (member : voter ∈ record.supporters)
    : MonoHistory (record.voterLog voter) := by
  intro earlier later earlierEntry laterEntry order
      earlierFound laterFound
  rcases
      electionFacts.voterCanonical
        term record voter recorded member later laterEntry laterFound with
    ⟨canonicalLater, agreed⟩
  have earlierInVoterTake :
      entryAt? ((record.voterLog voter).take later) earlier =
        some earlierEntry := by
    rw [entryAtTake_of_le order.le]
    exact earlierFound
  have earlierInCanonicalTake :
      entryAt? ((canonicalHistory laterEntry.term).take later) earlier =
        some earlierEntry := by
    rw [← agreed]
    exact earlierInVoterTake
  have earlierInCanonical :
      entryAt? (canonicalHistory laterEntry.term) earlier =
        some earlierEntry := by
    rw [← entryAtTake_of_le order.le]
    exact earlierInCanonicalTake
  exact
    ownership.canonicalMonoLog laterEntry.term
      earlier later earlierEntry laterEntry order
        earlierInCanonical canonicalLater

omit [DecidableEq TxId] in
/-- Canonical agreement transfers canonical monotonicity to any snapshot. -/
lemma canonicalSnapshotMono
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    {history : List (Entry Node TxId)}
    (canonical : HistoryCanonical canonicalHistory history)
    : MonoHistory history := by
  intro earlier later earlierEntry laterEntry order
      earlierFound laterFound
  rcases canonical later laterEntry laterFound with
    ⟨canonicalLater, agreed⟩
  have earlierInHistoryTake :
      entryAt? (history.take later) earlier =
        some earlierEntry := by
    rw [entryAtTake_of_le order.le]
    exact earlierFound
  have earlierInCanonicalTake :
      entryAt? ((canonicalHistory laterEntry.term).take later) earlier =
        some earlierEntry := by
    rw [← agreed]
    exact earlierInHistoryTake
  have earlierInCanonical :
      entryAt? (canonicalHistory laterEntry.term) earlier =
        some earlierEntry := by
    rw [← entryAtTake_of_le order.le]
    exact earlierInCanonicalTake
  exact
    ownership.canonicalMonoLog laterEntry.term
      earlier later earlierEntry laterEntry order
        earlierInCanonical canonicalLater

/--
A recorded voter cannot remain below the recorded term: its retained vote
would otherwise contradict the vote history's empty-future property.
-/
lemma electionHistoryVoterTerm
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (voteFacts : VoteHistoryFacts state votes)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    {term : Nat}
    {record : ElectionRecord Node TxId}
    {voter : Node}
    (recorded : elections term = some record)
    (member : voter ∈ record.supporters)
    : term <= (state.nodes voter).currentTerm := by
  by_contra notBounded
  have future :=
    voteFacts.future voter term (Nat.lt_of_not_ge notBounded)
  rw [electionFacts.voted term record voter recorded member] at future
  contradiction

omit [DecidableEq TxId] [Bootstrap Node] in
/--
A candidate's persistent self-vote cannot belong to the empty bootstrap vote
history, so every candidate term is strictly above the bootstrap term.
-/
lemma candidatesSelfVoteAboveBootstrap
    {state : View Node TxId}
    {votes : VoteHistory Node}
    (termsPositive : CurrentTermsPositive state)
    (selfVotes : CandidatesSelfVote state)
    (voteFacts : VoteHistoryFacts state votes)
    : CandidatesAboveBootstrap state := by
  intro candidate role
  have positive :=
    termsPositive candidate (by rw [role]; decide)
  have selfVote := (selfVotes candidate role).1
  have currentVote := voteFacts.current candidate
  rw [selfVote] at currentVote
  have termNe :
      Not ((state.nodes candidate).currentTerm = BOOTSTRAP_TERM) := by
    intro termEq
    rw [termEq, voteFacts.bootstrapEmpty candidate] at currentVote
    contradiction
  omega

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Canonical agreement restricts to every prefix. -/
lemma historyCanonicalOfPrefix
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {shorter history : List (Entry Node TxId)}
    (canonical : HistoryCanonical canonicalHistory history)
    (isPrefix : shorter <+: history)
    : HistoryCanonical canonicalHistory shorter := by
  intro index entry found
  have historyFound :=
    entryAt_of_prefix isPrefix found
  rcases canonical index entry historyFound with
    ⟨canonicalFound, agreed⟩
  exact ⟨
    canonicalFound,
    (takeEqOfPrefix isPrefix
      (entryAtSomeIndexBound found)).trans
      agreed
  ⟩

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Log-term monotonicity restricts to every prefix. -/
lemma monoHistoryOfPrefix
    {shorter history : List (Entry Node TxId)}
    (mono : MonoHistory history)
    (isPrefix : shorter <+: history)
    : MonoHistory shorter := by
  intro earlier later earlierEntry laterEntry order
      earlierFound laterFound
  exact
    mono earlier later earlierEntry laterEntry order
      (entryAt_of_prefix isPrefix earlierFound)
      (entryAt_of_prefix isPrefix laterFound)

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Extending a monotone history cannot decrease its final term. -/
lemma termAtLastMonotoneOfPrefix
    {shorter history : List (Entry Node TxId)}
    (isPrefix : shorter <+: history)
    (mono : MonoHistory history)
    : termAt shorter shorter.length <= termAt history history.length := by
  by_cases shorterEmpty : shorter = []
  · simp [shorterEmpty, termAt, entryAt?]
  have shorterPositive : 0 < shorter.length :=
    List.length_pos_iff_ne_nil.mpr shorterEmpty
  rcases
      entryAtSomeOfPositiveBound shorterPositive le_rfl with
    ⟨shorterLast, shorterFound⟩
  have historyPositive : 0 < history.length :=
    lt_of_lt_of_le shorterPositive isPrefix.length_le
  rcases
      entryAtSomeOfPositiveBound historyPositive le_rfl with
    ⟨historyLast, historyFound⟩
  have shorterFoundInHistory :
      entryAt? history shorter.length = some shorterLast :=
    entryAt_of_prefix isPrefix shorterFound
  have termOrder : shorterLast.term <= historyLast.term := by
    by_cases sameLength : shorter.length = history.length
    · rw [sameLength] at shorterFoundInHistory
      exact (congrArg Entry.term
              (Option.some.inj (shorterFoundInHistory.symm.trans historyFound))).le
    · exact
        mono shorter.length history.length shorterLast historyLast
          (lt_of_le_of_ne isPrefix.length_le sameLength)
          shorterFoundInHistory historyFound
  simpa [termAt, shorterFound, historyFound] using termOrder

omit [Bootstrap Node] in
/-- Extending a monotone history cannot decrease its latest signature term. -/
lemma maxCommittableTermMonotoneOfPrefix
    {shorter history : List (Entry Node TxId)}
    (isPrefix : shorter <+: history)
    (mono : MonoHistory history)
    : maxCommittableTerm shorter <= maxCommittableTerm history := by
  let shorterIndex := maxCommittableIndex shorter
  let historyIndex := maxCommittableIndex history
  have indexOrder : shorterIndex <= historyIndex := by
    exact maxCommittableIndex_le_of_prefix isPrefix
  change termAt shorter shorterIndex <= termAt history historyIndex
  by_cases shorterZero : shorterIndex = 0
  · simp [ shorterIndex, shorterZero, termAt, entryAt?]
  have shorterPositive : 0 < shorterIndex := Nat.pos_of_ne_zero shorterZero
  rcases
      isSignatureAtTrue
        (maxCommittableIndexPositiveIsSignature
          (log := shorter) shorterPositive) with
    ⟨shorterEntry, shorterFound, _⟩
  have shorterFound' :
      entryAt? shorter shorterIndex = some shorterEntry := by
    simpa [shorterIndex] using shorterFound
  have shorterFoundInHistory :
      entryAt? history shorterIndex = some shorterEntry :=
    entryAt_of_prefix isPrefix shorterFound
  by_cases sameIndex : shorterIndex = historyIndex
  · rw [← sameIndex]
    simp [termAt, shorterFound', shorterFoundInHistory]
  have historyPositive : 0 < historyIndex := lt_of_lt_of_le shorterPositive indexOrder
  rcases
      isSignatureAtTrue
        (maxCommittableIndexPositiveIsSignature
          (log := history) historyPositive) with
    ⟨historyEntry, historyFound, _⟩
  have historyFound' :
      entryAt? history historyIndex = some historyEntry := by
    simpa [historyIndex] using historyFound
  have termOrder :=
    mono shorterIndex historyIndex shorterEntry historyEntry
      (lt_of_le_of_ne indexOrder sameIndex)
      shorterFoundInHistory historyFound'
  simpa [termAt, shorterFound', historyFound'] using termOrder

omit [Bootstrap Node] in
/-- A signature-only commit frontier is no later than the latest signature. -/
lemma lastCommittableIndex_eq_maxCommittableIndex
    (state : NodeState Node TxId)
    (committedSignature
      : 0 < state.commitIndex -> isSignatureAt state.log state.commitIndex = true)
    : lastCommittableIndex state = maxCommittableIndex state.log := by
  unfold lastCommittableIndex
  apply max_eq_right
  by_cases zero : state.commitIndex = 0
  · omega
  exact
    signatureIndex_le_maxCommittableIndex
      (committedSignature (Nat.pos_of_ne_zero zero))

omit [Bootstrap Node] in
/-- A signature-only commit does not alter the latest-signature election term. -/
lemma lastCommittableTerm_eq_maxCommittableTerm
    (state : NodeState Node TxId)
    (committedSignature
      : 0 < state.commitIndex -> isSignatureAt state.log state.commitIndex = true)
    : lastCommittableTerm state = maxCommittableTerm state.log := by
  simp [
    lastCommittableTerm, maxCommittableTerm,
    lastCommittableIndex_eq_maxCommittableIndex
      state committedSignature
  ]

omit [Bootstrap Node] in
/-- Election frontier fields depend only on the log and commit index. -/
lemma lastCommittableIndexFrame
    {before after : NodeState Node TxId}
    (logEq : after.log = before.log)
    (commitEq : after.commitIndex = before.commitIndex)
    : lastCommittableIndex after = lastCommittableIndex before := by
  simp [lastCommittableIndex, logEq, commitEq]

omit [Bootstrap Node] in
/-- Election frontier terms frame with the log and commit index. -/
lemma lastCommittableTermFrame
    {before after : NodeState Node TxId}
    (logEq : after.log = before.log)
    (commitEq : after.commitIndex = before.commitIndex)
    : lastCommittableTerm after = lastCommittableTerm before := by
  simp [
    lastCommittableTerm, logEq,
    lastCommittableIndexFrame logEq commitEq
  ]

omit [Bootstrap Node] in
/-- A signature-only committed frontier lies within the latest signature. -/
lemma commitIndex_le_maxCommittableIndex
    (state : NodeState Node TxId)
    (committedSignature
      : 0 < state.commitIndex -> isSignatureAt state.log state.commitIndex = true)
    : state.commitIndex <= maxCommittableIndex state.log := by
  by_cases zero : state.commitIndex = 0
  · omega
  exact
    signatureIndex_le_maxCommittableIndex
      (committedSignature (Nat.pos_of_ne_zero zero))

omit [Bootstrap Node] in
/-- A voter accepting one committable prefix also accepts any monotone extension. -/
lemma voteLogUpToDateOfCandidatePrefix
    (voter : NodeState Node TxId)
    (source destination : Node)
    {candidatePrefix candidateHistory : List (Entry Node TxId)}
    (isPrefix : candidatePrefix <+: candidateHistory)
    (mono : MonoHistory candidateHistory)
    (upToDate
      : voteLogUpToDate voter
          {
            term := voter.currentTerm
            lastCommittableTerm := maxCommittableTerm candidatePrefix
            lastCommittableIndex := maxCommittableIndex candidatePrefix
            source
            destination
          })
    : voteLogUpToDate voter
        {
          term := voter.currentTerm
          lastCommittableTerm := maxCommittableTerm candidateHistory
          lastCommittableIndex := maxCommittableIndex candidateHistory
          source
          destination
        } := by
  have termMonotone :=
    maxCommittableTermMonotoneOfPrefix isPrefix mono
  have indexMonotone :=
    maxCommittableIndex_le_of_prefix isPrefix
  unfold voteLogUpToDate at upToDate ⊢
  simp only at upToDate ⊢
  rcases upToDate with newer | same
  · left
    omega
  · by_cases termStrict :
        maxCommittableTerm candidatePrefix <
          maxCommittableTerm candidateHistory
    · left
      omega
    · right
      omega

omit [Bootstrap Node] in
/-- A candidate accepted against a longer voter log also passes its prefix. -/
lemma voteLogUpToDateOfVoterPrefix
    {beforeLog afterLog : List (Entry Node TxId)}
    (isPrefix : beforeLog <+: afterLog)
    (mono : MonoHistory afterLog)
    (before after : NodeState Node TxId)
    (request : RequestVoteRequest Node)
    (beforeLogEq : before.log = beforeLog)
    (afterLogEq : after.log = afterLog)
    (upToDate : voteLogUpToDate after request)
    : voteLogUpToDate before request := by
  have termMonotone :=
    maxCommittableTermMonotoneOfPrefix isPrefix mono
  have indexMonotone :=
    maxCommittableIndex_le_of_prefix isPrefix
  unfold voteLogUpToDate at upToDate ⊢
  rw [beforeLogEq]
  rw [afterLogEq] at upToDate
  rcases upToDate with newer | same
  · left
    omega
  · by_cases termStrict :
        maxCommittableTerm beforeLog <
          maxCommittableTerm afterLog
    · left
      omega
    · right
      omega

omit [Bootstrap Node] in
/-- Replying to one AppendEntries request cannot introduce another request. -/
lemma appendRequestMemberBeforeReply
    (state : View Node TxId)
    (source destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (response : AppendEntriesResponse Node)
    (remaining : List (Message Node TxId))
    (taken
      : Selected source (state.network destination) (.appendEntriesRequest request)
          remaining)
    : forall queuedDestination queuedRequest,
        Message.appendEntriesRequest queuedRequest
          ∈ reply state.network destination remaining response queuedDestination
        -> Message.appendEntriesRequest queuedRequest
            ∈ state.network queuedDestination := by
  intro queuedDestination queuedRequest member
  rcases
      memEnqueue
        (updateQueue state.network destination remaining)
        (.appendEntriesResponse response)
        (.appendEntriesRequest queuedRequest)
        queuedDestination
        (by simpa [reply] using member) with
    old | new
  · by_cases destinationEq : queuedDestination = destination
    · subst queuedDestination
      have remainingMember :
          Message.appendEntriesRequest queuedRequest ∈ remaining := by
        simpa [updateQueue] using old
      exact (selectedSound taken).2.2
        (.appendEntriesRequest queuedRequest) remainingMember
    · simpa [
        updateQueue, Function.update, destinationEq
      ] using old
  · simp at new

/--
The evidence component of AppendEntries receive is fully preserved:
unchanged commits retain their node evidence, while advances inherit a
request evidence restricted to the request-end-bounded learned prefix.
-/
lemma receiveAppendRequestCommitEvidenceFacts
    (state : View Node TxId)
    (source destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse Node)
    (remaining : List (Message Node TxId))
    (votes : VoteHistory Node)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (commitBounded : CommitIndicesBounded state)
    (committedSignature : CommittedFrontierIsSignature state)
    (taken
      : Selected source (state.network destination) (.appendEntriesRequest request)
          remaining)
    (handled
      : handleAppendEntriesRequest? (state.nodes destination) request
        = some (nextNode, response))
    : CommitEvidenceFacts
        {
          state with
            nodes := updateNode state.nodes destination nextNode
            network := reply state.network destination remaining response
        }
        appendHistory
        (appendRequestNodeEvidence
          state destination request nextNode
          nodeEvidence requestEvidence)
        requestEvidence := by
  have requestMember :
      Message.appendEntriesRequest request ∈ state.network destination :=
    (selectedSound taken).2.1
  apply
    appendRequestCommitEvidenceFacts
      state destination request nextNode response
        (reply state.network destination remaining response)
        appendHistory nodeEvidence requestEvidence evidenceFacts
        (commitBounded destination) handled requestMember
  · intro advanced
    exact
      handledAppendRequestAdvancedCommittedHistory
        state votes appendHistory canonicalHistory owners ownership
          destination request nextNode response requestMember snapshot
          (commitBounded destination) handled advanced
  · exact committedSignature destination
  · exact
      appendRequestMemberBeforeReply
        state source destination request response remaining taken

/-- Live evidence after AppendEntries receive is either unchanged or a
restriction of the selected request's pre-state evidence. -/
lemma receiveAppendRequestKnownEvidenceInherited
    (state : View Node TxId)
    (source destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse Node)
    (remaining : List (Message Node TxId))
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (_commitBounded : CommitIndicesBounded state)
    (taken
      : Selected source (state.network destination) (.appendEntriesRequest request)
          remaining)
    (handled
      : handleAppendEntriesRequest? (state.nodes destination) request
        = some (nextNode, response))
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (known
      : KnownCommitEvidence
          {
            state with
              nodes := updateNode state.nodes destination nextNode
              network := reply state.network destination remaining response
          }
          appendHistory
          (appendRequestNodeEvidence
            state destination request nextNode
            nodeEvidence requestEvidence)
          requestEvidence evidence supportedPrefix)
    : Exists
        fun oldEvidence =>
          Exists
            fun oldPrefix =>
              KnownCommitEvidence
                state appendHistory nodeEvidence requestEvidence
                oldEvidence oldPrefix
              /\ evidence.commitTerm = oldEvidence.commitTerm
              /\ evidence.history = oldEvidence.history
              /\ evidence.commitFrontier = oldEvidence.commitFrontier
              /\ evidence.ackQuorum = oldEvidence.ackQuorum
              /\ evidence.supportedLength <= oldEvidence.supportedLength := by
  let post := handleAppendEntriesRequestLocalPost handled
  have requestMember :
      Message.appendEntriesRequest request ∈ state.network destination :=
    (selectedSound taken).2.1
  rcases known with nodeKnown | requestKnown
  · rcases nodeKnown with
      ⟨node, positive, stored, prefixEq⟩
    by_cases same : node = destination
    · subst node
      have nextPositive : 0 < nextNode.commitIndex := by simpa [updateNode] using positive
      by_cases unchanged :
          nextNode.commitIndex =
            (state.nodes destination).commitIndex
      · have oldPositive :
            0 < (state.nodes destination).commitIndex := by
          omega
        have oldStored :
            nodeEvidence destination = some evidence := by
          simpa [appendRequestNodeEvidence, unchanged] using stored
        exact ⟨
          evidence,
          (state.nodes destination).committedLog,
          Or.inl ⟨destination, oldPositive, oldStored, rfl⟩,
          rfl,
          rfl,
          rfl,
          rfl,
          le_rfl
        ⟩
      · have advanced :
            (state.nodes destination).commitIndex <
              nextNode.commitIndex := by
          have monotone := post.commitIndexMonotone
          omega
        have succeeded : response.success = true :=
          post.commitAdvancedSuccessful advanced
        have withinLeaderCommit :
            nextNode.commitIndex <= request.leaderCommit := by
          rcases le_max_iff.mp post.commitUpperBound with old | learned
          · omega
          · exact learned
        have leaderCommitPositive : 0 < request.leaderCommit := by
          omega
        cases oldStored : requestEvidence request with
        | none =>
            simp [
              appendRequestNodeEvidence, unchanged, oldStored
            ] at stored
        | some oldEvidence =>
            have restrictedEq :
                oldEvidence.restrict nextNode.commitIndex = evidence := by
              exact Option.some.inj (by
                simpa [
                  appendRequestNodeEvidence, unchanged, oldStored
                ] using stored)
            subst evidence
            rcases
                evidenceFacts.requestPositive
                  destination request requestMember leaderCommitPositive with
              ⟨storedEvidence, evidenceStored, _valid,
                supportedLength, _termBound⟩
            have evidenceEq : storedEvidence = oldEvidence :=
              Option.some.inj (evidenceStored.symm.trans oldStored)
            subst storedEvidence
            exact ⟨
              oldEvidence,
              (appendHistory request).take request.leaderCommit,
              Or.inr
                ⟨
                  destination,
                  request,
                  requestMember,
                  leaderCommitPositive,
                  oldStored,
                  rfl
                ⟩,
              by simp [CommitEvidence.restrict],
              by simp [CommitEvidence.restrict],
              by simp [CommitEvidence.restrict],
              by simp [CommitEvidence.restrict],
              by simpa [CommitEvidence.restrict, supportedLength] using withinLeaderCommit
            ⟩
    · have oldPositive :
          0 < (state.nodes node).commitIndex := by
        simpa [updateNode, Function.update, same] using positive
      have oldStored :
          nodeEvidence node = some evidence := by
        simpa [appendRequestNodeEvidence, Function.update, same] using stored
      exact ⟨
        evidence,
        (state.nodes node).committedLog,
        Or.inl ⟨node, oldPositive, oldStored, rfl⟩,
        rfl,
        rfl,
        rfl,
        rfl,
        le_rfl
      ⟩
  · rcases requestKnown with
      ⟨queuedDestination, queuedRequest, member,
        positive, stored, prefixEq⟩
    exact ⟨
      evidence,
      (appendHistory queuedRequest).take queuedRequest.leaderCommit,
      Or.inr
        ⟨
          queuedDestination,
          queuedRequest,
          appendRequestMemberBeforeReply
            state source destination request response remaining taken
            queuedDestination queuedRequest member,
          positive,
          stored,
          rfl
        ⟩,
      rfl,
      rfl,
      rfl,
      rfl,
      le_rfl
    ⟩

/--
Every inherited evidence frontier survives handling the selected request at an
ACK-quorum member.  A same-term stale request is either compatible through its
queued history or was already fully represented before handling.
-/
lemma handledAppendRequestRetainsEvidenceFrontier
    (state : View Node TxId)
    (destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse Node)
    (votes : VoteHistory Node)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    {elections : ElectionHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (electionQueuedFacts : ElectionQueuedHistoryFacts state appendHistory elections)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
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
    (ackMember : destination ∈ evidence.ackQuorum)
    (requestMember : Message.appendEntriesRequest request ∈ state.network destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled
      : handleAppendEntriesRequest? (state.nodes destination) request
        = some (nextNode, response))
    : evidence.history.take evidence.commitFrontier <+: nextNode.log := by
  let post := handleAppendEntriesRequestLocalPost handled
  have currentPrefix :=
    prospectiveFacts.currentMember
      evidence supportedPrefix known destination ackMember
  by_cases succeeded : response.success = true
  · have requestCurrent :
        request.term = (state.nodes destination).currentTerm :=
      post.successfulCurrentTerm succeeded
    by_cases older : evidence.commitTerm < request.term
    · exact
        handledAppendRequestRetainsSharedPrefix
          state votes appendHistory canonicalHistory owners ownership
            destination request nextNode response requestMember snapshot
            handled succeeded currentPrefix
            (knownCommitEvidenceQueuedAppendContainsFrontier
              ownership electionFacts electionQueuedFacts prospectiveFacts
                known requestMember older)
    · by_cases same : evidence.commitTerm = request.term
      · rcases
            prospectiveFacts.sameTermQueuedComparable
              evidence supportedPrefix known destination request
                requestMember same with
          requestBeforeEvidence | frontierBeforeRequest
        · have valid := knownCommitEvidenceValid evidenceFacts known
          by_cases frontierWithin :
              evidence.commitFrontier <=
                (appendHistory request).length
          · have frontierBeforeRequest :
                evidence.history.take evidence.commitFrontier <+:
                  appendHistory request := by
              rw [List.prefix_iff_eq_take]
              have frontierLength :
                  (evidence.history.take evidence.commitFrontier).length =
                    evidence.commitFrontier := by
                simp [valid.1]
              calc
                evidence.history.take evidence.commitFrontier
                    = (appendHistory request).take evidence.commitFrontier :=
                  (takeEqOfPrefix requestBeforeEvidence frontierWithin).symm
                _ = (appendHistory request).take
                      (evidence.history.take evidence.commitFrontier).length := by
                  rw [frontierLength]
            exact
              handledAppendRequestRetainsSharedPrefix
                state votes appendHistory canonicalHistory owners ownership
                  destination request nextNode response requestMember snapshot
                  handled succeeded currentPrefix frontierBeforeRequest
          · have requestBeforeFrontier :
                appendHistory request <+:
                  evidence.history.take evidence.commitFrontier := by
              rw [List.prefix_take_iff]
              exact ⟨requestBeforeEvidence, by omega⟩
            have requestBeforeNode :=
              requestBeforeFrontier.trans currentPrefix
            have already :
                alreadyDone (state.nodes destination) request :=
              appendRequestAlreadyDoneOfSharedPrefix
                snapshot requestBeforeNode (prefixRefl _)
                  snapshot.1
            have unchanged :=
              successfulAlreadyDoneAppendLogUnchanged
                already handled succeeded
            simpa [unchanged] using currentPrefix
        · exact
            handledAppendRequestRetainsSharedPrefix
              state votes appendHistory canonicalHistory owners ownership
                destination request nextNode response requestMember snapshot
                handled succeeded currentPrefix frontierBeforeRequest
      · have greater : request.term < evidence.commitTerm := by omega
        have valid := knownCommitEvidenceValid evidenceFacts known
        have supportedPositive :=
          knownCommitEvidenceSupportedLengthPositive evidenceFacts known
        have frontierPositive : 0 < evidence.commitFrontier := by
          exact lt_of_lt_of_le supportedPositive valid.2.2.1
        have commitTermPositive :
            0 < evidence.commitTerm := by
          have positive :=
            prospectiveFacts.commitTermPositive
              evidence supportedPrefix known
          exact positiveOfBootstrapTermLe positive
        rcases termAtPositiveEntry
            (show 0 < termAt evidence.history evidence.commitFrontier by
              rw [valid.2.1]
              exact commitTermPositive) with
          ⟨frontierEntry, frontierFound, frontierTerm⟩
        have prefixFound :
            entryAt?
                (evidence.history.take evidence.commitFrontier)
                evidence.commitFrontier =
              some frontierEntry := by
          rw [entryAtTake_of_le le_rfl]
          exact frontierFound
        have destinationFound :=
          entryAt_of_prefix currentPrefix prefixFound
        have bounded :=
          entriesBounded destination frontierEntry
            (entryAtSomeMember destinationFound)
        have entryTerm :
            frontierEntry.term = evidence.commitTerm :=
          frontierTerm.trans valid.2.1
        rw [entryTerm, ← requestCurrent] at bounded
        omega
  · have failed : response.success = false :=
      Bool.eq_false_of_not_eq_true succeeded
    simpa [post.failedStateUnchanged failed] using currentPrefix

end CCFRaft.Proofs.Invariant
