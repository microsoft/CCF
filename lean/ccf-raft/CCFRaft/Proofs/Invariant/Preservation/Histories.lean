-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Frames
import CCFRaft.Proofs.Ledger

set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Proofs.Config

open CCFRaft.Model.Node
open Concrete
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable {joined : Finset Node}
variable [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node]
  [LinearOrder Node] [Inhabited TxId]

attribute [local simp] Shared.Envelope.target ConfigurationCoverageWitness.sharedPrefix

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
    {state : Model.State Node TxId}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts
      : ProspectiveCommitEvidenceFacts (joined := joined)
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
      entryAt? ((nodeOf state) member).log evidence.commitFrontier =
        some frontierEntry :=
    entryAt_of_prefix memberCovered prefixFound
  have memberAgreed :=
    (ownership.logEntryAgreement
      member evidence.commitFrontier frontierEntry memberFound).2
  calc
    evidence.history.take evidence.commitFrontier
        = ((nodeOf state) member).log.take evidence.commitFrontier := by
      have covered := prefixEqTake memberCovered
      rw [prefixLength] at covered
      exact covered.symm
    _ = (canonicalHistory frontierEntry.term).take evidence.commitFrontier :=
      memberAgreed
    _ = (canonicalHistory evidence.commitTerm).take evidence.commitFrontier := by
      rw [frontierEntryTerm]

/-- Every effective ACK supporter has advanced to at least the ACKed term. -/
lemma effectiveAckerCurrentTermBound
    {state : Model.State Node TxId}
    {responseHistory : AppendResponseKey Node -> List (Entry Node TxId)}
    {elections : ElectionHistory Node TxId}
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (currentHistory
      : AckerCurrentHistory (joined := joined) state responseHistory elections)
    {leader supporter : Node}
    {frontier : Nat}
    (leaderRole : ((nodeOf state) leader).role = .leader)
    (frontierTerm
      : termAt ((nodeOf state) leader).log frontier = ((nodeOf state) leader).currentTerm)
    (frontierSignature : isSignatureAt ((nodeOf state) leader).log frontier = true)
    (member
      : supporter
        ∈ effectiveAckers (joined := joined) state responseHistory leader frontier)
    : ((nodeOf state) leader).currentTerm <= ((nodeOf state) supporter).currentTerm := by
  rcases
      currentHistory leader frontier leaderRole frontierTerm
        frontierSignature supporter member with
    retained | bad
  · rcases isSignatureAtTrue frontierSignature with
      ⟨entry, found, _signature⟩
    have entryTerm :
        entry.term = ((nodeOf state) leader).currentTerm := by
      simpa [termAt, found] using frontierTerm
    have prefixFound :
        entryAt?
            (((nodeOf state) leader).log.take frontier)
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

/-- Taking beyond an index leaves its term lookup unchanged. -/
lemma termAtTakeOfLe
    {log : List (Entry Node TxId)}
    {index count : Nat}
    (within : index <= count)
    : termAt (log.take count) index = termAt log index := by
  unfold termAt
  rw [entryAtTake_of_le within]

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

/-- Taking through the latest signature retains its committable term. -/
lemma maxCommittableTermTakeMax (log : List (Entry Node TxId))
    : maxCommittableTerm (log.take (maxCommittableIndex log))
      = maxCommittableTerm log := by
  unfold maxCommittableTerm
  rw [maxCommittableIndexTakeMax]
  exact termAtTakeOfLe le_rfl

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

/-- Extract one governing configuration's processed replication majority. -/
lemma majorityAtConfiguration
    {state : Model.State Node TxId}
    {leader : Node}
    {index : Nat}
    (majority : hasMajorityAt (inferInstance) (nodeOf state leader) leader index)
    {configuration : Configuration Node}
    (active
      : configuration ∈ activeConfigurationsOf (inferInstance) ((nodeOf state) leader))
    (_governs : configuration.index <= index)
    : hasConfigurationMajority
        (acknowledgingNodes (inferInstance) (nodeOf state leader) leader index)
        configuration := by
  rw [hasMajorityAt, List.all_eq_true] at majority
  exact of_decide_eq_true (majority configuration active)

/-- Extract one governing configuration's effective replication majority. -/
lemma effectiveMajorityAtConfiguration
    {state : Model.State Node TxId}
    {responseHistory : AppendResponseKey Node -> List (Entry Node TxId)}
    {leader : Node}
    {index : Nat}
    (majority
      : hasEffectiveMajorityAt (joined := joined) state responseHistory leader index)
    {configuration : Configuration Node}
    (active
      : configuration ∈ activeConfigurationsOf (inferInstance) ((nodeOf state) leader))
    (governs : configuration.index <= index)
    : hasConfigurationMajority
        (effectiveAckers (joined := joined) state responseHistory leader index)
        configuration := by
  rw [hasEffectiveMajorityAt, List.all_eq_true] at majority
  exact (of_decide_eq_true (majority configuration active)) governs

/-- Extract one active configuration's potential replication majority. -/
lemma potentialMajorityAtConfiguration
    {state : Model.State Node TxId}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendResponseKey Node -> List (Entry Node TxId)}
    {leader : Node}
    {index : Nat}
    (majority
      : hasPotentialMajorityAt (joined := joined) state appendHistory responseHistory
          leader index)
    {configuration : Configuration Node}
    (active
      : configuration ∈ activeConfigurationsOf (inferInstance) ((nodeOf state) leader))
    (governs : configuration.index <= index)
    : hasConfigurationMajority
        (potentialAckers (joined := joined) state appendHistory responseHistory leader
          index)
        configuration := by
  rw [hasPotentialMajorityAt, List.all_eq_true] at majority
  exact (of_decide_eq_true (majority configuration active)) governs

/-- Extract one active configuration's processed election majority. -/
lemma electionMajorityAtConfiguration
    {state : Model.State Node TxId}
    {candidate : Node}
    (majority : hasElectionMajority (inferInstance) (nodeOf state candidate))
    {configuration : Configuration Node}
    (active
      : configuration ∈ activeConfigurationsOf (inferInstance) ((nodeOf state) candidate))
    : hasConfigurationMajority ((nodeOf state) candidate).votesGranted configuration := by
  rw [hasElectionMajority, List.all_eq_true] at majority
  exact of_decide_eq_true (majority configuration active)

/-- Extract one active configuration's effective election majority. -/
lemma effectiveElectionMajorityAtConfiguration
    {state : Model.State Node TxId}
    {candidate : Node}
    (majority : hasEffectiveElectionMajority (joined := joined) state candidate)
    {configuration : Configuration Node}
    (active
      : configuration ∈ activeConfigurationsOf (inferInstance) ((nodeOf state) candidate))
    : hasConfigurationMajority
        (effectiveElectionVoters (joined := joined) state candidate)
        configuration := by
  rw [hasEffectiveElectionMajority, List.all_eq_true] at majority
  exact of_decide_eq_true (majority configuration active)

/-- Extract one active configuration's potential election majority. -/
lemma potentialElectionMajorityAtConfiguration
    {state : Model.State Node TxId}
    {candidate : Node}
    (majority : hasPotentialElectionMajority (joined := joined) state candidate)
    {configuration : Configuration Node}
    (active
      : configuration ∈ activeConfigurationsOf (inferInstance) ((nodeOf state) candidate))
    : hasConfigurationMajority
        (potentialElectionVoters (joined := joined) state candidate)
        configuration := by
  rw [hasPotentialElectionMajority, List.all_eq_true] at majority
  exact of_decide_eq_true (majority configuration active)

/-- Materialised election support is included in potential election support. -/
lemma effectiveElectionMajorityIsPotential
    (state : Model.State Node TxId)
    (candidate : Node)
    (majority : hasEffectiveElectionMajority (joined := joined) state candidate)
    : hasPotentialElectionMajority (joined := joined) state candidate := by
  rw [
    hasEffectiveElectionMajority, List.all_eq_true
  ] at majority
  rw [hasPotentialElectionMajority, List.all_eq_true]
  intro configuration active
  apply decide_eq_true
  have effectiveMajority :
      hasConfigurationMajority
        (effectiveElectionVoters (joined := joined) state candidate)
        configuration :=
    of_decide_eq_true (majority configuration active)
  apply
    hasConfigurationMajority_mono
      (configuration := configuration)
      (smaller := effectiveElectionVoters (joined := joined) state candidate)
      (larger := potentialElectionVoters (joined := joined) state candidate)
      _ effectiveMajority
  intro voter member
  have joined : voter ∈ joined := by
    have unpacked :
        voter ∈ joined /\
          (voter ∈ ((nodeOf state) candidate).votesGranted \/
            queuedGrantedVote state candidate voter) := by
      simpa [effectiveElectionVoters] using member
    exact unpacked.1
  simpa [potentialElectionVoters] using And.intro joined (Or.inl member)

/--
A potential election majority lifts to a frozen future ballot whenever every
potential voter is a future voter and the ballot configurations are unchanged.
-/
lemma potentialElectionMajorityImpliesFuture
    {state after : Model.State Node TxId}
    {candidate : Node}
    {targetTerm : Nat}
    {ballotActive : List (Configuration Node)}
    (subset
      : potentialElectionVoters (joined := joined) after candidate
        ⊆ futureElectionVoters (joined := joined) state candidate targetTerm)
    (active
      : ballotActive = activeConfigurationsOf (inferInstance) ((nodeOf after) candidate))
    (majority : hasPotentialElectionMajority (joined := joined) after candidate)
    : hasFutureElectionMajority (joined := joined) state candidate targetTerm
        ballotActive := by
  rw [hasPotentialElectionMajority, List.all_eq_true] at majority
  rw [hasFutureElectionMajority, List.all_eq_true]
  intro configuration ballotMember
  apply decide_eq_true
  have afterMember :
      configuration ∈
        activeConfigurationsOf (inferInstance) ((nodeOf after) candidate) := by
    simpa [active] using ballotMember
  exact
    hasConfigurationMajority_mono subset
      (of_decide_eq_true (majority configuration afterMember))

/-- Extract one frozen ballot configuration's future election majority. -/
lemma futureElectionMajorityAtConfiguration
    {state : Model.State Node TxId}
    {candidate : Node}
    {targetTerm : Nat}
    {ballotActive : List (Configuration Node)}
    (majority
      : hasFutureElectionMajority (joined := joined) state candidate targetTerm
          ballotActive)
    {configuration : Configuration Node}
    (active : configuration ∈ ballotActive)
    : hasConfigurationMajority
        (futureElectionVoters (joined := joined) state candidate targetTerm)
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
    {state : Model.State Node TxId}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
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
      : ProspectiveCommitEvidenceFacts (joined := joined)
          state appendHistory nodeEvidence requestEvidence elections)
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (known
      : KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {leader member : Node}
    (leaderRole : ((nodeOf state) leader).role = .leader)
    (termRelation : evidence.commitTerm <= ((nodeOf state) leader).currentTerm)
    (ackMember : member ∈ evidence.ackQuorum)
    : evidence.history.take evidence.commitFrontier <+: ((nodeOf state) leader).log := by
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
      entryAt? ((nodeOf state) member).log evidence.commitFrontier =
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
      evidencePrefix = ((nodeOf state) member).log.take evidence.commitFrontier := by
        have covered := prefixEqTake memberCovered
        rw [prefixLength] at covered
        exact covered.symm
      _ = (canonicalHistory frontierEntry.term).take evidence.commitFrontier :=
        memberAgreed
      _ = (canonicalHistory evidence.commitTerm).take evidence.commitFrontier := by
        rw [frontierEntryTerm]
  by_cases newer :
      evidence.commitTerm < ((nodeOf state) leader).currentTerm
  · have owned :=
      ownership.activeLeader leader leaderRole
    rcases
        electionFacts.ownerRecorded
          ((nodeOf state) leader).currentTerm leader owned with
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
            ((nodeOf state) leader).currentTerm record
            recordStored newer
      have canonicalPrefix :=
        promotionPrefix.trans
          (electionFacts.promotionCanonical
            ((nodeOf state) leader).currentTerm record recordStored)
      rw [ownership.activeLeaderHistory leader leaderRole] at canonicalPrefix
      exact canonicalPrefix
  · have sameTerm :
        evidence.commitTerm =
          ((nodeOf state) leader).currentTerm := by
      omega
    rw [List.prefix_iff_eq_take]
    calc
      evidencePrefix
          = (canonicalHistory evidence.commitTerm).take evidence.commitFrontier :=
        prefixCanonical
      _ = ((nodeOf state) leader).log.take evidence.commitFrontier := by
        rw [sameTerm, ownership.activeLeaderHistory leader leaderRole]
      _ = ((nodeOf state) leader).log.take evidencePrefix.length := by
        rw [prefixLength]

/--
Ballot ancestry also derives containment for a higher-term queued
AppendEntries history.  Queued metadata identifies the term owner, the frozen
election record inherits the evidence frontier through `electionClosure`, and
`ElectionQueuedHistoryFacts` carries that promotion ancestry into the queued
history.  Equal terms remain governed by `sameTermQueuedComparable`.
-/
lemma knownCommitEvidenceQueuedAppendContainsFrontier
    {state : Model.State Node TxId}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
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
      : ProspectiveCommitEvidenceFacts (joined := joined)
          state appendHistory nodeEvidence requestEvidence elections)
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (known
      : KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {destination : Node}
    {request : AppendRequestKey Node TxId}
    (queued
      : (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination))
    (newer : evidence.commitTerm < request.2.2.term)
    : evidence.history.take evidence.commitFrontier <+: appendHistory request := by
  rcases ownership.queuedAppendMetadata destination request queued with
    ⟨_distinct, owned, _entriesBounded⟩
  rcases
      electionFacts.ownerRecorded request.2.2.term request.1 owned with
    bootstrap | recorded
  · rw [bootstrap.1] at newer
    have positive :=
      prospectiveFacts.commitTermPositive
        evidence supportedPrefix known
    omega
  · rcases recorded with
      ⟨record, recordStored, _recordLeader⟩
    exact (prospectiveFacts.electionClosure
            evidence supportedPrefix known request.2.2.term record
            recordStored newer).trans
      (electionQueuedFacts destination request queued record recordStored)

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

/-- Appending a suffix does not change the term inside the base. -/
lemma termAtAppend_of_le_length
    {base suffix : List (Entry Node TxId)}
    {index : Nat}
    (within : index <= base.length)
    : termAt (base ++ suffix) index = termAt base index := by
  unfold termAt
  rw [entryAtAppend_of_le_length within]

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

/-- A node log and a queued history with equal positive terms at an index agree up to it. -/
lemma queuedHistoryTakeAgreement
    {state : Model.State Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    {destination : Node}
    {request : AppendRequestKey Node TxId}
    (requestMember
      : (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination))
    {index : Nat}
    (positive : 0 < index)
    (nodeBound : index <= ((nodeOf state) destination).log.length)
    (historyBound : index <= (appendHistory request).length)
    (sameTerm
      : termAt ((nodeOf state) destination).log index
        = termAt (appendHistory request) index)
    : ((nodeOf state) destination).log.take index
      = (appendHistory request).take index := by
  rcases entryAtSomeOfPositiveBound positive nodeBound with ⟨nodeEntry, nodeFound⟩
  rcases entryAtSomeOfPositiveBound positive historyBound with ⟨historyEntry, historyFound⟩
  have termEq : nodeEntry.term = historyEntry.term := by
    simpa [termAt, nodeFound, historyFound] using sameTerm
  rcases ownership.logEntryAgreement destination index nodeEntry nodeFound with
    ⟨_, nodeAgreed⟩
  rcases
      ownership.queuedHistoryEntryAgreement
        destination request requestMember index historyEntry historyFound with
    ⟨_, historyAgreed⟩
  rw [nodeAgreed, historyAgreed, termEq]

/-- A successful request whose entries are already present, by term, leaves the log
unchanged. -/
lemma successfulAppendLogUnchangedOfTerms
    {before nextNode : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : AppendEntriesResponse}
    (post : AppendRequestLocalPost before nextNode request response)
    (success : response.success = true)
    (covered : request.prevLogIndex + request.entries.length <= before.log.length)
    (terms
      : ((before.log.drop request.prevLogIndex).take request.entries.length).map
          Entry.term
        = request.entries.map Entry.term)
    : nextNode.log = before.log := by
  rcases post.successfulShape success with ⟨-, logEq⟩ | ⟨conflict, -⟩
  · rw [logEq, List.drop_eq_nil_of_le (by omega), List.append_nil]
  · exact absurd conflict
      (noConflictOfMappedTerms _ _ (by simpa [List.take_take] using terms))

/-- Without a term conflict, positions shared by the old log and the request
carry the request-history terms. -/
lemma termAtOverlapOfNoConflict
    {log history entries : List (Entry Node TxId)}
    {previous index : Nat}
    (historyEnd
      : history.take (previous + entries.length) = history.take previous ++ entries)
    (historyBound : previous + entries.length <= history.length)
    (noConflict
      : Not
          (((log.drop previous).zip entries).any
              (fun (pair : Entry Node TxId × Entry Node TxId) =>
                pair.1.term != pair.2.term)
            = true))
    (afterPrevious : previous < index)
    (inLog : index <= log.length)
    (inRequest : index <= previous + entries.length)
    : termAt log index = termAt history index := by
  have overlap := overlapTermsOfNoConflict (log.drop previous) entries noConflict
  rw [List.length_drop] at overlap
  rcases entryAtSomeOfPositiveBound (by omega) inLog with ⟨existing, existingFound⟩
  rcases entryAtSomeOfPositiveBound (log := entries) (index := index - previous)
      (by omega) (by omega) with ⟨incoming, incomingFound⟩
  have termEq :=
    entryTermsEqualOfMappedTerms overlap
      ((entryAtDropTake afterPrevious inRequest).trans existingFound)
      ((entryAtTake_of_le (by omega)).trans incomingFound)
  have historyFound : entryAt? history index = some incoming := by
    rw [← entryAtTake_of_le inRequest, historyEnd, entryAtAppend_right (by simp; omega),
      List.length_take, Nat.min_eq_left (by omega)]
    exact incomingFound
  simp [termAt, existingFound, historyFound, termEq]

/--
After a successful append, a log whose terms agree with a request history at
shared positions matches that history through the request end, and only keeps
a longer suffix when it is unchanged.
-/
lemma appendedLogPrefixAgreement
    {log next history entries : List (Entry Node TxId)}
    {previous previousTerm : Nat}
    (agreeAt
      : forall index,
          0 < index
          -> index <= log.length
          -> index <= history.length
          -> termAt log index = termAt history index
          -> log.take index = history.take index)
    (historyBound : previous + entries.length <= history.length)
    (historyTerm : previousTerm = termAt history previous)
    (historyEnd
      : history.take (previous + entries.length) = history.take previous ++ entries)
    (matching
      : previous = 0 \/ (previous <= log.length /\ termAt log previous = previousTerm))
    (shape
      : (Not
            (((log.drop previous).zip entries).any
                (fun (pair : Entry Node TxId × Entry Node TxId) =>
                  pair.1.term != pair.2.term)
              = true)
          /\ next = log ++ entries.drop (log.length - previous))
        \/ next = log.take previous ++ entries)
    : next.take (previous + entries.length) = history.take (previous + entries.length)
      /\ previous + entries.length <= next.length
      /\ (previous + entries.length < next.length -> next = log) := by
  have previousBound : previous <= log.length := by
    rcases matching with zero | present
    · omega
    · exact present.1
  have previousAgreement : log.take previous = history.take previous := by
    by_cases zero : previous = 0
    · simp [zero]
    · rcases matching with impossible | present
      · exact absurd impossible zero
      exact agreeAt previous (by omega) previousBound (by omega) (present.2.trans historyTerm)
  have historyLength : (history.take previous).length = previous := by
    simp only [List.length_take]
    omega
  rcases shape with ⟨noConflict, nextEq⟩ | nextEq
  · by_cases covered : previous + entries.length <= log.length
    · have unchanged : next = log := by
        rw [nextEq, List.drop_eq_nil_of_le (by omega), List.append_nil]
      refine ⟨?_, by rw [unchanged]; omega, fun _ => unchanged⟩
      rw [unchanged]
      by_cases empty : entries.length = 0
      · rw [empty, Nat.add_zero, previousAgreement]
      exact agreeAt _ (by omega) covered historyBound
        (termAtOverlapOfNoConflict historyEnd historyBound noConflict (by omega) covered le_rfl)
    · have logAgreement : log = history.take log.length := by
        by_cases same : log.length = previous
        · rw [same, ← previousAgreement, List.take_of_length_le (by omega)]
        · have agreed :=
            agreeAt _ (by omega) le_rfl (by omega)
              (termAtOverlapOfNoConflict historyEnd historyBound noConflict (by omega) le_rfl
                (by omega))
          rwa [List.take_length] at agreed
      have historyPrefix :
          history.take log.length = history.take previous ++ entries.take (log.length - previous) := by
        have taken := congrArg (List.take log.length) historyEnd
        rw [List.take_take, Nat.min_eq_left (by omega), List.take_append, historyLength,
          List.take_of_length_le (l := history.take previous) (by rw [historyLength]; omega)]
          at taken
        exact taken
      have logHistory := logAgreement.trans historyPrefix
      have nextHistory : next = history.take (previous + entries.length) := by
        calc
          next = log ++ entries.drop (log.length - previous) := nextEq
          _ = history.take previous
              ++ entries.take (log.length - previous)
              ++ entries.drop (log.length - previous) := by
            rw [← logHistory]
          _ = history.take (previous + entries.length) := by
            rw [List.append_assoc, List.take_append_drop, historyEnd]
      have nextLength : next.length = previous + entries.length := by
        rw [nextHistory, List.length_take]
        omega
      refine ⟨?_, by omega, fun longer => by omega⟩
      rw [List.take_of_length_le (by omega), nextHistory]
  · have nextLength : next.length = previous + entries.length := by
      rw [nextEq]
      simp
      omega
    refine ⟨?_, by omega, fun longer => by omega⟩
    rw [List.take_of_length_le (by omega), nextEq, previousAgreement, historyEnd]

/--
An accepted request agrees with its immutable history through the end of the
request, and only keeps a longer suffix when the log is unchanged.
-/
lemma handledAppendRequestPrefixAgreement
    {state : Model.State Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    {destination : Node}
    {request : AppendRequestKey Node TxId}
    {nextNode : NodeState Node TxId}
    {response : AppendEntriesResponse}
    (requestMember
      : (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination))
    (snapshot : RequestSnapshots (appendHistory request) request)
    (post
      : AppendRequestLocalPost ((nodeOf state) destination) nextNode request.2.2 response)
    (success : response.success = true)
    : nextNode.log.take (request.2.2.prevLogIndex + request.2.2.entries.length)
        = (appendHistory request).take
            (request.2.2.prevLogIndex + request.2.2.entries.length)
      /\ request.2.2.prevLogIndex + request.2.2.entries.length <= nextNode.log.length
      /\ (request.2.2.prevLogIndex + request.2.2.entries.length < nextNode.log.length
          -> nextNode.log = ((nodeOf state) destination).log) :=
  appendedLogPrefixAgreement
    (fun _ positive nodeBound historyBound sameTerm =>
      queuedHistoryTakeAgreement ownership requestMember positive nodeBound historyBound
        sameTerm)
    snapshot.1 snapshot.2.1 snapshot.2.2 (post.successfulLogOk success)
    (by
      rcases post.successfulShape success with ⟨noConflict, logEq⟩ | ⟨-, logEq⟩
      · exact Or.inl ⟨noConflict, logEq⟩
      · exact Or.inr logEq)

/-- Advancing the commit index commits a prefix of the request history. -/
lemma handledAppendRequestAdvancedCommittedHistory
    (state : Model.State Node TxId)
    (votes : VoteHistory Node)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendRequestKey Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse)
    (requestMember
      : (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination))
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled
      : handleAppendEntriesRequest? (inferInstance) request.2.1
          ((nodeOf state) destination) request.2.2
        = some (nextNode, response))
    (advanced : ((nodeOf state) destination).commitIndex < nextNode.commitIndex)
    : nextNode.committedLog = (appendHistory request).take nextNode.commitIndex := by
  let post := handleAppendEntriesRequestLocalPost handled
  have succeeded : response.success = true := post.commitAdvancedSuccessful advanced
  have withinEnd :
      nextNode.commitIndex <= request.2.2.prevLogIndex + request.2.2.entries.length := by
    rcases le_max_iff.mp post.commitRequestEndBound with old | learned
    · omega
    · exact learned
  have agreement :=
    (handledAppendRequestPrefixAgreement ownership requestMember snapshot post succeeded).1
  have taken := congrArg (List.take nextNode.commitIndex) agreement
  simp only [List.take_take, min_eq_left withinEnd] at taken
  simpa [NodeState.committedLog] using taken

/-- A shared prefix covering the complete request makes the request already
present in the destination log. -/
lemma appendRequestAlreadyDoneOfSharedPrefix
    {before : NodeState Node TxId}
    {request : AppendRequestKey Node TxId}
    {history sharedPrefix : List (Entry Node TxId)}
    (snapshot : RequestSnapshots history request)
    (beforePrefix : sharedPrefix <+: before.log)
    (historyPrefix : sharedPrefix <+: history)
    (covers
      : request.2.2.prevLogIndex + request.2.2.entries.length <= sharedPrefix.length)
    : alreadyDone before request.2.2 := by
  right
  constructor
  · exact Nat.le_trans covers beforePrefix.length_le
  · have beforeTake :
        before.log.take
            (request.2.2.prevLogIndex + request.2.2.entries.length) =
          history.take
            (request.2.2.prevLogIndex + request.2.2.entries.length) := by
      calc
        before.log.take (request.2.2.prevLogIndex + request.2.2.entries.length)
            = sharedPrefix.take (request.2.2.prevLogIndex + request.2.2.entries.length) :=
          (takeEqOfPrefix beforePrefix covers).symm
        _ = history.take (request.2.2.prevLogIndex + request.2.2.entries.length) :=
          takeEqOfPrefix historyPrefix covers
    have exactEntries :
        (before.log.drop request.2.2.prevLogIndex).take
            request.2.2.entries.length =
          request.2.2.entries := by
      have dropped :=
        congrArg (List.drop request.2.2.prevLogIndex) beforeTake
      rw [snapshot.2.2] at dropped
      have previousBound :
          request.2.2.prevLogIndex <= history.length := by
        exact Nat.le_trans
          (Nat.le_add_right _ _) snapshot.1
      simpa [
        List.drop_take,
        List.length_take,
        previousBound
      ] using dropped
    rw [exactEntries]

/-- A successful request already represented in the destination log leaves
that log unchanged. -/
lemma successfulAlreadyDoneAppendLogUnchanged
    {before nextNode : NodeState Node TxId}
    {request : AppendRequestKey Node TxId}
    {response : AppendEntriesResponse}
    (already : alreadyDone before request.2.2)
    (handled
      : handleAppendEntriesRequest? (inferInstance) request.2.1 before request.2.2
        = some (nextNode, response))
    (success : response.success = true)
    : nextNode.log = before.log := by
  let post := handleAppendEntriesRequestLocalPost handled
  rcases already with empty | ⟨covered, terms⟩
  · rcases post.successfulShape success with ⟨-, logEq⟩ | ⟨conflict, -⟩
    · simp [logEq, empty]
    · simp [hasTermConflict, empty] at conflict
  · exact successfulAppendLogUnchangedOfTerms post success covered terms

/-- Successful handling retains every prefix shared by the old destination log
and the immutable queued request history. -/
lemma handledAppendRequestRetainsSharedPrefix
    (state : Model.State Node TxId)
    (votes : VoteHistory Node)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendRequestKey Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse)
    (requestMember
      : (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination))
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled
      : handleAppendEntriesRequest? (inferInstance) request.2.1
          ((nodeOf state) destination) request.2.2
        = some (nextNode, response))
    (success : response.success = true)
    {sharedPrefix : List (Entry Node TxId)}
    (beforePrefix : sharedPrefix <+: ((nodeOf state) destination).log)
    (historyPrefix : sharedPrefix <+: appendHistory request)
    : sharedPrefix <+: nextNode.log := by
  let post := handleAppendEntriesRequestLocalPost handled
  by_cases covers
    : request.2.2.prevLogIndex + request.2.2.entries.length <= sharedPrefix.length
  · rw [successfulAlreadyDoneAppendLogUnchanged
      (appendRequestAlreadyDoneOfSharedPrefix snapshot beforePrefix historyPrefix covers)
      handled success]
    exact beforePrefix
  · rcases handledAppendRequestPrefixAgreement ownership requestMember snapshot post success with
      ⟨agreement, bound, -⟩
    have shorter :
        sharedPrefix.length <= request.2.2.prevLogIndex + request.2.2.entries.length := by
      omega
    have historyTake := takeEqOfPrefix historyPrefix (le_refl sharedPrefix.length)
    rw [List.take_length] at historyTake
    rw [List.prefix_iff_eq_take]
    calc
      sharedPrefix = (appendHistory request).take sharedPrefix.length := historyTake
      _ = ((appendHistory request).take
            (request.2.2.prevLogIndex + request.2.2.entries.length)).take
            sharedPrefix.length := by
        rw [List.take_take, Nat.min_eq_left shorter]
      _ = nextNode.log.take sharedPrefix.length := by
        rw [← agreement, List.take_take, Nat.min_eq_left shorter]

/-- A queued AppendEntries request never carries its leader destination's own term. -/
lemma queuedAppendRequestNotOwnTerm
    {state : Model.State Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    {destination : Node}
    {request : AppendRequestKey Node TxId}
    (requestMember
      : appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
    : ((nodeOf state) destination).role = .leader
      -> request.2.2.term ≠ ((nodeOf state) destination).currentTerm := by
  intro role same
  have metadata := ownership.queuedAppendMetadata destination request requestMember
  have owner := ownership.activeLeader destination role
  rw [← same, metadata.2.1] at owner
  exact metadata.1 ((Option.some.inj owner).trans requestMember.2.symm)

/-- A leader only accepts requests from its own term, which it never sends to
itself; candidates step down before accepting. Either way active nodes are
unchanged. -/
lemma handleAppendEntriesRequestActiveUnchanged
    {before nextNode : NodeState Node TxId}
    {request : AppendRequestKey Node TxId}
    {response : AppendEntriesResponse}
    (notStepped
      : ¬ (request.2.2.term = before.currentTerm
            ∧ (before.role = .candidate ∨ before.role = .preVoteCandidate)))
    (notOwnTerm : before.role = .leader -> request.2.2.term ≠ before.currentTerm)
    (handled
      : handleAppendEntriesRequest? (inferInstance) request.2.1 before request.2.2
        = some (nextNode, response))
    (active : before.role = .candidate \/ before.role = .leader)
    : nextNode = before := by
  let post := handleAppendEntriesRequestLocalPost handled
  cases succeeded : response.success
  · exact post.failedStateUnchanged succeeded
  · have sameTerm := post.successfulCurrentTerm succeeded
    rcases active with candidate | leader
    · simp [sameTerm, candidate] at notStepped
    · exact absurd sameTerm (notOwnTerm leader)

/-- Every successful response acknowledges an index present in the resulting
destination log. -/
lemma successfulAppendResponseIndexWithinLog
    {before nextNode : NodeState Node TxId}
    {request : AppendRequestKey Node TxId}
    {response : AppendEntriesResponse}
    (handled
      : handleAppendEntriesRequest? (inferInstance) request.2.1 before request.2.2
        = some (nextNode, response))
    (success : response.success = true)
    : response.lastLogIndex <= nextNode.log.length := by
  let post := handleAppendEntriesRequestLocalPost handled
  have previousBound : request.2.2.prevLogIndex <= before.log.length := by
    rcases post.successfulLogOk success with zero | present
    · omega
    · exact present.1
  rw [post.successfulIndexExact success]
  rcases post.successfulShape success with ⟨-, logEq⟩ | ⟨-, logEq⟩
  · rw [logEq]
    simp
    omega
  · rw [logEq]
    simp
    omega

/-- A successful selected request materialises the corresponding source-log
prefix in the destination log. -/
lemma handledAppendRequestAcknowledgesSourcePrefix
    (state : Model.State Node TxId)
    (votes : VoteHistory Node)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendRequestKey Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse)
    (requestMember
      : (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination))
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled
      : handleAppendEntriesRequest? (inferInstance) request.2.1
          ((nodeOf state) destination) request.2.2
        = some (nextNode, response))
    (success : response.success = true)
    (sourceRole : ((nodeOf state) request.1).role = .leader)
    (requestTerm : request.2.2.term = ((nodeOf state) request.1).currentTerm)
    {index : Nat}
    (acknowledged : index <= response.lastLogIndex)
    : ((nodeOf state) request.1).log.take index <+: nextNode.log := by
  let post := handleAppendEntriesRequestLocalPost handled
  have withinEnd :
      index <= request.2.2.prevLogIndex + request.2.2.entries.length := by
    exact Nat.le_trans acknowledged (post.successfulIndexBound success)
  have historyBound : index <= (appendHistory request).length :=
    Nat.le_trans withinEnd snapshot.1
  have sourceHistory :=
    ownership.queuedActiveSourceHistory
      destination request requestMember requestTerm sourceRole
  have sourceBound : index <= ((nodeOf state) request.1).log.length :=
    Nat.le_trans historyBound sourceHistory.length_le
  rcases handledAppendRequestPrefixAgreement ownership requestMember snapshot post success with
    ⟨agreement, bound, -⟩
  have nextTake : nextNode.log.take index = (appendHistory request).take index := by
    have taken := congrArg (List.take index) agreement
    simpa [List.take_take, Nat.min_eq_left withinEnd] using taken
  rw [List.prefix_iff_eq_take]
  simp only [List.length_take, Nat.min_eq_left sourceBound]
  rw [nextTake]
  exact (takeEqOfPrefix sourceHistory historyBound).symm

/-- A handled request leaves every destination entry on its owned canonical
history, including entries copied from an immutable queued snapshot. -/
lemma handledAppendRequestCanonicalAgreement
    (state : Model.State Node TxId)
    (votes : VoteHistory Node)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (destination : Node)
    (request : AppendRequestKey Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse)
    (requestMember
      : (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination))
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled
      : handleAppendEntriesRequest? (inferInstance) request.2.1
          ((nodeOf state) destination) request.2.2
        = some (nextNode, response))
    : forall index entry,
        entryAt? nextNode.log index = some entry
        -> entryAt? (canonicalHistory entry.term) index = some entry
            /\ nextNode.log.take index = (canonicalHistory entry.term).take index := by
  let post := handleAppendEntriesRequestLocalPost handled
  intro index entry found
  cases succeeded : response.success
  · rw [post.failedStateUnchanged succeeded] at found ⊢
    exact ownership.logEntryAgreement destination index entry found
  rcases handledAppendRequestPrefixAgreement ownership requestMember snapshot post succeeded with
    ⟨agreement, bound, longer⟩
  by_cases within : index <= request.2.2.prevLogIndex + request.2.2.entries.length
  · have historyFound : entryAt? (appendHistory request) index = some entry := by
      rw [← entryAtTake_of_le within, ← agreement, entryAtTake_of_le within]
      exact found
    rcases
        ownership.queuedHistoryEntryAgreement
          destination request requestMember index entry historyFound with
      ⟨canonicalFound, agreed⟩
    refine ⟨canonicalFound, ?_⟩
    have taken := congrArg (List.take index) agreement
    simp only [List.take_take, Nat.min_eq_left within] at taken
    rw [taken, agreed]
  · have unchanged := longer (by have := entryAtSomeIndexBound found; omega)
    rw [unchanged] at found ⊢
    exact ownership.logEntryAgreement destination index entry found

/-- Canonical history monotonicity transfers to every represented node log. -/
lemma canonicalHistoriesMonoLog
    {state : Model.State Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
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
      entryAt? (((nodeOf state) node).log.take later) earlier =
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

/--
Canonical agreement locates a local log entry in its canonical history, whose
entry-owner fact then supplies the term owner.
-/
lemma termOwnershipLogEntryOwner
    {state : Model.State Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    {node : Node}
    {entry : Entry Node TxId}
    (member : entry ∈ ((nodeOf state) node).log)
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
    {state : Model.State Node TxId}
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
    {state : Model.State Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (node : Node)
    (index : Nat)
    : TermNumberValid (termAt ((nodeOf state) node).log index) := by
  by_cases zero : termAt ((nodeOf state) node).log index = 0
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
    {state : Model.State Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
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

/-- Canonical agreement transfers canonical monotonicity to any snapshot. -/
lemma canonicalSnapshotMono
    {state : Model.State Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
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
    {state : Model.State Node TxId}
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
    : term <= ((nodeOf state) voter).currentTerm := by
  by_contra notBounded
  have future :=
    voteFacts.future voter term (Nat.lt_of_not_ge notBounded)
  rw [electionFacts.voted term record voter recorded member] at future
  contradiction

/--
A candidate's persistent self-vote cannot belong to the empty bootstrap vote
history, so every candidate term is strictly above the bootstrap term.
-/
lemma candidatesSelfVoteAboveBootstrap
    {state : Model.State Node TxId}
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
      Not (((nodeOf state) candidate).currentTerm = BOOTSTRAP_TERM) := by
    intro termEq
    rw [termEq, voteFacts.bootstrapEmpty candidate] at currentVote
    contradiction
  omega

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

/-- Election frontier fields depend only on the log and commit index. -/
lemma lastCommittableIndexFrame
    {before after : NodeState Node TxId}
    (logEq : after.log = before.log)
    (commitEq : after.commitIndex = before.commitIndex)
    : lastCommittableIndex after = lastCommittableIndex before := by
  simp [lastCommittableIndex, logEq, commitEq]

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

/-- A voter accepting one committable prefix also accepts any monotone extension. -/
lemma voteLogUpToDateOfCandidatePrefix
    (voter : NodeState Node TxId)
    (_source _destination : Node)
    {candidatePrefix candidateHistory : List (Entry Node TxId)}
    (isPrefix : candidatePrefix <+: candidateHistory)
    (mono : MonoHistory candidateHistory)
    (upToDate
      : voteLogUpToDate voter
          {
            term := voter.currentTerm
            lastCommittableTerm := maxCommittableTerm candidatePrefix
            lastCommittableIndex := maxCommittableIndex candidatePrefix

          })
    : voteLogUpToDate voter
        {
          term := voter.currentTerm
          lastCommittableTerm := maxCommittableTerm candidateHistory
          lastCommittableIndex := maxCommittableIndex candidateHistory

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

/-- A candidate accepted against a longer voter log also passes its prefix. -/
lemma voteLogUpToDateOfVoterPrefix
    {beforeLog afterLog : List (Entry Node TxId)}
    (isPrefix : beforeLog <+: afterLog)
    (mono : MonoHistory afterLog)
    (before after : NodeState Node TxId)
    (request : VoteRequestKey Node)
    (beforeLogEq : before.log = beforeLog)
    (afterLogEq : after.log = afterLog)
    (upToDate : voteLogUpToDate after request.2.2)
    : voteLogUpToDate before request.2.2 := by
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

/-- Replying to one AppendEntries request cannot introduce another request. -/
lemma appendRequestMemberBeforeReply
    (state : Model.State Node TxId) (source : Node)
    (request : AppendRequestKey Node TxId) (response : AppendResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (taken : Selected source state.network (appendRequestEnvelope request) remaining)
    : forall queuedDestination queuedRequest,
        (appendRequestEnvelope queuedRequest ∈ reply remaining response
          ∧ queuedRequest.2.1 = queuedDestination)
        -> (appendRequestEnvelope queuedRequest ∈ state.network
            ∧ queuedRequest.2.1 = queuedDestination) := by
  intro queuedDestination queuedRequest member
  rcases List.mem_append.mp member.1 with old | added
  · exact ⟨(selectedSound taken).2.2 _ old, member.2⟩
  · simp [appendRequestEnvelope, appendResponseEnvelope] at added

/--
The evidence component of AppendEntries receive is fully preserved:
unchanged commits retain their node evidence, while advances inherit a
request evidence restricted to the request-end-bounded learned prefix.
-/
lemma receiveAppendRequestCommitEvidenceFacts
    (state : Model.State Node TxId)
    (source destination : Node)
    (present : destination ∈ state.nodes.map Prod.fst)
    (request : AppendRequestKey Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse)
    (remaining : List (Model.Envelope Node TxId))
    (votes : VoteHistory Node)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (commitBounded : CommitIndicesBounded state)
    (committedSignature : CommittedFrontierIsSignature state)
    (addressed : request.2.1 = destination)
    (taken : Selected source state.network (appendRequestEnvelope request) remaining)
    (handled
      : handleAppendEntriesRequest? (inferInstance) request.2.1
          ((nodeOf state) destination) request.2.2
        = some (nextNode, response))
    : CommitEvidenceFacts
        {
          state with
            nodes := replaceNode state.nodes destination nextNode
            network := (reply remaining (request.2.1, request.1, response))
        }
        appendHistory
        (appendRequestNodeEvidence
          state destination request nextNode
          nodeEvidence requestEvidence)
        requestEvidence := by
  have requestMember :
      (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination) :=
    ⟨(selectedSound taken).2.1, addressed⟩
  apply
    appendRequestCommitEvidenceFacts
      state destination present request nextNode response
        ((reply remaining (request.2.1, request.1, response)))
        appendHistory nodeEvidence requestEvidence evidenceFacts
        (commitBounded destination) (handleAppendEntriesRequestLocalPost handled) requestMember
  · intro advanced
    exact
      handledAppendRequestAdvancedCommittedHistory
        state votes appendHistory canonicalHistory owners ownership
          destination request nextNode response requestMember snapshot
          handled advanced
  · exact committedSignature destination
  · exact
      appendRequestMemberBeforeReply
        state source request (request.2.1, request.1, response) remaining taken

/-- Live evidence after AppendEntries receive is either unchanged or a
restriction of the selected request's pre-state evidence. -/
lemma receiveAppendRequestKnownEvidenceInherited
    (state : Model.State Node TxId)
    (source destination : Node)
    (present : destination ∈ state.nodes.map Prod.fst)
    (request : AppendRequestKey Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse)
    (remaining : List (Model.Envelope Node TxId))
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (_commitBounded : CommitIndicesBounded state)
    (addressed : request.2.1 = destination)
    (taken : Selected source state.network (appendRequestEnvelope request) remaining)
    (handled
      : handleAppendEntriesRequest? (inferInstance) request.2.1
          ((nodeOf state) destination) request.2.2
        = some (nextNode, response))
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (known
      : KnownCommitEvidence
          {
            state with
              nodes := replaceNode state.nodes destination nextNode
              network := (reply remaining (request.2.1, request.1, response))
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
      (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination) :=
    ⟨(selectedSound taken).2.1, addressed⟩
  rcases known with nodeKnown | requestKnown
  · rcases nodeKnown with
      ⟨node, positive, stored, prefixEq⟩
    by_cases same : node = destination
    · subst node
      have nextPositive : 0 < nextNode.commitIndex := by simpa [nodeOf_replaceNode, present] using positive
      by_cases unchanged :
          nextNode.commitIndex =
            ((nodeOf state) destination).commitIndex
      · have oldPositive :
            0 < ((nodeOf state) destination).commitIndex := by
          omega
        have oldStored :
            nodeEvidence destination = some evidence := by
          simpa [appendRequestNodeEvidence, unchanged] using stored
        exact ⟨
          evidence,
          ((nodeOf state) destination).committedLog,
          Or.inl ⟨destination, oldPositive, oldStored, rfl⟩,
          rfl,
          rfl,
          rfl,
          rfl,
          le_rfl
        ⟩
      · have advanced :
            ((nodeOf state) destination).commitIndex <
              nextNode.commitIndex := by
          have monotone := post.commitIndexMonotone
          omega
        have succeeded : response.success = true :=
          post.commitAdvancedSuccessful advanced
        have withinLeaderCommit :
            nextNode.commitIndex <= request.2.2.leaderCommit := by
          rcases le_max_iff.mp post.commitUpperBound with old | learned
          · omega
          · exact learned
        have leaderCommitPositive : 0 < request.2.2.leaderCommit := by
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
              (appendHistory request).take request.2.2.leaderCommit,
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
          0 < ((nodeOf state) node).commitIndex := by
        simpa [nodeOf_replaceNode, present, Function.update, same] using positive
      have oldStored :
          nodeEvidence node = some evidence := by
        simpa [appendRequestNodeEvidence, Function.update, same] using stored
      exact ⟨
        evidence,
        ((nodeOf state) node).committedLog,
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
      (appendHistory queuedRequest).take queuedRequest.2.2.leaderCommit,
      Or.inr
        ⟨
          queuedDestination,
          queuedRequest,
          appendRequestMemberBeforeReply
            state source request (request.2.1, request.1, response) remaining taken
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
    (state : Model.State Node TxId)
    (destination : Node)
    (request : AppendRequestKey Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse)
    (votes : VoteHistory Node)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
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
      : ProspectiveCommitEvidenceFacts (joined := joined)
          state appendHistory nodeEvidence requestEvidence elections)
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (known
      : KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    (ackMember : destination ∈ evidence.ackQuorum)
    (requestMember
      : (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination))
    (snapshot : RequestSnapshots (appendHistory request) request)
    (handled
      : handleAppendEntriesRequest? (inferInstance) request.2.1
          ((nodeOf state) destination) request.2.2
        = some (nextNode, response))
    : evidence.history.take evidence.commitFrontier <+: nextNode.log := by
  let post := handleAppendEntriesRequestLocalPost handled
  have currentPrefix :=
    prospectiveFacts.currentMember
      evidence supportedPrefix known destination ackMember
  by_cases succeeded : response.success = true
  · have requestCurrent :
        request.2.2.term = ((nodeOf state) destination).currentTerm :=
      post.successfulCurrentTerm succeeded
    by_cases older : evidence.commitTerm < request.2.2.term
    · exact
        handledAppendRequestRetainsSharedPrefix
          state votes appendHistory canonicalHistory owners ownership
            destination request nextNode response requestMember snapshot
            handled succeeded currentPrefix
            (knownCommitEvidenceQueuedAppendContainsFrontier
              ownership electionFacts electionQueuedFacts prospectiveFacts
                known requestMember older)
    · by_cases same : evidence.commitTerm = request.2.2.term
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
                alreadyDone ((nodeOf state) destination) request.2.2 :=
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
      · have greater : request.2.2.term < evidence.commitTerm := by omega
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
