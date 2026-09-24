-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.ConfigurationCoverage
import CCFRaft.Proofs.Invariant.TermAuthority
import CCFRaft.Proofs.Invariant.VotedForFrame
import CCFRaft.Proofs.Invariant.Effects
import CCFRaft.Proofs.Invariant.Safety
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

lemma positiveOfBootstrapTermLe {term : Nat} (bound : BOOTSTRAP_TERM <= term)
    : 0 < term :=
  Nat.lt_of_lt_of_le (by decide : 0 < BOOTSTRAP_TERM) bound

lemma invariantCurrentTermsValid
    {state : View Node TxId}
    (invariant : SystemInductiveInvariant state)
    : CurrentTermsValid state := by
  rcases invariant with ⟨_, _, _, _, _, _, facts⟩
  exact facts.currentTermsValid

omit [DecidableEq TxId] [Bootstrap Node] in
lemma networkTermsValidEnqueue
    {state : View Node TxId}
    {message : Message Node TxId}
    (valid : NetworkTermsValid state)
    (termValid : TermNumberValid message.term)
    : NetworkTermsValid { state with network := enqueue state.network message } := by
  intro destination queued member
  rcases memEnqueue state.network message queued destination member with
    old | added
  · exact valid destination queued old
  · rw [added.2]
    exact termValid

omit [Bootstrap Node] in
lemma networkTermsValidDequeue
    {state : View Node TxId}
    {source destination : Node}
    {message : Message Node TxId}
    {remaining : List (Message Node TxId)}
    (valid : NetworkTermsValid state)
    (taken : Selected source (state.network destination) message remaining)
    : NetworkTermsValid
        { state with network := updateQueue state.network destination remaining } := by
  intro peer queued member
  apply valid peer queued
  by_cases same : peer = destination
  · subst peer
    exact (selectedSound taken).2.2 queued
      (by simpa [updateQueue, Function.update] using member)
  · simpa [updateQueue, Function.update, same] using member

omit [DecidableEq TxId] [Bootstrap Node] in
/-- A same-term successful response to an active leader retains its snapshot. -/
lemma successfulResponseSnapshotCoveredOfLeader
    {state : View Node TxId}
    {history : List (Entry Node TxId)}
    {response : AppendEntriesResponse Node}
    (snapshot : SuccessfulResponseSnapshot state history response)
    (success : response.success = true)
    (sameTerm : response.term = (state.nodes response.destination).currentTerm)
    (leader : (state.nodes response.destination).role = .leader)
    : history <+: (state.nodes response.destination).log := by
  rcases snapshot success with ⟨_, _, destinationState⟩
  simpa [leader] using destinationState sameTerm

omit [DecidableEq Node] [Bootstrap Node] in
lemma Finset.subset_of_eq {left right : Finset Node} (same : left = right)
    : left ⊆ right := by
  rw [same]

omit [DecidableEq TxId] [Bootstrap Node] in
lemma AllocatedNodesExactlyJoined.frame
    {state after : View Node TxId}
    (facts : AllocatedNodesExactlyJoined state)
    (allocatedEq : forall node, after.allocated node <-> state.allocated node)
    (hasJoinedEq : after.hasJoined = state.hasJoined)
    : AllocatedNodesExactlyJoined after := by
  intro node
  rw [allocatedEq node, hasJoinedEq]
  exact facts node

lemma committedConfigurationCoverageFrame
    {state after : View Node TxId}
    {activations : ActivationHistory Node TxId}
    (facts : CommittedConfigurationCoverage state activations)
    (logEq : forall node, (after.nodes node).log = (state.nodes node).log)
    (commitEq
      : forall node, (after.nodes node).commitIndex = (state.nodes node).commitIndex)
    (termMonotone
      : forall node, (state.nodes node).currentTerm <= (after.nodes node).currentTerm)
    : CommittedConfigurationCoverage after activations := by
  intro node frontier within positive signature
  rcases
      facts node frontier
        (by simpa [commitEq] using within)
        (by simpa [logEq] using positive)
        (by simpa [logEq] using signature) with
    ⟨witness⟩
  refine ⟨⟨
            witness.activationIndex,
            witness.activation,
            witness.stored,
            by simpa [logEq] using witness.configurationCovered,
            witness.activationTermBound.trans (termMonotone node),
            by simpa [logEq] using witness.configurationIndexBound,
            by simpa [logEq] using witness.historyAgreement,
            ?_,
            ?_,
            ?_
          ⟩⟩
  · intro higherIndex higher stored order
    simpa [logEq]
      using witness.higherAuthority higherIndex higher stored
        (by simpa [logEq] using order)
  · intro lowerIndex lower stored order
    simpa [logEq]
      using witness.lowerAuthority lowerIndex lower stored (by simpa [logEq] using order)
  · intro sameIndex same stored sameConfiguration
    simpa [logEq]
      using witness.sameAuthority sameIndex same stored
        (by simpa [logEq] using sameConfiguration)

lemma queuedConfigurationCoverageFrame
    {state after : View Node TxId}
    {appendHistory afterAppendHistory
      : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {activations : ActivationHistory Node TxId}
    (facts : QueuedConfigurationCoverage state appendHistory activations)
    (networkBack
      : forall destination request,
          Message.appendEntriesRequest request ∈ after.network destination
          -> Message.appendEntriesRequest request ∈ state.network destination)
    (historyEq : forall request, afterAppendHistory request = appendHistory request)
    : QueuedConfigurationCoverage after afterAppendHistory activations := by
  intro destination request queued frontier within positive signature
  rcases
      facts destination request (networkBack destination request queued)
        frontier within
        (by simpa [historyEq] using positive)
        (by simpa [historyEq] using signature) with
    ⟨witness⟩
  exact ⟨by simpa [historyEq] using witness⟩

omit [DecidableEq TxId] in
lemma currentConfigurationAt_append_of_le_length
    (log : List (Entry Node TxId))
    (entry : Entry Node TxId)
    (frontier : Nat)
    (within : frontier <= log.length)
    : currentConfigurationAt (log ++ [entry]) frontier
      = currentConfigurationAt log frontier := by
  cases content : entry.content <;>
    simp [
      currentConfigurationAt, configurationsInLog,
      configurationsInLogFrom_append, configurationsInLogFrom,
      content
    ]
  omega

omit [DecidableEq TxId] in
/-- Current configuration depends only on the log through its frontier. -/
lemma currentConfigurationAt_eq_of_take_eq
    {left right : List (Entry Node TxId)}
    {frontier : Nat}
    (leftBound : frontier <= left.length)
    (rightBound : frontier <= right.length)
    (takeEq : left.take frontier = right.take frontier)
    : currentConfigurationAt left frontier = currentConfigurationAt right frontier := by
  let leftNode : NodeState Node TxId :=
    { initialNodeState (TxId := TxId) INITIAL_LEADER with
      log := left
      commitIndex := frontier }
  let rightNode : NodeState Node TxId :=
    { initialNodeState (TxId := TxId) INITIAL_LEADER with
      log := right
      commitIndex := frontier }
  have leftCurrentKnown :
      currentConfigurationAt left frontier ∈ allConfigurations left := by
    simpa [leftNode, currentConfiguration]
      using currentConfiguration_mem_allConfigurations leftNode
  have rightCurrentKnown :
      currentConfigurationAt right frontier ∈ allConfigurations right := by
    simpa [rightNode, currentConfiguration]
      using currentConfiguration_mem_allConfigurations rightNode
  have leftCurrentBound :
      (currentConfigurationAt left frontier).index <= frontier := by
    simpa [leftNode, currentConfiguration]
      using currentConfiguration_index_le_commitIndex leftNode
  have rightCurrentBound :
      (currentConfigurationAt right frontier).index <= frontier := by
    simpa [rightNode, currentConfiguration]
      using currentConfiguration_index_le_commitIndex rightNode
  have leftKnownRight :
      currentConfigurationAt left frontier ∈ allConfigurations right := by
    apply
      CCFRaft.Proofs.Invariant.memOfPrefix
        (allConfigurations_mono_prefix
          (List.take_prefix frontier right))
    rw [← takeEq]
    exact
      allConfigurations_mem_take_of_index_le
        left frontier leftBound leftCurrentKnown leftCurrentBound
  have rightKnownLeft :
      currentConfigurationAt right frontier ∈ allConfigurations left := by
    apply
      CCFRaft.Proofs.Invariant.memOfPrefix
        (allConfigurations_mono_prefix
          (List.take_prefix frontier left))
    rw [takeEq]
    exact
      allConfigurations_mem_take_of_index_le
        right frontier rightBound rightCurrentKnown rightCurrentBound
  have leftLeRight :
      (currentConfigurationAt left frontier).index <=
        (currentConfigurationAt right frontier).index := by
    simpa [rightNode, currentConfiguration]
      using configuration_index_le_currentConfiguration
        rightNode (currentConfigurationAt left frontier)
        (by simpa [rightNode] using leftKnownRight)
        (by simpa [rightNode] using leftCurrentBound)
  have rightLeLeft :
      (currentConfigurationAt right frontier).index <=
        (currentConfigurationAt left frontier).index := by
    simpa [leftNode, currentConfiguration]
      using configuration_index_le_currentConfiguration
        leftNode (currentConfigurationAt right frontier)
        (by simpa [leftNode] using rightKnownLeft)
        (by simpa [leftNode] using rightCurrentBound)
  exact
    allConfigurations_index_unique
      (TxId := TxId) right
      leftKnownRight rightCurrentKnown
      (Nat.le_antisymm leftLeRight rightLeLeft)

lemma committedConfigurationCoverageTakeFrame
    {state after : View Node TxId}
    {activations : ActivationHistory Node TxId}
    (facts : CommittedConfigurationCoverage state activations)
    (oldCommitBound : CommitIndicesBounded state)
    (afterCommitBound : CommitIndicesBounded after)
    (commitEq
      : forall node, (after.nodes node).commitIndex = (state.nodes node).commitIndex)
    (termMonotone
      : forall node, (state.nodes node).currentTerm <= (after.nodes node).currentTerm)
    (logTakeEq
      : forall node frontier,
          frontier <= (state.nodes node).commitIndex
          -> (after.nodes node).log.take frontier = (state.nodes node).log.take frontier)
    : CommittedConfigurationCoverage after activations := by
  intro node frontier within positive signature
  have oldWithin :
      frontier <= (state.nodes node).commitIndex := by
    simpa [commitEq] using within
  have frontierEq := logTakeEq node frontier oldWithin
  have configurationEq :
      currentConfigurationAt (after.nodes node).log frontier =
        currentConfigurationAt (state.nodes node).log frontier := by
    apply currentConfigurationAt_eq_of_take_eq
    · exact within.trans (afterCommitBound node)
    · exact oldWithin.trans (oldCommitBound node)
    · exact frontierEq
  rcases
      facts node frontier oldWithin
        (by simpa [configurationEq] using positive)
        (by
          have afterTake :=
            isSignatureAt_take_of_le le_rfl signature
          rw [frontierEq] at afterTake
          exact
            isSignatureAt_of_prefix
              (List.take_prefix frontier (state.nodes node).log)
              afterTake) with
    ⟨witness⟩
  refine ⟨⟨
            witness.activationIndex,
            witness.activation,
            witness.stored,
            by simpa [configurationEq] using witness.configurationCovered,
            witness.activationTermBound.trans (termMonotone node),
            by simpa [configurationEq] using witness.configurationIndexBound,
            ?_,
            ?_,
            ?_,
            ?_
          ⟩⟩
  · have sharedWithin :
        min frontier witness.activation.activationFrontier <=
          (state.nodes node).commitIndex :=
      (Nat.min_le_left _ _).trans oldWithin
    simpa [logTakeEq node _ sharedWithin] using witness.historyAgreement
  · intro higherIndex higher stored order
    simpa [configurationEq]
      using witness.higherAuthority higherIndex higher stored
        (by simpa [configurationEq] using order)
  · intro lowerIndex lower stored order
    simpa [configurationEq]
      using witness.lowerAuthority lowerIndex lower stored
        (by simpa [configurationEq] using order)
  · intro sameIndex same stored sameConfiguration
    simpa [configurationEq]
      using witness.sameAuthority sameIndex same stored
        (by simpa [configurationEq] using sameConfiguration)

/-- Restricting evidence preserves its actual commit and ACK support. -/
lemma commitEvidenceRestrictValid
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    {shorterLength : Nat}
    (valid : evidence.Valid supportedPrefix)
    (shorter : shorterLength <= evidence.supportedLength)
    (shorterSignature
      : 0 < shorterLength -> isSignatureAt evidence.history shorterLength = true)
    : (evidence.restrict shorterLength).Valid (evidence.history.take shorterLength) := by
  rcases valid with
    ⟨frontierBound, frontierTerm, supportedBound, _,
      authority, majority, frontierSignature, _⟩
  exact ⟨
    by simpa [CommitEvidence.restrict] using frontierBound,
    by simpa [CommitEvidence.restrict] using frontierTerm,
    by simpa [CommitEvidence.restrict] using Nat.le_trans shorter supportedBound,
    by simp [CommitEvidence.restrict],
    by simpa [CommitEvidence.restrict] using authority,
    by simpa [CommitEvidence.restrict] using majority,
    by simpa [CommitEvidence.restrict] using frontierSignature,
    by simpa [CommitEvidence.restrict] using shorterSignature
  ⟩

/-- Every live node/request evidence slot exposes a valid evidence. -/
lemma knownCommitEvidenceValid
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (facts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (known
      : KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    : evidence.Valid supportedPrefix := by
  rcases known with nodeKnown | requestKnown
  · rcases nodeKnown with
      ⟨node, positive, storedKnown, prefixEq⟩
    rcases facts.nodePositive node positive with
      ⟨storedEvidence, stored, valid, _, _⟩
    have evidenceEq : storedEvidence = evidence :=
      Option.some.inj (stored.symm.trans storedKnown)
    subst storedEvidence
    simpa [prefixEq] using valid
  · rcases requestKnown with
      ⟨destination, request, member, positive, storedKnown, prefixEq⟩
    rcases facts.requestPositive destination request member positive with
      ⟨storedEvidence, stored, valid, _, _⟩
    have evidenceEq : storedEvidence = evidence :=
      Option.some.inj (stored.symm.trans storedKnown)
    subst storedEvidence
    simpa [prefixEq] using valid

def configurationFrontierCoverageFrame
    {activations : ActivationHistory Node TxId}
    {oldHistory newHistory : List (Entry Node TxId)}
    {frontier oldTerm newTerm : Nat}
    (witness
      : ConfigurationFrontierCoverageWitness activations oldHistory frontier oldTerm)
    (oldBound : frontier <= oldHistory.length)
    (newBound : frontier <= newHistory.length)
    (takeEq : newHistory.take frontier = oldHistory.take frontier)
    (termMonotone : oldTerm <= newTerm)
    : ConfigurationFrontierCoverageWitness activations newHistory frontier newTerm := by
  have configurationEq :
      currentConfigurationAt newHistory frontier =
        currentConfigurationAt oldHistory frontier :=
    currentConfigurationAt_eq_of_take_eq
      newBound oldBound takeEq
  refine ⟨
    witness.activationIndex,
    witness.activation,
    witness.stored,
    by simpa [configurationEq] using witness.configurationCovered,
    witness.activationTermBound.trans termMonotone,
    by simpa [configurationEq] using witness.configurationIndexBound,
    ?_,
    ?_,
    ?_,
    ?_
  ⟩
  · have sharedWithin :
        min frontier witness.activation.activationFrontier <= frontier :=
      Nat.min_le_left _ _
    have sharedEq :
        newHistory.take
            (min frontier witness.activation.activationFrontier) =
          oldHistory.take
            (min frontier witness.activation.activationFrontier) := by
      have agreed :=
        congrArg
          (fun history =>
            history.take
              (min frontier witness.activation.activationFrontier))
          takeEq
      simpa [
        List.take_take,
        Nat.min_eq_left sharedWithin
      ] using agreed
    simpa [sharedEq] using witness.historyAgreement
  · intro higherIndex higher stored order
    simpa [configurationEq]
      using witness.higherAuthority higherIndex higher stored
        (by simpa [configurationEq] using order)
  · intro lowerIndex lower stored order
    simpa [configurationEq]
      using witness.lowerAuthority lowerIndex lower stored
        (by simpa [configurationEq] using order)
  · intro sameIndex same stored sameConfiguration
    simpa [configurationEq]
      using witness.sameAuthority sameIndex same stored
        (by simpa [configurationEq] using sameConfiguration)

def configurationCoverageWitnessNodeFrame
    {state after : View Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    (nodeEq : after.nodes node = state.nodes node)
    : ConfigurationCoverageWitness after activations node := by
  refine ⟨
    witness.activationIndex,
    witness.activation,
    witness.stored,
    by simpa [nodeEq] using witness.configurationCovered,
    by simpa [nodeEq] using witness.activationTermBound,
    by simpa [nodeEq] using witness.configurationIndexBound,
    by simpa [nodeEq] using witness.historyAgreement,
    ?_,
    ?_,
    ?_,
    ?_
  ⟩
  · intro higherIndex higher stored order
    simpa [nodeEq]
      using witness.higherAuthority higherIndex higher stored
        (by simpa [nodeEq] using order)
  · intro lowerIndex lower stored order
    simpa [nodeEq]
      using witness.lowerAuthority lowerIndex lower stored (by simpa [nodeEq] using order)
  · intro sameIndex same stored sameConfiguration
    simpa [nodeEq]
      using witness.sameAuthority sameIndex same stored
        (by simpa [nodeEq] using sameConfiguration)
  · intro role
    simpa [nodeEq] using witness.candidateTermStrict (by simpa [nodeEq] using role)

/-- Every live evidence supports a nonempty prefix. -/
lemma knownCommitEvidenceSupportedLengthPositive
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (facts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (known
      : KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    : 0 < evidence.supportedLength := by
  rcases known with nodeKnown | requestKnown
  · rcases nodeKnown with
      ⟨node, positive, storedKnown, _⟩
    rcases facts.nodePositive node positive with
      ⟨storedEvidence, stored, _, supportedLength, _⟩
    have evidenceEq : storedEvidence = evidence :=
      Option.some.inj (stored.symm.trans storedKnown)
    subst storedEvidence
    omega
  · rcases requestKnown with
      ⟨destination, request, member, positive, storedKnown, _⟩
    rcases facts.requestPositive destination request member positive with
      ⟨storedEvidence, stored, _, supportedLength, _⟩
    have evidenceEq : storedEvidence = evidence :=
      Option.some.inj (stored.symm.trans storedKnown)
    subst storedEvidence
    omega

/-- Frame changes preserve commit evidence when committed prefixes do not change. -/
lemma commitEvidenceFrame
    (state after : View Node TxId)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    (facts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (commitEq
      : forall node, (after.nodes node).commitIndex = (state.nodes node).commitIndex)
    (committedEq
      : forall node, (after.nodes node).committedLog = (state.nodes node).committedLog)
    (termMonotone
      : forall node, (state.nodes node).currentTerm <= (after.nodes node).currentTerm)
    (networkSubset
      : forall destination request,
          Message.appendEntriesRequest request ∈ after.network destination
          -> Message.appendEntriesRequest request ∈ state.network destination)
    : CommitEvidenceFacts after appendHistory nodeEvidence requestEvidence := by
  constructor
  · intro node positive
    have oldPositive :
        0 < (state.nodes node).commitIndex := by
      simpa [commitEq] using positive
    rcases facts.nodePositive node oldPositive with
      ⟨evidence, stored, valid, lengthEq, termBound⟩
    exact ⟨
      evidence,
      stored,
      by simpa [committedEq] using valid,
      by simpa [commitEq] using lengthEq,
      Nat.le_trans termBound (termMonotone node)
    ⟩
  · intro destination request member positive
    exact
      facts.requestPositive destination request
        (networkSubset destination request member) positive

/-- A relaxed voter in a frame either maps back or proves the result. -/
def RelaxedMemberFrameResult
    (state after : View Node TxId)
    (evidence : CommitEvidence Node TxId)
    (candidate member : Node)
    : Prop :=
  ((state.nodes candidate).role = .candidate
    /\ evidence.commitTerm < (state.nodes candidate).currentTerm
    /\ (forall entry,
          entry ∈ (state.nodes candidate).log
          -> entry.term < (state.nodes candidate).currentTerm)
    /\ member ∈ relaxedElectionVoters state candidate
    /\ (state.nodes candidate).log <+: (after.nodes candidate).log)
  \/ evidence.history.take evidence.commitFrontier <+: (after.nodes candidate).log

/-- Same-term queued comparability either maps back or is proved directly. -/
def SameTermQueuedFrameResult
    (state : View Node TxId)
    (oldAppendHistory newAppendHistory
      : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (evidence : CommitEvidence Node TxId)
    (destination : Node)
    (request : AppendEntriesRequest Node TxId)
    : Prop :=
  (Message.appendEntriesRequest request ∈ state.network destination
    /\ oldAppendHistory request = newAppendHistory request)
  \/ newAppendHistory request <+: evidence.history
  \/ evidence.history.take evidence.commitFrontier <+: newAppendHistory request

omit [Bootstrap Node] in
/-- Frame preservation for the member-wise prospective commit witness. -/
lemma prospectiveCommitEvidenceFrame
    (state after : View Node TxId)
    (oldAppendHistory newAppendHistory
      : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (oldNodeEvidence newNodeEvidence : NodeCommitEvidence Node TxId)
    (oldRequestEvidence newRequestEvidence : RequestCommitEvidence Node TxId)
    (elections : ElectionHistory Node TxId)
    (oldFacts
      : ProspectiveCommitEvidenceFacts
          state oldAppendHistory oldNodeEvidence oldRequestEvidence elections)
    (knownBack
      : forall evidence supportedPrefix,
          KnownCommitEvidence
            after newAppendHistory newNodeEvidence newRequestEvidence
            evidence supportedPrefix
          -> KnownCommitEvidence
              state oldAppendHistory oldNodeEvidence oldRequestEvidence
              evidence supportedPrefix)
    (currentBack : forall member, (state.nodes member).log <+: (after.nodes member).log)
    (sameTermQueuedBack
      : forall evidence supportedPrefix destination request,
          KnownCommitEvidence
            after newAppendHistory newNodeEvidence newRequestEvidence
            evidence supportedPrefix
          -> Message.appendEntriesRequest request ∈ after.network destination
          -> evidence.commitTerm = request.term
          -> SameTermQueuedFrameResult
              state oldAppendHistory newAppendHistory
              evidence destination request)
    (relaxedBack
      : forall evidence supportedPrefix candidate member,
          KnownCommitEvidence
            after newAppendHistory newNodeEvidence newRequestEvidence
            evidence supportedPrefix
          -> (after.nodes candidate).role = .candidate
          -> evidence.commitTerm < (after.nodes candidate).currentTerm
          -> (forall entry,
                entry ∈ (after.nodes candidate).log
                -> entry.term < (after.nodes candidate).currentTerm)
          -> member ∈ evidence.ackQuorum
          -> member ∈ relaxedElectionVoters after candidate
          -> RelaxedMemberFrameResult state after evidence candidate member)
    : ProspectiveCommitEvidenceFacts
        after newAppendHistory newNodeEvidence newRequestEvidence elections := by
  constructor
  · intro evidence supportedPrefix known
    exact
      oldFacts.commitTermPositive
        evidence supportedPrefix
          (knownBack evidence supportedPrefix known)
  · intro evidence supportedPrefix known term record recorded newer
    exact
      oldFacts.electionClosure
        evidence supportedPrefix
          (knownBack evidence supportedPrefix known)
          term record recorded newer
  · intro evidence supportedPrefix known member ackMember
    exact (oldFacts.currentMember
            evidence supportedPrefix
            (knownBack evidence supportedPrefix known)
            member ackMember).trans
      (currentBack member)
  · intro evidence supportedPrefix known destination request queued sameTerm
    rcases
        sameTermQueuedBack
          evidence supportedPrefix destination request
            known queued sameTerm with
      old | direct
    · simpa [old.2]
        using oldFacts.sameTermQueuedComparable
          evidence supportedPrefix
          (knownBack evidence supportedPrefix known)
          destination request old.1 sameTerm
    · exact direct
  · intro evidence supportedPrefix known candidate member role newer
      entriesBefore ackMember relaxed
    rcases
        relaxedBack
          evidence supportedPrefix candidate member known role newer
            entriesBefore ackMember relaxed with
      old | direct
    · rcases old with
        ⟨oldRole, oldNewer, oldEntriesBefore,
          oldRelaxed, logPrefix⟩
      exact (oldFacts.relaxedSupporterCarriesFrontier
              evidence supportedPrefix
              (knownBack evidence supportedPrefix known)
              candidate member oldRole oldNewer oldEntriesBefore
              ackMember oldRelaxed).trans
        logPrefix
    · exact direct

omit [DecidableEq TxId] in
/-- Every member of an active configuration belongs to its active-node union. -/
lemma configurationNodes_subset_activeNodeUnion
    (nodeState : NodeState Node TxId)
    (configuration : Configuration Node)
    (active : configuration ∈ activeConfigurations nodeState)
    : configuration.nodes ⊆ activeNodeUnion nodeState := by
  unfold activeNodeUnion
  generalize activeConfigurations nodeState = configurations at active ⊢
  have foldlPreserves :
      forall (remaining : List (Configuration Node)) (accumulator : Finset Node),
        accumulator ⊆
          remaining.foldl
            (fun nodes current => nodes ∪ current.nodes)
            accumulator := by
    intro remaining
    induction remaining with
    | nil => exact fun _ => Finset.Subset.rfl
    | cons head tail inductionHypothesis =>
        intro accumulator
        exact
          Finset.Subset.trans Finset.subset_union_left
            (inductionHypothesis (accumulator ∪ head.nodes))
  have foldlMono :
      forall (remaining : List (Configuration Node)) {left right : Finset Node},
        left ⊆ right ->
          remaining.foldl
              (fun nodes current => nodes ∪ current.nodes) left ⊆
            remaining.foldl
              (fun nodes current => nodes ∪ current.nodes) right := by
    intro remaining
    induction remaining with
    | nil => exact fun included => included
    | cons head tail inductionHypothesis =>
        intro left right included
        apply inductionHypothesis
        intro peer member
        simp only [Finset.mem_union] at member ⊢
        rcases member with member | member
        · exact Or.inl (included member)
        · exact Or.inr member
  induction configurations generalizing configuration with
  | nil => simp at active
  | cons head tail inductionHypothesis =>
      simp only [List.mem_cons] at active
      rcases active with same | active
      · subst configuration
        exact
          Finset.Subset.trans Finset.subset_union_right
            (foldlPreserves tail (∅ ∪ head.nodes))
      · exact
          Finset.Subset.trans
            (inductionHypothesis configuration active)
            (foldlMono tail Finset.subset_union_left)

omit [DecidableEq TxId] in
/-- Shrinking the active configuration list can only shrink its node union. -/
lemma activeNodeUnion_subset_of_activeConfigurations_subset
    (before after : NodeState Node TxId)
    (subset
      : forall configuration,
          configuration ∈ activeConfigurations after
          -> configuration ∈ activeConfigurations before)
    : activeNodeUnion after ⊆ activeNodeUnion before := by
  intro peer member
  unfold activeNodeUnion at member
  generalize configurationsEq :
    activeConfigurations after = configurations at member
  have foldMember :
      forall (remaining : List (Configuration Node))
        (accumulator : Finset Node),
        peer ∈ remaining.foldl
            (fun nodes configuration => nodes ∪ configuration.nodes)
            accumulator ->
          peer ∈ accumulator \/
            Exists fun configuration =>
              configuration ∈ remaining /\ peer ∈ configuration.nodes := by
    intro remaining
    induction remaining with
    | nil =>
        intro accumulator included
        exact Or.inl included
    | cons head tail inductionHypothesis =>
        intro accumulator included
        simp only [List.foldl_cons] at included
        rcases inductionHypothesis (accumulator ∪ head.nodes) included with
          old | ⟨configuration, inTail, inNodes⟩
        · simp only [Finset.mem_union] at old
          rcases old with old | inHead
          · exact Or.inl old
          · exact Or.inr ⟨head, by simp, inHead⟩
        · exact Or.inr ⟨configuration, by simp [inTail], inNodes⟩
  rcases foldMember configurations ∅ member with
    impossible | ⟨configuration, active, inNodes⟩
  · simp at impossible
  · apply
      configurationNodes_subset_activeNodeUnion before configuration
        (subset configuration (by simpa [configurationsEq] using active))
    exact inNodes

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Configuration node sets do not depend on the projection's starting index. -/
lemma configurationsInLogFrom_node_sets_independent
    (leftStart rightStart : Nat)
    (log : List (Entry Node TxId))
    : (configurationsInLogFrom leftStart log).map Configuration.nodes
      = (configurationsInLogFrom rightStart log).map Configuration.nodes := by
  induction log generalizing leftStart rightStart with
  | nil => simp [configurationsInLogFrom]
  | cons entry entries inductionHypothesis =>
      cases content : entry.content <;>
        simp [
          configurationsInLogFrom, content,
          inductionHypothesis (leftStart := leftStart + 1)
            (rightStart := rightStart + 1)
        ]

omit [DecidableEq TxId] in
/-- The latest projected configuration is among all known configurations. -/
lemma latestConfiguration_mem_allConfigurations (nodeState : NodeState Node TxId)
    : latestConfiguration nodeState ∈ allConfigurations nodeState.log := by
  unfold latestConfiguration allConfigurations
  generalize configurationsInLog nodeState.log = configurations
  have foldMember :
      forall (remaining : List (Configuration Node)) accumulator,
          remaining.foldl (fun _ configuration => configuration) accumulator =
              accumulator \/
            remaining.foldl (fun _ configuration => configuration) accumulator ∈
              remaining := by
    intro remaining
    induction remaining with
    | nil => intro accumulator; exact Or.inl rfl
    | cons head tail inductionHypothesis =>
        intro accumulator
        rcases inductionHypothesis head with same | member
        · exact Or.inr (by simp [same])
        · exact Or.inr (by simp [member])
  rcases foldMember configurations implicitConfiguration with same | member
  · exact List.mem_cons.mpr (Or.inl same)
  · exact List.mem_cons.mpr (Or.inr member)

omit [DecidableEq TxId] in
/-- Configuration carriers compose across concatenated logs. -/
lemma allConfigurations_append_nodes_carried
    (left right : List (Entry Node TxId))
    (carrier : Finset Node)
    (leftCarried
      : forall configuration,
          configuration ∈ allConfigurations left -> configuration.nodes ⊆ carrier)
    (rightCarried
      : forall configuration,
          configuration ∈ allConfigurations right -> configuration.nodes ⊆ carrier)
    : forall configuration,
        configuration ∈ allConfigurations (left ++ right)
        -> configuration.nodes ⊆ carrier := by
  intro configuration member
  rw [allConfigurations] at member
  rcases List.mem_cons.mp member with implicit | physical
  · subst configuration
    exact
      leftCarried implicitConfiguration
        (by simp [allConfigurations])
  · rw [
      configurationsInLog, configurationsInLogFrom_append
    ] at physical
    rcases List.mem_append.mp physical with inLeft | inRight
    · exact
        leftCarried configuration
          (by
            rw [allConfigurations]
            exact List.mem_cons.mpr (Or.inr inLeft))
    · have nodeSetMember :
          configuration.nodes ∈
            (configurationsInLogFrom 1 right).map Configuration.nodes := by
        rw [
          ← configurationsInLogFrom_node_sets_independent
            (TxId := TxId) (1 + left.length) 1 right
        ]
        exact List.mem_map.mpr ⟨configuration, inRight, rfl⟩
      rcases List.mem_map.mp nodeSetMember with
        ⟨original, originalMember, sameNodes⟩
      rw [← sameNodes]
      exact
        rightCarried original
          (by
            rw [allConfigurations, configurationsInLog]
            exact List.mem_cons.mpr (Or.inr originalMember))

omit [DecidableEq TxId] in
/-- A log suffix inherits the node carrier of the complete log. -/
lemma allConfigurations_suffix_nodes_carried
    (left right : List (Entry Node TxId))
    (carrier : Finset Node)
    (carried
      : forall configuration,
          configuration ∈ allConfigurations (left ++ right)
          -> configuration.nodes ⊆ carrier)
    : forall configuration,
        configuration ∈ allConfigurations right -> configuration.nodes ⊆ carrier := by
  intro configuration member
  rw [allConfigurations] at member
  rcases List.mem_cons.mp member with implicit | physical
  · subst configuration
    exact
      carried implicitConfiguration
        (by simp [allConfigurations])
  · have nodeSetMember :
        configuration.nodes ∈
          (configurationsInLogFrom (1 + left.length) right).map
            Configuration.nodes := by
      rw [
        configurationsInLogFrom_node_sets_independent
          (TxId := TxId) (1 + left.length) 1 right
      ]
      exact List.mem_map.mpr
        ⟨configuration, by simpa [configurationsInLog] using physical, rfl⟩
    rcases List.mem_map.mp nodeSetMember with
      ⟨shifted, shiftedMember, sameNodes⟩
    rw [← sameNodes]
    apply carried shifted
    rw [
      allConfigurations, configurationsInLog,
      configurationsInLogFrom_append
    ]
    exact List.mem_cons.mpr
      (Or.inr (List.mem_append.mpr (Or.inr shiftedMember)))

omit [DecidableEq TxId] in
/-- Covering every known configuration covers the active-node union. -/
lemma activeNodeUnion_subset_of_allConfigurations_carrier
    (nodeState : NodeState Node TxId)
    (carrier : Finset Node)
    (covered
      : forall configuration,
          configuration ∈ allConfigurations nodeState.log
          -> configuration.nodes ⊆ carrier)
    : activeNodeUnion nodeState ⊆ carrier := by
  unfold activeNodeUnion
  have foldCovered :
        forall (configurations : List (Configuration Node))
          (accumulator : Finset Node),
          accumulator ⊆ carrier ->
          (forall configuration,
            configuration ∈ configurations ->
              configuration.nodes ⊆ carrier) ->
          configurations.foldl
              (fun nodes configuration => nodes ∪ configuration.nodes)
              accumulator ⊆ carrier := by
    intro configurations
    induction configurations with
    | nil =>
        intro accumulator accumulatorCovered _
        exact accumulatorCovered
    | cons head tail inductionHypothesis =>
        intro accumulator accumulatorCovered configurationsCovered
        apply inductionHypothesis
        · exact
            Finset.union_subset accumulatorCovered
              (configurationsCovered head (by simp))
        · intro configuration member
          exact configurationsCovered configuration (by simp [member])
  apply foldCovered (activeConfigurations nodeState) ∅
  · exact Finset.empty_subset _
  · intro configuration member
    apply covered configuration
    exact (List.mem_filter.mp member).1

omit [Bootstrap Node] in
/-- Support inclusion only matters on members of the governing configuration. -/
lemma hasConfigurationMajority_mono_on_configuration
    {configuration : Configuration Node}
    {smaller larger : Finset Node}
    (subset : forall node, node ∈ smaller -> node ∈ configuration.nodes -> node ∈ larger)
    (majority : hasConfigurationMajority smaller configuration)
    : hasConfigurationMajority larger configuration := by
  unfold hasConfigurationMajority at majority ⊢
  apply
    lt_of_lt_of_le majority
      (Nat.mul_le_mul_right 2 (Finset.card_le_card ?_))
  intro node member
  exact
    Finset.mem_inter.mpr
      ⟨subset node
          (Finset.mem_inter.mp member).1
          (Finset.mem_inter.mp member).2,
        (Finset.mem_inter.mp member).2⟩

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- A successful one-based log lookup has a positive index. -/
lemma entryAtSomeIndexPositive
    {log : List (Entry Node TxId)}
    {index : Nat}
    {entry : Entry Node TxId}
    (found : entryAt? log index = some entry)
    : 0 < index := by
  by_contra notPositive
  have zero : index = 0 := Nat.eq_zero_of_not_pos notPositive
  subst index
  simp [entryAt?] at found

omit [Bootstrap Node] in
/-- A signature can occur only at a positive log index. -/
lemma isSignatureAtIndexPositive
    {log : List (Entry Node TxId)}
    {index : Nat}
    (signature : isSignatureAt log index = true)
    : 0 < index := by
  rcases isSignatureAtTrue signature with ⟨entry, found, _⟩
  exact entryAtSomeIndexPositive found

omit [DecidableEq TxId] in
/-- Frame joined carriers through shrinking configurations and vote sets. -/
lemma joinedCarrierFactsFrame
    (state after : View Node TxId)
    (facts : JoinedCarrierFacts state)
    (hasJoinedEq : after.hasJoined = state.hasJoined)
    (activeSubset
      : forall node configuration,
          configuration ∈ activeConfigurations (after.nodes node)
          -> configuration ∈ activeConfigurations (state.nodes node))
    (configurationSubset
      : forall node configuration,
          configuration ∈ allConfigurations (after.nodes node).log
          -> configuration ∈ allConfigurations (state.nodes node).log)
    (votesSubset
      : forall node, (after.nodes node).votesGranted ⊆ (state.nodes node).votesGranted)
    (activeRoleJoined
      : forall node,
          (after.nodes node).role = .candidate \/ (after.nodes node).role = .leader
          -> node ∈ after.hasJoined)
    (positiveMatchJoined
      : forall leader peer,
          0 < (after.nodes leader).matchIndex peer -> peer ∈ after.hasJoined)
    (nonemptyLogJoined
      : forall node, Not ((after.nodes node).log = []) -> node ∈ after.hasJoined)
    (networkSubset
      : forall destination message,
          message ∈ after.network destination -> message ∈ state.network destination)
    : JoinedCarrierFacts after := by
  constructor
  · intro node peer member
    rw [hasJoinedEq]
    exact
      facts.activeNodes node
        (activeNodeUnion_subset_of_activeConfigurations_subset
          (state.nodes node) (after.nodes node)
          (activeSubset node) member)
  · intro node configuration member peer inNodes
    rw [hasJoinedEq]
    exact
      facts.configurationNodes node configuration
        (configurationSubset node configuration member) inNodes
  · intro node peer member
    rw [hasJoinedEq]
    exact facts.grantedVotes node (votesSubset node member)
  · intro destination request member
    rw [hasJoinedEq]
    exact
      facts.voteRequestDestinations destination request
        (networkSubset destination _ member)
  · intro destination request member
    rw [hasJoinedEq]
    exact
      facts.appendRequestDestinations destination request
        (networkSubset destination _ member)
  · intro destination request member configuration configured peer inNodes
    rw [hasJoinedEq]
    exact
      facts.appendRequestConfigurations destination request
        (networkSubset destination _ member)
        configuration configured inNodes
  · intro destination response member
    rw [hasJoinedEq]
    exact
      facts.voteResponseSources destination response
        (networkSubset destination _ member)
  · constructor
    · exact activeRoleJoined
    · exact positiveMatchJoined
    · intro destination response member
      rw [hasJoinedEq]
      exact
        facts.runtimeNodes.appendResponses destination response
          (networkSubset destination _ member)
    · exact nonemptyLogJoined

/-- A queued vote request is addressed to a joined node. -/
lemma systemVoteRequestDestinationJoined
    (state : View Node TxId)
    (invariant : SystemInductiveInvariant state)
    (destination : Node)
    (request : RequestVoteRequest Node)
    (member : Message.requestVoteRequest request ∈ state.network destination)
    : request.destination ∈ state.hasJoined := by
  rcases invariant with
    ⟨_, _, _, _, _, _, facts⟩
  have destinationEq : request.destination = destination := by
    simpa using facts.networkHistory.addressed destination _ member
  rw [destinationEq]
  exact
    facts.joinedCarriers.voteRequestDestinations
      destination request member

omit [DecidableEq TxId] in
/-- Processed acknowledgements are always effective acknowledgement evidence. -/
lemma acknowledgingNodes_subset_effectiveAckers
    (state : View Node TxId)
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (leader : Node)
    (index : Nat)
    (activeNodesJoined : activeNodeUnion (state.nodes leader) ⊆ state.hasJoined)
    : acknowledgingNodes state leader index
      ⊆ effectiveAckers state responseHistory leader index := by
  intro peer member
  simp only [
    acknowledgingNodes, effectiveAckers,
    Finset.mem_filter] at member ⊢
  rcases member with ⟨active, self | matched⟩
  · exact ⟨activeNodesJoined active, Or.inl self⟩
  · exact ⟨activeNodesJoined active, Or.inr (Or.inl matched)⟩

/-- Frame permanent authority evidence through an action's live-slot mapping. -/
lemma activationEvidenceFrame
    (state after : View Node TxId)
    (oldAppendHistory newAppendHistory
      : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (oldResponseHistory newResponseHistory
      : AppendEntriesResponse Node -> List (Entry Node TxId))
    (oldNodeEvidence newNodeEvidence : NodeCommitEvidence Node TxId)
    (oldRequestEvidence newRequestEvidence : RequestCommitEvidence Node TxId)
    (oldElections newElections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    (facts
      : ActivationEvidenceFacts
          state oldAppendHistory oldResponseHistory
          oldNodeEvidence oldRequestEvidence
          oldElections activations)
    (knownBack
      : forall evidence supportedPrefix,
          KnownCommitEvidence
            after newAppendHistory newNodeEvidence newRequestEvidence
            evidence supportedPrefix
          -> KnownCommitEvidence
              state oldAppendHistory oldNodeEvidence oldRequestEvidence
              evidence supportedPrefix)
    (candidateBack
      : forall candidate,
          (after.nodes candidate).role = .candidate
          -> hasPotentialElectionMajority after candidate
          -> (state.nodes candidate).role = .candidate
              /\ hasPotentialElectionMajority state candidate)
    (candidateTermEq
      : forall candidate,
          (after.nodes candidate).role = .candidate
          -> (after.nodes candidate).currentTerm = (state.nodes candidate).currentTerm)
    (candidateLogPrefix
      : forall candidate,
          (after.nodes candidate).role = .candidate
          -> (state.nodes candidate).log <+: (after.nodes candidate).log)
    (candidateActive
      : forall candidate configuration,
          (after.nodes candidate).role = .candidate
          -> configuration ∈ activeConfigurations (state.nodes candidate)
          -> configuration ∈ activeConfigurations (after.nodes candidate))
    : ActivationEvidenceFacts
        after newAppendHistory newResponseHistory
        newNodeEvidence newRequestEvidence
        newElections activations := by
  constructor
  · intro evidence supportedPrefix known
    exact facts.authorityRecorded
      evidence supportedPrefix (knownBack evidence supportedPrefix known)
  · intro left leftPrefix leftKnown right rightPrefix rightKnown same
    exact facts.authorityIndexUnique
      left leftPrefix (knownBack left leftPrefix leftKnown)
      right rightPrefix (knownBack right rightPrefix rightKnown) same
  · intro earlier earlierPrefix earlierKnown later laterPrefix laterKnown order
    exact facts.authorityBridge
      earlier earlierPrefix (knownBack earlier earlierPrefix earlierKnown)
      later laterPrefix (knownBack later laterPrefix laterKnown) order
  · intro left leftPrefix leftKnown right rightPrefix rightKnown
    exact
      facts.supportedPrefixesComparable
        left leftPrefix (knownBack left leftPrefix leftKnown)
        right rightPrefix (knownBack right rightPrefix rightKnown)
  · intro evidence supportedPrefix known candidate role majority newer
    have old := candidateBack candidate role majority
    have oldNewer :
        evidence.commitTerm < (state.nodes candidate).currentTerm := by
      simpa [candidateTermEq candidate role] using newer
    rcases
        facts.candidateBridge
          evidence supportedPrefix
            (knownBack evidence supportedPrefix known)
          candidate old.1 old.2 oldNewer with
      direct | authorityActive
    · exact Or.inl (direct.trans (candidateLogPrefix candidate role))
    · exact Or.inr
        (candidateActive candidate evidence.authority role authorityActive)

omit [DecidableEq TxId] [Bootstrap Node] in
/-- Monotone node terms preserve every recorded activation supporter's bound. -/
lemma activationSupporterProgressFrame
    (state after : View Node TxId)
    (activations : ActivationHistory Node TxId)
    (facts : ActivationSupporterProgress state activations)
    (termMonotone
      : forall node, (state.nodes node).currentTerm <= (after.nodes node).currentTerm)
    : ActivationSupporterProgress after activations := by
  intro index record recorded supporter member
  exact
    Nat.le_trans
      (facts index record recorded supporter member)
      (termMonotone supporter)

/-- Canonical extensions preserve immutable activation provenance. -/
lemma activationCanonicalFrame
    (canonicalHistory afterCanonicalHistory : Nat -> List (Entry Node TxId))
    (owners afterOwners : TermOwners Node)
    (activations : ActivationHistory Node TxId)
    (historyFacts : ActivationHistoryFacts activations)
    (facts : ActivationCanonicalFacts canonicalHistory owners activations)
    (ownersPreserved
      : forall index record,
          activations index = some record
          -> afterOwners record.activationTerm = owners record.activationTerm)
    (canonicalFrame
      : forall history,
          HistoryCanonical canonicalHistory history
          -> HistoryCanonical afterCanonicalHistory history)
    : ActivationCanonicalFacts afterCanonicalHistory afterOwners activations := by
  constructor
  · intro index record recorded
    rw [ownersPreserved index record recorded]
    exact facts.termOwner index record recorded
  · intro index record recorded
    exact canonicalFrame _ (facts.recordCanonical index record recorded)
  · intro index record recorded
    have canonical :=
      canonicalFrame _ (facts.recordCanonical index record recorded)
    have valid := historyFacts.valid index record recorded
    rcases isSignatureAtTrue valid.2.2.2.2.2.1 with
      ⟨entry, found, _⟩
    have entryTerm :
        entry.term = record.activationTerm := by
      have activationTerm :=
        (historyFacts.supporterAcks index record recorded).1
      unfold termAt at activationTerm
      simpa [found] using activationTerm
    exact (canonical record.activationFrontier entry found).2.trans (by
      rw [entryTerm])
  · intro index record recorded supporter member
    exact
      canonicalFrame _
        (facts.supporterCanonical
          index record recorded supporter member)

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- The qualified temporal closure always yields the activation prefix. -/
lemma activationPrefixInLaterElection
    {votes : VoteHistory Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (facts : ActivationElectionFacts votes elections activations)
    {activationIndex : ActivationKey Node}
    {electionTerm : Nat}
    {activation : ActivationRecord Node TxId}
    {election : ElectionRecord Node TxId}
    (activationStored : activations activationIndex = some activation)
    (electionStored : elections electionTerm = some election)
    (later : activation.activationTerm < electionTerm)
    : activation.history.take activation.activationFrontier
      <+: election.promotionLog := by
  rcases
      facts.closure
        activationIndex activation electionTerm election
          activationStored electionStored later with
    direct | shared
  · exact direct
  · rcases shared with
      ⟨_configuration, _activationActive, _ballotActive,
        _voter, _activationSupporter, _electionSupporter,
        _voted, _voterPrefix, promotionPrefix⟩
    exact promotionPrefix

/-- Empty promotion logs cannot follow a nonempty signed activation. -/
lemma activationElectionPromotionNonempty
    {votes : VoteHistory Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (historyFacts : ActivationHistoryFacts activations)
    (facts : ActivationElectionFacts votes elections activations)
    {activationIndex : ActivationKey Node}
    {electionTerm : Nat}
    {activation : ActivationRecord Node TxId}
    {election : ElectionRecord Node TxId}
    (activationStored : activations activationIndex = some activation)
    (electionStored : elections electionTerm = some election)
    (later : activation.activationTerm < electionTerm)
    : election.promotionLog = ([] : List (Entry Node TxId)) -> False := by
  intro emptyPromotion
  have covered :
      List.IsPrefix
        (activation.history.take activation.activationFrontier)
        election.promotionLog := by
    exact
      activationPrefixInLaterElection
        facts activationStored electionStored later
  have activationBound :=
    (historyFacts.valid
      activationIndex activation activationStored).2.1
  have activationPositive :
      0 < activation.activationFrontier := by
    have priorBefore :=
      (historyFacts.valid
        activationIndex activation activationStored).1
    omega
  have prefixLength := covered.length_le
  rw [emptyPromotion] at prefixLength
  simp [
    List.length_take,
    Nat.min_eq_left activationBound
  ] at prefixLength
  omega

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Frame immutable activation/election closure through preserved old votes. -/
lemma activationElectionFrame
    (votes afterVotes : VoteHistory Node)
    (elections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    (facts : ActivationElectionFacts votes elections activations)
    (votesPreserved
      : forall activationIndex activation electionTerm election voter,
          activations activationIndex = some activation
          -> elections electionTerm = some election
          -> voter ∈ election.supporters
          -> afterVotes voter electionTerm = votes voter electionTerm)
    : ActivationElectionFacts afterVotes elections activations := by
  constructor
  intro activationIndex activation electionTerm election
      activationStored electionStored later
  rcases
      facts.closure
        activationIndex activation electionTerm election
          activationStored electionStored later with
    direct | shared
  · exact Or.inl direct
  · right
    rcases shared with
      ⟨configuration, activationActive, ballotActive,
        voter, activationSupporter, electionSupporter,
        voted, voterPrefix, promotionPrefix⟩
    exact ⟨
      configuration,
      activationActive,
      ballotActive,
      voter,
      activationSupporter,
      electionSupporter,
      by
        rw [votesPreserved
          activationIndex activation electionTerm election voter
            activationStored electionStored electionSupporter]
        exact voted,
      voterPrefix,
      promotionPrefix
    ⟩

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/--
Frame activation vote history through a vote projection and voter-snapshot
update.
-/
lemma activationVoteHistoryFrame
    (votes afterVotes : VoteHistory Node)
    (voteVoterHistory afterVoteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    (facts : ActivationVoteHistory votes voteVoterHistory elections activations)
    (voteBack
      : forall activationIndex activation voter voteTerm candidate,
          activations activationIndex = some activation
          -> voter ∈ activation.jointSupporters
          -> afterVotes voter voteTerm = some candidate
          -> Not (voter = candidate)
          -> activation.activationTerm < voteTerm
          -> votes voter voteTerm = some candidate)
    (snapshotForward
      : forall voter voteTerm candidate supportedPrefix,
          supportedPrefix <+: voteVoterHistory (grantedVoteKey voter voteTerm candidate)
          -> supportedPrefix
              <+: afterVoteVoterHistory (grantedVoteKey voter voteTerm candidate))
    : ActivationVoteHistory afterVotes afterVoteVoterHistory elections activations := by
  intro activationIndex activation voter voteTerm candidate
      activationStored supporter voted different later
  rcases
      facts activationIndex activation voter voteTerm candidate
        activationStored supporter
        (voteBack
          activationIndex activation voter voteTerm candidate
            activationStored supporter voted different later)
        different later with
    retained | bad
  · exact Or.inl
      (snapshotForward voter voteTerm candidate
        (activation.history.take activation.activationFrontier) retained)
  · exact Or.inr bad

omit [DecidableEq TxId] in
/-- Frame term ownership while supplying the action-specific queued history. -/
lemma termOwnershipFrame
    (state after : View Node TxId)
    (oldAppendHistory newAppendHistory
      : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (votes : VoteHistory Node)
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (facts : TermOwnershipFacts state votes oldAppendHistory canonicalHistory owners)
    (roleBack
      : forall leader,
          (after.nodes leader).role = .leader -> (state.nodes leader).role = .leader)
    (ownerRoleForward
      : forall owner,
          ((state.nodes owner).role = .leader
            \/ (state.nodes owner).role = .follower
            \/ (state.nodes owner).role = .preVoteCandidate
            \/ (state.nodes owner).role = .none)
          -> ((after.nodes owner).role = .leader
              \/ (after.nodes owner).role = .follower
              \/ (after.nodes owner).role = .preVoteCandidate
              \/ (after.nodes owner).role = .none))
    (termEq
      : forall node, (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq : forall node, (after.nodes node).log = (state.nodes node).log)
    (queuedHistory
      : forall destination request,
          Message.appendEntriesRequest request ∈ after.network destination
          -> forall index entry,
              entryAt? (newAppendHistory request) index = some entry
              -> entryAt? (canonicalHistory entry.term) index = some entry
                  /\ (newAppendHistory request).take index
                      = (canonicalHistory entry.term).take index)
    (queuedMetadata
      : forall destination request,
          Message.appendEntriesRequest request ∈ after.network destination
          -> Not (request.source = request.destination)
              /\ owners request.term = some request.source
              /\ forall entry,
                  entry ∈ newAppendHistory request -> entry.term <= request.term)
    (queuedActive
      : forall destination request,
          Message.appendEntriesRequest request ∈ after.network destination
          -> request.term = (after.nodes request.source).currentTerm
          -> (after.nodes request.source).role = .leader
          -> newAppendHistory request <+: (after.nodes request.source).log)
    : TermOwnershipFacts after votes newAppendHistory canonicalHistory owners := by
  constructor
  · exact facts.bootstrap
  · intro leader role
    rw [termEq]
    exact facts.activeLeader leader (roleBack leader role)
  · intro node index entry found
    rcases
        facts.logEntryAgreement node index entry
          (by simpa [logEq] using found) with
      ⟨canonicalFound, agreed⟩
    exact ⟨canonicalFound, by simpa [logEq] using agreed⟩
  · exact queuedHistory
  · intro leader role
    rw [termEq]
    simpa [logEq] using facts.activeLeaderHistory leader (roleBack leader role)
  · exact facts.canonicalEntryOwner
  · exact facts.canonicalMonoLog
  · intro term owner owned
    rcases facts.ownerProgress term owner owned with
      ⟨bound, active⟩
    constructor
    · simpa [termEq] using bound
    · intro same
      exact ownerRoleForward owner (active (by simpa [termEq] using same))
  · exact queuedMetadata
  · exact queuedActive

/-- Read the exact immutable ACK snapshot retained for one activation supporter. -/
lemma activationSupporterAckSnapshot
    {activations : ActivationHistory Node TxId}
    (facts : ActivationHistoryFacts activations)
    {index : ActivationKey Node}
    {record : ActivationRecord Node TxId}
    (recorded : activations index = some record)
    {supporter : Node}
    (member : supporter ∈ record.jointSupporters)
    : termAt record.history record.activationFrontier = record.activationTerm
      /\ record.supporterAckTerm supporter = record.activationTerm
      /\ record.activationFrontier <= record.supporterAckIndex supporter
      /\ record.supporterAckIndex supporter <= (record.supporterHistory supporter).length
      /\ (record.supporterHistory supporter).take record.activationFrontier
          = record.history.take record.activationFrontier := by
  rcases facts.supporterAcks index record recorded with
    ⟨activationTerm, supporterFacts⟩
  exact ⟨activationTerm, supporterFacts supporter member⟩

omit [DecidableEq TxId] [Bootstrap Node] in
/--
Every effective ACK supporter has one exact immutable snapshot covering the
acknowledged frontier, whether the ACK is self, processed, or still queued.
-/
lemma effectiveAckerSnapshotExists
    {state : View Node TxId}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {ackHistory : ProcessedAckHistory Node TxId}
    (networkFacts
      : forall destination response,
          Message.appendEntriesResponse response ∈ state.network destination
          -> response.success = true
          -> response.lastLogIndex <= (responseHistory response).length)
    (ackFacts : ProcessedAckHistoryFacts state ackHistory)
    {leader supporter : Node}
    {frontier : Nat}
    (leaderRole : (state.nodes leader).role = .leader)
    (frontierPositive : 0 < frontier)
    (frontierBound : frontier <= (state.nodes leader).log.length)
    (member : supporter ∈ effectiveAckers state responseHistory leader frontier)
    : Exists
        fun snapshot : ProcessedAckSnapshot Node TxId =>
          snapshot.term = (state.nodes leader).currentTerm
          /\ frontier <= snapshot.index
          /\ snapshot.index <= snapshot.history.length
          /\ snapshot.history.take frontier = (state.nodes leader).log.take frontier := by
  simp only [
    effectiveAckers, Finset.mem_filter] at member
  rcases member with ⟨_joined, self | processed | queued⟩
  · subst supporter
    exact ⟨
      {
        term := (state.nodes leader).currentTerm
        index := frontier
        history := (state.nodes leader).log
      },
      rfl,
      le_rfl,
      frontierBound,
      rfl
    ⟩
  · have positive :
        0 < (state.nodes leader).matchIndex supporter :=
      lt_of_lt_of_le frontierPositive processed
    rcases ackFacts.positive leader leaderRole supporter positive with
      ⟨snapshot, _stored, snapshotTerm, snapshotIndex,
        historyBound, agreed⟩
    have frontierIndex : frontier <= snapshot.index := by
      simpa [snapshotIndex] using processed
    have frontierAgreement :
        snapshot.history.take frontier =
          (state.nodes leader).log.take frontier := by
      calc
        snapshot.history.take frontier
            = (snapshot.history.take snapshot.index).take frontier := by
          simp [List.take_take, Nat.min_eq_left frontierIndex]
        _ = ((state.nodes leader).log.take snapshot.index).take frontier := by
          rw [agreed]
        _ = (state.nodes leader).log.take frontier := by
          simp [List.take_take, Nat.min_eq_left frontierIndex]
    exact ⟨snapshot, snapshotTerm, frontierIndex, historyBound, frontierAgreement⟩
  · rcases queued with
      ⟨response, queued, success, responseTerm,
        responseSource, responseDestination, acknowledged, covered⟩
    have historyBound :
        response.lastLogIndex <=
          (responseHistory response).length :=
      networkFacts leader response queued success
    have frontierAgreement :
        (responseHistory response).take frontier =
          (state.nodes leader).log.take frontier := by
      have historyCovered :=
        (List.take_prefix frontier (responseHistory response)).trans covered
      have takenLength :
          ((responseHistory response).take frontier).length = frontier := by
        simp [Nat.min_eq_left (acknowledged.trans historyBound)]
      simpa [takenLength] using (prefixEqTake historyCovered).symm
    exact ⟨
      {
        term := response.term
        index := response.lastLogIndex
        history := responseHistory response
      },
      responseTerm,
      acknowledged,
      historyBound,
      frontierAgreement
    ⟩

omit [DecidableEq TxId] [Bootstrap Node] in
/--
Frame activation-supporter chronology through append-only logs, monotone terms,
and preserved frozen elections.
-/
lemma activationSupporterCurrentHistoryFrame
    (state after : View Node TxId)
    (elections afterElections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    (facts : ActivationSupporterCurrentHistory state elections activations)
    (logMonotone : forall node, (state.nodes node).log <+: (after.nodes node).log)
    (termMonotone
      : forall node, (state.nodes node).currentTerm <= (after.nodes node).currentTerm)
    (electionPreserved
      : forall term record,
          elections term = some record -> afterElections term = some record)
    : ActivationSupporterCurrentHistory after afterElections activations := by
  intro index record recorded supporter member
  rcases facts index record recorded supporter member with
    retained | bad
  · exact Or.inl (retained.trans (logMonotone supporter))
  · right
    rcases bad with
      ⟨badTerm, badRecord, later, bounded, badRecorded, missing⟩
    exact ⟨
      badTerm,
      badRecord,
      later,
      bounded.trans (termMonotone supporter),
      electionPreserved badTerm badRecord badRecorded,
      missing
    ⟩

/-- Frame shared ballot configurations through unchanged candidacies. -/
lemma electionConfigurationFrame
    (state after : View Node TxId)
    (elections : ElectionHistory Node TxId)
    (activations afterActivations : ActivationHistory Node TxId)
    (facts : ElectionConfigurationFacts state elections activations)
    (activationPreserved
      : forall index activation,
          activations index = some activation -> afterActivations index = some activation)
    (supporterCurrentAfter
      : ActivationSupporterCurrentHistory after elections afterActivations)
    (candidateBack
      : forall candidate,
          (after.nodes candidate).role = .candidate
          -> hasEffectiveElectionMajority after candidate
          -> (state.nodes candidate).role = .candidate
              /\ (after.nodes candidate).currentTerm = (state.nodes candidate).currentTerm
              /\ hasEffectiveElectionMajority state candidate)
    (activeForward
      : forall candidate configuration,
          (after.nodes candidate).role = .candidate
          -> configuration ∈ activeConfigurations (state.nodes candidate)
          -> configuration ∈ activeConfigurations (after.nodes candidate))
    (candidateEntriesBefore
      : forall candidate,
          (after.nodes candidate).role = .candidate
          -> forall entry,
              entry ∈ (after.nodes candidate).log
              -> entry.term < (after.nodes candidate).currentTerm)
    : ElectionConfigurationFacts after elections afterActivations := by
  constructor
  · exact facts.ballotCommittedFrontierSignature
  · intro term record recorded positive
    rcases
        facts.ballotCurrentAuthorityActivation
          term record recorded positive with
      ⟨activationIndex, activation, stored, authority,
        termBound, configurationBound, agreed⟩
    exact ⟨
      activationIndex,
      activation,
      activationPreserved _ _ stored,
      authority,
      termBound,
      configurationBound,
      agreed
    ⟩
  · exact facts.ballotCurrentAuthorityActive
  · exact supporterCurrentAfter
  · intro term record candidate recorded role termEq majority
    have old := candidateBack candidate role majority
    have oldTerm :
        (state.nodes candidate).currentTerm = term := by
      rw [← old.2.1, termEq]
    rcases
        facts.potentialShared
          term record candidate recorded old.1 oldTerm old.2.2 with
      ⟨configuration, ballotActive, candidateActive⟩
    exact ⟨
      configuration,
      ballotActive,
      activeForward candidate configuration role candidateActive
    ⟩
  · intro left right leftRole rightRole sameTerm leftMajority rightMajority
    have oldLeft := candidateBack left leftRole leftMajority
    have oldRight := candidateBack right rightRole rightMajority
    have oldSameTerm :
        (state.nodes left).currentTerm =
          (state.nodes right).currentTerm := by
      simpa [oldLeft.2.1, oldRight.2.1] using sameTerm
    rcases
        facts.effectiveCandidatesShared
          left right oldLeft.1 oldRight.1 oldSameTerm
          oldLeft.2.2 oldRight.2.2 with
      ⟨configuration, leftActive, rightActive⟩
    exact ⟨
      configuration,
      activeForward left configuration leftRole leftActive,
      activeForward right configuration rightRole rightActive
    ⟩
  · exact candidateEntriesBefore

omit [DecidableEq TxId] [Bootstrap Node] in
/-- Live evidence in a frame state came from the corresponding old slot. -/
lemma knownCommitEvidenceFrameBack
    (state after : View Node TxId)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    (commitEq
      : forall node, (after.nodes node).commitIndex = (state.nodes node).commitIndex)
    (committedEq
      : forall node, (after.nodes node).committedLog = (state.nodes node).committedLog)
    (networkSubset
      : forall destination request,
          Message.appendEntriesRequest request ∈ after.network destination
          -> Message.appendEntriesRequest request ∈ state.network destination)
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (known
      : KnownCommitEvidence
          after appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    : KnownCommitEvidence
        state appendHistory nodeEvidence requestEvidence
        evidence supportedPrefix := by
  rcases known with nodeKnown | requestKnown
  · rcases nodeKnown with
      ⟨node, positive, stored, prefixEq⟩
    exact Or.inl
      ⟨node,
        by simpa [commitEq] using positive,
        stored,
        by simpa [committedEq] using prefixEq⟩
  · rcases requestKnown with
      ⟨destination, request, member, positive, stored, prefixEq⟩
    exact Or.inr
      ⟨destination, request,
        networkSubset destination request member,
        positive, stored, prefixEq⟩

/-- The proof-only node evidence selected by AppendEntries receive. -/
def appendRequestNodeEvidence
    (state : View Node TxId)
    (destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (nextNode : NodeState Node TxId)
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    : NodeCommitEvidence Node TxId :=
  Function.update nodeEvidence destination
    (if nextNode.commitIndex = (state.nodes destination).commitIndex then
        nodeEvidence destination
      else
        (requestEvidence request).map
          fun evidence =>
            evidence.restrict nextNode.commitIndex)

/--
AppendEntries receive retains the destination's old evidence when commit
does not advance, and otherwise restricts the request's advertised
evidence to the newly learned frontier.
-/
lemma appendRequestCommitEvidenceFacts
    (state : View Node TxId)
    (destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse Node)
    (afterNetwork : Node -> List (Message Node TxId))
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    (facts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (oldCommitBound
      : (state.nodes destination).commitIndex <= (state.nodes destination).log.length)
    (handled
      : handleAppendEntriesRequest? (state.nodes destination) request
        = some (nextNode, response))
    (requestMember : Message.appendEntriesRequest request ∈ state.network destination)
    (advancedHistory
      : (state.nodes destination).commitIndex < nextNode.commitIndex
        -> nextNode.committedLog = (appendHistory request).take nextNode.commitIndex)
    (committedSignature
      : 0 < (state.nodes destination).commitIndex
        -> isSignatureAt
              (state.nodes destination).log
              (state.nodes destination).commitIndex
            = true)
    (networkSubset
      : forall queuedDestination queuedRequest,
          Message.appendEntriesRequest queuedRequest ∈ afterNetwork queuedDestination
          -> Message.appendEntriesRequest queuedRequest ∈ state.network queuedDestination)
    : CommitEvidenceFacts
        {
          state with
            nodes := updateNode state.nodes destination nextNode
            network := afterNetwork
        }
        appendHistory
        (appendRequestNodeEvidence
          state destination request nextNode
          nodeEvidence requestEvidence)
        requestEvidence := by
  let post :=
    CCFRaft.Proofs.Invariant.handleAppendEntriesRequestLocalPost handled
  let newNodeEvidence : NodeCommitEvidence Node TxId :=
    appendRequestNodeEvidence
      state destination request nextNode nodeEvidence requestEvidence
  change
    CommitEvidenceFacts
      { state with
        nodes := updateNode state.nodes destination nextNode
        network := afterNetwork }
      appendHistory newNodeEvidence requestEvidence
  constructor
  · intro node positive
    by_cases same : node = destination
    · subst node
      have nextPositive : 0 < nextNode.commitIndex := by simpa [updateNode] using positive
      by_cases unchanged :
          nextNode.commitIndex =
            (state.nodes destination).commitIndex
      · have oldPositive :
            0 < (state.nodes destination).commitIndex := by
          omega
        rcases facts.nodePositive destination oldPositive with
          ⟨evidence, stored, valid, supportedLength, termBound⟩
        have committedEq :
            nextNode.committedLog =
              (state.nodes destination).committedLog := by
          have prefixEq :=
            CCFRaft.Proofs.Invariant.prefixEqTake post.previousCommittedPrefix
          have oldLength :
              (state.nodes destination).committedLog.length =
                (state.nodes destination).commitIndex := by
            simp [
              NodeState.committedLog, List.length_take,
              Nat.min_eq_left oldCommitBound
            ]
          unfold NodeState.committedLog
          rw [unchanged]
          rw [oldLength] at prefixEq
          exact prefixEq
        exact ⟨
          evidence,
          by simp [
              newNodeEvidence, appendRequestNodeEvidence,
              unchanged, stored
            ],
          by simpa [committedEq] using valid,
          by simpa [unchanged] using supportedLength,
          by simpa [post.currentTermUnchanged] using termBound
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
        rcases
            facts.requestPositive
              destination request requestMember leaderCommitPositive with
          ⟨evidence, stored, valid, supportedLength, termBound⟩
        have historyTake :
            evidence.history.take nextNode.commitIndex =
              (appendHistory request).take nextNode.commitIndex := by
          have evidencePrefix :
              evidence.history.take request.leaderCommit =
                (appendHistory request).take request.leaderCommit := by
            simpa [supportedLength] using valid.2.2.2.1
          calc
            evidence.history.take nextNode.commitIndex
                = (evidence.history.take request.leaderCommit).take
                    nextNode.commitIndex := by
              simp [List.take_take, Nat.min_eq_left withinLeaderCommit]
            _ = ((appendHistory request).take request.leaderCommit).take
                  nextNode.commitIndex := by
              rw [evidencePrefix]
            _ = (appendHistory request).take nextNode.commitIndex := by
              simp [List.take_take, Nat.min_eq_left withinLeaderCommit]
        have evidenceSignature :
            isSignatureAt evidence.history nextNode.commitIndex = true := by
          have nextSignature :=
            post.commitIndexSignature committedSignature nextPositive
          have committedSignature :
              isSignatureAt nextNode.committedLog nextNode.commitIndex =
                true := by
            simpa [NodeState.committedLog]
              using isSignatureAt_take_of_le le_rfl nextSignature
          have requestTakeSignature :
              isSignatureAt
                  ((appendHistory request).take nextNode.commitIndex)
                  nextNode.commitIndex =
                true := by
            simpa [advancedHistory advanced] using committedSignature
          have evidenceTakeSignature :
              isSignatureAt
                  (evidence.history.take nextNode.commitIndex)
                  nextNode.commitIndex =
                true := by
            simpa [historyTake] using requestTakeSignature
          exact
            isSignatureAt_of_prefix
              (List.take_prefix nextNode.commitIndex evidence.history)
              evidenceTakeSignature
        have restrictedValid :
            (evidence.restrict nextNode.commitIndex).Valid
              nextNode.committedLog := by
          have validRestricted :=
            commitEvidenceRestrictValid valid
              (by simpa [supportedLength] using withinLeaderCommit)
              (fun _ => evidenceSignature)
          simpa [advancedHistory advanced, historyTake] using validRestricted
        exact ⟨
          evidence.restrict nextNode.commitIndex,
          by simp [
              newNodeEvidence, appendRequestNodeEvidence,
              unchanged, stored
            ],
          by simpa [updateNode] using restrictedValid,
          by simp [CommitEvidence.restrict],
          by
            have requestCurrent :
                request.term =
                  (state.nodes destination).currentTerm :=
              post.successfulCurrentTerm succeeded
            simpa [
              CommitEvidence.restrict, post.currentTermUnchanged, requestCurrent
            ] using termBound
        ⟩
    · have oldPositive :
          0 < (state.nodes node).commitIndex := by
        simpa [updateNode, Function.update, same] using positive
      rcases facts.nodePositive node oldPositive with
        ⟨evidence, stored, valid, supportedLength, termBound⟩
      exact ⟨
        evidence,
        by simpa [
            newNodeEvidence, appendRequestNodeEvidence,
            Function.update, same
          ] using stored,
        by simpa [
            updateNode, Function.update, same,
            NodeState.committedLog
          ] using valid,
        by simpa [
            updateNode, Function.update, same
          ] using supportedLength,
        by simpa [
            updateNode, Function.update, same
          ] using termBound
      ⟩
  · intro queuedDestination queuedRequest member positive
    exact
      facts.requestPositive queuedDestination queuedRequest
        (networkSubset queuedDestination queuedRequest member) positive

end CCFRaft.Proofs.Invariant
