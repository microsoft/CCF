-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Histories
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

/-- A winning candidate cannot share a term with an active leader. -/
lemma winningCandidateTermDiffersFromLeader
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (candidatesAbove : CandidatesAboveBootstrap state)
    (_voteFacts : VoteHistoryFacts state votes)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
    {candidate leader : Node}
    (candidateRole : (state.nodes candidate).role = .candidate)
    (candidateMajority : hasEffectiveElectionMajority state candidate)
    (leaderRole : (state.nodes leader).role = .leader)
    : Not ((state.nodes candidate).currentTerm = (state.nodes leader).currentTerm) := by
  intro sameTerm
  have owned := ownership.activeLeader leader leaderRole
  rcases
      electionFacts.ownerRecorded
        (state.nodes leader).currentTerm leader owned with
    bootstrap | recorded
  · have candidateAbove := candidatesAbove candidate candidateRole
    rw [sameTerm, bootstrap.1] at candidateAbove
    omega
  · rcases recorded with
      ⟨record, recordStored, recordLeader⟩
    rcases
        configurationFacts.potentialShared
          (state.nodes candidate).currentTerm record candidate
          (by simpa [sameTerm] using recordStored)
          candidateRole rfl candidateMajority with
      ⟨configuration, ballotActive, candidateActive⟩
    have recordMajority :=
      electionFacts.majority
        (state.nodes candidate).currentTerm record
        (by simpa [sameTerm] using recordStored)
        configuration ballotActive
    have candidateConfigurationMajority :=
      effectiveElectionMajorityAtConfiguration
        candidateMajority candidateActive
    rcases
        configurationMajoritiesIntersect
          candidateConfigurationMajority recordMajority with
      ⟨voter, _configurationMember, candidateMember, recordMember⟩
    have candidateVote :=
      (snapshots candidate voter (Or.inl candidateRole)
        candidateMember).1
    have leaderVote :=
      electionFacts.voted
        (state.nodes candidate).currentTerm record voter
        (by simpa [sameTerm] using recordStored) recordMember
    rw [recordLeader] at leaderVote
    rw [sameTerm] at candidateVote leaderVote
    have sameCandidate :
        candidate = leader :=
      Option.some.inj (candidateVote.symm.trans leaderVote)
    have candidateLeaderRole :
        (state.nodes candidate).role = .leader := by
      rw [sameCandidate]
      exact leaderRole
    exact Role.noConfusion (candidateRole.symm.trans candidateLeaderRole)

/-- An effective winning candidate's current term has not been claimed before. -/
lemma effectiveCandidateTermUnowned
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (candidatesAbove : CandidatesAboveBootstrap state)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
    {candidate : Node}
    (role : (state.nodes candidate).role = .candidate)
    (majority : hasEffectiveElectionMajority state candidate)
    : owners (state.nodes candidate).currentTerm = none := by
  cases ownerAtTerm : owners (state.nodes candidate).currentTerm with
  | none => rfl
  | some owner =>
      rcases
          electionHistoryOwnerProvenance
            electionFacts ownerAtTerm with
        bootstrap | elected
      · have above := candidatesAbove candidate role
        rw [bootstrap.1] at above
        omega
      · rcases elected with
          ⟨record, recordStored, recordLeader⟩
        rcases
            configurationFacts.potentialShared
              (state.nodes candidate).currentTerm record candidate
              recordStored role rfl majority with
          ⟨configuration, ballotActive, candidateActive⟩
        have recordMajority :=
          electionFacts.majority
            (state.nodes candidate).currentTerm record recordStored
            configuration ballotActive
        have candidateConfigurationMajority :=
          effectiveElectionMajorityAtConfiguration
            majority candidateActive
        rcases
            configurationMajoritiesIntersect
              candidateConfigurationMajority recordMajority with
          ⟨voter, _configurationMember, candidateMember, recordMember⟩
        have candidateVote :=
          (snapshots candidate voter (Or.inl role)
            candidateMember).1
        have ownerVote :
            votes voter (state.nodes candidate).currentTerm = some owner := by
          rw [← recordLeader]
          exact
            electionFacts.voted
              (state.nodes candidate).currentTerm record voter
              recordStored recordMember
        have candidateOwner : candidate = owner :=
          Option.some.inj (candidateVote.symm.trans ownerVote)
        have candidateOwned :
            owners (state.nodes candidate).currentTerm =
              some candidate := by
          simpa [candidateOwner] using ownerAtTerm
        have progress :=
          ownership.ownerProgress
            (state.nodes candidate).currentTerm candidate candidateOwned
        rcases progress.2 rfl with leader | follower | preVoteCandidate | inactive
        · exact False.elim
            (Role.noConfusion (leader.symm.trans role))
        · exact False.elim
            (Role.noConfusion (follower.symm.trans role))
        · exact False.elim
            (Role.noConfusion (preVoteCandidate.symm.trans role))
        · exact False.elim
            (Role.noConfusion (inactive.symm.trans role))

/-- A materialised winning candidate's current term has not been claimed before. -/
lemma potentialCandidateTermUnowned
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (_voteFacts : VoteHistoryFacts state votes)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
    {candidate : Node}
    (role : (state.nodes candidate).role = .candidate)
    (majority : hasEffectiveElectionMajority state candidate)
    : owners (state.nodes candidate).currentTerm = none := by
  exact
    effectiveCandidateTermUnowned
      candidatesAbove snapshots ownership electionFacts configurationFacts
        role majority

/-- Term ownership derives the previous candidate-term absence support fact. -/
lemma termOwnershipCandidateTermNotInLogs
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (candidatesAbove : CandidatesAboveBootstrap state)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
    : CandidateTermNotInLogs state := by
  intro candidate role majority node index entry found sameTerm
  have member : entry ∈ (state.nodes node).log :=
    entryAtSomeMember found
  rcases termOwnershipLogEntryOwner ownership member with
    ⟨owner, owned⟩
  have unowned :=
    effectiveCandidateTermUnowned
      candidatesAbove snapshots ownership electionFacts configurationFacts
        role majority
  rw [sameTerm] at owned
  rw [unowned] at owned
  contradiction

/-- Term ownership also excludes a materialised candidate term from all logs. -/
lemma termOwnershipPotentialCandidateTermNotInLogs
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (voteFacts : VoteHistoryFacts state votes)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
    {candidate : Node}
    (role : (state.nodes candidate).role = .candidate)
    (majority : hasEffectiveElectionMajority state candidate)
    : forall node index entry,
        entryAt? (state.nodes node).log index = some entry
        -> Not (entry.term = (state.nodes candidate).currentTerm) := by
  intro node index entry found sameTerm
  have member : entry ∈ (state.nodes node).log :=
    entryAtSomeMember found
  rcases termOwnershipLogEntryOwner ownership member with
    ⟨owner, owned⟩
  have unowned :=
    potentialCandidateTermUnowned
      voteFacts candidatesAbove snapshots ownership electionFacts
        configurationFacts role majority
  rw [sameTerm] at owned
  rw [unowned] at owned
  contradiction

omit [DecidableEq TxId] in
/-- Every processed acknowledgement quorum is also an effective quorum. -/
lemma majorityImpliesEffectiveMajority
    (state : View Node TxId)
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (leader : Node)
    (index : Nat)
    (activeNodesJoined : activeNodeUnion (state.nodes leader) ⊆ state.hasJoined)
    (majority : hasMajorityAt state leader index)
    : hasEffectiveMajorityAt state responseHistory leader index := by
  have subset :
      acknowledgingNodes state leader index ⊆
        effectiveAckers state responseHistory leader index := by
    intro node member
    simp only [
      acknowledgingNodes, effectiveAckers,
      Finset.mem_filter] at member ⊢
    rcases member with ⟨active, self | matched⟩
    · exact ⟨activeNodesJoined active, Or.inl self⟩
    · exact ⟨activeNodesJoined active, Or.inr (Or.inl matched)⟩
  rw [hasMajorityAt, List.all_eq_true] at majority
  rw [hasEffectiveMajorityAt, List.all_eq_true]
  intro configuration active
  apply decide_eq_true
  intro governs
  exact
    hasConfigurationMajority_mono subset
      ((of_decide_eq_true
        (majority configuration active)) governs)

omit [DecidableEq TxId] in
/-- Every processed election quorum is also an effective election quorum. -/
lemma electionMajorityImpliesEffective
    (state : View Node TxId)
    (candidate : Node)
    (votersJoined : (state.nodes candidate).votesGranted ⊆ state.hasJoined)
    (majority : hasElectionMajority state candidate)
    : hasEffectiveElectionMajority state candidate := by
  have subset :
      (state.nodes candidate).votesGranted ⊆
        effectiveElectionVoters state candidate := by
    intro voter member
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    exact ⟨votersJoined member, Or.inl member⟩
  rw [hasElectionMajority, List.all_eq_true] at majority
  rw [hasEffectiveElectionMajority, List.all_eq_true]
  intro configuration active
  apply decide_eq_true
  exact
    hasConfigurationMajority_mono subset
      (of_decide_eq_true (majority configuration active))

omit [Bootstrap Node] in
/-- Materialised election evidence is also prospective election evidence. -/
lemma effectiveElectionVotersSubsetPotential (state : View Node TxId) (candidate : Node)
    : effectiveElectionVoters state candidate
      ⊆ potentialElectionVoters state candidate := by
  intro voter member
  have joined : voter ∈ state.hasJoined := by
    have unpacked :
        voter ∈ state.hasJoined /\
          (voter ∈ (state.nodes candidate).votesGranted \/
            queuedGrantedVote state candidate voter) := by
      simpa [effectiveElectionVoters] using member
    exact unpacked.1
  simpa [potentialElectionVoters] using And.intro joined (Or.inl member)

/-- An effective election quorum is also a prospective election quorum. -/
lemma effectiveElectionMajorityImpliesPotential
    (state : View Node TxId)
    (candidate : Node)
    (majority : hasEffectiveElectionMajority state candidate)
    : hasPotentialElectionMajority state candidate := by
  exact effectiveElectionMajorityIsPotential state candidate majority

/-- A prospective quorum remains a quorum in any finite superset. -/
lemma potentialElectionMajorityOfSubset
    {state after : View Node TxId}
    {candidate : Node}
    (subset
      : potentialElectionVoters after candidate ⊆ potentialElectionVoters state candidate)
    (activeEq
      : activeConfigurations (after.nodes candidate)
        = activeConfigurations (state.nodes candidate))
    (majority : hasPotentialElectionMajority after candidate)
    : hasPotentialElectionMajority state candidate := by
  rw [hasPotentialElectionMajority, List.all_eq_true] at majority
  rw [hasPotentialElectionMajority, List.all_eq_true]
  intro configuration active
  apply decide_eq_true
  have afterActive :
      configuration ∈ activeConfigurations (after.nodes candidate) := by
    simpa [activeEq] using active
  exact
    hasConfigurationMajority_mono subset
      (of_decide_eq_true (majority configuration afterActive))

/-- Every materialised acknowledgement is also a potential supporter. -/
lemma effectiveAckersSubsetPotential
    (state : View Node TxId)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (leader : Node)
    (index : Nat)
    : effectiveAckers state responseHistory leader index
      ⊆ potentialAckers state appendHistory responseHistory leader index := by
  intro voter member
  have joined : voter ∈ state.hasJoined := by
    have unpacked :
        voter ∈ state.hasJoined /\
          (voter = leader \/
            index <= (state.nodes leader).matchIndex voter \/
              queuedSuccessfulAck
                state responseHistory leader voter index) := by
      simpa [effectiveAckers] using member
    exact unpacked.1
  simpa [potentialAckers] using And.intro joined (Or.inl member)

/-- A materialised acknowledgement quorum is also a potential quorum. -/
lemma effectiveMajorityImpliesPotential
    (state : View Node TxId)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (leader : Node)
    (index : Nat)
    (majority : hasEffectiveMajorityAt state responseHistory leader index)
    : hasPotentialMajorityAt state appendHistory responseHistory leader index := by
  let subset :=
    effectiveAckersSubsetPotential
      state appendHistory responseHistory leader index
  rw [hasEffectiveMajorityAt, List.all_eq_true] at majority
  rw [hasPotentialMajorityAt, List.all_eq_true]
  intro configuration active
  apply decide_eq_true
  intro governs
  exact
    hasConfigurationMajority_mono subset
      ((of_decide_eq_true
        (majority configuration active)) governs)

omit [Bootstrap Node] in
/-- Effective election evidence places every voter at or above the term voted. -/
lemma effectiveElectionVoterTermBound
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    {candidate voter : Node}
    (active
      : (state.nodes candidate).role = .candidate
        \/ (state.nodes candidate).role = .leader)
    (member : voter ∈ effectiveElectionVoters state candidate)
    : (state.nodes candidate).currentTerm <= (state.nodes voter).currentTerm := by
  rcases snapshots candidate voter active member with
    ⟨_, self | recorded⟩
  · subst voter
    exact le_rfl
  · exact recorded.2.2.2.1

omit [Bootstrap Node] in
/-- Every prospective election voter is at the candidate's current term. -/
lemma potentialElectionVoterTermBound
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    {candidate voter : Node}
    (active
      : (state.nodes candidate).role = .candidate
        \/ (state.nodes candidate).role = .leader)
    (member : voter ∈ potentialElectionVoters state candidate)
    : (state.nodes candidate).currentTerm <= (state.nodes voter).currentTerm := by
  simp only [
    potentialElectionVoters, Finset.mem_filter] at member
  rcases member with ⟨_joined, effective | eligible⟩
  · exact effectiveElectionVoterTermBound snapshots active effective
  · simpa [
      currentlyEligibleElectionVoter,
      makeRequestVoteRequest
    ] using eligible.1.le

/-- A reserved peer has not advanced beyond the request source term. -/
lemma queuedAppendReservePeerTerm
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {leader peer : Node}
    {index : Nat}
    (reserve : queuedAppendReserve state appendHistory leader peer index)
    : (state.nodes peer).currentTerm <= (state.nodes leader).currentTerm := by
  rcases reserve with
    ⟨request, _, _, requestDestination, requestTerm,
      producible, _⟩
  rcases producible with direct | prepared
  · rcases direct with
      ⟨nextNode, response, handled, success, _⟩
    have localPost :=
      handleAppendEntriesRequestLocalPost handled
    have peerTerm :
        request.term = (state.nodes peer).currentTerm := by
      simpa [requestDestination, protocolNodeState]
        using localPost.successfulCurrentTerm success
    exact (peerTerm.symm.trans requestTerm).le
  · simpa [requestDestination, requestTerm] using prepared.1.le

/--
The intersection of a prospective replication quorum and a strictly
higher-term election quorum contains a materialised ACK, not merely a queued
request reserve.
-/
lemma potentialElectionIntersectionEffective
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    {leader candidate : Node}
    {index : Nat}
    {configuration : Configuration Node}
    (potential : hasPotentialMajorityAt state appendHistory responseHistory leader index)
    (leaderActive : configuration ∈ activeConfigurations (state.nodes leader))
    (configurationGoverns : configuration.index <= index)
    (candidateActive
      : (state.nodes candidate).role = .candidate
        \/ (state.nodes candidate).role = .leader)
    (elected : hasEffectiveElectionMajority state candidate)
    (candidateConfigurationActive
      : configuration ∈ activeConfigurations (state.nodes candidate))
    (newer : (state.nodes leader).currentTerm < (state.nodes candidate).currentTerm)
    : Exists
        fun voter =>
          voter ∈ effectiveAckers state responseHistory leader index
          /\ voter ∈ effectiveElectionVoters state candidate := by
  have replicationMajority :=
    potentialMajorityAtConfiguration
      potential leaderActive configurationGoverns
  have electionMajority :=
    effectiveElectionMajorityAtConfiguration
      elected candidateConfigurationActive
  rcases
      configurationMajoritiesIntersect
        replicationMajority electionMajority with
    ⟨voter, _configurationMember, potentialMember, electionMember⟩
  simp only [
    potentialAckers, Finset.mem_filter] at potentialMember
  rcases potentialMember with ⟨_joined, effective | reserve⟩
  · exact ⟨voter, effective, electionMember⟩
  · have reserveTerm :=
      queuedAppendReservePeerTerm reserve
    have voteTerm :=
      effectiveElectionVoterTermBound
        snapshots candidateActive electionMember
    omega

/--
A prospective replication quorum and a higher prospective election quorum
still intersect in a materialised acknowledgement.
-/
lemma potentialElectionMajorityIntersectionEffective
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    {leader candidate : Node}
    {index : Nat}
    {configuration : Configuration Node}
    (potential : hasPotentialMajorityAt state appendHistory responseHistory leader index)
    (leaderActive : configuration ∈ activeConfigurations (state.nodes leader))
    (configurationGoverns : configuration.index <= index)
    (candidateActive
      : (state.nodes candidate).role = .candidate
        \/ (state.nodes candidate).role = .leader)
    (elected : hasPotentialElectionMajority state candidate)
    (candidateConfigurationActive
      : configuration ∈ activeConfigurations (state.nodes candidate))
    (newer : (state.nodes leader).currentTerm < (state.nodes candidate).currentTerm)
    : Exists
        fun voter =>
          voter ∈ effectiveAckers state responseHistory leader index
          /\ voter ∈ potentialElectionVoters state candidate := by
  have replicationMajority :=
    potentialMajorityAtConfiguration
      potential leaderActive configurationGoverns
  have electionMajority :=
    potentialElectionMajorityAtConfiguration
      elected candidateConfigurationActive
  rcases
      configurationMajoritiesIntersect
        replicationMajority electionMajority with
    ⟨voter, _configurationMember, potentialMember, electionMember⟩
  simp only [
    potentialAckers, Finset.mem_filter] at potentialMember
  rcases potentialMember with ⟨_joined, effective | reserve⟩
  · exact ⟨voter, effective, electionMember⟩
  · have reserveTerm :=
      queuedAppendReservePeerTerm reserve
    have voteTerm :=
      potentialElectionVoterTermBound
        snapshots candidateActive electionMember
    omega

/-- A prospective support quorum intersects a frozen higher-term election in an ACK. -/
lemma potentialElectionRecordIntersectionEffective
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (voteFacts : VoteHistoryFacts state votes)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    {leader : Node}
    {index term : Nat}
    {record : ElectionRecord Node TxId}
    {configuration : Configuration Node}
    (potential : hasPotentialMajorityAt state appendHistory responseHistory leader index)
    (leaderActive : configuration ∈ activeConfigurations (state.nodes leader))
    (configurationGoverns : configuration.index <= index)
    (recorded : elections term = some record)
    (ballotActive : configuration ∈ record.ballotActive)
    (newer : (state.nodes leader).currentTerm < term)
    : Exists
        fun voter =>
          voter ∈ effectiveAckers state responseHistory leader index
          /\ voter ∈ record.supporters := by
  have replicationMajority :=
    potentialMajorityAtConfiguration
      potential leaderActive configurationGoverns
  have electionMajority :=
    electionFacts.majority
      term record recorded configuration ballotActive
  rcases
      configurationMajoritiesIntersect
        replicationMajority electionMajority with
    ⟨voter, _configurationMember, potentialMember, electionMember⟩
  simp only [
    potentialAckers, Finset.mem_filter] at potentialMember
  rcases potentialMember with ⟨_joined, effective | reserve⟩
  · exact ⟨voter, effective, electionMember⟩
  · have reserveTerm :=
      queuedAppendReservePeerTerm reserve
    have voteTerm :=
      electionHistoryVoterTerm
        voteFacts electionFacts recorded electionMember
    omega

/-- A retained activation ACK snapshot transfers its lower signed prefix. -/
lemma activationSupporterSnapshotContainsPrefix
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {activations : ActivationHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (historyFacts : ActivationHistoryFacts activations)
    (canonicalFacts : ActivationCanonicalFacts canonicalHistory owners activations)
    {source supporter : Node}
    {index : Nat}
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (activationStored : activations activationIndex = some activation)
    (activationSupporter : supporter ∈ activation.jointSupporters)
    (later : (state.nodes source).currentTerm < activation.activationTerm)
    (retained
      : (state.nodes source).log.take index <+: activation.supporterHistory supporter)
    : (state.nodes source).log.take index
      <+: activation.history.take activation.activationFrontier := by
  rcases isSignatureAtTrue currentSignature with
    ⟨sourceEntry, sourceFound, _⟩
  have sourceEntryTerm :
      sourceEntry.term = (state.nodes source).currentTerm := by
    simpa [termAt, sourceFound] using currentEntry
  have activationValid :=
    historyFacts.valid activationIndex activation activationStored
  rcases isSignatureAtTrue activationValid.2.2.2.2.2.1 with
    ⟨activationEntry, activationFound, _⟩
  have activationEntryTerm :
      activationEntry.term = activation.activationTerm := by
    have activationTerm :=
      (historyFacts.supporterAcks
        activationIndex activation activationStored).1
    simpa [termAt, activationFound] using activationTerm
  rcases
      activationSupporterAckSnapshot
        historyFacts activationStored activationSupporter with
    ⟨_activationTerm, _ackTerm, frontierAck, ackBound, agreement⟩
  have frontierBound :
      activation.activationFrontier <=
        (activation.supporterHistory supporter).length :=
    frontierAck.trans ackBound
  have activationInSupporter :
      entryAt?
          (activation.supporterHistory supporter)
          activation.activationFrontier =
        some activationEntry := by
    rw [← entryAtTake_of_le
      (log := activation.supporterHistory supporter) le_rfl]
    rw [agreement]
    rw [entryAtTake_of_le le_rfl]
    exact activationFound
  have sourceInPrefix :
      entryAt? ((state.nodes source).log.take index) index =
        some sourceEntry := by
    rw [entryAtTake_of_le le_rfl]
    exact sourceFound
  have sourceInSupporter :
      entryAt? (activation.supporterHistory supporter) index =
        some sourceEntry :=
    entryAt_of_prefix retained sourceInPrefix
  have supporterMono :
      MonoHistory (activation.supporterHistory supporter) :=
    canonicalSnapshotMono ownership
      (canonicalFacts.supporterCanonical
        activationIndex activation activationStored
          supporter activationSupporter)
  have indexBeforeFrontier :
      index < activation.activationFrontier := by
    by_contra notBefore
    have frontierLe : activation.activationFrontier <= index := by omega
    by_cases same : activation.activationFrontier = index
    · have sameEntry : activationEntry = sourceEntry :=
        Option.some.inj
          (activationInSupporter.symm.trans (by simpa [same] using sourceInSupporter))
      rw [sameEntry, sourceEntryTerm] at activationEntryTerm
      omega
    · have strict : activation.activationFrontier < index := by omega
      have monotone :=
        supporterMono
          activation.activationFrontier index
          activationEntry sourceEntry strict
          activationInSupporter sourceInSupporter
      rw [activationEntryTerm, sourceEntryTerm] at monotone
      omega
  have sourceBound :
      index <= (state.nodes source).log.length :=
    entryAtSomeIndexBound sourceFound
  have sourceLength :
      ((state.nodes source).log.take index).length = index := by
    simp [Nat.min_eq_left sourceBound]
  have supporterTake :
      (activation.supporterHistory supporter).take index =
        (state.nodes source).log.take index := by
    have exactTake := prefixEqTake retained
    simpa [sourceLength] using exactTake
  rw [List.prefix_iff_eq_take]
  calc
    (state.nodes source).log.take index
        = (activation.supporterHistory supporter).take index :=
      supporterTake.symm
    _ = ((activation.supporterHistory supporter).take activation.activationFrontier).take
          index := by
      simp [
        List.take_take,
        Nat.min_eq_left indexBeforeFrontier.le
      ]
    _ = (activation.history.take activation.activationFrontier).take index := by
      rw [agreement]
    _ = (activation.history.take activation.activationFrontier).take
          ((state.nodes source).log.take index).length := by
      rw [sourceLength]

/--
A potential quorum on an activation authority contains a materialised ACK
supporter whose activation snapshot carries the lower signed prefix, unless a
strictly intermediate election is already bad.
-/
lemma potentialPrefixInActivation
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (historyFacts : ActivationHistoryFacts activations)
    (canonicalFacts : ActivationCanonicalFacts canonicalHistory owners activations)
    (progress : ActivationSupporterProgress state activations)
    (activationHistory
      : AckerActivationHistory state responseHistory elections activations)
    {source : Node}
    {index : Nat}
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    {configuration : Configuration Node}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (sourceActive : configuration ∈ activeConfigurations (state.nodes source))
    (configurationGoverns : configuration.index <= index)
    (activationStored : activations activationIndex = some activation)
    (activationGoverning : configuration ∈ activation.governingActive)
    (later : (state.nodes source).currentTerm < activation.activationTerm)
    (earlierSafe
      : forall earlierTerm earlierRecord,
          (state.nodes source).currentTerm < earlierTerm
          -> earlierTerm <= activation.activationTerm
          -> elections earlierTerm = some earlierRecord
          -> (state.nodes source).log.take index <+: earlierRecord.promotionLog)
    : (state.nodes source).log.take index
      <+: activation.history.take activation.activationFrontier := by
  have sourceMajority :=
    potentialMajorityAtConfiguration
      potential sourceActive configurationGoverns
  have activationMajority :=
    (historyFacts.valid
      activationIndex activation activationStored).2.2.2.2.2.2.2.2
      configuration activationGoverning
  rcases
      configurationMajoritiesIntersect
        sourceMajority activationMajority with
    ⟨supporter, _configurationMember, sourceSupporter,
      activationSupporter⟩
  have effective :
      supporter ∈ effectiveAckers state responseHistory source index := by
    simp only [
      potentialAckers, Finset.mem_filter] at sourceSupporter
    rcases sourceSupporter with ⟨_joined, materialised | reserve⟩
    · exact materialised
    · have peerTerm := queuedAppendReservePeerTerm reserve
      have supporterProgress :=
        progress activationIndex activation activationStored
          supporter activationSupporter
      omega
  rcases
      activationHistory
        source index sourceRole currentEntry currentSignature
        activationIndex activation configuration supporter
        activationStored activationGoverning activationSupporter
        effective later with
    retained | bad
  · exact
      activationSupporterSnapshotContainsPrefix
        ownership historyFacts canonicalFacts
        currentEntry currentSignature activationStored
        activationSupporter later retained
  · rcases bad with
      ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
    exact False.elim
      (missing (earlierSafe badTerm badRecord above bounded recorded))

/--
An acknowledging quorum on an activation authority contains a materialised ACK
supporter whose activation snapshot carries the lower signed prefix, unless a
strictly intermediate election is already bad.
-/
lemma acknowledgedPrefixInActivation
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (historyFacts : ActivationHistoryFacts activations)
    (canonicalFacts : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationHistory
      : AckerActivationHistory state responseHistory elections activations)
    {source : Node}
    {index : Nat}
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    {configuration : Configuration Node}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (sourceMajority
      : hasConfigurationMajority
          (effectiveAckers state responseHistory source index)
          configuration)
    (_sourceActive : configuration ∈ activeConfigurations (state.nodes source))
    (_configurationGoverns : configuration.index <= index)
    (activationStored : activations activationIndex = some activation)
    (activationGoverning : configuration ∈ activation.governingActive)
    (later : (state.nodes source).currentTerm < activation.activationTerm)
    (earlierSafe
      : forall earlierTerm earlierRecord,
          (state.nodes source).currentTerm < earlierTerm
          -> earlierTerm <= activation.activationTerm
          -> elections earlierTerm = some earlierRecord
          -> (state.nodes source).log.take index <+: earlierRecord.promotionLog)
    : (state.nodes source).log.take index
      <+: activation.history.take activation.activationFrontier := by
  have activationMajority :=
    (historyFacts.valid
      activationIndex activation activationStored).2.2.2.2.2.2.2.2
      configuration activationGoverning
  rcases
      configurationMajoritiesIntersect
        sourceMajority activationMajority with
    ⟨supporter, _configurationMember, sourceSupporter,
      activationSupporter⟩
  have effective :
      supporter ∈ effectiveAckers state responseHistory source index :=
    sourceSupporter
  rcases
      activationHistory
        source index sourceRole currentEntry currentSignature
        activationIndex activation configuration supporter
        activationStored activationGoverning activationSupporter
        effective later with
    retained | bad
  · exact
      activationSupporterSnapshotContainsPrefix
        ownership historyFacts canonicalFacts
        currentEntry currentSignature activationStored
        activationSupporter later retained
  · rcases bad with
      ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
    exact False.elim
      (missing (earlierSafe badTerm badRecord above bounded recorded))

/-- Any prefix of an election promotion precedes that term's activation. -/
lemma electionPromotionPrefixInActivationCore
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (canonicalFacts : ActivationCanonicalFacts canonicalHistory owners activations)
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    {record : ElectionRecord Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (activationStored : activations activationIndex = some activation)
    (recorded : elections activation.activationTerm = some record)
    (sourcePrefix : supportedPrefix <+: record.promotionLog)
    : supportedPrefix <+: activation.history.take activation.activationFrontier := by
  have valid :=
    historyFacts.valid activationIndex activation activationStored
  rcases isSignatureAtTrue valid.2.2.2.2.2.1 with
    ⟨activationEntry, activationFound, _⟩
  have activationEntryTerm :
      activationEntry.term = activation.activationTerm := by
    have activationTerm :=
      (historyFacts.supporterAcks
        activationIndex activation activationStored).1
    simpa [termAt, activationFound] using activationTerm
  have activationCanonicalFound :
      entryAt?
          (canonicalHistory activation.activationTerm)
          activation.activationFrontier =
        some activationEntry := by
    simpa [activationEntryTerm]
      using (canonicalFacts.recordCanonical
              activationIndex activation activationStored
              activation.activationFrontier activationEntry activationFound).1
  have promotionCanonical :=
    electionFacts.promotionCanonical
      activation.activationTerm record recorded
  have promotionBeforeFrontier :
      record.promotionLog.length <
        activation.activationFrontier := by
    by_contra notBefore
    have frontierWithin :
        activation.activationFrontier <=
          record.promotionLog.length := by
      omega
    have promotionFound :
        entryAt?
            record.promotionLog
            activation.activationFrontier =
          some activationEntry := by
      rw [← entryAtTake_of_le
        (log := record.promotionLog) le_rfl]
      rw [
        takeEqOfPrefix promotionCanonical frontierWithin
      ]
      rw [entryAtTake_of_le le_rfl]
      exact activationCanonicalFound
    have before :=
      electionFacts.promotionEntriesBeforeTerm
        activation.activationTerm record recorded activationEntry
          (entryAtSomeMember promotionFound)
    rw [activationEntryTerm] at before
    omega
  have promotionInActivationCanonical :
      record.promotionLog <+:
        (canonicalHistory activation.activationTerm).take
          activation.activationFrontier := by
    rw [List.prefix_take_iff]
    exact ⟨promotionCanonical, promotionBeforeFrontier.le⟩
  exact sourcePrefix.trans
    (promotionInActivationCanonical.trans
      (by
        rw [
          ← canonicalFacts.activationFrontierCanonical
            activationIndex activation activationStored
        ]))

/-- An election promotion from the activation term precedes its activation. -/
lemma electionPromotionPrefixInActivation
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (historyFacts : ActivationHistoryFacts activations)
    (canonicalFacts : ActivationCanonicalFacts canonicalHistory owners activations)
    {source : Node}
    {index : Nat}
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    {record : ElectionRecord Node TxId}
    (activationStored : activations activationIndex = some activation)
    (recorded : elections activation.activationTerm = some record)
    (sourcePrefix : (state.nodes source).log.take index <+: record.promotionLog)
    : (state.nodes source).log.take index
      <+: activation.history.take activation.activationFrontier :=
  electionPromotionPrefixInActivationCore
    electionFacts historyFacts canonicalFacts
    activationStored recorded sourcePrefix

/-- The activated configuration occurs in the signed activation prefix. -/
lemma activationNewConfigurationKnown
    {activations : ActivationHistory Node TxId}
    (historyFacts : ActivationHistoryFacts activations)
    {activationIndex : ActivationKey Node}
    {activation : ActivationRecord Node TxId}
    (activationStored : activations activationIndex = some activation)
    : activation.newConfiguration
      ∈ allConfigurations (activation.history.take activation.activationFrontier) := by
  have valid :=
    historyFacts.valid activationIndex activation activationStored
  have governingMember : activation.newConfiguration ∈
      ((allConfigurations activation.history).filter fun configuration =>
        activation.oldConfiguration.index <= configuration.index /\
          configuration.index <= activation.activationFrontier) := by
    simpa [valid.2.2.2.2.2.2.1] using valid.2.2.2.2.2.2.2.1
  have known :
      activation.newConfiguration ∈
        allConfigurations activation.history :=
    (List.mem_filter.mp governingMember).1
  have within :
      activation.newConfiguration.index <=
        activation.activationFrontier :=
    (of_decide_eq_true (List.mem_filter.mp governingMember).2).2
  exact
    allConfigurations_mem_take_of_index_le
      activation.history activation.activationFrontier
      valid.2.1 known within

/-- A configuration known beyond a frozen ballot frontier is ballot-active. -/
lemma electionConfigurationActiveOfKnown
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    {term : Nat}
    {record : ElectionRecord Node TxId}
    {configuration : Configuration Node}
    (recorded : elections term = some record)
    (known : configuration ∈ allConfigurations record.ballotLog)
    (notRetired
      : (currentConfigurationAt record.ballotLog record.ballotCommitIndex).index
        <= configuration.index)
    : configuration ∈ record.ballotActive := by
  rw [
    electionFacts.ballotConfigurations term record recorded
  ]
  apply List.mem_filter.mpr
  exact ⟨known, decide_eq_true notRetired⟩

/-- Early form used by the activation/election closure induction. -/
lemma leastBadElectionHasPrefixVoterForActivation
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (voteFacts : VoteHistoryFacts state votes)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (ackerHistory : AckerElectionHistory state responseHistory elections)
    {source : Node}
    {index term : Nat}
    {record : ElectionRecord Node TxId}
    {configuration : Configuration Node}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (sourceConfigurationActive
      : configuration ∈ activeConfigurations (state.nodes source))
    (configurationGoverns : configuration.index <= index)
    (recorded : elections term = some record)
    (ballotActive : configuration ∈ record.ballotActive)
    (newer : (state.nodes source).currentTerm < term)
    (earlierSafe
      : forall earlierTerm earlierRecord,
          (state.nodes source).currentTerm < earlierTerm
          -> earlierTerm < term
          -> elections earlierTerm = some earlierRecord
          -> (state.nodes source).log.take index <+: earlierRecord.promotionLog)
    : Exists
        fun voter =>
          voter ∈ record.supporters
          /\ (state.nodes source).log.take index <+: record.voterLog voter := by
  rcases
      potentialElectionRecordIntersectionEffective
        voteFacts electionFacts potential sourceConfigurationActive
          configurationGoverns recorded ballotActive newer with
    ⟨voter, effective, electionMember⟩
  rcases
      ackerHistory source index sourceRole currentEntry currentSignature
        term record voter recorded electionMember effective newer with
    voterPrefix | earlier
  · exact ⟨voter, electionMember, voterPrefix⟩
  · rcases earlier with
      ⟨earlierTerm, earlierRecord, above, below, earlierRecorded, bad⟩
    exact False.elim
      (bad
        (earlierSafe
          earlierTerm earlierRecord above below earlierRecorded))

/-- Early promotion form used by the activation/election closure induction. -/
lemma leastBadElectionPromotionContainsPrefixForActivation
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (ackerHistory : AckerElectionHistory state responseHistory elections)
    {source : Node}
    {index term : Nat}
    {record : ElectionRecord Node TxId}
    {configuration : Configuration Node}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (sourceConfigurationActive
      : configuration ∈ activeConfigurations (state.nodes source))
    (configurationGoverns : configuration.index <= index)
    (recorded : elections term = some record)
    (ballotActive : configuration ∈ record.ballotActive)
    (newer : (state.nodes source).currentTerm < term)
    (earlierSafe
      : forall earlierTerm earlierRecord,
          (state.nodes source).currentTerm < earlierTerm
          -> earlierTerm < term
          -> elections earlierTerm = some earlierRecord
          -> (state.nodes source).log.take index <+: earlierRecord.promotionLog)
    : (state.nodes source).log.take index <+: record.promotionLog := by
  rcases
      leastBadElectionHasPrefixVoterForActivation
        voteFacts electionFacts ackerHistory sourceRole currentEntry
          currentSignature potential sourceConfigurationActive
          configurationGoverns recorded ballotActive newer earlierSafe with
    ⟨voter, electionMember, voterPrefix⟩
  let supportedPrefix := (state.nodes source).log.take index
  have sourceTermPositive :
      0 < (state.nodes source).currentTerm := by
    exact positiveOfBootstrapTermLe
      (termsPositive source (by rw [sourceRole]; decide))
  have lookupPositive :
      0 < termAt (state.nodes source).log index := by
    rw [currentEntry]
    exact sourceTermPositive
  rcases termAtPositiveEntry lookupPositive with
    ⟨sourceEntry, sourceFound, sourceEntryTerm⟩
  have sourceEntryCurrent :
      sourceEntry.term = (state.nodes source).currentTerm :=
    sourceEntryTerm.trans currentEntry
  have sourceBound :
      index <= (state.nodes source).log.length :=
    entryAtSomeIndexBound sourceFound
  have prefixLength : supportedPrefix.length = index := by
    simp [
      supportedPrefix, List.length_take,
      Nat.min_eq_left sourceBound
    ]
  have voterLength : index <= (record.voterLog voter).length := by
    have covered := voterPrefix.length_le
    rw [prefixLength] at covered
    exact covered
  have voterTakeEq :
      (record.voterLog voter).take index = supportedPrefix := by
    have covered := prefixEqTake voterPrefix
    rw [prefixLength] at covered
    exact covered
  have voterFound :
      entryAt? (record.voterLog voter) index = some sourceEntry := by
    rw [← entryAtTake_of_le (log := record.voterLog voter) le_rfl]
    rw [voterTakeEq]
    rw [entryAtTake_of_le le_rfl]
    exact sourceFound
  have voterNonempty : Not (record.voterLog voter = []) := by
    intro empty
    rw [empty] at voterLength
    simp at voterLength
    have indexPositive : 0 < index := by
      have indexNe : Not (index = 0) := by
        intro zero
        rw [zero] at sourceFound
        simp [entryAt?] at sourceFound
      exact Nat.pos_of_ne_zero indexNe
    omega
  have voterLastPositive : 0 < (record.voterLog voter).length :=
    List.length_pos_iff_ne_nil.mpr voterNonempty
  rcases
      entryAtSomeOfPositiveBound voterLastPositive le_rfl with
    ⟨voterLastEntry, voterLastFound⟩
  have sourceTermLeVoterLast :
      (state.nodes source).currentTerm <= voterLastEntry.term := by
    by_cases atEnd : index = (record.voterLog voter).length
    · rw [atEnd] at voterFound
      have sameEntry : sourceEntry = voterLastEntry :=
        Option.some.inj (voterFound.symm.trans voterLastFound)
      simpa [sameEntry] using sourceEntryCurrent.symm.le
    · have beforeEnd : index < (record.voterLog voter).length := by
        omega
      have monotone :=
        electionHistoryVoterMono
          ownership electionFacts recorded electionMember
            index (record.voterLog voter).length
            sourceEntry voterLastEntry
            beforeEnd voterFound voterLastFound
      rw [sourceEntryCurrent] at monotone
      exact monotone
  have voterLastTerm :
      termAt (record.voterLog voter) (record.voterLog voter).length =
        voterLastEntry.term := by
    simp [termAt, voterLastFound]
  have candidatePrefix :=
    electionFacts.candidatePrefix
      term record voter recorded electionMember
  have candidateCanonical :=
    electionFacts.candidateCanonical
      term record voter recorded electionMember
  have voterCanonical :=
    electionFacts.voterCanonical
      term record voter recorded electionMember
  rcases
      electionFacts.upToDate
        term record voter recorded electionMember with
    candidateNewer | candidateSame
  · have candidateNonempty :
        Not (record.candidateLog voter = []) := by
      intro empty
      simp [
        empty, maxCommittableTerm, termAt, entryAt?
      ] at candidateNewer
    have candidateLastPositive :
        0 < (record.candidateLog voter).length :=
      List.length_pos_iff_ne_nil.mpr candidateNonempty
    rcases
        entryAtSomeOfPositiveBound candidateLastPositive le_rfl with
      ⟨candidateLastEntry, candidateLastFound⟩
    have candidateLastTerm :
        termAt
            (record.candidateLog voter)
            (record.candidateLog voter).length =
          candidateLastEntry.term := by
      simp [termAt, candidateLastFound]
    have sourceTermLtCandidateLast :
        (state.nodes source).currentTerm <
          candidateLastEntry.term := by
      have candidateNewer' :
          voterLastEntry.term < candidateLastEntry.term := by
        simpa [maxCommittableTerm,
          electionFacts.voterCommittable
            term record voter recorded electionMember, candidateLastTerm, voterLastTerm]
          using candidateNewer
      omega
    have candidateEntryInPromotion :
        candidateLastEntry ∈ record.promotionLog :=
      memOfPrefix candidatePrefix
        (entryAtSomeMember candidateLastFound)
    have candidateTermBeforeElection :
        candidateLastEntry.term < term :=
      electionFacts.promotionEntriesBeforeTerm
        term record recorded candidateLastEntry candidateEntryInPromotion
    rcases
        candidateCanonical
          (record.candidateLog voter).length
          candidateLastEntry candidateLastFound with
      ⟨candidateCanonicalFound, candidateAgreed⟩
    rcases
        ownership.canonicalEntryOwner
          candidateLastEntry.term
          (record.candidateLog voter).length
          candidateLastEntry candidateCanonicalFound with
      ⟨candidateOwner, candidateOwned⟩
    rcases
        electionFacts.ownerRecorded
          candidateLastEntry.term candidateOwner candidateOwned with
      bootstrap | candidateElection
    · rw [bootstrap.1] at sourceTermLtCandidateLast
      have sourcePositive :=
        termsPositive source (by rw [sourceRole]; decide)
      omega
    · rcases candidateElection with
        ⟨earlierRecord, earlierRecorded, _⟩
      have prefixInEarlier :=
        earlierSafe
          candidateLastEntry.term earlierRecord
            sourceTermLtCandidateLast
            candidateTermBeforeElection earlierRecorded
      have prefixInCanonical :
          supportedPrefix <+:
            canonicalHistory candidateLastEntry.term :=
        prefixInEarlier.trans
          (electionFacts.promotionCanonical
            candidateLastEntry.term earlierRecord earlierRecorded)
      have canonicalTakeEq :
          (canonicalHistory candidateLastEntry.term).take index =
            supportedPrefix := by
        have covered := prefixEqTake prefixInCanonical
        simpa [prefixLength] using covered
      have canonicalSourceFound :
          entryAt?
              (canonicalHistory candidateLastEntry.term)
              index =
            some sourceEntry := by
        rw [← entryAtTake_of_le
          (log := canonicalHistory candidateLastEntry.term) le_rfl]
        rw [canonicalTakeEq]
        rw [entryAtTake_of_le le_rfl]
        exact sourceFound
      have indexLeCandidateLength :
          index <= (record.candidateLog voter).length := by
        by_contra outside
        have order :
            (record.candidateLog voter).length < index := by omega
        have monotone :=
          ownership.canonicalMonoLog
            candidateLastEntry.term
              (record.candidateLog voter).length index
              candidateLastEntry sourceEntry
              order candidateCanonicalFound canonicalSourceFound
        rw [sourceEntryCurrent] at monotone
        omega
      have prefixInCandidate :
          supportedPrefix <+: record.candidateLog voter := by
        have candidateEq :
            record.candidateLog voter =
              (canonicalHistory candidateLastEntry.term).take
                (record.candidateLog voter).length := by
          simpa using candidateAgreed
        calc
          supportedPrefix = (canonicalHistory candidateLastEntry.term).take index :=
            canonicalTakeEq.symm
          _ <+: (canonicalHistory candidateLastEntry.term).take
                  (record.candidateLog voter).length := by
            rw [List.prefix_take_iff]
            exact ⟨
              List.take_prefix index _,
              Nat.le_trans (List.length_take_le _ _) indexLeCandidateLength
            ⟩
          _ = record.candidateLog voter := candidateEq.symm
      exact prefixInCandidate.trans candidatePrefix
  · have voterCandidatePrefix : record.voterLog voter <+: record.candidateLog voter :=
      canonicalHistoriesPrefixOfSameLastTerm
        canonicalHistory voterCanonical candidateCanonical
        voterNonempty
        (by
          have voterCommittable :=
            electionFacts.voterCommittable
              term record voter recorded electionMember
          have candidateIndex := candidateSame.2
          simp only at candidateIndex
          rw [voterCommittable] at candidateIndex
          exact candidateIndex)
        (by
          simpa [maxCommittableTerm,
            electionFacts.voterCommittable
              term record voter recorded electionMember]
            using candidateSame.1.symm)
    exact voterPrefix.trans (voterCandidatePrefix.trans candidatePrefix)

/--
Activation/election chronology closes every higher frozen election without
assuming that a newly queued AppendEntries reserve existed in the prior state.
-/
lemma potentialPrefixInElectionRecordsFromActivationHistory
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (_entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
    (historyFacts : ActivationHistoryFacts activations)
    (activationProgress : ActivationSupporterProgress state activations)
    (ackerActivation : AckerActivationHistory state responseHistory elections activations)
    (ackerElection : AckerElectionHistory state responseHistory elections)
    (activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations)
    (activationElections : ActivationElectionFacts votes elections activations)
    (configurationActivations : ConfigurationCoverageFacts state activations)
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts
      : ProspectiveCommitEvidenceFacts
          state appendHistory nodeEvidence requestEvidence elections)
    {source : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    : forall term record,
        elections term = some record
        -> (state.nodes source).currentTerm < term
        -> (state.nodes source).log.take index <+: record.promotionLog := by
  intro term
  induction term using Nat.strong_induction_on with
  | h term inductionHypothesis =>
      intro record recorded later
      by_cases committed : index <= (state.nodes source).commitIndex
      · have indexPositive : 0 < index := by
          rcases isSignatureAtTrue currentSignature with
            ⟨entry, found, _⟩
          by_contra notPositive
          have indexZero : index = 0 := Nat.eq_zero_of_not_pos notPositive
          subst index
          simp [entryAt?] at found
        have commitPositive : 0 < (state.nodes source).commitIndex := by
          omega
        rcases evidenceFacts.nodePositive source commitPositive with
          ⟨evidence, stored, valid, _supportedLength, termBound⟩
        have known :
            KnownCommitEvidence
              state appendHistory nodeEvidence requestEvidence
                evidence (state.nodes source).committedLog :=
          Or.inl ⟨source, commitPositive, stored, rfl⟩
        have sourceBound :
            index <= (state.nodes source).log.length := by
          rcases isSignatureAtTrue currentSignature with
            ⟨entry, found, _⟩
          exact entryAtSomeIndexBound found
        have sourceInCommitted :
            (state.nodes source).log.take index <+:
              (state.nodes source).committedLog := by
          unfold NodeState.committedLog
          rw [List.prefix_take_iff]
          exact ⟨
            List.take_prefix index (state.nodes source).log,
            by
              simp [
                List.length_take,
                Nat.min_eq_left sourceBound
              ]
              exact committed
          ⟩
        have evidenceInElection :=
          prospectiveFacts.electionClosure
            evidence (state.nodes source).committedLog known
            term record recorded (termBound.trans_lt later)
        exact
          sourceInCommitted.trans
            ((validEvidenceSupportedPrefixFrontier valid).trans
              evidenceInElection)
      · let sourceConfiguration :=
          currentConfiguration (state.nodes source)
        let ballotConfiguration :=
          currentConfigurationAt
            record.ballotLog record.ballotCommitIndex
        have sourceConfigurationActive :
            sourceConfiguration ∈
              activeConfigurations (state.nodes source) := by
          exact currentConfiguration_mem_activeConfigurations _
        have sourceConfigurationGoverns :
            sourceConfiguration.index <= index := by
          have currentBound :=
            currentConfiguration_index_le_commitIndex
              (state.nodes source)
          dsimp [sourceConfiguration]
          omega
        have ballotConfigurationActive :
            ballotConfiguration ∈ record.ballotActive := by
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
        have directOfShared :
            forall configuration,
              configuration ∈
                  activeConfigurations (state.nodes source) ->
              configuration.index <= index ->
              configuration ∈ record.ballotActive ->
                (state.nodes source).log.take index <+:
                  record.promotionLog := by
          intro configuration sourceActive governs ballotActive
          apply
            leastBadElectionPromotionContainsPrefixForActivation
              termsPositive voteFacts ownership electionFacts
              ackerElection sourceRole currentEntry currentSignature
              potential sourceActive governs recorded ballotActive later
          intro earlierTerm earlierRecord above below earlierRecorded
          exact
            inductionHypothesis earlierTerm below
              earlierRecord earlierRecorded above
        by_cases ballotImplicit :
            ballotConfiguration = implicitConfiguration
        · by_cases sourceImplicit :
              sourceConfiguration = implicitConfiguration
          · exact
              directOfShared
                sourceConfiguration sourceConfigurationActive
                sourceConfigurationGoverns
                (by
                  have same :
                      sourceConfiguration = ballotConfiguration :=
                    sourceImplicit.trans ballotImplicit.symm
                  simpa [same] using ballotConfigurationActive)
          · have sourcePositive :
                0 < sourceConfiguration.index := by
              have sourceNonzero :
                  sourceConfiguration.index ≠ 0 := by
                intro zero
                have implicitEq :
                    sourceConfiguration = implicitConfiguration := by
                  apply
                    allConfigurations_index_unique
                      (TxId := TxId)
                      (state.nodes source).log
                  · exact currentConfiguration_mem_allConfigurations _
                  · simp [allConfigurations, implicitConfiguration]
                  · simpa [implicitConfiguration] using zero
                exact sourceImplicit implicitEq
              exact Nat.pos_of_ne_zero sourceNonzero
            rcases
                configurationActivations source sourcePositive with
              ⟨sourceCoverage⟩
            have sourceActivationInPromotion :=
              activationPrefixInLaterElection
                activationElections sourceCoverage.stored recorded
                (sourceCoverage.activationTerm_le_currentTerm.trans_lt later)
            have sourceConfigurationKnownEvent :
                sourceConfiguration ∈
                  allConfigurations
                    (sourceCoverage.activation.history.take
                      sourceCoverage.activation.activationFrontier) := by
              apply
                memOfPrefix
                  (allConfigurations_mono_prefix
                    sourceCoverage.sharedPrefix_prefix_activationPrefix)
              simpa [sourceConfiguration]
                using sourceCoverage.configuration_mem_activationHistoryTake historyFacts
            have sourceConfigurationKnownActivation :=
              sourceConfigurationKnownEvent
            have sourceConfigurationKnownPromotion :
                sourceConfiguration ∈
                  allConfigurations record.promotionLog := by
              have configurationsPrefix :=
                allConfigurations_mono_prefix sourceActivationInPromotion
              apply memOfPrefix configurationsPrefix
              exact sourceConfigurationKnownActivation
            have sourceConfigurationKnownBallot :
                sourceConfiguration ∈
                  allConfigurations record.ballotLog :=
              memOfPrefix
                (allConfigurations_mono_prefix
                  ((electionFacts.promotionFromBallot
                    term record recorded).symm ▸
                    List.take_prefix
                      (maxCommittableIndex record.ballotLog)
                      record.ballotLog))
                sourceConfigurationKnownPromotion
            have ballotBeforeSource :
                ballotConfiguration.index <=
                  sourceConfiguration.index := by
              simp [ballotConfiguration, ballotImplicit,
                implicitConfiguration]
            exact
              directOfShared
                sourceConfiguration sourceConfigurationActive
                sourceConfigurationGoverns
                (electionConfigurationActiveOfKnown
                  electionFacts recorded
                  sourceConfigurationKnownBallot ballotBeforeSource)
        · have ballotPositive :
              0 < ballotConfiguration.index := by
            have known :
                ballotConfiguration ∈
                  allConfigurations record.ballotLog := by
              simpa [ballotConfiguration, currentConfiguration]
                using currentConfiguration_mem_allConfigurations
                  {
                    (state.nodes record.leader) with
                      log := record.ballotLog
                      commitIndex := record.ballotCommitIndex
                  }
            rw [allConfigurations] at known
            rcases List.mem_cons.mp known with implicit | physical
            · exact False.elim (ballotImplicit implicit)
            · exact (configurationsInLog_index_bounds
                      (TxId := TxId) record.ballotLog physical).1
          rcases
              configurationFacts.ballotCurrentAuthorityActivation
                term record recorded ballotPositive with
            ⟨ballotActivationIndex, ballotActivation,
              ballotActivationStored, ballotAuthorityGoverning,
              ballotActivationTermBefore, ballotAuthorityWithinShared,
              ballotSharedAgreement⟩
          let ballotShared :=
            min record.ballotCommitIndex
              ballotActivation.activationFrontier
          have ballotSharedInPromotion :
              ballotActivation.history.take ballotShared <+:
                record.promotionLog := by
            rw [ballotSharedAgreement]
            apply (show
              record.ballotLog.take ballotShared <+:
                record.ballotLog.take record.ballotCommitIndex by
              rw [List.prefix_take_iff]
              exact
                ⟨List.take_prefix _ _,
                  (List.length_take_le _ _).trans
                    (Nat.min_le_left _ _)⟩).trans
            exact ballotCommitPrefixPromotion
          have ballotActivationInPromotion
              : ballotActivation.history.take ballotActivation.activationFrontier
                <+: record.promotionLog := by
            rcases
                activationElections.closure
                  ballotActivationIndex ballotActivation term record
                  ballotActivationStored recorded
                  ballotActivationTermBefore with
              direct | shared
            · exact direct
            · rcases shared with
                ⟨_, _, _, _, _, _, _, _, promotionPrefix⟩
              exact promotionPrefix
          have ballotConfigurationKnownActivation :
              ballotConfiguration ∈
                allConfigurations ballotActivation.history := by
            have valid :=
              historyFacts.valid
                ballotActivationIndex ballotActivation
                ballotActivationStored
            have governing := ballotAuthorityGoverning
            rw [valid.2.2.2.2.2.2.1] at governing
            exact (List.mem_filter.mp governing).1
          have ballotConfigurationWithinActivation :
              ballotConfiguration.index <=
                ballotActivation.activationFrontier :=
            ballotAuthorityWithinShared.trans (Nat.min_le_right _ _)
          have ballotConfigurationKnownActivationPrefix :
              ballotConfiguration ∈
                allConfigurations
                  (ballotActivation.history.take
                    ballotActivation.activationFrontier) := by
            exact
              allConfigurations_mem_take_of_index_le
                ballotActivation.history
                ballotActivation.activationFrontier
                (historyFacts.valid
                  ballotActivationIndex ballotActivation
                  ballotActivationStored).2.1
                ballotConfigurationKnownActivation
                ballotConfigurationWithinActivation
          by_cases ballotBeforeSource :
              ballotConfiguration.index <= sourceConfiguration.index
          · by_cases sameIndex :
                ballotConfiguration.index = sourceConfiguration.index
            · have sameConfiguration :
                  ballotConfiguration = sourceConfiguration := by
                by_cases sourceZero : sourceConfiguration.index = 0
                · have sourceEq :
                      sourceConfiguration = implicitConfiguration := by
                    apply
                      allConfigurations_index_unique
                        (TxId := TxId)
                        (state.nodes source).log
                    · exact currentConfiguration_mem_allConfigurations _
                    · simp [allConfigurations, implicitConfiguration]
                    · simpa [implicitConfiguration] using sourceZero
                  have ballotEq :
                      ballotConfiguration = implicitConfiguration := by
                    apply
                      allConfigurations_index_unique
                        (TxId := TxId) record.ballotLog
                    · simpa [ballotConfiguration, currentConfiguration]
                        using currentConfiguration_mem_allConfigurations
                          {
                            (state.nodes record.leader) with
                              log := record.ballotLog
                              commitIndex := record.ballotCommitIndex
                          }
                    · simp [allConfigurations, implicitConfiguration]
                    · simp [
                        sameIndex, sourceZero, implicitConfiguration
                      ]
                  exact False.elim (ballotImplicit ballotEq)
                · rcases
                    configurationActivations source
                      (Nat.pos_of_ne_zero sourceZero) with
                    ⟨sourceCoverage⟩
                  have ballotEventValid :=
                    historyFacts.valid
                      ballotActivationIndex ballotActivation
                      ballotActivationStored
                  let ballotEventState : NodeState Node TxId :=
                    { state.nodes source with
                      log := ballotActivation.history
                      commitIndex := ballotActivation.activationFrontier }
                  have ballotBeforeEvent :
                      ballotConfiguration.index <=
                        ballotActivation.newConfiguration.index := by
                    have ordered :=
                      configuration_index_le_currentConfiguration
                        ballotEventState ballotConfiguration
                        (by
                          simpa [ballotEventState]
                            using ballotConfigurationKnownActivation)
                        (by
                          simpa [ballotEventState]
                            using ballotConfigurationWithinActivation)
                    simpa [ballotEventState, currentConfiguration,
                      ballotEventValid.2.2.2.1]
                      using ordered
                  have sourceBeforeEvent :
                      sourceConfiguration.index <=
                        ballotActivation.newConfiguration.index := by
                    simpa [sameIndex] using ballotBeforeEvent
                  have sourceKnownActivation :
                      sourceConfiguration ∈
                        allConfigurations ballotActivation.history := by
                    rcases Nat.lt_or_eq_of_le sourceBeforeEvent with
                      strict | equal
                    · have sourcePrefixInBallot :=
                        sourceCoverage.sharedPrefix_prefix_higherAuthority
                          ballotActivationStored
                          (by simpa [sourceConfiguration] using strict)
                      apply
                        memOfPrefix
                          (allConfigurations_mono_prefix
                            (sourcePrefixInBallot.trans
                              (List.take_prefix
                                ballotActivation.activationFrontier
                                ballotActivation.history)))
                      simpa [sourceConfiguration]
                        using sourceCoverage.configuration_mem_activationHistoryTake
                          historyFacts
                    · have sameAuthority :
                          ballotActivation.newConfiguration =
                            sourceConfiguration := by
                        simpa [sourceConfiguration]
                          using sourceCoverage.sameAuthority_configurationEq
                            ballotActivationStored
                            (by simpa [sourceConfiguration] using equal.symm)
                      have eventKnown :=
                        activationNewConfigurationKnown
                          historyFacts ballotActivationStored
                      apply
                        memOfPrefix
                          (allConfigurations_mono_prefix
                            (List.take_prefix
                              ballotActivation.activationFrontier
                              ballotActivation.history))
                      simpa [sameAuthority] using eventKnown
                  exact
                    allConfigurations_index_unique
                      (TxId := TxId) ballotActivation.history
                      ballotConfigurationKnownActivation
                      sourceKnownActivation sameIndex
              exact directOfShared
                sourceConfiguration sourceConfigurationActive
                sourceConfigurationGoverns
                (by simpa [sameConfiguration] using ballotConfigurationActive)
            · have sourceStrict :
                  ballotConfiguration.index <
                    sourceConfiguration.index := by
                omega
              have sourcePositive : 0 < sourceConfiguration.index :=
                ballotPositive.trans sourceStrict
              rcases
                  configurationActivations source sourcePositive with
                ⟨sourceCoverage⟩
              have sourceActivationInPromotion :=
                activationPrefixInLaterElection
                  activationElections sourceCoverage.stored recorded
                  (sourceCoverage.activationTerm_le_currentTerm.trans_lt later)
              have sourceConfigurationKnownEvent :
                  sourceConfiguration ∈
                    allConfigurations
                      (sourceCoverage.activation.history.take
                        sourceCoverage.activation.activationFrontier) := by
                apply
                  memOfPrefix
                    (allConfigurations_mono_prefix
                      sourceCoverage.sharedPrefix_prefix_activationPrefix)
                simpa [sourceConfiguration]
                  using sourceCoverage.configuration_mem_activationHistoryTake
                    historyFacts
              have sourceConfigurationKnownPromotion :
                  sourceConfiguration ∈
                    allConfigurations record.promotionLog := by
                exact
                  memOfPrefix
                    (allConfigurations_mono_prefix
                      sourceActivationInPromotion)
                    sourceConfigurationKnownEvent
              have sourceConfigurationKnownBallot :
                  sourceConfiguration ∈
                    allConfigurations record.ballotLog := by
                apply
                  memOfPrefix
                    (allConfigurations_mono_prefix
                      (List.take_prefix
                        (maxCommittableIndex record.ballotLog)
                        record.ballotLog))
                simpa [
                  electionFacts.promotionFromBallot term record recorded
                ] using sourceConfigurationKnownPromotion
              exact
                directOfShared
                  sourceConfiguration sourceConfigurationActive
                  sourceConfigurationGoverns
                  (electionConfigurationActiveOfKnown
                    electionFacts recorded
                    sourceConfigurationKnownBallot sourceStrict.le)
          · have sourceBeforeBallot :
                sourceConfiguration.index <
                  ballotConfiguration.index := by
              omega
            by_cases sourceBeforeActivation :
                (state.nodes source).currentTerm <
                  ballotActivation.activationTerm
            · have sourceInActivation :
                  (state.nodes source).log.take index <+:
                    ballotActivation.history.take
                      ballotActivation.activationFrontier := by
                by_cases governing :
                    sourceConfiguration ∈
                      ballotActivation.governingActive
                · apply
                    potentialPrefixInActivation
                      ownership historyFacts activationCanonical
                      activationProgress ackerActivation
                      sourceRole currentEntry currentSignature potential
                      sourceConfigurationActive sourceConfigurationGoverns
                      ballotActivationStored governing
                      sourceBeforeActivation
                  intro earlierTerm earlierRecord above bounded
                      earlierRecorded
                  exact
                    inductionHypothesis earlierTerm
                      (bounded.trans_lt ballotActivationTermBefore)
                      earlierRecord earlierRecorded above
                · rcases
                    electionFacts.ownerRecorded
                      ballotActivation.activationTerm
                      ballotActivation.leader
                      (activationCanonical.termOwner
                        ballotActivationIndex ballotActivation
                          ballotActivationStored) with
                    bootstrap | activationElection
                  · rw [bootstrap.1] at sourceBeforeActivation
                    have positive :=
                      termsPositive source (by rw [sourceRole]; decide)
                    omega
                  · rcases activationElection with
                      ⟨activationRecord, activationRecorded, leaderEq⟩
                    have sourceInElection :=
                      inductionHypothesis
                        ballotActivation.activationTerm
                        ballotActivationTermBefore
                        activationRecord activationRecorded
                        sourceBeforeActivation
                    exact
                      electionPromotionPrefixInActivation
                        electionFacts historyFacts activationCanonical
                        ballotActivationStored
                        (by simpa [leaderEq] using activationRecorded)
                        sourceInElection
              exact sourceInActivation.trans ballotActivationInPromotion
            · have activationBeforeSource :
                  ballotActivation.activationTerm <=
                    (state.nodes source).currentTerm := by
                omega
              by_cases sameTerm :
                  ballotActivation.activationTerm =
                    (state.nodes source).currentTerm
              · have activationCanonicalEq :
                    ballotActivation.history.take
                        ballotActivation.activationFrontier =
                      (state.nodes source).log.take
                        ballotActivation.activationFrontier := by
                  calc
                    ballotActivation.history.take ballotActivation.activationFrontier
                        = (canonicalHistory ballotActivation.activationTerm).take
                            ballotActivation.activationFrontier :=
                      activationCanonical.activationFrontierCanonical
                        ballotActivationIndex ballotActivation
                        ballotActivationStored
                    _ = (state.nodes source).log.take
                          ballotActivation.activationFrontier := by
                      rw [sameTerm, ownership.activeLeaderHistory
                        source sourceRole]
                by_cases indexBefore :
                    index <= ballotActivation.activationFrontier
                · have sourceInActivation :
                      (state.nodes source).log.take index <+:
                        ballotActivation.history.take
                          ballotActivation.activationFrontier := by
                    rw [List.prefix_iff_eq_take]
                    calc
                      (state.nodes source).log.take index
                          = ((state.nodes source).log.take
                              ballotActivation.activationFrontier).take
                              ((state.nodes source).log.take index).length := by
                        have indexBound :
                            index <= (state.nodes source).log.length := by
                          rcases isSignatureAtTrue currentSignature with
                            ⟨entry, found, _⟩
                          exact entryAtSomeIndexBound found
                        simp [
                          List.take_take,
                          List.length_take,
                          Nat.min_eq_left indexBefore,
                          Nat.min_eq_left indexBound
                        ]
                      _ = (ballotActivation.history.take
                            ballotActivation.activationFrontier).take
                            ((state.nodes source).log.take index).length := by
                        rw [activationCanonicalEq]
                  exact sourceInActivation.trans ballotActivationInPromotion
                · have ballotGoverns :
                      ballotConfiguration.index <= index := by
                    exact
                      ballotConfigurationWithinActivation.trans
                        (Nat.lt_of_not_ge indexBefore).le
                  have ballotKnownSource :
                      ballotConfiguration ∈
                        allConfigurations (state.nodes source).log := by
                    have activationPrefixSource :
                        ballotActivation.history.take
                            ballotActivation.activationFrontier <+:
                          (state.nodes source).log := by
                      calc
                        ballotActivation.history.take ballotActivation.activationFrontier
                            = (state.nodes source).log.take
                                ballotActivation.activationFrontier :=
                          activationCanonicalEq
                        _ <+: (state.nodes source).log :=
                          List.take_prefix _ _
                    apply
                      memOfPrefix
                        (allConfigurations_mono_prefix
                          activationPrefixSource)
                    exact ballotConfigurationKnownActivationPrefix
                  have ballotActiveSource :
                      ballotConfiguration ∈
                        activeConfigurations (state.nodes source) := by
                    simpa [activeConfigurations, sourceConfiguration]
                      using And.intro ballotKnownSource sourceBeforeBallot.le
                  exact
                    directOfShared
                      ballotConfiguration ballotActiveSource
                      ballotGoverns ballotConfigurationActive
              · have strict :
                    ballotActivation.activationTerm <
                      (state.nodes source).currentTerm := by
                  omega
                rcases
                    electionFacts.ownerRecorded
                      (state.nodes source).currentTerm source
                      (ownership.activeLeader source sourceRole) with
                  bootstrap | sourceElection
                · rw [bootstrap.1] at strict
                  have activationPositive :=
                    historyFacts.termPositive
                      ballotActivationIndex ballotActivation
                        ballotActivationStored
                  omega
                · rcases sourceElection with
                    ⟨sourceRecord, sourceRecorded, sourceLeader⟩
                  have activationInSourceElection :=
                    activationPrefixInLaterElection
                      activationElections ballotActivationStored
                        sourceRecorded strict
                  have activationInSource :
                      ballotActivation.history.take
                          ballotActivation.activationFrontier <+:
                        (state.nodes source).log := by
                    exact
                      activationInSourceElection.trans
                        ((electionFacts.promotionCanonical
                          (state.nodes source).currentTerm
                          sourceRecord sourceRecorded).trans (by
                            rw [
                              ownership.activeLeaderHistory source sourceRole
                            ]))
                  have ballotKnownSource :
                      ballotConfiguration ∈
                        allConfigurations (state.nodes source).log :=
                    memOfPrefix
                      (allConfigurations_mono_prefix activationInSource)
                      ballotConfigurationKnownActivationPrefix
                  have ballotActiveSource :
                      ballotConfiguration ∈
                        activeConfigurations (state.nodes source) := by
                    simpa [activeConfigurations, sourceConfiguration]
                      using And.intro ballotKnownSource sourceBeforeBallot.le
                  have frontierBeforeIndex :
                      ballotActivation.activationFrontier < index := by
                    rcases isSignatureAtTrue currentSignature with
                      ⟨sourceEntry, sourceFound, _⟩
                    have sourceEntryTerm :
                        sourceEntry.term =
                          (state.nodes source).currentTerm := by
                      simpa [termAt, sourceFound] using currentEntry
                    rcases isSignatureAtTrue
                        (historyFacts.valid
                          ballotActivationIndex ballotActivation
                            ballotActivationStored).2.2.2.2.2.1 with
                      ⟨activationEntry, activationFound, _⟩
                    have activationEntryTerm :
                        activationEntry.term =
                          ballotActivation.activationTerm := by
                      have activationTerm :=
                        (historyFacts.supporterAcks
                          ballotActivationIndex ballotActivation
                            ballotActivationStored).1
                      simpa [termAt, activationFound] using activationTerm
                    have activationFoundSource :=
                      entryAt_of_prefix
                        activationInSource (by
                          rw [entryAtTake_of_le le_rfl]
                          exact activationFound)
                    have mono := canonicalHistoriesMonoLog ownership
                    by_contra notBefore
                    have indexLe :
                        index <= ballotActivation.activationFrontier := by
                      omega
                    by_cases equal :
                        index = ballotActivation.activationFrontier
                    · have sameEntry : sourceEntry = activationEntry :=
                        Option.some.inj
                          (sourceFound.symm.trans
                            (by simpa [equal] using activationFoundSource))
                      rw [sameEntry, activationEntryTerm] at sourceEntryTerm
                      omega
                    · have order :
                          index < ballotActivation.activationFrontier := by
                        omega
                      have monotone :=
                        mono source index
                          ballotActivation.activationFrontier
                          sourceEntry activationEntry order
                          sourceFound activationFoundSource
                      rw [sourceEntryTerm, activationEntryTerm] at monotone
                      omega
                  have ballotGoverns :
                      ballotConfiguration.index <= index := by
                    exact
                      ballotConfigurationWithinActivation.trans
                        frontierBeforeIndex.le
                  exact
                    directOfShared
                      ballotConfiguration ballotActiveSource
                      ballotGoverns ballotConfigurationActive

/--
For the least higher-term election whose promotion log omits a prospective
signature frontier, quorum intersection yields a voter whose frozen voter log
contains that frontier.
-/
lemma leastBadElectionHasPrefixVoter
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (voteFacts : VoteHistoryFacts state votes)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (ackerHistory : AckerElectionHistory state responseHistory elections)
    {source : Node}
    {index term : Nat}
    {record : ElectionRecord Node TxId}
    {configuration : Configuration Node}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (sourceConfigurationActive
      : configuration ∈ activeConfigurations (state.nodes source))
    (configurationGoverns : configuration.index <= index)
    (recorded : elections term = some record)
    (ballotActive : configuration ∈ record.ballotActive)
    (newer : (state.nodes source).currentTerm < term)
    (earlierSafe
      : forall earlierTerm earlierRecord,
          (state.nodes source).currentTerm < earlierTerm
          -> earlierTerm < term
          -> elections earlierTerm = some earlierRecord
          -> (state.nodes source).log.take index <+: earlierRecord.promotionLog)
    : Exists
        fun voter =>
          voter ∈ record.supporters
          /\ (state.nodes source).log.take index <+: record.voterLog voter := by
  rcases
      potentialElectionRecordIntersectionEffective
        voteFacts electionFacts potential sourceConfigurationActive
          configurationGoverns recorded ballotActive newer with
    ⟨voter, effective, electionMember⟩
  rcases
      ackerHistory source index sourceRole currentEntry currentSignature
        term record voter recorded electionMember effective newer with
    voterPrefix | earlier
  · exact ⟨voter, electionMember, voterPrefix⟩
  · rcases earlier with
      ⟨earlierTerm, earlierRecord, above, below, earlierRecorded, bad⟩
    exact False.elim
      (bad
        (earlierSafe
          earlierTerm earlierRecord above below earlierRecorded))

/--
The least higher-term election cannot omit a prospectively quorum-supported
current-term signature frontier.
-/
lemma leastBadElectionPromotionContainsPrefix
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    (termsPositive : CurrentTermsPositive state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (ackerHistory : AckerElectionHistory state responseHistory elections)
    {source : Node}
    {index term : Nat}
    {record : ElectionRecord Node TxId}
    {configuration : Configuration Node}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (sourceConfigurationActive
      : configuration ∈ activeConfigurations (state.nodes source))
    (configurationGoverns : configuration.index <= index)
    (recorded : elections term = some record)
    (ballotActive : configuration ∈ record.ballotActive)
    (newer : (state.nodes source).currentTerm < term)
    (earlierSafe
      : forall earlierTerm earlierRecord,
          (state.nodes source).currentTerm < earlierTerm
          -> earlierTerm < term
          -> elections earlierTerm = some earlierRecord
          -> (state.nodes source).log.take index <+: earlierRecord.promotionLog)
    : (state.nodes source).log.take index <+: record.promotionLog := by
  rcases
      leastBadElectionHasPrefixVoter
        voteFacts electionFacts ackerHistory sourceRole currentEntry
          currentSignature
          potential sourceConfigurationActive configurationGoverns
          recorded ballotActive newer earlierSafe with
    ⟨voter, electionMember, voterPrefix⟩
  let supportedPrefix := (state.nodes source).log.take index
  have sourceTermPositive :
      0 < (state.nodes source).currentTerm := by
    exact positiveOfBootstrapTermLe
      (termsPositive source (by rw [sourceRole]; decide))
  have lookupPositive :
      0 < termAt (state.nodes source).log index := by
    rw [currentEntry]
    exact sourceTermPositive
  rcases termAtPositiveEntry lookupPositive with
    ⟨sourceEntry, sourceFound, sourceEntryTerm⟩
  have sourceEntryCurrent :
      sourceEntry.term = (state.nodes source).currentTerm :=
    sourceEntryTerm.trans currentEntry
  have sourceBound :
      index <= (state.nodes source).log.length :=
    entryAtSomeIndexBound sourceFound
  have prefixLength : supportedPrefix.length = index := by
    simp [
      supportedPrefix, List.length_take,
      Nat.min_eq_left sourceBound
    ]
  have indexPositive : 0 < index := by
    have indexNe : Not (index = 0) := by
      intro zero
      rw [zero] at sourceFound
      simp [entryAt?] at sourceFound
    exact Nat.pos_of_ne_zero indexNe
  have voterLength : index <= (record.voterLog voter).length := by
    have covered := voterPrefix.length_le
    rw [prefixLength] at covered
    exact covered
  have voterTakeEq :
      (record.voterLog voter).take index = supportedPrefix := by
    have covered := prefixEqTake voterPrefix
    rw [prefixLength] at covered
    exact covered
  have voterFound :
      entryAt? (record.voterLog voter) index = some sourceEntry := by
    rw [← entryAtTake_of_le (log := record.voterLog voter) le_rfl]
    rw [voterTakeEq]
    rw [entryAtTake_of_le le_rfl]
    exact sourceFound
  have voterNonempty : Not (record.voterLog voter = []) := by
    intro empty
    rw [empty] at voterLength
    simp at voterLength
    omega
  have voterLastPositive : 0 < (record.voterLog voter).length :=
    List.length_pos_iff_ne_nil.mpr voterNonempty
  rcases
      entryAtSomeOfPositiveBound voterLastPositive le_rfl with
    ⟨voterLastEntry, voterLastFound⟩
  have sourceTermLeVoterLast :
      (state.nodes source).currentTerm <= voterLastEntry.term := by
    by_cases atEnd : index = (record.voterLog voter).length
    · rw [atEnd] at voterFound
      have sameEntry : sourceEntry = voterLastEntry :=
        Option.some.inj (voterFound.symm.trans voterLastFound)
      simpa [sameEntry] using sourceEntryCurrent.symm.le
    · have beforeEnd : index < (record.voterLog voter).length := by
        omega
      have monotone :=
        electionHistoryVoterMono
          ownership electionFacts recorded electionMember
            index (record.voterLog voter).length
            sourceEntry voterLastEntry
            beforeEnd voterFound voterLastFound
      rw [sourceEntryCurrent] at monotone
      exact monotone
  have voterLastTerm :
      termAt (record.voterLog voter) (record.voterLog voter).length =
        voterLastEntry.term := by
    simp [termAt, voterLastFound]
  have candidatePrefix :=
    electionFacts.candidatePrefix
      term record voter recorded electionMember
  have candidateCanonical :=
    electionFacts.candidateCanonical
      term record voter recorded electionMember
  have voterCanonical :=
    electionFacts.voterCanonical
      term record voter recorded electionMember
  rcases
      electionFacts.upToDate
        term record voter recorded electionMember with
    candidateNewer | candidateSame
  · have candidateNonempty :
        Not (record.candidateLog voter = []) := by
      intro empty
      simp [
        empty, maxCommittableTerm, termAt, entryAt?
      ] at candidateNewer
    have candidateLastPositive :
        0 < (record.candidateLog voter).length :=
      List.length_pos_iff_ne_nil.mpr candidateNonempty
    rcases
        entryAtSomeOfPositiveBound candidateLastPositive le_rfl with
      ⟨candidateLastEntry, candidateLastFound⟩
    have candidateLastTerm :
        termAt
            (record.candidateLog voter)
            (record.candidateLog voter).length =
          candidateLastEntry.term := by
      simp [termAt, candidateLastFound]
    have sourceTermLtCandidateLast :
        (state.nodes source).currentTerm <
          candidateLastEntry.term := by
      have candidateNewer' :
          voterLastEntry.term < candidateLastEntry.term := by
        simpa [maxCommittableTerm,
          electionFacts.voterCommittable
            term record voter recorded electionMember, candidateLastTerm, voterLastTerm]
          using candidateNewer
      omega
    have candidateEntryInPromotion :
        candidateLastEntry ∈ record.promotionLog :=
      memOfPrefix candidatePrefix
        (entryAtSomeMember candidateLastFound)
    have candidateTermBeforeElection :
        candidateLastEntry.term < term :=
      electionFacts.promotionEntriesBeforeTerm
        term record recorded candidateLastEntry
          candidateEntryInPromotion
    rcases
        candidateCanonical
          (record.candidateLog voter).length
          candidateLastEntry candidateLastFound with
      ⟨candidateCanonicalFound, candidateAgreed⟩
    rcases
        ownership.canonicalEntryOwner
          candidateLastEntry.term
          (record.candidateLog voter).length
          candidateLastEntry candidateCanonicalFound with
      ⟨candidateOwner, candidateOwned⟩
    rcases
        electionFacts.ownerRecorded
          candidateLastEntry.term candidateOwner candidateOwned with
      bootstrap | candidateElection
    · rw [bootstrap.1] at sourceTermLtCandidateLast
      have sourcePositive :=
        termsPositive source (by rw [sourceRole]; decide)
      omega
    · rcases candidateElection with
        ⟨earlierRecord, earlierRecorded, _⟩
      have prefixInEarlier :=
        earlierSafe
          candidateLastEntry.term earlierRecord
            sourceTermLtCandidateLast
            candidateTermBeforeElection earlierRecorded
      have prefixInCanonical :
          supportedPrefix <+:
            canonicalHistory candidateLastEntry.term :=
        prefixInEarlier.trans
          (electionFacts.promotionCanonical
            candidateLastEntry.term earlierRecord earlierRecorded)
      have canonicalTakeEq :
          (canonicalHistory candidateLastEntry.term).take index =
            supportedPrefix := by
        have covered := prefixEqTake prefixInCanonical
        simpa [prefixLength] using covered
      have canonicalSourceFound :
          entryAt?
              (canonicalHistory candidateLastEntry.term)
              index =
            some sourceEntry := by
        rw [← entryAtTake_of_le
          (log := canonicalHistory candidateLastEntry.term) le_rfl]
        rw [canonicalTakeEq]
        rw [entryAtTake_of_le le_rfl]
        exact sourceFound
      have indexLeCandidateLength :
          index <= (record.candidateLog voter).length := by
        by_contra outside
        have order :
            (record.candidateLog voter).length < index := by omega
        have monotone :=
          ownership.canonicalMonoLog
            candidateLastEntry.term
              (record.candidateLog voter).length index
              candidateLastEntry sourceEntry
              order candidateCanonicalFound canonicalSourceFound
        rw [sourceEntryCurrent] at monotone
        omega
      have prefixInCandidate :
          supportedPrefix <+: record.candidateLog voter := by
        have candidateEq :
            record.candidateLog voter =
              (canonicalHistory candidateLastEntry.term).take
                (record.candidateLog voter).length := by
          simpa using candidateAgreed
        calc
          supportedPrefix = (canonicalHistory candidateLastEntry.term).take index :=
            canonicalTakeEq.symm
          _ <+: (canonicalHistory candidateLastEntry.term).take
                  (record.candidateLog voter).length := by
            rw [List.prefix_take_iff]
            exact ⟨
              List.take_prefix index _,
              Nat.le_trans (List.length_take_le _ _) indexLeCandidateLength
            ⟩
          _ = record.candidateLog voter := candidateEq.symm
      exact prefixInCandidate.trans candidatePrefix
  · have voterCandidatePrefix : record.voterLog voter <+: record.candidateLog voter :=
      canonicalHistoriesPrefixOfSameLastTerm
        canonicalHistory voterCanonical candidateCanonical
        voterNonempty
        (by
          have voterCommittable :=
            electionFacts.voterCommittable
              term record voter recorded electionMember
          have candidateIndex := candidateSame.2
          simp only at candidateIndex
          rw [voterCommittable] at candidateIndex
          exact candidateIndex)
        (by
          simpa [maxCommittableTerm,
            electionFacts.voterCommittable
              term record voter recorded electionMember]
            using candidateSame.1.symm)
    exact voterPrefix.trans (voterCandidatePrefix.trans candidatePrefix)

/-- Every higher frozen election record contains a prospective signature frontier. -/
lemma potentialPrefixInElectionRecords
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
    (ackerHistory : AckerElectionHistory state responseHistory elections)
    (activationQuorums
      : ActivationQuorumFacts state appendHistory responseHistory elections activations)
    {source : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    : forall term record,
        elections term = some record
        -> (state.nodes source).currentTerm < term
        -> (state.nodes source).log.take index <+: record.promotionLog := by
  intro term
  induction term using Nat.strong_induction_on with
  | h term inductionHypothesis =>
      intro record recorded newer
      rcases
          activationQuorums.recordBridge
            source index sourceRole currentEntry currentSignature potential
            term record recorded newer with
        direct | shared
      · exact direct
      · rcases shared with
          ⟨configuration, sourceActive, governs, ballotActive⟩
        apply
          leastBadElectionPromotionContainsPrefix
            termsPositive voteFacts ownership electionFacts ackerHistory
              sourceRole currentEntry currentSignature potential
              sourceActive governs recorded ballotActive newer
        intro earlierTerm earlierRecord above below earlierRecorded
        exact
          inductionHypothesis earlierTerm below
            earlierRecord earlierRecorded above

/-- Every higher active leader contains a prospective current-term signature frontier. -/
lemma potentialPrefixInHigherLeader
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
    (ackerHistory : AckerElectionHistory state responseHistory elections)
    (activationQuorums
      : ActivationQuorumFacts state appendHistory responseHistory elections activations)
    {source leader : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (leaderRole : (state.nodes leader).role = .leader)
    (newer : (state.nodes source).currentTerm < (state.nodes leader).currentTerm)
    : (state.nodes source).log.take index <+: (state.nodes leader).log := by
  have owned :=
    ownership.activeLeader leader leaderRole
  rcases
      electionFacts.ownerRecorded
        (state.nodes leader).currentTerm leader owned with
    bootstrap | recorded
  · rw [bootstrap.1] at newer
    have positive :=
      termsPositive source (by rw [sourceRole]; decide)
    omega
  · rcases recorded with
      ⟨record, recordStored, recordLeader⟩
    have promotionPrefix :=
      potentialPrefixInElectionRecords
        termsPositive voteFacts ownership electionFacts ackerHistory
          activationQuorums
          sourceRole currentEntry currentSignature potential
          (state.nodes leader).currentTerm record
          recordStored newer
    have canonicalPrefix :=
      promotionPrefix.trans
        (electionFacts.promotionCanonical
          (state.nodes leader).currentTerm record recordStored)
    rw [ownership.activeLeaderHistory leader leaderRole] at canonicalPrefix
    exact canonicalPrefix

/--
An up-to-date candidate snapshot contains a supported history prefix once
every strictly intermediate elected term is known to contain it.
-/
lemma candidateSnapshotContainsSupportedPrefix
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {supportedHistory : List (Entry Node TxId)}
    {supportedTerm index targetTerm : Nat}
    (supportedTermPositive : BOOTSTRAP_TERM <= supportedTerm)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    {candidateLog voterLog promotionLog : List (Entry Node TxId)}
    (supportedEntry : termAt supportedHistory index = supportedTerm)
    (supportedSignature : isSignatureAt supportedHistory index = true)
    (voterPrefix : supportedHistory.take index <+: voterLog)
    (candidatePrefix : candidateLog <+: promotionLog)
    (candidateCanonical : HistoryCanonical canonicalHistory candidateLog)
    (voterCanonical : HistoryCanonical canonicalHistory voterLog)
    (voterMono : MonoHistory voterLog)
    (candidateEntrySafe
      : forall entry,
          entry ∈ candidateLog
          -> entry.term < targetTerm
              \/ (entry.term = targetTerm
                  /\ forall record,
                      elections targetTerm = some record
                      -> supportedHistory.take index <+: record.promotionLog))
    (upToDate
      : maxCommittableTerm candidateLog > maxCommittableTerm voterLog
        \/ (maxCommittableTerm candidateLog = maxCommittableTerm voterLog
            /\ maxCommittableIndex candidateLog >= maxCommittableIndex voterLog))
    (earlierSafe
      : forall earlierTerm earlierRecord,
          supportedTerm < earlierTerm
          -> earlierTerm < targetTerm
          -> elections earlierTerm = some earlierRecord
          -> supportedHistory.take index <+: earlierRecord.promotionLog)
    : supportedHistory.take index <+: promotionLog := by
  let supportedPrefix := supportedHistory.take index
  have supportedTermPositive' : 0 < supportedTerm := by
    exact positiveOfBootstrapTermLe supportedTermPositive
  have lookupPositive :
      0 < termAt supportedHistory index := by
    rw [supportedEntry]
    exact supportedTermPositive'
  rcases termAtPositiveEntry lookupPositive with
    ⟨supportedEntryAtIndex, supportedFound, supportedEntryTerm⟩
  have supportedEntryCurrent :
      supportedEntryAtIndex.term = supportedTerm :=
    supportedEntryTerm.trans supportedEntry
  have supportedBound :
      index <= supportedHistory.length :=
    entryAtSomeIndexBound supportedFound
  have prefixLength : supportedPrefix.length = index := by
    simp [
      supportedPrefix, List.length_take,
      Nat.min_eq_left supportedBound
    ]
  have voterLength : index <= voterLog.length := by
    have covered := voterPrefix.length_le
    rw [prefixLength] at covered
    exact covered
  have voterTakeEq : voterLog.take index = supportedPrefix := by
    have covered := prefixEqTake voterPrefix
    rw [prefixLength] at covered
    exact covered
  have voterFound :
      entryAt? voterLog index = some supportedEntryAtIndex := by
    rw [← entryAtTake_of_le (log := voterLog) le_rfl]
    rw [voterTakeEq]
    rw [entryAtTake_of_le le_rfl]
    exact supportedFound
  have supportedPrefixSignature :
      isSignatureAt supportedPrefix index = true := by
    exact isSignatureAt_take_of_le le_rfl supportedSignature
  have voterSignature :
      isSignatureAt voterLog index = true :=
    isSignatureAt_of_prefix voterPrefix supportedPrefixSignature
  have voterFrontierBound :
      index <= maxCommittableIndex voterLog :=
    signatureIndex_le_maxCommittableIndex voterSignature
  have voterFrontierPositive :
      0 < maxCommittableIndex voterLog := by
    have indexPositive : 0 < index := by
      apply Nat.pos_of_ne_zero
      intro indexZero
      rw [indexZero] at supportedFound
      simp [entryAt?] at supportedFound
    omega
  rcases
      isSignatureAtTrue
        (maxCommittableIndexPositiveIsSignature voterFrontierPositive) with
    ⟨voterLastEntry, voterLastFound, _⟩
  have supportedTermLeVoterLast :
      supportedTerm <= voterLastEntry.term := by
    by_cases atEnd : index = maxCommittableIndex voterLog
    · rw [atEnd] at voterFound
      have sameEntry : supportedEntryAtIndex = voterLastEntry :=
        Option.some.inj (voterFound.symm.trans voterLastFound)
      simpa [sameEntry] using supportedEntryCurrent.symm.le
    · have beforeEnd : index < maxCommittableIndex voterLog := by omega
      have monotone :=
        voterMono index (maxCommittableIndex voterLog)
          supportedEntryAtIndex voterLastEntry
          beforeEnd voterFound voterLastFound
      rw [supportedEntryCurrent] at monotone
      exact monotone
  have voterLastTerm :
      maxCommittableTerm voterLog = voterLastEntry.term := by
    simp [maxCommittableTerm, termAt, voterLastFound]
  rcases upToDate with candidateNewer | candidateSame
  · have candidateTermPositive :
        0 < maxCommittableTerm candidateLog := by
      have voterTermPositive :
          0 < maxCommittableTerm voterLog := by
        rw [voterLastTerm]
        exact supportedTermPositive'.trans_le supportedTermLeVoterLast
      exact voterTermPositive.trans candidateNewer
    have candidateFrontierPositive :
        0 < maxCommittableIndex candidateLog := by
      apply Nat.pos_of_ne_zero
      intro frontierZero
      unfold maxCommittableTerm at candidateTermPositive
      rw [frontierZero] at candidateTermPositive
      simp [termAt, entryAt?] at candidateTermPositive
    rcases
        isSignatureAtTrue
          (maxCommittableIndexPositiveIsSignature
            candidateFrontierPositive) with
      ⟨candidateLastEntry, candidateLastFound, _⟩
    have candidateLastTerm :
        maxCommittableTerm candidateLog =
          candidateLastEntry.term := by
      simp [maxCommittableTerm, termAt, candidateLastFound]
    have candidateNewer' :
        voterLastEntry.term < candidateLastEntry.term := by
      simpa [candidateLastTerm, voterLastTerm] using candidateNewer
    have supportedTermLtCandidateLast :
        supportedTerm < candidateLastEntry.term := by
      omega
    have candidateSafe :=
      candidateEntrySafe candidateLastEntry
        (entryAtSomeMember candidateLastFound)
    rcases
        candidateCanonical (maxCommittableIndex candidateLog)
          candidateLastEntry candidateLastFound with
      ⟨candidateCanonicalFound, candidateAgreed⟩
    rcases
        ownership.canonicalEntryOwner
          candidateLastEntry.term (maxCommittableIndex candidateLog)
          candidateLastEntry candidateCanonicalFound with
      ⟨candidateOwner, candidateOwned⟩
    rcases
        electionFacts.ownerRecorded
          candidateLastEntry.term candidateOwner candidateOwned with
      bootstrap | candidateElection
    · rw [bootstrap.1] at supportedTermLtCandidateLast
      omega
    · rcases candidateElection with
        ⟨earlierRecord, earlierRecorded, _⟩
      have prefixInEarlier : supportedPrefix <+: earlierRecord.promotionLog := by
        rcases candidateSafe with before | atTarget
        · exact
            earlierSafe
              candidateLastEntry.term earlierRecord
                supportedTermLtCandidateLast before earlierRecorded
        · exact atTarget.2 earlierRecord (by simpa [atTarget.1] using earlierRecorded)
      have prefixInCanonical :
          supportedPrefix <+:
            canonicalHistory candidateLastEntry.term :=
        prefixInEarlier.trans
          (electionFacts.promotionCanonical
            candidateLastEntry.term earlierRecord earlierRecorded)
      have canonicalTakeEq :
          (canonicalHistory candidateLastEntry.term).take index =
            supportedPrefix := by
        have covered := prefixEqTake prefixInCanonical
        rw [prefixLength] at covered
        exact covered
      have canonicalSupportedFound :
          entryAt?
              (canonicalHistory candidateLastEntry.term)
              index =
            some supportedEntryAtIndex := by
        rw [← entryAtTake_of_le
          (log := canonicalHistory candidateLastEntry.term) le_rfl]
        rw [canonicalTakeEq]
        rw [entryAtTake_of_le le_rfl]
        exact supportedFound
      have indexLeCandidateFrontier :
          index <= maxCommittableIndex candidateLog := by
        by_contra outside
        have order : maxCommittableIndex candidateLog < index := by omega
        have monotone :=
          ownership.canonicalMonoLog
            candidateLastEntry.term
              (maxCommittableIndex candidateLog) index
              candidateLastEntry supportedEntryAtIndex
              order candidateCanonicalFound canonicalSupportedFound
        rw [supportedEntryCurrent] at monotone
        omega
      have prefixInCandidate : supportedPrefix <+: candidateLog := by
        calc
          supportedPrefix = (canonicalHistory candidateLastEntry.term).take index :=
            canonicalTakeEq.symm
          _ <+: (canonicalHistory candidateLastEntry.term).take
                  (maxCommittableIndex candidateLog) := by
            rw [List.prefix_take_iff]
            exact ⟨
              List.take_prefix index _,
              Nat.le_trans (List.length_take_le _ _) indexLeCandidateFrontier
            ⟩
          _ = candidateLog.take (maxCommittableIndex candidateLog) :=
            candidateAgreed.symm
          _ <+: candidateLog :=
            List.take_prefix _ _
      exact prefixInCandidate.trans candidatePrefix
  · have candidateFrontierPositive :
        0 < maxCommittableIndex candidateLog := by
      exact lt_of_lt_of_le voterFrontierPositive candidateSame.2
    rcases
        isSignatureAtTrue
          (maxCommittableIndexPositiveIsSignature
            candidateFrontierPositive) with
      ⟨candidateLastEntry, candidateLastFound, _⟩
    have candidateLastTerm :
        maxCommittableTerm candidateLog =
          candidateLastEntry.term := by
      simp [maxCommittableTerm, termAt, candidateLastFound]
    have sameTerm :
        voterLastEntry.term = candidateLastEntry.term := by
      rw [← voterLastTerm, ← candidateLastTerm]
      exact candidateSame.1.symm
    rcases
        voterCanonical (maxCommittableIndex voterLog)
          voterLastEntry voterLastFound with
      ⟨_, voterAgreed⟩
    rcases
        candidateCanonical (maxCommittableIndex candidateLog)
          candidateLastEntry candidateLastFound with
      ⟨_, candidateAgreed⟩
    have supportedInVoterFrontier :
        supportedPrefix <+:
          voterLog.take (maxCommittableIndex voterLog) := by
      rw [List.prefix_iff_eq_take]
      calc
        supportedPrefix = voterLog.take index := voterTakeEq.symm
        _ = (voterLog.take (maxCommittableIndex voterLog)).take
              supportedPrefix.length := by
          simp [List.take_take, prefixLength,
            Nat.min_eq_left voterFrontierBound]
    have voterInCandidateFrontier :
        voterLog.take (maxCommittableIndex voterLog) <+:
          candidateLog.take (maxCommittableIndex candidateLog) := by
      rw [voterAgreed]
      rw [sameTerm, candidateAgreed]
      rw [List.prefix_take_iff]
      exact ⟨
        List.take_prefix _ _,
        (List.length_take_le
          (maxCommittableIndex voterLog)
          (canonicalHistory candidateLastEntry.term)).trans
          candidateSame.2
      ⟩
    exact
      supportedInVoterFrontier.trans
        (voterInCandidateFrontier.trans
          ((List.take_prefix _ _).trans candidatePrefix))

/--
An up-to-date candidate snapshot contains a prospective prefix once every
strictly intermediate elected term is known to contain it.
-/
lemma candidateSnapshotContainsProspectivePrefix
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {source : Node}
    (sourceTermPositive : BOOTSTRAP_TERM <= (state.nodes source).currentTerm)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    {index targetTerm : Nat}
    {candidateLog voterLog promotionLog : List (Entry Node TxId)}
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (voterPrefix : (state.nodes source).log.take index <+: voterLog)
    (candidatePrefix : candidateLog <+: promotionLog)
    (candidateCanonical : HistoryCanonical canonicalHistory candidateLog)
    (voterCanonical : HistoryCanonical canonicalHistory voterLog)
    (voterMono : MonoHistory voterLog)
    (candidateEntrySafe
      : forall entry,
          entry ∈ candidateLog
          -> entry.term < targetTerm
              \/ (entry.term = targetTerm
                  /\ forall record,
                      elections targetTerm = some record
                      -> (state.nodes source).log.take index <+: record.promotionLog))
    (upToDate
      : voteLogUpToDate
          { (state.nodes source) with log := voterLog }
          {
            term := targetTerm
            lastCommittableTerm := maxCommittableTerm candidateLog
            lastCommittableIndex := maxCommittableIndex candidateLog
            source
            destination := source
          })
    (earlierSafe
      : forall earlierTerm earlierRecord,
          (state.nodes source).currentTerm < earlierTerm
          -> earlierTerm < targetTerm
          -> elections earlierTerm = some earlierRecord
          -> (state.nodes source).log.take index <+: earlierRecord.promotionLog)
    : (state.nodes source).log.take index <+: promotionLog := by
  apply
    candidateSnapshotContainsSupportedPrefix
      (targetTerm := targetTerm)
      sourceTermPositive ownership electionFacts
        currentEntry currentSignature voterPrefix candidatePrefix
        candidateCanonical voterCanonical voterMono
        candidateEntrySafe
  · simpa [voteLogUpToDate] using upToDate
  · exact earlierSafe

/-- Every higher prospective winning candidate contains a prospective prefix. -/
lemma potentialPrefixInHigherCandidateOfSharedConfiguration
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
    (_candidatesAbove : CandidatesAboveBootstrap state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (voteFacts : VoteHistoryFacts state votes)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (canonicalSnapshots
      : GrantedVoteCanonicalSnapshots
          state canonicalHistory voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (_configurationFacts : ElectionConfigurationFacts state elections activations)
    (currentHistory : AckerCurrentHistory state responseHistory elections)
    (voteHistory
      : AckerVoteHistory state votes responseHistory voteVoterHistory elections)
    (electedHistory : AckerElectionHistory state responseHistory elections)
    (activationQuorums
      : ActivationQuorumFacts state appendHistory responseHistory elections activations)
    {source candidate : Node}
    {index : Nat}
    {configuration : Configuration Node}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (candidateRole : (state.nodes candidate).role = .candidate)
    (candidateMajority : hasPotentialElectionMajority state candidate)
    (sourceConfigurationActive
      : configuration ∈ activeConfigurations (state.nodes source))
    (configurationGoverns : configuration.index <= index)
    (candidateConfigurationActive
      : configuration ∈ activeConfigurations (state.nodes candidate))
    (newer : (state.nodes source).currentTerm < (state.nodes candidate).currentTerm)
    : (state.nodes source).log.take index <+: (state.nodes candidate).log := by
  rcases
      potentialElectionMajorityIntersectionEffective
        snapshots potential sourceConfigurationActive
          configurationGoverns (Or.inl candidateRole)
          candidateMajority candidateConfigurationActive newer with
    ⟨voter, effective, electionMember⟩
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
  have badImpossible :
      forall bound,
        bound <= (state.nodes candidate).currentTerm ->
        EarlierBadElection state elections source index bound ->
          False := by
    intro bound bounded bad
    rcases bad with
      ⟨badTerm, badRecord, above, badBound, recorded, missing⟩
    exact
      missing
        (potentialPrefixInElectionRecords
          termsPositive voteFacts ownership electionFacts electedHistory
            activationQuorums
            sourceRole currentEntry currentSignature potential
            badTerm badRecord recorded above)
  by_cases voterEq : voter = candidate
  · subst voter
    rcases
        currentHistory source index sourceRole currentEntry currentSignature
          candidate effective with
      retained | bad
    · exact retained
    · exact False.elim
        (badImpossible
          (state.nodes candidate).currentTerm le_rfl bad)
  · simp only [
      potentialElectionVoters, Finset.mem_filter] at electionMember
    rcases electionMember with ⟨_joined, materialised | eligible⟩
    · have snapshot :=
        snapshots candidate voter
          (Or.inl candidateRole) materialised
      have recordedVote := snapshot.1
      rcases
          voteHistory source index sourceRole currentEntry currentSignature
            voter (state.nodes candidate).currentTerm candidate
            effective recordedVote voterEq newer with
        voterPrefix | bad
      · rcases snapshot.2 with self | voteSnapshot
        · exact False.elim (voterEq self)
        · rcases
            canonicalSnapshots candidate voter
              (Or.inl candidateRole) materialised with
          self | canonicalSnapshot
          · exact False.elim (voterEq self)
          · let response :=
              grantedVoteKey
                voter (state.nodes candidate).currentTerm candidate
            have candidateEntrySafe :
                forall entry,
                  entry ∈ voteCandidateHistory response ->
                    entry.term < (state.nodes candidate).currentTerm \/
                      (entry.term = (state.nodes candidate).currentTerm /\
                        forall record,
                          elections (state.nodes candidate).currentTerm =
                              some record ->
                            (state.nodes source).log.take index <+:
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
                    potentialPrefixInElectionRecords
                      termsPositive voteFacts ownership electionFacts
                        electedHistory activationQuorums
                        sourceRole currentEntry currentSignature potential
                        (state.nodes candidate).currentTerm record
                        recorded newer⟩
              · exact Or.inl (by omega)
            apply
              candidateSnapshotContainsProspectivePrefix
                (targetTerm := (state.nodes candidate).currentTerm)
                (termsPositive source (by rw [sourceRole]; decide))
                ownership electionFacts
                  currentEntry currentSignature voterPrefix voteSnapshot.1
                  canonicalSnapshot.1
                  canonicalSnapshot.2.2.1
                  canonicalSnapshot.2.2.2
                  candidateEntrySafe
            · simpa [
                response, voteLogUpToDate, maxCommittableTerm,
                voteSnapshot.2.1, voteSnapshot.2.2.1
              ] using voteSnapshot.2.2.2.2
            · exact earlierSafe
      · exact False.elim
          (badImpossible
            (state.nodes candidate).currentTerm le_rfl bad)
    · have voterPrefix :
          (state.nodes source).log.take index <+:
            (state.nodes voter).log := by
        rcases
            currentHistory source index sourceRole currentEntry
              currentSignature
              voter effective with
          retained | bad
        · exact retained
        · exact False.elim
            (badImpossible
              (state.nodes candidate).currentTerm
                le_rfl
                (by
                  have voterTerm :
                      (state.nodes voter).currentTerm =
                        (state.nodes candidate).currentTerm := by
                    simpa [
                      currentlyEligibleElectionVoter,
                      makeRequestVoteRequest
                    ] using eligible.1.symm
                  simpa [voterTerm] using bad))
      have candidateEntrySafe :
          forall entry,
            entry ∈ (state.nodes candidate).log ->
              entry.term < (state.nodes candidate).currentTerm \/
                (entry.term = (state.nodes candidate).currentTerm /\
                  forall record,
                    elections (state.nodes candidate).currentTerm =
                        some record ->
                      (state.nodes source).log.take index <+:
                        record.promotionLog) := by
        intro entry member
        have bounded := entriesBounded candidate entry member
        by_cases same :
            entry.term = (state.nodes candidate).currentTerm
        · exact Or.inr
            ⟨same, fun record recorded =>
              potentialPrefixInElectionRecords
                termsPositive voteFacts ownership electionFacts
                  electedHistory activationQuorums
                  sourceRole currentEntry currentSignature potential
                  (state.nodes candidate).currentTerm record
                  recorded newer⟩
        · exact Or.inl (by omega)
      apply
        candidateSnapshotContainsProspectivePrefix
          (termsPositive source (by rw [sourceRole]; decide))
          ownership electionFacts
            currentEntry currentSignature voterPrefix
            (prefixRefl (state.nodes candidate).log)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement
                candidate entryIndex entry found)
            (fun entryIndex entry found =>
              ownership.logEntryAgreement
                voter entryIndex entry found)
            ((canonicalHistoriesMonoLog ownership) voter)
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
      · exact earlierSafe

/--
Activation history discharges the cross-configuration case before the ordinary
same-configuration election argument is applied.
-/
lemma potentialPrefixInHigherCandidate
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
    {source candidate : Node}
    {index : Nat}
    (sourceRole : (state.nodes source).role = .leader)
    (currentEntry
      : termAt (state.nodes source).log index = (state.nodes source).currentTerm)
    (currentSignature : isSignatureAt (state.nodes source).log index = true)
    (potential : hasPotentialMajorityAt state appendHistory responseHistory source index)
    (candidateRole : (state.nodes candidate).role = .candidate)
    (candidateMajority : hasPotentialElectionMajority state candidate)
    (newer : (state.nodes source).currentTerm < (state.nodes candidate).currentTerm)
    : (state.nodes source).log.take index <+: (state.nodes candidate).log := by
  rcases
      activationQuorums.candidateBridge
        source index sourceRole currentEntry currentSignature potential
        candidate candidateRole candidateMajority newer with
    direct | shared
  · exact direct
  · rcases shared with
      ⟨configuration, sourceActive, governs, candidateActive⟩
    exact
      potentialPrefixInHigherCandidateOfSharedConfiguration
        termsPositive committedSignature candidatesAbove entriesBounded
        voteFacts snapshots canonicalSnapshots ownership electionFacts
        configurationFacts currentHistory voteHistory electedHistory
        activationQuorums sourceRole currentEntry currentSignature potential
        candidateRole candidateMajority
        sourceActive governs candidateActive
        newer

/--
Prospective per-ACK evidence covers a candidate with materialised election
support.
-/
lemma prospectiveKnownEffectiveWinnerCompletenessOfSharedAuthority
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (_entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (_candidatesAbove : CandidatesAboveBootstrap state)
    (_voteFacts : VoteHistoryFacts state votes)
    (_snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (_ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (_electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
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
    (candidateRole : (state.nodes candidate).role = .candidate)
    (candidateMajority : hasPotentialElectionMajority state candidate)
    (authorityActive : evidence.authority ∈ activeConfigurations (state.nodes candidate))
    (newer : evidence.commitTerm < (state.nodes candidate).currentTerm)
    : supportedPrefix <+: (state.nodes candidate).log := by
  have candidateEntriesBefore :
      forall entry,
        entry ∈ (state.nodes candidate).log ->
          entry.term < (state.nodes candidate).currentTerm := by
    exact configurationFacts.candidateEntriesBeforeTerm candidate candidateRole
  have valid := knownCommitEvidenceValid evidenceFacts known
  have candidateAuthorityMajority :=
    potentialElectionMajorityAtConfiguration
      candidateMajority authorityActive
  rcases
      configurationMajoritiesIntersect
        valid.2.2.2.2.2.1 candidateAuthorityMajority with
    ⟨member, _authorityMember, ackMember, candidateMember⟩
  have parts :
      member ∈ evidence.ackQuorum /\
        member ∈ potentialElectionVoters state candidate :=
    ⟨ackMember, candidateMember⟩
  have relaxed :
      member ∈ relaxedElectionVoters state candidate := by
    simp only [
      potentialElectionVoters, Finset.mem_filter] at parts
    simp only [
      relaxedElectionVoters, Finset.mem_filter]
    rcases parts.2 with ⟨joined, effective | eligible⟩
    · exact ⟨joined, Or.inl effective⟩
    · refine ⟨joined, Or.inr ?_⟩
      unfold currentlyEligibleElectionVoter at eligible
      exact ⟨
        by simpa [makeRequestVoteRequest] using eligible.1.symm.le,
        by
          simpa [makeRequestVoteRequest, voteLogUpToDate] using eligible.2.1
      ⟩
  exact (validEvidenceSupportedPrefixFrontier valid).trans
    (prospectiveFacts.relaxedSupporterCarriesFrontier
      evidence supportedPrefix known candidate member
      candidateRole newer candidateEntriesBefore
      parts.1 relaxed)

/-- Activation bridges the evidence prefix or supplies a shared authority. -/
lemma prospectiveKnownEffectiveWinnerCompleteness
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
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (voteFacts : VoteHistoryFacts state votes)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts
      : ProspectiveCommitEvidenceFacts
          state appendHistory nodeEvidence requestEvidence elections)
    (activationEvidence
      : ActivationEvidenceFacts
          state appendHistory responseHistory nodeEvidence requestEvidence
          elections activations)
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (known
      : KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix)
    {candidate : Node}
    (candidateRole : (state.nodes candidate).role = .candidate)
    (candidateMajority : hasPotentialElectionMajority state candidate)
    (newer : evidence.commitTerm < (state.nodes candidate).currentTerm)
    : supportedPrefix <+: (state.nodes candidate).log := by
  rcases
      activationEvidence.candidateBridge
        evidence supportedPrefix known candidate candidateRole
          candidateMajority newer with
    direct | authorityActive
  · exact (validEvidenceSupportedPrefixFrontier
            (knownCommitEvidenceValid evidenceFacts known)).trans
      direct
  · exact
      prospectiveKnownEffectiveWinnerCompletenessOfSharedAuthority
        entriesBounded candidatesAbove voteFacts snapshots ownership
          electionFacts configurationFacts evidenceFacts prospectiveFacts
          known candidateRole candidateMajority authorityActive newer

/--
Known commit evidence makes every lower-term committed prefix part of an
active leader's log.
-/
lemma knownCommitEvidenceLeaderCompleteness
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
    : LeaderCompleteness state := by
  intro leader leaderRole node _different newer
  by_cases zero : (state.nodes node).commitIndex = 0
  · simp [NodeState.committedLog, zero]
  · have positive : 0 < (state.nodes node).commitIndex :=
      Nat.pos_of_ne_zero zero
    rcases evidenceFacts.nodePositive node positive with
      ⟨evidence, stored, valid, _supportedLength, termBound⟩
    have known :
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
            evidence (state.nodes node).committedLog :=
      Or.inl ⟨node, positive, stored, rfl⟩
    rcases
        configurationMajorityNonempty valid.2.2.2.2.2.1 with
      ⟨member, _authorityMember, ackMember⟩
    exact (validEvidenceSupportedPrefixFrontier valid).trans
      (knownCommitEvidenceActiveLeaderContainsFrontier
        ownership electionFacts evidenceFacts prospectiveFacts
        known leaderRole (by omega) ackMember)

/--
Prospective commit closure makes every lower-term committed prefix part of a
candidate's log as soon as its effective election quorum is complete.
-/
lemma prospectiveCommitEvidenceWinningCandidateCompleteness
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
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (candidatesAbove : CandidatesAboveBootstrap state)
    (voteFacts : VoteHistoryFacts state votes)
    (snapshots : GrantedVoteSnapshots state votes voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts state elections activations)
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (prospectiveFacts
      : ProspectiveCommitEvidenceFacts
          state appendHistory nodeEvidence requestEvidence elections)
    (activationEvidence
      : ActivationEvidenceFacts
          state appendHistory responseHistory nodeEvidence requestEvidence
          elections activations)
    : WinningCandidateCompleteness state := by
  intro candidate candidateRole candidateMajority
      node _different newer
  by_cases zero : (state.nodes node).commitIndex = 0
  · simp [NodeState.committedLog, zero]
  · have positive : 0 < (state.nodes node).commitIndex :=
      Nat.pos_of_ne_zero zero
    rcases evidenceFacts.nodePositive node positive with
      ⟨evidence, stored, _valid, _supportedLength, termBound⟩
    have known :
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
            evidence (state.nodes node).committedLog :=
      Or.inl ⟨node, positive, stored, rfl⟩
    apply
      prospectiveKnownEffectiveWinnerCompleteness
        entriesBounded candidatesAbove voteFacts snapshots ownership
          electionFacts
          configurationFacts evidenceFacts prospectiveFacts
          activationEvidence known candidateRole
            (effectiveElectionMajorityImpliesPotential
              state candidate candidateMajority)
    omega

omit [DecidableEq TxId] in
/--
An active leader's canonical history and canonical entry agreement imply that
its log dominates every occurrence of an entry from its current term.
-/
lemma activeLeaderHistoryLeaderTermDominance
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    : LeaderTermDominance state := by
  intro leader leaderRole node index entry found sameTerm
  rcases ownership.logEntryAgreement node index entry found with
    ⟨canonicalFound, agreed⟩
  have leaderHistory :=
    ownership.activeLeaderHistory leader leaderRole
  constructor
  · have bound := entryAtSomeIndexBound canonicalFound
    rw [sameTerm, leaderHistory] at bound
    exact bound
  · calc
      (state.nodes node).log.take index =
          (canonicalHistory entry.term).take index :=
        agreed
      _ =
          (canonicalHistory
            (state.nodes leader).currentTerm).take index := by
        rw [sameTerm]
      _ = (state.nodes leader).log.take index := by
        rw [leaderHistory]

/-- The retained canonical witness derives state-local log matching. -/
lemma invariantFactsLogMatchingFromCanonicalHistories
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {voteRequestHistory : RequestVoteRequest Node -> List (Entry Node TxId)}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (facts
      : InvariantFacts
          state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory)
    : LogMatching state := by
  rcases facts.historicalSafety with
    ⟨owners, _canonicalHistory, _elections, _activations,
      _nodeEvidence, _requestEvidence, ownership, _⟩
  exact canonicalHistoriesLogMatching ownership

/-- The retained canonical histories derive state-local log monotonicity. -/
lemma invariantFactsMonoLogFromCanonicalHistories
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {voteRequestHistory : RequestVoteRequest Node -> List (Entry Node TxId)}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (facts
      : InvariantFacts
          state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory)
    : MonoLog state := by
  rcases facts.historicalSafety with
    ⟨_owners, _canonicalHistory, _elections, _activations,
      _nodeEvidence, _requestEvidence, ownership, _⟩
  exact canonicalHistoriesMonoLog ownership

/-- Persistent self-votes derive the post-bootstrap candidate-term bound. -/
lemma invariantFactsCandidatesAboveBootstrap
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {voteRequestHistory : RequestVoteRequest Node -> List (Entry Node TxId)}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (facts
      : InvariantFacts
          state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory)
    : CandidatesAboveBootstrap state :=
  candidatesSelfVoteAboveBootstrap
    facts.currentTermsPositive facts.candidatesSelfVote facts.voteHistory

/--
Live node commit evidence derives the signature-only committed frontier.
The supported-prefix equality transfers the evidence signature to the node log.
-/
lemma invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {voteRequestHistory : RequestVoteRequest Node -> List (Entry Node TxId)}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (facts
      : InvariantFacts
          state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory)
    : CommittedFrontierIsSignature state := by
  rcases facts.historicalSafety with
    ⟨_owners, _canonicalHistory, _elections, _activations,
      _nodeEvidence, _requestEvidence, _ownership, _electionFacts,
      _configurationFacts, _voteCanonicalFacts, _ackerCurrentFacts,
      _ackerVoteFacts, _activationVoteFacts, _ackerElectionFacts,
      _ackerActivationFacts,
      _electionQueuedFacts,
      _activationProgress, _activationQuorums, evidenceFacts, _prospectiveFacts,
      _activationEvidence, _activationCanonical, _activationElections,
      _configurationActivations⟩
  intro node positive
  rcases evidenceFacts.nodePositive node positive with
    ⟨evidence, _stored, valid, supportedLength, _termBound⟩
  rcases valid with
    ⟨_frontierBound, _frontierTerm, _supportedBound, supportedPrefix,
      _authority, _majority, _frontierSignature, supportedSignature⟩
  have evidenceSignature :
      isSignatureAt evidence.history evidence.supportedLength = true :=
    supportedSignature (by simpa [supportedLength] using positive)
  have committedSignature :
      isSignatureAt
          (state.nodes node).committedLog
          (state.nodes node).commitIndex =
        true := by
    rw [← supportedLength, ← supportedPrefix]
    exact isSignatureAt_take_of_le le_rfl evidenceSignature
  exact isSignatureAt_of_prefix
    (List.take_prefix (state.nodes node).commitIndex (state.nodes node).log)
    (by simpa [NodeState.committedLog] using committedSignature)

/-- The retained known commit witnesses derive leader completeness. -/
lemma invariantFactsLeaderCompletenessFromCommitEvidence
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {voteRequestHistory : RequestVoteRequest Node -> List (Entry Node TxId)}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (facts
      : InvariantFacts
          state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory)
    : LeaderCompleteness state := by
  rcases facts.historicalSafety with
    ⟨_owners, _canonicalHistory, _elections, _activations,
      _nodeEvidence, _requestEvidence, ownership, electionFacts,
      _configurationFacts, _voteCanonicalFacts, _ackerCurrentFacts,
      _ackerVoteFacts, _activationVoteFacts, _ackerElectionFacts,
      _ackerActivationFacts,
      _electionQueuedFacts,
      _activationProgress, _activationQuorums, evidenceFacts, prospectiveFacts,
      _activationEvidence, _activationCanonical, _activationElections,
      _configurationActivations⟩
  exact
    knownCommitEvidenceLeaderCompleteness
      ownership electionFacts evidenceFacts prospectiveFacts

/-- The retained prospective commit witnesses derive candidate completeness. -/
lemma invariantFactsWinningCandidateCompletenessFromCommitEvidence
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {voteRequestHistory : RequestVoteRequest Node -> List (Entry Node TxId)}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (facts
      : InvariantFacts
          state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory)
    : WinningCandidateCompleteness state := by
  rcases facts.historicalSafety with
    ⟨_owners, _canonicalHistory, _elections, activations,
      _nodeEvidence, _requestEvidence, ownership, electionFacts,
      configurationFacts, _voteCanonicalFacts, _ackerCurrentFacts,
      _ackerVoteFacts, _activationVoteFacts, _ackerElectionFacts,
      _ackerActivationFacts,
      _electionQueuedFacts,
      _activationProgress, _activationQuorums, evidenceFacts, prospectiveFacts,
      activationEvidence, _activationCanonical, _activationElections,
      _configurationActivations⟩
  exact
    prospectiveCommitEvidenceWinningCandidateCompleteness
      facts.entriesDoNotExceedCurrentTerm
      (invariantFactsCandidatesAboveBootstrap facts) facts.voteHistory
      facts.grantedVoteSnapshots ownership electionFacts
        configurationFacts evidenceFacts prospectiveFacts
        (activations := activations) activationEvidence

/-- The retained active canonical histories derive leader-term dominance. -/
lemma invariantFactsLeaderTermDominanceFromCanonicalHistories
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {voteRequestHistory : RequestVoteRequest Node -> List (Entry Node TxId)}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (facts
      : InvariantFacts
          state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory)
    : LeaderTermDominance state := by
  rcases facts.historicalSafety with
    ⟨_owners, _canonicalHistory, _elections, _activations,
      _nodeEvidence, _requestEvidence, ownership, _⟩
  exact activeLeaderHistoryLeaderTermDominance ownership

end CCFRaft.Proofs.Invariant
