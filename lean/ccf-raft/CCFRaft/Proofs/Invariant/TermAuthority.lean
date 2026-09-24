-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Facts
import CCFRaft.Proofs.Invariant.HandlerFacts
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
variable {joined : Finset Node}

/--
Transfer a shared-configuration authority conclusion across a term-only state
change. The `preGhostAuthority` premise isolates the history-only argument over
the preserved pre-state facts, while this theorem proves the UpdateTerm-specific
quorum intersection, reserve elimination, and voter-state transport.
-/
lemma updateTermPotentialPrefixOfRelaxedAuthority
    {before after : Model.State Node TxId}
    {appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendResponseKey Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory
      : VoteResponseKey Node -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    {source candidate : Node}
    {index : Nat}
    {configuration : Configuration Node}
    (sourceNodeEq : (nodeOf after) source = (nodeOf before) source)
    (candidateNodeEq : (nodeOf after) candidate = (nodeOf before) candidate)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf before) node).log)
    (termMonotone
      : forall node, ((nodeOf before) node).currentTerm <= ((nodeOf after) node).currentTerm)
    (effectiveAckersBack
      : effectiveAckers (joined := joined) after responseHistory source index
        ⊆ effectiveAckers (joined := joined) before responseHistory source index)
    (effectiveElectionVotersBack
      : effectiveElectionVoters (joined := joined) after candidate
        ⊆ effectiveElectionVoters (joined := joined) before candidate)
    (snapshots : GrantedVoteSnapshots (joined := joined) before votes voteCandidateHistory voteVoterHistory)
    (termsPositive : CurrentTermsPositive before)
    (committedSignature : CommittedFrontierIsSignature before)
    (entriesBounded : EntriesDoNotExceedCurrentTerm before)
    (voteFacts : VoteHistoryFacts before votes)
    (canonicalSnapshots
      : GrantedVoteCanonicalSnapshots (joined := joined)
          before canonicalHistory voteCandidateHistory voteVoterHistory)
    (ownership : TermOwnershipFacts before votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts before votes canonicalHistory owners elections)
    (configurationFacts : ElectionConfigurationFacts (joined := joined) before elections activations)
    (currentHistory : AckerCurrentHistory (joined := joined) before responseHistory elections)
    (voteHistory
      : AckerVoteHistory (joined := joined) before votes responseHistory voteVoterHistory elections)
    (electedHistory : AckerElectionHistory (joined := joined) before responseHistory elections)
    (activationQuorums
      : ActivationQuorumFacts (joined := joined) before appendHistory responseHistory elections activations)
    (sourceRole : ((nodeOf after) source).role = .leader)
    (currentEntry
      : termAt ((nodeOf after) source).log index = ((nodeOf after) source).currentTerm)
    (currentSignature : isSignatureAt ((nodeOf after) source).log index = true)
    (potential : hasPotentialMajorityAt (joined := joined) after appendHistory responseHistory source index)
    (candidateRole : ((nodeOf after) candidate).role = .candidate)
    (candidateMajority : hasPotentialElectionMajority (joined := joined) after candidate)
    (sourceConfigurationActive
      : configuration ∈ activeConfigurations ((nodeOf after) source))
    (configurationGoverns : configuration.index <= index)
    (candidateConfigurationActive
      : configuration ∈ activeConfigurations ((nodeOf after) candidate))
    (newer : ((nodeOf after) source).currentTerm < ((nodeOf after) candidate).currentTerm)
    (preGhostAuthority
      : CurrentTermsPositive before -> CommittedFrontierIsSignature before
        -> EntriesDoNotExceedCurrentTerm before -> VoteHistoryFacts before votes
        -> GrantedVoteSnapshots (joined := joined) before votes voteCandidateHistory voteVoterHistory
        -> GrantedVoteCanonicalSnapshots (joined := joined)
            before canonicalHistory voteCandidateHistory voteVoterHistory
        -> TermOwnershipFacts before votes appendHistory canonicalHistory owners
        -> ElectionHistoryFacts before votes canonicalHistory owners elections
        -> ElectionConfigurationFacts (joined := joined) before elections activations
        -> AckerCurrentHistory (joined := joined) before responseHistory elections
        -> AckerVoteHistory (joined := joined) before votes responseHistory voteVoterHistory elections
        -> AckerElectionHistory (joined := joined) before responseHistory elections
        -> ActivationQuorumFacts (joined := joined)
            before appendHistory responseHistory elections activations
        -> ((nodeOf before) source).role = .leader
        -> termAt ((nodeOf before) source).log index = ((nodeOf before) source).currentTerm
        -> isSignatureAt ((nodeOf before) source).log index = true
        -> hasPotentialMajorityAt (joined := joined) after appendHistory responseHistory source index
        -> ((nodeOf before) candidate).role = .candidate
        -> ((nodeOf before) source).currentTerm < ((nodeOf before) candidate).currentTerm
        -> forall voter,
            voter ∈ effectiveAckers (joined := joined) before responseHistory source index
            -> voter ∈ relaxedElectionVoters (joined := joined) before candidate
            -> ((nodeOf before) source).log.take index <+: ((nodeOf before) candidate).log)
    : ((nodeOf after) source).log.take index <+: ((nodeOf after) candidate).log := by
  have sourceRoleBefore :
      ((nodeOf before) source).role = .leader := by
    simpa [sourceNodeEq] using sourceRole
  have currentEntryBefore :
      termAt ((nodeOf before) source).log index =
        ((nodeOf before) source).currentTerm := by
    simpa [sourceNodeEq] using currentEntry
  have currentSignatureBefore :
      isSignatureAt ((nodeOf before) source).log index = true := by
    simpa [sourceNodeEq] using currentSignature
  have candidateRoleBefore :
      ((nodeOf before) candidate).role = .candidate := by
    simpa [candidateNodeEq] using candidateRole
  have newerBefore :
      ((nodeOf before) source).currentTerm <
        ((nodeOf before) candidate).currentTerm := by
    simpa [sourceNodeEq, candidateNodeEq] using newer
  have candidateActiveBefore :
      ((nodeOf before) candidate).role = .candidate \/
        ((nodeOf before) candidate).role = .leader :=
    Or.inl candidateRoleBefore
  have prospectiveVoterTermBound :
      forall voter,
        voter ∈ potentialElectionVoters (joined := joined) after candidate ->
          ((nodeOf after) candidate).currentTerm <=
            ((nodeOf after) voter).currentTerm := by
    intro voter member
    simp only [
      potentialElectionVoters, Finset.mem_filter
    ] at member
    rcases member with ⟨_, effective | eligible⟩
    · have effectiveBefore :=
        effectiveElectionVotersBack effective
      rcases
          snapshots candidate voter candidateActiveBefore effectiveBefore with
        ⟨_, self | recorded⟩
      · subst voter
        exact le_rfl
      · calc
          ((nodeOf after) candidate).currentTerm =
              ((nodeOf before) candidate).currentTerm := by
                rw [candidateNodeEq]
          _ <= ((nodeOf before) voter).currentTerm := recorded.2.2.2.1
          _ <= ((nodeOf after) voter).currentTerm := termMonotone voter
    · simpa [
        currentlyEligibleElectionVoter,
        voteRequestKey, Model.Local.makeRequestVoteRequest
      ] using eligible.1.le
  have replicationMajority :
      hasConfigurationMajority
        (potentialAckers (joined := joined)
          after appendHistory responseHistory source index)
        configuration := by
    rw [hasPotentialMajorityAt, List.all_eq_true] at potential
    exact (of_decide_eq_true (potential configuration sourceConfigurationActive))
      configurationGoverns
  have electionMajority :
      hasConfigurationMajority
        (potentialElectionVoters (joined := joined) after candidate)
        configuration := by
    rw [hasPotentialElectionMajority, List.all_eq_true] at candidateMajority
    exact
      of_decide_eq_true
        (candidateMajority configuration candidateConfigurationActive)
  rcases
      configurationMajoritiesIntersect
        replicationMajority electionMajority with
    ⟨voter, _, replicationMember, electionMember⟩
  have effectiveAfter :
      voter ∈ effectiveAckers (joined := joined) after responseHistory source index := by
    simp only [
      potentialAckers, Finset.mem_filter
    ] at replicationMember
    rcases replicationMember with ⟨_, effective | reserve⟩
    · exact effective
    · have reserveTerm :
          ((nodeOf after) voter).currentTerm <=
            ((nodeOf after) source).currentTerm := by
        rcases reserve with
          ⟨request, _, _, requestDestination, requestTerm,
            producible, _⟩
        rcases producible with direct | prepared
        · rcases direct with
            ⟨nextNode, response, handled, success, _⟩
          have localPost :=
            CCFRaft.Proofs.Invariant.handleAppendEntriesRequest_successfulCurrentTerm handled success
          have voterTerm :
              request.2.2.term = ((nodeOf after) voter).currentTerm := by
            simpa [requestDestination]
              using localPost
          exact (voterTerm.symm.trans requestTerm).le
        · exact (by simpa [requestDestination, requestTerm] using prepared.1.le)
      have voterTermBound :=
        prospectiveVoterTermBound voter electionMember
      omega
  have relaxedBefore :
      voter ∈ relaxedElectionVoters (joined := joined) before candidate := by
    simp only [
      potentialElectionVoters, Finset.mem_filter
    ] at electionMember
    simp only [
      relaxedElectionVoters, Finset.mem_filter
    ]
    rcases electionMember with ⟨joinedAfter, effective | eligible⟩
    · refine ⟨
        by simpa only [] using joinedAfter,
        Or.inl (effectiveElectionVotersBack effective)
      ⟩
    · refine ⟨by simpa only [] using joinedAfter, Or.inr ?_⟩
      refine ⟨?_, ?_⟩
      · calc
          ((nodeOf before) voter).currentTerm <= ((nodeOf after) voter).currentTerm :=
            termMonotone voter
          _ = ((nodeOf after) candidate).currentTerm := by
            simpa [currentlyEligibleElectionVoter, voteRequestKey, Model.Local.makeRequestVoteRequest]
              using eligible.1.symm
          _ = ((nodeOf before) candidate).currentTerm := by
            rw [candidateNodeEq]
      · simpa [
          currentlyEligibleElectionVoter,
          voteRequestKey, Model.Local.makeRequestVoteRequest,
          candidateNodeEq, logEq,
          Model.Local.voteLogUpToDate
        ] using eligible.2.1
  have prefixBefore :=
    preGhostAuthority
      termsPositive committedSignature entriesBounded voteFacts snapshots
      canonicalSnapshots ownership electionFacts configurationFacts
      currentHistory voteHistory electedHistory activationQuorums
      sourceRoleBefore currentEntryBefore currentSignatureBefore
      potential candidateRoleBefore newerBefore voter
      (effectiveAckersBack effectiveAfter) relaxedBefore
  simpa [sourceNodeEq, candidateNodeEq] using prefixBefore

end CCFRaft.Proofs.Invariant
