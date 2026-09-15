-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant
import CCFRaft.Proofs.HandlerProofs

import CCFRaft.Proofs.Support

open CCFRaft.Protocol CCFRaft.Protocol.Model CCFRaft.Protocol.Safety CCFRaft.Proofs.Support CCFRaft.Proofs.ModelProofs CCFRaft.Proofs.Invariant CCFRaft.Proofs.HandlerProofs

set_option autoImplicit false

/-!
# UpdateTerm configuration authority

`UpdateTerm` can clear one vote and thereby create a new potential election
supporter. This module isolates the mixed-state step: a post-state potential
replication/election intersection contains a materialised ACKer, and the
post-state election supporter maps to the pre-state relaxed supporter used by
the historical authority proof.
-/

namespace CCFRaft.Proofs.UpdateTermAuthority

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]
variable [Bootstrap Node]

/--
Transfer a shared-configuration authority conclusion across a term-only state
change. The `preGhostAuthority` premise isolates the history-only argument over
the preserved pre-state facts, while this theorem proves the UpdateTerm-specific
quorum intersection, reserve elimination, and voter-state transport.
-/
lemma updateTermPotentialPrefixOfRelaxedAuthority
    {before after : State Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {votes : VoteHistory Node}
    {voteCandidateHistory voteVoterHistory :
      RequestVoteResponse Node -> List (Entry Node TxId)}
    {canonicalHistory : Nat -> List (Entry Node TxId)}
    {owners : TermOwners Node}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    {source candidate : Node}
    {index : Nat}
    {configuration : Configuration Node}
    (sourceNodeEq : after.nodes source = before.nodes source)
    (candidateNodeEq : after.nodes candidate = before.nodes candidate)
    (logEq :
      forall node,
        (after.nodes node).log = (before.nodes node).log)
    (termMonotone :
      forall node,
        (before.nodes node).currentTerm <=
          (after.nodes node).currentTerm)
    (hasJoinedEq : after.hasJoined = before.hasJoined)
    (effectiveAckersBack :
      effectiveAckers after responseHistory source index ⊆
        effectiveAckers before responseHistory source index)
    (effectiveElectionVotersBack :
      effectiveElectionVoters after candidate ⊆
        effectiveElectionVoters before candidate)
    (snapshots :
      GrantedVoteSnapshots
        before votes voteCandidateHistory voteVoterHistory)
    (termsPositive : CurrentTermsPositive before)
    (committedSignature : CommittedFrontierIsSignature before)
    (entriesBounded : EntriesDoNotExceedCurrentTerm before)
    (voteFacts : VoteHistoryFacts before votes)
    (canonicalSnapshots :
      GrantedVoteCanonicalSnapshots
        before canonicalHistory voteCandidateHistory voteVoterHistory)
    (ownership :
      TermOwnershipFacts
        before votes appendHistory canonicalHistory owners)
    (electionFacts :
      ElectionHistoryFacts
        before votes canonicalHistory owners elections)
    (configurationFacts :
      ElectionConfigurationFacts before elections activations)
    (currentHistory :
      AckerCurrentHistory before responseHistory elections)
    (voteHistory :
      AckerVoteHistory
        before votes responseHistory voteVoterHistory elections)
    (electedHistory :
      AckerElectionHistory before responseHistory elections)
    (activationQuorums :
      ActivationQuorumFacts
        before appendHistory responseHistory elections activations)
    (sourceRole : (after.nodes source).role = .leader)
    (currentEntry :
      termAt (after.nodes source).log index =
        (after.nodes source).currentTerm)
    (currentSignature :
      isSignatureAt (after.nodes source).log index = true)
    (potential :
      hasPotentialMajorityAt
        after appendHistory responseHistory source index)
    (candidateRole : (after.nodes candidate).role = .candidate)
    (candidateMajority :
      hasPotentialElectionMajority after candidate)
    (sourceConfigurationActive :
      configuration ∈ activeConfigurations (after.nodes source))
    (configurationGoverns : configuration.index <= index)
    (candidateConfigurationActive :
      configuration ∈ activeConfigurations (after.nodes candidate))
    (newer :
      (after.nodes source).currentTerm <
        (after.nodes candidate).currentTerm)
    (preGhostAuthority :
      CurrentTermsPositive before ->
      CommittedFrontierIsSignature before ->
      EntriesDoNotExceedCurrentTerm before ->
      VoteHistoryFacts before votes ->
      GrantedVoteSnapshots
        before votes voteCandidateHistory voteVoterHistory ->
      GrantedVoteCanonicalSnapshots
        before canonicalHistory voteCandidateHistory voteVoterHistory ->
      TermOwnershipFacts
        before votes appendHistory canonicalHistory owners ->
      ElectionHistoryFacts
        before votes canonicalHistory owners elections ->
      ElectionConfigurationFacts before elections activations ->
      AckerCurrentHistory before responseHistory elections ->
      AckerVoteHistory
        before votes responseHistory voteVoterHistory elections ->
      AckerElectionHistory before responseHistory elections ->
      ActivationQuorumFacts
        before appendHistory responseHistory elections activations ->
      (before.nodes source).role = .leader ->
      termAt (before.nodes source).log index =
        (before.nodes source).currentTerm ->
      isSignatureAt (before.nodes source).log index = true ->
      hasPotentialMajorityAt
        after appendHistory responseHistory source index ->
      (before.nodes candidate).role = .candidate ->
      (before.nodes source).currentTerm <
        (before.nodes candidate).currentTerm ->
      forall voter,
        voter ∈ effectiveAckers before responseHistory source index ->
        voter ∈ relaxedElectionVoters before candidate ->
          (before.nodes source).log.take index <+:
            (before.nodes candidate).log) :
    (after.nodes source).log.take index <+:
      (after.nodes candidate).log := by
  have sourceRoleBefore :
      (before.nodes source).role = .leader := by
    simpa [sourceNodeEq] using sourceRole
  have currentEntryBefore :
      termAt (before.nodes source).log index =
        (before.nodes source).currentTerm := by
    simpa [sourceNodeEq] using currentEntry
  have currentSignatureBefore :
      isSignatureAt (before.nodes source).log index = true := by
    simpa [sourceNodeEq] using currentSignature
  have candidateRoleBefore :
      (before.nodes candidate).role = .candidate := by
    simpa [candidateNodeEq] using candidateRole
  have newerBefore :
      (before.nodes source).currentTerm <
        (before.nodes candidate).currentTerm := by
    simpa [sourceNodeEq, candidateNodeEq] using newer
  have candidateActiveBefore :
      (before.nodes candidate).role = .candidate \/
        (before.nodes candidate).role = .leader :=
    Or.inl candidateRoleBefore
  have prospectiveVoterTermBound :
      forall voter,
        voter ∈ potentialElectionVoters after candidate ->
          (after.nodes candidate).currentTerm <=
            (after.nodes voter).currentTerm := by
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
          (after.nodes candidate).currentTerm =
              (before.nodes candidate).currentTerm := by
                rw [candidateNodeEq]
          _ <= (before.nodes voter).currentTerm := recorded.2.2.2.1
          _ <= (after.nodes voter).currentTerm := termMonotone voter
    · simpa [
        currentlyEligibleElectionVoter,
        makeRequestVoteRequest
      ] using eligible.1.le
  have replicationMajority :
      hasConfigurationMajority
        (potentialAckers
          after appendHistory responseHistory source index)
        configuration := by
    rw [hasPotentialMajorityAt, List.all_eq_true] at potential
    exact
      (of_decide_eq_true
        (potential configuration sourceConfigurationActive))
        configurationGoverns
  have electionMajority :
      hasConfigurationMajority
        (potentialElectionVoters after candidate)
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
      voter ∈ effectiveAckers after responseHistory source index := by
    simp only [
      potentialAckers, Finset.mem_filter
    ] at replicationMember
    rcases replicationMember with ⟨_, effective | reserve⟩
    · exact effective
    · have reserveTerm :
          (after.nodes voter).currentTerm <=
            (after.nodes source).currentTerm := by
        rcases reserve with
          ⟨request, _, _, requestDestination, requestTerm,
            producible, _⟩
        rcases producible with direct | prepared
        · rcases direct with
            ⟨nextNode, response, handled, success, _⟩
          have localPost :=
            CCFRaft.Proofs.HandlerProofs.handleAppendEntriesRequestLocalPost handled
          have voterTerm :
              request.term = (after.nodes voter).currentTerm := by
            simpa [requestDestination, protocolNodeState] using
              localPost.successfulCurrentTerm success
          exact (voterTerm.symm.trans requestTerm).le
        · exact
            (by simpa [requestDestination, requestTerm] using prepared.1.le)
      have voterTermBound :=
        prospectiveVoterTermBound voter electionMember
      omega
  have relaxedBefore :
      voter ∈ relaxedElectionVoters before candidate := by
    simp only [
      potentialElectionVoters, Finset.mem_filter
    ] at electionMember
    simp only [
      relaxedElectionVoters, Finset.mem_filter
    ]
    rcases electionMember with ⟨joinedAfter, effective | eligible⟩
    · refine
        ⟨by simpa [hasJoinedEq] using joinedAfter,
          Or.inl (effectiveElectionVotersBack effective)⟩
    · refine
        ⟨by simpa [hasJoinedEq] using joinedAfter, Or.inr ?_⟩
      refine ⟨?_, ?_⟩
      · calc
          (before.nodes voter).currentTerm <=
              (after.nodes voter).currentTerm := termMonotone voter
          _ = (after.nodes candidate).currentTerm := by
            simpa [
              currentlyEligibleElectionVoter,
              makeRequestVoteRequest
            ] using eligible.1.symm
          _ = (before.nodes candidate).currentTerm := by
            rw [candidateNodeEq]
      · simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          candidateNodeEq, logEq,
          voteLogUpToDate
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

end CCFRaft.Proofs.UpdateTermAuthority
