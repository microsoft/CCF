-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.AppendSend
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
The three configuration-qualified obligations introduced by one fresh timeout
candidate. This is a proof-layer wrapper only; it is not stored in the
inductive invariant.
-/
structure TimeoutCandidatePackage
    (state after : View Node TxId)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    (candidate : Node)
    (targetTerm : Nat)
    : Prop where
  potentialShared
    : hasPotentialElectionMajority after candidate
      -> forall record,
          elections targetTerm = some record
          -> Exists
              fun configuration =>
                configuration ∈ record.ballotActive
                /\ configuration ∈ activeConfigurations (after.nodes candidate)
  candidateBridge
    : hasPotentialElectionMajority after candidate
      -> forall source index,
          (after.nodes source).role = .leader
          -> termAt (after.nodes source).log index = (after.nodes source).currentTerm
          -> isSignatureAt (after.nodes source).log index = true
          -> hasPotentialMajorityAt after appendHistory responseHistory source index
          -> (after.nodes source).currentTerm < targetTerm
          -> (after.nodes source).log.take index <+: (after.nodes candidate).log
  evidenceBridge
    : hasPotentialElectionMajority after candidate
      -> forall evidence supportedPrefix,
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix
          -> evidence.commitTerm < targetTerm
          -> supportedPrefix <+: (after.nodes candidate).log

/--
After a timeout, every potential voter for the fresh self-ballot was already a
supporter for that exact future term in the pre-state.
-/
lemma timeoutPotentialElectionVotersSubsetFuture
    (state : View Node TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    : potentialElectionVoters (timeoutEffect state node) node
      ⊆ futureElectionVoters state node ((state.nodes node).currentTerm + 1) := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  intro voter member
  simp only [
    potentialElectionVoters, Finset.mem_filter] at member
  simp only [
    futureElectionVoters, Finset.mem_filter]
  rcases member with ⟨joined, effective | eligible⟩
  · refine ⟨by simpa [view_effects] using joined, ?_⟩
    simp only [
      effectiveElectionVoters, Finset.mem_filter] at effective
    rcases effective with ⟨_joined, processed | queued⟩
    · have voterEq : voter = node := by simpa [view_effects] using processed
      exact Or.inl voterEq
    · rcases queued with
        ⟨response, queued, granted, responseTerm,
          responseSource, responseDestination⟩
      have oldQueued :
          Message.requestVoteResponse response ∈
            state.network node := by
        simpa [view_effects] using queued
      have oldBound :=
        (facts.networkHistory.voteResponse
          node response oldQueued granted).1
      rw [responseDestination] at oldBound
      simp [view_effects] at responseTerm
      omega
  · refine ⟨by simpa [view_effects] using joined, ?_⟩
    by_cases voterEq : voter = node
    · exact Or.inl voterEq
    · right
      simp only [currentlyEligibleElectionVoter] at eligible
      refine ⟨?_, ?_⟩
      · have sameTerm := eligible.1
        simp [
          view_effects, updateNode, voterEq,
          makeRequestVoteRequest
        ] at sameTerm
        omega
      · simpa [
          view_effects, updateNode,
          Function.update, voterEq,
          makeRequestVoteRequest,
          voteLogUpToDate, lastCommittableTerm, lastCommittableIndex
        ] using eligible.2.1

/-- Entering a successor election preserves the arbitrary-term invariant. -/
lemma candidateTransitionPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : state.allocated node
        /\ ((state.nodes node).role = .follower
            \/ (state.nodes node).role = .preVoteCandidate
            \/ (state.nodes node).role = .candidate))
    : SystemInductiveInvariant (timeoutEffect state node) := by
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
  let newTerm := (state.nodes node).currentTerm + 1
  let newVotes : VoteHistory (Node : Type) :=
    Function.update votes node
      (Function.update (votes node) newTerm (some node))
  have activationVoteHistoryAfter :
      ActivationVoteHistory
        newVotes voteVoterHistory elections activations := by
    apply
      activationVoteHistoryFrame
        votes newVotes voteVoterHistory voteVoterHistory
          elections activations activationVoteHistory
    · intro _ _ voter voteTerm candidate _ _ voted different _
      by_cases voterEq : voter = node
      · subst voter
        by_cases termEq : voteTerm = newTerm
        · subst voteTerm
          have selfVote : node = candidate := by
            simpa [newVotes, Function.update] using voted
          exact False.elim (different selfVote)
        · simpa [newVotes, Function.update, termEq] using voted
      · simpa [newVotes, Function.update, voterEq] using voted
    · intro _ _ _ _ retained
      exact retained
  have oldNotLeader :
      Not ((state.nodes node).role = .leader) := by
    rcases enabled.2 with follower | preVoteCandidate | candidate
    · exact fun leader => Role.noConfusion (follower.symm.trans leader)
    · exact
        fun leader =>
          Role.noConfusion (preVoteCandidate.symm.trans leader)
    · exact fun leader => Role.noConfusion (candidate.symm.trans leader)
  have roleNode :
      ((timeoutEffect state node).nodes node).role = .candidate := by
    simp [view_effects]
  have roleOther :
      forall candidate,
        Not (candidate = node) ->
        ((timeoutEffect state node).nodes candidate).role =
          (state.nodes candidate).role := by
    intro candidate different
    simp [
      view_effects, updateNode, different
    ]
  have termNode :
      ((timeoutEffect state node).nodes node).currentTerm = newTerm := by
    simp [view_effects, newTerm]
  have termOther :
      forall candidate,
        Not (candidate = node) ->
        ((timeoutEffect state node).nodes candidate).currentTerm =
          (state.nodes candidate).currentTerm := by
    intro candidate different
    simp [
      view_effects, updateNode, different
    ]
  have logEq :
      forall candidate,
        ((timeoutEffect state node).nodes candidate).log =
          (state.nodes candidate).log := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        view_effects, updateNode, same
      ]
  have commitEq :
      forall candidate,
        ((timeoutEffect state node).nodes candidate).commitIndex =
          (state.nodes candidate).commitIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        view_effects, updateNode, same
      ]
  have lastIndexEq :
      forall candidate,
        lastCommittableIndex
            ((timeoutEffect state node).nodes candidate) =
          lastCommittableIndex (state.nodes candidate) := by
    intro candidate
    exact lastCommittableIndexFrame (logEq candidate) (commitEq candidate)
  have lastTermEq :
      forall candidate,
        lastCommittableTerm
            ((timeoutEffect state node).nodes candidate) =
          lastCommittableTerm (state.nodes candidate) := by
    intro candidate
    exact lastCommittableTermFrame (logEq candidate) (commitEq candidate)
  have committedEq :
      forall candidate,
        ((timeoutEffect state node).nodes candidate).committedLog =
          (state.nodes candidate).committedLog := by
    intro candidate
    simp [NodeState.committedLog, commitEq, logEq]
  have activeConfigurationsEq :
      forall candidate,
        activeConfigurations
            ((timeoutEffect state node).nodes candidate) =
          activeConfigurations (state.nodes candidate) := by
    intro candidate
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have sentEq :
      forall candidate,
        ((timeoutEffect state node).nodes candidate).sentIndex =
          (state.nodes candidate).sentIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        view_effects, updateNode, same
      ]
  have matchEq :
      forall candidate,
        ((timeoutEffect state node).nodes candidate).matchIndex =
          (state.nodes candidate).matchIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        view_effects, updateNode, same
      ]
  have votedNode :
      ((timeoutEffect state node).nodes node).votedFor = some node := by
    simp [view_effects]
  have votesNode :
      ((timeoutEffect state node).nodes node).votesGranted = {node} := by
    simp [view_effects]
  have votedOther :
      forall candidate,
        Not (candidate = node) ->
        ((timeoutEffect state node).nodes candidate).votedFor =
          (state.nodes candidate).votedFor := by
    intro candidate different
    simp [
      view_effects, updateNode, different
    ]
  have votesOther :
      forall candidate,
        Not (candidate = node) ->
        ((timeoutEffect state node).nodes candidate).votesGranted =
          (state.nodes candidate).votesGranted := by
    intro candidate different
    simp [
      view_effects, updateNode, different
    ]
  have effectiveAckersEq :
      forall leader,
        Not (leader = node) ->
          forall index,
            effectiveAckers
                (timeoutEffect state node)
                responseHistory leader index =
              effectiveAckers state responseHistory leader index := by
    intro leader leaderNe index
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
        exact ⟨
          response,
          by simpa [view_effects] using member,
          success,
          by simpa [termOther leader leaderNe] using term,
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
      · refine ⟨
          by simpa [view_effects] using joined,
          Or.inr (Or.inr ?_)
        ⟩
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact ⟨
          response,
          by simpa [view_effects] using member,
          success,
          by simpa [termOther leader leaderNe] using term,
          sourceEq,
          destinationEq,
          lastIndex,
          by simpa [logEq] using covered
        ⟩
  have effectiveMajorityEq :
      forall leader,
        Not (leader = node) ->
          forall index,
            hasEffectiveMajorityAt
                (timeoutEffect state node)
                responseHistory leader index ↔
              hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader leaderNe index
    simp only [
      hasEffectiveMajorityAt, activeConfigurationsEq,
      effectiveAckersEq leader leaderNe index
    ]
  have effectiveElectionVotersNode :
      effectiveElectionVoters
          (timeoutEffect state node) node ⊆
        {node} := by
    intro voter member
    simp only [
      effectiveElectionVoters, Finset.mem_filter, Finset.mem_singleton
    ] at member ⊢
    rcases member with ⟨_joined, processed | queued⟩
    · simpa [votesNode] using processed
    · rcases queued with
        ⟨response, member, granted, responseTerm,
          responseSource, responseDestination⟩
      have oldMember :
          Message.requestVoteResponse response ∈
            state.network node := by
        simpa [view_effects] using member
      have oldBound :=
        (facts.networkHistory.voteResponse
          node response oldMember granted).1
      rw [responseDestination] at oldBound
      rw [termNode] at responseTerm
      simp [newTerm] at responseTerm
      omega
  have effectiveElectionVotersOtherEq :
      forall candidate,
        Not (candidate = node) ->
          effectiveElectionVoters
              (timeoutEffect state node) candidate =
            effectiveElectionVoters state candidate := by
    intro candidate candidateNe
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [view_effects] using joined,
          Or.inl (by simpa [votesOther candidate candidateNe] using processed)
        ⟩
      · refine ⟨
          by simpa [view_effects] using joined,
          Or.inr ?_
        ⟩
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact ⟨
          response,
          by simpa [view_effects] using member,
          granted,
          by simpa [termOther candidate candidateNe] using responseTerm,
          responseSource,
          responseDestination
        ⟩
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [view_effects] using joined,
          Or.inl (by simpa [votesOther candidate candidateNe] using processed)
        ⟩
      · refine ⟨
          by simpa [view_effects] using joined,
          Or.inr ?_
        ⟩
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact ⟨
          response,
          by simpa [view_effects] using member,
          granted,
          by simpa [termOther candidate candidateNe] using responseTerm,
          responseSource,
          responseDestination
        ⟩
  have effectiveElectionMajorityOtherEq :
      forall candidate,
        Not (candidate = node) ->
        (hasEffectiveElectionMajority
            (timeoutEffect state node) candidate ↔
          hasEffectiveElectionMajority state candidate) := by
    intro candidate candidateNe
    simp only [
      hasEffectiveElectionMajority, activeConfigurationsEq,
      effectiveElectionVotersOtherEq candidate candidateNe
    ]
  have potentialElectionVotersOtherSubset :
      forall candidate,
        Not (candidate = node) ->
          potentialElectionVoters
              (timeoutEffect state node) candidate ⊆
            potentialElectionVoters state candidate := by
    intro candidate candidateNe voter member
    simp only [
      potentialElectionVoters, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | eligible⟩
    · exact ⟨by simpa [view_effects] using joined, Or.inl
        (by
          rw [effectiveElectionVotersOtherEq candidate candidateNe] at effective
          exact effective)⟩
    · refine ⟨by simpa [view_effects] using joined, Or.inr ?_⟩
      by_cases voterEq : voter = node
      · subst voter
        simp only [currentlyEligibleElectionVoter] at eligible
        have voteChoice := eligible.2.2
        simp [view_effects] at voteChoice
        exact False.elim (candidateNe voteChoice.symm)
      · simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          termOther candidate candidateNe,
          termOther voter voterEq,
          logEq, lastIndexEq, lastTermEq,
          votedOther voter voterEq,
          voteLogUpToDate
        ] using eligible
  have potentialElectionMajorityOtherBack :
      forall candidate,
        Not (candidate = node) ->
        hasPotentialElectionMajority
            (timeoutEffect state node) candidate ->
          hasPotentialElectionMajority state candidate := by
    intro candidate candidateNe majority
    exact
      potentialElectionMajorityOfSubset
        (potentialElectionVotersOtherSubset candidate candidateNe)
        (activeConfigurationsEq candidate)
        majority
  have newTermAboveBootstrap : BOOTSTRAP_TERM < newTerm := by
    have participating : Not ((state.nodes node).role = .none) := by
      rcases enabled.2 with follower | preVoteCandidate | candidate
      · simp [follower]
      · simp [preVoteCandidate]
      · simp [candidate]
    have positive := facts.currentTermsPositive node participating
    simp [newTerm]
    omega
  have temporalFacts :=
    ackerTemporalFrameSameLogs state
      (timeoutEffect state node)
      votes newVotes responseHistory voteVoterHistory elections
      ackerCurrentFacts ackerVoteFacts ackerElectionFacts
      (fun leader role => by
        have leaderNe : Not (leader = node) := by
          intro same
          subst leader
          exact Role.noConfusion (role.symm.trans roleNode)
        simpa [roleOther leader leaderNe] using role)
      (fun leader role => by
        have leaderNe : Not (leader = node) := by
          intro same
          subst leader
          exact Role.noConfusion (role.symm.trans roleNode)
        exact termOther leader leaderNe)
      logEq
      (fun leader index voter role current member => by
        have leaderNe : Not (leader = node) := by
          intro same
          subst leader
          exact Role.noConfusion (role.symm.trans roleNode)
        rw [effectiveAckersEq leader leaderNe index] at member
        exact member)
      (fun candidate => by
        by_cases candidateEq : candidate = node
        · subst candidate
          rw [termNode]
          simp [newTerm]
        · exact Nat.le_of_eq (termOther candidate candidateEq).symm)
      (fun voter voteTerm candidate voted different => by
        by_cases voterEq : voter = node
        · subst voter
          by_cases voteTermEq : voteTerm = newTerm
          · subst voteTerm
            have chosen : some node = some candidate := by simpa [newVotes] using voted
            exact False.elim
              (different (Option.some.inj chosen))
          · simpa [
              newVotes, Function.update, voteTermEq
            ] using voted
        · simpa [
            newVotes, Function.update, voterEq
          ] using voted)
  have snapshotsAfter :
      GrantedVoteSnapshots
        (timeoutEffect state node)
        newVotes voteCandidateHistory voteVoterHistory := by
    intro candidate voter active member
    by_cases candidateEq : candidate = node
    · subst candidate
      have voterEq : voter = node := by
        have : voter ∈ ({node} : Finset Node) :=
          effectiveElectionVotersNode member
        simpa using this
      subst voter
      refine ⟨?_, Or.inl rfl⟩
      simp [newVotes, Function.update, termNode, newTerm]
    · have oldActive :
          (state.nodes candidate).role = .candidate \/
            (state.nodes candidate).role = .leader := by
        rw [roleOther candidate candidateEq] at active
        exact active
      rw [termOther candidate candidateEq]
      have oldMember :
          voter ∈ effectiveElectionVoters state candidate := by
        rw [effectiveElectionVotersOtherEq candidate candidateEq] at member
        exact member
      rcases
          facts.grantedVoteSnapshots
            candidate voter oldActive oldMember with
        ⟨recorded, self | snapshot⟩
      all_goals
        have newRecorded :
            newVotes voter (state.nodes candidate).currentTerm =
              some candidate := by
          by_cases voterEq : voter = node
          · rw [voterEq] at recorded ⊢
            have termNe :
                Not ((state.nodes candidate).currentTerm = newTerm) := by
              intro sameTerm
              have futureEmpty :=
                facts.voteHistory.future
                  node (state.nodes candidate).currentTerm
                  (by simp [newTerm] at sameTerm ⊢; omega)
              rw [recorded] at futureEmpty
              contradiction
            simpa [newVotes, Function.update, termNe] using recorded
          · simpa [newVotes, Function.update, voterEq] using recorded
      · refine ⟨?_, Or.inl self⟩
        exact newRecorded
      · rcases snapshot with
          ⟨candidatePrefix, candidateCommittable, voterCommittable,
            voterBound, upToDate⟩
        refine ⟨?_, Or.inr ⟨?_, ?_, ?_, ?_, ?_⟩⟩
        · exact newRecorded
        · simpa [logEq] using candidatePrefix
        · exact candidateCommittable
        · exact voterCommittable
        · by_cases voterEq : voter = node
          · subst voter
            rw [termNode]
            exact Nat.le_trans voterBound (by simp [newTerm])
          · simpa [termOther voter voterEq] using voterBound
        · simpa [voteLogUpToDate] using upToDate
  refine ⟨
    newVotes,
    appendHistory,
    responseHistory,
    voteRequestHistory,
    voteCandidateHistory,
    voteVoterHistory,
    ?_
  ⟩
  constructor
  · intro candidate
    rw [commitEq, logEq]
    exact facts.commitIndicesBounded candidate
  · intro candidate participating
    by_cases same : candidate = node
    · subst candidate
      rw [termNode]
      exact Nat.le_of_lt newTermAboveBootstrap
    · rw [termOther candidate same]
      apply facts.currentTermsPositive candidate
      intro none
      apply participating
      simpa [roleOther candidate same] using none
  · intro candidate entry member
    rw [logEq] at member
    by_cases same : candidate = node
    · subst candidate
      rw [termNode]
      have oldBound :=
        facts.entriesDoNotExceedCurrentTerm node entry member
      simp [newTerm]
      omega
    · rw [termOther candidate same]
      exact facts.entriesDoNotExceedCurrentTerm candidate entry member
  · intro candidate role
    by_cases same : candidate = node
    · subst candidate
      exact ⟨votedNode, by simp [votesNode]⟩
    · have oldRole : (state.nodes candidate).role = .candidate := by
        rw [roleOther candidate same] at role
        exact role
      rw [votedOther candidate same, votesOther candidate same]
      exact facts.candidatesSelfVote candidate oldRole
  · intro leader role
    have leaderNe : Not (leader = node) := by
      intro same
      subst leader
      exact Role.noConfusion (role.symm.trans roleNode)
    rw [roleOther leader leaderNe] at role
    have old := facts.leadersHaveElectionWitness leader role
    rw [termOther leader leaderNe]
    rcases old with bootstrap | majority
    · exact Or.inl bootstrap
    · exact Or.inr (by
        simpa [logEq, votesOther leader leaderNe] using majority)
  · intro leader role peer
    have leaderNe : Not (leader = node) := by
      intro same
      subst leader
      exact Role.noConfusion (role.symm.trans roleNode)
    rw [roleOther leader leaderNe] at role
    have old := facts.leaderProgressBounded leader role peer
    rw [sentEq, matchEq, logEq]
    exact old
  · constructor
    · intro voter
      by_cases voterEq : voter = node
      · subst voter
        have termNe : Not (BOOTSTRAP_TERM = newTerm) :=
          ne_of_lt newTermAboveBootstrap
        simp [
          newVotes, Function.update, newTerm,
          termNe, facts.voteHistory.bootstrapEmpty node
        ]
      · simp [
          newVotes, voterEq,
          facts.voteHistory.bootstrapEmpty voter
        ]
    · intro voter
      by_cases voterEq : voter = node
      · subst voter
        rw [termNode, votedNode]
        simp [newVotes, Function.update]
      · rw [termOther voter voterEq, votedOther voter voterEq]
        simpa [newVotes, Function.update, voterEq] using facts.voteHistory.current voter
    · intro voter term future
      by_cases voterEq : voter = node
      · subst voter
        rw [termNode] at future
        have termNe : Not (term = newTerm) := by omega
        simp [
          newVotes, Function.update, termNe,
          facts.voteHistory.future node term (by
            simp [newTerm] at future ⊢
            omega)
        ]
      · rw [termOther voter voterEq] at future
        simpa [newVotes, Function.update, voterEq]
          using facts.voteHistory.future voter term future
    · intro candidate voter active member
      by_cases candidateEq : candidate = node
      · subst candidate
        rw [votesNode] at member
        simp at member
        subst voter
        rw [termNode]
        simp [newVotes, Function.update]
      · have oldActive :
            (state.nodes candidate).role = .candidate \/
              (state.nodes candidate).role = .leader := by
          rw [roleOther candidate candidateEq] at active
          exact active
        rw [votesOther candidate candidateEq] at member
        have oldCounted :=
          facts.voteHistory.counted candidate voter oldActive member
        rw [termOther candidate candidateEq]
        by_cases voterEq : voter = node
        · subst voter
          have termNe :
              Not ((state.nodes candidate).currentTerm = newTerm) := by
            intro sameTerm
            have empty :=
              facts.voteHistory.future
                node (state.nodes candidate).currentTerm
                (by
                  simp [newTerm] at sameTerm ⊢
                  omega)
            rw [oldCounted] at empty
            contradiction
          simpa [newVotes, Function.update, termNe] using oldCounted
        · simpa [newVotes, Function.update, voterEq] using oldCounted
  · constructor
    · exact facts.networkHistory.addressed
    · intro destination request member
      have old := facts.networkHistory.appendRequest destination request member
      refine ⟨old.1, old.2.1, ?_⟩
      unfold RequestCommitStillPresent at old ⊢
      rw [committedEq]
      exact old.2.2
    · intro destination response member success
      have oldMember :
          Message.appendEntriesResponse response ∈
            state.network destination := by
        simpa [view_effects] using member
      have responseDestination :
          response.destination = destination := by
        simpa using
          facts.networkHistory.addressed
            destination (.appendEntriesResponse response) oldMember
      subst destination
      rcases
          facts.networkHistory.appendResponse response.destination response
            oldMember success with
        ⟨lengthBound, termBound, supported⟩
      refine ⟨lengthBound, ?_, ?_⟩
      · by_cases destinationEq : response.destination = node
        · rw [destinationEq, termNode]
          rw [destinationEq] at termBound
          simp [newTerm]
          omega
        · simpa [termOther response.destination destinationEq] using termBound
      intro sameTerm
      by_cases destinationEq : response.destination = node
      · have impossibleOldTerm :
            response.term >
              (state.nodes response.destination).currentTerm := by
          rw [destinationEq, termNode] at sameTerm
          rw [destinationEq]
          simp [newTerm] at sameTerm ⊢
          omega
        exact False.elim (Nat.not_lt_of_ge termBound impossibleOldTerm)
      · have oldTerm :
            response.term =
              (state.nodes response.destination).currentTerm := by
          simpa [termOther response.destination destinationEq] using sameTerm
        rcases supported oldTerm with active | follower | preVoteCandidate
        · exact Or.inl
            ⟨by
                simpa [roleOther response.destination destinationEq] using
                  active.1,
              by simpa [logEq] using active.2⟩
        · exact Or.inr
            (Or.inl (by
              simpa [roleOther response.destination destinationEq] using
                follower))
        · exact Or.inr
            (Or.inr (by
              simpa [roleOther response.destination destinationEq] using
                preVoteCandidate))
    · intro destination request member
      rcases
          facts.networkHistory.voteRequest destination request member with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      refine ⟨lastIndex, lastTerm, maxIndex, aboveBootstrap, ?_, ?_⟩
      · by_cases sourceEq : request.source = node
        · have oldBound :
              request.term <= (state.nodes node).currentTerm := by
            simpa [sourceEq] using termBound
          rw [sourceEq, termNode]
          simp [newTerm]
          omega
        · simpa [termOther request.source sourceEq] using termBound
      · intro sameTerm active
        by_cases sourceEq : request.source = node
        · have oldBound :
              request.term <= (state.nodes node).currentTerm := by
            simpa [sourceEq] using termBound
          have newSame :
              request.term = newTerm := by
            simpa [sourceEq, termNode] using sameTerm
          simp [newTerm] at newSame
          omega
        · have oldPrefix :=
            activePrefix
              (by simpa [termOther request.source sourceEq] using sameTerm)
              (by simpa [roleOther request.source sourceEq] using active)
          simpa [logEq] using oldPrefix
    · intro destination response member granted
      rcases
          facts.networkHistory.voteResponse
            destination response member granted with
        ⟨oldBound, oldVote, upToDate⟩
      refine ⟨?_, ?_, upToDate⟩
      · by_cases responseDestinationEq :
            response.destination = node
        · rw [responseDestinationEq, termNode]
          rw [responseDestinationEq] at oldBound
          simp [newTerm]
          omega
        · simpa [
            termOther response.destination responseDestinationEq
          ] using oldBound
      · by_cases sourceEq : response.source = node
        · rw [sourceEq] at oldVote ⊢
          by_cases termEq : response.term = newTerm
          · have empty :=
              facts.voteHistory.future node response.term (by
                simp [newTerm] at termEq ⊢
                omega)
            rw [oldVote] at empty
            contradiction
          · simpa [newVotes, Function.update, termEq] using oldVote
        · simpa [newVotes, Function.update, sourceEq] using oldVote
  have evidenceAfter :
      CommitEvidenceFacts
        (timeoutEffect state node)
        appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
      state (timeoutEffect state node)
        appendHistory nodeEvidence requestEvidence evidenceFacts
        commitEq committedEq
    · intro candidate
      by_cases candidateEq : candidate = node
      · subst candidate
        rw [termNode]
        simp [newTerm]
      · exact Nat.le_of_eq (termOther candidate candidateEq).symm
    · intro destination request member
      simpa [view_effects] using member
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        (timeoutEffect state node)
        appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state (timeoutEffect state node)
          appendHistory appendHistory
          nodeEvidence nodeEvidence requestEvidence requestEvidence
            elections prospectiveFacts
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [view_effects] using member)
            known
    · intro member
      simp [logEq]
    · intro evidence supportedPrefix destination request known queued sameTerm
      left
      exact ⟨by simpa [view_effects] using queued, rfl⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      by_cases candidateEq : candidate = node
      · subst candidate
        right
        have oldKnown :=
          knownCommitEvidenceFrameBack
            state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [view_effects] using member)
            known
        have futureMember :
            member ∈ futureElectionVoters state node newTerm := by
          simp only [
            relaxedElectionVoters, futureElectionVoters,
            Finset.mem_filter] at relaxed ⊢
          rcases relaxed with ⟨joined, effective | supporter⟩
          · have voterEq : member = node := by
              have voterIn : member ∈ ({node} : Finset Node) :=
                effectiveElectionVotersNode effective
              simpa using voterIn
            exact ⟨
              by simpa [view_effects] using joined,
              Or.inl voterEq
            ⟩
          · by_cases memberEq : member = node
            · exact ⟨
                by simpa [view_effects] using joined,
                Or.inl memberEq
              ⟩
            · exact ⟨
                by simpa [view_effects] using joined,
                Or.inr
                  ⟨
                    by simpa [termOther member memberEq, termNode] using supporter.1,
                    by simpa [
                        makeRequestVoteRequest,
                        logEq, lastIndexEq, lastTermEq,
                        voteLogUpToDate
                      ] using supporter.2
                  ⟩
              ⟩
        have oldCandidateBefore :
            (state.nodes node).currentTerm < newTerm := by
          simp [newTerm]
        have covered :=
          prospectiveCommitFutureMember
            ownership
              (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
                facts)
              electionFacts evidenceFacts prospectiveFacts
              oldKnown oldCandidateBefore ackMember futureMember
        simpa [logEq] using covered
      · left
        refine ⟨
          by simpa [roleOther candidate candidateEq] using role,
          by simpa [termOther candidate candidateEq] using newer,
          ?_,
          ?_,
          ?_
        ⟩
        · intro entry entryMember
          simpa [termOther candidate candidateEq]
            using entriesBefore entry (by simpa [logEq] using entryMember)
        · simp only [
            relaxedElectionVoters, Finset.mem_filter] at relaxed ⊢
          rcases relaxed with ⟨joined, effective | supporter⟩
          · rw [effectiveElectionVotersOtherEq candidate candidateEq] at effective
            exact ⟨
              by simpa [view_effects] using joined,
              Or.inl effective
            ⟩
          · refine ⟨
              by simpa [view_effects] using joined,
              Or.inr ⟨?_, ?_⟩
            ⟩
            · by_cases memberEq : member = node
              · have afterBound := supporter.1
                rw [memberEq, termNode,
                  termOther candidate candidateEq] at afterBound
                simp [newTerm] at afterBound
                rw [memberEq]
                omega
              · simpa [termOther member memberEq,
                  termOther candidate candidateEq] using supporter.1
            · simpa [
                makeRequestVoteRequest,
                termOther candidate candidateEq,
                logEq, lastIndexEq, lastTermEq,
                voteLogUpToDate
              ] using supporter.2
        · simp [logEq]
  have timeoutVoterSubset :
      potentialElectionVoters (timeoutEffect state node) node ⊆
        futureElectionVoters state node newTerm := by
    simpa [newTerm]
      using timeoutPotentialElectionVotersSubsetFuture state node
        ⟨
          votes,
          appendHistory,
          responseHistory,
          voteRequestHistory,
          voteCandidateHistory,
          voteVoterHistory,
          facts
        ⟩
  have timeoutFutureMajority :
      hasPotentialElectionMajority
          (timeoutEffect state node) node ->
        hasFutureElectionMajority
          state node newTerm
            (activeConfigurations (state.nodes node)) := by
    intro majority
    apply
      potentialElectionMajorityImpliesFuture
        timeoutVoterSubset
        (ballotActive :=
          activeConfigurations (state.nodes node))
    · exact (activeConfigurationsEq node).symm
    · exact majority
  have timeoutPotentialVoterTerm :
      forall voter,
        voter ∈
            potentialElectionVoters
              (timeoutEffect state node) node ->
          ((timeoutEffect state node).nodes voter).currentTerm =
            newTerm := by
    intro voter member
    simp only [
      potentialElectionVoters, Finset.mem_filter] at member
    rcases member with ⟨_joined, effective | eligible⟩
    · have voterIn : voter ∈ ({node} : Finset Node) :=
        effectiveElectionVotersNode effective
      have voterEq : voter = node := by simpa using voterIn
      subst voter
      exact termNode
    · simp only [currentlyEligibleElectionVoter] at eligible
      simpa [makeRequestVoteRequest, termNode] using eligible.1.symm
  have timeoutPotentialAckersSubset :
      forall source index,
        ((timeoutEffect state node).nodes source).role = .leader ->
        potentialAckers
            (timeoutEffect state node)
            appendHistory responseHistory source index ⊆
          potentialAckers
            state appendHistory responseHistory source index := by
    intro source index role peer member
    have sourceNe : Not (source = node) := by
      intro same
      subst source
      exact Role.noConfusion (role.symm.trans roleNode)
    simp only [
      potentialAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | reserve⟩
    · refine ⟨by simpa [view_effects] using joined, Or.inl ?_⟩
      rw [effectiveAckersEq source sourceNe index] at effective
      exact effective
    · refine ⟨by simpa [view_effects] using joined, Or.inr ?_⟩
      rcases reserve with
        ⟨request, queued, requestSource, requestDestination,
          requestTerm, producible, covered⟩
      have requestDestinationEq := requestDestination
      refine ⟨
        request,
        by simpa [view_effects] using queued,
        requestSource,
        requestDestination,
        by simpa [termOther source sourceNe] using requestTerm,
        ?_,
        by simpa [logEq] using covered
      ⟩
      by_cases peerEq : peer = node
      · have destinationEq : request.destination = node :=
          requestDestinationEq.trans peerEq
        rcases producible with direct | future
        · have follower := canProduceAppendAckAt_role direct
          rw [peerEq, roleNode] at follower
          contradiction
        · exact Or.inr
            ⟨by
              have futureTerm := future.1
              rw [peerEq, termNode] at futureTerm
              have oldBeforeNew :
                  (state.nodes node).currentTerm < newTerm := by
                simp [newTerm]
              simpa [peerEq] using oldBeforeNew.trans futureTerm,
              future.2⟩
      · simpa [
          view_effects, updateNode,
          Function.update, peerEq
        ] using producible
  have timeoutPotentialMajorityBack :
      forall source index,
        ((timeoutEffect state node).nodes source).role = .leader ->
        hasPotentialMajorityAt
            (timeoutEffect state node)
            appendHistory responseHistory source index ->
          hasPotentialMajorityAt
            state appendHistory responseHistory source index := by
    intro source index role majority
    rw [hasPotentialMajorityAt, List.all_eq_true] at majority
    rw [hasPotentialMajorityAt, List.all_eq_true]
    intro configuration active
    apply decide_eq_true
    intro governs
    have afterActive :
        configuration ∈
          activeConfigurations
            ((timeoutEffect state node).nodes source) := by
      simpa [activeConfigurationsEq] using active
    exact
      hasConfigurationMajority_mono
        (timeoutPotentialAckersSubset source index role)
        ((of_decide_eq_true
          (majority configuration afterActive)) governs)
  have activationSupporterCurrentAfter :
      ActivationSupporterCurrentHistory
        (timeoutEffect state node) elections activations := by
    apply
      activationSupporterCurrentHistoryFrame
        state (timeoutEffect state node)
        elections elections activations
        configurationFacts.supporterCurrentHistory
    · intro candidate
      rw [logEq]
    · intro candidate
      by_cases candidateEq : candidate = node
      · subst candidate
        rw [termNode]
        simp [newTerm]
      · exact Nat.le_of_eq (termOther candidate candidateEq).symm
    · intro _ _ stored
      exact stored
  have timeoutEvidenceBridge :
      hasPotentialElectionMajority (timeoutEffect state node) node ->
      forall evidence supportedPrefix,
        KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
        evidence.commitTerm < newTerm ->
          evidence.history.take evidence.commitFrontier <+:
            ((timeoutEffect state node).nodes node).log := by
    intro candidateMajority evidence supportedPrefix known newer
    have futureMajority := timeoutFutureMajority candidateMajority
    let candidateConfiguration :=
      currentConfiguration (state.nodes node)
    have candidateBefore :
        (state.nodes node).currentTerm < newTerm := by
      simp [newTerm]
    have directOfActive
        (authorityActive :
          evidence.authority ∈
            activeConfigurations (state.nodes node)) :
        evidence.history.take evidence.commitFrontier <+:
          ((timeoutEffect state node).nodes node).log := by
      simpa [logEq]
        using (prospectiveCommitFutureCandidateOfSharedAuthority
                ownership
                (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts)
                electionFacts evidenceFacts prospectiveFacts known
                candidateBefore futureMajority authorityActive)
    rcases Nat.lt_trichotomy
        evidence.authority.index candidateConfiguration.index with
      authorityBefore | sameIndex | candidateBeforeAuthority
    · have candidatePositive : 0 < candidateConfiguration.index := by omega
      have commitPositive : 0 < (state.nodes node).commitIndex := by
        exact
          candidatePositive.trans_le
            (by simpa [candidateConfiguration] using
              currentConfiguration_index_le_commitIndex (state.nodes node))
      rcases evidenceFacts.nodePositive node commitPositive with
        ⟨candidateEvidence, candidateStored, candidateValid,
          candidateSupportedLength, _candidateTermBound⟩
      have candidateKnown :
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            candidateEvidence (state.nodes node).committedLog :=
        Or.inl ⟨node, commitPositive, candidateStored, rfl⟩
      have candidateConfigurationKnownCommitted :
          candidateConfiguration ∈
            allConfigurations (state.nodes node).committedLog := by
        unfold NodeState.committedLog
        apply
          allConfigurations_mem_take_of_index_le
            (state.nodes node).log (state.nodes node).commitIndex
        · exact facts.commitIndicesBounded node
        · simpa [candidateConfiguration]
            using currentConfiguration_mem_allConfigurations (state.nodes node)
        · simpa [candidateConfiguration]
            using currentConfiguration_index_le_commitIndex (state.nodes node)
      have committedInEvidence :
          (state.nodes node).committedLog <+:
            candidateEvidence.history := by
        rw [← candidateValid.2.2.2.1]
        exact List.take_prefix _ _
      have candidateConfigurationKnownEvidence :
          candidateConfiguration ∈
            allConfigurations candidateEvidence.history :=
        memOfPrefix
          (allConfigurations_mono_prefix committedInEvidence)
          candidateConfigurationKnownCommitted
      have candidateConfigurationBeforeEvidenceAuthority :
          candidateConfiguration.index <=
            candidateEvidence.authority.index := by
        have supportedBound :
            candidateConfiguration.index <=
              candidateEvidence.supportedLength := by
          rw [candidateSupportedLength]
          simpa [candidateConfiguration]
            using currentConfiguration_index_le_commitIndex (state.nodes node)
        have frontierBound :
            candidateConfiguration.index <=
              candidateEvidence.commitFrontier :=
          supportedBound.trans candidateValid.2.2.1
        let evidenceNode : NodeState Node TxId :=
          { state.nodes node with
            log := candidateEvidence.history
            commitIndex := candidateEvidence.commitFrontier }
        have bound :=
          configuration_index_le_currentConfiguration
            evidenceNode candidateConfiguration
            (by simpa [evidenceNode] using candidateConfigurationKnownEvidence)
            frontierBound
        simpa [evidenceNode, currentConfiguration, candidateValid.2.2.2.2.1] using bound
      have evidenceBeforeCandidateEvidence :
          evidence.authority.index <
            candidateEvidence.authority.index :=
        authorityBefore.trans_le
          candidateConfigurationBeforeEvidenceAuthority
      have covered :=
        activationEvidence.authorityBridge
          evidence supportedPrefix known
          candidateEvidence (state.nodes node).committedLog candidateKnown
          evidenceBeforeCandidateEvidence
      have valid := knownCommitEvidenceValid evidenceFacts known
      have evidenceFrontierBound :
          evidence.commitFrontier <= candidateEvidence.supportedLength := by
        by_contra outside
        have candidateIndexWithinSupported :
            candidateConfiguration.index <=
              candidateEvidence.supportedLength := by
          rw [candidateSupportedLength]
          simpa [candidateConfiguration]
            using currentConfiguration_index_le_commitIndex (state.nodes node)
        have candidateIndexWithinEvidence :
            candidateConfiguration.index <= evidence.commitFrontier := by
          exact
            candidateIndexWithinSupported.trans
              (Nat.le_of_lt (Nat.lt_of_not_ge outside))
        have frontierWithinCandidateFrontier
            : evidence.commitFrontier <= candidateEvidence.commitFrontier := calc
          evidence.commitFrontier
              = (evidence.history.take evidence.commitFrontier).length := by
            simp [Nat.min_eq_left valid.1]
          _ <= (candidateEvidence.history.take candidateEvidence.commitFrontier).length :=
            covered.length_le
          _ <= candidateEvidence.commitFrontier := by simp
        have evidenceFrontierWithinCandidateHistory :
            evidence.commitFrontier <= candidateEvidence.history.length :=
          frontierWithinCandidateFrontier.trans candidateValid.1
        have candidateKnownAtEvidenceFrontier :
            candidateConfiguration ∈
              allConfigurations
                (candidateEvidence.history.take evidence.commitFrontier) :=
          allConfigurations_mem_take_of_index_le
            candidateEvidence.history evidence.commitFrontier
            evidenceFrontierWithinCandidateHistory
            candidateConfigurationKnownEvidence
            candidateIndexWithinEvidence
        have historiesAgree :
            evidence.history.take evidence.commitFrontier =
              candidateEvidence.history.take evidence.commitFrontier := by
          have agreed := prefixEqTake covered
          have evidenceLength :
              (evidence.history.take evidence.commitFrontier).length =
                evidence.commitFrontier := by
            simp [Nat.min_eq_left valid.1]
          rw [evidenceLength] at agreed
          simpa [
            List.take_take,
            Nat.min_eq_left frontierWithinCandidateFrontier
          ] using agreed.symm
        have candidateKnownEvidence :
            candidateConfiguration ∈
              allConfigurations evidence.history := by
          apply
            memOfPrefix
              (allConfigurations_mono_prefix
                (List.take_prefix evidence.commitFrontier evidence.history))
          rw [historiesAgree]
          exact candidateKnownAtEvidenceFrontier
        have candidateBeforeEvidenceAuthority :
            candidateConfiguration.index <= evidence.authority.index := by
          let evidenceNode : NodeState Node TxId :=
            { state.nodes node with
              log := evidence.history
              commitIndex := evidence.commitFrontier }
          have maximal :=
            configuration_index_le_currentConfiguration
              evidenceNode candidateConfiguration
              (by simpa [evidenceNode] using candidateKnownEvidence)
              (by simpa [evidenceNode] using candidateIndexWithinEvidence)
          simpa [
            evidenceNode, currentConfiguration,
            valid.2.2.2.2.1
          ] using maximal
        omega
      have coveredCommitted :
          evidence.history.take evidence.commitFrontier <+:
            candidateEvidence.history.take
              candidateEvidence.supportedLength := by
        rw [List.prefix_take_iff]
        exact ⟨
          covered.trans
            (List.take_prefix candidateEvidence.commitFrontier candidateEvidence.history),
          by
            simp [Nat.min_eq_left valid.1]
            exact evidenceFrontierBound
        ⟩
      have committedPrefix :
          (state.nodes node).committedLog <+:
            (state.nodes node).log := by
        unfold NodeState.committedLog
        exact List.take_prefix _ _
      exact coveredCommitted.trans
        (by
          rw [candidateValid.2.2.2.1]
          simpa [logEq] using committedPrefix)
    · have sameConfiguration :
          evidence.authority = candidateConfiguration := by
        by_cases zero : evidence.authority.index = 0
        · have valid := knownCommitEvidenceValid evidenceFacts known
          have evidenceKnown :
              evidence.authority ∈ allConfigurations evidence.history := by
            let evidenceNode : NodeState Node TxId :=
              { state.nodes node with
                log := evidence.history
                commitIndex := evidence.commitFrontier }
            have knownConfiguration :=
              currentConfiguration_mem_allConfigurations evidenceNode
            simpa [
              evidenceNode, currentConfiguration,
              valid.2.2.2.2.1
            ] using knownConfiguration
          have evidenceImplicit :
              evidence.authority = implicitConfiguration := by
            apply
              allConfigurations_index_unique
                (TxId := TxId) evidence.history
            · exact evidenceKnown
            · simp [allConfigurations, implicitConfiguration]
            · simpa [implicitConfiguration] using zero
          have candidateZero : candidateConfiguration.index = 0 := by
            simpa [sameIndex] using zero
          have candidateImplicit :
              candidateConfiguration = implicitConfiguration := by
            apply
              allConfigurations_index_unique
                (TxId := TxId) (state.nodes node).log
            · simpa [candidateConfiguration]
                using currentConfiguration_mem_allConfigurations (state.nodes node)
            · simp [allConfigurations, implicitConfiguration]
            · simpa [implicitConfiguration] using candidateZero
          exact evidenceImplicit.trans candidateImplicit.symm
        · rcases activationEvidence.authorityRecorded
              evidence supportedPrefix known with
            implicit | recordedAuthority
          · exact False.elim (zero (by rw [implicit]; rfl))
          · rcases recordedAuthority with
              ⟨authorityActivationIndex, authorityActivation,
                authorityStored, authorityGoverning, _⟩
            have candidatePositive : 0 < candidateConfiguration.index := by
              simpa [sameIndex] using Nat.pos_of_ne_zero zero
            rcases configurationActivations node
                (by simpa [candidateConfiguration] using candidatePositive) with
              ⟨candidateCoverage⟩
            have authorityKnown :
                evidence.authority ∈
                  allConfigurations authorityActivation.history := by
              have valid :=
                activationQuorums.history.valid
                  authorityActivationIndex authorityActivation authorityStored
              have governing := authorityGoverning
              rw [valid.2.2.2.2.2.2.1] at governing
              exact (List.mem_filter.mp governing).1
            have candidateAtOrBeforeActivation :
                candidateConfiguration.index <=
                  authorityActivation.newConfiguration.index := by
              have authorityAtOrBefore :=
                activationGoverningConfigurationIndexLeNew
                  activationQuorums.history authorityStored
                  authorityGoverning
              simpa [candidateConfiguration, sameIndex] using authorityAtOrBefore
            have candidateKnown :
                candidateConfiguration ∈
                  allConfigurations authorityActivation.history := by
              rcases lt_or_eq_of_le candidateAtOrBeforeActivation with
                strict | equal
              · apply memOfPrefix
                  (allConfigurations_mono_prefix
                    ((candidateCoverage.sharedPrefix_prefix_higherAuthority
                        authorityStored
                        (by simpa [candidateConfiguration] using strict)).trans
                      (List.take_prefix
                        authorityActivation.activationFrontier
                        authorityActivation.history)))
                simpa [candidateConfiguration]
                  using
                    ConfigurationCoverageWitness.configuration_mem_activationHistoryTake
                      activationQuorums.history candidateCoverage
              · have configurationEq :=
                  candidateCoverage.sameAuthority_configurationEq
                    authorityStored
                    (by simpa [candidateConfiguration] using equal.symm)
                simpa [configurationEq]
                  using memOfPrefix
                    (allConfigurations_mono_prefix
                      (List.take_prefix
                        authorityActivation.activationFrontier
                        authorityActivation.history))
                    (activationNewConfigurationKnown
                      activationQuorums.history authorityStored)
            exact allConfigurations_index_unique
              (TxId := TxId) authorityActivation.history
              authorityKnown candidateKnown
              (by simpa [candidateConfiguration] using sameIndex)
      apply directOfActive
      rw [sameConfiguration]
      simpa [candidateConfiguration]
        using currentConfiguration_mem_activeConfigurations (state.nodes node)
    · rcases activationEvidence.authorityRecorded
          evidence supportedPrefix known with
        implicit | recordedAuthority
      · rw [implicit] at candidateBeforeAuthority
        simp [implicitConfiguration] at candidateBeforeAuthority
      · rcases recordedAuthority with
          ⟨authorityActivationIndex, authorityActivation,
            authorityStored, authorityGoverning, _⟩
        have candidateBeforeActivation :
            candidateConfiguration.index <
              authorityActivation.newConfiguration.index := by
          have candidateBeforeAuthorityIndex :
              candidateConfiguration.index < evidence.authority.index := by
            simpa [candidateConfiguration] using candidateBeforeAuthority
          exact candidateBeforeAuthorityIndex.trans_le
            (activationGoverningConfigurationIndexLeNew
              activationQuorums.history authorityStored authorityGoverning)
        have activationInCandidate :=
          activationPrefixInFutureCandidateByCoverageAuthorityChain
            (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
              facts)
            ownership electionFacts activationQuorums.history
            configurationFacts.supporterCurrentHistory
            activationCanonical activationElections configurationActivations
            futureMajority rfl
            authorityActivation.newConfiguration.index
            authorityActivationIndex
            authorityActivation
            rfl
            authorityStored
            candidateBeforeActivation
        have authorityKnownCandidate
            : evidence.authority ∈ allConfigurations (state.nodes node).log := by
          apply
            memOfPrefix
              (allConfigurations_mono_prefix activationInCandidate)
          have valid :=
            activationQuorums.history.valid
              authorityActivationIndex authorityActivation authorityStored
          have governing := authorityGoverning
          rw [valid.2.2.2.2.2.2.1] at governing
          exact
            allConfigurations_mem_take_of_index_le
              authorityActivation.history
              authorityActivation.activationFrontier valid.2.1
              (List.mem_filter.mp governing).1
              (of_decide_eq_true
                (List.mem_filter.mp governing).2).2
        apply directOfActive
        simpa [activeConfigurations, candidateConfiguration]
          using And.intro authorityKnownCandidate candidateBeforeAuthority.le
  have timeoutCandidateBridge :
      hasPotentialElectionMajority (timeoutEffect state node) node ->
      forall source index,
        ((timeoutEffect state node).nodes source).role = .leader ->
        termAt
            ((timeoutEffect state node).nodes source).log index =
          ((timeoutEffect state node).nodes source).currentTerm ->
        isSignatureAt
            ((timeoutEffect state node).nodes source).log index = true ->
        hasPotentialMajorityAt
            (timeoutEffect state node)
            appendHistory responseHistory source index ->
        ((timeoutEffect state node).nodes source).currentTerm < newTerm ->
          ((timeoutEffect state node).nodes source).log.take index <+:
            ((timeoutEffect state node).nodes node).log := by
    intro candidateMajority source index role current signature potential lower
    have sourceNe : Not (source = node) := by
      intro same
      subst source
      exact Role.noConfusion (role.symm.trans roleNode)
    have oldRole : (state.nodes source).role = .leader := by
      simpa [roleOther source sourceNe] using role
    have oldCurrent :
        termAt (state.nodes source).log index =
          (state.nodes source).currentTerm := by
      simpa [logEq, termOther source sourceNe] using current
    have oldSignature :
        isSignatureAt (state.nodes source).log index = true := by
      simpa [logEq] using signature
    have oldPotential :=
      timeoutPotentialMajorityBack source index role potential
    have futureMajority := timeoutFutureMajority candidateMajority
    let sourceConfiguration :=
      currentConfiguration (state.nodes source)
    let candidateConfiguration :=
      currentConfiguration (state.nodes node)
    have sourceActive :
        sourceConfiguration ∈
          activeConfigurations
            ((timeoutEffect state node).nodes source) := by
      simpa [activeConfigurationsEq, sourceConfiguration]
        using currentConfiguration_mem_activeConfigurations (state.nodes source)
    have useCommitted
        (indexCommitted : index <= (state.nodes source).commitIndex) :
        ((timeoutEffect state node).nodes source).log.take index <+:
          ((timeoutEffect state node).nodes node).log := by
      rcases isSignatureAtTrue oldSignature with
        ⟨entry, found, _⟩
      have indexPositive : 0 < index := by
        by_contra notPositive
        have indexZero : index = 0 := Nat.eq_zero_of_not_pos notPositive
        subst index
        simp [entryAt?] at found
      have commitPositive : 0 < (state.nodes source).commitIndex := by omega
      rcases evidenceFacts.nodePositive source commitPositive with
        ⟨evidence, stored, valid, _supportedLength, termBound⟩
      have known :
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence (state.nodes source).committedLog :=
        Or.inl ⟨source, commitPositive, stored, rfl⟩
      have sourceBound := entryAtSomeIndexBound found
      have sourceInCommitted :
          (state.nodes source).log.take index <+:
            (state.nodes source).committedLog := by
        unfold NodeState.committedLog
        rw [List.prefix_take_iff]
        exact ⟨
          List.take_prefix _ _,
          by
            simp [List.length_take, Nat.min_eq_left sourceBound]
            exact indexCommitted
        ⟩
      have committedInCandidate :=
        timeoutEvidenceBridge candidateMajority
          evidence (state.nodes source).committedLog known
          (termBound.trans_lt
            (by simpa [termOther source sourceNe] using lower))
      simpa [logEq]
        using sourceInCommitted.trans
          ((validEvidenceSupportedPrefixFrontier valid).trans committedInCandidate)
    have useShared
        (configuration : Configuration Node)
        (sourceConfigurationActive :
          configuration ∈
            activeConfigurations
              ((timeoutEffect state node).nodes source))
        (configurationGoverns : configuration.index <= index)
        (candidateConfigurationActive :
          configuration ∈
            activeConfigurations
              ((timeoutEffect state node).nodes node)) :
        ((timeoutEffect state node).nodes source).log.take index <+:
          ((timeoutEffect state node).nodes node).log := by
      simpa [logEq]
        using potentialPrefixInFutureCandidateOfSharedConfiguration
          facts.currentTermsPositive
          (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts)
          facts.entriesDoNotExceedCurrentTerm facts.voteHistory
          ownership electionFacts ackerCurrentFacts ackerElectionFacts
          activationQuorums
          oldRole oldCurrent oldSignature potential oldPotential
          sourceConfigurationActive configurationGoverns
          candidateMajority candidateConfigurationActive
          (by simpa [termOther source sourceNe] using lower)
          (by simp [newTerm])
          (logEq source)
          (termOther source sourceNe)
          (fun voter effective => by
            rw [effectiveAckersEq source sourceNe index] at effective
            exact effective)
          timeoutVoterSubset timeoutPotentialVoterTerm
    rcases Nat.lt_trichotomy
        sourceConfiguration.index candidateConfiguration.index with
      sourceBeforeCandidate | sameIndex | candidateBeforeSource
    · have candidatePositive : 0 < candidateConfiguration.index := by
        omega
      rcases configurationActivations node
          (by simpa [candidateConfiguration] using candidatePositive) with
        ⟨candidateCoverage⟩
      let candidateActivation := candidateCoverage.activation
      have candidateStored :
          activations candidateCoverage.activationIndex =
            some candidateActivation :=
        candidateCoverage.stored
      have candidateValid :=
        activationQuorums.history.valid
          candidateCoverage.activationIndex candidateActivation candidateStored
      have candidateWithin :
          candidateConfiguration.index <=
            candidateActivation.activationFrontier := by
        exact
          candidateCoverage.configurationIndexBound.trans
            candidateCoverage.sharedFrontier_le_activationFrontier
      have candidateEventInCandidate :
          candidateActivation.history.take
              candidateActivation.activationFrontier <+:
            (state.nodes node).log := by
        exact
          activationPrefixInFutureCandidateOfGoverningConfiguration
            ownership
            (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
              facts)
            electionFacts activationQuorums.history
            configurationFacts.supporterCurrentHistory
            activationElections candidateStored futureMajority
            candidateCoverage.configurationCovered
            (currentConfiguration_mem_activeConfigurations
              (state.nodes node))
      rcases Nat.lt_trichotomy
          (state.nodes source).currentTerm
          candidateActivation.activationTerm with
        sourceBeforeActivation | sameTerm | activationBeforeSource
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
            facts.currentTermsPositive source (by rw [oldRole]; decide)
          omega
        · rcases activationElection with
            ⟨activationRecord, activationRecorded, activationLeader⟩
          have sourceInElection :=
            potentialPrefixInElectionRecordsFromActivationHistory
              facts.currentTermsPositive facts.entriesDoNotExceedCurrentTerm
              facts.voteHistory ownership electionFacts configurationFacts
              activationQuorums.history activationProgress
              ackerActivationFacts ackerElectionFacts activationCanonical
              activationElections configurationActivations
              evidenceFacts prospectiveFacts
              oldRole oldCurrent oldSignature oldPotential
              candidateActivation.activationTerm activationRecord
              activationRecorded sourceBeforeActivation
          have sourceInActivation :=
            electionPromotionPrefixInActivation
              electionFacts activationQuorums.history activationCanonical
              candidateStored
              (by simpa [activationLeader] using activationRecorded)
              sourceInElection
          have activationInCandidate :
              candidateActivation.history.take
                  candidateActivation.activationFrontier <+:
                (state.nodes node).log := by
            exact candidateEventInCandidate
          exact (by simpa [logEq] using sourceInActivation.trans activationInCandidate)
      · have activationCanonicalEq :
            candidateActivation.history.take
                candidateActivation.activationFrontier =
              (state.nodes source).log.take
                candidateActivation.activationFrontier := by
          calc
            candidateActivation.history.take candidateActivation.activationFrontier
                = (canonicalHistory candidateActivation.activationTerm).take
                    candidateActivation.activationFrontier :=
              activationCanonical.activationFrontierCanonical
                candidateCoverage.activationIndex candidateActivation
                candidateStored
            _ = (state.nodes source).log.take candidateActivation.activationFrontier := by
              rw [← sameTerm, ownership.activeLeaderHistory source oldRole]
        by_cases indexWithin :
            index <= candidateActivation.activationFrontier
        · have direct :
              (state.nodes source).log.take index <+:
                candidateActivation.history.take
                  candidateActivation.activationFrontier := by
            rw [activationCanonicalEq, List.prefix_take_iff]
            exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans indexWithin⟩
          have activationInCandidate :
              candidateActivation.history.take
                  candidateActivation.activationFrontier <+:
                (state.nodes node).log := by
            exact candidateEventInCandidate
          exact (by simpa [logEq] using direct.trans activationInCandidate)
        · have candidateKnownSource :
              candidateConfiguration ∈
                allConfigurations (state.nodes source).log := by
            have activationPrefixSource :
                candidateActivation.history.take
                    candidateActivation.activationFrontier <+:
                  (state.nodes source).log := by
              rw [activationCanonicalEq]
              exact List.take_prefix _ _
            have candidateKnownActivation :=
              candidateCoverage.configuration_mem_activationHistoryTake
                activationQuorums.history
            exact
              memOfPrefix
                (allConfigurations_mono_prefix activationPrefixSource)
                (memOfPrefix
                  (allConfigurations_mono_prefix
                    candidateCoverage.sharedPrefix_prefix_activationPrefix)
                  (by simpa [candidateConfiguration] using
                    candidateKnownActivation))
          have candidateActiveSource :
              candidateConfiguration ∈
                activeConfigurations
                  ((timeoutEffect state node).nodes source) := by
            rw [activeConfigurationsEq source]
            simpa [activeConfigurations, sourceConfiguration]
              using And.intro candidateKnownSource sourceBeforeCandidate.le
          exact useShared candidateConfiguration candidateActiveSource
            (candidateWithin.trans (Nat.le_of_not_ge indexWithin))
            (by
              rw [activeConfigurationsEq node]
              simpa [candidateConfiguration]
                using currentConfiguration_mem_activeConfigurations (state.nodes node))
      · have activationInSource :
            candidateActivation.history.take
                candidateActivation.activationFrontier <+:
              (state.nodes source).log := by
          rcases
              electionFacts.ownerRecorded
                (state.nodes source).currentTerm source
                (ownership.activeLeader source oldRole) with
            bootstrap | sourceElection
          · rw [bootstrap.1] at activationBeforeSource
            have positive :=
              activationQuorums.history.termPositive
                candidateCoverage.activationIndex candidateActivation
                  candidateStored
            omega
          · rcases sourceElection with
              ⟨sourceRecord, sourceRecorded, sourceLeader⟩
            exact (activationPrefixInLaterElection
                    activationElections candidateStored sourceRecorded
                    activationBeforeSource).trans
              ((electionFacts.promotionCanonical
                  (state.nodes source).currentTerm
                  sourceRecord sourceRecorded).trans
                (by rw [ownership.activeLeaderHistory source oldRole]))
        have frontierBeforeIndex :
            candidateActivation.activationFrontier < index := by
          rcases isSignatureAtTrue oldSignature with
            ⟨sourceEntry, sourceFound, _⟩
          rcases isSignatureAtTrue candidateValid.2.2.2.2.2.1 with
            ⟨activationEntry, activationFound, _⟩
          have activationFoundSource :=
            entryAt_of_prefix activationInSource (by
              rw [entryAtTake_of_le le_rfl]
              exact activationFound)
          have sourceEntryTerm :
              sourceEntry.term = (state.nodes source).currentTerm := by
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
              index <= candidateActivation.activationFrontier := by omega
          by_cases equal :
              index = candidateActivation.activationFrontier
          · have sameEntry : sourceEntry = activationEntry :=
              Option.some.inj
                (sourceFound.symm.trans (by simpa [equal] using activationFoundSource))
            rw [sameEntry, activationEntryTerm] at sourceEntryTerm
            omega
          · have monotone :=
              (canonicalHistoriesMonoLog ownership)
                source index candidateActivation.activationFrontier
                sourceEntry activationEntry (by omega)
                sourceFound activationFoundSource
            rw [sourceEntryTerm, activationEntryTerm] at monotone
            omega
        have candidateKnownSource
            : candidateConfiguration ∈ allConfigurations (state.nodes source).log := by
          have candidateKnownActivation :=
            candidateCoverage.configuration_mem_activationHistoryTake
              activationQuorums.history
          exact memOfPrefix
            (allConfigurations_mono_prefix activationInSource)
            (memOfPrefix
              (allConfigurations_mono_prefix
                candidateCoverage.sharedPrefix_prefix_activationPrefix)
              (by simpa [candidateConfiguration] using candidateKnownActivation))
        have candidateActiveSource :
            candidateConfiguration ∈
              activeConfigurations
                ((timeoutEffect state node).nodes source) := by
          rw [activeConfigurationsEq source]
          simpa [activeConfigurations, sourceConfiguration]
            using And.intro candidateKnownSource sourceBeforeCandidate.le
        exact useShared candidateConfiguration candidateActiveSource
          (candidateWithin.trans frontierBeforeIndex.le)
          (by
            rw [activeConfigurationsEq node]
            simpa [candidateConfiguration]
              using currentConfiguration_mem_activeConfigurations (state.nodes node))
    · have sameConfiguration :
          sourceConfiguration = candidateConfiguration := by
        by_cases zero : sourceConfiguration.index = 0
        · have sourceImplicit :
              sourceConfiguration = implicitConfiguration := by
            apply
              allConfigurations_index_unique
                (TxId := TxId) (state.nodes source).log
            · simpa [sourceConfiguration]
                using currentConfiguration_mem_allConfigurations (state.nodes source)
            · simp [allConfigurations, implicitConfiguration]
            · simpa [implicitConfiguration] using zero
          have candidateZero : candidateConfiguration.index = 0 := by
            simpa [sameIndex] using zero
          have candidateImplicit :
              candidateConfiguration = implicitConfiguration := by
            apply
              allConfigurations_index_unique
                (TxId := TxId) (state.nodes node).log
            · simpa [candidateConfiguration]
                using currentConfiguration_mem_allConfigurations (state.nodes node)
            · simp [allConfigurations, implicitConfiguration]
            · simpa [implicitConfiguration] using candidateZero
          exact sourceImplicit.trans candidateImplicit.symm
        · have sourcePositive : 0 < sourceConfiguration.index :=
            Nat.pos_of_ne_zero zero
          have candidatePositive : 0 < candidateConfiguration.index := by
            simpa [sameIndex] using sourcePositive
          exact configurationCoverageCurrentIndexUnique
            activationQuorums.history configurationActivations
            (by simpa [sourceConfiguration] using sourcePositive)
            (by simpa [candidateConfiguration] using candidatePositive)
            (by simpa [
                sourceConfiguration, candidateConfiguration
              ] using sameIndex)
      by_cases sourceGoverns : sourceConfiguration.index <= index
      · exact
          useShared sourceConfiguration sourceActive sourceGoverns
            (by
              rw [sameConfiguration]
              simpa [activeConfigurationsEq, candidateConfiguration] using
                currentConfiguration_mem_activeConfigurations
                  (state.nodes node))
      · apply useCommitted
        have currentBound :=
          currentConfiguration_index_le_commitIndex (state.nodes source)
        dsimp [sourceConfiguration] at sourceGoverns
        omega
    · have sourcePositive : 0 < sourceConfiguration.index := by
        omega
      rcases configurationActivations source
          (by simpa [sourceConfiguration] using sourcePositive) with
        ⟨sourceCoverage⟩
      let sourceActivation := sourceCoverage.activation
      have sourceStored :
          activations sourceCoverage.activationIndex =
            some sourceActivation :=
        sourceCoverage.stored
      have sourceActivationInCandidate :=
        activationPrefixInFutureCandidateByCoverageAuthorityChain
          (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts)
          ownership electionFacts activationQuorums.history
          configurationFacts.supporterCurrentHistory
          activationCanonical activationElections configurationActivations
          futureMajority rfl
          sourceActivation.newConfiguration.index
          sourceCoverage.activationIndex
          sourceActivation
          rfl sourceStored
          (by
            have sourceBeforeEvent :=
              candidateBeforeSource.trans_le
                (sourceCoverage.configurationIndex_le_activationConfiguration
                  activationQuorums.history)
            simpa [sourceConfiguration, candidateConfiguration] using sourceBeforeEvent)
      have sourceKnownCandidate
          : sourceConfiguration ∈ allConfigurations (state.nodes node).log := by
        have sourceKnownActivation :=
          sourceCoverage.configuration_mem_activationHistoryTake
            activationQuorums.history
        exact memOfPrefix
          (allConfigurations_mono_prefix sourceActivationInCandidate)
          (memOfPrefix
            (allConfigurations_mono_prefix
              sourceCoverage.sharedPrefix_prefix_activationPrefix)
            (by simpa [sourceConfiguration] using sourceKnownActivation))
      by_cases sourceGoverns : sourceConfiguration.index <= index
      · exact
          useShared sourceConfiguration sourceActive sourceGoverns
            (by
              rw [activeConfigurationsEq node]
              simpa [
                activeConfigurations,
                candidateConfiguration
              ] using
                And.intro sourceKnownCandidate candidateBeforeSource.le)
      · apply useCommitted
        have currentBound :=
          currentConfiguration_index_le_commitIndex (state.nodes source)
        dsimp [sourceConfiguration] at sourceGoverns
        omega
  have activationEvidenceAfter :
      ActivationEvidenceFacts
        (timeoutEffect state node)
        appendHistory responseHistory nodeEvidence requestEvidence
          elections activations := by
    constructor
    · intro evidence supportedPrefix known
      exact
        activationEvidence.authorityRecorded
          evidence supportedPrefix
          (knownCommitEvidenceFrameBack
            state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [view_effects] using member)
            known)
    · intro left leftPrefix leftKnown right rightPrefix rightKnown same
      exact
        activationEvidence.authorityIndexUnique
          left leftPrefix
          (knownCommitEvidenceFrameBack
            state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [view_effects] using member)
            leftKnown)
          right rightPrefix
          (knownCommitEvidenceFrameBack
            state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [view_effects] using member)
            rightKnown)
          same
    · intro earlier earlierPrefix earlierKnown
        later laterPrefix laterKnown order
      exact
        activationEvidence.authorityBridge
          earlier earlierPrefix
          (knownCommitEvidenceFrameBack
            state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [view_effects] using member)
            earlierKnown)
          later laterPrefix
          (knownCommitEvidenceFrameBack
            state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [view_effects] using member)
            laterKnown)
          order
    · intro left leftPrefix leftKnown right rightPrefix rightKnown
      exact
        activationEvidence.supportedPrefixesComparable
          left leftPrefix
          (knownCommitEvidenceFrameBack
            state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [view_effects] using member)
            leftKnown)
          right rightPrefix
          (knownCommitEvidenceFrameBack
            state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [view_effects] using member)
            rightKnown)
    · intro evidence supportedPrefix known candidate role majority newer
      have oldKnown :=
        knownCommitEvidenceFrameBack
          state (timeoutEffect state node)
          appendHistory nodeEvidence requestEvidence
          commitEq committedEq
          (fun destination request member => by
            simpa [view_effects] using member)
          known
      by_cases candidateEq : candidate = node
      · subst candidate
        have full :=
          timeoutEvidenceBridge
            majority evidence supportedPrefix oldKnown
            (by simpa [termNode] using newer)
        exact Or.inl full
      · have oldRole : (state.nodes candidate).role = .candidate := by
          simpa [roleOther candidate candidateEq] using role
        have oldMajority :=
          potentialElectionMajorityOtherBack
            candidate candidateEq majority
        have oldNewer :
            evidence.commitTerm <
              (state.nodes candidate).currentTerm := by
          simpa [termOther candidate candidateEq] using newer
        rcases
            activationEvidence.candidateBridge
              evidence supportedPrefix oldKnown candidate
              oldRole oldMajority oldNewer with
          direct | authorityActive
        · exact Or.inl (by simpa [logEq] using direct)
        · exact Or.inr
            (by simpa [activeConfigurationsEq] using authorityActive)
  have activationProgressAfter :
      ActivationSupporterProgress
        (timeoutEffect state node) activations := by
    apply
      activationSupporterProgressFrame
        state (timeoutEffect state node)
          activations activationProgress
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      rw [termNode]
      simp [newTerm]
    · exact Nat.le_of_eq (termOther candidate candidateEq).symm
  have configurationActivationsAfter :
      ConfigurationCoverageFacts
        (timeoutEffect state node) activations := by
    apply
      configurationCoverageFrame
        configurationActivations
    · intro candidate
      unfold currentConfiguration
      rw [logEq, commitEq]
    · intro candidate
      by_cases candidateEq : candidate = node
      · subst candidate
        rw [termNode]
        simp [newTerm]
      · exact Nat.le_of_eq (termOther candidate candidateEq).symm
    · exact commitEq
    · intro candidate frontier _
      rw [logEq]
    · intro candidate witness role
      by_cases candidateEq : candidate = node
      · subst candidate
        have oldBound := witness.activationTermBound
        rw [termNode]
        simp [newTerm]
        omega
      · exact (by
                have old :=
                  witness.candidateTermStrict
                    (by simpa [roleOther candidate candidateEq] using role)
                simpa [termOther candidate candidateEq] using old)
  have activationElectionsAfter :
      ActivationElectionFacts newVotes elections activations := by
    apply
      activationElectionFrame
        votes newVotes elections activations activationElections
    intro activationIndex activation electionTerm election voter
        activationStored electionStored member
    by_cases voterEq : voter = node
    · subst voter
      by_cases termEq : electionTerm = newTerm
      · subst electionTerm
        have bound :=
          electionHistoryVoterTerm
            facts.voteHistory electionFacts electionStored member
        simp [newTerm] at bound
      · simp [newVotes, Function.update, termEq]
    · simp [newVotes, voterEq]
  have ackerActivationAfter :
      AckerActivationHistory
        (timeoutEffect state node)
        responseHistory elections activations := by
    apply
      ackerActivationFrameSameLogs
        state (timeoutEffect state node)
          responseHistory elections elections activations
          ackerActivationFacts
    · intro source role
      have sourceNe : Not (source = node) := by
        intro same
        subst source
        exact Role.noConfusion (role.symm.trans roleNode)
      simpa [roleOther source sourceNe] using role
    · intro source role
      have sourceNe : Not (source = node) := by
        intro same
        subst source
        exact Role.noConfusion (role.symm.trans roleNode)
      exact termOther source sourceNe
    · exact logEq
    · intro source index supporter role current member
      have sourceNe : Not (source = node) := by
        intro same
        subst source
        exact Role.noConfusion (role.symm.trans roleNode)
      rw [effectiveAckersEq source sourceNe index] at member
      exact member
    · intro term record stored
      exact stored
  have ownershipAfter :
      TermOwnershipFacts
        (timeoutEffect state node)
        newVotes appendHistory canonicalHistory owners := by
    constructor
    · exact ownership.bootstrap
    · intro leader role
      have leaderNe : Not (leader = node) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleNode)
      rw [termOther leader leaderNe]
      exact ownership.activeLeader leader
        (by simpa [roleOther leader leaderNe] using role)
    · intro owner index entry found
      rcases
          ownership.logEntryAgreement owner index entry
            (by simpa [logEq] using found) with
        ⟨canonicalFound, agreed⟩
      exact ⟨canonicalFound, by simpa [logEq] using agreed⟩
    · intro destination request member index entry found
      exact
        ownership.queuedHistoryEntryAgreement
          destination request
            (by simpa [view_effects] using member)
            index entry found
    · intro leader role
      have leaderNe : Not (leader = node) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleNode)
      rw [termOther leader leaderNe]
      have oldRole : (state.nodes leader).role = .leader := by
        simpa [roleOther leader leaderNe] using role
      simpa [logEq] using ownership.activeLeaderHistory leader oldRole
    · exact ownership.canonicalEntryOwner
    · exact ownership.canonicalMonoLog
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bound, oldLeader⟩
      by_cases ownerEq : owner = node
      · subst owner
        constructor
        · rw [termNode]
          simp [newTerm]
          omega
        · intro same
          rw [termNode] at same
          simp [newTerm] at same
          omega
      · constructor
        · simpa [termOther owner ownerEq] using bound
        · intro same
          have oldSame :
              term = (state.nodes owner).currentTerm := by
            simpa [termOther owner ownerEq] using same
          simpa [roleOther owner ownerEq] using oldLeader oldSame
    · intro destination request member
      exact
        ownership.queuedAppendMetadata destination request
          (by simpa [view_effects] using member)
    · intro destination request member sameTerm leaderRole
      by_cases sourceEq : request.source = node
      · have afterLeader :
            ((timeoutEffect state node).nodes node).role = .leader := by
          simpa [sourceEq] using leaderRole
        exact False.elim
          (Role.noConfusion (afterLeader.symm.trans roleNode))
      · exact (ownership.queuedActiveSourceHistory
                destination request
                (by simpa [view_effects] using member)
                (by simpa [termOther request.source sourceEq] using sameTerm)
                (by simpa [roleOther request.source sourceEq] using leaderRole)).trans
          (by simp [logEq])
  have electionFactsAfter :
      ElectionHistoryFacts
        (timeoutEffect state node)
        newVotes canonicalHistory owners elections := by
    apply
      electionHistoryFrame
        state (timeoutEffect state node)
        votes newVotes canonicalHistory canonicalHistory
        owners elections electionFacts
    · intro term record voter recorded member
      by_cases voterEq : voter = node
      · subst voter
        by_cases termEq : term = newTerm
        · subst term
          have bound :=
            electionHistoryVoterTerm
              facts.voteHistory electionFacts recorded member
          simp [newTerm] at bound
        · simp [newVotes, Function.update, termEq]
      · simp [newVotes, voterEq]
    · intro term
      exact prefixRefl (canonicalHistory term)
    · intro history canonical
      exact canonical
  have voteFactsAfter :
      VoteHistoryFacts (timeoutEffect state node) newVotes := by
    constructor
    · intro voter
      by_cases voterEq : voter = node
      · subst voter
        have newTermNe : Not (newTerm = BOOTSTRAP_TERM) := by
          have participating : Not ((state.nodes node).role = .none) := by
            rcases enabled.2 with follower | preVoteCandidate | candidate
            · rw [follower]
              decide
            · rw [preVoteCandidate]
              decide
            · rw [candidate]
              decide
          have positive := facts.currentTermsPositive node participating
          simp [newTerm]
          omega
        simp [
          newVotes, Function.update, Ne.symm newTermNe,
          facts.voteHistory.bootstrapEmpty
        ]
      · simpa [newVotes, Function.update, voterEq]
          using facts.voteHistory.bootstrapEmpty voter
    · intro voter
      by_cases voterEq : voter = node
      · subst voter
        simp [newVotes, Function.update, termNode, votedNode]
      · simp only [newVotes, Function.update, voterEq]
        simpa [
          termOther voter voterEq, votedOther voter voterEq
        ] using facts.voteHistory.current voter
    · intro voter term future
      by_cases voterEq : voter = node
      · subst voter
        rw [termNode] at future
        by_cases termEq : term = newTerm
        · omega
        · simpa [newVotes, Function.update, termEq]
            using facts.voteHistory.future node term
              (by simp [newTerm] at future ⊢; omega)
      · simp only [newVotes, Function.update, voterEq]
        exact
          facts.voteHistory.future voter term
            (by simpa [termOther voter voterEq] using future)
    · intro candidate voter active member
      by_cases candidateEq : candidate = node
      · subst candidate
        have voterEq : voter = node := by simpa [votesNode] using member
        subst voter
        simp [newVotes, Function.update, termNode]
      · have oldRecorded :=
          facts.voteHistory.counted candidate voter
            (by simpa [roleOther candidate candidateEq] using active)
            (by simpa [votesOther candidate candidateEq] using member)
        by_cases voterEq : voter = node
        · subst voter
          have termNe :
              Not ((state.nodes candidate).currentTerm = newTerm) := by
            intro sameTerm
            have futureEmpty :=
              facts.voteHistory.future
                node (state.nodes candidate).currentTerm
                (by simp [newTerm] at sameTerm ⊢; omega)
            rw [oldRecorded] at futureEmpty
            contradiction
          simpa [
            newVotes, Function.update,
            termOther candidate candidateEq, termNe
          ] using oldRecorded
        · simp only [newVotes, Function.update, voterEq]
          simpa [termOther candidate candidateEq] using oldRecorded
  have committedSignatureAfter :
      CommittedFrontierIsSignature
        (timeoutEffect state node) := by
    intro candidate positive
    have oldPositive : 0 < (state.nodes candidate).commitIndex := by
      simpa [commitEq] using positive
    simpa [logEq, commitEq]
      using invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
        facts candidate oldPositive
  have entriesBoundedAfter :
      EntriesDoNotExceedCurrentTerm
        (timeoutEffect state node) := by
    intro candidate entry member
    rw [logEq] at member
    by_cases candidateEq : candidate = node
    · subst candidate
      rw [termNode]
      exact (facts.entriesDoNotExceedCurrentTerm node entry member).trans
        (by simp [newTerm])
    · rw [termOther candidate candidateEq]
      exact facts.entriesDoNotExceedCurrentTerm candidate entry member
  have voteCanonicalAfter :
      GrantedVoteCanonicalSnapshots
        (timeoutEffect state node)
        canonicalHistory voteCandidateHistory voteVoterHistory := by
    intro candidate voter active member
    by_cases candidateEq : candidate = node
    · subst candidate
      left
      have voterIn : voter ∈ ({node} : Finset Node) :=
        effectiveElectionVotersNode member
      simpa using voterIn
    · have oldActive :
          (state.nodes candidate).role = .candidate \/
            (state.nodes candidate).role = .leader := by
        rw [roleOther candidate candidateEq] at active
        exact active
      have oldMember :
          voter ∈ effectiveElectionVoters state candidate := by
        rw [effectiveElectionVotersOtherEq candidate candidateEq] at member
        exact member
      simpa [termOther candidate candidateEq]
        using voteCanonicalFacts candidate voter oldActive oldMember
  have configurationFactsAfter :
      ElectionConfigurationFacts
        (timeoutEffect state node) elections activations := by
    constructor
    · exact configurationFacts.ballotCommittedFrontierSignature
    · exact configurationFacts.ballotCurrentAuthorityActivation
    · exact configurationFacts.ballotCurrentAuthorityActive
    · exact activationSupporterCurrentAfter
    · intro term record candidate recorded role candidateTerm majority
      by_cases candidateEq : candidate = node
      · subst candidate
        have targetTerm : term = newTerm := by simpa [termNode] using candidateTerm.symm
        have recordedNew :
            elections newTerm = some record := by
          simpa [targetTerm] using recorded
        have shared :=
          futureElectionRecordSharedConfigurationCoverage
            (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
              facts)
            ownership electionFacts
            configurationFacts activationQuorums.history
            activationCanonical activationElections
            configurationActivations recordedNew
            (candidate := node)
            (term := newTerm)
            (by simp [newTerm])
            (timeoutFutureMajority
              (effectiveElectionMajorityImpliesPotential
                (timeoutEffect state node) node majority))
        rcases shared with
          ⟨configuration, ballotMember, candidateMember⟩
        exact ⟨
          configuration,
          ballotMember,
          by simpa [activeConfigurationsEq] using candidateMember
        ⟩
      · have oldRole : (state.nodes candidate).role = .candidate := by
          simpa [roleOther candidate candidateEq] using role
        have oldTerm :
            (state.nodes candidate).currentTerm = term := by
          simpa [termOther candidate candidateEq] using candidateTerm
        have oldMajority :=
          (effectiveElectionMajorityOtherEq candidate candidateEq).mp majority
        rcases
            configurationFacts.potentialShared
              term record candidate recorded oldRole oldTerm oldMajority with
          ⟨configuration, ballotMember, candidateMember⟩
        exact ⟨
          configuration,
          ballotMember,
          by simpa [activeConfigurationsEq] using candidateMember
        ⟩
    · intro left right leftRole rightRole sameTerm
        leftMajority rightMajority
      rcases
          potentialCandidatesSharedConfigurationCoverage
            committedSignatureAfter entriesBoundedAfter
            snapshotsAfter voteCanonicalAfter ownershipAfter
            electionFactsAfter activationQuorums.history
            activationSupporterCurrentAfter activationVoteHistoryAfter
            activationCanonical activationElectionsAfter
            configurationActivationsAfter
            leftRole rightRole sameTerm
            (effectiveElectionMajorityImpliesPotential
              (timeoutEffect state node) left leftMajority)
            (effectiveElectionMajorityImpliesPotential
              (timeoutEffect state node) right rightMajority) with
        ⟨configuration, leftActive, rightActive⟩
      exact ⟨configuration, leftActive, rightActive⟩
    · intro candidate role entry member
      by_cases candidateEq : candidate = node
      · subst candidate
        have bounded :=
          facts.entriesDoNotExceedCurrentTerm node entry
            (by simpa [logEq] using member)
        rw [termNode]
        omega
      · simpa [termOther candidate candidateEq]
          using configurationFacts.candidateEntriesBeforeTerm
            candidate
            (by simpa [roleOther candidate candidateEq] using role)
            entry
            (by simpa [logEq] using member)
  have activationQuorumsAfter :
      ActivationQuorumFacts
        (timeoutEffect state node)
        appendHistory responseHistory elections activations := by
    constructor
    · exact activationQuorums.history
    · intro source index role current signature potential
        term record recorded later
      exact Or.inl
        (potentialPrefixInElectionRecordsFromActivationHistory
          (by
            intro candidate participating
            by_cases candidateEq : candidate = node
            · subst candidate
              rw [termNode]
              have participating : Not ((state.nodes node).role = .none) := by
                rcases enabled.2 with
                  follower | preVoteCandidate | candidate
                · rw [follower]
                  decide
                · rw [preVoteCandidate]
                  decide
                · rw [candidate]
                  decide
              have positive :=
                facts.currentTermsPositive node participating
              simp [newTerm]
              omega
            · rw [termOther candidate candidateEq]
              apply facts.currentTermsPositive candidate
              intro none
              apply participating
              simpa [roleOther candidate candidateEq] using none)
          (by
            intro candidate entry member
            rw [logEq] at member
            by_cases candidateEq : candidate = node
            · subst candidate
              rw [termNode]
              exact
                (facts.entriesDoNotExceedCurrentTerm node entry member).trans
                  (by simp [newTerm])
            · rw [termOther candidate candidateEq]
              exact facts.entriesDoNotExceedCurrentTerm candidate entry member)
          voteFactsAfter ownershipAfter electionFactsAfter
          configurationFactsAfter activationQuorums.history
          activationProgressAfter ackerActivationAfter
          temporalFacts.2.2 activationCanonical activationElectionsAfter
          configurationActivationsAfter evidenceAfter prospectiveAfter
          role current signature potential term record recorded later)
    · intro source index role current signature potential
        candidate candidateRole candidateMajority later
      by_cases candidateEq : candidate = node
      · subst candidate
        exact Or.inl
          (timeoutCandidateBridge
            candidateMajority
            source index role current signature potential
            (by simpa [termNode] using later))
      · have oldCandidateRole :
            (state.nodes candidate).role = .candidate := by
          simpa [roleOther candidate candidateEq] using candidateRole
        have oldCandidateMajority :=
          potentialElectionMajorityOtherBack
            candidate candidateEq candidateMajority
        have sourceNe : Not (source = node) := by
          intro same
          subst source
          exact Role.noConfusion (role.symm.trans roleNode)
        have oldPotential :=
          timeoutPotentialMajorityBack source index role potential
        rcases
            activationQuorums.candidateBridge
              source index
              (by simpa [roleOther source sourceNe] using role)
              (by simpa [logEq, termOther source sourceNe] using current)
              (by simpa [logEq] using signature)
              oldPotential candidate oldCandidateRole oldCandidateMajority
              (by simpa [
                termOther source sourceNe,
                termOther candidate candidateEq
              ] using later) with
          direct | shared
        · exact Or.inl (by simpa [logEq] using direct)
        · rcases shared with
            ⟨configuration, sourceActive, governs, candidateActive⟩
          exact Or.inr
            ⟨configuration,
              by simpa [activeConfigurationsEq] using sourceActive,
              governs,
              by simpa [activeConfigurationsEq] using candidateActive⟩
    · intro source index role current signature majority candidate
      have sourceNe : Not (source = node) := by
        intro same
        subst source
        exact Role.noConfusion (role.symm.trans roleNode)
      rcases
          activationQuorums.committedBridge
            source index
            (by simpa [roleOther source sourceNe] using role)
            (by simpa [logEq, termOther source sourceNe] using current)
            (by simpa [logEq] using signature)
            ((effectiveMajorityEq source sourceNe index).mp majority)
            candidate with
        direct | direct | shared
      · exact Or.inl (by simpa [logEq, committedEq] using direct)
      · exact Or.inr (Or.inl
          (by simpa [logEq, committedEq] using direct))
      · rcases shared with
          ⟨configuration, active, governs, configurationEq⟩
        exact Or.inr (Or.inr
          ⟨configuration,
            by simpa [activeConfigurationsEq] using active,
            governs,
            by
              unfold currentConfiguration at configurationEq ⊢
              simpa [commitEq, logEq] using configurationEq⟩)
    · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
        right rightIndex rightRole rightCurrent rightSignature rightMajority
      have leftNe : Not (left = node) := by
        intro same
        subst left
        exact Role.noConfusion (leftRole.symm.trans roleNode)
      have rightNe : Not (right = node) := by
        intro same
        subst right
        exact Role.noConfusion (rightRole.symm.trans roleNode)
      rcases
          activationQuorums.potentialBridge
            left leftIndex
            (by simpa [roleOther left leftNe] using leftRole)
            (by simpa [logEq, termOther left leftNe] using leftCurrent)
            (by simpa [logEq] using leftSignature)
            ((effectiveMajorityEq left leftNe leftIndex).mp leftMajority)
            right rightIndex
            (by simpa [roleOther right rightNe] using rightRole)
            (by simpa [logEq, termOther right rightNe] using rightCurrent)
            (by simpa [logEq] using rightSignature)
            ((effectiveMajorityEq right rightNe rightIndex).mp rightMajority) with
        direct | direct | shared
      · exact Or.inl (by simpa [logEq] using direct)
      · exact Or.inr (Or.inl (by simpa [logEq] using direct))
      · rcases shared with
          ⟨configuration, leftActive, leftGoverns,
            rightActive, rightGoverns⟩
        exact Or.inr (Or.inr
          ⟨configuration,
            by simpa [activeConfigurationsEq] using leftActive,
            leftGoverns,
            by simpa [activeConfigurationsEq] using rightActive,
            rightGoverns⟩)
    · intro activationIndex activation queuedDestination queuedRequest
        stored queued sameTerm
      exact
        activationQuorums.queuedComparable
          activationIndex activation queuedDestination queuedRequest
          stored
          (by simpa [view_effects] using queued)
          sameTerm
    · exact
        committedConfigurationCoverageFrame
          activationQuorums.committedCoverage logEq commitEq
          (fun candidate => by
            by_cases candidateEq : candidate = node
            · subst candidate
              rw [termNode]
              simp [newTerm]
            · exact Nat.le_of_eq (termOther candidate candidateEq).symm)
    · apply
        queuedConfigurationCoverageFrame
          activationQuorums.queuedCoverage
          (afterAppendHistory := appendHistory)
      · intro queuedDestination queuedRequest queued
        simpa [view_effects] using queued
      · intro _
        rfl
  · refine ⟨
      owners,
      canonicalHistory,
      elections,
      activations,
      nodeEvidence,
      requestEvidence,
      ?_,
      ?_,
      configurationFactsAfter,
      ?_,
      ?_,
      ?_,
      activationVoteHistoryAfter,
      ?_,
      ?_,
      ?_,
      activationProgressAfter,
      activationQuorumsAfter,
      evidenceAfter,
      prospectiveAfter,
      activationEvidenceAfter,
      activationCanonical,
      activationElectionsAfter,
      configurationActivationsAfter
    ⟩
    exact ownershipAfter
    · exact electionFactsAfter
    · exact voteCanonicalAfter
    · exact temporalFacts.1
    · exact temporalFacts.2.1
    · exact temporalFacts.2.2
    · exact ackerActivationAfter
    · intro queuedDestination request member record recorded
      exact
        electionQueuedFacts
          queuedDestination request
            (by simpa [view_effects] using member)
            record recorded
  · exact snapshotsAfter
  · refine ⟨ackHistory, ?_⟩
    constructor
    · intro leader role peer zero
      have leaderNe : Not (leader = node) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleNode)
      exact
        ackFacts.zero leader
          (by simpa [roleOther leader leaderNe] using role)
          peer (by simpa [matchEq] using zero)
    · intro leader role peer positive
      have leaderNe : Not (leader = node) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleNode)
      rcases
          ackFacts.positive leader
            (by simpa [roleOther leader leaderNe] using role)
            peer (by simpa [matchEq] using positive) with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      exact ⟨
        snapshot,
        stored,
        by simpa [termOther leader leaderNe] using snapshotTerm,
        by simpa [matchEq] using snapshotIndex,
        historyBound,
        by simpa [logEq] using agreed
      ⟩
  · constructor
    · intro candidate peer member
      exact
        facts.joinedCarriers.activeNodes candidate
          (by
            simpa [activeNodeUnion, activeConfigurationsEq] using member)
    · intro candidate configuration member peer inNodes
      exact
        facts.joinedCarriers.configurationNodes candidate configuration
          (by simpa [logEq] using member) inNodes
    · intro candidate peer member
      by_cases candidateEq : candidate = node
      · subst candidate
        have peerEq : peer = node := by simpa [view_effects] using member
        subst peer
        exact (facts.allocatedNodesExactlyJoined node).mp enabled.1
      · exact
          facts.joinedCarriers.grantedVotes candidate
            (by simpa [
              view_effects, updateNode,
              Function.update, candidateEq
            ] using member)
    · intro destination request member
      exact
        facts.joinedCarriers.voteRequestDestinations
          destination request
          (by simpa [view_effects] using member)
    · intro destination request member
      exact
        facts.joinedCarriers.appendRequestDestinations
          destination request
          (by simpa [view_effects] using member)
    · intro destination request member configuration configured peer inNodes
      exact
        facts.joinedCarriers.appendRequestConfigurations
          destination request
            (by simpa [view_effects] using member)
          configuration configured inNodes
    · intro destination response member
      exact
        facts.joinedCarriers.voteResponseSources
          destination response
          (by simpa [view_effects] using member)
    · constructor
      · intro candidate active
        by_cases same : candidate = node
        · subst candidate
          exact (facts.allocatedNodesExactlyJoined node).mp enabled.1
        · exact
            facts.joinedCarriers.runtimeNodes.activeRoles candidate
              (by simpa [roleOther candidate same] using active)
      · intro leader peer positive
        exact
          facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
            (by simpa [matchEq] using positive)
      · intro destination response member
        exact
          facts.joinedCarriers.runtimeNodes.appendResponses
            destination response
              (by simpa [view_effects] using member)
      · intro candidate nonempty
        exact
          facts.joinedCarriers.runtimeNodes.nonemptyLogs candidate
            (by simpa [logEq] using nonempty)
  · exact fun _ => Iff.rfl
  · intro candidate
    by_cases same : candidate = node
    · subst candidate
      rw [termNode]
      exact Or.inr newTermAboveBootstrap.le
    · rw [termOther candidate same]
      exact facts.currentTermsValid candidate
  · exact facts.networkTermsValid

/-- A pre-vote-capable timeout starts a regular election when not enabled. -/
lemma timeoutPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : (state.allocated node
          /\ ((state.nodes node).role = .follower
              \/ (state.nodes node).role = .preVoteCandidate
              \/ (state.nodes node).role = .candidate)
          /\ ((node ∈ activeNodeUnion (state.nodes node)
                /\ campaignEligible node (state.nodes node))
              \/ node ∈ (state.nodes node).retirementCompleted)
          /\ Not ((state.nodes node).membershipState = .retiredCommitted)
          /\ Not (INITIAL_PRE_VOTE_STATUS node = .enabled)))
    : SystemInductiveInvariant (timeoutEffect state node) :=
  candidateTransitionPreservesSystemInductiveInvariant
    state node invariant
    ⟨enabled.1, enabled.2.1⟩

/-- A successful pre-vote starts the view_effects regular election term. -/
lemma becomeCandidatePreservesSystemInductiveInvariant
    (state : View Node TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : (state.allocated node
          /\ (state.nodes node).role = .preVoteCandidate
          /\ ((node ∈ activeNodeUnion (state.nodes node)
                /\ campaignEligible node (state.nodes node))
              \/ node ∈ (state.nodes node).retirementCompleted)
          /\ Not ((state.nodes node).membershipState = .retiredCommitted)
          /\ INITIAL_PRE_VOTE_STATUS node = .enabled
          /\ hasPreVoteMajority state node))
    : SystemInductiveInvariant (becomeCandidateEffect state node) := by
  have preserved :=
    candidateTransitionPreservesSystemInductiveInvariant
      state node invariant
        ⟨enabled.1, Or.inr (Or.inl enabled.2.1)⟩
  simpa [view_effects] using preserved

end CCFRaft.Proofs.Invariant
