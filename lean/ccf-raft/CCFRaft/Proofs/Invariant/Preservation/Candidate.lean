-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.AppendSend
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

/--
After a timeout, every potential voter for the fresh self-ballot was already a
supporter for that exact future term in the pre-state.
-/
lemma timeoutPotentialElectionVotersSubsetFuture
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    : potentialElectionVoters (joined := joinedNodes) (timeoutEffect state node) node
      ⊆ futureElectionVoters (joined := joinedNodes) state node (((nodeOf state) node).currentTerm + 1) := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  intro voter member
  simp only [
    potentialElectionVoters, Finset.mem_filter] at member
  simp only [
    futureElectionVoters, Finset.mem_filter]
  rcases member with ⟨joined, effective | eligible⟩
  · refine ⟨by simpa [concrete_effects, becomeCandidateState, present] using joined, ?_⟩
    simp only [
      effectiveElectionVoters, Finset.mem_filter] at effective
    rcases effective with ⟨_joined, processed | queued⟩
    · have voterEq : voter = node := by simpa [concrete_effects, becomeCandidateState, present] using processed
      exact Or.inl voterEq
    · rcases queued with
        ⟨response, queued, granted, responseTerm,
          responseSource, responseDestination⟩
      have oldQueued :
          (voteResponseEnvelope response ∈ state.network /\ response.2.1 = node) := by
        simpa [concrete_effects, becomeCandidateState, present] using queued
      have oldBound :=
        (facts.networkHistory.voteResponse
          node response oldQueued granted).1
      rw [responseDestination] at oldBound
      simp [concrete_effects, becomeCandidateState, present] at responseTerm
      omega
  · refine ⟨by simpa [concrete_effects, becomeCandidateState, present] using joined, ?_⟩
    by_cases voterEq : voter = node
    · exact Or.inl voterEq
    · right
      simp only [currentlyEligibleElectionVoter] at eligible
      refine ⟨?_, ?_⟩
      · have sameTerm := eligible.1
        simp [
          concrete_effects, becomeCandidateState, present, nodeOf_replaceNode, voterEq,
          voteRequestKey, Model.Local.makeRequestVoteRequest
        ] at sameTerm
        omega
      · simpa [
          concrete_effects, becomeCandidateState, present, nodeOf_replaceNode,
          Function.update, voterEq,
          voteRequestKey, Model.Local.makeRequestVoteRequest,
          voteLogUpToDate, lastCommittableTerm, lastCommittableIndex
        ] using eligible.2.1

/-- Entering a successor election preserves the arbitrary-term invariant. -/
lemma candidateTransitionPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : node ∈ joinedNodes
        /\ (((nodeOf state) node).role = .follower
            \/ ((nodeOf state) node).role = .preVoteCandidate
            \/ ((nodeOf state) node).role = .candidate))
    : SystemInductiveInvariant (joined := joinedNodes) (timeoutEffect state node) := by
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
  let newTerm := ((nodeOf state) node).currentTerm + 1
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
      Not (((nodeOf state) node).role = .leader) := by
    rcases enabled.2 with follower | preVoteCandidate | candidate
    · exact fun leader => Role.noConfusion (follower.symm.trans leader)
    · exact
        fun leader =>
          Role.noConfusion (preVoteCandidate.symm.trans leader)
    · exact fun leader => Role.noConfusion (candidate.symm.trans leader)
  have roleNode :
      ((nodeOf (timeoutEffect state node)) node).role = .candidate := by
    simp [concrete_effects, becomeCandidateState, present]
  have roleOther :
      forall candidate,
        Not (candidate = node) ->
        ((nodeOf (timeoutEffect state node)) candidate).role =
          ((nodeOf state) candidate).role := by
    intro candidate different
    simp [
      concrete_effects, becomeCandidateState, present, nodeOf_replaceNode, different
    ]
  have termNode :
      ((nodeOf (timeoutEffect state node)) node).currentTerm = newTerm := by
    simp [concrete_effects, becomeCandidateState, present, newTerm]
  have termOther :
      forall candidate,
        Not (candidate = node) ->
        ((nodeOf (timeoutEffect state node)) candidate).currentTerm =
          ((nodeOf state) candidate).currentTerm := by
    intro candidate different
    simp [
      concrete_effects, becomeCandidateState, present, nodeOf_replaceNode, different
    ]
  have logEq :
      forall candidate,
        ((nodeOf (timeoutEffect state node)) candidate).log =
          ((nodeOf state) candidate).log := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        concrete_effects, becomeCandidateState, present, nodeOf_replaceNode, same
      ]
  have commitEq :
      forall candidate,
        ((nodeOf (timeoutEffect state node)) candidate).commitIndex =
          ((nodeOf state) candidate).commitIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        concrete_effects, becomeCandidateState, present, nodeOf_replaceNode, same
      ]
  have lastIndexEq :
      forall candidate,
        lastCommittableIndex
            ((nodeOf (timeoutEffect state node)) candidate) =
          lastCommittableIndex ((nodeOf state) candidate) := by
    intro candidate
    exact lastCommittableIndexFrame (logEq candidate) (commitEq candidate)
  have lastTermEq :
      forall candidate,
        lastCommittableTerm
            ((nodeOf (timeoutEffect state node)) candidate) =
          lastCommittableTerm ((nodeOf state) candidate) := by
    intro candidate
    exact lastCommittableTermFrame (logEq candidate) (commitEq candidate)
  have committedEq :
      forall candidate,
        ((nodeOf (timeoutEffect state node)) candidate).committedLog =
          ((nodeOf state) candidate).committedLog := by
    intro candidate
    simp [NodeState.committedLog, commitEq, logEq]
  have activeConfigurationsEq :
      forall candidate,
        activeConfigurations
            ((nodeOf (timeoutEffect state node)) candidate) =
          activeConfigurations ((nodeOf state) candidate) := by
    intro candidate
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have sentEq :
      forall candidate,
        ((nodeOf (timeoutEffect state node)) candidate).sentIndex =
          ((nodeOf state) candidate).sentIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        concrete_effects, becomeCandidateState, present, nodeOf_replaceNode, same
      ]
  have matchEq :
      forall candidate,
        ((nodeOf (timeoutEffect state node)) candidate).matchIndex =
          ((nodeOf state) candidate).matchIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        concrete_effects, becomeCandidateState, present, nodeOf_replaceNode, same
      ]
  have votedNode :
      ((nodeOf (timeoutEffect state node)) node).votedFor = some node := by
    simp [concrete_effects, becomeCandidateState, present]
  have votesNode :
      ((nodeOf (timeoutEffect state node)) node).votesGranted = {node} := by
    simp [concrete_effects, becomeCandidateState, present]
  have votedOther :
      forall candidate,
        Not (candidate = node) ->
        ((nodeOf (timeoutEffect state node)) candidate).votedFor =
          ((nodeOf state) candidate).votedFor := by
    intro candidate different
    simp [
      concrete_effects, becomeCandidateState, present, nodeOf_replaceNode, different
    ]
  have votesOther :
      forall candidate,
        Not (candidate = node) ->
        ((nodeOf (timeoutEffect state node)) candidate).votesGranted =
          ((nodeOf state) candidate).votesGranted := by
    intro candidate different
    simp [
      concrete_effects, becomeCandidateState, present, nodeOf_replaceNode, different
    ]
  have effectiveAckersEq :
      forall leader,
        Not (leader = node) ->
          forall index,
            effectiveAckers (joined := joinedNodes)
                (timeoutEffect state node)
                responseHistory leader index =
              effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
    intro leader leaderNe index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter]
    constructor
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨by simpa [concrete_effects, becomeCandidateState, present] using joined, Or.inl self⟩
      · exact ⟨
          by simpa [concrete_effects, becomeCandidateState, present] using joined,
          Or.inr (Or.inl (by simpa [matchEq] using matched))
        ⟩
      · refine ⟨
          by simpa [concrete_effects, becomeCandidateState, present] using joined,
          Or.inr (Or.inr ?_)
        ⟩
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact ⟨
          response,
          by simpa [concrete_effects, becomeCandidateState, present] using member,
          success,
          by simpa [termOther leader leaderNe] using term,
          sourceEq,
          destinationEq,
          lastIndex,
          by simpa [logEq] using covered
        ⟩
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨by simpa [concrete_effects, becomeCandidateState, present] using joined, Or.inl self⟩
      · exact ⟨
          by simpa [concrete_effects, becomeCandidateState, present] using joined,
          Or.inr (Or.inl (by simpa [matchEq] using matched))
        ⟩
      · refine ⟨
          by simpa [concrete_effects, becomeCandidateState, present] using joined,
          Or.inr (Or.inr ?_)
        ⟩
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact ⟨
          response,
          by simpa [concrete_effects, becomeCandidateState, present] using member,
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
            hasEffectiveMajorityAt (joined := joinedNodes)
                (timeoutEffect state node)
                responseHistory leader index ↔
              hasEffectiveMajorityAt (joined := joinedNodes) state responseHistory leader index := by
    intro leader leaderNe index
    simp only [
      hasEffectiveMajorityAt, activeConfigurationsEq,
      effectiveAckersEq leader leaderNe index
    ]
  have effectiveElectionVotersNode :
      effectiveElectionVoters (joined := joinedNodes)
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
          (voteResponseEnvelope response ∈ state.network /\ response.2.1 = node) := by
        simpa [concrete_effects, becomeCandidateState, present] using member
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
          effectiveElectionVoters (joined := joinedNodes)
              (timeoutEffect state node) candidate =
            effectiveElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate candidateNe
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [concrete_effects, becomeCandidateState, present] using joined,
          Or.inl (by simpa [votesOther candidate candidateNe] using processed)
        ⟩
      · refine ⟨
          by simpa [concrete_effects, becomeCandidateState, present] using joined,
          Or.inr ?_
        ⟩
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact ⟨
          response,
          by simpa [concrete_effects, becomeCandidateState, present] using member,
          granted,
          by simpa [termOther candidate candidateNe] using responseTerm,
          responseSource,
          responseDestination
        ⟩
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [concrete_effects, becomeCandidateState, present] using joined,
          Or.inl (by simpa [votesOther candidate candidateNe] using processed)
        ⟩
      · refine ⟨
          by simpa [concrete_effects, becomeCandidateState, present] using joined,
          Or.inr ?_
        ⟩
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact ⟨
          response,
          by simpa [concrete_effects, becomeCandidateState, present] using member,
          granted,
          by simpa [termOther candidate candidateNe] using responseTerm,
          responseSource,
          responseDestination
        ⟩
  have effectiveElectionMajorityOtherEq :
      forall candidate,
        Not (candidate = node) ->
        (hasEffectiveElectionMajority (joined := joinedNodes)
            (timeoutEffect state node) candidate ↔
          hasEffectiveElectionMajority (joined := joinedNodes) state candidate) := by
    intro candidate candidateNe
    simp only [
      hasEffectiveElectionMajority, activeConfigurationsEq,
      effectiveElectionVotersOtherEq candidate candidateNe
    ]
  have potentialElectionVotersOtherSubset :
      forall candidate,
        Not (candidate = node) ->
          potentialElectionVoters (joined := joinedNodes)
              (timeoutEffect state node) candidate ⊆
            potentialElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate candidateNe voter member
    simp only [
      potentialElectionVoters, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | eligible⟩
    · exact ⟨by simpa [concrete_effects, becomeCandidateState, present] using joined, Or.inl
        (by
          rw [effectiveElectionVotersOtherEq candidate candidateNe] at effective
          exact effective)⟩
    · refine ⟨by simpa [concrete_effects, becomeCandidateState, present] using joined, Or.inr ?_⟩
      by_cases voterEq : voter = node
      · subst voter
        simp only [currentlyEligibleElectionVoter] at eligible
        have voteChoice := eligible.2.2
        simp [concrete_effects, becomeCandidateState, present] at voteChoice
        exact False.elim (candidateNe voteChoice.symm)
      · simpa [
          currentlyEligibleElectionVoter,
          voteRequestKey, Model.Local.makeRequestVoteRequest,
          termOther candidate candidateNe,
          termOther voter voterEq,
          logEq, lastIndexEq, lastTermEq,
          votedOther voter voterEq,
          voteLogUpToDate
        ] using eligible
  have potentialElectionMajorityOtherBack :
      forall candidate,
        Not (candidate = node) ->
        hasPotentialElectionMajority (joined := joinedNodes)
            (timeoutEffect state node) candidate ->
          hasPotentialElectionMajority (joined := joinedNodes) state candidate := by
    intro candidate candidateNe majority
    exact
      potentialElectionMajorityOfSubset
        (potentialElectionVotersOtherSubset candidate candidateNe)
        (activeConfigurationsEq candidate)
        majority
  have newTermAboveBootstrap : BOOTSTRAP_TERM < newTerm := by
    have participating : Not (((nodeOf state) node).role = .none) := by
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
      GrantedVoteSnapshots (joined := joinedNodes)
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
          ((nodeOf state) candidate).role = .candidate \/
            ((nodeOf state) candidate).role = .leader := by
        rw [roleOther candidate candidateEq] at active
        exact active
      rw [termOther candidate candidateEq]
      have oldMember :
          voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
        rw [effectiveElectionVotersOtherEq candidate candidateEq] at member
        exact member
      rcases
          facts.grantedVoteSnapshots
            candidate voter oldActive oldMember with
        ⟨recorded, self | snapshot⟩
      all_goals
        have newRecorded :
            newVotes voter ((nodeOf state) candidate).currentTerm =
              some candidate := by
          by_cases voterEq : voter = node
          · rw [voterEq] at recorded ⊢
            have termNe :
                Not (((nodeOf state) candidate).currentTerm = newTerm) := by
              intro sameTerm
              have futureEmpty :=
                facts.voteHistory.future
                  node ((nodeOf state) candidate).currentTerm
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
    · have oldRole : ((nodeOf state) candidate).role = .candidate := by
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
            ((nodeOf state) candidate).role = .candidate \/
              ((nodeOf state) candidate).role = .leader := by
          rw [roleOther candidate candidateEq] at active
          exact active
        rw [votesOther candidate candidateEq] at member
        have oldCounted :=
          facts.voteHistory.counted candidate voter oldActive member
        rw [termOther candidate candidateEq]
        by_cases voterEq : voter = node
        · subst voter
          have termNe :
              Not (((nodeOf state) candidate).currentTerm = newTerm) := by
            intro sameTerm
            have empty :=
              facts.voteHistory.future
                node ((nodeOf state) candidate).currentTerm
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
          (appendResponseEnvelope response ∈ state.network /\ response.2.1 = destination) := by
        simpa [concrete_effects, becomeCandidateState, present] using member
      have responseDestination :
          response.2.1 = destination := by
        simpa using
          facts.networkHistory.addressed
            destination (appendResponseEnvelope response) oldMember
      subst destination
      rcases
          facts.networkHistory.appendResponse response.2.1 response
            oldMember success with
        ⟨lengthBound, termBound, supported⟩
      refine ⟨lengthBound, ?_, ?_⟩
      · by_cases destinationEq : response.2.1 = node
        · rw [destinationEq, termNode]
          rw [destinationEq] at termBound
          simp [newTerm]
          omega
        · simpa [termOther response.2.1 destinationEq] using termBound
      intro sameTerm
      by_cases destinationEq : response.2.1 = node
      · have impossibleOldTerm :
            response.2.2.term >
              ((nodeOf state) response.2.1).currentTerm := by
          rw [destinationEq, termNode] at sameTerm
          rw [destinationEq]
          simp [newTerm] at sameTerm ⊢
          omega
        exact False.elim (Nat.not_lt_of_ge termBound impossibleOldTerm)
      · have oldTerm :
            response.2.2.term =
              ((nodeOf state) response.2.1).currentTerm := by
          simpa [termOther response.2.1 destinationEq] using sameTerm
        rcases supported oldTerm with active | follower | preVoteCandidate
        · exact Or.inl
            ⟨by
                simpa [roleOther response.2.1 destinationEq] using
                  active.1,
              by simpa [logEq] using active.2⟩
        · exact Or.inr
            (Or.inl (by
              simpa [roleOther response.2.1 destinationEq] using
                follower))
        · exact Or.inr
            (Or.inr (by
              simpa [roleOther response.2.1 destinationEq] using
                preVoteCandidate))
    · intro destination request member
      rcases
          facts.networkHistory.voteRequest destination request member with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      refine ⟨lastIndex, lastTerm, maxIndex, aboveBootstrap, ?_, ?_⟩
      · by_cases sourceEq : request.1 = node
        · have oldBound :
              request.2.2.term <= ((nodeOf state) node).currentTerm := by
            simpa [sourceEq] using termBound
          rw [sourceEq, termNode]
          simp [newTerm]
          omega
        · simpa [termOther request.1 sourceEq] using termBound
      · intro sameTerm active
        by_cases sourceEq : request.1 = node
        · have oldBound :
              request.2.2.term <= ((nodeOf state) node).currentTerm := by
            simpa [sourceEq] using termBound
          have newSame :
              request.2.2.term = newTerm := by
            simpa [sourceEq, termNode] using sameTerm
          simp [newTerm] at newSame
          omega
        · have oldPrefix :=
            activePrefix
              (by simpa [termOther request.1 sourceEq] using sameTerm)
              (by simpa [roleOther request.1 sourceEq] using active)
          simpa [logEq] using oldPrefix
    · intro destination response member granted
      rcases
          facts.networkHistory.voteResponse
            destination response member granted with
        ⟨oldBound, oldVote, upToDate⟩
      refine ⟨?_, ?_, upToDate⟩
      · by_cases responseDestinationEq :
            response.2.1 = node
        · rw [responseDestinationEq, termNode]
          rw [responseDestinationEq] at oldBound
          simp [newTerm]
          omega
        · simpa [
            termOther response.2.1 responseDestinationEq
          ] using oldBound
      · by_cases sourceEq : response.1 = node
        · rw [sourceEq] at oldVote ⊢
          by_cases termEq : response.2.2.term = newTerm
          · have empty :=
              facts.voteHistory.future node response.2.2.term (by
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
      simpa [concrete_effects, becomeCandidateState, present] using member
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts (joined := joinedNodes)
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
              simpa [concrete_effects, becomeCandidateState, present] using member)
            known
    · intro member
      simp [logEq]
    · intro evidence supportedPrefix destination request known queued sameTerm
      left
      exact ⟨by simpa [concrete_effects, becomeCandidateState, present] using queued, rfl⟩
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
              simpa [concrete_effects, becomeCandidateState, present] using member)
            known
        have futureMember :
            member ∈ futureElectionVoters (joined := joinedNodes) state node newTerm := by
          simp only [
            relaxedElectionVoters, futureElectionVoters,
            Finset.mem_filter] at relaxed ⊢
          rcases relaxed with ⟨joined, effective | supporter⟩
          · have voterEq : member = node := by
              have voterIn : member ∈ ({node} : Finset Node) :=
                effectiveElectionVotersNode effective
              simpa using voterIn
            exact ⟨
              by simpa [concrete_effects, becomeCandidateState, present] using joined,
              Or.inl voterEq
            ⟩
          · by_cases memberEq : member = node
            · exact ⟨
                by simpa [concrete_effects, becomeCandidateState, present] using joined,
                Or.inl memberEq
              ⟩
            · exact ⟨
                by simpa [concrete_effects, becomeCandidateState, present] using joined,
                Or.inr
                  ⟨
                    by simpa [termOther member memberEq, termNode] using supporter.1,
                    by simpa [
                        voteRequestKey, Model.Local.makeRequestVoteRequest,
                        logEq, lastIndexEq, lastTermEq,
                        voteLogUpToDate
                      ] using supporter.2
                  ⟩
              ⟩
        have oldCandidateBefore :
            ((nodeOf state) node).currentTerm < newTerm := by
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
              by simpa [concrete_effects, becomeCandidateState, present] using joined,
              Or.inl effective
            ⟩
          · refine ⟨
              by simpa [concrete_effects, becomeCandidateState, present] using joined,
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
                voteRequestKey, Model.Local.makeRequestVoteRequest,
                termOther candidate candidateEq,
                logEq, lastIndexEq, lastTermEq,
                voteLogUpToDate
              ] using supporter.2
        · simp [logEq]
  have timeoutVoterSubset :
      potentialElectionVoters (joined := joinedNodes) (timeoutEffect state node) node ⊆
        futureElectionVoters (joined := joinedNodes) state node newTerm := by
    simpa [newTerm]
      using timeoutPotentialElectionVotersSubsetFuture (present := present) state node
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
      hasPotentialElectionMajority (joined := joinedNodes)
          (timeoutEffect state node) node ->
        hasFutureElectionMajority (joined := joinedNodes)
          state node newTerm
            (activeConfigurations ((nodeOf state) node)) := by
    intro majority
    apply
      potentialElectionMajorityImpliesFuture
        timeoutVoterSubset
        (ballotActive :=
          activeConfigurations ((nodeOf state) node))
    · exact (activeConfigurationsEq node).symm
    · exact majority
  have timeoutPotentialVoterTerm :
      forall voter,
        voter ∈
            potentialElectionVoters (joined := joinedNodes)
              (timeoutEffect state node) node ->
          ((nodeOf (timeoutEffect state node)) voter).currentTerm =
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
      simpa [voteRequestKey, Model.Local.makeRequestVoteRequest, termNode] using eligible.1.symm
  have timeoutPotentialAckersSubset :
      forall source index,
        ((nodeOf (timeoutEffect state node)) source).role = .leader ->
        potentialAckers (joined := joinedNodes)
            (timeoutEffect state node)
            appendHistory responseHistory source index ⊆
          potentialAckers (joined := joinedNodes)
            state appendHistory responseHistory source index := by
    intro source index role peer member
    have sourceNe : Not (source = node) := by
      intro same
      subst source
      exact Role.noConfusion (role.symm.trans roleNode)
    simp only [
      potentialAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | reserve⟩
    · refine ⟨by simpa [concrete_effects, becomeCandidateState, present] using joined, Or.inl ?_⟩
      rw [effectiveAckersEq source sourceNe index] at effective
      exact effective
    · refine ⟨by simpa [concrete_effects, becomeCandidateState, present] using joined, Or.inr ?_⟩
      rcases reserve with
        ⟨request, queued, requestSource, requestDestination,
          requestTerm, producible, covered⟩
      have requestDestinationEq := requestDestination
      refine ⟨
        request,
        by simpa [concrete_effects, becomeCandidateState, present] using queued,
        requestSource,
        requestDestination,
        by simpa [termOther source sourceNe] using requestTerm,
        ?_,
        by simpa [logEq] using covered
      ⟩
      by_cases peerEq : peer = node
      · have destinationEq : request.2.1 = node :=
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
                  ((nodeOf state) node).currentTerm < newTerm := by
                simp [newTerm]
              simpa [peerEq] using oldBeforeNew.trans futureTerm,
              future.2⟩
      · simpa [
          concrete_effects, becomeCandidateState, present, nodeOf_replaceNode,
          Function.update, peerEq
        ] using producible
  have timeoutPotentialMajorityBack :
      forall source index,
        ((nodeOf (timeoutEffect state node)) source).role = .leader ->
        hasPotentialMajorityAt (joined := joinedNodes)
            (timeoutEffect state node)
            appendHistory responseHistory source index ->
          hasPotentialMajorityAt (joined := joinedNodes)
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
            ((nodeOf (timeoutEffect state node)) source) := by
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
      hasPotentialElectionMajority (joined := joinedNodes) (timeoutEffect state node) node ->
      forall evidence supportedPrefix,
        KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
        evidence.commitTerm < newTerm ->
          evidence.history.take evidence.commitFrontier <+:
            ((nodeOf (timeoutEffect state node)) node).log := by
    intro candidateMajority evidence supportedPrefix known newer
    have futureMajority := timeoutFutureMajority candidateMajority
    let candidateConfiguration :=
      currentConfiguration ((nodeOf state) node)
    have candidateBefore :
        ((nodeOf state) node).currentTerm < newTerm := by
      simp [newTerm]
    have directOfActive
        (authorityActive :
          evidence.authority ∈
            activeConfigurations ((nodeOf state) node)) :
        evidence.history.take evidence.commitFrontier <+:
          ((nodeOf (timeoutEffect state node)) node).log := by
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
      have commitPositive : 0 < ((nodeOf state) node).commitIndex := by
        exact
          candidatePositive.trans_le
            (by simpa [candidateConfiguration] using
              currentConfiguration_index_le_commitIndex ((nodeOf state) node))
      rcases evidenceFacts.nodePositive node commitPositive with
        ⟨candidateEvidence, candidateStored, candidateValid,
          candidateSupportedLength, _candidateTermBound⟩
      have candidateKnown :
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            candidateEvidence ((nodeOf state) node).committedLog :=
        Or.inl ⟨node, commitPositive, candidateStored, rfl⟩
      have candidateConfigurationKnownCommitted :
          candidateConfiguration ∈
            allConfigurations ((nodeOf state) node).committedLog := by
        unfold NodeState.committedLog
        apply
          allConfigurations_mem_take_of_index_le
            ((nodeOf state) node).log ((nodeOf state) node).commitIndex
        · exact facts.commitIndicesBounded node
        · simpa [candidateConfiguration]
            using currentConfiguration_mem_allConfigurations ((nodeOf state) node)
        · simpa [candidateConfiguration]
            using currentConfiguration_index_le_commitIndex ((nodeOf state) node)
      have committedInEvidence :
          ((nodeOf state) node).committedLog <+:
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
            using currentConfiguration_index_le_commitIndex ((nodeOf state) node)
        have frontierBound :
            candidateConfiguration.index <=
              candidateEvidence.commitFrontier :=
          supportedBound.trans candidateValid.2.2.1
        let evidenceNode : NodeState Node TxId :=
          { (nodeOf state) node with
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
          candidateEvidence ((nodeOf state) node).committedLog candidateKnown
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
            using currentConfiguration_index_le_commitIndex ((nodeOf state) node)
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
            { (nodeOf state) node with
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
          ((nodeOf state) node).committedLog <+:
            ((nodeOf state) node).log := by
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
              { (nodeOf state) node with
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
                (TxId := TxId) ((nodeOf state) node).log
            · simpa [candidateConfiguration]
                using currentConfiguration_mem_allConfigurations ((nodeOf state) node)
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
        using currentConfiguration_mem_activeConfigurations ((nodeOf state) node)
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
            : evidence.authority ∈ allConfigurations ((nodeOf state) node).log := by
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
      hasPotentialElectionMajority (joined := joinedNodes) (timeoutEffect state node) node ->
      forall source index,
        ((nodeOf (timeoutEffect state node)) source).role = .leader ->
        termAt
            ((nodeOf (timeoutEffect state node)) source).log index =
          ((nodeOf (timeoutEffect state node)) source).currentTerm ->
        isSignatureAt
            ((nodeOf (timeoutEffect state node)) source).log index = true ->
        hasPotentialMajorityAt (joined := joinedNodes)
            (timeoutEffect state node)
            appendHistory responseHistory source index ->
        ((nodeOf (timeoutEffect state node)) source).currentTerm < newTerm ->
          ((nodeOf (timeoutEffect state node)) source).log.take index <+:
            ((nodeOf (timeoutEffect state node)) node).log := by
    intro candidateMajority source index role current signature potential lower
    have sourceNe : Not (source = node) := by
      intro same
      subst source
      exact Role.noConfusion (role.symm.trans roleNode)
    have oldRole : ((nodeOf state) source).role = .leader := by
      simpa [roleOther source sourceNe] using role
    have oldCurrent :
        termAt ((nodeOf state) source).log index =
          ((nodeOf state) source).currentTerm := by
      simpa [logEq, termOther source sourceNe] using current
    have oldSignature :
        isSignatureAt ((nodeOf state) source).log index = true := by
      simpa [logEq] using signature
    have oldPotential :=
      timeoutPotentialMajorityBack source index role potential
    have futureMajority := timeoutFutureMajority candidateMajority
    let sourceConfiguration :=
      currentConfiguration ((nodeOf state) source)
    let candidateConfiguration :=
      currentConfiguration ((nodeOf state) node)
    have sourceActive :
        sourceConfiguration ∈
          activeConfigurations
            ((nodeOf (timeoutEffect state node)) source) := by
      simpa [activeConfigurationsEq, sourceConfiguration]
        using currentConfiguration_mem_activeConfigurations ((nodeOf state) source)
    have useCommitted
        (indexCommitted : index <= ((nodeOf state) source).commitIndex) :
        ((nodeOf (timeoutEffect state node)) source).log.take index <+:
          ((nodeOf (timeoutEffect state node)) node).log := by
      rcases isSignatureAtTrue oldSignature with
        ⟨entry, found, _⟩
      have indexPositive : 0 < index := by
        by_contra notPositive
        have indexZero : index = 0 := Nat.eq_zero_of_not_pos notPositive
        subst index
        simp [entryAt?] at found
      have commitPositive : 0 < ((nodeOf state) source).commitIndex := by omega
      rcases evidenceFacts.nodePositive source commitPositive with
        ⟨evidence, stored, valid, _supportedLength, termBound⟩
      have known :
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence ((nodeOf state) source).committedLog :=
        Or.inl ⟨source, commitPositive, stored, rfl⟩
      have sourceBound := entryAtSomeIndexBound found
      have sourceInCommitted :
          ((nodeOf state) source).log.take index <+:
            ((nodeOf state) source).committedLog := by
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
          evidence ((nodeOf state) source).committedLog known
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
              ((nodeOf (timeoutEffect state node)) source))
        (configurationGoverns : configuration.index <= index)
        (candidateConfigurationActive :
          configuration ∈
            activeConfigurations
              ((nodeOf (timeoutEffect state node)) node)) :
        ((nodeOf (timeoutEffect state node)) source).log.take index <+:
          ((nodeOf (timeoutEffect state node)) node).log := by
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
            ((nodeOf state) node).log := by
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
              ((nodeOf state) node))
      rcases Nat.lt_trichotomy
          ((nodeOf state) source).currentTerm
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
                ((nodeOf state) node).log := by
            exact candidateEventInCandidate
          exact (by simpa [logEq] using sourceInActivation.trans activationInCandidate)
      · have activationCanonicalEq :
            candidateActivation.history.take
                candidateActivation.activationFrontier =
              ((nodeOf state) source).log.take
                candidateActivation.activationFrontier := by
          calc
            candidateActivation.history.take candidateActivation.activationFrontier
                = (canonicalHistory candidateActivation.activationTerm).take
                    candidateActivation.activationFrontier :=
              activationCanonical.activationFrontierCanonical
                candidateCoverage.activationIndex candidateActivation
                candidateStored
            _ = ((nodeOf state) source).log.take candidateActivation.activationFrontier := by
              rw [← sameTerm, ownership.activeLeaderHistory source oldRole]
        by_cases indexWithin :
            index <= candidateActivation.activationFrontier
        · have direct :
              ((nodeOf state) source).log.take index <+:
                candidateActivation.history.take
                  candidateActivation.activationFrontier := by
            rw [activationCanonicalEq, List.prefix_take_iff]
            exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans indexWithin⟩
          have activationInCandidate :
              candidateActivation.history.take
                  candidateActivation.activationFrontier <+:
                ((nodeOf state) node).log := by
            exact candidateEventInCandidate
          exact (by simpa [logEq] using direct.trans activationInCandidate)
        · have candidateKnownSource :
              candidateConfiguration ∈
                allConfigurations ((nodeOf state) source).log := by
            have activationPrefixSource :
                candidateActivation.history.take
                    candidateActivation.activationFrontier <+:
                  ((nodeOf state) source).log := by
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
                  ((nodeOf (timeoutEffect state node)) source) := by
            rw [activeConfigurationsEq source]
            simpa [activeConfigurations, sourceConfiguration]
              using And.intro candidateKnownSource sourceBeforeCandidate.le
          exact useShared candidateConfiguration candidateActiveSource
            (candidateWithin.trans (Nat.le_of_not_ge indexWithin))
            (by
              rw [activeConfigurationsEq node]
              simpa [candidateConfiguration]
                using currentConfiguration_mem_activeConfigurations ((nodeOf state) node))
      · have activationInSource :
            candidateActivation.history.take
                candidateActivation.activationFrontier <+:
              ((nodeOf state) source).log := by
          rcases
              electionFacts.ownerRecorded
                ((nodeOf state) source).currentTerm source
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
                  ((nodeOf state) source).currentTerm
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
              sourceEntry.term = ((nodeOf state) source).currentTerm := by
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
            : candidateConfiguration ∈ allConfigurations ((nodeOf state) source).log := by
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
                ((nodeOf (timeoutEffect state node)) source) := by
          rw [activeConfigurationsEq source]
          simpa [activeConfigurations, sourceConfiguration]
            using And.intro candidateKnownSource sourceBeforeCandidate.le
        exact useShared candidateConfiguration candidateActiveSource
          (candidateWithin.trans frontierBeforeIndex.le)
          (by
            rw [activeConfigurationsEq node]
            simpa [candidateConfiguration]
              using currentConfiguration_mem_activeConfigurations ((nodeOf state) node))
    · have sameConfiguration :
          sourceConfiguration = candidateConfiguration := by
        by_cases zero : sourceConfiguration.index = 0
        · have sourceImplicit :
              sourceConfiguration = implicitConfiguration := by
            apply
              allConfigurations_index_unique
                (TxId := TxId) ((nodeOf state) source).log
            · simpa [sourceConfiguration]
                using currentConfiguration_mem_allConfigurations ((nodeOf state) source)
            · simp [allConfigurations, implicitConfiguration]
            · simpa [implicitConfiguration] using zero
          have candidateZero : candidateConfiguration.index = 0 := by
            simpa [sameIndex] using zero
          have candidateImplicit :
              candidateConfiguration = implicitConfiguration := by
            apply
              allConfigurations_index_unique
                (TxId := TxId) ((nodeOf state) node).log
            · simpa [candidateConfiguration]
                using currentConfiguration_mem_allConfigurations ((nodeOf state) node)
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
                  ((nodeOf state) node))
      · apply useCommitted
        have currentBound :=
          currentConfiguration_index_le_commitIndex ((nodeOf state) source)
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
          : sourceConfiguration ∈ allConfigurations ((nodeOf state) node).log := by
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
          currentConfiguration_index_le_commitIndex ((nodeOf state) source)
        dsimp [sourceConfiguration] at sourceGoverns
        omega
  have activationEvidenceAfter :
      ActivationEvidenceFacts (joined := joinedNodes)
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
              simpa [concrete_effects, becomeCandidateState, present] using member)
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
              simpa [concrete_effects, becomeCandidateState, present] using member)
            leftKnown)
          right rightPrefix
          (knownCommitEvidenceFrameBack
            state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [concrete_effects, becomeCandidateState, present] using member)
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
              simpa [concrete_effects, becomeCandidateState, present] using member)
            earlierKnown)
          later laterPrefix
          (knownCommitEvidenceFrameBack
            state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [concrete_effects, becomeCandidateState, present] using member)
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
              simpa [concrete_effects, becomeCandidateState, present] using member)
            leftKnown)
          right rightPrefix
          (knownCommitEvidenceFrameBack
            state (timeoutEffect state node)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun destination request member => by
              simpa [concrete_effects, becomeCandidateState, present] using member)
            rightKnown)
    · intro evidence supportedPrefix known candidate role majority newer
      have oldKnown :=
        knownCommitEvidenceFrameBack
          state (timeoutEffect state node)
          appendHistory nodeEvidence requestEvidence
          commitEq committedEq
          (fun destination request member => by
            simpa [concrete_effects, becomeCandidateState, present] using member)
          known
      by_cases candidateEq : candidate = node
      · subst candidate
        have full :=
          timeoutEvidenceBridge
            majority evidence supportedPrefix oldKnown
            (by simpa [termNode] using newer)
        exact Or.inl full
      · have oldRole : ((nodeOf state) candidate).role = .candidate := by
          simpa [roleOther candidate candidateEq] using role
        have oldMajority :=
          potentialElectionMajorityOtherBack
            candidate candidateEq majority
        have oldNewer :
            evidence.commitTerm <
              ((nodeOf state) candidate).currentTerm := by
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
      AckerActivationHistory (joined := joinedNodes)
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
            (by simpa [concrete_effects, becomeCandidateState, present] using member)
            index entry found
    · intro leader role
      have leaderNe : Not (leader = node) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleNode)
      rw [termOther leader leaderNe]
      have oldRole : ((nodeOf state) leader).role = .leader := by
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
              term = ((nodeOf state) owner).currentTerm := by
            simpa [termOther owner ownerEq] using same
          simpa [roleOther owner ownerEq] using oldLeader oldSame
    · intro destination request member
      exact
        ownership.queuedAppendMetadata destination request
          (by simpa [concrete_effects, becomeCandidateState, present] using member)
    · intro destination request member sameTerm leaderRole
      by_cases sourceEq : request.1 = node
      · have afterLeader :
            ((nodeOf (timeoutEffect state node)) node).role = .leader := by
          simpa [sourceEq] using leaderRole
        exact False.elim
          (Role.noConfusion (afterLeader.symm.trans roleNode))
      · exact (ownership.queuedActiveSourceHistory
                destination request
                (by simpa [concrete_effects, becomeCandidateState, present] using member)
                (by simpa [termOther request.1 sourceEq] using sameTerm)
                (by simpa [roleOther request.1 sourceEq] using leaderRole)).trans
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
          have participating : Not (((nodeOf state) node).role = .none) := by
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
              Not (((nodeOf state) candidate).currentTerm = newTerm) := by
            intro sameTerm
            have futureEmpty :=
              facts.voteHistory.future
                node ((nodeOf state) candidate).currentTerm
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
    have oldPositive : 0 < ((nodeOf state) candidate).commitIndex := by
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
      GrantedVoteCanonicalSnapshots (joined := joinedNodes)
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
          ((nodeOf state) candidate).role = .candidate \/
            ((nodeOf state) candidate).role = .leader := by
        rw [roleOther candidate candidateEq] at active
        exact active
      have oldMember :
          voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
        rw [effectiveElectionVotersOtherEq candidate candidateEq] at member
        exact member
      simpa [termOther candidate candidateEq]
        using voteCanonicalFacts candidate voter oldActive oldMember
  have configurationFactsAfter :
      ElectionConfigurationFacts (joined := joinedNodes)
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
      · have oldRole : ((nodeOf state) candidate).role = .candidate := by
          simpa [roleOther candidate candidateEq] using role
        have oldTerm :
            ((nodeOf state) candidate).currentTerm = term := by
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
      ActivationQuorumFacts (joined := joinedNodes)
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
              have participating : Not (((nodeOf state) node).role = .none) := by
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
            ((nodeOf state) candidate).role = .candidate := by
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
          (by simpa [concrete_effects, becomeCandidateState, present] using queued)
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
        simpa [concrete_effects, becomeCandidateState, present] using queued
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
            (by simpa [concrete_effects, becomeCandidateState, present] using member)
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
        have peerEq : peer = node := by simpa [concrete_effects, becomeCandidateState, present] using member
        subst peer
        exact (facts.allocatedNodesExactlyJoined node).mp enabled.1
      · exact
          facts.joinedCarriers.grantedVotes candidate
            (by simpa [
              concrete_effects, becomeCandidateState, present, nodeOf_replaceNode,
              Function.update, candidateEq
            ] using member)
    · intro destination request member
      exact
        facts.joinedCarriers.voteRequestDestinations
          destination request
          (by simpa [concrete_effects, becomeCandidateState, present] using member)
    · intro destination request member
      exact
        facts.joinedCarriers.appendRequestDestinations
          destination request
          (by simpa [concrete_effects, becomeCandidateState, present] using member)
    · intro destination request member configuration configured peer inNodes
      exact
        facts.joinedCarriers.appendRequestConfigurations
          destination request
            (by simpa [concrete_effects, becomeCandidateState, present] using member)
          configuration configured inNodes
    · intro destination response member
      exact
        facts.joinedCarriers.voteResponseSources
          destination response
          (by simpa [concrete_effects, becomeCandidateState, present] using member)
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
              (by simpa [concrete_effects, becomeCandidateState, present] using member)
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
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : (node ∈ joinedNodes
          /\ (((nodeOf state) node).role = .follower
              \/ ((nodeOf state) node).role = .preVoteCandidate
              \/ ((nodeOf state) node).role = .candidate)
          /\ ((node ∈ activeNodeUnion ((nodeOf state) node)
                /\ campaignEligible node ((nodeOf state) node))
              \/ node ∈ ((nodeOf state) node).retirementCompleted)
          /\ Not (((nodeOf state) node).membershipState = .retiredCommitted)
          /\ Not (INITIAL_PRE_VOTE_STATUS node = .enabled)))
    : SystemInductiveInvariant (joined := joinedNodes) (timeoutEffect state node) :=
  candidateTransitionPreservesSystemInductiveInvariant (present := present)
    state node invariant
    ⟨enabled.1, enabled.2.1⟩

/-- A successful pre-vote starts the concrete_effects regular election term. -/
lemma becomeCandidatePreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : (node ∈ joinedNodes
          /\ ((nodeOf state) node).role = .preVoteCandidate
          /\ ((node ∈ activeNodeUnion ((nodeOf state) node)
                /\ campaignEligible node ((nodeOf state) node))
              \/ node ∈ ((nodeOf state) node).retirementCompleted)
          /\ Not (((nodeOf state) node).membershipState = .retiredCommitted)
          /\ INITIAL_PRE_VOTE_STATUS node = .enabled
          /\ hasPreVoteMajority (nodeOf state node)))
    : SystemInductiveInvariant (joined := joinedNodes) (becomeCandidateEffect state node) := by
  have preserved :=
    candidateTransitionPreservesSystemInductiveInvariant (present := present)
      state node invariant
        ⟨enabled.1, Or.inr (Or.inl enabled.2.1)⟩
  simpa [concrete_effects, becomeCandidateState, present] using preserved

end CCFRaft.Proofs.Invariant
