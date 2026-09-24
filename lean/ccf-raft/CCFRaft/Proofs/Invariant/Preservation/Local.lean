-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.PreVote
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

/-- Appending a pending configuration preserves the arbitrary-term invariant. -/
lemma changeConfigurationPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (source : Node)
    (newConfiguration : Finset Node)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : (state.allocated source
          /\ (state.nodes source).role = .leader
          /\ Not ((state.nodes source).membershipState = .retiredCommitted)
          /\ newConfiguration.Nonempty
          /\ Not (newConfiguration = ((latestConfiguration (state.nodes source)).nodes))
          /\ Not
              ((refreshRetirementState source
                  ({
                    (state.nodes source) with
                      log :=
                        (state.nodes source).log
                        ++ [({
                              term := (state.nodes source).currentTerm,
                              content := .reconfiguration newConfiguration
                            })]
                  })).membershipState
                = .retiredCommitted)))
    : SystemInductiveInvariant
        (changeConfigurationEffect state source newConfiguration) := by
  simpa [leaderAppendState, view_effects]
    using leaderAppendPreservesSystemInductiveInvariant
      state source (.reconfiguration newConfiguration)
      invariant enabled.1 enabled.2.1

/-- Demotion to a passive role preserves a leader's history and term ownership. -/
lemma leaderDemotionPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (node : Node)
    (newRole : Role)
    (passive : newRole = .follower \/ newRole = .none)
    (newFollower : Bool)
    (invariant : SystemInductiveInvariant state)
    (_nodeAllocated : state.allocated node)
    (oldRole : (state.nodes node).role = .leader)
    : SystemInductiveInvariant
        {
          state with
            nodes :=
              updateNode state.nodes node
                { state.nodes node with role := newRole, isNewFollower := newFollower }
        } := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafety with
    ⟨owners, canonicalHistory, elections, activations,
      nodeEvidence, requestEvidence, historical⟩
  have ownership := historical.termOwnership
  let after : View Node TxId :=
    { state with
      nodes :=
        updateNode state.nodes node
          { state.nodes node with role := newRole, isNewFollower := newFollower } }
  have packed : SystemInductiveInvariant state :=
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have oldRole : (state.nodes node).role = .leader := oldRole
  have roleNode : (after.nodes node).role = newRole := by
    simp [after]
  have roleOther :
      forall candidate,
        Not (candidate = node) ->
          (after.nodes candidate).role =
            (state.nodes candidate).role := by
    intro candidate different
    simp [
      after, updateNode, different
    ]
  have termEq :
      forall candidate,
        (after.nodes candidate).currentTerm =
          (state.nodes candidate).currentTerm := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, updateNode, same
      ]
  have logEq :
      forall candidate,
        (after.nodes candidate).log =
          (state.nodes candidate).log := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, updateNode, same
      ]
  have commitEq :
      forall candidate,
        (after.nodes candidate).commitIndex =
          (state.nodes candidate).commitIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, updateNode, same
      ]
  have sentEq :
      forall candidate,
        (after.nodes candidate).sentIndex =
          (state.nodes candidate).sentIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, updateNode, same
      ]
  have matchEq :
      forall candidate,
        (after.nodes candidate).matchIndex =
          (state.nodes candidate).matchIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, updateNode, same
      ]
  have votedEq :
      forall candidate,
        (after.nodes candidate).votedFor =
          (state.nodes candidate).votedFor := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, updateNode, same
      ]
  have votesEq :
      forall candidate,
        (after.nodes candidate).votesGranted =
          (state.nodes candidate).votesGranted := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, updateNode, same
      ]
  have activeConfigurationsEq :
      forall candidate,
        activeConfigurations (after.nodes candidate) =
          activeConfigurations (state.nodes candidate) := by
    intro candidate
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have participatingBack :
      forall candidate,
        Not ((after.nodes candidate).role = .none) ->
          Not ((state.nodes candidate).role = .none) := by
    intro candidate participating
    by_cases same : candidate = node
    · subst candidate
      rw [oldRole]
      decide
    · simpa [roleOther candidate same] using participating
  have candidateBack :
      forall candidate,
        (after.nodes candidate).role = .candidate ->
          (state.nodes candidate).role = .candidate := by
    intro candidate role
    by_cases same : candidate = node
    · subst candidate
      rcases passive with rfl | rfl <;>
        exact False.elim (Role.noConfusion (roleNode.symm.trans role))
    · simpa [roleOther candidate same] using role
  have leaderBack :
      forall leader,
        (after.nodes leader).role = .leader ->
          (state.nodes leader).role = .leader := by
    intro leader role
    by_cases same : leader = node
    · subst leader
      rcases passive with rfl | rfl <;>
        exact False.elim (Role.noConfusion (roleNode.symm.trans role))
    · simpa [roleOther leader same] using role
  have ownerRoleForward :
      forall owner,
        ((state.nodes owner).role = .leader \/
          (state.nodes owner).role = .follower \/
          (state.nodes owner).role = .preVoteCandidate \/
          (state.nodes owner).role = .none) ->
        ((after.nodes owner).role = .leader \/
          (after.nodes owner).role = .follower \/
          (after.nodes owner).role = .preVoteCandidate \/
          (after.nodes owner).role = .none) := by
    intro owner ownerRole
    by_cases same : owner = node
    · subst owner
      rcases passive with rfl | rfl
      · exact Or.inr (Or.inl roleNode)
      · exact Or.inr (Or.inr (Or.inr roleNode))
    · simpa [roleOther owner same] using ownerRole
  have passiveRoleForward :
      forall owner,
        ((state.nodes owner).role = .follower \/
          (state.nodes owner).role = .preVoteCandidate \/
          (state.nodes owner).role = .none) ->
        ((after.nodes owner).role = .follower \/
          (after.nodes owner).role = .preVoteCandidate \/
          (after.nodes owner).role = .none) := by
    intro owner ownerRole
    by_cases same : owner = node
    · subst owner
      rcases passive with rfl | rfl
      · exact Or.inl roleNode
      · exact Or.inr (Or.inr roleNode)
    · simpa [roleOther owner same] using ownerRole
  have activeRoleBack :
      forall candidate,
        ((after.nodes candidate).role = .candidate \/
          (after.nodes candidate).role = .leader) ->
        ((state.nodes candidate).role = .candidate \/
          (state.nodes candidate).role = .leader) := by
    intro candidate active
    rcases active with candidateRole | leaderRole
    · exact Or.inl (candidateBack candidate candidateRole)
    · exact Or.inr (leaderBack candidate leaderRole)
  have effectiveAckersEq :
      forall actualResponseHistory leader index,
        effectiveAckers after actualResponseHistory leader index =
          effectiveAckers state actualResponseHistory leader index :=
    effectiveAckersFrame
      state after
        (by simp [after])
        (by simp [after])
        termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters after candidate =
          effectiveElectionVoters state candidate :=
    effectiveElectionVotersFrame
      state after
        (by simp [after])
        (by simp [after])
        termEq votesEq
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters after candidate =
          potentialElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨
          by simpa [after] using joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq] at effective
              exact effective)
        ⟩
      · exact ⟨
          by simpa [after] using joined,
          Or.inr
            (by
              simpa [currentlyEligibleElectionVoter, makeRequestVoteRequest, termEq,
                logEq, commitEq, votedEq,
                lastCommittableIndexFrame
                  (logEq candidate) (commitEq candidate),
                lastCommittableTermFrame
                  (logEq candidate) (commitEq candidate), voteLogUpToDate]
                using eligible)
        ⟩
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨
          by simpa [after] using joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq]
              exact effective)
        ⟩
      · exact ⟨
          by simpa [after] using joined,
          Or.inr
            (by
              simpa [currentlyEligibleElectionVoter, makeRequestVoteRequest, termEq,
                logEq, commitEq, votedEq,
                lastCommittableIndexFrame
                  (logEq candidate) (commitEq candidate),
                lastCommittableTermFrame
                  (logEq candidate) (commitEq candidate), voteLogUpToDate]
                using eligible)
        ⟩
  have joinedCarriersAfter : JoinedCarrierFacts after := by
    apply
      joinedCarrierFactsFrame
        state after facts.joinedCarriers
          (by simp [after])
          (fun candidate configuration active => by
            simpa [activeConfigurationsEq] using active)
          (fun candidate configuration member => by
            simpa [logEq] using member)
          (fun candidate peer member => by
            simpa [votesEq] using member)
          (fun candidate active => by
            exact
              facts.joinedCarriers.runtimeNodes.activeRoles candidate
                (activeRoleBack candidate active))
          (fun leader peer positive => by
            exact
              facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
                (by simpa [matchEq] using positive))
          (fun candidate nonempty => by
            exact
              facts.joinedCarriers.runtimeNodes.nonemptyLogs candidate
                (by simpa [logEq] using nonempty))
          (fun destination message member => by
            simpa [after] using member)
  have candidatesSelfVoteAfter : CandidatesSelfVote after := by
    intro candidate role
    rcases
        facts.candidatesSelfVote candidate
          (candidateBack candidate role) with
      ⟨voted, counted⟩
    exact ⟨by simpa [votedEq] using voted, by simpa [votesEq] using counted⟩
  have leadersHaveElectionWitnessAfter :
      LeadersHaveElectionWitness after := by
    intro leader role
    rcases
        facts.leadersHaveElectionWitness leader
          (leaderBack leader role) with
      bootstrap | majority
    · exact Or.inl
        ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
    · exact Or.inr (by simpa [logEq, votesEq] using majority)
  change SystemInductiveInvariant after
  apply roleAndNetworkFramePreservesSystemInductiveInvariant state after packed
    (by simp [after])
    (fun _ => Iff.rfl)
    joinedCarriersAfter participatingBack candidateBack
    leaderBack ownerRoleForward passiveRoleForward
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
          (activeRoleBack candidate active)
          (by simpa [votesEq] using member)
  · intro _ _ _ _ _ _ actualFacts
    rcases actualFacts.processedAckHistory with
      ⟨history, historyFacts⟩
    exact ⟨
      history,
      processedAckHistoryFrameBack
        state after history historyFacts leaderBack termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
    ⟩
  · intro destination message member
    exact
      Or.inl
        (by simpa [after] using member)
  · intro leader role peer
    simpa [sentEq, matchEq, logEq]
      using facts.leaderProgressBounded leader (leaderBack leader role) peer
  · intro _ _ actualResponseHistory _ _ _ _ leader index
    exact Finset.subset_of_eq
      (effectiveAckersEq actualResponseHistory leader index)
  · intro _ actualAppendHistory actualResponseHistory
      _ _ _ _ leader index peer member
    simp only [
      potentialAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | reserve⟩
    · exact ⟨
        by simpa [after] using joined,
        Or.inl
          (by
            rw [effectiveAckersEq actualResponseHistory leader index]
              at effective
            exact effective)
      ⟩
    · rcases reserve with
        ⟨request, queued, requestSource, requestDestination,
          requestTerm, producible, covered⟩
      have oldProducible :
          canProduceAppendAckEventuallyAt
            (state.nodes peer) request index := by
        by_cases peerEq : peer = node
        · rcases producible with direct | future
          · rcases direct with
              ⟨nextNode, response, handled, success, acknowledged⟩
            have localPost := handleAppendEntriesRequestLocalPost handled
            have requestAtNode :
                request.term = (state.nodes node).currentTerm := by
              calc
                request.term = (after.nodes peer).currentTerm :=
                  localPost.successfulCurrentTerm success
                _ = (state.nodes peer).currentTerm := termEq peer
                _ = (state.nodes node).currentTerm := by rw [peerEq]
            have nodeOwned :
                owners request.term = some node := by
              simpa [requestAtNode] using ownership.activeLeader node oldRole
            have sourceOwned :
                owners request.term = some request.source :=
              (ownership.queuedAppendMetadata
                peer request queued).2.1
            have sourceEqNode : request.source = node :=
              Option.some.inj (sourceOwned.symm.trans nodeOwned)
            have destinationEqNode : request.destination = node :=
              requestDestination.trans peerEq
            exact False.elim
              ((ownership.queuedAppendMetadata peer request queued).1
                (sourceEqNode.trans destinationEqNode.symm))
          · exact Or.inr
              ⟨by simpa [termEq] using future.1, future.2⟩
        · have peerStateEq :
              after.nodes peer = state.nodes peer := by
            simp [
              after, updateNode, peerEq
            ]
          simpa [peerStateEq] using producible
      exact ⟨
        by simpa [after] using joined,
        Or.inr
          ⟨
            request,
            by simpa [after] using queued,
            requestSource,
            requestDestination,
            by simpa [termEq] using requestTerm,
            oldProducible,
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

/-- A failed quorum check demotes a leader without changing its term or log. -/
lemma leaderStepDownPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (nodeAllocated : state.allocated node)
    (oldRole : (state.nodes node).role = .leader)
    : SystemInductiveInvariant (stepDownState state node) :=
  leaderDemotionPreservesSystemInductiveInvariant
    state node .follower (Or.inl rfl) true invariant nodeAllocated oldRole

/-- The guarded CheckQuorum action uses the generic same-term demotion proof. -/
lemma checkQuorumPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : (state.allocated node
          /\ (state.nodes node).role = .leader
          /\ hasOtherActiveReplica state node))
    : SystemInductiveInvariant (checkQuorumEffect state node) := by
  simpa [view_effects]
    using leaderStepDownPreservesSystemInductiveInvariant
      state node invariant enabled.1 enabled.2.1

/-- Commit advancement and terminal demotion preserve the safety invariant. -/
lemma advanceCommitTransitionPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : state.allocated node
        /\ (state.nodes node).role = .leader
        /\ (state.nodes node).commitIndex < highestCommittableIndex state node)
    : SystemInductiveInvariant
        (demoteRetiredCommitted (advanceCommitState state node) node) := by
  have committed :=
    advanceCommitStatePreservesSystemInductiveInvariant
      state node invariant enabled
  by_cases terminal :
      ((advanceCommitState state node).nodes node).membershipState =
        .retiredCommitted
  · have nodeAllocated :
        (advanceCommitState state node).allocated node := enabled.1
    have leader :
        ((advanceCommitState state node).nodes node).role = .leader := by
      simp [advanceCommitState, enabled.2.1]
    simpa [demoteRetiredCommitted, terminal]
      using leaderDemotionPreservesSystemInductiveInvariant
        (advanceCommitState state node) node .none (Or.inr rfl)
        ((advanceCommitState state node).nodes node).isNewFollower
        committed nodeAllocated leader
  · simpa [demoteRetiredCommitted, terminal] using committed

/-- A nonterminal commit uses the ordinary commit action. -/
lemma advanceCommitPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : (state.allocated node
          /\ (state.nodes node).role = .leader
          /\ (state.nodes node).commitIndex < highestCommittableIndex state node
          /\ Not (terminalRetirementCommit state node)))
    : SystemInductiveInvariant (advanceCommitIndexEffect state node) := by
  simpa [view_effects]
    using advanceCommitTransitionPreservesSystemInductiveInvariant
      state node invariant
      ⟨enabled.1, enabled.2.1, enabled.2.2.1⟩

/-- A terminal commit atomically enqueues its explicitly selected successor. -/
lemma advanceCommitAndProposeVotePreservesSystemInductiveInvariant
    (state : View Node TxId)
    (source destination : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : (state.allocated source
          /\ state.allocated destination
          /\ (state.nodes source).role = .leader
          /\ (state.nodes source).commitIndex < highestCommittableIndex state source
          /\ terminalRetirementCommit state source
          /\ plausibleSuccessor state source destination))
    : SystemInductiveInvariant
        (advanceCommitIndexAndProposeVoteEffect state source destination) := by
  let advanced :=
    demoteRetiredCommitted (advanceCommitState state source) source
  let request := makeProposeVoteRequest state source destination
  have advancedInvariant : SystemInductiveInvariant advanced := by
    exact
      advanceCommitTransitionPreservesSystemInductiveInvariant
        state source invariant
          ⟨enabled.1, enabled.2.2.1, enabled.2.2.2.1⟩
  simpa [view_effects, advanced, request]
    using enqueueProposeVoteRequestPreservesSystemInductiveInvariant
      advanced request advancedInvariant
      (invariantCurrentTermsValid invariant source)

/-- Entering a speculative election changes no consensus-safety evidence. -/
lemma becomePreVoteCandidatePreservesSystemInductiveInvariant
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
          /\ INITIAL_PRE_VOTE_STATUS node = .enabled))
    : SystemInductiveInvariant (becomePreVoteCandidateEffect state node) := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  let after := becomePreVoteCandidateEffect state node
  have packed : SystemInductiveInvariant state :=
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have oldParticipating :
      Not ((state.nodes node).role = .none) := by
    rcases enabled.2.1 with follower | preVoteCandidate | candidate
    · simp [follower]
    · simp [preVoteCandidate]
    · simp [candidate]
  have oldNotLeader :
      Not ((state.nodes node).role = .leader) := by
    rcases enabled.2.1 with follower | preVoteCandidate | candidate
    · exact fun leader => Role.noConfusion (follower.symm.trans leader)
    · exact
        fun leader =>
          Role.noConfusion (preVoteCandidate.symm.trans leader)
    · exact fun leader => Role.noConfusion (candidate.symm.trans leader)
  have roleNode :
      (after.nodes node).role = .preVoteCandidate := by
    simp [after, view_effects]
  have roleOther :
      forall candidate,
        Not (candidate = node) ->
          (after.nodes candidate).role =
            (state.nodes candidate).role := by
    intro candidate different
    simp [
      after, view_effects, updateNode, different
    ]
  have termEq :
      forall candidate,
        (after.nodes candidate).currentTerm =
          (state.nodes candidate).currentTerm := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, view_effects, updateNode, same
      ]
  have logEq :
      forall candidate,
        (after.nodes candidate).log =
          (state.nodes candidate).log := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, view_effects, updateNode, same
      ]
  have commitEq :
      forall candidate,
        (after.nodes candidate).commitIndex =
          (state.nodes candidate).commitIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, view_effects, updateNode, same
      ]
  have sentEq :
      forall candidate,
        (after.nodes candidate).sentIndex =
          (state.nodes candidate).sentIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, view_effects, updateNode, same
      ]
  have matchEq :
      forall candidate,
        (after.nodes candidate).matchIndex =
          (state.nodes candidate).matchIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, view_effects, updateNode, same
      ]
  have votedEq :
      forall candidate,
        (after.nodes candidate).votedFor =
          (state.nodes candidate).votedFor := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, view_effects, updateNode, same
      ]
  have votesEq :
      forall candidate,
        (after.nodes candidate).votesGranted =
          (state.nodes candidate).votesGranted := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, view_effects, updateNode, same
      ]
  have activeConfigurationsEq :
      forall candidate,
        activeConfigurations (after.nodes candidate) =
          activeConfigurations (state.nodes candidate) := by
    intro candidate
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have participatingBack :
      forall candidate,
        Not ((after.nodes candidate).role = .none) ->
          Not ((state.nodes candidate).role = .none) := by
    intro candidate participating
    by_cases same : candidate = node
    · subst candidate
      exact oldParticipating
    · simpa [roleOther candidate same] using participating
  have candidateBack :
      forall candidate,
        (after.nodes candidate).role = .candidate ->
          (state.nodes candidate).role = .candidate := by
    intro candidate role
    by_cases same : candidate = node
    · subst candidate
      exact False.elim (Role.noConfusion (roleNode.symm.trans role))
    · simpa [roleOther candidate same] using role
  have leaderBack :
      forall leader,
        (after.nodes leader).role = .leader ->
          (state.nodes leader).role = .leader := by
    intro leader role
    by_cases same : leader = node
    · subst leader
      exact False.elim (Role.noConfusion (roleNode.symm.trans role))
    · simpa [roleOther leader same] using role
  have activeRoleBack :
      forall candidate,
        ((after.nodes candidate).role = .candidate \/
          (after.nodes candidate).role = .leader) ->
        ((state.nodes candidate).role = .candidate \/
          (state.nodes candidate).role = .leader) := by
    intro candidate active
    rcases active with candidateRole | leaderRole
    · exact Or.inl (candidateBack candidate candidateRole)
    · exact Or.inr (leaderBack candidate leaderRole)
  have effectiveAckersEq :
      forall actualResponseHistory leader index,
        effectiveAckers after actualResponseHistory leader index =
          effectiveAckers state actualResponseHistory leader index :=
    effectiveAckersFrame
      state after
        (by simp [after, view_effects])
        (by simp [after, view_effects])
        termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters after candidate =
          effectiveElectionVoters state candidate :=
    effectiveElectionVotersFrame
      state after
        (by simp [after, view_effects])
        (by simp [after, view_effects])
        termEq votesEq
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters after candidate =
          potentialElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨
          by simpa [after, view_effects] using joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq] at effective
              exact effective)
        ⟩
      · exact ⟨
          by simpa [after, view_effects] using joined,
          Or.inr
            (by
              simpa [currentlyEligibleElectionVoter, makeRequestVoteRequest, termEq,
                logEq, commitEq, votedEq,
                lastCommittableIndexFrame
                  (logEq candidate) (commitEq candidate),
                lastCommittableTermFrame
                  (logEq candidate) (commitEq candidate), voteLogUpToDate]
                using eligible)
        ⟩
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨
          by simpa [after, view_effects] using joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq]
              exact effective)
        ⟩
      · exact ⟨
          by simpa [after, view_effects] using joined,
          Or.inr
            (by
              simpa [currentlyEligibleElectionVoter, makeRequestVoteRequest, termEq,
                logEq, commitEq, votedEq,
                lastCommittableIndexFrame
                  (logEq candidate) (commitEq candidate),
                lastCommittableTermFrame
                  (logEq candidate) (commitEq candidate), voteLogUpToDate]
                using eligible)
        ⟩
  have joinedCarriersAfter : JoinedCarrierFacts after := by
    apply
      joinedCarrierFactsFrame
        state after facts.joinedCarriers
          (by simp [after, view_effects])
          (fun candidate configuration active => by
            simpa [activeConfigurationsEq] using active)
          (fun candidate configuration member => by
            simpa [logEq] using member)
          (fun candidate peer member => by
            simpa [votesEq] using member)
          (fun candidate active => by
            exact
              facts.joinedCarriers.runtimeNodes.activeRoles candidate
                (activeRoleBack candidate active))
          (fun leader peer positive => by
            exact
              facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
                (by simpa [matchEq] using positive))
          (fun candidate nonempty => by
            exact
              facts.joinedCarriers.runtimeNodes.nonemptyLogs candidate
                (by simpa [logEq] using nonempty))
          (fun destination message member => by
            simpa [after, view_effects] using member)
  have candidatesSelfVoteAfter : CandidatesSelfVote after := by
    intro candidate role
    rcases
        facts.candidatesSelfVote candidate
          (candidateBack candidate role) with
      ⟨voted, counted⟩
    exact ⟨by simpa [votedEq] using voted, by simpa [votesEq] using counted⟩
  have leadersHaveElectionWitnessAfter :
      LeadersHaveElectionWitness after := by
    intro leader role
    rcases
        facts.leadersHaveElectionWitness leader
          (leaderBack leader role) with
      bootstrap | majority
    · exact Or.inl
        ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
    · exact Or.inr (by simpa [logEq, votesEq] using majority)
  change SystemInductiveInvariant after
  apply roleAndNetworkFramePreservesSystemInductiveInvariant state after packed
    (by simp [after, view_effects])
    (fun _ => Iff.rfl)
    joinedCarriersAfter participatingBack candidateBack leaderBack
    (fun owner role => by
      by_cases same : owner = node
      · subst owner
        exact Or.inr (Or.inr (Or.inl roleNode))
      · simpa [roleOther owner same] using role)
    (fun owner role => by
      by_cases same : owner = node
      · subst owner
        exact Or.inr (Or.inl roleNode)
      · simpa [roleOther owner same] using role)
    termEq logEq commitEq candidatesSelfVoteAfter leadersHaveElectionWitnessAfter
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
          (activeRoleBack candidate active)
          (by simpa [votesEq] using member)
  · intro _ _ _ _ _ _ actualFacts
    rcases actualFacts.processedAckHistory with
      ⟨history, historyFacts⟩
    exact ⟨
      history,
      processedAckHistoryFrameBack
        state after history historyFacts leaderBack termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
    ⟩
  · intro destination message member
    exact
      Or.inl
        (by simpa [after, view_effects] using member)
  · intro leader role peer
    simpa [sentEq, matchEq, logEq]
      using facts.leaderProgressBounded leader (leaderBack leader role) peer
  · intro _ _ actualResponseHistory _ _ _ _ leader index
    exact Finset.subset_of_eq
      (effectiveAckersEq actualResponseHistory leader index)
  · intro _ actualAppendHistory actualResponseHistory
      _ _ _ _ leader index peer member
    simp only [
      potentialAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | reserve⟩
    · exact ⟨
        by simpa [after, view_effects] using joined,
        Or.inl
          (by
            rw [effectiveAckersEq actualResponseHistory leader index]
              at effective
            exact effective)
      ⟩
    · rcases reserve with
        ⟨request, queued, sourceEq, destinationEq,
          requestTerm, producible, covered⟩
      have oldProducible :
          canProduceAppendAckEventuallyAt
            (state.nodes peer) request index := by
        by_cases same : peer = node
        · subst peer
          rw [same] at producible ⊢
          rcases producible with direct | future
          · have follower := canProduceAppendAckAt_role direct
            exact False.elim
              (Role.noConfusion (follower.symm.trans roleNode))
          · exact Or.inr
              ⟨by simpa [termEq] using future.1, future.2⟩
        · have peerStateEq :
              after.nodes peer = state.nodes peer := by
            simp [
              after, view_effects, updateNode, same
            ]
          simpa [peerStateEq] using producible
      exact ⟨
        by simpa [after, view_effects] using joined,
        Or.inr
          ⟨
            request,
            by simpa [after, view_effects] using queued,
            sourceEq,
            destinationEq,
            by simpa [termEq] using requestTerm,
            oldProducible,
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

lemma initializeConfigurationPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : (node = INITIAL_LEADER
          /\ state.allocated node
          /\ (state.nodes node).role = .leader
          /\ (state.nodes node).currentTerm = BOOTSTRAP_TERM
          /\ (state.nodes node).log = []
          /\ (state.nodes node).commitIndex = 0
          /\ (state.nodes node).membershipState = .active))
    : SystemInductiveInvariant (initializeConfigurationEffect state node) := by
  rcases enabled with ⟨_, allocated, leader, _, emptyLog, _, _⟩
  have latest :
      latestConfiguration (state.nodes node) = implicitConfiguration := by
    simp [latestConfiguration, configurationsInLog, configurationsInLogFrom, emptyLog]
  let appended := leaderAppendState state node
    (.reconfiguration INITIAL_CONFIGURATION)
  have appendedInvariant : SystemInductiveInvariant appended :=
    leaderAppendPreservesSystemInductiveInvariant state node
      (.reconfiguration INITIAL_CONFIGURATION)
      invariant allocated leader
  apply retirementMetadataFramePreservesSystemInductiveInvariant
    appended _ appendedInvariant
  · simp [appended, leaderAppendState, latest, implicitConfiguration, view_effects]
  · intro candidate
    simp [View.allocated, view_effects, appended, leaderAppendState, latest, implicitConfiguration]
  · rfl
  all_goals
    intro candidate
    by_cases same : candidate = node <;>
      simp [appended, leaderAppendState, latest, implicitConfiguration, view_effects,
        updateNode, same, emptyLog, protocolNodeState]

end CCFRaft.Proofs.Invariant
