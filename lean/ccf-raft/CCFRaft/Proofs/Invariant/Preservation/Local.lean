-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.PreVote
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

/-- Appending a pending configuration preserves the arbitrary-term invariant. -/
lemma changeConfigurationPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (source : Node)
    {present : source ∈ state.nodes.map Prod.fst}
    (newConfiguration : Finset Node)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : (source ∈ joinedNodes
          /\ ((nodeOf state) source).role = .leader
          /\ Not (((nodeOf state) source).membershipState = .retiredCommitted)
          /\ newConfiguration.Nonempty
          /\ Not (newConfiguration = ((latestConfiguration ((nodeOf state) source)).nodes))
          /\ Not
              ((refreshRetirementState source
                  ({
                    ((nodeOf state) source) with
                      log :=
                        ((nodeOf state) source).log
                        ++ [({
                              term := ((nodeOf state) source).currentTerm,
                              content := .reconfiguration newConfiguration
                            })]
                  })).membershipState
                = .retiredCommitted)))
    : SystemInductiveInvariant (joined := leaderAppendJoined joinedNodes state source (.reconfiguration newConfiguration))
        (changeConfigurationEffect state source newConfiguration) := by
  simpa [leaderAppendState, present, concrete_effects, present]
    using leaderAppendPreservesSystemInductiveInvariant (present := present)
      state source (.reconfiguration newConfiguration)
      invariant enabled.1 enabled.2.1

/-- Demotion to a passive role preserves a leader's history and term ownership. -/
lemma leaderDemotionPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (newRole : Role)
    (passive : newRole = .follower \/ newRole = .none)
    (newFollower : Bool)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (_nodeAllocated : node ∈ joinedNodes)
    (oldRole : ((nodeOf state) node).role = .leader)
    : SystemInductiveInvariant (joined := joinedNodes)
        {
          state with
            nodes :=
              replaceNode state.nodes node
                { (nodeOf state) node with role := newRole, isNewFollower := newFollower }
        } := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafety with
    ⟨owners, canonicalHistory, elections, activations,
      nodeEvidence, requestEvidence, historical⟩
  have ownership := historical.termOwnership
  let after : Model.State Node TxId :=
    { state with
      nodes :=
        replaceNode state.nodes node
          { (nodeOf state) node with role := newRole, isNewFollower := newFollower } }
  have packed : SystemInductiveInvariant (joined := joinedNodes) state :=
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have oldRole : ((nodeOf state) node).role = .leader := oldRole
  have roleNode : ((nodeOf after) node).role = newRole := by
    simp [after, present]
  have roleOther :
      forall candidate,
        Not (candidate = node) ->
          ((nodeOf after) candidate).role =
            ((nodeOf state) candidate).role := by
    intro candidate different
    simp [
      after, present, nodeOf_replaceNode, different
    ]
  have termEq :
      forall candidate,
        ((nodeOf after) candidate).currentTerm =
          ((nodeOf state) candidate).currentTerm := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, nodeOf_replaceNode, same
      ]
  have logEq :
      forall candidate,
        ((nodeOf after) candidate).log =
          ((nodeOf state) candidate).log := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, nodeOf_replaceNode, same
      ]
  have commitEq :
      forall candidate,
        ((nodeOf after) candidate).commitIndex =
          ((nodeOf state) candidate).commitIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, nodeOf_replaceNode, same
      ]
  have sentEq :
      forall candidate,
        ((nodeOf after) candidate).sentIndex =
          ((nodeOf state) candidate).sentIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, nodeOf_replaceNode, same
      ]
  have matchEq :
      forall candidate,
        ((nodeOf after) candidate).matchIndex =
          ((nodeOf state) candidate).matchIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, nodeOf_replaceNode, same
      ]
  have votedEq :
      forall candidate,
        ((nodeOf after) candidate).votedFor =
          ((nodeOf state) candidate).votedFor := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, nodeOf_replaceNode, same
      ]
  have votesEq :
      forall candidate,
        ((nodeOf after) candidate).votesGranted =
          ((nodeOf state) candidate).votesGranted := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, nodeOf_replaceNode, same
      ]
  have activeConfigurationsEq :
      forall candidate,
        activeConfigurations ((nodeOf after) candidate) =
          activeConfigurations ((nodeOf state) candidate) := by
    intro candidate
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have participatingBack :
      forall candidate,
        Not (((nodeOf after) candidate).role = .none) ->
          Not (((nodeOf state) candidate).role = .none) := by
    intro candidate participating
    by_cases same : candidate = node
    · subst candidate
      rw [oldRole]
      decide
    · simpa [roleOther candidate same] using participating
  have candidateBack :
      forall candidate,
        ((nodeOf after) candidate).role = .candidate ->
          ((nodeOf state) candidate).role = .candidate := by
    intro candidate role
    by_cases same : candidate = node
    · subst candidate
      rcases passive with rfl | rfl <;>
        exact False.elim (Role.noConfusion (roleNode.symm.trans role))
    · simpa [roleOther candidate same] using role
  have leaderBack :
      forall leader,
        ((nodeOf after) leader).role = .leader ->
          ((nodeOf state) leader).role = .leader := by
    intro leader role
    by_cases same : leader = node
    · subst leader
      rcases passive with rfl | rfl <;>
        exact False.elim (Role.noConfusion (roleNode.symm.trans role))
    · simpa [roleOther leader same] using role
  have ownerRoleForward :
      forall owner,
        (((nodeOf state) owner).role = .leader \/
          ((nodeOf state) owner).role = .follower \/
          ((nodeOf state) owner).role = .preVoteCandidate \/
          ((nodeOf state) owner).role = .none) ->
        (((nodeOf after) owner).role = .leader \/
          ((nodeOf after) owner).role = .follower \/
          ((nodeOf after) owner).role = .preVoteCandidate \/
          ((nodeOf after) owner).role = .none) := by
    intro owner ownerRole
    by_cases same : owner = node
    · subst owner
      rcases passive with rfl | rfl
      · exact Or.inr (Or.inl roleNode)
      · exact Or.inr (Or.inr (Or.inr roleNode))
    · simpa [roleOther owner same] using ownerRole
  have passiveRoleForward :
      forall owner,
        (((nodeOf state) owner).role = .follower \/
          ((nodeOf state) owner).role = .preVoteCandidate \/
          ((nodeOf state) owner).role = .none) ->
        (((nodeOf after) owner).role = .follower \/
          ((nodeOf after) owner).role = .preVoteCandidate \/
          ((nodeOf after) owner).role = .none) := by
    intro owner ownerRole
    by_cases same : owner = node
    · subst owner
      rcases passive with rfl | rfl
      · exact Or.inl roleNode
      · exact Or.inr (Or.inr roleNode)
    · simpa [roleOther owner same] using ownerRole
  have activeRoleBack :
      forall candidate,
        (((nodeOf after) candidate).role = .candidate \/
          ((nodeOf after) candidate).role = .leader) ->
        (((nodeOf state) candidate).role = .candidate \/
          ((nodeOf state) candidate).role = .leader) := by
    intro candidate active
    rcases active with candidateRole | leaderRole
    · exact Or.inl (candidateBack candidate candidateRole)
    · exact Or.inr (leaderBack candidate leaderRole)
  have effectiveAckersEq :
      forall actualResponseHistory leader index,
        effectiveAckers (joined := joinedNodes) after actualResponseHistory leader index =
          effectiveAckers (joined := joinedNodes) state actualResponseHistory leader index :=
    effectiveAckersFrame
      state after
        (by simp [after, present])
        (by simp [after, present])
        termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters (joined := joinedNodes) after candidate =
          effectiveElectionVoters (joined := joinedNodes) state candidate :=
    effectiveElectionVotersFrame
      state after
        (by simp [after, present])
        (by simp [after, present])
        termEq votesEq
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters (joined := joinedNodes) after candidate =
          potentialElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨
          by simpa [after, present] using joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq] at effective
              exact effective)
        ⟩
      · exact ⟨
          by simpa [after, present] using joined,
          Or.inr
            (by
              simpa [currentlyEligibleElectionVoter, voteRequestKey, Model.Local.makeRequestVoteRequest, termEq,
                logEq, commitEq, votedEq,
                lastCommittableIndexFrame
                  (logEq candidate) (commitEq candidate),
                lastCommittableTermFrame
                  (logEq candidate) (commitEq candidate), voteLogUpToDate]
                using eligible)
        ⟩
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨
          by simpa [after, present] using joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq]
              exact effective)
        ⟩
      · exact ⟨
          by simpa [after, present] using joined,
          Or.inr
            (by
              simpa [currentlyEligibleElectionVoter, voteRequestKey, Model.Local.makeRequestVoteRequest, termEq,
                logEq, commitEq, votedEq,
                lastCommittableIndexFrame
                  (logEq candidate) (commitEq candidate),
                lastCommittableTermFrame
                  (logEq candidate) (commitEq candidate), voteLogUpToDate]
                using eligible)
        ⟩
  have joinedCarriersAfter : JoinedCarrierFacts (joined := joinedNodes) after := by
    apply
      joinedCarrierFactsFrame
        state after facts.joinedCarriers
          (by simp [after, present])
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
            simpa [after, present] using member)
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
  change SystemInductiveInvariant (joined := joinedNodes) after
  apply roleAndNetworkFramePreservesSystemInductiveInvariant state after packed (by simp [after, present])
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
        (by simpa [after, present] using member)
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
        by simpa [after, present] using joined,
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
            ((nodeOf state) peer) request index := by
        by_cases peerEq : peer = node
        · rcases producible with direct | future
          · rcases direct with
              ⟨nextNode, response, handled, success, acknowledged⟩
            have localPost := acceptAppendEntriesRequestLocalPost handled
            have requestAtNode :
                request.2.2.term = ((nodeOf state) node).currentTerm := by
              calc
                request.2.2.term = ((nodeOf after) peer).currentTerm :=
                  localPost.successfulCurrentTerm success
                _ = ((nodeOf state) peer).currentTerm := termEq peer
                _ = ((nodeOf state) node).currentTerm := by rw [peerEq]
            have nodeOwned :
                owners request.2.2.term = some node := by
              simpa [requestAtNode] using ownership.activeLeader node oldRole
            have sourceOwned :
                owners request.2.2.term = some request.1 :=
              (ownership.queuedAppendMetadata
                peer request queued).2.1
            have sourceEqNode : request.1 = node :=
              Option.some.inj (sourceOwned.symm.trans nodeOwned)
            have destinationEqNode : request.2.1 = node :=
              requestDestination.trans peerEq
            exact False.elim
              ((ownership.queuedAppendMetadata peer request queued).1
                (sourceEqNode.trans destinationEqNode.symm))
          · exact Or.inr
              ⟨by simpa [termEq] using future.1, future.2⟩
        · have peerStateEq :
              (nodeOf after) peer = (nodeOf state) peer := by
            simp [
              after, present, nodeOf_replaceNode, peerEq
            ]
          simpa [peerStateEq] using producible
      exact ⟨
        by simpa [after, present] using joined,
        Or.inr
          ⟨
            request,
            by simpa [after, present] using queued,
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
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (nodeAllocated : node ∈ joinedNodes)
    (oldRole : ((nodeOf state) node).role = .leader)
    : SystemInductiveInvariant (joined := joinedNodes) (stepDownState state node) :=
  leaderDemotionPreservesSystemInductiveInvariant (present := present)
    state node .follower (Or.inl rfl) true invariant nodeAllocated oldRole

/-- The guarded CheckQuorum action uses the generic same-term demotion proof. -/
lemma checkQuorumPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : (node ∈ joinedNodes
          /\ ((nodeOf state) node).role = .leader
          /\ hasOtherActiveReplica (nodeOf state node) node))
    : SystemInductiveInvariant (joined := joinedNodes) (checkQuorumEffect state node) := by
  simpa [concrete_effects, present]
    using leaderStepDownPreservesSystemInductiveInvariant (present := present)
      state node invariant enabled.1 enabled.2.1

/-- Commit advancement and terminal demotion preserve the safety invariant. -/
lemma advanceCommitTransitionPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (distinct : (state.nodes.map Prod.fst).Nodup)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : node ∈ joinedNodes
        /\ ((nodeOf state) node).role = .leader
        /\ ((nodeOf state) node).commitIndex < highestCommittableIndex (nodeOf state node) node)
    : SystemInductiveInvariant (joined := joinedNodes)
        (demoteRetiredCommitted (advanceCommitState state node) node) := by
  have committed :=
    advanceCommitStatePreservesSystemInductiveInvariant (present := present)
      state node invariant enabled
  by_cases terminal :
      ((nodeOf (advanceCommitState state node)) node).membershipState =
        .retiredCommitted
  · have nodeAllocated :
        node ∈ joinedNodes := enabled.1
    have leader :
        ((nodeOf (advanceCommitState state node)) node).role = .leader := by
      simp [advanceCommitState, Model.Local.advanceCommit, present, enabled.2.1]
    simpa [demoteRetiredCommitted, Model.Local.demoteRetiredCommitted, terminal]
      using leaderDemotionPreservesSystemInductiveInvariant
        (advanceCommitState state node) node (present := by simpa [advanceCommitState, replaceNode_keys] using present) .none (Or.inr rfl)
        ((nodeOf (advanceCommitState state node)) node).isNewFollower
        committed nodeAllocated leader
  · have keys : ((advanceCommitState state node).nodes.map Prod.fst).Nodup := by
      simpa [advanceCommitState, replaceNode_keys] using distinct
    simpa [demoteRetiredCommitted, Model.Local.demoteRetiredCommitted, terminal,
      replaceNode_nodeOf _ _ keys] using committed

/-- A nonterminal commit uses the ordinary commit action. -/
lemma advanceCommitPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (distinct : (state.nodes.map Prod.fst).Nodup)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : (node ∈ joinedNodes
          /\ ((nodeOf state) node).role = .leader
          /\ ((nodeOf state) node).commitIndex < highestCommittableIndex (nodeOf state node) node
          /\ Not (terminalRetirementCommit (nodeOf state node) node)))
    : SystemInductiveInvariant (joined := joinedNodes) (advanceCommitIndexEffect state node) := by
  simpa [concrete_effects, present]
    using advanceCommitTransitionPreservesSystemInductiveInvariant (present := present)
      state node distinct invariant
      ⟨enabled.1, enabled.2.1, enabled.2.2.1⟩

/-- A terminal commit atomically enqueues its explicitly selected successor. -/
lemma advanceCommitAndProposeVotePreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (source destination : Node)
    {present : source ∈ state.nodes.map Prod.fst}
    (distinct : (state.nodes.map Prod.fst).Nodup)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : (source ∈ joinedNodes
          /\ destination ∈ joinedNodes
          /\ ((nodeOf state) source).role = .leader
          /\ ((nodeOf state) source).commitIndex < highestCommittableIndex (nodeOf state source) source
          /\ terminalRetirementCommit (nodeOf state source) source
          /\ plausibleSuccessor (nodeOf state source) source destination))
    : SystemInductiveInvariant (joined := joinedNodes)
        (advanceCommitIndexAndProposeVoteEffect state source destination) := by
  let advanced :=
    demoteRetiredCommitted (advanceCommitState state source) source
  let request := (source, destination, (nodeOf state source).currentTerm)
  have advancedInvariant : SystemInductiveInvariant (joined := joinedNodes) advanced := by
    exact
      advanceCommitTransitionPreservesSystemInductiveInvariant (present := present)
        state source distinct invariant
          ⟨enabled.1, enabled.2.2.1, enabled.2.2.2.1⟩
  simpa [concrete_effects, present, advanced, request]
    using enqueueProposeVoteRequestPreservesSystemInductiveInvariant
      advanced request advancedInvariant
      (invariantCurrentTermsValid invariant source)

/-- Entering a speculative election changes no consensus-safety evidence. -/
lemma becomePreVoteCandidatePreservesSystemInductiveInvariant
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
          /\ INITIAL_PRE_VOTE_STATUS node = .enabled))
    : SystemInductiveInvariant (joined := joinedNodes) (becomePreVoteCandidateEffect state node) := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  let after := becomePreVoteCandidateEffect state node
  have packed : SystemInductiveInvariant (joined := joinedNodes) state :=
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have oldParticipating :
      Not (((nodeOf state) node).role = .none) := by
    rcases enabled.2.1 with follower | preVoteCandidate | candidate
    · simp [follower]
    · simp [preVoteCandidate]
    · simp [candidate]
  have oldNotLeader :
      Not (((nodeOf state) node).role = .leader) := by
    rcases enabled.2.1 with follower | preVoteCandidate | candidate
    · exact fun leader => Role.noConfusion (follower.symm.trans leader)
    · exact
        fun leader =>
          Role.noConfusion (preVoteCandidate.symm.trans leader)
    · exact fun leader => Role.noConfusion (candidate.symm.trans leader)
  have roleNode :
      ((nodeOf after) node).role = .preVoteCandidate := by
    simp [after, present, concrete_effects, present]
  have roleOther :
      forall candidate,
        Not (candidate = node) ->
          ((nodeOf after) candidate).role =
            ((nodeOf state) candidate).role := by
    intro candidate different
    simp [
      after, present, concrete_effects, present, nodeOf_replaceNode, different
    ]
  have termEq :
      forall candidate,
        ((nodeOf after) candidate).currentTerm =
          ((nodeOf state) candidate).currentTerm := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, concrete_effects, present, nodeOf_replaceNode, same
      ]
  have logEq :
      forall candidate,
        ((nodeOf after) candidate).log =
          ((nodeOf state) candidate).log := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, concrete_effects, present, nodeOf_replaceNode, same
      ]
  have commitEq :
      forall candidate,
        ((nodeOf after) candidate).commitIndex =
          ((nodeOf state) candidate).commitIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, concrete_effects, present, nodeOf_replaceNode, same
      ]
  have sentEq :
      forall candidate,
        ((nodeOf after) candidate).sentIndex =
          ((nodeOf state) candidate).sentIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, concrete_effects, present, nodeOf_replaceNode, same
      ]
  have matchEq :
      forall candidate,
        ((nodeOf after) candidate).matchIndex =
          ((nodeOf state) candidate).matchIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, concrete_effects, present, nodeOf_replaceNode, same
      ]
  have votedEq :
      forall candidate,
        ((nodeOf after) candidate).votedFor =
          ((nodeOf state) candidate).votedFor := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, concrete_effects, present, nodeOf_replaceNode, same
      ]
  have votesEq :
      forall candidate,
        ((nodeOf after) candidate).votesGranted =
          ((nodeOf state) candidate).votesGranted := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        after, present, concrete_effects, present, nodeOf_replaceNode, same
      ]
  have activeConfigurationsEq :
      forall candidate,
        activeConfigurations ((nodeOf after) candidate) =
          activeConfigurations ((nodeOf state) candidate) := by
    intro candidate
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have participatingBack :
      forall candidate,
        Not (((nodeOf after) candidate).role = .none) ->
          Not (((nodeOf state) candidate).role = .none) := by
    intro candidate participating
    by_cases same : candidate = node
    · subst candidate
      exact oldParticipating
    · simpa [roleOther candidate same] using participating
  have candidateBack :
      forall candidate,
        ((nodeOf after) candidate).role = .candidate ->
          ((nodeOf state) candidate).role = .candidate := by
    intro candidate role
    by_cases same : candidate = node
    · subst candidate
      exact False.elim (Role.noConfusion (roleNode.symm.trans role))
    · simpa [roleOther candidate same] using role
  have leaderBack :
      forall leader,
        ((nodeOf after) leader).role = .leader ->
          ((nodeOf state) leader).role = .leader := by
    intro leader role
    by_cases same : leader = node
    · subst leader
      exact False.elim (Role.noConfusion (roleNode.symm.trans role))
    · simpa [roleOther leader same] using role
  have activeRoleBack :
      forall candidate,
        (((nodeOf after) candidate).role = .candidate \/
          ((nodeOf after) candidate).role = .leader) ->
        (((nodeOf state) candidate).role = .candidate \/
          ((nodeOf state) candidate).role = .leader) := by
    intro candidate active
    rcases active with candidateRole | leaderRole
    · exact Or.inl (candidateBack candidate candidateRole)
    · exact Or.inr (leaderBack candidate leaderRole)
  have effectiveAckersEq :
      forall actualResponseHistory leader index,
        effectiveAckers (joined := joinedNodes) after actualResponseHistory leader index =
          effectiveAckers (joined := joinedNodes) state actualResponseHistory leader index :=
    effectiveAckersFrame
      state after
        (by simp [after, present, concrete_effects, present])
        (by simp [after, present, concrete_effects, present])
        termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters (joined := joinedNodes) after candidate =
          effectiveElectionVoters (joined := joinedNodes) state candidate :=
    effectiveElectionVotersFrame
      state after
        (by simp [after, present, concrete_effects, present])
        (by simp [after, present, concrete_effects, present])
        termEq votesEq
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters (joined := joinedNodes) after candidate =
          potentialElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨
          by simpa [after, present, concrete_effects, present] using joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq] at effective
              exact effective)
        ⟩
      · exact ⟨
          by simpa [after, present, concrete_effects, present] using joined,
          Or.inr
            (by
              simpa [currentlyEligibleElectionVoter, voteRequestKey, Model.Local.makeRequestVoteRequest, termEq,
                logEq, commitEq, votedEq,
                lastCommittableIndexFrame
                  (logEq candidate) (commitEq candidate),
                lastCommittableTermFrame
                  (logEq candidate) (commitEq candidate), voteLogUpToDate]
                using eligible)
        ⟩
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨
          by simpa [after, present, concrete_effects, present] using joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq]
              exact effective)
        ⟩
      · exact ⟨
          by simpa [after, present, concrete_effects, present] using joined,
          Or.inr
            (by
              simpa [currentlyEligibleElectionVoter, voteRequestKey, Model.Local.makeRequestVoteRequest, termEq,
                logEq, commitEq, votedEq,
                lastCommittableIndexFrame
                  (logEq candidate) (commitEq candidate),
                lastCommittableTermFrame
                  (logEq candidate) (commitEq candidate), voteLogUpToDate]
                using eligible)
        ⟩
  have joinedCarriersAfter : JoinedCarrierFacts (joined := joinedNodes) after := by
    apply
      joinedCarrierFactsFrame
        state after facts.joinedCarriers
          (by simp [after, present, concrete_effects, present])
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
            simpa [after, present, concrete_effects, present] using member)
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
  change SystemInductiveInvariant (joined := joinedNodes) after
  apply roleAndNetworkFramePreservesSystemInductiveInvariant state after packed (by simp [after, present, concrete_effects, present])
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
        (by simpa [after, present, concrete_effects, present] using member)
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
        by simpa [after, present, concrete_effects, present] using joined,
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
            ((nodeOf state) peer) request index := by
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
              (nodeOf after) peer = (nodeOf state) peer := by
            simp [
              after, present, concrete_effects, present, nodeOf_replaceNode, same
            ]
          simpa [peerStateEq] using producible
      exact ⟨
        by simpa [after, present, concrete_effects, present] using joined,
        Or.inr
          ⟨
            request,
            by simpa [after, present, concrete_effects, present] using queued,
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
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : (node = INITIAL_LEADER
          /\ node ∈ joinedNodes
          /\ ((nodeOf state) node).role = .leader
          /\ ((nodeOf state) node).currentTerm = BOOTSTRAP_TERM
          /\ ((nodeOf state) node).log = []
          /\ ((nodeOf state) node).commitIndex = 0
          /\ ((nodeOf state) node).membershipState = .active))
    : SystemInductiveInvariant (joined := joinedNodes) (initializeConfigurationEffect state node) := by
  rcases enabled with ⟨_, allocated, leader, _, emptyLog, _, _⟩
  have latest :
      latestConfiguration ((nodeOf state) node) = implicitConfiguration := by
    simp [latestConfiguration, configurationsInLog, configurationsInLogFrom, emptyLog]
  let appended := leaderAppendState state node
    (.reconfiguration INITIAL_CONFIGURATION)
  have appendedInvariant : SystemInductiveInvariant (joined := joinedNodes) appended := by
    simpa only [leaderAppendJoined, latest, implicitConfiguration, Finset.sdiff_self, Finset.union_empty]
      using leaderAppendPreservesSystemInductiveInvariant state node (present := present)
        (.reconfiguration INITIAL_CONFIGURATION) invariant allocated leader
  apply retirementMetadataFramePreservesSystemInductiveInvariant
    appended _ appendedInvariant
  · simp [appended, leaderAppendState, present, latest, implicitConfiguration, concrete_effects, present]
  · rfl
  all_goals
    intro candidate
    by_cases same : candidate = node <;>
      simp [appended, leaderAppendState, present, latest, implicitConfiguration, concrete_effects, present,
        nodeOf_replaceNode, same, emptyLog]

end CCFRaft.Proofs.Invariant
