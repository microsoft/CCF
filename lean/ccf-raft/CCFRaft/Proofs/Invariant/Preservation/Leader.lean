-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.ObserveTerm
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

/-- Promoting a winning candidate preserves all arbitrary-term support facts. -/
lemma becomeLeaderPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (node : Node)
    (invariant : SystemInductiveInvariant state)
    (enabled
      : (state.allocated node
          /\ (state.nodes node).role = .candidate
          /\ Not ((state.nodes node).membershipState = .retiredCommitted)
          /\ hasElectionMajority state node
          /\ Not
              ((refreshRetirementState node
                  ({
                    (state.nodes node) with
                      log :=
                        ((state.nodes node).log.take
                          (maxCommittableIndex (state.nodes node).log))
                  })).membershipState
                = .retiredCommitted)))
    : SystemInductiveInvariant (becomeLeaderEffect state node) := by
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
  have monoLog := invariantFactsMonoLogFromCanonicalHistories facts
  have candidatesAboveBootstrap :=
    invariantFactsCandidatesAboveBootstrap facts
  have oldRole : (state.nodes node).role = .candidate := enabled.2.1
  have oldMajority : hasElectionMajority state node := enabled.2.2.2.1
  have oldEffectiveMajority :
      hasEffectiveElectionMajority state node :=
    electionMajorityImpliesEffective
      state node (facts.joinedCarriers.grantedVotes node) oldMajority
  have oldPotentialMajority :
      hasPotentialElectionMajority state node :=
    effectiveElectionMajorityImpliesPotential
      state node oldEffectiveMajority
  have oldTermUnowned :
      owners (state.nodes node).currentTerm = none :=
    effectiveCandidateTermUnowned
      candidatesAboveBootstrap facts.grantedVoteSnapshots
        ownership electionFacts configurationFacts
        oldRole oldEffectiveMajority
  have oldCandidateTermNot :
      CandidateTermNotInLogs state :=
    termOwnershipCandidateTermNotInLogs
      candidatesAboveBootstrap facts.grantedVoteSnapshots
        ownership electionFacts configurationFacts
  let promotionLog :=
    (state.nodes node).log.take
      (maxCommittableIndex (state.nodes node).log)
  have promotionPrefix :
      promotionLog <+: (state.nodes node).log :=
    List.take_prefix _ _
  have promotionLength :
      promotionLog.length =
        maxCommittableIndex (state.nodes node).log := by
    simp [
      promotionLog,
      Nat.min_eq_left
        (maxCommittableIndexBounded (state.nodes node).log)
    ]
  have promotionCommittable :
      EndsAtMaxCommittable promotionLog := by
    change maxCommittableIndex promotionLog = promotionLog.length
    rw [promotionLength]
    exact maxCommittableIndexTakeMax (state.nodes node).log
  let newOwners : TermOwners (Node : Type) :=
    Function.update owners (state.nodes node).currentTerm (some node)
  let newCanonicalHistory : Nat -> List (Entry Node TxId) :=
    Function.update canonicalHistory
      (state.nodes node).currentTerm promotionLog
  let electionRecord : ElectionRecord Node TxId :=
    { leader := node
      supporters := (state.nodes node).votesGranted
      ballotLog := (state.nodes node).log
      ballotCommitIndex := (state.nodes node).commitIndex
      ballotActive := activeConfigurations (state.nodes node)
      promotionLog
      candidateLog := fun voter =>
        if voter = node then
          promotionLog
        else
          voteCandidateHistory
            (grantedVoteKey
              voter (state.nodes node).currentTerm node)
      voterLog := fun voter =>
        if voter = node then
          promotionLog
        else
          voteVoterHistory
            (grantedVoteKey
              voter (state.nodes node).currentTerm node) }
  let newElections : ElectionHistory Node TxId :=
    Function.update elections
      (state.nodes node).currentTerm (some electionRecord)
  have canonicalFrameToNew :
      forall history,
        HistoryCanonical canonicalHistory history ->
          HistoryCanonical newCanonicalHistory history := by
    intro history canonical index entry found
    rcases canonical index entry found with
      ⟨canonicalFound, agreed⟩
    have entryTermNe :
        Not (entry.term = (state.nodes node).currentTerm) := by
      intro same
      rcases
          ownership.canonicalEntryOwner
            entry.term index entry canonicalFound with
        ⟨owner, owned⟩
      rw [same, oldTermUnowned] at owned
      contradiction
    exact ⟨
      by simpa [
          newCanonicalHistory, Function.update, entryTermNe
        ] using canonicalFound,
      by simpa [
          newCanonicalHistory, Function.update, entryTermNe
        ] using agreed
    ⟩
  have recordedTermNeNew :
      forall term record,
        elections term = some record ->
          Not (term = (state.nodes node).currentTerm) := by
    intro term record recorded same
    subst term
    have owned :=
      electionFacts.recordOwned
        (state.nodes node).currentTerm record recorded
    rw [oldTermUnowned] at owned
    contradiction
  let newAckHistory : ProcessedAckHistory Node TxId :=
    Function.update ackHistory node (fun _ => none)
  have roleNode :
      ((becomeLeaderEffect state node).nodes node).role = .leader := by
    simp [view_effects]
  have roleOther :
      forall candidate,
        Not (candidate = node) ->
        ((becomeLeaderEffect state node).nodes candidate).role =
          (state.nodes candidate).role := by
    intro candidate different
    simp [
      view_effects, updateNode, different
    ]
  have logNode :
      ((becomeLeaderEffect state node).nodes node).log =
        promotionLog := by
    simp [view_effects, promotionLog]
  have logOther :
      forall candidate,
        Not (candidate = node) ->
        ((becomeLeaderEffect state node).nodes candidate).log =
          (state.nodes candidate).log := by
    intro candidate different
    simp [
      view_effects, updateNode, different
    ]
  have termEq :
      forall candidate,
        ((becomeLeaderEffect state node).nodes candidate).currentTerm =
          (state.nodes candidate).currentTerm := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        view_effects, updateNode, same
      ]
  have commitEq :
      forall candidate,
        ((becomeLeaderEffect state node).nodes candidate).commitIndex =
          (state.nodes candidate).commitIndex := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        view_effects, updateNode, same
      ]
  have committedEq :
      forall candidate,
        ((becomeLeaderEffect state node).nodes candidate).committedLog =
          (state.nodes candidate).committedLog := by
    intro candidate
    by_cases same : candidate = node
    · subst candidate
      have commitBound :=
        commitIndex_le_maxCommittableIndex
          (state.nodes node)
          (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
            facts node)
      simp [
        NodeState.committedLog, commitEq, logNode,
        promotionLog, List.take_take,
        Nat.min_eq_left commitBound
      ]
    · simp [
        NodeState.committedLog, commitEq,
        logOther candidate same
      ]
  have maxCommittableIndexEq :
      forall candidate,
        maxCommittableIndex
            ((becomeLeaderEffect state node).nodes candidate).log =
          maxCommittableIndex (state.nodes candidate).log := by
    intro candidate
    by_cases same : candidate = node
    · subst candidate
      rw [logNode, promotionCommittable, promotionLength]
    · rw [logOther candidate same]
  have maxCommittableTermEq :
      forall candidate,
        maxCommittableTerm
            ((becomeLeaderEffect state node).nodes candidate).log =
          maxCommittableTerm (state.nodes candidate).log := by
    intro candidate
    by_cases same : candidate = node
    · subst candidate
      unfold maxCommittableTerm
      rw [maxCommittableIndexEq, logNode]
      exact termAtTakeOfLe le_rfl
    · rw [logOther candidate same]
  have lastIndexEq :
      forall candidate,
        lastCommittableIndex
            ((becomeLeaderEffect state node).nodes candidate) =
          lastCommittableIndex (state.nodes candidate) := by
    intro candidate
    simp [
      lastCommittableIndex, commitEq,
      maxCommittableIndexEq
    ]
  have lastTermEq :
      forall candidate,
        lastCommittableTerm
            ((becomeLeaderEffect state node).nodes candidate) =
          lastCommittableTerm (state.nodes candidate) := by
    intro candidate
    unfold lastCommittableTerm
    rw [lastIndexEq]
    by_cases same : candidate = node
    · subst candidate
      rw [logNode]
      rw [lastCommittableIndex_eq_maxCommittableIndex
        (state.nodes node)
        (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
          facts node)]
      exact termAtTakeOfLe le_rfl
    · rw [logOther candidate same]
  have votedEq :
      forall candidate,
        ((becomeLeaderEffect state node).nodes candidate).votedFor =
          (state.nodes candidate).votedFor := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        view_effects, updateNode, same
      ]
  have votesEq :
      forall candidate,
        ((becomeLeaderEffect state node).nodes candidate).votesGranted =
          (state.nodes candidate).votesGranted := by
    intro candidate
    by_cases same : candidate = node <;>
      simp [
        view_effects, updateNode, same
      ]
  have sentNode :
      ((becomeLeaderEffect state node).nodes node).sentIndex =
        fun _ => promotionLog.length := by
    simp [view_effects, promotionLog]
  have matchNode :
      ((becomeLeaderEffect state node).nodes node).matchIndex =
        fun _ => 0 := by
    simp [view_effects]
  have sentOther :
      forall candidate,
        Not (candidate = node) ->
        ((becomeLeaderEffect state node).nodes candidate).sentIndex =
          (state.nodes candidate).sentIndex := by
    intro candidate different
    simp [
      view_effects, updateNode, different
    ]
  have matchOther :
      forall candidate,
        Not (candidate = node) ->
        ((becomeLeaderEffect state node).nodes candidate).matchIndex =
          (state.nodes candidate).matchIndex := by
    intro candidate different
    simp [
      view_effects, updateNode, different
    ]
  have networkEq :
      (becomeLeaderEffect state node).network = state.network := by
    simp [view_effects]
  have currentConfigurationNodeEq :
      currentConfiguration
          ((becomeLeaderEffect state node).nodes node) =
        currentConfiguration (state.nodes node) := by
    let afterNode := (becomeLeaderEffect state node).nodes node
    have oldKnownAfter :
        currentConfiguration (state.nodes node) ∈
          allConfigurations afterNode.log := by
      rw [show afterNode.log = promotionLog by
        simpa [afterNode] using logNode]
      simpa [promotionLog]
        using allConfigurations_mem_take_of_index_le
          (state.nodes node).log
          (maxCommittableIndex (state.nodes node).log)
          (maxCommittableIndexBounded (state.nodes node).log)
          (currentConfiguration_mem_allConfigurations (state.nodes node))
          ((currentConfiguration_index_le_commitIndex (state.nodes node)).trans
            (commitIndex_le_maxCommittableIndex
              (state.nodes node)
              (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts node)))
    have afterKnownOld :
        currentConfiguration afterNode ∈
          allConfigurations (state.nodes node).log := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix promotionPrefix)
      simpa [afterNode, logNode]
        using currentConfiguration_mem_allConfigurations afterNode
    have oldIndexLeAfter :
        (currentConfiguration (state.nodes node)).index <=
          (currentConfiguration afterNode).index := by
      apply
        configuration_index_le_currentConfiguration
          afterNode (currentConfiguration (state.nodes node))
          oldKnownAfter
      simpa [afterNode, commitEq]
        using currentConfiguration_index_le_commitIndex (state.nodes node)
    have afterIndexLeOld :
        (currentConfiguration afterNode).index <=
          (currentConfiguration (state.nodes node)).index := by
      apply
        configuration_index_le_currentConfiguration
          (state.nodes node) (currentConfiguration afterNode)
          afterKnownOld
      have bound :=
        currentConfiguration_index_le_commitIndex afterNode
      simpa [afterNode, commitEq] using bound
    exact
      allConfigurations_index_unique
        (state.nodes node).log afterKnownOld
        (currentConfiguration_mem_allConfigurations (state.nodes node))
        (Nat.le_antisymm afterIndexLeOld oldIndexLeAfter)
  have currentConfigurationEq :
      forall candidate,
        currentConfiguration
            ((becomeLeaderEffect state node).nodes candidate) =
          currentConfiguration (state.nodes candidate) := by
    intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      exact currentConfigurationNodeEq
    · unfold currentConfiguration
      rw [logOther candidate candidateEq, commitEq]
  have activeConfigurationsNodeSubset :
      forall configuration,
        configuration ∈
            activeConfigurations
              ((becomeLeaderEffect state node).nodes node) ->
          configuration ∈ activeConfigurations (state.nodes node) := by
    intro configuration active
    have parts :
        configuration ∈
            allConfigurations
              ((becomeLeaderEffect state node).nodes node).log /\
          (currentConfiguration
              ((becomeLeaderEffect state node).nodes node)).index <=
            configuration.index := by
      simpa [activeConfigurations] using active
    have knownOld :
        configuration ∈ allConfigurations (state.nodes node).log := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix promotionPrefix)
      simpa [logNode] using parts.1
    simpa [activeConfigurations, currentConfigurationNodeEq]
      using And.intro knownOld parts.2
  have activeConfigurationsOtherEq :
      forall candidate,
        Not (candidate = node) ->
          activeConfigurations
              ((becomeLeaderEffect state node).nodes candidate) =
            activeConfigurations (state.nodes candidate) := by
    intro candidate candidateNe
    unfold activeConfigurations currentConfiguration
    rw [logOther candidate candidateNe, commitEq]
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters
            (becomeLeaderEffect state node) candidate =
          effectiveElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [view_effects] using joined,
          Or.inl (by simpa [votesEq] using processed)
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
          by simpa [networkEq] using member,
          granted,
          by simpa [termEq] using responseTerm,
          responseSource,
          responseDestination
        ⟩
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [view_effects] using joined,
          Or.inl (by simpa [votesEq] using processed)
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
          by simpa [networkEq] using member,
          granted,
          by simpa [termEq] using responseTerm,
          responseSource,
          responseDestination
        ⟩
  have effectiveElectionMajorityEq :
      forall candidate,
        Not (candidate = node) ->
          (hasEffectiveElectionMajority
              (becomeLeaderEffect state node) candidate ↔
            hasEffectiveElectionMajority state candidate) := by
    intro candidate candidateNe
    simp only [
      hasEffectiveElectionMajority,
      effectiveElectionVotersEq,
      activeConfigurationsOtherEq candidate candidateNe
    ]
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters
            (becomeLeaderEffect state node) candidate =
          potentialElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter]
    constructor <;> rintro ⟨joined, effective | eligible⟩
    · exact ⟨by simpa [view_effects] using joined, Or.inl (by
        rw [effectiveElectionVotersEq] at effective
        exact effective)⟩
    · exact ⟨by simpa [view_effects] using joined, Or.inr (by
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          termEq, maxCommittableIndexEq, maxCommittableTermEq,
          lastIndexEq, lastTermEq, votedEq, voteLogUpToDate
        ] using eligible)⟩
    · exact ⟨by simpa [view_effects] using joined, Or.inl (by
        rw [effectiveElectionVotersEq]
        exact effective)⟩
    · exact ⟨by simpa [view_effects] using joined, Or.inr (by
        simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          termEq, maxCommittableIndexEq, maxCommittableTermEq,
          lastIndexEq, lastTermEq, votedEq, voteLogUpToDate
        ] using eligible)⟩
  have potentialElectionMajorityEq :
      forall candidate,
        Not (candidate = node) ->
          (hasPotentialElectionMajority
              (becomeLeaderEffect state node) candidate ↔
            hasPotentialElectionMajority state candidate) := by
    intro candidate candidateNe
    simp only [
      hasPotentialElectionMajority,
      potentialElectionVotersEq,
      activeConfigurationsOtherEq candidate candidateNe
    ]
  have effectiveAckersOtherEq :
      forall leader,
        Not (leader = node) ->
          forall index,
            effectiveAckers
                (becomeLeaderEffect state node)
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
          Or.inr (Or.inl (by simpa [matchOther leader leaderNe] using matched))
        ⟩
      · refine ⟨
          by simpa [view_effects] using joined,
          Or.inr (Or.inr ?_)
        ⟩
        rcases queued with
          ⟨response, member, success, responseTerm, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact ⟨
          response,
          by simpa [networkEq] using member,
          success,
          by simpa [termEq] using responseTerm,
          sourceEq,
          destinationEq,
          lastIndex,
          by simpa [logOther leader leaderNe] using covered
        ⟩
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨by simpa [view_effects] using joined, Or.inl self⟩
      · exact ⟨
          by simpa [view_effects] using joined,
          Or.inr (Or.inl (by simpa [matchOther leader leaderNe] using matched))
        ⟩
      · refine ⟨
          by simpa [view_effects] using joined,
          Or.inr (Or.inr ?_)
        ⟩
        rcases queued with
          ⟨response, member, success, responseTerm, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact ⟨
          response,
          by simpa [networkEq] using member,
          success,
          by simpa [termEq] using responseTerm,
          sourceEq,
          destinationEq,
          lastIndex,
          by simpa [logOther leader leaderNe] using covered
        ⟩
  have effectiveMajorityOtherEq :
      forall leader,
        Not (leader = node) ->
          forall index,
            hasEffectiveMajorityAt
                (becomeLeaderEffect state node)
                responseHistory leader index ↔
              hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader leaderNe index
    simp only [
      hasEffectiveMajorityAt,
      effectiveAckersOtherEq leader leaderNe index,
      activeConfigurationsOtherEq leader leaderNe
    ]
  have potentialAckersOtherSubset :
      forall leader,
        Not (leader = node) ->
          forall index,
            potentialAckers
                (becomeLeaderEffect state node)
                appendHistory responseHistory leader index ⊆
              potentialAckers
                state appendHistory responseHistory leader index := by
    intro leader leaderNe index peer member
    simp only [
      potentialAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | reserve⟩
    · exact ⟨by simpa [view_effects] using joined, Or.inl (by
        rw [effectiveAckersOtherEq leader leaderNe index] at effective
        exact effective)⟩
    · refine ⟨by simpa [view_effects] using joined, Or.inr ?_⟩
      rcases reserve with
        ⟨request, queued, requestSource, requestDestination,
          requestTerm, producible, covered⟩
      have requestDestinationEq := requestDestination
      exact ⟨
        request,
        by simpa [networkEq] using queued,
        requestSource,
        requestDestination,
        by simpa [termEq] using requestTerm,
        by
          by_cases peerEq : peer = node
          · have destinationEq : request.destination = node :=
              requestDestinationEq.trans peerEq
            rcases producible with direct | future
            · have follower := canProduceAppendAckAt_role direct
              rw [peerEq, roleNode] at follower
              contradiction
            · exact Or.inr (by simpa [termEq] using future)
          · simpa [
              view_effects, updateNode,
              Function.update, peerEq
            ] using producible,
        by simpa [logOther leader leaderNe] using covered
      ⟩
  have potentialMajorityOtherBack :
      forall leader,
        Not (leader = node) ->
          forall index,
            hasPotentialMajorityAt
                (becomeLeaderEffect state node)
                appendHistory responseHistory leader index ->
              hasPotentialMajorityAt
                state appendHistory responseHistory leader index := by
    intro leader leaderNe index majority
    rw [hasPotentialMajorityAt, List.all_eq_true] at majority
    rw [hasPotentialMajorityAt, List.all_eq_true]
    intro configuration active
    apply decide_eq_true
    intro governs
    have afterActive :
        configuration ∈
          activeConfigurations
            ((becomeLeaderEffect state node).nodes leader) := by
      simpa [activeConfigurationsOtherEq leader leaderNe] using active
    exact
      hasConfigurationMajority_mono
        (potentialAckersOtherSubset leader leaderNe index)
        ((of_decide_eq_true
          (majority configuration afterActive)) governs)
  have noNewLeaderCurrentTerm :
      forall index,
        Not (
          termAt
              ((becomeLeaderEffect state node).nodes node).log index =
            ((becomeLeaderEffect state node).nodes node).currentTerm) := by
    intro index current
    have positive :
        0 <
          termAt
            ((becomeLeaderEffect state node).nodes node).log index := by
      rw [current, termEq]
      exact positiveOfBootstrapTermLe
        (facts.currentTermsPositive node (by rw [oldRole]; decide))
    rcases termAtPositiveEntry positive with
      ⟨foundEntry, found, foundTerm⟩
    have oldFound :
        entryAt? (state.nodes node).log index = some foundEntry := by
      rw [logNode] at found
      exact entryAt_of_prefix promotionPrefix found
    exact
      oldCandidateTermNot
        node oldRole oldEffectiveMajority node index foundEntry
          oldFound
          (by simpa [termEq] using foundTerm.trans current)
  have preserveEarlierBad :
      forall source index bound,
        Not (source = node) ->
        EarlierBadElection state elections source index bound ->
          EarlierBadElection
            (becomeLeaderEffect state node)
              newElections source index bound := by
    intro source index bound sourceNe bad
    rcases bad with
      ⟨badTerm, badRecord, above, bounded, badRecorded, missing⟩
    have badTermNe :=
      recordedTermNeNew badTerm badRecord badRecorded
    exact ⟨
      badTerm,
      badRecord,
      by simpa [termEq] using above,
      bounded,
      by simpa [
          newElections, Function.update, badTermNe
        ] using badRecorded,
      by simpa [logOther source sourceNe] using missing
    ⟩
  refine ⟨
    votes,
    appendHistory,
    responseHistory,
    voteRequestHistory,
    voteCandidateHistory,
    voteVoterHistory,
    ?_
  ⟩
  constructor
  · intro candidate
    by_cases same : candidate = node
    · subst candidate
      rw [commitEq, logNode, promotionLength]
      exact
        commitIndex_le_maxCommittableIndex
          (state.nodes node)
          (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
            facts node)
    · rw [commitEq, logOther candidate same]
      exact facts.commitIndicesBounded candidate
  · intro candidate participating
    rw [termEq]
    apply facts.currentTermsPositive candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      rw [oldRole]
      decide
    · intro none
      apply participating
      simpa [roleOther candidate candidateEq] using none
  · intro candidate entry member
    rw [termEq]
    by_cases same : candidate = node
    · subst candidate
      rw [logNode] at member
      exact
        facts.entriesDoNotExceedCurrentTerm node entry
          (memOfPrefix promotionPrefix member)
    · rw [logOther candidate same] at member
      exact facts.entriesDoNotExceedCurrentTerm candidate entry member
  · intro candidate role
    have candidateNe : Not (candidate = node) := by
      intro same
      subst candidate
      exact Role.noConfusion (role.symm.trans roleNode)
    rw [roleOther candidate candidateNe] at role
    rw [votedEq, votesEq]
    exact facts.candidatesSelfVote candidate role
  · intro leader role
    by_cases leaderEq : leader = node
    · subst leader
      refine Or.inr
        ⟨currentConfiguration (state.nodes node), ?_, ?_⟩
      · rw [← currentConfigurationNodeEq]
        exact currentConfiguration_mem_allConfigurations _
      · rw [votesEq]
        exact
          electionMajorityAtConfiguration oldMajority
            (currentConfiguration_mem_activeConfigurations _)
    · rw [roleOther leader leaderEq] at role
      have old := facts.leadersHaveElectionWitness leader role
      rw [termEq]
      rcases old with bootstrap | majority
      · exact Or.inl bootstrap
      · exact Or.inr (by
          simpa [logOther leader leaderEq, votesEq] using majority)
  · intro leader role peer
    by_cases leaderEq : leader = node
    · subst leader
      rw [sentNode, matchNode, logNode]
      simp
    · rw [roleOther leader leaderEq] at role
      have old := facts.leaderProgressBounded leader role peer
      rw [
        sentOther leader leaderEq, matchOther leader leaderEq,
        logOther leader leaderEq
      ]
      exact old
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [termEq, votedEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      rw [termEq] at future
      exact facts.voteHistory.future voter term future
    · intro candidate voter active member
      rw [termEq]
      rw [votesEq] at member
      by_cases candidateEq : candidate = node
      · subst candidate
        exact
          facts.voteHistory.counted
            node voter (Or.inl oldRole) member
      · rw [roleOther candidate candidateEq] at active
        exact facts.voteHistory.counted candidate voter active member
  · constructor
    · intro destination message member
      rw [networkEq] at member
      exact facts.networkHistory.addressed destination message member
    · intro destination request member
      rw [networkEq] at member
      have old := facts.networkHistory.appendRequest destination request member
      refine ⟨old.1, old.2.1, ?_⟩
      unfold RequestCommitStillPresent at old ⊢
      rw [committedEq]
      exact old.2.2
    · intro destination response member success
      rw [networkEq] at member
      have responseDestination :
          response.destination = destination := by
        simpa using
          facts.networkHistory.addressed
            destination (.appendEntriesResponse response) member
      subst destination
      rcases
          facts.networkHistory.appendResponse
            response.destination response member success with
        ⟨lengthBound, termBound, supported⟩
      refine ⟨lengthBound, by simpa [termEq] using termBound, ?_⟩
      intro sameTerm
      have oldSameTerm :
          response.term =
            (state.nodes response.destination).currentTerm := by
        simpa [termEq] using sameTerm
      by_cases destinationEq : response.destination = node
      · rcases supported oldSameTerm with
          active | follower | preVoteCandidate | inactive
        · have oldLeader :
              (state.nodes node).role = .leader := by
            simpa [destinationEq] using active.1
          exact False.elim
            (Role.noConfusion (oldRole.symm.trans oldLeader))
        · have oldFollower :
              (state.nodes node).role = .follower := by
            simpa [destinationEq] using follower
          exact False.elim
            (Role.noConfusion (oldRole.symm.trans oldFollower))
        · have oldPreVoteCandidate :
              (state.nodes node).role = .preVoteCandidate := by
            simpa [destinationEq] using preVoteCandidate
          exact False.elim
            (Role.noConfusion (oldRole.symm.trans oldPreVoteCandidate))
        · have oldInactive : (state.nodes node).role = .none := by
            simpa [destinationEq] using inactive
          exact False.elim
            (Role.noConfusion (oldRole.symm.trans oldInactive))
      · rcases supported oldSameTerm with
          active | follower | preVoteCandidate
        · exact Or.inl
            ⟨by
                simpa [roleOther response.destination destinationEq] using
                  active.1,
              by simpa [logOther response.destination destinationEq] using
                active.2⟩
        · exact Or.inr
            (Or.inl (by
              simpa [roleOther response.destination destinationEq] using
                follower))
        · exact Or.inr
            (Or.inr (by
              simpa [roleOther response.destination destinationEq] using
                preVoteCandidate))
    · intro destination request member
      rw [networkEq] at member
      rcases
          facts.networkHistory.voteRequest destination request member with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      refine ⟨
        lastIndex,
        lastTerm,
        maxIndex,
        aboveBootstrap,
        by simpa [termEq] using termBound,
        ?_
      ⟩
      intro sameTerm active
      have oldPrefix := activePrefix
        (by simpa [termEq] using sameTerm)
        (by
          by_cases sourceEq : request.source = node
          · rw [sourceEq]
            exact Or.inl oldRole
          · simpa [roleOther request.source sourceEq] using active)
      by_cases sourceEq : request.source = node
      · rw [sourceEq] at oldPrefix ⊢
        rw [logNode]
        exact
          committablePrefixOfMaxTake oldPrefix maxIndex
      · simpa [logOther request.source sourceEq] using oldPrefix
    · intro destination response member granted
      rw [networkEq] at member
      rcases
          facts.networkHistory.voteResponse destination response member granted with
        ⟨termBound, vote, candidateCommittable,
          voterCommittable, upToDate⟩
      exact ⟨
        by simpa [termEq] using termBound,
        vote,
        candidateCommittable,
        voterCommittable,
        by simpa [voteLogUpToDate] using upToDate
      ⟩
  have evidenceAfter :
      CommitEvidenceFacts
        (becomeLeaderEffect state node)
        appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
        state (becomeLeaderEffect state node)
        appendHistory nodeEvidence requestEvidence evidenceFacts
        commitEq committedEq
    · intro candidate
      exact Nat.le_of_eq (termEq candidate).symm
    · intro destination request member
      simpa [networkEq] using member
  have knownBack :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            (becomeLeaderEffect state node)
            appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix := by
    intro evidence supportedPrefix known
    exact
      knownCommitEvidenceFrameBack
        state (becomeLeaderEffect state node)
          appendHistory nodeEvidence requestEvidence
          commitEq committedEq
          (fun destination request member => by
            simpa [networkEq] using member)
          known
  have newPromotionCovered :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            (becomeLeaderEffect state node)
            appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
        evidence.commitTerm < (state.nodes node).currentTerm ->
          evidence.history.take evidence.commitFrontier <+:
            promotionLog := by
    intro evidence supportedPrefix known strict
    have oldKnown := knownBack evidence supportedPrefix known
    rcases knownCommitEvidenceValid evidenceFacts oldKnown with
      ⟨frontierBound, frontierTerm, supportedBound,
        supportedEq, _authority, ackMajority, frontierSignature,
        _supportedSignature⟩
    rcases
        activationEvidence.candidateBridge
          evidence supportedPrefix oldKnown node oldRole
          (effectiveElectionMajorityImpliesPotential
            state node oldEffectiveMajority)
          strict with
      direct | authorityActive
    · apply signatureEndedPrefixOfMaxTake direct
      have prefixLength :
          (evidence.history.take evidence.commitFrontier).length =
            evidence.commitFrontier := by
        simp [Nat.min_eq_left frontierBound]
      rw [prefixLength]
      exact isSignatureAt_take_of_le le_rfl frontierSignature
    · have electionMajority :=
        effectiveElectionMajorityAtConfiguration
          oldEffectiveMajority authorityActive
      rcases
          configurationMajoritiesIntersect
            ackMajority electionMajority with
        ⟨witness, _authorityMember, ackMember, electionMember⟩
      have candidateEntriesBefore :
          forall entry,
            entry ∈ (state.nodes node).log ->
              entry.term < (state.nodes node).currentTerm := by
        intro entry entryMember
        have bounded :=
          facts.entriesDoNotExceedCurrentTerm node entry entryMember
        have different :
            Not (entry.term = (state.nodes node).currentTerm) := by
          intro same
          rcases memberEntryAt entryMember with ⟨index, found⟩
          exact
            oldCandidateTermNot
              node oldRole oldEffectiveMajority
                node index entry found same
        omega
      have covered :=
        prospectiveFacts.relaxedSupporterCarriesFrontier evidence supportedPrefix oldKnown
          node witness oldRole strict candidateEntriesBefore ackMember
          (by
            simp only [
              relaxedElectionVoters, Finset.mem_filter]
            have joined : witness ∈ state.hasJoined := by
              have unpacked :
                  witness ∈ state.hasJoined /\
                    (witness ∈ (state.nodes node).votesGranted \/
                      queuedGrantedVote state node witness) := by
                simpa [effectiveElectionVoters] using electionMember
              exact unpacked.1
            exact ⟨joined, Or.inl electionMember⟩)
      apply signatureEndedPrefixOfMaxTake covered
      have prefixLength :
          (evidence.history.take evidence.commitFrontier).length =
            evidence.commitFrontier := by
        simp [Nat.min_eq_left frontierBound]
      rw [prefixLength]
      exact isSignatureAt_take_of_le le_rfl frontierSignature
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        (becomeLeaderEffect state node)
        appendHistory nodeEvidence requestEvidence newElections := by
    constructor
    · intro evidence supportedPrefix known
      exact
        prospectiveFacts.commitTermPositive
          evidence supportedPrefix
          (knownBack evidence supportedPrefix known)
    · intro evidence supportedPrefix known term record recorded newer
      by_cases termEqNode :
          term = (state.nodes node).currentTerm
      · subst term
        have recordEq : electionRecord = record :=
          Option.some.inj (by simpa [newElections] using recorded)
        subst record
        simpa [electionRecord]
          using newPromotionCovered evidence supportedPrefix known newer
      · have oldRecorded :
            elections term = some record := by
          simpa [newElections, Function.update, termEqNode] using recorded
        exact
          prospectiveFacts.electionClosure
            evidence supportedPrefix
              (knownBack evidence supportedPrefix known)
              term record oldRecorded newer
    · intro evidence supportedPrefix known member ackMember
      by_cases memberEq : member = node
      · subst member
        have oldKnown := knownBack evidence supportedPrefix known
        have oldCovered :=
          prospectiveFacts.currentMember
            evidence supportedPrefix oldKnown node ackMember
        have valid := knownCommitEvidenceValid evidenceFacts oldKnown
        have frontierPositive : 0 < evidence.commitFrontier := by
          have supportedPositive :=
            knownCommitEvidenceSupportedLengthPositive evidenceFacts oldKnown
          exact supportedPositive.trans_le valid.2.2.1
        rcases
            entryAtSomeOfPositiveBound frontierPositive valid.1 with
          ⟨frontierEntry, historyFound⟩
        have prefixFound :
            entryAt?
                (evidence.history.take evidence.commitFrontier)
                evidence.commitFrontier =
              some frontierEntry := by
          rw [entryAtTake_of_le le_rfl]
          exact historyFound
        have nodeFound :
            entryAt? (state.nodes node).log evidence.commitFrontier =
              some frontierEntry :=
          entryAt_of_prefix oldCovered prefixFound
        have frontierTerm :
            frontierEntry.term = evidence.commitTerm := by
          simpa [termAt, historyFound] using valid.2.1
        have termBound :=
          facts.entriesDoNotExceedCurrentTerm node frontierEntry
            (entryAt_mem nodeFound)
        have termNe :
            Not (
              frontierEntry.term =
                (state.nodes node).currentTerm) :=
          oldCandidateTermNot
            node oldRole oldEffectiveMajority node
              evidence.commitFrontier frontierEntry nodeFound
        have strict :
            evidence.commitTerm < (state.nodes node).currentTerm := by
          rw [← frontierTerm]
          omega
        simpa [logNode] using newPromotionCovered evidence supportedPrefix known strict
      · simpa [logOther member memberEq]
          using prospectiveFacts.currentMember
            evidence supportedPrefix
            (knownBack evidence supportedPrefix known)
            member ackMember
    · intro evidence supportedPrefix known destination request
        queued sameTerm
      exact
        prospectiveFacts.sameTermQueuedComparable
          evidence supportedPrefix
            (knownBack evidence supportedPrefix known)
            destination request
            (by simpa [networkEq] using queued)
            sameTerm
    · intro evidence supportedPrefix known candidate member role newer
        entriesBefore ackMember relaxed
      have candidateNe : Not (candidate = node) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleNode)
      simpa [roleOther candidate candidateNe, termEq, logOther candidate candidateNe,
        maxCommittableIndexEq, maxCommittableTermEq, lastIndexEq, lastTermEq, votedEq,
        effectiveElectionVotersEq, relaxedElectionVoters, makeRequestVoteRequest,
        voteLogUpToDate]
        using prospectiveFacts.relaxedSupporterCarriesFrontier evidence supportedPrefix
          (knownBack evidence supportedPrefix known)
          candidate member
          (by simpa [roleOther candidate candidateNe] using role)
          (by simpa [termEq] using newer)
          (by
            intro entry entryMember
            simpa [termEq]
              using entriesBefore entry
                (by simpa [logOther candidate candidateNe] using entryMember))
          ackMember
          (by simpa [
              relaxedElectionVoters,
              makeRequestVoteRequest,
              termEq, logOther candidate candidateNe,
              maxCommittableIndexEq, maxCommittableTermEq,
              lastIndexEq, lastTermEq, votedEq,
              effectiveElectionVotersEq,
              show (becomeLeaderEffect state node).hasJoined = state.hasJoined from rfl,
              voteLogUpToDate
            ] using relaxed)
  have activationEvidenceAfter :
      ActivationEvidenceFacts
        (becomeLeaderEffect state node)
        appendHistory responseHistory nodeEvidence requestEvidence
          newElections activations := by
    apply
      activationEvidenceFrame
        state (becomeLeaderEffect state node)
        appendHistory appendHistory responseHistory responseHistory
        nodeEvidence nodeEvidence
        requestEvidence requestEvidence elections newElections activations
        activationEvidence
    · exact fun _ _ known => knownBack _ _ known
    · intro candidate role majority
      have candidateNe : Not (candidate = node) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleNode)
      exact ⟨
        by simpa [roleOther candidate candidateNe] using role,
        (potentialElectionMajorityEq candidate candidateNe).mp majority
      ⟩
    · intro candidate role
      exact termEq candidate
    · intro candidate role
      have candidateNe : Not (candidate = node) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleNode)
      rw [logOther candidate candidateNe]
    · intro candidate configuration role active
      have candidateNe : Not (candidate = node) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleNode)
      simpa [activeConfigurationsOtherEq candidate candidateNe] using active
  have activationCanonicalAfter :
      ActivationCanonicalFacts newCanonicalHistory newOwners activations := by
    apply
      activationCanonicalFrame
        canonicalHistory newCanonicalHistory owners newOwners activations
        activationQuorums.history activationCanonical
    · intro index activation stored
      have owned :=
        activationCanonical.termOwner index activation stored
      have termNe :
          Not (
            activation.activationTerm =
              (state.nodes node).currentTerm) := by
        intro same
        rw [same, oldTermUnowned] at owned
        contradiction
      simp [newOwners, termNe]
    · exact canonicalFrameToNew
  have configurationActivationsAfter :
      ConfigurationCoverageFacts
        (becomeLeaderEffect state node) activations := by
    apply
      configurationCoverageFrame
        configurationActivations currentConfigurationEq
        (fun candidate => by rw [termEq])
        (fun candidate => by rw [commitEq])
    · intro candidate frontier within
      by_cases candidateEq : candidate = node
      · subst candidate
        have frontierBound :
            frontier <= maxCommittableIndex (state.nodes node).log :=
          within.trans
            (commitIndex_le_maxCommittableIndex
              (state.nodes node)
              (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
                facts node))
        simp [
          logNode, promotionLog, List.take_take,
          Nat.min_eq_left frontierBound
        ]
      · rw [logOther candidate candidateEq]
    · intro candidate witness role
      have candidateNe : Not (candidate = node) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleNode)
      simpa [termEq]
        using witness.candidateTermStrict
          (by simpa [roleOther candidate candidateNe] using role)
  have activationVoteHistoryAfter :
      ActivationVoteHistory
        votes voteVoterHistory newElections activations := by
    intro activationIndex activation voter voteTerm candidate
        activationStored supporter voted different later
    rcases
        activationVoteHistory
          activationIndex activation voter voteTerm candidate
          activationStored supporter voted different later with
      retained | bad
    · exact Or.inl retained
    · right
      rcases bad with
        ⟨badTerm, badRecord, above, bounded, badStored, missing⟩
      have badTermNe :=
        recordedTermNeNew badTerm badRecord badStored
      exact ⟨
        badTerm,
        badRecord,
        above,
        bounded,
        by simpa [
            newElections, Function.update, badTermNe
          ] using badStored,
        missing
      ⟩
  have activationElectionsAfter :
      ActivationElectionFacts votes newElections activations := by
    constructor
    intro activationIndex activation electionTerm election
        activationStored electionStored later
    by_cases termEqNode :
        electionTerm = (state.nodes node).currentTerm
    · have electionEq : electionRecord = election :=
        Option.some.inj
          (by simpa [newElections, Function.update, termEqNode] using electionStored)
      subst election
      exact Or.inl
        (by
          simpa [electionRecord]
            using activationPrefixInPotentialCandidateByCoverageAuthorityChain
              (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts)
              facts.entriesDoNotExceedCurrentTerm facts.grantedVoteSnapshots
              voteCanonicalFacts ownership electionFacts
              activationQuorums.history
              configurationFacts.supporterCurrentHistory
              activationVoteHistory activationCanonical activationElections
              configurationActivations oldRole
              (effectiveElectionMajorityImpliesPotential state node oldEffectiveMajority)
              activation.newConfiguration.index activationIndex activation
              rfl activationStored
              (by simpa [termEqNode] using later))
    · exact
        activationElections.closure
          activationIndex activation electionTerm election
          activationStored
          (by simpa [
            newElections, Function.update, termEqNode
          ] using electionStored)
          later
  · refine ⟨
      newOwners,
      newCanonicalHistory,
      newElections,
      activations,
      nodeEvidence,
      requestEvidence,
      ?_,
      ?_,
      ?_,
      ?_,
      ?_,
      ?_,
      activationVoteHistoryAfter,
      ?_,
      ?_,
      ?_,
      ?_,
      ?_,
      evidenceAfter,
      prospectiveAfter,
      activationEvidenceAfter,
      activationCanonicalAfter,
      activationElectionsAfter,
      configurationActivationsAfter
    ⟩
    constructor
    · have above := candidatesAboveBootstrap node oldRole
      have termNe :
          Not (BOOTSTRAP_TERM = (state.nodes node).currentTerm) := by
        omega
      simpa [
        newOwners, Function.update, termNe
      ] using ownership.bootstrap
    · intro leader role
      by_cases leaderEq : leader = node
      · subst leader
        simp [newOwners, termEq]
      · have oldLeader :
            (state.nodes leader).role = .leader := by
          simpa [roleOther leader leaderEq] using role
        have differentTerm :
            Not (
              (state.nodes leader).currentTerm =
                (state.nodes node).currentTerm) :=
          fun same =>
            winningCandidateTermDiffersFromLeader
              candidatesAboveBootstrap facts.voteHistory
                facts.grantedVoteSnapshots ownership electionFacts
                configurationFacts oldRole oldEffectiveMajority
                oldLeader same.symm
        have oldOwned := ownership.activeLeader leader oldLeader
        simpa [newOwners, Function.update, termEq, differentTerm] using oldOwned
    · intro owner index entry found
      have oldFound :
          entryAt? (state.nodes owner).log index = some entry := by
        by_cases ownerEq : owner = node
        · subst owner
          rw [logNode] at found
          exact entryAt_of_prefix promotionPrefix found
        · simpa [logOther owner ownerEq] using found
      have termNe :
          Not (entry.term = (state.nodes node).currentTerm) :=
        oldCandidateTermNot
          node oldRole oldEffectiveMajority owner index entry oldFound
      rcases
          ownership.logEntryAgreement owner index entry oldFound with
        ⟨canonicalFound, agreed⟩
      exact ⟨
        by simpa [
            newCanonicalHistory, Function.update, termNe
          ] using canonicalFound,
        by
          by_cases ownerEq : owner = node
          · subst owner
            have promotionFound :
                entryAt? promotionLog index = some entry := by
              simpa [logNode] using found
            rw [logNode]
            calc
              promotionLog.take index = (state.nodes node).log.take index :=
                takeEqOfPrefix promotionPrefix
                  (entryAtSomeIndexBound promotionFound)
              _ = (newCanonicalHistory entry.term).take index := by
                simpa [newCanonicalHistory, Function.update, termNe] using agreed
          · simpa [
              logOther owner ownerEq,
              newCanonicalHistory, Function.update, termNe
            ] using agreed
      ⟩
    · intro destination request member index entry found
      have oldMember :
          Message.appendEntriesRequest request ∈
            state.network destination := by
        simpa [networkEq] using member
      rcases
          ownership.queuedHistoryEntryAgreement
            destination request oldMember index entry found with
        ⟨canonicalFound, agreed⟩
      have termNe :
          Not (entry.term = (state.nodes node).currentTerm) := by
        intro same
        rcases
            ownership.canonicalEntryOwner
              entry.term index entry canonicalFound with
          ⟨termOwner, owned⟩
        rw [same, oldTermUnowned] at owned
        contradiction
      exact ⟨
        by simpa [
            newCanonicalHistory, Function.update, termNe
          ] using canonicalFound,
        by simpa [
            newCanonicalHistory, Function.update, termNe
          ] using agreed
      ⟩
    · intro leader role
      by_cases leaderEq : leader = node
      · subst leader
        simp [
          newCanonicalHistory, termEq, logNode
        ]
      · have oldLeader :
            (state.nodes leader).role = .leader := by
          simpa [roleOther leader leaderEq] using role
        have differentTerm :
            Not (
              (state.nodes leader).currentTerm =
                (state.nodes node).currentTerm) :=
          fun same =>
            winningCandidateTermDiffersFromLeader
              candidatesAboveBootstrap facts.voteHistory
                facts.grantedVoteSnapshots ownership electionFacts
                configurationFacts oldRole oldEffectiveMajority
                oldLeader same.symm
        have oldHistory :=
          ownership.activeLeaderHistory leader oldLeader
        simpa [newCanonicalHistory, Function.update, differentTerm, termEq,
          logOther leader leaderEq]
          using oldHistory
    · intro term index entry found
      by_cases termEqNode :
          term = (state.nodes node).currentTerm
      · subst term
        have candidateFound :
            entryAt? (state.nodes node).log index = some entry := by
          have promotionFound :
              entryAt? promotionLog index = some entry := by
            simpa [newCanonicalHistory, Function.update] using found
          exact entryAt_of_prefix promotionPrefix
            promotionFound
        have entryTermNe :
            Not (entry.term = (state.nodes node).currentTerm) :=
          oldCandidateTermNot
            node oldRole oldEffectiveMajority node index entry candidateFound
        rcases
            termOwnershipLogEntryOwner ownership
              (entryAtSomeMember candidateFound) with
          ⟨termOwner, owned⟩
        exact ⟨termOwner, by simpa [newOwners, Function.update, entryTermNe] using owned⟩
      · have oldFound :
            entryAt? (canonicalHistory term) index = some entry := by
          simpa [newCanonicalHistory, Function.update, termEqNode] using found
        rcases
            ownership.canonicalEntryOwner term index entry oldFound with
          ⟨termOwner, owned⟩
        have entryTermNe :
            Not (entry.term = (state.nodes node).currentTerm) := by
          intro same
          rw [same, oldTermUnowned] at owned
          contradiction
        exact ⟨termOwner, by simpa [newOwners, Function.update, entryTermNe] using owned⟩
    · intro term
      by_cases termEqNode :
          term = (state.nodes node).currentTerm
      · subst term
        simpa [newCanonicalHistory, Function.update]
          using monoHistoryOfPrefix
            ((canonicalHistoriesMonoLog ownership) node)
            promotionPrefix
      · simpa [
          newCanonicalHistory, Function.update, termEqNode
        ] using ownership.canonicalMonoLog term
    · intro term owner owned
      by_cases termEqNode :
          term = (state.nodes node).currentTerm
      · subst term
        have ownerEq : owner = node := by
          have nodeEqOwner : node = owner := by simpa [newOwners] using owned
          exact nodeEqOwner.symm
        subst owner
        exact ⟨
          by simp [termEq],
          by intro _
             exact Or.inl roleNode
        ⟩
      · have oldOwned : owners term = some owner := by
          simpa [newOwners, Function.update, termEqNode] using owned
        rcases ownership.ownerProgress term owner oldOwned with
          ⟨bound, oldLeader⟩
        constructor
        · simpa [termEq] using bound
        · intro same
          by_cases ownerEq : owner = node
          · subst owner
            exact Or.inl roleNode
          · have oldSame :
                term = (state.nodes owner).currentTerm := by
              simpa [termEq] using same
            simpa [roleOther owner ownerEq] using oldLeader oldSame
    · intro destination request member
      rcases
          ownership.queuedAppendMetadata destination request
            (by simpa [networkEq] using member) with
        ⟨distinct, owned, bounded⟩
      refine ⟨distinct, ?_, bounded⟩
      by_cases requestTermEq :
          request.term = (state.nodes node).currentTerm
      · rw [requestTermEq, oldTermUnowned] at owned
        contradiction
      · simpa [
          newOwners, Function.update, requestTermEq
        ] using owned
    · intro destination request member sameTerm leaderRole
      have oldMember :
          Message.appendEntriesRequest request ∈
            state.network destination := by
        simpa [networkEq] using member
      by_cases sourceEq : request.source = node
      · have requestSourceEq : request.source = node := sourceEq
        rcases
            ownership.queuedAppendMetadata
              destination request oldMember with
          ⟨_, owned, _⟩
        have progress :=
          ownership.ownerProgress request.term node
            (by simpa [requestSourceEq] using owned)
        have oldSame :
            request.term = (state.nodes node).currentTerm := by
          simpa [termEq, requestSourceEq] using sameTerm
        rcases progress.2 oldSame with leader | follower | preVoteCandidate | inactive
        · exact False.elim
            (Role.noConfusion (leader.symm.trans oldRole))
        · exact False.elim
            (Role.noConfusion (follower.symm.trans oldRole))
        · exact False.elim
            (Role.noConfusion (preVoteCandidate.symm.trans oldRole))
        · exact False.elim
            (Role.noConfusion (inactive.symm.trans oldRole))
      · have oldPrefix :=
          ownership.queuedActiveSourceHistory
            destination request oldMember
              (by simpa [termEq] using sameTerm)
              (by simpa [roleOther request.source sourceEq] using leaderRole)
        simpa [logOther request.source sourceEq] using oldPrefix
    · constructor
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          simp [newOwners, electionRecord]
        · have oldRecorded :
              elections term = some record := by
            simpa [newElections, Function.update, termEqNode] using recorded
          simpa [newOwners, Function.update, termEqNode]
            using electionFacts.recordOwned term record oldRecorded
      · intro term owner owned
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have ownerEq : node = owner :=
            Option.some.inj (by simpa [newOwners] using owned)
          subst owner
          right
          exact ⟨electionRecord, by simp [newElections], by simp [electionRecord]⟩
        · have oldOwned : owners term = some owner := by
            simpa [newOwners, Function.update, termEqNode] using owned
          rcases
              electionFacts.ownerRecorded term owner oldOwned with
            bootstrap | recorded
          · exact Or.inl bootstrap
          · right
            rcases recorded with
              ⟨record, oldRecorded, recordLeader⟩
            exact ⟨
              record,
              by simpa [
                  newElections, Function.update, termEqNode
                ] using oldRecorded,
              recordLeader
            ⟩
      · intro term record recorded configuration member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          exact electionMajorityAtConfiguration oldMajority
            (by simpa [electionRecord] using member)
        · exact
            electionFacts.majority term record
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
              configuration member
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          exact facts.voteHistory.counted node voter
            (Or.inl oldRole)
            (by simpa [electionRecord] using member)
        · exact
            electionFacts.voted term record voter
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
              member
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          rfl
        · have oldRecorded :
              elections term = some record := by
            simpa [newElections, Function.update, termEqNode] using recorded
          exact electionFacts.ballotConfigurations term record oldRecorded
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          simp [electionRecord, promotionLog]
        · exact
            electionFacts.promotionFromBallot term record
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          simp [
            electionRecord, newCanonicalHistory
          ]
        · have oldRecorded :
              elections term = some record := by
            simpa [newElections, Function.update, termEqNode] using recorded
          simpa [newCanonicalHistory, Function.update, termEqNode]
            using electionFacts.promotionCanonical term record oldRecorded
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          simpa [electionRecord] using promotionCommittable
        · exact
            electionFacts.promotionCommittable term record
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
      · intro term record recorded entry member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          have oldMember :
              entry ∈ (state.nodes node).log :=
            memOfPrefix promotionPrefix
              (by simpa [electionRecord] using member)
          have bounded :=
            facts.entriesDoNotExceedCurrentTerm
              node entry oldMember
          have different :
              Not (entry.term = (state.nodes node).currentTerm) := by
            intro same
            rcases
                termOwnershipLogEntryOwner ownership
                  oldMember with
              ⟨owner, owned⟩
            rw [same, oldTermUnowned] at owned
            contradiction
          omega
        · exact
            electionFacts.promotionEntriesBeforeTerm
              term record
                (by simpa [
                  newElections, Function.update, termEqNode
                ] using recorded)
                entry member
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            simp [electionRecord]
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              have granted :
                  voter ∈ (state.nodes node).votesGranted := by
                simpa [electionRecord] using member
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter]
              exact ⟨facts.joinedCarriers.grantedVotes node granted, Or.inl granted⟩
            rcases
                facts.grantedVoteSnapshots
                  node voter (Or.inl oldRole) effectiveMember with
              ⟨_, self | snapshot⟩
            · exact False.elim (voterEq self)
            · simpa [electionRecord, voterEq]
                using committablePrefixOfMaxTake snapshot.1 snapshot.2.1
        · exact
            electionFacts.candidatePrefix term record voter
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
              member
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            simpa [electionRecord]
              using canonicalFrameToNew
                promotionLog
                (historyCanonicalOfPrefix
                  (nodeLogCanonical ownership node)
                  promotionPrefix)
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              have granted :
                  voter ∈ (state.nodes node).votesGranted := by
                simpa [electionRecord] using member
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter]
              exact ⟨facts.joinedCarriers.grantedVotes node granted, Or.inl granted⟩
            rcases
                voteCanonicalFacts
                  node voter (Or.inl oldRole) effectiveMember with
              self | snapshots
            · exact False.elim (voterEq self)
            · simpa [electionRecord, voterEq] using canonicalFrameToNew _ snapshots.1
        · exact
            canonicalFrameToNew _
              (electionFacts.candidateCanonical
                term record voter
                  (by simpa [
                    newElections, Function.update, termEqNode
                  ] using recorded)
                  member)
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            simpa [electionRecord] using promotionCommittable
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              have granted :
                  voter ∈ (state.nodes node).votesGranted := by
                simpa [electionRecord] using member
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter]
              exact ⟨facts.joinedCarriers.grantedVotes node granted, Or.inl granted⟩
            rcases
                facts.grantedVoteSnapshots
                  node voter (Or.inl oldRole) effectiveMember with
              ⟨_, self | snapshot⟩
            · exact False.elim (voterEq self)
            · simpa [electionRecord, voterEq] using snapshot.2.1
        · exact
            electionFacts.candidateCommittable term record voter
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
              member
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            simpa [electionRecord]
              using canonicalFrameToNew
                promotionLog
                (historyCanonicalOfPrefix
                  (nodeLogCanonical ownership node)
                  promotionPrefix)
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              have granted :
                  voter ∈ (state.nodes node).votesGranted := by
                simpa [electionRecord] using member
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter]
              exact ⟨facts.joinedCarriers.grantedVotes node granted, Or.inl granted⟩
            rcases
                voteCanonicalFacts
                  node voter (Or.inl oldRole) effectiveMember with
              self | snapshots
            · exact False.elim (voterEq self)
            · simpa [electionRecord, voterEq] using canonicalFrameToNew _ snapshots.2.2.1
        · exact
            canonicalFrameToNew _
              (electionFacts.voterCanonical
                term record voter
                  (by simpa [
                    newElections, Function.update, termEqNode
                  ] using recorded)
                  member)
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            simpa [electionRecord] using promotionCommittable
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              have granted :
                  voter ∈ (state.nodes node).votesGranted := by
                simpa [electionRecord] using member
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter]
              exact ⟨facts.joinedCarriers.grantedVotes node granted, Or.inl granted⟩
            rcases
                facts.grantedVoteSnapshots
                  node voter (Or.inl oldRole) effectiveMember with
              ⟨_, self | snapshot⟩
            · exact False.elim (voterEq self)
            · simpa [electionRecord, voterEq] using snapshot.2.2.1
        · exact
            electionFacts.voterCommittable term record voter
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
              member
      · intro term record voter recorded member
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          by_cases voterEq : voter = node
          · subst voter
            right
            constructor
            · simp [
                electionRecord, maxCommittableTerm,
                promotionCommittable
              ]
            · simp [electionRecord, promotionCommittable]
          · have effectiveMember :
                voter ∈ effectiveElectionVoters state node := by
              have granted :
                  voter ∈ (state.nodes node).votesGranted := by
                simpa [electionRecord] using member
              simp only [
                effectiveElectionVoters,
                Finset.mem_filter]
              exact ⟨facts.joinedCarriers.grantedVotes node granted, Or.inl granted⟩
            rcases
                facts.grantedVoteSnapshots
                  node voter (Or.inl oldRole) effectiveMember with
              ⟨_, self | snapshot⟩
            · exact False.elim (voterEq self)
            · simpa [
                electionRecord, voterEq, voteLogUpToDate
              ] using snapshot.2.2.2.2
        · exact
            electionFacts.upToDate term record voter
              (by simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
              member
      · intro term record recorded
        by_cases same : term = (state.nodes node).currentTerm
        · subst term
          exact candidatesAboveBootstrap node oldRole
        · exact electionFacts.termAboveBootstrap term record
            (by simpa [newElections, Function.update, same] using recorded)
    · constructor
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          exact ⟨
            commitIndex_le_maxCommittableIndex
              (state.nodes node)
              (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts node),
            invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts node
          ⟩
        · exact
            configurationFacts.ballotCommittedFrontierSignature
              term record
                (by simpa [
                  newElections, Function.update, termEqNode
                ] using recorded)
      · intro term record recorded positive
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          rcases
              configurationActivations node
                (by simpa [electionRecord, currentConfiguration] using
                  positive) with
            ⟨coverage⟩
          simpa [electionRecord]
            using (coverage.ballotConfigurationCoverage
                    (record := electionRecord)
                    oldRole rfl rfl rfl)
              positive
        · exact
            configurationFacts.ballotCurrentAuthorityActivation
              term record
                (by simpa [
                  newElections, Function.update, termEqNode
                ] using recorded)
                positive
      · intro term record recorded
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · subst term
          have recordEq : electionRecord = record :=
            Option.some.inj (by simpa [newElections] using recorded)
          subst record
          simpa [electionRecord, currentConfiguration]
            using currentConfiguration_mem_activeConfigurations (state.nodes node)
        · exact
            configurationFacts.ballotCurrentAuthorityActive
              term record
                (by simpa [
                  newElections, Function.update, termEqNode
                ] using recorded)
      · intro index activation stored supporter member
        rcases
            configurationFacts.supporterCurrentHistory
              index activation stored supporter member with
          retained | bad
        · by_cases supporterEq : supporter = node
          · subst supporter
            exact Or.inl (by
              rw [logNode]
              apply signatureEndedPrefixOfMaxTake retained
              exact
                signatureAtTakeLength
                  (activationQuorums.history.valid
                    index activation stored).2.2.2.2.2.1)
          · exact Or.inl
              (by simpa [logOther supporter supporterEq] using retained)
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, bounded,
              badRecorded, missing⟩
          have badTermNe :=
            recordedTermNeNew badTerm badRecord badRecorded
          exact ⟨
            badTerm,
            badRecord,
            above,
            by simpa [termEq] using bounded,
            by simpa [
                newElections, Function.update, badTermNe
              ] using badRecorded,
            missing
          ⟩
      · intro term record candidate recorded role candidateTerm majority
        have candidateNe : Not (candidate = node) := by
          intro same
          subst candidate
          exact Role.noConfusion (role.symm.trans roleNode)
        have oldCandidateRole :
            (state.nodes candidate).role = .candidate := by
          simpa [roleOther candidate candidateNe] using role
        have oldCandidateMajority :
            hasEffectiveElectionMajority state candidate :=
          (effectiveElectionMajorityEq
            candidate candidateNe).mp majority
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        ·
          have recordEq : electionRecord = record :=
            Option.some.inj (by
              simpa [
                newElections, Function.update, termEqNode
              ] using recorded)
          subst record
          have oldSameTerm :
              (state.nodes node).currentTerm =
                (state.nodes candidate).currentTerm := by
            calc
              (state.nodes node).currentTerm = term := termEqNode.symm
              _ =
                  ((becomeLeaderEffect state node).nodes
                    candidate).currentTerm := candidateTerm.symm
              _ = (state.nodes candidate).currentTerm := termEq candidate
          rcases
              configurationFacts.effectiveCandidatesShared
                node candidate oldRole oldCandidateRole oldSameTerm
                oldEffectiveMajority oldCandidateMajority with
            ⟨configuration, ballotActive, candidateActive⟩
          exact
            ⟨configuration,
              by simpa [electionRecord] using ballotActive,
              by simpa [
                activeConfigurationsOtherEq candidate candidateNe
              ] using candidateActive⟩
        · have oldRecorded :
              elections term = some record := by
            simpa [newElections, Function.update, termEqNode] using recorded
          rcases
              configurationFacts.potentialShared
                term record candidate oldRecorded oldCandidateRole
                (by simpa [termEq] using candidateTerm)
                oldCandidateMajority with
            ⟨configuration, ballotActive, candidateActive⟩
          exact ⟨
            configuration,
            ballotActive,
            by simpa [
                activeConfigurationsOtherEq candidate candidateNe
              ] using candidateActive
          ⟩
      · intro left right leftRole rightRole sameTerm
          leftMajority rightMajority
        have leftNe : Not (left = node) := by
          intro same
          subst left
          exact Role.noConfusion (leftRole.symm.trans roleNode)
        have rightNe : Not (right = node) := by
          intro same
          subst right
          exact Role.noConfusion (rightRole.symm.trans roleNode)
        rcases
            configurationFacts.effectiveCandidatesShared
              left right
              (by simpa [roleOther left leftNe] using leftRole)
              (by simpa [roleOther right rightNe] using rightRole)
              (by simpa [termEq] using sameTerm)
              ((effectiveElectionMajorityEq left leftNe).mp leftMajority)
              ((effectiveElectionMajorityEq right rightNe).mp
                rightMajority) with
          ⟨configuration, leftActive, rightActive⟩
        exact ⟨
          configuration,
          by simpa [
              activeConfigurationsOtherEq left leftNe
            ] using leftActive,
          by simpa [
              activeConfigurationsOtherEq right rightNe
            ] using rightActive
        ⟩
      · intro candidate role entry member
        have candidateNe : Not (candidate = node) := by
          intro same
          subst candidate
          exact Role.noConfusion (role.symm.trans roleNode)
        simpa [termEq]
          using configurationFacts.candidateEntriesBeforeTerm
            candidate
            (by simpa [roleOther candidate candidateNe] using role)
            entry
            (by simpa [logOther candidate candidateNe] using member)
    · apply
        grantedVoteCanonicalFrame
          state (becomeLeaderEffect state node)
            canonicalHistory newCanonicalHistory
            voteCandidateHistory voteVoterHistory voteCanonicalFacts
            (fun candidate _ => termEq candidate)
      · intro candidate active
        by_cases candidateEq : candidate = node
        · subst candidate
          exact Or.inl oldRole
        · rw [roleOther candidate candidateEq] at active
          exact active
      · intro candidate voter _ member
        rw [effectiveElectionVotersEq] at member
        exact member
      · intro history canonical index entry found
        rcases canonical index entry found with
          ⟨canonicalFound, agreed⟩
        have entryTermNe :
            Not (entry.term = (state.nodes node).currentTerm) := by
          intro same
          rcases
              ownership.canonicalEntryOwner
                entry.term index entry canonicalFound with
            ⟨owner, owned⟩
          rw [same, oldTermUnowned] at owned
          contradiction
        exact ⟨
          by simpa [
              newCanonicalHistory, Function.update, entryTermNe
            ] using canonicalFound,
          by simpa [
              newCanonicalHistory, Function.update, entryTermNe
            ] using agreed
        ⟩
    · intro source index role current signature voter effective
      have sourceNe : Not (source = node) := by
        intro same
        subst source
        exact noNewLeaderCurrentTerm index current
      have oldRole : (state.nodes source).role = .leader := by
        simpa [roleOther source sourceNe] using role
      have oldCurrent :
          termAt (state.nodes source).log index =
            (state.nodes source).currentTerm := by
        simpa [logOther source sourceNe, termEq] using current
      have oldSignature :
          isSignatureAt (state.nodes source).log index = true := by
        simpa [logOther source sourceNe] using signature
      have oldEffective :
          voter ∈ effectiveAckers state responseHistory source index := by
        rw [effectiveAckersOtherEq source sourceNe index] at effective
        exact effective
      rcases
          ackerCurrentFacts source index oldRole oldCurrent oldSignature
            voter oldEffective with
        retained | bad
      · left
        by_cases voterEq : voter = node
        · subst voter
          simpa [logOther source sourceNe, logNode]
            using (signatureEndedPrefixOfMaxTake
                    retained (signatureAtTakeLength oldSignature))
        · simpa [
            logOther source sourceNe,
            logOther voter voterEq
          ] using retained
      · exact Or.inr (by
          simpa [termEq] using
            preserveEarlierBad
              source index (state.nodes voter).currentTerm sourceNe bad)
    · intro source index role current signature
        voter voteTerm candidate effective voted different newer
      have sourceNe : Not (source = node) := by
        intro same
        subst source
        exact noNewLeaderCurrentTerm index current
      have oldRole : (state.nodes source).role = .leader := by
        simpa [roleOther source sourceNe] using role
      have oldCurrent :
          termAt (state.nodes source).log index =
            (state.nodes source).currentTerm := by
        simpa [logOther source sourceNe, termEq] using current
      have oldSignature :
          isSignatureAt (state.nodes source).log index = true := by
        simpa [logOther source sourceNe] using signature
      have oldEffective :
          voter ∈ effectiveAckers state responseHistory source index := by
        rw [effectiveAckersOtherEq source sourceNe index] at effective
        exact effective
      rcases
          ackerVoteFacts source index oldRole oldCurrent oldSignature
            voter voteTerm candidate oldEffective voted different
              (by simpa [termEq] using newer) with
        retained | bad
      · exact Or.inl
          (by simpa [logOther source sourceNe] using retained)
      · exact Or.inr
          (preserveEarlierBad source index voteTerm sourceNe bad)
    · intro source index role current signature term record voter
        recorded member effective newer
      have sourceNe : Not (source = node) := by
        intro same
        subst source
        exact noNewLeaderCurrentTerm index current
      have oldRole : (state.nodes source).role = .leader := by
        simpa [roleOther source sourceNe] using role
      have oldCurrent :
          termAt (state.nodes source).log index =
            (state.nodes source).currentTerm := by
        simpa [logOther source sourceNe, termEq] using current
      have oldSignature :
          isSignatureAt (state.nodes source).log index = true := by
        simpa [logOther source sourceNe] using signature
      have oldEffective :
          voter ∈ effectiveAckers state responseHistory source index := by
        rw [effectiveAckersOtherEq source sourceNe index] at effective
        exact effective
      by_cases termEqNode :
          term = (state.nodes node).currentTerm
      · subst term
        have recordEq : electionRecord = record :=
          Option.some.inj (by simpa [newElections] using recorded)
        subst record
        by_cases voterEq : voter = node
        · subst voter
          rcases
              ackerCurrentFacts source index oldRole oldCurrent
                oldSignature node oldEffective with
            retained | bad
          · exact Or.inl
              (by simpa [
                electionRecord, logOther source sourceNe
              ] using
                (signatureEndedPrefixOfMaxTake
                  retained (signatureAtTakeLength oldSignature)))
          · right
            rcases bad with
              ⟨badTerm, badRecord, above, bounded,
                badRecorded, missing⟩
            have badTermNe :=
              recordedTermNeNew badTerm badRecord badRecorded
            exact ⟨
              badTerm,
              badRecord,
              by simpa [termEq] using above,
              by omega,
              by simpa [
                  newElections, Function.update, badTermNe
                ] using badRecorded,
              by simpa [logOther source sourceNe] using missing
            ⟩
        · have voterInVotes :
              voter ∈ (state.nodes node).votesGranted := by
            simpa [electionRecord] using member
          have voterVoted :
              votes voter (state.nodes node).currentTerm = some node :=
            facts.voteHistory.counted
              node voter (Or.inl enabled.2.1) voterInVotes
          rcases
              ackerVoteFacts source index oldRole oldCurrent
                oldSignature
                voter (state.nodes node).currentTerm node
                oldEffective voterVoted voterEq
                (by simpa [termEq] using newer) with
            retained | bad
          · exact Or.inl
              (by simpa [
                electionRecord, voterEq,
                logOther source sourceNe
              ] using retained)
          · right
            rcases bad with
              ⟨badTerm, badRecord, above, bounded,
                badRecorded, missing⟩
            have badTermNe :=
              recordedTermNeNew badTerm badRecord badRecorded
            exact ⟨
              badTerm,
              badRecord,
              by simpa [termEq] using above,
              by omega,
              by simpa [
                  newElections, Function.update, badTermNe
                ] using badRecorded,
              by simpa [logOther source sourceNe] using missing
            ⟩
      · have oldRecorded :
            elections term = some record := by
          simpa [newElections, Function.update, termEqNode] using recorded
        rcases
            ackerElectionFacts source index oldRole oldCurrent
              oldSignature term record voter oldRecorded member oldEffective
                (by simpa [termEq] using newer) with
          retained | bad
        · exact Or.inl
            (by simpa [logOther source sourceNe] using retained)
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, below,
              badRecorded, missing⟩
          have badTermNe :=
            recordedTermNeNew badTerm badRecord badRecorded
          exact ⟨
            badTerm,
            badRecord,
            by simpa [termEq] using above,
            below,
            by simpa [
                newElections, Function.update, badTermNe
              ] using badRecorded,
            by simpa [logOther source sourceNe] using missing
          ⟩
    · intro source index role current signature
        activationIndex activation configuration supporter
        activationStored governing supporterMember effective newer
      have sourceNe : Not (source = node) := by
        intro same
        subst source
        exact noNewLeaderCurrentTerm index current
      have oldRole : (state.nodes source).role = .leader := by
        simpa [roleOther source sourceNe] using role
      have oldCurrent :
          termAt (state.nodes source).log index =
            (state.nodes source).currentTerm := by
        simpa [logOther source sourceNe, termEq] using current
      have oldSignature :
          isSignatureAt (state.nodes source).log index = true := by
        simpa [logOther source sourceNe] using signature
      have oldEffective :
          supporter ∈
            effectiveAckers state responseHistory source index := by
        rw [effectiveAckersOtherEq source sourceNe index] at effective
        exact effective
      rcases
          ackerActivationFacts
            source index oldRole oldCurrent oldSignature
            activationIndex activation configuration supporter
            activationStored governing supporterMember oldEffective
            (by simpa [termEq] using newer) with
        retained | bad
      · exact Or.inl
          (by simpa [logOther source sourceNe] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded,
            badRecorded, missing⟩
        have badTermNe :=
          recordedTermNeNew badTerm badRecord badRecorded
        exact ⟨
          badTerm,
          badRecord,
          by simpa [termEq] using above,
          bounded,
          by simpa [
              newElections, Function.update, badTermNe
            ] using badRecorded,
          by simpa [logOther source sourceNe] using missing
        ⟩
    · intro destination request member record recorded
      have oldMember :
          Message.appendEntriesRequest request ∈
            state.network destination := by
        simpa [networkEq] using member
      by_cases termEqNode :
          request.term = (state.nodes node).currentTerm
      · have owned :=
          (ownership.queuedAppendMetadata
            destination request oldMember).2.1
        rw [termEqNode, oldTermUnowned] at owned
        contradiction
      · have oldRecorded :
            elections request.term = some record := by
          simpa [newElections, Function.update, termEqNode] using recorded
        exact
          electionQueuedFacts
            destination request oldMember record oldRecorded
    · intro index activation stored supporter member
      simpa [termEq] using activationProgress index activation stored supporter member
    · constructor
      · exact activationQuorums.history
      · intro source index role current signature potential
          term record recorded later
        have sourceNe : Not (source = node) := by
          intro same
          subst source
          exact noNewLeaderCurrentTerm index current
        have oldRole : (state.nodes source).role = .leader := by
          simpa [roleOther source sourceNe] using role
        have oldCurrent :
            termAt (state.nodes source).log index =
              (state.nodes source).currentTerm := by
          simpa [logOther source sourceNe, termEq] using current
        have oldSignature :
            isSignatureAt (state.nodes source).log index = true := by
          simpa [logOther source sourceNe] using signature
        have oldPotential :=
          potentialMajorityOtherBack source sourceNe index potential
        by_cases termEqNode :
            term = (state.nodes node).currentTerm
        · have recordEq : electionRecord = record :=
            Option.some.inj
              (by simpa [newElections, Function.update, termEqNode] using recorded)
          subst record
          have oldCovered :=
            signatureEndedPrefixOfMaxTake
              (potentialPrefixInHigherCandidate
                facts.currentTermsPositive
                (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
                  facts)
                candidatesAboveBootstrap facts.entriesDoNotExceedCurrentTerm
                facts.voteHistory facts.grantedVoteSnapshots
                voteCanonicalFacts ownership electionFacts
                configurationFacts ackerCurrentFacts ackerVoteFacts
                ackerElectionFacts activationQuorums
                oldRole oldCurrent oldSignature oldPotential
                enabled.2.1
                (effectiveElectionMajorityImpliesPotential
                  state node oldEffectiveMajority)
                (by simpa [termEqNode, termEq] using later))
              (signatureAtTakeLength oldSignature)
          exact Or.inl
            (by simpa [logOther source sourceNe, electionRecord] using oldCovered)
        · rcases
              activationQuorums.recordBridge
                source index oldRole oldCurrent oldSignature oldPotential
                term record
                (by simpa [
                  newElections, Function.update, termEqNode
                ] using recorded)
                (by simpa [termEq] using later) with
            direct | shared
          · exact Or.inl (by simpa [logOther source sourceNe] using direct)
          · rcases shared with
              ⟨configuration, sourceActive, governs, ballotActive⟩
            exact Or.inr
              ⟨configuration,
                by simpa [
                  activeConfigurationsOtherEq source sourceNe
                ] using sourceActive,
                governs, ballotActive⟩
      · intro source index role current signature potential
          candidate candidateRole candidateMajority later
        have sourceNe : Not (source = node) := by
          intro same
          subst source
          exact noNewLeaderCurrentTerm index current
        have candidateNe : Not (candidate = node) := by
          intro same
          subst candidate
          exact Role.noConfusion (candidateRole.symm.trans roleNode)
        rcases
            activationQuorums.candidateBridge
              source index
              (by simpa [roleOther source sourceNe] using role)
              (by simpa [logOther source sourceNe, termEq] using current)
              (by simpa [logOther source sourceNe] using signature)
              (potentialMajorityOtherBack
                source sourceNe index potential)
              candidate
              (by simpa [roleOther candidate candidateNe] using candidateRole)
              ((potentialElectionMajorityEq
                candidate candidateNe).mp candidateMajority)
              (by simpa [termEq] using later) with
          direct | shared
        · exact Or.inl
            (by simpa [
              logOther source sourceNe,
              logOther candidate candidateNe
            ] using direct)
        · rcases shared with
            ⟨configuration, sourceActive, governs, candidateActive⟩
          exact Or.inr
            ⟨configuration,
              by simpa [
                activeConfigurationsOtherEq source sourceNe
              ] using sourceActive,
              governs,
              by simpa [
                activeConfigurationsOtherEq candidate candidateNe
              ] using candidateActive⟩
      · intro source index role current signature majority committed
        have sourceNe : Not (source = node) := by
          intro same
          subst source
          exact noNewLeaderCurrentTerm index current
        rcases
            activationQuorums.committedBridge
              source index
              (by simpa [roleOther source sourceNe] using role)
              (by simpa [logOther source sourceNe, termEq] using current)
              (by simpa [logOther source sourceNe] using signature)
              ((effectiveMajorityOtherEq source sourceNe index).mp majority)
              committed with
          direct | direct | shared
        · exact Or.inl
            (by simpa [
              logOther source sourceNe, committedEq
            ] using direct)
        · exact Or.inr (Or.inl
            (by simpa [
              logOther source sourceNe, committedEq
            ] using direct))
        · rcases shared with
            ⟨configuration, sourceActive, governs, configurationEq⟩
          exact Or.inr (Or.inr
            ⟨configuration,
              by simpa [
                activeConfigurationsOtherEq source sourceNe
              ] using sourceActive,
              governs,
              by simpa [currentConfigurationEq] using configurationEq⟩)
      · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
          right rightIndex rightRole rightCurrent rightSignature rightMajority
        have leftNe : Not (left = node) := by
          intro same
          subst left
          exact noNewLeaderCurrentTerm leftIndex leftCurrent
        have rightNe : Not (right = node) := by
          intro same
          subst right
          exact noNewLeaderCurrentTerm rightIndex rightCurrent
        rcases
            activationQuorums.potentialBridge
              left leftIndex
              (by simpa [roleOther left leftNe] using leftRole)
              (by simpa [logOther left leftNe, termEq] using leftCurrent)
              (by simpa [logOther left leftNe] using leftSignature)
              ((effectiveMajorityOtherEq left leftNe leftIndex).mp
                leftMajority)
              right rightIndex
              (by simpa [roleOther right rightNe] using rightRole)
              (by simpa [logOther right rightNe, termEq] using rightCurrent)
              (by simpa [logOther right rightNe] using rightSignature)
              ((effectiveMajorityOtherEq right rightNe rightIndex).mp
                rightMajority) with
          direct | direct | shared
        · exact Or.inl
            (by simpa [
              logOther left leftNe, logOther right rightNe
            ] using direct)
        · exact Or.inr (Or.inl
            (by simpa [
              logOther left leftNe, logOther right rightNe
            ] using direct))
        · rcases shared with
            ⟨configuration, leftActive, leftGoverns,
              rightActive, rightGoverns⟩
          exact Or.inr (Or.inr
            ⟨configuration,
              by simpa [
                activeConfigurationsOtherEq left leftNe
              ] using leftActive,
              leftGoverns,
              by simpa [
                activeConfigurationsOtherEq right rightNe
              ] using rightActive,
              rightGoverns⟩)
      · intro activationIndex activation queuedDestination queuedRequest
          stored queued sameTerm
        exact
          activationQuorums.queuedComparable
            activationIndex activation queuedDestination queuedRequest
            stored
            (by simpa [view_effects] using queued)
            sameTerm
      · apply
          committedConfigurationCoverageTakeFrame
            activationQuorums.committedCoverage facts.commitIndicesBounded
            (fun candidate => by
              by_cases candidateEq : candidate = node
              · subst candidate
                rw [commitEq, logNode, promotionLength]
                exact
                  commitIndex_le_maxCommittableIndex
                    (state.nodes node)
                    (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
                      facts node)
              · simpa [
                  commitEq, logOther candidate candidateEq
                ] using facts.commitIndicesBounded candidate)
            commitEq
            (fun candidate => Nat.le_of_eq (termEq candidate).symm)
        intro candidate frontier within
        by_cases candidateEq : candidate = node
        · subst candidate
          rw [logNode]
          have frontierMax :
              frontier <= maxCommittableIndex (state.nodes node).log := by
            have oldWithin :
                frontier <= (state.nodes node).commitIndex := by
              simpa [commitEq] using within
            exact oldWithin.trans
              (commitIndex_le_maxCommittableIndex
                (state.nodes node)
                (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
                  facts node))
          simp [promotionLog, List.take_take,
            Nat.min_eq_left frontierMax]
        · rw [logOther candidate candidateEq]
      · apply
          queuedConfigurationCoverageFrame
            activationQuorums.queuedCoverage
            (afterAppendHistory := appendHistory)
        · intro queuedDestination queuedRequest queued
          simpa [view_effects] using queued
        · intro _
          rfl
  · intro candidate voter active member
    rw [termEq candidate, termEq voter]
    have oldMember :
        voter ∈ effectiveElectionVoters state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    have oldActive :
        (state.nodes candidate).role = .candidate \/
          (state.nodes candidate).role = .leader := by
      by_cases candidateEq : candidate = node
      · subst candidate
        exact Or.inl oldRole
      · rw [roleOther candidate candidateEq] at active
        exact active
    rcases
        facts.grantedVoteSnapshots
          candidate voter oldActive oldMember with
      ⟨recorded, self | snapshot⟩
    · exact ⟨recorded, Or.inl self⟩
    · refine ⟨recorded, Or.inr ⟨?_, snapshot.2.1,
        snapshot.2.2.1, ?_, ?_⟩⟩
      · by_cases candidateEq : candidate = node
        · subst candidate
          rw [logNode]
          exact
            committablePrefixOfMaxTake snapshot.1 snapshot.2.1
        · simpa [logOther candidate candidateEq] using snapshot.1
      · simpa [termEq] using snapshot.2.2.2.1
      · simpa [voteLogUpToDate, maxCommittableIndexEq,
          maxCommittableTermEq] using snapshot.2.2.2.2
  · refine ⟨newAckHistory, ?_⟩
    constructor
    · intro leader role peer zero
      by_cases leaderEq : leader = node
      · subst leader
        simp [newAckHistory]
      · have oldRole : (state.nodes leader).role = .leader := by
          simpa [roleOther leader leaderEq] using role
        have oldZero :
            (state.nodes leader).matchIndex peer = 0 := by
          simpa [matchOther leader leaderEq] using zero
        simpa [newAckHistory, Function.update, leaderEq]
          using ackFacts.zero leader oldRole peer oldZero
    · intro leader role peer positive
      by_cases leaderEq : leader = node
      · subst leader
        rw [matchNode] at positive
        simp at positive
      · have oldRole : (state.nodes leader).role = .leader := by
          simpa [roleOther leader leaderEq] using role
        have oldPositive :
            0 < (state.nodes leader).matchIndex peer := by
          simpa [matchOther leader leaderEq] using positive
        rcases
            ackFacts.positive leader oldRole peer oldPositive with
          ⟨snapshot, stored, snapshotTerm, snapshotIndex,
            historyBound, agreed⟩
        exact ⟨
          snapshot,
          by simpa [
              newAckHistory, Function.update, leaderEq
            ] using stored,
          by simpa [termEq] using snapshotTerm,
          by simpa [matchOther leader leaderEq] using snapshotIndex,
          historyBound,
          by simpa [logOther leader leaderEq] using agreed
        ⟩
  · apply joinedCarrierFactsFrame
      state (becomeLeaderEffect state node)
      facts.joinedCarriers
      (by simp [view_effects])
    · intro candidate configuration active
      by_cases candidateEq : candidate = node
      · subst candidate
        exact activeConfigurationsNodeSubset configuration active
      · rw [activeConfigurationsOtherEq candidate candidateEq] at active
        exact active
    · intro candidate configuration member
      by_cases candidateEq : candidate = node
      · subst candidate
        apply
          memOfPrefix
            (allConfigurations_mono_prefix promotionPrefix)
        simpa [logNode] using member
      · simpa [logOther candidate candidateEq] using member
    · intro candidate peer member
      simpa [votesEq] using member
    · intro candidate active
      by_cases same : candidate = node
      · subst candidate
        simpa [view_effects]
          using facts.joinedCarriers.runtimeNodes.activeRoles node (Or.inl oldRole)
      · simpa [view_effects]
          using facts.joinedCarriers.runtimeNodes.activeRoles candidate
            (by simpa [roleOther candidate same] using active)
    · intro leader peer positive
      by_cases same : leader = node
      · subst leader
        rw [matchNode] at positive
        simp at positive
      · simpa [view_effects]
          using facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
            (by simpa [matchOther leader same] using positive)
    · intro candidate nonempty
      by_cases same : candidate = node
      · subst candidate
        simpa [view_effects]
          using facts.joinedCarriers.runtimeNodes.activeRoles node (Or.inl oldRole)
      · simpa [view_effects]
          using facts.joinedCarriers.runtimeNodes.nonemptyLogs candidate
            (by simpa [logOther candidate same] using nonempty)
    · intro destination message member
      simpa [view_effects] using member
  · exact fun _ => Iff.rfl
  · intro candidate
    simpa only [termEq] using facts.currentTermsValid candidate
  · simpa only [NetworkTermsValid, networkEq] using facts.networkTermsValid

end CCFRaft.Proofs.Invariant
