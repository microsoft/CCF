-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Leader
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

/-- Advancing a current-term quorum frontier preserves all safety evidence. -/
lemma advanceCommitStatePreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : node ∈ joinedNodes
        /\ ((nodeOf state) node).role = .leader
        /\ ((nodeOf state) node).commitIndex < highestCommittableIndex (nodeOf state node) node)
    : SystemInductiveInvariant (joined := joinedNodes) (advanceCommitState state node) := by
  classical
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
  have candidatesAboveBootstrap :=
    invariantFactsCandidatesAboveBootstrap facts
  have potentialCommitElectionSafe :
      PotentialCommitElectionSafe (joined := joinedNodes) state responseHistory :=
    derivePotentialCommitElectionSafe
      facts.currentTermsPositive
      (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts)
      candidatesAboveBootstrap
      facts.entriesDoNotExceedCurrentTerm
      facts.voteHistory
      facts.grantedVoteSnapshots
      voteCanonicalFacts ownership electionFacts
      configurationFacts
      ackerCurrentFacts ackerVoteFacts ackerElectionFacts
      activationQuorums
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  let frontier := highestCommittableIndex (nodeOf state node) node
  have leaderRole : ((nodeOf state) node).role = .leader := enabled.2.1
  have advances : ((nodeOf state) node).commitIndex < frontier := by
    simpa [frontier] using enabled.2.2
  have frontierBound : frontier <= ((nodeOf state) node).log.length := by
    simpa [frontier] using highestCommittableIndexBounded state node
  have frontierValid
      : termAt ((nodeOf state) node).log frontier = ((nodeOf state) node).currentTerm
        /\ hasMajorityAt (nodeOf state node) node frontier := by
    simpa [frontier]
      using highestCommittableIndexValid state node (by simpa [frontier] using advances)
  have frontierSignature : isSignatureAt ((nodeOf state) node).log frontier = true := by
    simpa [frontier]
      using highestCommittableIndexIsSignature state node
        (by simpa [frontier] using advances)
  let evidence : CommitEvidence Node TxId :=
    { commitTerm := ((nodeOf state) node).currentTerm
      history := ((nodeOf state) node).log
      commitFrontier := frontier
      supportedLength := frontier
      authority :=
        currentConfigurationAt ((nodeOf state) node).log frontier
      ackQuorum := acknowledgingNodes (nodeOf state node) node frontier }
  let newNodeEvidence : NodeCommitEvidence Node TxId :=
    Function.update nodeEvidence node (some evidence)
  have roleEq :
        forall candidate,
          ((nodeOf (advanceCommitState state node)) candidate).role =
            ((nodeOf state) candidate).role := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          advanceCommitState, Model.Local.advanceCommit, present, nodeOf_replaceNode, same
        ]
  have termEq :
        forall candidate,
          ((nodeOf (advanceCommitState state node)) candidate).currentTerm =
            ((nodeOf state) candidate).currentTerm := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          advanceCommitState, Model.Local.advanceCommit, present, nodeOf_replaceNode, same
        ]
  have logEq :
        forall candidate,
          ((nodeOf (advanceCommitState state node)) candidate).log =
            ((nodeOf state) candidate).log := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          advanceCommitState, Model.Local.advanceCommit, present, nodeOf_replaceNode, same
        ]
  have sentEq :
        forall candidate,
          ((nodeOf (advanceCommitState state node)) candidate).sentIndex =
            ((nodeOf state) candidate).sentIndex := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          advanceCommitState, Model.Local.advanceCommit, present, nodeOf_replaceNode, same
        ]
  have matchEq :
        forall candidate,
          ((nodeOf (advanceCommitState state node)) candidate).matchIndex =
            ((nodeOf state) candidate).matchIndex := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          advanceCommitState, Model.Local.advanceCommit, present, nodeOf_replaceNode, same
        ]
  have votedEq :
        forall candidate,
          ((nodeOf (advanceCommitState state node)) candidate).votedFor =
            ((nodeOf state) candidate).votedFor := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          advanceCommitState, Model.Local.advanceCommit, present, nodeOf_replaceNode, same
        ]
  have votesEq :
        forall candidate,
          ((nodeOf (advanceCommitState state node)) candidate).votesGranted =
            ((nodeOf state) candidate).votesGranted := by
      intro candidate
      by_cases same : candidate = node <;>
        simp [
          advanceCommitState, Model.Local.advanceCommit, present, nodeOf_replaceNode, same
        ]
  have commitNode :
        ((nodeOf (advanceCommitState state node)) node).commitIndex =
          frontier := by
      simp [advanceCommitState, Model.Local.advanceCommit, present, frontier]
  have commitOther :
        forall candidate,
          Not (candidate = node) ->
          ((nodeOf (advanceCommitState state node)) candidate).commitIndex =
            ((nodeOf state) candidate).commitIndex := by
      intro candidate different
      simp [
        advanceCommitState, Model.Local.advanceCommit, present, nodeOf_replaceNode, different
      ]
  have roleNode :
      ((nodeOf (advanceCommitState state node)) node).role =
        .leader := by
    simpa [roleEq] using leaderRole
  have nodeNotCandidate :
      Not (
        ((nodeOf (advanceCommitState state node)) node).role =
          .candidate) := by
    rw [roleNode]
    decide
  have activeConfigurationsOtherEq :
      forall candidate,
        Not (candidate = node) ->
          activeConfigurations
              ((nodeOf (advanceCommitState state node)) candidate) =
            activeConfigurations ((nodeOf state) candidate) := by
    intro candidate different
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitOther candidate different]
  have committedSignatureAfter :
      CommittedFrontierIsSignature
        (advanceCommitState state node) := by
    intro candidate positive
    by_cases same : candidate = node
    · subst candidate
      rw [commitNode, logEq]
      exact frontierSignature
    · rw [commitOther candidate same, logEq]
      apply
        invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
          facts candidate
      simpa [commitOther candidate same] using positive
  have lastIndexEq :
      forall candidate,
        lastCommittableIndex
            ((nodeOf (advanceCommitState state node)) candidate) =
          lastCommittableIndex ((nodeOf state) candidate) := by
    intro candidate
    rw [
      lastCommittableIndex_eq_maxCommittableIndex
        ((nodeOf (advanceCommitState state node)) candidate)
        (committedSignatureAfter candidate),
      lastCommittableIndex_eq_maxCommittableIndex
        ((nodeOf state) candidate)
        (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
          facts candidate),
      logEq
    ]
  have lastTermEq :
      forall candidate,
        lastCommittableTerm
            ((nodeOf (advanceCommitState state node)) candidate) =
          lastCommittableTerm ((nodeOf state) candidate) := by
    intro candidate
    rw [
      lastCommittableTerm_eq_maxCommittableTerm
        ((nodeOf (advanceCommitState state node)) candidate)
        (committedSignatureAfter candidate),
      lastCommittableTerm_eq_maxCommittableTerm
        ((nodeOf state) candidate)
        (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
          facts candidate),
      logEq
    ]
  have committedNode :
        ((nodeOf (advanceCommitState state node)) node).committedLog =
          ((nodeOf state) node).log.take frontier := by
      simp [NodeState.committedLog, commitNode, logEq]
  have committedOther :
        forall candidate,
          Not (candidate = node) ->
          ((nodeOf (advanceCommitState state node)) candidate).committedLog =
            ((nodeOf state) candidate).committedLog := by
      intro candidate different
      simp [NodeState.committedLog, commitOther candidate different, logEq]
  have committedMonotonic :
        forall candidate,
          ((nodeOf state) candidate).committedLog <+:
            ((nodeOf (advanceCommitState state node)) candidate).committedLog := by
      intro candidate
      by_cases same : candidate = node
      · subst candidate
        rw [committedNode]
        have oldLe :
            ((nodeOf state) node).commitIndex <= frontier :=
          Nat.le_of_lt advances
        have taken :=
          List.take_prefix
            ((nodeOf state) node).commitIndex
            (((nodeOf state) node).log.take frontier)
        simpa [
          NodeState.committedLog,
          List.take_take, Nat.min_eq_left oldLe
        ] using taken
      · rw [committedOther candidate same]
  have networkEq :
        (advanceCommitState state node).network = state.network := by
      simp [advanceCommitState, Model.Local.advanceCommit, present]
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers (joined := joinedNodes)
            (advanceCommitState state node)
            responseHistory leader index =
          effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter]
    constructor
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined, Or.inl self⟩
      · exact ⟨
          by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined,
          Or.inr (Or.inl (by simpa [matchEq] using matched))
        ⟩
      · refine ⟨by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined, Or.inr (Or.inr ?_)⟩
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
          by simpa [logEq] using covered
        ⟩
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined, Or.inl self⟩
      · exact ⟨
          by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined,
          Or.inr (Or.inl (by simpa [matchEq] using matched))
        ⟩
      · refine ⟨by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined, Or.inr (Or.inr ?_)⟩
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
          by simpa [logEq] using covered
        ⟩
  have effectiveMajorityOtherEq :
      forall leader,
        Not (leader = node) ->
          forall index,
            (hasEffectiveMajorityAt (joined := joinedNodes)
                (advanceCommitState state node)
                responseHistory leader index ↔
              hasEffectiveMajorityAt (joined := joinedNodes) state responseHistory leader index) := by
    intro leader different index
    simp only [
      hasEffectiveMajorityAt,
      effectiveAckersEq,
      activeConfigurationsOtherEq leader different
    ]
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters (joined := joinedNodes)
            (advanceCommitState state node) candidate =
          effectiveElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    constructor <;> rintro ⟨joined, processed | queued⟩
    · exact ⟨
        by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined,
        Or.inl (by simpa [votesEq] using processed)
      ⟩
    · refine ⟨by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined, Or.inr ?_⟩
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
    · exact ⟨
        by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined,
        Or.inl (by simpa [votesEq] using processed)
      ⟩
    · refine ⟨by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined, Or.inr ?_⟩
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
  have effectiveElectionMajorityOtherEq :
      forall candidate,
        Not (candidate = node) ->
          (hasEffectiveElectionMajority (joined := joinedNodes)
              (advanceCommitState state node) candidate ↔
            hasEffectiveElectionMajority (joined := joinedNodes) state candidate) := by
    intro candidate different
    simp only [
      hasEffectiveElectionMajority,
      effectiveElectionVotersEq,
      activeConfigurationsOtherEq candidate different
    ]
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters (joined := joinedNodes)
            (advanceCommitState state node) candidate =
          potentialElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter]
    constructor <;> rintro ⟨joined, effective | eligible⟩
    · exact ⟨by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined, Or.inl (by
        rw [effectiveElectionVotersEq] at effective
        exact effective)⟩
    · exact ⟨by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined, Or.inr (by
        simpa [
          currentlyEligibleElectionVoter,
          voteRequestKey, Model.Local.makeRequestVoteRequest,
          termEq, logEq, lastIndexEq, lastTermEq,
          votedEq, voteLogUpToDate
        ] using eligible)⟩
    · exact ⟨by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined, Or.inl (by
        rw [effectiveElectionVotersEq]
        exact effective)⟩
    · exact ⟨by simpa [advanceCommitState, Model.Local.advanceCommit, present] using joined, Or.inr (by
        simpa [
          currentlyEligibleElectionVoter,
          voteRequestKey, Model.Local.makeRequestVoteRequest,
          termEq, logEq, lastIndexEq, lastTermEq,
          votedEq, voteLogUpToDate
        ] using eligible)⟩
  have potentialElectionMajorityOtherEq :
      forall candidate,
        Not (candidate = node) ->
          (hasPotentialElectionMajority (joined := joinedNodes)
              (advanceCommitState state node) candidate ↔
            hasPotentialElectionMajority (joined := joinedNodes) state candidate) := by
    intro candidate different
    simp only [
      hasPotentialElectionMajority,
      potentialElectionVotersEq,
      activeConfigurationsOtherEq candidate different
    ]
  have leaderCannotProduceAppendAck :
      forall (leaderState : NodeState Node TxId) request index,
        leaderState.role = .leader ->
          Not (canProduceAppendAckAt leaderState request index) := by
    intro leaderState request index role direct
    exact Role.noConfusion ((canProduceAppendAckAt_role direct).symm.trans role)
  have queuedAppendReserveEq :
      forall leader peer index,
        queuedAppendReserve
            (advanceCommitState state node)
            appendHistory leader peer index ↔
          queuedAppendReserve state appendHistory leader peer index := by
    intro leader peer index
    constructor
    <;> rintro ⟨request, member, sourceEq, destinationEq,
                 requestTerm, producible, covered⟩
    · exact ⟨
        request,
        by simpa [networkEq] using member,
        sourceEq,
        destinationEq,
        by simpa [termEq] using requestTerm,
        by
          by_cases peerEq : peer = node
          · have destinationNode : request.2.1 = node :=
              destinationEq.trans peerEq
            subst peer
            rcases producible with direct | future
            · rw [destinationNode] at direct
              exact False.elim
                (leaderCannotProduceAppendAck
                  ((nodeOf (advanceCommitState state node)) node)
                  request index roleNode direct)
            · exact Or.inr (by simpa [termEq] using future)
          · simpa [
              canProduceAppendAckEventuallyAt,
              canProduceAppendAckAt, advanceCommitState, Model.Local.advanceCommit, present,
              nodeOf_replaceNode, Function.update, peerEq
            ] using producible,
        by simpa [logEq] using covered
      ⟩
    · exact ⟨
        request,
        by simpa [networkEq] using member,
        sourceEq,
        destinationEq,
        by simpa [termEq] using requestTerm,
        by
          by_cases peerEq : peer = node
          · have destinationNode : request.2.1 = node :=
              destinationEq.trans peerEq
            subst peer
            rcases producible with direct | future
            · rw [destinationNode] at direct
              exact False.elim
                (leaderCannotProduceAppendAck
                  ((nodeOf state) node) request index leaderRole direct)
            · exact Or.inr (by simpa [termEq] using future)
          · simpa [
              canProduceAppendAckEventuallyAt,
              canProduceAppendAckAt, advanceCommitState, Model.Local.advanceCommit, present,
              nodeOf_replaceNode, Function.update, peerEq
            ] using producible,
        by simpa [logEq] using covered
      ⟩
  have potentialAckersEq :
      forall leader index,
        potentialAckers (joined := joinedNodes)
            (advanceCommitState state node)
            appendHistory responseHistory leader index =
          potentialAckers (joined := joinedNodes)
            state appendHistory responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      potentialAckers, Finset.mem_filter,
      effectiveAckersEq, queuedAppendReserveEq
    ]
  have potentialMajorityOtherEq :
      forall leader,
        Not (leader = node) ->
          forall index,
            (hasPotentialMajorityAt (joined := joinedNodes)
                (advanceCommitState state node)
                appendHistory responseHistory leader index ↔
              hasPotentialMajorityAt (joined := joinedNodes)
                state appendHistory responseHistory leader index) := by
    intro leader different index
    simp only [
      hasPotentialMajorityAt,
      potentialAckersEq,
      activeConfigurationsOtherEq leader different
    ]
  have frontierEffective :
      hasEffectiveMajorityAt (joined := joinedNodes) state responseHistory node frontier :=
    majorityImpliesEffectiveMajority
      state responseHistory node frontier
        (facts.joinedCarriers.activeNodes node) frontierValid.2
  have frontierPotential :
      hasPotentialMajorityAt (joined := joinedNodes)
        state appendHistory responseHistory node frontier :=
    effectiveMajorityImpliesPotential
      state appendHistory responseHistory node frontier frontierEffective
  have frontierPositive : 0 < frontier := by
    omega
  have supporterSnapshotExists :
      forall supporter,
        supporter ∈
            effectiveAckers (joined := joinedNodes) state responseHistory node frontier ->
          Exists fun snapshot : ProcessedAckSnapshot Node TxId =>
            snapshot.term = ((nodeOf state) node).currentTerm /\
              frontier <= snapshot.index /\
              snapshot.index <= snapshot.history.length /\
              snapshot.history.take frontier =
                ((nodeOf state) node).log.take frontier := by
    intro supporter member
    exact
      effectiveAckerSnapshotExists
        (fun destination response queued success =>
          (facts.networkHistory.appendResponse
            destination response queued success).1)
        ackFacts leaderRole frontierPositive frontierBound member
  let supporterSnapshot : Node -> ProcessedAckSnapshot Node TxId :=
    fun supporter =>
      if member :
          supporter ∈
            effectiveAckers (joined := joinedNodes) state responseHistory node frontier then
        Classical.choose (supporterSnapshotExists supporter member)
      else
        { term := 0
          index := 0
          history := [] }
  have supporterSnapshotSpec :
      forall supporter,
        supporter ∈
            effectiveAckers (joined := joinedNodes) state responseHistory node frontier ->
          (supporterSnapshot supporter).term =
              ((nodeOf state) node).currentTerm /\
            frontier <= (supporterSnapshot supporter).index /\
            (supporterSnapshot supporter).index <=
              (supporterSnapshot supporter).history.length /\
            (supporterSnapshot supporter).history.take frontier =
              ((nodeOf state) node).log.take frontier := by
    intro supporter member
    simpa [supporterSnapshot, member]
      using Classical.choose_spec (supporterSnapshotExists supporter member)
  have frontierHistoryCanonical :
      HistoryCanonical
        canonicalHistory (((nodeOf state) node).log.take frontier) :=
    historyCanonicalOfPrefix
      (nodeLogCanonical ownership node)
      (List.take_prefix frontier ((nodeOf state) node).log)
  let oldConfiguration := currentConfiguration ((nodeOf state) node)
  let newConfiguration :=
    currentConfigurationAt ((nodeOf state) node).log frontier
  let activationRecord : ActivationRecord Node TxId :=
    { leader := node
      history := ((nodeOf state) node).log
      priorCommitIndex := ((nodeOf state) node).commitIndex
      activationFrontier := frontier
      activationTerm := ((nodeOf state) node).currentTerm
      oldConfiguration
      newConfiguration
      governingActive :=
        ((allConfigurations ((nodeOf state) node).log).filter fun configuration =>
          oldConfiguration.index <= configuration.index /\
            configuration.index <= frontier)
      jointSupporters :=
        effectiveAckers (joined := joinedNodes) state responseHistory node frontier
      supporterAckTerm :=
        fun supporter => (supporterSnapshot supporter).term
      supporterAckIndex :=
        fun _ => frontier
      supporterHistory :=
        fun supporter =>
          (supporterSnapshot supporter).history.take frontier }
  let newActivationKey : ActivationKey (Node : Type) :=
    { configurationIndex := newConfiguration.index
      term := ((nodeOf state) node).currentTerm
      frontier
      leader := node }
  have oldConfigurationKnown :
      oldConfiguration ∈ allConfigurations ((nodeOf state) node).log := by
    simpa [oldConfiguration]
      using currentConfiguration_mem_allConfigurations ((nodeOf state) node)
  have oldConfigurationIndexBound :
      oldConfiguration.index <= ((nodeOf state) node).commitIndex := by
    simpa [oldConfiguration]
      using currentConfiguration_index_le_commitIndex ((nodeOf state) node)
  have newConfigurationKnown :
      newConfiguration ∈ allConfigurations ((nodeOf state) node).log := by
    simpa [newConfiguration, currentConfiguration]
      using currentConfiguration_mem_allConfigurations
        { ((nodeOf state) node) with commitIndex := frontier }
  have newConfigurationIndexBound :
      newConfiguration.index <= frontier := by
    simpa [newConfiguration, currentConfiguration]
      using currentConfiguration_index_le_commitIndex
        { ((nodeOf state) node) with commitIndex := frontier }
  have oldConfigurationBeforeNew :
      oldConfiguration.index <= newConfiguration.index := by
    have oldFrontierBound :
        oldConfiguration.index <= frontier :=
      oldConfigurationIndexBound.trans (Nat.le_of_lt advances)
    simpa [newConfiguration, currentConfiguration]
      using configuration_index_le_currentConfiguration
        { ((nodeOf state) node) with commitIndex := frontier }
        oldConfiguration
        (by simpa using oldConfigurationKnown)
        oldFrontierBound
  have newConfigurationActiveBefore :
      newConfiguration ∈ activeConfigurations ((nodeOf state) node) := by
    simpa [activeConfigurations, oldConfiguration]
      using And.intro newConfigurationKnown oldConfigurationBeforeNew
  have frontierAuthorityMajority :
      hasConfigurationMajority
        (acknowledgingNodes (nodeOf state node) node frontier)
        newConfiguration :=
    majorityAtConfiguration
      frontierValid.2 newConfigurationActiveBefore
      newConfigurationIndexBound
  have frontierEffectiveAuthorityMajority :
      hasConfigurationMajority
        (effectiveAckers (joined := joinedNodes) state responseHistory node frontier)
        (currentConfigurationAt ((nodeOf state) node).log frontier) := by
    simpa [newConfiguration]
      using hasConfigurationMajority_mono
        (acknowledgingNodes_subset_effectiveAckers
          state responseHistory node frontier
          (facts.joinedCarriers.activeNodes node))
        frontierAuthorityMajority
  have frontierCanonicalEq :
      ((nodeOf state) node).log.take frontier =
        (canonicalHistory ((nodeOf state) node).currentTerm).take frontier := by
    rcases isSignatureAtTrue frontierSignature with
      ⟨frontierEntry, frontierFound, _⟩
    have agreement :=
      (ownership.logEntryAgreement node frontier frontierEntry frontierFound).2
    have entryTerm :
        frontierEntry.term = ((nodeOf state) node).currentTerm := by
      simpa [termAt, frontierFound] using frontierValid.1
    simpa [entryTerm] using agreement
  have activationPrefixComparable
      (activationIndex : ActivationKey Node)
      (record : ActivationRecord Node TxId)
      (stored : activations activationIndex = some record) :
      record.history.take record.activationFrontier <+:
          ((nodeOf state) node).log.take frontier \/
        ((nodeOf state) node).log.take frontier <+:
          record.history.take record.activationFrontier := by
    have recordTermPositive :=
      activationQuorums.history.termPositive
        activationIndex record stored
    rcases Nat.lt_trichotomy
        record.activationTerm ((nodeOf state) node).currentTerm with
      earlier | sameTerm | later
    · have nodeOwned := ownership.activeLeader node leaderRole
      rcases
          electionFacts.ownerRecorded
            ((nodeOf state) node).currentTerm node nodeOwned with
        bootstrap | elected
      · have nodeTerm : ((nodeOf state) node).currentTerm = BOOTSTRAP_TERM := by
          simpa using bootstrap.1
        omega
      · rcases elected with ⟨election, electionStored, electionLeader⟩
        have recordInLeader :
            record.history.take record.activationFrontier <+:
              ((nodeOf state) node).log :=
          (activationPrefixInLaterElection
            activationElections stored electionStored earlier).trans
            ((electionFacts.promotionCanonical
              ((nodeOf state) node).currentTerm election electionStored).trans
              (by rw [ownership.activeLeaderHistory node leaderRole]))
        have activationBound :
            record.activationFrontier <= frontier := by
          rcases
              isSignatureAtTrue
                (activationQuorums.history.valid
                  activationIndex record stored).2.2.2.2.2.1 with
            ⟨activationEntry, activationFound, _⟩
          rcases isSignatureAtTrue frontierSignature with
            ⟨frontierEntry, frontierFound, _⟩
          have activationFoundLeader :
              entryAt? ((nodeOf state) node).log record.activationFrontier =
                some activationEntry :=
            entryAt_of_prefix recordInLeader
              (by
                rw [entryAtTake_of_le le_rfl]
                exact activationFound)
          have activationEntryTerm :
              activationEntry.term = record.activationTerm := by
            have activationTerm :=
              (activationQuorums.history.supporterAcks
                activationIndex record stored).1
            simpa [termAt, activationFound] using activationTerm
          have frontierEntryTerm :
              frontierEntry.term = ((nodeOf state) node).currentTerm := by
            simpa [termAt, frontierFound] using frontierValid.1
          by_contra outside
          have monotone :=
            (canonicalHistoriesMonoLog ownership) node
              frontier record.activationFrontier frontierEntry activationEntry
              (by omega) frontierFound activationFoundLeader
          rw [frontierEntryTerm, activationEntryTerm] at monotone
          omega
        left
        rw [List.prefix_take_iff]
        exact ⟨recordInLeader, (List.length_take_le _ _).trans activationBound⟩
    · have activationCanonicalEq :=
        activationCanonical.activationFrontierCanonical
        activationIndex record stored
      rw [sameTerm] at activationCanonicalEq
      by_cases activationBefore :
          record.activationFrontier <= frontier
      · left
        rw [activationCanonicalEq, frontierCanonicalEq]
        rw [List.prefix_take_iff]
        exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans activationBefore⟩
      · right
        rw [activationCanonicalEq, frontierCanonicalEq]
        rw [List.prefix_take_iff]
        exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans (by omega)⟩
    · right
      have recordOwned :=
        activationCanonical.termOwner
          activationIndex record stored
      rcases
          electionFacts.ownerRecorded
            record.activationTerm record.leader recordOwned with
        bootstrap | elected
      · have recordTerm : record.activationTerm = BOOTSTRAP_TERM := by
          simpa using bootstrap.1
        have nodePositive :=
          facts.currentTermsPositive node (by rw [leaderRole]; decide)
        omega
      · rcases elected with ⟨election, electionStored, electionLeader⟩
        have frontierInElection :=
          potentialPrefixInElectionRecordsFromActivationHistory
            facts.currentTermsPositive
            facts.entriesDoNotExceedCurrentTerm facts.voteHistory
            ownership electionFacts configurationFacts
            activationQuorums.history activationProgress
            ackerActivationFacts ackerElectionFacts
            activationCanonical activationElections
            configurationActivations evidenceFacts prospectiveFacts
            leaderRole frontierValid.1 frontierSignature frontierPotential
            record.activationTerm election electionStored later
        exact
          electionPromotionPrefixInActivation
            electionFacts activationQuorums.history activationCanonical
            stored electionStored frontierInElection
  let retainedActivation : Prop :=
    Exists fun activationIndex =>
      Exists fun record =>
        activations activationIndex = some record /\
          newConfiguration ∈ record.governingActive /\
          record.activationTerm <= ((nodeOf state) node).currentTerm /\
          record.history.take
              (min frontier record.activationFrontier) =
            ((nodeOf state) node).log.take
              (min frontier record.activationFrontier)
  let replaceActivation : Prop :=
    Not (oldConfiguration = newConfiguration) /\
      Not retainedActivation
  let newActivations : ActivationHistory Node TxId :=
    if replace : replaceActivation then
      Function.update activations newActivationKey
        (some activationRecord)
    else
      activations
  have retainedActivationOfGoverning
      (activationIndex : ActivationKey Node)
      (record : ActivationRecord Node TxId)
      (stored : activations activationIndex = some record)
      (governing : newConfiguration ∈ record.governingActive)
      (termBound :
        record.activationTerm <= ((nodeOf state) node).currentTerm) :
      retainedActivation := by
    refine ⟨activationIndex, record, stored, governing, termBound, ?_⟩
    let shared := min frontier record.activationFrontier
    have recordLength :
        (record.history.take record.activationFrontier).length =
          record.activationFrontier := by
      simp [Nat.min_eq_left
        (activationQuorums.history.valid
          activationIndex record stored).2.1]
    have frontierLength :
        (((nodeOf state) node).log.take frontier).length = frontier := by
      simp [Nat.min_eq_left frontierBound]
    rcases activationPrefixComparable activationIndex record stored with
      recordBefore | frontierBefore
    · have agreed :=
        takeEqOfPrefix recordBefore
          (count := shared)
          (by simp [shared, recordLength])
      simpa [shared, List.take_take] using agreed
    · have agreed :=
        takeEqOfPrefix frontierBefore
          (count := shared)
          (by simp [shared, frontierLength])
      simpa [shared, List.take_take] using agreed.symm
  have activationConfigurationEqNew
      (activationIndex : ActivationKey Node)
      (record : ActivationRecord Node TxId)
      (stored : activations activationIndex = some record)
      (sameIndex :
        record.newConfiguration.index = newConfiguration.index) :
      record.newConfiguration = newConfiguration := by
    rcases activationPrefixComparable activationIndex record stored with
      recordBefore | frontierBefore
    · apply
        allConfigurations_index_unique
          (TxId := TxId) ((nodeOf state) node).log
      · apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (recordBefore.trans
                (List.take_prefix frontier ((nodeOf state) node).log)))
        exact activationNewConfigurationKnown
          activationQuorums.history stored
      · exact newConfigurationKnown
      · exact sameIndex
    · apply
        allConfigurations_index_unique
          (TxId := TxId) record.history
      · exact
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix
                record.activationFrontier record.history))
            (activationNewConfigurationKnown
              activationQuorums.history stored)
      · apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (frontierBefore.trans
                (List.take_prefix record.activationFrontier record.history)))
        exact
          allConfigurations_mem_take_of_index_le
            ((nodeOf state) node).log frontier frontierBound
            newConfigurationKnown newConfigurationIndexBound
      · exact sameIndex
  have storedAtNewConfigurationEq
      (record : ActivationRecord Node TxId)
      (stored : activations newActivationKey = some record) :
      record.newConfiguration = newConfiguration := by
    have recordValid :=
      activationQuorums.history.valid
        newActivationKey record stored
    have indexed :=
      activationQuorums.history.indexed
        newActivationKey record stored
    exact
      activationConfigurationEqNew newActivationKey record stored
        (by simpa [newActivationKey] using indexed.1.symm)
  have retainedActivationOfStored
      (record : ActivationRecord Node TxId)
      (stored : activations newActivationKey = some record) :
      retainedActivation := by
    have recordConfiguration :=
      storedAtNewConfigurationEq record stored
    have governing :
        newConfiguration ∈ record.governingActive := by
      simpa [recordConfiguration]
        using (activationQuorums.history.valid
                newActivationKey record stored).2.2.2.2.2.2.2.1
    exact retainedActivationOfGoverning
      newActivationKey record stored governing
      (by
        have indexed :=
          activationQuorums.history.indexed
            newActivationKey record stored
        simpa [newActivationKey] using Nat.le_of_eq indexed.2.1.symm)
  have activationAbsentAtNew
      (create : replaceActivation) :
      activations newActivationKey = none := by
    cases stored : activations newActivationKey with
    | none => rfl
    | some record =>
        exact False.elim
          (create.2 (retainedActivationOfStored record stored))
  have retainedActivationOfCoveringWitness
      (witness :
        ConfigurationCoverageWitness state activations node)
      (newBeforeWitness :
        newConfiguration.index <=
          witness.activation.newConfiguration.index) :
      retainedActivation := by
    have valid :=
      activationQuorums.history.valid
        witness.activationIndex witness.activation witness.stored
    have newWithinActivation :
        newConfiguration.index <=
          witness.activation.activationFrontier := by
      have newGoverning :=
        valid.2.2.2.2.2.2.2.1
      rw [valid.2.2.2.2.2.2.1] at newGoverning
      exact
        newBeforeWitness.trans
          (of_decide_eq_true
            (List.mem_filter.mp newGoverning).2).2
    have newKnownActivation :
        newConfiguration ∈ allConfigurations witness.activation.history := by
      have newKnownLeaderTake :=
        allConfigurations_mem_take_of_index_le
          ((nodeOf state) node).log newConfiguration.index
          (newConfigurationIndexBound.trans frontierBound)
          newConfigurationKnown le_rfl
      have activationLength :
          (witness.activation.history.take
            witness.activation.activationFrontier).length =
              witness.activation.activationFrontier := by
        simp [Nat.min_eq_left valid.2.1]
      have frontierLength :
          (((nodeOf state) node).log.take frontier).length = frontier := by
        simp [Nat.min_eq_left frontierBound]
      rcases
          activationPrefixComparable
            witness.activationIndex witness.activation witness.stored with
        activationBefore | frontierBefore
      · have agreed :=
          takeEqOfPrefix activationBefore
            (count := newConfiguration.index)
            (by simpa [activationLength] using newWithinActivation)
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix
                newConfiguration.index witness.activation.history))
        rw [show
          witness.activation.history.take newConfiguration.index =
              ((nodeOf state) node).log.take newConfiguration.index by
            simpa [
              List.take_take,
              Nat.min_eq_left newWithinActivation,
              Nat.min_eq_left newConfigurationIndexBound
            ] using agreed]
        exact newKnownLeaderTake
      · have agreed :=
          takeEqOfPrefix frontierBefore
            (count := newConfiguration.index)
            (by simpa [frontierLength] using newConfigurationIndexBound)
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix
                newConfiguration.index witness.activation.history))
        rw [show
          witness.activation.history.take newConfiguration.index =
              ((nodeOf state) node).log.take newConfiguration.index by
            simpa [
              List.take_take,
              Nat.min_eq_left newWithinActivation,
              Nat.min_eq_left newConfigurationIndexBound
            ] using agreed.symm]
        exact newKnownLeaderTake
    have oldBeforeNew :
        witness.activation.oldConfiguration.index <=
          newConfiguration.index := by
      have covered := witness.configurationCovered
      rw [valid.2.2.2.2.2.2.1] at covered
      exact (of_decide_eq_true (List.mem_filter.mp covered).2).1
      |>.trans oldConfigurationBeforeNew
    have newGoverning :
        newConfiguration ∈ witness.activation.governingActive := by
      rw [valid.2.2.2.2.2.2.1]
      exact
        List.mem_filter.mpr
          ⟨newKnownActivation,
            decide_eq_true
              ⟨oldBeforeNew, newWithinActivation⟩⟩
    exact
      retainedActivationOfGoverning
        witness.activationIndex witness.activation witness.stored
        newGoverning witness.activationTermBound
  have coveringWitnessBeforeNew
      (create : replaceActivation)
      (witness :
        ConfigurationCoverageWitness state activations node) :
      witness.activation.newConfiguration.index <
        newConfiguration.index := by
    by_contra notBefore
    exact
      create.2
        (retainedActivationOfCoveringWitness witness
          (Nat.le_of_not_gt notBefore))
  have noOldActivationGovernsNew
      (create : replaceActivation)
      (activationIndex : ActivationKey Node)
      (record : ActivationRecord Node TxId)
      (stored : activations activationIndex = some record)
      (termBound :
        record.activationTerm <= ((nodeOf state) node).currentTerm) :
      Not (newConfiguration ∈ record.governingActive) := by
    intro governing
    exact
      create.2
        (retainedActivationOfGoverning
          activationIndex record stored governing termBound)
  have currentConfigurationNodeEq :
      currentConfiguration
          ((nodeOf (advanceCommitState state node)) node) =
        newConfiguration := by
    simp [
      currentConfiguration, newConfiguration,
      commitNode, logEq
    ]
  have activeConfigurationsNodeSubset :
      forall configuration,
        configuration ∈
            activeConfigurations
              ((nodeOf (advanceCommitState state node)) node) ->
          configuration ∈ activeConfigurations ((nodeOf state) node) := by
    intro configuration active
    have parts :
        configuration ∈ allConfigurations ((nodeOf state) node).log /\
          newConfiguration.index <= configuration.index := by
      simpa [activeConfigurations, currentConfigurationNodeEq, logEq] using active
    simpa [activeConfigurations, oldConfiguration]
      using And.intro parts.1 (oldConfigurationBeforeNew.trans parts.2)
  have effectiveMajorityNodeAfterOfBefore :
      forall index,
        hasEffectiveMajorityAt (joined := joinedNodes) state responseHistory node index ->
          hasEffectiveMajorityAt (joined := joinedNodes)
            (advanceCommitState state node)
            responseHistory node index := by
    intro index majority
    rw [hasEffectiveMajorityAt, List.all_eq_true] at majority ⊢
    intro configuration active
    simpa [effectiveAckersEq]
      using majority configuration (activeConfigurationsNodeSubset configuration active)
  have activationRecordValid
      (different : Not (oldConfiguration = newConfiguration)) :
      activationRecord.Valid := by
    refine ⟨advances, frontierBound, ?_, ?_, different, frontierSignature, rfl, ?_, ?_⟩
    · simp [activationRecord, oldConfiguration, currentConfiguration]
    · simp [activationRecord, newConfiguration]
    · simp [
        activationRecord, newConfigurationKnown,
        oldConfigurationBeforeNew, newConfigurationIndexBound
      ]
    · intro configuration member
      simp only [
        activationRecord, List.mem_filter
      ] at member
      have bounds := of_decide_eq_true member.2
      have active :
          configuration ∈ activeConfigurations ((nodeOf state) node) := by
        simp [
          activeConfigurations, oldConfiguration,
          member.1, bounds.1
        ]
      exact
        effectiveMajorityAtConfiguration
          frontierEffective active bounds.2
  have activationRecordPermanent :
      activationRecord.Permanent := by
    intro laterFrontier activationBefore laterBound
    have newKnown :
        newConfiguration ∈
          allConfigurations ((nodeOf state) node).log :=
      newConfigurationKnown
    have newCommitted :
        newConfiguration.index <= laterFrontier :=
      newConfigurationIndexBound.trans activationBefore
    simpa [activationRecord, newConfiguration, currentConfiguration]
      using configuration_index_le_currentConfiguration
        { ((nodeOf state) node) with commitIndex := laterFrontier }
        newConfiguration
        (by simpa using newKnown)
        newCommitted
  have activationHistoryAfter :
      ActivationHistoryFacts newActivations := by
    by_cases create : replaceActivation
    · constructor
      · intro index record stored
        by_cases same : index = newActivationKey
        · subst index
          have recordEq : activationRecord = record := by
            simpa [newActivations, create] using stored
          subst record
          simp [newActivationKey, activationRecord]
        · have oldStored :
              activations index = some record := by
            simpa [newActivations, create, Function.update, same] using stored
          exact activationQuorums.history.indexed index record oldStored
      · intro leftIndex left rightIndex right leftStored rightStored
          _sameConfiguration
        by_cases leftNew : leftIndex = newActivationKey
        · subst leftIndex
          have leftEq : activationRecord = left := by
            simpa [newActivations, create] using leftStored
          subst left
          by_cases rightNew : rightIndex = newActivationKey
          · subst rightIndex
            have rightEq : activationRecord = right := by
              simpa [newActivations, create] using rightStored
            subst right
            exact Or.inl (prefixRefl _)
          · have oldRight :
                activations rightIndex = some right := by
              simpa [newActivations, create, Function.update, rightNew] using rightStored
            rcases
                activationPrefixComparable rightIndex right oldRight with
              rightBefore | newBefore
            · exact Or.inr (by simpa [activationRecord] using rightBefore)
            · exact Or.inl (by simpa [activationRecord] using newBefore)
        · have oldLeft :
              activations leftIndex = some left := by
            simpa [newActivations, create, Function.update, leftNew] using leftStored
          by_cases rightNew : rightIndex = newActivationKey
          · subst rightIndex
            have rightEq : activationRecord = right := by
              simpa [newActivations, create] using rightStored
            subst right
            rcases
                activationPrefixComparable leftIndex left oldLeft with
              leftBefore | newBefore
            · exact Or.inl (by simpa [activationRecord] using leftBefore)
            · exact Or.inr (by simpa [activationRecord] using newBefore)
          · exact
              activationQuorums.history.sameConfigurationComparable
                leftIndex left rightIndex right oldLeft
                (by simpa [
                  newActivations, create, Function.update, rightNew
                ] using rightStored)
                _sameConfiguration
      · intro index record stored
        by_cases same : index = newActivationKey
        · subst index
          have recordEq : activationRecord = record := by
            simpa [newActivations, create] using stored
          subst record
          exact activationRecordValid create.1
        · have oldStored :
              activations index = some record := by
            simpa [newActivations, create, Function.update, same] using stored
          exact activationQuorums.history.valid index record oldStored
      · intro index record stored
        by_cases same : index = newActivationKey
        · subst index
          have recordEq : activationRecord = record := by
            simpa [newActivations, create] using stored
          subst record
          exact activationRecordPermanent
        · have oldStored :
              activations index = some record := by
            simpa [newActivations, create, Function.update, same] using stored
          exact activationQuorums.history.permanent index record oldStored
      · intro index record stored
        by_cases same : index = newActivationKey
        · subst index
          have recordEq : activationRecord = record := by
            simpa [newActivations, create] using stored
          subst record
          simpa [activationRecord, EarlierBadElection]
            using facts.currentTermsPositive node (by rw [leaderRole]; decide)
        · have oldStored :
              activations index = some record := by
            simpa [newActivations, create, Function.update, same] using stored
          exact
            activationQuorums.history.termPositive
              index record oldStored
      · intro index record stored
        by_cases same : index = newActivationKey
        · subst index
          have recordEq : activationRecord = record := by
            simpa [newActivations, create] using stored
          subst record
          refine ⟨?_, ?_⟩
          · simpa [activationRecord] using frontierValid.1
          · intro supporter member
            have snapshot := supporterSnapshotSpec supporter member
            exact ⟨
              by simpa [activationRecord] using snapshot.1,
              by simp [activationRecord],
              by
                simp [
                  activationRecord,
                  List.length_take,
                  Nat.min_eq_left
                    (snapshot.2.1.trans snapshot.2.2.1)
                ],
              by
                simpa [activationRecord, List.take_take,
                  Nat.min_eq_left (le_refl frontier)]
                  using snapshot.2.2.2
            ⟩
        · have oldStored :
              activations index = some record := by
            simpa [newActivations, create, Function.update, same] using stored
          exact
            activationQuorums.history.supporterAcks
              index record oldStored
      · intro index record stored oldPositive
        by_cases same : index = newActivationKey
        · subst index
          have recordEq : activationRecord = record := by
            simpa [newActivations, create] using stored
          subst record
          rcases
              configurationActivations node
                (by simpa [activationRecord] using oldPositive) with
            ⟨witness⟩
          have priorBeforeNew :=
            coveringWitnessBeforeNew create witness
          have witnessIndexNe :
              Not (witness.activationIndex = newActivationKey) := by
            intro sameIndex
            have indexed :=
              activationQuorums.history.indexed
                witness.activationIndex witness.activation witness.stored
            rw [sameIndex] at indexed
            simp [newActivationKey] at indexed
            omega
          have witnessStoredAfter :
              newActivations witness.activationIndex =
                some witness.activation := by
            simpa [newActivations, create, Function.update, witnessIndexNe]
              using witness.stored
          have witnessPrefixInFrontier :
              witness.activation.history.take
                  witness.activation.activationFrontier <+:
                ((nodeOf state) node).log.take frontier := by
            rcases
                activationPrefixComparable
                  witness.activationIndex witness.activation
                    witness.stored with
              ordered | reversed
            · exact ordered
            · have newKnownActivation :
                  newConfiguration ∈
                    allConfigurations witness.activation.history := by
                apply
                  memOfPrefix
                    (allConfigurations_mono_prefix
                      (reversed.trans
                        (List.take_prefix
                          witness.activation.activationFrontier
                          witness.activation.history)))
                exact
                  allConfigurations_mem_take_of_index_le
                    ((nodeOf state) node).log frontier frontierBound
                    newConfigurationKnown newConfigurationIndexBound
              have valid :=
                activationQuorums.history.valid
                  witness.activationIndex witness.activation witness.stored
              have activationLength :
                  (witness.activation.history.take
                    witness.activation.activationFrontier).length =
                      witness.activation.activationFrontier := by
                simp [Nat.min_eq_left valid.2.1]
              have frontierLength :
                  (((nodeOf state) node).log.take frontier).length = frontier := by
                simp [Nat.min_eq_left frontierBound]
              have frontierWithin :
                  frontier <= witness.activation.activationFrontier := by
                simpa [activationLength, frontierLength] using reversed.length_le
              let activationNode : NodeState Node TxId :=
                { (nodeOf state) node with
                  log := witness.activation.history
                  commitIndex := witness.activation.activationFrontier }
              have maximal :=
                configuration_index_le_currentConfiguration
                  activationNode newConfiguration
                  (by simpa [activationNode] using newKnownActivation)
                  (by
                    simpa [activationNode]
                      using newConfigurationIndexBound.trans frontierWithin)
              have contradiction :
                  newConfiguration.index <=
                    witness.activation.newConfiguration.index := by
                simpa [activationNode, currentConfiguration, valid.2.2.2.1] using maximal
              omega
          have activationFrontierBeforeNew :
              witness.activation.activationFrontier <
                newConfiguration.index := by
            by_contra notBefore
            have newWithin :
                newConfiguration.index <=
                  witness.activation.activationFrontier :=
              Nat.le_of_not_gt notBefore
            have valid :=
              activationQuorums.history.valid
                witness.activationIndex witness.activation witness.stored
            have activationLength :
                (witness.activation.history.take
                  witness.activation.activationFrontier).length =
                    witness.activation.activationFrontier := by
              simp [Nat.min_eq_left valid.2.1]
            have activationFrontierInLeader :
                witness.activation.activationFrontier <=
                  frontier := by
              have frontierLength :
                  (((nodeOf state) node).log.take frontier).length = frontier := by
                simp [Nat.min_eq_left frontierBound]
              simpa [activationLength, frontierLength]
                using witnessPrefixInFrontier.length_le
            have newKnownActivation :
                newConfiguration ∈
                  allConfigurations witness.activation.history := by
              have exactTake :
                  ((nodeOf state) node).log.take
                      witness.activation.activationFrontier =
                    witness.activation.history.take
                      witness.activation.activationFrontier := by
                simpa [activationLength, List.take_take,
                  Nat.min_eq_left activationFrontierInLeader]
                  using prefixEqTake witnessPrefixInFrontier
              apply
                memOfPrefix
                  (allConfigurations_mono_prefix
                    (List.take_prefix
                      witness.activation.activationFrontier
                      witness.activation.history))
              rw [← exactTake]
              exact
                allConfigurations_mem_take_of_index_le
                  ((nodeOf state) node).log
                  witness.activation.activationFrontier
                  (activationFrontierInLeader.trans frontierBound)
                  newConfigurationKnown newWithin
            let activationNode : NodeState Node TxId :=
              { (nodeOf state) node with
                log := witness.activation.history
                commitIndex := witness.activation.activationFrontier }
            have ordered :=
              configuration_index_le_currentConfiguration
                activationNode newConfiguration
                (by simpa [activationNode] using newKnownActivation)
                (by simpa [activationNode] using newWithin)
            have newBeforePrior :
                newConfiguration.index <=
                  witness.activation.newConfiguration.index := by
              simpa [activationNode, currentConfiguration, valid.2.2.2.1] using ordered
            omega
          exact ⟨
            witness.activationIndex,
            witness.activation,
            witnessStoredAfter,
            priorBeforeNew,
            by simpa [activationRecord] using witness.configurationCovered,
            by simpa [
                activationRecord
              ] using witnessPrefixInFrontier
          ⟩
        · have oldStored :
              activations index = some record := by
            simpa [newActivations, create, Function.update, same] using stored
          obtain ⟨priorIndex, prior, priorFacts⟩ :=
            activationQuorums.history.priorActivation
              index record oldStored oldPositive
          have priorIndexNe :
              Not (priorIndex = newActivationKey) := by
            intro sameIndex
            have absent := activationAbsentAtNew create
            rw [← sameIndex, priorFacts.1] at absent
            contradiction
          exact ⟨
            priorIndex,
            prior,
            by simpa [
                newActivations, create, Function.update, priorIndexNe
              ] using priorFacts.1,
            priorFacts.2.1,
            priorFacts.2.2.1,
            priorFacts.2.2.2
          ⟩
    · simpa [newActivations, create] using activationQuorums.history
  have oldActivationProgressAfter :
      ActivationSupporterProgress
        (advanceCommitState state node) activations := by
    apply
      activationSupporterProgressFrame
        state (advanceCommitState state node)
          activations activationProgress
    intro candidate
    rw [termEq]
  have activationProgressAfter :
      ActivationSupporterProgress
        (advanceCommitState state node) newActivations := by
    by_cases create : replaceActivation
    · intro index record stored supporter member
      by_cases same : index = newActivationKey
      · subst index
        have recordEq : activationRecord = record := by
          simpa [newActivations, create] using stored
        subst record
        rw [termEq]
        apply
          effectiveAckerCurrentTermBound
            facts.entriesDoNotExceedCurrentTerm ackerCurrentFacts
            leaderRole frontierValid.1 frontierSignature
        simpa [activationRecord] using member
      · have oldStored :
            activations index = some record := by
          simpa [newActivations, create, Function.update, same] using stored
        exact
          oldActivationProgressAfter
            index record oldStored supporter member
    · simpa [newActivations, create] using oldActivationProgressAfter
  have activationCanonicalAfter :
      ActivationCanonicalFacts
        canonicalHistory owners newActivations := by
    by_cases create : replaceActivation
    · constructor
      · intro index record stored
        by_cases same : index = newActivationKey
        · subst index
          have recordEq : activationRecord = record := by
            simpa [newActivations, create] using stored
          subst record
          simpa [activationRecord] using ownership.activeLeader node leaderRole
        · exact
            activationCanonical.termOwner index record
              (by simpa [
                newActivations, create, Function.update, same
              ] using stored)
      · intro index record stored
        by_cases same : index = newActivationKey
        · subst index
          have recordEq : activationRecord = record := by
            simpa [newActivations, create] using stored
          subst record
          simpa [activationRecord] using nodeLogCanonical ownership node
        · exact
            activationCanonical.recordCanonical index record
              (by simpa [
                newActivations, create, Function.update, same
              ] using stored)
      · intro index record stored
        by_cases same : index = newActivationKey
        · subst index
          have recordEq : activationRecord = record := by
            simpa [newActivations, create] using stored
          subst record
          have activeHistory :=
            ownership.activeLeaderHistory node leaderRole
          simp [activationRecord, activeHistory]
        · exact
            activationCanonical.activationFrontierCanonical index record
              (by simpa [
                newActivations, create, Function.update, same
              ] using stored)
      · intro index record stored supporter member
        by_cases same : index = newActivationKey
        · subst index
          have recordEq : activationRecord = record := by
            simpa [newActivations, create] using stored
          subst record
          have snapshot := supporterSnapshotSpec supporter member
          rw [show
            (activationRecord.supporterHistory supporter) =
                ((nodeOf state) node).log.take frontier by
              simpa [activationRecord] using snapshot.2.2.2]
          exact frontierHistoryCanonical
        · exact
            activationCanonical.supporterCanonical
              index record
                (by simpa [
                  newActivations, create, Function.update, same
                ] using stored)
              supporter member
    · simpa [newActivations, create] using activationCanonical
  have temporalFacts :=
    ackerTemporalFrameSameLogs
      state (advanceCommitState state node)
        votes votes responseHistory voteVoterHistory elections
        ackerCurrentFacts ackerVoteFacts ackerElectionFacts
        (fun leader role => by simpa [roleEq] using role)
        (fun leader _ => termEq leader)
        logEq
        (fun leader index voter _ _ member => by
          rw [effectiveAckersEq] at member
          exact member)
        (fun candidate => Nat.le_of_eq (termEq candidate).symm)
        (fun _ _ _ voted _ => voted)
  have oldAckerActivationAfter :
      AckerActivationHistory (joined := joinedNodes)
        (advanceCommitState state node)
        responseHistory elections activations := by
    apply
      ackerActivationFrameSameLogs
        state (advanceCommitState state node)
          responseHistory elections elections activations
          ackerActivationFacts
    · intro source role
      simpa [roleEq] using role
    · intro source role
      exact termEq source
    · exact logEq
    · intro source index supporter role current member
      rw [effectiveAckersEq] at member
      exact member
    · intro term record stored
      exact stored
  have ackerActivationAfter :
      AckerActivationHistory (joined := joinedNodes)
        (advanceCommitState state node)
        responseHistory elections newActivations := by
    by_cases create : replaceActivation
    · intro source index role current signature
          activationIndex activation configuration supporter
          stored governing activationSupporter effective later
      by_cases same : activationIndex = newActivationKey
      · subst activationIndex
        have activationEq : activationRecord = activation := by
          simpa [newActivations, create] using stored
        subst activation
        rcases
            electionFacts.ownerRecorded
              ((nodeOf state) node).currentTerm node
              (ownership.activeLeader node leaderRole) with
          bootstrap | recordedElection
        · have sourcePositive :=
            facts.currentTermsPositive source
              (by
                have oldRole : ((nodeOf state) source).role = .leader := by
                  simpa [roleEq] using role
                rw [oldRole]
                decide)
          have bootstrapTerm :
              ((nodeOf state) node).currentTerm = BOOTSTRAP_TERM := by
            simpa using bootstrap.1
          have sourceBeforeBootstrap :
              ((nodeOf state) source).currentTerm < BOOTSTRAP_TERM := by
            simpa [activationRecord, termEq, bootstrapTerm] using later
          omega
        · rcases recordedElection with
            ⟨activationElection, electionStored, electionLeader⟩
          let sourcePrefix :=
            ((nodeOf (advanceCommitState state node)) source).log.take index
          by_cases retained :
              sourcePrefix <+: activationElection.promotionLog
          · left
            have promotionInLeader :
                activationElection.promotionLog <+:
                  ((nodeOf state) node).log :=
              (electionFacts.promotionCanonical
                ((nodeOf state) node).currentTerm
                activationElection electionStored).trans
                (by rw [ownership.activeLeaderHistory node leaderRole])
            have sourceInLeader :
                sourcePrefix <+: ((nodeOf state) node).log :=
              retained.trans promotionInLeader
            rcases isSignatureAtTrue signature with
              ⟨sourceEntry, sourceFound, _⟩
            rcases isSignatureAtTrue frontierSignature with
              ⟨frontierEntry, frontierFound, _⟩
            have sourceEntryTerm :
                sourceEntry.term =
                  ((nodeOf state) source).currentTerm := by
              simpa [termAt, sourceFound, termEq] using current
            have frontierEntryTerm :
                frontierEntry.term =
                  ((nodeOf state) node).currentTerm := by
              simpa [termAt, frontierFound] using frontierValid.1
            have sourceFoundLeader :
                entryAt? ((nodeOf state) node).log index =
                  some sourceEntry := by
              apply entryAt_of_prefix sourceInLeader
              rw [entryAtTake_of_le le_rfl]
              exact sourceFound
            have indexLeFrontier : index <= frontier := by
              by_contra outside
              have monotone :=
                (canonicalHistoriesMonoLog ownership) node
                  frontier index frontierEntry sourceEntry
                  (by omega) frontierFound sourceFoundLeader
              rw [frontierEntryTerm, sourceEntryTerm] at monotone
              have sourceBefore :
                  ((nodeOf state) source).currentTerm <
                    ((nodeOf state) node).currentTerm := by
                simpa [activationRecord, termEq] using later
              omega
            have sourceInFrontier :
                sourcePrefix <+:
                  ((nodeOf state) node).log.take frontier := by
              rw [List.prefix_take_iff]
              refine ⟨sourceInLeader, ?_⟩
              have sourceBound := entryAtSomeIndexBound sourceFound
              simpa [
                sourcePrefix, List.length_take,
                Nat.min_eq_left sourceBound
              ] using indexLeFrontier
            have snapshot :=
              supporterSnapshotSpec supporter activationSupporter
            rw [show
              activationRecord.supporterHistory supporter =
                  ((nodeOf state) node).log.take frontier by
                simpa [activationRecord] using snapshot.2.2.2]
            exact sourceInFrontier
          · right
            exact ⟨
              ((nodeOf state) node).currentTerm,
              activationElection,
              by simpa [termEq] using later,
              le_rfl,
              electionStored,
              by simpa [sourcePrefix] using retained
            ⟩
      · have oldStored :
            activations activationIndex = some activation := by
          simpa [newActivations, create, Function.update, same] using stored
        exact
          oldAckerActivationAfter
            source index role current signature
            activationIndex activation configuration supporter
            oldStored governing activationSupporter effective later
    · simpa [newActivations, create] using oldAckerActivationAfter
  have activationElectionsAfter :
      ActivationElectionFacts votes elections newActivations := by
    constructor
    intro activationIndex activation electionTerm election
        activationStored electionStored laterElection
    by_cases create : replaceActivation
    · by_cases same : activationIndex = newActivationKey
      · subst activationIndex
        have activationEq : activationRecord = activation := by
          simpa [newActivations, create] using activationStored
        subst activation
        exact Or.inl
          (by
            simpa [activationRecord]
              using (potentialPrefixInElectionRecordsFromActivationHistory
                      facts.currentTermsPositive
                      facts.entriesDoNotExceedCurrentTerm facts.voteHistory
                      ownership electionFacts configurationFacts
                      activationQuorums.history activationProgress
                      ackerActivationFacts ackerElectionFacts
                      activationCanonical activationElections
                      configurationActivations evidenceFacts prospectiveFacts
                      leaderRole frontierValid.1 frontierSignature
                      frontierPotential electionTerm election electionStored
                      (by simpa [activationRecord] using laterElection)))
      · have oldStored :
            activations activationIndex = some activation := by
          simpa [newActivations, create, Function.update, same] using activationStored
        exact
          activationElections.closure
            activationIndex activation electionTerm election
            oldStored electionStored laterElection
    · simpa [newActivations, create]
        using (activationElections.closure
                activationIndex activation electionTerm election
                (by simpa [newActivations, create] using activationStored)
                electionStored laterElection)
  have activationPreservedOfNe :
      forall index activation,
        Not (index = newActivationKey) ->
        activations index = some activation ->
          newActivations index = some activation := by
    intro index activation different stored
    by_cases create : replaceActivation
    · simpa [
        newActivations, create, Function.update, different
      ] using stored
    · simpa [newActivations, create] using stored
  have oldActivationPrefixInNew
      (activationIndex : ActivationKey Node)
      (activation : ActivationRecord Node TxId)
      (stored : activations activationIndex = some activation)
      (before :
        activation.newConfiguration.index < newConfiguration.index) :
      activation.history.take activation.activationFrontier <+:
        ((nodeOf state) node).log.take frontier := by
    rcases activationPrefixComparable activationIndex activation stored with
      ordered | reversed
    · exact ordered
    · have newKnownActivation :
          newConfiguration ∈ allConfigurations activation.history := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (reversed.trans
                (List.take_prefix
                  activation.activationFrontier activation.history)))
        exact
          allConfigurations_mem_take_of_index_le
            ((nodeOf state) node).log frontier frontierBound
            newConfigurationKnown newConfigurationIndexBound
      let activationNode : NodeState Node TxId :=
        { (nodeOf state) node with
          log := activation.history
          commitIndex := activation.activationFrontier }
      have maximal :=
        configuration_index_le_currentConfiguration activationNode newConfiguration
          (by simpa [activationNode] using newKnownActivation)
          (by
            have reversedLength := reversed.length_le
            have activationLength :
                (activation.history.take
                  activation.activationFrontier).length =
                    activation.activationFrontier := by
              simp [Nat.min_eq_left
                (activationQuorums.history.valid
                  activationIndex activation stored).2.1]
            have frontierLength :
                (((nodeOf state) node).log.take frontier).length =
                  frontier := by
              simp [Nat.min_eq_left frontierBound]
            have frontierBeforeActivation :
                frontier <= activation.activationFrontier := by
              simpa [activationLength, frontierLength] using reversedLength
            simpa [activationNode]
              using newConfigurationIndexBound.trans frontierBeforeActivation)
      have contradiction :
          newConfiguration.index <=
            activation.newConfiguration.index := by
        simpa [activationNode, currentConfiguration,
          (activationQuorums.history.valid
            activationIndex activation stored).2.2.2.1]
          using maximal
      omega
  have newActivationPrefixInOld
      (activationIndex : ActivationKey Node)
      (activation : ActivationRecord Node TxId)
      (stored : activations activationIndex = some activation)
      (before :
        newConfiguration.index < activation.newConfiguration.index) :
      ((nodeOf state) node).log.take frontier <+:
        activation.history.take activation.activationFrontier := by
    rcases activationPrefixComparable activationIndex activation stored with
      reversed | ordered
    · have activationKnownLeader :
          activation.newConfiguration ∈
            allConfigurations ((nodeOf state) node).log := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (reversed.trans
                (List.take_prefix frontier ((nodeOf state) node).log)))
        exact
          activationNewConfigurationKnown
            activationQuorums.history stored
      have activationWithin :
          activation.newConfiguration.index <= frontier := by
        have reversedLength := reversed.length_le
        have activationLength :
            (activation.history.take
              activation.activationFrontier).length =
                activation.activationFrontier := by
          simp [Nat.min_eq_left
            (activationQuorums.history.valid
              activationIndex activation stored).2.1]
        have frontierLength :
            (((nodeOf state) node).log.take frontier).length = frontier := by
          simp [Nat.min_eq_left frontierBound]
        have newWithinActivation :
            activation.newConfiguration.index <=
              activation.activationFrontier := by
          have governing :=
            (activationQuorums.history.valid
              activationIndex activation stored).2.2.2.2.2.2.2.1
          rw [
            (activationQuorums.history.valid
              activationIndex activation stored).2.2.2.2.2.2.1
          ] at governing
          exact (of_decide_eq_true (List.mem_filter.mp governing).2).2
        exact newWithinActivation.trans
          (by simpa [activationLength, frontierLength] using reversedLength)
      have maximal :=
        configuration_index_le_currentConfiguration
          { (nodeOf state) node with commitIndex := frontier }
          activation.newConfiguration activationKnownLeader
          (by simpa using activationWithin)
      have contradiction :
          activation.newConfiguration.index <= newConfiguration.index := by
        simpa [currentConfiguration, newConfiguration] using maximal
      omega
    · exact ordered
  have activationPrefixOrderAfter
      (create : replaceActivation)
      (lowerIndex : ActivationKey Node)
      (lower : ActivationRecord Node TxId)
      (lowerStored : newActivations lowerIndex = some lower)
      (higherIndex : ActivationKey Node)
      (higher : ActivationRecord Node TxId)
      (higherStored : newActivations higherIndex = some higher)
      (order :
        lower.newConfiguration.index <
          higher.newConfiguration.index) :
      lower.history.take lower.activationFrontier <+:
        higher.history.take higher.activationFrontier := by
    by_cases lowerNew : lowerIndex = newActivationKey
    · subst lowerIndex
      have lowerEq : activationRecord = lower := by
        simpa [newActivations, create] using lowerStored
      subst lower
      have higherNew :
          Not (higherIndex = newActivationKey) := by
        intro same
        subst higherIndex
        have higherEq : activationRecord = higher := by
          simpa [newActivations, create] using higherStored
        subst higher
        omega
      have oldHigher :
          activations higherIndex = some higher := by
        simpa [newActivations, create, Function.update, higherNew] using higherStored
      simpa [activationRecord]
        using newActivationPrefixInOld higherIndex higher oldHigher
          (by simpa [activationRecord] using order)
    · have oldLower :
          activations lowerIndex = some lower := by
        simpa [newActivations, create, Function.update, lowerNew] using lowerStored
      by_cases higherNew : higherIndex = newActivationKey
      · subst higherIndex
        have higherEq : activationRecord = higher := by
          simpa [newActivations, create] using higherStored
        subst higher
        simpa [activationRecord]
          using oldActivationPrefixInNew lowerIndex lower oldLower
            (by simpa [activationRecord] using order)
      · have oldHigher :
            activations higherIndex = some higher := by
          simpa [newActivations, create, Function.update, higherNew] using higherStored
        exact
          activationPrefixInHigherActivation
            ownership electionFacts activationQuorums.history
            activationCanonical activationElections
            oldLower oldHigher order
  have oldCoverageSharedPrefixInNew
      (create : replaceActivation)
      (candidate : Node)
      (witness :
        ConfigurationCoverageWitness state activations candidate)
      (before :
        (currentConfiguration ((nodeOf state) candidate)).index <
          newConfiguration.index) :
      witness.sharedPrefix <+:
        ((nodeOf state) node).log.take frontier := by
    rcases
        activationPrefixComparable
          witness.activationIndex witness.activation witness.stored with
      activationBefore | frontierBefore
    · exact
        witness.sharedPrefix_prefix_activationPrefix.trans activationBefore
    · have sharedBeforeNew :
          witness.sharedFrontier < newConfiguration.index := by
        by_contra outside
        have newWithinShared :
            newConfiguration.index <= witness.sharedFrontier :=
          Nat.le_of_not_gt outside
        have newKnownActivation :
            newConfiguration ∈
              allConfigurations witness.activation.history := by
          apply
            memOfPrefix
              (allConfigurations_mono_prefix
                (frontierBefore.trans
                  (List.take_prefix
                    witness.activation.activationFrontier
                    witness.activation.history)))
          exact
            allConfigurations_mem_take_of_index_le
              ((nodeOf state) node).log frontier frontierBound
              newConfigurationKnown newConfigurationIndexBound
        have newKnownActivationShared :
            newConfiguration ∈
              allConfigurations
                (witness.activation.history.take witness.sharedFrontier) :=
          allConfigurations_mem_take_of_index_le
            witness.activation.history witness.sharedFrontier
            (witness.sharedFrontier_le_activationFrontier.trans
              (activationQuorums.history.valid
                witness.activationIndex witness.activation
                  witness.stored).2.1)
            newKnownActivation newWithinShared
        have newKnownCandidate :
            newConfiguration ∈
              allConfigurations ((nodeOf state) candidate).log := by
          apply
            memOfPrefix
              (allConfigurations_mono_prefix
                (List.take_prefix
                  witness.sharedFrontier ((nodeOf state) candidate).log))
          rw [← show
            witness.activation.history.take witness.sharedFrontier =
                ((nodeOf state) candidate).log.take witness.sharedFrontier by
              simpa [
                ConfigurationCoverageWitness.sharedFrontier
              ] using witness.historyAgreement]
          exact newKnownActivationShared
        have maximal :=
          configuration_index_le_currentConfiguration
            ((nodeOf state) candidate) newConfiguration newKnownCandidate
            (newWithinShared.trans witness.sharedFrontier_le_commitIndex)
        omega
      have sharedWithinFrontier :
          witness.sharedFrontier <= frontier :=
        sharedBeforeNew.le.trans newConfigurationIndexBound
      have frontierLength :
          (((nodeOf state) node).log.take frontier).length = frontier := by
        simp [Nat.min_eq_left frontierBound]
      have agreed :=
        takeEqOfPrefix frontierBefore
          (count := witness.sharedFrontier)
          (by simpa [frontierLength] using sharedWithinFrontier)
      rw [ConfigurationCoverageWitness.sharedPrefix]
      have exactShared :
          witness.activation.history.take witness.sharedFrontier =
            ((nodeOf state) node).log.take witness.sharedFrontier := by
        simpa [List.take_take,
          Nat.min_eq_left witness.sharedFrontier_le_activationFrontier,
          Nat.min_eq_left sharedWithinFrontier]
          using agreed.symm
      rw [exactShared]
      have taken :=
        List.take_prefix witness.sharedFrontier
          (((nodeOf state) node).log.take frontier)
      simpa [List.take_take, Nat.min_eq_left sharedWithinFrontier] using taken
  have newPrefixInOldCoverageSharedPrefix
      (create : replaceActivation)
      (candidate : Node)
      (witness :
        ConfigurationCoverageWitness state activations candidate)
      (before :
        newConfiguration.index <
          (currentConfiguration ((nodeOf state) candidate)).index) :
      ((nodeOf state) node).log.take frontier <+:
        witness.sharedPrefix := by
    have newBeforeWitness :
        newConfiguration.index <
          witness.activation.newConfiguration.index :=
      before.trans_le
        (activationGoverningConfigurationIndexLeNew
          activationQuorums.history witness.stored
          witness.configurationCovered)
    have newPrefixInWitness :=
      newActivationPrefixInOld
        witness.activationIndex witness.activation witness.stored
        newBeforeWitness
    have frontierBeforeShared :
        frontier <= witness.sharedFrontier := by
      by_contra notBefore
      have sharedBeforeFrontier :
          witness.sharedFrontier < frontier := by
        omega
      have sharedWithinNewPrefix :
          witness.sharedFrontier <=
            (((nodeOf state) node).log.take frontier).length := by
        simp [Nat.min_eq_left frontierBound]
        exact sharedBeforeFrontier.le
      have agreed :=
        takeEqOfPrefix newPrefixInWitness sharedWithinNewPrefix
      have candidateKnownNewPrefix :
          currentConfiguration ((nodeOf state) candidate) ∈
            allConfigurations (((nodeOf state) node).log.take frontier) := by
        have candidateKnownShared :=
          witness.configuration_mem_activationHistoryTake
            activationQuorums.history
        have agreedShared :
            (((nodeOf state) node).log.take frontier).take
                witness.sharedFrontier =
              witness.activation.history.take witness.sharedFrontier := by
          simpa [ConfigurationCoverageWitness.sharedPrefix, List.take_take,
            Nat.min_eq_left witness.sharedFrontier_le_activationFrontier]
            using agreed
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix
                witness.sharedFrontier
                (((nodeOf state) node).log.take frontier)))
        rw [agreedShared]
        simpa [
               ConfigurationCoverageWitness.sharedPrefix]
          using candidateKnownShared
      have candidateKnownLeader :
          currentConfiguration ((nodeOf state) candidate) ∈
            allConfigurations ((nodeOf state) node).log :=
        memOfPrefix
          (allConfigurations_mono_prefix
            (List.take_prefix frontier ((nodeOf state) node).log))
          candidateKnownNewPrefix
      have maximal :=
        configuration_index_le_currentConfiguration
          { (nodeOf state) node with commitIndex := frontier }
          (currentConfiguration ((nodeOf state) candidate))
          candidateKnownLeader
          (by
            simpa using
              witness.configurationIndexBound.trans
                (Nat.le_of_lt sharedBeforeFrontier))
      have contradiction :
          (currentConfiguration ((nodeOf state) candidate)).index <=
            newConfiguration.index := by
        simpa [currentConfiguration, newConfiguration] using maximal
      omega
    rw [
      ConfigurationCoverageWitness.sharedPrefix,
      List.prefix_take_iff
    ]
    refine ⟨
      newPrefixInWitness.trans
        (List.take_prefix
          witness.activation.activationFrontier
          witness.activation.history),
      ?_
    ⟩
    have newPrefixLength :
        (((nodeOf state) node).log.take frontier).length = frontier := by
      simp [Nat.min_eq_left frontierBound]
    have sharedBound :
        witness.sharedFrontier <= witness.activation.history.length :=
      witness.sharedFrontier_le_activationFrontier.trans
        (activationQuorums.history.valid
          witness.activationIndex witness.activation witness.stored).2.1
    simpa [newPrefixLength, List.length_take, Nat.min_eq_left sharedBound]
      using frontierBeforeShared
  have oldCoverageCurrentConfigurationEqNew
      (candidate : Node)
      (witness :
        ConfigurationCoverageWitness state activations candidate)
      (sameIndex :
        (currentConfiguration ((nodeOf state) candidate)).index =
          newConfiguration.index) :
      currentConfiguration ((nodeOf state) candidate) = newConfiguration := by
    have newAtOrBeforeWitness :
        newConfiguration.index <=
          witness.activation.newConfiguration.index := by
      simpa [sameIndex]
        using activationGoverningConfigurationIndexLeNew
          activationQuorums.history witness.stored
          witness.configurationCovered
    have newKnownWitness :
        newConfiguration ∈
          allConfigurations witness.activation.history := by
      rcases lt_or_eq_of_le newAtOrBeforeWitness with strict | equal
      · have newPrefixInWitness :=
          newActivationPrefixInOld
            witness.activationIndex witness.activation witness.stored strict
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (newPrefixInWitness.trans
                (List.take_prefix
                  witness.activation.activationFrontier
                  witness.activation.history)))
        exact
          allConfigurations_mem_take_of_index_le
            ((nodeOf state) node).log frontier frontierBound
            newConfigurationKnown newConfigurationIndexBound
      · have configurationEq :=
          activationConfigurationEqNew
            witness.activationIndex witness.activation witness.stored
            equal.symm
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix
                witness.activation.activationFrontier
                witness.activation.history))
        simpa [configurationEq]
          using activationNewConfigurationKnown activationQuorums.history witness.stored
    have currentKnownWitness :
        currentConfiguration ((nodeOf state) candidate) ∈
          allConfigurations witness.activation.history := by
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            (List.take_prefix
              witness.activation.activationFrontier
              witness.activation.history))
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            witness.sharedPrefix_prefix_activationPrefix)
      exact
        ConfigurationCoverageWitness.configuration_mem_activationHistoryTake
          activationQuorums.history witness
    exact
      allConfigurations_index_unique
        (TxId := TxId) witness.activation.history
        currentKnownWitness newKnownWitness sameIndex
  have coveredConfigurationKnownInNewFrontier
      (candidate : Node)
      (witness :
        ConfigurationCoverageWitness state activations candidate)
      (before :
        (currentConfiguration ((nodeOf state) candidate)).index <
          newConfiguration.index) :
      currentConfiguration ((nodeOf state) candidate) ∈
        allConfigurations (((nodeOf state) node).log.take frontier) := by
    let configuration := currentConfiguration ((nodeOf state) candidate)
    have configurationKnownActivation
        : configuration ∈ allConfigurations witness.activation.history :=
      memOfPrefix
        (allConfigurations_mono_prefix
          (List.take_prefix
            witness.activation.activationFrontier
            witness.activation.history))
        (memOfPrefix
          (allConfigurations_mono_prefix witness.sharedPrefix_prefix_activationPrefix)
          (by
            simpa [configuration]
              using (ConfigurationCoverageWitness.configuration_mem_activationHistoryTake
                      (TxId := TxId)
                      (state := state) (activations := activations)
                      (node := candidate) activationQuorums.history witness)))
    have configurationWithinActivation :
        configuration.index <= witness.activation.activationFrontier := by
      simpa [configuration]
        using witness.configurationIndexBound.trans
          witness.sharedFrontier_le_activationFrontier
    have configurationKnownActivationTake :=
      allConfigurations_mem_take_of_index_le
        witness.activation.history configuration.index
        (configurationWithinActivation.trans
          (activationQuorums.history.valid
            witness.activationIndex witness.activation witness.stored).2.1)
        configurationKnownActivation le_rfl
    have configurationWithinFrontier :
        configuration.index <= frontier := by
      simpa [configuration] using (Nat.le_of_lt before).trans newConfigurationIndexBound
    rcases
        activationPrefixComparable
          witness.activationIndex witness.activation witness.stored with
      activationBefore | frontierBefore
    · have agreed :=
        takeEqOfPrefix activationBefore
          (count := configuration.index)
          (by
            have activationLength :
                (witness.activation.history.take
                  witness.activation.activationFrontier).length =
                    witness.activation.activationFrontier := by
              simp [Nat.min_eq_left
                (activationQuorums.history.valid
                  witness.activationIndex witness.activation
                    witness.stored).2.1]
            simpa [activationLength] using configurationWithinActivation)
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            (List.take_prefix
              configuration.index (((nodeOf state) node).log.take frontier)))
      simpa [List.take_take, Nat.min_eq_left configurationWithinFrontier]
        using (show
          configuration ∈
            allConfigurations
              (((nodeOf state) node).log.take configuration.index) by
          rw [← show
            witness.activation.history.take configuration.index =
                ((nodeOf state) node).log.take configuration.index by
              simpa [
                List.take_take,
                Nat.min_eq_left configurationWithinActivation,
                Nat.min_eq_left configurationWithinFrontier
              ] using agreed]
          exact configurationKnownActivationTake)
    · have agreed :=
        takeEqOfPrefix frontierBefore
          (count := configuration.index)
          (by
            have frontierLength :
                (((nodeOf state) node).log.take frontier).length = frontier := by
              simp [Nat.min_eq_left frontierBound]
            simpa [frontierLength] using configurationWithinFrontier)
      apply
        memOfPrefix
          (allConfigurations_mono_prefix
            (List.take_prefix
              configuration.index (((nodeOf state) node).log.take frontier)))
      simpa [List.take_take, Nat.min_eq_left configurationWithinFrontier]
        using (show
          configuration ∈
            allConfigurations
              (((nodeOf state) node).log.take configuration.index) by
          rw [← show
            witness.activation.history.take configuration.index =
                ((nodeOf state) node).log.take configuration.index by
              simpa [
                List.take_take,
                Nat.min_eq_left configurationWithinActivation,
                Nat.min_eq_left configurationWithinFrontier
              ] using agreed.symm]
          exact configurationKnownActivationTake)
  have newConfigurationKnownInCoverageShared
      (candidate : Node)
      (witness :
        ConfigurationCoverageWitness state activations candidate)
      (before :
        newConfiguration.index <
          (currentConfiguration ((nodeOf state) candidate)).index) :
      newConfiguration ∈ allConfigurations witness.sharedPrefix := by
    have newWithinShared :
        newConfiguration.index <= witness.sharedFrontier :=
      (Nat.le_of_lt before).trans witness.configurationIndexBound
    have newWithinActivation :
        newConfiguration.index <= witness.activation.activationFrontier :=
      newWithinShared.trans witness.sharedFrontier_le_activationFrontier
    have newKnownLeaderTake :=
      allConfigurations_mem_take_of_index_le
        ((nodeOf state) node).log newConfiguration.index
        (newConfigurationIndexBound.trans frontierBound)
        newConfigurationKnown le_rfl
    have newKnownActivationTake :
        newConfiguration ∈
          allConfigurations
            (witness.activation.history.take newConfiguration.index) := by
      rcases
          activationPrefixComparable
            witness.activationIndex witness.activation witness.stored with
        activationBefore | frontierBefore
      · have activationLength :
            (witness.activation.history.take
              witness.activation.activationFrontier).length =
                witness.activation.activationFrontier := by
          simp [Nat.min_eq_left
            (activationQuorums.history.valid
              witness.activationIndex witness.activation
                witness.stored).2.1]
        have agreed :=
          takeEqOfPrefix activationBefore
            (count := newConfiguration.index)
            (by simpa [activationLength] using newWithinActivation)
        rw [show
          witness.activation.history.take newConfiguration.index =
              ((nodeOf state) node).log.take newConfiguration.index by
            simpa [
              List.take_take,
              Nat.min_eq_left newWithinActivation,
              Nat.min_eq_left newConfigurationIndexBound
            ] using agreed]
        exact newKnownLeaderTake
      · have frontierLength :
            (((nodeOf state) node).log.take frontier).length = frontier := by
          simp [Nat.min_eq_left frontierBound]
        have agreed :=
          takeEqOfPrefix frontierBefore
            (count := newConfiguration.index)
            (by simpa [frontierLength] using newConfigurationIndexBound)
        rw [show
          witness.activation.history.take newConfiguration.index =
              ((nodeOf state) node).log.take newConfiguration.index by
            simpa [
              List.take_take,
              Nat.min_eq_left newWithinActivation,
              Nat.min_eq_left newConfigurationIndexBound
            ] using agreed.symm]
        exact newKnownLeaderTake
    apply
      memOfPrefix
        (allConfigurations_mono_prefix
          (List.take_prefix newConfiguration.index witness.sharedPrefix))
    simpa [
      ConfigurationCoverageWitness.sharedPrefix,
      List.take_take,
      Nat.min_eq_left newWithinShared
    ] using newKnownActivationTake
  have activationVoteHistoryAfter :
      ActivationVoteHistory
        votes voteVoterHistory elections newActivations := by
    intro activationIndex activation voter voteTerm candidate
        stored supporter voted different later
    by_cases create : replaceActivation
    · by_cases same : activationIndex = newActivationKey
      · subst activationIndex
        have activationEq : activationRecord = activation := by
          simpa [newActivations, create] using stored
        subst activation
        simpa [activationRecord, EarlierBadElection]
          using ackerVoteFacts node frontier leaderRole frontierValid.1
            frontierSignature voter voteTerm candidate supporter
            voted different (by simpa [activationRecord] using later)
      · exact
          activationVoteHistory
            activationIndex activation voter voteTerm candidate
            (by simpa [
              newActivations, create, Function.update, same
            ] using stored)
            supporter voted different later
    · exact
        activationVoteHistory
          activationIndex activation voter voteTerm candidate
          (by simpa [newActivations, create] using stored)
          supporter voted different later
  have supporterCurrentHistoryAfter :
      ActivationSupporterCurrentHistory
        (advanceCommitState state node)
        elections newActivations := by
    intro activationIndex activation stored supporter member
    by_cases create : replaceActivation
    · by_cases same : activationIndex = newActivationKey
      · subst activationIndex
        have activationEq : activationRecord = activation := by
          simpa [newActivations, create] using stored
        subst activation
        left
        simpa [activationRecord, logEq]
          using effectiveAckerContainsPotentialPrefix
            facts.currentTermsPositive facts.voteHistory
            ownership electionFacts ackerCurrentFacts ackerElectionFacts
            activationQuorums leaderRole frontierValid.1
            frontierSignature frontierPotential member
      · rcases
            configurationFacts.supporterCurrentHistory
              activationIndex activation
              (by simpa [
                newActivations, create, Function.update, same
              ] using stored)
              supporter member with
          retained | bad
        · exact Or.inl (by simpa [logEq] using retained)
        · exact Or.inr (by simpa [termEq] using bad)
    · rcases
          configurationFacts.supporterCurrentHistory
            activationIndex activation
            (by simpa [newActivations, create] using stored)
            supporter member with
        retained | bad
      · exact Or.inl (by simpa [logEq] using retained)
      · exact Or.inr (by simpa [termEq] using bad)
  have configurationFactsAfter :
      ElectionConfigurationFacts (joined := joinedNodes)
        (advanceCommitState state node)
        elections newActivations := by
    constructor
    · exact configurationFacts.ballotCommittedFrontierSignature
    · intro term record recorded positive
      rcases
          configurationFacts.ballotCurrentAuthorityActivation
            term record recorded positive with
        ⟨activationIndex, activation, stored, authority,
          activationBeforeTerm, authorityBound, historyAgreement⟩
      by_cases create : replaceActivation
      · have different :
            Not (activationIndex = newActivationKey) := by
          intro same
          have absent := activationAbsentAtNew create
          rw [← same, stored] at absent
          contradiction
        exact ⟨
          activationIndex,
          activation,
          by simpa [
              newActivations, create, Function.update, different
            ] using stored,
          authority,
          activationBeforeTerm,
          authorityBound,
          historyAgreement
        ⟩
      · exact ⟨
          activationIndex,
          activation,
          by simpa [newActivations, create] using stored,
          authority,
          activationBeforeTerm,
          authorityBound,
          historyAgreement
        ⟩
    · exact configurationFacts.ballotCurrentAuthorityActive
    · exact supporterCurrentHistoryAfter
    · intro term record candidate recorded role candidateTerm majority
      have different : Not (candidate = node) := by
        intro same
        subst candidate
        exact nodeNotCandidate role
      rcases
          configurationFacts.potentialShared
            term record candidate recorded
            (by simpa [roleEq] using role)
            (by simpa [termEq] using candidateTerm)
            ((effectiveElectionMajorityOtherEq candidate different).mp
              majority) with
        ⟨configuration, ballotActive, candidateActive⟩
      exact ⟨
        configuration,
        ballotActive,
        by simpa [
            activeConfigurationsOtherEq candidate different
          ] using candidateActive
      ⟩
    · intro left right leftRole rightRole sameTerm
        leftMajority rightMajority
      have leftNe : Not (left = node) := by
        intro same
        subst left
        exact nodeNotCandidate leftRole
      have rightNe : Not (right = node) := by
        intro same
        subst right
        exact nodeNotCandidate rightRole
      rcases
          configurationFacts.effectiveCandidatesShared
            left right
            (by simpa [roleEq] using leftRole)
            (by simpa [roleEq] using rightRole)
            (by simpa [termEq] using sameTerm)
            ((effectiveElectionMajorityOtherEq left leftNe).mp leftMajority)
            ((effectiveElectionMajorityOtherEq right rightNe).mp
              rightMajority) with
        ⟨configuration, leftActive, rightActive⟩
      exact ⟨
        configuration,
        by simpa [activeConfigurationsOtherEq left leftNe] using leftActive,
        by simpa [activeConfigurationsOtherEq right rightNe] using rightActive
      ⟩
    · intro candidate role entry member
      simpa [termEq]
        using configurationFacts.candidateEntriesBeforeTerm
          candidate
          (by simpa [roleEq] using role)
          entry
          (by simpa [logEq] using member)
  have configurationActivationsAfter :
      ConfigurationCoverageFacts
        (advanceCommitState state node) newActivations := by
    have activationRecordStoredAfter
        (create : replaceActivation) :
        newActivations newActivationKey = some activationRecord := by
      dsimp [newActivations]
      simp [create, Function.update]
    intro candidate positive
    by_cases create : replaceActivation
    · by_cases candidateEq : candidate = node
      · subst candidate
        refine ⟨⟨
                  newActivationKey,
                  activationRecord,
                  activationRecordStoredAfter create,
                  ?_,
                  ?_,
                  ?_,
                  ?_,
                  ?_,
                  ?_,
                  ?_,
                  ?_
                ⟩⟩
        · simpa [currentConfigurationNodeEq]
            using (activationRecordValid create.1).2.2.2.2.2.2.2.1
        · simp [activationRecord, termEq]
        · simpa [
            currentConfigurationNodeEq, activationRecord, commitNode
          ] using newConfigurationIndexBound
        · simp [ activationRecord,
            commitNode, logEq
          ]
        · intro higherIndex higher stored order
          simpa [currentConfigurationNodeEq, activationRecord, commitNode]
            using activationPrefixOrderAfter create
              newActivationKey activationRecord
              (activationRecordStoredAfter create)
              higherIndex higher stored
              (by simpa [currentConfigurationNodeEq, activationRecord] using order)
        · intro lowerIndex lower stored order
          simpa [currentConfigurationNodeEq, activationRecord, commitNode]
            using activationPrefixOrderAfter create
              lowerIndex lower stored
              newActivationKey activationRecord
              (activationRecordStoredAfter create)
              (by simpa [currentConfigurationNodeEq, activationRecord] using order)
        · intro sameIndex same stored sameConfiguration
          by_cases sameNew : sameIndex = newActivationKey
          · subst sameIndex
            have sameEq : activationRecord = same :=
              Option.some.inj
                ((activationRecordStoredAfter create).symm.trans stored)
            subst same
            simp [currentConfigurationNodeEq, activationRecord]
          · have oldStored :
                activations sameIndex = some same := by
              simpa [newActivations, create, Function.update, sameNew] using stored
            simpa [currentConfigurationNodeEq]
              using (activationConfigurationEqNew
                      sameIndex same oldStored
                      (by simpa [currentConfigurationNodeEq] using sameConfiguration))
        · intro candidateRole
          exact False.elim (nodeNotCandidate candidateRole)
      · have oldPositive :
            0 < (currentConfiguration ((nodeOf state) candidate)).index := by
          simpa [currentConfiguration, logEq, commitOther candidate candidateEq]
            using positive
        rcases configurationActivations candidate oldPositive with
          ⟨witness⟩
        have afterConfiguration :
            currentConfiguration
                ((nodeOf (advanceCommitState state node)) candidate) =
              currentConfiguration ((nodeOf state) candidate) := by
          simp [
            currentConfiguration, logEq,
            commitOther candidate candidateEq
          ]
        have witnessIndexNe :
            Not (witness.activationIndex = newActivationKey) := by
          intro same
          have absent := activationAbsentAtNew create
          rw [← same, witness.stored] at absent
          contradiction
        refine ⟨⟨
                  witness.activationIndex,
                  witness.activation,
                  activationPreservedOfNe _ _ witnessIndexNe witness.stored,
                  by simpa [afterConfiguration] using witness.configurationCovered,
                  by simpa [termEq] using witness.activationTermBound,
                  by simpa [
                      afterConfiguration, commitOther candidate candidateEq
                    ] using witness.configurationIndexBound,
                  by simpa [
                      afterConfiguration, commitOther candidate candidateEq, logEq
                    ] using witness.historyAgreement,
                  ?_,
                  ?_,
                  ?_,
                  ?_
                ⟩⟩
        · intro higherIndex higher stored order
          by_cases higherNew : higherIndex = newActivationKey
          · subst higherIndex
            have higherEq : activationRecord = higher := by
              exact Option.some.inj
                ((activationRecordStoredAfter create).symm.trans stored)
            subst higher
            simpa [afterConfiguration, activationRecord,
              ConfigurationCoverageWitness.sharedPrefix,
              ConfigurationCoverageWitness.sharedFrontier,
              commitOther candidate candidateEq]
              using oldCoverageSharedPrefixInNew
                create candidate witness
                (by simpa [afterConfiguration, activationRecord] using order)
          · exact
              (by
              simpa [afterConfiguration, commitOther candidate candidateEq,
                ConfigurationCoverageWitness.sharedPrefix,
                ConfigurationCoverageWitness.sharedFrontier]
                using witness.higherAuthority higherIndex higher (by simpa [
                    newActivations, create, Function.update, higherNew
                  ] using stored) (by simpa [afterConfiguration] using order))
        · intro lowerIndex lower stored order
          by_cases lowerNew : lowerIndex = newActivationKey
          · subst lowerIndex
            have lowerEq : activationRecord = lower := by
              exact Option.some.inj
                ((activationRecordStoredAfter create).symm.trans stored)
            subst lower
            simpa [afterConfiguration, activationRecord,
              ConfigurationCoverageWitness.sharedPrefix,
              ConfigurationCoverageWitness.sharedFrontier,
              commitOther candidate candidateEq]
              using newPrefixInOldCoverageSharedPrefix
                create candidate witness
                (by simpa [afterConfiguration, activationRecord] using order)
          · exact
              (by
              simpa [afterConfiguration, commitOther candidate candidateEq,
                ConfigurationCoverageWitness.sharedPrefix,
                ConfigurationCoverageWitness.sharedFrontier]
                using witness.lowerAuthority lowerIndex lower (by simpa [
                    newActivations, create, Function.update, lowerNew
                  ] using stored) (by simpa [afterConfiguration] using order))
        · intro sameIndex same stored sameConfiguration
          by_cases sameNew : sameIndex = newActivationKey
          · subst sameIndex
            have sameEq : activationRecord = same := by
              exact Option.some.inj
                ((activationRecordStoredAfter create).symm.trans stored)
            subst same
            simpa [afterConfiguration, activationRecord]
              using (oldCoverageCurrentConfigurationEqNew
                      candidate witness
                      (by
                        simpa [afterConfiguration, activationRecord]
                          using sameConfiguration.symm)).symm
          · exact
              (by
              simpa [afterConfiguration, commitOther candidate candidateEq,
                ConfigurationCoverageWitness.sharedPrefix,
                ConfigurationCoverageWitness.sharedFrontier]
                using witness.sameAuthority sameIndex same (by simpa [
                    newActivations, create, Function.update, sameNew
                  ] using stored) (by simpa [afterConfiguration] using sameConfiguration))
        · intro role
          rw [termEq]
          exact witness.candidateTermStrict (by simpa [roleEq] using role)
    · have unchangedOrRetained :
          oldConfiguration = newConfiguration \/ retainedActivation := by
        by_cases unchanged : oldConfiguration = newConfiguration
        · exact Or.inl unchanged
        · exact Or.inr (by
            by_contra missing
            exact create ⟨unchanged, missing⟩)
      rcases unchangedOrRetained with unchanged | retained
      · have currentConfigurationEq :
            forall candidate,
              currentConfiguration
                  ((nodeOf (advanceCommitState state node)) candidate) =
                currentConfiguration ((nodeOf state) candidate) := by
          intro candidate
          by_cases same : candidate = node
          · subst candidate
            simpa [oldConfiguration] using currentConfigurationNodeEq.trans unchanged.symm
          · simp [
              currentConfiguration, logEq,
              commitOther candidate same
            ]
        by_cases candidateEq : candidate = node
        · subst candidate
          have oldPositive :
              0 < (currentConfiguration ((nodeOf state) node)).index := by
            simpa [currentConfigurationEq node] using positive
          rcases configurationActivations node oldPositive with ⟨witness⟩
          let afterShared :=
            min frontier witness.activation.activationFrontier
          have sharedOrder :
              witness.sharedFrontier <= afterShared := by
            unfold ConfigurationCoverageWitness.sharedFrontier afterShared
            omega
          have oldSharedInAfterShared :
              witness.sharedPrefix <+:
                witness.activation.history.take afterShared := by
            rw [
              ConfigurationCoverageWitness.sharedPrefix,
              List.prefix_take_iff
            ]
            refine ⟨List.take_prefix _ _, ?_⟩
            have oldBound :
                witness.sharedFrontier <=
                  witness.activation.history.length :=
              witness.sharedFrontier_le_activationFrontier.trans
                (activationQuorums.history.valid
                  witness.activationIndex witness.activation
                    witness.stored).2.1
            have afterBound :
                afterShared <= witness.activation.history.length :=
              (Nat.min_le_right _ _).trans
                (activationQuorums.history.valid
                  witness.activationIndex witness.activation
                    witness.stored).2.1
            simpa [List.length_take, Nat.min_eq_left oldBound, Nat.min_eq_left afterBound]
              using sharedOrder
          have afterHistoryAgreement :
              witness.activation.history.take afterShared =
                ((nodeOf state) node).log.take afterShared := by
            have activationLength :
                (witness.activation.history.take
                  witness.activation.activationFrontier).length =
                    witness.activation.activationFrontier := by
              simp [Nat.min_eq_left
                (activationQuorums.history.valid
                  witness.activationIndex witness.activation
                    witness.stored).2.1]
            have afterWithin :
                afterShared <= witness.activation.activationFrontier := by
              exact Nat.min_le_right _ _
            have afterWithinFrontier : afterShared <= frontier :=
              Nat.min_le_left _ _
            rcases
                activationPrefixComparable
                  witness.activationIndex witness.activation
                    witness.stored with
              activationBefore | frontierBefore
            · have agreed :=
                takeEqOfPrefix activationBefore
                  (count := afterShared)
                  (by simpa [activationLength] using afterWithin)
              simpa [
                List.take_take,
                Nat.min_eq_left afterWithin,
                Nat.min_eq_left afterWithinFrontier
              ] using agreed
            · have frontierLength :
                  (((nodeOf state) node).log.take frontier).length = frontier := by
                simp [Nat.min_eq_left frontierBound]
              have agreed :=
                takeEqOfPrefix frontierBefore
                  (count := afterShared)
                  (by simpa [frontierLength] using afterWithinFrontier)
              simpa [
                List.take_take,
                Nat.min_eq_left afterWithin,
                Nat.min_eq_left afterWithinFrontier
              ] using agreed.symm
          refine ⟨⟨
                    witness.activationIndex,
                    witness.activation,
                    by simpa [newActivations, create] using witness.stored,
                    by
                      simpa [currentConfigurationEq node]
                        using witness.configurationCovered,
                    by simpa [termEq] using witness.activationTermBound,
                    by
                      simpa [currentConfigurationEq node, commitNode, afterShared]
                        using witness.configurationIndexBound.trans sharedOrder,
                    by simpa [
                        currentConfigurationEq node, commitNode, logEq, afterShared
                      ] using afterHistoryAgreement,
                    ?_,
                    ?_,
                    ?_,
                    ?_
                  ⟩⟩
          · intro higherIndex higher stored order
            have oldStored :
                activations higherIndex = some higher := by
              simpa [newActivations, create] using stored
            have frontierInHigher :=
              newActivationPrefixInOld higherIndex higher oldStored
                (by simpa [
                  currentConfigurationEq node, unchanged, oldConfiguration
                ] using order)
            have afterInFrontier :
                ((nodeOf state) node).log.take afterShared <+:
                  ((nodeOf state) node).log.take frontier := by
              rw [List.prefix_take_iff]
              refine ⟨List.take_prefix _ _, ?_⟩
              have afterBound : afterShared <= frontier :=
                Nat.min_le_left _ _
              have frontierLength :
                  (((nodeOf state) node).log.take frontier).length = frontier := by
                simp [Nat.min_eq_left frontierBound]
              simpa [
                List.length_take,
                Nat.min_eq_left
                  (afterBound.trans frontierBound),
                frontierLength
              ] using afterBound
            simpa [currentConfigurationEq node, commitNode, afterShared]
              using (by
                      rw [afterHistoryAgreement]
                      exact afterInFrontier.trans frontierInHigher)
          · intro lowerIndex lower stored order
            have ordered :=
              (witness.lowerAuthority lowerIndex lower
                (by simpa [newActivations, create] using stored)
                (by simpa [currentConfigurationEq node] using order)).trans
                oldSharedInAfterShared
            simpa [
              currentConfigurationEq node, commitNode, afterShared,
              ConfigurationCoverageWitness.sharedPrefix,
              ConfigurationCoverageWitness.sharedFrontier
            ] using ordered
          · intro sameIndex same stored sameConfiguration
            exact (witness.sameAuthority sameIndex same
                    (by simpa [newActivations, create] using stored)
                    (by
                      simpa [currentConfigurationEq node] using sameConfiguration)).trans
              (currentConfigurationEq node).symm
          · intro role
            exact False.elim (nodeNotCandidate role)
        · have oldPositive :
              0 < (currentConfiguration ((nodeOf state) candidate)).index := by
            simpa [currentConfigurationEq candidate] using positive
          rcases configurationActivations candidate oldPositive with
            ⟨witness⟩
          refine ⟨⟨
                    witness.activationIndex,
                    witness.activation,
                    by simpa [newActivations, create] using witness.stored,
                    by
                      simpa [currentConfigurationEq candidate]
                        using witness.configurationCovered,
                    by simpa [termEq] using witness.activationTermBound,
                    by simpa [
                        currentConfigurationEq candidate,
                        commitOther candidate candidateEq
                      ] using witness.configurationIndexBound,
                    by simpa [
                        currentConfigurationEq candidate,
                        commitOther candidate candidateEq, logEq
                      ] using witness.historyAgreement,
                    ?_,
                    ?_,
                    ?_,
                    ?_
                  ⟩⟩
          · intro higherIndex higher stored order
            simpa [currentConfigurationEq candidate, commitOther candidate candidateEq]
              using witness.higherAuthority higherIndex higher
                (by simpa [newActivations, create] using stored)
                (by simpa [currentConfigurationEq candidate] using order)
          · intro lowerIndex lower stored order
            simpa [currentConfigurationEq candidate, commitOther candidate candidateEq]
              using witness.lowerAuthority lowerIndex lower
                (by simpa [newActivations, create] using stored)
                (by simpa [currentConfigurationEq candidate] using order)
          · intro sameIndex same stored sameConfiguration
            simpa [currentConfigurationEq candidate, commitOther candidate candidateEq]
              using witness.sameAuthority sameIndex same
                (by simpa [newActivations, create] using stored)
                (by simpa [currentConfigurationEq candidate] using sameConfiguration)
          · intro role
            rw [termEq]
            exact witness.candidateTermStrict
              (by simpa [roleEq] using role)
      · rcases retained with
          ⟨activationIndex, activation, activationStored,
              configurationGoverning, selectedTermBound, historyAgreement⟩
        let shared := min frontier activation.activationFrontier
        have newWithinShared :
            newConfiguration.index <= shared := by
          have valid :=
            activationQuorums.history.valid
              activationIndex activation activationStored
          have governing := configurationGoverning
          rw [valid.2.2.2.2.2.2.1] at governing
          exact
            Nat.le_min.mpr
              ⟨newConfigurationIndexBound,
                (of_decide_eq_true
                  (List.mem_filter.mp governing).2).2⟩
        have leaderSharedInFrontier :
            ((nodeOf state) node).log.take shared <+:
              ((nodeOf state) node).log.take frontier := by
          rw [List.prefix_take_iff]
          refine ⟨List.take_prefix _ _, ?_⟩
          have sharedBefore : shared <= frontier := Nat.min_le_left _ _
          have sharedBound : shared <= ((nodeOf state) node).log.length :=
            sharedBefore.trans frontierBound
          have frontierLength :
              (((nodeOf state) node).log.take frontier).length = frontier := by
            simp [Nat.min_eq_left frontierBound]
          simpa [
            List.length_take, Nat.min_eq_left sharedBound,
            frontierLength
          ] using sharedBefore
        by_cases candidateEq : candidate = node
        · subst candidate
          refine ⟨⟨
                    activationIndex,
                    activation,
                    by simpa [newActivations, create] using activationStored,
                    by simpa [currentConfigurationNodeEq] using configurationGoverning,
                    by simpa [termEq] using selectedTermBound,
                    by simpa [
                        currentConfigurationNodeEq, commitNode, shared
                      ] using newWithinShared,
                    by simpa [
                        currentConfigurationNodeEq, commitNode, logEq, shared
                      ] using historyAgreement,
                    ?_,
                    ?_,
                    ?_,
                    ?_
                  ⟩⟩
          · intro higherIndex higher stored order
            have oldStored :
                activations higherIndex = some higher := by
              simpa [newActivations, create] using stored
            have frontierInHigher :=
              newActivationPrefixInOld higherIndex higher oldStored
                (by simpa [currentConfigurationNodeEq] using order)
            rw [commitNode, historyAgreement]
            exact leaderSharedInFrontier.trans frontierInHigher
          · intro lowerIndex lower stored order
            have oldStored :
                activations lowerIndex = some lower := by
              simpa [newActivations, create] using stored
            have lowerBeforeNew :
                lower.newConfiguration.index < newConfiguration.index := by
              simpa [currentConfigurationNodeEq] using order
            have lowerInFrontier :=
              oldActivationPrefixInNew lowerIndex lower oldStored
                lowerBeforeNew
            have lowerFrontierBeforeShared :
                lower.activationFrontier <= shared := by
              by_contra outside
              have newWithinLower :
                  newConfiguration.index <= lower.activationFrontier := by
                omega
              have lowerLength :
                  (lower.history.take lower.activationFrontier).length =
                    lower.activationFrontier := by
                simp [Nat.min_eq_left
                  (activationQuorums.history.valid
                    lowerIndex lower oldStored).2.1]
              have lowerWithinFrontier :
                  lower.activationFrontier <= frontier := by
                have frontierLength :
                    (((nodeOf state) node).log.take frontier).length = frontier := by
                  simp [Nat.min_eq_left frontierBound]
                simpa [lowerLength, frontierLength] using lowerInFrontier.length_le
              have exactTake :
                  (((nodeOf state) node).log.take frontier).take
                      lower.activationFrontier =
                    lower.history.take lower.activationFrontier := by
                simpa [lowerLength, List.take_take, Nat.min_eq_left lowerWithinFrontier]
                  using prefixEqTake lowerInFrontier
              have newKnownLower :
                  newConfiguration ∈ allConfigurations lower.history := by
                apply
                  memOfPrefix
                    (allConfigurations_mono_prefix
                      (List.take_prefix lower.activationFrontier lower.history))
                rw [← exactTake]
                exact
                  allConfigurations_mem_take_of_index_le
                    (((nodeOf state) node).log.take frontier)
                    lower.activationFrontier
                    (by
                      have frontierLength :
                          (((nodeOf state) node).log.take frontier).length =
                            frontier := by
                        simp [Nat.min_eq_left frontierBound]
                      simpa [frontierLength] using lowerWithinFrontier)
                    (allConfigurations_mem_take_of_index_le
                      ((nodeOf state) node).log frontier frontierBound
                      newConfigurationKnown newConfigurationIndexBound)
                    newWithinLower
              let lowerNode : NodeState Node TxId :=
                { (nodeOf state) node with
                  log := lower.history
                  commitIndex := lower.activationFrontier }
              have maximal :=
                configuration_index_le_currentConfiguration
                  lowerNode newConfiguration
                  (by simpa [lowerNode] using newKnownLower)
                  (by simpa [lowerNode] using newWithinLower)
              have contradiction :
                  newConfiguration.index <= lower.newConfiguration.index := by
                simpa [lowerNode, currentConfiguration,
                  (activationQuorums.history.valid
                    lowerIndex lower oldStored).2.2.2.1]
                  using maximal
              exact (Nat.not_le_of_gt lowerBeforeNew) contradiction
            have lowerInLeaderShared :
                lower.history.take lower.activationFrontier <+:
                  ((nodeOf state) node).log.take shared := by
              rw [List.prefix_take_iff]
              refine ⟨
                lowerInFrontier.trans (List.take_prefix frontier ((nodeOf state) node).log),
                ?_
              ⟩
              have lowerLength :
                  (lower.history.take lower.activationFrontier).length =
                    lower.activationFrontier := by
                simp [Nat.min_eq_left
                  (activationQuorums.history.valid
                    lowerIndex lower oldStored).2.1]
              have sharedBound :
                  shared <= ((nodeOf state) node).log.length :=
                (Nat.min_le_left _ _).trans frontierBound
              simpa [lowerLength, List.length_take, Nat.min_eq_left sharedBound]
                using lowerFrontierBeforeShared
            rw [commitNode, historyAgreement]
            exact lowerInLeaderShared
          · intro sameIndex same stored sameConfiguration
            have oldStored :
                activations sameIndex = some same := by
              simpa [newActivations, create] using stored
            simpa [currentConfigurationNodeEq]
              using activationConfigurationEqNew
                sameIndex same oldStored
                (by simpa [currentConfigurationNodeEq] using sameConfiguration)
          · intro role
            exact False.elim (nodeNotCandidate role)
        · have oldPositive :
              0 < (currentConfiguration ((nodeOf state) candidate)).index := by
            simpa [currentConfiguration, logEq, commitOther candidate candidateEq]
              using positive
          rcases configurationActivations candidate oldPositive with
            ⟨witness⟩
          have afterConfiguration :
              currentConfiguration
                  ((nodeOf (advanceCommitState state node)) candidate) =
                currentConfiguration ((nodeOf state) candidate) := by
            simp [
              currentConfiguration, logEq,
              commitOther candidate candidateEq
            ]
          refine ⟨⟨
                    witness.activationIndex,
                    witness.activation,
                    by simpa [newActivations, create] using witness.stored,
                    by simpa [afterConfiguration] using witness.configurationCovered,
                    by simpa [termEq] using witness.activationTermBound,
                    by simpa [
                        afterConfiguration, commitOther candidate candidateEq
                      ] using witness.configurationIndexBound,
                    by simpa [
                        afterConfiguration, commitOther candidate candidateEq, logEq
                      ] using witness.historyAgreement,
                    ?_,
                    ?_,
                    ?_,
                    ?_
                  ⟩⟩
          · intro higherIndex higher stored order
            simpa [afterConfiguration, commitOther candidate candidateEq]
              using witness.higherAuthority higherIndex higher
                (by simpa [newActivations, create] using stored)
                (by simpa [afterConfiguration] using order)
          · intro lowerIndex lower stored order
            simpa [afterConfiguration, commitOther candidate candidateEq]
              using witness.lowerAuthority lowerIndex lower
                (by simpa [newActivations, create] using stored)
                (by simpa [afterConfiguration] using order)
          · intro sameIndex same stored sameConfiguration
            exact (witness.sameAuthority sameIndex same
                    (by simpa [newActivations, create] using stored)
                    (by simpa [afterConfiguration] using sameConfiguration)).trans
              afterConfiguration.symm
          · intro role
            rw [termEq]
            exact witness.candidateTermStrict
              (by simpa [roleEq] using role)
  have evidenceValid :
      evidence.Valid (((nodeOf state) node).log.take frontier) := by
    have newConfigurationActive :
        newConfiguration ∈ activeConfigurations ((nodeOf state) node) := by
      simp [
        activeConfigurations, newConfigurationKnown,
        oldConfiguration, oldConfigurationBeforeNew
      ]
    have authorityMajority :
        hasConfigurationMajority
          (acknowledgingNodes (nodeOf state node) node frontier)
          newConfiguration :=
      majorityAtConfiguration
        frontierValid.2 newConfigurationActive newConfigurationIndexBound
    refine ⟨
      frontierBound,
      frontierValid.1,
      le_rfl,
      by simp [evidence],
      by simp [evidence],
      ?_,
      by simpa [evidence],
      fun _ => by simpa [evidence] using frontierSignature
    ⟩
    · simpa [evidence] using authorityMajority
  have knownNewOrOld :
      forall knownEvidence supportedPrefix,
        KnownCommitEvidence
            (advanceCommitState state node)
            appendHistory newNodeEvidence requestEvidence
            knownEvidence supportedPrefix ->
          (knownEvidence = evidence /\
            supportedPrefix =
              ((nodeOf (advanceCommitState state node)) node).committedLog) \/
            KnownCommitEvidence
              state appendHistory nodeEvidence requestEvidence
              knownEvidence supportedPrefix := by
    intro knownEvidence supportedPrefix known
    rcases known with nodeKnown | requestKnown
    · rcases nodeKnown with
        ⟨committed, positive, stored, prefixEq⟩
      by_cases same : committed = node
      · subst committed
        left
        exact ⟨Option.some.inj (by simpa [newNodeEvidence] using stored.symm), prefixEq⟩
      · right
        exact Or.inl
          ⟨committed,
            by simpa [commitOther committed same] using positive,
            by simpa [
              newNodeEvidence, Function.update, same
            ] using stored,
            by simpa [committedOther committed same] using prefixEq⟩
    · right
      rcases requestKnown with
        ⟨destination, request, member, positive, stored, prefixEq⟩
      exact Or.inr
        ⟨destination, request,
          by simpa [networkEq] using member,
          positive, stored, prefixEq⟩
  have evidenceAfter :
      CommitEvidenceFacts
        (advanceCommitState state node)
        appendHistory newNodeEvidence requestEvidence := by
    constructor
    · intro candidate positive
      by_cases same : candidate = node
      · subst candidate
        refine ⟨
          evidence,
          by simp [newNodeEvidence],
          by simpa [committedNode] using evidenceValid,
          by simp [evidence, commitNode],
          by simp [evidence, termEq]
        ⟩
      · have oldPositive :
            0 < ((nodeOf state) candidate).commitIndex := by
          simpa [commitOther candidate same] using positive
        rcases evidenceFacts.nodePositive candidate oldPositive with
          ⟨oldEvidence, stored, valid, lengthEq, termBound⟩
        exact ⟨
          oldEvidence,
          by simpa [
              newNodeEvidence, Function.update, same
            ] using stored,
          by simpa [committedOther candidate same] using valid,
          by simpa [commitOther candidate same] using lengthEq,
          by simpa [termEq] using termBound
        ⟩
    · intro destination request member positive
      exact
        evidenceFacts.requestPositive destination request
          (by simpa [advanceCommitState, Model.Local.advanceCommit, present] using member) positive
  have evidenceMemberEffective :
      forall member,
        member ∈ evidence.ackQuorum ->
          member ∈
            effectiveAckers (joined := joinedNodes) state responseHistory node frontier := by
    intro member memberIn
    simp only [
      evidence, acknowledgingNodes, effectiveAckers,
      Finset.mem_filter] at memberIn ⊢
    rcases memberIn with ⟨active, self | matched⟩
    · exact ⟨facts.joinedCarriers.activeNodes node active, Or.inl self⟩
    · exact ⟨facts.joinedCarriers.activeNodes node active, Or.inr (Or.inl matched)⟩
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts (joined := joinedNodes)
        (advanceCommitState state node)
        appendHistory newNodeEvidence requestEvidence elections := by
    constructor
    · intro knownEvidence supportedPrefix known
      rcases
          knownNewOrOld knownEvidence supportedPrefix known with
        new | old
      · rcases new with ⟨new, _⟩
        subst knownEvidence
        simpa [evidence]
          using facts.currentTermsPositive node (by rw [leaderRole]; decide)
      · exact
          prospectiveFacts.commitTermPositive
            knownEvidence supportedPrefix old
    · intro knownEvidence supportedPrefix known term record recorded newer
      rcases
          knownNewOrOld knownEvidence supportedPrefix known with
        new | old
      · rcases new with ⟨new, _⟩
        subst knownEvidence
        simpa [evidence]
          using potentialPrefixInElectionRecords
            facts.currentTermsPositive facts.voteHistory
            ownership electionFacts
            ackerElectionFacts activationQuorums
            leaderRole frontierValid.1
            frontierSignature
            frontierPotential term record recorded
            (by simpa [evidence] using newer)
      · exact
          prospectiveFacts.electionClosure
            knownEvidence supportedPrefix old
              term record recorded newer
    · intro knownEvidence supportedPrefix known member ackMember
      rcases
          knownNewOrOld knownEvidence supportedPrefix known with
        new | old
      · rcases new with ⟨new, _⟩
        subst knownEvidence
        simpa [evidence, logEq]
          using effectiveAckerContainsPotentialPrefix
            facts.currentTermsPositive facts.voteHistory
            ownership electionFacts
            ackerCurrentFacts ackerElectionFacts activationQuorums
            leaderRole frontierValid.1 frontierSignature frontierPotential
            (evidenceMemberEffective member ackMember)
      · simpa [logEq]
          using prospectiveFacts.currentMember
            knownEvidence supportedPrefix old member ackMember
    · intro knownEvidence supportedPrefix known destination request
        queued sameTerm
      rcases
          knownNewOrOld knownEvidence supportedPrefix known with
        new | old
      · rcases new with ⟨new, _⟩
        subst knownEvidence
        have oldQueued :
            (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination) := by
          simpa [networkEq] using queued
        have requestOwned :=
          (ownership.queuedAppendMetadata
            destination request oldQueued).2.1
        have nodeOwned := ownership.activeLeader node leaderRole
        have requestTerm :
            request.2.2.term = ((nodeOf state) node).currentTerm := by
          simpa [evidence] using sameTerm.symm
        rw [requestTerm] at requestOwned
        have sourceEq : request.1 = node :=
          Option.some.inj (requestOwned.symm.trans nodeOwned)
        left
        have sourceHistory :=
          ownership.queuedActiveSourceHistory
            destination request oldQueued
              (by simpa [sourceEq] using requestTerm)
              (by simpa [sourceEq] using leaderRole)
        simpa [evidence, sourceEq] using sourceHistory
      · exact
          prospectiveFacts.sameTermQueuedComparable
            knownEvidence supportedPrefix old
              destination request
              (by simpa [networkEq] using queued)
              sameTerm
    · intro knownEvidence supportedPrefix known candidate member
        role newer entriesBefore ackMember relaxed
      rcases
          knownNewOrOld knownEvidence supportedPrefix known with
        new | old
      · rcases new with ⟨new, _⟩
        subst knownEvidence
        have oldRole :
            ((nodeOf state) candidate).role = .candidate := by
          simpa [roleEq] using role
        have oldNewer :
            ((nodeOf state) node).currentTerm <
              ((nodeOf state) candidate).currentTerm := by
          simpa [evidence, termEq] using newer
        have oldEntriesBefore :
            forall entry,
              entry ∈ ((nodeOf state) candidate).log ->
                entry.term < ((nodeOf state) candidate).currentTerm := by
          intro entry member
          simpa [termEq] using entriesBefore entry (by simpa [logEq] using member)
        have oldRelaxed :
            member ∈ relaxedElectionVoters (joined := joinedNodes) state candidate := by
          simpa [relaxedElectionVoters, voteRequestKey, Model.Local.makeRequestVoteRequest, termEq, logEq,
            lastIndexEq, lastTermEq, effectiveElectionVotersEq,
            show joinedNodes = joinedNodes from rfl,
            voteLogUpToDate]
            using relaxed
        simpa [evidence, logEq]
          using effectiveAckerRelaxedCandidateContainsPotentialPrefix
            facts.currentTermsPositive
            (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts)
            facts.voteHistory
            ownership electionFacts
            facts.grantedVoteSnapshots voteCanonicalFacts
            ackerCurrentFacts ackerVoteFacts ackerElectionFacts
            activationQuorums
            leaderRole frontierValid.1 frontierSignature frontierPotential
            oldRole oldNewer oldEntriesBefore
            (evidenceMemberEffective member ackMember)
            oldRelaxed
      · have oldRole :
            ((nodeOf state) candidate).role = .candidate := by
          simpa [roleEq] using role
        have oldNewer :
            knownEvidence.commitTerm <
              ((nodeOf state) candidate).currentTerm := by
          simpa [termEq] using newer
        have oldEntriesBefore :
            forall entry,
              entry ∈ ((nodeOf state) candidate).log ->
                entry.term < ((nodeOf state) candidate).currentTerm := by
          intro entry member
          simpa [termEq] using entriesBefore entry (by simpa [logEq] using member)
        have oldRelaxed :
            member ∈ relaxedElectionVoters (joined := joinedNodes) state candidate := by
          simpa [relaxedElectionVoters, voteRequestKey, Model.Local.makeRequestVoteRequest, termEq, logEq,
            lastIndexEq, lastTermEq, effectiveElectionVotersEq,
            show joinedNodes = joinedNodes from rfl,
            voteLogUpToDate]
            using relaxed
        simpa [logEq]
          using prospectiveFacts.relaxedSupporterCarriesFrontier
            knownEvidence supportedPrefix old candidate member
            oldRole oldNewer oldEntriesBefore ackMember oldRelaxed
  have ownershipAfter :
      TermOwnershipFacts
        (advanceCommitState state node)
        votes appendHistory canonicalHistory owners := by
    apply
      termOwnershipFrame
        state (advanceCommitState state node)
        appendHistory appendHistory votes canonicalHistory owners ownership
    · intro leader role
      simpa [roleEq] using role
    · intro owner role
      simpa [roleEq] using role
    · exact termEq
    · exact logEq
    · intro destination request member index entry found
      exact
        ownership.queuedHistoryEntryAgreement
          destination request
          (by simpa [networkEq] using member)
          index entry found
    · intro destination request member
      exact
        ownership.queuedAppendMetadata destination request
          (by simpa [networkEq] using member)
    · intro destination request member sameTerm sourceRole
      simpa [logEq]
        using ownership.queuedActiveSourceHistory destination request
          (by simpa [networkEq] using member)
          (by simpa [termEq] using sameTerm)
          (by simpa [roleEq] using sourceRole)
  have electionFactsAfter :
      ElectionHistoryFacts
        (advanceCommitState state node)
        votes canonicalHistory owners elections := by
    apply
      electionHistoryFrame
        state (advanceCommitState state node)
        votes votes canonicalHistory canonicalHistory
        owners elections electionFacts
    · intros
      rfl
    · intro term
      exact prefixRefl (canonicalHistory term)
    · intro history canonical
      exact canonical
  have voteCanonicalAfter :
      GrantedVoteCanonicalSnapshots (joined := joinedNodes)
        (advanceCommitState state node)
        canonicalHistory voteCandidateHistory voteVoterHistory := by
    apply
      grantedVoteCanonicalFrame
        state (advanceCommitState state node)
        canonicalHistory canonicalHistory
        voteCandidateHistory voteVoterHistory voteCanonicalFacts
        (fun candidate _ => termEq candidate)
    · intro candidate active
      simpa [roleEq] using active
    · intro candidate voter active member
      rw [effectiveElectionVotersEq] at member
      exact member
    · intro history canonical
      exact canonical
  have grantedSnapshotsAfter :
      GrantedVoteSnapshots (joined := joinedNodes)
        (advanceCommitState state node)
        votes voteCandidateHistory voteVoterHistory := by
    intro candidate voter active member
    rw [termEq candidate, termEq voter]
    have oldActive := active
    rw [roleEq] at oldActive
    have oldMember :
        voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    simpa [voteLogUpToDate, logEq]
      using facts.grantedVoteSnapshots candidate voter oldActive oldMember
  have termsPositiveAfter :
      CurrentTermsPositive
        (advanceCommitState state node) := by
    intro candidate active
    rw [termEq]
    exact
      facts.currentTermsPositive candidate
        (by simpa [roleEq] using active)
  have entriesBoundedAfter :
      EntriesDoNotExceedCurrentTerm
        (advanceCommitState state node) := by
    intro candidate entry member
    rw [termEq]
    exact
      facts.entriesDoNotExceedCurrentTerm candidate entry
        (by simpa [logEq] using member)
  have voteFactsAfter :
      VoteHistoryFacts
        (advanceCommitState state node) votes := by
    constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [termEq, votedEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      exact facts.voteHistory.future voter term
        (by simpa [termEq] using future)
    · intro candidate voter active member
      rw [termEq]
      exact
        facts.voteHistory.counted candidate voter
          (by simpa [roleEq] using active)
          (by simpa [votesEq] using member)
  have candidatesAboveAfter :
      CandidatesAboveBootstrap
        (advanceCommitState state node) := by
    intro candidate role
    have different : Not (candidate = node) := by
      intro same
      subst candidate
      exact nodeNotCandidate role
    simpa [termEq] using candidatesAboveBootstrap candidate (by simpa [roleEq] using role)
  have recordBridgeAfter :
      forall source index,
        ((nodeOf (advanceCommitState state node)) source).role =
            .leader ->
        termAt
            ((nodeOf (advanceCommitState state node)) source).log index =
          ((nodeOf (advanceCommitState state node)) source).currentTerm ->
        isSignatureAt
            ((nodeOf (advanceCommitState state node)) source).log index =
          true ->
        hasPotentialMajorityAt (joined := joinedNodes)
            (advanceCommitState state node)
            appendHistory responseHistory source index ->
          forall term record,
            elections term = some record ->
            ((nodeOf (advanceCommitState state node)) source).currentTerm <
                term ->
              ((nodeOf (advanceCommitState state node)) source).log.take
                  index <+:
                record.promotionLog := by
    intro source index sourceRole current signature potential
        term record recorded newer
    exact
      potentialPrefixInElectionRecordsFromActivationHistory
        termsPositiveAfter entriesBoundedAfter voteFactsAfter
        ownershipAfter electionFactsAfter configurationFactsAfter
        activationHistoryAfter activationProgressAfter
        ackerActivationAfter temporalFacts.2.2
        activationCanonicalAfter activationElectionsAfter
        configurationActivationsAfter evidenceAfter prospectiveAfter
        sourceRole current signature potential
        term record recorded newer
  have candidateBridgeAfter :
      forall source index,
        ((nodeOf (advanceCommitState state node)) source).role =
            .leader ->
        termAt
            ((nodeOf (advanceCommitState state node)) source).log index =
          ((nodeOf (advanceCommitState state node)) source).currentTerm ->
        isSignatureAt
            ((nodeOf (advanceCommitState state node)) source).log index =
          true ->
        hasPotentialMajorityAt (joined := joinedNodes)
            (advanceCommitState state node)
            appendHistory responseHistory source index ->
          forall candidate,
            ((nodeOf (advanceCommitState state node)) candidate).role =
                .candidate ->
            hasPotentialElectionMajority (joined := joinedNodes)
              (advanceCommitState state node) candidate ->
            ((nodeOf (advanceCommitState state node)) source).currentTerm <
              ((nodeOf (advanceCommitState state node))
                candidate).currentTerm ->
              ((nodeOf (advanceCommitState state node)) source).log.take
                    index <+:
                  ((nodeOf (advanceCommitState state node)) candidate).log \/
                Exists fun configuration =>
                  configuration ∈
                      activeConfigurations
                        ((nodeOf (advanceCommitState state node)) source) /\
                    configuration.index <= index /\
                    configuration ∈
                      activeConfigurations
                        ((nodeOf (advanceCommitState state node))
                          candidate) := by
    intro source index sourceRole current signature potential
        candidate candidateRole candidateMajority newer
    have candidateNe : Not (candidate = node) := by
      intro same
      subst candidate
      exact nodeNotCandidate candidateRole
    by_cases sourceEq : source = node
    · subst source
      have oldCandidateRole :
          ((nodeOf state) candidate).role = .candidate := by
        simpa [roleEq] using candidateRole
      have oldCandidateMajority :
          hasPotentialElectionMajority (joined := joinedNodes) state candidate :=
        (potentialElectionMajorityOtherEq candidate candidateNe).mp
          candidateMajority
      have oldNewer :
          ((nodeOf state) node).currentTerm <
            ((nodeOf state) candidate).currentTerm := by
        simpa [termEq] using newer
      have frontierInCandidate
          : ((nodeOf state) node).log.take frontier <+: ((nodeOf state) candidate).log := by
        have frontierPotential :=
          effectiveMajorityImpliesPotential
            state appendHistory responseHistory node frontier
              frontierEffective
        rcases
            activationQuorums.candidateBridge
              node frontier leaderRole frontierValid.1 frontierSignature
              frontierPotential candidate oldCandidateRole
              oldCandidateMajority oldNewer with
          direct | shared
        · exact direct
        · rcases shared with
            ⟨configuration, sourceActive, governs, candidateActive⟩
          exact
            potentialPrefixInHigherCandidateOfSharedConfiguration
              facts.currentTermsPositive
              (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
                facts)
              (invariantFactsCandidatesAboveBootstrap facts)
              facts.entriesDoNotExceedCurrentTerm facts.voteHistory
              facts.grantedVoteSnapshots voteCanonicalFacts
              ownership electionFacts configurationFacts
              ackerCurrentFacts ackerVoteFacts ackerElectionFacts
              activationQuorums leaderRole frontierValid.1
              frontierSignature frontierPotential oldCandidateRole
              oldCandidateMajority sourceActive governs candidateActive
              oldNewer
      let candidateConfiguration :=
        currentConfiguration
          ((nodeOf (advanceCommitState state node)) candidate)
      have newKnownCandidate :
          newConfiguration ∈
            allConfigurations
              ((nodeOf (advanceCommitState state node)) candidate).log := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (by simpa [logEq] using frontierInCandidate))
        exact
          allConfigurations_mem_take_of_index_le
            ((nodeOf state) node).log frontier frontierBound
            newConfigurationKnown newConfigurationIndexBound
      by_cases candidateBefore :
          candidateConfiguration.index <= newConfiguration.index
      · by_cases governs : newConfiguration.index <= index
        · right
          exact ⟨
            newConfiguration,
            by
              rw [← currentConfigurationNodeEq]
              exact
                currentConfiguration_mem_activeConfigurations
                  ((nodeOf (advanceCommitState state node)) node),
            governs,
            by
              simpa [candidateConfiguration, activeConfigurations]
                using And.intro newKnownCandidate candidateBefore
          ⟩
        · left
          have indexBefore : index <= frontier := by
            omega
          have indexPrefix :
              ((nodeOf (advanceCommitState state node)) node).log.take
                  index <+:
                ((nodeOf state) node).log.take frontier := by
            simpa [logEq]
              using (show ((nodeOf state) node).log.take index <+:
                  ((nodeOf state) node).log.take frontier by
                rw [List.prefix_take_iff]
                exact
                  ⟨List.take_prefix _ _,
                    (List.length_take_le _ _).trans indexBefore⟩)
          exact indexPrefix.trans (by simpa [logEq] using frontierInCandidate)
      · have candidateAfter :
            newConfiguration.index < candidateConfiguration.index := by
          omega
        have candidatePositive : 0 < candidateConfiguration.index := by
          omega
        rcases
            configurationActivationsAfter candidate
              (by simpa [candidateConfiguration] using candidatePositive) with
          ⟨candidateWitness⟩
        let candidateActivation := candidateWitness.activation
        let candidateActivationIndex := candidateWitness.activationIndex
        have candidateStored :
            newActivations candidateActivationIndex =
              some candidateActivation :=
          candidateWitness.stored
        have candidateConfigurationKnown :
            candidateConfiguration ∈
              allConfigurations
                (candidateActivation.history.take
                  candidateActivation.activationFrontier) := by
          apply
            memOfPrefix
              (allConfigurations_mono_prefix
                candidateWitness.sharedPrefix_prefix_activationPrefix)
          simpa [candidateConfiguration]
            using ConfigurationCoverageWitness.configuration_mem_activationHistoryTake
              activationHistoryAfter candidateWitness
        have candidateActivationInCandidate :=
          activationPrefixInPotentialCandidatePromotionOfGoverningConfiguration
            committedSignatureAfter entriesBoundedAfter grantedSnapshotsAfter
            voteCanonicalAfter ownershipAfter electionFactsAfter
            activationHistoryAfter supporterCurrentHistoryAfter
            activationVoteHistoryAfter activationElectionsAfter
            candidateStored candidateRole candidateMajority
            (candidateWitness.candidateTermStrict candidateRole)
            candidateWitness.configurationCovered
            (currentConfiguration_mem_activeConfigurations
              ((nodeOf (advanceCommitState state node)) candidate))
        rcases Nat.lt_trichotomy
            ((nodeOf state) node).currentTerm
            candidateActivation.activationTerm with
          activationLater | sameTerm | activationEarlier
        · left
          have activationOwned :=
            activationCanonicalAfter.termOwner
              candidateActivationIndex candidateActivation
              candidateStored
          rcases
              electionFactsAfter.ownerRecorded
                candidateActivation.activationTerm
                candidateActivation.leader activationOwned with
            bootstrap | elected
          · have activationTerm :
                candidateActivation.activationTerm = BOOTSTRAP_TERM := by
              simpa using bootstrap.1
            have nodePositive :=
              facts.currentTermsPositive node (by rw [leaderRole]; decide)
            omega
          · rcases elected with
              ⟨activationElection, electionStored, electionLeader⟩
            have sourceInElection :=
              recordBridgeAfter node index sourceRole current signature
                potential candidateActivation.activationTerm
                activationElection electionStored
                (by simpa [termEq] using activationLater)
            have sourceInActivation :=
              electionPromotionPrefixInActivation
                electionFactsAfter activationHistoryAfter
                activationCanonicalAfter candidateStored electionStored
                sourceInElection
            exact
              sourceInActivation.trans
                (candidateActivationInCandidate.trans
                  (List.take_prefix _ _))
        · have activationInSource :
              candidateActivation.history.take
                  candidateActivation.activationFrontier <+:
                ((nodeOf state) node).log := by
            have activationCanonicalEq :=
              activationCanonicalAfter.activationFrontierCanonical
                candidateActivationIndex candidateActivation
                candidateStored
            rw [← sameTerm] at activationCanonicalEq
            rw [activationCanonicalEq]
            exact (List.take_prefix _ _).trans
              (by rw [ownership.activeLeaderHistory node leaderRole])
          have candidateKnownSource :
              candidateConfiguration ∈
                allConfigurations ((nodeOf state) node).log := by
            apply
              memOfPrefix
                (allConfigurations_mono_prefix activationInSource)
            exact candidateConfigurationKnown
          by_cases governs : candidateConfiguration.index <= index
          · right
            exact ⟨
              candidateConfiguration,
              by simpa [
                  activeConfigurations, currentConfigurationNodeEq,
                  candidateConfiguration, logEq
                ] using And.intro candidateKnownSource candidateAfter.le,
              governs,
              currentConfiguration_mem_activeConfigurations
                ((nodeOf (advanceCommitState state node)) candidate)
            ⟩
          · left
            have activationLength :
                (candidateActivation.history.take
                    candidateActivation.activationFrontier).length =
                  candidateActivation.activationFrontier := by
              simp [Nat.min_eq_left
                (activationHistoryAfter.valid
                  candidateActivationIndex candidateActivation
                  candidateStored).2.1]
            have exactTake := prefixEqTake activationInSource
            have exactFrontierTake :
                ((nodeOf state) node).log.take
                    candidateActivation.activationFrontier =
                  candidateActivation.history.take
                    candidateActivation.activationFrontier := by
              simpa [activationLength] using exactTake
            have indexBefore :
                index <= candidateActivation.activationFrontier := by
              have configurationWithin :
                  candidateConfiguration.index <=
                    candidateActivation.activationFrontier := by
                simpa [candidateConfiguration]
                  using candidateWitness.configurationIndexBound.trans
                    candidateWitness.sharedFrontier_le_activationFrontier
              omega
            have sourceInActivation :
                ((nodeOf (advanceCommitState state node)) node).log.take
                    index <+:
                  candidateActivation.history.take
                    candidateActivation.activationFrontier := by
              rw [List.prefix_iff_eq_take]
              calc
                ((nodeOf (advanceCommitState state node)) node).log.take index
                    = ((nodeOf state) node).log.take index := by
                  rw [logEq]
                _ = (candidateActivation.history.take
                      candidateActivation.activationFrontier).take
                      index := by
                  rw [← exactFrontierTake]
                  simp [List.take_take, Nat.min_eq_left indexBefore]
                _ = (candidateActivation.history.take
                      candidateActivation.activationFrontier).take
                      (((nodeOf (advanceCommitState state node)) node).log.take
                        index).length := by
                  rcases isSignatureAtTrue signature with
                    ⟨entry, found, _⟩
                  have lengthEq :
                      (((nodeOf (advanceCommitState state node)) node).log.take
                        index).length = index := by
                    simp [
                      List.length_take,
                      Nat.min_eq_left (entryAtSomeIndexBound found)
                    ]
                  rw [lengthEq]
            exact
              sourceInActivation.trans
                (candidateActivationInCandidate.trans (List.take_prefix _ _))
        · have nodeOwned := ownership.activeLeader node leaderRole
          rcases
              electionFacts.ownerRecorded
                ((nodeOf state) node).currentTerm node nodeOwned with
            bootstrap | elected
          · have nodeTerm : ((nodeOf state) node).currentTerm = BOOTSTRAP_TERM := by
              simpa using bootstrap.1
            have activationPositive :=
              activationHistoryAfter.termPositive
                candidateActivationIndex candidateActivation
                candidateStored
            omega
          · rcases elected with
              ⟨sourceElection, sourceElectionStored, sourceElectionLeader⟩
            have activationInSource :
              candidateActivation.history.take
                  candidateActivation.activationFrontier <+:
                ((nodeOf state) node).log := by
              exact (activationPrefixInLaterElection
                      activationElectionsAfter candidateStored
                      sourceElectionStored activationEarlier).trans
                ((electionFacts.promotionCanonical
                    ((nodeOf state) node).currentTerm sourceElection
                    sourceElectionStored).trans
                  (by rw [ownership.activeLeaderHistory node leaderRole]))
            have candidateKnownSource :
                candidateConfiguration ∈
                  allConfigurations ((nodeOf state) node).log := by
              apply
                memOfPrefix
                  (allConfigurations_mono_prefix activationInSource)
              exact candidateConfigurationKnown
            by_cases governs : candidateConfiguration.index <= index
            · right
              exact ⟨
                candidateConfiguration,
                by simpa [
                    activeConfigurations, currentConfigurationNodeEq,
                    candidateConfiguration, logEq
                  ] using And.intro candidateKnownSource candidateAfter.le,
                governs,
                currentConfiguration_mem_activeConfigurations
                  ((nodeOf (advanceCommitState state node)) candidate)
              ⟩
            · left
              have activationLength :
                  (candidateActivation.history.take
                      candidateActivation.activationFrontier).length =
                    candidateActivation.activationFrontier := by
                simp [Nat.min_eq_left
                  (activationHistoryAfter.valid
                    candidateActivationIndex candidateActivation
                    candidateStored).2.1]
              have exactTake := prefixEqTake activationInSource
              have exactFrontierTake :
                  ((nodeOf state) node).log.take
                      candidateActivation.activationFrontier =
                    candidateActivation.history.take
                      candidateActivation.activationFrontier := by
                simpa [activationLength] using exactTake
              have sourceInActivation :
                  ((nodeOf (advanceCommitState state node)) node).log.take
                      index <+:
                    candidateActivation.history.take
                      candidateActivation.activationFrontier := by
                rw [List.prefix_iff_eq_take]
                calc
                  ((nodeOf (advanceCommitState state node)) node).log.take index
                      = ((nodeOf state) node).log.take index := by
                    rw [logEq]
                  _ = (candidateActivation.history.take
                        candidateActivation.activationFrontier).take
                        index := by
                    rw [← exactFrontierTake]
                    have configurationWithin :
                        candidateConfiguration.index <=
                          candidateActivation.activationFrontier := by
                      simpa [candidateConfiguration]
                        using candidateWitness.configurationIndexBound.trans
                          candidateWitness.sharedFrontier_le_activationFrontier
                    simp [
                      List.take_take,
                      Nat.min_eq_left (by omega :
                        index <= candidateActivation.activationFrontier)
                    ]
                  _ = (candidateActivation.history.take
                        candidateActivation.activationFrontier).take
                        (((nodeOf (advanceCommitState state node)) node).log.take
                          index).length := by
                    rcases isSignatureAtTrue signature with
                      ⟨entry, found, _⟩
                    have lengthEq :
                        (((nodeOf (advanceCommitState state node)) node).log.take
                          index).length = index := by
                      simp [
                        List.length_take,
                        Nat.min_eq_left (entryAtSomeIndexBound found)
                      ]
                    rw [lengthEq]
              exact
                sourceInActivation.trans
                  (candidateActivationInCandidate.trans (List.take_prefix _ _))
    · have oldSourceRole :
          ((nodeOf state) source).role = .leader := by
        simpa [roleEq] using sourceRole
      have oldCurrent :
          termAt ((nodeOf state) source).log index =
            ((nodeOf state) source).currentTerm := by
        simpa [logEq, termEq] using current
      have oldSignature :
          isSignatureAt ((nodeOf state) source).log index = true := by
        simpa [logEq] using signature
      have oldPotential :=
        (potentialMajorityOtherEq source sourceEq index).mp potential
      have oldCandidateRole :
          ((nodeOf state) candidate).role = .candidate := by
        simpa [roleEq] using candidateRole
      have oldCandidateMajority :=
        (potentialElectionMajorityOtherEq candidate candidateNe).mp
          candidateMajority
      have oldNewer :
          ((nodeOf state) source).currentTerm <
            ((nodeOf state) candidate).currentTerm := by
        simpa [termEq] using newer
      rcases
          activationQuorums.candidateBridge
            source index oldSourceRole oldCurrent oldSignature oldPotential
            candidate oldCandidateRole oldCandidateMajority oldNewer with
        direct | shared
      · exact Or.inl (by simpa [logEq] using direct)
      · right
        rcases shared with
          ⟨configuration, sourceActive, governs, candidateActive⟩
        exact ⟨
          configuration,
          by simpa [
              activeConfigurationsOtherEq source sourceEq
            ] using sourceActive,
          governs,
          by simpa [
              activeConfigurationsOtherEq candidate candidateNe
            ] using candidateActive
        ⟩
  have knownEvidenceFrontierCanonicalAfter :
      forall knownEvidence supportedPrefix,
        KnownCommitEvidence
            (advanceCommitState state node)
            appendHistory newNodeEvidence requestEvidence
            knownEvidence supportedPrefix ->
          knownEvidence.history.take knownEvidence.commitFrontier =
            (canonicalHistory knownEvidence.commitTerm).take
              knownEvidence.commitFrontier := by
    intro knownEvidence supportedPrefix known
    have valid := knownCommitEvidenceValid evidenceAfter known
    have supportedPositive :=
      knownCommitEvidenceSupportedLengthPositive evidenceAfter known
    have frontierPositive : 0 < knownEvidence.commitFrontier := by
      exact supportedPositive.trans_le valid.2.2.1
    rcases
        entryAtSomeOfPositiveBound frontierPositive valid.1 with
      ⟨frontierEntry, historyFound⟩
    have frontierEntryTerm :
        frontierEntry.term = knownEvidence.commitTerm := by
      simpa [termAt, historyFound] using valid.2.1
    rcases
        configurationMajorityNonempty valid.2.2.2.2.2.1 with
      ⟨member, _authorityMember, ackMember⟩
    have memberCovered :=
      prospectiveAfter.currentMember
        knownEvidence supportedPrefix known member ackMember
    have prefixLength :
        (knownEvidence.history.take
            knownEvidence.commitFrontier).length =
          knownEvidence.commitFrontier := by
      simp [Nat.min_eq_left valid.1]
    have prefixFound :
        entryAt?
            (knownEvidence.history.take knownEvidence.commitFrontier)
            knownEvidence.commitFrontier =
          some frontierEntry := by
      rw [entryAtTake_of_le le_rfl]
      exact historyFound
    have memberFound :
        entryAt?
            ((nodeOf (advanceCommitState state node)) member).log
            knownEvidence.commitFrontier =
          some frontierEntry :=
      entryAt_of_prefix memberCovered prefixFound
    have memberAgreed :=
      (ownershipAfter.logEntryAgreement
        member knownEvidence.commitFrontier frontierEntry memberFound).2
    calc
      knownEvidence.history.take knownEvidence.commitFrontier
          = ((nodeOf (advanceCommitState state node)) member).log.take
              knownEvidence.commitFrontier := by
        have covered := prefixEqTake memberCovered
        rw [prefixLength] at covered
        exact covered.symm
      _ = (canonicalHistory frontierEntry.term).take knownEvidence.commitFrontier :=
        memberAgreed
      _ = (canonicalHistory knownEvidence.commitTerm).take
            knownEvidence.commitFrontier := by
        rw [frontierEntryTerm]
  have activationRecordStoredForCoverage
      (create : replaceActivation) :
      newActivations newActivationKey = some activationRecord := by
    dsimp [newActivations]
    simp [create, Function.update]
  have oldFrontierCoveragePrefixInNew
      {history : List (Entry Node TxId)}
      {coveredFrontier termBound : Nat}
      (witness :
        ConfigurationFrontierCoverageWitness
          activations history coveredFrontier termBound)
      (before :
        (currentConfigurationAt history coveredFrontier).index <
          newConfiguration.index) :
      witness.activation.history.take
          (min coveredFrontier witness.activation.activationFrontier) <+:
        ((nodeOf state) node).log.take frontier := by
    rcases
        activationPrefixComparable
          witness.activationIndex witness.activation witness.stored with
      activationBefore | frontierBefore
    · have sharedPrefix :
          witness.activation.history.take
              (min coveredFrontier
                witness.activation.activationFrontier) <+:
            witness.activation.history.take
              witness.activation.activationFrontier := by
        rw [List.prefix_take_iff]
        exact ⟨
          List.take_prefix _ _,
          (List.length_take_le _ _).trans (Nat.min_le_right _ _)
        ⟩
      exact sharedPrefix.trans activationBefore
    · have sharedBeforeNew :
          min coveredFrontier witness.activation.activationFrontier <
            newConfiguration.index := by
        by_contra outside
        have newWithinShared :
            newConfiguration.index <=
              min coveredFrontier witness.activation.activationFrontier :=
          Nat.le_of_not_gt outside
        have newKnownActivation :
            newConfiguration ∈ allConfigurations witness.activation.history := by
          apply
            memOfPrefix
              (allConfigurations_mono_prefix
                (frontierBefore.trans
                  (List.take_prefix
                    witness.activation.activationFrontier
                    witness.activation.history)))
          exact
            allConfigurations_mem_take_of_index_le
              ((nodeOf state) node).log frontier frontierBound
              newConfigurationKnown newConfigurationIndexBound
        have newKnownActivationShared :
            newConfiguration ∈
              allConfigurations
                (witness.activation.history.take
                  (min coveredFrontier
                    witness.activation.activationFrontier)) :=
          allConfigurations_mem_take_of_index_le
            witness.activation.history
            (min coveredFrontier witness.activation.activationFrontier)
            ((Nat.min_le_right _ _).trans
              (activationQuorums.history.valid
                witness.activationIndex witness.activation
                  witness.stored).2.1)
            newKnownActivation newWithinShared
        have newKnownHistoryTake :
            newConfiguration ∈
              allConfigurations
                (history.take
                  (min coveredFrontier
                    witness.activation.activationFrontier)) := by
          rw [← witness.historyAgreement]
          exact newKnownActivationShared
        have newKnownHistory :
            newConfiguration ∈ allConfigurations history :=
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix
                (min coveredFrontier
                  witness.activation.activationFrontier)
                history))
            newKnownHistoryTake
        have maximal :=
          configuration_index_le_currentConfiguration
            { ((nodeOf state) node) with
              log := history
              commitIndex := coveredFrontier }
            newConfiguration newKnownHistory
            (newWithinShared.trans (Nat.min_le_left _ _))
        have contradiction :
            newConfiguration.index <=
              (currentConfigurationAt history coveredFrontier).index := by
          simpa [currentConfiguration] using maximal
        omega
      have sharedWithinFrontier :
          min coveredFrontier witness.activation.activationFrontier <=
            frontier :=
        sharedBeforeNew.le.trans newConfigurationIndexBound
      have frontierLength :
          (((nodeOf state) node).log.take frontier).length = frontier := by
        simp [Nat.min_eq_left frontierBound]
      have agreed :=
        takeEqOfPrefix frontierBefore
          (count :=
            min coveredFrontier witness.activation.activationFrontier)
          (by simpa [frontierLength] using sharedWithinFrontier)
      rw [show
        witness.activation.history.take
              (min coveredFrontier
                witness.activation.activationFrontier) =
            ((nodeOf state) node).log.take
              (min coveredFrontier
                witness.activation.activationFrontier) by
          simpa [
            List.take_take,
            Nat.min_eq_left (Nat.min_le_right _ _),
            Nat.min_eq_left sharedWithinFrontier
          ] using agreed.symm]
      have taken :=
        List.take_prefix
          (min coveredFrontier witness.activation.activationFrontier)
          (((nodeOf state) node).log.take frontier)
      simpa [List.take_take, Nat.min_eq_left sharedWithinFrontier] using taken
  have newPrefixInOldFrontierCoverage
      {history : List (Entry Node TxId)}
      {coveredFrontier termBound : Nat}
      (witness :
        ConfigurationFrontierCoverageWitness
          activations history coveredFrontier termBound)
      (before :
        newConfiguration.index <
          (currentConfigurationAt history coveredFrontier).index) :
      ((nodeOf state) node).log.take frontier <+:
        witness.activation.history.take
          (min coveredFrontier witness.activation.activationFrontier) := by
    have newBeforeWitness :
        newConfiguration.index <
          witness.activation.newConfiguration.index :=
      before.trans_le
        (activationGoverningConfigurationIndexLeNew
          activationQuorums.history witness.stored
          witness.configurationCovered)
    have newPrefixInWitness :=
      newActivationPrefixInOld
        witness.activationIndex witness.activation witness.stored
          newBeforeWitness
    have frontierBeforeShared :
        frontier <=
          min coveredFrontier witness.activation.activationFrontier := by
      by_contra notBefore
      have sharedBeforeFrontier :
          min coveredFrontier witness.activation.activationFrontier <
            frontier := by
        omega
      have coveredKnownActivation :
          currentConfigurationAt history coveredFrontier ∈
            allConfigurations witness.activation.history := by
        have valid :=
          activationQuorums.history.valid
            witness.activationIndex witness.activation witness.stored
        have governing := witness.configurationCovered
        rw [valid.2.2.2.2.2.2.1] at governing
        exact (List.mem_filter.mp governing).1
      have coveredKnownShared :
          currentConfigurationAt history coveredFrontier ∈
            allConfigurations
              (witness.activation.history.take
                (min coveredFrontier
                  witness.activation.activationFrontier)) :=
        allConfigurations_mem_take_of_index_le
          witness.activation.history
          (min coveredFrontier witness.activation.activationFrontier)
          ((Nat.min_le_right _ _).trans
            (activationQuorums.history.valid
              witness.activationIndex witness.activation
                witness.stored).2.1)
          coveredKnownActivation witness.configurationIndexBound
      have sharedWithinNewPrefix :
          min coveredFrontier witness.activation.activationFrontier <=
            (((nodeOf state) node).log.take frontier).length := by
        rw [List.length_take, Nat.min_eq_left frontierBound]
        exact sharedBeforeFrontier.le
      have agreed :=
        takeEqOfPrefix newPrefixInWitness sharedWithinNewPrefix
      have coveredKnownNewPrefix :
          currentConfigurationAt history coveredFrontier ∈
            allConfigurations (((nodeOf state) node).log.take frontier) := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix
                (min coveredFrontier
                  witness.activation.activationFrontier)
                (((nodeOf state) node).log.take frontier)))
        rw [show
          (((nodeOf state) node).log.take frontier).take
                (min coveredFrontier
                  witness.activation.activationFrontier) =
              witness.activation.history.take
                (min coveredFrontier
                  witness.activation.activationFrontier) by
            simpa [
              List.take_take,
              Nat.min_eq_left (Nat.min_le_right _ _)
            ] using agreed]
        exact coveredKnownShared
      have coveredKnownLeader :
          currentConfigurationAt history coveredFrontier ∈
            allConfigurations ((nodeOf state) node).log :=
        memOfPrefix
          (allConfigurations_mono_prefix
            (List.take_prefix frontier ((nodeOf state) node).log))
          coveredKnownNewPrefix
      have maximal :=
        configuration_index_le_currentConfiguration
          { (nodeOf state) node with commitIndex := frontier }
          (currentConfigurationAt history coveredFrontier)
          coveredKnownLeader
          (by
            simpa using
              witness.configurationIndexBound.trans
                (Nat.le_of_lt sharedBeforeFrontier))
      have contradiction :
          (currentConfigurationAt history coveredFrontier).index <=
            newConfiguration.index := by
        simpa [currentConfiguration, newConfiguration] using maximal
      omega
    rw [List.prefix_take_iff]
    refine ⟨
      newPrefixInWitness.trans
        (List.take_prefix
          witness.activation.activationFrontier
          witness.activation.history),
      ?_
    ⟩
    have newPrefixLength :
        (((nodeOf state) node).log.take frontier).length = frontier := by
      simp [Nat.min_eq_left frontierBound]
    have sharedBound :
        min coveredFrontier witness.activation.activationFrontier <=
          witness.activation.history.length :=
      (Nat.min_le_right _ _).trans
        (activationQuorums.history.valid
          witness.activationIndex witness.activation witness.stored).2.1
    simpa [newPrefixLength, List.length_take, Nat.min_eq_left sharedBound]
      using frontierBeforeShared
  have migrateFrontierCoverage
      {history : List (Entry Node TxId)}
      {coveredFrontier termBound : Nat}
      (witness :
        ConfigurationFrontierCoverageWitness
          activations history coveredFrontier termBound)
      (newConfigurationEq :
        newConfiguration.index =
            (currentConfigurationAt history coveredFrontier).index ->
          newConfiguration =
            currentConfigurationAt history coveredFrontier) :
      ConfigurationFrontierCoverageWitness
        newActivations history coveredFrontier termBound := by
    by_cases create : replaceActivation
    · have witnessIndexNe :
          Not (witness.activationIndex = newActivationKey) := by
        intro same
        have absent := activationAbsentAtNew create
        rw [← same, witness.stored] at absent
        contradiction
      have witnessStoredAfter :
          newActivations witness.activationIndex =
            some witness.activation :=
        activationPreservedOfNe
          witness.activationIndex witness.activation witnessIndexNe
            witness.stored
      refine ⟨
        witness.activationIndex,
        witness.activation,
        witnessStoredAfter,
        witness.configurationCovered,
        witness.activationTermBound,
        witness.configurationIndexBound,
        witness.historyAgreement,
        ?_,
        ?_,
        ?_
      ⟩
      · intro higherIndex higher stored order
        by_cases higherNew : higherIndex = newActivationKey
        · subst higherIndex
          have higherEq : activationRecord = higher :=
            Option.some.inj
              ((activationRecordStoredForCoverage create).symm.trans stored)
          subst higher
          simpa [activationRecord]
            using oldFrontierCoveragePrefixInNew witness
              (by simpa [activationRecord] using order)
        · exact
            witness.higherAuthority higherIndex higher
              (by simpa [
                newActivations, create, Function.update, higherNew
              ] using stored)
              order
      · intro lowerIndex lower stored order
        by_cases lowerNew : lowerIndex = newActivationKey
        · subst lowerIndex
          have lowerEq : activationRecord = lower :=
            Option.some.inj
              ((activationRecordStoredForCoverage create).symm.trans stored)
          subst lower
          simpa [activationRecord]
            using newPrefixInOldFrontierCoverage witness
              (by simpa [activationRecord] using order)
        · exact
            witness.lowerAuthority lowerIndex lower
              (by simpa [
                newActivations, create, Function.update, lowerNew
              ] using stored)
              order
      · intro sameIndex same stored sameConfiguration
        by_cases sameNew : sameIndex = newActivationKey
        · subst sameIndex
          have sameEq : activationRecord = same :=
            Option.some.inj
              ((activationRecordStoredForCoverage create).symm.trans stored)
          subst same
          simpa [activationRecord]
            using newConfigurationEq (by simpa [activationRecord] using sameConfiguration)
        · exact
            witness.sameAuthority sameIndex same
              (by simpa [
                newActivations, create, Function.update, sameNew
              ] using stored)
              sameConfiguration
    · simpa [newActivations, create] using witness
  have newConfigurationEqOfCommittedConfiguration
      (candidate : Node)
      (configuration : Configuration Node)
      (configurationKnown :
        configuration ∈ allConfigurations ((nodeOf state) candidate).log)
      (configurationCommitted :
        configuration.index <= ((nodeOf state) candidate).commitIndex)
      (sameIndex : newConfiguration.index = configuration.index) :
      newConfiguration = configuration := by
    have newKnownAtFrontier :
        newConfiguration ∈
          allConfigurations (((nodeOf state) node).log.take frontier) :=
      allConfigurations_mem_take_of_index_le
        ((nodeOf state) node).log frontier frontierBound
        newConfigurationKnown newConfigurationIndexBound
    have configurationKnownCommitted :
        configuration ∈
          allConfigurations ((nodeOf state) candidate).committedLog := by
      simpa [NodeState.committedLog]
        using allConfigurations_mem_take_of_index_le
          ((nodeOf state) candidate).log
          ((nodeOf state) candidate).commitIndex
          (facts.commitIndicesBounded candidate)
          configurationKnown configurationCommitted
    rcases
        activationQuorums.committedBridge
          node frontier leaderRole frontierValid.1 frontierSignature
          frontierEffective candidate with
      newBefore | candidateBefore | shared
    · have newKnownCandidate :
          newConfiguration ∈
            allConfigurations ((nodeOf state) candidate).log := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (newBefore.trans
                (List.take_prefix
                  ((nodeOf state) candidate).commitIndex
                  ((nodeOf state) candidate).log)))
        exact newKnownAtFrontier
      exact
        allConfigurations_index_unique
          (TxId := TxId) ((nodeOf state) candidate).log
          newKnownCandidate configurationKnown sameIndex
    · have configurationKnownLeader :
          configuration ∈ allConfigurations ((nodeOf state) node).log := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (candidateBefore.trans
                (List.take_prefix frontier ((nodeOf state) node).log)))
        exact configurationKnownCommitted
      exact
        allConfigurations_index_unique
          (TxId := TxId) ((nodeOf state) node).log
          newConfigurationKnown configurationKnownLeader sameIndex
    · rcases shared with
        ⟨sharedConfiguration, sharedActive, sharedGoverns,
          sharedConfigurationEq⟩
      have sharedKnown :
          sharedConfiguration ∈ allConfigurations ((nodeOf state) node).log :=
        (List.mem_filter.mp sharedActive).1
      have sharedLeNew :
          sharedConfiguration.index <= newConfiguration.index := by
        simpa [newConfiguration, currentConfiguration]
          using configuration_index_le_currentConfiguration
            { (nodeOf state) node with commitIndex := frontier }
            sharedConfiguration sharedKnown sharedGoverns
      have configurationLeShared :
          configuration.index <= sharedConfiguration.index := by
        rw [sharedConfigurationEq]
        exact
          configuration_index_le_currentConfiguration
            ((nodeOf state) candidate) configuration configurationKnown
              configurationCommitted
      have sharedIndex :
          sharedConfiguration.index = newConfiguration.index := by
        omega
      have sharedEqNew :
          sharedConfiguration = newConfiguration :=
        allConfigurations_index_unique
          (TxId := TxId) ((nodeOf state) node).log
          sharedKnown newConfigurationKnown sharedIndex
      have candidateCurrentEq :
          currentConfiguration ((nodeOf state) candidate) =
            newConfiguration := by
        exact sharedConfigurationEq.symm.trans sharedEqNew
      have candidateCurrentKnown :=
        currentConfiguration_mem_allConfigurations
          ((nodeOf state) candidate)
      have configurationEq :
          configuration =
            currentConfiguration ((nodeOf state) candidate) := by
        apply
          allConfigurations_index_unique
            (TxId := TxId) ((nodeOf state) candidate).log
            configurationKnown candidateCurrentKnown
        simpa [candidateCurrentEq] using sameIndex.symm
      exact candidateCurrentEq.symm.trans configurationEq.symm
  have oldActivationConfigurationEqAtFrontier
      (coveredFrontier : Nat)
      (coveredWithin : coveredFrontier <= frontier)
      (activationIndex : ActivationKey Node)
      (activation : ActivationRecord Node TxId)
      (stored : activations activationIndex = some activation)
      (sameIndex :
        activation.newConfiguration.index =
          (currentConfigurationAt
            ((nodeOf state) node).log coveredFrontier).index) :
      activation.newConfiguration =
        currentConfigurationAt
          ((nodeOf state) node).log coveredFrontier := by
    have coveredKnown :
        currentConfigurationAt
            ((nodeOf state) node).log coveredFrontier ∈
          allConfigurations ((nodeOf state) node).log := by
      simpa [currentConfiguration]
        using currentConfiguration_mem_allConfigurations
          { (nodeOf state) node with commitIndex := coveredFrontier }
    have activationKnown :
        activation.newConfiguration ∈
          allConfigurations
            (activation.history.take activation.activationFrontier) :=
      activationNewConfigurationKnown activationQuorums.history stored
    rcases
        activationPrefixComparable activationIndex activation stored with
      activationBefore | frontierBefore
    · have activationKnownLeader :
          activation.newConfiguration ∈
            allConfigurations ((nodeOf state) node).log :=
        memOfPrefix
          (allConfigurations_mono_prefix
            (activationBefore.trans
              (List.take_prefix frontier ((nodeOf state) node).log)))
          activationKnown
      exact
        allConfigurations_index_unique
          (TxId := TxId) ((nodeOf state) node).log
          activationKnownLeader coveredKnown sameIndex
    · have coveredKnownActivation :
          currentConfigurationAt
              ((nodeOf state) node).log coveredFrontier ∈
            allConfigurations
              (activation.history.take activation.activationFrontier) := by
        have coveredIndexBound :
            (currentConfigurationAt
                ((nodeOf state) node).log coveredFrontier).index <= frontier := by
          have withinCovered :
              (currentConfigurationAt
                  ((nodeOf state) node).log coveredFrontier).index <=
                coveredFrontier := by
            simpa [currentConfiguration]
              using currentConfiguration_index_le_commitIndex
                { (nodeOf state) node with commitIndex := coveredFrontier }
          exact withinCovered.trans coveredWithin
        apply
          memOfPrefix
            (allConfigurations_mono_prefix frontierBefore)
        exact
          allConfigurations_mem_take_of_index_le
            ((nodeOf state) node).log frontier frontierBound
            coveredKnown coveredIndexBound
      exact
        allConfigurations_index_unique
          (TxId := TxId)
          (activation.history.take activation.activationFrontier)
          activationKnown coveredKnownActivation sameIndex
  have coveredPrefixInHigherActivationAfter
      (create : replaceActivation)
      (coveredFrontier : Nat)
      (coveredWithin : coveredFrontier <= frontier)
      (higherIndex : ActivationKey Node)
      (higher : ActivationRecord Node TxId)
      (higherStored : newActivations higherIndex = some higher)
      (order :
        (currentConfigurationAt
            ((nodeOf state) node).log coveredFrontier).index <
          higher.newConfiguration.index) :
      ((nodeOf state) node).log.take coveredFrontier <+:
        higher.history.take higher.activationFrontier := by
    by_cases higherNew : higherIndex = newActivationKey
    · subst higherIndex
      have higherEq : activationRecord = higher :=
        Option.some.inj
          ((activationRecordStoredForCoverage create).symm.trans
            higherStored)
      subst higher
      simpa [activationRecord]
        using (show
          ((nodeOf state) node).log.take coveredFrontier <+:
            ((nodeOf state) node).log.take frontier by
          rw [List.prefix_take_iff]
          exact
            ⟨List.take_prefix _ _,
              (List.length_take_le _ _).trans coveredWithin⟩)
    · have oldStored :
          activations higherIndex = some higher := by
        simpa [newActivations, create, Function.update, higherNew] using higherStored
      rcases
          activationPrefixComparable higherIndex higher oldStored with
        higherBefore | frontierBefore
      · have higherKnownLeader :
          higher.newConfiguration ∈
            allConfigurations ((nodeOf state) node).log := by
          apply
            memOfPrefix
              (allConfigurations_mono_prefix
                (higherBefore.trans
                  (List.take_prefix frontier ((nodeOf state) node).log)))
          exact
            activationNewConfigurationKnown
              activationQuorums.history oldStored
        have coveredBeforeHigher :
            coveredFrontier < higher.newConfiguration.index := by
          by_contra outside
          have maximal :=
            configuration_index_le_currentConfiguration
              { (nodeOf state) node with commitIndex := coveredFrontier }
              higher.newConfiguration higherKnownLeader
              (Nat.le_of_not_gt outside)
          have contradiction :
              higher.newConfiguration.index <=
                (currentConfigurationAt
                  ((nodeOf state) node).log coveredFrontier).index := by
            simpa [currentConfiguration] using maximal
          omega
        have coveredWithinHigher : coveredFrontier <= higher.activationFrontier :=
          coveredBeforeHigher.le.trans
            (by
              have valid :=
                activationQuorums.history.valid
                  higherIndex higher oldStored
              have governing := valid.2.2.2.2.2.2.2.1
              rw [valid.2.2.2.2.2.2.1] at governing
              exact (of_decide_eq_true (List.mem_filter.mp governing).2).2)
        have higherLength :
            (higher.history.take higher.activationFrontier).length =
              higher.activationFrontier := by
          simp [Nat.min_eq_left
            (activationQuorums.history.valid
              higherIndex higher oldStored).2.1]
        have agreed :=
          takeEqOfPrefix higherBefore
            (count := coveredFrontier)
            (by simpa [higherLength] using coveredWithinHigher)
        have exactTake :
          ((nodeOf state) node).log.take coveredFrontier =
            higher.history.take coveredFrontier := by
          simpa [List.take_take, Nat.min_eq_left coveredWithin,
            Nat.min_eq_left coveredWithinHigher]
            using agreed.symm
        rw [exactTake, List.prefix_take_iff]
        exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans coveredWithinHigher⟩
      · have coveredPrefix :
            ((nodeOf state) node).log.take coveredFrontier <+:
              ((nodeOf state) node).log.take frontier := by
          rw [List.prefix_take_iff]
          exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans coveredWithin⟩
        exact coveredPrefix.trans frontierBefore
  have lowerActivationPrefixInCoveredAfter
      (create : replaceActivation)
      (coveredFrontier : Nat)
      (coveredWithin : coveredFrontier <= frontier)
      (lowerIndex : ActivationKey Node)
      (lower : ActivationRecord Node TxId)
      (lowerStored : newActivations lowerIndex = some lower)
      (order :
        lower.newConfiguration.index <
          (currentConfigurationAt
            ((nodeOf state) node).log coveredFrontier).index) :
      lower.history.take lower.activationFrontier <+:
        ((nodeOf state) node).log.take coveredFrontier := by
    have lowerNew : Not (lowerIndex = newActivationKey) := by
      intro same
      subst lowerIndex
      have lowerEq : activationRecord = lower :=
        Option.some.inj
          ((activationRecordStoredForCoverage create).symm.trans lowerStored)
      subst lower
      have coveredLeNew :
          (currentConfigurationAt
              ((nodeOf state) node).log coveredFrontier).index <=
            newConfiguration.index := by
        simpa [newConfiguration, currentConfiguration]
          using configuration_index_le_currentConfiguration
            { (nodeOf state) node with commitIndex := frontier }
            (currentConfigurationAt ((nodeOf state) node).log coveredFrontier)
            (by
              simpa [currentConfiguration]
                using currentConfiguration_mem_allConfigurations
                  { (nodeOf state) node with commitIndex := coveredFrontier })
            (by
              simpa [currentConfiguration]
                using (currentConfiguration_index_le_commitIndex
                        { (nodeOf state) node with commitIndex := coveredFrontier }).trans
                  coveredWithin)
      simpa [activationRecord] using (not_lt_of_ge coveredLeNew order)
    have oldStored :
        activations lowerIndex = some lower := by
      simpa [newActivations, create, Function.update, lowerNew] using lowerStored
    rcases
        activationPrefixComparable lowerIndex lower oldStored with
      lowerBefore | frontierBefore
    · have lowerWithinCovered :
          lower.activationFrontier <= coveredFrontier := by
        by_contra outside
        have coveredWithinLower :
            coveredFrontier < lower.activationFrontier := by
          omega
        have lowerLength :
            (lower.history.take lower.activationFrontier).length =
              lower.activationFrontier := by
          simp [Nat.min_eq_left
            (activationQuorums.history.valid
              lowerIndex lower oldStored).2.1]
        have exactLower := prefixEqTake lowerBefore
        have leaderLength :
            (((nodeOf state) node).log.take frontier).length = frontier := by
          simp [Nat.min_eq_left frontierBound]
        have lowerWithinFrontier :
            lower.activationFrontier <= frontier := by
          have lengthBound := lowerBefore.length_le
          simpa [lowerLength, leaderLength] using lengthBound
        have lowerTakeEq :
            lower.history.take lower.activationFrontier =
              ((nodeOf state) node).log.take lower.activationFrontier := by
          simpa [lowerLength, List.take_take, Nat.min_eq_left lowerWithinFrontier]
            using exactLower.symm
        have coveredKnownLower :
            currentConfigurationAt
                ((nodeOf state) node).log coveredFrontier ∈
              allConfigurations lower.history := by
          apply
            memOfPrefix
              (allConfigurations_mono_prefix
                (List.take_prefix lower.activationFrontier lower.history))
          rw [lowerTakeEq]
          exact
            allConfigurations_mem_take_of_index_le
              ((nodeOf state) node).log lower.activationFrontier
              (by
                have lowerLength :
                    (lower.history.take lower.activationFrontier).length =
                      lower.activationFrontier := by
                  simp [Nat.min_eq_left
                    (activationQuorums.history.valid
                      lowerIndex lower oldStored).2.1]
                have leaderLength :
                    (((nodeOf state) node).log.take frontier).length =
                      frontier := by
                  simp [Nat.min_eq_left frontierBound]
                have lengthBound := lowerBefore.length_le
                have lowerWithinFrontier :
                    lower.activationFrontier <= frontier := by
                  simpa [lowerLength, leaderLength] using lengthBound
                exact lowerWithinFrontier.trans frontierBound)
              (by
                simpa [currentConfiguration] using
                  currentConfiguration_mem_allConfigurations
                    { (nodeOf state) node with
                      commitIndex := coveredFrontier })
              (by
                simpa [currentConfiguration] using
                  (currentConfiguration_index_le_commitIndex
                    { (nodeOf state) node with
                      commitIndex := coveredFrontier }).trans
                    coveredWithinLower.le)
        have maximal :=
          configuration_index_le_currentConfiguration
            {
              (nodeOf state) node with
                log := lower.history
                commitIndex := lower.activationFrontier
            }
            (currentConfigurationAt ((nodeOf state) node).log coveredFrontier)
            (by simpa using coveredKnownLower)
            (by
              have coveredIndexBound :
                  (currentConfigurationAt
                      ((nodeOf state) node).log coveredFrontier).index <=
                    coveredFrontier := by
                simpa [currentConfiguration]
                  using currentConfiguration_index_le_commitIndex
                    { (nodeOf state) node with commitIndex := coveredFrontier }
              simpa using
                coveredIndexBound.trans coveredWithinLower.le)
        have contradiction :
            (currentConfigurationAt
                ((nodeOf state) node).log coveredFrontier).index <=
              lower.newConfiguration.index := by
          simpa [currentConfiguration,
            (activationQuorums.history.valid
              lowerIndex lower oldStored).2.2.2.1]
            using maximal
        omega
      rw [List.prefix_take_iff]
      exact ⟨
        lowerBefore.trans (List.take_prefix frontier ((nodeOf state) node).log),
        by
          have lowerLength :
              (lower.history.take lower.activationFrontier).length =
                lower.activationFrontier := by
            simp [Nat.min_eq_left
              (activationQuorums.history.valid
                lowerIndex lower oldStored).2.1]
          simpa [lowerLength] using lowerWithinCovered
      ⟩
    · have coveredKnownLower :
          currentConfigurationAt
              ((nodeOf state) node).log coveredFrontier ∈
            allConfigurations lower.history := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (frontierBefore.trans
                (List.take_prefix lower.activationFrontier lower.history)))
        exact
          allConfigurations_mem_take_of_index_le
            ((nodeOf state) node).log frontier frontierBound
            (by
              simpa [currentConfiguration] using
                currentConfiguration_mem_allConfigurations
                  { (nodeOf state) node with
                    commitIndex := coveredFrontier })
            (by
              simpa [currentConfiguration] using
                (currentConfiguration_index_le_commitIndex
                  { (nodeOf state) node with
                    commitIndex := coveredFrontier }).trans coveredWithin)
      have maximal :=
        configuration_index_le_currentConfiguration
          {
            (nodeOf state) node with
              log := lower.history
              commitIndex := lower.activationFrontier
          }
          (currentConfigurationAt ((nodeOf state) node).log coveredFrontier)
          (by simpa using coveredKnownLower)
          (by
            have frontierLength :
                (((nodeOf state) node).log.take frontier).length = frontier := by
              simp [Nat.min_eq_left frontierBound]
            have lowerLength :
                (lower.history.take lower.activationFrontier).length =
                  lower.activationFrontier := by
              simp [Nat.min_eq_left
                (activationQuorums.history.valid
                  lowerIndex lower oldStored).2.1]
            have lengthBound := frontierBefore.length_le
            have frontierLeLower :
                frontier <= lower.activationFrontier := by
              simpa [frontierLength, lowerLength] using lengthBound
            have coveredIndexBound :
                (currentConfigurationAt
                    ((nodeOf state) node).log coveredFrontier).index <=
                  coveredFrontier := by
              simpa [currentConfiguration]
                using currentConfiguration_index_le_commitIndex
                  { (nodeOf state) node with commitIndex := coveredFrontier }
            exact coveredIndexBound.trans (coveredWithin.trans frontierLeLower))
      have contradiction :
          (currentConfigurationAt
              ((nodeOf state) node).log coveredFrontier).index <=
            lower.newConfiguration.index := by
        simpa [currentConfiguration,
          (activationQuorums.history.valid
            lowerIndex lower oldStored).2.2.2.1]
          using maximal
      omega
  have coveredPrefixInOldHigherActivation
      (coveredFrontier : Nat)
      (coveredWithin : coveredFrontier <= frontier)
      (higherIndex : ActivationKey Node)
      (higher : ActivationRecord Node TxId)
      (higherStored : activations higherIndex = some higher)
      (order :
        (currentConfigurationAt
            ((nodeOf state) node).log coveredFrontier).index <
          higher.newConfiguration.index) :
      ((nodeOf state) node).log.take coveredFrontier <+:
        higher.history.take higher.activationFrontier := by
    rcases
        activationPrefixComparable higherIndex higher higherStored with
      higherBefore | frontierBefore
    · have higherKnownLeader :
          higher.newConfiguration ∈
            allConfigurations ((nodeOf state) node).log := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (higherBefore.trans
                (List.take_prefix frontier ((nodeOf state) node).log)))
        exact
          activationNewConfigurationKnown
            activationQuorums.history higherStored
      have coveredBeforeHigher :
          coveredFrontier < higher.newConfiguration.index := by
        by_contra outside
        have maximal :=
          configuration_index_le_currentConfiguration
            { (nodeOf state) node with commitIndex := coveredFrontier }
            higher.newConfiguration higherKnownLeader
            (Nat.le_of_not_gt outside)
        have contradiction :
            higher.newConfiguration.index <=
              (currentConfigurationAt
                ((nodeOf state) node).log coveredFrontier).index := by
          simpa [currentConfiguration] using maximal
        omega
      have coveredWithinHigher : coveredFrontier <= higher.activationFrontier :=
        coveredBeforeHigher.le.trans
          (by
            have valid :=
              activationQuorums.history.valid
                higherIndex higher higherStored
            have governing := valid.2.2.2.2.2.2.2.1
            rw [valid.2.2.2.2.2.2.1] at governing
            exact (of_decide_eq_true (List.mem_filter.mp governing).2).2)
      have higherLength :
          (higher.history.take higher.activationFrontier).length =
            higher.activationFrontier := by
        simp [Nat.min_eq_left
          (activationQuorums.history.valid
            higherIndex higher higherStored).2.1]
      have agreed :=
        takeEqOfPrefix higherBefore
          (count := coveredFrontier)
          (by simpa [higherLength] using coveredWithinHigher)
      have exactTake :
          ((nodeOf state) node).log.take coveredFrontier =
            higher.history.take coveredFrontier := by
        simpa [List.take_take, Nat.min_eq_left coveredWithin,
          Nat.min_eq_left coveredWithinHigher]
          using agreed.symm
      rw [exactTake, List.prefix_take_iff]
      exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans coveredWithinHigher⟩
    · have coveredPrefix :
          ((nodeOf state) node).log.take coveredFrontier <+:
            ((nodeOf state) node).log.take frontier := by
        rw [List.prefix_take_iff]
        exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans coveredWithin⟩
      exact coveredPrefix.trans frontierBefore
  have activationQuorumsAfter :
      ActivationQuorumFacts (joined := joinedNodes)
        (advanceCommitState state node)
        appendHistory responseHistory elections newActivations := by
    constructor
    · exact activationHistoryAfter
    · intro source index role current signature potential
        term record recorded newer
      exact Or.inl
        (recordBridgeAfter
          source index role current signature potential
          term record recorded newer)
    · exact candidateBridgeAfter
    · intro source index role current signature majority committed
      by_cases zero :
          ((nodeOf (advanceCommitState state node)) committed).commitIndex = 0
      · exact Or.inr (Or.inl (by
          simp [NodeState.committedLog, zero]))
      · have positive :
            0 <
              ((nodeOf (advanceCommitState state node)) committed).commitIndex :=
          Nat.pos_of_ne_zero zero
        rcases evidenceAfter.nodePositive committed positive with
          ⟨committedEvidence, stored, valid, _lengthEq, _termBound⟩
        have known :
            KnownCommitEvidence
              (advanceCommitState state node)
              appendHistory newNodeEvidence requestEvidence
              committedEvidence
              ((nodeOf (advanceCommitState state node)) committed).committedLog :=
          Or.inl ⟨committed, positive, stored, rfl⟩
        by_cases termOrder :
            committedEvidence.commitTerm <=
              ((nodeOf (advanceCommitState state node)) source).currentTerm
        · rcases
              configurationMajorityNonempty valid.2.2.2.2.2.1 with
            ⟨member, _authorityMember, ackMember⟩
          have committedInSource :
              ((nodeOf (advanceCommitState state node)) committed).committedLog <+:
                ((nodeOf (advanceCommitState state node)) source).log :=
            (validEvidenceSupportedPrefixFrontier valid).trans
              (knownCommitEvidenceActiveLeaderContainsFrontier
                ownershipAfter electionFactsAfter evidenceAfter
                prospectiveAfter known role termOrder ackMember)
          rcases
              prefixesComparable
                (List.take_prefix index
                  ((nodeOf (advanceCommitState state node)) source).log)
                committedInSource with
            direct | direct
          · exact Or.inl direct
          · exact Or.inr (Or.inl direct)
        · have sourceBefore :
              ((nodeOf (advanceCommitState state node)) source).currentTerm <
                committedEvidence.commitTerm := by
            omega
          have canonicalEq :=
            knownEvidenceFrontierCanonicalAfter
              committedEvidence
              ((nodeOf (advanceCommitState state node)) committed).committedLog
              known
          have frontierPositive : 0 < committedEvidence.commitFrontier := by
            have supportedPositive :=
              knownCommitEvidenceSupportedLengthPositive evidenceAfter known
            exact supportedPositive.trans_le valid.2.2.1
          rcases
              entryAtSomeOfPositiveBound frontierPositive valid.1 with
            ⟨frontierEntry, historyFound⟩
          have frontierEntryTerm :
              frontierEntry.term = committedEvidence.commitTerm := by
            simpa [termAt, historyFound] using valid.2.1
          have historyTakeFound :
              entryAt?
                  (committedEvidence.history.take
                    committedEvidence.commitFrontier)
                  committedEvidence.commitFrontier =
                some frontierEntry := by
            rw [entryAtTake_of_le le_rfl]
            exact historyFound
          have canonicalTakeFound :
              entryAt?
                  ((canonicalHistory committedEvidence.commitTerm).take
                    committedEvidence.commitFrontier)
                  committedEvidence.commitFrontier =
                some frontierEntry := by
            rw [← canonicalEq]
            exact historyTakeFound
          have canonicalFound :
              entryAt?
                  (canonicalHistory committedEvidence.commitTerm)
                  committedEvidence.commitFrontier =
                some frontierEntry := by
            rw [← entryAtTake_of_le
              (log := canonicalHistory committedEvidence.commitTerm)
              le_rfl]
            exact canonicalTakeFound
          rcases
              ownershipAfter.canonicalEntryOwner
                committedEvidence.commitTerm
                committedEvidence.commitFrontier
                frontierEntry canonicalFound with
            ⟨owner, owned⟩
          rw [frontierEntryTerm] at owned
          rcases
              electionFactsAfter.ownerRecorded
                committedEvidence.commitTerm owner owned with
            bootstrap | elected
          · have sourcePositive :=
              termsPositiveAfter source (by rw [role]; decide)
            rw [bootstrap.1] at sourceBefore
            omega
          · rcases elected with
              ⟨record, recordStored, _recordLeader⟩
            have sourceInCanonical :
                ((nodeOf (advanceCommitState state node)) source).log.take index <+:
                  canonicalHistory committedEvidence.commitTerm :=
              (recordBridgeAfter
                source index role current signature
                (effectiveMajorityImpliesPotential
                  (advanceCommitState state node)
                  appendHistory responseHistory source index majority)
                committedEvidence.commitTerm record recordStored
                sourceBefore).trans
                (electionFactsAfter.promotionCanonical
                  committedEvidence.commitTerm record recordStored)
            have committedInCanonical :
                ((nodeOf (advanceCommitState state node)) committed).committedLog <+:
                  canonicalHistory committedEvidence.commitTerm :=
              (validEvidenceSupportedPrefixFrontier valid).trans
                (by
                  rw [canonicalEq]
                  exact List.take_prefix _ _)
            rcases
                prefixesComparable
                  sourceInCanonical committedInCanonical with
              direct | direct
            · exact Or.inl direct
            · exact Or.inr (Or.inl direct)
    · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
        right rightIndex rightRole rightCurrent rightSignature rightMajority
      rcases Nat.lt_trichotomy
          ((nodeOf (advanceCommitState state node)) left).currentTerm
          ((nodeOf (advanceCommitState state node)) right).currentTerm with
        leftBefore | sameTerm | rightBefore
      · have rightOwned := ownershipAfter.activeLeader right rightRole
        rcases
            electionFactsAfter.ownerRecorded
              ((nodeOf (advanceCommitState state node)) right).currentTerm
              right rightOwned with
          bootstrap | elected
        · have leftPositive :=
            termsPositiveAfter left (by rw [leftRole]; decide)
          rw [bootstrap.1] at leftBefore
          omega
        · rcases elected with
            ⟨record, recordStored, _recordLeader⟩
          have leftInRight :
              ((nodeOf (advanceCommitState state node)) left).log.take leftIndex <+:
                ((nodeOf (advanceCommitState state node)) right).log :=
            (recordBridgeAfter
              left leftIndex leftRole leftCurrent leftSignature
              (effectiveMajorityImpliesPotential
                (advanceCommitState state node)
                appendHistory responseHistory left leftIndex leftMajority)
              ((nodeOf (advanceCommitState state node)) right).currentTerm
              record recordStored leftBefore).trans
              ((electionFactsAfter.promotionCanonical
                ((nodeOf (advanceCommitState state node)) right).currentTerm
                record recordStored).trans
                (by
                  rw [ownershipAfter.activeLeaderHistory right rightRole]))
          rcases
              prefixesComparable
                leftInRight
                (List.take_prefix rightIndex
                  ((nodeOf (advanceCommitState state node)) right).log) with
            direct | direct
          · exact Or.inl direct
          · exact Or.inr (Or.inl direct)
      · have leftOwned := ownershipAfter.activeLeader left leftRole
        have rightOwned := ownershipAfter.activeLeader right rightRole
        rw [sameTerm] at leftOwned
        have sameNode : left = right :=
          Option.some.inj (leftOwned.symm.trans rightOwned)
        subst right
        rcases
            prefixesComparable
              (List.take_prefix leftIndex
                ((nodeOf (advanceCommitState state node)) left).log)
              (List.take_prefix rightIndex
                ((nodeOf (advanceCommitState state node)) left).log) with
          direct | direct
        · exact Or.inl direct
        · exact Or.inr (Or.inl direct)
      · have leftOwned := ownershipAfter.activeLeader left leftRole
        rcases
            electionFactsAfter.ownerRecorded
              ((nodeOf (advanceCommitState state node)) left).currentTerm
              left leftOwned with
          bootstrap | elected
        · have rightPositive :=
            termsPositiveAfter right (by rw [rightRole]; decide)
          rw [bootstrap.1] at rightBefore
          omega
        · rcases elected with
            ⟨record, recordStored, _recordLeader⟩
          have rightInLeft :
              ((nodeOf (advanceCommitState state node)) right).log.take rightIndex <+:
                ((nodeOf (advanceCommitState state node)) left).log :=
            (recordBridgeAfter
              right rightIndex rightRole rightCurrent rightSignature
              (effectiveMajorityImpliesPotential
                (advanceCommitState state node)
                appendHistory responseHistory right rightIndex rightMajority)
              ((nodeOf (advanceCommitState state node)) left).currentTerm
              record recordStored rightBefore).trans
              ((electionFactsAfter.promotionCanonical
                ((nodeOf (advanceCommitState state node)) left).currentTerm
                record recordStored).trans
                (by
                  rw [ownershipAfter.activeLeaderHistory left leftRole]))
          rcases
              prefixesComparable
                rightInLeft
                (List.take_prefix leftIndex
                  ((nodeOf (advanceCommitState state node)) left).log) with
            direct | direct
          · exact Or.inr (Or.inl direct)
          · exact Or.inl direct
    · intro activationIndex activation queuedDestination queuedRequest
        stored queued sameTerm
      by_cases create : replaceActivation
      · by_cases same : activationIndex = newActivationKey
        · subst activationIndex
          have recordEq : activationRecord = activation := by
            simpa [newActivations, create] using stored
          subst activation
          have requestTerm :
              queuedRequest.2.2.term =
                ((nodeOf state) node).currentTerm := by
            simpa [activationRecord] using sameTerm
          have requestOwned :=
            (ownership.queuedAppendMetadata
              queuedDestination queuedRequest queued).2.1
          have leaderOwned := ownership.activeLeader node leaderRole
          have sourceEq : queuedRequest.1 = node := by
            rw [requestTerm, leaderOwned] at requestOwned
            exact (Option.some.inj requestOwned).symm
          have historyPrefix :
              appendHistory queuedRequest <+: ((nodeOf state) node).log := by
            simpa [sourceEq]
              using ownership.queuedActiveSourceHistory
                queuedDestination queuedRequest queued
                (by simpa [sourceEq] using requestTerm)
                (by simpa [sourceEq] using leaderRole)
          have activationPrefix :
              activationRecord.history.take
                  activationRecord.activationFrontier <+:
                ((nodeOf state) node).log := by
            simpa [activationRecord]
              using List.take_prefix frontier ((nodeOf state) node).log
          exact prefixesComparable activationPrefix
            historyPrefix
        · have oldStored :
              activations activationIndex = some activation := by
            simpa [newActivations, create, Function.update, same] using stored
          exact
            activationQuorums.queuedComparable
              activationIndex activation queuedDestination queuedRequest
              oldStored queued sameTerm
      · exact
          activationQuorums.queuedComparable
            activationIndex activation queuedDestination queuedRequest
            (by simpa [newActivations, create] using stored)
            queued sameTerm
    · intro coveredNode coveredFrontier within positive signature
      have afterCommitBound :
          coveredFrontier <=
            ((nodeOf (advanceCommitState state node)) coveredNode).log.length :=
        within.trans
          (by
            by_cases coveredNodeEq : coveredNode = node
            · subst coveredNode
              simpa [commitNode, logEq] using frontierBound
            · simpa [
                commitOther coveredNode coveredNodeEq, logEq
              ] using facts.commitIndicesBounded coveredNode)
      by_cases oldWithin :
          coveredFrontier <= ((nodeOf state) coveredNode).commitIndex
      · rcases
            activationQuorums.committedCoverage
              coveredNode coveredFrontier oldWithin
              (by simpa [logEq] using positive)
              (by simpa [logEq] using signature) with
          ⟨witness⟩
        have migrated :
            ConfigurationFrontierCoverageWitness
              newActivations ((nodeOf state) coveredNode).log
                coveredFrontier ((nodeOf state) coveredNode).currentTerm := by
          apply migrateFrontierCoverage witness
          intro sameIndex
          have configurationKnown :
              currentConfigurationAt
                  ((nodeOf state) coveredNode).log coveredFrontier ∈
                allConfigurations ((nodeOf state) coveredNode).log := by
            simpa [currentConfiguration]
              using currentConfiguration_mem_allConfigurations
                { (nodeOf state) coveredNode with commitIndex := coveredFrontier }
          have configurationCommitted :
              (currentConfigurationAt
                  ((nodeOf state) coveredNode).log coveredFrontier).index <=
                ((nodeOf state) coveredNode).commitIndex := by
            have configurationWithin :
                (currentConfigurationAt
                    ((nodeOf state) coveredNode).log coveredFrontier).index <=
                  coveredFrontier := by
              simpa [currentConfiguration]
                using currentConfiguration_index_le_commitIndex
                  { (nodeOf state) coveredNode with commitIndex := coveredFrontier }
            exact configurationWithin.trans oldWithin
          exact
            newConfigurationEqOfCommittedConfiguration
              coveredNode
              (currentConfigurationAt
                ((nodeOf state) coveredNode).log coveredFrontier)
              configurationKnown configurationCommitted sameIndex
        exact ⟨by simpa [logEq, termEq] using migrated⟩
      · have coveredNodeEq : coveredNode = node := by
          by_contra different
          have oldCommitEq :
              ((nodeOf (advanceCommitState state node)) coveredNode).commitIndex =
                ((nodeOf state) coveredNode).commitIndex :=
            commitOther coveredNode different
          omega
        subst coveredNode
        have coveredWithin : coveredFrontier <= frontier := by
          simpa [commitNode] using within
        let coveredConfiguration :=
          currentConfigurationAt ((nodeOf state) node).log coveredFrontier
        have coveredConfigurationKnown :
            coveredConfiguration ∈
              allConfigurations ((nodeOf state) node).log := by
          simpa [coveredConfiguration, currentConfiguration]
            using currentConfiguration_mem_allConfigurations
              { (nodeOf state) node with commitIndex := coveredFrontier }
        have coveredConfigurationIndexBound :
            coveredConfiguration.index <= coveredFrontier := by
          simpa [coveredConfiguration, currentConfiguration]
            using currentConfiguration_index_le_commitIndex
              { (nodeOf state) node with commitIndex := coveredFrontier }
        have coveredConfigurationAfterEq :
            currentConfigurationAt
                ((nodeOf (advanceCommitState state node)) node).log
                coveredFrontier =
              coveredConfiguration := by
          simp [coveredConfiguration, logEq]
        have oldBeforeCovered :
            oldConfiguration.index <= coveredConfiguration.index := by
          simpa [coveredConfiguration, currentConfiguration]
            using configuration_index_le_currentConfiguration
              { (nodeOf state) node with commitIndex := coveredFrontier }
              oldConfiguration
              (by simpa using oldConfigurationKnown)
              (oldConfigurationIndexBound.trans
                (Nat.le_of_lt (Nat.lt_of_not_ge oldWithin)))
        by_cases create : replaceActivation
        · refine ⟨⟨
                    newActivationKey,
                    activationRecord,
                    activationRecordStoredForCoverage create,
                    ?_,
                    ?_,
                    ?_,
                    ?_,
                    ?_,
                    ?_,
                    ?_
                  ⟩⟩
          · rw [coveredConfigurationAfterEq]
            simp only [activationRecord, List.mem_filter]
            exact ⟨
              coveredConfigurationKnown,
              by
                apply decide_eq_true
                exact ⟨
                  oldBeforeCovered,
                  coveredConfigurationIndexBound.trans coveredWithin
                ⟩
            ⟩
          · simp [activationRecord, termEq]
          · simp [
              activationRecord, coveredConfigurationIndexBound,
              coveredWithin, coveredConfigurationAfterEq
            ]
          · simp [activationRecord, logEq]
          · intro higherIndex higher stored order
            rw [coveredConfigurationAfterEq] at order
            simpa [activationRecord, coveredConfiguration, Nat.min_eq_left coveredWithin]
              using coveredPrefixInHigherActivationAfter
                create coveredFrontier coveredWithin
                higherIndex higher stored
                (by simpa [coveredConfiguration] using order)
          · intro lowerIndex lower stored order
            rw [coveredConfigurationAfterEq] at order
            simpa [activationRecord, coveredConfiguration, Nat.min_eq_left coveredWithin]
              using lowerActivationPrefixInCoveredAfter
                create coveredFrontier coveredWithin
                lowerIndex lower stored
                (by simpa [coveredConfiguration] using order)
          · intro sameIndex same stored sameConfiguration
            rw [coveredConfigurationAfterEq] at sameConfiguration
            by_cases sameNew : sameIndex = newActivationKey
            · subst sameIndex
              have sameEq : activationRecord = same :=
                Option.some.inj
                  ((activationRecordStoredForCoverage create).symm.trans stored)
              subst same
              have coveredEqNew :
                  coveredConfiguration = newConfiguration := by
                apply
                  allConfigurations_index_unique
                    (TxId := TxId) ((nodeOf state) node).log
                    coveredConfigurationKnown newConfigurationKnown
                simpa [
                  activationRecord, coveredConfiguration,
                  coveredConfigurationAfterEq
                ] using sameConfiguration.symm
              simpa [
                activationRecord, coveredConfiguration,
                coveredConfigurationAfterEq
              ] using coveredEqNew.symm
            · have oldStored :
                  activations sameIndex = some same := by
                simpa [newActivations, create, Function.update, sameNew] using stored
              simpa [coveredConfiguration, coveredConfigurationAfterEq]
                using oldActivationConfigurationEqAtFrontier
                  coveredFrontier coveredWithin sameIndex same oldStored
                  (by simpa [coveredConfiguration] using sameConfiguration)
        · have coveredBeforeNew :
              coveredConfiguration.index <= newConfiguration.index := by
            simpa [coveredConfiguration, newConfiguration, currentConfiguration]
              using configuration_index_le_currentConfiguration
                { (nodeOf state) node with commitIndex := frontier }
                coveredConfiguration coveredConfigurationKnown
                (coveredConfigurationIndexBound.trans coveredWithin)
          have retained : retainedActivation := by
            by_cases changed : oldConfiguration = newConfiguration
            · have oldPositive : 0 < oldConfiguration.index := by
                have coveredPositive :
                    0 < coveredConfiguration.index := by
                  simpa [coveredConfiguration, coveredConfigurationAfterEq] using positive
                have sameIndex :
                    coveredConfiguration.index = oldConfiguration.index := by
                  exact
                    Nat.le_antisymm
                      (coveredBeforeNew.trans (by simp [changed]))
                      oldBeforeCovered
                simpa [sameIndex] using coveredPositive
              rcases configurationActivations node oldPositive with
                ⟨oldWitness⟩
              apply
                retainedActivationOfCoveringWitness oldWitness
              have oldBeforeWitness :=
                oldWitness.configurationIndex_le_activationConfiguration
                  activationQuorums.history
              rw [← changed]
              exact oldBeforeWitness
            · by_contra missing
              exact create ⟨changed, missing⟩
          rcases retained with
            ⟨retainedIndex, retainedRecord, retainedStored,
              retainedGoverning, retainedTermBound,
              retainedAgreement⟩
          have findCoverage :
              forall configurationIndex,
                forall activationIndex activation,
                  activation.newConfiguration.index = configurationIndex ->
                  activations activationIndex = some activation ->
                  coveredConfiguration.index <=
                    activation.newConfiguration.index ->
                  activation.activationTerm <=
                    ((nodeOf state) node).currentTerm ->
                  activation.history.take
                      (min frontier activation.activationFrontier) =
                    ((nodeOf state) node).log.take
                      (min frontier activation.activationFrontier) ->
                    Exists fun coveringIndex =>
                      Exists fun covering =>
                        activations coveringIndex = some covering /\
                          coveredConfiguration ∈ covering.governingActive /\
                          covering.activationTerm <=
                            ((nodeOf state) node).currentTerm /\
                          covering.history.take
                              (min coveredFrontier
                                covering.activationFrontier) =
                            ((nodeOf state) node).log.take
                              (min coveredFrontier
                                covering.activationFrontier) := by
            intro configurationIndex
            induction configurationIndex using Nat.strong_induction_on with
            | h configurationIndex inductionHypothesis =>
                intro activationIndex activation indexEq stored
                    coveredBeforeActivation activationTermBound agreement
                have valid :=
                  activationQuorums.history.valid
                    activationIndex activation stored
                by_cases oldBeforeCovered :
                    activation.oldConfiguration.index <=
                      coveredConfiguration.index
                · have coveredWithinActivation
                      : coveredConfiguration.index <= activation.activationFrontier :=
                    coveredBeforeActivation.trans
                      (by
                        have newGoverning :=
                          valid.2.2.2.2.2.2.2.1
                        rw [valid.2.2.2.2.2.2.1] at newGoverning
                        exact (of_decide_eq_true (List.mem_filter.mp newGoverning).2).2)
                  have coveredWithinShared :
                      coveredConfiguration.index <=
                        min frontier activation.activationFrontier :=
                    Nat.le_min.mpr
                      ⟨coveredConfigurationIndexBound.trans coveredWithin,
                        coveredWithinActivation⟩
                  have coveredKnownLeaderTake :
                      coveredConfiguration ∈
                        allConfigurations
                          (((nodeOf state) node).log.take
                            coveredConfiguration.index) :=
                    allConfigurations_mem_take_of_index_le
                      ((nodeOf state) node).log coveredConfiguration.index
                      (coveredConfigurationIndexBound.trans
                        (coveredWithin.trans frontierBound))
                      coveredConfigurationKnown le_rfl
                  have agreementAtCovered :=
                    congrArg
                      (fun history =>
                        history.take coveredConfiguration.index)
                      agreement
                  have coveredKnownActivation :
                      coveredConfiguration ∈
                        allConfigurations activation.history := by
                    apply
                      memOfPrefix
                        (allConfigurations_mono_prefix
                          (List.take_prefix
                            coveredConfiguration.index activation.history))
                    rw [show
                      activation.history.take
                            coveredConfiguration.index =
                          ((nodeOf state) node).log.take
                            coveredConfiguration.index by
                        simpa [
                          List.take_take,
                          Nat.min_eq_left coveredWithinShared
                        ] using agreementAtCovered]
                    exact coveredKnownLeaderTake
                  have coveredGoverning :
                      coveredConfiguration ∈
                        activation.governingActive := by
                    rw [valid.2.2.2.2.2.2.1]
                    simp only [List.mem_filter]
                    exact ⟨
                      coveredKnownActivation,
                      decide_eq_true ⟨oldBeforeCovered, coveredWithinActivation⟩
                    ⟩
                  refine ⟨
                    activationIndex,
                    activation,
                    stored,
                    coveredGoverning,
                    activationTermBound,
                    ?_
                  ⟩
                  have targetBeforeShared
                      : min coveredFrontier activation.activationFrontier
                        <= min frontier activation.activationFrontier := by
                    omega
                  have restricted :=
                    congrArg
                      (fun history =>
                        history.take
                          (min coveredFrontier
                            activation.activationFrontier))
                      agreement
                  simpa [List.take_take, Nat.min_eq_left targetBeforeShared]
                    using restricted
                · have coveredBeforeOld :
                      coveredConfiguration.index <
                        activation.oldConfiguration.index := by
                    omega
                  have oldPositive :
                      0 < activation.oldConfiguration.index := by omega
                  obtain ⟨priorIndex, prior, priorFacts⟩ :=
                    activationQuorums.history.priorActivation
                      activationIndex activation stored oldPositive
                  have priorStored := priorFacts.1
                  have priorBeforeActivation := priorFacts.2.1
                  have oldGoverning := priorFacts.2.2.1
                  have priorPrefix := priorFacts.2.2.2
                  have oldBeforePrior :
                      activation.oldConfiguration.index <=
                        prior.newConfiguration.index :=
                    activationGoverningConfigurationIndexLeNew
                      activationQuorums.history priorStored oldGoverning
                  have priorTermBound :
                      prior.activationTerm <=
                        ((nodeOf state) node).currentTerm :=
                    (activationTermLeOfPrefix
                      ownership activationQuorums.history
                      activationCanonical
                      priorStored stored priorPrefix).trans
                      activationTermBound
                  have priorFrontierLe :
                      prior.activationFrontier <=
                        activation.activationFrontier := by
                    have priorLength :
                        (prior.history.take prior.activationFrontier).length =
                          prior.activationFrontier := by
                      simp [Nat.min_eq_left
                        (activationQuorums.history.valid
                          priorIndex prior priorStored).2.1]
                    have activationLength :
                        (activation.history.take
                          activation.activationFrontier).length =
                            activation.activationFrontier := by
                      simp [Nat.min_eq_left valid.2.1]
                    simpa [priorLength, activationLength] using priorPrefix.length_le
                  have priorSharedLe
                      : min frontier prior.activationFrontier
                        <= min frontier activation.activationFrontier := by
                    omega
                  have priorTakeEq :
                      prior.history.take
                            (min frontier prior.activationFrontier) =
                        activation.history.take
                            (min frontier prior.activationFrontier) := by
                    have priorLength :
                        (prior.history.take prior.activationFrontier).length =
                          prior.activationFrontier := by
                      simp [Nat.min_eq_left
                        (activationQuorums.history.valid
                          priorIndex prior priorStored).2.1]
                    have agreed :=
                      takeEqOfPrefix priorPrefix
                        (count := min frontier prior.activationFrontier)
                        (by simp [priorLength])
                    simpa [
                      List.take_take,
                      Nat.min_eq_left (Nat.min_le_right _ _),
                      Nat.min_eq_left
                        ((Nat.min_le_right _ _).trans priorFrontierLe)
                    ] using agreed
                  have activationTakeEq :
                      activation.history.take
                            (min frontier prior.activationFrontier) =
                        ((nodeOf state) node).log.take
                            (min frontier prior.activationFrontier) := by
                    have restricted :=
                      congrArg
                        (fun history =>
                          history.take
                            (min frontier prior.activationFrontier))
                        agreement
                    simpa [
                      List.take_take,
                      Nat.min_eq_left priorSharedLe
                    ] using restricted
                  have priorAgreement :
                      prior.history.take
                            (min frontier prior.activationFrontier) =
                        ((nodeOf state) node).log.take
                            (min frontier prior.activationFrontier) :=
                    priorTakeEq.trans activationTakeEq
                  apply inductionHypothesis
                    prior.newConfiguration.index
                    (by simpa [indexEq] using priorBeforeActivation)
                    priorIndex prior rfl priorStored
                    (coveredBeforeOld.le.trans oldBeforePrior)
                    priorTermBound priorAgreement
          rcases
              findCoverage retainedRecord.newConfiguration.index
                retainedIndex retainedRecord rfl retainedStored
                (coveredBeforeNew.trans
                  (activationGoverningConfigurationIndexLeNew
                    activationQuorums.history retainedStored
                    retainedGoverning))
                retainedTermBound retainedAgreement with
            ⟨coveringIndex, covering, coveringStored,
              coveredGoverning, coveringTermBound,
              coveringAgreement⟩
          refine ⟨⟨
                    coveringIndex,
                    covering,
                    by simpa [newActivations, create] using coveringStored,
                    by simpa [
                        coveredConfigurationAfterEq
                      ] using coveredGoverning,
                    by simpa [termEq] using coveringTermBound,
                    by
                      simpa [
                             coveredConfigurationAfterEq]
                        using (show coveredConfiguration.index <=
                            min coveredFrontier covering.activationFrontier by
                          have valid :=
                            activationQuorums.history.valid
                              coveringIndex covering coveringStored
                          have governing := coveredGoverning
                          rw [valid.2.2.2.2.2.2.1] at governing
                          exact
                            Nat.le_min.mpr
                              ⟨coveredConfigurationIndexBound,
                                (of_decide_eq_true
                                  (List.mem_filter.mp governing).2).2⟩),
                    by simpa [logEq] using coveringAgreement,
                    ?_,
                    ?_,
                    ?_
                  ⟩⟩
          · intro higherIndex higher stored order
            rw [coveredConfigurationAfterEq] at order
            have coveredPrefix :
                covering.history.take
                    (min coveredFrontier covering.activationFrontier) <+:
                  ((nodeOf state) node).log.take coveredFrontier := by
              rw [coveringAgreement, List.prefix_take_iff]
              exact ⟨
                List.take_prefix _ _,
                (List.length_take_le _ _).trans (Nat.min_le_left _ _)
              ⟩
            have oldHigherStored :
                activations higherIndex = some higher := by
              simpa [newActivations, create] using stored
            exact coveredPrefix.trans
              (coveredPrefixInOldHigherActivation
                coveredFrontier coveredWithin higherIndex higher
                oldHigherStored
                (by simpa [coveredConfiguration] using order))
          · intro lowerIndex lower stored order
            rw [coveredConfigurationAfterEq] at order
            have oldLowerStored :
                activations lowerIndex = some lower := by
              simpa [newActivations, create] using stored
            have lowerBeforeCovered :
                lower.newConfiguration.index <
                  coveredConfiguration.index := by
              simpa [coveredConfiguration] using order
            have lowerInCovering :=
              activationPrefixInHigherActivation
                ownership electionFacts activationQuorums.history
                activationCanonical activationElections
                oldLowerStored coveringStored
                (lowerBeforeCovered.trans_le
                  (activationGoverningConfigurationIndexLeNew
                    activationQuorums.history coveringStored
                    coveredGoverning))
            have lowerFrontierLeShared :
                lower.activationFrontier <=
                  min coveredFrontier covering.activationFrontier := by
              by_contra outside
              have sharedBeforeLower :
                  min coveredFrontier covering.activationFrontier <
                    lower.activationFrontier := by omega
              have lowerLength :
                  (lower.history.take lower.activationFrontier).length =
                    lower.activationFrontier := by
                simp [Nat.min_eq_left
                  (activationQuorums.history.valid
                    lowerIndex lower oldLowerStored).2.1]
              have exactLower := prefixEqTake lowerInCovering
              have valid :=
                activationQuorums.history.valid
                  coveringIndex covering coveringStored
              have governing := coveredGoverning
              rw [valid.2.2.2.2.2.2.1] at governing
              have coveredKnownCoveringShared :
                  coveredConfiguration ∈
                    allConfigurations
                      (covering.history.take
                        (min coveredFrontier
                          covering.activationFrontier)) :=
                allConfigurations_mem_take_of_index_le
                  covering.history
                  (min coveredFrontier covering.activationFrontier)
                  ((Nat.min_le_right _ _).trans valid.2.1)
                  (List.mem_filter.mp governing).1
                  (Nat.le_min.mpr
                    ⟨coveredConfigurationIndexBound,
                      (of_decide_eq_true
                        (List.mem_filter.mp governing).2).2⟩)
              have sharedTakeEq :
                  lower.history.take
                        (min coveredFrontier
                          covering.activationFrontier) =
                    covering.history.take
                        (min coveredFrontier
                          covering.activationFrontier) := by
                have agreed :=
                  congrArg
                    (fun history =>
                      history.take
                        (min coveredFrontier
                          covering.activationFrontier))
                    exactLower
                simpa [
                  lowerLength, List.take_take,
                  Nat.min_eq_left sharedBeforeLower.le,
                  Nat.min_eq_left (Nat.min_le_right _ _),
                  Nat.min_assoc, Nat.min_left_comm, Nat.min_comm
                ] using agreed.symm
              have coveredKnownLower :
                  coveredConfiguration ∈ allConfigurations lower.history := by
                apply
                  memOfPrefix
                    (allConfigurations_mono_prefix
                      (List.take_prefix
                        (min coveredFrontier
                          covering.activationFrontier)
                        lower.history))
                rw [sharedTakeEq]
                exact coveredKnownCoveringShared
              have maximal :=
                configuration_index_le_currentConfiguration
                  { (nodeOf state) node with
                    log := lower.history
                    commitIndex := lower.activationFrontier }
                  coveredConfiguration
                  (by simpa using coveredKnownLower)
                  (by
                    have coveredLeShared :
                        coveredConfiguration.index <=
                          min coveredFrontier
                            covering.activationFrontier := by
                      have valid :=
                        activationQuorums.history.valid
                          coveringIndex covering coveringStored
                      have governing := coveredGoverning
                      rw [valid.2.2.2.2.2.2.1] at governing
                      exact
                        Nat.le_min.mpr
                          ⟨coveredConfigurationIndexBound,
                            (of_decide_eq_true
                              (List.mem_filter.mp governing).2).2⟩
                    exact coveredLeShared.trans sharedBeforeLower.le)
              have contradiction :
                  coveredConfiguration.index <=
                    lower.newConfiguration.index := by
                simpa [currentConfiguration,
                  (activationQuorums.history.valid
                    lowerIndex lower oldLowerStored).2.2.2.1]
                  using maximal
              omega
            rw [List.prefix_take_iff]
            exact ⟨
              lowerInCovering.trans
                (List.take_prefix covering.activationFrontier covering.history),
              by
                have lowerLength :
                    (lower.history.take lower.activationFrontier).length =
                      lower.activationFrontier := by
                  simp [Nat.min_eq_left
                    (activationQuorums.history.valid
                      lowerIndex lower oldLowerStored).2.1]
                simpa [lowerLength] using lowerFrontierLeShared
            ⟩
          · intro sameIndex same stored sameConfiguration
            rw [coveredConfigurationAfterEq] at sameConfiguration
            exact
              (by
              simpa [logEq]
                using (oldActivationConfigurationEqAtFrontier
                        coveredFrontier coveredWithin sameIndex same
                        (by simpa [newActivations, create] using stored)
                        (by simpa [coveredConfiguration] using sameConfiguration)))
    · intro queuedDestination queuedRequest queued coveredFrontier within
        positive signature
      have oldQueued :
          (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
        simpa [advanceCommitState, Model.Local.advanceCommit, present] using queued
      rcases
          activationQuorums.queuedCoverage
            queuedDestination queuedRequest oldQueued coveredFrontier within
              positive signature with
        ⟨witness⟩
      refine ⟨migrateFrontierCoverage witness ?_⟩
      intro sameIndex
      let configuration :=
        currentConfigurationAt
          (appendHistory queuedRequest) coveredFrontier
      have requestFacts :=
        facts.networkHistory.appendRequest
          queuedDestination queuedRequest oldQueued
      have configurationKnownHistory :
          configuration ∈ allConfigurations (appendHistory queuedRequest) := by
        simpa [configuration, currentConfiguration]
          using currentConfiguration_mem_allConfigurations
            {
              (nodeOf state) queuedRequest.1 with
                log := appendHistory queuedRequest
                commitIndex := coveredFrontier
            }
      have configurationIndexBound :
          configuration.index <= coveredFrontier := by
        simpa [configuration, currentConfiguration]
          using currentConfiguration_index_le_commitIndex
            {
              (nodeOf state) queuedRequest.1 with
                log := appendHistory queuedRequest
                commitIndex := coveredFrontier
            }
      have coveredByLeaderCommit :
          coveredFrontier <= queuedRequest.2.2.leaderCommit :=
        within.trans (Nat.min_le_left _ _)
      have requestCommittedPrefix :
          (appendHistory queuedRequest).take queuedRequest.2.2.leaderCommit <+:
            ((nodeOf state) queuedRequest.1).committedLog := by
        exact requestFacts.2.2
      have configurationKnownRequestCommit :
          configuration ∈
            allConfigurations
              ((appendHistory queuedRequest).take
                queuedRequest.2.2.leaderCommit) :=
        allConfigurations_mem_take_of_index_le
          (appendHistory queuedRequest) queuedRequest.2.2.leaderCommit
          requestFacts.2.1 configurationKnownHistory
          (configurationIndexBound.trans coveredByLeaderCommit)
      have configurationKnownCommitted :
          configuration ∈
            allConfigurations
              ((nodeOf state) queuedRequest.1).committedLog :=
        memOfPrefix
          (allConfigurations_mono_prefix requestCommittedPrefix)
          configurationKnownRequestCommit
      have configurationKnownSource :
          configuration ∈
            allConfigurations ((nodeOf state) queuedRequest.1).log := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix
                ((nodeOf state) queuedRequest.1).commitIndex
                ((nodeOf state) queuedRequest.1).log))
        simpa [
          NodeState.committedLog,
          Nat.min_eq_left
            (facts.commitIndicesBounded queuedRequest.1)
        ] using configurationKnownCommitted
      have leaderCommitLeSourceCommit :
          queuedRequest.2.2.leaderCommit <=
            ((nodeOf state) queuedRequest.1).commitIndex := by
        have prefixLength := requestCommittedPrefix.length_le
        simpa [
          NodeState.committedLog,
          Nat.min_eq_left requestFacts.2.1,
          Nat.min_eq_left
            (facts.commitIndicesBounded queuedRequest.1)
        ] using prefixLength
      exact newConfigurationEqOfCommittedConfiguration
        queuedRequest.1 configuration configurationKnownSource
        (configurationIndexBound.trans
          (coveredByLeaderCommit.trans leaderCommitLeSourceCommit))
        (by simpa [configuration] using sameIndex)
  have configurationIndexLeOfMemTake :
      forall (history : List (Entry Node TxId)) frontier configuration,
        configuration ∈ allConfigurations (history.take frontier) ->
          configuration.index <= frontier := by
    intro history takeIndex configuration member
    rw [allConfigurations] at member
    rcases List.mem_cons.mp member with implicit | physical
    · rw [implicit]
      simp [implicitConfiguration]
    · exact (configurationsInLog_index_bounds
              (TxId := TxId) (history.take takeIndex) physical).2.trans
        (List.length_take_le takeIndex history)
  have newConfigurationKnownAtFrontier :
      newConfiguration ∈
        allConfigurations (((nodeOf state) node).log.take frontier) :=
    allConfigurations_mem_take_of_index_le
      ((nodeOf state) node).log frontier frontierBound
      newConfigurationKnown newConfigurationIndexBound
  have frontierEffectiveAfter :
      hasEffectiveMajorityAt (joined := joinedNodes)
        (advanceCommitState state node)
        responseHistory node frontier :=
    effectiveMajorityNodeAfterOfBefore frontier frontierEffective
  have frontierPotentialAfter :
      hasPotentialMajorityAt (joined := joinedNodes)
        (advanceCommitState state node)
        appendHistory responseHistory node frontier :=
    effectiveMajorityImpliesPotential
      (advanceCommitState state node)
      appendHistory responseHistory node frontier frontierEffectiveAfter
  have newFrontierComparableKnownAfter :
      forall knownEvidence supportedPrefix,
        KnownCommitEvidence
            (advanceCommitState state node)
            appendHistory newNodeEvidence requestEvidence
            knownEvidence supportedPrefix ->
          ((nodeOf state) node).log.take frontier <+:
              knownEvidence.history.take knownEvidence.commitFrontier \/
            knownEvidence.history.take knownEvidence.commitFrontier <+:
              ((nodeOf state) node).log.take frontier := by
    intro knownEvidence supportedPrefix known
    have valid := knownCommitEvidenceValid evidenceAfter known
    by_cases termOrder :
        knownEvidence.commitTerm <= ((nodeOf state) node).currentTerm
    · rcases
          configurationMajorityNonempty valid.2.2.2.2.2.1 with
        ⟨member, _authorityMember, ackMember⟩
      have knownInNode :
          knownEvidence.history.take knownEvidence.commitFrontier <+:
            ((nodeOf state) node).log := by
        simpa [logEq]
          using knownCommitEvidenceActiveLeaderContainsFrontier
            ownershipAfter electionFactsAfter evidenceAfter
            prospectiveAfter known roleNode
            (by simpa [termEq] using termOrder) ackMember
      exact
        prefixesComparable
          (List.take_prefix frontier ((nodeOf state) node).log)
          knownInNode
    · have nodeBefore :
          ((nodeOf state) node).currentTerm <
            knownEvidence.commitTerm := by
        omega
      have canonicalEq :=
        knownEvidenceFrontierCanonicalAfter
          knownEvidence supportedPrefix known
      have supportedPositive :=
        knownCommitEvidenceSupportedLengthPositive evidenceAfter known
      have frontierPositive :
          0 < knownEvidence.commitFrontier :=
        supportedPositive.trans_le valid.2.2.1
      rcases
          entryAtSomeOfPositiveBound frontierPositive valid.1 with
        ⟨frontierEntry, historyFound⟩
      have frontierEntryTerm :
          frontierEntry.term = knownEvidence.commitTerm := by
        simpa [termAt, historyFound] using valid.2.1
      have historyTakeFound :
          entryAt?
              (knownEvidence.history.take knownEvidence.commitFrontier)
              knownEvidence.commitFrontier =
            some frontierEntry := by
        rw [entryAtTake_of_le le_rfl]
        exact historyFound
      have canonicalTakeFound :
          entryAt?
              ((canonicalHistory knownEvidence.commitTerm).take
                knownEvidence.commitFrontier)
              knownEvidence.commitFrontier =
            some frontierEntry := by
        rw [← canonicalEq]
        exact historyTakeFound
      have canonicalFound :
          entryAt?
              (canonicalHistory knownEvidence.commitTerm)
              knownEvidence.commitFrontier =
            some frontierEntry := by
        rw [← entryAtTake_of_le
          (log := canonicalHistory knownEvidence.commitTerm) le_rfl]
        exact canonicalTakeFound
      rcases
          ownershipAfter.canonicalEntryOwner
            knownEvidence.commitTerm knownEvidence.commitFrontier
            frontierEntry canonicalFound with
        ⟨owner, owned⟩
      rw [frontierEntryTerm] at owned
      rcases
          electionFactsAfter.ownerRecorded
            knownEvidence.commitTerm owner owned with
        bootstrap | elected
      · have nodePositive :=
          facts.currentTermsPositive node (by rw [leaderRole]; decide)
        rw [bootstrap.1] at nodeBefore
        omega
      · rcases elected with
          ⟨record, recordStored, _recordLeader⟩
        have newInCanonical :
            ((nodeOf state) node).log.take frontier <+:
              canonicalHistory knownEvidence.commitTerm := by
          simpa [logEq]
            using (recordBridgeAfter
                    node frontier roleNode
                    (by simpa [logEq, termEq] using frontierValid.1)
                    (by simpa [logEq] using frontierSignature)
                    frontierPotentialAfter
                    knownEvidence.commitTerm record recordStored
                    (by simpa [termEq] using nodeBefore)).trans
              (electionFactsAfter.promotionCanonical
                knownEvidence.commitTerm record recordStored)
        have knownInCanonical :
            knownEvidence.history.take knownEvidence.commitFrontier <+:
              canonicalHistory knownEvidence.commitTerm := by
          rw [canonicalEq]
          exact List.take_prefix _ _
        exact
          prefixesComparable
            newInCanonical knownInCanonical
  have knownFrontierBeforeNewOfAuthorityBefore :
      forall knownEvidence supportedPrefix,
        KnownCommitEvidence
            (advanceCommitState state node)
            appendHistory newNodeEvidence requestEvidence
            knownEvidence supportedPrefix ->
        knownEvidence.authority.index < newConfiguration.index ->
          knownEvidence.history.take knownEvidence.commitFrontier <+:
            ((nodeOf state) node).log.take frontier := by
    intro knownEvidence supportedPrefix known order
    rcases
        newFrontierComparableKnownAfter
          knownEvidence supportedPrefix known with
      newBefore | knownBefore
    · have newKnownEvidenceFrontier :
          newConfiguration ∈
            allConfigurations
              (knownEvidence.history.take knownEvidence.commitFrontier) :=
        memOfPrefix
          (allConfigurations_mono_prefix newBefore)
          newConfigurationKnownAtFrontier
      have newKnownEvidenceHistory :
          newConfiguration ∈
            allConfigurations knownEvidence.history :=
        memOfPrefix
          (allConfigurations_mono_prefix
            (List.take_prefix
              knownEvidence.commitFrontier knownEvidence.history))
          newKnownEvidenceFrontier
      have newIndexBound :
          newConfiguration.index <= knownEvidence.commitFrontier :=
        configurationIndexLeOfMemTake
          knownEvidence.history knownEvidence.commitFrontier
          newConfiguration newKnownEvidenceFrontier
      have valid := knownCommitEvidenceValid evidenceAfter known
      let evidenceNode : NodeState Node TxId :=
        { (nodeOf state) node with
          log := knownEvidence.history
          commitIndex := knownEvidence.commitFrontier }
      have authorityAfterNew :=
        configuration_index_le_currentConfiguration
          evidenceNode newConfiguration
          (by simpa [evidenceNode] using newKnownEvidenceHistory)
          newIndexBound
      have contradiction :
          newConfiguration.index <= knownEvidence.authority.index := by
        simpa [evidenceNode, currentConfiguration, valid.2.2.2.2.1]
          using authorityAfterNew
      omega
    · exact knownBefore
  have newFrontierBeforeKnownOfAuthorityAfter :
      forall knownEvidence supportedPrefix,
        KnownCommitEvidence
            (advanceCommitState state node)
            appendHistory newNodeEvidence requestEvidence
            knownEvidence supportedPrefix ->
        newConfiguration.index < knownEvidence.authority.index ->
          ((nodeOf state) node).log.take frontier <+:
            knownEvidence.history.take knownEvidence.commitFrontier := by
    intro knownEvidence supportedPrefix known order
    rcases
        newFrontierComparableKnownAfter
          knownEvidence supportedPrefix known with
      newBefore | knownBefore
    · exact newBefore
    · have valid := knownCommitEvidenceValid evidenceAfter known
      have authorityKnownHistory :
          knownEvidence.authority ∈
            allConfigurations knownEvidence.history := by
        have currentKnown :=
          currentConfiguration_mem_allConfigurations
            { ((nodeOf state) node) with
              log := knownEvidence.history
              commitIndex := knownEvidence.commitFrontier }
        simpa [
          currentConfiguration, valid.2.2.2.2.1
        ] using currentKnown
      have authorityIndexBound :
          knownEvidence.authority.index <=
            knownEvidence.commitFrontier := by
        let evidenceNode : NodeState Node TxId :=
          { (nodeOf state) node with
            log := knownEvidence.history
            commitIndex := knownEvidence.commitFrontier }
        have bound :=
          currentConfiguration_index_le_commitIndex evidenceNode
        simpa [
          evidenceNode, currentConfiguration,
          valid.2.2.2.2.1
        ] using bound
      have authorityKnownFrontier :
          knownEvidence.authority ∈
            allConfigurations
              (knownEvidence.history.take knownEvidence.commitFrontier) :=
        allConfigurations_mem_take_of_index_le
          knownEvidence.history knownEvidence.commitFrontier valid.1
          authorityKnownHistory authorityIndexBound
      have authorityKnownNewFrontier :
          knownEvidence.authority ∈
            allConfigurations (((nodeOf state) node).log.take frontier) :=
        memOfPrefix
          (allConfigurations_mono_prefix knownBefore)
          authorityKnownFrontier
      have authorityKnownNode :
          knownEvidence.authority ∈
            allConfigurations ((nodeOf state) node).log :=
        memOfPrefix
          (allConfigurations_mono_prefix
            (List.take_prefix frontier ((nodeOf state) node).log))
          authorityKnownNewFrontier
      have authorityBound :
          knownEvidence.authority.index <= frontier :=
        configurationIndexLeOfMemTake
          ((nodeOf state) node).log frontier knownEvidence.authority
          authorityKnownNewFrontier
      have currentAfterAuthority :=
        configuration_index_le_currentConfiguration
          { ((nodeOf state) node) with commitIndex := frontier }
          knownEvidence.authority authorityKnownNode authorityBound
      have contradiction :
          knownEvidence.authority.index <= newConfiguration.index := by
        simpa [currentConfiguration, newConfiguration] using currentAfterAuthority
      omega
  have knownAuthorityImplicitOfZeroAfter :
      forall knownEvidence supportedPrefix,
        KnownCommitEvidence
            (advanceCommitState state node)
            appendHistory newNodeEvidence requestEvidence
            knownEvidence supportedPrefix ->
        knownEvidence.authority.index = 0 ->
          knownEvidence.authority = implicitConfiguration := by
    intro knownEvidence supportedPrefix known zero
    have valid := knownCommitEvidenceValid evidenceAfter known
    have authorityKnown :
        knownEvidence.authority ∈
          allConfigurations knownEvidence.history := by
      have currentKnown :=
        currentConfiguration_mem_allConfigurations
          { ((nodeOf state) node) with
            log := knownEvidence.history
            commitIndex := knownEvidence.commitFrontier }
      simpa [
        currentConfiguration, valid.2.2.2.2.1
      ] using currentKnown
    apply
      allConfigurations_index_unique
        (TxId := TxId) knownEvidence.history
        authorityKnown
    · simp [allConfigurations, implicitConfiguration]
    · simpa [implicitConfiguration] using zero
  have authorityRecordedAfter :
      forall knownEvidence supportedPrefix,
        KnownCommitEvidence
            (advanceCommitState state node)
            appendHistory newNodeEvidence requestEvidence
            knownEvidence supportedPrefix ->
          knownEvidence.authority = implicitConfiguration \/
            Exists fun activationIndex =>
              Exists fun record =>
                newActivations activationIndex = some record /\
                  knownEvidence.authority ∈ record.governingActive /\
                  record.activationTerm <= knownEvidence.commitTerm := by
    intro knownEvidence supportedPrefix known
    rcases
        knownNewOrOld knownEvidence supportedPrefix known with
      new | old
    · rcases new with ⟨new, _supported⟩
      subst knownEvidence
      by_cases zero : newConfiguration.index = 0
      · left
        have newImplicit :
            newConfiguration = implicitConfiguration := by
          apply
            allConfigurations_index_unique
              (TxId := TxId) ((nodeOf state) node).log
              newConfigurationKnown
          · simp [allConfigurations, implicitConfiguration]
          · simpa [implicitConfiguration] using zero
        simpa [evidence, newConfiguration] using newImplicit
      · right
        rcases
            configurationActivationsAfter node
              (by simpa [currentConfigurationNodeEq] using
                Nat.pos_of_ne_zero zero) with
          ⟨witness⟩
        exact ⟨
          witness.activationIndex,
          witness.activation,
          witness.stored,
          by
            simpa [evidence, currentConfigurationNodeEq]
              using witness.configurationCovered,
          by simpa [evidence, termEq] using witness.activationTermBound
        ⟩
    · rcases
          activationEvidence.authorityRecorded
            knownEvidence supportedPrefix old with
        implicit | recorded
      · exact Or.inl implicit
      · right
        rcases recorded with
          ⟨activationIndex, record, stored, governing, termBound⟩
        by_cases create : replaceActivation
        · have different : Not (activationIndex = newActivationKey) := by
            intro same
            have absent := activationAbsentAtNew create
            rw [← same, stored] at absent
            exact Option.some_ne_none _ absent
          exact ⟨
            activationIndex,
            record,
            by simpa [
                newActivations, create, Function.update, different
              ] using stored,
            governing,
            termBound
          ⟩
        · exact ⟨
            activationIndex,
            record,
            by simpa [newActivations, create] using stored,
            governing,
            termBound
          ⟩
  have knownAuthorityEqNewOfSameIndex
      (knownEvidence : CommitEvidence Node TxId)
      (supportedPrefix : List (Entry Node TxId))
      (known :
        KnownCommitEvidence
          (advanceCommitState state node)
          appendHistory newNodeEvidence requestEvidence
          knownEvidence supportedPrefix)
      (sameIndex :
        knownEvidence.authority.index = newConfiguration.index) :
      knownEvidence.authority = newConfiguration := by
    have valid := knownCommitEvidenceValid evidenceAfter known
    have authorityKnownHistory :
        knownEvidence.authority ∈
          allConfigurations knownEvidence.history := by
      have currentKnown :=
        currentConfiguration_mem_allConfigurations
          { (nodeOf state) node with
            log := knownEvidence.history
            commitIndex := knownEvidence.commitFrontier }
      simpa [currentConfiguration, valid.2.2.2.2.1] using currentKnown
    have authorityWithin :
        knownEvidence.authority.index <= knownEvidence.commitFrontier := by
      let evidenceNode : NodeState Node TxId :=
        { (nodeOf state) node with
          log := knownEvidence.history
          commitIndex := knownEvidence.commitFrontier }
      have bound := currentConfiguration_index_le_commitIndex evidenceNode
      simpa [
        evidenceNode, currentConfiguration, valid.2.2.2.2.1
      ] using bound
    have authorityKnownFrontier :=
      allConfigurations_mem_take_of_index_le
        knownEvidence.history knownEvidence.commitFrontier valid.1
        authorityKnownHistory authorityWithin
    rcases
        newFrontierComparableKnownAfter
          knownEvidence supportedPrefix known with
      newBefore | knownBefore
    · have newKnownEvidence :
          newConfiguration ∈ allConfigurations knownEvidence.history := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix
                knownEvidence.commitFrontier knownEvidence.history))
        exact
          memOfPrefix
            (allConfigurations_mono_prefix newBefore)
            newConfigurationKnownAtFrontier
      exact
        allConfigurations_index_unique
          (TxId := TxId) knownEvidence.history
          authorityKnownHistory newKnownEvidence sameIndex
    · have authorityKnownNode :
          knownEvidence.authority ∈
            allConfigurations ((nodeOf state) node).log := by
        apply
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix frontier ((nodeOf state) node).log))
        exact
          memOfPrefix
            (allConfigurations_mono_prefix knownBefore)
            authorityKnownFrontier
      exact
        allConfigurations_index_unique
          (TxId := TxId) ((nodeOf state) node).log
          authorityKnownNode newConfigurationKnown sameIndex
  have activationEvidenceAfter :
      ActivationEvidenceFacts (joined := joinedNodes)
        (advanceCommitState state node)
        appendHistory responseHistory newNodeEvidence requestEvidence
          elections newActivations := by
    constructor
    · exact authorityRecordedAfter
    · intro left leftPrefix leftKnown right rightPrefix rightKnown same
      rcases
          knownNewOrOld left leftPrefix leftKnown with
        leftNew | leftOld
      · rcases leftNew with ⟨leftEq, _⟩
        subst left
        exact (knownAuthorityEqNewOfSameIndex
                right rightPrefix rightKnown
                (by simpa [evidence] using same.symm)).symm
      · rcases
            knownNewOrOld right rightPrefix rightKnown with
          rightNew | rightOld
        · rcases rightNew with ⟨rightEq, _⟩
          subst right
          exact
            knownAuthorityEqNewOfSameIndex
              left leftPrefix leftKnown
              (by simpa [evidence] using same)
        · exact
            activationEvidence.authorityIndexUnique
              left leftPrefix leftOld right rightPrefix rightOld same
    · intro earlier earlierPrefix earlierKnown
        later laterPrefix laterKnown order
      rcases
          knownNewOrOld earlier earlierPrefix earlierKnown with
        earlierNew | earlierOld
      · rcases earlierNew with ⟨earlierNew, _earlierPrefix⟩
        subst earlier
        rcases
            knownNewOrOld later laterPrefix laterKnown with
          laterNew | laterOld
        · rcases laterNew with ⟨laterNew, _laterPrefix⟩
          subst later
          omega
        · simpa [evidence, newConfiguration]
            using newFrontierBeforeKnownOfAuthorityAfter
              later laterPrefix laterKnown
              (by simpa [evidence, newConfiguration] using order)
      · rcases
            knownNewOrOld later laterPrefix laterKnown with
          laterNew | laterOld
        · rcases laterNew with ⟨laterNew, laterPrefixEq⟩
          subst later
          have fullFrontier :=
            knownFrontierBeforeNewOfAuthorityBefore
              earlier earlierPrefix earlierKnown
              (by simpa [evidence, newConfiguration] using order)
          simpa [evidence] using fullFrontier
        · exact
            activationEvidence.authorityBridge
              earlier earlierPrefix earlierOld
              later laterPrefix laterOld order
    · intro left leftPrefix leftKnown right rightPrefix rightKnown
      have supportedInCommit
          (knownEvidence : CommitEvidence Node TxId)
          (knownPrefix : List (Entry Node TxId))
          (known :
            KnownCommitEvidence
              (advanceCommitState state node)
              appendHistory newNodeEvidence requestEvidence
              knownEvidence knownPrefix) :
          knownEvidence.history.take knownEvidence.supportedLength <+:
            knownEvidence.history.take knownEvidence.commitFrontier := by
        have valid := knownCommitEvidenceValid evidenceAfter known
        rw [List.prefix_take_iff]
        exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans valid.2.2.1⟩
      rcases knownNewOrOld left leftPrefix leftKnown with
        leftNew | leftOld
      · rcases leftNew with ⟨leftEq, _⟩
        subst left
        rcases knownNewOrOld right rightPrefix rightKnown with
          rightNew | rightOld
        · rcases rightNew with ⟨rightEq, _⟩
          subst right
          exact Or.inl (prefixRefl _)
        · rcases
              newFrontierComparableKnownAfter
                right rightPrefix rightKnown with
            newBefore | rightBefore
          · simpa [evidence]
              using prefixesComparable
                newBefore
                (supportedInCommit right rightPrefix rightKnown)
          · exact Or.inr (by
              simpa [evidence] using
                (supportedInCommit right rightPrefix rightKnown).trans
                  rightBefore)
      · rcases knownNewOrOld right rightPrefix rightKnown with
          rightNew | rightOld
        · rcases rightNew with ⟨rightEq, _⟩
          subst right
          rcases
              newFrontierComparableKnownAfter
                left leftPrefix leftKnown with
            newBefore | leftBefore
          · rcases
                prefixesComparable
                  newBefore
                  (supportedInCommit left leftPrefix leftKnown) with
              newInLeft | leftInNew
            · exact Or.inr (by simpa [evidence] using newInLeft)
            · exact Or.inl (by simpa [evidence] using leftInNew)
          · exact Or.inl (by
              simpa [evidence] using
                (supportedInCommit left leftPrefix leftKnown).trans
                  leftBefore)
        · exact
            activationEvidence.supportedPrefixesComparable
              left leftPrefix leftOld right rightPrefix rightOld
    · intro knownEvidence supportedPrefix known
        candidate role majority newer
      rcases
          knownNewOrOld knownEvidence supportedPrefix known with
        new | old
      · rcases new with ⟨new, _supported⟩
        subst knownEvidence
        have frontierEffectiveAfter :
            hasEffectiveMajorityAt (joined := joinedNodes)
              (advanceCommitState state node)
              responseHistory node frontier :=
          effectiveMajorityNodeAfterOfBefore frontier frontierEffective
        rcases
            candidateBridgeAfter
              node frontier roleNode
              (by simpa [logEq, termEq] using frontierValid.1)
              (by simpa [logEq] using frontierSignature)
              (effectiveMajorityImpliesPotential
                (advanceCommitState state node)
                appendHistory responseHistory node frontier
                frontierEffectiveAfter)
              candidate role majority
              (by simpa [evidence, termEq] using newer) with
          direct | shared
        · exact Or.inl (by simpa [evidence, logEq] using direct)
        · rcases shared with
            ⟨configuration, sourceActive, governs, candidateActive⟩
          have sourceParts :
              configuration ∈ allConfigurations ((nodeOf state) node).log /\
                newConfiguration.index <= configuration.index := by
            simpa [activeConfigurations, currentConfigurationNodeEq, logEq]
              using sourceActive
          have configurationBeforeNew :
              configuration.index <= newConfiguration.index := by
            have bound :=
              configuration_index_le_currentConfiguration
                { (nodeOf state) node with commitIndex := frontier }
                configuration sourceParts.1 governs
            simpa [
              currentConfiguration, newConfiguration
            ] using bound
          have configurationEq : configuration = newConfiguration :=
            allConfigurations_index_unique
              (TxId := TxId) ((nodeOf state) node).log
              sourceParts.1 newConfigurationKnown
              (Nat.le_antisymm
                configurationBeforeNew sourceParts.2)
          exact Or.inr (by simpa [evidence, configurationEq] using candidateActive)
      · have candidateNe : Not (candidate = node) := by
          intro same
          subst candidate
          exact nodeNotCandidate role
        rcases
            activationEvidence.candidateBridge
              knownEvidence supportedPrefix old candidate
              (by simpa [roleEq] using role)
              ((potentialElectionMajorityOtherEq
                candidate candidateNe).mp majority)
              (by simpa [termEq] using newer) with
          direct | authorityActive
        · exact Or.inl (by simpa [logEq] using direct)
        · exact Or.inr
            (by simpa [
              activeConfigurationsOtherEq candidate candidateNe
            ] using authorityActive)
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
      rw [commitNode, logEq]
      exact frontierBound
    · rw [commitOther candidate same, logEq]
      exact facts.commitIndicesBounded candidate
  · intro candidate
    rw [termEq]
    intro active
    exact
      facts.currentTermsPositive candidate
        (by simpa [roleEq] using active)
  · intro candidate entry member
    rw [logEq] at member
    rw [termEq]
    exact facts.entriesDoNotExceedCurrentTerm candidate entry member
  · intro candidate role
    rw [roleEq] at role
    rw [votedEq, votesEq]
    exact facts.candidatesSelfVote candidate role
  · intro leader role
    have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
    have old := facts.leadersHaveElectionWitness leader oldRole
    rw [termEq]
    rcases old with bootstrap | majority
    · exact Or.inl bootstrap
    · exact Or.inr (by simpa [logEq, votesEq] using majority)
  · intro leader role peer
    rw [roleEq] at role
    have old := facts.leaderProgressBounded leader role peer
    rw [sentEq, matchEq, logEq]
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
      rw [roleEq] at active
      rw [votesEq] at member
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
      exact old.2.2.trans (committedMonotonic request.1)
    · intro destination response member
      rw [networkEq] at member
      simpa [SuccessfulResponseSnapshot, termEq, roleEq, logEq]
        using facts.networkHistory.appendResponse destination response member
    · intro destination request member
      rw [networkEq] at member
      simpa [termEq, roleEq, logEq]
        using facts.networkHistory.voteRequest destination request member
    · intro destination response member granted
      rw [networkEq] at member
      rcases
          facts.networkHistory.voteResponse destination response member granted with
        ⟨termBound, vote, upToDate⟩
      exact ⟨
        by simpa [termEq] using termBound,
        vote,
        by simpa [voteLogUpToDate] using upToDate
      ⟩
  · refine ⟨
      owners,
      canonicalHistory,
      elections,
      newActivations,
      newNodeEvidence,
      requestEvidence,
      ownershipAfter,
      electionFactsAfter,
      configurationFactsAfter,
      voteCanonicalAfter,
      temporalFacts.1,
      temporalFacts.2.1,
      activationVoteHistoryAfter,
      temporalFacts.2.2,
      ackerActivationAfter,
      electionQueuedFacts,
      activationProgressAfter,
      activationQuorumsAfter,
      evidenceAfter,
      prospectiveAfter,
      activationEvidenceAfter,
      activationCanonicalAfter,
      activationElectionsAfter,
      configurationActivationsAfter
    ⟩
  · intro candidate voter active member
    rw [termEq candidate, termEq voter]
    rw [roleEq] at active
    have oldMember :
        voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    simpa [voteLogUpToDate, logEq]
      using facts.grantedVoteSnapshots candidate voter active oldMember
  · refine ⟨ackHistory, ?_⟩
    constructor
    · intro leader role peer zero
      exact
        ackFacts.zero leader
          (by simpa [roleEq] using role)
          peer (by simpa [matchEq] using zero)
    · intro leader role peer positive
      rcases
          ackFacts.positive leader
            (by simpa [roleEq] using role)
            peer (by simpa [matchEq] using positive) with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      exact ⟨
        snapshot,
        stored,
        by simpa [termEq] using snapshotTerm,
        by simpa [matchEq] using snapshotIndex,
        historyBound,
        by simpa [logEq] using agreed
      ⟩
  · apply joinedCarrierFactsFrame
      state (advanceCommitState state node)
      facts.joinedCarriers
      (by simp [advanceCommitState, Model.Local.advanceCommit, present])
    · intro candidate configuration active
      by_cases candidateEq : candidate = node
      · subst candidate
        exact activeConfigurationsNodeSubset configuration active
      · rw [activeConfigurationsOtherEq candidate candidateEq] at active
        exact active
    · intro candidate configuration member
      simpa [logEq] using member
    · intro candidate peer member
      simpa [votesEq] using member
    · intro candidate active
      simpa [advanceCommitState, Model.Local.advanceCommit, present]
        using facts.joinedCarriers.runtimeNodes.activeRoles candidate
          (by simpa [roleEq] using active)
    · intro leader peer positive
      simpa [advanceCommitState, Model.Local.advanceCommit, present]
        using facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
          (by simpa [matchEq] using positive)
    · intro candidate nonempty
      simpa [advanceCommitState, Model.Local.advanceCommit, present]
        using facts.joinedCarriers.runtimeNodes.nonemptyLogs candidate
          (by simpa [logEq] using nonempty)
    · intro destination message member
      simpa [advanceCommitState, Model.Local.advanceCommit, present] using member
  · intro candidate
    simpa only [termEq] using facts.currentTermsValid candidate
  · simpa only [NetworkTermsValid, networkEq] using facts.networkTermsValid

end CCFRaft.Proofs.Invariant
