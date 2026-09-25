-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Candidate
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

/-- Observing a queued newer term steps down without changing log history. -/
lemma updateTermPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (destination : Node)
    {present : destination ∈ state.nodes.map Prod.fst}
    (selected : Model.Envelope Node TxId)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (selectedMember : selected ∈ state.network ∧ selected.target = destination)
    (newer : ((nodeOf state) destination).currentTerm < selected.payload.term)
    : SystemInductiveInvariant (joined := joinedNodes)
        (observeTermEffect state destination selected.payload.term) := by
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
  have activationVoteHistoryAfter :
      ActivationVoteHistory
        votes voteVoterHistory elections activations := by
    apply
      activationVoteHistoryFrame
        votes votes voteVoterHistory voteVoterHistory
          elections activations activationVoteHistory
    · intro _ _ _ _ _ _ _ voted _ _
      exact voted
    · intro _ _ _ _ retained
      exact retained
  have selectedTermBound : BOOTSTRAP_TERM <= selected.payload.term := by
    rcases facts.networkTermsValid destination selected selectedMember with
      zero | bound
    · simp [zero] at newer
    · exact bound
  have roleDestination :
      ((nodeOf (observeTermEffect state destination selected.payload.term)) destination).role =
        .follower := by
    simp [concrete_effects, updateTerm, newer, present]
  have termDestination :
      ((nodeOf (observeTermEffect state destination selected.payload.term)) destination).currentTerm =
        selected.payload.term := by
    simp [concrete_effects, updateTerm, newer, present]
  have votedDestination :
      ((nodeOf (observeTermEffect state destination selected.payload.term)) destination).votedFor =
        none := by
    simp [concrete_effects, updateTerm, newer, present]
  have roleOther :
      forall node,
        Not (node = destination) ->
        ((nodeOf (observeTermEffect state destination selected.payload.term)) node).role =
          ((nodeOf state) node).role := by
    intro node different
    simp [
      concrete_effects, updateTerm, newer, present, nodeOf_replaceNode, different
    ]
  have termOther :
      forall node,
        Not (node = destination) ->
        ((nodeOf (observeTermEffect state destination selected.payload.term)) node).currentTerm =
          ((nodeOf state) node).currentTerm := by
    intro node different
    simp [
      concrete_effects, updateTerm, newer, present, nodeOf_replaceNode, different
    ]
  have votedOther :
      forall node,
        Not (node = destination) ->
        ((nodeOf (observeTermEffect state destination selected.payload.term)) node).votedFor =
          ((nodeOf state) node).votedFor := by
    intro node different
    simp [
      concrete_effects, updateTerm, newer, present, nodeOf_replaceNode, different
    ]
  have logEq :
      forall node,
        ((nodeOf (observeTermEffect state destination selected.payload.term)) node).log =
          ((nodeOf state) node).log := by
    intro node
    by_cases same : node = destination <;>
      simp [
        concrete_effects, updateTerm, newer, present, nodeOf_replaceNode, same
      ]
  have commitEq :
      forall node,
        ((nodeOf (observeTermEffect state destination selected.payload.term)) node).commitIndex =
          ((nodeOf state) node).commitIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        concrete_effects, updateTerm, newer, present, nodeOf_replaceNode, same
      ]
  have lastIndexEq :
      forall node,
        lastCommittableIndex
            ((nodeOf (observeTermEffect state destination selected.payload.term)) node) =
          lastCommittableIndex ((nodeOf state) node) := by
    intro node
    exact lastCommittableIndexFrame (logEq node) (commitEq node)
  have lastTermEq :
      forall node,
        lastCommittableTerm
            ((nodeOf (observeTermEffect state destination selected.payload.term)) node) =
          lastCommittableTerm ((nodeOf state) node) := by
    intro node
    exact lastCommittableTermFrame (logEq node) (commitEq node)
  have committedEq :
      forall node,
        ((nodeOf (observeTermEffect state destination selected.payload.term)) node).committedLog =
          ((nodeOf state) node).committedLog := by
    intro node
    simp [NodeState.committedLog, commitEq, logEq]
  have activeConfigurationsEq :
      forall node,
        activeConfigurations
            ((nodeOf (observeTermEffect state destination selected.payload.term)) node) =
          activeConfigurations ((nodeOf state) node) := by
    intro node
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have sentEq :
      forall node,
        ((nodeOf (observeTermEffect state destination selected.payload.term)) node).sentIndex =
          ((nodeOf state) node).sentIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        concrete_effects, updateTerm, newer, present, nodeOf_replaceNode, same
      ]
  have matchEq :
      forall node,
        ((nodeOf (observeTermEffect state destination selected.payload.term)) node).matchIndex =
          ((nodeOf state) node).matchIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        concrete_effects, updateTerm, newer, present, nodeOf_replaceNode, same
      ]
  have votesEq :
      forall node,
        ((nodeOf (observeTermEffect state destination selected.payload.term)) node).votesGranted =
          ((nodeOf state) node).votesGranted := by
    intro node
    by_cases same : node = destination <;>
      simp [
        concrete_effects, updateTerm, newer, present, nodeOf_replaceNode, same
      ]
  have networkEq :
      (observeTermEffect state destination selected.payload.term).network =
        state.network := by
    simp [concrete_effects, updateTerm, newer, present]
  have effectiveAckersEq :
      forall leader,
        Not (leader = destination) ->
          forall index,
            effectiveAckers (joined := joinedNodes)
                (observeTermEffect state destination selected.payload.term)
                responseHistory leader index =
              effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
    intro leader leaderNe index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter]
    constructor
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨
          by simpa [concrete_effects, updateTerm, newer, present] using joined,
          Or.inl self
        ⟩
      · exact ⟨
          by simpa [concrete_effects, updateTerm, newer, present] using joined,
          Or.inr (Or.inl (by simpa [matchEq] using matched))
        ⟩
      · refine ⟨
          by simpa [concrete_effects, updateTerm, newer, present] using joined,
          Or.inr (Or.inr ?_)
        ⟩
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact ⟨
          response,
          by simpa [networkEq] using member,
          success,
          by simpa [termOther leader leaderNe] using term,
          sourceEq,
          destinationEq,
          lastIndex,
          by simpa [logEq] using covered
        ⟩
    · rintro ⟨joined, self | matched | queued⟩
      · exact ⟨
          by simpa [concrete_effects, updateTerm, newer, present] using joined,
          Or.inl self
        ⟩
      · exact ⟨
          by simpa [concrete_effects, updateTerm, newer, present] using joined,
          Or.inr (Or.inl (by simpa [matchEq] using matched))
        ⟩
      · refine ⟨
          by simpa [concrete_effects, updateTerm, newer, present] using joined,
          Or.inr (Or.inr ?_)
        ⟩
        rcases queued with
          ⟨response, member, success, term, sourceEq,
            destinationEq, lastIndex, covered⟩
        exact ⟨
          response,
          by simpa [networkEq] using member,
          success,
          by simpa [termOther leader leaderNe] using term,
          sourceEq,
          destinationEq,
          lastIndex,
          by simpa [logEq] using covered
        ⟩
  have effectiveMajorityEq :
      forall leader,
        Not (leader = destination) ->
          forall index,
            hasEffectiveMajorityAt (joined := joinedNodes)
                (observeTermEffect state destination selected.payload.term)
                responseHistory leader index ↔
              hasEffectiveMajorityAt (joined := joinedNodes) state responseHistory leader index := by
    intro leader leaderNe index
    simp only [
      hasEffectiveMajorityAt, activeConfigurationsEq,
      effectiveAckersEq leader leaderNe index
    ]
  have effectiveElectionVotersEq :
      forall candidate,
        Not (candidate = destination) ->
          effectiveElectionVoters (joined := joinedNodes)
              (observeTermEffect state destination selected.payload.term) candidate =
            effectiveElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate candidateNe
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [concrete_effects, updateTerm, newer, present] using joined,
          Or.inl (by simpa [votesEq] using processed)
        ⟩
      · refine ⟨
          by simpa [concrete_effects, updateTerm, newer, present] using joined,
          Or.inr ?_
        ⟩
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact ⟨
          response,
          by simpa [networkEq] using member,
          granted,
          by simpa [termOther candidate candidateNe] using responseTerm,
          responseSource,
          responseDestination
        ⟩
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          by simpa [concrete_effects, updateTerm, newer, present] using joined,
          Or.inl (by simpa [votesEq] using processed)
        ⟩
      · refine ⟨
          by simpa [concrete_effects, updateTerm, newer, present] using joined,
          Or.inr ?_
        ⟩
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact ⟨
          response,
          by simpa [networkEq] using member,
          granted,
          by simpa [termOther candidate candidateNe] using responseTerm,
          responseSource,
          responseDestination
        ⟩
  have effectiveElectionMajorityEq :
      forall candidate,
        Not (candidate = destination) ->
          (hasEffectiveElectionMajority (joined := joinedNodes)
              (observeTermEffect state destination selected.payload.term) candidate ↔
            hasEffectiveElectionMajority (joined := joinedNodes) state candidate) := by
    intro candidate candidateNe
    simp only [
      hasEffectiveElectionMajority, activeConfigurationsEq,
      effectiveElectionVotersEq candidate candidateNe
    ]
  have potentialAckersBack :
      forall leader,
        Not (leader = destination) ->
          forall index,
            potentialAckers (joined := joinedNodes)
                (observeTermEffect state destination selected.payload.term)
                appendHistory responseHistory leader index ⊆
              potentialAckers (joined := joinedNodes)
                state appendHistory responseHistory leader index := by
    intro leader leaderNe index peer member
    simp only [
      potentialAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | reserve⟩
    · exact ⟨
        by simpa [concrete_effects, updateTerm, newer, present] using joined,
        Or.inl
          (by
            rw [effectiveAckersEq leader leaderNe index] at effective
            exact effective)
      ⟩
    · refine ⟨
        by simpa [concrete_effects, updateTerm, newer, present] using joined,
        Or.inr ?_
      ⟩
      rcases reserve with
        ⟨request, queued, requestSource, requestDestination,
          requestTerm, producible, covered⟩
      have requestDestinationEq := requestDestination
      refine ⟨
        request,
        by simpa [networkEq] using queued,
        requestSource,
        requestDestination,
        by simpa [termOther leader leaderNe] using requestTerm,
        ?_,
        by simpa [logEq] using covered
      ⟩
      by_cases peerEq : peer = destination
      · have destinationEq : request.2.1 = destination :=
          requestDestinationEq.trans peerEq
        rcases producible with direct | future
        · rcases direct with
            ⟨nextNode, response, handled, success, acknowledged⟩
          have localPost :=
            acceptAppendEntriesRequestLocalPost handled
          have requestCurrent :
              request.2.2.term = selected.payload.term := by
            calc
              request.2.2.term
                  = ((nodeOf (observeTermEffect state destination selected.payload.term))
                      peer).currentTerm := by
                exact localPost.successfulCurrentTerm success
              _ = selected.payload.term := by
                rw [peerEq]
                exact termDestination
          exact Or.inr
            ⟨
              by simpa [peerEq, requestCurrent] using newer,
              canProduceAppendAckAt_index_le_requestEnd
                ⟨nextNode, response, handled, success, acknowledged⟩
            ⟩
        · exact Or.inr
            ⟨by simpa [peerEq] using
                newer.trans
                  (by simpa [
                    peerEq, termDestination
                  ] using future.1),
              future.2⟩
      · simpa [
          concrete_effects, updateTerm, newer, present, nodeOf_replaceNode,
          Function.update, peerEq
        ] using producible
  have potentialMajorityBack :
      forall leader,
        Not (leader = destination) ->
          forall index,
            hasPotentialMajorityAt (joined := joinedNodes)
                (observeTermEffect state destination selected.payload.term)
                appendHistory responseHistory leader index ->
              hasPotentialMajorityAt (joined := joinedNodes)
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
            ((nodeOf (observeTermEffect state destination selected.payload.term))
              leader) := by
      simpa [activeConfigurationsEq] using active
    exact
      hasConfigurationMajority_mono
        (potentialAckersBack leader leaderNe index)
        ((of_decide_eq_true
          (majority configuration afterActive)) governs)
  have termMonotone :
      forall node,
        ((nodeOf state) node).currentTerm <=
          ((nodeOf (observeTermEffect state destination selected.payload.term))
            node).currentTerm := by
    intro node
    by_cases nodeEq : node = destination
    · subst node
      rw [termDestination]
      exact newer.le
    · exact Nat.le_of_eq (termOther node nodeEq).symm
  have voteFactsAfter :
      VoteHistoryFacts
        (observeTermEffect state destination selected.payload.term) votes := by
    constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      by_cases voterEq : voter = destination
      · subst voter
        rw [termDestination, votedDestination]
        exact facts.voteHistory.future destination selected.payload.term newer
      · rw [termOther voter voterEq, votedOther voter voterEq]
        exact facts.voteHistory.current voter
    · intro voter term future
      by_cases voterEq : voter = destination
      · subst voter
        rw [termDestination] at future
        exact
          facts.voteHistory.future destination term
            (Nat.lt_trans newer future)
      · rw [termOther voter voterEq] at future
        exact facts.voteHistory.future voter term future
    · intro candidate voter active member
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        rcases active with candidateRole | leaderRole
        · exact Role.noConfusion
            (candidateRole.symm.trans roleDestination)
        · exact Role.noConfusion
            (leaderRole.symm.trans roleDestination)
      rw [roleOther candidate candidateNe] at active
      rw [votesEq] at member
      rw [termOther candidate candidateNe]
      exact facts.voteHistory.counted candidate voter active member
  have temporalFacts :=
    ackerTemporalFrameSameLogs
      state (observeTermEffect state destination selected.payload.term)
        votes votes responseHistory voteVoterHistory elections
        ackerCurrentFacts ackerVoteFacts ackerElectionFacts
        (fun leader role => by
          have leaderNe : Not (leader = destination) := by
            intro same
            subst leader
            exact Role.noConfusion
              (role.symm.trans roleDestination)
          simpa [roleOther leader leaderNe] using role)
        (fun leader role => by
          have leaderNe : Not (leader = destination) := by
            intro same
            subst leader
            exact Role.noConfusion
              (role.symm.trans roleDestination)
          exact termOther leader leaderNe)
        logEq
        (fun leader index voter role _ member => by
          have leaderNe : Not (leader = destination) := by
            intro same
            subst leader
            exact Role.noConfusion
              (role.symm.trans roleDestination)
          rw [effectiveAckersEq leader leaderNe index] at member
          exact member)
        termMonotone
        (fun _ _ _ voted _ => voted)
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
  · intro node
    rw [commitEq, logEq]
    exact facts.commitIndicesBounded node
  · intro node participating
    by_cases same : node = destination
    · subst node
      rw [termDestination]
      exact selectedTermBound
    · rw [termOther node same]
      apply facts.currentTermsPositive node
      intro none
      apply participating
      simpa [roleOther node same] using none
  · intro node entry member
    rw [logEq] at member
    by_cases same : node = destination
    · subst node
      rw [termDestination]
      exact
        Nat.le_trans
          (facts.entriesDoNotExceedCurrentTerm destination entry member)
          newer.le
    · rw [termOther node same]
      exact facts.entriesDoNotExceedCurrentTerm node entry member
  · intro node role
    have nodeNe : Not (node = destination) := by
      intro same
      subst node
      exact Role.noConfusion (role.symm.trans roleDestination)
    rw [roleOther node nodeNe] at role
    rw [votedOther node nodeNe, votesEq]
    exact facts.candidatesSelfVote node role
  · intro node role
    have nodeNe : Not (node = destination) := by
      intro same
      subst node
      exact Role.noConfusion (role.symm.trans roleDestination)
    rw [roleOther node nodeNe] at role
    have old := facts.leadersHaveElectionWitness node role
    rw [termOther node nodeNe]
    rcases old with bootstrap | majority
    · exact Or.inl bootstrap
    · exact Or.inr (by simpa [logEq, votesEq] using majority)
  · intro leader role peer
    have leaderNe : Not (leader = destination) := by
      intro same
      subst leader
      exact Role.noConfusion (role.symm.trans roleDestination)
    rw [roleOther leader leaderNe] at role
    have old := facts.leaderProgressBounded leader role peer
    rw [sentEq, matchEq, logEq]
    exact old
  · exact voteFactsAfter
  · constructor
    · intro queuedDestination message member
      rw [networkEq] at member
      exact
        facts.networkHistory.addressed
          queuedDestination message member
    · intro queuedDestination request member
      rw [networkEq] at member
      have old :=
        facts.networkHistory.appendRequest
          queuedDestination request member
      refine ⟨old.1, old.2.1, ?_⟩
      unfold RequestCommitStillPresent at old ⊢
      rw [committedEq]
      exact old.2.2
    · intro queuedDestination response member success
      rw [networkEq] at member
      have responseDestination :
          response.2.1 = queuedDestination := by
        simpa using
          facts.networkHistory.addressed
            queuedDestination (appendResponseEnvelope response) member
      subst queuedDestination
      rcases
          facts.networkHistory.appendResponse
            response.2.1 response member success with
        ⟨lengthBound, termBound, supported⟩
      refine ⟨lengthBound, ?_, ?_⟩
      · by_cases destinationEq : response.2.1 = destination
        · rw [destinationEq, termDestination]
          exact Nat.le_trans (by simpa [destinationEq] using termBound) newer.le
        · simpa [termOther response.2.1 destinationEq] using termBound
      intro sameTerm
      by_cases destinationEq : response.2.1 = destination
      · have impossibleOldTerm :
            response.2.2.term >
              ((nodeOf state) response.2.1).currentTerm := by
          rw [destinationEq, termDestination] at sameTerm
          rw [destinationEq]
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
    · intro queuedDestination request member
      rw [networkEq] at member
      rcases
          facts.networkHistory.voteRequest
            queuedDestination request member with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      refine ⟨lastIndex, lastTerm, maxIndex, aboveBootstrap, ?_, ?_⟩
      · by_cases sourceEq : request.1 = destination
        · have oldBound :
              request.2.2.term <=
                ((nodeOf state) destination).currentTerm := by
            simpa [sourceEq] using termBound
          rw [sourceEq, termDestination]
          exact Nat.le_trans oldBound newer.le
        · simpa [termOther request.1 sourceEq] using termBound
      · intro sameTerm active
        by_cases sourceEq : request.1 = destination
        · have oldBound :
              request.2.2.term <=
                ((nodeOf state) destination).currentTerm := by
            simpa [sourceEq] using termBound
          have newSame :
              request.2.2.term = selected.payload.term := by
            simpa [sourceEq, termDestination] using sameTerm
          omega
        · have oldPrefix :=
            activePrefix
              (by simpa [termOther request.1 sourceEq] using sameTerm)
              (by simpa [roleOther request.1 sourceEq] using active)
          simpa [logEq] using oldPrefix
    · intro queuedDestination response member granted
      rw [networkEq] at member
      rcases
          facts.networkHistory.voteResponse
            queuedDestination response member granted with
        ⟨oldBound, oldVote, upToDate⟩
      refine ⟨?_, oldVote, ?_⟩
      · by_cases responseDestinationEq :
            response.2.1 = destination
        · rw [responseDestinationEq, termDestination]
          exact
            Nat.le_trans
              (by simpa [responseDestinationEq] using oldBound)
              newer.le
        · simpa [
            termOther response.2.1 responseDestinationEq
          ] using oldBound
      · simpa [voteLogUpToDate] using upToDate
  have evidenceAfter :
      CommitEvidenceFacts
        (observeTermEffect state destination selected.payload.term)
        appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
        state (observeTermEffect state destination selected.payload.term)
        appendHistory nodeEvidence requestEvidence evidenceFacts
        commitEq committedEq
    · intro node
      by_cases nodeEq : node = destination
      · subst node
        rw [termDestination]
        exact newer.le
      · exact Nat.le_of_eq (termOther node nodeEq).symm
    · intro queuedDestination request member
      simpa [concrete_effects, updateTerm, newer, present] using member
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts (joined := joinedNodes)
        (observeTermEffect state destination selected.payload.term)
        appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state (observeTermEffect state destination selected.payload.term)
          appendHistory appendHistory
          nodeEvidence nodeEvidence requestEvidence requestEvidence
            elections prospectiveFacts
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state (observeTermEffect state destination selected.payload.term)
            appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun queuedDestination request member => by
              simpa [concrete_effects, updateTerm, newer, present] using member)
            known
    · intro member
      simp [logEq]
    · intro evidence supportedPrefix queuedDestination request
        known queued sameTerm
      left
      exact ⟨
        by simpa [concrete_effects, updateTerm, newer, present] using queued,
        rfl
      ⟩
    · intro evidence supportedPrefix candidate member known role
        newerEvidence entriesBefore ackMember relaxed
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleDestination)
      left
      refine ⟨
        by simpa [roleOther candidate candidateNe] using role,
        by simpa [termOther candidate candidateNe] using newerEvidence,
        ?_,
        ?_,
        ?_
      ⟩
      · intro entry entryMember
        simpa [termOther candidate candidateNe]
          using entriesBefore entry (by simpa [logEq] using entryMember)
      · simp only [
          relaxedElectionVoters, Finset.mem_filter] at relaxed ⊢
        rcases relaxed with ⟨joined, effective | supporter⟩
        · rw [effectiveElectionVotersEq candidate candidateNe] at effective
          exact ⟨
            by simpa [concrete_effects, updateTerm, newer, present] using joined,
            Or.inl effective
          ⟩
        · refine ⟨
            by simpa [concrete_effects, updateTerm, newer, present] using joined,
            Or.inr ⟨?_, ?_⟩
          ⟩
          · by_cases memberEq : member = destination
            · have oldTermLe :
                  ((nodeOf state) destination).currentTerm <=
                    ((nodeOf (observeTermEffect state destination selected.payload.term))
                        destination).currentTerm := by
                rw [termDestination]
                exact newer.le
              have afterBound := supporter.1
              rw [memberEq, termOther candidate candidateNe] at afterBound
              rw [memberEq]
              omega
            · simpa [termOther member memberEq,
                termOther candidate candidateNe] using supporter.1
          · simpa [
              voteRequestKey, Model.Local.makeRequestVoteRequest,
              termOther candidate candidateNe,
              logEq, lastIndexEq, lastTermEq,
              voteLogUpToDate
            ] using supporter.2
      · simp [logEq]
  have ownershipAfter :
      TermOwnershipFacts
        (observeTermEffect state destination selected.payload.term)
        votes appendHistory canonicalHistory owners := by
    constructor
    · exact ownership.bootstrap
    · intro leader role
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      rw [termOther leader leaderNe]
      exact ownership.activeLeader leader
        (by simpa [roleOther leader leaderNe] using role)
    · intro node index entry foundEntry
      rcases
          ownership.logEntryAgreement node index entry
            (by simpa [logEq] using foundEntry) with
        ⟨canonicalFound, agreed⟩
      exact ⟨canonicalFound, by simpa [logEq] using agreed⟩
    · intro queuedDestination request member index entry foundEntry
      exact
        ownership.queuedHistoryEntryAgreement
          queuedDestination request
            (by simpa [concrete_effects, updateTerm, newer, present] using member)
            index entry foundEntry
    · intro leader role
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      rw [termOther leader leaderNe]
      have oldRole : ((nodeOf state) leader).role = .leader := by
        simpa [roleOther leader leaderNe] using role
      simpa [logEq] using ownership.activeLeaderHistory leader oldRole
    · exact ownership.canonicalEntryOwner
    · exact ownership.canonicalMonoLog
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bound, oldLeader⟩
      by_cases ownerEq : owner = destination
      · subst owner
        constructor
        · rw [termDestination]
          omega
        · intro same
          rw [termDestination] at same
          omega
      · constructor
        · simpa [termOther owner ownerEq] using bound
        · intro same
          have oldSame :
              term = ((nodeOf state) owner).currentTerm := by
            simpa [termOther owner ownerEq] using same
          simpa [roleOther owner ownerEq] using oldLeader oldSame
    · intro queuedDestination request member
      exact
        ownership.queuedAppendMetadata queuedDestination request
          (by simpa [concrete_effects, updateTerm, newer, present] using member)
    · intro queuedDestination request member sameTerm leaderRole
      by_cases sourceEq : request.1 = destination
      · have afterLeader :
            ((nodeOf (observeTermEffect state destination selected.payload.term))
              destination).role = .leader := by
          simpa [sourceEq] using leaderRole
        exact False.elim
          (Role.noConfusion (afterLeader.symm.trans roleDestination))
      · have oldMember :
            (appendRequestEnvelope request ∈ state.network /\ request.2.1 = queuedDestination) := by
          simpa [concrete_effects, updateTerm, newer, present] using member
        have oldPrefix :=
          ownership.queuedActiveSourceHistory
            queuedDestination request oldMember
              (by simpa [termOther request.1 sourceEq] using sameTerm)
              (by simpa [roleOther request.1 sourceEq] using leaderRole)
        simpa [logEq] using oldPrefix
  have electionFactsAfter :
      ElectionHistoryFacts
        (observeTermEffect state destination selected.payload.term)
        votes canonicalHistory owners elections := by
    apply
      electionHistoryFrame
        state (observeTermEffect state destination selected.payload.term)
          votes votes canonicalHistory canonicalHistory
          owners elections electionFacts
    · intros
      rfl
    · intro term
      exact prefixRefl (canonicalHistory term)
    · intro history canonical
      exact canonical
  have activationProgressAfter :
      ActivationSupporterProgress
        (observeTermEffect state destination selected.payload.term) activations :=
    activationSupporterProgressFrame
      state (observeTermEffect state destination selected.payload.term)
        activations activationProgress termMonotone
  have currentConfigurationEq :
      forall node,
        currentConfiguration
            ((nodeOf (observeTermEffect state destination selected.payload.term)) node) =
          currentConfiguration ((nodeOf state) node) := by
    intro node
    unfold currentConfiguration
    rw [logEq, commitEq]
  have configurationActivationsAfter :
      ConfigurationCoverageFacts
        (observeTermEffect state destination selected.payload.term) activations := by
    apply
      configurationCoverageFrame
        configurationActivations currentConfigurationEq
        termMonotone commitEq
        (fun node frontier _ => by rw [logEq])
    · intro candidate witness role
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleDestination)
      simpa [termOther candidate candidateNe]
        using witness.candidateTermStrict
          (by simpa [roleOther candidate candidateNe] using role)
  have ackerActivationAfter :
      AckerActivationHistory (joined := joinedNodes)
        (observeTermEffect state destination selected.payload.term)
        responseHistory elections activations := by
    apply
      ackerActivationFrameSameLogs
        state (observeTermEffect state destination selected.payload.term)
          responseHistory elections elections activations
          ackerActivationFacts
    · intro leader role
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      simpa [roleOther leader leaderNe] using role
    · intro leader role
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      exact termOther leader leaderNe
    · exact logEq
    · intro leader index supporter role _ member
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      rw [effectiveAckersEq leader leaderNe index] at member
      exact member
    · intro _ _ stored
      exact stored
  have supporterCurrentAfter :
      ActivationSupporterCurrentHistory
        (observeTermEffect state destination selected.payload.term)
        elections activations := by
    apply
      activationSupporterCurrentHistoryFrame
        state (observeTermEffect state destination selected.payload.term)
          elections elections activations
          configurationFacts.supporterCurrentHistory
    · intro node
      rw [logEq]
    · exact termMonotone
    · intro _ _ stored
      exact stored
  have configurationFactsAfter :
      ElectionConfigurationFacts (joined := joinedNodes)
        (observeTermEffect state destination selected.payload.term)
        elections activations := by
    apply
      electionConfigurationFrame
        state (observeTermEffect state destination selected.payload.term)
          elections activations activations configurationFacts
    · intro _ _ stored
      exact stored
    · exact supporterCurrentAfter
    · intro candidate role majority
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleDestination)
      exact ⟨
        by simpa [roleOther candidate candidateNe] using role,
        termOther candidate candidateNe,
        (effectiveElectionMajorityEq candidate candidateNe).mp majority
      ⟩
    · intro candidate configuration role active
      simpa [activeConfigurationsEq] using active
    · intro candidate role entry member
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleDestination)
      simpa [termOther candidate candidateNe]
        using configurationFacts.candidateEntriesBeforeTerm
          candidate
          (by simpa [roleOther candidate candidateNe] using role)
          entry
          (by simpa [logEq] using member)
  have termsPositiveAfter :
      CurrentTermsPositive
        (observeTermEffect state destination selected.payload.term) := by
    intro node participating
    by_cases nodeEq : node = destination
    · subst node
      rw [termDestination]
      exact selectedTermBound
    · rw [termOther node nodeEq]
      apply facts.currentTermsPositive node
      intro none
      apply participating
      simpa [roleOther node nodeEq] using none
  have entriesBoundedAfter :
      EntriesDoNotExceedCurrentTerm
        (observeTermEffect state destination selected.payload.term) := by
    intro node entry member
    rw [logEq] at member
    exact (facts.entriesDoNotExceedCurrentTerm node entry member).trans
      (termMonotone node)
  have committedSignatureAfter :
      CommittedFrontierIsSignature
        (observeTermEffect state destination selected.payload.term) := by
    intro node positive
    have oldPositive : 0 < ((nodeOf state) node).commitIndex := by
      simpa [commitEq] using positive
    simpa [commitEq, logEq]
      using (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
              facts node oldPositive)
  have voteCanonicalFactsAfter :
      GrantedVoteCanonicalSnapshots (joined := joinedNodes)
        (observeTermEffect state destination selected.payload.term)
        canonicalHistory voteCandidateHistory voteVoterHistory := by
    apply
      grantedVoteCanonicalFrame
        state (observeTermEffect state destination selected.payload.term)
          canonicalHistory canonicalHistory
          voteCandidateHistory voteVoterHistory voteCanonicalFacts
          (fun candidate active => by
            have candidateNe : Not (candidate = destination) := by
              intro same
              subst candidate
              rcases active with candidateRole | leaderRole
              · exact Role.noConfusion
                  (candidateRole.symm.trans roleDestination)
              · exact Role.noConfusion
                  (leaderRole.symm.trans roleDestination)
            exact termOther candidate candidateNe)
    · intro candidate active
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        rcases active with candidateRole | leaderRole
        · exact Role.noConfusion
            (candidateRole.symm.trans roleDestination)
        · exact Role.noConfusion
            (leaderRole.symm.trans roleDestination)
      rw [roleOther candidate candidateNe] at active
      exact active
    · intro candidate voter active member
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        rcases active with candidateRole | leaderRole
        · exact Role.noConfusion
            (candidateRole.symm.trans roleDestination)
        · exact Role.noConfusion
            (leaderRole.symm.trans roleDestination)
      rw [effectiveElectionVotersEq candidate candidateNe] at member
      exact member
    · intro history canonical
      exact canonical
  have snapshotsAfter :
      GrantedVoteSnapshots (joined := joinedNodes)
        (observeTermEffect state destination selected.payload.term)
        votes voteCandidateHistory voteVoterHistory := by
    intro candidate voter active member
    have candidateNe : Not (candidate = destination) := by
      intro same
      subst candidate
      rcases active with candidateRole | leaderRole
      · exact Role.noConfusion (candidateRole.symm.trans roleDestination)
      · exact Role.noConfusion (leaderRole.symm.trans roleDestination)
    rw [termOther candidate candidateNe]
    have oldActive :
        ((nodeOf state) candidate).role = .candidate \/
          ((nodeOf state) candidate).role = .leader := by
      rw [roleOther candidate candidateNe] at active
      exact active
    have oldMember :
        voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
      rw [effectiveElectionVotersEq candidate candidateNe] at member
      exact member
    rcases
        facts.grantedVoteSnapshots
          candidate voter oldActive oldMember with
      ⟨recorded, self | snapshot⟩
    · exact ⟨recorded, Or.inl self⟩
    · rcases snapshot with
        ⟨candidatePrefix, candidateCommittable, voterCommittable,
          voterBound, upToDate⟩
      refine ⟨recorded, Or.inr ⟨?_, candidateCommittable, voterCommittable, ?_, ?_⟩⟩
      · simpa [logEq] using candidatePrefix
      · by_cases voterEq : voter = destination
        · subst voter
          rw [termDestination]
          exact Nat.le_trans voterBound newer.le
        · simpa [termOther voter voterEq] using voterBound
      · simpa [voteLogUpToDate] using upToDate
  have knownBack :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            (observeTermEffect state destination selected.payload.term)
            appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix := by
    intro evidence supportedPrefix known
    exact
      knownCommitEvidenceFrameBack
        state (observeTermEffect state destination selected.payload.term)
          appendHistory nodeEvidence requestEvidence
          commitEq committedEq
          (fun queuedDestination request member => by
            simpa [concrete_effects, updateTerm, newer, present] using member)
          known
  have updateTermEvidenceBridge :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            (observeTermEffect state destination selected.payload.term)
            appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
        forall candidate,
          ((nodeOf (observeTermEffect state destination selected.payload.term)) candidate).role =
              .candidate ->
          hasPotentialElectionMajority (joined := joinedNodes)
            (observeTermEffect state destination selected.payload.term) candidate ->
          evidence.commitTerm <
            ((nodeOf (observeTermEffect state destination selected.payload.term))
                candidate).currentTerm ->
            evidence.history.take evidence.commitFrontier <+:
                ((nodeOf (observeTermEffect state destination selected.payload.term)) candidate).log \/
              evidence.authority ∈
                activeConfigurations
                  ((nodeOf (observeTermEffect state destination selected.payload.term)) candidate) := by
    intro evidence supportedPrefix known candidate candidateRole
        candidateMajority evidenceBeforeCandidate
    have candidateNe : Not (candidate = destination) := by
      intro same
      subst candidate
      exact Role.noConfusion
        (candidateRole.symm.trans roleDestination)
    have candidateUnchanged :
        (nodeOf (observeTermEffect state destination selected.payload.term)) candidate =
          (nodeOf state) candidate := by
      simp [
        concrete_effects, updateTerm, newer, present, nodeOf_replaceNode, candidateNe
      ]
    have oldKnown := knownBack evidence supportedPrefix known
    let candidateConfiguration :=
      currentConfiguration ((nodeOf state) candidate)
    have directOfActive
        (authorityActive :
          evidence.authority ∈
            activeConfigurations
              ((nodeOf (observeTermEffect state destination selected.payload.term)) candidate)) :
        evidence.history.take evidence.commitFrontier <+:
          ((nodeOf (observeTermEffect state destination selected.payload.term)) candidate).log := by
      have valid := knownCommitEvidenceValid evidenceAfter known
      have electionMajority :=
        potentialElectionMajorityAtConfiguration
          candidateMajority authorityActive
      rcases
          configurationMajoritiesIntersect
            valid.2.2.2.2.2.1 electionMajority with
        ⟨member, _authorityMember, ackMember, electionMember⟩
      have relaxed :
          member ∈
            relaxedElectionVoters (joined := joinedNodes)
              (observeTermEffect state destination selected.payload.term)
              candidate := by
        simp only [
          potentialElectionVoters, relaxedElectionVoters,
          Finset.mem_filter] at electionMember ⊢
        rcases electionMember with
          ⟨joined, materialised | eligible⟩
        · exact ⟨joined, Or.inl materialised⟩
        · refine ⟨joined, Or.inr ?_⟩
          unfold currentlyEligibleElectionVoter at eligible
          exact ⟨
            by simpa [voteRequestKey, Model.Local.makeRequestVoteRequest] using eligible.1.symm.le,
            by simpa [
                voteRequestKey, Model.Local.makeRequestVoteRequest, voteLogUpToDate
              ] using eligible.2.1
          ⟩
      exact
        prospectiveAfter.relaxedSupporterCarriesFrontier
          evidence supportedPrefix known candidate member
            candidateRole evidenceBeforeCandidate
            (configurationFactsAfter.candidateEntriesBeforeTerm
              candidate candidateRole)
            ackMember relaxed
    rcases Nat.lt_trichotomy
        evidence.authority.index candidateConfiguration.index with
      authorityBefore | sameIndex | candidateBeforeAuthority
    · have candidatePositive : 0 < candidateConfiguration.index := by
        exact Nat.zero_lt_of_lt authorityBefore
      have commitPositive :
          0 < ((nodeOf state) candidate).commitIndex := by
        have configurationBound :
            candidateConfiguration.index <=
              ((nodeOf state) candidate).commitIndex := by
          simpa [candidateConfiguration]
            using currentConfiguration_index_le_commitIndex ((nodeOf state) candidate)
        exact candidatePositive.trans_le configurationBound
      rcases evidenceFacts.nodePositive candidate commitPositive with
        ⟨candidateEvidence, candidateStored, candidateValid,
          candidateSupportedLength, _candidateTermBound⟩
      have candidateKnown :
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            candidateEvidence ((nodeOf state) candidate).committedLog :=
        Or.inl ⟨candidate, commitPositive, candidateStored, rfl⟩
      have candidateConfigurationKnownCommitted :
          candidateConfiguration ∈
            allConfigurations ((nodeOf state) candidate).committedLog := by
        unfold NodeState.committedLog
        have candidateConfigurationKnown :
            candidateConfiguration ∈
              allConfigurations ((nodeOf state) candidate).log := by
          simpa [candidateConfiguration]
            using currentConfiguration_mem_allConfigurations ((nodeOf state) candidate)
        have candidateConfigurationBound :
            candidateConfiguration.index <=
              ((nodeOf state) candidate).commitIndex := by
          simpa [candidateConfiguration]
            using currentConfiguration_index_le_commitIndex ((nodeOf state) candidate)
        exact
          allConfigurations_mem_take_of_index_le
            ((nodeOf state) candidate).log
            ((nodeOf state) candidate).commitIndex
            (facts.commitIndicesBounded candidate)
            candidateConfigurationKnown candidateConfigurationBound
      have committedInEvidence :
          ((nodeOf state) candidate).committedLog <+:
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
            using currentConfiguration_index_le_commitIndex ((nodeOf state) candidate)
        let evidenceNode : NodeState Node TxId :=
          { (nodeOf state) candidate with
            log := candidateEvidence.history
            commitIndex := candidateEvidence.commitFrontier }
        have bound :=
          configuration_index_le_currentConfiguration
            evidenceNode candidateConfiguration
            (by simpa [evidenceNode] using candidateConfigurationKnownEvidence)
            (supportedBound.trans candidateValid.2.2.1)
        simpa [evidenceNode, currentConfiguration, candidateValid.2.2.2.2.1] using bound
      have evidenceBeforeCandidateEvidence :
          evidence.authority.index <
            candidateEvidence.authority.index :=
        authorityBefore.trans_le
          candidateConfigurationBeforeEvidenceAuthority
      have covered :=
        activationEvidence.authorityBridge
          evidence supportedPrefix oldKnown
          candidateEvidence ((nodeOf state) candidate).committedLog
          candidateKnown evidenceBeforeCandidateEvidence
      have valid := knownCommitEvidenceValid evidenceFacts oldKnown
      have evidenceFrontierBound :
          evidence.commitFrontier <=
            candidateEvidence.supportedLength := by
        by_contra outside
        have candidateIndexWithinSupported :
            candidateConfiguration.index <=
              candidateEvidence.supportedLength := by
          rw [candidateSupportedLength]
          simpa [candidateConfiguration]
            using currentConfiguration_index_le_commitIndex ((nodeOf state) candidate)
        have candidateIndexWithinEvidence :
            candidateConfiguration.index <= evidence.commitFrontier :=
          candidateIndexWithinSupported.trans
            (Nat.le_of_lt (Nat.lt_of_not_ge outside))
        have frontierWithinCandidateFrontier :
            evidence.commitFrontier <=
              candidateEvidence.commitFrontier := by
          calc
            evidence.commitFrontier
                = (evidence.history.take evidence.commitFrontier).length := by
              simp [Nat.min_eq_left valid.1]
            _ <= (candidateEvidence.history.take
                    candidateEvidence.commitFrontier).length :=
              covered.length_le
            _ <= candidateEvidence.commitFrontier := by simp
        have candidateKnownAtEvidenceFrontier :
            candidateConfiguration ∈
              allConfigurations
                (candidateEvidence.history.take
                  evidence.commitFrontier) :=
          allConfigurations_mem_take_of_index_le
            candidateEvidence.history evidence.commitFrontier
            (frontierWithinCandidateFrontier.trans candidateValid.1)
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
            { (nodeOf state) candidate with
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
      left
      have coveredSupported :
          evidence.history.take evidence.commitFrontier <+:
            candidateEvidence.history.take
              candidateEvidence.supportedLength := by
        rw [List.prefix_take_iff]
        exact ⟨
          covered.trans
            (List.take_prefix
              candidateEvidence.commitFrontier
              candidateEvidence.history),
          by
            simp [Nat.min_eq_left valid.1]
            exact evidenceFrontierBound
        ⟩
      exact coveredSupported.trans
        (by
          rw [candidateValid.2.2.2.1]
          simpa [candidateUnchanged]
            using (show ((nodeOf state) candidate).committedLog <+:
                ((nodeOf state) candidate).log by
              unfold NodeState.committedLog
              exact List.take_prefix _ _))
    · right
      have sameConfiguration :
          evidence.authority = candidateConfiguration := by
        by_cases zero : evidence.authority.index = 0
        · have valid := knownCommitEvidenceValid evidenceFacts oldKnown
          have evidenceKnown :
              evidence.authority ∈ allConfigurations evidence.history := by
            let evidenceNode : NodeState Node TxId :=
              { (nodeOf state) candidate with
                log := evidence.history
                commitIndex := evidence.commitFrontier }
            simpa [evidenceNode, currentConfiguration, valid.2.2.2.2.1]
              using currentConfiguration_mem_allConfigurations evidenceNode
          have evidenceImplicit :
              evidence.authority = implicitConfiguration := by
            apply
              allConfigurations_index_unique
                (TxId := TxId) evidence.history
                evidenceKnown
            · simp [allConfigurations, implicitConfiguration]
            · simpa [implicitConfiguration] using zero
          have candidateZero :
              candidateConfiguration.index = 0 := by
            simpa [sameIndex] using zero
          have candidateImplicit :
              candidateConfiguration = implicitConfiguration := by
            apply
              allConfigurations_index_unique
                (TxId := TxId) ((nodeOf state) candidate).log
            · simpa [candidateConfiguration]
                using currentConfiguration_mem_allConfigurations
                  ((nodeOf state) candidate)
            · simp [allConfigurations, implicitConfiguration]
            · simpa [implicitConfiguration] using candidateZero
          exact evidenceImplicit.trans candidateImplicit.symm
        · rcases
              activationEvidence.authorityRecorded
                evidence supportedPrefix oldKnown with
            implicit | recordedAuthority
          · exact False.elim (zero (by rw [implicit]; rfl))
          · rcases recordedAuthority with
              ⟨authorityActivationIndex, authorityActivation,
                authorityStored, authorityGoverning, _⟩
            have candidatePositive :
                0 < candidateConfiguration.index := by
              simpa [sameIndex] using Nat.pos_of_ne_zero zero
            rcases
                configurationActivations candidate
                  (by simpa [candidateConfiguration] using
                    candidatePositive) with
              ⟨candidateCoverage⟩
            have authorityKnown :
                evidence.authority ∈
                  allConfigurations authorityActivation.history := by
              have valid :=
                activationQuorums.history.valid
                  authorityActivationIndex authorityActivation
                  authorityStored
              have governing := authorityGoverning
              rw [valid.2.2.2.2.2.2.1] at governing
              exact (List.mem_filter.mp governing).1
            have candidateAtOrBeforeActivation :
                candidateConfiguration.index <=
                  authorityActivation.newConfiguration.index := by
              have bound :=
                activationGoverningConfigurationIndexLeNew
                  activationQuorums.history authorityStored
                  authorityGoverning
              simpa [candidateConfiguration, sameIndex] using bound
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
                  using candidateCoverage.configuration_mem_activationHistoryTake
                    activationQuorums.history
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
      rw [sameConfiguration]
      simpa [candidateConfiguration, activeConfigurationsEq]
        using currentConfiguration_mem_activeConfigurations ((nodeOf state) candidate)
    · right
      rcases
          activationEvidence.authorityRecorded
            evidence supportedPrefix oldKnown with
        implicit | recordedAuthority
      · rw [implicit] at candidateBeforeAuthority
        simp [implicitConfiguration] at candidateBeforeAuthority
      · rcases recordedAuthority with
          ⟨authorityActivationIndex, authorityActivation,
            authorityStored, authorityGoverning,
            activationTermBound⟩
        have candidateBeforeActivation :
            candidateConfiguration.index <
              authorityActivation.newConfiguration.index :=
          candidateBeforeAuthority.trans_le
            (activationGoverningConfigurationIndexLeNew
              activationQuorums.history authorityStored
              authorityGoverning)
        have activationInCandidate :=
          activationPrefixInPotentialCandidateByCoverageAuthorityChain
            committedSignatureAfter entriesBoundedAfter snapshotsAfter
            voteCanonicalFactsAfter ownershipAfter electionFactsAfter
            activationQuorums.history supporterCurrentAfter
            activationVoteHistoryAfter activationCanonical
            activationElections configurationActivationsAfter
            candidateRole candidateMajority
            authorityActivation.newConfiguration.index
            authorityActivationIndex authorityActivation rfl
            authorityStored
            (activationTermBound.trans_lt
              (by simpa [candidateUnchanged] using evidenceBeforeCandidate))
        have authorityKnownCandidate :
            evidence.authority ∈
              allConfigurations
                ((nodeOf (observeTermEffect state destination selected.payload.term)) candidate).log := by
          apply
            memOfPrefix
              (allConfigurations_mono_prefix
                (activationInCandidate.trans
                  (List.take_prefix
                    (maxCommittableIndex
                      ((nodeOf (observeTermEffect state destination selected.payload.term))
                          candidate).log)
                    ((nodeOf (observeTermEffect state destination selected.payload.term)) candidate).log)))
          have valid :=
            activationQuorums.history.valid
              authorityActivationIndex authorityActivation
              authorityStored
          have governing := authorityGoverning
          rw [valid.2.2.2.2.2.2.1] at governing
          exact
            allConfigurations_mem_take_of_index_le
              authorityActivation.history
              authorityActivation.activationFrontier valid.2.1
              (List.mem_filter.mp governing).1
              (of_decide_eq_true
                (List.mem_filter.mp governing).2).2
        simpa [activeConfigurations, candidateConfiguration, candidateUnchanged]
          using And.intro authorityKnownCandidate candidateBeforeAuthority.le
  have activationEvidenceAfter :
      ActivationEvidenceFacts (joined := joinedNodes)
        (observeTermEffect state destination selected.payload.term)
        appendHistory responseHistory nodeEvidence requestEvidence
          elections activations := by
    constructor
    · intro evidence supportedPrefix known
      exact
        activationEvidence.authorityRecorded
          evidence supportedPrefix
          (knownBack evidence supportedPrefix known)
    · intro left leftPrefix leftKnown right rightPrefix rightKnown same
      exact
        activationEvidence.authorityIndexUnique
          left leftPrefix (knownBack left leftPrefix leftKnown)
          right rightPrefix (knownBack right rightPrefix rightKnown) same
    · intro earlier earlierPrefix earlierKnown
        later laterPrefix laterKnown order
      exact
        activationEvidence.authorityBridge
          earlier earlierPrefix
            (knownBack earlier earlierPrefix earlierKnown)
          later laterPrefix
            (knownBack later laterPrefix laterKnown)
          order
    · intro left leftPrefix leftKnown right rightPrefix rightKnown
      exact
        activationEvidence.supportedPrefixesComparable
          left leftPrefix (knownBack left leftPrefix leftKnown)
          right rightPrefix (knownBack right rightPrefix rightKnown)
    · exact updateTermEvidenceBridge
  have activationQuorumsAfter :
      ActivationQuorumFacts (joined := joinedNodes)
        (observeTermEffect state destination selected.payload.term)
        appendHistory responseHistory elections activations := by
    constructor
    · exact activationQuorums.history
    · intro leader index role current signature potential
        term record recorded later
      exact Or.inl
        (potentialPrefixInElectionRecordsFromActivationHistory
          (by
            intro node participating
            by_cases nodeEq : node = destination
            · subst node
              rw [termDestination]
              exact selectedTermBound
            · rw [termOther node nodeEq]
              apply facts.currentTermsPositive node
              intro none
              apply participating
              simpa [roleOther node nodeEq] using none)
          (by
            intro node entry member
            rw [logEq] at member
            exact
              (facts.entriesDoNotExceedCurrentTerm node entry member).trans
                (termMonotone node))
          voteFactsAfter ownershipAfter electionFactsAfter
          configurationFactsAfter activationQuorums.history
          activationProgressAfter ackerActivationAfter
          temporalFacts.2.2 activationCanonical activationElections
          configurationActivationsAfter evidenceAfter prospectiveAfter
          role current signature potential term record recorded later)
    · intro leader index role current signature potential
        candidate candidateRole candidateMajority later
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        exact Role.noConfusion
          (candidateRole.symm.trans roleDestination)
      exact Or.inl
        (activationPrefixInEffectiveCandidateByAuthorityChain
          termsPositiveAfter committedSignatureAfter entriesBoundedAfter
          voteFactsAfter snapshotsAfter voteCanonicalFactsAfter
          ownershipAfter electionFactsAfter configurationFactsAfter
          activationQuorums.history supporterCurrentAfter
          activationVoteHistoryAfter activationProgressAfter
          ackerActivationAfter temporalFacts.2.2 activationCanonical
          activationElections configurationActivationsAfter
          evidenceAfter prospectiveAfter
          role current signature potential candidateRole
          candidateMajority later
          (by
            intro configuration sourceActive governs candidateActive
            exact
              updateTermPotentialPrefixOfRelaxedAuthority
                (before := state)
                (after := observeTermEffect state destination selected.payload.term)
                (source := leader)
                (candidate := candidate)
                (index := index)
                (configuration := configuration)
                (by
                  simp [
                    concrete_effects, updateTerm, newer, present, nodeOf_replaceNode, leaderNe
                  ])
                (by
                  simp [
                    concrete_effects, updateTerm, newer, present, nodeOf_replaceNode, candidateNe
                  ])
                logEq termMonotone
                (by
                  intro voter member
                  rw [effectiveAckersEq leader leaderNe index] at member
                  exact member)
                (by
                  intro voter member
                  rw [
                    effectiveElectionVotersEq candidate candidateNe
                  ] at member
                  exact member)
                facts.grantedVoteSnapshots
                facts.currentTermsPositive
                (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
                  facts)
                facts.entriesDoNotExceedCurrentTerm facts.voteHistory
                voteCanonicalFacts ownership electionFacts
                configurationFacts ackerCurrentFacts ackerVoteFacts
                ackerElectionFacts activationQuorums
                role current signature potential candidateRole
                candidateMajority sourceActive governs candidateActive later
                (by
                  intro oldTermsPositive oldCommittedSignature
                      _oldEntriesBounded oldVoteFacts oldSnapshots
                      oldCanonicalSnapshots oldOwnership oldElectionFacts
                      oldConfigurationFacts oldCurrentHistory oldVoteHistory
                      oldElectedHistory oldActivationQuorums
                      oldSourceRole oldCurrent oldSignature afterPotential
                      oldCandidateRole oldLater voter effective relaxed
                  exact
                    effectiveAckerRelaxedCandidateContainsPotentialPrefix
                      oldTermsPositive oldCommittedSignature oldVoteFacts
                      oldOwnership oldElectionFacts oldSnapshots
                      oldCanonicalSnapshots oldCurrentHistory oldVoteHistory
                      oldElectedHistory oldActivationQuorums
                      oldSourceRole oldCurrent oldSignature
                      (potentialMajorityBack
                        leader leaderNe index afterPotential)
                      oldCandidateRole oldLater
                      (oldConfigurationFacts.candidateEntriesBeforeTerm
                        candidate oldCandidateRole)
                      effective relaxed)))
    · intro leader index role current signature majority node
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      rcases
          activationQuorums.committedBridge
            leader index
            (by simpa [roleOther leader leaderNe] using role)
            (by simpa [logEq, termOther leader leaderNe] using current)
            (by simpa [logEq] using signature)
            ((effectiveMajorityEq leader leaderNe index).mp majority)
            node with
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
            by simpa [currentConfigurationEq] using configurationEq⟩)
    · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
        right rightIndex rightRole rightCurrent rightSignature rightMajority
      have leftNe : Not (left = destination) := by
        intro same
        subst left
        exact Role.noConfusion (leftRole.symm.trans roleDestination)
      have rightNe : Not (right = destination) := by
        intro same
        subst right
        exact Role.noConfusion (rightRole.symm.trans roleDestination)
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
            ((effectiveMajorityEq right rightNe rightIndex).mp
              rightMajority) with
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
          (by simpa [concrete_effects, updateTerm, newer, present] using queued)
          sameTerm
    · exact
        committedConfigurationCoverageFrame
          activationQuorums.committedCoverage logEq commitEq termMonotone
    · apply
        queuedConfigurationCoverageFrame
          activationQuorums.queuedCoverage
          (afterAppendHistory := appendHistory)
      · intro queuedDestination queuedRequest queued
        simpa [concrete_effects, updateTerm, newer, present] using queued
      · intro _
        rfl
  · refine ⟨
      owners,
      canonicalHistory,
      elections,
      activations,
      nodeEvidence,
      requestEvidence,
      ownershipAfter,
      electionFactsAfter,
      configurationFactsAfter,
      ?_,
      temporalFacts.1,
      temporalFacts.2.1,
      activationVoteHistoryAfter,
      temporalFacts.2.2,
      ackerActivationAfter,
      ?_,
      activationProgressAfter,
      activationQuorumsAfter,
      evidenceAfter,
      prospectiveAfter,
      activationEvidenceAfter,
      activationCanonical,
      activationElections,
      configurationActivationsAfter
    ⟩
    · apply
        grantedVoteCanonicalFrame
          state (observeTermEffect state destination selected.payload.term)
            canonicalHistory canonicalHistory
            voteCandidateHistory voteVoterHistory voteCanonicalFacts
            (fun candidate active => by
              have candidateNe : Not (candidate = destination) := by
                intro same
                subst candidate
                rcases active with candidateRole | leaderRole
                · exact Role.noConfusion
                    (candidateRole.symm.trans roleDestination)
                · exact Role.noConfusion
                    (leaderRole.symm.trans roleDestination)
              exact termOther candidate candidateNe)
      · intro candidate active
        have candidateNe : Not (candidate = destination) := by
          intro same
          subst candidate
          rcases active with candidateRole | leaderRole
          · exact Role.noConfusion
              (candidateRole.symm.trans roleDestination)
          · exact Role.noConfusion
              (leaderRole.symm.trans roleDestination)
        rw [roleOther candidate candidateNe] at active
        exact active
      · intro candidate voter active member
        have candidateNe : Not (candidate = destination) := by
          intro same
          subst candidate
          rcases active with candidateRole | leaderRole
          · exact Role.noConfusion
              (candidateRole.symm.trans roleDestination)
          · exact Role.noConfusion
              (leaderRole.symm.trans roleDestination)
        rw [effectiveElectionVotersEq candidate candidateNe] at member
        exact member
      · intro history canonical
        exact canonical
    · intro queuedDestination request member record recorded
      have oldMember := member
      rw [networkEq] at oldMember
      exact
        electionQueuedFacts
          queuedDestination request oldMember record recorded
  · intro candidate voter active member
    have candidateNe : Not (candidate = destination) := by
      intro same
      subst candidate
      rcases active with candidateRole | leaderRole
      · exact Role.noConfusion (candidateRole.symm.trans roleDestination)
      · exact Role.noConfusion (leaderRole.symm.trans roleDestination)
    rw [termOther candidate candidateNe]
    have oldActive :
        ((nodeOf state) candidate).role = .candidate \/
          ((nodeOf state) candidate).role = .leader := by
      rw [roleOther candidate candidateNe] at active
      exact active
    have oldMember :
        voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
      rw [effectiveElectionVotersEq candidate candidateNe] at member
      exact member
    rcases
        facts.grantedVoteSnapshots
          candidate voter oldActive oldMember with
      ⟨recorded, self | snapshot⟩
    · exact ⟨recorded, Or.inl self⟩
    · rcases snapshot with
        ⟨candidatePrefix, candidateCommittable, voterCommittable,
          voterBound, upToDate⟩
      refine ⟨recorded, Or.inr ⟨?_, candidateCommittable, voterCommittable, ?_, ?_⟩⟩
      · simpa [logEq] using candidatePrefix
      · by_cases voterEq : voter = destination
        · subst voter
          rw [termDestination]
          exact Nat.le_trans voterBound newer.le
        · simpa [termOther voter voterEq] using voterBound
      · simpa [voteLogUpToDate] using upToDate
  · refine ⟨ackHistory, ?_⟩
    constructor
    · intro leader role peer zero
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      exact
        ackFacts.zero leader
          (by simpa [roleOther leader leaderNe] using role)
          peer (by simpa [matchEq] using zero)
    · intro leader role peer positive
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
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
    · intro node peer member
      simpa [concrete_effects, updateTerm, newer, present]
        using facts.joinedCarriers.activeNodes node
          (by simpa [activeNodeUnion, activeConfigurationsEq] using member)
    · intro node configuration member peer inNodes
      simpa [concrete_effects, updateTerm, newer, present]
        using facts.joinedCarriers.configurationNodes node configuration
          (by simpa [logEq] using member) inNodes
    · intro node peer member
      simpa [concrete_effects, updateTerm, newer, present]
        using facts.joinedCarriers.grantedVotes node
          (by rw [← votesEq node]; exact member)
    · intro queuedDestination request member
      simpa [concrete_effects, updateTerm, newer, present]
        using facts.joinedCarriers.voteRequestDestinations
          queuedDestination request
          (by simpa [concrete_effects, updateTerm, newer, present] using member)
    · intro queuedDestination request member
      simpa [concrete_effects, updateTerm, newer, present]
        using facts.joinedCarriers.appendRequestDestinations
          queuedDestination request
          (by simpa [concrete_effects, updateTerm, newer, present] using member)
    · intro queuedDestination request member configuration configured
        peer inNodes
      simpa [concrete_effects, updateTerm, newer, present]
        using facts.joinedCarriers.appendRequestConfigurations
          queuedDestination request
          (by simpa [concrete_effects, updateTerm, newer, present] using member)
          configuration configured inNodes
    · intro queuedDestination response member
      simpa [concrete_effects, updateTerm, newer, present]
        using facts.joinedCarriers.voteResponseSources
          queuedDestination response
          (by simpa [concrete_effects, updateTerm, newer, present] using member)
    · constructor
      · intro candidate active
        have different : Not (candidate = destination) := by
          intro same
          subst candidate
          rcases active with candidateRole | leaderRole
          · exact Role.noConfusion (candidateRole.symm.trans roleDestination)
          · exact Role.noConfusion (leaderRole.symm.trans roleDestination)
        simpa [concrete_effects, updateTerm, newer, present]
          using facts.joinedCarriers.runtimeNodes.activeRoles candidate
            (by simpa [roleOther candidate different] using active)
      · intro leader peer positive
        simpa [concrete_effects, updateTerm, newer, present]
          using facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
            (by simpa [matchEq] using positive)
      · intro queuedDestination response member
        simpa [concrete_effects, updateTerm, newer, present]
          using facts.joinedCarriers.runtimeNodes.appendResponses
            queuedDestination response
            (by simpa [concrete_effects, updateTerm, newer, present] using member)
      · intro candidate nonempty
        simpa [concrete_effects, updateTerm, newer, present]
          using facts.joinedCarriers.runtimeNodes.nonemptyLogs candidate
            (by simpa [logEq] using nonempty)
  · intro candidate
    by_cases same : candidate = destination
    · subst candidate
      rw [termDestination]
      exact Or.inr selectedTermBound
    · rw [termOther candidate same]
      exact facts.currentTermsValid candidate
  · simpa only [NetworkTermsValid, networkEq] using facts.networkTermsValid

end CCFRaft.Proofs.Invariant
