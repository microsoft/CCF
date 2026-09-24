-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Commit
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
A same-term candidate or pre-vote candidate may step down before consuming
AppendEntries. Every leader/election obligation either reuses the old fact or
excludes the node which just became a follower.
-/
lemma returnToFollowerPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (destination : Node)
    {present : destination ∈ state.nodes.map Prod.fst}
    (request : AppendRequestKey Node TxId)
    (nextNode : NodeState Node TxId)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (_destinationAllocated : destination ∈ joinedNodes)
    (canReturn : request.2.2.term = (nodeOf state destination).currentTerm
      ∧ ((nodeOf state destination).role = .candidate ∨ (nodeOf state destination).role = .preVoteCandidate))
    (stepped : nextNode = { nodeOf state destination with role := .follower, isNewFollower := true })
    : SystemInductiveInvariant (joined := joinedNodes)
        { state with nodes := replaceNode state.nodes destination nextNode } := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafety with
    ⟨owners, canonicalHistory, elections, activations,
      nodeEvidence, requestEvidence, ownership, electionFacts,
      configurationFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, activationVoteHistory,
      ackerElectionFacts, ackerActivationFacts,
      electionQueuedFacts, activationProgress, activationQuorums,
      evidenceFacts, prospectiveFacts, activationEvidence,
      activationCanonical, activationElections, configurationActivations⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  subst nextNode
  let after : Model.State Node TxId :=
    { state with
      nodes :=
        replaceNode state.nodes destination
          { (nodeOf state) destination with
            role := .follower
            isNewFollower := true } }
  have oldParticipating :
      Not (((nodeOf state) destination).role = .none) := by
    rcases canReturn.2 with candidate | preVoteCandidate
    · simp [candidate]
    · simp [preVoteCandidate]
  have oldNotLeader :
      Not (((nodeOf state) destination).role = .leader) := by
    rcases canReturn.2 with candidate | preVoteCandidate
    · exact fun leader => Role.noConfusion (candidate.symm.trans leader)
    · exact
        fun leader =>
          Role.noConfusion (preVoteCandidate.symm.trans leader)
  have roleDestination :
      ((nodeOf after) destination).role = .follower := by
    simp [after, present, nodeOf_replaceNode]
  have roleOther :
      forall node,
        Not (node = destination) ->
          ((nodeOf after) node).role = ((nodeOf state) node).role := by
    intro node different
    simp [after, present, nodeOf_replaceNode, different]
  have termEq :
      forall node,
        ((nodeOf after) node).currentTerm =
          ((nodeOf state) node).currentTerm := by
    intro node
    by_cases same : node = destination <;>
      simp [after, present, nodeOf_replaceNode, same]
  have logEq :
      forall node,
        ((nodeOf after) node).log = ((nodeOf state) node).log := by
    intro node
    by_cases same : node = destination <;>
      simp [after, present, nodeOf_replaceNode, same]
  have commitEq :
      forall node,
        ((nodeOf after) node).commitIndex =
          ((nodeOf state) node).commitIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [after, present, nodeOf_replaceNode, same]
  have activeConfigurationsEq :
      forall node,
        activeConfigurations ((nodeOf after) node) =
          activeConfigurations ((nodeOf state) node) := by
    intro node
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have lastIndexEq :
      forall node,
        lastCommittableIndex ((nodeOf after) node) =
          lastCommittableIndex ((nodeOf state) node) := by
    intro node
    exact lastCommittableIndexFrame (logEq node) (commitEq node)
  have lastTermEq :
      forall node,
        lastCommittableTerm ((nodeOf after) node) =
          lastCommittableTerm ((nodeOf state) node) := by
    intro node
    exact lastCommittableTermFrame (logEq node) (commitEq node)
  have committedEq :
      forall node,
        ((nodeOf after) node).committedLog =
          ((nodeOf state) node).committedLog := by
    intro node
    simp [NodeState.committedLog, commitEq, logEq]
  have activeConfigurationsEq :
      forall node,
        activeConfigurations ((nodeOf after) node) =
          activeConfigurations ((nodeOf state) node) := by
    intro node
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have votedEq :
      forall node,
        ((nodeOf after) node).votedFor =
          ((nodeOf state) node).votedFor := by
    intro node
    by_cases same : node = destination <;>
      simp [after, present, nodeOf_replaceNode, same]
  have votesEq :
      forall node,
        ((nodeOf after) node).votesGranted =
          ((nodeOf state) node).votesGranted := by
    intro node
    by_cases same : node = destination <;>
      simp [after, present, nodeOf_replaceNode, same]
  have sentEq :
      forall node,
        ((nodeOf after) node).sentIndex =
          ((nodeOf state) node).sentIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [after, present, nodeOf_replaceNode, same]
  have matchEq :
      forall node,
        ((nodeOf after) node).matchIndex =
          ((nodeOf state) node).matchIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [after, present, nodeOf_replaceNode, same]
  have networkEq : after.network = state.network := by
    rfl
  have hasJoinedEq : joinedNodes = joinedNodes := by
    rfl
  have acknowledgingNodesEq :
      forall leader index,
        acknowledgingNodes (nodeOf after leader) leader index =
          acknowledgingNodes (nodeOf state leader) leader index := by
    intro leader index
    ext peer
    simp [
      acknowledgingNodes, matchEq,
      activeNodeUnion, activeConfigurationsEq
    ]
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers (joined := joinedNodes) after responseHistory leader index =
          effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter]
    apply and_congr
    · simp only [hasJoinedEq]
    · constructor
      · rintro (self | matched | queued)
        · exact Or.inl self
        · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
        · right
          right
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
      · rintro (self | matched | queued)
        · exact Or.inl self
        · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
        · right
          right
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
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt (joined := joinedNodes) after responseHistory leader index ↔
          hasEffectiveMajorityAt (joined := joinedNodes) state responseHistory leader index := by
    intro leader index
    simp only [
      hasEffectiveMajorityAt, effectiveAckersEq,
      activeConfigurationsEq
    ]
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters (joined := joinedNodes) after candidate =
          effectiveElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    apply and_congr
    · simp only [hasJoinedEq]
    · constructor <;> rintro (processed | queued)
      · exact Or.inl (by simpa [votesEq] using processed)
      · right
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
      · exact Or.inl (by simpa [votesEq] using processed)
      · right
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
        hasEffectiveElectionMajority (joined := joinedNodes) after candidate ↔
          hasEffectiveElectionMajority (joined := joinedNodes) state candidate := by
    intro candidate
    simp only [
      hasEffectiveElectionMajority,
      effectiveElectionVotersEq,
      activeConfigurationsEq
    ]
  have potentialElectionVotersEq :
    forall candidate,
      potentialElectionVoters (joined := joinedNodes) after candidate =
        potentialElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate
    ext voter
    simp only [
    potentialElectionVoters, Finset.mem_filter]
    apply and_congr
    · simp only [hasJoinedEq]
    · constructor <;> rintro (effective | eligible)
      · exact Or.inl (by
          rw [effectiveElectionVotersEq] at effective
          exact effective)
      · exact Or.inr (by
          simpa [
            currentlyEligibleElectionVoter,
            voteRequestKey, Model.Local.makeRequestVoteRequest,
            termEq, logEq, lastIndexEq, lastTermEq,
            votedEq, voteLogUpToDate
          ] using eligible)
      · exact Or.inl (by
          rw [effectiveElectionVotersEq]
          exact effective)
      · exact Or.inr (by
          simpa [
            currentlyEligibleElectionVoter,
            voteRequestKey, Model.Local.makeRequestVoteRequest,
            termEq, logEq, lastIndexEq, lastTermEq,
            votedEq, voteLogUpToDate
          ] using eligible)
  have potentialElectionMajorityEq :
    forall candidate,
      hasPotentialElectionMajority (joined := joinedNodes) after candidate ↔
        hasPotentialElectionMajority (joined := joinedNodes) state candidate := by
    intro candidate
    simp only [
      hasPotentialElectionMajority,
      potentialElectionVotersEq,
      activeConfigurationsEq
    ]
  have temporalFacts :=
    ackerTemporalFrameSameLogs
      state after votes votes responseHistory voteVoterHistory elections
        ackerCurrentFacts ackerVoteFacts ackerElectionFacts
        (fun leader role => by
          have leaderNe : Not (leader = destination) := by
            intro same
            subst leader
            exact Role.noConfusion
              (role.symm.trans roleDestination)
          simpa [roleOther leader leaderNe] using role)
        (fun leader _ => termEq leader)
        logEq
        (fun leader index voter _ _ member => by
          rw [effectiveAckersEq] at member
          exact member)
        (fun node => Nat.le_of_eq (termEq node).symm)
        (fun _ _ _ voted _ => voted)
  change SystemInductiveInvariant (joined := joinedNodes) after
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
  · intro node active
    rw [termEq]
    exact
      facts.currentTermsPositive node
        (by
          by_cases same : node = destination
          · subst node
            exact oldParticipating
          · simpa [roleOther node same] using active)
  · intro node entry member
    rw [logEq] at member
    rw [termEq]
    exact facts.entriesDoNotExceedCurrentTerm node entry member
  · intro node role
    have nodeNe : Not (node = destination) := by
      intro same
      subst node
      exact Role.noConfusion (role.symm.trans roleDestination)
    rw [roleOther node nodeNe] at role
    rw [votedEq, votesEq]
    exact facts.candidatesSelfVote node role
  · intro leader role
    have leaderNe : Not (leader = destination) := by
      intro same
      subst leader
      exact Role.noConfusion (role.symm.trans roleDestination)
    rw [roleOther leader leaderNe] at role
    rcases facts.leadersHaveElectionWitness leader role with
      bootstrap | majority
    · exact Or.inl ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
    · exact Or.inr (by simpa [logEq, votesEq] using majority)
  · intro leader role peer
    have leaderNe : Not (leader = destination) := by
      intro same
      subst leader
      exact Role.noConfusion (role.symm.trans roleDestination)
    rw [roleOther leader leaderNe] at role
    simpa [sentEq, matchEq, logEq] using facts.leaderProgressBounded leader role peer
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      simpa [termEq, votedEq] using facts.voteHistory.current voter
    · intro voter term future
      rw [termEq] at future
      exact facts.voteHistory.future voter term future
    · intro candidate voter active member
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        rcases active with candidateActive | leaderActive
        · exact
            Role.noConfusion
              (candidateActive.symm.trans roleDestination)
        · exact
            Role.noConfusion
              (leaderActive.symm.trans roleDestination)
      rw [roleOther candidate candidateNe] at active
      rw [votesEq] at member
      rw [termEq]
      exact facts.voteHistory.counted candidate voter active member
  · constructor
    · intro queuedDestination message member
      rw [networkEq] at member
      exact facts.networkHistory.addressed queuedDestination message member
    · intro queuedDestination queuedRequest member
      rw [networkEq] at member
      rcases
          facts.networkHistory.appendRequest
            queuedDestination queuedRequest member with
        ⟨snapshot, commitBound, present⟩
      exact ⟨
        snapshot,
        commitBound,
        by simpa [RequestCommitStillPresent, committedEq] using present
      ⟩
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
      refine ⟨lengthBound, by simpa [termEq] using termBound, ?_⟩
      intro sameTerm
      have oldSameTerm :
          response.2.2.term =
            ((nodeOf state) response.2.1).currentTerm := by
        simpa [termEq] using sameTerm
      by_cases destinationEq : response.2.1 = destination
      · exact Or.inr (Or.inl (by
          simpa [destinationEq] using roleDestination))
      · rcases supported oldSameTerm with
          active | follower | preVoteCandidate
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
    · intro queuedDestination voteRequest member
      rw [networkEq] at member
      rcases
          facts.networkHistory.voteRequest
            queuedDestination voteRequest member with
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
      by_cases sourceEq : voteRequest.1 = destination
      · rw [sourceEq] at active
        rcases active with candidate | leader
        · exact False.elim
            (Role.noConfusion (candidate.symm.trans roleDestination))
        · exact False.elim
            (Role.noConfusion (leader.symm.trans roleDestination))
      · have oldPrefix :=
          activePrefix
            (by simpa [termEq] using sameTerm)
            (by simpa [roleOther voteRequest.1 sourceEq] using active)
        simpa [logEq] using oldPrefix
    · intro queuedDestination response member granted
      rw [networkEq] at member
      rcases
          facts.networkHistory.voteResponse
            queuedDestination response member granted with
        ⟨termBound, recorded, candidateCommittable,
          voterCommittable, upToDate⟩
      exact ⟨
        by simpa [termEq] using termBound,
        recorded,
        candidateCommittable,
        voterCommittable,
        by simpa [voteLogUpToDate] using upToDate
      ⟩
  have evidenceAfter :
      CommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
        state after appendHistory
          nodeEvidence requestEvidence evidenceFacts
          commitEq committedEq
    · intro node
      exact Nat.le_of_eq (termEq node).symm
    · intro queuedDestination queuedRequest member
      simpa [networkEq] using member
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts (joined := joinedNodes)
        after appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state after appendHistory appendHistory
          nodeEvidence nodeEvidence requestEvidence requestEvidence
        elections prospectiveFacts
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state after appendHistory nodeEvidence requestEvidence
            commitEq committedEq
            (fun queuedDestination queuedRequest member => by
              simpa [networkEq] using member)
            known
    · intro member
      simp [logEq]
    · intro evidence supportedPrefix queuedDestination queuedRequest
        known queued sameTerm
      left
      exact ⟨by simpa [networkEq] using queued, rfl⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleDestination)
      left
      exact ⟨
        by simpa [roleOther candidate candidateNe] using role,
        by simpa [termEq] using newer,
        by
          intro entry entryMember
          simpa [termEq] using entriesBefore entry (by simpa [logEq] using entryMember),
        by simpa [
            relaxedElectionVoters,
            voteRequestKey, Model.Local.makeRequestVoteRequest,
            termEq, logEq, lastIndexEq, lastTermEq,
            effectiveElectionVotersEq,
            voteLogUpToDate
          ] using relaxed,
        by simp [logEq]
      ⟩
  have ownershipAfter :
      TermOwnershipFacts
        after votes appendHistory canonicalHistory owners := by
    apply
      termOwnershipFrame
        state after appendHistory appendHistory votes canonicalHistory
          owners ownership
    · intro leader role
      have leaderNe : Not (leader = destination) := by
        intro same
        subst leader
        exact Role.noConfusion (role.symm.trans roleDestination)
      simpa [roleOther leader leaderNe] using role
    · intro owner role
      by_cases ownerEq : owner = destination
      · subst owner
        exact Or.inr (Or.inl roleDestination)
      · simpa [roleOther owner ownerEq] using role
    · exact termEq
    · exact logEq
    · intro queuedDestination queuedRequest member index entry found
      exact
        ownership.queuedHistoryEntryAgreement
          queuedDestination queuedRequest
          (by simpa [networkEq] using member)
          index entry found
    · intro queuedDestination queuedRequest member
      exact
        ownership.queuedAppendMetadata queuedDestination queuedRequest
          (by simpa [networkEq] using member)
    · intro queuedDestination queuedRequest member sameTerm leaderRole
      have sourceNe : Not (queuedRequest.1 = destination) := by
        intro same
        have destinationLeader :
            ((nodeOf after) destination).role = .leader := by
          simpa [same] using leaderRole
        exact Role.noConfusion
          (destinationLeader.symm.trans roleDestination)
      simpa [logEq]
        using ownership.queuedActiveSourceHistory
          queuedDestination queuedRequest
          (by simpa [networkEq] using member)
          (by simpa [termEq] using sameTerm)
          (by simpa [roleOther queuedRequest.1 sourceNe] using leaderRole)
  have electionFactsAfter :
      ElectionHistoryFacts after votes canonicalHistory owners elections := by
    apply
      electionHistoryFrame
        state after votes votes canonicalHistory canonicalHistory
        owners elections electionFacts
    · intros
      rfl
    · intro term
      exact prefixRefl (canonicalHistory term)
    · intro history canonical
      exact canonical
  have voteCanonicalAfter :
      GrantedVoteCanonicalSnapshots (joined := joinedNodes)
        after canonicalHistory voteCandidateHistory voteVoterHistory := by
    apply
      grantedVoteCanonicalFrame
        state after canonicalHistory canonicalHistory
        voteCandidateHistory voteVoterHistory voteCanonicalFacts
        (fun candidate _ => termEq candidate)
    · intro candidate active
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        rcases active with candidateRole | leaderRole
        · exact Role.noConfusion
            (candidateRole.symm.trans roleDestination)
        · exact Role.noConfusion
            (leaderRole.symm.trans roleDestination)
      simpa [roleOther candidate candidateNe] using active
    · intro candidate voter _ member
      rw [effectiveElectionVotersEq] at member
      exact member
    · intro history canonical
      exact canonical
  have voteFactsAfter : VoteHistoryFacts after votes := by
    constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      simpa [termEq, votedEq] using facts.voteHistory.current voter
    · intro voter term future
      exact
        facts.voteHistory.future voter term
          (by simpa [termEq] using future)
    · intro candidate voter active member
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        rcases active with candidateRole | leaderRole
        · exact Role.noConfusion
            (candidateRole.symm.trans roleDestination)
        · exact Role.noConfusion
            (leaderRole.symm.trans roleDestination)
      rw [termEq]
      exact
        facts.voteHistory.counted candidate voter
          (by simpa [roleOther candidate candidateNe] using active)
          (by simpa [votesEq] using member)
  have termsPositiveAfter : CurrentTermsPositive after := by
    intro node active
    rw [termEq]
    exact
      facts.currentTermsPositive node
        (by
          by_cases same : node = destination
          · subst node
            exact oldParticipating
          · simpa [roleOther node same] using active)
  have entriesBoundedAfter : EntriesDoNotExceedCurrentTerm after := by
    intro node entry member
    rw [termEq]
    exact
      facts.entriesDoNotExceedCurrentTerm node entry
        (by simpa [logEq] using member)
  have leaderRoleBack :
      forall leader,
        ((nodeOf after) leader).role = .leader ->
          ((nodeOf state) leader).role = .leader := by
    intro leader role
    have leaderNe : Not (leader = destination) := by
      intro same
      subst leader
      exact Role.noConfusion (role.symm.trans roleDestination)
    simpa [roleOther leader leaderNe] using role
  have candidateBack :
      forall candidate,
        ((nodeOf after) candidate).role = .candidate ->
        hasEffectiveElectionMajority (joined := joinedNodes) after candidate ->
          ((nodeOf state) candidate).role = .candidate /\
            ((nodeOf after) candidate).currentTerm =
              ((nodeOf state) candidate).currentTerm /\
            hasEffectiveElectionMajority (joined := joinedNodes) state candidate := by
    intro candidate role majority
    have candidateNe : Not (candidate = destination) := by
      intro same
      subst candidate
      exact Role.noConfusion (role.symm.trans roleDestination)
    exact ⟨
      by simpa [roleOther candidate candidateNe] using role,
      termEq candidate,
      (effectiveElectionMajorityEq candidate).mp majority
    ⟩
  have supporterCurrentAfter :
      ActivationSupporterCurrentHistory after elections activations := by
    apply
      activationSupporterCurrentHistoryFrame
        state after elections elections activations
          configurationFacts.supporterCurrentHistory
    · intro node
      simp [logEq]
    · intro node
      exact Nat.le_of_eq (termEq node).symm
    · intro term record stored
      exact stored
  have configurationFactsAfter :
      ElectionConfigurationFacts (joined := joinedNodes) after elections activations := by
    apply
      electionConfigurationFrame
        state after elections activations activations configurationFacts
    · intro _ _ stored
      exact stored
    · exact supporterCurrentAfter
    · exact candidateBack
    · intro candidate configuration role active
      simpa [activeConfigurationsEq] using active
    · intro candidate role entry member
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleDestination)
      simpa [termEq]
        using configurationFacts.candidateEntriesBeforeTerm
          candidate
          (by simpa [roleOther candidate candidateNe] using role)
          entry
          (by simpa [logEq] using member)
  have activationVoteHistoryAfter :
      ActivationVoteHistory
        votes voteVoterHistory elections activations :=
    activationVoteHistory
  have ackerActivationAfter :
      AckerActivationHistory (joined := joinedNodes)
        after responseHistory elections activations := by
    apply
      ackerActivationFrameSameLogs
        state after responseHistory elections elections activations
          ackerActivationFacts
    · exact leaderRoleBack
    · intro leader _
      exact termEq leader
    · exact logEq
    · intro leader index supporter role current member
      rw [effectiveAckersEq] at member
      exact member
    · intro term record stored
      exact stored
  have activationProgressAfter :
      ActivationSupporterProgress after activations := by
    apply
      activationSupporterProgressFrame
        state after activations activationProgress
    intro node
    exact Nat.le_of_eq (termEq node).symm
  have configurationActivationsAfter :
      ConfigurationCoverageFacts after activations := by
    apply
      configurationCoverageFrame configurationActivations
    · intro node
      unfold currentConfiguration
      rw [logEq, commitEq]
    · intro node
      exact Nat.le_of_eq (termEq node).symm
    · exact commitEq
    · intro node frontier _
      rw [logEq]
    · intro candidate witness role
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleDestination)
      rw [termEq]
      exact witness.candidateTermStrict
        (by simpa [roleOther candidate candidateNe] using role)
  have activationQuorumsAfter :
      ActivationQuorumFacts (joined := joinedNodes)
        after appendHistory responseHistory elections activations := by
    constructor
    · exact activationQuorums.history
    · intro source index role current signature potential
        term record recorded later
      exact Or.inl
        (potentialPrefixInElectionRecordsFromActivationHistory
          termsPositiveAfter entriesBoundedAfter voteFactsAfter
          ownershipAfter electionFactsAfter configurationFactsAfter
          activationQuorums.history activationProgressAfter
          ackerActivationAfter temporalFacts.2.2 activationCanonical
          activationElections configurationActivationsAfter
          evidenceAfter prospectiveAfter
          role current signature potential term record recorded later)
    · intro source index role current signature potential
        candidate candidateRole candidateMajority later
      have oldSourceRole : ((nodeOf state) source).role = .leader :=
        leaderRoleBack source role
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        exact Role.noConfusion
          (candidateRole.symm.trans roleDestination)
      have oldCandidateRole :
          ((nodeOf state) candidate).role = .candidate := by
        simpa [roleOther candidate candidateNe] using candidateRole
      have oldCandidateMajority :
          hasPotentialElectionMajority (joined := joinedNodes) state candidate :=
        (potentialElectionMajorityEq candidate).mp candidateMajority
      have oldCurrent :
          termAt ((nodeOf state) source).log index =
            ((nodeOf state) source).currentTerm := by
        simpa [logEq, termEq] using current
      have oldSignature :
          isSignatureAt ((nodeOf state) source).log index = true := by
        simpa [logEq] using signature
      have oldLater :
          ((nodeOf state) source).currentTerm <
            ((nodeOf state) candidate).currentTerm := by
        simpa [termEq] using later
      by_cases committed : index <= ((nodeOf state) source).commitIndex
      · have indexPositive : 0 < index := by
          rcases isSignatureAtTrue oldSignature with
            ⟨entry, found, _⟩
          by_contra zero
          have indexZero : index = 0 := Nat.eq_zero_of_not_pos zero
          subst index
          simp [entryAt?] at found
        have commitPositive :
            0 < ((nodeOf state) source).commitIndex := by
          omega
        rcases evidenceFacts.nodePositive source commitPositive with
          ⟨sourceEvidence, sourceStored, sourceValid,
            _supportedLength, sourceTermBound⟩
        have sourceKnown :
            KnownCommitEvidence
              state appendHistory nodeEvidence requestEvidence
              sourceEvidence ((nodeOf state) source).committedLog :=
          Or.inl ⟨source, commitPositive, sourceStored, rfl⟩
        have sourceBound :
            index <= ((nodeOf state) source).log.length := by
          rcases isSignatureAtTrue oldSignature with
            ⟨entry, found, _⟩
          exact entryAtSomeIndexBound found
        have sourceInCommitted :
            ((nodeOf state) source).log.take index <+:
              ((nodeOf state) source).committedLog := by
          unfold NodeState.committedLog
          rw [List.prefix_take_iff]
          exact ⟨
            List.take_prefix _ _,
            by
              simp [
                List.length_take,
                Nat.min_eq_left sourceBound
              ]
              exact committed
          ⟩
        have committedInCandidate :=
          prospectiveKnownEffectiveWinnerCompleteness
            facts.entriesDoNotExceedCurrentTerm
            (invariantFactsCandidatesAboveBootstrap facts)
            facts.voteHistory facts.grantedVoteSnapshots
            ownership electionFacts configurationFacts evidenceFacts
            prospectiveFacts activationEvidence sourceKnown
            oldCandidateRole oldCandidateMajority
            (sourceTermBound.trans_lt oldLater)
        exact Or.inl
          (by simpa [logEq] using sourceInCommitted.trans committedInCandidate)
      · let sourceConfiguration :=
          currentConfiguration ((nodeOf state) source)
        let candidateConfiguration :=
          currentConfiguration ((nodeOf state) candidate)
        have sourceActive :
            sourceConfiguration ∈
              activeConfigurations ((nodeOf state) source) := by
          simpa [sourceConfiguration]
            using currentConfiguration_mem_activeConfigurations ((nodeOf state) source)
        have sourceGoverns : sourceConfiguration.index <= index := by
          have currentBound :=
            currentConfiguration_index_le_commitIndex
              ((nodeOf state) source)
          dsimp [sourceConfiguration]
          omega
        by_cases candidateBefore :
            candidateConfiguration.index <= sourceConfiguration.index
        · have sourceKnownCandidate :
              sourceConfiguration ∈
                allConfigurations ((nodeOf state) candidate).log := by
            by_cases sourceZero : sourceConfiguration.index = 0
            · have sourceImplicit :
                  sourceConfiguration = implicitConfiguration := by
                apply
                  allConfigurations_index_unique
                    (TxId := TxId) ((nodeOf state) source).log
                · simpa [sourceConfiguration]
                    using currentConfiguration_mem_allConfigurations
                      ((nodeOf state) source)
                · simp [allConfigurations, implicitConfiguration]
                · simpa [implicitConfiguration] using sourceZero
              simp [sourceImplicit, allConfigurations]
            · rcases
                  configurationActivations source
                    (by simpa [sourceConfiguration] using
                      Nat.pos_of_ne_zero sourceZero) with
                ⟨sourceWitness⟩
              have activationInCandidate :=
                activationPrefixInPotentialCandidateByCoverageAuthorityChain
                  (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
                    facts)
                  facts.entriesDoNotExceedCurrentTerm
                  facts.grantedVoteSnapshots
                  voteCanonicalFacts ownership electionFacts
                  activationQuorums.history
                  configurationFacts.supporterCurrentHistory
                  activationVoteHistory activationCanonical
                  activationElections configurationActivations
                  oldCandidateRole oldCandidateMajority
                  sourceWitness.activation.newConfiguration.index
                  sourceWitness.activationIndex sourceWitness.activation
                  rfl sourceWitness.stored
                  (sourceWitness.activationTermBound.trans_lt oldLater)
              apply
                memOfPrefix
                  (allConfigurations_mono_prefix
                    (activationInCandidate.trans
                      (List.take_prefix
                        (maxCommittableIndex
                          ((nodeOf state) candidate).log)
                        ((nodeOf state) candidate).log)))
              apply
                memOfPrefix
                  (allConfigurations_mono_prefix
                    sourceWitness.sharedPrefix_prefix_activationPrefix)
              simpa [sourceConfiguration]
                using
                  ConfigurationCoverageWitness.configuration_mem_activationHistoryTake
                    activationQuorums.history sourceWitness
          right
          exact ⟨
            sourceConfiguration,
            by simpa [activeConfigurationsEq] using sourceActive,
            sourceGoverns,
            by
              rw [activeConfigurationsEq]
              simpa [activeConfigurations, candidateConfiguration]
                using And.intro sourceKnownCandidate candidateBefore
          ⟩
        · have sourceBeforeCandidate :
              sourceConfiguration.index <
                candidateConfiguration.index := by
            omega
          have candidatePositive : 0 < candidateConfiguration.index := by
            omega
          rcases
              configurationActivations candidate
                (by simpa [candidateConfiguration] using
                  candidatePositive) with
            ⟨candidateWitness⟩
          let candidateActivation := candidateWitness.activation
          let candidateActivationIndex := candidateWitness.activationIndex
          have candidateStored :
              activations candidateActivationIndex =
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
                activationQuorums.history candidateWitness
          have candidateActivationInCandidate :=
            activationPrefixInPotentialCandidatePromotionOfGoverningConfiguration
              (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
                facts)
              facts.entriesDoNotExceedCurrentTerm
              facts.grantedVoteSnapshots voteCanonicalFacts
              ownership electionFacts activationQuorums.history
              configurationFacts.supporterCurrentHistory
              activationVoteHistory activationElections candidateStored
              oldCandidateRole oldCandidateMajority
              (candidateWitness.candidateTermStrict oldCandidateRole)
              candidateWitness.configurationCovered
              (currentConfiguration_mem_activeConfigurations
                ((nodeOf state) candidate))
          rcases Nat.lt_trichotomy
              ((nodeOf state) source).currentTerm
              candidateActivation.activationTerm with
            activationLater | sameTerm | activationEarlier
          · have owned :=
              activationCanonical.termOwner
                candidateActivationIndex candidateActivation
                candidateStored
            rcases
                electionFacts.ownerRecorded
                  candidateActivation.activationTerm
                  candidateActivation.leader owned with
              bootstrap | elected
            · have activationTerm :
                  candidateActivation.activationTerm = BOOTSTRAP_TERM := by
                simpa using bootstrap.1
              have sourcePositive :=
                facts.currentTermsPositive source
                  (by rw [oldSourceRole]; decide)
              omega
            · rcases elected with
                ⟨activationElection, electionStored, _leader⟩
              have sourceInElection :=
                potentialPrefixInElectionRecordsFromActivationHistory
                  termsPositiveAfter entriesBoundedAfter voteFactsAfter
                  ownershipAfter electionFactsAfter configurationFactsAfter
                  activationQuorums.history activationProgressAfter
                  ackerActivationAfter temporalFacts.2.2
                  activationCanonical activationElections
                  configurationActivationsAfter evidenceAfter prospectiveAfter
                  role current signature potential
                  candidateActivation.activationTerm
                  activationElection electionStored
                  (by simpa [termEq] using activationLater)
              have sourceInActivation :=
                electionPromotionPrefixInActivation
                  electionFacts activationQuorums.history
                  activationCanonical candidateStored electionStored
                  (by simpa [logEq] using sourceInElection)
              exact Or.inl
                (by simpa [logEq, committedEq] using
                  (sourceInActivation.trans
                    (candidateActivationInCandidate.trans
                      (List.take_prefix _ _))))
          · have activationInSource :
                candidateActivation.history.take
                    candidateActivation.activationFrontier <+:
                  ((nodeOf state) source).log := by
              rw [
                activationCanonical.activationFrontierCanonical
                  candidateActivationIndex candidateActivation
                  candidateStored,
                ← sameTerm,
                ownership.activeLeaderHistory source oldSourceRole
              ]
              exact List.take_prefix _ _
            have candidateKnownSource :
                candidateConfiguration ∈
                  allConfigurations ((nodeOf state) source).log := by
              apply
                memOfPrefix
                  (allConfigurations_mono_prefix activationInSource)
              exact candidateConfigurationKnown
            by_cases governs : candidateConfiguration.index <= index
            · exact Or.inr
                ⟨candidateConfiguration,
                  by
                    rw [activeConfigurationsEq]
                    simpa [activeConfigurations, sourceConfiguration] using
                      And.intro candidateKnownSource
                        sourceBeforeCandidate.le,
                  governs,
                  by simpa [activeConfigurationsEq,
                    candidateConfiguration] using
                    currentConfiguration_mem_activeConfigurations
                      ((nodeOf state) candidate)⟩
            · have activationLength :
                  (candidateActivation.history.take
                    candidateActivation.activationFrontier).length =
                      candidateActivation.activationFrontier := by
                simp [Nat.min_eq_left
                  (activationQuorums.history.valid
                    candidateActivationIndex candidateActivation
                    candidateStored).2.1]
              have exactTake := prefixEqTake activationInSource
              have exactFrontierTake :
                  ((nodeOf state) source).log.take
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
                  ((nodeOf state) source).log.take index <+:
                    candidateActivation.history.take
                      candidateActivation.activationFrontier := by
                rw [← exactFrontierTake]
                rcases isSignatureAtTrue oldSignature with
                  ⟨entry, found, _⟩
                rw [List.prefix_take_iff]
                exact ⟨
                  List.take_prefix _ _,
                  by
                    simp [
                      List.length_take,
                      Nat.min_eq_left (entryAtSomeIndexBound found)
                    ]
                    exact indexBefore
                ⟩
              exact Or.inl
                (by
                  simpa [logEq, committedEq]
                    using (sourceInActivation.trans
                            (candidateActivationInCandidate.trans
                              (List.take_prefix _ _))))
          · have sourceOwned := ownership.activeLeader source oldSourceRole
            rcases
                electionFacts.ownerRecorded
                  ((nodeOf state) source).currentTerm source sourceOwned with
              bootstrap | elected
            · have sourceTerm :
                  ((nodeOf state) source).currentTerm = BOOTSTRAP_TERM := by
                simpa using bootstrap.1
              have activationPositive :=
                activationQuorums.history.termPositive
                  candidateActivationIndex candidateActivation
                  candidateStored
              omega
            · rcases elected with
                ⟨sourceElection, sourceElectionStored, _leader⟩
              have activationInSource :
                  candidateActivation.history.take
                      candidateActivation.activationFrontier <+:
                    ((nodeOf state) source).log :=
                (activationPrefixInLaterElection
                  activationElections candidateStored
                  sourceElectionStored activationEarlier).trans
                  ((electionFacts.promotionCanonical
                    ((nodeOf state) source).currentTerm sourceElection
                    sourceElectionStored).trans
                    (by rw [
                      ownership.activeLeaderHistory source oldSourceRole
                    ]))
              have candidateKnownSource :
                  candidateConfiguration ∈
                    allConfigurations ((nodeOf state) source).log := by
                apply
                  memOfPrefix
                    (allConfigurations_mono_prefix activationInSource)
                exact candidateConfigurationKnown
              by_cases governs :
                  candidateConfiguration.index <= index
              · exact Or.inr
                  ⟨candidateConfiguration,
                    by
                      rw [activeConfigurationsEq]
                      simpa [activeConfigurations, sourceConfiguration] using
                        And.intro candidateKnownSource
                          sourceBeforeCandidate.le,
                    governs,
                    by simpa [activeConfigurationsEq,
                      candidateConfiguration] using
                      currentConfiguration_mem_activeConfigurations
                        ((nodeOf state) candidate)⟩
              · have activationLength :
                    (candidateActivation.history.take
                      candidateActivation.activationFrontier).length =
                        candidateActivation.activationFrontier := by
                  simp [Nat.min_eq_left
                    (activationQuorums.history.valid
                      candidateActivationIndex candidateActivation
                      candidateStored).2.1]
                have exactTake := prefixEqTake activationInSource
                have exactFrontierTake :
                    ((nodeOf state) source).log.take
                        candidateActivation.activationFrontier =
                      candidateActivation.history.take
                        candidateActivation.activationFrontier := by
                  simpa [activationLength] using exactTake
                have sourceInActivation :
                    ((nodeOf state) source).log.take index <+:
                      candidateActivation.history.take
                        candidateActivation.activationFrontier := by
                  rw [← exactFrontierTake]
                  have configurationWithin :
                      candidateConfiguration.index <=
                        candidateActivation.activationFrontier := by
                    simpa [candidateConfiguration]
                      using candidateWitness.configurationIndexBound.trans
                        candidateWitness.sharedFrontier_le_activationFrontier
                  rcases isSignatureAtTrue oldSignature with
                    ⟨entry, found, _⟩
                  rw [List.prefix_take_iff]
                  exact ⟨
                    List.take_prefix _ _,
                    by
                      simp [
                        List.length_take,
                        Nat.min_eq_left (entryAtSomeIndexBound found)
                      ]
                      omega
                  ⟩
                exact Or.inl
                  (by
                    simpa [logEq, committedEq]
                      using (sourceInActivation.trans
                              (candidateActivationInCandidate.trans
                                (List.take_prefix _ _))))
    · intro source index role current signature majority node
      rcases
          activationQuorums.committedBridge
            source index (leaderRoleBack source role)
            (by simpa [logEq, termEq] using current)
            (by simpa [logEq] using signature)
            ((effectiveMajorityEq source index).mp majority)
            node with
        direct | direct | shared
      · exact Or.inl (by simpa [logEq, committedEq] using direct)
      · exact Or.inr (Or.inl
          (by simpa [logEq, committedEq] using direct))
      · right
        right
        rcases shared with
          ⟨configuration, sourceActive, governs, configurationEq⟩
        exact ⟨
          configuration,
          by simpa [activeConfigurationsEq] using sourceActive,
          governs,
          by simpa [currentConfiguration, logEq, commitEq] using configurationEq
        ⟩
    · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
        right rightIndex rightRole rightCurrent rightSignature rightMajority
      rcases
          activationQuorums.potentialBridge
            left leftIndex (leaderRoleBack left leftRole)
            (by simpa [logEq, termEq] using leftCurrent)
            (by simpa [logEq] using leftSignature)
            ((effectiveMajorityEq left leftIndex).mp leftMajority)
            right rightIndex (leaderRoleBack right rightRole)
            (by simpa [logEq, termEq] using rightCurrent)
            (by simpa [logEq] using rightSignature)
            ((effectiveMajorityEq right rightIndex).mp rightMajority) with
        direct | direct | shared
      · exact Or.inl (by simpa [logEq] using direct)
      · exact Or.inr (Or.inl (by simpa [logEq] using direct))
      · right
        right
        rcases shared with
          ⟨configuration, leftActive, leftGoverns,
            rightActive, rightGoverns⟩
        exact ⟨
          configuration,
          by simpa [activeConfigurationsEq] using leftActive,
          leftGoverns,
          by simpa [activeConfigurationsEq] using rightActive,
          rightGoverns
        ⟩
    · intro activationIndex activation queuedDestination queuedRequest
        stored queued sameTerm
      exact
        activationQuorums.queuedComparable
          activationIndex activation queuedDestination queuedRequest
          stored
          (by simpa [networkEq] using queued)
          sameTerm
    · exact
        committedConfigurationCoverageFrame
          activationQuorums.committedCoverage logEq commitEq
          (fun node => Nat.le_of_eq (termEq node).symm)
    · apply
        queuedConfigurationCoverageFrame
          activationQuorums.queuedCoverage
          (afterAppendHistory := appendHistory)
      · intro queuedDestination queuedRequest queued
        simpa [networkEq] using queued
      · intro _
        rfl
  have activationEvidenceAfter :
      ActivationEvidenceFacts (joined := joinedNodes)
        after appendHistory responseHistory nodeEvidence requestEvidence
          elections activations := by
    apply
      activationEvidenceFrame
        state after appendHistory appendHistory
        responseHistory responseHistory
        nodeEvidence nodeEvidence requestEvidence requestEvidence
        elections elections activations activationEvidence
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state after appendHistory nodeEvidence requestEvidence
          commitEq committedEq
          (fun queuedDestination queuedRequest member => by
            simpa [networkEq] using member)
          known
    · intro candidate role majority
      have candidateNe : Not (candidate = destination) := by
        intro same
        subst candidate
        exact Role.noConfusion (role.symm.trans roleDestination)
      exact ⟨
        by simpa [roleOther candidate candidateNe] using role,
        (potentialElectionMajorityEq candidate).mp majority
      ⟩
    · intro candidate role
      exact termEq candidate
    · intro candidate role
      simp [logEq]
    · intro candidate configuration role active
      simpa [activeConfigurationsEq] using active
  · exact ⟨
      owners,
      canonicalHistory,
      elections,
      activations,
      nodeEvidence,
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
      activationCanonical,
      activationElections,
      configurationActivationsAfter
    ⟩
  · intro candidate voter active member
    have candidateNe : Not (candidate = destination) := by
      intro same
      subst candidate
      rcases active with candidateActive | leaderActive
      · exact Role.noConfusion (candidateActive.symm.trans roleDestination)
      · exact Role.noConfusion (leaderActive.symm.trans roleDestination)
    rw [termEq candidate, termEq voter]
    have oldActive :
        ((nodeOf state) candidate).role = .candidate \/
          ((nodeOf state) candidate).role = .leader := by
      rw [roleOther candidate candidateNe] at active
      exact active
    have oldMember :
        voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    simpa [voteLogUpToDate, logEq]
      using facts.grantedVoteSnapshots candidate voter oldActive oldMember
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
        by simpa [termEq] using snapshotTerm,
        by simpa [matchEq] using snapshotIndex,
        historyBound,
        by simpa [logEq] using agreed
      ⟩
  · constructor
    · intro node peer member
      exact
        facts.joinedCarriers.activeNodes node
          (activeNodeUnion_subset_of_activeConfigurations_subset
            ((nodeOf state) node) ((nodeOf after) node)
            (by
              intro configuration active
              simpa [activeConfigurationsEq] using active)
            member)
    · intro node configuration member peer inNodes
      exact
        facts.joinedCarriers.configurationNodes node configuration
          (by simpa [logEq] using member) inNodes
    · intro node peer member
      exact
        facts.joinedCarriers.grantedVotes node
          (by simpa [votesEq] using member)
    · intro queuedDestination request member
      exact
        facts.joinedCarriers.voteRequestDestinations
          queuedDestination request
          (by simpa [networkEq] using member)
    · intro queuedDestination request member
      exact
        facts.joinedCarriers.appendRequestDestinations
          queuedDestination request
          (by simpa [networkEq] using member)
    · intro queuedDestination request member configuration configured
        peer inNodes
      exact
        facts.joinedCarriers.appendRequestConfigurations
          queuedDestination request
            (by simpa [networkEq] using member)
          configuration configured inNodes
    · intro queuedDestination response member
      exact
        facts.joinedCarriers.voteResponseSources
          queuedDestination response
          (by simpa [networkEq] using member)
    · constructor
      · intro candidate active
        have different : Not (candidate = destination) := by
          intro same
          subst candidate
          rcases active with candidateRole | leaderRole
          · exact Role.noConfusion (candidateRole.symm.trans roleDestination)
          · exact Role.noConfusion (leaderRole.symm.trans roleDestination)
        exact
          facts.joinedCarriers.runtimeNodes.activeRoles candidate
            (by simpa [roleOther candidate different] using active)
      · intro leader peer positive
        exact
          facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
            (by simpa [matchEq] using positive)
      · intro queuedDestination response member
        exact
          facts.joinedCarriers.runtimeNodes.appendResponses
            queuedDestination response
              (by simpa [networkEq] using member)
      · intro candidate nonempty
        exact
          facts.joinedCarriers.runtimeNodes.nonemptyLogs candidate
            (by simpa [logEq] using nonempty)
  · intro candidate
    simpa only [termEq] using facts.currentTermsValid candidate
  · simpa only [NetworkTermsValid, networkEq] using facts.networkTermsValid

end CCFRaft.Proofs.Invariant
