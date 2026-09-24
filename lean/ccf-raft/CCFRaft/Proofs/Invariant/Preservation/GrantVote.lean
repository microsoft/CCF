-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.RejectVote
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

/-- Enqueuing a granted vote response materialises prospective election evidence. -/
lemma enqueueGrantedVoteResponsePreservesSystemInductiveInvariant
    (state : View Node TxId)
    (source destination : Node)
    (request : RequestVoteRequest Node)
    (nextNode : NodeState Node TxId)
    (response : RequestVoteResponse Node)
    (remaining : List (Message Node TxId))
    (invariant : SystemInductiveInvariant state)
    (taken
      : Selected source (state.network destination) (.requestVoteRequest request)
          remaining)
    (handled
      : handleRequestVoteRequest? (state.nodes destination) request
        = some (nextNode, response))
    (granted : response.voteGranted = true)
    : SystemInductiveInvariant
        {
          state with
            nodes := updateNode state.nodes destination nextNode
            network :=
              enqueue state.network (.requestVoteResponse response)
        } := by
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
  let post := handleRequestVoteRequestLocalPost handled
  have grantFacts := post.granted granted
  have selectedMember :
      Message.requestVoteRequest request ∈ state.network destination :=
    (selectedSound taken).2.1
  have requestSource : request.source = source :=
    (selectedSound taken).1
  have requestFacts :=
    facts.networkHistory.voteRequest destination request selectedMember
  have requestDestination : request.destination = destination := by
    simpa using
      facts.networkHistory.addressed
        destination (.requestVoteRequest request) selectedMember
  have responseKey :
      response =
        grantedVoteKey destination request.term request.source := by
    cases response
    simp only [grantedVoteKey, RequestVoteResponse.mk.injEq]
    exact ⟨
      post.responseTerm.trans grantFacts.1.symm,
      granted,
      post.responseSource.trans requestDestination,
      post.responseDestination
    ⟩
  let newVotes : VoteHistory (Node : Type) :=
    Function.update votes destination
      (Function.update
        (votes destination) request.term (some request.source))
  let newCandidateHistory :=
    Function.update voteCandidateHistory response
      (voteRequestHistory request)
  let newVoterHistory :=
    Function.update voteVoterHistory response
      ((state.nodes destination).log.take
        (maxCommittableIndex (state.nodes destination).log))
  have voterSnapshotCommittable :
      maxCommittableIndex
          ((state.nodes destination).log.take
            (maxCommittableIndex (state.nodes destination).log)) =
        ((state.nodes destination).log.take
          (maxCommittableIndex (state.nodes destination).log)).length := by
    rw [maxCommittableIndexTakeMax]
    simp [
      Nat.min_eq_left
        (maxCommittableIndexBounded (state.nodes destination).log)
    ]
  let after : View Node TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network :=
        enqueue state.network (.requestVoteResponse response) }
  have roleEq :
      forall node,
        (after.nodes node).role = (state.nodes node).role := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.roleUnchanged
    · simp [after, updateNode, same]
  have termEq :
      forall node,
        (after.nodes node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.currentTermUnchanged
    · simp [after, updateNode, same]
  have logEq :
      forall node,
        (after.nodes node).log = (state.nodes node).log := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.logUnchanged
    · simp [after, updateNode, same]
  have commitEq :
      forall node,
        (after.nodes node).commitIndex =
          (state.nodes node).commitIndex := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.commitIndexUnchanged
    · simp [after, updateNode, same]
  have lastIndexEq :
      forall node,
        lastCommittableIndex (after.nodes node) =
          lastCommittableIndex (state.nodes node) := by
    intro node
    exact lastCommittableIndexFrame (logEq node) (commitEq node)
  have lastTermEq :
      forall node,
        lastCommittableTerm (after.nodes node) =
          lastCommittableTerm (state.nodes node) := by
    intro node
    exact lastCommittableTermFrame (logEq node) (commitEq node)
  have sentEq :
      forall node,
        (after.nodes node).sentIndex =
          (state.nodes node).sentIndex := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.sentIndexUnchanged
    · simp [after, updateNode, same]
  have matchEq :
      forall node,
        (after.nodes node).matchIndex =
          (state.nodes node).matchIndex := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.matchIndexUnchanged
    · simp [after, updateNode, same]
  have votesGrantedEq :
      forall node,
        (after.nodes node).votesGranted =
          (state.nodes node).votesGranted := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, updateNode] using post.votesGrantedUnchanged
    · simp [after, updateNode, same]
  have votedForDestination :
      (after.nodes destination).votedFor =
        some request.source := by
    simpa [after, updateNode] using grantFacts.2.2.2
  have votedForOther :
      forall node,
        Not (node = destination) ->
          (after.nodes node).votedFor =
            (state.nodes node).votedFor := by
    intro node different
    simp [after, updateNode, different]
  have committedEq :
      forall node,
        (after.nodes node).committedLog =
          (state.nodes node).committedLog := by
    intro node
    simp [NodeState.committedLog, commitEq, logEq]
  have activeConfigurationsEq :
      forall node,
        activeConfigurations (after.nodes node) =
          activeConfigurations (state.nodes node) := by
    intro node
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have appendRequestEq :
      forall queuedDestination queuedRequest,
        Message.appendEntriesRequest queuedRequest ∈
            after.network queuedDestination ↔
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
    intro queuedDestination queuedRequest
    constructor
    · intro member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.appendEntriesRequest queuedRequest) queuedDestination
              (by simpa [after] using member) with
        old | new
      · exact old
      · simp at new
    · intro member
      simpa [after]
        using memEnqueueNoDupOfMem
          state.network (.requestVoteResponse response)
          (.appendEntriesRequest queuedRequest)
          queuedDestination member
  have appendResponseEq :
      forall queuedDestination queuedResponse,
        Message.appendEntriesResponse queuedResponse ∈
            after.network queuedDestination ↔
          Message.appendEntriesResponse queuedResponse ∈
            state.network queuedDestination := by
    intro queuedDestination queuedResponse
    constructor
    · intro member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.appendEntriesResponse queuedResponse) queuedDestination
              (by simpa [after] using member) with
        old | new
      · exact old
      · simp at new
    · intro member
      simpa [after]
        using memEnqueueNoDupOfMem
          state.network (.requestVoteResponse response)
          (.appendEntriesResponse queuedResponse)
          queuedDestination member
  have effectiveAckersEq :
      forall leader index,
        effectiveAckers after responseHistory leader index =
          effectiveAckers state responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      effectiveAckers, Finset.mem_filter]
    apply and_congr (by simp [after])
    constructor <;> rintro (self | matched | queued)
    · exact Or.inl self
    · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      exact ⟨
        queuedResponse,
        (appendResponseEq leader queuedResponse).mp member,
        success,
        by simpa [termEq] using responseTerm,
        responseSource,
        responseDestination,
        lastIndex,
        by simpa [logEq] using covered
      ⟩
    · exact Or.inl self
    · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      exact ⟨
        queuedResponse,
        (appendResponseEq leader queuedResponse).mpr member,
        success,
        by simpa [termEq] using responseTerm,
        responseSource,
        responseDestination,
        lastIndex,
        by simpa [logEq] using covered
      ⟩
  have queuedAppendReserveEq :
      forall leader peer index,
        queuedAppendReserve after appendHistory leader peer index ↔
          queuedAppendReserve state appendHistory leader peer index := by
    intro leader peer index
    have producibleEq :
        forall queuedRequest,
          canProduceAppendAckEventuallyAt
              (after.nodes peer) queuedRequest index ↔
            canProduceAppendAckEventuallyAt
              (state.nodes peer) queuedRequest index := by
      intro queuedRequest
      by_cases peerEq : peer = destination
      · subst peer
        have destinationStateEq :
            after.nodes destination =
              { state.nodes destination with
                votedFor := some request.source } := by
          simp [
            after, updateNode, post.grantedState granted
          ]
        rw [destinationStateEq]
        exact
          canProduceAppendAckEventuallyAt_votedFor
            (state.nodes destination) (some request.source)
              queuedRequest index
      · simp [after, updateNode, peerEq]
    constructor
    · rintro ⟨queuedRequest, member, requestSource, requestDestination,
               requestTerm, producible, covered⟩
      exact ⟨
        queuedRequest,
        (appendRequestEq peer queuedRequest).mp member,
        requestSource,
        requestDestination,
        by simpa [termEq] using requestTerm,
        (producibleEq queuedRequest).mp producible,
        by simpa [logEq] using covered
      ⟩
    · rintro ⟨queuedRequest, member, requestSource, requestDestination,
               requestTerm, producible, covered⟩
      exact ⟨
        queuedRequest,
        (appendRequestEq peer queuedRequest).mpr member,
        requestSource,
        requestDestination,
        by simpa [termEq] using requestTerm,
        (producibleEq queuedRequest).mpr producible,
        by simpa [logEq] using covered
      ⟩
  have potentialAckersEq :
      forall leader index,
        potentialAckers after appendHistory responseHistory leader index =
          potentialAckers
            state appendHistory responseHistory leader index := by
    intro leader index
    ext peer
    simp only [
      potentialAckers, Finset.mem_filter,
      effectiveAckersEq, queuedAppendReserveEq
    ]
    simp [after]
  have potentialReplicationMajorityEq :
      forall leader index,
        hasPotentialMajorityAt
            after appendHistory responseHistory leader index ↔
          hasPotentialMajorityAt
            state appendHistory responseHistory leader index := by
    intro leader index
    unfold hasPotentialMajorityAt
    rw [potentialAckersEq, activeConfigurationsEq]
  have oldEffectiveSubset :
      forall candidate,
        effectiveElectionVoters state candidate ⊆
          effectiveElectionVoters after candidate := by
    intro candidate voter member
    simp only [
      effectiveElectionVoters, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, processed | queued⟩
    · exact ⟨
        by simpa [after] using joined,
        Or.inl (by simpa [votesGrantedEq] using processed)
      ⟩
    · refine ⟨by simpa [after] using joined, Or.inr ?_⟩
      rcases queued with
        ⟨queuedResponse, queuedMember, queuedGranted, responseTerm,
          responseSource, responseDestination⟩
      exact ⟨
        queuedResponse,
        by
          simpa [after]
            using memEnqueueNoDupOfMem
              state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse)
              candidate queuedMember,
        queuedGranted,
        by simpa [termEq] using responseTerm,
        responseSource,
        responseDestination
      ⟩
  have newEffectiveClassify :
      forall candidate voter,
        voter ∈ effectiveElectionVoters after candidate ->
          voter ∈ effectiveElectionVoters state candidate \/
            (candidate = request.source /\
              voter = destination /\
              (state.nodes candidate).currentTerm = request.term) := by
    intro candidate voter member
    simp only [
      effectiveElectionVoters, Finset.mem_filter] at member
    rcases member with ⟨joined, processed | queued⟩
    · left
      simp only [
        effectiveElectionVoters, Finset.mem_filter]
      exact ⟨
        by simpa [after] using joined,
        Or.inl (by simpa [votesGrantedEq] using processed)
      ⟩
    · rcases queued with
        ⟨queuedResponse, queuedMember, queuedGranted, responseTerm,
          responseSource, responseDestination⟩
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse) candidate
              (by simpa [after] using queuedMember) with
        old | new
      · left
        simp only [
          effectiveElectionVoters, Finset.mem_filter]
        exact ⟨
          by simpa [after] using joined,
          Or.inr
            ⟨
              queuedResponse,
              old,
              queuedGranted,
              by simpa [termEq] using responseTerm,
              responseSource,
              responseDestination
            ⟩
        ⟩
      · simp only [Message.requestVoteResponse.injEq] at new
        have sameResponse : queuedResponse = response := new.2
        subst queuedResponse
        right
        have candidateEq :
            candidate = request.source := by
          exact new.1.trans post.responseDestination
        have voterEq : voter = destination := by
          simpa [post.responseSource, requestDestination] using responseSource.symm
        exact ⟨
          candidateEq,
          voterEq,
          by
            rw [candidateEq]
            have candidateResponse :
                response.term =
                  (state.nodes request.source).currentTerm := by
              simpa [termEq, candidateEq] using responseTerm
            exact
              candidateResponse.symm.trans
                (post.responseTerm.trans grantFacts.1.symm)
        ⟩
  have effectiveElectionVotersOtherEq :
      forall candidate,
        Not (candidate = request.source) ->
          effectiveElectionVoters after candidate =
            effectiveElectionVoters state candidate := by
    intro candidate candidateNe
    apply Finset.Subset.antisymm
    · intro voter member
      rcases newEffectiveClassify candidate voter member with old | added
      · exact old
      · exact False.elim (candidateNe added.1)
    · exact oldEffectiveSubset candidate
  have effectiveElectionMajorityOtherEq :
      forall candidate,
        Not (candidate = request.source) ->
          (hasEffectiveElectionMajority after candidate ↔
            hasEffectiveElectionMajority state candidate) := by
    intro candidate candidateNe
    unfold hasEffectiveElectionMajority
    rw [
      effectiveElectionVotersOtherEq candidate candidateNe,
      activeConfigurationsEq
    ]
  have effectiveSubsetPotential :
      forall candidate,
        (after.nodes candidate).role = .candidate ->
        effectiveElectionVoters after candidate ⊆
          potentialElectionVoters state candidate := by
    intro candidate candidateRole voter member
    rcases newEffectiveClassify candidate voter member with old | new
    · exact
        effectiveElectionVotersSubsetPotential
          state candidate old
    · rcases new with ⟨candidateEq, voterEq, candidateTerm⟩
      subst candidate
      subst voter
      simp only [
        potentialElectionVoters, Finset.mem_filter]
      refine ⟨
        facts.joinedCarriers.voteRequestDestinations destination request selectedMember,
        Or.inr ?_
      ⟩
      unfold currentlyEligibleElectionVoter
      have sourceRole :
          (state.nodes request.source).role = .candidate := by
        simpa [roleEq] using candidateRole
      have sourceCurrent :
          request.term =
            (state.nodes request.source).currentTerm :=
        candidateTerm.symm
      have candidatePrefix :
          voteRequestHistory request <+:
            (state.nodes request.source).log :=
        requestFacts.2.2.2.2.2
          sourceCurrent (Or.inl sourceRole)
      have canonicalUpToDate :
          voteLogUpToDate
            (state.nodes destination)
            (makeRequestVoteRequest
              state request.source destination) := by
        simpa [voteLogUpToDate, makeRequestVoteRequest,
          lastCommittableIndex_eq_maxCommittableIndex
            (state.nodes request.source)
            (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
              facts request.source),
          lastCommittableTerm_eq_maxCommittableTerm
            (state.nodes request.source)
            (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
              facts request.source), sourceCurrent, grantFacts.1]
          using (voteLogUpToDateOfCandidatePrefix
                  (state.nodes destination) request.source destination
                  candidatePrefix
                  (monoLog request.source)
                  (by simpa [
                      voteLogUpToDate, maxCommittableTerm,
                      requestFacts.1, requestFacts.2.1,
                      requestFacts.2.2.1
                    ] using grantFacts.2.1))
      exact ⟨
        by simpa [makeRequestVoteRequest] using sourceCurrent.symm.trans grantFacts.1,
        canonicalUpToDate,
        grantFacts.2.2.1
      ⟩
  have potentialMajorityBack :
      forall candidate,
        (after.nodes candidate).role = .candidate ->
        hasEffectiveElectionMajority after candidate ->
          hasPotentialElectionMajority state candidate := by
    intro candidate role majority
    rw [hasEffectiveElectionMajority, List.all_eq_true] at majority
    rw [hasPotentialElectionMajority, List.all_eq_true]
    intro configuration active
    apply decide_eq_true
    exact
      hasConfigurationMajority_mono
        (effectiveSubsetPotential candidate role)
        (of_decide_eq_true
          (majority configuration
            (by simpa [activeConfigurationsEq] using active)))
  have potentialElectionVotersAfterSubset :
      forall candidate,
        (after.nodes candidate).role = .candidate ->
          potentialElectionVoters after candidate ⊆
            potentialElectionVoters state candidate := by
    intro candidate candidateRole voter member
    simp only [
      potentialElectionVoters, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | eligible⟩
    · simpa [potentialElectionVoters]
        using effectiveSubsetPotential candidate candidateRole effective
    · refine ⟨by simpa [after] using joined, Or.inr ?_⟩
      by_cases voterEq : voter = destination
      · subst voter
        unfold currentlyEligibleElectionVoter at eligible ⊢
        have candidateEq : candidate = request.source := by
          rcases eligible.2.2 with noVote | sameVote
          · rw [votedForDestination] at noVote
            contradiction
          · rw [votedForDestination] at sameVote
            exact (Option.some.inj sameVote).symm
        refine ⟨
          by simpa [
              makeRequestVoteRequest, termEq, candidateEq
            ] using eligible.1,
          by simpa [
              makeRequestVoteRequest, logEq,
              lastIndexEq, lastTermEq, voteLogUpToDate
            ] using eligible.2.1,
          ?_
        ⟩
        simpa [candidateEq] using grantFacts.2.2.1
      · simpa [
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          termEq, logEq, lastIndexEq, lastTermEq,
          votedForOther voter voterEq, voteLogUpToDate
        ] using eligible
  have potentialElectionMajorityBack :
      forall candidate,
        (after.nodes candidate).role = .candidate ->
        hasPotentialElectionMajority after candidate ->
          hasPotentialElectionMajority state candidate := by
    intro candidate role majority
    exact
      potentialElectionMajorityOfSubset
        (potentialElectionVotersAfterSubset candidate role)
        (activeConfigurationsEq candidate) majority
  have effectiveMajorityEq :
      forall leader index,
        hasEffectiveMajorityAt after responseHistory leader index ↔
          hasEffectiveMajorityAt state responseHistory leader index := by
    intro leader index
    unfold hasEffectiveMajorityAt
    rw [effectiveAckersEq, activeConfigurationsEq]
  have votesPreserved :
      forall term record voter,
        elections term = some record ->
        voter ∈ record.supporters ->
          newVotes voter term = votes voter term := by
    intro term record voter recorded member
    by_cases voterEq : voter = destination
    · subst voter
      by_cases termEqRequest : term = request.term
      · subst term
        have oldVote :=
          electionFacts.voted
            request.term record destination recorded member
        have currentVote :=
          facts.voteHistory.current destination
        rw [← grantFacts.1] at currentVote
        rcases grantFacts.2.2.1 with noVote | sameVote
        · rw [currentVote, noVote] at oldVote
          contradiction
        · have candidateEq :
              record.leader = request.source := by
            rw [currentVote, sameVote] at oldVote
            exact (Option.some.inj oldVote).symm
          simp [
            newVotes, Function.update,
            oldVote, candidateEq
          ]
      · simp [newVotes, Function.update, termEqRequest]
    · simp [newVotes, voterEq]
  have newElectionFacts :
      ElectionHistoryFacts
        after newVotes canonicalHistory owners elections :=
    electionHistoryFrame
      state after votes newVotes canonicalHistory canonicalHistory
        owners elections electionFacts votesPreserved
        (fun term => prefixRefl (canonicalHistory term))
        (fun _ canonical => canonical)
  have voteHistoryAfter : VoteHistoryFacts after newVotes := by
    constructor
    · intro voter
      by_cases voterEq : voter = destination
      · subst voter
        have requestAbove : BOOTSTRAP_TERM < request.term :=
          requestFacts.2.2.2.1
        simpa [
          newVotes, Function.update,
          requestAbove.ne
        ] using facts.voteHistory.bootstrapEmpty destination
      · simpa [newVotes, Function.update, voterEq]
          using facts.voteHistory.bootstrapEmpty voter
    · intro voter
      by_cases voterEq : voter = destination
      · subst voter
        simp [
          newVotes, Function.update,
          termEq, grantFacts.1, votedForDestination
        ]
      · simpa [
          newVotes, Function.update, voterEq,
          termEq, votedForOther voter voterEq
        ] using facts.voteHistory.current voter
    · intro voter term future
      by_cases voterEq : voter = destination
      · subst voter
        have termNe : Not (term = request.term) := by
          intro same
          subst term
          rw [termEq, grantFacts.1] at future
          omega
        simpa [newVotes, Function.update, termNe]
          using facts.voteHistory.future destination term (by simpa [termEq] using future)
      · simpa [newVotes, Function.update, voterEq]
          using facts.voteHistory.future voter term (by simpa [termEq] using future)
    · intro candidate voter active member
      have oldActive :
          (state.nodes candidate).role = .candidate \/
            (state.nodes candidate).role = .leader := by
        simpa [roleEq] using active
      have oldMember :
          voter ∈ (state.nodes candidate).votesGranted := by
        simpa [votesGrantedEq] using member
      have oldCounted :=
        facts.voteHistory.counted
          candidate voter oldActive oldMember
      by_cases voterEq : voter = destination
      · subst voter
        by_cases termEqRequest :
            (state.nodes candidate).currentTerm = request.term
        · have currentVote :=
            facts.voteHistory.current destination
          rw [← grantFacts.1, ← termEqRequest] at currentVote
          rcases grantFacts.2.2.1 with noVote | sameVote
          · rw [currentVote, noVote] at oldCounted
            contradiction
          · have candidateEq : candidate = request.source := by
              rw [currentVote, sameVote] at oldCounted
              exact (Option.some.inj oldCounted).symm
            rw [termEq, termEqRequest, candidateEq]
            simp [newVotes]
        · simpa [
            newVotes, Function.update,
            termEq, termEqRequest
          ] using oldCounted
      · simpa [
          newVotes, Function.update,
          voterEq, termEq
        ] using oldCounted
  have responseTermRequest : response.term = request.term :=
    post.responseTerm.trans grantFacts.1.symm
  have recordedVotePreserved :
      forall voter term candidate,
        votes voter term = some candidate ->
          newVotes voter term = some candidate := by
    intro voter term candidate voted
    by_cases voterEq : voter = destination
    · subst voter
      by_cases termRequest : term = request.term
      · subst term
        have currentVote := facts.voteHistory.current destination
        rw [← grantFacts.1] at currentVote
        rcases grantFacts.2.2.1 with noVote | sameVote
        · rw [currentVote, noVote] at voted
          contradiction
        · have candidateEq : candidate = request.source := by
            rw [currentVote, sameVote] at voted
            exact (Option.some.inj voted).symm
          simp [newVotes, candidateEq]
      · simpa [
          newVotes, Function.update, termRequest
        ] using voted
    · simpa [
        newVotes, Function.update, voterEq
      ] using voted
  have responseTermBound :
      response.term <=
        (after.nodes response.destination).currentTerm := by
    rw [post.responseDestination, termEq]
    exact responseTermRequest.trans_le requestFacts.2.2.2.2.1
  have oldGrantedVotePreserved :
      forall queuedDestination queuedResponse,
        Message.requestVoteResponse queuedResponse ∈
            state.network queuedDestination ->
        queuedResponse.voteGranted = true ->
          newVotes queuedResponse.source queuedResponse.term =
            some queuedResponse.destination := by
    intro queuedDestination queuedResponse member queuedGranted
    rcases
        facts.networkHistory.voteResponse
          queuedDestination queuedResponse member queuedGranted with
      ⟨_, voted, _⟩
    by_cases sourceEq : queuedResponse.source = destination
    · by_cases termRequest : queuedResponse.term = request.term
      · have currentVote := facts.voteHistory.current destination
        have relevantCurrent :
            votes queuedResponse.source queuedResponse.term =
              (state.nodes destination).votedFor := by
          simpa [sourceEq, termRequest, grantFacts.1] using currentVote
        rcases grantFacts.2.2.1 with noVote | sameVote
        · rw [relevantCurrent, noVote] at voted
          contradiction
        · have candidateEq :
              queuedResponse.destination = request.source := by
            rw [relevantCurrent, sameVote] at voted
            exact (Option.some.inj voted).symm
          simp [
            newVotes, Function.update,
            sourceEq, termRequest, candidateEq
          ]
      · simpa [
          newVotes, Function.update,
          sourceEq, termRequest
        ] using voted
    · simpa [
        newVotes, Function.update, sourceEq
      ] using voted
  change SystemInductiveInvariant after
  refine ⟨
    newVotes,
    appendHistory,
    responseHistory,
    voteRequestHistory,
    newCandidateHistory,
    newVoterHistory,
    ?_
  ⟩
  constructor
  · intro node
    rw [commitEq, logEq]
    exact facts.commitIndicesBounded node
  · intro node
    rw [termEq]
    intro active
    exact
      facts.currentTermsPositive node
        (by simpa [roleEq] using active)
  · intro node entry member
    rw [termEq]
    apply
      facts.entriesDoNotExceedCurrentTerm node entry
    simpa [logEq] using member
  · intro candidate role
    have oldRole : (state.nodes candidate).role = .candidate := by
      simpa [roleEq] using role
    have old := facts.candidatesSelfVote candidate oldRole
    exact ⟨
      by
        by_cases same : candidate = destination
        · subst candidate
          have candidateVote :
              (state.nodes destination).votedFor = some destination :=
            old.1
          rcases grantFacts.2.2.1 with noVote | sameVote
          · rw [candidateVote] at noVote
            contradiction
          · rw [candidateVote] at sameVote
            have sourceEq :
                request.source = destination :=
              Option.some.inj sameVote.symm
            simp [votedForDestination, sourceEq]
        · simpa [votedForOther candidate same] using old.1,
      by simpa [votesGrantedEq] using old.2
    ⟩
  · intro leader role
    rcases
        facts.leadersHaveElectionWitness leader
          (by simpa [roleEq] using role) with
      bootstrap | majority
    · exact Or.inl
        ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
    · exact Or.inr (by
        simpa [logEq, votesGrantedEq] using majority)
  · intro leader role peer
    simpa [sentEq, matchEq, logEq]
      using facts.leaderProgressBounded leader (by simpa [roleEq] using role) peer
  · exact voteHistoryAfter
  · constructor
    · intro queuedDestination message member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              message queuedDestination
              (by simpa [after] using member) with
        old | new
      · exact
          facts.networkHistory.addressed
            queuedDestination message old
      · exact (congrArg Message.destination new.2).trans new.1.symm
    · intro queuedDestination queuedRequest member
      have old :=
        facts.networkHistory.appendRequest
          queuedDestination queuedRequest
            ((appendRequestEq queuedDestination queuedRequest).mp member)
      refine ⟨old.1, old.2.1, ?_⟩
      unfold RequestCommitStillPresent at old ⊢
      simpa [committedEq] using old.2.2
    · intro queuedDestination queuedResponse member
      have old :=
        facts.networkHistory.appendResponse
          queuedDestination queuedResponse
            ((appendResponseEq queuedDestination queuedResponse).mp member)
      intro success
      rcases old success with ⟨bound, termBound, active⟩
      exact ⟨
        bound,
        by simpa [termEq] using termBound,
        by
          intro sameTerm
          rcases active (by simpa [termEq] using sameTerm) with
            active | follower | preVoteCandidate
          · exact Or.inl
              ⟨by simpa [roleEq] using active.1,
                by simpa [logEq] using active.2⟩
          · exact Or.inr
              (Or.inl (by simpa [roleEq] using follower))
          · exact Or.inr
              (Or.inr (by simpa [roleEq] using preVoteCandidate))
      ⟩
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.requestVoteRequest queuedRequest) queuedDestination
              (by simpa [after] using member) with
        old | new
      · exact
          (by
          simpa [termEq, roleEq, logEq]
            using (facts.networkHistory.voteRequest queuedDestination queuedRequest old))
      · simp at new
    · intro queuedDestination queuedResponse member queuedGranted
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse) queuedDestination
              (by simpa [after] using member) with
        old | new
      · rcases
          facts.networkHistory.voteResponse
            queuedDestination queuedResponse old queuedGranted with
          ⟨termBound, voted, candidateCommittable,
            voterCommittable, upToDate⟩
        have keyNeOrEq :
            queuedResponse = response \/
              Not (queuedResponse = response) := Classical.em _
        rcases keyNeOrEq with same | different
        · subst queuedResponse
          exact ⟨
            responseTermBound,
            by simp [newVotes, responseKey, grantedVoteKey],
            by simpa [
                newCandidateHistory, Function.update
              ] using requestFacts.2.2.1,
            by simpa [
                EndsAtMaxCommittable,
                newVoterHistory, Function.update
              ] using voterSnapshotCommittable,
            by simpa [
                newCandidateHistory, newVoterHistory,
                maxCommittableIndexTakeMax,
                maxCommittableTermTakeMax,
                requestFacts.2.2.1,
                requestFacts.1, requestFacts.2.1,
                post.responseTerm, post.responseSource,
                post.responseDestination,
                requestDestination, voteLogUpToDate
              ] using grantFacts.2.1
          ⟩
        · exact ⟨
            by simpa [termEq] using termBound,
            oldGrantedVotePreserved queuedDestination queuedResponse old queuedGranted,
            by simpa [
                newCandidateHistory, Function.update, different
              ] using candidateCommittable,
            by simpa [
                newVoterHistory, Function.update, different
              ] using voterCommittable,
            by simpa [
                newCandidateHistory, newVoterHistory,
                Function.update, different, logEq,
                voteLogUpToDate
              ] using upToDate
          ⟩
      · simp only [Message.requestVoteResponse.injEq] at new
        have same : queuedResponse = response := new.2
        subst queuedResponse
        exact ⟨
          responseTermBound,
          by simp [newVotes, responseKey, grantedVoteKey],
          by simpa [
              newCandidateHistory, Function.update
            ] using requestFacts.2.2.1,
          by simpa [
              EndsAtMaxCommittable,
              newVoterHistory, Function.update
            ] using voterSnapshotCommittable,
          by simpa [
              newCandidateHistory, newVoterHistory,
              maxCommittableIndexTakeMax,
              maxCommittableTermTakeMax,
              requestFacts.2.2.1,
              requestFacts.1, requestFacts.2.1,
              post.responseTerm, post.responseSource,
              post.responseDestination,
              requestDestination, voteLogUpToDate
            ] using grantFacts.2.1
        ⟩
  have knownBack :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix ->
          KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            evidence supportedPrefix := by
    intro evidence supportedPrefix known
    rcases known with nodeKnown | requestKnown
    · left
      rcases nodeKnown with ⟨node, positive, stored, prefixEq⟩
      exact ⟨
        node,
        by simpa [commitEq] using positive,
        stored,
        by simpa [committedEq] using prefixEq
      ⟩
    · right
      rcases requestKnown with
        ⟨queuedDestination, queuedRequest, member,
          positive, stored, prefixEq⟩
      exact ⟨
        queuedDestination,
        queuedRequest,
        (appendRequestEq queuedDestination queuedRequest).mp member,
        positive,
        stored,
        prefixEq
      ⟩
  have evidenceAfter :
      CommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence := by
    constructor
    · intro node positive
      rcases evidenceFacts.nodePositive node
        (by simpa [commitEq] using positive) with
        ⟨evidence, stored, valid, supportedLength, termBound⟩
      exact ⟨
        evidence,
        stored,
        by simpa [committedEq] using valid,
        by simpa [commitEq] using supportedLength,
        by simpa [termEq] using termBound
      ⟩
    · intro queuedDestination queuedRequest member positive
      exact evidenceFacts.requestPositive
        queuedDestination queuedRequest
          ((appendRequestEq queuedDestination queuedRequest).mp member)
          positive
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts
        after appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state after appendHistory appendHistory
          nodeEvidence nodeEvidence requestEvidence requestEvidence
          elections prospectiveFacts knownBack
    · intro member
      simp [logEq]
    · intro evidence supportedPrefix queuedDestination queuedRequest
        known queued sameTerm
      left
      exact ⟨(appendRequestEq queuedDestination queuedRequest).mp queued, rfl⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      have oldRole :
          (state.nodes candidate).role = .candidate := by
        simpa [roleEq] using role
      have oldRelaxed :
          member ∈ relaxedElectionVoters state candidate := by
        simp only [
          relaxedElectionVoters, Finset.mem_filter] at relaxed ⊢
        rcases relaxed with ⟨joined, effective | eligible⟩
        · rcases newEffectiveClassify candidate member effective with
            old | new
          · have oldJoined : member ∈ state.hasJoined := by
              have unpacked :
                  member ∈ state.hasJoined /\
                    (member ∈ (state.nodes candidate).votesGranted \/
                      queuedGrantedVote state candidate member) := by
                simpa [effectiveElectionVoters] using old
              exact unpacked.1
            exact ⟨oldJoined, Or.inl old⟩
          · rcases new with ⟨candidateEq, memberEq, candidateTerm⟩
            refine ⟨by simpa [after] using joined, Or.inr ?_⟩
            subst candidate
            subst member
            have sourceRole :
                (state.nodes request.source).role = .candidate := oldRole
            have candidatePrefix :
                voteRequestHistory request <+:
                  (state.nodes request.source).log :=
              requestFacts.2.2.2.2.2
                candidateTerm.symm (Or.inl sourceRole)
            have canonicalUpToDate :
                voteLogUpToDate
                  (state.nodes destination)
                  (makeRequestVoteRequest
                    state request.source request.source) := by
              simpa [voteLogUpToDate, makeRequestVoteRequest,
                lastCommittableIndex_eq_maxCommittableIndex
                  (state.nodes request.source)
                  (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
                    facts request.source),
                lastCommittableTerm_eq_maxCommittableTerm
                  (state.nodes request.source)
                  (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
                    facts request.source), candidateTerm, grantFacts.1]
                using (voteLogUpToDateOfCandidatePrefix
                        (state.nodes destination)
                        request.source request.source
                        candidatePrefix
                        (monoLog request.source)
                        (by simpa [
                            voteLogUpToDate, maxCommittableTerm,
                            requestFacts.1, requestFacts.2.1,
                            requestFacts.2.2.1
                          ] using grantFacts.2.1))
            exact ⟨by simp [candidateTerm, grantFacts.1], canonicalUpToDate⟩
        · exact ⟨
            by simpa [after] using joined,
            Or.inr
              (by simpa [
                  makeRequestVoteRequest,
                  termEq, logEq, lastIndexEq, lastTermEq,
                  voteLogUpToDate
                ] using eligible)
          ⟩
      left
      exact ⟨
        oldRole,
        by simpa [termEq] using newer,
        by
          intro entry entryMember
          simpa [termEq] using entriesBefore entry (by simpa [logEq] using entryMember),
        oldRelaxed,
        by simp [logEq]
      ⟩
  have configurationFactsAfter :
      ElectionConfigurationFacts after elections activations := by
    constructor
    · exact configurationFacts.ballotCommittedFrontierSignature
    · exact configurationFacts.ballotCurrentAuthorityActivation
    · exact configurationFacts.ballotCurrentAuthorityActive
    · apply
        activationSupporterCurrentHistoryFrame
          state after elections elections activations
            configurationFacts.supporterCurrentHistory
      · intro node
        simp [logEq]
      · intro node
        exact Nat.le_of_eq (termEq node).symm
      · intro _ _ stored
        exact stored
    · intro electionTerm record candidate recorded role same majority
      have oldRole : (state.nodes candidate).role = .candidate := by
        simpa [roleEq] using role
      have oldSame :
          (state.nodes candidate).currentTerm = electionTerm := by
        simpa [termEq] using same
      rcases
          potentialCandidateElectionRecordSharedConfigurationCoverage
            (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
              facts)
            facts.entriesDoNotExceedCurrentTerm
            facts.grantedVoteSnapshots voteCanonicalFacts
            ownership electionFacts configurationFacts
            activationQuorums.history
            configurationFacts.supporterCurrentHistory
            activationVoteHistory activationCanonical
            activationElections configurationActivations
            recorded oldRole oldSame
            (potentialMajorityBack candidate role majority) with
        ⟨configuration, ballotActive, candidateActive⟩
      exact ⟨
        configuration,
        ballotActive,
        by simpa [activeConfigurationsEq] using candidateActive
      ⟩
    · intro left right leftRole rightRole same
        leftMajority rightMajority
      have oldLeftRole : (state.nodes left).role = .candidate := by
        simpa [roleEq] using leftRole
      have oldRightRole : (state.nodes right).role = .candidate := by
        simpa [roleEq] using rightRole
      have oldSame :
          (state.nodes left).currentTerm =
            (state.nodes right).currentTerm := by
        simpa [termEq] using same
      rcases
          potentialCandidatesSharedConfigurationCoverage
            (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
              facts)
            facts.entriesDoNotExceedCurrentTerm
            facts.grantedVoteSnapshots voteCanonicalFacts
            ownership electionFacts activationQuorums.history
            configurationFacts.supporterCurrentHistory
            activationVoteHistory activationCanonical
            activationElections configurationActivations
            oldLeftRole oldRightRole oldSame
            (potentialMajorityBack left leftRole leftMajority)
            (potentialMajorityBack right rightRole rightMajority) with
        ⟨configuration, leftActive, rightActive⟩
      exact ⟨
        configuration,
        by simpa [activeConfigurationsEq] using leftActive,
        by simpa [activeConfigurationsEq] using rightActive
      ⟩
    · intro candidate role entry member
      simpa [termEq]
        using configurationFacts.candidateEntriesBeforeTerm
          candidate
          (by simpa [roleEq] using role)
          entry
          (by simpa [logEq] using member)
  have activationVoteHistoryAfter :
      ActivationVoteHistory
        newVotes newVoterHistory elections activations := by
    intro activationIndex activation voter voteTerm candidate
        activationStored supporter voted different later
    by_cases voterEq : voter = destination
    · subst voter
      by_cases voteTermEq : voteTerm = request.term
      · subst voteTerm
        have candidateEq : candidate = request.source := by
          have chosen :
              some request.source = some candidate := by
            simpa [newVotes, Function.update] using voted
          exact (Option.some.inj chosen).symm
        subst candidate
        rcases
            configurationFacts.supporterCurrentHistory
              activationIndex activation activationStored
              destination supporter with
          retained | bad
        · left
          have activationSignature :
              isSignatureAt
                  (activation.history.take activation.activationFrontier)
                  (activation.history.take
                    activation.activationFrontier).length =
                true :=
            signatureAtTakeLength
              (activationQuorums.history.valid
                activationIndex activation activationStored).2.2.2.2.2.1
          simpa [newVoterHistory, responseKey]
            using signatureEndedPrefixOfMaxTake retained activationSignature
        · right
          simpa [grantFacts.1] using bad
      · have oldVoted :
            votes destination voteTerm = some candidate := by
          simpa [newVotes, Function.update, voteTermEq] using voted
        rcases
            activationVoteHistory
              activationIndex activation destination voteTerm candidate
                activationStored supporter oldVoted different later with
          retained | bad
        · left
          have keyNe :
              Not (
                grantedVoteKey destination voteTerm candidate =
                  response) := by
            intro same
            have sameTerm :
                voteTerm = request.term := by
              exact (congrArg RequestVoteResponse.term same).trans responseTermRequest
            exact voteTermEq sameTerm
          simpa [newVoterHistory, Function.update, keyNe] using retained
        · exact Or.inr bad
    · have oldVoted :
          votes voter voteTerm = some candidate := by
        simpa [newVotes, Function.update, voterEq] using voted
      rcases
          activationVoteHistory
            activationIndex activation voter voteTerm candidate
              activationStored supporter oldVoted different later with
        retained | bad
      · left
        have keyNe :
            Not (
              grantedVoteKey voter voteTerm candidate =
                response) := by
          intro same
          have sameVoter :
              voter = destination := by
            exact (congrArg RequestVoteResponse.source same).trans
              (post.responseSource.trans requestDestination)
          exact voterEq sameVoter
        simpa [newVoterHistory, Function.update, keyNe] using retained
      · exact Or.inr bad
  have ackerVoteHistoryAfter :
      AckerVoteHistory
        after newVotes responseHistory newVoterHistory elections := by
    simpa [newVoterHistory, responseKey]
      using ackerVoteHistoryAfterGrantedRequest
        state after votes responseHistory voteVoterHistory
        elections destination request
        ackerCurrentFacts ackerVoteFacts grantFacts.1
        roleEq termEq logEq effectiveAckersEq
  have ackerActivationAfter :
      AckerActivationHistory
        after responseHistory elections activations := by
    apply
      ackerActivationFrameSameLogs
        state after responseHistory elections elections activations
          ackerActivationFacts
    · intro leader role
      simpa [roleEq] using role
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
  have activationQuorumsAfter :
      ActivationQuorumFacts
        after appendHistory responseHistory elections activations := by
    constructor
    · exact activationQuorums.history
    · intro leader index role current signature potential
        electionTerm record recorded newer
      have old :=
        activationQuorums.recordBridge
          leader index
          (by simpa [roleEq] using role)
          (by simpa [logEq, termEq] using current)
          (by simpa [logEq] using signature)
          ((potentialReplicationMajorityEq leader index).mp potential)
          electionTerm record recorded
          (by simpa [termEq] using newer)
      simpa [logEq, activeConfigurationsEq] using old
    · intro leader index role current signature potential
        candidate candidateRole candidateMajority newer
      have old :=
        activationQuorums.candidateBridge
          leader index
          (by simpa [roleEq] using role)
          (by simpa [logEq, termEq] using current)
          (by simpa [logEq] using signature)
          ((potentialReplicationMajorityEq leader index).mp potential)
          candidate
          (by simpa [roleEq] using candidateRole)
          (potentialElectionMajorityBack
            candidate candidateRole candidateMajority)
          (by simpa [termEq] using newer)
      simpa [logEq, activeConfigurationsEq] using old
    · intro leader index role current signature majority node
      have old :=
        activationQuorums.committedBridge
          leader index
          (by simpa [roleEq] using role)
          (by simpa [logEq, termEq] using current)
          (by simpa [logEq] using signature)
          ((effectiveMajorityEq leader index).mp majority)
          node
      simpa [
        logEq, committedEq, activeConfigurationsEq,
        currentConfiguration, commitEq
      ] using old
    · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
        right rightIndex rightRole rightCurrent rightSignature rightMajority
      have old :=
        activationQuorums.potentialBridge
          left leftIndex
          (by simpa [roleEq] using leftRole)
          (by simpa [logEq, termEq] using leftCurrent)
          (by simpa [logEq] using leftSignature)
          ((effectiveMajorityEq left leftIndex).mp leftMajority)
          right rightIndex
          (by simpa [roleEq] using rightRole)
          (by simpa [logEq, termEq] using rightCurrent)
          (by simpa [logEq] using rightSignature)
          ((effectiveMajorityEq right rightIndex).mp rightMajority)
      simpa [logEq, activeConfigurationsEq] using old
    · intro activationIndex activation queuedDestination queuedRequest
        stored queued sameTerm
      exact
        activationQuorums.queuedComparable
          activationIndex activation queuedDestination queuedRequest
          stored
          ((appendRequestEq queuedDestination queuedRequest).mp queued)
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
        exact (appendRequestEq queuedDestination queuedRequest).mp queued
      · intro _
        rfl
  have activationEvidenceAfter :
      ActivationEvidenceFacts
        after appendHistory responseHistory nodeEvidence requestEvidence
          elections activations := by
    apply
      activationEvidenceFrame
        state after
        appendHistory appendHistory responseHistory responseHistory
        nodeEvidence nodeEvidence requestEvidence requestEvidence
        elections elections activations activationEvidence
    · exact knownBack
    · intro candidate role majority
      exact ⟨
        by simpa [roleEq] using role,
        potentialElectionMajorityBack candidate role majority
      ⟩
    · intro candidate _
      exact termEq candidate
    · intro candidate _
      simp [logEq]
    · intro candidate configuration _ active
      simpa [activeConfigurationsEq] using active
  have activationElectionsAfter :
      ActivationElectionFacts newVotes elections activations := by
    apply
      activationElectionFrame
        votes newVotes elections activations activationElections
    intro activationIndex activation electionTerm election voter
        activationStored electionStored supporter
    exact
      votesPreserved electionTerm election voter electionStored supporter
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
      rw [termEq]
      exact witness.candidateTermStrict (by simpa [roleEq] using role)
  · refine ⟨
      owners,
      canonicalHistory,
      elections,
      activations,
      nodeEvidence,
      requestEvidence,
      ?_,
      newElectionFacts,
      configurationFactsAfter,
      ?_,
      ?_,
      ackerVoteHistoryAfter,
      activationVoteHistoryAfter,
      ?_,
      ackerActivationAfter,
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
    · constructor
      · exact ownership.bootstrap
      · intro leader role
        rw [termEq]
        exact ownership.activeLeader leader
          (by simpa [roleEq] using role)
      · intro node index entry found
        rcases ownership.logEntryAgreement node index entry
          (by simpa [logEq] using found) with
          ⟨canonical, agreed⟩
        exact ⟨canonical, by simpa [logEq] using agreed⟩
      · intro queuedDestination queuedRequest member index entry found
        exact
          ownership.queuedHistoryEntryAgreement
            queuedDestination queuedRequest
              ((appendRequestEq queuedDestination queuedRequest).mp member)
              index entry found
      · intro leader role
        rw [termEq]
        simpa [logEq]
          using ownership.activeLeaderHistory leader (by simpa [roleEq] using role)
      · exact ownership.canonicalEntryOwner
      · exact ownership.canonicalMonoLog
      · intro term owner owned
        rcases ownership.ownerProgress term owner owned with
          ⟨bound, oldLeader⟩
        exact ⟨
          by simpa [termEq] using bound,
          by
            intro same
            have oldSame :
                term = (state.nodes owner).currentTerm := by
              simpa [termEq] using same
            simpa [roleEq] using oldLeader oldSame
        ⟩
      · intro queuedDestination queuedRequest member
        exact
          ownership.queuedAppendMetadata
            queuedDestination queuedRequest
              ((appendRequestEq queuedDestination queuedRequest).mp member)
      · intro queuedDestination queuedRequest member sameTerm leaderRole
        simpa [logEq]
          using ownership.queuedActiveSourceHistory
            queuedDestination queuedRequest
            ((appendRequestEq queuedDestination queuedRequest).mp member)
            (by simpa [termEq] using sameTerm)
            (by simpa [roleEq] using leaderRole)
    · intro candidate voter active member
      rw [termEq candidate]
      rcases newEffectiveClassify candidate voter member with old | new
      · rcases voteCanonicalFacts candidate voter
          (by simpa [roleEq] using active) old with
          self | snapshots
        · exact Or.inl self
        · by_cases keyEq :
            grantedVoteKey voter
                (state.nodes candidate).currentTerm candidate =
              response
          · right
            have voterEq :
                voter = destination := by
              exact (congrArg RequestVoteResponse.source keyEq).trans
                (post.responseSource.trans requestDestination)
            have candidateEq :
                candidate = request.source := by
              exact (congrArg RequestVoteResponse.destination keyEq).trans
                post.responseDestination
            have candidateTerm :
                (state.nodes candidate).currentTerm = request.term := by
              exact (congrArg RequestVoteResponse.term keyEq).trans responseTermRequest
            subst voter
            subst candidate
            have sourceRole :
                (state.nodes request.source).role = .candidate \/
                  (state.nodes request.source).role = .leader := by
              simpa [roleEq] using active
            have candidatePrefix :
                voteRequestHistory request <+:
                  (state.nodes request.source).log :=
              requestFacts.2.2.2.2.2 candidateTerm.symm sourceRole
            exact ⟨
              by
                simpa [newCandidateHistory, keyEq]
                  using historyCanonicalOfPrefix
                    (nodeLogCanonical ownership request.source)
                    candidatePrefix,
              by
                simpa [newCandidateHistory, keyEq]
                  using monoHistoryOfPrefix
                    ((canonicalHistoriesMonoLog ownership) request.source)
                    candidatePrefix,
              by
                simpa [newVoterHistory, keyEq]
                  using historyCanonicalOfPrefix
                    (nodeLogCanonical ownership destination)
                    (List.take_prefix
                      (maxCommittableIndex (state.nodes destination).log)
                      (state.nodes destination).log),
              by
                simpa [newVoterHistory, keyEq]
                  using monoHistoryOfPrefix
                    ((canonicalHistoriesMonoLog ownership) destination)
                    (List.take_prefix
                      (maxCommittableIndex (state.nodes destination).log)
                      (state.nodes destination).log)
            ⟩
          · right
            simpa [
              newCandidateHistory, newVoterHistory,
              Function.update, keyEq
            ] using snapshots
      · rcases new with ⟨candidateEq, voterEq, candidateTerm⟩
        subst candidate
        subst voter
        have sourceRole :
            (state.nodes request.source).role = .candidate \/
              (state.nodes request.source).role = .leader := by
          simpa [roleEq] using active
        have candidatePrefix :
            voteRequestHistory request <+:
              (state.nodes request.source).log :=
          requestFacts.2.2.2.2.2 candidateTerm.symm sourceRole
        right
        refine ⟨
          by
            simpa [newCandidateHistory, termEq, candidateTerm, responseKey]
              using historyCanonicalOfPrefix
                (nodeLogCanonical ownership request.source)
                candidatePrefix,
          by
            simpa [newCandidateHistory, termEq, candidateTerm, responseKey]
              using monoHistoryOfPrefix
                ((canonicalHistoriesMonoLog ownership) request.source)
                candidatePrefix,
          ?_,
          ?_
        ⟩
        · simpa [newVoterHistory, termEq, candidateTerm, responseKey]
            using historyCanonicalOfPrefix
              (nodeLogCanonical ownership destination)
              (List.take_prefix
                (maxCommittableIndex (state.nodes destination).log)
                (state.nodes destination).log)
        · simpa [newVoterHistory, termEq, candidateTerm, responseKey]
            using monoHistoryOfPrefix
              ((canonicalHistoriesMonoLog ownership) destination)
              (List.take_prefix
                (maxCommittableIndex (state.nodes destination).log)
                (state.nodes destination).log)
    · intro sourceNode index role current signature voter effective
      rcases
          ackerCurrentFacts sourceNode index
            (by simpa [roleEq] using role)
            (by simpa [logEq, termEq] using current)
            (by simpa [logEq] using signature)
            voter
            (by rw [effectiveAckersEq] at effective; exact effective) with
        retained | bad
      · exact Or.inl (by simpa [logEq] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
        exact ⟨
          badTerm,
          badRecord,
          by simpa [termEq] using above,
          by simpa [termEq] using bounded,
          recorded,
          by simpa [logEq] using missing
        ⟩
    · intro sourceNode index role current signature term record voter recorded member
        effective newer
      rcases
          ackerElectionFacts sourceNode index
            (by simpa [roleEq] using role)
            (by simpa [logEq, termEq] using current)
            (by simpa [logEq] using signature)
            term record voter recorded member
            (by rw [effectiveAckersEq] at effective; exact effective)
            (by simpa [termEq] using newer) with
        retained | bad
      · exact Or.inl (by simpa [logEq] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, below, badRecorded, missing⟩
        exact ⟨
          badTerm,
          badRecord,
          by simpa [termEq] using above,
          below,
          badRecorded,
          by simpa [logEq] using missing
        ⟩
    · intro queuedDestination queuedRequest member record recorded
      exact
        electionQueuedFacts queuedDestination queuedRequest
          ((appendRequestEq queuedDestination queuedRequest).mp member)
          record recorded
  · intro candidate voter active member
    rw [termEq candidate]
    rcases newEffectiveClassify candidate voter member with old | new
    · rcases
        facts.grantedVoteSnapshots candidate voter
          (by simpa [roleEq] using active) old with
        ⟨voted, self | snapshot⟩
      · exact ⟨
          recordedVotePreserved voter (state.nodes candidate).currentTerm candidate voted,
          Or.inl self
        ⟩
      · have keyNeOrEq :
            grantedVoteKey voter
                (state.nodes candidate).currentTerm candidate =
              response \/
              Not (
                grantedVoteKey voter
                    (state.nodes candidate).currentTerm candidate =
                  response) := Classical.em _
        rcases keyNeOrEq with keyEq | keyNe
        · have voterEq :
              voter = destination := by
            exact (congrArg RequestVoteResponse.source keyEq).trans
              (post.responseSource.trans requestDestination)
          have candidateEq :
              candidate = request.source := by
            exact (congrArg RequestVoteResponse.destination keyEq).trans
              post.responseDestination
          have candidateTerm :
              (state.nodes candidate).currentTerm = request.term := by
            exact (congrArg RequestVoteResponse.term keyEq).trans responseTermRequest
          have sourceRole :
              (state.nodes request.source).role = .candidate \/
                (state.nodes request.source).role = .leader := by
            simpa [candidateEq, roleEq] using active
          have candidatePrefix :
              voteRequestHistory request <+:
                (state.nodes request.source).log :=
            requestFacts.2.2.2.2.2
              (by simpa [candidateEq] using candidateTerm.symm)
              sourceRole
          have candidateHistoryEq :
              newCandidateHistory
                  (grantedVoteKey voter
                    (state.nodes candidate).currentTerm candidate) =
                voteRequestHistory request := by
            simp [newCandidateHistory, keyEq]
          have voterHistoryEq :
              newVoterHistory
                  (grantedVoteKey voter
                    (state.nodes candidate).currentTerm candidate) =
                (state.nodes destination).log.take
                  (maxCommittableIndex
                    (state.nodes destination).log) := by
            simp [newVoterHistory, keyEq]
          exact ⟨
            recordedVotePreserved
              voter (state.nodes candidate).currentTerm candidate voted,
            Or.inr
              ⟨
                by
                  rw [candidateHistoryEq]
                  simpa [candidateEq, logEq] using candidatePrefix,
                by simpa [candidateHistoryEq] using requestFacts.2.2.1,
                by
                  simpa [EndsAtMaxCommittable, voterHistoryEq]
                    using voterSnapshotCommittable,
                by
                  simp [
                    grantedVoteKey,
                    voterEq, termEq,
                    candidateTerm, grantFacts.1
                  ],
                by
                  rw [candidateHistoryEq, voterHistoryEq]
                  simpa [
                    maxCommittableIndexTakeMax,
                    maxCommittableTermTakeMax,
                    requestFacts.2.2.1,
                    candidateEq, voterEq,
                    requestFacts.1, requestFacts.2.1,
                    voteLogUpToDate
                  ] using grantFacts.2.1
              ⟩
          ⟩
        · exact ⟨
            recordedVotePreserved
              voter (state.nodes candidate).currentTerm candidate voted,
            Or.inr
              ⟨
                by simpa [
                    newCandidateHistory, keyNe,
                    logEq
                  ] using snapshot.1,
                by simpa [
                    newCandidateHistory, keyNe
                  ] using snapshot.2.1,
                by simpa [
                    newVoterHistory, keyNe
                  ] using snapshot.2.2.1,
                by simpa [termEq] using snapshot.2.2.2.1,
                by simpa [
                    newCandidateHistory, newVoterHistory,
                    keyNe, voteLogUpToDate
                  ] using snapshot.2.2.2.2
              ⟩
          ⟩
    · rcases new with ⟨candidateEq, voterEq, candidateTerm⟩
      subst candidate
      subst voter
      have sourceRole :
          (state.nodes request.source).role = .candidate \/
            (state.nodes request.source).role = .leader := by
        simpa [roleEq] using active
      have candidatePrefix :
          voteRequestHistory request <+:
            (state.nodes request.source).log :=
        requestFacts.2.2.2.2.2 candidateTerm.symm sourceRole
      have keyEq :
          grantedVoteKey destination
              (state.nodes request.source).currentTerm request.source =
            response := by
        simpa [candidateTerm] using responseKey.symm
      have candidateHistoryEq :
          newCandidateHistory
              (grantedVoteKey destination
                (state.nodes request.source).currentTerm request.source) =
            voteRequestHistory request := by
        simp [newCandidateHistory, keyEq]
      have voterHistoryEq :
          newVoterHistory
              (grantedVoteKey destination
                (state.nodes request.source).currentTerm request.source) =
            (state.nodes destination).log.take
              (maxCommittableIndex
                (state.nodes destination).log) := by
        simp [newVoterHistory, keyEq]
      exact ⟨
        by simp [newVotes, candidateTerm],
        Or.inr
          ⟨
            by
              rw [candidateHistoryEq]
              simpa [logEq] using candidatePrefix,
            by simpa [candidateHistoryEq] using requestFacts.2.2.1,
            by
              simpa [EndsAtMaxCommittable, voterHistoryEq] using voterSnapshotCommittable,
            by
              simp [
                grantedVoteKey,
                termEq, candidateTerm, grantFacts.1
              ],
            by
              rw [candidateHistoryEq, voterHistoryEq]
              simpa [
                maxCommittableIndexTakeMax,
                maxCommittableTermTakeMax,
                requestFacts.2.2.1,
                requestFacts.1, requestFacts.2.1,
                voteLogUpToDate
              ] using grantFacts.2.1
          ⟩
      ⟩
  · exact ⟨
      ackHistory,
      processedAckHistoryFrame
        state after ackHistory ackFacts
        roleEq termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
    ⟩
  · constructor
    · intro node peer member
      exact
        facts.joinedCarriers.activeNodes node
          (activeNodeUnion_subset_of_activeConfigurations_subset
            (state.nodes node) (after.nodes node)
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
          (by simpa [votesGrantedEq] using member)
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.requestVoteRequest queuedRequest) queuedDestination
              (by simpa [after] using member) with
        old | new
      · exact
          facts.joinedCarriers.voteRequestDestinations
            queuedDestination queuedRequest old
      · simp at new
    · intro queuedDestination queuedRequest member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.appendEntriesRequest queuedRequest) queuedDestination
              (by simpa [after] using member) with
        old | new
      · exact
          facts.joinedCarriers.appendRequestDestinations
            queuedDestination queuedRequest old
      · simp at new
    · intro queuedDestination queuedRequest member configuration configured
        peer inNodes
      have old :
          Message.appendEntriesRequest queuedRequest ∈
            state.network queuedDestination := by
        rcases
            memEnqueue
              state.network (.requestVoteResponse response)
                (.appendEntriesRequest queuedRequest) queuedDestination
                (by simpa [after] using member) with
          old | new
        · exact old
        · simp at new
      exact
        facts.joinedCarriers.appendRequestConfigurations
          queuedDestination queuedRequest old configuration configured
            inNodes
    · intro queuedDestination queuedResponse member
      rcases
          memEnqueue
            state.network (.requestVoteResponse response)
              (.requestVoteResponse queuedResponse) queuedDestination
              (by simpa [after] using member) with
        old | new
      · exact
          facts.joinedCarriers.voteResponseSources
            queuedDestination queuedResponse old
      · simp only [Message.requestVoteResponse.injEq] at new
        rw [new.2, post.responseSource, requestDestination]
        exact
          facts.joinedCarriers.voteRequestDestinations
            destination request selectedMember
    · constructor
      · intro node active
        exact
          facts.joinedCarriers.runtimeNodes.activeRoles node
            (by simpa [roleEq] using active)
      · intro leader peer positive
        exact
          facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
            (by simpa [matchEq] using positive)
      · intro queuedDestination queuedResponse member
        rcases
            memEnqueue
              state.network (.requestVoteResponse response)
                (.appendEntriesResponse queuedResponse) queuedDestination
                (by simpa [after] using member) with
          old | new
        · exact
            facts.joinedCarriers.runtimeNodes.appendResponses
              queuedDestination queuedResponse old
        · simp at new
      · intro node nonempty
        exact
          facts.joinedCarriers.runtimeNodes.nonemptyLogs node
            (by simpa [logEq] using nonempty)
  · exact fun _ => Iff.rfl
  · intro node
    simpa only [termEq] using facts.currentTermsValid node
  · have responseValid : TermNumberValid response.term := by
      rw [post.responseTerm]
      exact facts.currentTermsValid destination
    simpa only [NetworkTermsValid, after]
      using (networkTermsValidEnqueue
              (message := .requestVoteResponse response)
              facts.networkTermsValid responseValid)

end CCFRaft.Proofs.Invariant
