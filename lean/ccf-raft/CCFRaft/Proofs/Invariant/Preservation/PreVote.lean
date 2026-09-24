-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.VoteRequest
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

/-- Receiving RequestPreVote replies without changing persistent vote state. -/
lemma receiveRequestPreVotePreservesSystemInductiveInvariant
    (state : View Node TxId)
    (source destination : Node)
    (request : RequestPreVote Node)
    (remaining : List (Message Node TxId))
    (nextNode : NodeState Node TxId)
    (response : RequestPreVoteResponse Node)
    (invariant : SystemInductiveInvariant state)
    (_destinationAllocated : state.allocated destination)
    (taken
      : Selected source (state.network destination) (.requestPreVote request) remaining)
    (handled
      : handleRequestPreVote? (state.nodes destination) request
        = some (nextNode, response))
    : SystemInductiveInvariant
        {
          state with
            nodes := updateNode state.nodes destination nextNode
            network :=
              enqueue
                (updateQueue state.network destination remaining)
                (.requestPreVoteResponse response)
        } := by
  have nextNodeEq :
      nextNode = state.nodes destination :=
    handleRequestPreVoteStateUnchanged handled
  have collapsedNodes :
      updateNode state.nodes destination (state.nodes destination) =
        state.nodes := by exact (by simp [updateNode])
  let after : View Node TxId :=
    { state with
      network :=
        enqueue
          (updateQueue state.network destination remaining)
          (.requestPreVoteResponse response) }
  have remainingOld := (selectedSound taken).2.2
  have frame :
      forall queuedDestination message,
        message ∈ after.network queuedDestination ->
          message ∈ state.network queuedDestination \/
            (Message.IsSafetyInert message /\
              message.destination = queuedDestination /\
              TermNumberValid message.term) := by
    intro queuedDestination message member
    rcases
        memEnqueue
          (updateQueue state.network destination remaining)
          (.requestPreVoteResponse response)
          message queuedDestination
          (by simpa [after] using member) with
      old | new
    · left
      by_cases same : queuedDestination = destination
      · subst queuedDestination
        exact remainingOld message
          (by simpa [updateQueue, Function.update] using old)
      · simpa [updateQueue, Function.update, same] using old
    · rcases new with ⟨destinationEq, messageEq⟩
      subst queuedDestination
      subst message
      have responseTerm :
          response.term = (state.nodes destination).currentTerm := by
        unfold handleRequestPreVote? at handled
        split at handled
        · exact congrArg (fun result => result.2.term)
            (Option.some.inj handled).symm
        · contradiction
      exact Or.inr
        ⟨by simp [Message.IsSafetyInert], rfl,
          by
            change TermNumberValid response.term
            rw [responseTerm]
            exact invariantCurrentTermsValid invariant destination⟩
  rw [nextNodeEq, collapsedNodes]
  change SystemInductiveInvariant after
  exact
    safetyInertNetworkChangePreservesSystemInductiveInvariant
      state after invariant rfl (fun _ => Iff.rfl) (fun _ => rfl) frame

/-- Receiving a RequestPreVote response changes only speculative vote state. -/
lemma receiveRequestPreVoteResponsePreservesSystemInductiveInvariant
    (state : View Node TxId)
    (source destination : Node)
    (response : RequestPreVoteResponse Node)
    (remaining : List (Message Node TxId))
    (nextNode : NodeState Node TxId)
    (invariant : SystemInductiveInvariant state)
    (_destinationAllocated : state.allocated destination)
    (taken
      : Selected source (state.network destination) (.requestPreVoteResponse response)
          remaining)
    (handled
      : handleRequestPreVoteResponse? (state.nodes destination) response = some nextNode)
    : SystemInductiveInvariant
        {
          state with
            nodes := updateNode state.nodes destination nextNode
            network := updateQueue state.network destination remaining
        } := by
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have packed : SystemInductiveInvariant state :=
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have post := handleRequestPreVoteResponsePreserves handled
  let intermediate : View Node TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode }
  let after : View Node TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network := updateQueue state.network destination remaining }
  have roleEq :
      forall node,
        (intermediate.nodes node).role =
          (state.nodes node).role := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.roleUnchanged
      ]
  have termEq :
      forall node,
        (intermediate.nodes node).currentTerm =
          (state.nodes node).currentTerm := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.currentTermUnchanged
      ]
  have logEq :
      forall node,
        (intermediate.nodes node).log =
          (state.nodes node).log := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.logUnchanged
      ]
  have commitEq :
      forall node,
        (intermediate.nodes node).commitIndex =
          (state.nodes node).commitIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.commitIndexUnchanged
      ]
  have sentEq :
      forall node,
        (intermediate.nodes node).sentIndex =
          (state.nodes node).sentIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.sentIndexUnchanged
      ]
  have matchEq :
      forall node,
        (intermediate.nodes node).matchIndex =
          (state.nodes node).matchIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.matchIndexUnchanged
      ]
  have votedEq :
      forall node,
        (intermediate.nodes node).votedFor =
          (state.nodes node).votedFor := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.votedForUnchanged
      ]
  have votesEq :
      forall node,
        (intermediate.nodes node).votesGranted =
          (state.nodes node).votesGranted := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.votesGrantedUnchanged
      ]
  have activeConfigurationsEq :
      forall candidate,
        activeConfigurations (intermediate.nodes candidate) =
          activeConfigurations (state.nodes candidate) := by
    intro candidate
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have effectiveAckersEq :
      forall actualResponseHistory leader index,
        effectiveAckers intermediate actualResponseHistory leader index =
          effectiveAckers state actualResponseHistory leader index :=
    effectiveAckersFrame
      state intermediate rfl rfl termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters intermediate candidate =
          effectiveElectionVoters state candidate :=
    effectiveElectionVotersFrame
      state intermediate rfl rfl termEq votesEq
  have potentialElectionVotersEq :
      forall candidate,
        potentialElectionVoters intermediate candidate =
          potentialElectionVoters state candidate := by
    intro candidate
    ext voter
    simp only [
      potentialElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, effective | eligible⟩
      · exact ⟨
          joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq] at effective
              exact effective)
        ⟩
      · exact ⟨
          joined,
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
          joined,
          Or.inl
            (by
              rw [effectiveElectionVotersEq]
              exact effective)
        ⟩
      · exact ⟨
          joined,
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
  have joinedCarriersIntermediate : JoinedCarrierFacts intermediate := by
    apply
      joinedCarrierFactsFrame
        state intermediate facts.joinedCarriers rfl
          (fun candidate configuration active => by
            simpa [activeConfigurationsEq] using active)
          (fun candidate configuration member => by
            simpa [logEq] using member)
          (fun candidate peer member => by
            simpa [votesEq] using member)
          (fun candidate active => by
            exact
              facts.joinedCarriers.runtimeNodes.activeRoles candidate
                (by simpa [roleEq] using active))
          (fun leader peer positive => by
            exact
              facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
                (by simpa [matchEq] using positive))
          (fun candidate nonempty => by
            exact
              facts.joinedCarriers.runtimeNodes.nonemptyLogs candidate
                (by simpa [logEq] using nonempty))
          (fun _ _ member => member)
  have candidatesSelfVoteIntermediate : CandidatesSelfVote intermediate := by
    intro candidate role
    rcases
        facts.candidatesSelfVote candidate
          (by simpa [roleEq] using role) with
      ⟨voted, counted⟩
    exact ⟨by simpa [votedEq] using voted, by simpa [votesEq] using counted⟩
  have leadersHaveElectionWitnessIntermediate :
      LeadersHaveElectionWitness intermediate := by
    intro leader role
    rcases
        facts.leadersHaveElectionWitness leader
          (by simpa [roleEq] using role) with
      bootstrap | majority
    · exact Or.inl
        ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
    · exact Or.inr (by simpa [logEq, votesEq] using majority)
  have intermediateInvariant :
      SystemInductiveInvariant intermediate := by
    apply
      roleAndNetworkFramePreservesSystemInductiveInvariant
        state intermediate packed rfl
          (fun _ => Iff.rfl)
          joinedCarriersIntermediate
          (fun node active => by simpa [roleEq] using active)
          (fun node role => by simpa [roleEq] using role)
          (fun node role => by simpa [roleEq] using role)
          (fun node role => by simpa [roleEq] using role)
          (fun node role => by simpa [roleEq] using role)
          termEq logEq commitEq
          candidatesSelfVoteIntermediate
          leadersHaveElectionWitnessIntermediate
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
            (by simpa [roleEq] using active)
            (by simpa [votesEq] using member)
    · intro _ _ _ _ _ _ actualFacts
      rcases actualFacts.processedAckHistory with
        ⟨history, historyFacts⟩
      exact ⟨
        history,
        processedAckHistoryFrame
          state intermediate history historyFacts roleEq termEq logEq
          (fun leader peer => congrFun (matchEq leader) peer)
      ⟩
    · intro destination message member
      exact Or.inl member
    · intro leader role peer
      simpa [sentEq, matchEq, logEq]
        using facts.leaderProgressBounded leader (by simpa [roleEq] using role) peer
    · intro _ _ actualResponseHistory _ _ _ _ leader index
      exact Finset.subset_of_eq
        (effectiveAckersEq actualResponseHistory leader index)
    · intro _ actualAppendHistory actualResponseHistory
        _ _ _ _ leader index peer member
      simp only [
        potentialAckers, Finset.mem_filter] at member ⊢
      rcases member with ⟨joined, effective | reserve⟩
      · exact ⟨
          joined,
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
          by_cases peerEq : peer = destination
          · subst peer
            rw [peerEq] at producible ⊢
            rcases post.preVotesUpdate with unchanged | inserted
            · have nodeEq :
                  intermediate.nodes destination =
                    state.nodes destination := by
                have roleField := roleEq destination
                have termField := termEq destination
                have logField := logEq destination
                have commitField := commitEq destination
                have sentField := sentEq destination
                have matchField := matchEq destination
                have newFollowerField :
                    (intermediate.nodes destination).isNewFollower =
                      (state.nodes destination).isNewFollower := by
                  simpa [intermediate, updateNode] using post.isNewFollowerUnchanged
                have votedField := votedEq destination
                have votesField := votesEq destination
                have preVotesField :
                    (intermediate.nodes destination).preVotesGranted =
                      (state.nodes destination).preVotesGranted := by
                  simpa [intermediate, updateNode] using unchanged
                have membershipField :
                    (intermediate.nodes destination).membershipState =
                      (state.nodes destination).membershipState := by
                  simpa [intermediate, updateNode] using post.membershipStateUnchanged
                have retirementField :
                    (intermediate.nodes destination).retirementIndex =
                      (state.nodes destination).retirementIndex := by
                  simpa [intermediate, updateNode] using post.retirementIndexUnchanged
                have retirementCommittableField :
                    (intermediate.nodes destination).retirementCommittableIndex =
                      (state.nodes destination).retirementCommittableIndex := by
                  simpa [intermediate, updateNode]
                    using post.retirementCommittableIndexUnchanged
                have retiredCommittedField :
                    (intermediate.nodes destination).retiredCommittedIndex =
                      (state.nodes destination).retiredCommittedIndex := by
                  simpa [intermediate, updateNode]
                    using post.retiredCommittedIndexUnchanged
                cases hIntermediate : intermediate.nodes destination
                cases hState : state.nodes destination
                simp_all
              simpa [nodeEq] using producible
            · rcases producible with direct | future
              · have follower := canProduceAppendAckAt_role direct
                have preVoteCandidate :
                    (intermediate.nodes destination).role =
                      .preVoteCandidate := by
                  rw [roleEq]
                  exact inserted.2.2.1
                exact False.elim
                  (Role.noConfusion
                    (follower.symm.trans preVoteCandidate))
              · exact Or.inr
                  ⟨by simpa [termEq] using future.1, future.2⟩
          · have nodeEq :
                intermediate.nodes peer = state.nodes peer := by
              simp [
                intermediate, updateNode, peerEq
              ]
            simpa [nodeEq] using producible
        exact ⟨
          joined,
          Or.inr
            ⟨
              request,
              queued,
              sourceEq,
              destinationEq,
              by simpa [termEq] using requestTerm,
              oldProducible,
              by simpa [logEq] using covered
            ⟩
        ⟩
    · intro candidate _ majority
      unfold hasEffectiveElectionMajority at majority ⊢
      simpa [
        activeConfigurationsEq, effectiveElectionVotersEq
      ] using majority
    · intro candidate _ majority
      unfold hasPotentialElectionMajority at majority ⊢
      simpa [
        activeConfigurationsEq, potentialElectionVotersEq
      ] using majority
    · intro candidate voter _ member
      simpa [effectiveElectionVotersEq] using member
  have remainingOld := (selectedSound taken).2.2
  change SystemInductiveInvariant after
  apply
    safetyInertNetworkChangePreservesSystemInductiveInvariant
      intermediate after intermediateInvariant rfl
        (fun _ => Iff.rfl) (fun _ => rfl)
  intro queuedDestination message member
  left
  by_cases same : queuedDestination = destination
  · subst queuedDestination
    exact remainingOld message
      (by simpa [after, updateQueue, Function.update] using member)
  · simpa [after, updateQueue, Function.update, same] using member

lemma pureNetworkDequeuePreservesSystemInductiveInvariant
    (state : View Node TxId)
    (network : Node -> List (Message Node TxId))
    (invariant : SystemInductiveInvariant state)
    (networkSubset
      : forall destination message,
          message ∈ network destination -> message ∈ state.network destination)
    : SystemInductiveInvariant { state with network } := by
  let after : View Node TxId := { state with network }
  have effectiveElectionSubset :
      forall candidate,
        effectiveElectionVoters after candidate ⊆
          effectiveElectionVoters state candidate := by
    intro candidate voter member
    simp only [
      effectiveElectionVoters, Finset.mem_filter
    ] at member ⊢
    rcases member with ⟨joined, processed | queued⟩
    · exact ⟨joined, Or.inl processed⟩
    · rcases queued with
        ⟨response, queued, granted, term, source, destination⟩
      exact ⟨
        joined,
        Or.inr
          ⟨
            response,
            networkSubset candidate (.requestVoteResponse response) queued,
            granted,
            term,
            source,
            destination
          ⟩
      ⟩
  change SystemInductiveInvariant after
  apply
    networkFramePreservesSystemInductiveInvariant
      state after invariant rfl (fun _ => Iff.rfl)
        (fun _ => rfl)
        (fun destination message member =>
          Or.inl (networkSubset destination message member))
  · intro _ _ responseHistory _ _ _ _ leader index peer member
    simp only [effectiveAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, self | matched | queued⟩
    · exact ⟨joined, Or.inl self⟩
    · exact ⟨joined, Or.inr (Or.inl matched)⟩
    · rcases queued with
        ⟨response, queued, success, term, source, destination,
          acknowledged, covered⟩
      exact ⟨
        joined,
        Or.inr
          (Or.inr
            ⟨
              response,
              networkSubset leader (.appendEntriesResponse response) queued,
              success,
              term,
              source,
              destination,
              acknowledged,
              covered
            ⟩)
      ⟩
  · intro candidate _ majority
    rw [hasEffectiveElectionMajority, List.all_eq_true] at majority ⊢
    intro configuration active
    apply decide_eq_true
    exact
      hasConfigurationMajority_mono
        (effectiveElectionSubset candidate)
        (of_decide_eq_true (majority configuration active))
  · intro candidate voter _ member
    exact effectiveElectionSubset candidate member

/--
Receiving a proposal either performs the ordinary candidate transition or
only consumes the ignored packet.
-/
lemma receiveProposeVoteRequestPreservesSystemInductiveInvariant
    (state : View Node TxId)
    (source destination : Node)
    (request : ProposeVoteRequest Node)
    (remaining : List (Message Node TxId))
    (nextNode : NodeState Node TxId)
    (invariant : SystemInductiveInvariant state)
    (_destinationAllocated : state.allocated destination)
    (taken
      : Selected source (state.network destination) (.proposeVoteRequest request)
          remaining)
    (handled : handleProposeVoteRequest? state destination request = some nextNode)
    : SystemInductiveInvariant
        {
          state with
            nodes := updateNode state.nodes destination nextNode
            network := updateQueue state.network destination remaining
        } := by
  have remainingOld := (selectedSound taken).2.2
  rcases handleProposeVoteRequestCases handled with
    unchanged | transitioned
  · subst nextNode
    have collapsedNodes :
        updateNode state.nodes destination (state.nodes destination) =
          state.nodes :=
      (by simp [updateNode])
    rw [collapsedNodes]
    exact
      pureNetworkDequeuePreservesSystemInductiveInvariant
        state (updateQueue state.network destination remaining)
          invariant
          (fun queuedDestination message member => by
            by_cases same : queuedDestination = destination
            · subst queuedDestination
              exact remainingOld message
                (by simpa [updateQueue, Function.update] using member)
            · simpa [updateQueue, Function.update, same] using member)
  · rcases transitioned with
      ⟨_sameTerm, candidateEnabled, nextNodeEq⟩
    subst nextNode
    let intermediate := becomeCandidateState state destination
    have intermediateInvariant : SystemInductiveInvariant intermediate := by
      simpa [intermediate, view_effects, becomeCandidateState]
        using candidateTransitionPreservesSystemInductiveInvariant
          state destination invariant
          ⟨candidateEnabled.1, candidateEnabled.2.1⟩
    have networkSubset :
        forall queuedDestination message,
          message ∈
              updateQueue state.network destination remaining
                queuedDestination ->
            message ∈ intermediate.network queuedDestination := by
      intro queuedDestination message member
      change message ∈ state.network queuedDestination
      by_cases same : queuedDestination = destination
      · subst queuedDestination
        exact remainingOld message
          (by simpa [updateQueue, Function.update] using member)
      · simpa [updateQueue, Function.update, same] using member
    simpa [intermediate, becomeCandidateState]
      using pureNetworkDequeuePreservesSystemInductiveInvariant
        intermediate (updateQueue state.network destination remaining)
        intermediateInvariant networkSubset

end CCFRaft.Proofs.Invariant
