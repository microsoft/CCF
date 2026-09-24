-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.AppendResponse
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
variable {joinedNodes joinedNext : Finset Node}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

attribute [local simp] Shared.Envelope.target ConfigurationCoverageWitness.sharedPrefix

/-- Dequeuing a vote response leaves latent replication acknowledgements unchanged. -/
lemma effectiveAckersAfterVoteResponse
    (state after : Model.State Node TxId)
    (_destination : Node)
    (response : VoteResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (taken
      : Selected response.1 state.network
          (voteResponseEnvelope response) remaining)
    (networkEq : after.network = remaining)
    (hasJoinedEq : joinedNext = joinedNodes)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf state) node).log)
    (matchEq
      : forall leader peer,
          ((nodeOf after) leader).matchIndex peer = ((nodeOf state) leader).matchIndex peer)
    : forall (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
              leader index,
        effectiveAckers (joined := joinedNext) after responseHistory leader index
        = effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
  classical
  subst joinedNext
  have ackMember (ack : AppendResponseKey Node) :
      (appendResponseEnvelope ack ∈ remaining) ↔ (appendResponseEnvelope ack ∈ state.network) := by
    constructor
    · exact (selectedSound taken).2.2 _
    · intro old
      rcases memSelectedOrRemaining taken old with same | retained
      · simp [appendResponseEnvelope, voteResponseEnvelope] at same
      · exact retained
  intro responseHistory leader index
  ext peer
  simp only [effectiveAckers, Finset.mem_filter]
  simp only [queuedSuccessfulAck, matchEq, logEq, termEq, networkEq, ackMember]

/--
Processing a vote response never creates new effective election evidence:
a newly recorded vote was already represented by the selected queued grant.
-/
lemma effectiveElectionVotersAfterVoteResponseSubset
    (state after : Model.State Node TxId)
    (destination : Node)
    (response : VoteResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (taken
      : Selected response.1 state.network
          (voteResponseEnvelope response) remaining)
    (responseDestination : response.2.1 = destination)
    (networkEq : after.network = remaining)
    (hasJoinedEq : joinedNext = joinedNodes)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (votesDestination
      : ((nodeOf after) destination).votesGranted = ((nodeOf state) destination).votesGranted
        \/ (response.2.2.voteGranted = true
            /\ response.2.2.term = ((nodeOf state) destination).currentTerm
            /\ ((nodeOf after) destination).votesGranted
                = insert response.1 ((nodeOf state) destination).votesGranted))
    (votesOther
      : forall candidate,
          Not (candidate = destination)
          -> ((nodeOf after) candidate).votesGranted = ((nodeOf state) candidate).votesGranted)
    : forall candidate,
        effectiveElectionVoters (joined := joinedNext) after candidate
        ⊆ effectiveElectionVoters (joined := joinedNodes) state candidate := by
  intro candidate voter member
  have selectedMember :
      (voteResponseEnvelope response ∈ state.network /\ response.2.1 = destination) :=
    ⟨(selectedSound taken).2.1, responseDestination⟩
  have remainingOld := (selectedSound taken).2.2
  simp only [
    effectiveElectionVoters, Finset.mem_filter] at member ⊢
  rcases member with ⟨joined, processed | queued⟩
  · refine ⟨by simpa [hasJoinedEq] using joined, ?_⟩
    by_cases candidateEq : candidate = destination
    · subst candidate
      rcases votesDestination with unchanged | inserted
      · exact Or.inl (by simpa [unchanged] using processed)
      · have sourceOrOld :
            voter = response.1 \/
              voter ∈ ((nodeOf state) destination).votesGranted := by
          simpa [inserted.2.2] using processed
        rcases sourceOrOld with sourceEq | old
        · subst voter
          exact Or.inr
            ⟨response, selectedMember, inserted.1, inserted.2.1,
              rfl, responseDestination⟩
        · exact Or.inl old
    · exact Or.inl
        (by simpa [votesOther candidate candidateEq] using processed)
  · refine ⟨by simpa [hasJoinedEq] using joined, Or.inr ?_⟩
    rcases queued with
      ⟨queuedResponse, queuedMember, granted, responseTerm,
        responseSource, queuedDestination⟩
    have oldMember :
        voteResponseEnvelope queuedResponse ∈ state.network ∧ queuedResponse.2.1 = candidate :=
      ⟨remainingOld _ (by simpa [networkEq] using queuedMember.1), queuedMember.2⟩
    exact ⟨
      queuedResponse,
      oldMember,
      granted,
      by simpa [termEq] using responseTerm,
      responseSource,
      queuedDestination
    ⟩

/--
Before dequeue, recording a granted vote only changes the representation of
evidence already present in the selected queued response.
-/
lemma effectiveElectionVotersAfterVoteResponseHandler
    (state after : Model.State Node TxId)
    (destination : Node)
    (response : VoteResponseKey Node)
    (selectedMember : (voteResponseEnvelope response ∈ state.network /\ response.2.1 = destination))
    (responseDestination : response.2.1 = destination)
    (networkEq : after.network = state.network)
    (hasJoinedEq : joinedNext = joinedNodes)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (votesDestination
      : ((nodeOf after) destination).votesGranted = ((nodeOf state) destination).votesGranted
        \/ (response.2.2.voteGranted = true
            /\ response.2.2.term = ((nodeOf state) destination).currentTerm
            /\ ((nodeOf after) destination).votesGranted
                = insert response.1 ((nodeOf state) destination).votesGranted))
    (votesOther
      : forall candidate,
          Not (candidate = destination)
          -> ((nodeOf after) candidate).votesGranted = ((nodeOf state) candidate).votesGranted)
    : forall candidate,
        effectiveElectionVoters (joined := joinedNext) after candidate
        = effectiveElectionVoters (joined := joinedNodes) state candidate := by
  intro candidate
  ext voter
  simp only [
    effectiveElectionVoters, Finset.mem_filter]
  apply and_congr (by simp only [hasJoinedEq])
  constructor
  · rintro (processed | queued)
    · by_cases candidateEq : candidate = destination
      · subst candidate
        rcases votesDestination with unchanged | inserted
        · exact Or.inl (by simpa [unchanged] using processed)
        · have sourceOrOld :
              voter = response.1 \/
                voter ∈ ((nodeOf state) destination).votesGranted := by
            simpa [inserted.2.2] using processed
          rcases sourceOrOld with sourceEq | old
          · subst voter
            exact Or.inr
              ⟨response, selectedMember, inserted.1, inserted.2.1,
                rfl, responseDestination⟩
          · exact Or.inl old
      · exact Or.inl
          (by simpa [votesOther candidate candidateEq] using processed)
    · right
      rcases queued with
        ⟨queuedResponse, member, granted, responseTerm,
          responseSource, queuedDestination⟩
      exact ⟨
        queuedResponse,
        by simpa [networkEq] using member,
        granted,
        by simpa [termEq] using responseTerm,
        responseSource,
        queuedDestination
      ⟩
  · rintro (processed | queued)
    · left
      by_cases candidateEq : candidate = destination
      · subst candidate
        rcases votesDestination with unchanged | inserted
        · simpa [unchanged] using processed
        · rw [inserted.2.2]
          exact Finset.mem_insert_of_mem processed
      · simpa [votesOther candidate candidateEq] using processed
    · right
      rcases queued with
        ⟨queuedResponse, member, granted, responseTerm,
          responseSource, queuedDestination⟩
      exact ⟨
        queuedResponse,
        by simpa [networkEq] using member,
        granted,
        by simpa [termEq] using responseTerm,
        responseSource,
        queuedDestination
      ⟩

/-- The exact vote-set alternatives of the RequestVote response handler. -/
lemma handleRequestVoteResponseVoteUpdate
    {before after : NodeState Node TxId}
    {response : VoteResponseKey Node}
    (handled : handleRequestVoteResponse before response.1 response.2.2 = after)
    : after.votesGranted = before.votesGranted
      \/ (response.2.2.voteGranted = true
          /\ response.2.2.term = before.currentTerm
          /\ before.role = .candidate
          /\ after.votesGranted = insert response.1 before.votesGranted) := by
  subst after
  unfold handleRequestVoteResponse
  split_ifs with granted
  · exact Or.inr ⟨granted.2.2, granted.2.1, granted.1, rfl⟩
  · exact Or.inl rfl

/-- Receiving a RequestVote response transfers latent vote evidence to runtime state. -/
lemma receiveRequestVoteResponsePreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (source destination : Node)
    {present : destination ∈ state.nodes.map Prod.fst}
    (response : VoteResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (nextNode : NodeState Node TxId)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (_destinationAllocated : destination ∈ joinedNodes)
    (taken
      : Selected source state.network (voteResponseEnvelope response)
          remaining)
    (responseDestination : response.2.1 = destination)
    (handled
      : handleRequestVoteResponse ((nodeOf state) destination) response.1 response.2.2 = nextNode)
    : SystemInductiveInvariant (joined := joinedNodes)
        {
          state with
            nodes := replaceNode state.nodes destination nextNode
            network := remaining
        } := by
  have responseSource : response.1 = source :=
    (selectedSound taken).1
  have takenByResponseSource :
      Selected response.1 state.network (voteResponseEnvelope response) remaining := by
    simpa [responseSource] using taken
  have selectedMember :
      (voteResponseEnvelope response ∈ state.network /\ response.2.1 = destination) :=
    ⟨(selectedSound taken).2.1, responseDestination⟩
  have remainingOld := (selectedSound taken).2.2
  have updateQueueSubset :
      forall queuedDestination message,
        (message ∈ remaining ∧ message.target = queuedDestination) ->
          (message ∈ state.network ∧ message.target = queuedDestination) := by
    intro queuedDestination message member
    exact ⟨remainingOld message member.1, member.2⟩
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have packed :
      SystemInductiveInvariant (joined := joinedNodes) state :=
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have post := handleRequestVoteResponsePreserves handled
  have voteUpdate := handleRequestVoteResponseVoteUpdate handled
  let intermediate : Model.State Node TxId :=
    { state with
      nodes := replaceNode state.nodes destination nextNode }
  let after : Model.State Node TxId :=
    { state with
      nodes := replaceNode state.nodes destination nextNode
      network := remaining }
  have roleEq :
      forall node,
        ((nodeOf intermediate) node).role = ((nodeOf state) node).role := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.roleUnchanged
      ]
  have termEq :
      forall node,
        ((nodeOf intermediate) node).currentTerm =
          ((nodeOf state) node).currentTerm := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.currentTermUnchanged
      ]
  have logEq :
      forall node,
        ((nodeOf intermediate) node).log = ((nodeOf state) node).log := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.logUnchanged
      ]
  have commitEq :
      forall node,
        ((nodeOf intermediate) node).commitIndex =
          ((nodeOf state) node).commitIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.commitIndexUnchanged
      ]
  have votedEq :
      forall node,
        ((nodeOf intermediate) node).votedFor =
          ((nodeOf state) node).votedFor := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.votedForUnchanged
      ]
  have preVotesEq :
      forall node,
        ((nodeOf intermediate) node).preVotesGranted =
          ((nodeOf state) node).preVotesGranted := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.preVotesGrantedUnchanged
      ]
  have membershipEq :
      forall node,
        ((nodeOf intermediate) node).membershipState =
          ((nodeOf state) node).membershipState := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.membershipStateUnchanged
      ]
  have retirementIndexEq :
      forall node,
        ((nodeOf intermediate) node).retirementIndex =
          ((nodeOf state) node).retirementIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.retirementIndexUnchanged
      ]
  have retirementCommittableIndexEq :
      forall node,
        ((nodeOf intermediate) node).retirementCommittableIndex =
          ((nodeOf state) node).retirementCommittableIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.retirementCommittableIndexUnchanged
      ]
  have retiredCommittedIndexEq :
      forall node,
        ((nodeOf intermediate) node).retiredCommittedIndex =
          ((nodeOf state) node).retiredCommittedIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.retiredCommittedIndexUnchanged
      ]
  have sentEq :
      forall node,
        ((nodeOf intermediate) node).sentIndex =
          ((nodeOf state) node).sentIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.sentIndexUnchanged
      ]
  have matchEq :
      forall node,
        ((nodeOf intermediate) node).matchIndex =
          ((nodeOf state) node).matchIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, present, nodeOf_replaceNode, same,
        post.matchIndexUnchanged
      ]
  have nextNewFollower :
      nextNode.isNewFollower =
        ((nodeOf state) destination).isNewFollower := by
    rw [← handled]
    unfold handleRequestVoteResponse
    split_ifs <;> rfl
  have newFollowerEq :
      forall node,
        ((nodeOf intermediate) node).isNewFollower =
          ((nodeOf state) node).isNewFollower := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [intermediate, present, nodeOf_replaceNode] using nextNewFollower
    · simp [intermediate, present, nodeOf_replaceNode, same]
  have votesDestination :
      ((nodeOf intermediate) destination).votesGranted =
          ((nodeOf state) destination).votesGranted \/
        (response.2.2.voteGranted = true /\
          response.2.2.term = ((nodeOf state) destination).currentTerm /\
          ((nodeOf state) destination).role = .candidate /\
          ((nodeOf intermediate) destination).votesGranted =
            insert
              response.1
              ((nodeOf state) destination).votesGranted) := by
    rcases voteUpdate with unchanged | inserted
    · exact Or.inl
        (by simpa [intermediate, present, nodeOf_replaceNode] using unchanged)
    · exact Or.inr
        ⟨inserted.1, inserted.2.1, inserted.2.2.1,
          by simpa [intermediate, present, nodeOf_replaceNode] using inserted.2.2.2⟩
  have votesDestinationPlain :
      ((nodeOf intermediate) destination).votesGranted =
          ((nodeOf state) destination).votesGranted \/
        (response.2.2.voteGranted = true /\
          response.2.2.term = ((nodeOf state) destination).currentTerm /\
          ((nodeOf intermediate) destination).votesGranted =
            insert
              response.1
              ((nodeOf state) destination).votesGranted) := by
    rcases votesDestination with unchanged | inserted
    · exact Or.inl unchanged
    · exact Or.inr
        ⟨inserted.1, inserted.2.1, inserted.2.2.2⟩
  have votesOther :
      forall candidate,
        Not (candidate = destination) ->
          ((nodeOf intermediate) candidate).votesGranted =
            ((nodeOf state) candidate).votesGranted := by
    intro candidate different
    simp [intermediate, present, nodeOf_replaceNode, different]
  have votesMonotone :
      forall candidate,
        ((nodeOf state) candidate).votesGranted ⊆
          ((nodeOf intermediate) candidate).votesGranted := by
    intro candidate voter member
    by_cases candidateEq : candidate = destination
    · subst candidate
      rcases votesDestination with unchanged | inserted
      · simpa [unchanged] using member
      · rw [inserted.2.2.2]
        exact Finset.mem_insert_of_mem member
    · simpa [votesOther candidate candidateEq] using member
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters (joined := joinedNodes) intermediate candidate =
          effectiveElectionVoters (joined := joinedNodes) state candidate :=
    effectiveElectionVotersAfterVoteResponseHandler
      state intermediate destination response selectedMember
        responseDestination rfl rfl termEq votesDestinationPlain votesOther
  have activeConfigurationsEq :
      forall candidate,
        activeConfigurations ((nodeOf intermediate) candidate) =
          activeConfigurations ((nodeOf state) candidate) := by
    intro candidate
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have candidatesSelfVoteIntermediate : CandidatesSelfVote intermediate := by
    intro candidate role
    have oldRole : ((nodeOf state) candidate).role = .candidate := by
      simpa [roleEq] using role
    rcases facts.candidatesSelfVote candidate oldRole with
      ⟨selfVote, selfCounted⟩
    exact ⟨by simpa [votedEq] using selfVote, votesMonotone candidate selfCounted⟩
  have leadersHaveElectionWitnessIntermediate :
      LeadersHaveElectionWitness intermediate := by
    intro leader role
    have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
    rcases facts.leadersHaveElectionWitness leader oldRole with
      bootstrap | majority
    · exact Or.inl
        ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
    · rcases majority with ⟨configuration, known, majority⟩
      exact Or.inr
        ⟨configuration,
          by simpa [logEq] using known,
          hasConfigurationMajority_mono
            (votesMonotone leader) majority⟩
  have voteHistoryIntermediate :
      forall
        (actualVotes : VoteHistory Node)
        (actualAppendHistory :
          AppendRequestKey Node TxId -> List (Entry Node TxId))
        (actualResponseHistory :
          AppendResponseKey Node -> List (Entry Node TxId))
        (actualVoteRequestHistory :
          VoteRequestKey Node -> List (Entry Node TxId))
        (actualVoteCandidateHistory actualVoteVoterHistory :
          VoteResponseKey Node -> List (Entry Node TxId)),
        InvariantFacts (joined := joinedNodes)
            state actualVotes actualAppendHistory actualResponseHistory
              actualVoteRequestHistory actualVoteCandidateHistory
              actualVoteVoterHistory ->
          VoteHistoryFacts intermediate actualVotes := by
    intro actualVotes _ _ _ _ _ actualFacts
    constructor
    · exact actualFacts.voteHistory.bootstrapEmpty
    · intro voter
      simpa [termEq, votedEq] using actualFacts.voteHistory.current voter
    · intro voter term future
      rw [termEq] at future
      exact actualFacts.voteHistory.future voter term future
    · intro candidate voter active member
      rw [termEq]
      have oldActive :
          ((nodeOf state) candidate).role = .candidate \/
            ((nodeOf state) candidate).role = .leader := by
        simpa [roleEq] using active
      by_cases candidateEq : candidate = destination
      · subst candidate
        rcases votesDestination with unchanged | inserted
        · exact
            actualFacts.voteHistory.counted destination voter oldActive
              (by simpa [unchanged] using member)
        · have sourceOrOld :
              voter = response.1 \/
                voter ∈ ((nodeOf state) destination).votesGranted := by
            simpa [inserted.2.2.2] using member
          rcases sourceOrOld with sourceEq | old
          · subst voter
            rcases
                actualFacts.networkHistory.voteResponse
                  destination response selectedMember inserted.1 with
              ⟨_, recorded, _⟩
            simpa [inserted.2.1, responseDestination] using recorded
          · exact
              actualFacts.voteHistory.counted
                destination voter oldActive old
      · exact
          actualFacts.voteHistory.counted candidate voter oldActive
            (by simpa [votesOther candidate candidateEq] using member)
  have progressIntermediate : LeaderProgressBounded intermediate := by
    intro leader role peer
    have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
    simpa [sentEq, matchEq, logEq] using facts.leaderProgressBounded leader oldRole peer
  have effectiveAckersEq :
      forall actualResponseHistory leader index,
        effectiveAckers (joined := joinedNodes) intermediate actualResponseHistory leader index =
          effectiveAckers (joined := joinedNodes) state actualResponseHistory leader index :=
    effectiveAckersFrame
      state intermediate rfl rfl termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
  have joinedCarriersIntermediate : JoinedCarrierFacts (joined := joinedNodes) intermediate := by
    constructor
    · intro candidate peer member
      exact
        facts.joinedCarriers.activeNodes candidate
          (activeNodeUnion_subset_of_activeConfigurations_subset
            ((nodeOf state) candidate) ((nodeOf intermediate) candidate)
            (by
              intro configuration active
              simpa [activeConfigurationsEq] using active)
            member)
    · intro candidate configuration member peer inNodes
      exact
        facts.joinedCarriers.configurationNodes candidate configuration
          (by simpa [logEq] using member) inNodes
    · intro candidate voter member
      by_cases candidateEq : candidate = destination
      · subst candidate
        rcases votesDestination with unchanged | inserted
        · exact
            facts.joinedCarriers.grantedVotes destination
              (by simpa [unchanged] using member)
        · have sourceOrOld :
              voter = response.1 \/
                voter ∈ ((nodeOf state) destination).votesGranted := by
            simpa [inserted.2.2.2] using member
          rcases sourceOrOld with rfl | old
          · exact
              facts.joinedCarriers.voteResponseSources
                destination response selectedMember
          · exact facts.joinedCarriers.grantedVotes destination old
      · exact
          facts.joinedCarriers.grantedVotes candidate
            (by simpa [votesOther candidate candidateEq] using member)
    · exact facts.joinedCarriers.voteRequestDestinations
    · exact facts.joinedCarriers.appendRequestDestinations
    · exact facts.joinedCarriers.appendRequestConfigurations
    · exact facts.joinedCarriers.voteResponseSources
    · constructor
      · intro candidate active
        exact
          facts.joinedCarriers.runtimeNodes.activeRoles candidate
            (by simpa [roleEq] using active)
      · intro leader peer positive
        exact
          facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
            (by simpa [matchEq] using positive)
      · exact facts.joinedCarriers.runtimeNodes.appendResponses
      · intro candidate nonempty
        exact
          facts.joinedCarriers.runtimeNodes.nonemptyLogs candidate
            (by simpa [logEq] using nonempty)
  have intermediateInvariant :
      SystemInductiveInvariant (joined := joinedNodes) intermediate := by
    apply
      roleAndNetworkFramePreservesSystemInductiveInvariant state intermediate packed rfl
          joinedCarriersIntermediate
          (fun node active => by simpa [roleEq] using active)
          (fun node role => by simpa [roleEq] using role)
          (fun node role => by simpa [roleEq] using role)
          (fun node role => by simpa [roleEq] using role)
          (fun node role => by simpa [roleEq] using role)
          termEq logEq commitEq
          candidatesSelfVoteIntermediate
          leadersHaveElectionWitnessIntermediate
    · exact voteHistoryIntermediate
    · intro _ _ _ _ _ _ actualFacts
      rcases actualFacts.processedAckHistory with
        ⟨actualAckHistory, actualAckFacts⟩
      exact ⟨
        actualAckHistory,
        processedAckHistoryFrame
          state intermediate actualAckHistory actualAckFacts
          roleEq termEq logEq
          (fun leader peer => congrFun (matchEq leader) peer)
      ⟩
    · intro queuedDestination message member
      exact Or.inl (by simpa [intermediate, present] using member)
    · exact progressIntermediate
    · intro _ _ actualResponseHistory _ _ _ _ leader index
      exact Finset.subset_of_eq
        (effectiveAckersEq actualResponseHistory leader index)
    · intro _ actualAppendHistory actualResponseHistory
        _ _ _ _ leader index peer member
      simp only [
        potentialAckers, Finset.mem_filter] at member ⊢
      rcases member with ⟨joined, effective | reserve⟩
      · exact ⟨
          by simpa [intermediate, present] using joined,
          Or.inl
            (by
              rw [effectiveAckersEq actualResponseHistory leader index]
                at effective
              exact effective)
        ⟩
      · refine ⟨by simpa [intermediate, present] using joined, Or.inr ?_⟩
        unfold queuedAppendReserve at reserve ⊢
        rcases reserve with
          ⟨request, queued, sourceEq, destinationEq,
            requestTerm, producible, covered⟩
        have oldProducible :
            canProduceAppendAckEventuallyAt
              ((nodeOf state) peer) request index := by
          by_cases peerEq : peer = destination
          · have destinationProducible :
                canProduceAppendAckEventuallyAt
                  ((nodeOf intermediate) destination) request index := by
              simpa only [peerEq] using producible
            rcases votesDestination with unchanged | inserted
            · have nodeEq :
                  (nodeOf intermediate) destination =
                    (nodeOf state) destination := by
                have roleField := roleEq destination
                have termField := termEq destination
                have logField := logEq destination
                have commitField := commitEq destination
                have sentField := sentEq destination
                have matchField := matchEq destination
                have newFollowerField := newFollowerEq destination
                have votedField := votedEq destination
                have preVotesField := preVotesEq destination
                have membershipField := membershipEq destination
                have retirementField := retirementIndexEq destination
                have retirementCommittableField :=
                  retirementCommittableIndexEq destination
                have retiredCommittedField :=
                  retiredCommittedIndexEq destination
                cases hIntermediate : (nodeOf intermediate) destination
                cases hState : (nodeOf state) destination
                simp_all
              rw [nodeEq] at destinationProducible
              simpa [peerEq] using destinationProducible
            · rcases destinationProducible with direct | future
              · have follower := canProduceAppendAckAt_role direct
                have candidate :
                    ((nodeOf intermediate) destination).role = .candidate := by
                  rw [roleEq]
                  exact inserted.2.2.1
                exact False.elim
                  (Role.noConfusion (follower.symm.trans candidate))
              · have result :
                    canProduceAppendAckEventuallyAt
                      ((nodeOf state) destination) request index :=
                  Or.inr
                    ⟨by simpa [termEq] using future.1, future.2⟩
                simpa [peerEq] using result
          · have nodeEq :
                (nodeOf intermediate) peer = (nodeOf state) peer := by
              simp [
                intermediate, present, nodeOf_replaceNode, peerEq
              ]
            rw [nodeEq] at producible
            exact producible
        exact ⟨
          request,
          by simpa [intermediate, present] using queued,
          sourceEq,
          destinationEq,
          by simpa [termEq] using requestTerm,
          oldProducible,
          by simpa [logEq] using covered
        ⟩
    · intro candidate role majority
      unfold hasEffectiveElectionMajority at majority ⊢
      simpa [
        activeConfigurationsEq, effectiveElectionVotersEq
      ] using majority
    · intro candidate role majority
      unfold hasPotentialElectionMajority at majority ⊢
      simpa [
        potentialElectionVoters,
        currentlyEligibleElectionVoter,
        voteRequestKey, Model.Local.makeRequestVoteRequest,
        activeConfigurationsEq, effectiveElectionVotersEq,
        termEq, logEq, commitEq, votedEq,
        lastCommittableIndexFrame
          (logEq candidate) (commitEq candidate),
        lastCommittableTermFrame
          (logEq candidate) (commitEq candidate),
        voteLogUpToDate
      ] using majority
    · intro candidate voter _ member
      simpa [effectiveElectionVotersEq] using member
  have nodeStateEq :
      forall node, (nodeOf after) node = (nodeOf intermediate) node := by
    intro node
    rfl
  have takenFromIntermediate :
      Selected response.1 intermediate.network (voteResponseEnvelope response) remaining := by
    simpa [intermediate, present] using takenByResponseSource
  have networkSubsetAfter :
      forall queuedDestination message,
        (message ∈ after.network /\ message.target = queuedDestination) ->
          (message ∈ intermediate.network /\ message.target = queuedDestination) := by
    intro queuedDestination message member
    have old :=
      updateQueueSubset queuedDestination message
        (by simpa [after, present] using member)
    simpa [intermediate, present] using old
  have effectiveElectionSubsetAfter :
      forall candidate,
        effectiveElectionVoters (joined := joinedNodes) after candidate ⊆
          effectiveElectionVoters (joined := joinedNodes) intermediate candidate :=
    effectiveElectionVotersAfterVoteResponseSubset
      intermediate after destination response remaining
        takenFromIntermediate responseDestination
        (by simp [after, present, intermediate, present])
        (by simp [after, present, intermediate, present])
        (fun node => by rw [nodeStateEq node])
        (Or.inl (by rfl))
        (fun candidate _ => by rw [nodeStateEq candidate])
  change SystemInductiveInvariant (joined := joinedNodes) after
  apply networkFramePreservesSystemInductiveInvariant intermediate after intermediateInvariant (by simp [after, present, intermediate, present]) nodeStateEq
    (fun destination message member =>
      Or.inl (networkSubsetAfter destination message member))
  · intro _ _ actualResponseHistory _ _ _ _ leader index
    exact Finset.subset_of_eq (
      effectiveAckersAfterVoteResponse
        intermediate after destination response remaining
          takenFromIntermediate
          (by simp [after, present, intermediate, present])
          (by simp [after, present, intermediate, present])
          (fun node => by rw [nodeStateEq node])
          (fun node => by rw [nodeStateEq node])
          (fun actualLeader peer => by rw [nodeStateEq actualLeader])
          actualResponseHistory leader index)
  · intro candidate role majority
    rw [hasEffectiveElectionMajority, List.all_eq_true] at majority ⊢
    intro configuration active
    apply decide_eq_true
    have afterActive :
        configuration ∈ activeConfigurations ((nodeOf after) candidate) := by
      simpa [nodeStateEq] using active
    exact
      hasConfigurationMajority_mono
        (effectiveElectionSubsetAfter candidate)
        (of_decide_eq_true (majority configuration afterActive))
  · exact fun candidate voter _ member =>
      effectiveElectionSubsetAfter candidate member

end CCFRaft.Proofs.Invariant
