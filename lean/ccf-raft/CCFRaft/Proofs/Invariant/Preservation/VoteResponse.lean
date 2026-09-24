-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.AppendResponse
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

omit [Bootstrap Node] in
/-- Dequeuing a vote response leaves latent replication acknowledgements unchanged. -/
lemma effectiveAckersAfterVoteResponse
    (state after : View Node TxId)
    (destination : Node)
    (response : RequestVoteResponse Node)
    (remaining : List (Message Node TxId))
    (taken
      : Selected response.source (state.network destination)
          (.requestVoteResponse response) remaining)
    (networkEq : after.network = updateQueue state.network destination remaining)
    (hasJoinedEq : after.hasJoined = state.hasJoined)
    (termEq
      : forall node, (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq : forall node, (after.nodes node).log = (state.nodes node).log)
    (matchEq
      : forall leader peer,
          (after.nodes leader).matchIndex peer = (state.nodes leader).matchIndex peer)
    : forall (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
              leader index,
        effectiveAckers after responseHistory leader index
        = effectiveAckers state responseHistory leader index := by
  intro responseHistory leader index
  have remainingOld := (selectedSound taken).2.2
  ext peer
  simp only [
    effectiveAckers, Finset.mem_filter]
  apply and_congr (by simp only [hasJoinedEq])
  constructor <;> rintro (self | matched | queued)
  · exact Or.inl self
  · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
  · right
    right
    rcases queued with
        ⟨queuedResponse, member, success, responseTerm, sourceEq,
          responseDestination, lastIndex, covered⟩
    have oldMember :
          Message.appendEntriesResponse queuedResponse ∈
            state.network leader := by
      rw [networkEq] at member
      by_cases leaderEq : leader = destination
      · have queuedDestination :
            queuedResponse.destination = destination :=
          responseDestination.trans leaderEq
        subst leader
        have remainingMember :
            Message.appendEntriesResponse queuedResponse ∈ remaining := by
          simpa [updateQueue, Function.update, queuedDestination] using member
        simpa [queuedDestination] using remainingOld _ remainingMember
      · simpa [updateQueue, Function.update, leaderEq] using member
    exact ⟨
      queuedResponse,
      oldMember,
      success,
      by simpa [termEq] using responseTerm,
      sourceEq,
      responseDestination,
      lastIndex,
      by simpa [logEq] using covered
    ⟩
  · exact Or.inl self
  · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
  · right
    right
    rcases queued with
        ⟨queuedResponse, member, success, responseTerm, sourceEq,
          responseDestination, lastIndex, covered⟩
    refine ⟨
      queuedResponse,
      ?_,
      success,
      by simpa [termEq] using responseTerm,
      sourceEq,
      responseDestination,
      lastIndex,
      by simpa [logEq] using covered
    ⟩
    rw [networkEq]
    by_cases leaderEq : leader = destination
    · have queuedDestination :
          queuedResponse.destination = destination :=
        responseDestination.trans leaderEq
      subst leader
      have oldMember :
          Message.appendEntriesResponse queuedResponse ∈
            state.network destination := by
        simpa [queuedDestination] using member
      rcases memSelectedOrRemaining taken oldMember with
        selectedEq | remainingMember
      · simp at selectedEq
      · simpa [
          updateQueue, Function.update, queuedDestination
        ] using remainingMember
    · simpa [updateQueue, Function.update, leaderEq] using member

omit [Bootstrap Node] in
/--
Processing a vote response never creates new effective election evidence:
a newly recorded vote was already represented by the selected queued grant.
-/
lemma effectiveElectionVotersAfterVoteResponseSubset
    (state after : View Node TxId)
    (destination : Node)
    (response : RequestVoteResponse Node)
    (remaining : List (Message Node TxId))
    (taken
      : Selected response.source (state.network destination)
          (.requestVoteResponse response) remaining)
    (responseDestination : response.destination = destination)
    (networkEq : after.network = updateQueue state.network destination remaining)
    (hasJoinedEq : after.hasJoined = state.hasJoined)
    (termEq
      : forall node, (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (votesDestination
      : (after.nodes destination).votesGranted = (state.nodes destination).votesGranted
        \/ (response.voteGranted = true
            /\ response.term = (state.nodes destination).currentTerm
            /\ (after.nodes destination).votesGranted
                = insert response.source (state.nodes destination).votesGranted))
    (votesOther
      : forall candidate,
          Not (candidate = destination)
          -> (after.nodes candidate).votesGranted = (state.nodes candidate).votesGranted)
    : forall candidate,
        effectiveElectionVoters after candidate
        ⊆ effectiveElectionVoters state candidate := by
  intro candidate voter member
  have selectedMember :
      Message.requestVoteResponse response ∈
        state.network destination :=
    (selectedSound taken).2.1
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
            voter = response.source \/
              voter ∈ (state.nodes destination).votesGranted := by
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
        Message.requestVoteResponse queuedResponse ∈
          state.network candidate := by
      rw [networkEq] at queuedMember
      by_cases candidateEq : candidate = destination
      · have queuedDestinationEq :
            queuedResponse.destination = destination :=
          queuedDestination.trans candidateEq
        subst candidate
        have remainingMember :
            Message.requestVoteResponse queuedResponse ∈ remaining := by
          simpa [updateQueue, Function.update, queuedDestinationEq] using queuedMember
        simpa [queuedDestinationEq] using remainingOld _ remainingMember
      · simpa [
          updateQueue, Function.update, candidateEq
        ] using queuedMember
    exact ⟨
      queuedResponse,
      oldMember,
      granted,
      by simpa [termEq] using responseTerm,
      responseSource,
      queuedDestination
    ⟩

omit [DecidableEq TxId] [Bootstrap Node] in
/--
Before dequeue, recording a granted vote only changes the representation of
evidence already present in the selected queued response.
-/
lemma effectiveElectionVotersAfterVoteResponseHandler
    (state after : View Node TxId)
    (destination : Node)
    (response : RequestVoteResponse Node)
    (selectedMember : Message.requestVoteResponse response ∈ state.network destination)
    (responseDestination : response.destination = destination)
    (networkEq : after.network = state.network)
    (hasJoinedEq : after.hasJoined = state.hasJoined)
    (termEq
      : forall node, (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (votesDestination
      : (after.nodes destination).votesGranted = (state.nodes destination).votesGranted
        \/ (response.voteGranted = true
            /\ response.term = (state.nodes destination).currentTerm
            /\ (after.nodes destination).votesGranted
                = insert response.source (state.nodes destination).votesGranted))
    (votesOther
      : forall candidate,
          Not (candidate = destination)
          -> (after.nodes candidate).votesGranted = (state.nodes candidate).votesGranted)
    : forall candidate,
        effectiveElectionVoters after candidate
        = effectiveElectionVoters state candidate := by
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
              voter = response.source \/
                voter ∈ (state.nodes destination).votesGranted := by
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

omit [DecidableEq TxId] [Bootstrap Node] in
/-- The exact vote-set alternatives of the RequestVote response handler. -/
lemma handleRequestVoteResponseVoteUpdate
    {before after : NodeState Node TxId}
    {response : RequestVoteResponse Node}
    (handled : handleRequestVoteResponse? before response = some after)
    : after.votesGranted = before.votesGranted
      \/ (response.voteGranted = true
          /\ response.term = before.currentTerm
          /\ before.role = .candidate
          /\ after.votesGranted = insert response.source before.votesGranted) := by
  unfold handleRequestVoteResponse? at handled
  split at handled
  · simp at handled
    subst after
    exact Or.inl rfl
  · split at handled
    · simp at handled
      subst after
      exact Or.inl rfl
    · rename_i candidateRole
      split at handled
      · rename_i currentTerm
        split at handled
        · rename_i granted
          simp at handled
          subst after
          exact
            Or.inr
              ⟨granted, currentTerm, by simpa using candidateRole, rfl⟩
        · simp at handled
          subst after
          exact Or.inl rfl
      · contradiction

/-- Receiving a RequestVote response transfers latent vote evidence to runtime state. -/
lemma receiveRequestVoteResponsePreservesSystemInductiveInvariant
    (state : View Node TxId)
    (source destination : Node)
    (response : RequestVoteResponse Node)
    (remaining : List (Message Node TxId))
    (nextNode : NodeState Node TxId)
    (invariant : SystemInductiveInvariant state)
    (_destinationAllocated : state.allocated destination)
    (taken
      : Selected source (state.network destination) (.requestVoteResponse response)
          remaining)
    (responseDestination : response.destination = destination)
    (handled
      : handleRequestVoteResponse? (state.nodes destination) response = some nextNode)
    : SystemInductiveInvariant
        {
          state with
            nodes := updateNode state.nodes destination nextNode
            network := updateQueue state.network destination remaining
        } := by
  have responseSource : response.source = source :=
    (selectedSound taken).1
  have takenByResponseSource :
      Selected response.source (state.network destination) (.requestVoteResponse response) remaining := by
    simpa [responseSource] using taken
  have selectedMember :
      Message.requestVoteResponse response ∈
        state.network destination :=
    (selectedSound taken).2.1
  have remainingOld := (selectedSound taken).2.2
  have updateQueueSubset :
      forall queuedDestination message,
        message ∈
            updateQueue state.network destination remaining
              queuedDestination ->
          message ∈ state.network queuedDestination := by
    intro queuedDestination message member
    by_cases destinationEq : queuedDestination = destination
    · subst queuedDestination
      exact remainingOld message
        (by simpa [updateQueue, Function.update] using member)
    · simpa [updateQueue, Function.update, destinationEq] using member
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have packed :
      SystemInductiveInvariant state :=
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  have post := handleRequestVoteResponsePreserves handled
  have voteUpdate := handleRequestVoteResponseVoteUpdate handled
  let intermediate : View Node TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode }
  let after : View Node TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network := updateQueue state.network destination remaining }
  have roleEq :
      forall node,
        (intermediate.nodes node).role = (state.nodes node).role := by
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
        (intermediate.nodes node).log = (state.nodes node).log := by
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
  have preVotesEq :
      forall node,
        (intermediate.nodes node).preVotesGranted =
          (state.nodes node).preVotesGranted := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.preVotesGrantedUnchanged
      ]
  have membershipEq :
      forall node,
        (intermediate.nodes node).membershipState =
          (state.nodes node).membershipState := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.membershipStateUnchanged
      ]
  have retirementIndexEq :
      forall node,
        (intermediate.nodes node).retirementIndex =
          (state.nodes node).retirementIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.retirementIndexUnchanged
      ]
  have retirementCommittableIndexEq :
      forall node,
        (intermediate.nodes node).retirementCommittableIndex =
          (state.nodes node).retirementCommittableIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.retirementCommittableIndexUnchanged
      ]
  have retiredCommittedIndexEq :
      forall node,
        (intermediate.nodes node).retiredCommittedIndex =
          (state.nodes node).retiredCommittedIndex := by
    intro node
    by_cases same : node = destination <;>
      simp [
        intermediate, updateNode, same,
        post.retiredCommittedIndexUnchanged
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
  have nextNewFollower :
      nextNode.isNewFollower =
        (state.nodes destination).isNewFollower := by
    have handledCopy := handled
    unfold handleRequestVoteResponse? at handledCopy
    split at handledCopy
    · simp at handledCopy
      subst nextNode
      rfl
    · split at handledCopy
      · simp at handledCopy
        subst nextNode
        rfl
      · split at handledCopy
        · split at handledCopy
          · simp at handledCopy
            subst nextNode
            rfl
          · simp at handledCopy
            subst nextNode
            rfl
        · contradiction
  have newFollowerEq :
      forall node,
        (intermediate.nodes node).isNewFollower =
          (state.nodes node).isNewFollower := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [intermediate, updateNode] using nextNewFollower
    · simp [intermediate, updateNode, same]
  have votesDestination :
      (intermediate.nodes destination).votesGranted =
          (state.nodes destination).votesGranted \/
        (response.voteGranted = true /\
          response.term = (state.nodes destination).currentTerm /\
          (state.nodes destination).role = .candidate /\
          (intermediate.nodes destination).votesGranted =
            insert
              response.source
              (state.nodes destination).votesGranted) := by
    rcases voteUpdate with unchanged | inserted
    · exact Or.inl
        (by simpa [intermediate, updateNode] using unchanged)
    · exact Or.inr
        ⟨inserted.1, inserted.2.1, inserted.2.2.1,
          by simpa [intermediate, updateNode] using inserted.2.2.2⟩
  have votesDestinationPlain :
      (intermediate.nodes destination).votesGranted =
          (state.nodes destination).votesGranted \/
        (response.voteGranted = true /\
          response.term = (state.nodes destination).currentTerm /\
          (intermediate.nodes destination).votesGranted =
            insert
              response.source
              (state.nodes destination).votesGranted) := by
    rcases votesDestination with unchanged | inserted
    · exact Or.inl unchanged
    · exact Or.inr
        ⟨inserted.1, inserted.2.1, inserted.2.2.2⟩
  have votesOther :
      forall candidate,
        Not (candidate = destination) ->
          (intermediate.nodes candidate).votesGranted =
            (state.nodes candidate).votesGranted := by
    intro candidate different
    simp [intermediate, updateNode, different]
  have votesMonotone :
      forall candidate,
        (state.nodes candidate).votesGranted ⊆
          (intermediate.nodes candidate).votesGranted := by
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
        effectiveElectionVoters intermediate candidate =
          effectiveElectionVoters state candidate :=
    effectiveElectionVotersAfterVoteResponseHandler
      state intermediate destination response selectedMember
        responseDestination rfl rfl termEq votesDestinationPlain votesOther
  have activeConfigurationsEq :
      forall candidate,
        activeConfigurations (intermediate.nodes candidate) =
          activeConfigurations (state.nodes candidate) := by
    intro candidate
    unfold activeConfigurations currentConfiguration
    rw [logEq, commitEq]
  have candidatesSelfVoteIntermediate : CandidatesSelfVote intermediate := by
    intro candidate role
    have oldRole : (state.nodes candidate).role = .candidate := by
      simpa [roleEq] using role
    rcases facts.candidatesSelfVote candidate oldRole with
      ⟨selfVote, selfCounted⟩
    exact ⟨by simpa [votedEq] using selfVote, votesMonotone candidate selfCounted⟩
  have leadersHaveElectionWitnessIntermediate :
      LeadersHaveElectionWitness intermediate := by
    intro leader role
    have oldRole : (state.nodes leader).role = .leader := by simpa [roleEq] using role
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
          AppendEntriesRequest Node TxId -> List (Entry Node TxId))
        (actualResponseHistory :
          AppendEntriesResponse Node -> List (Entry Node TxId))
        (actualVoteRequestHistory :
          RequestVoteRequest Node -> List (Entry Node TxId))
        (actualVoteCandidateHistory actualVoteVoterHistory :
          RequestVoteResponse Node -> List (Entry Node TxId)),
        InvariantFacts
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
          (state.nodes candidate).role = .candidate \/
            (state.nodes candidate).role = .leader := by
        simpa [roleEq] using active
      by_cases candidateEq : candidate = destination
      · subst candidate
        rcases votesDestination with unchanged | inserted
        · exact
            actualFacts.voteHistory.counted destination voter oldActive
              (by simpa [unchanged] using member)
        · have sourceOrOld :
              voter = response.source \/
                voter ∈ (state.nodes destination).votesGranted := by
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
    have oldRole : (state.nodes leader).role = .leader := by simpa [roleEq] using role
    simpa [sentEq, matchEq, logEq] using facts.leaderProgressBounded leader oldRole peer
  have effectiveAckersEq :
      forall actualResponseHistory leader index,
        effectiveAckers intermediate actualResponseHistory leader index =
          effectiveAckers state actualResponseHistory leader index :=
    effectiveAckersFrame
      state intermediate rfl rfl termEq logEq
        (fun leader peer => congrFun (matchEq leader) peer)
  have joinedCarriersIntermediate : JoinedCarrierFacts intermediate := by
    constructor
    · intro candidate peer member
      exact
        facts.joinedCarriers.activeNodes candidate
          (activeNodeUnion_subset_of_activeConfigurations_subset
            (state.nodes candidate) (intermediate.nodes candidate)
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
              voter = response.source \/
                voter ∈ (state.nodes destination).votesGranted := by
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
      exact Or.inl (by simpa [intermediate] using member)
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
          by simpa [intermediate] using joined,
          Or.inl
            (by
              rw [effectiveAckersEq actualResponseHistory leader index]
                at effective
              exact effective)
        ⟩
      · refine ⟨by simpa [intermediate] using joined, Or.inr ?_⟩
        unfold queuedAppendReserve at reserve ⊢
        rcases reserve with
          ⟨request, queued, sourceEq, destinationEq,
            requestTerm, producible, covered⟩
        have oldProducible :
            canProduceAppendAckEventuallyAt
              (state.nodes peer) request index := by
          by_cases peerEq : peer = destination
          · have destinationProducible :
                canProduceAppendAckEventuallyAt
                  (intermediate.nodes destination) request index := by
              simpa only [peerEq] using producible
            rcases votesDestination with unchanged | inserted
            · have nodeEq :
                  intermediate.nodes destination =
                    state.nodes destination := by
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
                cases hIntermediate : intermediate.nodes destination
                cases hState : state.nodes destination
                simp_all
              rw [nodeEq] at destinationProducible
              simpa [peerEq] using destinationProducible
            · rcases destinationProducible with direct | future
              · have follower := canProduceAppendAckAt_role direct
                have candidate :
                    (intermediate.nodes destination).role = .candidate := by
                  rw [roleEq]
                  exact inserted.2.2.1
                exact False.elim
                  (Role.noConfusion (follower.symm.trans candidate))
              · have result :
                    canProduceAppendAckEventuallyAt
                      (state.nodes destination) request index :=
                  Or.inr
                    ⟨by simpa [termEq] using future.1, future.2⟩
                simpa [peerEq] using result
          · have nodeEq :
                intermediate.nodes peer = state.nodes peer := by
              simp [
                intermediate, updateNode, peerEq
              ]
            rw [nodeEq] at producible
            exact producible
        exact ⟨
          request,
          by simpa [intermediate] using queued,
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
        makeRequestVoteRequest,
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
      forall node, after.nodes node = intermediate.nodes node := by
    intro node
    rfl
  have takenFromIntermediate :
      Selected response.source (intermediate.network destination) (.requestVoteResponse response) remaining := by
    simpa [intermediate] using takenByResponseSource
  have networkSubsetAfter :
      forall queuedDestination message,
        message ∈ after.network queuedDestination ->
          message ∈ intermediate.network queuedDestination := by
    intro queuedDestination message member
    have old :=
      updateQueueSubset queuedDestination message
        (by simpa [after] using member)
    simpa [intermediate] using old
  have effectiveElectionSubsetAfter :
      forall candidate,
        effectiveElectionVoters after candidate ⊆
          effectiveElectionVoters intermediate candidate :=
    effectiveElectionVotersAfterVoteResponseSubset
      intermediate after destination response remaining
        takenFromIntermediate responseDestination
        (by simp [after, intermediate])
        (by simp [after, intermediate])
        (fun node => by rw [nodeStateEq node])
        (Or.inl (by rfl))
        (fun candidate _ => by rw [nodeStateEq candidate])
  change SystemInductiveInvariant after
  apply networkFramePreservesSystemInductiveInvariant
    intermediate after intermediateInvariant
    (by simp [after, intermediate]) (fun _ => Iff.rfl) nodeStateEq
    (fun destination message member =>
      Or.inl (networkSubsetAfter destination message member))
  · intro _ _ actualResponseHistory _ _ _ _ leader index
    exact Finset.subset_of_eq (
      effectiveAckersAfterVoteResponse
        intermediate after destination response remaining
          takenFromIntermediate
          (by simp [after, intermediate])
          (by simp [after, intermediate])
          (fun node => by rw [nodeStateEq node])
          (fun node => by rw [nodeStateEq node])
          (fun actualLeader peer => by rw [nodeStateEq actualLeader])
          actualResponseHistory leader index)
  · intro candidate role majority
    rw [hasEffectiveElectionMajority, List.all_eq_true] at majority ⊢
    intro configuration active
    apply decide_eq_true
    have afterActive :
        configuration ∈ activeConfigurations (after.nodes candidate) := by
      simpa [nodeStateEq] using active
    exact
      hasConfigurationMajority_mono
        (effectiveElectionSubsetAfter candidate)
        (of_decide_eq_true (majority configuration afterActive))
  · exact fun candidate voter _ member =>
      effectiveElectionSubsetAfter candidate member

end CCFRaft.Proofs.Invariant
