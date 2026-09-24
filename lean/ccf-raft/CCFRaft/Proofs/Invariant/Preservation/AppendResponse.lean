-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.NetworkFrames
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

def setResultSentIndex
    (sentIndex : Node -> Nat)
    (result : NodeState Node TxId × AppendEntriesResponse Node)
    : NodeState Node TxId × AppendEntriesResponse Node :=
  ({ result.1 with sentIndex }, result.2)

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
lemma rejectAppendEntriesRequest_sentIndex
    (node : NodeState Node TxId)
    (sentIndex : Node -> Nat)
    (request : AppendEntriesRequest Node TxId)
    : rejectAppendEntriesRequest? { node with sentIndex } request
      = (rejectAppendEntriesRequest? node request).map
          (setResultSentIndex sentIndex) := by
  simp [
    rejectAppendEntriesRequest?, logOk, failureResponse,
    setResultSentIndex
  ]

omit [Bootstrap Node] in
lemma appendEntriesAlreadyDone_sentIndex
    (node : NodeState Node TxId)
    (sentIndex : Node -> Nat)
    (request : AppendEntriesRequest Node TxId)
    : appendEntriesAlreadyDone? { node with sentIndex } request
      = (appendEntriesAlreadyDone? node request).map (setResultSentIndex sentIndex) := by
  simp [
    appendEntriesAlreadyDone?, alreadyDone,
    committedFromLeader, successResponse, setResultSentIndex
  ]

lemma noConflictAppendEntriesRequest_sentIndex
    (node : NodeState Node TxId)
    (sentIndex : Node -> Nat)
    (request : AppendEntriesRequest Node TxId)
    : noConflictAppendEntriesRequest? { node with sentIndex } request
      = (noConflictAppendEntriesRequest? node request).map
          (setResultSentIndex sentIndex) := by
  unfold noConflictAppendEntriesRequest?
  split
  · rename_i extension
    change noConflictExtension node request at extension
    rw [ite_eq_left extension]
    rfl
  · rename_i extension
    change ¬ noConflictExtension node request at extension
    rw [ite_eq_right extension]
    rfl

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
lemma conflictAppendEntriesRequest_sentIndex
    (node : NodeState Node TxId)
    (sentIndex : Node -> Nat)
    (request : AppendEntriesRequest Node TxId)
    : conflictAppendEntriesRequest? { node with sentIndex } request
      = (conflictAppendEntriesRequest? node request).map
          (fun nextNode => { nextNode with sentIndex }) := by
  simp [
    conflictAppendEntriesRequest?, hasTermConflict,
    overlapLength
  ]

lemma acceptAppendEntriesRequest_sentIndex
    (node : NodeState Node TxId)
    (sentIndex : Node -> Nat)
    (request : AppendEntriesRequest Node TxId)
    : acceptAppendEntriesRequest? { node with sentIndex } request
      = (acceptAppendEntriesRequest? node request).map
          (setResultSentIndex sentIndex) := by
  unfold acceptAppendEntriesRequest?
  by_cases enabled :
      request.term = node.currentTerm /\
        node.role = .follower /\
        logOk node request /\
        request.prevLogIndex >= node.commitIndex
  · have updatedEnabled :
        request.term = ({ node with sentIndex }).currentTerm /\
          ({ node with sentIndex }).role = .follower /\
          logOk { node with sentIndex } request /\
          request.prevLogIndex >= ({ node with sentIndex }).commitIndex := by
      simpa [logOk] using enabled
    rw [ite_eq_left updatedEnabled, ite_eq_left enabled]
    rw [appendEntriesAlreadyDone_sentIndex]
    cases done : appendEntriesAlreadyDone? node request with
    | some result =>
        simp []
    | none =>
        simp only [ Option.map_none]
        rw [noConflictAppendEntriesRequest_sentIndex]
        cases extension : noConflictAppendEntriesRequest? node request with
        | some result =>
            simp []
        | none =>
            simp only [ Option.map_none]
            rw [conflictAppendEntriesRequest_sentIndex]
            cases conflict : conflictAppendEntriesRequest? node request with
            | none =>
                simp []
            | some truncated =>
                simp only [ Option.map_some]
                rw [appendEntriesAlreadyDone_sentIndex]
                cases repeated : appendEntriesAlreadyDone? truncated request with
                | some result =>
                    simp [ setResultSentIndex]
                | none =>
                    simp only [ Option.map_none]
                    rw [noConflictAppendEntriesRequest_sentIndex]
  · have updatedDisabled :
        Not (
          request.term = ({ node with sentIndex }).currentTerm /\
            ({ node with sentIndex }).role = .follower /\
            logOk { node with sentIndex } request /\
            request.prevLogIndex >=
              ({ node with sentIndex }).commitIndex) := by
      simpa [logOk] using enabled
    rw [ite_eq_right updatedDisabled, ite_eq_right enabled]
    rfl

lemma handleAppendEntriesRequest_sentIndex
    (node : NodeState Node TxId)
    (sentIndex : Node -> Nat)
    (request : AppendEntriesRequest Node TxId)
    : handleAppendEntriesRequest? { node with sentIndex } request
      = (handleAppendEntriesRequest? node request).map
          (setResultSentIndex sentIndex) := by
  unfold handleAppendEntriesRequest?
  rw [rejectAppendEntriesRequest_sentIndex]
  cases rejected : rejectAppendEntriesRequest? node request with
  | none =>
      simp [ acceptAppendEntriesRequest_sentIndex]
  | some result =>
      simp []

lemma canProduceAppendAckEventuallyAt_sentIndex
    (node : NodeState Node TxId)
    (sentIndex : Node -> Nat)
    (request : AppendEntriesRequest Node TxId)
    (index : Nat)
    : canProduceAppendAckEventuallyAt { node with sentIndex } request index
      ↔ canProduceAppendAckEventuallyAt node request index := by
  constructor
  · rintro (⟨nextNode, response, handled, success, covered⟩ | future)
    · rw [
        protocolNodeState_set_sentIndex,
        handleAppendEntriesRequest_sentIndex
      ] at handled
      cases oldResult : handleAppendEntriesRequest? (protocolNodeState node) request with
      | none =>
          simp [oldResult] at handled
      | some result =>
          simp [oldResult] at handled
          have responseEq : result.2 = response :=
            congrArg Prod.snd handled
          exact Or.inl
            ⟨
              result.1,
              result.2,
              oldResult,
              by rw [responseEq]; exact success,
              by rw [responseEq]; exact covered
            ⟩
    · exact Or.inr future
  · rintro (⟨nextNode, response, handled, success, covered⟩ | future)
    · exact Or.inl
        ⟨{ nextNode with sentIndex }, response,
          by
            rw [
              protocolNodeState_set_sentIndex,
              handleAppendEntriesRequest_sentIndex, handled
            ]
            rfl,
          success, covered⟩
    · exact Or.inr future

omit [Bootstrap Node] in
/-- Dequeuing an ACK which is not effective leaves effective evidence intact. -/
lemma effectiveAckersAfterInactiveResponse
    (state after : View Node TxId)
    (destination : Node)
    (response : AppendEntriesResponse Node)
    (remaining : List (Message Node TxId))
    (taken
      : Selected response.source (state.network destination)
          (.appendEntriesResponse response) remaining)
    (networkEq : after.network = updateQueue state.network destination remaining)
    (hasJoinedEq : after.hasJoined = state.hasJoined)
    (termEq
      : forall node, (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq : forall node, (after.nodes node).log = (state.nodes node).log)
    (matchEq
      : forall leader peer,
          (after.nodes leader).matchIndex peer = (state.nodes leader).matchIndex peer)
    (inactive
      : Not
          (response.success = true
            /\ response.term = (state.nodes destination).currentTerm))
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
  constructor
  · rintro (self | matched | queued)
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
  · rintro (self | matched | queued)
    · exact Or.inl self
    · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, success, responseTerm, sourceEq,
          responseDestination, lastIndex, covered⟩
      have afterMember :
          Message.appendEntriesResponse queuedResponse ∈
            after.network leader := by
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
          rcases
              memSelectedOrRemaining taken oldMember with
            selectedEq | remainingMember
          · simp only [Message.appendEntriesResponse.injEq] at selectedEq
            subst queuedResponse
            exact False.elim
              (inactive
                ⟨success,
                  by simpa [queuedDestination] using responseTerm⟩)
          · simpa [
              updateQueue, Function.update, queuedDestination
            ] using remainingMember
        · simpa [updateQueue, Function.update, leaderEq] using member
      exact ⟨
        queuedResponse,
        afterMember,
        success,
        by simpa [termEq] using responseTerm,
        sourceEq,
        responseDestination,
        lastIndex,
        by simpa [logEq] using covered
      ⟩

omit [Bootstrap Node] in
/--
Processing a successful same-term ACK transfers its evidence from the queue to
the destination leader's monotone `matchIndex`.
-/
lemma effectiveAckersAfterSuccessfulResponse
    (state after : View Node TxId)
    (destination : Node)
    (response : AppendEntriesResponse Node)
    (remaining : List (Message Node TxId))
    (taken
      : Selected response.source (state.network destination)
          (.appendEntriesResponse response) remaining)
    (responseDestination : response.destination = destination)
    (success : response.success = true)
    (sameTerm : response.term = (state.nodes destination).currentTerm)
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (covered : responseHistory response <+: (state.nodes destination).log)
    (networkEq : after.network = updateQueue state.network destination remaining)
    (hasJoinedEq : after.hasJoined = state.hasJoined)
    (termEq
      : forall node, (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq : forall node, (after.nodes node).log = (state.nodes node).log)
    (matchDestination
      : forall peer,
          (after.nodes destination).matchIndex peer
          = updateIndex
              (state.nodes destination).matchIndex
              response.source
              (max
                ((state.nodes destination).matchIndex response.source)
                response.lastLogIndex)
              peer)
    (matchOther
      : forall leader,
          Not (leader = destination)
          -> forall peer,
              (after.nodes leader).matchIndex peer = (state.nodes leader).matchIndex peer)
    : forall leader index,
        effectiveAckers after responseHistory leader index
        = effectiveAckers state responseHistory leader index := by
  intro leader index
  have selectedMember :
      Message.appendEntriesResponse response ∈
        state.network destination :=
    (selectedSound taken).2.1
  have remainingOld := (selectedSound taken).2.2
  ext peer
  simp only [
    effectiveAckers, Finset.mem_filter]
  apply and_congr (by simp only [hasJoinedEq])
  constructor
  · rintro (self | matched | queued)
    · exact Or.inl self
    · by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          rw [matchDestination, updateIndex_same] at matched
          by_cases oldCovers :
              index <=
                (state.nodes destination).matchIndex response.source
          · exact Or.inr (Or.inl oldCovers)
          · right
            right
            refine ⟨
              response,
              selectedMember,
              success,
              sameTerm,
              rfl,
              responseDestination,
              ?_,
              covered
            ⟩
            omega
        · right
          left
          simpa [
            matchDestination, updateIndex,
            Function.update, peerEq
          ] using matched
      · exact Or.inr
          (Or.inl (by simpa [matchOther leader leaderEq] using matched))
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, queuedSuccess, responseTerm, sourceEq,
          queuedDestination, lastIndex, queuedCovered⟩
      have oldMember :
          Message.appendEntriesResponse queuedResponse ∈
            state.network leader := by
        rw [networkEq] at member
        by_cases leaderEq : leader = destination
        · have queuedDestinationEq :
              queuedResponse.destination = destination :=
            queuedDestination.trans leaderEq
          subst leader
          have remainingMember :
              Message.appendEntriesResponse queuedResponse ∈ remaining := by
            simpa [updateQueue, Function.update, queuedDestinationEq] using member
          simpa [queuedDestinationEq] using remainingOld _ remainingMember
        · simpa [updateQueue, Function.update, leaderEq] using member
      exact ⟨
        queuedResponse,
        oldMember,
        queuedSuccess,
        by simpa [termEq] using responseTerm,
        sourceEq,
        queuedDestination,
        lastIndex,
        by simpa [logEq] using queuedCovered
      ⟩
  · rintro (self | matched | queued)
    · exact Or.inl self
    · right
      left
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          rw [matchDestination, updateIndex_same]
          omega
        · simpa [
            matchDestination, updateIndex,
            Function.update, peerEq
          ] using matched
      · simpa [matchOther leader leaderEq] using matched
    · rcases queued with
        ⟨queuedResponse, member, queuedSuccess, responseTerm, sourceEq,
          queuedDestination, lastIndex, queuedCovered⟩
      by_cases leaderEq : leader = destination
      · have queuedDestinationEq :
            queuedResponse.destination = destination :=
          queuedDestination.trans leaderEq
        subst leader
        have oldMember :
            Message.appendEntriesResponse queuedResponse ∈
              state.network destination := by
          simpa [queuedDestinationEq] using member
        rcases memSelectedOrRemaining taken oldMember with
          selectedEq | remainingMember
        · simp only [Message.appendEntriesResponse.injEq] at selectedEq
          rw [selectedEq] at sourceEq
          have peerEq : peer = response.source := sourceEq.symm
          subst peer
          subst queuedResponse
          right
          left
          rw [responseDestination, matchDestination, updateIndex_same]
          omega
        · right
          right
          refine ⟨
            queuedResponse,
            ?_,
            queuedSuccess,
            by simpa [termEq] using responseTerm,
            sourceEq,
            rfl,
            lastIndex,
            by simpa [logEq] using queuedCovered
          ⟩
          rw [networkEq]
          simpa [updateQueue, Function.update, queuedDestinationEq] using remainingMember
      · right
        right
        refine ⟨
          queuedResponse,
          ?_,
          queuedSuccess,
          by simpa [termEq] using responseTerm,
          sourceEq,
          queuedDestination,
          lastIndex,
          by simpa [logEq] using queuedCovered
        ⟩
        rw [networkEq]
        simpa [updateQueue, Function.update, leaderEq] using member

omit [DecidableEq TxId] [Bootstrap Node] in
/--
Before dequeue, a successful same-term ACK's monotone `matchIndex` update only
changes the representation of evidence already present in the queue.
-/
lemma effectiveAckersAfterSuccessfulResponseHandler
    (state after : View Node TxId)
    (destination : Node)
    (response : AppendEntriesResponse Node)
    (responseDestination : response.destination = destination)
    (success : response.success = true)
    (sameTerm : response.term = (state.nodes destination).currentTerm)
    (selectedMember : Message.appendEntriesResponse response ∈ state.network destination)
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (covered : responseHistory response <+: (state.nodes destination).log)
    (networkEq : after.network = state.network)
    (hasJoinedEq : after.hasJoined = state.hasJoined)
    (termEq
      : forall node, (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq : forall node, (after.nodes node).log = (state.nodes node).log)
    (matchDestination
      : forall peer,
          (after.nodes destination).matchIndex peer
          = updateIndex
              (state.nodes destination).matchIndex
              response.source
              (max
                ((state.nodes destination).matchIndex response.source)
                response.lastLogIndex)
              peer)
    (matchOther
      : forall leader,
          Not (leader = destination)
          -> forall peer,
              (after.nodes leader).matchIndex peer = (state.nodes leader).matchIndex peer)
    : forall leader index,
        effectiveAckers after responseHistory leader index
        = effectiveAckers state responseHistory leader index := by
  intro leader index
  ext peer
  simp only [
    effectiveAckers, Finset.mem_filter]
  apply and_congr (by simp only [hasJoinedEq])
  constructor
  · rintro (self | matched | queued)
    · exact Or.inl self
    · by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          rw [matchDestination, updateIndex_same] at matched
          by_cases oldCovers :
              index <=
                (state.nodes destination).matchIndex response.source
          · exact Or.inr (Or.inl oldCovers)
          · right
            right
            exact ⟨
              response,
              selectedMember,
              success,
              sameTerm,
              rfl,
              responseDestination,
              by omega,
              covered
            ⟩
        · right
          left
          simpa [
            matchDestination, updateIndex,
            Function.update, peerEq
          ] using matched
      · exact Or.inr
          (Or.inl (by simpa [matchOther leader leaderEq] using matched))
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, queuedSuccess, responseTerm, sourceEq,
          queuedDestination, lastIndex, queuedCovered⟩
      exact ⟨
        queuedResponse,
        by simpa [networkEq] using member,
        queuedSuccess,
        by simpa [termEq] using responseTerm,
        sourceEq,
        queuedDestination,
        lastIndex,
        by simpa [logEq] using queuedCovered
      ⟩
  · rintro (self | matched | queued)
    · exact Or.inl self
    · right
      left
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          rw [matchDestination, updateIndex_same]
          omega
        · simpa [
            matchDestination, updateIndex,
            Function.update, peerEq
          ] using matched
      · simpa [matchOther leader leaderEq] using matched
    · right
      right
      rcases queued with
        ⟨queuedResponse, member, queuedSuccess, responseTerm, sourceEq,
          queuedDestination, lastIndex, queuedCovered⟩
      exact ⟨
        queuedResponse,
        by simpa [networkEq] using member,
        queuedSuccess,
        by simpa [termEq] using responseTerm,
        sourceEq,
        queuedDestination,
        lastIndex,
        by simpa [logEq] using queuedCovered
      ⟩

omit [DecidableEq TxId] [Bootstrap Node] in
/-- A successful ACK transfers its immutable history into processed evidence. -/
lemma processedAckHistoryAfterSuccessfulResponse
    (state after : View Node TxId)
    (destination : Node)
    (response : AppendEntriesResponse Node)
    (history : ProcessedAckHistory Node TxId)
    (historyFacts : ProcessedAckHistoryFacts state history)
    (responseHistory : List (Entry Node TxId))
    (responseBound : response.lastLogIndex <= responseHistory.length)
    (responseCovered : responseHistory <+: (state.nodes destination).log)
    (successful
      : response.term = (state.nodes destination).currentTerm
        /\ (state.nodes destination).role = .leader)
    (roleEq : forall node, (after.nodes node).role = (state.nodes node).role)
    (termEq
      : forall node, (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq : forall node, (after.nodes node).log = (state.nodes node).log)
    (matchDestination
      : forall peer,
          (after.nodes destination).matchIndex peer
          = updateIndex
              (state.nodes destination).matchIndex
              response.source
              (max
                ((state.nodes destination).matchIndex response.source)
                response.lastLogIndex)
              peer)
    (matchOther
      : forall leader,
          Not (leader = destination)
          -> forall peer,
              (after.nodes leader).matchIndex peer = (state.nodes leader).matchIndex peer)
    : Exists
        fun nextHistory =>
          ProcessedAckHistoryFacts after nextHistory := by
  by_cases raised :
      (state.nodes destination).matchIndex response.source <
        response.lastLogIndex
  · let snapshot : ProcessedAckSnapshot Node TxId :=
      { term := response.term
        index := response.lastLogIndex
        history := responseHistory }
    let nextHistory : ProcessedAckHistory Node TxId :=
      Function.update history destination
        (Function.update
          (history destination) response.source (some snapshot))
    refine ⟨nextHistory, ?_⟩
    constructor
    · intro leader role peer zero
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          rw [matchDestination, updateIndex_same] at zero
          omega
        · have oldZero :
              (state.nodes destination).matchIndex peer = 0 := by
            simpa [matchDestination, updateIndex, Function.update, peerEq] using zero
          simpa [nextHistory, Function.update, peerEq]
            using historyFacts.zero destination successful.2 peer oldZero
      · have oldRole : (state.nodes leader).role = .leader := by simpa [roleEq] using role
        have oldZero :
            (state.nodes leader).matchIndex peer = 0 := by
          simpa [matchOther leader leaderEq] using zero
        simpa [nextHistory, Function.update, leaderEq]
          using historyFacts.zero leader oldRole peer oldZero
    · intro leader role peer positive
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          refine ⟨snapshot, ?_, ?_, ?_, ?_, ?_⟩
          · simp [nextHistory, snapshot]
          · simp only [snapshot]
            rw [termEq]
            exact successful.1
          · simp [
              snapshot, matchDestination, updateIndex_same,
              max_eq_right raised.le
            ]
          · simpa [snapshot] using responseBound
          · have equalTake :=
              takeEqOfPrefix responseCovered responseBound
            simp only [snapshot]
            rw [logEq]
            exact equalTake
        · have oldPositive :
              0 < (state.nodes destination).matchIndex peer := by
            simpa [matchDestination, updateIndex, Function.update, peerEq] using positive
          rcases
              historyFacts.positive
                destination successful.2 peer oldPositive with
            ⟨oldSnapshot, stored, snapshotTerm, snapshotIndex,
              historyBound, agreed⟩
          exact ⟨
            oldSnapshot,
            by simpa [
                nextHistory, Function.update, peerEq
              ] using stored,
            by simpa [termEq] using snapshotTerm,
            by simpa [
                matchDestination, updateIndex,
                Function.update, peerEq
              ] using snapshotIndex,
            historyBound,
            by simpa [logEq] using agreed
          ⟩
      · have oldRole : (state.nodes leader).role = .leader := by simpa [roleEq] using role
        have oldPositive :
            0 < (state.nodes leader).matchIndex peer := by
          simpa [matchOther leader leaderEq] using positive
        rcases
            historyFacts.positive leader oldRole peer oldPositive with
          ⟨oldSnapshot, stored, snapshotTerm, snapshotIndex,
            historyBound, agreed⟩
        exact ⟨
          oldSnapshot,
          by simpa [
              nextHistory, Function.update, leaderEq
            ] using stored,
          by simpa [termEq] using snapshotTerm,
          by simpa [matchOther leader leaderEq] using snapshotIndex,
          historyBound,
          by simpa [logEq] using agreed
        ⟩
  · refine ⟨history, ?_⟩
    have matchEq :
        forall leader peer,
          (after.nodes leader).matchIndex peer =
            (state.nodes leader).matchIndex peer := by
      intro leader peer
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.source
        · subst peer
          rw [matchDestination, updateIndex_same]
          omega
        · simp [
            matchDestination, updateIndex,
            Function.update, peerEq
          ]
      · exact matchOther leader leaderEq peer
    constructor
    · intro leader role peer zero
      exact
        historyFacts.zero leader
          (by simpa [roleEq] using role)
          peer (by simpa [matchEq] using zero)
    · intro leader role peer positive
      rcases
          historyFacts.positive leader
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

/-- Receiving an AppendEntries response preserves all delayed-ACK evidence. -/
lemma receiveAppendEntriesResponsePreservesSystemInductiveInvariant
    (state : View Node TxId)
    (source destination : Node)
    (response : AppendEntriesResponse Node)
    (remaining : List (Message Node TxId))
    (nextNode : NodeState Node TxId)
    (invariant : SystemInductiveInvariant state)
    (_destinationAllocated : state.allocated destination)
    (taken
      : Selected source (state.network destination) (.appendEntriesResponse response)
          remaining)
    (responseDestination : response.destination = destination)
    (handled
      : handleAppendEntriesResponse? (state.nodes destination) response = some nextNode)
    : SystemInductiveInvariant
        {
          state with
            nodes := updateNode state.nodes destination nextNode
            network := updateQueue state.network destination remaining
        } := by
  have responseSource : response.source = source :=
    (selectedSound taken).1
  have takenByResponseSource :
      Selected response.source (state.network destination) (.appendEntriesResponse response) remaining := by
    simpa [responseSource] using taken
  have selectedMember :
      Message.appendEntriesResponse response ∈
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
  by_cases isLeader : (state.nodes destination).role = .leader
  case neg =>
    rw [handleAppendEntriesResponseNonLeaderUnchanged
      (state.nodes destination) response isLeader] at handled
    have unchanged := Option.some.inj handled
    subst nextNode
    rw [show updateNode state.nodes destination (state.nodes destination) =
      state.nodes from (by simp [updateNode])]
    exact safetyInertNetworkChangePreservesSystemInductiveInvariant
      state _ packed rfl (fun _ => Iff.rfl) (fun _ => rfl)
      (fun queuedDestination message member =>
        Or.inl (updateQueueSubset queuedDestination message member))
  unfold handleAppendEntriesResponse? at handled
  by_cases successful :
      response.success = true /\
        response.term = (state.nodes destination).currentTerm /\
        (state.nodes destination).role = .leader
  · simp [successful] at handled
    subst nextNode
    let intermediate : View Node TxId :=
      { state with
        nodes :=
          updateNode state.nodes destination
            { state.nodes destination with
              matchIndex :=
                updateIndex
                  (state.nodes destination).matchIndex
                  response.source
                  (max
                    ((state.nodes destination).matchIndex response.source)
                    response.lastLogIndex) } }
    let after : View Node TxId :=
      { state with
        nodes :=
          updateNode state.nodes destination
            { state.nodes destination with
              matchIndex :=
                updateIndex
                  (state.nodes destination).matchIndex
                  response.source
                  (max
                    ((state.nodes destination).matchIndex response.source)
                    response.lastLogIndex) }
        network := updateQueue state.network destination remaining }
    have roleEq :
        forall node,
          (intermediate.nodes node).role = (state.nodes node).role := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, updateNode, same]
    have termEq :
        forall node,
          (intermediate.nodes node).currentTerm =
            (state.nodes node).currentTerm := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, updateNode, same]
    have logEq :
        forall node,
          (intermediate.nodes node).log = (state.nodes node).log := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, updateNode, same]
    have commitEq :
        forall node,
          (intermediate.nodes node).commitIndex =
            (state.nodes node).commitIndex := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, updateNode, same]
    have newFollowerEq :
        forall node,
          (intermediate.nodes node).isNewFollower =
            (state.nodes node).isNewFollower := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, updateNode, same]
    have votedEq :
        forall node,
          (intermediate.nodes node).votedFor =
            (state.nodes node).votedFor := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, updateNode, same]
    have votesEq :
        forall node,
          (intermediate.nodes node).votesGranted =
            (state.nodes node).votesGranted := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, updateNode, same]
    have activeConfigurationsEq :
        forall node,
          activeConfigurations (intermediate.nodes node) =
            activeConfigurations (state.nodes node) := by
      intro node
      unfold activeConfigurations currentConfiguration
      rw [logEq, commitEq]
    have matchDestination :
        forall peer,
          (intermediate.nodes destination).matchIndex peer =
            updateIndex
              (state.nodes destination).matchIndex
              response.source
              (max
                ((state.nodes destination).matchIndex response.source)
                response.lastLogIndex)
              peer := by
      intro peer
      simp [intermediate, updateNode]
    have matchOther :
        forall leader,
          Not (leader = destination) ->
            forall peer,
              (intermediate.nodes leader).matchIndex peer =
                (state.nodes leader).matchIndex peer := by
      intro leader different peer
      simp [intermediate, updateNode, different]
    have responseSnapshot :=
      facts.networkHistory.appendResponse
        destination response selectedMember successful.1
    have snapshotSameTerm :
        response.term =
          (state.nodes response.destination).currentTerm := by
      simpa [responseDestination] using successful.2.1
    have responseCovered :
        responseHistory response <+:
          (state.nodes destination).log := by
      have covered :=
        successfulResponseSnapshotCoveredOfLeader
          (facts.networkHistory.appendResponse
            destination response selectedMember)
          successful.1 snapshotSameTerm
          (by simpa [responseDestination] using successful.2.2)
      simpa [responseDestination] using covered
    have progressIntermediate : LeaderProgressBounded intermediate := by
      intro leader leaderRole peer
      rw [roleEq] at leaderRole
      have old := facts.leaderProgressBounded leader leaderRole peer
      by_cases leaderEq : leader = destination
      · subst leader
        constructor
        · simpa [intermediate, updateNode] using old.1
        · by_cases peerEq : peer = response.source
          · subst peer
            rw [matchDestination, updateIndex_same]
            rw [logEq]
            exact
              max_le old.2
                (Nat.le_trans responseSnapshot.1 responseCovered.length_le)
          · simpa [
              matchDestination, updateIndex,
              Function.update, peerEq, logEq
            ] using old.2
      · simpa [
          intermediate, updateNode, Function.update, leaderEq
        ] using old
    have effectiveElectionVotersIntermediate :
        forall candidate,
          effectiveElectionVoters intermediate candidate =
            effectiveElectionVoters state candidate :=
      effectiveElectionVotersFrame
        state intermediate (by rfl) (by rfl) termEq votesEq
    have intermediateInvariant :
        SystemInductiveInvariant intermediate := by
      apply roleAndNetworkFramePreservesSystemInductiveInvariant state intermediate packed
        (by rfl)
        (fun _ => Iff.rfl)
        (joinedCarrierFactsFrame state intermediate facts.joinedCarriers
          (by rfl)
          (by
            intro node configuration active
            have same :
                activeConfigurations (intermediate.nodes node) =
                  activeConfigurations (state.nodes node) := by
              unfold activeConfigurations currentConfiguration
              rw [logEq, commitEq]
            rw [same] at active
            exact active)
          (by
            intro node configuration member
            simpa [logEq] using member)
          (by
            intro node peer member
            simpa [votesEq] using member)
          (by
            intro node active
            exact facts.joinedCarriers.runtimeNodes.activeRoles node
              (by simpa [roleEq] using active))
          (by
            intro leader peer positive
            by_cases leaderEq : leader = destination
            · subst leader
              by_cases peerEq : peer = response.source
              · subst peer
                exact
                  facts.joinedCarriers.runtimeNodes.appendResponses
                    destination response selectedMember
              · exact
                  facts.joinedCarriers.runtimeNodes.positiveMatches
                    destination peer
                      (by
                        simpa [
                          matchDestination, updateIndex,
                          Function.update, peerEq
                        ] using positive)
            · exact
                facts.joinedCarriers.runtimeNodes.positiveMatches
                  leader peer
                    (by simpa [matchOther leader leaderEq] using positive))
          (by
            intro node nonempty
            exact facts.joinedCarriers.runtimeNodes.nonemptyLogs node
              (by simpa [logEq] using nonempty))
          (by
            intro destination message member
            exact member))
        (fun node active => by simpa [roleEq] using active)
        (fun node role => by simpa [roleEq] using role)
        (fun node role => by simpa [roleEq] using role)
        (fun node role => by simpa [roleEq] using role)
        (fun node role => by simpa [roleEq] using role)
        termEq logEq commitEq
      · intro node role
        rw [roleEq] at role
        simpa [votedEq, votesEq] using facts.candidatesSelfVote node role
      · intro leader role
        rw [roleEq] at role
        rcases facts.leadersHaveElectionWitness leader role with
          bootstrap | majority
        · exact Or.inl
            ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
        · exact Or.inr (by simpa [logEq, votesEq] using majority)
      · intro _ _ _ _ _ _ actualFacts
        constructor
        · exact actualFacts.voteHistory.bootstrapEmpty
        · intro voter
          simpa [termEq, votedEq] using actualFacts.voteHistory.current voter
        · intro voter term future
          rw [termEq] at future
          exact actualFacts.voteHistory.future voter term future
        · intro candidate voter active member
          rw [roleEq] at active
          rw [votesEq] at member
          rw [termEq]
          exact
            actualFacts.voteHistory.counted
              candidate voter active member
      · intro _ _ actualResponseHistory _ _ _ actualFacts
        rcases actualFacts.processedAckHistory with
          ⟨actualAckHistory, actualAckFacts⟩
        have actualSnapshot :=
          actualFacts.networkHistory.appendResponse
            destination response selectedMember successful.1
        have actualCovered :
            actualResponseHistory response <+:
              (state.nodes destination).log := by
          have covered :=
            successfulResponseSnapshotCoveredOfLeader
              (actualFacts.networkHistory.appendResponse
                destination response selectedMember)
              successful.1 snapshotSameTerm
              (by simpa [responseDestination] using successful.2.2)
          simpa [responseDestination] using covered
        exact
          processedAckHistoryAfterSuccessfulResponse
            state intermediate destination response
              actualAckHistory actualAckFacts
              (actualResponseHistory response)
              actualSnapshot.1 actualCovered
              ⟨successful.2.1,
                by simpa [responseDestination] using successful.2.2⟩
              roleEq termEq logEq matchDestination matchOther
      · intro queuedDestination message member
        exact Or.inl (by simpa [intermediate] using member)
      · exact progressIntermediate
      · intro _ _ actualResponseHistory _ _ _ actualFacts leader index
        have actualSnapshot :=
          actualFacts.networkHistory.appendResponse
            destination response selectedMember successful.1
        have actualCovered :
            actualResponseHistory response <+:
              (state.nodes destination).log := by
          have covered :=
            successfulResponseSnapshotCoveredOfLeader
              (actualFacts.networkHistory.appendResponse
                destination response selectedMember)
              successful.1 snapshotSameTerm
              (by simpa [responseDestination] using successful.2.2)
          simpa [responseDestination] using covered
        exact Finset.subset_of_eq (
          effectiveAckersAfterSuccessfulResponseHandler
            state intermediate destination response responseDestination
              successful.1 successful.2.1 selectedMember
              actualResponseHistory actualCovered rfl rfl
              termEq logEq matchDestination matchOther leader index)
      · intro actualVotes actualAppendHistory actualResponseHistory
          actualVoteRequestHistory actualVoteCandidateHistory
          actualVoteVoterHistory actualFacts leader index peer member
        simp only [
          potentialAckers, Finset.mem_filter] at member ⊢
        rcases member with ⟨joined, effective | reserve⟩
        · refine ⟨by simpa [intermediate] using joined, Or.inl ?_⟩
          rw [
            effectiveAckersAfterSuccessfulResponseHandler
              state intermediate destination response responseDestination
                successful.1 successful.2.1 selectedMember
                actualResponseHistory
                (by
                  have actualSnapshot :=
                    actualFacts.networkHistory.appendResponse
                      destination response selectedMember successful.1
                  have covered :=
                    successfulResponseSnapshotCoveredOfLeader
                      (actualFacts.networkHistory.appendResponse
                        destination response selectedMember)
                      successful.1 snapshotSameTerm
                      (by
                        simpa [responseDestination] using successful.2.2)
                  simpa [responseDestination] using covered)
                rfl rfl termEq logEq matchDestination matchOther
          ] at effective
          exact effective
        · refine ⟨by simpa [intermediate] using joined, Or.inr ?_⟩
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
              rcases destinationProducible with direct | future
              · have follower := canProduceAppendAckAt_role direct
                have leader :
                    (intermediate.nodes destination).role = .leader := by
                  rw [roleEq]
                  exact successful.2.2
                exact False.elim
                  (Role.noConfusion (follower.symm.trans leader))
              · have result :
                    canProduceAppendAckEventuallyAt
                      (state.nodes destination) request index :=
                  Or.inr
                    ⟨by simpa [termEq] using future.1, future.2⟩
                rw [peerEq]
                exact result
            · have nodesEq :
                  intermediate.nodes peer = state.nodes peer := by
                simp [
                  intermediate, updateNode, peerEq
                ]
              rw [nodesEq] at producible
              exact producible
          refine ⟨request, ?_, sourceEq, destinationEq, ?_, oldProducible, ?_⟩
          · simpa [intermediate] using queued
          · simpa [termEq] using requestTerm
          · simpa [logEq] using covered
      · intro candidate role majority
        unfold hasEffectiveElectionMajority at majority ⊢
        simpa [
          activeConfigurationsEq,
          effectiveElectionVotersIntermediate
        ] using majority
      · intro candidate role majority
        unfold hasPotentialElectionMajority at majority ⊢
        simpa [
          potentialElectionVoters,
          currentlyEligibleElectionVoter,
          makeRequestVoteRequest,
          activeConfigurationsEq,
          effectiveElectionVotersIntermediate,
          termEq, logEq, commitEq, votedEq,
          lastCommittableIndexFrame
            (logEq candidate) (commitEq candidate),
          lastCommittableTermFrame
            (logEq candidate) (commitEq candidate),
          voteLogUpToDate
        ] using majority
      · intro candidate voter _ member
        simpa [effectiveElectionVotersIntermediate] using member
    have nodeStateEq :
        forall node, after.nodes node = intermediate.nodes node := by
      intro node
      rfl
    have intermediateSelectedMember :
        Message.appendEntriesResponse response ∈
          intermediate.network destination := by
      simpa [intermediate] using selectedMember
    have takenFromIntermediate :
        Selected response.source (intermediate.network destination) (.appendEntriesResponse response) remaining := by
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
    have matchCoversResponse :
        response.lastLogIndex <=
          (intermediate.nodes destination).matchIndex response.source := by
      rw [matchDestination, updateIndex_same]
      omega
    have matchDestinationAfter :
        forall peer,
          (after.nodes destination).matchIndex peer =
            updateIndex
              (intermediate.nodes destination).matchIndex
              response.source
              (max
                ((intermediate.nodes destination).matchIndex response.source)
                response.lastLogIndex)
              peer := by
      intro peer
      rw [nodeStateEq]
      by_cases peerEq : peer = response.source
      · subst peer
        rw [updateIndex_same, max_eq_left matchCoversResponse]
      · simp [updateIndex, Function.update, peerEq]
    have effectiveElectionVotersAfter :
        forall candidate,
          effectiveElectionVoters after candidate =
            effectiveElectionVoters intermediate candidate :=
      effectiveElectionVotersAfterAppendResponse
        intermediate after destination response remaining
          takenFromIntermediate
          (by simp [after, intermediate])
          (by simp [after, intermediate])
          (fun node => by rw [nodeStateEq node])
          (fun node => by rw [nodeStateEq node])
    rw [← successful.2.2]
    change SystemInductiveInvariant after
    apply networkFramePreservesSystemInductiveInvariant
      intermediate after intermediateInvariant
      (by simp [after, intermediate]) (fun _ => Iff.rfl) nodeStateEq
      (fun destination message member =>
        Or.inl (networkSubsetAfter destination message member))
    · intro _ _ actualResponseHistory _ _ _ actualFacts leader index
      have actualSnapshot :=
        actualFacts.networkHistory.appendResponse
          destination response intermediateSelectedMember successful.1
      have sameTermIntermediate :
          response.term =
            (intermediate.nodes response.destination).currentTerm := by
        simpa [responseDestination, termEq] using successful.2.1
      have actualCovered :
          actualResponseHistory response <+:
            (intermediate.nodes destination).log := by
        have covered :=
          successfulResponseSnapshotCoveredOfLeader
            (actualFacts.networkHistory.appendResponse
              destination response intermediateSelectedMember)
            successful.1 sameTermIntermediate
            (by simpa [responseDestination, roleEq] using successful.2.2)
        simpa [responseDestination] using covered
      exact Finset.subset_of_eq
        (effectiveAckersAfterSuccessfulResponse
          intermediate after destination response remaining
          takenFromIntermediate responseDestination successful.1
          (by simpa [termEq] using successful.2.1)
          actualResponseHistory actualCovered
          (by simp [after, intermediate])
          (by simp [after, intermediate])
          (fun node => by rw [nodeStateEq node])
          (fun node => by rw [nodeStateEq node])
          matchDestinationAfter
          (fun leader _ peer => by rw [nodeStateEq leader])
          leader index)
    · intro candidate role majority
      unfold hasEffectiveElectionMajority at majority ⊢
      simpa [nodeStateEq, effectiveElectionVotersAfter] using majority
    · intro candidate voter _ member
      simpa [effectiveElectionVotersAfter] using member
  · by_cases failed : response.success = false
    · simp only [
        show ((state.nodes destination).role != .leader) = false by simp [isLeader],
        Bool.false_eq_true, ↓reduceIte, failed, false_and, Option.some.injEq
      ] at handled
      subst nextNode
      let intermediate : View Node TxId :=
        { state with
          nodes :=
            updateNode state.nodes destination
              { state.nodes destination with
                sentIndex :=
                  updateIndex
                    (state.nodes destination).sentIndex
                    response.source
                    (max
                      (min
                        (findHighestPossibleMatch
                          (state.nodes destination).log
                          response.lastLogIndex response.term)
                        ((state.nodes destination).sentIndex response.source))
                      ((state.nodes destination).matchIndex response.source)) } }
      let after : View Node TxId :=
        { state with
          nodes :=
            updateNode state.nodes destination
              { state.nodes destination with
                sentIndex :=
                  updateIndex
                    (state.nodes destination).sentIndex
                    response.source
                    (max
                      (min
                        (findHighestPossibleMatch
                          (state.nodes destination).log
                          response.lastLogIndex response.term)
                        ((state.nodes destination).sentIndex response.source))
                      ((state.nodes destination).matchIndex response.source)) }
          network := updateQueue state.network destination remaining }
      have roleEq :
          forall node,
            (intermediate.nodes node).role = (state.nodes node).role := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, updateNode, same]
      have termEq :
          forall node,
            (intermediate.nodes node).currentTerm =
              (state.nodes node).currentTerm := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, updateNode, same]
      have logEq :
          forall node,
            (intermediate.nodes node).log = (state.nodes node).log := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, updateNode, same]
      have commitEq :
          forall node,
            (intermediate.nodes node).commitIndex =
              (state.nodes node).commitIndex := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, updateNode, same]
      have newFollowerEq :
          forall node,
            (intermediate.nodes node).isNewFollower =
              (state.nodes node).isNewFollower := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, updateNode, same]
      have votedEq :
          forall node,
            (intermediate.nodes node).votedFor =
              (state.nodes node).votedFor := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, updateNode, same]
      have votesEq :
          forall node,
            (intermediate.nodes node).votesGranted =
              (state.nodes node).votesGranted := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, updateNode, same]
      have matchEq :
          forall leader peer,
            (intermediate.nodes leader).matchIndex peer =
              (state.nodes leader).matchIndex peer := by
        intro leader peer
        by_cases same : leader = destination <;>
          simp [intermediate, updateNode, same]
      have activeConfigurationsEq :
          forall node,
            activeConfigurations (intermediate.nodes node) =
              activeConfigurations (state.nodes node) := by
        intro node
        unfold activeConfigurations currentConfiguration
        rw [logEq, commitEq]
      have progressIntermediate : LeaderProgressBounded intermediate := by
        intro leader leaderRole peer
        rw [roleEq] at leaderRole
        have old := facts.leaderProgressBounded leader leaderRole peer
        by_cases leaderEq : leader = destination
        · subst leader
          constructor
          · by_cases peerEq : peer = response.source
            · subst peer
              simp [intermediate, updateNode, updateIndex_same]
              exact ⟨Or.inr old.1, old.2⟩
            · simpa [
                intermediate, updateNode, updateIndex,
                Function.update, peerEq
              ] using old.1
          · simpa [matchEq, logEq] using old.2
        · simpa [
            intermediate, updateNode, Function.update, leaderEq
          ] using old
      have effectiveAckersIntermediate :
          forall actualResponseHistory leader index,
            effectiveAckers intermediate actualResponseHistory leader index =
              effectiveAckers state actualResponseHistory leader index :=
        effectiveAckersFrame
          state intermediate rfl rfl termEq logEq matchEq
      have effectiveElectionVotersIntermediate :
          forall candidate,
            effectiveElectionVoters intermediate candidate =
              effectiveElectionVoters state candidate :=
        effectiveElectionVotersFrame
          state intermediate rfl rfl termEq votesEq
      have intermediateInvariant :
          SystemInductiveInvariant intermediate := by
        apply roleAndNetworkFramePreservesSystemInductiveInvariant
          state intermediate packed rfl
          (fun _ => Iff.rfl)
          (joinedCarrierFactsFrame state intermediate facts.joinedCarriers rfl
            (by
              intro node configuration active
              have same :
                  activeConfigurations (intermediate.nodes node) =
                    activeConfigurations (state.nodes node) := by
                unfold activeConfigurations currentConfiguration
                rw [logEq, commitEq]
              rw [same] at active
              exact active)
            (by
              intro node configuration member
              simpa [logEq] using member)
            (by
              intro node peer member
              simpa [votesEq] using member)
            (by
              intro node active
              exact facts.joinedCarriers.runtimeNodes.activeRoles node
                (by simpa [roleEq] using active))
            (by
              intro leader peer positive
              exact facts.joinedCarriers.runtimeNodes.positiveMatches
                leader peer (by simpa [matchEq] using positive))
            (by
              intro node nonempty
              exact facts.joinedCarriers.runtimeNodes.nonemptyLogs node
                (by simpa [logEq] using nonempty))
            (by
              intro destination message member
              exact member))
          (fun node active => by simpa [roleEq] using active)
          (fun node role => by simpa [roleEq] using role)
          (fun node role => by simpa [roleEq] using role)
          (fun node role => by simpa [roleEq] using role)
          (fun node role => by simpa [roleEq] using role)
          termEq logEq commitEq
        · intro node role
          rw [roleEq] at role
          simpa [votedEq, votesEq] using facts.candidatesSelfVote node role
        · intro leader role
          rw [roleEq] at role
          rcases facts.leadersHaveElectionWitness leader role with
            bootstrap | majority
          · exact Or.inl
              ⟨bootstrap.1, by simpa [termEq] using bootstrap.2⟩
          · exact Or.inr (by simpa [logEq, votesEq] using majority)
        · intro _ _ _ _ _ _ actualFacts
          constructor
          · exact actualFacts.voteHistory.bootstrapEmpty
          · intro voter
            simpa [termEq, votedEq] using actualFacts.voteHistory.current voter
          · intro voter term future
            rw [termEq] at future
            exact actualFacts.voteHistory.future voter term future
          · intro candidate voter active member
            rw [roleEq] at active
            rw [votesEq] at member
            rw [termEq]
            exact
              actualFacts.voteHistory.counted
                candidate voter active member
        · intro _ _ _ _ _ _ actualFacts
          rcases actualFacts.processedAckHistory with
            ⟨actualAckHistory, actualAckFacts⟩
          exact ⟨
            actualAckHistory,
            processedAckHistoryFrame
              state intermediate actualAckHistory actualAckFacts
              roleEq termEq logEq matchEq
          ⟩
        · intro queuedDestination message member
          exact Or.inl (by simpa [intermediate] using member)
        · exact progressIntermediate
        · intro _ _ actualResponseHistory _ _ _ _ leader index
          exact Finset.subset_of_eq
            (effectiveAckersIntermediate actualResponseHistory leader index)
        · intro _ actualAppendHistory actualResponseHistory
            _ _ _ _ leader index peer member
          simp only [
            potentialAckers, Finset.mem_filter] at member ⊢
          rcases member with ⟨joined, effective | reserve⟩
          · exact ⟨
              by simpa [intermediate] using joined,
              Or.inl
                (by
                  rw [
                    effectiveAckersIntermediate
                      actualResponseHistory leader index
                  ] at effective
                  exact effective)
            ⟩
          · refine ⟨by simpa [intermediate] using joined, Or.inr ?_⟩
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
                  simpa [peerEq] using producible
                have framed :=
                  (canProduceAppendAckEventuallyAt_sentIndex
                    (state.nodes destination)
                    (updateIndex
                      (state.nodes destination).sentIndex
                      response.source
                      (max
                        (min
                          (findHighestPossibleMatch
                            (state.nodes destination).log
                            response.lastLogIndex response.term)
                          ((state.nodes destination).sentIndex response.source))
                        ((state.nodes destination).matchIndex response.source)))
                    request index).mp
                    (by simpa [intermediate, updateNode] using destinationProducible)
                simpa [peerEq] using framed
              · simpa [
                  intermediate, updateNode, Function.update, peerEq
                ] using producible
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
            activeConfigurationsEq,
            effectiveElectionVotersIntermediate
          ] using majority
        · intro candidate role majority
          unfold hasPotentialElectionMajority at majority ⊢
          simpa [
            potentialElectionVoters,
            currentlyEligibleElectionVoter,
            makeRequestVoteRequest,
            activeConfigurationsEq,
            effectiveElectionVotersIntermediate,
            termEq, logEq, commitEq, votedEq,
            lastCommittableIndexFrame
              (logEq candidate) (commitEq candidate),
            lastCommittableTermFrame
              (logEq candidate) (commitEq candidate),
            voteLogUpToDate
          ] using majority
        · intro candidate voter _ member
          simpa [effectiveElectionVotersIntermediate] using member
      have nodeStateEq :
          forall node, after.nodes node = intermediate.nodes node := by
        intro node
        rfl
      have takenFromIntermediate :
          Selected response.source (intermediate.network destination) (.appendEntriesResponse response) remaining := by
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
      have effectiveElectionVotersAfter :
          forall candidate,
            effectiveElectionVoters after candidate =
              effectiveElectionVoters intermediate candidate :=
        effectiveElectionVotersAfterAppendResponse
          intermediate after destination response remaining
            takenFromIntermediate
            (by simp [after, intermediate])
            (by simp [after, intermediate])
            (fun node => by rw [nodeStateEq node])
            (fun node => by rw [nodeStateEq node])
      change SystemInductiveInvariant after
      apply networkFramePreservesSystemInductiveInvariant
        intermediate after intermediateInvariant
        (by simp [after, intermediate]) (fun _ => Iff.rfl) nodeStateEq
        (fun destination message member =>
          Or.inl (networkSubsetAfter destination message member))
      · intro _ _ actualResponseHistory _ _ _ _ leader index
        apply Finset.subset_of_eq
        apply effectiveAckersAfterInactiveResponse
            intermediate after destination response remaining
              takenFromIntermediate
        · simp [after, intermediate]
        · simp [after, intermediate]
        · intro node
          rw [nodeStateEq node]
        · intro node
          rw [nodeStateEq node]
        · intro actualLeader peer
          rw [nodeStateEq actualLeader]
        · intro active
          simp [failed] at active
      · intro candidate role majority
        unfold hasEffectiveElectionMajority at majority ⊢
        simpa [nodeStateEq, effectiveElectionVotersAfter] using majority
      · intro candidate voter _ member
        simpa [effectiveElectionVotersAfter] using member
    · by_cases notLeader :
        ((state.nodes destination).role != .leader) = true
      · simp [isLeader] at notLeader
      · by_cases stale :
          response.term < (state.nodes destination).currentTerm
        · have responseSuccess : response.success = true := by
            cases responseSuccess : response.success
            · exact False.elim (failed responseSuccess)
            · rfl
          have roleLeader :
              (state.nodes destination).role = .leader := by
            simpa using notLeader
          have differentTerm :
              Not (
                response.term =
                  (state.nodes destination).currentTerm) := by
            omega
          simp [responseSuccess, roleLeader, differentTerm] at handled
          have nextNodeEq := handled.2
          clear handled
          subst nextNode
          have updatedNodesEq :
              updateNode state.nodes destination (state.nodes destination) =
                state.nodes := by exact (by simp [updateNode])
          rw [updatedNodesEq]
          let after : View Node TxId :=
            { state with
              network := updateQueue state.network destination remaining }
          have fieldEq :
              forall node, after.nodes node = state.nodes node := by
            intro node
            rfl
          change SystemInductiveInvariant after
          apply networkFramePreservesSystemInductiveInvariant
            state after packed rfl (fun _ => Iff.rfl) fieldEq
            (fun queuedDestination message member =>
              Or.inl
                (updateQueueSubset queuedDestination message
                  (by simpa [after] using member)))
          · intro _ _ actualResponseHistory _ _ _ _ leader index
            apply Finset.subset_of_eq
            apply effectiveAckersAfterInactiveResponse
                state after destination response remaining
                  takenByResponseSource
            · rfl
            · rfl
            · intro node
              rfl
            · intro node
              rfl
            · intro leader peer
              rfl
            · rintro ⟨_, sameTerm⟩
              omega
          · intro candidate role majority
            unfold hasEffectiveElectionMajority at majority ⊢
            rw [
              effectiveElectionVotersAfterAppendResponse
                state after destination response remaining
                  takenByResponseSource rfl rfl
                  (fun node => rfl) (fun node => rfl)
            ] at majority
            exact majority
          · intro candidate voter active member
            rw [
              effectiveElectionVotersAfterAppendResponse
                state after destination response remaining
                  takenByResponseSource rfl rfl
                  (fun node => rfl) (fun node => rfl)
            ] at member
            exact member
        · have responseSuccess : response.success = true := by
            cases responseSuccess : response.success
            · exact False.elim (failed responseSuccess)
            · rfl
          have roleLeader :
              (state.nodes destination).role = .leader := by
            simpa using notLeader
          have differentTerm :
              Not (
                response.term =
                  (state.nodes destination).currentTerm) := by
            intro sameTerm
            exact successful ⟨responseSuccess, sameTerm, roleLeader⟩
          simp [
            responseSuccess, roleLeader, differentTerm, stale
          ] at handled

end CCFRaft.Proofs.Invariant
