-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.NetworkFrames
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

lemma canProduceAppendAckEventuallyAt_sentIndex
    (node : NodeState Node TxId) (sentIndex : Node -> Nat)
    (request : AppendRequestKey Node TxId) (index : Nat)
    : canProduceAppendAckEventuallyAt { node with sentIndex } request index
      ↔ canProduceAppendAckEventuallyAt node request index := by
  unfold canProduceAppendAckEventuallyAt
  apply or_congr
  · exact canProduceAppendAckAt_frame (before := node) (after := { node with sentIndex })
      rfl rfl rfl rfl rfl request index
  · rfl

/-- Dequeuing an ACK which is not effective leaves effective evidence intact. -/
lemma effectiveAckersAfterInactiveResponse
    (state after : Model.State Node TxId)
    (destination : Node)
    (response : AppendResponseKey Node)
    (responseDestination : response.2.1 = destination)
    (remaining : List (Model.Envelope Node TxId))
    (taken
      : Selected response.1 state.network
          (appendResponseEnvelope response) remaining)
    (networkEq : after.network = remaining)
    (hasJoinedEq : joinedNext = joinedNodes)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf state) node).log)
    (matchEq
      : forall leader peer,
          ((nodeOf after) leader).matchIndex peer = ((nodeOf state) leader).matchIndex peer)
    (inactive
      : Not
          (response.2.2.success = true
            /\ response.2.2.term = ((nodeOf state) destination).currentTerm))
    : forall (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
              leader index,
        effectiveAckers (joined := joinedNext) after responseHistory leader index
        = effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
  classical
  intro responseHistory leader index
  ext peer
  simp only [effectiveAckers, Finset.mem_filter]
  apply and_congr (by simp only [hasJoinedEq])
  constructor
  · rintro (self | matched | ⟨queued, member, success, term, source, target, covered, retainedLog⟩)
    · exact Or.inl self
    · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
    · exact Or.inr (Or.inr ⟨queued,
        ⟨(selectedSound taken).2.2 _ (by simpa [networkEq] using member.1), member.2⟩,
        success, by simpa [termEq] using term, source, target, covered,
        by simpa [logEq] using retainedLog⟩)
  · rintro (self | matched | ⟨queued, member, success, term, source, target, covered, retainedLog⟩)
    · exact Or.inl self
    · exact Or.inr (Or.inl (by simpa [matchEq] using matched))
    · have retained : appendResponseEnvelope queued ∈ remaining := by
        rcases memSelectedOrRemaining taken member.1 with same | retained
        · have equal := appendResponseEnvelope.injEq.mp same
          subst queued
          have here : leader = destination := target.symm.trans responseDestination
          exact False.elim (inactive ⟨success, by simpa [here] using term⟩)
        · exact retained
      exact Or.inr (Or.inr ⟨queued, ⟨by simpa [networkEq] using retained, member.2⟩,
        success, by simpa [termEq] using term, source, target, covered,
        by simpa [logEq] using retainedLog⟩)

/--
Processing a successful same-term ACK transfers its evidence from the queue to
the destination leader's monotone `matchIndex`.
-/
lemma effectiveAckersAfterSuccessfulResponse
    (state after : Model.State Node TxId)
    (destination : Node)
    (response : AppendResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (taken
      : Selected response.1 state.network
          (appendResponseEnvelope response) remaining)
    (responseDestination : response.2.1 = destination)
    (success : response.2.2.success = true)
    (sameTerm : response.2.2.term = ((nodeOf state) destination).currentTerm)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (covered : responseHistory response <+: ((nodeOf state) destination).log)
    (networkEq : after.network = remaining)
    (hasJoinedEq : joinedNext = joinedNodes)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf state) node).log)
    (matchDestination
      : forall peer,
          ((nodeOf after) destination).matchIndex peer
          = updateIndex
              ((nodeOf state) destination).matchIndex
              response.1
              (max
                (((nodeOf state) destination).matchIndex response.1)
                response.2.2.lastLogIndex)
              peer)
    (matchOther
      : forall leader,
          Not (leader = destination)
          -> forall peer,
              ((nodeOf after) leader).matchIndex peer = ((nodeOf state) leader).matchIndex peer)
    : forall leader index,
        effectiveAckers (joined := joinedNext) after responseHistory leader index
        = effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
  classical
  intro leader index
  ext peer
  simp only [effectiveAckers, Finset.mem_filter]
  apply and_congr (by simp only [hasJoinedEq])
  constructor
  · rintro (self | matched | ⟨queued, member, ok, term, source, target, coveredIndex, retainedLog⟩)
    · exact Or.inl self
    · by_cases here : leader = destination
      · subst leader
        by_cases sameSource : peer = response.1
        · subst peer
          rw [matchDestination, updateIndex_same] at matched
          rcases le_max_iff.mp matched with old | fresh
          · exact Or.inr (Or.inl old)
          · exact Or.inr (Or.inr ⟨response, ⟨taken.2.1, responseDestination⟩,
              success, sameTerm, rfl, responseDestination, fresh, covered⟩)
        · exact Or.inr (Or.inl (by simpa [matchDestination, updateIndex, sameSource] using matched))
      · exact Or.inr (Or.inl (by simpa [matchOther leader here] using matched))
    · exact Or.inr (Or.inr ⟨queued,
        ⟨(selectedSound taken).2.2 _ (by simpa [networkEq] using member.1), member.2⟩,
        ok, by simpa [termEq] using term, source, target, coveredIndex,
        by simpa [logEq] using retainedLog⟩)
  · rintro (self | matched | ⟨queued, member, ok, term, source, target, coveredIndex, retainedLog⟩)
    · exact Or.inl self
    · right
      left
      by_cases here : leader = destination
      · subst leader
        by_cases sameSource : peer = response.1
        · subst peer
          rw [matchDestination, updateIndex_same]
          exact matched.trans (le_max_left _ _)
        · simpa [matchDestination, updateIndex, sameSource] using matched
      · simpa [matchOther leader here] using matched
    · rcases memSelectedOrRemaining taken member.1 with same | retained
      · have equal := appendResponseEnvelope.injEq.mp same
        subst queued
        have here : leader = destination := target.symm.trans responseDestination
        subst leader
        subst peer
        right
        left
        rw [responseDestination, matchDestination, updateIndex_same]
        exact coveredIndex.trans (le_max_right _ _)
      · exact Or.inr (Or.inr ⟨queued, ⟨by simpa [networkEq] using retained, member.2⟩,
          ok, by simpa [termEq] using term, source, target, coveredIndex,
          by simpa [logEq] using retainedLog⟩)

/--
Before dequeue, a successful same-term ACK's monotone `matchIndex` update only
changes the representation of evidence already present in the queue.
-/
lemma effectiveAckersAfterSuccessfulResponseHandler
    (state after : Model.State Node TxId)
    (destination : Node)
    (response : AppendResponseKey Node)
    (responseDestination : response.2.1 = destination)
    (success : response.2.2.success = true)
    (sameTerm : response.2.2.term = ((nodeOf state) destination).currentTerm)
    (selectedMember : (appendResponseEnvelope response ∈ state.network /\ response.2.1 = destination))
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (covered : responseHistory response <+: ((nodeOf state) destination).log)
    (networkEq : after.network = state.network)
    (hasJoinedEq : joinedNext = joinedNodes)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf state) node).log)
    (matchDestination
      : forall peer,
          ((nodeOf after) destination).matchIndex peer
          = updateIndex
              ((nodeOf state) destination).matchIndex
              response.1
              (max
                (((nodeOf state) destination).matchIndex response.1)
                response.2.2.lastLogIndex)
              peer)
    (matchOther
      : forall leader,
          Not (leader = destination)
          -> forall peer,
              ((nodeOf after) leader).matchIndex peer = ((nodeOf state) leader).matchIndex peer)
    : forall leader index,
        effectiveAckers (joined := joinedNext) after responseHistory leader index
        = effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
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
        by_cases peerEq : peer = response.1
        · subst peer
          rw [matchDestination, updateIndex_same] at matched
          by_cases oldCovers :
              index <=
                ((nodeOf state) destination).matchIndex response.1
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
        by_cases peerEq : peer = response.1
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

/-- A successful ACK transfers its immutable history into processed evidence. -/
lemma processedAckHistoryAfterSuccessfulResponse
    (state after : Model.State Node TxId)
    (destination : Node)
    (response : AppendResponseKey Node)
    (history : ProcessedAckHistory Node TxId)
    (historyFacts : ProcessedAckHistoryFacts state history)
    (responseHistory : List (Entry Node TxId))
    (responseBound : response.2.2.lastLogIndex <= responseHistory.length)
    (responseCovered : responseHistory <+: ((nodeOf state) destination).log)
    (successful
      : response.2.2.term = ((nodeOf state) destination).currentTerm
        /\ ((nodeOf state) destination).role = .leader)
    (roleEq : forall node, ((nodeOf after) node).role = ((nodeOf state) node).role)
    (termEq
      : forall node, ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf state) node).log)
    (matchDestination
      : forall peer,
          ((nodeOf after) destination).matchIndex peer
          = updateIndex
              ((nodeOf state) destination).matchIndex
              response.1
              (max
                (((nodeOf state) destination).matchIndex response.1)
                response.2.2.lastLogIndex)
              peer)
    (matchOther
      : forall leader,
          Not (leader = destination)
          -> forall peer,
              ((nodeOf after) leader).matchIndex peer = ((nodeOf state) leader).matchIndex peer)
    : Exists
        fun nextHistory =>
          ProcessedAckHistoryFacts after nextHistory := by
  by_cases raised :
      ((nodeOf state) destination).matchIndex response.1 <
        response.2.2.lastLogIndex
  · let snapshot : ProcessedAckSnapshot Node TxId :=
      { term := response.2.2.term
        index := response.2.2.lastLogIndex
        history := responseHistory }
    let nextHistory : ProcessedAckHistory Node TxId :=
      Function.update history destination
        (Function.update
          (history destination) response.1 (some snapshot))
    refine ⟨nextHistory, ?_⟩
    constructor
    · intro leader role peer zero
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.1
        · subst peer
          rw [matchDestination, updateIndex_same] at zero
          omega
        · have oldZero :
              ((nodeOf state) destination).matchIndex peer = 0 := by
            simpa [matchDestination, updateIndex, Function.update, peerEq] using zero
          simpa [nextHistory, Function.update, peerEq]
            using historyFacts.zero destination successful.2 peer oldZero
      · have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
        have oldZero :
            ((nodeOf state) leader).matchIndex peer = 0 := by
          simpa [matchOther leader leaderEq] using zero
        simpa [nextHistory, Function.update, leaderEq]
          using historyFacts.zero leader oldRole peer oldZero
    · intro leader role peer positive
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.1
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
              0 < ((nodeOf state) destination).matchIndex peer := by
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
      · have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
        have oldPositive :
            0 < ((nodeOf state) leader).matchIndex peer := by
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
          ((nodeOf after) leader).matchIndex peer =
            ((nodeOf state) leader).matchIndex peer := by
      intro leader peer
      by_cases leaderEq : leader = destination
      · subst leader
        by_cases peerEq : peer = response.1
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
    (state : Model.State Node TxId)
    (source destination : Node)
    {present : destination ∈ state.nodes.map Prod.fst}
    (distinct : (state.nodes.map Prod.fst).Nodup)
    (response : AppendResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (nextNode : NodeState Node TxId)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (_destinationAllocated : destination ∈ joinedNodes)
    (taken
      : Selected source state.network (appendResponseEnvelope response)
          remaining)
    (responseDestination : response.2.1 = destination)
    (handled
      : handleAppendEntriesResponse ((nodeOf state) destination) response.1 response.2.2 = nextNode)
    : SystemInductiveInvariant (joined := joinedNodes)
        {
          state with
            nodes := replaceNode state.nodes destination nextNode
            network := remaining
        } := by
  have responseSource : response.1 = source :=
    (selectedSound taken).1
  have takenByResponseSource :
      Selected response.1 state.network (appendResponseEnvelope response) remaining := by
    simpa [responseSource] using taken
  have selectedMember :
      (appendResponseEnvelope response ∈ state.network /\ response.2.1 = destination) :=
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
  by_cases isLeader : ((nodeOf state) destination).role = .leader
  case neg =>
    rw [handleAppendEntriesResponseNonLeaderUnchanged
      ((nodeOf state) destination) response.1 response.2.2 isLeader] at handled
    subst nextNode
    rw [replaceNode_nodeOf state destination distinct]
    exact safetyInertNetworkChangePreservesSystemInductiveInvariant
      state _ packed rfl (fun _ => Iff.rfl) (fun _ => rfl)
      (fun queuedDestination message member =>
        Or.inl (updateQueueSubset queuedDestination message member))
  unfold handleAppendEntriesResponse at handled
  by_cases successful :
      response.2.2.success = true /\
        response.2.2.term = ((nodeOf state) destination).currentTerm /\
        ((nodeOf state) destination).role = .leader
  · simp [successful] at handled
    subst nextNode
    let intermediate : Model.State Node TxId :=
      { state with
        nodes :=
          replaceNode state.nodes destination
            { (nodeOf state) destination with
              matchIndex :=
                updateIndex
                  ((nodeOf state) destination).matchIndex
                  response.1
                  (max
                    (((nodeOf state) destination).matchIndex response.1)
                    response.2.2.lastLogIndex) } }
    let after : Model.State Node TxId :=
      { state with
        nodes :=
          replaceNode state.nodes destination
            { (nodeOf state) destination with
              matchIndex :=
                updateIndex
                  ((nodeOf state) destination).matchIndex
                  response.1
                  (max
                    (((nodeOf state) destination).matchIndex response.1)
                    response.2.2.lastLogIndex) }
        network := remaining }
    have roleEq :
        forall node,
          ((nodeOf intermediate) node).role = ((nodeOf state) node).role := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, present, nodeOf_replaceNode, present, same]
    have termEq :
        forall node,
          ((nodeOf intermediate) node).currentTerm =
            ((nodeOf state) node).currentTerm := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, present, nodeOf_replaceNode, present, same]
    have logEq :
        forall node,
          ((nodeOf intermediate) node).log = ((nodeOf state) node).log := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, present, nodeOf_replaceNode, present, same]
    have commitEq :
        forall node,
          ((nodeOf intermediate) node).commitIndex =
            ((nodeOf state) node).commitIndex := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, present, nodeOf_replaceNode, present, same]
    have newFollowerEq :
        forall node,
          ((nodeOf intermediate) node).isNewFollower =
            ((nodeOf state) node).isNewFollower := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, present, nodeOf_replaceNode, present, same]
    have votedEq :
        forall node,
          ((nodeOf intermediate) node).votedFor =
            ((nodeOf state) node).votedFor := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, present, nodeOf_replaceNode, present, same]
    have votesEq :
        forall node,
          ((nodeOf intermediate) node).votesGranted =
            ((nodeOf state) node).votesGranted := by
      intro node
      by_cases same : node = destination <;>
        simp [intermediate, present, nodeOf_replaceNode, present, same]
    have activeConfigurationsEq :
        forall node,
          activeConfigurations ((nodeOf intermediate) node) =
            activeConfigurations ((nodeOf state) node) := by
      intro node
      unfold activeConfigurations currentConfiguration
      rw [logEq, commitEq]
    have matchDestination :
        forall peer,
          ((nodeOf intermediate) destination).matchIndex peer =
            updateIndex
              ((nodeOf state) destination).matchIndex
              response.1
              (max
                (((nodeOf state) destination).matchIndex response.1)
                response.2.2.lastLogIndex)
              peer := by
      intro peer
      simp [intermediate, present, nodeOf_replaceNode, present]
    have matchOther :
        forall leader,
          Not (leader = destination) ->
            forall peer,
              ((nodeOf intermediate) leader).matchIndex peer =
                ((nodeOf state) leader).matchIndex peer := by
      intro leader different peer
      simp [intermediate, present, nodeOf_replaceNode, present, different]
    have responseSnapshot :=
      facts.networkHistory.appendResponse
        destination response selectedMember successful.1
    have snapshotSameTerm :
        response.2.2.term =
          ((nodeOf state) response.2.1).currentTerm := by
      simpa [responseDestination] using successful.2.1
    have responseCovered :
        responseHistory response <+:
          ((nodeOf state) destination).log := by
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
        · simpa [intermediate, present, nodeOf_replaceNode, present] using old.1
        · by_cases peerEq : peer = response.1
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
          intermediate, present, nodeOf_replaceNode, present, Function.update, leaderEq
        ] using old
    have effectiveElectionVotersIntermediate :
        forall candidate,
          effectiveElectionVoters (joined := joinedNodes) intermediate candidate =
            effectiveElectionVoters (joined := joinedNodes) state candidate :=
      effectiveElectionVotersFrame
        state intermediate (by rfl) (by rfl) termEq votesEq
    have intermediateInvariant :
        SystemInductiveInvariant (joined := joinedNodes) intermediate := by
      apply roleAndNetworkFramePreservesSystemInductiveInvariant state intermediate packed
        (by rfl)
        (fun _ => Iff.rfl)
        (joinedCarrierFactsFrame state intermediate facts.joinedCarriers
          (by rfl)
          (by
            intro node configuration active
            have same :
                activeConfigurations ((nodeOf intermediate) node) =
                  activeConfigurations ((nodeOf state) node) := by
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
              by_cases peerEq : peer = response.1
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
              ((nodeOf state) destination).log := by
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
        exact Or.inl (by simpa [intermediate, present] using member)
      · exact progressIntermediate
      · intro _ _ actualResponseHistory _ _ _ actualFacts leader index
        have actualSnapshot :=
          actualFacts.networkHistory.appendResponse
            destination response selectedMember successful.1
        have actualCovered :
            actualResponseHistory response <+:
              ((nodeOf state) destination).log := by
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
        · refine ⟨by simpa [intermediate, present] using joined, Or.inl ?_⟩
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
        · refine ⟨by simpa [intermediate, present] using joined, Or.inr ?_⟩
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
              rcases destinationProducible with direct | future
              · have follower := canProduceAppendAckAt_role direct
                have leader :
                    ((nodeOf intermediate) destination).role = .leader := by
                  rw [roleEq]
                  exact successful.2.2
                exact False.elim
                  (Role.noConfusion (follower.symm.trans leader))
              · have result :
                    canProduceAppendAckEventuallyAt
                      ((nodeOf state) destination) request index :=
                  Or.inr
                    ⟨by simpa [termEq] using future.1, future.2⟩
                rw [peerEq]
                exact result
            · have nodesEq :
                  (nodeOf intermediate) peer = (nodeOf state) peer := by
                simp [
                  intermediate, present, nodeOf_replaceNode, present, peerEq
                ]
              rw [nodesEq] at producible
              exact producible
          refine ⟨request, ?_, sourceEq, destinationEq, ?_, oldProducible, ?_⟩
          · simpa [intermediate, present] using queued
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
          voteRequestKey, Model.Local.makeRequestVoteRequest,
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
        forall node, (nodeOf after) node = (nodeOf intermediate) node := by
      intro node
      rfl
    have intermediateSelectedMember :
        (appendResponseEnvelope response ∈ intermediate.network /\ response.2.1 = destination) := by
      simpa [intermediate, present] using selectedMember
    have takenFromIntermediate :
        Selected response.1 intermediate.network (appendResponseEnvelope response) remaining := by
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
    have matchCoversResponse :
        response.2.2.lastLogIndex <=
          ((nodeOf intermediate) destination).matchIndex response.1 := by
      rw [matchDestination, updateIndex_same]
      omega
    have matchDestinationAfter :
        forall peer,
          ((nodeOf after) destination).matchIndex peer =
            updateIndex
              ((nodeOf intermediate) destination).matchIndex
              response.1
              (max
                (((nodeOf intermediate) destination).matchIndex response.1)
                response.2.2.lastLogIndex)
              peer := by
      intro peer
      rw [nodeStateEq]
      by_cases peerEq : peer = response.1
      · subst peer
        rw [updateIndex_same, max_eq_left matchCoversResponse]
      · simp [updateIndex, Function.update, peerEq]
    have effectiveElectionVotersAfter :
        forall candidate,
          effectiveElectionVoters (joined := joinedNodes) after candidate =
            effectiveElectionVoters (joined := joinedNodes) intermediate candidate :=
      effectiveElectionVotersAfterAppendResponse
        intermediate after response remaining
          takenFromIntermediate
          (by simp [after, present, intermediate, present])
          (by simp [after, present, intermediate, present])
          (fun node => by rw [nodeStateEq node])
          (fun node => by rw [nodeStateEq node])
    rw [← successful.2.2]
    change SystemInductiveInvariant (joined := joinedNodes) after
    apply networkFramePreservesSystemInductiveInvariant
      intermediate after intermediateInvariant
      (by simp [after, present, intermediate, present]) (fun _ => Iff.rfl) nodeStateEq
      (fun destination message member =>
        Or.inl (networkSubsetAfter destination message member))
    · intro _ _ actualResponseHistory _ _ _ actualFacts leader index
      have actualSnapshot :=
        actualFacts.networkHistory.appendResponse
          destination response intermediateSelectedMember successful.1
      have sameTermIntermediate :
          response.2.2.term =
            ((nodeOf intermediate) response.2.1).currentTerm := by
        simpa [responseDestination, termEq] using successful.2.1
      have actualCovered :
          actualResponseHistory response <+:
            ((nodeOf intermediate) destination).log := by
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
          (by simp [after, present, intermediate, present])
          (by simp [after, present, intermediate, present])
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
  · by_cases failed : response.2.2.success = false
    · simp only [
        show (((nodeOf state) destination).role != .leader) = false by simp [isLeader],
        Bool.false_eq_true, ↓reduceIte, failed, false_and, Bool.false_eq_true
      ] at handled
      subst nextNode
      let intermediate : Model.State Node TxId :=
        { state with
          nodes :=
            replaceNode state.nodes destination
              { (nodeOf state) destination with
                sentIndex :=
                  updateIndex
                    ((nodeOf state) destination).sentIndex
                    response.1
                    (max
                      (min
                        (findHighestPossibleMatch
                          ((nodeOf state) destination).log
                          response.2.2.lastLogIndex response.2.2.term)
                        (((nodeOf state) destination).sentIndex response.1))
                      (((nodeOf state) destination).matchIndex response.1)) } }
      let after : Model.State Node TxId :=
        { state with
          nodes :=
            replaceNode state.nodes destination
              { (nodeOf state) destination with
                sentIndex :=
                  updateIndex
                    ((nodeOf state) destination).sentIndex
                    response.1
                    (max
                      (min
                        (findHighestPossibleMatch
                          ((nodeOf state) destination).log
                          response.2.2.lastLogIndex response.2.2.term)
                        (((nodeOf state) destination).sentIndex response.1))
                      (((nodeOf state) destination).matchIndex response.1)) }
          network := remaining }
      have roleEq :
          forall node,
            ((nodeOf intermediate) node).role = ((nodeOf state) node).role := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, present, nodeOf_replaceNode, present, same]
      have termEq :
          forall node,
            ((nodeOf intermediate) node).currentTerm =
              ((nodeOf state) node).currentTerm := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, present, nodeOf_replaceNode, present, same]
      have logEq :
          forall node,
            ((nodeOf intermediate) node).log = ((nodeOf state) node).log := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, present, nodeOf_replaceNode, present, same]
      have commitEq :
          forall node,
            ((nodeOf intermediate) node).commitIndex =
              ((nodeOf state) node).commitIndex := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, present, nodeOf_replaceNode, present, same]
      have newFollowerEq :
          forall node,
            ((nodeOf intermediate) node).isNewFollower =
              ((nodeOf state) node).isNewFollower := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, present, nodeOf_replaceNode, present, same]
      have votedEq :
          forall node,
            ((nodeOf intermediate) node).votedFor =
              ((nodeOf state) node).votedFor := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, present, nodeOf_replaceNode, present, same]
      have votesEq :
          forall node,
            ((nodeOf intermediate) node).votesGranted =
              ((nodeOf state) node).votesGranted := by
        intro node
        by_cases same : node = destination <;>
          simp [intermediate, present, nodeOf_replaceNode, present, same]
      have matchEq :
          forall leader peer,
            ((nodeOf intermediate) leader).matchIndex peer =
              ((nodeOf state) leader).matchIndex peer := by
        intro leader peer
        by_cases same : leader = destination <;>
          simp [intermediate, present, nodeOf_replaceNode, present, same]
      have activeConfigurationsEq :
          forall node,
            activeConfigurations ((nodeOf intermediate) node) =
              activeConfigurations ((nodeOf state) node) := by
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
          · by_cases peerEq : peer = response.1
            · subst peer
              simp [intermediate, present, nodeOf_replaceNode, present, updateIndex_same]
              exact ⟨Or.inr old.1, old.2⟩
            · simpa [
                intermediate, present, nodeOf_replaceNode, present, updateIndex,
                Function.update, peerEq
              ] using old.1
          · simpa [matchEq, logEq] using old.2
        · simpa [
            intermediate, present, nodeOf_replaceNode, present, Function.update, leaderEq
          ] using old
      have effectiveAckersIntermediate :
          forall actualResponseHistory leader index,
            effectiveAckers (joined := joinedNodes) intermediate actualResponseHistory leader index =
              effectiveAckers (joined := joinedNodes) state actualResponseHistory leader index :=
        effectiveAckersFrame
          state intermediate rfl rfl termEq logEq matchEq
      have effectiveElectionVotersIntermediate :
          forall candidate,
            effectiveElectionVoters (joined := joinedNodes) intermediate candidate =
              effectiveElectionVoters (joined := joinedNodes) state candidate :=
        effectiveElectionVotersFrame
          state intermediate rfl rfl termEq votesEq
      have intermediateInvariant :
          SystemInductiveInvariant (joined := joinedNodes) intermediate := by
        apply roleAndNetworkFramePreservesSystemInductiveInvariant
          state intermediate packed rfl
          (fun _ => Iff.rfl)
          (joinedCarrierFactsFrame state intermediate facts.joinedCarriers rfl
            (by
              intro node configuration active
              have same :
                  activeConfigurations ((nodeOf intermediate) node) =
                    activeConfigurations ((nodeOf state) node) := by
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
          exact Or.inl (by simpa [intermediate, present] using member)
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
              by simpa [intermediate, present] using joined,
              Or.inl
                (by
                  rw [
                    effectiveAckersIntermediate
                      actualResponseHistory leader index
                  ] at effective
                  exact effective)
            ⟩
          · refine ⟨by simpa [intermediate, present] using joined, Or.inr ?_⟩
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
                  simpa [peerEq] using producible
                have framed :=
                  (canProduceAppendAckEventuallyAt_sentIndex
                    ((nodeOf state) destination)
                    (updateIndex
                      ((nodeOf state) destination).sentIndex
                      response.1
                      (max
                        (min
                          (findHighestPossibleMatch
                            ((nodeOf state) destination).log
                            response.2.2.lastLogIndex response.2.2.term)
                          (((nodeOf state) destination).sentIndex response.1))
                        (((nodeOf state) destination).matchIndex response.1)))
                    request index).mp
                    (by simpa [intermediate, present, nodeOf_replaceNode, present] using destinationProducible)
                simpa [peerEq] using framed
              · simpa [
                  intermediate, present, nodeOf_replaceNode, present, Function.update, peerEq
                ] using producible
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
            activeConfigurationsEq,
            effectiveElectionVotersIntermediate
          ] using majority
        · intro candidate role majority
          unfold hasPotentialElectionMajority at majority ⊢
          simpa [
            potentialElectionVoters,
            currentlyEligibleElectionVoter,
            voteRequestKey, Model.Local.makeRequestVoteRequest,
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
          forall node, (nodeOf after) node = (nodeOf intermediate) node := by
        intro node
        rfl
      have takenFromIntermediate :
          Selected response.1 intermediate.network (appendResponseEnvelope response) remaining := by
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
      have effectiveElectionVotersAfter :
          forall candidate,
            effectiveElectionVoters (joined := joinedNodes) after candidate =
              effectiveElectionVoters (joined := joinedNodes) intermediate candidate :=
        effectiveElectionVotersAfterAppendResponse
          intermediate after response remaining
            takenFromIntermediate
            (by simp [after, present, intermediate, present])
            (by simp [after, present, intermediate, present])
            (fun node => by rw [nodeStateEq node])
            (fun node => by rw [nodeStateEq node])
      change SystemInductiveInvariant (joined := joinedNodes) after
      apply networkFramePreservesSystemInductiveInvariant
        intermediate after intermediateInvariant
        (by simp [after, present, intermediate, present]) (fun _ => Iff.rfl) nodeStateEq
        (fun destination message member =>
          Or.inl (networkSubsetAfter destination message member))
      · intro _ _ actualResponseHistory _ _ _ _ leader index
        apply Finset.subset_of_eq
        apply effectiveAckersAfterInactiveResponse
            intermediate after destination response responseDestination remaining
              takenFromIntermediate
        · simp [after, present, intermediate, present]
        · simp [after, present, intermediate, present]
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
    · have responseSuccess : response.2.2.success = true := Bool.eq_true_of_not_eq_false failed
      have differentTerm : response.2.2.term ≠ (nodeOf state destination).currentTerm := by
        intro same
        exact successful ⟨responseSuccess, same, isLeader⟩
      simp [responseSuccess, isLeader, differentTerm] at handled
      subst nextNode
      rw [replaceNode_nodeOf state destination distinct]
      let after : Model.State Node TxId :=
        { state with
          network := remaining }
      have fieldEq :
          forall node, (nodeOf after) node = (nodeOf state) node := by
        intro node
        rfl
      change SystemInductiveInvariant (joined := joinedNodes) after
      apply networkFramePreservesSystemInductiveInvariant
        state after packed rfl (fun _ => Iff.rfl) fieldEq
        (fun queuedDestination message member =>
          Or.inl
            (updateQueueSubset queuedDestination message
              (by simpa [after, present] using member)))
      · intro _ _ actualResponseHistory _ _ _ _ leader index
        apply Finset.subset_of_eq
        apply effectiveAckersAfterInactiveResponse
            state after destination response responseDestination remaining
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
            state after response remaining
              takenByResponseSource rfl rfl
              (fun node => rfl) (fun node => rfl)
        ] at majority
        exact majority
      · intro candidate voter active member
        rw [
          effectiveElectionVotersAfterAppendResponse
            state after response remaining
              takenByResponseSource rfl rfl
              (fun node => rfl) (fun node => rfl)
        ] at member
        exact member

end CCFRaft.Proofs.Invariant
