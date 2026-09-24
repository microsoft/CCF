-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.VoteResponse
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

/-- Append responses are unaffected by consuming a vote request and replying. -/
lemma appendResponseMemAfterVoteRequestReceive
    (network : List (Model.Envelope Node TxId))
    (source _destination : Node)
    (request : VoteRequestKey Node)
    (response : VoteResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (taken : Selected source network (voteRequestEnvelope request) remaining)
    : forall queuedDestination queuedResponse,
        (appendResponseEnvelope queuedResponse
            ∈ enqueue (remaining) (voteResponseEnvelope response)
          ∧ queuedResponse.2.1 = queuedDestination)
        ↔ (appendResponseEnvelope queuedResponse ∈ network
            /\ queuedResponse.2.1 = queuedDestination) := by
  intro queuedDestination queuedResponse
  have retained : appendResponseEnvelope queuedResponse ∈ remaining ↔ appendResponseEnvelope queuedResponse ∈ network :=
    selected_mem_iff taken (by simp [appendResponseEnvelope, voteRequestEnvelope])
  simp only [reply, enqueue, List.mem_append, List.mem_singleton]
  have different : (appendResponseEnvelope queuedResponse : Model.Envelope Node TxId) ≠ voteResponseEnvelope response := by
    simp [appendResponseEnvelope, voteResponseEnvelope]
  simp only [different, or_false, retained]

/-- A queued vote response is old or is the response just produced. -/
lemma voteResponseMemAfterVoteRequestReceive
    (network : List (Model.Envelope Node TxId))
    (source _destination : Node)
    (request : VoteRequestKey Node)
    (response queuedResponse : VoteResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (taken : Selected source network (voteRequestEnvelope request) remaining)
    (queuedDestination : Node)
    (member
      : (voteResponseEnvelope queuedResponse
            ∈ enqueue (remaining) (voteResponseEnvelope response)
          ∧ queuedResponse.2.1 = queuedDestination))
    : (voteResponseEnvelope queuedResponse ∈ network
        /\ queuedResponse.2.1 = queuedDestination)
      \/ (queuedDestination = response.2.1 /\ queuedResponse = response) := by
  rcases memEnqueue remaining (voteResponseEnvelope response) (voteResponseEnvelope queuedResponse)
      queuedDestination member with old | added
  · exact Or.inl ⟨(selectedSound taken).2.2 _ old.1, old.2⟩
  · exact Or.inr ⟨added.1, voteResponseEnvelope.injEq.mp added.2⟩

/-- Every old vote response remains queued after consuming a vote request. -/
lemma oldVoteResponseMemAfterVoteRequestReceive
    (network : List (Model.Envelope Node TxId))
    (source _destination : Node)
    (request : VoteRequestKey Node)
    (response queuedResponse : VoteResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (taken : Selected source network (voteRequestEnvelope request) remaining)
    (queuedDestination : Node)
    (member
      : (voteResponseEnvelope queuedResponse ∈ network
          /\ queuedResponse.2.1 = queuedDestination))
    : (voteResponseEnvelope queuedResponse
          ∈ enqueue (remaining) (voteResponseEnvelope response)
        ∧ queuedResponse.2.1 = queuedDestination) := by
  have retained : voteResponseEnvelope queuedResponse ∈ remaining :=
    (selected_mem_iff taken (by simp [voteResponseEnvelope, voteRequestEnvelope])).mpr member.1
  exact ⟨List.mem_append_left _ retained, member.2⟩

/-- Vote requests are unaffected by consuming an AppendEntries request. -/
lemma voteRequestMemAfterAppendRequestReceive
    (network : List (Model.Envelope Node TxId))
    (source _destination : Node)
    (request : AppendRequestKey Node TxId)
    (response : AppendResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (taken : Selected source network (appendRequestEnvelope request) remaining)
    : forall queuedDestination queuedRequest,
        (voteRequestEnvelope queuedRequest ∈ (reply remaining response)
          ∧ queuedRequest.2.1 = queuedDestination)
        ↔ (voteRequestEnvelope queuedRequest ∈ network
            /\ queuedRequest.2.1 = queuedDestination) := by
  intro queuedDestination queuedRequest
  have retained : voteRequestEnvelope queuedRequest ∈ remaining ↔ voteRequestEnvelope queuedRequest ∈ network :=
    selected_mem_iff taken (by simp [voteRequestEnvelope, appendRequestEnvelope])
  simp only [reply, enqueue, List.mem_append, List.mem_singleton]
  have different : (voteRequestEnvelope queuedRequest : Model.Envelope Node TxId) ≠ appendResponseEnvelope response := by
    simp [voteRequestEnvelope, appendResponseEnvelope]
  simp only [different, or_false, retained]

/-- Vote responses are unaffected by consuming an AppendEntries request. -/
lemma voteResponseMemAfterAppendRequestReceive
    (network : List (Model.Envelope Node TxId))
    (source _destination : Node)
    (request : AppendRequestKey Node TxId)
    (response : AppendResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (taken : Selected source network (appendRequestEnvelope request) remaining)
    : forall queuedDestination queuedResponse,
        (voteResponseEnvelope queuedResponse ∈ (reply remaining response)
          ∧ queuedResponse.2.1 = queuedDestination)
        ↔ (voteResponseEnvelope queuedResponse ∈ network
            /\ queuedResponse.2.1 = queuedDestination) := by
  intro queuedDestination queuedResponse
  have retained : voteResponseEnvelope queuedResponse ∈ remaining ↔ voteResponseEnvelope queuedResponse ∈ network :=
    selected_mem_iff taken (by simp [voteResponseEnvelope, appendRequestEnvelope])
  simp only [reply, enqueue, List.mem_append, List.mem_singleton]
  have different : (voteResponseEnvelope queuedResponse : Model.Envelope Node TxId) ≠ appendResponseEnvelope response := by
    simp [voteResponseEnvelope, appendResponseEnvelope]
  simp only [different, or_false, retained]

/-- A queued AppendEntries response is old or is the response just produced. -/
lemma appendResponseMemAfterAppendRequestReceive
    (network : List (Model.Envelope Node TxId))
    (source _destination : Node)
    (request : AppendRequestKey Node TxId)
    (response queuedResponse : AppendResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (taken : Selected source network (appendRequestEnvelope request) remaining)
    (queuedDestination : Node)
    (member
      : (appendResponseEnvelope queuedResponse ∈ (reply remaining response)
          ∧ queuedResponse.2.1 = queuedDestination))
    : (appendResponseEnvelope queuedResponse ∈ network
        /\ queuedResponse.2.1 = queuedDestination)
      \/ (queuedDestination = response.2.1 /\ queuedResponse = response) := by
  rcases memEnqueue remaining (appendResponseEnvelope response) (appendResponseEnvelope queuedResponse)
      queuedDestination member with old | added
  · exact Or.inl ⟨(selectedSound taken).2.2 _ old.1, old.2⟩
  · exact Or.inr ⟨added.1, appendResponseEnvelope.injEq.mp added.2⟩

/-- Post-receive ACK evidence is old evidence or the selected request's newly
materialised destination ACK. -/
lemma effectiveAckerAfterAppendRequestReceive
    (state after : Model.State Node TxId)
    (source destination : Node)
    (request : AppendRequestKey Node TxId)
    (response : AppendResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (newHistory : List (Entry Node TxId))
    (taken : Selected source state.network (appendRequestEnvelope request) remaining)
    (producedSource : response.1 = destination)
    (producedDestination : response.2.1 = request.1)
    (producedTerm
      : response.2.2.success = true
        -> response.2.2.term = ((nodeOf state) destination).currentTerm)
    (successfulRequestTerm
      : response.2.2.success = true
        -> request.2.2.term = ((nodeOf state) destination).currentTerm)
    (networkEq : after.network = (reply remaining response))
    (hasJoinedEq : joinedNext = joinedNodes)
    (termEq
      : forall node,
          ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (matchEq
      : forall leader peer,
          ((nodeOf after) leader).matchIndex peer
          = ((nodeOf state) leader).matchIndex peer)
    (leaderLogEq
      : forall leader,
          ((nodeOf after) leader).role = .leader
          -> ((nodeOf after) leader).log = ((nodeOf state) leader).log)
    : forall leader index,
        ((nodeOf after) leader).role = .leader
        -> forall voter,
            voter
              ∈ effectiveAckers (joined := joinedNext) after
                  (Function.update responseHistory response newHistory)
                  leader index
            -> voter
                  ∈ effectiveAckers (joined := joinedNodes) state responseHistory leader
                      index
                \/ (response.2.2.success = true
                    /\ leader = request.1
                    /\ voter = destination
                    /\ index <= response.2.2.lastLogIndex
                    /\ request.2.2.term = ((nodeOf state) request.1).currentTerm) := by
  intro leader index role voter member
  simp only [
    effectiveAckers, Finset.mem_filter] at member ⊢
  have oldJoined : voter ∈ joinedNodes := by simpa [hasJoinedEq] using member.1
  rcases member.2 with self | matched | queued
  · exact Or.inl ⟨oldJoined, Or.inl self⟩
  · exact Or.inl
      ⟨oldJoined,
        Or.inr (Or.inl (by simpa [matchEq] using matched))⟩
  · rcases queued with
      ⟨queuedResponse, queuedMember, success, responseTerm,
        responseSource, responseDestination, covered, historyCovered⟩
    have memberCases :=
      appendResponseMemAfterAppendRequestReceive
        state.network source destination request response queuedResponse
          remaining taken leader
          (by simpa [networkEq] using queuedMember)
    by_cases sameResponse : queuedResponse = response
    · subst queuedResponse
      right
      have leaderSource : leader = request.1 := by
        rw [producedDestination] at responseDestination
        exact responseDestination.symm
      exact ⟨
        success,
        leaderSource,
        by rw [producedSource] at responseSource
           exact responseSource.symm,
        covered,
        by
          have responseRequestTerm :=
            (producedTerm success).symm.trans
              (by simpa [termEq] using responseTerm)
          exact (successfulRequestTerm success).trans
            (by simpa [leaderSource] using responseRequestTerm)
      ⟩
    · rcases memberCases with oldMember | new
      · left
        exact ⟨
          oldJoined,
          Or.inr
            (Or.inr
              (by
                refine ⟨
                  queuedResponse,
                  oldMember,
                  success,
                  by simpa [termEq] using responseTerm,
                  responseSource,
                  responseDestination,
                  covered,
                  ?_
                ⟩
                simpa [Function.update, sameResponse, leaderLogEq leader role]
                  using historyCovered))
        ⟩
      · exact False.elim (sameResponse new.2)

/-- Reserve materialisation preserves all temporal ACK histories. -/
lemma appendRequestAckerTemporalFacts
    (state : Model.State Node TxId)
    (source destination : Node)
    {present : destination ∈ state.nodes.map Prod.fst}
    (request : AppendRequestKey Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendResponseKey Node)
    (remaining : List (Model.Envelope Node TxId))
    (votes : VoteHistory Node)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (voteVoterHistory : VoteResponseKey Node -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (elections : ElectionHistory Node TxId)
    (termsPositive : CurrentTermsPositive state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (electionQueued : ElectionQueuedHistoryFacts state appendHistory elections)
    (currentFacts
      : AckerCurrentHistory (joined := joinedNodes) state responseHistory elections)
    (ackerVoteFacts
      : AckerVoteHistory (joined := joinedNodes) state votes responseHistory
          voteVoterHistory elections)
    (ackerElectionFacts
      : AckerElectionHistory (joined := joinedNodes) state responseHistory elections)
    (requestDestination : request.2.1 = destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (notStepped
      : ¬ (request.2.2.term = (nodeOf state destination).currentTerm
            ∧ ((nodeOf state destination).role = .candidate
                ∨ (nodeOf state destination).role = .preVoteCandidate)))
    (taken : Selected source state.network (appendRequestEnvelope request) remaining)
    (responseSource : response.1 = request.2.1)
    (responseDestination : response.2.1 = request.1)
    (handled
      : handleAppendEntriesRequest? request.2.1 ((nodeOf state) destination) request.2.2
        = some (nextNode, response.2.2))
    : let after : Model.State Node TxId :=
        {
          state with
            nodes := replaceNode state.nodes destination nextNode
            network := (reply remaining response)
        }
      let newResponseHistory :=
        Function.update responseHistory response (appendHistory request)
      AckerCurrentHistory (joined := joinedNodes) after newResponseHistory elections
      /\ AckerVoteHistory (joined := joinedNodes) after votes newResponseHistory
          voteVoterHistory elections
      /\ AckerElectionHistory (joined := joinedNodes) after newResponseHistory
          elections := by
  let post := handleAppendEntriesRequestLocalPost notStepped handled
  let after : Model.State Node TxId :=
    { state with
      nodes := replaceNode state.nodes destination nextNode
      network := (reply remaining response) }
  let newResponseHistory :=
    Function.update responseHistory response (appendHistory request)
  have requestMember :
      (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination) :=
    ⟨(selectedSound taken).2.1, requestDestination⟩
  have roleEq :
      forall node,
        ((nodeOf after) node).role = ((nodeOf state) node).role := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, present, nodeOf_replaceNode] using post.roleUnchanged
    · simp [after, present, nodeOf_replaceNode, same]
  have termEq :
      forall node,
        ((nodeOf after) node).currentTerm =
          ((nodeOf state) node).currentTerm := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, present, nodeOf_replaceNode] using post.currentTermUnchanged
    · simp [after, present, nodeOf_replaceNode, same]
  have matchEq :
      forall leader peer,
        ((nodeOf after) leader).matchIndex peer =
          ((nodeOf state) leader).matchIndex peer := by
    intro leader peer
    by_cases same : leader = destination
    · subst leader
      simpa [after, present, nodeOf_replaceNode] using congrFun post.matchIndexUnchanged peer
    · simp [after, present, nodeOf_replaceNode, same]
  have activeNodeEq :
      forall node,
        (((nodeOf state) node).role = .candidate \/
          ((nodeOf state) node).role = .leader) ->
          (nodeOf after) node = (nodeOf state) node := by
    intro node active
    by_cases same : node = destination
    · subst node
      have unchanged :=
        handleAppendEntriesRequestActiveUnchanged
          notStepped handled active
      simp [after, present, nodeOf_replaceNode, unchanged]
    · simp [after, present, nodeOf_replaceNode, same]
  have leaderLogEq :
      forall leader,
        ((nodeOf after) leader).role = .leader ->
          ((nodeOf after) leader).log = ((nodeOf state) leader).log := by
    intro leader role
    have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
    exact congrArg NodeState.log
      (activeNodeEq leader (Or.inr oldRole))
  have effectiveCases :
      forall leader index,
        ((nodeOf after) leader).role = .leader ->
        forall voter,
          voter ∈ effectiveAckers (joined := joinedNodes) after newResponseHistory leader index ->
            voter ∈ effectiveAckers (joined := joinedNodes) state responseHistory leader index \/
              (response.2.2.success = true /\
                leader = request.1 /\
                voter = destination /\
                index <= response.2.2.lastLogIndex /\
                request.2.2.term =
                  ((nodeOf state) request.1).currentTerm) := by
    intro leader index role voter member
    exact
      effectiveAckerAfterAppendRequestReceive
        state after source destination request response remaining
          responseHistory (appendHistory request) taken
          (by simpa [requestDestination] using responseSource)
          responseDestination
          post.successfulResponseTerm post.successfulCurrentTerm
          rfl rfl termEq matchEq leaderLogEq
          leader index role voter
          (by simpa [newResponseHistory] using member)
  have sourceStateEq :
      forall leader,
        ((nodeOf after) leader).role = .leader ->
          (nodeOf after) leader = (nodeOf state) leader := by
    intro leader role
    have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
    exact activeNodeEq leader (Or.inr oldRole)
  change
    AckerCurrentHistory (joined := joinedNodes) after newResponseHistory elections /\
      AckerVoteHistory (joined := joinedNodes)
        after votes newResponseHistory voteVoterHistory elections /\
      AckerElectionHistory (joined := joinedNodes) after newResponseHistory elections
  constructor
  · intro leader index role current signature voter effective
    have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
    have leaderEq := sourceStateEq leader role
    have oldCurrent :
        termAt ((nodeOf state) leader).log index =
          ((nodeOf state) leader).currentTerm := by
      simpa [leaderEq] using current
    have oldSignature :
        isSignatureAt ((nodeOf state) leader).log index = true := by
      simpa [leaderEq] using signature
    rcases effectiveCases leader index role voter effective with
      oldEffective | materialised
    · rcases
          currentFacts leader index oldRole oldCurrent oldSignature
            voter oldEffective with
        retained | bad
      · by_cases voterEq : voter = destination
        · subst voter
          by_cases succeeded : response.2.2.success = true
          · have destinationTerm :
                request.2.2.term =
                  ((nodeOf state) destination).currentTerm :=
              post.successfulCurrentTerm succeeded
            have leaderTermLe :
                ((nodeOf state) leader).currentTerm <= request.2.2.term := by
              have currentPositive :
                  0 < termAt ((nodeOf state) leader).log index := by
                rw [oldCurrent]
                exact
                  positiveOfBootstrapTermLe
                    (termsPositive leader (by rw [oldRole]; decide))
              rcases termAtPositiveEntry currentPositive with
                ⟨entry, found, entryTerm⟩
              have foundInPrefix :
                  entryAt?
                      (((nodeOf state) leader).log.take index)
                      index =
                    some entry := by
                rw [entryAtTake_of_le (le_refl index)]
                exact found
              have destinationFound :=
                entryAt_of_prefix retained foundInPrefix
              have bounded :=
                entriesBounded destination entry
                  (entryAtSomeMember destinationFound)
              simpa [entryTerm, oldCurrent, destinationTerm] using bounded
            by_cases sameTerm :
                ((nodeOf state) leader).currentTerm = request.2.2.term
            · have requestOwner :=
                (ownership.queuedAppendMetadata
                  destination request requestMember).2.1
              have leaderOwner := ownership.activeLeader leader oldRole
              rw [sameTerm] at leaderOwner
              have sameLeader :
                  leader = request.1 :=
                Option.some.inj (leaderOwner.symm.trans requestOwner)
              subst leader
              have requestHistory :=
                ownership.queuedActiveSourceHistory
                  destination request requestMember
                    (by simp [sameTerm])
                    oldRole
              let leaderPrefix :=
                ((nodeOf state) request.1).log.take index
              have prefixLength :
                  leaderPrefix.length = index := by
                have currentPositive :
                    0 < termAt
                      ((nodeOf state) request.1).log index := by
                  rw [oldCurrent]
                  exact
                    positiveOfBootstrapTermLe
                      (termsPositive request.1 (by rw [oldRole]; decide))
                rcases termAtPositiveEntry currentPositive with
                  ⟨entry, found, _⟩
                simp [
                  leaderPrefix, List.length_take,
                  entryAtSomeIndexBound found
                ]
              by_cases coveredByHistory :
                  leaderPrefix.length <=
                    (appendHistory request).length
              · have shared :
                    leaderPrefix <+: appendHistory request := by
                  rw [List.prefix_iff_eq_take]
                  calc
                    leaderPrefix
                        = ((nodeOf state) request.1).log.take leaderPrefix.length := by
                      simp [leaderPrefix, prefixLength]
                    _ = (appendHistory request).take leaderPrefix.length :=
                      (takeEqOfPrefix requestHistory coveredByHistory).symm
                have retainedNext :=
                  handledAppendRequestRetainsSharedPrefix
                    state votes appendHistory canonicalHistory owners
                      ownership destination request nextNode response.2.2
                      requestMember snapshot notStepped handled succeeded retained shared
                exact Or.inl
                  (by
                    rw [sourceStateEq request.1 role]
                    simpa [after, present, nodeOf_replaceNode, leaderPrefix] using retainedNext)
              · have historyInPrefix :
                    appendHistory request <+: leaderPrefix := by
                  rw [List.prefix_iff_eq_take]
                  have historyBound :
                      (appendHistory request).length <=
                        leaderPrefix.length := by omega
                  calc
                    appendHistory request
                        = ((nodeOf state) request.1).log.take
                            (appendHistory request).length :=
                      (prefixEqTake requestHistory).symm
                    _ = leaderPrefix.take (appendHistory request).length := by
                      simp [
                        leaderPrefix, List.take_take,
                        Nat.min_eq_left
                          (by simpa [prefixLength] using historyBound)
                      ]
                have historyBefore :
                    appendHistory request <+:
                      ((nodeOf state) destination).log :=
                  historyInPrefix.trans retained
                have already :
                    alreadyDone ((nodeOf state) destination) request.2.2 :=
                  appendRequestAlreadyDoneOfSharedPrefix
                    snapshot historyBefore (prefixRefl _)
                      snapshot.1
                have unchanged :=
                  successfulAlreadyDoneAppendLogUnchanged
                    already notStepped handled succeeded
                exact Or.inl
                  (by
                    rw [sourceStateEq request.1 role]
                    simpa [after, present, nodeOf_replaceNode, unchanged] using retained)
            · have strict :
                  ((nodeOf state) leader).currentTerm < request.2.2.term := by
                omega
              rcases
                  electionFacts.ownerRecorded
                    request.2.2.term request.1
                      ((ownership.queuedAppendMetadata
                        destination request requestMember).2.1) with
                bootstrap | recorded
              · have positive :=
                  termsPositive leader
                    (by rw [oldRole]; decide)
                rw [bootstrap.1] at strict
                omega
              · rcases recorded with
                  ⟨record, recordStored, _⟩
                by_cases inPromotion :
                    ((nodeOf state) leader).log.take index <+:
                      record.promotionLog
                · have shared :=
                    inPromotion.trans
                      (electionQueued
                        destination request requestMember
                          record recordStored)
                  have retainedNext :=
                    handledAppendRequestRetainsSharedPrefix
                      state votes appendHistory canonicalHistory owners
                        ownership destination request nextNode response.2.2
                        requestMember snapshot notStepped handled succeeded retained shared
                  exact Or.inl
                    (by
                      rw [leaderEq]
                      simpa [after, present, nodeOf_replaceNode] using retainedNext)
                · right
                  exact ⟨
                    request.2.2.term,
                    record,
                    by simpa [leaderEq] using strict,
                    by simp [termEq, destinationTerm],
                    recordStored,
                    by simpa [leaderEq] using inPromotion
                  ⟩
          · have failed : response.2.2.success = false :=
              Bool.eq_false_of_not_eq_true succeeded
            have unchanged := post.failedStateUnchanged failed
            exact Or.inl
              (by
                rw [leaderEq]
                simpa [after, present, nodeOf_replaceNode, unchanged] using retained)
        · exact Or.inl
            (by
              rw [leaderEq]
              simpa [
                after, present, nodeOf_replaceNode, Function.update, voterEq
              ] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
        exact ⟨
          badTerm,
          badRecord,
          by simpa [leaderEq] using above,
          by simpa [termEq] using bounded,
          recorded,
          by simpa [leaderEq] using missing
        ⟩
    · rcases materialised with
        ⟨succeeded, leaderSource, voterDestination,
          acknowledged, requestTerm⟩
      subst leader
      subst voter
      have acknowledgedPrefix :=
        handledAppendRequestAcknowledgesSourcePrefix
          state votes appendHistory canonicalHistory owners ownership
            destination request nextNode response.2.2 requestMember snapshot
            notStepped handled succeeded
            (by simpa [roleEq] using role)
            requestTerm acknowledged
      exact Or.inl
        (by
          rw [sourceStateEq request.1 role]
          simpa [after, present, nodeOf_replaceNode] using acknowledgedPrefix)
  · constructor
    · intro leader index role current signature
        voter voteTerm candidate effective voted different newer
      have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
      have leaderEq := sourceStateEq leader role
      have oldCurrent :
          termAt ((nodeOf state) leader).log index =
            ((nodeOf state) leader).currentTerm := by
        simpa [leaderEq] using current
      have oldSignature :
          isSignatureAt ((nodeOf state) leader).log index = true := by
        simpa [leaderEq] using signature
      rcases effectiveCases leader index role voter effective with
        oldEffective | materialised
      · rcases
            ackerVoteFacts leader index oldRole oldCurrent oldSignature
              voter voteTerm candidate oldEffective voted different
                (by simpa [leaderEq] using newer) with
          retained | bad
        · exact Or.inl (by simpa [leaderEq] using retained)
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
          exact ⟨
            badTerm,
            badRecord,
            by simpa [leaderEq] using above,
            bounded,
            recorded,
            by simpa [leaderEq] using missing
          ⟩
      · rcases materialised with
          ⟨succeeded, leaderSource, voterDestination,
            _, requestTerm⟩
        subst leader
        subst voter
        have destinationTerm :
            request.2.2.term =
              ((nodeOf state) destination).currentTerm :=
          post.successfulCurrentTerm succeeded
        have future : votes destination voteTerm = none :=
          voteFacts.future destination voteTerm
            (by
              have sourceNewer :
                  ((nodeOf state) request.1).currentTerm < voteTerm := by
                simpa [leaderEq] using newer
              rw [← destinationTerm, requestTerm]
              exact sourceNewer)
        rw [future] at voted
        contradiction
    · intro leader index role current signature
        term record voter recorded voterMember effective newer
      have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
      have leaderEq := sourceStateEq leader role
      have oldCurrent :
          termAt ((nodeOf state) leader).log index =
            ((nodeOf state) leader).currentTerm := by
        simpa [leaderEq] using current
      have oldSignature :
          isSignatureAt ((nodeOf state) leader).log index = true := by
        simpa [leaderEq] using signature
      rcases effectiveCases leader index role voter effective with
        oldEffective | materialised
      · rcases
            ackerElectionFacts leader index oldRole oldCurrent oldSignature
              term record voter recorded voterMember oldEffective
                (by simpa [leaderEq] using newer) with
          retained | bad
        · exact Or.inl (by simpa [leaderEq] using retained)
        · exact Or.inr (by simpa [leaderEq] using bad)
      · rcases materialised with
          ⟨succeeded, leaderSource, voterDestination,
            _, requestTerm⟩
        subst leader
        subst voter
        have destinationTerm :
            request.2.2.term =
              ((nodeOf state) destination).currentTerm :=
          post.successfulCurrentTerm succeeded
        have voterTerm :=
          electionHistoryVoterTerm
            voteFacts electionFacts recorded voterMember
        have sourceNewer :
            request.2.2.term < term := by
          simpa [leaderEq, requestTerm] using newer
        rw [destinationTerm] at sourceNewer
        omega

/-- Arbitrary-term local facts for one handled RequestVote request. -/
structure VoteRequestLocalPost
    (before after : NodeState Node TxId)
    (request : VoteRequestKey Node)
    (response : VoteResponseKey Node)
    : Prop where
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  logUnchanged : after.log = before.log
  commitIndexUnchanged : after.commitIndex = before.commitIndex
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  votesGrantedUnchanged : after.votesGranted = before.votesGranted
  votedForUpdate
    : after.votedFor = before.votedFor
      \/ (before.votedFor = none /\ after.votedFor = some request.1)
  responseTerm : response.2.2.term = before.currentTerm
  responseSource : response.1 = request.2.1
  responseDestination : response.2.1 = request.1
  granted
    : response.2.2.voteGranted = true
      -> request.2.2.term = before.currentTerm
          /\ voteLogUpToDate before request.2.2
          /\ (before.votedFor = none \/ before.votedFor = some request.1)
          /\ after.votedFor = some request.1
  grantedState
    : response.2.2.voteGranted = true
      -> after = { before with votedFor := some request.1 }
  rejectedState : response.2.2.voteGranted = false -> after = before

/-- The RequestVote handler changes only the persistent vote and reply. -/
lemma handleRequestVoteRequestLocalPost
    {before after : NodeState Node TxId}
    {request : VoteRequestKey Node}
    {response : VoteResponseKey Node}
    (responseSource : response.1 = request.2.1)
    (responseDestination : response.2.1 = request.1)
    (handled
      : handleRequestVoteRequest before request.1 request.2.2 = (after, response.2.2))
    : VoteRequestLocalPost before after request response := by
  have grant := (handleRequestVoteRequest before request.1 request.2.2).2.voteGranted
  unfold handleRequestVoteRequest at handled
  dsimp only at handled
  split_ifs at handled with granted
  · have equal := Prod.mk.inj handled
    have afterEq := equal.1.symm
    have payloadEq := equal.2.symm
    rw [afterEq]
    have freshness : request.2.2.term = before.currentTerm ∧ voteLogUpToDate before request.2.2
        ∧ (before.votedFor = none ∨ before.votedFor = some request.1) := by
      simpa only [decide_eq_true_eq] using granted
    constructor
    · rfl
    · rfl
    · rfl
    · rfl
    · rfl
    · rfl
    · rfl
    · rcases freshness.2.2 with absent | same
      · exact Or.inr ⟨absent, rfl⟩
      · exact Or.inl same.symm
    · simp [payloadEq]
    · exact responseSource
    · exact responseDestination
    · exact fun _ => ⟨freshness.1, freshness.2.1, freshness.2.2, rfl⟩
    · exact fun _ => rfl
    · intro rejected
      simp [payloadEq, granted] at rejected
  · have equal := Prod.mk.inj handled
    have afterEq := equal.1.symm
    have payloadEq := equal.2.symm
    rw [afterEq]
    constructor
    · rfl
    · rfl
    · rfl
    · rfl
    · rfl
    · rfl
    · rfl
    · exact Or.inl rfl
    · simp [payloadEq]
    · exact responseSource
    · exact responseDestination
    · intro accepted
      simp [payloadEq, granted] at accepted
    · intro accepted
      simp [payloadEq, granted] at accepted
    · exact fun _ => rfl

/-- Granting a vote freezes every prior ACK-retention fact at vote time. -/
lemma ackerVoteHistoryAfterGrantedRequest
    (state after : Model.State Node TxId)
    (votes : VoteHistory Node)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (voteVoterHistory : VoteResponseKey Node -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    (destination : Node)
    (request : VoteRequestKey Node)
    (currentFacts
      : AckerCurrentHistory (joined := joinedNodes) state responseHistory elections)
    (voteFacts
      : AckerVoteHistory (joined := joinedNodes) state votes responseHistory
          voteVoterHistory elections)
    (requestTerm : request.2.2.term = ((nodeOf state) destination).currentTerm)
    (roleEq : forall node, ((nodeOf after) node).role = ((nodeOf state) node).role)
    (termEq
      : forall node,
          ((nodeOf after) node).currentTerm = ((nodeOf state) node).currentTerm)
    (logEq : forall node, ((nodeOf after) node).log = ((nodeOf state) node).log)
    (effectiveEq
      : forall source index,
          effectiveAckers (joined := joinedNext) after responseHistory source index
          = effectiveAckers (joined := joinedNodes) state responseHistory source index)
    : let key := grantedVoteKey destination request.2.2.term request.1
      let newVotes : VoteHistory (Node : Type) :=
        Function.update votes destination
          (Function.update (votes destination) request.2.2.term (some request.1))
      let newVoterHistory :=
        Function.update voteVoterHistory key
          (((nodeOf state) destination).log.take
            (maxCommittableIndex ((nodeOf state) destination).log))
      AckerVoteHistory (joined := joinedNext) after newVotes responseHistory
        newVoterHistory elections := by
  dsimp
  intro source index role current signature
      voter voteTerm candidate effective voted different newer
  have oldRole : ((nodeOf state) source).role = .leader := by simpa [roleEq] using role
  have oldCurrent :
      termAt ((nodeOf state) source).log index =
        ((nodeOf state) source).currentTerm := by
    simpa [logEq, termEq] using current
  have oldSignature :
      isSignatureAt ((nodeOf state) source).log index = true := by
    simpa [logEq] using signature
  have oldEffective :
      voter ∈ effectiveAckers (joined := joinedNodes) state responseHistory source index := by
    rw [effectiveEq] at effective
    exact effective
  by_cases voterEq : voter = destination
  · subst voter
    by_cases voteTermEq : voteTerm = request.2.2.term
    · subst voteTerm
      have candidateEq : candidate = request.1 := by
        have chosen :
            some request.1 = some candidate := by
          simpa [Function.update] using voted
        exact (Option.some.inj chosen).symm
      subst candidate
      rcases
          currentFacts source index oldRole oldCurrent oldSignature
            destination oldEffective with
        retained | bad
      · left
        simpa [Function.update, logEq]
          using (signatureEndedPrefixOfMaxTake
                  retained (signatureAtTakeLength oldSignature))
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
        exact ⟨
          badTerm,
          badRecord,
          by simpa [termEq] using above,
          by simpa [requestTerm] using bounded,
          recorded,
          by simpa [logEq] using missing
        ⟩
    · have oldVoted :
          votes destination voteTerm = some candidate := by
        simpa [Function.update, voteTermEq] using voted
      rcases
          voteFacts source index oldRole oldCurrent oldSignature
            destination voteTerm candidate oldEffective oldVoted
              different (by simpa [termEq] using newer) with
        retained | bad
      · left
        have keyNe :
            Not (
              grantedVoteKey destination voteTerm candidate =
                grantedVoteKey
                  destination request.2.2.term request.1) := by
          intro same
          have sameTerm :
              voteTerm = request.2.2.term :=
            congrArg (fun key : VoteResponseKey Node => key.2.2.term) same
          exact voteTermEq sameTerm
        simpa [Function.update, keyNe, logEq] using retained
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
        exact ⟨
          badTerm,
          badRecord,
          by simpa [termEq] using above,
          bounded,
          recorded,
          by simpa [logEq] using missing
        ⟩
  · have oldVoted :
        votes voter voteTerm = some candidate := by
      simpa [Function.update, voterEq] using voted
    rcases
        voteFacts source index oldRole oldCurrent oldSignature
          voter voteTerm candidate oldEffective oldVoted
            different (by simpa [termEq] using newer) with
      retained | bad
    · left
      have keyNe :
          Not (
            grantedVoteKey voter voteTerm candidate =
              grantedVoteKey
                destination request.2.2.term request.1) := by
        intro same
        have sameVoter :
            voter = destination :=
          congrArg (fun key : VoteResponseKey Node => key.1) same
        exact voterEq sameVoter
      simpa [Function.update, keyNe, logEq] using retained
    · right
      rcases bad with
        ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
      exact ⟨
        badTerm,
        badRecord,
        by simpa [termEq] using above,
        bounded,
        recorded,
        by simpa [logEq] using missing
      ⟩

end CCFRaft.Proofs.Invariant
