-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.VoteResponse
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
/-- Append responses are unaffected by consuming a vote request and replying. -/
lemma appendResponseMemAfterVoteRequestReceive
    (network : Node -> List (Message Node TxId))
    (source destination : Node)
    (request : RequestVoteRequest Node)
    (response : RequestVoteResponse Node)
    (remaining : List (Message Node TxId))
    (taken
      : Selected source (network destination) (.requestVoteRequest request) remaining)
    : forall queuedDestination queuedResponse,
        Message.appendEntriesResponse queuedResponse
          ∈ enqueue
              (updateQueue network destination remaining)
              (.requestVoteResponse response)
              queuedDestination
        ↔ Message.appendEntriesResponse queuedResponse ∈ network queuedDestination := by
  intro queuedDestination queuedResponse
  constructor
  · intro member
    rcases
        memEnqueue
          (updateQueue network destination remaining)
          (.requestVoteResponse response)
          (.appendEntriesResponse queuedResponse)
          queuedDestination member with
      old | new
    · by_cases same : queuedDestination = destination
      · subst queuedDestination
        have retained :
            Message.appendEntriesResponse queuedResponse ∈ remaining := by
          simpa [updateQueue] using old
        exact (selectedSound taken).2.2 _ retained
      · simpa [updateQueue, Function.update, same] using old
    · simp at new
  · intro member
    apply memEnqueueNoDupOfMem
    by_cases same : queuedDestination = destination
    · subst queuedDestination
      rcases memSelectedOrRemaining taken member with selected | retained
      · simp at selected
      · simpa [updateQueue] using retained
    · simpa [updateQueue, Function.update, same] using member

omit [Bootstrap Node] in
/-- A queued vote response is old or is the response just produced. -/
lemma voteResponseMemAfterVoteRequestReceive
    (network : Node -> List (Message Node TxId))
    (source destination : Node)
    (request : RequestVoteRequest Node)
    (response queuedResponse : RequestVoteResponse Node)
    (remaining : List (Message Node TxId))
    (taken
      : Selected source (network destination) (.requestVoteRequest request) remaining)
    (queuedDestination : Node)
    (member
      : Message.requestVoteResponse queuedResponse
        ∈ enqueue
            (updateQueue network destination remaining)
            (.requestVoteResponse response)
            queuedDestination)
    : Message.requestVoteResponse queuedResponse ∈ network queuedDestination
      \/ (queuedDestination = response.destination /\ queuedResponse = response) := by
  rcases
      memEnqueue
        (updateQueue network destination remaining)
        (.requestVoteResponse response)
        (.requestVoteResponse queuedResponse)
        queuedDestination member with
    old | new
  · left
    by_cases same : queuedDestination = destination
    · subst queuedDestination
      have retained :
          Message.requestVoteResponse queuedResponse ∈ remaining := by
        simpa [updateQueue] using old
      exact (selectedSound taken).2.2 _ retained
    · simpa [updateQueue, Function.update, same] using old
  · simp only [Message.requestVoteResponse.injEq] at new
    exact Or.inr ⟨new.1, new.2⟩

omit [Bootstrap Node] in
/-- Every old vote response remains queued after consuming a vote request. -/
lemma oldVoteResponseMemAfterVoteRequestReceive
    (network : Node -> List (Message Node TxId))
    (source destination : Node)
    (request : RequestVoteRequest Node)
    (response queuedResponse : RequestVoteResponse Node)
    (remaining : List (Message Node TxId))
    (taken
      : Selected source (network destination) (.requestVoteRequest request) remaining)
    (queuedDestination : Node)
    (member : Message.requestVoteResponse queuedResponse ∈ network queuedDestination)
    : Message.requestVoteResponse queuedResponse
      ∈ enqueue
          (updateQueue network destination remaining)
          (.requestVoteResponse response)
          queuedDestination := by
  apply memEnqueueNoDupOfMem
  by_cases same : queuedDestination = destination
  · subst queuedDestination
    rcases memSelectedOrRemaining taken member with selected | retained
    · simp at selected
    · simpa [updateQueue] using retained
  · simpa [updateQueue, Function.update, same] using member

omit [Bootstrap Node] in
/-- Vote requests are unaffected by consuming an AppendEntries request. -/
lemma voteRequestMemAfterAppendRequestReceive
    (network : Node -> List (Message Node TxId))
    (source destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (response : AppendEntriesResponse Node)
    (remaining : List (Message Node TxId))
    (taken
      : Selected source (network destination) (.appendEntriesRequest request) remaining)
    : forall queuedDestination queuedRequest,
        Message.requestVoteRequest queuedRequest
          ∈ reply network destination remaining response queuedDestination
        ↔ Message.requestVoteRequest queuedRequest ∈ network queuedDestination := by
  intro queuedDestination queuedRequest
  constructor
  · intro member
    rcases
        memEnqueue
          (updateQueue network destination remaining)
          (.appendEntriesResponse response)
          (.requestVoteRequest queuedRequest)
          queuedDestination (by simpa [reply] using member) with
      old | new
    · by_cases same : queuedDestination = destination
      · subst queuedDestination
        exact (selectedSound taken).2.2 _
          (by simpa [updateQueue] using old)
      · simpa [updateQueue, Function.update, same] using old
    · simp at new
  · intro member
    rw [reply]
    apply memEnqueueNoDupOfMem
    by_cases same : queuedDestination = destination
    · subst queuedDestination
      rcases memSelectedOrRemaining taken member with selected | retained
      · simp at selected
      · simpa [updateQueue] using retained
    · simpa [updateQueue, Function.update, same] using member

omit [Bootstrap Node] in
/-- Vote responses are unaffected by consuming an AppendEntries request. -/
lemma voteResponseMemAfterAppendRequestReceive
    (network : Node -> List (Message Node TxId))
    (source destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (response : AppendEntriesResponse Node)
    (remaining : List (Message Node TxId))
    (taken
      : Selected source (network destination) (.appendEntriesRequest request) remaining)
    : forall queuedDestination queuedResponse,
        Message.requestVoteResponse queuedResponse
          ∈ reply network destination remaining response queuedDestination
        ↔ Message.requestVoteResponse queuedResponse ∈ network queuedDestination := by
  intro queuedDestination queuedResponse
  constructor
  · intro member
    rcases
        memEnqueue
          (updateQueue network destination remaining)
          (.appendEntriesResponse response)
          (.requestVoteResponse queuedResponse)
          queuedDestination (by simpa [reply] using member) with
      old | new
    · by_cases same : queuedDestination = destination
      · subst queuedDestination
        exact (selectedSound taken).2.2 _
          (by simpa [updateQueue] using old)
      · simpa [updateQueue, Function.update, same] using old
    · simp at new
  · intro member
    rw [reply]
    apply memEnqueueNoDupOfMem
    by_cases same : queuedDestination = destination
    · subst queuedDestination
      rcases memSelectedOrRemaining taken member with selected | retained
      · simp at selected
      · simpa [updateQueue] using retained
    · simpa [updateQueue, Function.update, same] using member

omit [Bootstrap Node] in
/-- A queued AppendEntries response is old or is the response just produced. -/
lemma appendResponseMemAfterAppendRequestReceive
    (network : Node -> List (Message Node TxId))
    (source destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (response queuedResponse : AppendEntriesResponse Node)
    (remaining : List (Message Node TxId))
    (taken
      : Selected source (network destination) (.appendEntriesRequest request) remaining)
    (queuedDestination : Node)
    (member
      : Message.appendEntriesResponse queuedResponse
        ∈ reply network destination remaining response queuedDestination)
    : Message.appendEntriesResponse queuedResponse ∈ network queuedDestination
      \/ (queuedDestination = response.destination /\ queuedResponse = response) := by
  rcases
      memEnqueue
        (updateQueue network destination remaining)
        (.appendEntriesResponse response)
        (.appendEntriesResponse queuedResponse)
        queuedDestination (by simpa [reply] using member) with
    old | new
  · left
    by_cases same : queuedDestination = destination
    · subst queuedDestination
      exact (selectedSound taken).2.2 _
        (by simpa [updateQueue] using old)
    · simpa [updateQueue, Function.update, same] using old
  · simp only [Message.appendEntriesResponse.injEq] at new
    exact Or.inr new

omit [Bootstrap Node] in
/-- Post-receive ACK evidence is old evidence or the selected request's newly
materialised destination ACK. -/
lemma effectiveAckerAfterAppendRequestReceive
    (state after : View Node TxId)
    (source destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (response : AppendEntriesResponse Node)
    (remaining : List (Message Node TxId))
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (newHistory : List (Entry Node TxId))
    (taken
      : Selected source (state.network destination) (.appendEntriesRequest request)
          remaining)
    (producedSource : response.source = destination)
    (producedDestination : response.destination = request.source)
    (producedTerm
      : response.success = true -> response.term = (state.nodes destination).currentTerm)
    (successfulRequestTerm
      : response.success = true -> request.term = (state.nodes destination).currentTerm)
    (networkEq : after.network = reply state.network destination remaining response)
    (hasJoinedEq : after.hasJoined = state.hasJoined)
    (termEq
      : forall node, (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (matchEq
      : forall leader peer,
          (after.nodes leader).matchIndex peer = (state.nodes leader).matchIndex peer)
    (leaderLogEq
      : forall leader,
          (after.nodes leader).role = .leader
          -> (after.nodes leader).log = (state.nodes leader).log)
    : forall leader index,
        (after.nodes leader).role = .leader
        -> forall voter,
            voter
              ∈ effectiveAckers after
                  (Function.update responseHistory response newHistory)
                  leader index
            -> voter ∈ effectiveAckers state responseHistory leader index
                \/ (response.success = true
                    /\ leader = request.source
                    /\ voter = destination
                    /\ index <= response.lastLogIndex
                    /\ request.term = (state.nodes request.source).currentTerm) := by
  intro leader index role voter member
  simp only [
    effectiveAckers, Finset.mem_filter] at member ⊢
  have oldJoined : voter ∈ state.hasJoined := by simpa [hasJoinedEq] using member.1
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
      have leaderSource : leader = request.source := by
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
    (state : View Node TxId)
    (source destination : Node)
    (request : AppendEntriesRequest Node TxId)
    (nextNode : NodeState Node TxId)
    (response : AppendEntriesResponse Node)
    (remaining : List (Message Node TxId))
    (votes : VoteHistory Node)
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (voteVoterHistory : RequestVoteResponse Node -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (elections : ElectionHistory Node TxId)
    (termsPositive : CurrentTermsPositive state)
    (entriesBounded : EntriesDoNotExceedCurrentTerm state)
    (voteFacts : VoteHistoryFacts state votes)
    (ownership : TermOwnershipFacts state votes appendHistory canonicalHistory owners)
    (electionFacts : ElectionHistoryFacts state votes canonicalHistory owners elections)
    (electionQueued : ElectionQueuedHistoryFacts state appendHistory elections)
    (currentFacts : AckerCurrentHistory state responseHistory elections)
    (ackerVoteFacts
      : AckerVoteHistory state votes responseHistory voteVoterHistory elections)
    (ackerElectionFacts : AckerElectionHistory state responseHistory elections)
    (requestDestination : request.destination = destination)
    (snapshot : RequestSnapshots (appendHistory request) request)
    (notStepped : returnToFollowerState? (state.nodes destination) request = none)
    (taken
      : Selected source (state.network destination) (.appendEntriesRequest request)
          remaining)
    (handled
      : handleAppendEntriesRequest? (state.nodes destination) request
        = some (nextNode, response))
    : let after : View Node TxId :=
        {
          state with
            nodes := updateNode state.nodes destination nextNode
            network := reply state.network destination remaining response
        }
      let newResponseHistory :=
        Function.update responseHistory response (appendHistory request)
      AckerCurrentHistory after newResponseHistory elections
      /\ AckerVoteHistory after votes newResponseHistory voteVoterHistory elections
      /\ AckerElectionHistory after newResponseHistory elections := by
  let post := handleAppendEntriesRequestLocalPost handled
  let after : View Node TxId :=
    { state with
      nodes := updateNode state.nodes destination nextNode
      network := reply state.network destination remaining response }
  let newResponseHistory :=
    Function.update responseHistory response (appendHistory request)
  have requestMember :
      Message.appendEntriesRequest request ∈ state.network destination :=
    (selectedSound taken).2.1
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
  have matchEq :
      forall leader peer,
        (after.nodes leader).matchIndex peer =
          (state.nodes leader).matchIndex peer := by
    intro leader peer
    by_cases same : leader = destination
    · subst leader
      simpa [after, updateNode] using congrFun post.matchIndexUnchanged peer
    · simp [after, updateNode, same]
  have activeNodeEq :
      forall node,
        ((state.nodes node).role = .candidate \/
          (state.nodes node).role = .leader) ->
          after.nodes node = state.nodes node := by
    intro node active
    by_cases same : node = destination
    · subst node
      have unchanged :=
        handleAppendEntriesRequestActiveUnchanged
          notStepped handled active
      simp [after, updateNode, unchanged]
    · simp [after, updateNode, same]
  have leaderLogEq :
      forall leader,
        (after.nodes leader).role = .leader ->
          (after.nodes leader).log = (state.nodes leader).log := by
    intro leader role
    have oldRole : (state.nodes leader).role = .leader := by simpa [roleEq] using role
    exact congrArg NodeState.log
      (activeNodeEq leader (Or.inr oldRole))
  have effectiveCases :
      forall leader index,
        (after.nodes leader).role = .leader ->
        forall voter,
          voter ∈ effectiveAckers after newResponseHistory leader index ->
            voter ∈ effectiveAckers state responseHistory leader index \/
              (response.success = true /\
                leader = request.source /\
                voter = destination /\
                index <= response.lastLogIndex /\
                request.term =
                  (state.nodes request.source).currentTerm) := by
    intro leader index role voter member
    exact
      effectiveAckerAfterAppendRequestReceive
        state after source destination request response remaining
          responseHistory (appendHistory request) taken
          (by simpa [requestDestination] using post.responseSource)
          post.responseDestination
          post.successfulResponseTerm post.successfulCurrentTerm
          rfl rfl termEq matchEq leaderLogEq
          leader index role voter
          (by simpa [newResponseHistory] using member)
  have sourceStateEq :
      forall leader,
        (after.nodes leader).role = .leader ->
          after.nodes leader = state.nodes leader := by
    intro leader role
    have oldRole : (state.nodes leader).role = .leader := by simpa [roleEq] using role
    exact activeNodeEq leader (Or.inr oldRole)
  change
    AckerCurrentHistory after newResponseHistory elections /\
      AckerVoteHistory
        after votes newResponseHistory voteVoterHistory elections /\
      AckerElectionHistory after newResponseHistory elections
  constructor
  · intro leader index role current signature voter effective
    have oldRole : (state.nodes leader).role = .leader := by simpa [roleEq] using role
    have leaderEq := sourceStateEq leader role
    have oldCurrent :
        termAt (state.nodes leader).log index =
          (state.nodes leader).currentTerm := by
      simpa [leaderEq] using current
    have oldSignature :
        isSignatureAt (state.nodes leader).log index = true := by
      simpa [leaderEq] using signature
    rcases effectiveCases leader index role voter effective with
      oldEffective | materialised
    · rcases
          currentFacts leader index oldRole oldCurrent oldSignature
            voter oldEffective with
        retained | bad
      · by_cases voterEq : voter = destination
        · subst voter
          by_cases succeeded : response.success = true
          · have destinationTerm :
                request.term =
                  (state.nodes destination).currentTerm :=
              post.successfulCurrentTerm succeeded
            have leaderTermLe :
                (state.nodes leader).currentTerm <= request.term := by
              have currentPositive :
                  0 < termAt (state.nodes leader).log index := by
                rw [oldCurrent]
                exact
                  positiveOfBootstrapTermLe
                    (termsPositive leader (by rw [oldRole]; decide))
              rcases termAtPositiveEntry currentPositive with
                ⟨entry, found, entryTerm⟩
              have foundInPrefix :
                  entryAt?
                      ((state.nodes leader).log.take index)
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
                (state.nodes leader).currentTerm = request.term
            · have requestOwner :=
                (ownership.queuedAppendMetadata
                  destination request requestMember).2.1
              have leaderOwner := ownership.activeLeader leader oldRole
              rw [sameTerm] at leaderOwner
              have sameLeader :
                  leader = request.source :=
                Option.some.inj (leaderOwner.symm.trans requestOwner)
              subst leader
              have requestHistory :=
                ownership.queuedActiveSourceHistory
                  destination request requestMember
                    (by simp [sameTerm])
                    oldRole
              let leaderPrefix :=
                (state.nodes request.source).log.take index
              have prefixLength :
                  leaderPrefix.length = index := by
                have currentPositive :
                    0 < termAt
                      (state.nodes request.source).log index := by
                  rw [oldCurrent]
                  exact
                    positiveOfBootstrapTermLe
                      (termsPositive request.source (by rw [oldRole]; decide))
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
                        = (state.nodes request.source).log.take leaderPrefix.length := by
                      simp [leaderPrefix, prefixLength]
                    _ = (appendHistory request).take leaderPrefix.length :=
                      (takeEqOfPrefix requestHistory coveredByHistory).symm
                have retainedNext :=
                  handledAppendRequestRetainsSharedPrefix
                    state votes appendHistory canonicalHistory owners
                      ownership destination request nextNode response
                      requestMember snapshot handled succeeded retained shared
                exact Or.inl
                  (by
                    rw [sourceStateEq request.source role]
                    simpa [after, updateNode, leaderPrefix] using retainedNext)
              · have historyInPrefix :
                    appendHistory request <+: leaderPrefix := by
                  rw [List.prefix_iff_eq_take]
                  have historyBound :
                      (appendHistory request).length <=
                        leaderPrefix.length := by omega
                  calc
                    appendHistory request
                        = (state.nodes request.source).log.take
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
                      (state.nodes destination).log :=
                  historyInPrefix.trans retained
                have already :
                    alreadyDone (state.nodes destination) request :=
                  appendRequestAlreadyDoneOfSharedPrefix
                    snapshot historyBefore (prefixRefl _)
                      snapshot.1
                have unchanged :=
                  successfulAlreadyDoneAppendLogUnchanged
                    already handled succeeded
                exact Or.inl
                  (by
                    rw [sourceStateEq request.source role]
                    simpa [after, updateNode, unchanged] using retained)
            · have strict :
                  (state.nodes leader).currentTerm < request.term := by
                omega
              rcases
                  electionFacts.ownerRecorded
                    request.term request.source
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
                    (state.nodes leader).log.take index <+:
                      record.promotionLog
                · have shared :=
                    inPromotion.trans
                      (electionQueued
                        destination request requestMember
                          record recordStored)
                  have retainedNext :=
                    handledAppendRequestRetainsSharedPrefix
                      state votes appendHistory canonicalHistory owners
                        ownership destination request nextNode response
                        requestMember snapshot handled succeeded retained shared
                  exact Or.inl
                    (by
                      rw [leaderEq]
                      simpa [after, updateNode] using retainedNext)
                · right
                  exact ⟨
                    request.term,
                    record,
                    by simpa [leaderEq] using strict,
                    by simp [termEq, destinationTerm],
                    recordStored,
                    by simpa [leaderEq] using inPromotion
                  ⟩
          · have failed : response.success = false :=
              Bool.eq_false_of_not_eq_true succeeded
            have unchanged := post.failedStateUnchanged failed
            exact Or.inl
              (by
                rw [leaderEq]
                simpa [after, updateNode, unchanged] using retained)
        · exact Or.inl
            (by
              rw [leaderEq]
              simpa [
                after, updateNode, Function.update, voterEq
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
            destination request nextNode response requestMember snapshot
            handled succeeded
            (by simpa [roleEq] using role)
            requestTerm acknowledged
      exact Or.inl
        (by
          rw [sourceStateEq request.source role]
          simpa [after, updateNode] using acknowledgedPrefix)
  · constructor
    · intro leader index role current signature
        voter voteTerm candidate effective voted different newer
      have oldRole : (state.nodes leader).role = .leader := by simpa [roleEq] using role
      have leaderEq := sourceStateEq leader role
      have oldCurrent :
          termAt (state.nodes leader).log index =
            (state.nodes leader).currentTerm := by
        simpa [leaderEq] using current
      have oldSignature :
          isSignatureAt (state.nodes leader).log index = true := by
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
            request.term =
              (state.nodes destination).currentTerm :=
          post.successfulCurrentTerm succeeded
        have future : votes destination voteTerm = none :=
          voteFacts.future destination voteTerm
            (by
              have sourceNewer :
                  (state.nodes request.source).currentTerm < voteTerm := by
                simpa [leaderEq] using newer
              rw [← destinationTerm, requestTerm]
              exact sourceNewer)
        rw [future] at voted
        contradiction
    · intro leader index role current signature
        term record voter recorded voterMember effective newer
      have oldRole : (state.nodes leader).role = .leader := by simpa [roleEq] using role
      have leaderEq := sourceStateEq leader role
      have oldCurrent :
          termAt (state.nodes leader).log index =
            (state.nodes leader).currentTerm := by
        simpa [leaderEq] using current
      have oldSignature :
          isSignatureAt (state.nodes leader).log index = true := by
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
            request.term =
              (state.nodes destination).currentTerm :=
          post.successfulCurrentTerm succeeded
        have voterTerm :=
          electionHistoryVoterTerm
            voteFacts electionFacts recorded voterMember
        have sourceNewer :
            request.term < term := by
          simpa [leaderEq, requestTerm] using newer
        rw [destinationTerm] at sourceNewer
        omega

/-- Arbitrary-term local facts for one handled RequestVote request. -/
structure VoteRequestLocalPost
    (before after : NodeState Node TxId)
    (request : RequestVoteRequest Node)
    (response : RequestVoteResponse Node)
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
      \/ (before.votedFor = none /\ after.votedFor = some request.source)
  responseTerm : response.term = before.currentTerm
  responseSource : response.source = request.destination
  responseDestination : response.destination = request.source
  granted
    : response.voteGranted = true
      -> request.term = before.currentTerm
          /\ voteLogUpToDate before request
          /\ (before.votedFor = none \/ before.votedFor = some request.source)
          /\ after.votedFor = some request.source
  grantedState
    : response.voteGranted = true
      -> after = { before with votedFor := some request.source }
  rejectedState : response.voteGranted = false -> after = before

omit [Bootstrap Node] in
/-- The RequestVote handler changes only the persistent vote and reply. -/
lemma handleRequestVoteRequestLocalPost
    {before after : NodeState Node TxId}
    {request : RequestVoteRequest Node}
    {response : RequestVoteResponse Node}
    (handled : handleRequestVoteRequest? before request = some (after, response))
    : VoteRequestLocalPost before after request response := by
  unfold handleRequestVoteRequest? at handled
  split at handled
  · rename_i current
    let grant : Bool :=
      decide (
        request.term = before.currentTerm /\
          voteLogUpToDate before request /\
          (before.votedFor = none \/
            before.votedFor = some request.source))
    by_cases granted : grant = true
    · have grantFacts :
          request.term = before.currentTerm /\
            voteLogUpToDate before request /\
            (before.votedFor = none \/
              before.votedFor = some request.source) := by
        simpa [grant, Bool.decide_eq_true] using granted
      have pairEq := Option.some.inj handled
      simp [grant, granted] at pairEq
      rcases pairEq with ⟨afterEq, responseEq⟩
      subst after
      subst response
      constructor
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rcases grantFacts.2.2 with noVote | sameVote
        · exact Or.inr ⟨noVote, by simp []⟩
        · exact Or.inl (by simp [ sameVote])
      · rfl
      · rfl
      · rfl
      · intro _
        exact ⟨grantFacts.1, grantFacts.2.1, grantFacts.2.2, by simp []⟩
      · intro _
        rfl
      · intro rejected
        contradiction
    · have notGranted :
          Not (
            request.term = before.currentTerm /\
              voteLogUpToDate before request /\
              (before.votedFor = none \/
                before.votedFor = some request.source)) := by
        intro facts
        apply granted
        simp [grant, facts]
      have pairEq := Option.some.inj handled
      simp [grant, granted] at pairEq
      rcases pairEq with ⟨afterEq, responseEq⟩
      subst after
      subst response
      constructor
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · rfl
      · exact Or.inl rfl
      · rfl
      · rfl
      · rfl
      · intro success
        simp [] at success
      · intro success
        contradiction
      · intro _
        rfl
  · contradiction

omit [Bootstrap Node] in
/-- Granting a vote freezes every prior ACK-retention fact at vote time. -/
lemma ackerVoteHistoryAfterGrantedRequest
    (state after : View Node TxId)
    (votes : VoteHistory Node)
    (responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId))
    (voteVoterHistory : RequestVoteResponse Node -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    (destination : Node)
    (request : RequestVoteRequest Node)
    (currentFacts : AckerCurrentHistory state responseHistory elections)
    (voteFacts : AckerVoteHistory state votes responseHistory voteVoterHistory elections)
    (requestTerm : request.term = (state.nodes destination).currentTerm)
    (roleEq : forall node, (after.nodes node).role = (state.nodes node).role)
    (termEq
      : forall node, (after.nodes node).currentTerm = (state.nodes node).currentTerm)
    (logEq : forall node, (after.nodes node).log = (state.nodes node).log)
    (effectiveEq
      : forall source index,
          effectiveAckers after responseHistory source index
          = effectiveAckers state responseHistory source index)
    : let key := grantedVoteKey destination request.term request.source
      let newVotes : VoteHistory (Node : Type) :=
        Function.update votes destination
          (Function.update (votes destination) request.term (some request.source))
      let newVoterHistory :=
        Function.update voteVoterHistory key
          ((state.nodes destination).log.take
            (maxCommittableIndex (state.nodes destination).log))
      AckerVoteHistory after newVotes responseHistory newVoterHistory elections := by
  dsimp
  intro source index role current signature
      voter voteTerm candidate effective voted different newer
  have oldRole : (state.nodes source).role = .leader := by simpa [roleEq] using role
  have oldCurrent :
      termAt (state.nodes source).log index =
        (state.nodes source).currentTerm := by
    simpa [logEq, termEq] using current
  have oldSignature :
      isSignatureAt (state.nodes source).log index = true := by
    simpa [logEq] using signature
  have oldEffective :
      voter ∈ effectiveAckers state responseHistory source index := by
    rw [effectiveEq] at effective
    exact effective
  by_cases voterEq : voter = destination
  · subst voter
    by_cases voteTermEq : voteTerm = request.term
    · subst voteTerm
      have candidateEq : candidate = request.source := by
        have chosen :
            some request.source = some candidate := by
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
                  destination request.term request.source) := by
          intro same
          have sameTerm :
              voteTerm = request.term :=
            congrArg RequestVoteResponse.term same
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
                destination request.term request.source) := by
        intro same
        have sameVoter :
            voter = destination :=
          congrArg RequestVoteResponse.source same
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
