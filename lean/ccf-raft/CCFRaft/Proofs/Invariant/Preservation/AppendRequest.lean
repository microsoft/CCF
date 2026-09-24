-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.GrantVote
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

private lemma accepted_of_success
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (notStepped : ¬ (request.term = before.currentTerm
      ∧ (before.role = .candidate ∨ before.role = .preVoteCandidate)))
    (handled : handleAppendEntriesRequest? self before request = some (after, response))
    (success : response.success = true)
    : acceptAppendEntriesRequest? self before request = some (after, response) := by
  simp only [handleAppendEntriesRequest?, notStepped, ite_false] at handled
  cases rejected : rejectAppendEntriesRequest? before request with
  | none => simpa only [rejected] using handled
  | some result =>
      simp only [rejected] at handled
      unfold rejectAppendEntriesRequest? at rejected
      split at rejected
      · have pair := Option.some.inj rejected
        subst result
        simp only [Option.some.injEq, Prod.mk.injEq] at handled
        have failed := failureResponseMetadata before request
        rw [handled.2] at failed
        simp [failed] at success
      · contradiction

/-- Receiving an AppendEntries request preserves the full arbitrary-term invariant. -/
lemma receiveAppendEntriesRequestPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (source destination : Node)
    {present : destination ∈ state.nodes.map Prod.fst}
    (request : AppendRequestKey Node TxId)
    (remaining : List (Model.Envelope Node TxId))
    (nextNode : NodeState Node TxId)
    (response : AppendResponseKey Node)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (addressed : request.2.1 = destination)
    (taken
      : Selected source state.network (appendRequestEnvelope request)
          remaining)
    (notStepped : ¬ (request.2.2.term = (nodeOf state destination).currentTerm ∧ ((nodeOf state destination).role = .candidate ∨ (nodeOf state destination).role = .preVoteCandidate)))
    (responseSource : response.1 = request.2.1)
    (responseDestination : response.2.1 = request.1)
    (handled
      : handleAppendEntriesRequest? request.2.1 ((nodeOf state) destination) request.2.2
        = some (nextNode, response.2.2))
    : SystemInductiveInvariant (joined := joinedNodes)
        {
          state with
            nodes := replaceNode state.nodes destination nextNode
            network := (reply remaining response)
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
  have responseKey : (request.2.1, request.1, response.2.2) = response :=
    Prod.ext responseSource.symm (Prod.ext responseDestination.symm rfl)
  let post := handleAppendEntriesRequestLocalPost notStepped handled
  let after : Model.State Node TxId :=
    { state with
      nodes := replaceNode state.nodes destination nextNode
      network := (reply remaining response) }
  let newResponseHistory :=
    Function.update responseHistory response (appendHistory request)
  let newNodeEvidence :=
    appendRequestNodeEvidence
      state destination request nextNode nodeEvidence requestEvidence
  have requestMember :
      (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination) :=
    ⟨(selectedSound taken).2.1, addressed⟩
  have requestDestination : request.2.1 = destination := by
    simpa using
      facts.networkHistory.addressed
        destination (appendRequestEnvelope request) requestMember
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
  have votedEq :
      forall node,
        ((nodeOf after) node).votedFor = ((nodeOf state) node).votedFor := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, present, nodeOf_replaceNode] using post.votedForUnchanged
    · simp [after, present, nodeOf_replaceNode, same]
  have votesEq :
      forall node,
        ((nodeOf after) node).votesGranted =
          ((nodeOf state) node).votesGranted := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, present, nodeOf_replaceNode] using post.votesGrantedUnchanged
    · simp [after, present, nodeOf_replaceNode, same]
  have sentEq :
      forall node,
        ((nodeOf after) node).sentIndex = ((nodeOf state) node).sentIndex := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, present, nodeOf_replaceNode] using post.sentIndexUnchanged
    · simp [after, present, nodeOf_replaceNode, same]
  have matchEq :
      forall node,
        ((nodeOf after) node).matchIndex = ((nodeOf state) node).matchIndex := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa [after, present, nodeOf_replaceNode] using post.matchIndexUnchanged
    · simp [after, present, nodeOf_replaceNode, same]
  have activeNodeEq :
      forall node,
        (((nodeOf after) node).role = .candidate \/
          ((nodeOf after) node).role = .leader) ->
          (nodeOf after) node = (nodeOf state) node := by
    intro node active
    have oldActive :
        ((nodeOf state) node).role = .candidate \/
          ((nodeOf state) node).role = .leader := by
      simpa [roleEq] using active
    by_cases same : node = destination
    · subst node
      have unchanged :=
        handleAppendEntriesRequestActiveUnchanged
          notStepped handled oldActive
      simp [after, present, nodeOf_replaceNode, unchanged]
    · simp [after, present, nodeOf_replaceNode, same]
  have committedSignatureAfter :
      CommittedFrontierIsSignature after := by
    intro node positive
    by_cases same : node = destination
    · subst node
      simpa [after, present, nodeOf_replaceNode]
        using post.commitIndexSignature
          (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts destination)
          (by simpa [after, present, nodeOf_replaceNode] using positive)
    · simpa [after, present, nodeOf_replaceNode, Function.update, same]
        using invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
          facts node
          (by simpa [after, present, nodeOf_replaceNode, Function.update, same] using positive)
  have committedMonotone :
      forall node,
        ((nodeOf state) node).committedLog <+:
          ((nodeOf after) node).committedLog := by
    intro node
    by_cases same : node = destination
    · subst node
      rw [show (nodeOf after) destination = nextNode by
        simp [after, present, nodeOf_replaceNode]]
      unfold NodeState.committedLog
      rw [List.prefix_take_iff]
      exact ⟨
        post.previousCommittedPrefix,
        by
          simp only [List.length_take]
          calc
            min ((nodeOf state) destination).commitIndex ((nodeOf state) destination).log.length
                = ((nodeOf state) destination).commitIndex :=
              Nat.min_eq_left (facts.commitIndicesBounded destination)
            _ <= nextNode.commitIndex :=
              post.commitIndexMonotone
      ⟩
    · have unchanged : (nodeOf after) node = (nodeOf state) node := by
        simp [after, present, nodeOf_replaceNode, same]
      rw [unchanged]
  have appendRequestBack :
      forall queuedDestination queuedRequest,
        (appendRequestEnvelope queuedRequest ∈ after.network /\ queuedRequest.2.1 = queuedDestination) ->
          (appendRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
    intro queuedDestination queuedRequest member
    exact
      appendRequestMemberBeforeReply
        state source request response remaining taken
          queuedDestination queuedRequest
          (by simpa [after, present] using member)
  have voteRequestEq :
      forall queuedDestination queuedRequest,
        (voteRequestEnvelope queuedRequest ∈ after.network /\ queuedRequest.2.1 = queuedDestination) ↔
          (voteRequestEnvelope queuedRequest ∈ state.network /\ queuedRequest.2.1 = queuedDestination) := by
    intro queuedDestination queuedRequest
    simpa [after, present]
      using voteRequestMemAfterAppendRequestReceive
        state.network source destination request response remaining taken
        queuedDestination queuedRequest
  have voteResponseEq :
      forall queuedDestination queuedResponse,
        (voteResponseEnvelope queuedResponse ∈ after.network /\ queuedResponse.2.1 = queuedDestination) ↔
          (voteResponseEnvelope queuedResponse ∈ state.network /\ queuedResponse.2.1 = queuedDestination) := by
    intro queuedDestination queuedResponse
    simpa [after, present]
      using voteResponseMemAfterAppendRequestReceive
        state.network source destination request response remaining taken
        queuedDestination queuedResponse
  have effectiveElectionVotersEq :
      forall candidate,
        effectiveElectionVoters (joined := joinedNodes) after candidate =
          effectiveElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    apply and_congr (by simp [after, present])
    constructor <;> rintro (processed | queued)
    · exact Or.inl (by simpa [votesEq] using processed)
    · right
      rcases queued with
        ⟨queuedResponse, member, granted, responseTerm,
          responseSource, responseDestination⟩
      exact ⟨
        queuedResponse,
        (voteResponseEq candidate queuedResponse).mp member,
        granted,
        by simpa [termEq] using responseTerm,
        responseSource,
        responseDestination
      ⟩
    · exact Or.inl (by simpa [votesEq] using processed)
    · right
      rcases queued with
        ⟨queuedResponse, member, granted, responseTerm,
          responseSource, responseDestination⟩
      exact ⟨
        queuedResponse,
        (voteResponseEq candidate queuedResponse).mpr member,
        granted,
        by simpa [termEq] using responseTerm,
        responseSource,
        responseDestination
      ⟩
  have ownershipAfter :
      TermOwnershipFacts
        after votes appendHistory canonicalHistory owners := by
    constructor
    · exact ownership.bootstrap
    · intro leader role
      have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
      have unchanged := activeNodeEq leader (Or.inr role)
      rw [unchanged]
      exact ownership.activeLeader leader oldRole
    · intro node index entry found
      by_cases same : node = destination
      · subst node
        simpa [after, present, nodeOf_replaceNode]
          using (handledAppendRequestCanonicalAgreement state votes appendHistory
                  canonicalHistory owners ownership destination request nextNode response.2.2
                  requestMember
                  (facts.networkHistory.appendRequest destination request requestMember).1
                  notStepped handled index entry (by simpa [after, present, nodeOf_replaceNode] using found))
      · simpa [after, present, nodeOf_replaceNode, Function.update, same]
          using (ownership.logEntryAgreement node index entry
                  (by simpa [after, present, nodeOf_replaceNode, Function.update, same] using found))
    · intro queuedDestination queuedRequest member index entry found
      exact ownership.queuedHistoryEntryAgreement
        queuedDestination queuedRequest
          (appendRequestBack queuedDestination queuedRequest member)
          index entry found
    · intro leader role
      have unchanged := activeNodeEq leader (Or.inr role)
      have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
      rw [unchanged]
      exact ownership.activeLeaderHistory leader oldRole
    · exact ownership.canonicalEntryOwner
    · exact ownership.canonicalMonoLog
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bounded, leader⟩
      exact ⟨
        by simpa [termEq] using bounded,
        by
          intro current
          have oldCurrent :
              term = ((nodeOf state) owner).currentTerm := by
            simpa [termEq] using current
          simpa [roleEq] using leader oldCurrent
      ⟩
    · intro queuedDestination queuedRequest member
      exact ownership.queuedAppendMetadata
        queuedDestination queuedRequest
          (appendRequestBack queuedDestination queuedRequest member)
    · intro queuedDestination queuedRequest member sameTerm leaderRole
      have oldMember :=
        appendRequestBack queuedDestination queuedRequest member
      have oldRole : ((nodeOf state) queuedRequest.1).role = .leader := by
        simpa [roleEq] using leaderRole
      have unchanged :=
        activeNodeEq queuedRequest.1 (Or.inr leaderRole)
      rw [unchanged]
      exact ownership.queuedActiveSourceHistory
        queuedDestination queuedRequest oldMember
        (by simpa [termEq] using sameTerm) oldRole
  have electionFactsAfter :
      ElectionHistoryFacts
        after votes canonicalHistory owners elections := by
    apply
      electionHistoryFrame
        state after votes votes canonicalHistory canonicalHistory
          owners elections electionFacts
    · intros
      rfl
    · intro term
      exact prefixRefl _
    · intro history canonical
      exact canonical
  have voteCanonicalAfter :
      GrantedVoteCanonicalSnapshots (joined := joinedNodes)
        after canonicalHistory voteCandidateHistory voteVoterHistory := by
    apply
      grantedVoteCanonicalFrame
        state after canonicalHistory canonicalHistory
          voteCandidateHistory voteVoterHistory voteCanonicalFacts
    · intro candidate active
      exact termEq candidate
    · intro candidate active
      simpa [roleEq] using active
    · intro candidate voter active member
      rw [effectiveElectionVotersEq] at member
      exact member
    · intro history canonical
      exact canonical
  have temporalFacts :=
    appendRequestAckerTemporalFacts (present := present)
      state source destination request nextNode response remaining
        votes appendHistory responseHistory voteVoterHistory
        canonicalHistory owners elections
        facts.currentTermsPositive facts.entriesDoNotExceedCurrentTerm
        facts.voteHistory ownership electionFacts electionQueuedFacts
        ackerCurrentFacts ackerVoteFacts ackerElectionFacts
        requestDestination
        (facts.networkHistory.appendRequest
          destination request requestMember).1
        notStepped taken responseSource responseDestination handled
  have evidenceAfter :
      CommitEvidenceFacts
        after appendHistory newNodeEvidence requestEvidence := by
    simpa only [responseKey, after, newNodeEvidence] using
      receiveAppendRequestCommitEvidenceFacts state source destination present request nextNode response.2.2 remaining
        votes appendHistory canonicalHistory owners ownership nodeEvidence requestEvidence evidenceFacts
        (facts.networkHistory.appendRequest destination request requestMember).1
        facts.commitIndicesBounded
        (invariantFactsCommittedFrontierIsSignatureFromCommitEvidence facts)
        addressed taken notStepped handled
  have knownInherited :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
              evidence supportedPrefix ->
          Exists fun oldEvidence =>
            Exists fun oldPrefix =>
              KnownCommitEvidence
                  state appendHistory nodeEvidence requestEvidence
                    oldEvidence oldPrefix /\
                evidence.commitTerm = oldEvidence.commitTerm /\
                evidence.history = oldEvidence.history /\
                evidence.commitFrontier = oldEvidence.commitFrontier /\
                evidence.ackQuorum = oldEvidence.ackQuorum /\
                evidence.supportedLength <= oldEvidence.supportedLength := by
    intro evidence supportedPrefix known
    exact
      receiveAppendRequestKnownEvidenceInherited
        state source destination present request nextNode response.2.2 remaining
          appendHistory nodeEvidence requestEvidence evidenceFacts
          facts.commitIndicesBounded addressed taken notStepped handled (by simpa only [responseKey, after, newNodeEvidence] using known)
  have termPositiveAfter :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
              evidence supportedPrefix ->
          BOOTSTRAP_TERM <= evidence.commitTerm := by
    intro evidence supportedPrefix known
    rcases knownInherited evidence supportedPrefix known with
      ⟨oldEvidence, oldPrefix, oldKnown, termSame, _, _, _, _⟩
    rw [termSame]
    exact prospectiveFacts.commitTermPositive
      oldEvidence oldPrefix oldKnown
  have electionClosureAfter :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
              evidence supportedPrefix ->
          forall term record,
            elections term = some record ->
            evidence.commitTerm < term ->
              evidence.history.take evidence.commitFrontier <+:
                record.promotionLog := by
    intro evidence supportedPrefix known term record recorded newer
    rcases knownInherited evidence supportedPrefix known with
      ⟨oldEvidence, oldPrefix, oldKnown,
        termSame, historySame, frontierSame, _, _⟩
    simpa [termSame, historySame, frontierSame]
      using prospectiveFacts.electionClosure
        oldEvidence oldPrefix oldKnown term record recorded
        (by simpa [termSame] using newer)
  have currentMemberAfter :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
              evidence supportedPrefix ->
          forall member,
            member ∈ evidence.ackQuorum ->
              evidence.history.take evidence.commitFrontier <+:
                ((nodeOf after) member).log := by
    intro evidence supportedPrefix known member ackMember
    rcases knownInherited evidence supportedPrefix known with
      ⟨oldEvidence, oldPrefix, oldKnown,
        _, historySame, frontierSame, quorumSame, _⟩
    have oldAck : member ∈ oldEvidence.ackQuorum := by simpa [quorumSame] using ackMember
    by_cases same : member = destination
    · subst member
      have retained :=
        handledAppendRequestRetainsEvidenceFrontier
          state destination request nextNode response.2.2
            votes appendHistory canonicalHistory owners ownership
            electionFacts electionQueuedFacts
            facts.entriesDoNotExceedCurrentTerm
            nodeEvidence requestEvidence evidenceFacts prospectiveFacts
            oldKnown oldAck requestMember
            (facts.networkHistory.appendRequest
              destination request requestMember).1 notStepped handled
      simpa [after, present, nodeOf_replaceNode, historySame, frontierSame] using retained
    · have old :=
        prospectiveFacts.currentMember
          oldEvidence oldPrefix oldKnown member oldAck
      simpa [
        after, present, nodeOf_replaceNode, Function.update, same,
        historySame, frontierSame
      ] using old
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts (joined := joinedNodes)
        after appendHistory newNodeEvidence requestEvidence elections := by
    constructor
    · exact termPositiveAfter
    · exact electionClosureAfter
    · exact currentMemberAfter
    · intro evidence supportedPrefix known
        queuedDestination queuedRequest queued sameTerm
      rcases knownInherited evidence supportedPrefix known with
        ⟨oldEvidence, oldPrefix, oldKnown,
          termSame, historySame, frontierSame, _, _⟩
      simpa [historySame, frontierSame]
        using prospectiveFacts.sameTermQueuedComparable
          oldEvidence oldPrefix oldKnown
          queuedDestination queuedRequest
          (appendRequestBack queuedDestination queuedRequest queued)
          (by simpa [termSame] using sameTerm)
    · intro evidence supportedPrefix known candidate member role newer
        entriesBefore ackMember relaxed
      rcases knownInherited evidence supportedPrefix known with
        ⟨oldEvidence, oldPrefix, oldKnown,
          termSame, historySame, frontierSame, quorumSame, _⟩
      have candidateUnchanged := activeNodeEq candidate (Or.inl role)
      have oldRole : ((nodeOf state) candidate).role = .candidate := by
        simpa [roleEq] using role
      have oldNewer :
          oldEvidence.commitTerm <
            ((nodeOf state) candidate).currentTerm := by
        simpa [termSame, termEq] using newer
      have oldEntriesBefore :
          forall entry,
            entry ∈ ((nodeOf state) candidate).log ->
              entry.term < ((nodeOf state) candidate).currentTerm := by
        intro entry member
        simpa [candidateUnchanged]
          using entriesBefore entry (by simpa [candidateUnchanged] using member)
      have oldAck : member ∈ oldEvidence.ackQuorum := by
        simpa [quorumSame] using ackMember
      simp only [
        relaxedElectionVoters, Finset.mem_filter] at relaxed
      rcases relaxed with ⟨joined, effective | supporter⟩
      · have oldRelaxed :
            member ∈ relaxedElectionVoters (joined := joinedNodes) state candidate := by
          simp only [
            relaxedElectionVoters, Finset.mem_filter]
          exact ⟨
            by simpa [after, present] using joined,
            Or.inl
              (by
                rw [effectiveElectionVotersEq] at effective
                exact effective)
          ⟩
        simpa [candidateUnchanged, historySame, frontierSame]
          using prospectiveFacts.relaxedSupporterCarriesFrontier
            oldEvidence oldPrefix oldKnown candidate member
            oldRole oldNewer oldEntriesBefore oldAck oldRelaxed
      · by_cases memberEq : member = destination
        · subst member
          have future :
              destination ∈
                futureElectionVoters (joined := joinedNodes)
                  after candidate ((nodeOf after) candidate).currentTerm := by
            simp only [
              futureElectionVoters, Finset.mem_filter]
            exact ⟨joined, Or.inr supporter⟩
          exact
            prospectiveCommitFutureMemberCore
              ownershipAfter committedSignatureAfter
                electionFactsAfter evidenceAfter
                termPositiveAfter electionClosureAfter currentMemberAfter
                known ackMember future
        · have oldRelaxed :
              member ∈ relaxedElectionVoters (joined := joinedNodes) state candidate := by
            simp only [
              relaxedElectionVoters, Finset.mem_filter]
            refine ⟨by simpa [after, present] using joined, Or.inr ?_⟩
            have memberUnchanged :
                (nodeOf after) member = (nodeOf state) member := by
              simp [after, present, nodeOf_replaceNode, memberEq]
            simp only [voteRequestKey, Model.Local.makeRequestVoteRequest] at supporter ⊢
            rw [memberUnchanged, candidateUnchanged] at supporter
            exact supporter
          simpa [candidateUnchanged, historySame, frontierSame]
            using prospectiveFacts.relaxedSupporterCarriesFrontier
              oldEvidence oldPrefix oldKnown candidate member
              oldRole oldNewer oldEntriesBefore oldAck oldRelaxed
  have snapshotsAfter :
      GrantedVoteSnapshots (joined := joinedNodes)
        after votes voteCandidateHistory voteVoterHistory := by
    intro candidate voter active member
    have unchanged := activeNodeEq candidate active
    have oldActive :
        ((nodeOf state) candidate).role = .candidate \/
          ((nodeOf state) candidate).role = .leader := by
      simpa [roleEq] using active
    have oldMember : voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    simpa [voteLogUpToDate, unchanged, termEq]
      using facts.grantedVoteSnapshots candidate voter oldActive oldMember
  have entriesBoundedAfter : EntriesDoNotExceedCurrentTerm after := by
    intro node entry member
    by_cases same : node = destination
    · subst node
      by_cases succeeded : response.2.2.success = true
      · rcases post.logShape with unchanged | truncated | extended
        · exact
            (by
            have oldMember :
                entry ∈ ((nodeOf state) destination).log := by
              simpa [after, present, nodeOf_replaceNode, unchanged] using member
            simpa [termEq]
              using facts.entriesDoNotExceedCurrentTerm destination entry oldMember)
        · have oldMember :
              entry ∈ ((nodeOf state) destination).log := by
            exact
              memOfPrefix
                (List.take_prefix request.2.2.prevLogIndex _)
                (by simpa [after, present, nodeOf_replaceNode, truncated] using member)
          simpa [termEq]
            using facts.entriesDoNotExceedCurrentTerm destination entry oldMember
        · have nextMember :
              entry ∈
                ((nodeOf state) destination).log.take request.2.2.prevLogIndex ++
                  request.2.2.entries := by
            simpa [after, present, nodeOf_replaceNode, extended] using member
          rcases List.mem_append.mp nextMember with old | learned
          · have oldMember :
                entry ∈ ((nodeOf state) destination).log :=
              memOfPrefix
                (List.take_prefix request.2.2.prevLogIndex _) old
            simpa [termEq]
              using facts.entriesDoNotExceedCurrentTerm destination entry oldMember
          · have historyMember : entry ∈ appendHistory request := by
              exact
                memOfPrefix
                  (List.take_prefix
                    (request.2.2.prevLogIndex + request.2.2.entries.length) _)
                  (by
                    rw [
                      (facts.networkHistory.appendRequest
                        destination request requestMember).1.2.2
                    ]
                    exact List.mem_append_right _ learned)
            have bounded :=
              (ownership.queuedAppendMetadata
                destination request requestMember).2.2
                entry historyMember
            simpa [
              termEq, post.successfulCurrentTerm succeeded
            ] using bounded
      · have failed : response.2.2.success = false :=
          Bool.eq_false_of_not_eq_true succeeded
        have unchanged := post.failedStateUnchanged failed
        simpa [after, present, nodeOf_replaceNode, unchanged, termEq]
          using facts.entriesDoNotExceedCurrentTerm
            destination entry
            (by simpa [after, present, nodeOf_replaceNode, unchanged] using member)
    · simpa [after, present, nodeOf_replaceNode, Function.update, same, termEq]
        using facts.entriesDoNotExceedCurrentTerm node entry
          (by simpa [after, present, nodeOf_replaceNode, Function.update, same] using member)
  have processedAckAfter :
      ProcessedAckHistoryFacts after ackHistory := by
    constructor
    · intro leader role peer zero
      have unchanged := activeNodeEq leader (Or.inr role)
      exact ackFacts.zero leader
        (by simpa [roleEq] using role)
        peer (by simpa [unchanged] using zero)
    · intro leader role peer positive
      have unchanged := activeNodeEq leader (Or.inr role)
      rcases
          ackFacts.positive leader
            (by simpa [roleEq] using role)
            peer (by simpa [unchanged] using positive) with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      exact ⟨
        snapshot,
        stored,
        by simpa [unchanged] using snapshotTerm,
        by simpa [unchanged] using snapshotIndex,
        historyBound,
        by simpa [unchanged] using agreed
      ⟩
  have termsPositiveAfter : CurrentTermsPositive after := by
    intro node participating
    rw [termEq]
    exact
      facts.currentTermsPositive node
        (by simpa [roleEq] using participating)
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
      have unchanged := activeNodeEq candidate active
      rw [unchanged]
      exact
        facts.voteHistory.counted candidate voter
          (by simpa [roleEq] using active)
          (by simpa [unchanged] using member)
  have candidatesAboveAfter : CandidatesAboveBootstrap after := by
    intro candidate role
    rw [termEq]
    exact (invariantFactsCandidatesAboveBootstrap facts)
      candidate (by simpa [roleEq] using role)
  have activeConfigurationsEq :
      forall node,
        (((nodeOf after) node).role = .candidate \/
          ((nodeOf after) node).role = .leader) ->
          activeConfigurations ((nodeOf after) node) =
            activeConfigurations ((nodeOf state) node) := by
    intro node active
    rw [activeNodeEq node active]
  have leaderStateEq :
      forall leader,
        ((nodeOf after) leader).role = .leader ->
          (nodeOf after) leader = (nodeOf state) leader := by
    intro leader role
    exact activeNodeEq leader (Or.inr role)
  have effectiveAckerCases :
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
          rfl rfl termEq
          (fun currentLeader peer =>
            congrFun (matchEq currentLeader) peer)
          (fun currentLeader currentRole =>
            congrArg NodeState.log
              (leaderStateEq currentLeader currentRole))
          leader index role voter
          (by simpa [newResponseHistory] using member)
  have effectiveAckersAfterSubsetPotentialBefore :
      forall leader index,
        ((nodeOf after) leader).role = .leader ->
          effectiveAckers (joined := joinedNodes) after newResponseHistory leader index ⊆
            potentialAckers (joined := joinedNodes)
              state appendHistory responseHistory leader index := by
    intro leader index role voter member
    rcases effectiveAckerCases leader index role voter member with
      old | materialised
    · exact
        effectiveAckersSubsetPotential
          state appendHistory responseHistory leader index old
    · rcases materialised with
        ⟨succeeded, leaderEq, voterEq, acknowledged, requestTerm⟩
      subst leader
      subst voter
      simp only [
        potentialAckers, Finset.mem_filter]
      refine ⟨
        facts.joinedCarriers.appendRequestDestinations destination request requestMember,
        Or.inr
          ⟨request, requestMember, rfl, requestDestination, requestTerm, Or.inl ?_, ?_⟩
      ⟩
      · exact ⟨nextNode, response.2.2,
          accepted_of_success notStepped handled succeeded, succeeded, acknowledged⟩
      · exact
          ownership.queuedActiveSourceHistory
            destination request requestMember requestTerm
            (by
              have roleAfter :
                  ((nodeOf after) request.1).role = .leader := by
                simpa using role
              simpa [roleEq] using roleAfter)
  have effectiveMajorityAfterImpliesPotentialBefore :
      forall leader index,
        ((nodeOf after) leader).role = .leader ->
        hasEffectiveMajorityAt (joined := joinedNodes) after newResponseHistory leader index ->
          hasPotentialMajorityAt (joined := joinedNodes)
            state appendHistory responseHistory leader index := by
    intro leader index role majority
    rw [hasEffectiveMajorityAt, List.all_eq_true] at majority
    rw [hasPotentialMajorityAt, List.all_eq_true]
    intro configuration active
    apply decide_eq_true
    intro governs
    exact
      hasConfigurationMajority_mono
        (effectiveAckersAfterSubsetPotentialBefore leader index role)
        ((of_decide_eq_true
          (majority configuration
            (by
              rw [activeConfigurationsEq leader (Or.inr role)]
              exact active))) governs)
  have activationVoteHistoryAfter :
      ActivationVoteHistory
        votes voteVoterHistory elections activations :=
    activationVoteHistory
  have activationProgressAfter :
      ActivationSupporterProgress after activations := by
    apply
      activationSupporterProgressFrame
        state after activations activationProgress
    intro node
    exact Nat.le_of_eq (termEq node).symm
  have activationElectionsAfter :
      ActivationElectionFacts votes elections activations :=
    activationElections
  have committedCoverageAfter :
      CommittedConfigurationCoverage after activations := by
    intro coveredNode frontier within positive signature
    by_cases nodeEq : coveredNode = destination
    · subst coveredNode
      have nextWithin : frontier <= nextNode.commitIndex := by
        simpa [after, present, nodeOf_replaceNode] using within
      by_cases oldWithin :
          frontier <= ((nodeOf state) destination).commitIndex
      · rcases
            activationQuorums.committedCoverage
              destination frontier oldWithin
              (by
                have takeEq :
                    nextNode.log.take frontier =
                      ((nodeOf state) destination).log.take frontier := by
                  have oldBound := facts.commitIndicesBounded destination
                  have agreed :=
                    takeEqOfPrefix post.previousCommittedPrefix
                      (count := frontier)
                      (by
                        simp [
                          NodeState.committedLog, List.length_take,
                          Nat.min_eq_left oldBound
                        ]
                        exact oldWithin)
                  simpa [
                    NodeState.committedLog, List.take_take,
                    Nat.min_eq_left oldWithin
                  ] using agreed.symm
                have configurationEq :=
                  currentConfigurationAt_eq_of_take_eq
                    (nextWithin.trans
                      (post.commitIndexBounded
                        (facts.commitIndicesBounded destination)))
                    (oldWithin.trans
                      (facts.commitIndicesBounded destination))
                    takeEq
                simpa [after, present, nodeOf_replaceNode, configurationEq] using positive)
              (by
                have takeEq :
                    nextNode.log.take frontier =
                      ((nodeOf state) destination).log.take frontier := by
                  have oldBound := facts.commitIndicesBounded destination
                  have agreed :=
                    takeEqOfPrefix post.previousCommittedPrefix
                      (count := frontier)
                      (by
                        simp [
                          NodeState.committedLog, List.length_take,
                          Nat.min_eq_left oldBound
                        ]
                        exact oldWithin)
                  simpa [
                    NodeState.committedLog, List.take_take,
                    Nat.min_eq_left oldWithin
                  ] using agreed.symm
                have nextTakeSignature :=
                  isSignatureAt_take_of_le le_rfl
                    (by simpa [after, present, nodeOf_replaceNode] using signature)
                rw [takeEq] at nextTakeSignature
                exact
                  isSignatureAt_of_prefix
                    (List.take_prefix frontier
                      ((nodeOf state) destination).log)
                    nextTakeSignature) with
          ⟨witness⟩
        have takeEq :
            nextNode.log.take frontier =
              ((nodeOf state) destination).log.take frontier := by
          have oldBound := facts.commitIndicesBounded destination
          have agreed :=
            takeEqOfPrefix post.previousCommittedPrefix
              (count := frontier)
              (by
                simp [
                  NodeState.committedLog, List.length_take,
                  Nat.min_eq_left oldBound
                ]
                exact oldWithin)
          simpa [
            NodeState.committedLog, List.take_take,
            Nat.min_eq_left oldWithin
          ] using agreed.symm
        have framed :=
          configurationFrontierCoverageFrame
            (newHistory := nextNode.log)
            (newTerm := nextNode.currentTerm)
            witness
            (oldWithin.trans (facts.commitIndicesBounded destination))
            (nextWithin.trans
              (post.commitIndexBounded
                (facts.commitIndicesBounded destination)))
            takeEq
            (Nat.le_of_eq post.currentTermUnchanged.symm)
        exact ⟨by simpa [after, present, nodeOf_replaceNode] using framed⟩
      · have advanced :
            ((nodeOf state) destination).commitIndex < nextNode.commitIndex := by
          omega
        have succeeded : response.2.2.success = true :=
          post.commitAdvancedSuccessful advanced
        have learned :=
          handledAppendRequestAdvancedCommittedHistory
            state votes appendHistory canonicalHistory owners ownership
            destination request nextNode response.2.2 requestMember
            (facts.networkHistory.appendRequest
              destination request requestMember).1
            (facts.commitIndicesBounded destination)
            notStepped handled advanced
        have requestBound :
            frontier <=
              min request.2.2.leaderCommit
                (request.2.2.prevLogIndex + request.2.2.entries.length) := by
          apply Nat.le_min.mpr
          constructor
          · rcases le_max_iff.mp post.commitUpperBound with old | learnedBound
            · omega
            · exact nextWithin.trans learnedBound
          · rcases le_max_iff.mp post.commitRequestEndBound with
              old | learnedBound
            · omega
            · exact nextWithin.trans learnedBound
        have takeEq :
            nextNode.log.take frontier =
              (appendHistory request).take frontier := by
          have nextBound :=
            post.commitIndexBounded (facts.commitIndicesBounded destination)
          have agreed :=
            congrArg (fun history => history.take frontier) learned
          simpa [
            NodeState.committedLog, List.take_take,
            Nat.min_eq_left nextWithin
          ] using agreed
        rcases
            activationQuorums.queuedCoverage
              destination request requestMember frontier requestBound
              (by
                have configurationEq :=
                  currentConfigurationAt_eq_of_take_eq
                    (nextWithin.trans
                      (post.commitIndexBounded
                        (facts.commitIndicesBounded destination)))
                    ((Nat.le_min.mp requestBound).2.trans
                      (facts.networkHistory.appendRequest
                        destination request requestMember).1.1)
                    takeEq
                simpa [after, present, nodeOf_replaceNode, configurationEq] using positive)
              (by
                have nextTakeSignature :=
                  isSignatureAt_take_of_le le_rfl
                    (by simpa [after, present, nodeOf_replaceNode] using signature)
                rw [takeEq] at nextTakeSignature
                exact
                  isSignatureAt_of_prefix
                    (List.take_prefix frontier (appendHistory request))
                    nextTakeSignature) with
          ⟨witness⟩
        have framed :=
          configurationFrontierCoverageFrame
            (newHistory := nextNode.log)
            (newTerm := nextNode.currentTerm)
            witness
            ((Nat.le_min.mp requestBound).2.trans
              (facts.networkHistory.appendRequest
                destination request requestMember).1.1)
            (nextWithin.trans
              (post.commitIndexBounded
                (facts.commitIndicesBounded destination)))
            takeEq
            (Nat.le_of_eq
              ((post.successfulCurrentTerm succeeded).trans
                post.currentTermUnchanged.symm))
        exact ⟨by simpa [after, present, nodeOf_replaceNode] using framed⟩
    · rcases
          activationQuorums.committedCoverage
            coveredNode frontier
              (by simpa [
                after, present, nodeOf_replaceNode, Function.update, nodeEq
              ] using within)
              (by simpa [
                after, present, nodeOf_replaceNode, Function.update, nodeEq
              ] using positive)
              (by simpa [
                after, present, nodeOf_replaceNode, Function.update, nodeEq
              ] using signature) with
        ⟨witness⟩
      exact ⟨by simpa [
                after, present, nodeOf_replaceNode, Function.update, nodeEq
              ] using witness⟩
  have queuedCoverageAfter :
      QueuedConfigurationCoverage after appendHistory activations := by
    apply
      queuedConfigurationCoverageFrame
        activationQuorums.queuedCoverage
        (afterAppendHistory := appendHistory)
    · intro queuedDestination queuedRequest queued
      exact appendRequestBack queuedDestination queuedRequest queued
    · intro _
      rfl
  have configurationCoverageAfter :
      ConfigurationCoverageFacts after activations := by
    intro coveredNode positive
    by_cases candidateRole :
        ((nodeOf after) coveredNode).role = .candidate
    · have unchanged := activeNodeEq coveredNode (Or.inl candidateRole)
      have oldPositive :
          0 < (currentConfiguration ((nodeOf state) coveredNode)).index := by
        simpa [unchanged] using positive
      rcases configurationActivations coveredNode oldPositive with
        ⟨witness⟩
      exact ⟨configurationCoverageWitnessNodeFrame witness unchanged⟩
    · by_cases nodeEq : coveredNode = destination
      · subst coveredNode
        rcases
            committedCoverageAfter destination
              ((nodeOf after) destination).commitIndex le_rfl positive
              (committedSignatureAfter destination
                (positive.trans_le
                  (currentConfiguration_index_le_commitIndex
                    ((nodeOf after) destination)))) with
          ⟨witness⟩
        refine ⟨⟨
                  witness.activationIndex,
                  witness.activation,
                  witness.stored,
                  by simpa [currentConfiguration] using witness.configurationCovered,
                  witness.activationTermBound,
                  by simpa [currentConfiguration] using witness.configurationIndexBound,
                  by simpa [currentConfiguration] using witness.historyAgreement,
                  ?_,
                  ?_,
                  ?_,
                  ?_
                ⟩⟩
        · intro higherIndex higher stored order
          simpa [currentConfiguration]
            using witness.higherAuthority higherIndex higher stored
              (by simpa [currentConfiguration] using order)
        · intro lowerIndex lower stored order
          simpa [currentConfiguration]
            using witness.lowerAuthority lowerIndex lower stored
              (by simpa [currentConfiguration] using order)
        · intro sameIndex same stored sameConfiguration
          simpa [currentConfiguration]
            using witness.sameAuthority sameIndex same stored
              (by simpa [currentConfiguration] using sameConfiguration)
        · intro role
          exact False.elim (candidateRole role)
      · have nodeStateEq :
            (nodeOf after) coveredNode = (nodeOf state) coveredNode := by
          simp [after, present, nodeOf_replaceNode, nodeEq]
        have oldPositive :
            0 < (currentConfiguration ((nodeOf state) coveredNode)).index := by
          simpa [nodeStateEq] using positive
        rcases configurationActivations coveredNode oldPositive with
          ⟨witness⟩
        exact ⟨configurationCoverageWitnessNodeFrame witness nodeStateEq⟩
  have activationPrefixInSupporterHistory :
      forall activationIndex activation supporter,
        activations activationIndex = some activation ->
        supporter ∈ activation.jointSupporters ->
          activation.history.take activation.activationFrontier <+:
            activation.supporterHistory supporter := by
    intro activationIndex activation supporter stored member
    have valid :=
      activationQuorums.history.valid
        activationIndex activation stored
    have agreement :=
      (activationQuorums.history.supporterAcks
        activationIndex activation stored).2 supporter member
    rw [List.prefix_iff_eq_take]
    calc
      activation.history.take activation.activationFrontier
          = (activation.supporterHistory supporter).take activation.activationFrontier :=
        agreement.2.2.2.symm
      _ = (activation.supporterHistory supporter).take
            (activation.history.take activation.activationFrontier).length := by
        simp [Nat.min_eq_left valid.2.1]
  have ackerActivationAfter :
      AckerActivationHistory (joined := joinedNodes)
        after newResponseHistory elections activations := by
    intro currentSource index role current signature
        activationIndex activation configuration supporter
        activationStored governing supporterMember effective newer
    have oldRole :
        ((nodeOf state) currentSource).role = .leader := by
      simpa [roleEq] using role
    have sourceEq := leaderStateEq currentSource role
    have oldCurrent :
        termAt ((nodeOf state) currentSource).log index =
          ((nodeOf state) currentSource).currentTerm := by
      simpa [sourceEq] using current
    have oldSignature :
        isSignatureAt ((nodeOf state) currentSource).log index = true := by
      simpa [sourceEq] using signature
    have oldNewer :
        ((nodeOf state) currentSource).currentTerm <
          activation.activationTerm := by
      simpa [sourceEq] using newer
    rcases
        effectiveAckerCases
          currentSource index role supporter effective with
      oldEffective | materialised
    · rcases
          ackerActivationFacts
            currentSource index oldRole oldCurrent oldSignature
            activationIndex activation configuration supporter
            activationStored governing supporterMember
            oldEffective oldNewer with
        retained | bad
      · exact Or.inl (by simpa [sourceEq] using retained)
      · exact Or.inr (by simpa [sourceEq] using bad)
    · rcases materialised with
        ⟨succeeded, sourceIsRequest, supporterIsDestination,
          acknowledged, requestTerm⟩
      subst currentSource
      subst supporter
      have owned :=
        activationCanonical.termOwner
          activationIndex activation activationStored
      rcases
          electionFacts.ownerRecorded
            activation.activationTerm activation.leader owned with
        bootstrap | elected
      · have sourcePositive :=
          facts.currentTermsPositive request.1
            (by rw [oldRole]; decide)
        rw [bootstrap.1] at oldNewer
        omega
      · rcases elected with ⟨record, recorded, _⟩
        by_cases sourceInPromotion :
            ((nodeOf state) request.1).log.take index <+:
              record.promotionLog
        · left
          have sourceInActivation :=
            electionPromotionPrefixInActivation
              electionFacts activationQuorums.history activationCanonical
              activationStored recorded sourceInPromotion
          simpa [sourceEq]
            using sourceInActivation.trans
              (activationPrefixInSupporterHistory
                activationIndex activation destination
                activationStored supporterMember)
        · right
          exact ⟨
            activation.activationTerm,
            record,
            by simpa [sourceEq] using oldNewer,
            le_rfl,
            recorded,
            by simpa [sourceEq] using sourceInPromotion
          ⟩
  have supporterCurrentAfter :
      ActivationSupporterCurrentHistory after elections activations := by
    intro activationIndex activation stored supporter member
    rcases
        configurationFacts.supporterCurrentHistory
          activationIndex activation stored supporter member with
      retained | bad
    · by_cases supporterEq : supporter = destination
      · subst supporter
        by_cases succeeded : response.2.2.success = true
        · have requestCurrent :
              request.2.2.term =
                ((nodeOf state) destination).currentTerm :=
            post.successfulCurrentTerm succeeded
          have activationTermBound :
              activation.activationTerm <= request.2.2.term := by
            have progress :=
              activationProgress
                activationIndex activation stored destination member
            omega
          rcases Nat.lt_or_eq_of_le activationTermBound with
            earlier | sameTerm
          · have requestOwned :=
              (ownership.queuedAppendMetadata
                destination request requestMember).2.1
            rcases
                electionFacts.ownerRecorded
                  request.2.2.term request.1 requestOwned with
              bootstrap | elected
            · have activationPositive :=
                activationQuorums.history.termPositive
                  activationIndex activation stored
              rw [bootstrap.1] at earlier
              omega
            · rcases elected with ⟨record, recorded, _⟩
              have activationInPromotion :
                  activation.history.take
                      activation.activationFrontier <+:
                    record.promotionLog := by
                rcases
                    activationElections.closure
                      activationIndex activation request.2.2.term record
                      stored recorded earlier with
                  direct | shared
                · exact direct
                · rcases shared with
                    ⟨_, _, _, _, _, _, _, _, promotionPrefix⟩
                  exact promotionPrefix
              have activationInRequest :
                  activation.history.take
                      activation.activationFrontier <+:
                    appendHistory request :=
                activationInPromotion.trans
                  (electionQueuedFacts
                    destination request requestMember record recorded)
              left
              simpa [after, present, nodeOf_replaceNode]
                using handledAppendRequestRetainsSharedPrefix
                  state votes appendHistory canonicalHistory owners ownership
                  destination request nextNode response.2.2 requestMember
                  (facts.networkHistory.appendRequest destination request requestMember).1
                  notStepped handled succeeded retained activationInRequest
          · rcases
                activationQuorums.queuedComparable
                  activationIndex activation destination request
                  stored requestMember sameTerm.symm with
              activationInRequest | requestInActivation
            · left
              simpa [after, present, nodeOf_replaceNode]
                using handledAppendRequestRetainsSharedPrefix
                  state votes appendHistory canonicalHistory owners ownership
                  destination request nextNode response.2.2 requestMember
                  (facts.networkHistory.appendRequest destination request requestMember).1
                  notStepped handled succeeded retained activationInRequest
            · have requestInNode :
                  appendHistory request <+:
                    ((nodeOf state) destination).log :=
                requestInActivation.trans retained
              have already :
                  alreadyDone ((nodeOf state) destination) request.2.2 :=
                appendRequestAlreadyDoneOfSharedPrefix
                  (facts.networkHistory.appendRequest
                    destination request requestMember).1
                  requestInNode (prefixRefl _)
                  (facts.networkHistory.appendRequest
                    destination request requestMember).1.1
              have unchanged :=
                successfulAlreadyDoneAppendLogUnchanged
                  already notStepped handled succeeded
              exact Or.inl
                (by simpa [after, present, nodeOf_replaceNode, unchanged] using retained)
        · have failed : response.2.2.success = false :=
            Bool.eq_false_of_not_eq_true succeeded
          have unchanged := post.failedStateUnchanged failed
          exact Or.inl
            (by simpa [after, present, nodeOf_replaceNode, unchanged] using retained)
      · exact Or.inl
          (by simpa [
            after, present, nodeOf_replaceNode, Function.update, supporterEq
          ] using retained)
    · exact Or.inr (by simpa [termEq] using bad)
  have configurationFactsAfter :
      ElectionConfigurationFacts (joined := joinedNodes) after elections activations := by
    apply
      electionConfigurationFrame
        state after elections activations activations configurationFacts
    · intro _ _ stored
      exact stored
    · exact supporterCurrentAfter
    · intro candidate role majority
      have unchanged := activeNodeEq candidate (Or.inl role)
      exact ⟨
        by simpa [roleEq] using role,
        by simp [unchanged],
        by
          rw [hasEffectiveElectionMajority] at majority ⊢
          rw [effectiveElectionVotersEq] at majority
          simpa [unchanged] using majority
      ⟩
    · intro candidate configuration role active
      simpa [activeConfigurationsEq candidate (Or.inl role)] using active
    · intro candidate role entry entryMember
      have unchanged := activeNodeEq candidate (Or.inl role)
      simpa [unchanged]
        using configurationFacts.candidateEntriesBeforeTerm
          candidate
          (by simpa [roleEq] using role)
          entry
          (by simpa [unchanged] using entryMember)
  have recordBridgeAfter :
      forall source index,
        ((nodeOf after) source).role = .leader ->
        termAt ((nodeOf after) source).log index =
          ((nodeOf after) source).currentTerm ->
        isSignatureAt ((nodeOf after) source).log index = true ->
        hasPotentialMajorityAt (joined := joinedNodes)
          after appendHistory newResponseHistory source index ->
        forall term record,
          elections term = some record ->
          ((nodeOf after) source).currentTerm < term ->
            ((nodeOf after) source).log.take index <+: record.promotionLog := by
    intro bridgeSource index role current signature potential
        term record recorded later
    exact
      potentialPrefixInElectionRecordsFromActivationHistory
        termsPositiveAfter entriesBoundedAfter voteFactsAfter
        ownershipAfter electionFactsAfter configurationFactsAfter
        activationQuorums.history activationProgressAfter
        ackerActivationAfter temporalFacts.2.2 activationCanonical
        activationElections configurationCoverageAfter
        evidenceAfter prospectiveAfter
        role current signature potential term record recorded later
  have candidateBridgeAfter :
      forall source index,
        ((nodeOf after) source).role = .leader ->
        termAt ((nodeOf after) source).log index =
          ((nodeOf after) source).currentTerm ->
        isSignatureAt ((nodeOf after) source).log index = true ->
        hasPotentialMajorityAt (joined := joinedNodes)
          after appendHistory newResponseHistory source index ->
        forall candidate,
          ((nodeOf after) candidate).role = .candidate ->
          hasPotentialElectionMajority (joined := joinedNodes) after candidate ->
          ((nodeOf after) source).currentTerm <
            ((nodeOf after) candidate).currentTerm ->
            ((nodeOf after) source).log.take index <+:
                ((nodeOf after) candidate).log \/
              Exists fun configuration =>
                configuration ∈ activeConfigurations ((nodeOf after) source) /\
                  configuration.index <= index /\
                  configuration ∈
                    activeConfigurations ((nodeOf after) candidate) := by
    intro bridgeSource index sourceRole current signature potential
        candidate candidateRole candidateMajority newer
    left
    apply
      activationPrefixInEffectiveCandidateByAuthorityChain
        termsPositiveAfter committedSignatureAfter entriesBoundedAfter
        voteFactsAfter snapshotsAfter voteCanonicalAfter ownershipAfter
        electionFactsAfter configurationFactsAfter activationQuorums.history
        configurationFactsAfter.supporterCurrentHistory
        activationVoteHistoryAfter activationProgressAfter
        ackerActivationAfter temporalFacts.2.2 activationCanonical
        activationElections configurationCoverageAfter
        evidenceAfter prospectiveAfter
        sourceRole current signature potential candidateRole
        candidateMajority newer
    intro configuration sourceActive governs candidateActive
    rcases
        potentialElectionMajorityIntersectionEffective
          snapshotsAfter potential sourceActive governs
          (Or.inl candidateRole) candidateMajority candidateActive newer with
      ⟨voter, effective, electionMember⟩
    have relaxed :
        voter ∈ relaxedElectionVoters (joined := joinedNodes) after candidate := by
      simp only [
        potentialElectionVoters, relaxedElectionVoters,
        Finset.mem_filter] at electionMember ⊢
      rcases electionMember with ⟨joined, materialised | eligible⟩
      · exact ⟨joined, Or.inl materialised⟩
      · exact ⟨
          joined,
          Or.inr
            ⟨
              by
                have termEq := eligible.1
                simpa [
                  currentlyEligibleElectionVoter,
                  voteRequestKey, Model.Local.makeRequestVoteRequest
                ] using Nat.le_of_eq termEq.symm,
              by simpa [
                  currentlyEligibleElectionVoter,
                  voteRequestKey, Model.Local.makeRequestVoteRequest, voteLogUpToDate
                ] using eligible.2.1
            ⟩
        ⟩
    exact
      effectiveAckerRelaxedCandidateContainsPrefixOfEarlierSafe
        termsPositiveAfter committedSignatureAfter ownershipAfter
        electionFactsAfter snapshotsAfter voteCanonicalAfter
        temporalFacts.1 temporalFacts.2.1
        sourceRole current signature candidateRole newer
        (configurationFactsAfter.candidateEntriesBeforeTerm
          candidate candidateRole)
        effective relaxed
        (fun term record above recorded =>
          recordBridgeAfter bridgeSource index sourceRole current signature
            potential term record recorded above)
  have knownEvidenceFrontierCanonicalAfter :
      forall knownEvidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
            knownEvidence supportedPrefix ->
          knownEvidence.history.take knownEvidence.commitFrontier =
            (canonicalHistory knownEvidence.commitTerm).take
              knownEvidence.commitFrontier := by
    intro knownEvidence supportedPrefix known
    have valid := knownCommitEvidenceValid evidenceAfter known
    have supportedPositive :=
      knownCommitEvidenceSupportedLengthPositive evidenceAfter known
    have frontierPositive : 0 < knownEvidence.commitFrontier := by
      exact supportedPositive.trans_le valid.2.2.1
    rcases
        entryAtSomeOfPositiveBound frontierPositive valid.1 with
      ⟨frontierEntry, historyFound⟩
    have frontierEntryTerm :
        frontierEntry.term = knownEvidence.commitTerm := by
      simpa [termAt, historyFound] using valid.2.1
    rcases
        configurationMajorityNonempty valid.2.2.2.2.2.1 with
      ⟨member, _authorityMember, ackMember⟩
    have memberCovered :=
      prospectiveAfter.currentMember
        knownEvidence supportedPrefix known member ackMember
    have prefixLength :
        (knownEvidence.history.take
            knownEvidence.commitFrontier).length =
          knownEvidence.commitFrontier := by
      simp [Nat.min_eq_left valid.1]
    have prefixFound :
        entryAt?
            (knownEvidence.history.take knownEvidence.commitFrontier)
            knownEvidence.commitFrontier =
          some frontierEntry := by
      rw [entryAtTake_of_le le_rfl]
      exact historyFound
    have memberFound :
        entryAt? ((nodeOf after) member).log knownEvidence.commitFrontier =
          some frontierEntry :=
      entryAt_of_prefix memberCovered prefixFound
    have memberAgreed :=
      (ownershipAfter.logEntryAgreement
        member knownEvidence.commitFrontier frontierEntry memberFound).2
    calc
      knownEvidence.history.take knownEvidence.commitFrontier
          = ((nodeOf after) member).log.take knownEvidence.commitFrontier := by
        have covered := prefixEqTake memberCovered
        rw [prefixLength] at covered
        exact covered.symm
      _ = (canonicalHistory frontierEntry.term).take knownEvidence.commitFrontier :=
        memberAgreed
      _ = (canonicalHistory knownEvidence.commitTerm).take
            knownEvidence.commitFrontier := by
        rw [frontierEntryTerm]
  have activationQuorumsAfter :
      ActivationQuorumFacts (joined := joinedNodes)
        after appendHistory newResponseHistory elections activations := by
    constructor
    · exact activationQuorums.history
    · intro bridgeSource index role current signature potential
        term record recorded newer
      exact Or.inl
        (recordBridgeAfter
          bridgeSource index role current signature potential
          term record recorded newer)
    · exact candidateBridgeAfter
    · intro bridgeSource index role current signature majority committed
      by_cases zero : ((nodeOf after) committed).commitIndex = 0
      · exact Or.inr (Or.inl (by
          simp [NodeState.committedLog, zero]))
      · have positive : 0 < ((nodeOf after) committed).commitIndex :=
          Nat.pos_of_ne_zero zero
        rcases evidenceAfter.nodePositive committed positive with
          ⟨committedEvidence, stored, valid, _lengthEq, _termBound⟩
        have known :
            KnownCommitEvidence
              after appendHistory newNodeEvidence requestEvidence
              committedEvidence ((nodeOf after) committed).committedLog :=
          Or.inl ⟨committed, positive, stored, rfl⟩
        by_cases termOrder :
            committedEvidence.commitTerm <=
              ((nodeOf after) bridgeSource).currentTerm
        · rcases
              configurationMajorityNonempty valid.2.2.2.2.2.1 with
            ⟨member, _authorityMember, ackMember⟩
          have committedInSource :
              ((nodeOf after) committed).committedLog <+:
                ((nodeOf after) bridgeSource).log :=
            (validEvidenceSupportedPrefixFrontier valid).trans
              (knownCommitEvidenceActiveLeaderContainsFrontier
                ownershipAfter electionFactsAfter evidenceAfter
                prospectiveAfter known role termOrder ackMember)
          rcases
              prefixesComparable
                (List.take_prefix index
                  ((nodeOf after) bridgeSource).log)
                committedInSource with
            direct | direct
          · exact Or.inl direct
          · exact Or.inr (Or.inl direct)
        · have sourceBefore :
              ((nodeOf after) bridgeSource).currentTerm <
                committedEvidence.commitTerm := by
            omega
          have canonicalEq :=
            knownEvidenceFrontierCanonicalAfter
              committedEvidence ((nodeOf after) committed).committedLog known
          have frontierPositive :
              0 < committedEvidence.commitFrontier := by
            have supportedPositive :=
              knownCommitEvidenceSupportedLengthPositive evidenceAfter known
            exact supportedPositive.trans_le valid.2.2.1
          rcases
              entryAtSomeOfPositiveBound frontierPositive valid.1 with
            ⟨frontierEntry, historyFound⟩
          have frontierEntryTerm :
              frontierEntry.term = committedEvidence.commitTerm := by
            simpa [termAt, historyFound] using valid.2.1
          have historyTakeFound :
              entryAt?
                  (committedEvidence.history.take
                    committedEvidence.commitFrontier)
                  committedEvidence.commitFrontier =
                some frontierEntry := by
            rw [entryAtTake_of_le le_rfl]
            exact historyFound
          have canonicalTakeFound :
              entryAt?
                  ((canonicalHistory committedEvidence.commitTerm).take
                    committedEvidence.commitFrontier)
                  committedEvidence.commitFrontier =
                some frontierEntry := by
            rw [← canonicalEq]
            exact historyTakeFound
          have canonicalFound :
              entryAt?
                  (canonicalHistory committedEvidence.commitTerm)
                  committedEvidence.commitFrontier =
                some frontierEntry := by
            rw [← entryAtTake_of_le
              (log := canonicalHistory committedEvidence.commitTerm)
              le_rfl]
            exact canonicalTakeFound
          rcases
              ownershipAfter.canonicalEntryOwner
                committedEvidence.commitTerm
                committedEvidence.commitFrontier
                frontierEntry canonicalFound with
            ⟨owner, owned⟩
          rw [frontierEntryTerm] at owned
          rcases
              electionFactsAfter.ownerRecorded
                committedEvidence.commitTerm owner owned with
            bootstrap | elected
          · have sourcePositive :=
              termsPositiveAfter bridgeSource (by rw [role]; decide)
            rw [bootstrap.1] at sourceBefore
            omega
          · rcases elected with
              ⟨record, recordStored, _recordLeader⟩
            have sourceInCanonical :
                ((nodeOf after) bridgeSource).log.take index <+:
                  canonicalHistory committedEvidence.commitTerm :=
              (recordBridgeAfter
                bridgeSource index role current signature
                (effectiveMajorityImpliesPotential
                  after appendHistory newResponseHistory
                    bridgeSource index majority)
                committedEvidence.commitTerm record recordStored
                sourceBefore).trans
                (electionFactsAfter.promotionCanonical
                  committedEvidence.commitTerm record recordStored)
            have committedInCanonical :
                ((nodeOf after) committed).committedLog <+:
                  canonicalHistory committedEvidence.commitTerm :=
              (validEvidenceSupportedPrefixFrontier valid).trans
                (by
                  rw [canonicalEq]
                  exact List.take_prefix _ _)
            rcases
                prefixesComparable
                  sourceInCanonical committedInCanonical with
              direct | direct
            · exact Or.inl direct
            · exact Or.inr (Or.inl direct)
    · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
        right rightIndex rightRole rightCurrent rightSignature rightMajority
      rcases Nat.lt_trichotomy
          ((nodeOf after) left).currentTerm
          ((nodeOf after) right).currentTerm with
        leftBefore | sameTerm | rightBefore
      · have rightOwned := ownershipAfter.activeLeader right rightRole
        rcases
            electionFactsAfter.ownerRecorded
              ((nodeOf after) right).currentTerm right rightOwned with
          bootstrap | elected
        · have leftPositive :=
            termsPositiveAfter left (by rw [leftRole]; decide)
          rw [bootstrap.1] at leftBefore
          omega
        · rcases elected with
            ⟨record, recordStored, _recordLeader⟩
          have leftInRight :
              ((nodeOf after) left).log.take leftIndex <+:
                ((nodeOf after) right).log :=
            (recordBridgeAfter
              left leftIndex leftRole leftCurrent leftSignature
              (effectiveMajorityImpliesPotential
                after appendHistory newResponseHistory
                  left leftIndex leftMajority)
              ((nodeOf after) right).currentTerm
              record recordStored leftBefore).trans
              ((electionFactsAfter.promotionCanonical
                ((nodeOf after) right).currentTerm record recordStored).trans
                (by rw [ownershipAfter.activeLeaderHistory right rightRole]))
          rcases
              prefixesComparable
                leftInRight
                (List.take_prefix rightIndex ((nodeOf after) right).log) with
            direct | direct
          · exact Or.inl direct
          · exact Or.inr (Or.inl direct)
      · have leftOwned := ownershipAfter.activeLeader left leftRole
        have rightOwned := ownershipAfter.activeLeader right rightRole
        rw [sameTerm] at leftOwned
        have sameNode : left = right :=
          Option.some.inj (leftOwned.symm.trans rightOwned)
        subst right
        rcases
            prefixesComparable
              (List.take_prefix leftIndex ((nodeOf after) left).log)
              (List.take_prefix rightIndex ((nodeOf after) left).log) with
          direct | direct
        · exact Or.inl direct
        · exact Or.inr (Or.inl direct)
      · have leftOwned := ownershipAfter.activeLeader left leftRole
        rcases
            electionFactsAfter.ownerRecorded
              ((nodeOf after) left).currentTerm left leftOwned with
          bootstrap | elected
        · have rightPositive :=
            termsPositiveAfter right (by rw [rightRole]; decide)
          rw [bootstrap.1] at rightBefore
          omega
        · rcases elected with
            ⟨record, recordStored, _recordLeader⟩
          have rightInLeft :
              ((nodeOf after) right).log.take rightIndex <+:
                ((nodeOf after) left).log :=
            (recordBridgeAfter
              right rightIndex rightRole rightCurrent rightSignature
              (effectiveMajorityImpliesPotential
                after appendHistory newResponseHistory
                  right rightIndex rightMajority)
              ((nodeOf after) left).currentTerm
              record recordStored rightBefore).trans
              ((electionFactsAfter.promotionCanonical
                ((nodeOf after) left).currentTerm record recordStored).trans
                (by rw [ownershipAfter.activeLeaderHistory left leftRole]))
          rcases
              prefixesComparable
                rightInLeft
                (List.take_prefix leftIndex ((nodeOf after) left).log) with
            direct | direct
          · exact Or.inr (Or.inl direct)
          · exact Or.inl direct
    · intro activationIndex activation queuedDestination queuedRequest
        stored queued sameTerm
      exact
        activationQuorums.queuedComparable
          activationIndex activation queuedDestination queuedRequest
          stored
          (appendRequestBack queuedDestination queuedRequest queued)
          sameTerm
    · exact committedCoverageAfter
    · exact queuedCoverageAfter
  have inheritedAuthorityEq :
      forall evidence supportedPrefix oldEvidence oldPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
            evidence supportedPrefix ->
        KnownCommitEvidence
            state appendHistory nodeEvidence requestEvidence
            oldEvidence oldPrefix ->
        evidence.history = oldEvidence.history ->
        evidence.commitFrontier = oldEvidence.commitFrontier ->
          evidence.authority = oldEvidence.authority := by
    intro evidence supportedPrefix oldEvidence oldPrefix
        known oldKnown historySame frontierSame
    have valid := knownCommitEvidenceValid evidenceAfter known
    have oldValid := knownCommitEvidenceValid evidenceFacts oldKnown
    calc
      evidence.authority
          = currentConfigurationAt evidence.history evidence.commitFrontier :=
        valid.2.2.2.2.1
      _ = currentConfigurationAt oldEvidence.history oldEvidence.commitFrontier := by
        rw [historySame, frontierSame]
      _ = oldEvidence.authority :=
        oldValid.2.2.2.2.1.symm
  have authorityRecordedAfter :
      forall evidence supportedPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
            evidence supportedPrefix ->
          evidence.authority = implicitConfiguration \/
            Exists fun activationIndex =>
              Exists fun record =>
                activations activationIndex = some record /\
                  evidence.authority ∈ record.governingActive /\
                  record.activationTerm <= evidence.commitTerm := by
    intro evidence supportedPrefix known
    rcases knownInherited evidence supportedPrefix known with
      ⟨oldEvidence, oldPrefix, oldKnown,
        termSame, historySame, frontierSame, _quorumSame, _supportedLe⟩
    have authoritySame :=
      inheritedAuthorityEq
        evidence supportedPrefix oldEvidence oldPrefix
          known oldKnown historySame frontierSame
    simpa [termSame, historySame, frontierSame, authoritySame]
      using activationEvidence.authorityRecorded oldEvidence oldPrefix oldKnown
  have authorityBridgeEvidenceAfter :
      forall earlier earlierPrefix,
        KnownCommitEvidence
            after appendHistory newNodeEvidence requestEvidence
            earlier earlierPrefix ->
        forall later laterPrefix,
          KnownCommitEvidence
              after appendHistory newNodeEvidence requestEvidence
              later laterPrefix ->
          earlier.authority.index < later.authority.index ->
            earlier.history.take earlier.commitFrontier <+:
              later.history.take later.commitFrontier := by
    intro earlier earlierPrefix earlierKnown
        later laterPrefix laterKnown order
    rcases knownInherited earlier earlierPrefix earlierKnown with
      ⟨oldEarlier, oldEarlierPrefix, oldEarlierKnown,
        _earlierTerm, earlierHistory, earlierFrontier,
        _earlierQuorum, _earlierSupported⟩
    rcases knownInherited later laterPrefix laterKnown with
      ⟨oldLater, oldLaterPrefix, oldLaterKnown,
        _laterTerm, laterHistory, laterFrontier,
        _laterQuorum, _laterSupported⟩
    have earlierAuthority :=
      inheritedAuthorityEq
        earlier earlierPrefix oldEarlier oldEarlierPrefix
          earlierKnown oldEarlierKnown earlierHistory earlierFrontier
    have laterAuthority :=
      inheritedAuthorityEq
        later laterPrefix oldLater oldLaterPrefix
          laterKnown oldLaterKnown laterHistory laterFrontier
    simpa [earlierHistory, earlierFrontier, laterHistory, laterFrontier]
      using activationEvidence.authorityBridge
        oldEarlier oldEarlierPrefix oldEarlierKnown
        oldLater oldLaterPrefix oldLaterKnown
        (by simpa [earlierAuthority, laterAuthority] using order)
  have activationEvidenceAfter :
      ActivationEvidenceFacts (joined := joinedNodes)
        after appendHistory newResponseHistory
          newNodeEvidence requestEvidence elections activations := by
    constructor
    · exact authorityRecordedAfter
    · intro left leftPrefix leftKnown right rightPrefix rightKnown same
      rcases knownInherited left leftPrefix leftKnown with
        ⟨oldLeft, oldLeftPrefix, oldLeftKnown,
          _leftTerm, leftHistory, leftFrontier,
          _leftQuorum, _leftSupported⟩
      rcases knownInherited right rightPrefix rightKnown with
        ⟨oldRight, oldRightPrefix, oldRightKnown,
          _rightTerm, rightHistory, rightFrontier,
          _rightQuorum, _rightSupported⟩
      have leftAuthority :=
        inheritedAuthorityEq
          left leftPrefix oldLeft oldLeftPrefix
            leftKnown oldLeftKnown leftHistory leftFrontier
      have rightAuthority :=
        inheritedAuthorityEq
          right rightPrefix oldRight oldRightPrefix
            rightKnown oldRightKnown rightHistory rightFrontier
      exact
        leftAuthority.trans
          ((activationEvidence.authorityIndexUnique
            oldLeft oldLeftPrefix oldLeftKnown
            oldRight oldRightPrefix oldRightKnown
            (by simpa [leftAuthority, rightAuthority] using same)).trans
            rightAuthority.symm)
    · exact authorityBridgeEvidenceAfter
    · intro left leftPrefix leftKnown right rightPrefix rightKnown
      rcases knownInherited left leftPrefix leftKnown with
        ⟨oldLeft, oldLeftPrefix, oldLeftKnown,
          _leftTerm, leftHistory, _leftFrontier,
          _leftQuorum, leftSupported⟩
      rcases knownInherited right rightPrefix rightKnown with
        ⟨oldRight, oldRightPrefix, oldRightKnown,
          _rightTerm, rightHistory, _rightFrontier,
          _rightQuorum, rightSupported⟩
      have leftRestricted :
          left.history.take left.supportedLength <+:
            oldLeft.history.take oldLeft.supportedLength := by
        rw [leftHistory, List.prefix_take_iff]
        exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans leftSupported⟩
      have rightRestricted :
          right.history.take right.supportedLength <+:
            oldRight.history.take oldRight.supportedLength := by
        rw [rightHistory, List.prefix_take_iff]
        exact ⟨List.take_prefix _ _, (List.length_take_le _ _).trans rightSupported⟩
      rcases
          activationEvidence.supportedPrefixesComparable
            oldLeft oldLeftPrefix oldLeftKnown
            oldRight oldRightPrefix oldRightKnown with
        oldLeftBefore | oldRightBefore
      · exact
          prefixesComparable
            (leftRestricted.trans oldLeftBefore) rightRestricted
      · rcases
            prefixesComparable
              leftRestricted (rightRestricted.trans oldRightBefore) with
          leftBefore | rightBefore
        · exact Or.inl leftBefore
        · exact Or.inr rightBefore
    · intro evidence supportedPrefix known candidate role majority newer
      let candidateConfiguration :=
        currentConfiguration ((nodeOf after) candidate)
      rcases Nat.lt_trichotomy
          evidence.authority.index candidateConfiguration.index with
        authorityBefore | sameIndex | candidateBeforeAuthority
      · have candidatePositive : 0 < candidateConfiguration.index := by
          omega
        have candidateConfigurationBound :
            candidateConfiguration.index <=
              ((nodeOf after) candidate).commitIndex := by
          simpa [candidateConfiguration]
            using currentConfiguration_index_le_commitIndex ((nodeOf after) candidate)
        have commitPositive :
            0 < ((nodeOf after) candidate).commitIndex :=
          candidatePositive.trans_le candidateConfigurationBound
        rcases evidenceAfter.nodePositive candidate commitPositive with
          ⟨candidateEvidence, candidateStored, candidateValid,
            candidateSupportedLength, _candidateTermBound⟩
        have candidateKnown :
            KnownCommitEvidence
              after appendHistory newNodeEvidence requestEvidence
              candidateEvidence ((nodeOf after) candidate).committedLog :=
          Or.inl ⟨candidate, commitPositive, candidateStored, rfl⟩
        have candidateConfigurationKnownCommitted :
            candidateConfiguration ∈
              allConfigurations ((nodeOf after) candidate).committedLog := by
          unfold NodeState.committedLog
          apply
            allConfigurations_mem_take_of_index_le
              ((nodeOf after) candidate).log
              ((nodeOf after) candidate).commitIndex
          · by_cases candidateEq : candidate = destination
            · subst candidate
              simpa [after, present, nodeOf_replaceNode]
                using post.commitIndexBounded (facts.commitIndicesBounded destination)
            · simpa [
                after, present, nodeOf_replaceNode, Function.update, candidateEq
              ] using facts.commitIndicesBounded candidate
          · simpa [candidateConfiguration]
              using currentConfiguration_mem_allConfigurations ((nodeOf after) candidate)
          · simpa [candidateConfiguration] using candidateConfigurationBound
        have committedInEvidence :
            ((nodeOf after) candidate).committedLog <+:
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
            exact candidateConfigurationBound
          have frontierBound :
              candidateConfiguration.index <=
                candidateEvidence.commitFrontier :=
            supportedBound.trans candidateValid.2.2.1
          let evidenceNode : NodeState Node TxId :=
            { (nodeOf after) candidate with
              log := candidateEvidence.history
              commitIndex := candidateEvidence.commitFrontier }
          have bound :=
            configuration_index_le_currentConfiguration
              evidenceNode candidateConfiguration
              (by simpa [evidenceNode] using candidateConfigurationKnownEvidence)
              frontierBound
          simpa [evidenceNode, currentConfiguration, candidateValid.2.2.2.2.1] using bound
        have evidenceBeforeCandidateEvidence :
            evidence.authority.index <
              candidateEvidence.authority.index :=
          authorityBefore.trans_le
            candidateConfigurationBeforeEvidenceAuthority
        have covered :=
          authorityBridgeEvidenceAfter
            evidence supportedPrefix known
            candidateEvidence ((nodeOf after) candidate).committedLog
              candidateKnown evidenceBeforeCandidateEvidence
        have valid := knownCommitEvidenceValid evidenceAfter known
        have evidenceFrontierBound :
            evidence.commitFrontier <=
              candidateEvidence.supportedLength := by
          by_contra outside
          have candidateIndexWithinSupported :
              candidateConfiguration.index <=
                candidateEvidence.supportedLength := by
            rw [candidateSupportedLength]
            simpa [candidateConfiguration]
              using currentConfiguration_index_le_commitIndex ((nodeOf after) candidate)
          have candidateIndexWithinEvidence :
              candidateConfiguration.index <= evidence.commitFrontier :=
            candidateIndexWithinSupported.trans
              (Nat.le_of_lt (Nat.lt_of_not_ge outside))
          have frontierWithinCandidateFrontier
              : evidence.commitFrontier <= candidateEvidence.commitFrontier := calc
            evidence.commitFrontier
                = (evidence.history.take evidence.commitFrontier).length := by
              simp [Nat.min_eq_left valid.1]
            _ <= (candidateEvidence.history.take
                    candidateEvidence.commitFrontier).length :=
              covered.length_le
            _ <= candidateEvidence.commitFrontier := by
              simp
          have evidenceFrontierWithinCandidateHistory :
              evidence.commitFrontier <= candidateEvidence.history.length :=
            frontierWithinCandidateFrontier.trans candidateValid.1
          have candidateKnownAtEvidenceFrontier :
              candidateConfiguration ∈
                allConfigurations
                  (candidateEvidence.history.take evidence.commitFrontier) :=
            allConfigurations_mem_take_of_index_le
              candidateEvidence.history evidence.commitFrontier
              evidenceFrontierWithinCandidateHistory
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
              { (nodeOf after) candidate with
                log := evidence.history
                commitIndex := evidence.commitFrontier }
            have maximal :=
              configuration_index_le_currentConfiguration
                evidenceNode candidateConfiguration
                (by simpa [evidenceNode] using candidateKnownEvidence)
                (by simpa [evidenceNode] using candidateIndexWithinEvidence)
            simpa [evidenceNode, currentConfiguration, valid.2.2.2.2.1] using maximal
          omega
        have coveredCommitted :
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
        exact Or.inl
          (coveredCommitted.trans
            (by
              rw [candidateValid.2.2.2.1]
              exact
                List.take_prefix
                  ((nodeOf after) candidate).commitIndex
                  ((nodeOf after) candidate).log))
      · have sameConfiguration :
            evidence.authority = candidateConfiguration := by
          by_cases zero : evidence.authority.index = 0
          · have valid := knownCommitEvidenceValid evidenceAfter known
            have evidenceKnown :
                evidence.authority ∈
                  allConfigurations evidence.history := by
              let evidenceNode : NodeState Node TxId :=
                { (nodeOf after) candidate with
                  log := evidence.history
                  commitIndex := evidence.commitFrontier }
              have knownConfiguration :=
                currentConfiguration_mem_allConfigurations evidenceNode
              simpa [
                evidenceNode, currentConfiguration,
                valid.2.2.2.2.1
              ] using knownConfiguration
            have evidenceImplicit :
                evidence.authority = implicitConfiguration := by
              apply
                allConfigurations_index_unique
                  (TxId := TxId) evidence.history
              · exact evidenceKnown
              · simp [allConfigurations, implicitConfiguration]
              · simpa [implicitConfiguration] using zero
            have candidateZero : candidateConfiguration.index = 0 := by
              simpa [sameIndex] using zero
            have candidateImplicit :
                candidateConfiguration = implicitConfiguration := by
              apply
                allConfigurations_index_unique
                  (TxId := TxId) ((nodeOf after) candidate).log
              · simpa [candidateConfiguration]
                  using currentConfiguration_mem_allConfigurations ((nodeOf after) candidate)
              · simp [allConfigurations, implicitConfiguration]
              · simpa [implicitConfiguration] using candidateZero
            exact evidenceImplicit.trans candidateImplicit.symm
          · rcases
                authorityRecordedAfter evidence supportedPrefix known with
              implicit | recordedAuthority
            · exact False.elim (zero (by rw [implicit]; rfl))
            · rcases recordedAuthority with
                ⟨authorityActivationIndex, authorityActivation,
                  authorityStored, authorityGoverning,
                  _activationTermBound⟩
              have candidatePositive :
                  0 < candidateConfiguration.index := by
                simpa [sameIndex] using Nat.pos_of_ne_zero zero
              rcases configurationCoverageAfter candidate
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
                have authorityAtOrBefore :=
                  activationGoverningConfigurationIndexLeNew
                    activationQuorums.history authorityStored
                    authorityGoverning
                simpa [candidateConfiguration, sameIndex] using authorityAtOrBefore
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
        exact Or.inr
          (by
            rw [sameConfiguration]
            simpa [candidateConfiguration]
              using currentConfiguration_mem_activeConfigurations ((nodeOf after) candidate))
      · rcases authorityRecordedAfter evidence supportedPrefix known with
          implicit | recordedAuthority
        · rw [implicit] at candidateBeforeAuthority
          simp [implicitConfiguration] at candidateBeforeAuthority
        · rcases recordedAuthority with
            ⟨authorityActivationIndex, authorityActivation,
              authorityStored, authorityGoverning,
              activationTermBound⟩
          have candidateBeforeActivation :
              candidateConfiguration.index <
                authorityActivation.newConfiguration.index := by
            exact candidateBeforeAuthority.trans_le
              (activationGoverningConfigurationIndexLeNew
                activationQuorums.history authorityStored
                authorityGoverning)
          have activationInCandidate :=
            activationPrefixInPotentialCandidateByCoverageAuthorityChain
              committedSignatureAfter entriesBoundedAfter snapshotsAfter
              voteCanonicalAfter ownershipAfter electionFactsAfter
              activationQuorums.history supporterCurrentAfter
              activationVoteHistoryAfter activationCanonical
              activationElectionsAfter configurationCoverageAfter
              role majority
              authorityActivation.newConfiguration.index
              authorityActivationIndex authorityActivation rfl
              authorityStored
              (activationTermBound.trans_lt newer)
          have authorityKnownCandidate :
              evidence.authority ∈
                allConfigurations ((nodeOf after) candidate).log := by
            apply
              memOfPrefix
                (allConfigurations_mono_prefix
                  (activationInCandidate.trans
                    (List.take_prefix
                      (maxCommittableIndex ((nodeOf after) candidate).log)
                      ((nodeOf after) candidate).log)))
            have valid :=
              activationQuorums.history.valid
                authorityActivationIndex authorityActivation authorityStored
            have governing := authorityGoverning
            rw [valid.2.2.2.2.2.2.1] at governing
            exact
              allConfigurations_mem_take_of_index_le
                authorityActivation.history
                authorityActivation.activationFrontier valid.2.1
                (List.mem_filter.mp governing).1
                (of_decide_eq_true
                  (List.mem_filter.mp governing).2).2
          exact Or.inr
            (by
              simpa [activeConfigurations, candidateConfiguration] using
                And.intro authorityKnownCandidate
                  candidateBeforeAuthority.le)
  have electionQueuedFactsAfter :
      ElectionQueuedHistoryFacts after appendHistory elections := by
    intro queuedDestination queuedRequest member record recorded
    exact
      electionQueuedFacts queuedDestination queuedRequest
        (appendRequestBack queuedDestination queuedRequest member)
        record recorded
  have configurationNodesAfter :
      forall node configuration,
        configuration ∈ allConfigurations ((nodeOf after) node).log ->
          configuration.nodes ⊆ joinedNodes := by
    intro node configuration member peer inNodes
    have joinedFromOld
        (oldMember :
          configuration ∈ allConfigurations ((nodeOf state) node).log) :
        peer ∈ joinedNodes := by
      simpa [after, present]
        using facts.joinedCarriers.configurationNodes node configuration oldMember inNodes
    by_cases same : node = destination
    · subst node
      have nextMember :
          configuration ∈ allConfigurations nextNode.log := by
        simpa [after, present, nodeOf_replaceNode] using member
      rcases post.logShape with unchanged | truncated | extended
      · apply joinedFromOld
        simpa [unchanged] using nextMember
      · apply joinedFromOld
        exact
          memOfPrefix
            (allConfigurations_mono_prefix
              (List.take_prefix request.2.2.prevLogIndex
                ((nodeOf state) destination).log))
            (by simpa [truncated] using nextMember)
      · have carried :
            configuration.nodes ⊆ joinedNodes :=
          allConfigurations_append_nodes_carried
            (((nodeOf state) destination).log.take request.2.2.prevLogIndex)
            request.2.2.entries joinedNodes
            (fun oldConfiguration oldMember =>
              facts.joinedCarriers.configurationNodes
                destination oldConfiguration
                  (memOfPrefix
                    (allConfigurations_mono_prefix
                      (List.take_prefix request.2.2.prevLogIndex
                        ((nodeOf state) destination).log))
                    oldMember))
            (facts.joinedCarriers.appendRequestConfigurations
              destination request requestMember)
            configuration
            (by simpa [extended] using nextMember)
        simpa [after, present] using carried inNodes
    · apply joinedFromOld
      simpa [after, present, nodeOf_replaceNode, Function.update, same] using member
  refine ⟨
    votes,
    appendHistory,
    newResponseHistory,
    voteRequestHistory,
    voteCandidateHistory,
    voteVoterHistory,
    ?_
  ⟩
  constructor
  · intro node
    by_cases same : node = destination
    · subst node
      simpa [after, present, nodeOf_replaceNode]
        using post.commitIndexBounded (facts.commitIndicesBounded destination)
    · simpa [after, present, nodeOf_replaceNode, Function.update, same]
        using facts.commitIndicesBounded node
  · intro node active
    change Not (((nodeOf after) node).role = .none) at active
    rw [termEq]
    exact
      facts.currentTermsPositive node
        (by simpa [roleEq] using active)
  · exact entriesBoundedAfter
  · intro candidate role
    have unchanged := activeNodeEq candidate (Or.inl role)
    have oldRole : ((nodeOf state) candidate).role = .candidate := by
      rw [roleEq] at role
      exact role
    rw [unchanged]
    exact facts.candidatesSelfVote candidate oldRole
  · intro leader role
    have unchanged := activeNodeEq leader (Or.inr role)
    have oldRole : ((nodeOf state) leader).role = .leader := by
      rw [roleEq] at role
      exact role
    rcases facts.leadersHaveElectionWitness leader oldRole with
      bootstrap | majority
    · left
      exact ⟨bootstrap.1, by rw [termEq]; exact bootstrap.2⟩
    · have unchangedNode :
          nodeOf after leader =
            (nodeOf state) leader := by
        simpa [after, present] using unchanged
      right
      change ∃ configuration ∈ allConfigurations (nodeOf after leader).log,
        hasConfigurationMajority (nodeOf after leader).votesGranted configuration
      simpa only [unchangedNode] using majority
  · intro leader role peer
    have unchanged := activeNodeEq leader (Or.inr role)
    have oldRole : ((nodeOf state) leader).role = .leader := by
      rw [roleEq] at role
      exact role
    rw [unchanged]
    exact facts.leaderProgressBounded leader oldRole peer
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [termEq, votedEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      exact facts.voteHistory.future voter term
        (by rw [termEq] at future; exact future)
    · intro candidate voter active member
      have unchanged := activeNodeEq candidate active
      have oldActive :
          ((nodeOf state) candidate).role = .candidate \/
            ((nodeOf state) candidate).role = .leader := by
        rw [roleEq] at active
        exact active
      have oldMember :
          voter ∈ ((nodeOf state) candidate).votesGranted := by
        rw [← unchanged]
        exact member
      rw [unchanged]
      exact facts.voteHistory.counted candidate voter oldActive oldMember
  · constructor
    · intro queuedDestination message member
      rcases
          memEnqueue
            (remaining)
            (appendResponseEnvelope response)
            message queuedDestination
            (by simpa [after, present, reply] using member) with
        old | new
      · have oldMember : (message ∈ state.network /\ message.target = queuedDestination) := by
          exact ⟨(selectedSound taken).2.2 _ old.1, old.2⟩
        exact facts.networkHistory.addressed
          queuedDestination message oldMember
      · rw [new.2]
        exact new.1.symm
    · intro queuedDestination queuedRequest member
      rcases
          facts.networkHistory.appendRequest
            queuedDestination queuedRequest
              (appendRequestBack queuedDestination queuedRequest member) with
        ⟨snapshot, commitBound, present⟩
      exact ⟨
        snapshot,
        commitBound,
        present.trans (committedMonotone queuedRequest.1)
      ⟩
    · intro queuedDestination queuedResponse member success
      rcases
          appendResponseMemAfterAppendRequestReceive
            state.network source destination request response queuedResponse
              remaining taken queuedDestination
              (by simpa [after, present] using member) with
        old | produced
      · by_cases same : queuedResponse = response
        · subst queuedResponse
          have responseLength :
              response.2.2.lastLogIndex <= (appendHistory request).length := by
            rw [post.successfulIndexExact success]
            exact (facts.networkHistory.appendRequest
                    destination request requestMember).1.1
          have responseTerm :
              response.2.2.term <=
                ((nodeOf after) response.2.1).currentTerm := by
            rw [responseDestination]
            have owned :=
              (ownership.queuedAppendMetadata
                destination request requestMember).2.1
            have progressed := (ownership.ownerProgress
              request.2.2.term request.1 owned).1
            rw [termEq]
            simpa [
              post.successfulResponseTerm success,
              post.successfulCurrentTerm success
            ] using progressed
          refine ⟨by simpa [newResponseHistory] using responseLength, responseTerm, ?_⟩
          intro sameTerm
          rw [termEq] at sameTerm
          have requestTerm :
              request.2.2.term =
                ((nodeOf state) request.1).currentTerm := by
            simpa [responseDestination, post.successfulResponseTerm success,
              post.successfulCurrentTerm success,]
              using sameTerm
          have sourceRole :=
            (ownership.ownerProgress request.2.2.term request.1
              (ownership.queuedAppendMetadata
              destination request requestMember).2.1).2 requestTerm
          have sourceNe : Not (request.1 = destination) := by
            simpa [requestDestination]
              using (ownership.queuedAppendMetadata destination request requestMember).1
          have unchanged :
              (nodeOf after) request.1 =
                (nodeOf state) request.1 := by
            simp [after, present, nodeOf_replaceNode, sourceNe]
          rcases sourceRole with leader | follower | preVoteCandidate
          · exact Or.inl
              ⟨by
                  rw [responseDestination, unchanged]
                  exact leader,
                by
                  rw [responseDestination, unchanged]
                  simpa [newResponseHistory] using
                    ownership.queuedActiveSourceHistory
                      destination request requestMember requestTerm leader⟩
          · exact Or.inr
              (Or.inl (by
                rw [responseDestination, unchanged]
                exact follower))
          · exact Or.inr
              (Or.inr (by
                rw [responseDestination, unchanged]
                exact preVoteCandidate))
        · rcases
              facts.networkHistory.appendResponse
                queuedDestination queuedResponse old success with
            ⟨lengthBound, termBound, supported⟩
          exact ⟨
            by simpa [newResponseHistory, Function.update, same] using lengthBound,
            by rw [termEq]; exact termBound,
            fun sameTerm => by
              have oldSame := sameTerm
              rw [termEq] at oldSame
              rcases supported oldSame with
                active | follower | preVoteCandidate
              · have afterRole :
                    ((nodeOf after) queuedResponse.2.1).role =
                      .leader := by
                  rw [roleEq]
                  exact active.1
                have unchanged :=
                  activeNodeEq queuedResponse.2.1
                    (Or.inr afterRole)
                exact Or.inl
                  ⟨by rw [unchanged]; exact active.1,
                    by
                      rw [unchanged]
                      simpa [
                        newResponseHistory, Function.update, same
                      ] using active.2⟩
              · exact Or.inr
                  (Or.inl (by rw [roleEq]; exact follower))
              · exact Or.inr
                  (Or.inr (by rw [roleEq]; exact preVoteCandidate))
          ⟩
      · rcases produced with ⟨destinationEq, responseEq⟩
        subst queuedDestination
        subst queuedResponse
        have responseLength :
            response.2.2.lastLogIndex <= (appendHistory request).length := by
          rw [post.successfulIndexExact success]
          exact (facts.networkHistory.appendRequest destination request requestMember).1.1
        have responseTerm :
            response.2.2.term <=
              ((nodeOf after) response.2.1).currentTerm := by
          rw [responseDestination]
          have progressed :=
            (ownership.ownerProgress request.2.2.term request.1
              (ownership.queuedAppendMetadata
                destination request requestMember).2.1).1
          rw [termEq]
          simpa [
            post.successfulResponseTerm success,
            post.successfulCurrentTerm success
          ] using progressed
        refine ⟨by simpa [newResponseHistory] using responseLength, responseTerm, ?_⟩
        intro sameTerm
        rw [termEq] at sameTerm
        have requestTerm :
            request.2.2.term =
              ((nodeOf state) request.1).currentTerm := by
          simpa [responseDestination, post.successfulResponseTerm success,
            post.successfulCurrentTerm success,]
            using sameTerm
        have sourceRole :=
          (ownership.ownerProgress request.2.2.term request.1
            (ownership.queuedAppendMetadata
              destination request requestMember).2.1).2 requestTerm
        have sourceNe : Not (request.1 = destination) := by
          simpa [requestDestination]
            using (ownership.queuedAppendMetadata destination request requestMember).1
        have unchanged :
            (nodeOf after) request.1 =
              (nodeOf state) request.1 := by
          simp [after, present, nodeOf_replaceNode, sourceNe]
        rcases sourceRole with leader | follower | preVoteCandidate
        · exact Or.inl
            ⟨by
                rw [responseDestination, unchanged]
                exact leader,
              by
                rw [responseDestination, unchanged]
                simpa [newResponseHistory] using
                  ownership.queuedActiveSourceHistory
                    destination request requestMember requestTerm leader⟩
        · exact Or.inr
            (Or.inl (by
              rw [responseDestination, unchanged]
              exact follower))
        · exact Or.inr
            (Or.inr (by
              rw [responseDestination, unchanged]
              exact preVoteCandidate))
    · intro queuedDestination queuedRequest member
      rcases
          facts.networkHistory.voteRequest
            queuedDestination queuedRequest
              ((voteRequestEq queuedDestination queuedRequest).mp member) with
        ⟨lastIndex, lastTerm, maxIndex, above, bounded, activePrefix⟩
      exact ⟨
        lastIndex,
        lastTerm,
        maxIndex,
        above,
        by rw [termEq]; exact bounded,
        fun sameTerm active => by
          have unchanged := activeNodeEq queuedRequest.1 active
          have oldSame := sameTerm
          rw [termEq] at oldSame
          have oldActive := active
          rw [roleEq] at oldActive
          rw [unchanged]
          exact activePrefix oldSame oldActive
      ⟩
    · intro queuedDestination queuedResponse member granted
      rcases
          facts.networkHistory.voteResponse
            queuedDestination queuedResponse
              ((voteResponseEq queuedDestination queuedResponse).mp member)
              granted with
        ⟨bounded, recorded, candidateCommittable,
          voterCommittable, upToDate⟩
      exact ⟨
        by rw [termEq]; exact bounded,
        recorded,
        candidateCommittable,
        voterCommittable,
        by simpa [voteLogUpToDate] using upToDate
      ⟩
  · exact ⟨
      owners,
      canonicalHistory,
      elections,
      activations,
      newNodeEvidence,
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
      electionQueuedFactsAfter,
      activationProgressAfter,
      activationQuorumsAfter,
      evidenceAfter,
      prospectiveAfter,
      activationEvidenceAfter,
      activationCanonical,
      activationElectionsAfter,
      configurationCoverageAfter
    ⟩
  · exact snapshotsAfter
  · exact ⟨ackHistory, processedAckAfter⟩
  · constructor
    · intro node
      exact
        activeNodeUnion_subset_of_allConfigurations_carrier
          ((nodeOf after) node) joinedNodes
            (configurationNodesAfter node)
    · exact configurationNodesAfter
    · intro node peer member
      simpa [after, present]
        using facts.joinedCarriers.grantedVotes node
          (by rw [← votesEq node]; exact member)
    · intro queuedDestination queuedRequest member
      simpa [after, present]
        using facts.joinedCarriers.voteRequestDestinations
          queuedDestination queuedRequest
          ((voteRequestEq queuedDestination queuedRequest).mp member)
    · intro queuedDestination queuedRequest member
      simpa [after, present]
        using facts.joinedCarriers.appendRequestDestinations
          queuedDestination queuedRequest
          (appendRequestBack queuedDestination queuedRequest member)
    · intro queuedDestination queuedRequest member
        configuration configured peer inNodes
      simpa [after, present]
        using facts.joinedCarriers.appendRequestConfigurations
          queuedDestination queuedRequest
          (appendRequestBack queuedDestination queuedRequest member)
          configuration configured inNodes
    · intro queuedDestination queuedResponse member
      simpa [after, present]
        using facts.joinedCarriers.voteResponseSources
          queuedDestination queuedResponse
          ((voteResponseEq queuedDestination queuedResponse).mp member)
    · constructor
      · intro node active
        have oldActive :
            ((nodeOf state) node).role = .candidate \/
              ((nodeOf state) node).role = .leader := by
          rcases active with candidate | leader
          · exact Or.inl (by
              rw [roleEq node] at candidate
              exact candidate)
          · exact Or.inr (by
              rw [roleEq node] at leader
              exact leader)
        simpa [after, present] using facts.joinedCarriers.runtimeNodes.activeRoles node oldActive
      · intro leader peer positive
        have oldPositive :
            0 < ((nodeOf state) leader).matchIndex peer := by
          rw [matchEq leader] at positive
          exact positive
        simpa [after, present]
          using facts.joinedCarriers.runtimeNodes.positiveMatches leader peer oldPositive
      · intro queuedDestination queuedResponse member
        rcases
            memEnqueue
              (remaining)
              (appendResponseEnvelope response)
              (appendResponseEnvelope queuedResponse) queuedDestination
              (by simpa [after, present, reply] using member) with
          old | new
        · have oldMember :
              (appendResponseEnvelope queuedResponse ∈ state.network /\ queuedResponse.2.1 = queuedDestination) := by
            exact ⟨(selectedSound taken).2.2 _ old.1, old.2⟩
          simpa [after, present]
            using facts.joinedCarriers.runtimeNodes.appendResponses
              queuedDestination queuedResponse oldMember
        · rcases new with ⟨_, responseEq⟩
          have sameResponse : queuedResponse = response := by
            exact appendResponseEnvelope.injEq.mp responseEq
          subst queuedResponse
          simpa [after, present, responseSource, requestDestination]
            using facts.joinedCarriers.appendRequestDestinations
              destination request requestMember
      · intro node nonempty
        by_cases same : node = destination
        · subst node
          simpa [after, present]
            using facts.joinedCarriers.appendRequestDestinations
              destination request requestMember
        · simpa [after, present]
            using facts.joinedCarriers.runtimeNodes.nonemptyLogs node (by
              intro empty
              apply nonempty
              simpa [after, present, nodeOf_replaceNode, Function.update, same] using empty)
  · intro node
    change TermNumberValid ((nodeOf after) node).currentTerm
    simpa only [termEq] using facts.currentTermsValid node
  · have responseValid : TermNumberValid response.2.2.term := by
      by_cases success : response.2.2.success = true
      · rw [post.successfulResponseTerm success]
        exact facts.currentTermsValid destination
      · rw [post.failedResponse (Bool.eq_false_of_not_eq_true success)]
        unfold failureResponse
        dsimp only
        split_ifs <;> first
        | exact facts.currentTermsValid destination
        | exact nodeLogTermNumberValid ownership electionFacts destination _
    simpa only [NetworkTermsValid, after, present, reply]
      using (networkTermsValidEnqueue
              (message := appendResponseEnvelope response)
              (networkTermsValidDequeue facts.networkTermsValid taken)
              responseValid)

/-- Recalculate retirement metadata after a successful AppendEntries receive. -/
lemma receiveAppendEntriesRequestWithRetirementPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (source destination : Node)
    {present : destination ∈ state.nodes.map Prod.fst}
    (request : AppendRequestKey Node TxId)
    (remaining : List (Model.Envelope Node TxId))
    (nextNode : NodeState Node TxId)
    (response : AppendResponseKey Node)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (_destinationAllocated : destination ∈ joinedNodes)
    (addressed : request.2.1 = destination)
    (taken
      : Selected source state.network (appendRequestEnvelope request)
          remaining)
    (notStepped : ¬ (request.2.2.term = (nodeOf state destination).currentTerm ∧ ((nodeOf state destination).role = .candidate ∨ (nodeOf state destination).role = .preVoteCandidate)))
    (responseSource : response.1 = request.2.1)
    (responseDestination : response.2.1 = request.1)
    (handled
      : handleAppendEntriesRequest? request.2.1 ((nodeOf state) destination) request.2.2
        = some (nextNode, response.2.2))
    : SystemInductiveInvariant (joined := joinedNodes)
        {
          state with
            nodes :=
              replaceNode state.nodes destination
                (refreshRetirementState destination nextNode)
            network := (reply remaining response)
        } := by
  let beforeRefresh : Model.State Node TxId :=
    { state with
      nodes := replaceNode state.nodes destination nextNode
      network := (reply remaining response) }
  let after : Model.State Node TxId :=
    { state with
      nodes :=
        replaceNode state.nodes destination
          (refreshRetirementState destination nextNode)
      network := (reply remaining response)
      }
  have beforeInvariant :
      SystemInductiveInvariant (joined := joinedNodes) beforeRefresh := by
    simpa [beforeRefresh, present]
      using receiveAppendEntriesRequestPreservesSystemInductiveInvariant (present := present)
        state source destination request remaining nextNode response
        invariant addressed taken notStepped responseSource responseDestination handled
  change SystemInductiveInvariant (joined := joinedNodes) after
  apply
    retirementMetadataFramePreservesSystemInductiveInvariant
      beforeRefresh after beforeInvariant rfl
  · rfl
  · intro candidate
    by_cases same : candidate = destination <;>
      simp [beforeRefresh, present, after, present, nodeOf_replaceNode, same]
  · intro candidate
    by_cases same : candidate = destination <;>
      simp [beforeRefresh, present, after, present, nodeOf_replaceNode, same]
  · intro candidate
    by_cases same : candidate = destination <;>
      simp [beforeRefresh, present, after, present, nodeOf_replaceNode, same]
  · intro candidate
    by_cases same : candidate = destination <;>
      simp [beforeRefresh, present, after, present, nodeOf_replaceNode, same]
  · intro candidate
    by_cases same : candidate = destination <;>
      simp [beforeRefresh, present, after, present, nodeOf_replaceNode, same]
  · intro candidate
    by_cases same : candidate = destination <;>
      simp [beforeRefresh, present, after, present, nodeOf_replaceNode, same]
  · intro candidate
    by_cases same : candidate = destination <;>
      simp [beforeRefresh, present, after, present, nodeOf_replaceNode, same]
  · intro candidate
    by_cases same : candidate = destination <;>
      simp [beforeRefresh, present, after, present, nodeOf_replaceNode, same]
  · intro candidate
    by_cases same : candidate = destination <;>
      simp [
        beforeRefresh, present, after, present, nodeOf_replaceNode, same
      ]

end CCFRaft.Proofs.Invariant
