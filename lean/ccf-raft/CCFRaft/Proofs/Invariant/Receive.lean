-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Internal
import CCFRaft.Proofs.Invariant.Handlers

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open Shared Concrete
open Model.Local (Bootstrap NodeState Role refreshRetirementState)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

@[simp]
theorem updateNode_updateNode (nodes : Node -> NodeState Node TxId) (node : Node)
    (first second : NodeState Node TxId)
    : updateNode (updateNode nodes node first) node second
      = updateNode nodes node second := by
  simp [updateNode]

/-- Term observation leaves the message queued for its handler. -/
theorem observeTerm_preserves {state : View Node TxId} (invariant : ViewInvariant state)
    (envelope : Model.Envelope Node TxId)
    (queued : toMessage envelope ∈ state.network envelope.target)
    : ViewInvariant
        {
          state with
            nodes :=
              updateNode state.nodes envelope.target
                (Model.Local.observeTerm (state.nodes envelope.target) envelope.payload)
        } := by
  have joined : envelope.target ∈ state.hasJoined := by
    simpa using (invariant.endpoints _ _ queued).2
  apply invariant.update joined (Finset.Subset.refl _) ?_ invariant.endpoints
  rcases observeTerm_eq_updateTerm (state.nodes envelope.target) envelope.payload with
    same | ⟨updated, newer, _⟩
  · simpa [same] using invariant.safety
  · have preserved := updateTermPreservesSystemInductiveInvariant
      state envelope.target (toMessage envelope) invariant.safety queued
      (by simpa using newer)
    simpa [view_effects, updated, Model.Local.updateTerm, newer] using preserved

theorem ViewInvariant.receivedEndpoints {state : View Node TxId}
    (invariant : ViewInvariant state) {envelope : Model.Envelope Node TxId}
    (queued : toMessage envelope ∈ state.network envelope.target)
    {sends : List (Model.Envelope Node TxId)}
    (replies
      : forall sent,
          sent ∈ sends -> sent.source = envelope.target /\ sent.target = envelope.source)
    : forall destination message,
        message
          ∈ updateQueue state.network envelope.target
              ((state.network envelope.target).erase (toMessage envelope)) destination
            ++ messagesAt sends destination
        -> message.source ∈ state.hasJoined /\ message.destination ∈ state.hasJoined := by
  intro destination message member
  rcases List.mem_append.mp member with old | outgoing
  · exact invariant.erasedEndpoints _ _ destination message old
  · obtain ⟨sent, listed, rfl⟩ := List.mem_map.mp outgoing
    obtain ⟨source, target⟩ := replies sent (List.mem_filter.mp listed).1
    obtain ⟨senderJoined, receiverJoined⟩ := invariant.endpoints _ _ queued
    simpa [source, target] using And.intro receiverJoined senderJoined

/-- Same-term step-down and the AppendEntries handler compose without dequeuing twice. -/
theorem appendRequest_safety {state : View Node TxId}
    (invariant : SystemInductiveInvariant state) {source destination : Node}
    (joined : state.allocated destination)
    {request : Model.Local.AppendEntriesRequest Node TxId}
    (queued
      : Message.appendEntriesRequest (annotateAppendRequest request source destination)
        ∈ state.network destination)
    {nextNode : NodeState Node TxId} {response : Model.Local.AppendEntriesResponse}
    (handled
      : Model.Local.handleAppendEntriesRequest? destination (state.nodes destination)
          request
        = some (nextNode, response))
    : SystemInductiveInvariant
        {
          state with
            nodes :=
              updateNode state.nodes destination
                (refreshRetirementState destination nextNode)
            network :=
              reply state.network destination
                ((state.network destination).erase
                  (.appendEntriesRequest
                    (annotateAppendRequest request source destination)))
                (annotateAppendResponse response destination source)
        } := by
  let middle : View Node TxId :=
    { state with nodes := updateNode state.nodes destination (stepDown (state.nodes destination) request) }
  have middleInvariant : SystemInductiveInvariant middle := by
    by_cases stepping : request.term = (state.nodes destination).currentTerm /\
        ((state.nodes destination).role = .candidate \/ (state.nodes destination).role = .preVoteCandidate)
    · exact returnToFollowerPreservesSystemInductiveInvariant
        state destination (annotateAppendRequest request source destination) _ invariant joined
        (by simp [returnToFollower_eq, stepping])
    · simpa [middle, stepDown, stepping] using invariant
  have noStep : ¬(request.term = (middle.nodes destination).currentTerm /\
      ((middle.nodes destination).role = .candidate \/ (middle.nodes destination).role = .preVoteCandidate)) := by
    simpa [middle] using stepDown_noStepDown (state.nodes destination) request
  have handledMiddle : handleAppendEntriesRequest? (middle.nodes destination)
      (annotateAppendRequest request source destination) =
        some (nextNode, annotateAppendResponse response destination source) := by
    rw [handleAppendEntriesRequest_eq _ _ _ _ noStep]
    have localHandled : Model.Local.handleAppendEntriesRequest? destination (middle.nodes destination) request
        = some (nextNode, response) := by
      simpa only [middle, updateNode_same, ← handleAppendEntriesRequest_stepDown]
        using handled
    simp [localHandled, annotateResult]
  have preserved := receiveAppendEntriesRequestWithRetirementPreservesSystemInductiveInvariant
    middle source destination (annotateAppendRequest request source destination) _ nextNode
    (annotateAppendResponse response destination source) middleInvariant joined
    (show Selected source (middle.network destination)
      (.appendEntriesRequest (annotateAppendRequest request source destination))
      ((state.network destination).erase (.appendEntriesRequest
        (annotateAppendRequest request source destination))) from ⟨rfl, queued, rfl⟩)
    (by simp [returnToFollower_eq, noStep]) handledMiddle
  simpa [middle] using preserved

theorem handleProposeVoteRequest_eq (state : View Node TxId) (source destination : Node)
    (term : Nat) (joined : state.allocated destination)
    : handleProposeVoteRequest? state destination { term, source, destination }
      = some
          (Model.Local.handleProposeVoteRequest (state.nodes destination) destination
            term) := by
  have eligible : candidateTransitionEnabled state destination
      ↔ Model.Local.candidateTransitionEnabled (state.nodes destination) destination := by
    simp [candidateTransitionEnabled, Model.Local.candidateTransitionEnabled, joined]
  simp only [handleProposeVoteRequest?, Model.Local.handleProposeVoteRequest, eligible]
  split_ifs <;> rfl

/-- A delivery observes the term, handles its message, erases it, and appends any reply. -/
theorem receive_preserves {state : View Node TxId} (invariant : ViewInvariant state)
    {envelope : Model.Envelope Node TxId}
    {execute : Model.Local.NodeEffect Node TxId (NodeState Node TxId)}
    (queued : toMessage envelope ∈ state.network envelope.target)
    (received
      : Model.Local.receive (Capabilities.record envelope.target) envelope.target
          envelope.source (state.nodes envelope.target) envelope.payload
        = some execute)
    : ViewInvariant
        {
          nodes := updateNode state.nodes envelope.target (execute.run {}).1
          network :=
            fun destination =>
              updateQueue state.network envelope.target
                ((state.network envelope.target).erase (toMessage envelope)) destination
              ++ messagesAt (execute.run {}).2.outgoing destination
          hasJoined := state.hasJoined
        } := by
  have joined : envelope.target ∈ state.hasJoined := by
    simpa using (invariant.endpoints _ _ queued).2
  let beforeHandler : View Node TxId :=
    { state with
      nodes := updateNode state.nodes envelope.target
        (Model.Local.observeTerm (state.nodes envelope.target) envelope.payload) }
  have prepared : ViewInvariant beforeHandler := observeTerm_preserves invariant envelope queued
  have receiver : beforeHandler.nodes envelope.target =
      Model.Local.observeTerm (state.nodes envelope.target) envelope.payload := by
    simp [beforeHandler]
  have taken : Selected envelope.source (beforeHandler.network envelope.target) (toMessage envelope)
      ((state.network envelope.target).erase (toMessage envelope)) :=
    ⟨toMessage_source _, queued, rfl⟩
  rcases envelope with ⟨source, destination, payload⟩
  cases payload with
  | appendEntriesRequest request =>
      simp only [Model.Local.receive] at received
      obtain ⟨⟨nextNode, response⟩, handled, done⟩ := Option.bind_eq_some_iff.mp received
      have done := Option.some.inj done
      subst done
      change ViewInvariant
        { nodes := updateNode state.nodes destination (refreshRetirementState destination nextNode)
          network := fun target =>
            updateQueue state.network destination
              ((state.network destination).erase
                (toMessage ⟨source, destination, .appendEntriesRequest request⟩)) target
            ++ messagesAt [⟨destination, source, .appendEntriesResponse response⟩] target
          hasJoined := state.hasJoined }
      apply invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.receivedEndpoints queued ?_)
      · have preserved := appendRequest_safety prepared.safety joined (by exact queued)
          (by rw [receiver]; exact handled)
        simpa [beforeHandler, append_messagesAt_singleton, toMessage, reply,
          annotateAppendRequest, annotateAppendResponse] using preserved
      · intro sent member
        simp only [List.mem_singleton] at member
        subst sent
        exact ⟨rfl, rfl⟩
  | appendEntriesResponse response =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      simp only [Direct.run_pure, messagesAt_nil, List.append_nil]
      apply invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.erasedEndpoints _ _)
      have bounded : (beforeHandler.nodes destination).role = .leader ->
          response.term <= (beforeHandler.nodes destination).currentTerm := by
        rw [receiver]
        simp only [Model.Local.observeTerm]
        split_ifs with leader
        · intro _
          exact updateTerm_bounded _ _
        · intro isLeader
          exact absurd isLeader leader
      have preserved := receiveAppendEntriesResponsePreservesSystemInductiveInvariant
        beforeHandler source destination (annotateAppendResponse response source destination) _ _
        prepared.safety joined taken rfl (handleAppendEntriesResponse_eq _ _ _ _ bounded)
      simpa [beforeHandler, toMessage, annotateAppendResponse] using preserved
  | requestVoteRequest request =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      let answer := Model.Local.handleRequestVoteRequest
        (Model.Local.observeTerm (state.nodes destination) (.requestVoteRequest request)) source request
      change ViewInvariant
        { nodes := updateNode state.nodes destination answer.1
          network := fun target =>
            updateQueue state.network destination
              ((state.network destination).erase
                (toMessage ⟨source, destination, .requestVoteRequest request⟩)) target
            ++ messagesAt [⟨destination, source, .requestVoteResponse answer.2⟩] target
          hasJoined := state.hasJoined }
      apply invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.receivedEndpoints queued ?_)
      · have bounded : request.term <= (beforeHandler.nodes destination).currentTerm := by
          rw [receiver]
          exact updateTerm_bounded _ _
        have preserved := receiveRequestVoteRequestPreservesSystemInductiveInvariant
          beforeHandler source destination (annotateVoteRequest request source destination) _ _ _
          prepared.safety joined taken (handleRequestVoteRequest_eq _ _ _ _ bounded)
        simpa [answer, beforeHandler, append_messagesAt_singleton, toMessage,
          annotateVoteRequest, annotateVoteResponse] using preserved
      · intro sent member
        simp only [List.mem_singleton] at member
        subst sent
        exact ⟨rfl, rfl⟩
  | requestVoteResponse response =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      simp only [Direct.run_pure, messagesAt_nil, List.append_nil]
      apply invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.erasedEndpoints _ _)
      have bounded : response.term <= (beforeHandler.nodes destination).currentTerm := by
        rw [receiver]
        exact updateTerm_bounded _ _
      have preserved := receiveRequestVoteResponsePreservesSystemInductiveInvariant
        beforeHandler source destination (annotateVoteResponse response source destination) _ _
        prepared.safety joined taken rfl (handleRequestVoteResponse_eq _ _ _ _ bounded)
      simpa [beforeHandler, toMessage, annotateVoteResponse] using preserved
  | requestPreVote request =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      let observedNode := Model.Local.observeTerm (state.nodes destination) (.requestPreVote request)
      change ViewInvariant
        { nodes := updateNode state.nodes destination observedNode
          network := fun target =>
            updateQueue state.network destination
              ((state.network destination).erase
                (toMessage ⟨source, destination, .requestPreVote request⟩)) target
            ++ messagesAt [⟨destination, source,
              .requestPreVoteResponse (Model.Local.handleRequestPreVote observedNode request)⟩] target
          hasJoined := state.hasJoined }
      apply invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.receivedEndpoints queued ?_)
      · have bounded : request.term <= (beforeHandler.nodes destination).currentTerm := by
          rw [receiver]
          exact updateTerm_bounded _ _
        have preserved := receiveRequestPreVotePreservesSystemInductiveInvariant
          beforeHandler source destination (annotatePreVote request source destination) _ _ _
          prepared.safety joined taken (handleRequestPreVote_eq _ _ _ _ bounded)
        simpa [observedNode, beforeHandler, append_messagesAt_singleton, toMessage,
          annotatePreVote, annotatePreVoteResponse] using preserved
      · intro sent member
        simp only [List.mem_singleton] at member
        subst sent
        exact ⟨rfl, rfl⟩
  | requestPreVoteResponse response =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      simp only [Direct.run_pure, messagesAt_nil, List.append_nil]
      apply invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.erasedEndpoints _ _)
      have bounded : response.term <= (beforeHandler.nodes destination).currentTerm := by
        rw [receiver]
        exact updateTerm_bounded _ _
      have preserved := receiveRequestPreVoteResponsePreservesSystemInductiveInvariant
        beforeHandler source destination (annotatePreVoteResponse response source destination) _ _
        prepared.safety joined taken (handleRequestPreVoteResponse_eq _ _ _ _ bounded)
      simpa [beforeHandler, toMessage, annotatePreVoteResponse] using preserved
  | proposeVoteRequest term =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      simp only [Direct.run_pure, messagesAt_nil, List.append_nil]
      apply invariant.update joined (Finset.Subset.refl _) ?_
        (invariant.erasedEndpoints _ _)
      have preserved := receiveProposeVoteRequestPreservesSystemInductiveInvariant
        beforeHandler source destination { term, source, destination } _ _
        prepared.safety joined taken (handleProposeVoteRequest_eq _ _ _ _ joined)
      simpa [beforeHandler, toMessage] using preserved

end CCFRaft.Proofs.Invariant
