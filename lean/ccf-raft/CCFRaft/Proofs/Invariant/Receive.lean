-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Internal

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Proofs.Config

open Shared Shared.MultiNodeTransitionSystem Concrete
open Model.Local

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node]

theorem observeTerm_preserves {state : Model.State Node TxId} {joined : Finset Node}
    (invariant : StateInvariant state joined) (envelope : Model.Envelope Node TxId)
    (present : envelope.target ∈ state.nodes.map Prod.fst)
    (queued : envelope ∈ state.network)
    : StateInvariant
        {
          state with
            nodes :=
              replaceNode state.nodes envelope.target
                (observeTerm (nodeOf state envelope.target) envelope.payload)
        } joined := by
  apply invariant.update (invariant.endpoints envelope queued).2 (Finset.Subset.refl _) ?_
    invariant.endpoints
  rcases observeTerm_eq_updateTerm (nodeOf state envelope.target) envelope.payload with
    same | ⟨updated, newer, _⟩
  · simpa only [same, replaceNode_nodeOf state envelope.target invariant.distinct] using invariant.safety
  · simpa only [concrete_effects, updated]
      using updateTermPreservesSystemInductiveInvariant state envelope.target
        (present := present) envelope invariant.safety ⟨queued, rfl⟩ newer

theorem StateInvariant.receivedEndpoints {state : Model.State Node TxId}
    {joined : Finset Node} (invariant : StateInvariant state joined)
    {envelope : Model.Envelope Node TxId} (queued : envelope ∈ state.network)
    {sends : List (Model.Envelope Node TxId)}
    (replies
      : forall sent,
          sent ∈ sends -> sent.source = envelope.target ∧ sent.target = envelope.source)
    : forall sent,
        sent ∈ removeOne envelope state.network ++ sends
        -> sent.source ∈ joined ∧ sent.target ∈ joined := by
  intro sent member
  rcases List.mem_append.mp member with old | outgoing
  · exact invariant.erasedEndpoints envelope sent old
  · obtain ⟨source, target⟩ := replies sent outgoing
    obtain ⟨senderJoined, receiverJoined⟩ := invariant.endpoints envelope queued
    exact ⟨source ▸ receiverJoined, target ▸ senderJoined⟩

theorem run_ite {σ α : Type} {c : Prop} [Decidable c] {a b : StateT σ Option α} {s : σ}
    {r : α × σ} (run : (if c then a else b).run s = some r)
    : (c ∧ a.run s = some r) ∨ (¬c ∧ b.run s = some r) := by
  by_cases h : c <;> simp_all

theorem observeTerm_appendRequest_term (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : request.term ≤ (observeTerm state (.appendEntriesRequest request)).currentTerm := by
  simp only [observeTerm, updateTerm]
  split_ifs with newer
  · simp [Message.term]
  · simp [Message.term] at newer ⊢
    omega

theorem handleAppendEntriesRequest_stepped {self : Node} {state : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    (stepping
      : request.term = state.currentTerm
        ∧ (state.role = .candidate ∨ state.role = .preVoteCandidate))
    : handleAppendEntriesRequest (inferInstance) self state request
      = handleAppendEntriesRequest (inferInstance) self
          { state with role := .follower, isNewFollower := true } request := by
  conv_lhs => unfold handleAppendEntriesRequest
  conv_rhs => unfold handleAppendEntriesRequest
  simp only [stepping, reduceCtorEq, or_self, and_false, and_true, ↓reduceIte]

/-- A non-stepping AE request either replies through the checked handler or is dropped. -/
theorem appendRequest_unstepped {state : Model.State Node TxId} {joined : Finset Node}
    (invariant : SystemInductiveInvariant (joined := joined) state)
    {source destination : Node} (present : destination ∈ state.nodes.map Prod.fst)
    (nodeJoined : destination ∈ joined) {request : AppendEntriesRequest Node TxId}
    (queued : appendRequestEnvelope (source, destination, request) ∈ state.network)
    (notNewer : request.term ≤ (nodeOf state destination).currentTerm)
    (notStepped
      : ¬ (request.term = (nodeOf state destination).currentTerm
            ∧ ((nodeOf state destination).role = .candidate
                ∨ (nodeOf state destination).role = .preVoteCandidate)))
    {nextNode : NodeState Node TxId} {response : Option AppendEntriesResponse}
    (handled
      : handleAppendEntriesRequest (inferInstance) destination (nodeOf state destination)
          request
        = (nextNode, response))
    : SystemInductiveInvariant (joined := joined)
        {
          state with
            nodes :=
              replaceNode state.nodes destination
                (refreshRetirementState (inferInstance) destination nextNode)
            network :=
              removeOne (appendRequestEnvelope (source, destination, request))
                state.network
              ++ (response.map
                    fun answer =>
                      appendResponseEnvelope (destination, source, answer)).toList
        } := by
  rcases handleAppendEntriesRequest_option notNewer notStepped handled with
    ⟨answer, rfl, accepted⟩ | ⟨rfl, -, rfl⟩
  · simpa [reply] using receiveAppendEntriesRequestWithRetirementPreservesSystemInductiveInvariant
      state source destination (present := present) (source, destination, request) _
      nextNode (destination, source, answer) invariant nodeJoined rfl
      ⟨rfl, queued, rfl⟩ notStepped rfl rfl accepted
  · have dequeued := pureNetworkDequeuePreservesSystemInductiveInvariant state
      (removeOne (appendRequestEnvelope (source, destination, request)) state.network) invariant
      (fun _ envelope member =>
        ⟨(selectedSound (⟨rfl, queued, rfl⟩ : Selected source state.network
            (appendRequestEnvelope (source, destination, request))
            (removeOne (appendRequestEnvelope (source, destination, request))
              state.network))).2.2 envelope member.1, member.2⟩)
    simp only [Option.map_none, Option.toList_none, List.append_nil]
    apply retirementMetadataFramePreservesSystemInductiveInvariant _ _ dequeued rfl
    · rfl
    all_goals
      intro node
      by_cases here : node = destination <;> simp [nodeOf_replaceNode _ _ _ _ present, here]

theorem appendRequest_safety {state : Model.State Node TxId} {joined : Finset Node}
    (invariant : SystemInductiveInvariant (joined := joined) state)
    {source destination : Node} (present : destination ∈ state.nodes.map Prod.fst)
    (nodeJoined : destination ∈ joined) {request : AppendEntriesRequest Node TxId}
    (queued : appendRequestEnvelope (source, destination, request) ∈ state.network)
    (notNewer : request.term ≤ (nodeOf state destination).currentTerm)
    {nextNode : NodeState Node TxId} {response : Option AppendEntriesResponse}
    (handled
      : handleAppendEntriesRequest (inferInstance) destination (nodeOf state destination)
          request
        = (nextNode, response))
    : SystemInductiveInvariant (joined := joined)
        {
          state with
            nodes :=
              replaceNode state.nodes destination
                (refreshRetirementState (inferInstance) destination nextNode)
            network :=
              removeOne (appendRequestEnvelope (source, destination, request))
                state.network
              ++ (response.map
                    fun answer =>
                      appendResponseEnvelope (destination, source, answer)).toList
        } := by
  by_cases stepping :
    request.term = (nodeOf state destination).currentTerm
    ∧ ((nodeOf state destination).role = .candidate
        ∨ (nodeOf state destination).role = .preVoteCandidate)
  · let middle : Model.State Node TxId :=
      { state with
        nodes := replaceNode state.nodes destination
          { nodeOf state destination with role := .follower, isNewFollower := true } }
    have middlePresent : destination ∈ middle.nodes.map Prod.fst := by
      simpa [middle, replaceNode_keys] using present
    have middleInvariant : SystemInductiveInvariant (joined := joined) middle :=
      returnToFollowerPreservesSystemInductiveInvariant state destination (present := present)
        (source, destination, request) _ invariant nodeJoined stepping rfl
    have follower : (nodeOf middle destination).role = .follower := by
      simp [middle, present]
    have handledMiddle
        : handleAppendEntriesRequest (inferInstance) destination (nodeOf middle destination)
            request
          = (nextNode, response) := by
      rw [← handled, handleAppendEntriesRequest_stepped stepping]
      simp [middle, present]
    have preserved := appendRequest_unstepped middleInvariant middlePresent nodeJoined queued
      (by simpa [middle, present] using notNewer) (by simp [follower]) handledMiddle
    simpa only [middle, replaceNode_twice] using preserved
  · exact appendRequest_unstepped invariant present nodeJoined queued notNewer stepping handled

/-- Delivery observes the term, handles the payload, removes one envelope, and appends replies. -/
theorem receive_preserves {state : Model.State Node TxId} {joined : Finset Node}
    (invariant : StateInvariant state joined) {envelope : Model.Envelope Node TxId}
    (present : envelope.target ∈ state.nodes.map Prod.fst)
    {next : NodeState Node TxId}
    {outputs : Outputs Node (Message Node TxId) Notification}
    (queued : envelope ∈ state.network)
    (received
      : (Model.Local.receive (inferInstance) (Capabilities.record envelope.target)
          envelope.target envelope.source (nodeOf state envelope.target)
          envelope.payload).run
          {}
        = some (next, outputs))
    : StateInvariant
        {
          state with
            nodes := replaceNode state.nodes envelope.target next
            network := removeOne envelope state.network ++ outputs.outgoing
        } joined := by
  have nodeJoined := (invariant.endpoints envelope queued).2
  let middle : Model.State Node TxId :=
    { state with
      nodes := replaceNode state.nodes envelope.target
        (observeTerm (nodeOf state envelope.target) envelope.payload) }
  have prepared : StateInvariant middle joined := observeTerm_preserves invariant envelope present queued
  have middlePresent : envelope.target ∈ middle.nodes.map Prod.fst := by
    simpa [middle, replaceNode_keys] using present
  have receiver : nodeOf middle envelope.target =
      observeTerm (nodeOf state envelope.target) envelope.payload := by
    simp [middle, present]
  rcases envelope with ⟨source, destination, payload⟩
  cases payload with
  | appendEntriesRequest request =>
      rcases handled : handleAppendEntriesRequest (inferInstance) destination
          (observeTerm (nodeOf state destination) (.appendEntriesRequest request)) request with
        ⟨nextNode, response⟩
      have preserved := appendRequest_safety prepared.safety middlePresent nodeJoined queued
        (by rw [receiver]; exact observeTerm_appendRequest_term _ _)
        (nextNode := nextNode) (response := response) (by rw [receiver]; exact handled)
      simp only [middle, replaceNode_twice] at preserved
      simp only [Model.Local.receive, handled] at received
      cases response <;> simp [Capabilities.record] at received <;>
        obtain ⟨rfl, rfl⟩ := received <;>
        apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
          (invariant.receivedEndpoints queued (by simp)) <;>
        simpa using preserved
  | appendEntriesResponse response =>
      simp [Model.Local.receive] at received
      obtain ⟨rfl, rfl⟩ := received
      simp only [List.append_nil]
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
        (invariant.erasedEndpoints _)
      have preserved := receiveAppendEntriesResponsePreservesSystemInductiveInvariant
        middle source destination (present := middlePresent) prepared.distinct
        (source, destination, response) _ _ prepared.safety nodeJoined
        ⟨rfl, queued, rfl⟩ rfl (by rw [receiver])
      simpa only [middle, replaceNode_twice] using preserved
  | requestVoteRequest request =>
      simp [Model.Local.receive, Capabilities.record] at received
      obtain ⟨rfl, rfl⟩ := received
      let answer := handleRequestVoteRequest (nodeOf middle destination) source request
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
        (invariant.receivedEndpoints queued (by simp))
      have preserved := receiveRequestVoteRequestPreservesSystemInductiveInvariant
        middle source destination (present := middlePresent) prepared.distinct
        (source, destination, request) _ answer.1 (destination, source, answer.2)
        prepared.safety nodeJoined rfl ⟨rfl, queued, rfl⟩ rfl rfl rfl
      simpa [answer, receiver, middle, replaceNode_twice, enqueue] using preserved
  | requestVoteResponse response =>
      simp [Model.Local.receive] at received
      obtain ⟨rfl, rfl⟩ := received
      simp only [List.append_nil]
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
        (invariant.erasedEndpoints _)
      have preserved := receiveRequestVoteResponsePreservesSystemInductiveInvariant
        middle source destination (present := middlePresent) (source, destination, response) _
        _ prepared.safety nodeJoined ⟨rfl, queued, rfl⟩ rfl (by rw [receiver])
      simpa only [middle, replaceNode_twice] using preserved
  | requestPreVote request =>
      simp [Model.Local.receive, Capabilities.record] at received
      obtain ⟨rfl, rfl⟩ := received
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
        (invariant.receivedEndpoints queued (by simp))
      have preserved := receiveRequestPreVotePreservesSystemInductiveInvariant
        middle source destination request
        { term := (nodeOf middle destination).currentTerm
          voteGranted :=
            decide (request.term = (nodeOf middle destination).currentTerm
              ∧ voteLogUpToDate (nodeOf middle destination) request) }
        _ prepared.safety ⟨rfl, queued, rfl⟩ rfl
      simpa [receiver, middle] using preserved
  | requestPreVoteResponse response =>
      simp [Model.Local.receive] at received
      obtain ⟨rfl, rfl⟩ := received
      simp only [List.append_nil]
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
        (invariant.erasedEndpoints _)
      have preserved := receiveRequestPreVoteResponsePreservesSystemInductiveInvariant
        middle source destination (present := middlePresent) response _ _ prepared.safety
        ⟨rfl, queued, rfl⟩ (by rw [receiver])
      simpa only [middle, replaceNode_twice] using preserved
  | proposeVoteRequest term =>
      have preserved := receiveProposeVoteRequestPreservesSystemInductiveInvariant
        middle source destination (present := middlePresent) prepared.distinct term _
        prepared.safety nodeJoined ⟨rfl, queued, rfl⟩
      rw [receiver] at preserved
      simp only [middle, replaceNode_twice, observeTerm] at preserved
      simp only [Model.Local.receive, observeTerm] at received
      have eligibleCases := run_ite received
      rcases eligibleCases with ⟨eligible, received⟩ | ⟨eligible, received⟩ <;>
        simp only [StateT.run_pure, Option.some.injEq, Prod.mk.injEq] at received <;>
        obtain ⟨rfl, rfl⟩ := received <;>
        rw [show (({} : Outputs Node (Message Node TxId) Notification).outgoing) = [] from rfl,
          List.append_nil] <;>
        apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
          (invariant.erasedEndpoints _) <;>
        convert preserved using 4 <;> first
          | simp only [eligible, ite_false]; done
          | exact (ite_eq_left eligible).symm

end CCFRaft.Proofs.Invariant
