-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Internal

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open Shared Shared.MultiNodeTransitionSystem Concrete
open Model.Local

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

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

theorem appendRequest_safety {state : Model.State Node TxId} {joined : Finset Node}
    (invariant : SystemInductiveInvariant (joined := joined) state)
    {source destination : Node} (present : destination ∈ state.nodes.map Prod.fst)
    (nodeJoined : destination ∈ joined) {request : AppendEntriesRequest Node TxId}
    (queued : appendRequestEnvelope (source, destination, request) ∈ state.network)
    {nextNode : NodeState Node TxId} {response : AppendEntriesResponse}
    (handled
      : handleAppendEntriesRequest? destination (nodeOf state destination) request
        = some (nextNode, response))
    : SystemInductiveInvariant (joined := joined)
        {
          state with
            nodes :=
              replaceNode state.nodes destination
                (refreshRetirementState destination nextNode)
            network :=
              removeOne (appendRequestEnvelope (source, destination, request))
                state.network
              ++ [appendResponseEnvelope (destination, source, response)]
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
    have handledMiddle : handleAppendEntriesRequest? destination (nodeOf middle destination) request
        = some (nextNode, response) := by
      simpa [middle, present, handleAppendEntriesRequest?, stepping] using handled
    have preserved := receiveAppendEntriesRequestWithRetirementPreservesSystemInductiveInvariant
      middle source destination (present := middlePresent) (source, destination, request) _
      nextNode (destination, source, response) middleInvariant nodeJoined rfl
      ⟨rfl, queued, rfl⟩ (by simp [follower]) rfl rfl handledMiddle
    simpa only [middle, replaceNode_twice, reply] using preserved
  · exact receiveAppendEntriesRequestWithRetirementPreservesSystemInductiveInvariant
      state source destination (present := present) (source, destination, request) _
      nextNode (destination, source, response) invariant nodeJoined rfl
      ⟨rfl, queued, rfl⟩ stepping rfl rfl handled

/-- Delivery observes the term, handles the payload, removes one envelope, and appends replies. -/
theorem receive_preserves {state : Model.State Node TxId} {joined : Finset Node}
    (invariant : StateInvariant state joined) {envelope : Model.Envelope Node TxId}
    (present : envelope.target ∈ state.nodes.map Prod.fst)
    {execute : NodeEffect Node TxId (NodeState Node TxId)}
    (queued : envelope ∈ state.network)
    (received
      : Model.Local.receive (Capabilities.record envelope.target) envelope.target
          envelope.source (nodeOf state envelope.target) envelope.payload
        = some execute)
    : StateInvariant
        {
          state with
            nodes := replaceNode state.nodes envelope.target (execute.run {}).1
            network := removeOne envelope state.network ++ (execute.run {}).2.outgoing
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
      simp only [Model.Local.receive] at received
      obtain ⟨⟨nextNode, response⟩, handled, done⟩ := Option.bind_eq_some_iff.mp received
      obtain rfl := Option.some.inj done
      change StateInvariant
        { state with
          nodes := replaceNode state.nodes destination (refreshRetirementState destination nextNode)
          network := removeOne ⟨source, destination, .appendEntriesRequest request⟩ state.network
            ++ [⟨destination, source, .appendEntriesResponse response⟩] } joined
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
        (invariant.receivedEndpoints queued (by simp))
      have preserved := appendRequest_safety prepared.safety middlePresent nodeJoined queued
        (by rw [receiver]; exact handled)
      simpa only [middle, replaceNode_twice] using preserved
  | appendEntriesResponse response =>
      simp only [Model.Local.receive] at received
      obtain rfl := Option.some.inj received
      simp only [Direct.run_pure, List.append_nil]
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
        (invariant.erasedEndpoints _)
      have preserved := receiveAppendEntriesResponsePreservesSystemInductiveInvariant
        middle source destination (present := middlePresent) prepared.distinct
        (source, destination, response) _ _ prepared.safety nodeJoined
        ⟨rfl, queued, rfl⟩ rfl (by rw [receiver])
      simpa only [middle, replaceNode_twice] using preserved
  | requestVoteRequest request =>
      simp only [Model.Local.receive] at received
      obtain rfl := Option.some.inj received
      let answer := handleRequestVoteRequest (nodeOf middle destination) source request
      change StateInvariant
        { state with
          nodes := replaceNode state.nodes destination
            (handleRequestVoteRequest (observeTerm (nodeOf state destination) (.requestVoteRequest request)) source request).1
          network := removeOne ⟨source, destination, .requestVoteRequest request⟩ state.network
            ++ [⟨destination, source, .requestVoteResponse
              (handleRequestVoteRequest (observeTerm (nodeOf state destination) (.requestVoteRequest request)) source request).2⟩] } joined
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
        (invariant.receivedEndpoints queued (by simp))
      have preserved := receiveRequestVoteRequestPreservesSystemInductiveInvariant
        middle source destination (present := middlePresent) prepared.distinct
        (source, destination, request) _ answer.1 (destination, source, answer.2)
        prepared.safety nodeJoined rfl ⟨rfl, queued, rfl⟩ rfl rfl rfl
      simpa only [answer, receiver, middle, replaceNode_twice, enqueue] using preserved
  | requestVoteResponse response =>
      simp only [Model.Local.receive] at received
      obtain rfl := Option.some.inj received
      simp only [Direct.run_pure, List.append_nil]
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
        (invariant.erasedEndpoints _)
      have preserved := receiveRequestVoteResponsePreservesSystemInductiveInvariant
        middle source destination (present := middlePresent) (source, destination, response) _
        _ prepared.safety nodeJoined ⟨rfl, queued, rfl⟩ rfl (by rw [receiver])
      simpa only [middle, replaceNode_twice] using preserved
  | requestPreVote request =>
      simp only [Model.Local.receive] at received
      obtain rfl := Option.some.inj received
      change StateInvariant
        { state with
          nodes := replaceNode state.nodes destination
            (observeTerm (nodeOf state destination) (.requestPreVote request))
          network := removeOne ⟨source, destination, .requestPreVote request⟩ state.network
            ++ [⟨destination, source, .requestPreVoteResponse
              (handleRequestPreVote (observeTerm (nodeOf state destination) (.requestPreVote request)) request)⟩] } joined
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
        (invariant.receivedEndpoints queued (by simp))
      have preserved := receiveRequestPreVotePreservesSystemInductiveInvariant
        middle source destination request _ prepared.safety ⟨rfl, queued, rfl⟩
      simpa only [receiver, middle] using preserved
  | requestPreVoteResponse response =>
      simp only [Model.Local.receive] at received
      obtain rfl := Option.some.inj received
      simp only [Direct.run_pure, List.append_nil]
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_
        (invariant.erasedEndpoints _)
      have preserved := receiveRequestPreVoteResponsePreservesSystemInductiveInvariant
        middle source destination (present := middlePresent) response _ _ prepared.safety
        ⟨rfl, queued, rfl⟩ (by rw [receiver])
      simpa only [middle, replaceNode_twice] using preserved
  | proposeVoteRequest term =>
      simp only [Model.Local.receive] at received
      obtain rfl := Option.some.inj received
      simp only [Direct.run_pure, List.append_nil]
      apply invariant.update nodeJoined (Finset.Subset.refl _) ?_ (invariant.erasedEndpoints _)
      have preserved := receiveProposeVoteRequestPreservesSystemInductiveInvariant
        middle source destination (present := middlePresent) prepared.distinct term _
        prepared.safety nodeJoined ⟨rfl, queued, rfl⟩
      simpa only [receiver, middle, replaceNode_twice] using preserved

end CCFRaft.Proofs.Invariant
