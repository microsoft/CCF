-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Refinement.Handlers

set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

/-!
# Simulating deliveries

A concrete delivery of envelope `e` to `d` is simulated by moving `e` to the
front of the abstract queue of `d`, then an abstract `updateTerm` when the
receiver adopts a newer term, then an abstract same-term step-down for an
AppendEntries request at a candidate, and finally an abstract `receive`.
-/

namespace CCFRaft.Proofs.Refinement

open Shared Shared.MultiNodeTransitionSystem
open Model.Local (NodeState Bootstrap Role retirementCompletedNodes refreshRetirementState
  )
open Abstract.Model (NodeStore updateNode updateQueue enqueue)
open Abstract.Invariant (SystemInductiveInvariant)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

theorem updateNode_self {nodes : NodeStore Node TxId} {node : Node}
    (allocated : nodes.allocated node)
    : updateNode nodes node (nodes node) = nodes := by
  rcases nodes with ⟨entries⟩
  simp only [updateNode, NodeStore.set, NodeStore.mk.injEq]
  apply Finmap.ext_lookup
  intro member
  by_cases same : member = node
  · subst member
    rw [Finmap.lookup_insert]
    simp only [NodeStore.allocated, NodeStore.node?, Option.isSome_iff_exists] at allocated
    obtain ⟨value, found⟩ := allocated
    simp [Abstract.Model.NodeStore.get, NodeStore.node?, found]
  · rw [Finmap.lookup_insert_of_ne _ same]

theorem updateQueue_updateQueue
    (network : Node -> List (Abstract.Model.Message Node TxId)) (destination : Node)
    (first second : List (Abstract.Model.Message Node TxId))
    : updateQueue (updateQueue network destination first) destination second
      = updateQueue network destination second := by
  simp [updateQueue]

theorem updateQueue_apply (network : Node -> List (Abstract.Model.Message Node TxId))
    (destination target : Node) (queue : List (Abstract.Model.Message Node TxId))
    : updateQueue network destination queue target
      = if target = destination then queue else network target := by
  by_cases same : target = destination
  · subst target
    simp [updateQueue]
  · simp [updateQueue, same]

/-- Correspondence after a delivery: the delivered envelope is gone from
both networks and the receiver took `value`. -/
theorem Corr.deliver {concrete : Model.State Node TxId}
    {abstract after : Abstract.Model.State Node TxId}
    {envelope : Model.Envelope Node TxId} {value : NodeState Node TxId}
    {sends : List (Model.Envelope Node TxId)} (corr : Corr concrete abstract)
    (nodesEq
      : forall member,
          after.nodes member
          = if member = envelope.target then value else abstract.nodes member)
    (networkEq
      : forall target,
          after.network target
          = (if target = envelope.target then
                (abstract.network target).erase (toAbstract envelope)
              else
                abstract.network target)
            ++ absQueue sends target)
    (preVote : after.preVoteStatus = abstract.preVoteStatus)
    (allocatedMono : forall member, abstract.allocated member -> after.allocated member)
    (retirementHere
      : after.retirementCompleted envelope.target
        = retirementCompletedNodes value.log value.commitIndex)
    (retirementOther
      : forall member,
          Not (member = envelope.target)
          -> after.retirementCompleted member = abstract.retirementCompleted member)
    (sendsAllocated
      : forall sent,
          sent ∈ sends -> after.allocated sent.source /\ after.allocated sent.target)
    : Corr
        {
          concrete with
            nodes := replaceNode concrete.nodes envelope.target value
            network := removeOne envelope concrete.network ++ sends
        }
        after := by
  apply corr.update nodesEq _ preVote _ _
  · intro target
    rw [networkEq, absQueue_append, removeOne_eq_erase, absQueue_erase]
    apply List.Perm.append_right
    by_cases same : target = envelope.target
    · subst target
      simp only [ite_true]
      exact (corr.network _).erase _
    · have different : Not (envelope.target = target) := fun equal => same equal.symm
      simp only [same, different, ite_false]
      exact corr.network target
  · intro member
    by_cases same : member = envelope.target
    · subst member
      simp [retirementHere, nodesEq]
    · rw [retirementOther member same, corr.retirementCompleted member, nodesEq member]
      simp [same]
  · intro sent member
    rcases List.mem_append.mp member with old | new
    · rw [removeOne_eq_erase] at old
      obtain ⟨source, target⟩ := corr.endpoints sent (List.mem_of_mem_erase old)
      exact ⟨allocatedMono _ source, allocatedMono _ target⟩
    · exact sendsAllocated sent new

/-- Move a queued envelope to the front of its abstract destination queue. -/
def reordered (abstract : Abstract.Model.State Node TxId)
    (envelope : Model.Envelope Node TxId)
    : Abstract.Model.State Node TxId :=
  {
    abstract with
      network :=
        updateQueue abstract.network envelope.target
          (toAbstract envelope
            :: (abstract.network envelope.target).erase (toAbstract envelope))
  }

theorem mem_abstract_queue {concrete : Model.State Node TxId}
    {abstract : Abstract.Model.State Node TxId} (corr : Corr concrete abstract)
    {envelope : Model.Envelope Node TxId} (member : envelope ∈ concrete.network)
    : toAbstract envelope ∈ abstract.network envelope.target := by
  apply (corr.network envelope.target).mem_iff.mpr
  simp only [absQueue, List.mem_map, List.mem_filter]
  exact ⟨envelope, ⟨member, by simp⟩, rfl⟩

theorem moves_reordered {concrete : Model.State Node TxId}
    {abstract : Abstract.Model.State Node TxId} (corr : Corr concrete abstract)
    {envelope : Model.Envelope Node TxId} (member : envelope ∈ concrete.network)
    : Moves abstract (reordered abstract envelope) :=
  .reorder envelope.target _ (List.perm_cons_erase (mem_abstract_queue corr member)).symm
    (.done _)

/-- The receiver after the model adopts a newer message term. -/
def observed (state : Abstract.Model.State Node TxId)
    (envelope : Model.Envelope Node TxId)
    : Abstract.Model.State Node TxId :=
  {
    state with
      nodes :=
        updateNode state.nodes envelope.target
          (Model.Local.observeTerm (state.nodes envelope.target) envelope.payload)
  }

theorem observeTerm_eq_updateTerm (state : NodeState Node TxId)
    (message : Model.Local.Message Node TxId)
    : Model.Local.observeTerm state message = state
      \/ (Model.Local.observeTerm state message
            = Model.Local.updateTerm state message.term
          /\ state.currentTerm < message.term
          /\ (forall term, Not (message = .proposeVoteRequest term))
          /\ (forall response,
                message = .appendEntriesResponse response -> state.role = .leader)) := by
  have update : forall term, Model.Local.updateTerm state term = state \/
      (state.currentTerm < term) := by
    intro term
    unfold Model.Local.updateTerm
    split_ifs with newer
    · exact Or.inr newer
    · exact Or.inl rfl
  cases message
  case proposeVoteRequest term => exact Or.inl rfl
  case appendEntriesResponse response =>
    by_cases leader : state.role = .leader
    · rcases update response.term with same | newer
      · left
        simp [Model.Local.observeTerm, leader, same]
      · right
        refine ⟨by simp [Model.Local.observeTerm, leader, Model.Local.Message.term], newer,
          by simp, fun _ _ => leader⟩
    · left
      simp [Model.Local.observeTerm, leader]
  case appendEntriesRequest payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestVoteRequest payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestVoteResponse payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestPreVote payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestPreVoteResponse payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩

theorem moves_observed {abstract : Abstract.Model.State Node TxId}
    {envelope : Model.Envelope Node TxId}
    (queued
      : abstract.network envelope.target
        = toAbstract envelope :: (abstract.network envelope.target).tail)
    (sourceAllocated : abstract.allocated envelope.source)
    (targetAllocated : abstract.allocated envelope.target)
    : Moves abstract (observed abstract envelope) := by
  rcases observeTerm_eq_updateTerm (abstract.nodes envelope.target) envelope.payload with
    same | ⟨updated, newer, notPropose, leaderOnly⟩
  · have unchanged : observed abstract envelope = abstract := by
      simp only [observed, same, updateNode_self targetAllocated]
    rw [unchanged]
    exact .done _
  · have newerSome : Abstract.Model.newerMessage? abstract envelope.source envelope.target =
        some (toAbstract envelope) := by
      unfold Abstract.Model.newerMessage?
      rw [queued]
      generalize (abstract.network envelope.target).tail = rest
      clear queued
      rcases envelope with ⟨source, target, payload⟩
      cases payload <;>
        simp_all [Abstract.Model.takeFirstFrom, toAbstract, Abstract.Model.messageSourceAllowed,
          Model.Local.Message.term, Abstract.Model.Message.term, Abstract.Model.Message.source]
    have nextEq : Abstract.Model.next abstract (.updateTerm envelope.source envelope.target) =
        observed abstract envelope := by
      simp only [Abstract.Model.next, newerSome, observed, updated, Model.Local.updateTerm, newer,
        ite_true, ite_self, toAbstract_term]
    rw [← nextEq]
    exact Moves.single ⟨targetAllocated, by simp [newerSome]⟩

section Receive

variable {state : Abstract.Model.State Node TxId} {source destination : Node}
  {rest : List (Abstract.Model.Message Node TxId)}

theorem takeFirstFrom_head (message : Abstract.Model.Message Node TxId)
    (fromSource : message.source = source)
    : Abstract.Model.takeFirstFrom source (message :: rest) = some (message, rest) := by
  simp [Abstract.Model.takeFirstFrom, fromSource]

theorem receive_appendRequest_stepDown
    {request : Model.Local.AppendEntriesRequest Node TxId}
    (queued
      : state.network destination
        = .appendEntriesRequest (absAppendRequest request source destination) :: rest)
    (stepping
      : request.term = (state.nodes destination).currentTerm
        /\ ((state.nodes destination).role = .candidate
            \/ (state.nodes destination).role = .preVoteCandidate))
    : Abstract.Model.handleReceive? state source destination
      = some
          {
            state with
              nodes :=
                updateNode state.nodes destination
                  (stepDown (state.nodes destination) request)
          } := by
  unfold Abstract.Model.handleReceive?
  rw [queued, takeFirstFrom_head (source := source) (rest := rest) _ rfl]
  simp only [Abstract.Model.Message.destination, absAppendRequest_destination, bne_self_eq_false,
    Bool.false_eq_true, ite_false, returnToFollower_eq, stepping, and_self, ite_true]

theorem receive_appendRequest {request : Model.Local.AppendEntriesRequest Node TxId}
    (queued
      : state.network destination
        = .appendEntriesRequest (absAppendRequest request source destination) :: rest)
    (noStepDown
      : Not
          (request.term = (state.nodes destination).currentTerm
            /\ ((state.nodes destination).role = .candidate
                \/ (state.nodes destination).role = .preVoteCandidate)))
    {next : NodeState Node TxId} {response : Model.Local.AppendEntriesResponse}
    (handled
      : Model.Local.handleAppendEntriesRequest? destination (state.nodes destination)
          request
        = some (next, response))
    : Abstract.Model.handleReceive? state source destination
      = some
          {
            state with
              nodes :=
                updateNode state.nodes destination
                  (refreshRetirementState destination next)
              network :=
                Abstract.Model.reply state.network destination rest
                  (absAppendResponse response destination source)
              retirementCompleted :=
                Abstract.Model.refreshRetirementCompleted state.retirementCompleted
                  destination (refreshRetirementState destination next)
          } := by
  unfold Abstract.Model.handleReceive?
  rw [queued, takeFirstFrom_head (source := source) (rest := rest) _ rfl]
  simp only [Abstract.Model.Message.destination, absAppendRequest_destination, bne_self_eq_false,
    Bool.false_eq_true, ite_false, returnToFollower_eq]
  rw [ite_eq_right_of_eq_false _ _ (eq_false noStepDown)]
  rw [handleAppendEntriesRequest_eq _ _ _ _ noStepDown, handled]
  rfl

theorem receive_appendResponse {response : Model.Local.AppendEntriesResponse}
    (queued
      : state.network destination
        = .appendEntriesResponse (absAppendResponse response source destination) :: rest)
    (sourceAllocated : state.allocated source)
    (bounded
      : (state.nodes destination).role = .leader
        -> response.term <= (state.nodes destination).currentTerm)
    : Abstract.Model.handleReceive? state source destination
      = some
          {
            state with
              nodes :=
                updateNode state.nodes destination
                  (Model.Local.handleAppendEntriesResponse (state.nodes destination)
                    source response)
              network := updateQueue state.network destination rest
          } := by
  unfold Abstract.Model.handleReceive?
  rw [queued, takeFirstFrom_head (source := source) (rest := rest) _ rfl]
  have allocated : state.allocated (absAppendResponse response source destination).source :=
    sourceAllocated
  simp only [Abstract.Model.Message.destination, absAppendResponse_destination,
    absVoteRequest_destination, absVoteResponse_destination, absPreVote_destination,
    absPreVoteResponse_destination, bne_self_eq_false, Bool.false_eq_true, ite_false,
    allocated, ite_true, handleAppendEntriesResponse_eq _ _ _ _ bounded]

theorem receive_voteRequest {request : Model.Local.RequestVoteRequest}
    (queued
      : state.network destination
        = .requestVoteRequest (absVoteRequest request source destination) :: rest)
    (bounded : request.term <= (state.nodes destination).currentTerm)
    : Abstract.Model.handleReceive? state source destination
      = some
          {
            state with
              nodes :=
                updateNode state.nodes destination
                  (Model.Local.handleRequestVoteRequest (state.nodes destination) source
                    request).1
              network :=
                enqueue (updateQueue state.network destination rest)
                  (.requestVoteResponse
                    (absVoteResponse
                      (Model.Local.handleRequestVoteRequest (state.nodes destination)
                        source request).2
                      destination source))
          } := by
  unfold Abstract.Model.handleReceive?
  rw [queued, takeFirstFrom_head (source := source) (rest := rest) _ rfl]
  simp only [Abstract.Model.Message.destination, absAppendResponse_destination,
    absVoteRequest_destination, absVoteResponse_destination, absPreVote_destination,
    absPreVoteResponse_destination, bne_self_eq_false, Bool.false_eq_true, ite_false,
    handleRequestVoteRequest_eq _ _ _ _ bounded]

theorem receive_voteResponse {response : Model.Local.RequestVoteResponse}
    (queued
      : state.network destination
        = .requestVoteResponse (absVoteResponse response source destination) :: rest)
    (sourceAllocated : state.allocated source)
    (bounded : response.term <= (state.nodes destination).currentTerm)
    : Abstract.Model.handleReceive? state source destination
      = some
          {
            state with
              nodes :=
                updateNode state.nodes destination
                  (Model.Local.handleRequestVoteResponse (state.nodes destination) source
                    response)
              network := updateQueue state.network destination rest
          } := by
  unfold Abstract.Model.handleReceive?
  rw [queued, takeFirstFrom_head (source := source) (rest := rest) _ rfl]
  have allocated : state.allocated (absVoteResponse response source destination).source :=
    sourceAllocated
  simp only [Abstract.Model.Message.destination, absAppendResponse_destination,
    absVoteRequest_destination, absVoteResponse_destination, absPreVote_destination,
    absPreVoteResponse_destination, bne_self_eq_false, Bool.false_eq_true, ite_false,
    allocated, ite_true, handleRequestVoteResponse_eq _ _ _ _ bounded]

theorem receive_preVote {request : Model.Local.RequestVoteRequest}
    (queued
      : state.network destination
        = .requestPreVote (absPreVote request source destination) :: rest)
    (bounded : request.term <= (state.nodes destination).currentTerm)
    : Abstract.Model.handleReceive? state source destination
      = some
          {
            state with
              nodes := updateNode state.nodes destination (state.nodes destination)
              network :=
                enqueue (updateQueue state.network destination rest)
                  (.requestPreVoteResponse
                    (absPreVoteResponse
                      (Model.Local.handleRequestPreVote (state.nodes destination) request)
                      destination source))
          } := by
  unfold Abstract.Model.handleReceive?
  rw [queued, takeFirstFrom_head (source := source) (rest := rest) _ rfl]
  simp only [Abstract.Model.Message.destination, absAppendResponse_destination,
    absVoteRequest_destination, absVoteResponse_destination, absPreVote_destination,
    absPreVoteResponse_destination, bne_self_eq_false, Bool.false_eq_true, ite_false,
    handleRequestPreVote_eq _ _ _ _ bounded]

theorem receive_preVoteResponse {response : Model.Local.RequestVoteResponse}
    (queued
      : state.network destination
        = .requestPreVoteResponse (absPreVoteResponse response source destination)
          :: rest)
    (sourceAllocated : state.allocated source)
    (bounded : response.term <= (state.nodes destination).currentTerm)
    : Abstract.Model.handleReceive? state source destination
      = some
          {
            state with
              nodes :=
                updateNode state.nodes destination
                  (Model.Local.handleRequestPreVoteResponse (state.nodes destination)
                    source response)
              network := updateQueue state.network destination rest
          } := by
  unfold Abstract.Model.handleReceive?
  rw [queued, takeFirstFrom_head (source := source) (rest := rest) _ rfl]
  have allocated : state.allocated (absPreVoteResponse response source destination).source :=
    sourceAllocated
  simp only [Abstract.Model.Message.destination, absAppendResponse_destination,
    absVoteRequest_destination, absVoteResponse_destination, absPreVote_destination,
    absPreVoteResponse_destination, bne_self_eq_false, Bool.false_eq_true, ite_false,
    allocated, ite_true, handleRequestPreVoteResponse_eq _ _ _ _ bounded]

theorem receive_proposeVote {term : Nat}
    (queued
      : state.network destination
        = .proposeVoteRequest { term, source, destination } :: rest)
    : Abstract.Model.handleReceive? state source destination
      = some
          {
            state with
              nodes :=
                updateNode state.nodes destination
                  (if term = (state.nodes destination).currentTerm
                      /\ Abstract.Model.candidateTransitionEnabled state destination then
                      Model.Local.becomeCandidateNodeState (state.nodes destination)
                        destination
                    else
                      state.nodes destination)
              network := updateQueue state.network destination rest
          } := by
  unfold Abstract.Model.handleReceive?
  rw [queued, takeFirstFrom_head (source := source) (rest := rest) _ rfl]
  simp only [Abstract.Model.Message.destination, bne_self_eq_false, Bool.false_eq_true, ite_false,
    Abstract.Model.handleProposeVoteRequest?]
  split_ifs <;> rfl

end Receive

/-- The abstract state just before the final abstract receive of `envelope`:
the envelope heads its queue and the receiver's state is `receiver`. -/
structure Staged (abstract pre : Abstract.Model.State Node TxId)
    (envelope : Model.Envelope Node TxId) (receiver : NodeState Node TxId)
    : Prop where
  nodes
    : forall member,
        pre.nodes member
        = if member = envelope.target then receiver else abstract.nodes member
  network
    : pre.network
      = updateQueue abstract.network envelope.target
          (toAbstract envelope
            :: (abstract.network envelope.target).erase (toAbstract envelope))
  preVoteStatus : pre.preVoteStatus = abstract.preVoteStatus
  retirementCompleted : pre.retirementCompleted = abstract.retirementCompleted
  allocated : forall member, pre.allocated member <-> abstract.allocated member

theorem Staged.queue {abstract pre : Abstract.Model.State Node TxId}
    {envelope : Model.Envelope Node TxId} {receiver : NodeState Node TxId}
    (staged : Staged abstract pre envelope receiver)
    : pre.network envelope.target
      = toAbstract envelope
        :: (abstract.network envelope.target).erase (toAbstract envelope) := by
  rw [staged.network]
  simp [updateQueue]

theorem Staged.receiver {abstract pre : Abstract.Model.State Node TxId}
    {envelope : Model.Envelope Node TxId} {receiver : NodeState Node TxId}
    (staged : Staged abstract pre envelope receiver)
    : pre.nodes envelope.target = receiver := by
  simp [staged.nodes]

theorem allocated_set_iff {nodes : NodeStore Node TxId} {node member : Node}
    {value : NodeState Node TxId} (allocated : nodes.allocated node)
    : (updateNode nodes node value).allocated member <-> nodes.allocated member :=
  Abstract.ReconfigurationPreservation.NodeStore.allocated_set_iff_of_allocated
    nodes node value allocated member

/-- Reordering and observing the message term stage the final receive. -/
theorem prepare {concrete : Model.State Node TxId}
    {abstract : Abstract.Model.State Node TxId} (corr : Corr concrete abstract)
    {envelope : Model.Envelope Node TxId} (member : envelope ∈ concrete.network)
    : Moves abstract (observed (reordered abstract envelope) envelope)
      /\ Staged abstract (observed (reordered abstract envelope) envelope) envelope
          (Model.Local.observeTerm (abstract.nodes envelope.target)
            envelope.payload) := by
  obtain ⟨sourceAllocated, targetAllocated⟩ := corr.endpoints envelope member
  refine ⟨(moves_reordered corr member).trans (moves_observed ?_ sourceAllocated targetAllocated),
    ?_, rfl, rfl, rfl, ?_⟩
  · simp [reordered, updateQueue]
  · intro node
    simp [observed, reordered, get_updateNode]
  · intro node
    exact allocated_set_iff targetAllocated

/-- An abstract same-term step-down keeps the receive staged. -/
theorem stage_stepDown {abstract pre : Abstract.Model.State Node TxId}
    {source destination : Node} {request : Model.Local.AppendEntriesRequest Node TxId}
    {receiver : NodeState Node TxId}
    (staged
      : Staged abstract pre ⟨source, destination, .appendEntriesRequest request⟩ receiver)
    (targetAllocated : abstract.allocated destination)
    (stepping
      : request.term = receiver.currentTerm
        /\ (receiver.role = .candidate \/ receiver.role = .preVoteCandidate))
    : Moves pre
        { pre with nodes := updateNode pre.nodes destination (stepDown receiver request) }
      /\ Staged abstract
          {
            pre with
              nodes := updateNode pre.nodes destination (stepDown receiver request)
          }
          ⟨source, destination, .appendEntriesRequest request⟩
          (stepDown receiver request) := by
  have received := receive_appendRequest_stepDown (state := pre) (source := source)
    (destination := destination) (rest := _) (request := request) staged.queue
    (by rw [staged.receiver]; exact stepping)
  rw [staged.receiver] at received
  refine ⟨?_, ?_, staged.network, staged.preVoteStatus, staged.retirementCompleted, ?_⟩
  · have enabled : Abstract.Model.Enabled pre (.receive source destination) :=
      ⟨(staged.allocated destination).mpr targetAllocated, by simp [received]⟩
    have nextEq : Abstract.Model.next pre (.receive source destination) =
        { pre with nodes := updateNode pre.nodes destination (stepDown receiver request) } := by
      simp [Abstract.Model.next, received]
    rw [← nextEq]
    exact Moves.single enabled
  · intro member
    simp only [get_updateNode]
    by_cases same : member = destination
    · simp [same]
    · simp [same, staged.nodes member]
  · intro member
    exact (allocated_set_iff ((staged.allocated destination).mpr targetAllocated)).trans
      (staged.allocated member)

/-- Finish a staged delivery with the abstract receive that produced `post`. -/
theorem finish {concrete : Model.State Node TxId}
    {abstract pre post : Abstract.Model.State Node TxId} (corr : Corr concrete abstract)
    {envelope : Model.Envelope Node TxId} (member : envelope ∈ concrete.network)
    {receiver value : NodeState Node TxId} {sends : List (Model.Envelope Node TxId)}
    (staged : Staged abstract pre envelope receiver)
    (received
      : Abstract.Model.handleReceive? pre envelope.source envelope.target = some post)
    (nodesPost : post.nodes = updateNode pre.nodes envelope.target value)
    (networkPost
      : forall target,
          post.network target
          = updateQueue pre.network envelope.target
              ((abstract.network envelope.target).erase (toAbstract envelope)) target
            ++ absQueue sends target)
    (preVotePost : post.preVoteStatus = pre.preVoteStatus)
    (retirementHere
      : post.retirementCompleted envelope.target
        = retirementCompletedNodes value.log value.commitIndex)
    (retirementOther
      : forall member,
          Not (member = envelope.target)
          -> post.retirementCompleted member = pre.retirementCompleted member)
    (sendsEndpoints
      : forall sent,
          sent ∈ sends -> sent.source = envelope.target /\ sent.target = envelope.source)
    : exists after,
        Moves pre after
        /\ Corr
            {
              concrete with
                nodes := replaceNode concrete.nodes envelope.target value
                network := removeOne envelope concrete.network ++ sends
            }
            after := by
  obtain ⟨sourceAllocated, targetAllocated⟩ := corr.endpoints envelope member
  have preTarget : pre.allocated envelope.target := (staged.allocated _).mpr targetAllocated
  have postAllocated : forall node, abstract.allocated node -> post.allocated node := by
    intro node allocated
    have : pre.allocated node := (staged.allocated node).mpr allocated
    simp only [Abstract.Model.State.allocated, nodesPost]
    exact (allocated_set_iff preTarget).mpr this
  refine ⟨post, ?_, ?_⟩
  · have enabled : Abstract.Model.Enabled pre (.receive envelope.source envelope.target) :=
      ⟨preTarget, by simp [received]⟩
    have nextEq : Abstract.Model.next pre (.receive envelope.source envelope.target) = post := by
      simp [Abstract.Model.next, received]
    rw [← nextEq]
    exact Moves.single enabled
  · apply corr.deliver
    · intro node
      rw [nodesPost, get_updateNode]
      by_cases same : node = envelope.target
      · simp [same]
      · simp [same, staged.nodes node]
    · intro target
      rw [networkPost, updateQueue_apply, staged.network, updateQueue_apply]
      by_cases same : target = envelope.target
      · simp [same]
      · simp [same]
    · rw [preVotePost, staged.preVoteStatus]
    · exact postAllocated
    · exact retirementHere
    · intro node different
      rw [retirementOther node different, staged.retirementCompleted]
    · intro sent listed
      obtain ⟨source, target⟩ := sendsEndpoints sent listed
      rw [source, target]
      exact ⟨postAllocated _ targetAllocated, postAllocated _ sourceAllocated⟩

section Simulation

variable {concrete : Model.State Node TxId} {abstract : Abstract.Model.State Node TxId}

theorem observeTerm_log (state : NodeState Node TxId)
    (message : Model.Local.Message Node TxId)
    : (Model.Local.observeTerm state message).log = state.log := by
  unfold Model.Local.observeTerm Model.Local.updateTerm
  split <;> (try split) <;> (try split) <;> rfl

theorem observeTerm_commitIndex (state : NodeState Node TxId)
    (message : Model.Local.Message Node TxId)
    : (Model.Local.observeTerm state message).commitIndex = state.commitIndex := by
  unfold Model.Local.observeTerm Model.Local.updateTerm
  split <;> (try split) <;> (try split) <;> rfl

theorem updateTerm_bounded (state : NodeState Node TxId) (term : Nat)
    : term <= (Model.Local.updateTerm state term).currentTerm := by
  unfold Model.Local.updateTerm
  split_ifs with newer
  · exact Nat.le_refl _
  · omega

theorem simulate_appendEntriesRequest (corr : Corr concrete abstract)
    {source destination : Node} {request : Model.Local.AppendEntriesRequest Node TxId}
    (member : ⟨source, destination, .appendEntriesRequest request⟩ ∈ concrete.network)
    {pre : Abstract.Model.State Node TxId} {receiver : NodeState Node TxId}
    (staged
      : Staged abstract pre ⟨source, destination, .appendEntriesRequest request⟩ receiver)
    {next : NodeState Node TxId} {response : Model.Local.AppendEntriesResponse}
    (handled
      : Model.Local.handleAppendEntriesRequest? destination receiver request
        = some (next, response))
    : exists after,
        Moves pre after
        /\ Corr
            {
              concrete with
                nodes :=
                  replaceNode concrete.nodes destination
                    (refreshRetirementState destination next)
                network :=
                  removeOne ⟨source, destination, .appendEntriesRequest request⟩
                    concrete.network
                  ++ [⟨destination, source, .appendEntriesResponse response⟩]
            }
            after := by
  obtain ⟨_, targetAllocated⟩ := corr.endpoints _ member
  have finishFrom : forall {current : Abstract.Model.State Node TxId}
      {receiver' : NodeState Node TxId},
      Staged abstract current ⟨source, destination, .appendEntriesRequest request⟩ receiver' ->
      Not (request.term = receiver'.currentTerm /\
        (receiver'.role = .candidate \/ receiver'.role = .preVoteCandidate)) ->
      Model.Local.handleAppendEntriesRequest? destination receiver' request = some (next, response) ->
      exists after, Moves current after /\
        Corr { concrete with
          nodes := replaceNode concrete.nodes destination (refreshRetirementState destination next)
          network := removeOne ⟨source, destination, .appendEntriesRequest request⟩ concrete.network ++
            [⟨destination, source, .appendEntriesResponse response⟩] } after := by
    intro current receiver' staged' noStepDown handled'
    have received := receive_appendRequest (state := current) staged'.queue
      (by rw [staged'.receiver]; exact noStepDown) (by rw [staged'.receiver]; exact handled')
    refine finish corr member staged' received rfl ?_ rfl ?_ ?_ ?_
    · intro target
      simp only [Abstract.Model.reply]
      rw [show (Abstract.Model.Message.appendEntriesResponse
          (absAppendResponse response destination source)) =
          toAbstract ⟨destination, source, .appendEntriesResponse response⟩ from rfl,
        enqueue_toAbstract, staged'.network, updateQueue_updateQueue]
    · simp [Abstract.Model.refreshRetirementCompleted]
    · intro node different
      simp [Abstract.Model.refreshRetirementCompleted, different]
    · intro sent listed
      simp only [List.mem_singleton] at listed
      subst listed
      exact ⟨rfl, rfl⟩
  by_cases stepping : request.term = receiver.currentTerm /\
      (receiver.role = .candidate \/ receiver.role = .preVoteCandidate)
  · obtain ⟨stepped, staged'⟩ := stage_stepDown staged targetAllocated stepping
    obtain ⟨after, moves, related⟩ := finishFrom staged' (stepDown_noStepDown receiver request)
      (by rw [← handleAppendEntriesRequest_stepDown]; exact handled)
    exact ⟨after, stepped.trans moves, related⟩
  · exact finishFrom staged stepping handled

/-- Finish a delivery whose handler leaves the log and commit index alone. -/
theorem finish_plain (corr : Corr concrete abstract) {envelope : Model.Envelope Node TxId}
    (member : envelope ∈ concrete.network) {pre post : Abstract.Model.State Node TxId}
    {receiver value : NodeState Node TxId} {sends : List (Model.Envelope Node TxId)}
    (staged : Staged abstract pre envelope receiver)
    (received
      : Abstract.Model.handleReceive? pre envelope.source envelope.target = some post)
    (nodesPost : post.nodes = updateNode pre.nodes envelope.target value)
    (networkPost
      : forall target,
          post.network target
          = updateQueue pre.network envelope.target
              ((abstract.network envelope.target).erase (toAbstract envelope)) target
            ++ absQueue sends target)
    (preVotePost : post.preVoteStatus = pre.preVoteStatus)
    (retirementPost : post.retirementCompleted = pre.retirementCompleted)
    (logEq : value.log = (abstract.nodes envelope.target).log)
    (commitEq : value.commitIndex = (abstract.nodes envelope.target).commitIndex)
    (sendsEndpoints
      : forall sent,
          sent ∈ sends -> sent.source = envelope.target /\ sent.target = envelope.source)
    : exists after,
        Moves pre after
        /\ Corr
            {
              concrete with
                nodes := replaceNode concrete.nodes envelope.target value
                network := removeOne envelope concrete.network ++ sends
            }
            after := by
  refine finish corr member staged received nodesPost networkPost preVotePost ?_ ?_ sendsEndpoints
  · rw [retirementPost, staged.retirementCompleted, corr.retirementCompleted, logEq, commitEq]
  · intro node _
    rw [retirementPost]

theorem simulate_plainResponse {pre post : Abstract.Model.State Node TxId}
    (corr : Corr concrete abstract) {envelope : Model.Envelope Node TxId}
    (member : envelope ∈ concrete.network) {receiver value : NodeState Node TxId}
    (staged : Staged abstract pre envelope receiver)
    (received
      : Abstract.Model.handleReceive? pre envelope.source envelope.target = some post)
    (postEq
      : post
        = {
          pre with
            nodes := updateNode pre.nodes envelope.target value
            network :=
              updateQueue pre.network envelope.target
                ((abstract.network envelope.target).erase (toAbstract envelope))
        })
    (logEq : value.log = (abstract.nodes envelope.target).log)
    (commitEq : value.commitIndex = (abstract.nodes envelope.target).commitIndex)
    : exists after,
        Moves pre after
        /\ Corr
            {
              concrete with
                nodes := replaceNode concrete.nodes envelope.target value
                network := removeOne envelope concrete.network ++ []
            }
            after := by
  subst postEq
  refine finish_plain corr member staged received rfl ?_ rfl rfl logEq commitEq (by simp)
  intro target
  simp [absQueue]

theorem simulate_withResponse {pre post : Abstract.Model.State Node TxId}
    (corr : Corr concrete abstract) {envelope reply : Model.Envelope Node TxId}
    (member : envelope ∈ concrete.network) {receiver value : NodeState Node TxId}
    (staged : Staged abstract pre envelope receiver)
    (received
      : Abstract.Model.handleReceive? pre envelope.source envelope.target = some post)
    (postEq
      : post
        = {
          pre with
            nodes := updateNode pre.nodes envelope.target value
            network :=
              enqueue
                (updateQueue pre.network envelope.target
                  ((abstract.network envelope.target).erase (toAbstract envelope)))
                (toAbstract reply)
        })
    (logEq : value.log = (abstract.nodes envelope.target).log)
    (commitEq : value.commitIndex = (abstract.nodes envelope.target).commitIndex)
    (replySource : reply.source = envelope.target)
    (replyTarget : reply.target = envelope.source)
    : exists after,
        Moves pre after
        /\ Corr
            {
              concrete with
                nodes := replaceNode concrete.nodes envelope.target value
                network := removeOne envelope concrete.network ++ [reply]
            }
            after := by
  subst postEq
  refine finish_plain corr member staged received rfl ?_ rfl rfl logEq commitEq ?_
  · intro target
    exact enqueue_toAbstract _ _ _
  · intro sent listed
    simp only [List.mem_singleton] at listed
    subst listed
    exact ⟨replySource, replyTarget⟩

theorem handleAppendEntriesResponse_log (state : NodeState Node TxId) (source : Node)
    (response : Model.Local.AppendEntriesResponse)
    : (Model.Local.handleAppendEntriesResponse state source response).log = state.log
      /\ (Model.Local.handleAppendEntriesResponse state source response).commitIndex
          = state.commitIndex := by
  unfold Model.Local.handleAppendEntriesResponse
  split_ifs <;> exact ⟨rfl, rfl⟩

theorem handleRequestVoteRequest_log (state : NodeState Node TxId) (source : Node)
    (request : Model.Local.RequestVoteRequest)
    : (Model.Local.handleRequestVoteRequest state source request).1.log = state.log
      /\ (Model.Local.handleRequestVoteRequest state source request).1.commitIndex
          = state.commitIndex := by
  unfold Model.Local.handleRequestVoteRequest
  dsimp only
  split_ifs <;> exact ⟨rfl, rfl⟩

theorem handleRequestVoteResponse_log (state : NodeState Node TxId) (source : Node)
    (response : Model.Local.RequestVoteResponse)
    : (Model.Local.handleRequestVoteResponse state source response).log = state.log
      /\ (Model.Local.handleRequestVoteResponse state source response).commitIndex
          = state.commitIndex := by
  unfold Model.Local.handleRequestVoteResponse
  split_ifs <;> exact ⟨rfl, rfl⟩

theorem handleRequestPreVoteResponse_log (state : NodeState Node TxId) (source : Node)
    (response : Model.Local.RequestVoteResponse)
    : (Model.Local.handleRequestPreVoteResponse state source response).log = state.log
      /\ (Model.Local.handleRequestPreVoteResponse state source response).commitIndex
          = state.commitIndex := by
  unfold Model.Local.handleRequestPreVoteResponse
  split_ifs <;> exact ⟨rfl, rfl⟩

theorem handleProposeVoteRequest_log (state : NodeState Node TxId) (self : Node)
    (term : Nat)
    : (Model.Local.handleProposeVoteRequest state self term).log = state.log
      /\ (Model.Local.handleProposeVoteRequest state self term).commitIndex
          = state.commitIndex := by
  unfold Model.Local.handleProposeVoteRequest
  split_ifs <;> exact ⟨rfl, rfl⟩

/-- Every enabled delivery is simulated by abstract moves. -/
theorem simulate_deliver (corr : Corr concrete abstract)
    {envelope : Model.Envelope Node TxId} (member : envelope ∈ concrete.network)
    {state : NodeState Node TxId}
    (found : nodeState concrete envelope.target = some state)
    {execute : Model.Local.NodeEffect Node TxId (NodeState Node TxId)}
    (received
      : Model.Local.receive (Capabilities.record envelope.target) envelope.target
          envelope.source state envelope.payload
        = some execute)
    : exists after,
        Moves abstract after
        /\ Corr
            {
              concrete with
                nodes := replaceNode concrete.nodes envelope.target (execute.run {}).1
                network :=
                  removeOne envelope concrete.network ++ (execute.run {}).2.outgoing
            }
            after := by
  have here := corr.state found
  obtain ⟨prepared, staged⟩ := prepare corr member
  obtain ⟨sourceAllocated, _⟩ := corr.endpoints envelope member
  have preSource := (staged.allocated envelope.source).mpr sourceAllocated
  generalize observed (reordered abstract envelope) envelope = pre at prepared staged preSource
  rw [here] at staged
  have logOf : (Model.Local.observeTerm state envelope.payload).log =
      (abstract.nodes envelope.target).log := by
    rw [here]
    exact observeTerm_log state envelope.payload
  have commitOf : (Model.Local.observeTerm state envelope.payload).commitIndex =
      (abstract.nodes envelope.target).commitIndex := by
    rw [here]
    exact observeTerm_commitIndex state envelope.payload
  rcases envelope with ⟨source, destination, payload⟩
  cases payload with
  | appendEntriesRequest request =>
      simp only [Model.Local.receive] at received
      obtain ⟨⟨next, response⟩, handled, done⟩ := Option.bind_eq_some_iff.mp received
      have done := Option.some.inj done
      subst done
      obtain ⟨after, moves, related⟩ := simulate_appendEntriesRequest corr member staged handled
      exact ⟨after, prepared.trans moves, related⟩
  | appendEntriesResponse response =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      have bounded : (pre.nodes destination).role = .leader ->
          response.term <= (pre.nodes destination).currentTerm := by
        rw [staged.receiver]
        simp only [Model.Local.observeTerm]
        split_ifs with leader
        · intro _
          exact updateTerm_bounded _ _
        · intro isLeader
          exact absurd isLeader leader
      have handled := receive_appendResponse (state := pre) staged.queue preSource bounded
      rw [staged.receiver] at handled
      obtain ⟨after, moves, related⟩ := simulate_plainResponse corr member staged handled rfl
        ((handleAppendEntriesResponse_log _ _ _).1.trans logOf)
        ((handleAppendEntriesResponse_log _ _ _).2.trans commitOf)
      exact ⟨after, prepared.trans moves, related⟩
  | requestVoteRequest request =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      have bounded : request.term <= (pre.nodes destination).currentTerm := by
        rw [staged.receiver]
        exact updateTerm_bounded _ _
      have handled := receive_voteRequest (state := pre) staged.queue bounded
      rw [staged.receiver] at handled
      obtain ⟨after, moves, related⟩ := simulate_withResponse corr member staged handled
        (reply := ⟨destination, source, .requestVoteResponse
          (Model.Local.handleRequestVoteRequest
            (Model.Local.observeTerm state (.requestVoteRequest request)) source request).2⟩) rfl
        ((handleRequestVoteRequest_log _ _ _).1.trans logOf)
        ((handleRequestVoteRequest_log _ _ _).2.trans commitOf) rfl rfl
      exact ⟨after, prepared.trans moves, related⟩
  | requestVoteResponse response =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      have bounded : response.term <= (pre.nodes destination).currentTerm := by
        rw [staged.receiver]
        exact updateTerm_bounded _ _
      have handled := receive_voteResponse (state := pre) staged.queue preSource bounded
      rw [staged.receiver] at handled
      obtain ⟨after, moves, related⟩ := simulate_plainResponse corr member staged handled rfl
        ((handleRequestVoteResponse_log _ _ _).1.trans logOf)
        ((handleRequestVoteResponse_log _ _ _).2.trans commitOf)
      exact ⟨after, prepared.trans moves, related⟩
  | requestPreVote request =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      have bounded : request.term <= (pre.nodes destination).currentTerm := by
        rw [staged.receiver]
        exact updateTerm_bounded _ _
      have handled := receive_preVote (state := pre) staged.queue bounded
      rw [staged.receiver] at handled
      obtain ⟨after, moves, related⟩ := simulate_withResponse corr member staged handled
        (reply := ⟨destination, source, .requestPreVoteResponse
          (Model.Local.handleRequestPreVote
            (Model.Local.observeTerm state (.requestPreVote request)) request)⟩) rfl
        logOf commitOf rfl rfl
      exact ⟨after, prepared.trans moves, related⟩
  | requestPreVoteResponse response =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      have bounded : response.term <= (pre.nodes destination).currentTerm := by
        rw [staged.receiver]
        exact updateTerm_bounded _ _
      have handled := receive_preVoteResponse (state := pre) staged.queue preSource bounded
      rw [staged.receiver] at handled
      obtain ⟨after, moves, related⟩ := simulate_plainResponse corr member staged handled rfl
        ((handleRequestPreVoteResponse_log _ _ _).1.trans logOf)
        ((handleRequestPreVoteResponse_log _ _ _).2.trans commitOf)
      exact ⟨after, prepared.trans moves, related⟩
  | proposeVoteRequest term =>
      simp only [Model.Local.receive] at received
      have done := Option.some.inj received
      subst done
      have handled := receive_proposeVote (state := pre) staged.queue
      rw [staged.receiver] at handled
      have preTarget : pre.allocated destination :=
        (staged.allocated destination).mpr (corr.endpoints _ member).2
      have eligible : Abstract.Model.candidateTransitionEnabled pre destination <->
          Model.Local.candidateTransitionEnabled state destination := by
        unfold Abstract.Model.candidateTransitionEnabled Model.Local.candidateTransitionEnabled
        rw [staged.receiver, staged.retirementCompleted, corr.retirementCompleted destination]
        simp only [Model.Local.observeTerm, Model.Local.NodeState.retirementCompleted]
        rw [show abstract.nodes destination = state from here]
        exact ⟨fun enabled => enabled.2, fun enabled => ⟨preTarget, enabled⟩⟩
      obtain ⟨after, moves, related⟩ := simulate_plainResponse corr member staged handled
        (value := Model.Local.handleProposeVoteRequest state destination term)
        (by simp only [Model.Local.observeTerm, Model.Local.handleProposeVoteRequest, eligible])
        ((handleProposeVoteRequest_log _ _ _).1.trans (by rw [here]))
        ((handleProposeVoteRequest_log _ _ _).2.trans (by rw [here]))
      exact ⟨after, prepared.trans moves, related⟩

end Simulation

end CCFRaft.Proofs.Refinement
