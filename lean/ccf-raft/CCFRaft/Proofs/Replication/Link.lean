module

public import CCFRaft.Proofs.Replication.Run

import all Init.Control.State

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The link from the stable primary to one peer

Facts about the AppendEntries traffic between the stable primary and a peer of
its term: what the primary sends, what a delivered request carries, and how the
peer's log compares with the primary's at every index.
-/

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft
open CCFRaft.Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Replication

theorem messageEntries_length {log : List Entry} {previous batchEnd : Nat}
    (bound : batchEnd <= log.length)
    : (messageEntries log previous batchEnd).length = batchEnd - previous := by
  simp only [messageEntries, List.length_take, List.length_drop]
  omega

variable [Config.InitialConfiguration]

/-- What a node's state says about its log relative to the primary's log. -/
structure View (leaderLog : List Entry) (term : Nat) (state : NodeState)
    (matchIndex : Nat)
    : Prop where
  matching
    : forall index,
        0 < index
        -> index <= state.log.length
        -> index <= leaderLog.length
        -> termAt state.log index = termAt leaderLog index
        -> state.log.take index = leaderLog.take index
  commit : state.commitIndex <= agree state.log leaderLog
  settled : Settled state -> state.log <+: leaderLog
  sorted : state.log.Pairwise fun first second => first.term <= second.term
  positive
    : forall index, 0 < index -> index <= state.log.length -> 0 < termAt state.log index
  matchLe : matchIndex <= agree state.log leaderLog
  leaderSorted : leaderLog.Pairwise fun first second => first.term <= second.term
  leaderTerms : forall index, termAt leaderLog index <= term
  leaderPositive
    : forall index, 0 < index -> index <= leaderLog.length -> 0 < termAt leaderLog index

section Trace

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {nodes : List NodeID} {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- A peer of the term, seen against the stable primary at the same index. -/
theorem view_at {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {peer : NodeID}
    (different : Not (peer = leader)) {index : Nat} (le : start <= index)
    {leaderState state : NodeState}
    (leaderFound : nodeAt trace index leader = some leaderState)
    (found : nodeAt trace index peer = some state) (current : state.currentTerm = term)
    : View leaderState.log term state (leaderState.matchIndex peer) := by
  obtain ⟨point, pointFound, leaderFound⟩ := nodeAt_eq_some.mp leaderFound
  rw [nodeAt_of_stateAt pointFound] at found
  obtain ⟨rest, exec⟩ := history_at admissible pointFound
  have lead := lead_at stable le pointFound exec leaderFound
  have now := now_of_found (rest := rest) found
  exact {
    matching := fun _ positive bound leaderBound same =>
      lead.matching now.seen positive bound leaderBound same
    commit := lead.commit_le now current.le
    settled := fun settled => lead.settled_prefix now settled current
    sorted := lead.inv.sorted peer state now
    positive := fun _ positive bound => termAt_pos lead.inv now positive bound
    matchLe := lead.match_le different now current
    leaderSorted := lead.sorted
    leaderTerms := lead.termAt_le
    leaderPositive := fun _ positive bound => termAt_pos lead.inv lead.now positive bound
  }

/-- A request of the term delivered at an index is a slice of the stable
primary's log at that index. -/
theorem request_at {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {envelope : Model.Envelope}
    (delivered : step.action.delivered = some envelope) {request : AppendEntriesRequest}
    (payload : envelope.payload = .appendEntriesRequest request)
    (current : request.term = term) {leaderState : NodeState}
    (leaderFound : nodeState (proto step.before) leader = some leaderState)
    : envelope.source = leader
      /\ Not (envelope.target = leader)
      /\ request.prevLogIndex <= leaderState.log.length
      /\ request.prevLogTerm = termAt leaderState.log request.prevLogIndex
      /\ request.entries <+: leaderState.log.drop request.prevLogIndex := by
  obtain ⟨rest, exec⟩ := history_at admissible (Trace.stateAt_of_stepAt stepped)
  have lead := lead_at stable le (Trace.stateAt_of_stepAt stepped) exec leaderFound
  have queued := (Concrete.step_deliver
    (admissible.step stepped (action_of_delivered delivered))).1
  exact lead.request queued payload current

/-- Every request of the stable primary to a peer eligible when it was sent is a
batch of a `sendEntries` pass over the primary's log. -/
theorem leader_request {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {before : NodeState}
    (found : nodeState (proto step.before) leader = some before) {packet : Packet}
    (eligible : packet.envelope.target ∈ eligiblePeers before leader)
    (sent : SentAt trace index packet) (source : packet.envelope.source = leader)
    {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    : exists batchEnds batch,
        step.action = .local leader (.sendEntries packet.envelope.target batchEnds)
        /\ isPass before.log (before.sentIndex packet.envelope.target) batchEnds = true
        /\ batch ∈ passBatches (before.sentIndex packet.envelope.target) batchEnds
        /\ request = makeAppendEntriesRequest before batch.1 batch.2 := by
  have packetFound : nodeState (proto step.before) packet.envelope.source = some before := by
    rw [source]
    exact found
  rcases request_origin admissible stepped sent payload packetFound
      (stable.primary le (by rw [nodeAt_before stepped, found]))
      with ⟨batchEnds, batch, event, valid, member, requestEq⟩
      | ⟨_, _, _, _, _, aimed⟩
  · rw [source] at event
    exact ⟨batchEnds, batch, event, valid, member, requestEq⟩
  · rw [source] at aimed
    exact absurd eligible aimed

/-- The shape of a stable primary's request to `peer`. -/
theorem leader_request_shape {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {before : NodeState}
    (found : nodeState (proto step.before) leader = some before) {packet : Packet}
    (eligible : packet.envelope.target ∈ eligiblePeers before leader)
    (sent : SentAt trace index packet) (source : packet.envelope.source = leader)
    {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    : request.term = term
      /\ before.sentIndex packet.envelope.target <= request.prevLogIndex
      /\ request.prevLogIndex + request.entries.length <= before.log.length := by
  obtain ⟨_, batch, _, valid, member, rfl⟩ :=
    leader_request admissible stable le stepped found eligible sent source payload
  obtain ⟨low, ordered, bound, _⟩ := passBatches_bounds valid batch member
  refine ⟨stable.current le (by rw [nodeAt_before stepped, found]), low, ?_⟩
  simp only [makeAppendEntriesRequest, messageEntries_length bound]
  omega

/-- A node that receives a request is at least at the request's term afterwards. -/
theorem request_term_le {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {envelope : Model.Envelope}
    (delivered : step.action.delivered = some envelope)
    {request : AppendEntriesRequest}
    (payload : envelope.payload = .appendEntriesRequest request) {after : NodeState}
    (found' : nodeState (proto step.after) envelope.target = some after)
    : request.term <= after.currentTerm := by
  have selected := action_of_delivered delivered
  obtain ⟨actor, localEvent, state, next, outputs, ⟨actorEq, eventEq⟩, _, ran, actorFound', _,
      _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  subst actorEq eventEq
  rw [payload] at ran
  rw [found', Option.some.injEq] at actorFound'
  subst actorFound'
  obtain ⟨_, _, received, _⟩ :=
    CCFRaft.Proofs.Safety.receive_ae_term envelope.target state envelope.source request {} _ _ ran
  exact received

end Trace

end CCFRaft.Proofs.Replication
