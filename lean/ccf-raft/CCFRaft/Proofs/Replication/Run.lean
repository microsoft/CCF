module

public import CCFRaft.Proofs.Replication.Step
public import CCFRaft.Proofs.Safety.Origin
public import CCFRaft.Proofs.Replication.Eligible
public import CCFRaft.Proofs.Direct.AppendOnly

import all Init.Control.State

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The stable primary and its peers along a recorded execution

How a recorded step moves the stable primary's frontiers for a peer, and where AppendEntries traffic comes from.
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

/-! ## Events -/

theorem packet_of_delivered {event : Liveness.Event} {envelope : Model.Envelope}
    (delivered : event.delivered = some envelope)
    : exists packet, event = .deliver packet /\ packet.envelope = envelope := by
  cases event <;> simp_all [Event.delivered]

theorem action_of_delivered {event : Liveness.Event} {envelope : Model.Envelope}
    (delivered : event.delivered = some envelope)
    : event.action = some (.deliver envelope) := by
  cases event <;> simp_all [Event.action, Event.delivered]

theorem event_of_local {event : Liveness.Event} {node : NodeID} {input : Input}
    (selected : event.action = some (.local node input))
    : event = .local node input := by
  cases event <;> simp_all [Event.action]

theorem acts_internal {action : Model.Action} {actor : NodeID} {event : Model.Node.Event}
    {input : Input} (acts : Acts action actor event) (eq : event = .internal input)
    : action = .local actor input := by
  cases action with
  | «local» node input' =>
      obtain ⟨actorEq, eventEq⟩ := acts
      rw [eventEq] at eq
      cases eq
      rw [actorEq]
  | deliver envelope =>
      obtain ⟨_, eventEq⟩ := acts
      rw [eventEq] at eq
      cases eq

variable [Config.InitialConfiguration]

section Trace

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {nodes : List NodeID} {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- A node's commit index lies within its log. -/
theorem commit_le_length {index : Nat} {node : NodeID} {state : NodeState}
    (found : nodeAt trace index node = some state)
    : state.commitIndex <= state.log.length := by
  obtain ⟨point, pointFound, found⟩ := nodeAt_eq_some.mp found
  obtain ⟨_, exec⟩ := history_at admissible pointFound
  exact (now_of_found found).seen.commit_le exec

/-- The step that emitted a packet, the packet among its actor's sends. -/
theorem sent_step {index : Nat} {packet : Packet} (sent : SentAt trace index packet)
    : exists step action actor event state next outputs,
        trace.stepAt index = some step
        /\ step.action.action = some action
        /\ Acts action actor event
        /\ nodeState (proto step.before) actor = some state
        /\ (Model.Node.step (Capabilities.record actor) actor state event).run {}
            = some (next, outputs)
        /\ nodeState (proto step.after) actor = some next
        /\ packet.envelope ∈ outputs.outgoing
        /\ packet.envelope.source = actor := by
  obtain ⟨step, action, emitted, stepped, selected, out, member, -⟩ :=
    admissible.sentAt_emitted sent
  obtain ⟨actor, event, state, next, outputs, acts, found, ran, found', out', _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  rw [out', Option.some.injEq] at out
  subst out
  obtain ⟨new, eq, holds⟩ := CCFRaft.Proofs.Safety.summary actor state event {} _ _ ran
  have facts : Summary actor state event next outputs.outgoing := by simpa [eq] using holds
  exact ⟨step, action, actor, event, state, next, outputs, stepped, selected, acts, found,
    ran, found', member, (Summary.sends facts _ member).1⟩

/-! ## The stable primary's frontiers -/

/-- How one step moves the stable primary's frontiers for `peer`. -/
theorem leader_move {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) (peer : NodeID) {index : Nat}
    (le : start <= index) {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    {before after : NodeState}
    (found : nodeState (proto step.before) leader = some before)
    (found' : nodeState (proto step.after) leader = some after)
    : (after.matchIndex peer = before.matchIndex peer
        \/ exists envelope response,
            step.action.delivered = some envelope
            /\ envelope.source = peer
            /\ envelope.target = leader
            /\ envelope.payload = .appendEntriesResponse response
            /\ response.success = true
            /\ response.term = term
            /\ after.matchIndex peer = max (before.matchIndex peer) response.lastLogIndex)
      /\ (after.sentIndex peer = before.sentIndex peer
          \/ (exists batchEnds sent,
                step.action = .local leader (.sendEntries peer batchEnds)
                /\ Pass leader before peer batchEnds after sent
                /\ forall envelope,
                    envelope ∈ sent
                    -> exists packet,
                        SentAt trace index packet /\ packet.envelope = envelope)
          \/ (exists envelope response,
                step.action.delivered = some envelope
                /\ envelope.source = peer
                /\ envelope.target = leader
                /\ envelope.payload = .appendEntriesResponse response
                /\ response.success = false
                /\ after.sentIndex peer
                    = max
                        (min
                          (findHighestPossibleMatch before.log response.lastLogIndex
                            response.term)
                          (before.sentIndex peer))
                        (before.matchIndex peer))
          \/ exists contents content,
              step.action = .local leader (.append contents)
              /\ content ∈ contents
              /\ Not (content.metadata.configuration = none)
              /\ Not (peer ∈ eligiblePeers before leader)) := by
  cases selected : step.action.action with
  | none =>
      rw [admissible.stutter stepped selected, found, Option.some.injEq] at found'
      subst found'
      exact ⟨Or.inl rfl, Or.inl rfl⟩
  | some action =>
      obtain ⟨actor, event, state, next, outputs, acts, actorFound, ran, actorFound', out, others⟩ :=
        step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
      by_cases isLeader : actor = leader
      swap
      · have kept := others leader before (Ne.symm isLeader) found
        rw [found', Option.some.injEq] at kept
        subst kept
        exact ⟨Or.inl rfl, Or.inl rfl⟩
      subst isLeader
      rw [found, Option.some.injEq] at actorFound
      rw [found', Option.some.injEq] at actorFound'
      subst state next
      obtain ⟨primary, beforeTerm, _⟩ :=
        stable.state le (by rw [nodeAt_before stepped, found])
      obtain ⟨afterPrimary, afterTerm, _⟩ :=
        stable.state (Nat.le_succ_of_le le) (by rw [nodeAt_succ stepped, found'])
      obtain ⟨_, _, flow⟩ := leader_flow actor peer before primary event {} _ _ ran
      obtain ⟨matched, sentMove⟩ := flow afterPrimary (afterTerm.trans beforeTerm.symm)
      refine ⟨?_, ?_⟩
      · rcases matched with same | ⟨response, eventEq, success, termEq, value⟩
        · exact Or.inl same
        · obtain ⟨envelope, rfl, targetEq, sourceEq, payloadEq⟩ :=
            acts_receive acts eventEq
          exact Or.inr
            ⟨
              envelope,
              response,
              delivered_of_action selected,
              sourceEq,
              targetEq.symm,
              payloadEq,
              success,
              termEq.trans beforeTerm,
              value
            ⟩
      · rcases sentMove with same | ⟨batchEnds, eventEq, _, _⟩
            | ⟨response, eventEq, failure, value⟩ | ⟨contents, content, eventEq, member, config⟩
        · exact Or.inl same
        · have actionEq := acts_internal acts eventEq
          subst actionEq
          rw [eventEq] at ran
          obtain ⟨sent, outEq, pass⟩ := sendEntries_pass actor before peer batchEnds {} _ _ ran
          rw [outEq] at out
          refine Or.inr
            (Or.inl ⟨batchEnds, sent, event_of_local selected, pass, fun _ member => ?_⟩)
          obtain ⟨packet, recorded, envelope, -⟩ :=
            admissible.sentAt_of_emitted stepped selected out (List.mem_append_right _ member)
          exact ⟨packet, recorded, envelope⟩
        · obtain ⟨envelope, rfl, targetEq, sourceEq, payloadEq⟩ :=
            acts_receive acts eventEq
          exact Or.inr
            (Or.inr
              (Or.inl
                ⟨
                  envelope,
                  response,
                  delivered_of_action selected,
                  sourceEq,
                  targetEq.symm,
                  payloadEq,
                  failure,
                  value
                ⟩))
        · have actionEq := acts_internal acts eventEq
          subst actionEq
          by_cases eligible : peer ∈ eligiblePeers before actor
          · rw [eventEq] at ran
            obtain ⟨_, _, kept, _⟩ :=
              appendBatch_eligible actor before contents
                (commit_le_length admissible
                  (by rw [nodeAt_before stepped, found])) {} _ _ ran
            exact Or.inl (kept peer eligible)
          · exact Or.inr
              (Or.inr
                (Or.inr ⟨contents, content, event_of_local selected, member, config, eligible⟩))

/-- A node's commit index never drops in a recorded step. -/
theorem commit_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {node : NodeID} {before after : NodeState}
    (found : nodeState (proto step.before) node = some before)
    (found' : nodeState (proto step.after) node = some after)
    : before.commitIndex <= after.commitIndex := by
  cases selected : step.action.action with
  | none =>
      rw [admissible.stutter stepped selected, found, Option.some.injEq] at found'
      exact (congrArg NodeState.commitIndex found').le
  | some action =>
      obtain ⟨actor, event, state, next, outputs, _, actorFound, ran, actorFound', _, others⟩ :=
        step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
      by_cases same : actor = node
      · subst same
        rw [found, Option.some.injEq] at actorFound
        rw [found', Option.some.injEq] at actorFound'
        subst state next
        exact (CCFRaft.Proofs.Direct.extends_step ran).1
      · have kept := others node before (Ne.symm same) found
        rw [found', Option.some.injEq] at kept
        exact (congrArg NodeState.commitIndex kept).ge

/-- A node's commit index never drops between recorded states. -/
theorem commit_mono {node : NodeID} {index later : Nat} (le : index <= later)
    {before after : NodeState} (found : nodeAt trace index node = some before)
    (found' : nodeAt trace later node = some after)
    : before.commitIndex <= after.commitIndex := by
  obtain ⟨first, firstFound, nodeFound⟩ := nodeAt_eq_some.mp found
  obtain ⟨last, lastFound, nodeFound'⟩ := nodeAt_eq_some.mp found'
  obtain ⟨state, stateFound, grows⟩ :=
    trace.induction (start := index)
      (motive := fun _ point =>
        exists state, nodeState (proto point) node = some state
          /\ before.commitIndex <= state.commitIndex)
      (fun point pointFound => by
        rw [firstFound, Option.some.injEq] at pointFound
        subst pointFound
        exact ⟨before, nodeFound, le_rfl⟩)
      (fun index step _ stepped ⟨state, stateFound, grows⟩ => by
        obtain ⟨next, nextFound, _⟩ :=
          term_mono admissible (Nat.le_succ index)
            (by rw [nodeAt_before stepped, stateFound])
            (Trace.stateAt_succ_of_stepAt stepped)
        rw [nodeAt_succ stepped] at nextFound
        exact ⟨next, nextFound, grows.trans (commit_step admissible stepped stateFound nextFound)⟩)
      later last le lastFound
  rw [nodeFound', Option.some.injEq] at stateFound
  subst stateFound
  exact grows

/-- A rejection delivered to the stable primary from an eligible peer moves that
peer's retry index exactly as the handler computes it. -/
theorem nack_exact {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {envelope : Model.Envelope}
    (delivered : step.action.delivered = some envelope)
    (target : envelope.target = leader) {response : AppendEntriesResponse}
    (payload : envelope.payload = .appendEntriesResponse response)
    (failure : response.success = false) {before after : NodeState}
    (found : nodeState (proto step.before) leader = some before)
    (found' : nodeState (proto step.after) leader = some after)
    (eligible : envelope.source ∈ eligiblePeers before leader)
    : after.sentIndex envelope.source
      = max
          (min (findHighestPossibleMatch before.log response.lastLogIndex response.term)
            (before.sentIndex envelope.source))
          (before.matchIndex envelope.source) := by
  have selected := action_of_delivered delivered
  obtain ⟨actor, event, state, next, outputs, ⟨actorEq, eventEq⟩, actorFound, ran, actorFound',
      _, _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  subst actorEq eventEq
  rw [target] at actorFound actorFound' ran
  rw [payload] at ran
  rw [found, Option.some.injEq] at actorFound
  rw [found', Option.some.injEq] at actorFound'
  subst state next
  obtain ⟨primary, beforeTerm, _⟩ :=
    stable.state le (by rw [nodeAt_before stepped, found])
  have afterTerm :=
    stable.current (Nat.le_succ_of_le le) (by rw [nodeAt_succ stepped, found'])
  have le : response.term <= before.currentTerm := by
    by_contra newer
    have bumped := newer_response_deposes leader envelope.source before after response outputs
      ran eligible primary (Nat.lt_of_not_le newer)
    omega
  obtain ⟨_, _, value⟩ := receive_nack leader before primary envelope.source eligible response
    failure le {} _ _ ran
  exact value

/-- A success of the term or newer delivered to the stable primary from an eligible
peer raises that peer's match index to the acknowledged index. -/
theorem ack_exact {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {envelope : Model.Envelope}
    (delivered : step.action.delivered = some envelope)
    (target : envelope.target = leader) {response : AppendEntriesResponse}
    (payload : envelope.payload = .appendEntriesResponse response)
    (success : response.success = true) (current : term <= response.term)
    {before after : NodeState}
    (found : nodeState (proto step.before) leader = some before)
    (found' : nodeState (proto step.after) leader = some after)
    (eligible : envelope.source ∈ eligiblePeers before leader)
    : after.matchIndex envelope.source
      = max (before.matchIndex envelope.source) response.lastLogIndex := by
  have selected := action_of_delivered delivered
  obtain ⟨actor, event, state, next, outputs, ⟨actorEq, eventEq⟩, actorFound, ran, actorFound',
      _, _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  subst actorEq eventEq
  rw [target] at actorFound actorFound' ran
  rw [payload] at ran
  rw [found, Option.some.injEq] at actorFound
  rw [found', Option.some.injEq] at actorFound'
  subst state next
  obtain ⟨primary, beforeTerm, _⟩ :=
    stable.state le (by rw [nodeAt_before stepped, found])
  have afterTerm :=
    stable.current (Nat.le_succ_of_le le) (by rw [nodeAt_succ stepped, found'])
  have le : response.term <= before.currentTerm := by
    by_contra newer
    have bumped := newer_response_deposes leader envelope.source before after response outputs
      ran eligible primary (Nat.lt_of_not_le newer)
    omega
  obtain ⟨_, _, value⟩ := receive_ack leader before primary envelope.source eligible response
    success (by omega) {} _ _ ran
  exact value

/-! ## AppendEntries traffic -/

/-- A node receiving an AppendEntries request no newer than its term runs `AEStep`,
and the step's sends are exactly the `AEStep` sends. -/
theorem receive_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {envelope : Model.Envelope}
    (delivered : step.action.delivered = some envelope)
    {request : AppendEntriesRequest}
    (payload : envelope.payload = .appendEntriesRequest request) {before : NodeState}
    (found : nodeState (proto step.before) envelope.target = some before)
    (le : request.term <= before.currentTerm)
    : exists after sends,
        nodeState (proto step.after) envelope.target = some after
        /\ AEStep envelope.target envelope.source (awareState before request) request
            after sends
        /\ outgoing (proto step.before) (.deliver envelope) = some sends := by
  have selected := action_of_delivered delivered
  obtain ⟨actor, event, state, next, outputs, ⟨actorEq, eventEq⟩, actorFound, ran, actorFound',
      out, _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  subst actorEq eventEq
  rw [found, Option.some.injEq] at actorFound
  subst state
  rw [payload] at ran
  obtain ⟨new, outEq, step⟩ := receive_ae envelope.target before envelope.source request le
    {} _ _ ran
  refine ⟨next, new, actorFound', step, ?_⟩
  rw [out, outEq]
  simp

/-- Every AppendEntries response answers an AppendEntries request delivered in the
same step. -/
theorem response_origin {index : Nat} {packet : Packet} (sent : SentAt trace index packet)
    {response : AppendEntriesResponse}
    (payload : packet.envelope.payload = .appendEntriesResponse response)
    : exists step envelope request before,
        trace.stepAt index = some step
        /\ step.action.delivered = some envelope
        /\ envelope.target = packet.envelope.source
        /\ envelope.payload = .appendEntriesRequest request
        /\ nodeState (proto step.before) envelope.target = some before := by
  obtain ⟨step, action, actor, event, state, _, outputs, stepped, selected, acts, found, ran,
      _, member, source⟩ := sent_step admissible sent
  obtain ⟨new, outEq, origins⟩ := origin actor state event {} _ _ ran
  have mem : packet.envelope ∈ new := by
    have := member
    rw [outEq] at this
    simpa using this
  obtain ⟨requester, request, eventEq⟩ := (origins _ mem).1 response payload
  obtain ⟨envelope, rfl, targetEq, _, payloadEq⟩ := acts_receive acts eventEq
  refine ⟨
    step,
    envelope,
    request,
    state,
    stepped,
    delivered_of_action selected,
    ?_,
    payloadEq,
    ?_
  ⟩
  · rw [← targetEq, source]
  · rw [← targetEq]
    exact found

/-- Every AppendEntries request a primary sends is a batch of a `sendEntries` pass,
or comes from appending a configuration change. -/
theorem request_origin {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (sent : SentAt trace index packet) {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    {before : NodeState}
    (found : nodeState (proto step.before) packet.envelope.source = some before)
    (primary : before.role = .primary)
    : (exists batchEnds batch,
        step.action
          = .local packet.envelope.source (.sendEntries packet.envelope.target batchEnds)
        /\ isPass before.log (before.sentIndex packet.envelope.target) batchEnds = true
        /\ batch ∈ passBatches (before.sentIndex packet.envelope.target) batchEnds
        /\ request = makeAppendEntriesRequest before batch.1 batch.2)
      \/ exists contents content,
          step.action = .local packet.envelope.source (.append contents)
          /\ content ∈ contents
          /\ Not (content.metadata.configuration = none)
          /\ Not
              (packet.envelope.target ∈ eligiblePeers before packet.envelope.source) := by
  obtain ⟨sentStep, action, actor, event, state, _, _, sentStepped, selected, acts, actorFound,
      ran, _, member, source⟩ := sent_step admissible sent
  rw [stepped, Option.some.injEq] at sentStepped
  subst sentStep
  rw [← source, found, Option.some.injEq] at actorFound
  subst state
  obtain ⟨new, outEq, origins⟩ := origin actor before event {} _ _ ran
  have mem : packet.envelope ∈ new := by
    have := member
    rw [outEq] at this
    simpa using this
  rcases (origins _ mem).2 request payload primary
      with ⟨batchEnds, batch, eventEq, valid, batchMem, requestEq⟩
      | ⟨contents, content, eventEq, contentMem, config⟩
  · have actionEq := acts_internal acts eventEq
    subst actionEq
    exact Or.inl ⟨batchEnds, batch, by rw [source]; exact event_of_local selected, valid,
      batchMem, requestEq⟩
  · have actionEq := acts_internal acts eventEq
    subst actionEq
    rw [eventEq] at ran
    obtain ⟨new', outEq', _, aimed⟩ :=
      appendBatch_eligible actor before contents
        (commit_le_length admissible
          (by rw [nodeAt_before stepped, found])) {} _ _ ran
    have mem' : packet.envelope ∈ new' := by
      have := member
      rw [outEq'] at this
      simpa using this
    refine Or.inr ⟨contents, content, by rw [source]; exact event_of_local selected, contentMem,
      config, ?_⟩
    rw [source]
    exact aimed _ request mem' payload

end Trace

end CCFRaft.Proofs.Replication
