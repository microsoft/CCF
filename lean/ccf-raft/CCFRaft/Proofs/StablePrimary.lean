module

public import CCFRaft.Proofs.CommitLiveness

import all Init.Control.State

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Executions with a stable primary

Step facts about a stable primary: what a step and a send pass record, that a
response with a newer term from an eligible peer deposes it, and the requests it
sends from the start of its stability.

The final commit step is also proved here: a successful current-term
acknowledgement reaching a primary whose signature is already acknowledged by a
quorum commits that signature.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.StablePrimary

open CCFRaft.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)

/-- The node and local event that an action runs. -/
def Acts : Model.Action -> NodeID -> Model.Node.Event -> Prop
  | .local node input, actor, event => actor = node /\ event = .internal input
  | .deliver envelope, actor, event =>
      actor = envelope.target /\ event = .receive envelope.source envelope.payload

section Steps

variable [Config.InitialConfiguration]

/-- One protocol step: its actor's states and sends, other nodes unchanged. -/
theorem step_found {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable before)
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    : exists actor event state next outputs,
        Acts action actor event
        /\ nodeState before actor = some state
        /\ (Model.Node.step (Capabilities.record actor) actor state event).run {}
            = some (next, outputs)
        /\ nodeState after actor = some next
        /\ outgoing before action = some outputs.outgoing
        /\ forall node other,
            Not (node = actor)
            -> nodeState before node = some other
            -> nodeState after node = some other := by
  have distinct := Direct.keys_nodup (TransitionSystem.Reachable.step reachable stepped)
  cases action with
  | «local» node input =>
      obtain ⟨state, next, outputs, found, ran, rfl⟩ := Concrete.step_local stepped
      have ran' :
          (Model.Node.step (Capabilities.record node) node state (.internal input)).run {}
            = some (next, outputs) := ran
      refine ⟨
        node,
        .internal input,
        state,
        next,
        outputs,
        ⟨rfl, rfl⟩,
        found,
        ran',
        ?_,
        ?_,
        ?_
      ⟩
      · exact Direct.nodeState_of_mem distinct
          (List.mem_map.mpr ⟨(node, state), Concrete.mem_of_nodeState found, by simp⟩)
      · simp [outgoing, found, ran']
      · intro other value different otherFound
        exact Direct.nodeState_of_mem distinct
          (List.mem_map.mpr
            ⟨(other, value), Concrete.mem_of_nodeState otherFound, by simp [different]⟩)
  | deliver envelope =>
      obtain ⟨_, state, next, outputs, found, ran, rfl⟩ := Concrete.step_deliver stepped
      have ran' :
          (Model.Node.step (Capabilities.record envelope.target) envelope.target state
                (.receive envelope.source envelope.payload)).run
              {}
            = some (next, outputs) := ran
      refine ⟨
        envelope.target,
        .receive envelope.source envelope.payload,
        state,
        next,
        outputs,
        ⟨rfl, rfl⟩,
        found,
        ran',
        ?_,
        ?_,
        ?_
      ⟩
      · exact Direct.nodeState_of_mem distinct
          (List.mem_map.mpr ⟨(envelope.target, state), Concrete.mem_of_nodeState found, by simp⟩)
      · simp [outgoing, found, ran']
      · intro other value different otherFound
        exact Direct.nodeState_of_mem distinct
          (List.mem_map.mpr
            ⟨(other, value), Concrete.mem_of_nodeState otherFound, by simp [different]⟩)

end Steps

/-! ## Local handlers -/

/-- A primary that hears of a newer term from an eligible peer stops being primary. -/
theorem newer_response_deposes (self source : NodeID) (state next : NodeState)
    (response : AppendEntriesResponse)
    (outputs : CCF.Outputs NodeID Message Notification)
    (ran
      : (receive (Capabilities.record self) self source state
          (.appendEntriesResponse response)).run
          {}
        = some (next, outputs))
    (eligible : source ∈ eligiblePeers state self) (primary : state.role = .primary)
    (newer : state.currentTerm < response.term)
    : next.currentTerm = response.term := by
  have observed :
      observeTerm state (.appendEntriesResponse response) = bumpedState state response.term := by
    rcases observe_response state response with ⟨_, _, bumped⟩ | ⟨stays, _⟩
    · exact bumped
    · exact absurd (stays primary) (Nat.not_le.mpr newer)
  unfold receive at ran
  simp only [eligible, observed] at ran
  simp [handleAppendEntriesResponse, bumpedState, StateT.run, pure, StateT.pure] at ran
  rw [← ran.1]

theorem hasQuorum_mono {configurations : List Configuration} {small large : Finset NodeID}
    (quorum : hasQuorum configurations small) (sub : small ⊆ large)
    : hasQuorum configurations large := by
  refine ⟨quorum.1, List.all_eq_true.mpr fun configuration member => ?_⟩
  have majority := hasQuorum_majority quorum member
  simp only [hasConfigurationMajority, decide_eq_true_eq] at majority ⊢
  have := Finset.card_le_card (Finset.inter_subset_inter sub (subset_refl configuration.nodes))
  omega

/-- The final commit step: a successful current-term acknowledgement that reaches
a primary holding a quorum-acknowledged current-term signature commits it. -/
theorem ack_commits (self source : NodeID) (state next : NodeState)
    (response : AppendEntriesResponse)
    (outputs : CCF.Outputs NodeID Message Notification)
    (ran
      : (receive (Capabilities.record self) self source state
          (.appendEntriesResponse response)).run
          {}
        = some (next, outputs))
    (eligible : source ∈ eligiblePeers state self) (primary : state.role = .primary)
    (success : response.success = true) (current : response.term = state.currentTerm)
    {signature : Nat} (ready : SignatureReady state self signature)
    : signature <= next.commitIndex := by
  have observed : observeTerm state (.appendEntriesResponse response) = state := by
    rcases observe_response state response with ⟨_, newer, _⟩ | ⟨_, stays⟩
    · omega
    · exact stays
  let updated : NodeState :=
    {
      state with
        matchIndex :=
          Function.update state.matchIndex source
            (max (state.matchIndex source) response.lastLogIndex)
    }
  have ready' : SignatureReady updated self signature := by
    obtain ⟨inLog, isSignature, termEq, quorum⟩ := ready
    refine ⟨inLog, isSignature, termEq, hasQuorum_mono quorum ?_⟩
    intro node member
    simp only [Finset.mem_filter] at member ⊢
    refine ⟨member.1, member.2.imp id fun covered => le_trans covered ?_⟩
    by_cases same : node = source
    · subst same
      simp [updated]
    · simp [updated, Function.update, same]
  have reduces
      : receive (Capabilities.record self) self source state (.appendEntriesResponse response)
        = advanceCommit (Capabilities.record self) updated self := by
    unfold receive
    simp [eligible, observed, handleAppendEntriesResponse, primary, success, current, updated]
  obtain ⟨after, effects, run, committed⟩ :=
    CCFRaft.Proofs.Liveness.acknowledged_signature_commits updated self signature ready'
  rw [reduces, run, Option.some.injEq, Prod.mk.injEq] at ran
  rw [← ran.1]
  exact committed

/-! ## The stable primary's peers -/

section Recorded

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {nodes : List NodeID} {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- Every send of the execution comes from a step satisfying the step summary. -/
theorem sent_summary {index : Nat} {packet : Packet} (sent : SentAt trace index packet)
    : exists actor event state next sends,
        nodeAt trace (index + 1) actor = some next
        /\ Summary actor state event next sends
        /\ packet.envelope ∈ sends := by
  obtain ⟨step, action, emitted, stepped, selected, out, member, -⟩ :=
    admissible.sentAt_emitted sent
  obtain ⟨actor, event, state, next, outputs, _, _, ran, found', out', _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  obtain ⟨new, eq, holds⟩ := CCFRaft.Proofs.Safety.summary actor state event {} _ _ ran
  rw [out', Option.some.injEq] at out
  subst out
  refine ⟨actor, event, state, next, outputs.outgoing, ?_, ?_, member⟩
  · rw [nodeAt_succ stepped, found']
  · simpa [eq] using holds

/-- A recorded send pass: its effect on the primary, and the recorded sends of its
batches, all at the step's before-time. -/
theorem pass_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {leader peer : NodeID}
    {batchEnds : List Nat}
    (event : step.action = .local leader (.sendEntries peer batchEnds))
    {before : NodeState} (found : nodeState (proto step.before) leader = some before)
    : exists after sent,
        nodeState (proto step.after) leader = some after
        /\ Pass leader before peer batchEnds after sent
        /\ forall envelope,
            envelope ∈ sent
            -> exists packet,
                SentAt trace index packet
                /\ packet.envelope = envelope
                /\ packet.sentAt = time step.before := by
  have selected : step.action.action = some (.local leader (.sendEntries peer batchEnds)) := by
    rw [event]
    rfl
  obtain ⟨actor, localEvent, current, next, outputs, ⟨actorEq, eventEq⟩, actorFound, ran,
      nextFound, out, _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  subst actorEq eventEq
  rw [found, Option.some.injEq] at actorFound
  subst actorFound
  obtain ⟨sent, outEq, pass⟩ := sendEntries_pass actor before peer batchEnds {} _ _ ran
  rw [outEq] at out
  exact ⟨next, sent, nextFound, pass, fun _ member =>
    admissible.sentAt_of_emitted stepped selected out (List.mem_append_right _ member)⟩

/-- A send pass of a primary whose retirement is not committed records each of its
batches. -/
theorem pass_sends {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {leader peer : NodeID}
    {batchEnds : List Nat}
    (event : step.action = .local leader (.sendEntries peer batchEnds))
    {before : NodeState} (found : nodeState (proto step.before) leader = some before)
    (notRetired : Not (before.isRetiredCommitted leader)) {batch : Nat × Nat}
    (member : batch ∈ passBatches (before.sentIndex peer) batchEnds)
    : exists packet,
        SentAt trace index packet
        /\ packet.envelope = batchEnvelope before leader peer batch
        /\ packet.sentAt = time step.before := by
  obtain ⟨_, _, _, pass, recorded⟩ := pass_step admissible stepped event found
  exact recorded _ (pass.sent_of_mem notRetired member)

/-- A node's term never decreases along an execution, and the node stays present. -/
theorem term_mono {node : NodeID} {index later : Nat} (le : index <= later)
    {before : NodeState} (found : nodeAt trace index node = some before)
    {last : W} (lastFound : trace.stateAt later = some last)
    : exists after,
        nodeAt trace later node = some after
        /\ before.currentTerm <= after.currentTerm := by
  obtain ⟨first, firstFound, nodeFound⟩ := nodeAt_eq_some.mp found
  obtain ⟨after, afterFound, grows⟩ :=
    trace.chain
      (relation := fun first last =>
        forall before,
          nodeState (proto first) node = some before
          -> exists after,
              nodeState (proto last) node = some after
              /\ before.currentTerm <= after.currentTerm)
      (fun _ before found => ⟨before, found, le_rfl⟩)
      (fun _ _ _ first second before found => by
        obtain ⟨middle, middleFound, grows⟩ := first before found
        obtain ⟨after, afterFound, grows'⟩ := second middle middleFound
        exact ⟨after, afterFound, grows.trans grows'⟩)
      (fun _ step stepped middle middleFound => by
        cases selected : step.action.action with
        | none =>
            exact ⟨middle, by rw [admissible.stutter stepped selected]; exact middleFound,
              le_rfl⟩
        | some action =>
            obtain ⟨actor, event, state, next, outputs, _, actorFound, ran, actorFound', _,
                others⟩ :=
              step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
            by_cases same : node = actor
            · subst same
              rw [actorFound, Option.some.injEq] at middleFound
              subst middleFound
              obtain ⟨_, _, facts⟩ := CCFRaft.Proofs.Safety.summary node state event {} _ _ ran
              exact ⟨next, actorFound', Summary.term_le facts⟩
            · exact ⟨middle, others node middle same middleFound, le_rfl⟩)
      le firstFound lastFound before nodeFound
  exact ⟨after, by rw [nodeAt_of_stateAt lastFound, afterFound], grows⟩

/-- Every AppendEntries request a stable primary sends from `start` on carries its
term. -/
theorem stable_requests {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {sent : Nat} {packet : Packet}
    (afterStart : start <= sent) (sentAt : SentAt trace sent packet)
    (source : packet.envelope.source = leader) {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    : request.term = term := by
  obtain ⟨actor, event, state, next, sends, found, facts, member⟩ :=
    sent_summary admissible sentAt
  obtain ⟨sender, ok⟩ := Summary.sends facts _ member
  rw [payload] at ok
  have same : actor = leader := sender.symm.trans source
  subst same
  exact ok.1.2.1.trans (stable.current (Nat.le_succ_of_le afterStart) found)

/-- The final commit step along an execution, for an acknowledgement of the
primary's term or newer. -/
theorem ack_commits_trace {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat}
    (afterStart : start <= index) {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (action : step.action = .deliver packet) (target : packet.envelope.target = leader)
    {response : AppendEntriesResponse}
    (payload : packet.envelope.payload = .appendEntriesResponse response)
    (success : response.success = true) (current : term <= response.term)
    {state : NodeState} (found : nodeAt trace index leader = some state)
    (eligible : packet.envelope.source ∈ eligiblePeers state leader) {signature : Nat}
    (ready : SignatureReady state leader signature)
    : exists after,
        nodeAt trace (index + 1) leader = some after
        /\ signature <= after.commitIndex := by
  have selected : step.action.action = some (.deliver packet.envelope) := by
    rw [action]; rfl
  obtain ⟨actor, localEvent, primary, next, outputs, acts, actorFound, ran, actorFound', _, _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  obtain ⟨same, eventEq⟩ := acts
  subst same eventEq
  rw [target] at actorFound actorFound' ran
  rw [payload] at ran
  have role := stable.primary afterStart found
  have stableTerm := stable.current afterStart found
  rw [nodeAt_before stepped, actorFound, Option.some.injEq] at found
  subst found
  have afterNode : nodeAt trace (index + 1) leader = some next := by
    rw [nodeAt_succ stepped, actorFound']
  have le : response.term <= primary.currentTerm := by
    by_contra newer
    have bumped := newer_response_deposes leader _ primary next response outputs ran eligible role
      (Nat.lt_of_not_le newer)
    have := stable.current (Nat.le_succ_of_le afterStart) afterNode
    omega
  exact ⟨
    next,
    afterNode,
    ack_commits leader _ primary next response outputs ran eligible role success
      (by omega) ready
  ⟩

end Recorded

end CCFRaft.Proofs.StablePrimary
