module

public import CCFRaft.Proofs.StablePrimary
public import CCFRaft.Proofs.Safety.LeaderFlow
public import CCFRaft.Proofs.Replication.Lead

import all Init.Control.State

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Steps of a timed execution under a stable primary

Each protocol step of a timed execution is a step of a safety history, so the
safety invariant and the primary-relative facts of `Lead` hold at every index.
This file derives the per-step facts the replication argument uses: how a
follower of the term changes its log, and how a rejection moves the primary's
retry index.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Replication

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)

/-! ## Handlers -/

section Handlers

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

/-- A primary that receives a rejection of its term or older from an eligible peer
moves that peer's retry index exactly as the handler computes it. -/
theorem receive_nack (before : NodeState) (leader : before.role = .primary)
    (source : NodeID) (eligible : source ∈ eligiblePeers before self)
    (response : AppendEntriesResponse) (failure : response.success = false)
    (le : response.term <= before.currentTerm)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          after.sentIndex source
          = max
              (min
                (findHighestPossibleMatch before.log response.lastLogIndex response.term)
                (before.sentIndex source))
              (before.matchIndex source))
        (receive caps self source before (.appendEntriesResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun ignored => absurd eligible (by simpa using ignored)) fun _ => ?_
  rcases observe_response before response with ⟨_, bump, _⟩ | ⟨_, eq⟩
  · exact absurd le (Nat.not_le.mpr bump)
  rw [eq]
  simp only [handleAppendEntriesResponse]
  refine Sends.ite' (fun notLeader => absurd leader (by simpa using notLeader))
    fun _ => ?_
  refine Sends.ite' (fun success => absurd failure (by simpa using success)) fun _ => ?_
  exact Sends.pure' (by simp)

/-- A primary that receives a success of its own term from an eligible peer raises
that peer's match index to the acknowledged index. -/
theorem receive_ack (before : NodeState) (leader : before.role = .primary)
    (source : NodeID) (eligible : source ∈ eligiblePeers before self)
    (response : AppendEntriesResponse) (success : response.success = true)
    (current : response.term = before.currentTerm)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          after.matchIndex source = max (before.matchIndex source) response.lastLogIndex)
        (receive caps self source before (.appendEntriesResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun ignored => absurd eligible (by simpa using ignored)) fun _ => ?_
  rcases observe_response before response with ⟨_, bump, _⟩ | ⟨_, eq⟩
  · omega
  rw [eq]
  simp only [handleAppendEntriesResponse]
  refine Sends.ite' (fun notLeader => absurd leader (by simpa using notLeader))
    fun _ => ?_
  refine Sends.ite' (fun _ => ?_) fun failure => absurd success (by simpa using failure)
  refine Sends.ite' (fun _ => ?_) fun stale => absurd current stale
  exact Sends.mono (advanceCommit_sends self _) fun after _ ⟨advance, _⟩ => by
    rw [advance.matchIndex]
    simp

end Handlers

/-! ## Protocol steps as history steps -/

variable [Config.InitialConfiguration]

theorem delivered_of_action {event : Liveness.Event} {envelope : Model.Envelope}
    (selected : event.action = some (.deliver envelope))
    : event.delivered = some envelope := by
  cases event <;> simp_all [Event.action, Event.delivered]

theorem now_of_found {state : Model.State} {rest : History} {node : NodeID}
    {local_ : NodeState} (found : nodeState state node = some local_)
    : Now (state :: rest) node local_ :=
  Concrete.mem_of_nodeState found

theorem found_of_now {nodes : List NodeID} {state : Model.State} {rest : History}
    (exec : Exec nodes (state :: rest)) {node : NodeID} {local_ : NodeState}
    (now : Now (state :: rest) node local_)
    : nodeState state node = some local_ :=
  Direct.nodeState_of_mem (exec.keys List.mem_cons_self) now

/-- A model step as a local transition of its actor. -/
theorem transition_acts {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    : exists tr : LocalTransition before after,
        Acts action tr.actor tr.event
        /\ outgoing before action = some tr.outputs.outgoing := by
  cases action with
  | «local» actor input =>
      obtain ⟨pre, post, outputs, found, ran, rfl⟩ := Concrete.step_local stepped
      have ran' :
          (Model.Node.step (Capabilities.record actor) actor pre (.internal input)).run {}
            = some (post, outputs) := ran
      exact ⟨
        {
          actor,
          pre,
          post
          event := .internal input,
          outputs
          pending := before.network
          found
          ran := ran'
          nodesEq := rfl
          networkEq := rfl
          pendingSub := fun _ member => member
          source := Or.inl ⟨input, rfl, rfl⟩
        },
        ⟨rfl, rfl⟩,
        by simp [outgoing, found, ran']
      ⟩
  | deliver envelope =>
      obtain ⟨queued, pre, post, outputs, found, ran, rfl⟩ := Concrete.step_deliver stepped
      have ran' :
          (Model.Node.step (Capabilities.record envelope.target) envelope.target pre
                (.receive envelope.source envelope.payload)).run
              {}
            = some (post, outputs) := ran
      exact ⟨
        {
          actor := envelope.target,
          pre,
          post
          event := .receive envelope.source envelope.payload,
          outputs
          pending := removeOne envelope before.network
          found
          ran := ran'
          nodesEq := rfl
          networkEq := rfl
          pendingSub := fun _ member => mem_removeOne member
          source := Or.inr ⟨envelope, queued, rfl, rfl, rfl⟩
        },
        ⟨rfl, rfl⟩,
        by simp [outgoing, found, ran']
      ⟩

/-- A step that receives a message delivers an envelope carrying it. -/
theorem acts_receive {action : Model.Action} {actor : NodeID} {event : Model.Node.Event}
    {source : NodeID} {message : Message} (acts : Acts action actor event)
    (eq : event = .receive source message)
    : exists envelope,
        action = .deliver envelope
        /\ actor = envelope.target
        /\ envelope.source = source
        /\ envelope.payload = message := by
  cases action with
  | «local» node input =>
      obtain ⟨_, eventEq⟩ := acts
      rw [eventEq] at eq
      cases eq
  | deliver envelope =>
      obtain ⟨actorEq, eventEq⟩ := acts
      rw [eventEq] at eq
      injection eq with sourceEq payloadEq
      exact ⟨envelope, rfl, actorEq, sourceEq, payloadEq⟩

section Trace

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}

/-- The stable primary at a recorded index, in any history ending there. -/
theorem lead_at {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat} (le : start <= index)
    {point : W} (found : trace.stateAt index = some point) {rest : History}
    (exec : Exec nodes (proto point :: rest)) {state : NodeState}
    (nodeFound : nodeState (proto point) leader = some state)
    : Lead nodes (proto point :: rest) leader term state := by
  obtain ⟨_, state', nodeFound', primary, termEq, _⟩ := stable.leads le found
  rw [nodeFound, Option.some.injEq] at nodeFound'
  subst nodeFound'
  exact ⟨exec, now_of_found nodeFound, primary, termEq⟩

variable
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- A recorded protocol step as a step of a safety history. -/
theorem ctx_at {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {action : Model.Action}
    (selected : step.action.action = some action)
    : exists rest,
    exists c : Ctx nodes (proto step.after) (proto step.before) rest,
      Acts action c.tr.actor c.tr.event
      /\ outgoing (proto step.before) action = some c.tr.outputs.outgoing := by
  obtain ⟨rest, exec⟩ := exec_of_reachable (admissible.reachable_before stepped)
  have next := admissible.step stepped selected
  obtain ⟨tr, acts, out⟩ := transition_acts next
  exact ⟨rest, ⟨.step exec next, tr, good_of_exec exec⟩, acts, out⟩

/-- A recorded state ends a safety history. -/
theorem history_at {index : Nat} {point : W} (found : trace.stateAt index = some point)
    : exists rest, Exec nodes (proto point :: rest) :=
  exec_of_reachable (admissible.reachable found)

/-- A node other than the primary of its term before a recorded step, of that term on
both sides of the step, changes its log only by accepting a request of the term from the
primary. Its new log is the primary's log up to the end of the batch, and it
acknowledges that end. -/
theorem follower_step_of_leads {leader : NodeID} {term : Nat} {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (leads
      : exists state,
          nodeState (proto step.before) leader = some state
          /\ state.role = .primary
          /\ state.currentTerm = term) {peer : NodeID}
    (different : Not (peer = leader)) {pre post : NodeState}
    (preFound : nodeState (proto step.before) peer = some pre)
    (postFound : nodeState (proto step.after) peer = some post)
    (preTerm : pre.currentTerm = term) (postTerm : post.currentTerm = term)
    (changed : Not (post.log = pre.log))
    : exists envelope request leaderState,
        step.action.delivered = some envelope
        /\ envelope.source = leader
        /\ envelope.target = peer
        /\ envelope.payload = .appendEntriesRequest request
        /\ request.term = term
        /\ nodeState (proto step.before) leader = some leaderState
        /\ request.prevLogIndex + request.entries.length <= leaderState.log.length
        /\ post.log = leaderState.log.take (request.prevLogIndex + request.entries.length)
        /\ Not
            (pre.log.take (request.prevLogIndex + request.entries.length)
              = leaderState.log.take (request.prevLogIndex + request.entries.length))
        /\ exists packet,
            SentAt trace index packet
            /\ packet.envelope
                = {
                  source := peer
                  target := leader
                  payload :=
                    .appendEntriesResponse
                      {
                        term
                        success := true
                        lastLogIndex := request.prevLogIndex + request.entries.length
                      }
                } := by
  cases selected : step.action.action with
  | none =>
      rw [admissible.stutter stepped selected, preFound, Option.some.injEq] at postFound
      exact absurd (by rw [postFound]) changed
  | some action =>
      obtain ⟨rest, c, acts, out⟩ := ctx_at admissible stepped selected
      have actorEq : c.tr.actor = peer := by
        by_contra other
        have kept :=
          found_of_now c.exec (c.now_other (Ne.symm other) (now_of_found preFound))
        rw [postFound, Option.some.injEq] at kept
        exact changed (by rw [kept])
      have prePre : c.tr.pre = pre := by
        have found := c.tr.found
        rw [actorEq, preFound, Option.some.injEq] at found
        exact found.symm
      have postPost : c.tr.post = post := by
        have found := found_of_now c.exec c.post_now
        rw [show c.actor = peer from actorEq, postFound, Option.some.injEq] at found
        exact found.symm
      obtain ⟨leaderState, leaderFound, primary, termEq⟩ := leads
      have lead : Lead nodes (proto step.before :: rest) leader term leaderState :=
        ⟨c.prior, now_of_found leaderFound, primary, termEq⟩
      have changed' : Not (c.post.log = c.pre.log) := by
        show Not (c.tr.post.log = c.tr.pre.log)
        rw [prePre, postPost]
        exact changed
      have preTerm' : c.pre.currentTerm = term := by
        show c.tr.pre.currentTerm = term
        rw [prePre, preTerm]
      have postTerm' : c.post.currentTerm = term := by
        show c.tr.post.currentTerm = term
        rw [postPost, postTerm]
      have notLeader : Not (c.actor = leader) := by
        show Not (c.tr.actor = leader)
        rw [actorEq]
        exact different
      cases Summary.kind c.sum with
      | same log _ => exact absurd log changed'
      | append _ _ primary _ _ _ =>
          have led := c.inv.leader_led c.actor c.pre c.pre_now primary
          rw [preTerm'] at led
          exact absurd (lead.unique led) notLeader
      | ack _ _ _ _ _ _ advance => exact absurd (Advance.facts advance).1 changed'
      | elect wins =>
          have led
              : Led (proto step.after :: proto step.before :: rest) c.actor term := by
            rw [← postTerm']
            exact Or.inr ⟨_, _, _, _, rest, List.suffix_refl _, c.wins_elect wins⟩
          have inv := good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
          exact absurd (inv.election_safety _ _ _ led (lead.led.mono c.suffix_tail))
            notLeader
      | accept source request eq accepted =>
          obtain ⟨requestTerm, _, _, prevBound, prevTermEq, logEq, _⟩ := accepted
          rw [postTerm'] at requestTerm
          obtain ⟨queued, pending, queuedSource, _, queuedPayload⟩ := c.received eq
          obtain ⟨sourceEq, _, prevLeader, prevLeaderTerm, entries⟩ :=
            lead.request pending queuedPayload requestTerm
          rw [queuedSource] at sourceEq
          obtain ⟨envelope, rfl, targetEq, envelopeSource, envelopePayload⟩ :=
            acts_receive acts eq
          have prevAgree
              : c.pre.log.take request.prevLogIndex = leaderState.log.take request.prevLogIndex := by
            rcases Nat.eq_zero_or_pos request.prevLogIndex with zero | positive
            · rw [zero, List.take_zero, List.take_zero]
            · exact lead.matching c.pre_seen positive prevBound prevLeader
                (prevTermEq.trans prevLeaderTerm)
          have shape := acceptLog_eq prevBound prevLeader prevAgree entries
            fun _ positive bound leaderBound same =>
              lead.matching c.pre_seen positive bound leaderBound same
          have bound
              : request.prevLogIndex + request.entries.length
                <= leaderState.log.length := by
            have := entries.length_le
            simp only [List.length_drop] at this
            omega
          have differ
              : Not (c.pre.log.take (request.prevLogIndex + request.entries.length)
                  = leaderState.log.take (request.prevLogIndex + request.entries.length)) := by
            intro same
            apply changed'
            rw [logEq, shape, ← same]
            simp
          rw [shape] at logEq
          simp only [differ, ↓reduceIte, List.append_nil] at logEq
          have ran
              : (receive (Capabilities.record c.tr.actor) c.tr.actor source c.tr.pre
                    (.appendEntriesRequest request)).run {}
                = some (c.tr.post, c.tr.outputs) := by
            have ran := c.tr.ran
            have eq' : c.tr.event = .receive source (.appendEntriesRequest request) := eq
            rw [eq'] at ran
            exact ran
          have le : request.term <= c.tr.pre.currentTerm := by
            rw [requestTerm]
            exact preTerm'.ge
          obtain ⟨new, outEq, step⟩ :=
            receive_ae c.tr.actor c.tr.pre source request le {} _ _ ran
          rcases step with ⟨_, postEq, _⟩ | ⟨_, _, _, postEq, _⟩
              | ⟨_, _, _, _, _, _, _, _, _, _, sentEq⟩
          · exact absurd
              (by show c.tr.post.log = c.tr.pre.log; rw [postEq, awareState_log]) changed'
          · exact absurd
              (by
                show c.tr.post.log = c.tr.pre.log; rw [postEq]; exact awareState_log _ _)
              changed'
          rw [outEq, sentEq] at out
          obtain ⟨packet, sent, envelopeEq, -⟩ :=
            admissible.sentAt_of_emitted stepped selected out
              (List.mem_append_right _ (List.mem_singleton_self _))
          refine ⟨
            envelope,
            request,
            leaderState,
            delivered_of_action selected,
            envelopeSource.trans sourceEq,
            targetEq.symm.trans actorEq,
            envelopePayload,
            requestTerm,
            leaderFound,
            bound,
            postPost ▸ logEq,
            prePre ▸ differ,
            packet,
            sent,
            ?_
          ⟩
          rw [envelopeEq]
          simp [actorEq, sourceEq, awareState_term, prePre, preTerm]

/-- A node other than the stable primary, of its term on both sides of a recorded
step, changes its log only by accepting a request of the term from the primary. Its
new log is the primary's log up to the end of the batch, and it acknowledges that end. -/
theorem follower_step {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {peer : NodeID}
    (different : Not (peer = leader)) {pre post : NodeState}
    (preFound : nodeState (proto step.before) peer = some pre)
    (postFound : nodeState (proto step.after) peer = some post)
    (preTerm : pre.currentTerm = term) (postTerm : post.currentTerm = term)
    (changed : Not (post.log = pre.log))
    : exists envelope request leaderState,
        step.action.delivered = some envelope
        /\ envelope.source = leader
        /\ envelope.target = peer
        /\ envelope.payload = .appendEntriesRequest request
        /\ request.term = term
        /\ nodeState (proto step.before) leader = some leaderState
        /\ request.prevLogIndex + request.entries.length <= leaderState.log.length
        /\ post.log = leaderState.log.take (request.prevLogIndex + request.entries.length)
        /\ Not
            (pre.log.take (request.prevLogIndex + request.entries.length)
              = leaderState.log.take (request.prevLogIndex + request.entries.length))
        /\ exists packet,
            SentAt trace index packet
            /\ packet.envelope
                = {
                  source := peer
                  target := leader
                  payload :=
                    .appendEntriesResponse
                      {
                        term
                        success := true
                        lastLogIndex := request.prevLogIndex + request.entries.length
                      }
                } := by
  obtain ⟨_, leaderState, leaderFound, primary, termEq, _⟩ :=
    stable.leads le (Trace.stateAt_of_stepAt stepped)
  exact follower_step_of_leads admissible stepped ⟨leaderState, leaderFound, primary, termEq⟩
    different preFound postFound preTerm postTerm changed

end Trace

end CCFRaft.Proofs.Replication
