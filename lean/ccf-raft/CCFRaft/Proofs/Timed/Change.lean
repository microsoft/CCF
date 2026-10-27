module

public import CCFRaft.Proofs.Timed.Chain
public import CCFRaft.Proofs.Timed.Follower
public import CCFRaft.Proofs.Timed.Fifo

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A changing peer log

A peer of the term changes its log only by accepting a batch of the primary's term
that starts inside its agreement and at or above its commit index. That batch
belongs to a pass, and the pass's batches chain to an acknowledgement of the
primary's whole log at the pass.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.CommitLiveness (stable_log_prefix)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)
  {start : Nat} {leader : NodeID} {term : Nat}
  (stable : StableLeader trace start leader term)
  {peer : NodeID} (different : Not (peer = leader))

include admissible stable different

/-- A step that changes the log of a peer of the term delivers a request of the
term from the primary that starts inside the peer's agreement with the primary
and at or above its commit index. -/
theorem change_good {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {pre post : NodeState}
    (preFound : nodeState (proto step.before) peer = some pre)
    (postFound : nodeState (proto step.after) peer = some post)
    (preTerm : pre.currentTerm = term) (postTerm : post.currentTerm = term)
    (changed : Not (post.log = pre.log))
    : exists packet request primary,
        step.action = .deliver packet
        /\ packet.envelope.source = leader
        /\ packet.envelope.target = peer
        /\ packet.envelope.payload = .appendEntriesRequest request
        /\ request.term = term
        /\ nodeState (proto step.before) leader = some primary
        /\ request.prevLogIndex <= agree pre.log primary.log
        /\ pre.commitIndex <= request.prevLogIndex := by
  cases selected : step.action.action with
  | none =>
      rw [admissible.stutter stepped selected, preFound, Option.some.injEq] at postFound
      exact absurd (by rw [postFound]) changed
  | some action =>
      obtain ⟨rest, c, acts, _⟩ := ctx_at admissible stepped selected
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
      obtain ⟨_, leaderState, leaderFound, _, _, _⟩ := stable.leads le (Trace.stateAt_of_stepAt stepped)
      have lead := lead_at stable le (Trace.stateAt_of_stepAt stepped) c.prior leaderFound
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
          obtain ⟨requestTerm, _, commitLe, prevBound, prevTermEq, _, _⟩ := accepted
          rw [postTerm'] at requestTerm
          obtain ⟨_, pending, queuedSource, _, queuedPayload⟩ := c.received eq
          obtain ⟨sourceEq, _, prevLeader, prevLeaderTerm, _⟩ :=
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
          have agreed := le_agree _ _ _ prevBound prevLeader prevAgree
          obtain ⟨packet, event, rfl⟩ := packet_of_delivered (delivered_of_action selected)
          refine ⟨
            packet,
            request,
            leaderState,
            event,
            envelopeSource.trans sourceEq,
            targetEq.symm.trans actorEq,
            envelopePayload,
            requestTerm,
            leaderFound,
            ?_,
            ?_
          ⟩
          · exact prePre ▸ agreed
          · exact prePre ▸ commitLe

variable {last : Nat} {stop delay interval : Real}
  (env : Env trace start last stop delay interval leader peer)
  (current
    : forall index point,
        start <= index
        -> index <= last
        -> trace.stateAt index = some point
        -> exists state,
            nodeState (proto point) peer = some state /\ state.currentTerm = term)
  (eligible
    : forall index state,
        start <= index
        -> nodeAt trace index leader = some state
        -> peer ∈ eligiblePeers state leader)
  (nonneg : 0 <= delay)

include env current eligible nonneg

/-- A peer log change more than a delay after `base` leads, within two delays, to
the primary receiving an acknowledgement of at least its log at `base`. -/
theorem change_acks {base : Nat} (startLe : start <= base) (baseLe : base <= last)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {pre post : NodeState}
    (preFound : nodeState (proto step.before) peer = some pre)
    (postFound : nodeState (proto step.after) peer = some post)
    (changed : Not (post.log = pre.log))
    (late : clock trace base + delay < clock trace index)
    (timely : clock trace index + 2 * delay <= stop)
    : exists later step' reply acked,
        index < later
        /\ clock trace later <= clock trace index + 2 * delay
        /\ trace.stepAt later = some step'
        /\ step'.action = .deliver reply
        /\ reply.envelope
            = {
              source := peer
              target := leader
              payload :=
                .appendEntriesResponse { term, success := true, lastLogIndex := acked }
            }
        /\ forall state,
            nodeAt trace base leader = some state -> state.log.length <= acked := by
  have indexLt : index < last := env.ends index step stepped
  have baseLt : base < index := by
    by_contra notLt
    have := env.mono index base (by omega) baseLe
    linarith
  have le : start <= index := by omega
  obtain ⟨pre', preFound', preTerm⟩ :=
    current index step.before le (by omega) (Trace.stateAt_of_stepAt stepped)
  rw [preFound, Option.some.injEq] at preFound'
  subst preFound'
  obtain ⟨post', postFound', postTerm⟩ :=
    current (index + 1) step.after (by omega) (by omega) (Trace.stateAt_succ_of_stepAt stepped)
  rw [postFound, Option.some.injEq] at postFound'
  subst postFound'
  obtain ⟨packet, request, primary, event, source, target, payload, requestTerm, leaderFound,
      agreed, committed⟩ :=
    change_good admissible stable different le stepped preFound postFound preTerm postTerm changed
  obtain ⟨sent, sentLt, sentAt⟩ :=
    admissible.consumed_sent stepped (by rw [event]; rfl)
  have prompt := env.prompt index step packet sent stepped event sentAt
  have baseSent : base < sent := by
    by_contra notLt
    have := env.mono sent base (by omega) baseLe
    linarith
  have sentStart : start <= sent := by omega
  have sentClock := env.mono sent index (by omega) (by omega)
  obtain ⟨sentStep, sentStepped, -⟩ := id sentAt
  obtain ⟨_, before, beforeFound, beforePrimary, _, _⟩ :=
    stable.leads sentStart (Trace.stateAt_of_stepAt sentStepped)
  have beforeAt : nodeAt trace sent leader = some before := by
    rw [nodeAt_before sentStepped, beforeFound]
  have sourceFound : nodeState (proto sentStep.before) packet.envelope.source = some before := by
    rw [source]; exact beforeFound
  rcases request_origin admissible sentStepped sentAt payload sourceFound beforePrimary
      with ⟨batchEnds, batch, passEvent, _, batchMem, requestEq⟩
      | ⟨_, _, _, _, _, notEligible⟩
  · rw [source, target] at passEvent
    rw [target] at batchMem
    obtain ⟨position, bound, getEq⟩ := List.mem_iff_getElem.mp batchMem
    have envelopeEq
        : packet.envelope
          = batchEnvelope before leader peer
              ((passBatches (before.sentIndex peer) batchEnds)[position]'bound) := by
      have shape
          : forall envelope : Model.Envelope,
              envelope.source = leader
              -> envelope.target = peer
              -> envelope.payload = .appendEntriesRequest request
              -> envelope
                = batchEnvelope before leader peer
                    ((passBatches (before.sentIndex peer) batchEnds)[position]'bound) := by
        rintro ⟨_, _, _⟩ rfl rfl rfl
        rw [requestEq, getEq]
        rfl
      exact shape _ source target payload
    have prevEq
        : ((passBatches (before.sentIndex peer) batchEnds)[position]'bound).1
          = request.prevLogIndex := by
      rw [getEq, requestEq]
      rfl
    obtain ⟨later, step', reply, laterGt, laterClock, laterStepped, delivered, replyEq⟩ :=
      pass_chain admissible stable different env current sentStart sentStepped passEvent
        beforeFound (by linarith) bound sentAt envelopeEq stepped event preFound leaderFound
        (by rw [prevEq]; exact agreed) (by rw [prevEq]; exact committed)
    refine ⟨later, step', reply, before.log.length, laterGt, by linarith, laterStepped,
      delivered, replyEq, fun state found => ?_⟩
    exact (stable_log_prefix admissible stable startLe (by omega) found beforeAt).length_le
  · rw [source, target] at notEligible
    exact absurd (eligible sent before sentStart beforeAt) notEligible

end CCFRaft.Proofs.Timed
