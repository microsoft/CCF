module

public import CCFRaft.Proofs.Replication.Peer

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A peer of the stable primary's term

A peer that stays in the primary's term changes its log and commit index only on
an AppendEntries request of the term from the primary. A request that starts
inside the peer's agreement with the primary, at or above the peer's commit
index, is accepted: the peer then agrees up to the end of the batch, commits no
further, and acknowledges that end.
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

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)
  {start : Nat} {leader : NodeID} {term : Nat}
  (stable : StableLeader trace start leader term)
  {peer : NodeID} (different : Not (peer = leader))

include admissible stable different

/-- A peer in the term on both sides of a step changes its log or commit index only
by receiving an AppendEntries request of the term from the primary. -/
theorem peer_changes {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {pre post : NodeState}
    (preFound : nodeState (proto step.before) peer = some pre)
    (postFound : nodeState (proto step.after) peer = some post)
    (preTerm : pre.currentTerm = term) (postTerm : post.currentTerm = term)
    (changed : Not (post.log = pre.log) \/ Not (post.commitIndex = pre.commitIndex))
    : exists packet request,
        step.action = .deliver packet
        /\ packet.envelope.source = leader
        /\ packet.envelope.target = peer
        /\ packet.envelope.payload = .appendEntriesRequest request
        /\ request.term = term := by
  cases selected : step.action.action with
  | none =>
      rw [admissible.stutter stepped selected, preFound, Option.some.injEq] at postFound
      subst postFound
      rcases changed with c | c <;> exact (c rfl).elim
  | some action =>
      obtain ⟨rest, c, acts, _⟩ := ctx_at admissible stepped selected
      have actorEq : c.tr.actor = peer := by
        by_contra other
        have kept :=
          found_of_now c.exec (c.now_other (Ne.symm other) (now_of_found preFound))
        rw [postFound, Option.some.injEq] at kept
        subst kept
        rcases changed with c | c <;> exact c rfl
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
      | same log commit =>
          have log' : post.log = pre.log := by rw [← prePre, ← postPost]; exact log
          have commit' : post.commitIndex = pre.commitIndex := by
            rw [← prePre, ← postPost]; exact commit
          rcases changed with c | c
          · exact absurd log' c
          · exact absurd commit' c
      | append _ _ primary _ _ _ =>
          have led := c.inv.leader_led c.actor c.pre c.pre_now primary
          rw [preTerm'] at led
          exact absurd (lead.unique led) notLeader
      | ack _ _ _ primary _ _ _ =>
          have led := c.inv.leader_led c.actor c.pre c.pre_now primary
          rw [preTerm'] at led
          exact absurd (lead.unique led) notLeader
      | elect wins =>
          have led
              : Led (proto step.after :: proto step.before :: rest) c.actor term := by
            rw [← postTerm']
            exact Or.inr ⟨_, _, _, _, rest, List.suffix_refl _, c.wins_elect wins⟩
          have inv := good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
          exact absurd (inv.election_safety _ _ _ led (lead.led.mono c.suffix_tail))
            notLeader
      | accept source request eq accepted =>
          obtain ⟨requestTerm, _⟩ := accepted
          rw [postTerm'] at requestTerm
          obtain ⟨_, pending, queuedSource, _, queuedPayload⟩ := c.received eq
          obtain ⟨sourceEq, _⟩ := lead.request pending queuedPayload requestTerm
          rw [queuedSource] at sourceEq
          obtain ⟨envelope, rfl, targetEq, envelopeSource, envelopePayload⟩ :=
            acts_receive acts eq
          obtain ⟨packet, event, rfl⟩ := packet_of_delivered (delivered_of_action selected)
          exact ⟨packet, request, event, envelopeSource.trans sourceEq,
            targetEq.symm.trans actorEq, envelopePayload, requestTerm⟩

/-- A request of the term from the primary, starting inside the peer's agreement
and at or above its commit index, is accepted and acknowledged at its end. -/
theorem accept_good {index : Nat} (le : start <= index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (event : step.action = .deliver packet) (source : packet.envelope.source = leader)
    (target : packet.envelope.target = peer) {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    (requestTerm : request.term = term) {pre primary : NodeState}
    (preFound : nodeState (proto step.before) peer = some pre)
    (preTerm : pre.currentTerm = term)
    (leaderFound : nodeState (proto step.before) leader = some primary)
    (agreed : request.prevLogIndex <= agree pre.log primary.log)
    (committed : pre.commitIndex <= request.prevLogIndex)
    : exists post,
        nodeState (proto step.after) peer = some post
        /\ post.currentTerm = term
        /\ request.prevLogIndex + request.entries.length <= agree post.log primary.log
        /\ post.commitIndex <= request.prevLogIndex + request.entries.length
        /\ exists reply,
            SentAt trace index reply
            /\ reply.envelope
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
  have delivered : step.action.delivered = some packet.envelope := by rw [event]; rfl
  have selected : step.action.action = some (.deliver packet.envelope) := by rw [event]; rfl
  have foundAt : nodeState (proto step.before) packet.envelope.target = some pre := by
    rw [target]; exact preFound
  obtain ⟨after, sends, foundAfter, received, out⟩ :=
    receive_step admissible stepped delivered payload foundAt (by omega)
  rw [target] at foundAfter
  obtain ⟨_, _, prevLe, prevTerm, entries⟩ :=
    request_at admissible stable le stepped delivered payload requestTerm leaderFound
  have view := view_at admissible stable different le
    (by rw [nodeAt_before stepped, leaderFound])
    (by rw [nodeAt_before stepped, preFound]) preTerm
  have wTerm : (awareState pre request).currentTerm = term :=
    (awareState_term pre request).trans preTerm
  have wLog := awareState_log pre request
  have prevLen : request.prevLogIndex <= pre.log.length := agreed.trans (agree_le_left _ _)
  have prevMatch : termAt pre.log request.prevLogIndex = request.prevLogTerm := by
    rw [prevTerm]; exact termAt_agree agreed
  rw [target, source] at received
  rcases received with ⟨reject, _, _⟩ | ⟨_, _, ignore, _, _⟩
      | ⟨_, _, _, _, afterTerm, _, acceptEq, _, _, _, sendsEq⟩
  · exfalso
    rcases reject with stale | notMatched
    · omega
    · exact notMatched ⟨by rw [wLog]; exact prevLen, by rw [wLog]; exact prevMatch⟩
  · exfalso
    rcases ignore with low | ⟨conflict, settledFlag⟩
    · have : (awareState pre request).commitIndex = pre.commitIndex := by
        unfold awareState
        split <;> rfl
      omega
    · obtain ⟨same, campaigning⟩ := awareState_settled settledFlag
      obtain ⟨notCandidate, notPre⟩ := campaigning (requestTerm.trans preTerm.symm)
      have sub := view.settled ⟨notCandidate, notPre, by rw [← same]; exact settledFlag⟩
      rw [wLog, conflictIndex_eq_none (sub.drop request.prevLogIndex) entries] at conflict
      simp at conflict
  rw [wLog] at acceptEq
  have aligned
      : forall j, 0 < j -> j <= pre.log.length -> j <= primary.log.length
        -> termAt pre.log j = termAt primary.log j -> pre.log.take j = primary.log.take j :=
    view.matching
  have prevAgree
      : pre.log.take request.prevLogIndex = primary.log.take request.prevLogIndex := by
    by_cases zero : request.prevLogIndex = 0
    · simp [zero]
    · exact aligned _ (by omega) prevLen prevLe (by rw [prevMatch, prevTerm])
  have shape := acceptLog_eq prevLen prevLe prevAgree entries aligned
  rw [← acceptEq] at shape
  have batch := entries.length_le
  rw [List.length_drop] at batch
  have lengthLe : request.prevLogIndex + request.entries.length <= after.log.length := by
    rw [shape, List.length_append, List.length_take]
    omega
  have takeEq : after.log.take (request.prevLogIndex + request.entries.length)
      = primary.log.take (request.prevLogIndex + request.entries.length) := by
    rw [shape]
    exact List.take_left' (by rw [List.length_take]; omega)
  have agreeLe := le_agree _ _ _ lengthLe (by omega) takeEq
  have postTerm : after.currentTerm = term := afterTerm.trans wTerm
  obtain ⟨rest, c, acts, _⟩ := ctx_at admissible stepped selected
  obtain ⟨actorEq, eventEq⟩ := acts
  have prePre : c.tr.pre = pre := by
    have found := c.tr.found
    rw [actorEq, target, preFound, Option.some.injEq] at found
    exact found.symm
  have postPost : c.tr.post = after := by
    have found := found_of_now c.exec c.post_now
    rw [show c.actor = peer from actorEq.trans target, foundAfter, Option.some.injEq] at found
    exact found.symm
  have lead := lead_at stable le (Trace.stateAt_of_stepAt stepped) c.prior leaderFound
  have preTerm' : c.pre.currentTerm = term := by
    show c.tr.pre.currentTerm = term
    rw [prePre, preTerm]
  have postTerm' : c.post.currentTerm = term := by
    show c.tr.post.currentTerm = term
    rw [postPost, postTerm]
  have notLeader : Not (c.actor = leader) := by
    show Not (c.tr.actor = leader)
    rw [actorEq, target]
    exact different
  have commitLe : after.commitIndex <= request.prevLogIndex + request.entries.length := by
    cases Summary.kind c.sum with
    | same _ commit =>
        have commit' : after.commitIndex = pre.commitIndex := by
          rw [← prePre, ← postPost]; exact commit
        omega
    | append _ _ primary _ _ _ =>
        have led := c.inv.leader_led c.actor c.pre c.pre_now primary
        rw [preTerm'] at led
        exact absurd (lead.unique led) notLeader
    | ack _ _ _ primary _ _ _ =>
        have led := c.inv.leader_led c.actor c.pre c.pre_now primary
        rw [preTerm'] at led
        exact absurd (lead.unique led) notLeader
    | elect wins =>
        have led
            : Led (proto step.after :: proto step.before :: rest) c.actor term := by
          rw [← postTerm']
          exact Or.inr ⟨_, _, _, _, rest, List.suffix_refl _, c.wins_elect wins⟩
        have inv := good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
        exact absurd (inv.election_safety _ _ _ led (lead.led.mono c.suffix_tail))
          notLeader
    | accept _ request' eq accepted =>
        have eq' : c.tr.event = _ := eq
        rw [eventEq, payload] at eq'
        injection eq' with _ messageEq
        injection messageEq with requestEq
        subst requestEq
        obtain ⟨_, _, _, _, _, _, commitEq⟩ := accepted
        have bounded := maxCommittableIndexUpTo_le c.post.log
          (min request.primaryCommit (request.prevLogIndex + request.entries.length))
        have commitEq' : after.commitIndex = max pre.commitIndex
            (maxCommittableIndexUpTo c.post.log
              (min request.primaryCommit (request.prevLogIndex + request.entries.length))) := by
          rw [← prePre, ← postPost]; exact commitEq
        omega
  obtain ⟨reply, sent, envelopeEq, -⟩ :=
    admissible.sentAt_of_emitted stepped selected out
      (by rw [sendsEq]; exact List.mem_singleton_self _)
  refine ⟨after, foundAfter, postTerm, agreeLe, commitLe, reply, sent, ?_⟩
  rw [envelopeEq, wTerm]

end CCFRaft.Proofs.Timed
