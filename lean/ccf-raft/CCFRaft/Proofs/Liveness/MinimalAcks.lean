module

public import CCFRaft.Proofs.Leadership.CatchUp
public import CCFRaft.Proofs.Liveness.Delay

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# An anchored primary passes its quorum checks

While the anchor invariant holds, every anchor node acknowledges the primary
within a bounded time after any point, so if the primary heard from every anchor
node within a heartbeat interval before the start, and the election timeout
exceeds that bound, every quorum check finds a quorum of recent responders in its
only configuration. `CheckQuorumScheduling` then forbids the check.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Leadership
open CCFRaft.Proofs.Timed (ackBound)
open HasProtocol (proto)
open HasTime (time)

/-- A quorum check runs only on a primary. -/
theorem checkQuorum_guard (self : NodeID) (state : NodeState)
    : Sends (fun _ _ => state.role = .primary) (checkQuorum state self) := by
  unfold checkQuorum
  exact Sends.bind' Sends.guard' fun _ _ ⟨holds, _⟩ => Sends.pure' holds.1

section Acks

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {nodes : List NodeID} {trace : Trace W Liveness.Event}

omit [Config.InitialConfiguration] [HasLive W] [HasNetwork W] in
/-- An acknowledgement after `since` before `index` is one after any earlier time
before any later index. -/
theorem acked_mono {index later : Nat} {leader peer : NodeID} {since earlier : Real}
    (acked : AckedAfter trace index leader peer since) (le : index <= later)
    (before : earlier <= since)
    : AckedAfter trace later leader peer earlier := by
  obtain ⟨at_, reset, lt, stepped, resets, after⟩ := acked
  exact ⟨at_, reset, by omega, stepped, resets, by linarith⟩

variable (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- While the anchor invariant holds, the primary has heard from every other anchor
node within `timeout` before each step, if it had within `interval` before the
start and `timeout` exceeds twelve delays and eight heartbeat intervals. -/
theorem acked_recently {interval timeout maxDelay : Real}
    (diverges : TimeDiverges trace)
    (bounded : Satisfies trace (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    (heartbeats : HeartbeatScheduling trace (some interval))
    (ratio : 12 * maxDelay + 8 * max interval 0 < timeout)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants anchor : Finset NodeID}
    (good : GoodBase trace start duration participants)
    (behind : BacklogTerms trace start leader anchor 0)
    (subset : anchor ⊆ participants) (leaderIn : leader ∈ anchor)
    {first : W} (firstFound : trace.stateAt start = some first)
    (startAcks
      : forall peer,
          peer ∈ anchor
          -> Not (peer = leader)
          -> AckedAfter trace start leader peer (time first - interval))
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) (afterStart : start <= index)
    (within : Within trace start duration index)
    (invariant
      : forall earlier point,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> AnchorBaseInv participants anchor leader term (proto point)
              /\ NoProposals participants term point)
    {peer : NodeID} (peerIn : peer ∈ anchor) (different : Not (peer = leader))
    : AckedAfter trace index leader peer (time step.before - timeout) := by
  have indexFound := Trace.stateAt_of_stepAt stepped
  have intervalNonneg : 0 <= max interval 0 := le_max_right _ _
  have intervalLe : interval <= max interval 0 := le_max_left _ _
  by_cases early : time step.before - timeout <= time first - interval
  · exact acked_mono (startAcks peer peerIn different) afterStart early
  push Not at early
  -- A point no later than `interval` past the cutoff, after which every recorded
  -- state is past the cutoff.
  obtain ⟨earlier, point, afterStart', le, found, below, beyond⟩
      : exists earlier point,
          start <= earlier
          /\ earlier <= index
          /\ trace.stateAt earlier = some point
          /\ time point <= time step.before - timeout + max interval 0
          /\ forall later point',
              earlier < later
              -> trace.stateAt later = some point'
              -> time step.before - timeout < time point' := by
    by_cases reached : time first <= time step.before - timeout
    · obtain ⟨exit, after, before, ⟨exitPoint, exitFound, exitLe⟩, outside⟩ :=
        exists_exit
          (holds := fun position =>
            exists point,
              trace.stateAt position = some point
              /\ time point <= time step.before - timeout)
          afterStart ⟨first, firstFound, reached⟩
          (by
            rintro ⟨point, found, pointLe⟩
            rw [indexFound, Option.some.injEq] at found
            subst found
            linarith)
      refine ⟨exit, exitPoint, after, before.le, exitFound, by linarith,
        fun later point' lt found' => ?_⟩
      obtain ⟨exitStep, exitStepped⟩ := Trace.stepAt_of_stateAt_lt before indexFound
      have nextFound := Trace.stateAt_succ_of_stepAt exitStepped
      have nextLate : time step.before - timeout < time exitStep.after := by
        by_contra notLate
        exact outside ⟨exitStep.after, nextFound, not_lt.mp notLate⟩
      have := admissible.time_le lt nextFound found'
      linarith
    · push Not at reached
      refine ⟨start, first, le_rfl, afterStart, firstFound, by linarith,
        fun later point' lt found' => ?_⟩
      have := admissible.time_le lt.le firstFound found'
      linarith
  have ackEq : ackBound maxDelay (max interval 0) 0 = 10 * maxDelay + 6 * max interval 0 := by
    unfold ackBound
    push_cast
    ring
  have gapLt
      : time point + (maxDelay + max interval 0 + ackBound maxDelay (max interval 0) 0)
        < time step.before := by
    rw [ackEq]
    linarith
  obtain ⟨sent, sender, reply, response, sentAfter, senderStepped, senderTime, sentAt, source,
      target, payload, _⟩ :=
    acks_before_timeout admissible diverges bounded nonneg heartbeats good behind subset
      leaderIn peerIn different stepped within firstFound
      (fun earlier point after le found =>
        ⟨(invariant earlier point after le found).1.quietAmong admissible found,
          NoProposals.mono (invariant earlier point after le found).2 subset⟩)
      (fun earlier point _ after le found leaderFound =>
        (invariant earlier point after le found).1.liveQuorum good
          (within_of_le admissible within indexFound after le) found leaderFound)
      (fun earlier point _ after le found leaderFound =>
        (invariant earlier point after le found).1.tracked peerIn different leaderFound)
      (fun earlier point after le found => by
        obtain ⟨_, exec⟩ := history_at admissible found
        obtain ⟨local_, now, termEq, _⟩ :=
          (invariant earlier point after le found).1.anchored.settled peer peerIn
        exact ⟨local_, found_of_now exec now, termEq⟩)
      (fun earlier point state after le found leaderFound =>
        (invariant earlier point after le found).1.retained leader state
          (Concrete.mem_of_nodeState leaderFound) leaderIn)
      earlier point afterStart' le found gapLt
  obtain ⟨_, _, _, emitStepped, _, _, _, _, _, sentTime⟩ := admissible.sentAt_emitted sentAt
  rw [senderStepped, Option.some.injEq] at emitStepped
  subst emitStepped
  have sendLate : reply.sentAt + maxDelay < time step.before := by
    rw [sentTime, ackEq] at *
    linarith
  obtain ⟨later, deliverStep, sentBefore, laterBefore, deliverStepped, _, action⟩ :=
    delivered_within admissible bounded nonneg good sentAt (by omega)
      (by rw [source]; exact subset peerIn) (by rw [target]; exact subset leaderIn)
      indexFound within sendLate
  have deliverFound := Trace.stateAt_of_stepAt deliverStepped
  obtain ⟨leaderState, leaderFound, primary, _⟩ :=
    (invariant later deliverStep.before (by omega) laterBefore.le deliverFound).1.leads
      admissible deliverFound
  exact ⟨
    later,
    deliverStep,
    laterBefore,
    deliverStepped,
    Or.inl
      ⟨
        ⟨leaderState, leaderFound, primary⟩,
        reply,
        response,
        action,
        source,
        target,
        payload
      ⟩,
    beyond later deliverStep.before (by omega) deliverFound
  ⟩

/-- While the anchor invariant holds, the primary runs no quorum check, under the
hypotheses of `acked_recently`. -/
theorem no_check_quorum {interval timeout maxDelay : Real}
    (diverges : TimeDiverges trace)
    (bounded : Satisfies trace (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    (heartbeats : HeartbeatScheduling trace (some interval))
    (scheduling : CheckQuorumScheduling trace timeout)
    (ratio : 12 * maxDelay + 8 * max interval 0 < timeout)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants anchor : Finset NodeID}
    (good : GoodBase trace start duration participants)
    (behind : BacklogTerms trace start leader anchor 0)
    (subset : anchor ⊆ participants) (leaderIn : leader ∈ anchor)
    {first : W} (firstFound : trace.stateAt start = some first)
    (startAcks
      : forall peer,
          peer ∈ anchor
          -> Not (peer = leader)
          -> AckedAfter trace start leader peer (time first - interval))
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) (afterStart : start <= index)
    (within : Within trace start duration index)
    (invariant
      : forall earlier point,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> AnchorBaseInv participants anchor leader term (proto point)
              /\ NoProposals participants term point)
    (action : step.action = .local leader (.timeout .checkQuorum))
    : False := by
  obtain ⟨state, leaderFound, configuration, member, lacking⟩ :=
    scheduling index step leader stepped action
  have inv := (invariant index step.before afterStart le_rfl (Trace.stateAt_of_stepAt stepped)).1
  refine lacking ⟨anchor,
    hasQuorum_majority (inv.anchored.quorum state (Concrete.mem_of_nodeState leaderFound))
      member,
    fun peer peerIn => ?_⟩
  by_cases same : peer = leader
  · exact Or.inl same
  · exact Or.inr
      (acked_recently admissible diverges bounded nonneg heartbeats ratio good behind subset
        leaderIn firstFound startAcks stepped afterStart within invariant peerIn same)

end Acks

end CCFRaft.Proofs.Liveness
