module

public import CCFRaft.Proofs.Leadership.Timers
public import CCFRaft.Proofs.Leadership.Membership
public import CCFRaft.Proofs.Liveness.Delay
public import CCFRaft.Proofs.Liveness.Timers
public import CCFRaft.Proofs.Leadership.NoProposals
public import Mathlib.Data.List.Perm.Subperm

@[expose] public section

/-!
# Good periods

A good period (`GoodBase`) is a window in which participants stay live, no
configuration is appended, no successor is nominated, no packet between
participants is dropped, and participants receive only from participants.
Inside a good period the primary's AppendEntries to a participant are not
dropped, so bounded delay delivers them within `maxDelay` of their send, as long
as the recording reaches that time (`delivered_within`). Isolation keeps
non-participants from reaching participants, so they are unconstrained.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible exists_exit pending_deadline)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- A good period of `duration` from `start` among `participants`. A live quorum
and the absence of quorum-check step-downs are not part of it; the anchored
path derives them from the anchor where it needs them. -/
structure GoodBase (trace : Trace W Liveness.Event) (start : Nat) (duration : Real)
    (participants : Finset NodeID)
    : Prop where
  participantsLive
    : forall index point node,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> node ∈ participants
        -> node ∈ live point
  noReconfiguration
    : forall index step node entries,
        Within trace start duration index
        -> trace.stepAt index = some step
        -> step.action = .local node (.append entries)
        -> forall entry, entry ∈ entries -> entry.metadata.configuration = none
  noNominations
    : forall index step node,
        Within trace start duration index
        -> trace.stepAt index = some step
        -> Not (step.action = .local node .nominateSuccessor)
  lossless
    : forall index step packet,
        Within trace start duration index
        -> trace.stepAt index = some step
        -> step.action = .drop packet
        -> Not
            (packet.envelope.source ∈ participants
              /\ packet.envelope.target ∈ participants)
  isolated
    : forall index step envelope,
        Within trace start duration index
        -> trace.stepAt index = some step
        -> step.action.delivered = some envelope
        -> envelope.target ∈ participants
        -> envelope.source ∈ participants

section Trace

variable {config : Finset NodeID} {nodes : List NodeID}
  {trace : Trace W Liveness.Event} (admissible : Admissible config nodes trace)

include admissible

/-- A recorded index between the start and a recorded index of the window is in
the window. -/
theorem within_of_le {start duration index earlier} {last : W}
    (within : Within trace start duration index)
    (lastFound : trace.stateAt index = some last) (afterStart : start <= earlier)
    (le : earlier <= index)
    : Within trace start duration earlier := by
  refine ⟨afterStart, fun first point firstFound found => ?_⟩
  have := admissible.time_le le found lastFound
  have := within.2 first last firstFound lastFound
  linarith

/-- In a good period, a packet the primary sends a participant in the window is
delivered no later than `maxDelay` after its send, if the recording reaches a
later state of the window past that time. -/
theorem delivered_within {maxDelay : Real}
    (bounded : Satisfies trace (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    {start : Nat} {duration : Real} {participants : Finset NodeID}
    (good : GoodBase trace start duration participants)
    {sent : Nat} {packet : Packet} (sentAt : SentAt trace sent packet)
    (afterStart : start <= sent) (source : packet.envelope.source ∈ participants)
    (target : packet.envelope.target ∈ participants)
    {index : Nat} {last : W} (lastFound : trace.stateAt index = some last)
    (within : Within trace start duration index)
    (late : packet.sentAt + maxDelay < time last)
    : exists later step,
        sent < later
        /\ later < index
        /\ trace.stepAt later = some step
        /\ time step.before <= packet.sentAt + maxDelay
        /\ step.action = .deliver packet := by
  obtain ⟨_, _, _, emitStepped, _, _, _, _, _, sentTime⟩ := admissible.sentAt_emitted sentAt
  obtain ⟨sendStep, sendStepped, member, _⟩ := sentAt
  rw [sendStepped, Option.some.injEq] at emitStepped
  subst emitStepped
  have targetLive : packet.envelope.target ∈ live last :=
    good.participantsLive index last _ within lastFound target
  have sentBefore : sent < index := by
    by_contra notBefore
    have := admissible.time_le (Nat.le_of_not_lt notBefore) lastFound
      (Trace.stateAt_of_stepAt sendStepped)
    linarith
  let Outstanding (position : Nat) : Prop :=
    exists point, trace.stateAt position = some point /\ packet ∈ pending point
  have lastOut : Not (Outstanding index) := by
    rintro ⟨point, found, pendingNow⟩
    rw [lastFound, Option.some.injEq] at found
    subst found
    have := pending_deadline bounded lastFound pendingNow targetLive
    linarith
  obtain ⟨exit, after, before, ⟨exitPoint, exitFound, exitMember⟩, outside⟩ :=
    exists_exit (holds := Outstanding) (Nat.succ_le_of_lt sentBefore)
      ⟨sendStep.after, Trace.stateAt_succ_of_stepAt sendStepped, member⟩ lastOut
  obtain ⟨step, stepped⟩ := Trace.stepAt_of_stateAt_lt before lastFound
  have exitBefore := Trace.stateAt_of_stepAt stepped
  rw [exitFound, Option.some.injEq] at exitBefore
  subst exitBefore
  have exitLive : packet.envelope.target ∈ live step.before :=
    admissible.live_anti before.le exitFound lastFound targetLive
  have consumed := admissible.consumed_of_left stepped exitMember fun stillPending =>
    outside ⟨step.after, Trace.stateAt_succ_of_stepAt stepped, stillPending⟩
  refine ⟨
    exit,
    step,
    by omega,
    before,
    stepped,
    pending_deadline bounded exitFound exitMember exitLive,
    ?_
  ⟩
  cases action : step.action with
  | deliver delivered =>
      rw [action] at consumed
      simp only [Event.consumedPacket, Option.some.injEq] at consumed
      rw [consumed]
  | drop dropped =>
      rw [action] at consumed
      simp only [Event.consumedPacket, Option.some.injEq] at consumed
      subst consumed
      exact (good.lossless exit step dropped
              (within_of_le admissible within lastFound (by omega) before.le) stepped
              action ⟨source, target⟩).elim
  | _ =>
      rw [action] at consumed
      simp [Event.consumedPacket] at consumed

end Trace

section Recorded

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- The primary of a quiet term, at a recorded state. -/
theorem quietTerm_leader {participants : Finset NodeID} {leader : NodeID}
    {term index : Nat} {point : W} (found : trace.stateAt index = some point)
    (quiet : QuietTerm participants leader term (proto point))
    : exists state,
        nodeState (proto point) leader = some state
        /\ state.role = .primary
        /\ state.currentTerm = term := by
  obtain ⟨_, exec⟩ := history_at admissible found
  obtain ⟨local_, now, primary, termEq⟩ := quiet.leader
  exact ⟨local_, found_of_now exec now, primary, termEq⟩

/-- The primary of a term quiet among participants, at a recorded state. -/
theorem quietAmong_leader {participants : Finset NodeID} {leader : NodeID}
    {term index : Nat} {point : W} (found : trace.stateAt index = some point)
    (quiet : QuietAmong participants leader term (proto point))
    : exists state,
        nodeState (proto point) leader = some state
        /\ state.role = .primary
        /\ state.currentTerm = term :=
  quietTerm_leader admissible found quiet.quietTerm

end Recorded

end CCFRaft.Proofs.Leadership
