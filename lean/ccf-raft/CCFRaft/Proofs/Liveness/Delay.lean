module

public import CCFRaft.Properties.Liveness.Model.Timers
public import CCFRaft.Proofs.Liveness.Network
public import Mathlib.Tactic.Linarith

@[expose] public section

/-!
# Bounded delay

`boundedDelayModel maxDelay` only stops the clock from passing a packet's
deadline while the packet is outstanding to a live target. Once the clock
diverges, the deadline must be met: the packet is consumed, or its target
crashes, at a step no later than `maxDelay` after the packet was sent.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open Model.Node
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)

/-- Every recorded state is within the deadline of each packet outstanding to a
live target. -/
theorem pending_deadline {W : Type} [HasTime W] [HasLive W] [HasNetwork W]
    {trace : Trace W Liveness.Event} {maxDelay : Real}
    (bounded : Satisfies trace (boundedDelayModel maxDelay)) {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {packet : Packet}
    (member : packet ∈ pending point) (targetLive : packet.envelope.target ∈ live point)
    : time point <= packet.sentAt + maxDelay := by
  cases index with
  | zero =>
      rw [Trace.stateAt_zero, Option.some.injEq] at found
      subst found
      exact bounded.init.2 packet member targetLive
  | succ index =>
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      exact bounded.next stepped packet member targetLive

/-- A property that holds at `first` and fails at `last` stops holding at some
step in between. -/
theorem exists_exit {holds : Nat -> Prop} {first last : Nat} (le : first <= last)
    (initially : holds first) (atLast : Not (holds last))
    : exists index,
        first <= index /\ index < last /\ holds index /\ Not (holds (index + 1)) := by
  induction last, le using Nat.le_induction with
  | base => exact absurd initially atLast
  | succ last le ih =>
      by_cases held : holds last
      · exact ⟨last, le, Nat.lt_succ_self _, held, atLast⟩
      · obtain ⟨index, after, before, inside, outside⟩ := ih held
        exact ⟨index, after, Nat.lt_succ_of_lt before, inside, outside⟩

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {config : Finset NodeID} {nodes : List NodeID}
  {trace : Trace W Liveness.Event}

/-- Under bounded delay and a diverging clock, a packet outstanding to a live
target is consumed, or the target crashes, at a step that happens no later than
`maxDelay` after the packet was sent. -/
theorem Admissible.consumed_within (admissible : Admissible config nodes trace)
    {maxDelay : Real} (bounded : Satisfies trace (boundedDelayModel maxDelay))
    (diverges : TimeDiverges trace) {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {packet : Packet}
    (member : packet ∈ pending point) (targetLive : packet.envelope.target ∈ live point)
    : exists later step,
        index <= later
        /\ trace.stepAt later = some step
        /\ time step.before <= packet.sentAt + maxDelay
        /\ (step.action.consumedPacket = some packet
            \/ step.action = .crash packet.envelope.target) := by
  let Outstanding (position : Nat) : Prop :=
    exists point,
      trace.stateAt position = some point
      /\ packet ∈ pending point
      /\ packet.envelope.target ∈ live point
  obtain ⟨far, farPoint, farFound, late⟩ := diverges (packet.sentAt + maxDelay + 1)
  have farOut : Not (Outstanding far) := by
    rintro ⟨point, found, member, targetLive⟩
    rw [farFound, Option.some.injEq] at found
    subst found
    have := pending_deadline bounded farFound member targetLive
    linarith
  have afterIndex : index <= far := by
    by_contra before
    have := admissible.time_le (Nat.le_of_lt (Nat.lt_of_not_le before)) farFound found
    have := pending_deadline bounded found member targetLive
    linarith
  obtain ⟨exit, after, before, ⟨exitPoint, exitFound, exitMember, exitLive⟩, outside⟩ :=
    exists_exit (holds := Outstanding) afterIndex ⟨point, found, member, targetLive⟩ farOut
  obtain ⟨step, stepped⟩ := Trace.stepAt_of_stateAt_lt before farFound
  have exitBefore := Trace.stateAt_of_stepAt stepped
  rw [exitFound, Option.some.injEq] at exitBefore
  subst exitBefore
  refine ⟨
    exit,
    step,
    after,
    stepped,
    pending_deadline bounded exitFound exitMember exitLive,
    ?_
  ⟩
  by_cases stillLive : packet.envelope.target ∈ live step.after
  · refine Or.inl (admissible.consumed_of_left stepped exitMember fun stillPending => ?_)
    exact outside ⟨step.after, Trace.stateAt_succ_of_stepAt stepped, stillPending, stillLive⟩
  · exact Or.inr (admissible.crashes stepped exitLive stillLive)

end CCFRaft.Proofs.Liveness
