module

public import CCFRaft.Properties.Liveness.Model.Timers
public import CCFRaft.Proofs.Liveness.Trace
public import Mathlib.Tactic.Linarith

@[expose] public section

/-!
# Election deadlines

Valid election timeouts imply `ElectionSpacing`: each reset draws a deadline
at least the minimum interval after its time, a later reset
only draws one later still, and a node times out only once its deadline has passed.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open HasTime (time)
open HasTimers (deadline)

/-- Time never runs backwards between recorded states. -/
theorem time_mono {W : Type} [HasTime W] {trace : Trace W Liveness.Event}
    (timing : Satisfies trace timingModel)
    {earlier later : Nat} (le : earlier <= later) {first last : W}
    (firstFound : trace.stateAt earlier = some first)
    (lastFound : trace.stateAt later = some last)
    : time first <= time last :=
  trace.chain (relation := fun first last => time first <= time last)
    (fun _ => le_rfl) (fun _ _ _ => le_trans)
    (fun _ _ stepped => (timing.next stepped).1) le firstFound lastFound

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasTimers W]
  {trace : Trace W Liveness.Event}

/-- After a reset, the deadline stays at least the minimum interval past it. -/
theorem deadline_after_reset {minimum : Real} (timing : Satisfies trace timingModel)
    (timers : ElectionTimeouts trace (some minimum)) {earlier : Nat}
    {reset : CCF.Execution.Step W Liveness.Event} {node : Model.Node.NodeID}
    (resetAt : trace.stepAt earlier = some reset) (resets : ElectionReset reset node)
    {index : Nat} {point : W} (after : earlier < index)
    (found : trace.stateAt index = some point)
    : time reset.before + minimum <= deadline point node :=
  trace.induction
    (start := earlier + 1)
    (motive := fun _ point => time reset.before + minimum <= deadline point node)
    (fun point found => by
      rw [Trace.stateAt_succ_of_stepAt resetAt, Option.some.injEq] at found
      exact found ▸ (((timers.next resetAt) node).1 resets).1)
    (fun later step afterReset stepped held => by
      by_cases stepResets : ElectionReset step node
      · have elapsed :=
          time_mono timing (Nat.le_of_succ_le afterReset) (Trace.stateAt_of_stepAt resetAt)
            (Trace.stateAt_of_stepAt stepped)
        have drawn := (((timers.next stepped) node).1 stepResets).1
        linarith
      · rw [((timers.next stepped) node).2.1 stepResets]
        exact held)
    index point after found

/-- Valid election deadlines imply minimum spacing, not timeout progress. -/
theorem electionSpacing_of_timeouts {minimum : Real}
    (timing : Satisfies trace timingModel)
    (timers : ElectionTimeouts trace (some minimum))
    : ElectionSpacing trace (some minimum) := by
  intro earlier index reset timeout node lt resetAt timeoutAt fires resets
  have drawn :=
    deadline_after_reset timing timers resetAt resets lt (Trace.stateAt_of_stepAt timeoutAt)
  have passed := ((timers.next timeoutAt) node).2.2 fires
  linarith

end CCFRaft.Proofs.Liveness

namespace CCFRaft.Liveness

/-- Minimum spacing follows from valid timeouts and the timing model. -/
theorem ElectionScheduling.spacing
    {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasTimers W]
    {trace : Trace W Event} {minimum jitter : Option Real}
    (scheduled : ElectionScheduling trace minimum jitter)
    (timing : Satisfies trace timingModel)
    : ElectionSpacing trace minimum := by
  cases minimum with
  | none => trivial
  | some minimum =>
      exact Proofs.Liveness.electionSpacing_of_timeouts timing scheduled.timeouts

end CCFRaft.Liveness
