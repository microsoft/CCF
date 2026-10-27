module

public import CCFRaft.Properties.Liveness.Model.Trace
public import CCFRaft.Properties.Liveness.Model.World

@[expose] public section

open CCF.Execution (Trace)

namespace CCFRaft.Liveness

open HasTime (time)

/-- Absolute time is nondecreasing, with an unrestricted initial value.
Only an idle step advances time; every other event takes zero time. This follows
`RTnow` in the `RealTime` module of Lamport's Specifying Systems, where `now`
changes only in steps that leave every other variable unchanged.
A CCF action is dated at one instant; the processing time around it is
attributed to idle steps.
A step thus happens at its before-time, which is also its after-time unless it
is idle. Every timing constraint on a step reads its before-time.
Needed: otherwise a single-node primary can append and commit a request at the
start of a window while the same step advances the clock past the window's end,
so no state in the window records the commit. -/
def timingModel {W : Type} [HasTime W] : Model W Event where
  init _ := True
  next step :=
    time step.before <= time step.after
    /\ (Not (step.action = .idle) -> time step.after = time step.before)

/-- Index `index` is at or after `start` and happens within `duration` of it:
a window bounded in real time, not in the number of steps. -/
def Within {W A : Type} [HasTime W] (trace : Trace W A) (start : Nat) (duration : Real)
    (index : Nat)
    : Prop :=
  start <= index
  /\ forall first point,
      trace.stateAt start = some first
      -> trace.stateAt index = some point
      -> time point <= time first + duration

end CCFRaft.Liveness
