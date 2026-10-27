module

public import CCFRaft.Properties.Liveness.Assumptions
public import CCFRaft.Proofs.Liveness.Trace
public import Mathlib.Tactic.Linarith

@[expose] public section

/-!
# Timers that keep being reset

A timer that is reset within `gap` of every recorded state of an execution has
been reset less than `window > gap` before any state at least `window` after the
start. This turns the heartbeat and delivery bounds into the timer condition that
`ElectionSpacing` excludes.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Leadership

open CCFRaft.Liveness
open HasTime (time)

/-- If every recorded state from `start` to `index` more than `gap` before
`index` is followed, strictly later and within `gap` in time, by a `reset`, and
`index` is at least `window` after `start`, then a reset happens strictly before
`index` and less than `window` before it. -/
theorem recent_reset {W A : Type} [HasTime W] {trace : Trace W A}
    (monotone
      : forall earlier later first last,
          earlier <= later
          -> trace.stateAt earlier = some first
          -> trace.stateAt later = some last
          -> time first <= time last)
    {reset : Nat -> Prop} {gap window : Real} (lt : gap < window) {start index : Nat}
    {first last : W} (le : start <= index) (firstFound : trace.stateAt start = some first)
    (lastFound : trace.stateAt index = some last)
    (late : time first + window <= time last)
    (follows
      : forall earlier point,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> time point + gap < time last
          -> exists later laterPoint,
              earlier < later
              /\ trace.stateAt later = some laterPoint
              /\ time laterPoint <= time point + gap
              /\ reset later)
    : exists later laterPoint,
        start < later
        /\ later < index
        /\ trace.stateAt later = some laterPoint
        /\ time last - window < time laterPoint
        /\ reset later := by
  classical
  let early := fun j => start <= j /\ exists point, trace.stateAt j = some point
    /\ time point <= time last - window
  have startEarly : early start := ⟨le_rfl, first, firstFound, by linarith⟩
  set anchor := Nat.findGreatest early index with anchorDef
  obtain ⟨afterStart, anchorPoint, anchorFound, anchorTime⟩ :
      early anchor := Nat.findGreatest_spec (P := early) le startEarly
  have anchorLe : anchor <= index := Nat.findGreatest_le (P := early) index
  obtain ⟨later, laterPoint, after, laterFound, within, holds⟩ :=
    follows anchor anchorPoint afterStart anchorLe anchorFound (by linarith)
  have before : later < index := by
    by_contra notBefore
    have := monotone index later last laterPoint (Nat.le_of_not_lt notBefore) lastFound laterFound
    linarith
  obtain ⟨next, nextFound⟩ := Trace.stateAt_ge_stable (Nat.succ_le_of_lt after) laterFound
  have notEarly : Not (early (anchor + 1)) :=
    Nat.findGreatest_is_greatest (P := early) (Nat.lt_succ_self anchor) (by omega)
  have nextTime : time last - window < time next := by
    by_contra notLater
    exact notEarly ⟨by omega, next, nextFound, le_of_not_gt notLater⟩
  have mono := monotone (anchor + 1) later next laterPoint (Nat.succ_le_of_lt after) nextFound
    laterFound
  exact ⟨later, laterPoint, by omega, before, laterFound, by linarith, holds⟩

end CCFRaft.Proofs.Leadership
