module

public import CCFRaft.Properties.Liveness.Model.Trace

@[expose] public section

/-!
# Satisfying a model

Generic facts about a trace that satisfies a model: each step is one of the
model's steps, and an invariant of the model holds at every state of the trace.
-/

namespace CCFRaft.Liveness

open CCF.Execution (Trace)

variable {W A : Type} {trace : Trace W A} {model : Model W A}

theorem Satisfies.init (satisfies : Satisfies trace model) : model.init trace.initial :=
  satisfies.1

theorem Satisfies.next (satisfies : Satisfies trace model) {index : Nat}
    {step : CCF.Execution.Step W A} (stepped : trace.stepAt index = some step)
    : model.next step :=
  satisfies.2 index step stepped

/-- An invariant of a model holds at every state of a trace that satisfies it. -/
theorem Satisfies.invariant (satisfies : Satisfies trace model) {invariant : W -> Prop}
    (init : forall point, model.init point -> invariant point)
    (next : forall step, model.next step -> invariant step.before -> invariant step.after)
    {index : Nat} {point : W} (found : trace.stateAt index = some point)
    : invariant point :=
  trace.induction (start := 0) (motive := fun _ point => invariant point)
    (fun point found => by
      rw [Trace.stateAt_zero, Option.some.injEq] at found
      exact found ▸ init _ satisfies.init)
    (fun _ _ _ stepped held => next _ (satisfies.next stepped) held)
    index point (Nat.zero_le _) found

end CCFRaft.Liveness
