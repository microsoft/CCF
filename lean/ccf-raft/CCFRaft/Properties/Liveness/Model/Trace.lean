module

public import CCF.Execution

@[expose] public section

namespace CCFRaft.Liveness

open CCF.Execution (Trace)

/-- A TLA-style initial predicate and action on a recorded step.
Fields left unmentioned are unconstrained; models have no variable ownership. -/
structure Model (W A : Type) where
  init : W -> Prop
  next : CCF.Execution.Step W A -> Prop

/-- The trace starts in a state the model admits, and every step satisfies the
model, independently of other models. -/
def Satisfies {W A : Type} (trace : Trace W A) (model : Model W A) : Prop :=
  model.init trace.initial
  /\ forall index step, trace.stepAt index = some step -> model.next step

/-- Eventually, at or after `index`, an existing recorded state satisfies the predicate. -/
def Eventually {W A : Type} (trace : Trace W A) (index : Nat)
    (predicate : Nat -> W -> Prop)
    : Prop :=
  exists later point,
    index <= later /\ trace.stateAt later = some point /\ predicate later point

end CCFRaft.Liveness
