module

public import CCF.TransitionSystem
public import CCF.Seq

@[expose] public section

namespace CCF.Execution

/-!
Executions of a `TransitionSystem`. `Run` relates a start state, a finite
action list, and an end state. `Trace` records an initial state and a finite or
infinite sequence of actions paired with their successor states, with a validity proof.
Execution constructors and theorems are in `CCF.Proofs.Execution`.
-/

/-- `Run system start actions final`: executing `actions` from `start` reaches `final`. -/
inductive Run (system : TransitionSystem)
    : system.State -> List system.Action -> system.State -> Prop where
  /-- An empty action list leaves the state unchanged. -/
  | nil (state : system.State) : Run system state [] state
  /-- Prepend one enabled action to the rest of an execution. -/
  | cons {before middle after : system.State} {action : system.Action}
    {actions : List system.Action}
    (step : system.step before action = some middle)
    (rest : Run system middle actions after)
    : Run system before (action :: actions) after

/-- An initial state and recorded actions paired with their successor states. -/
structure TraceImpl (system : TransitionSystem) where
  /-- The initial state. -/
  init : system.State
  /-- Each action is paired with the state it reaches. -/
  steps : CCF.Seq (system.Action × system.State)

/-- The initial state is allowed and each recorded action reaches its paired state. -/
def TraceImpl.Valid {system : TransitionSystem} (trace : TraceImpl system) : Prop :=
  system.init trace.init
  /\ forall n before action,
      (CCF.Seq.cons trace.init (trace.steps.map Prod.snd)).get? n = some before
      -> (trace.steps.map Prod.fst).get? n = some action
      -> system.step before action = (trace.steps.map Prod.snd).get? n

/-- A nonempty, valid finite or infinite execution. -/
abbrev Trace (system : TransitionSystem) :=
  {trace : TraceImpl system // trace.Valid}

namespace Trace

/-- The visited states, initial state first. -/
def states {system : TransitionSystem} (trace : Trace system) : CCF.Seq system.State :=
  CCF.Seq.cons trace.val.init (trace.val.steps.map Prod.snd)

/-- The actions recorded by the execution. -/
def actions {system : TransitionSystem} (trace : Trace system) : CCF.Seq system.Action :=
  trace.val.steps.map Prod.fst

/-- The state at an index, or `none` beyond a finite trace. -/
@[simp]
def stateAt {system : TransitionSystem} (trace : Trace system) (n : Nat)
    : Option system.State :=
  trace.states.get? n

/-- The action at an index, or `none` beyond a finite trace. -/
@[simp]
def actionAt {system : TransitionSystem} (trace : Trace system) (n : Nat)
    : Option system.Action :=
  trace.actions.get? n

instance {system : TransitionSystem} : Membership system.State (Trace system) :=
  ⟨fun trace state => state ∈ trace.states⟩

end Trace

end CCF.Execution
