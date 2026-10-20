module

public import CCF.TransitionSystem

@[expose] public section

namespace CCF.Execution

/-!
Executions of a `TransitionSystem`. `Run` relates a start state, an action list,
and an end state. `Trace` records a countably infinite sequence indexed by `Nat`.
Actions are not stored in the trace, so each step's action is existentially
quantified in validity.
-/

/-- `Run system start actions final`: executing `actions` from `start` reaches `final`. -/
inductive Run {State Action : Type} (system : TransitionSystem State Action)
    : State -> List Action -> State -> Prop where
  /-- An empty action list leaves the state unchanged. -/
  | nil (state : State) : Run system state [] state
  /-- Prepend one enabled action to the rest of an execution. -/
  | cons {before middle after : State} {action : Action} {actions : List Action}
    (step : system.step before action = some middle)
    (rest : Run system middle actions after)
    : Run system before (action :: actions) after

/-- A countably infinite sequence of execution states, initial state first. -/
structure Trace (State : Type) where
  /-- The state at each natural-number position. States may repeat. -/
  states : Nat -> State

/-- A state occurs in a trace when it appears at some finite index. -/
instance {State : Type} : Membership State (Trace State) where
  mem trace state := exists index, trace.states index = state

/-- The first state is initial, and every adjacent pair has an enabled action. -/
def Trace.Valid {State Action : Type} (trace : Trace State)
    (system : TransitionSystem State Action)
    : Prop :=
  system.init (trace.states 0)
  /\ forall index,
      exists action,
        system.step (trace.states index) action = some (trace.states (index + 1))

/-- Every state in a valid infinite trace is reachable by finitely many steps. -/
theorem Trace.Valid.reachable {State Action : Type}
    {system : TransitionSystem State Action}
    {trace : Trace State} (valid : trace.Valid system) {state : State}
    (member : state ∈ trace)
    : system.Reachable state := by
  obtain ⟨index, rfl⟩ := member
  have reaches : forall index, system.Reachable (trace.states index) := by
    intro index
    induction index with
    | zero => exact .initial valid.1
    | succ index ih =>
        obtain ⟨action, step⟩ := valid.2 index
        exact .step ih step
  exact reaches index

end CCF.Execution
