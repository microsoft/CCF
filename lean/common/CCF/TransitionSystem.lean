module

public import Std
public import Mathlib.Data.Set.Operations

@[expose] public section

namespace CCF

/-!
The minimal interface every model implements, bundling its state and action types.
`init` picks out the initial
states; `step` applies one action. Every other shared definition (traces,
reachability, the multi-node network) is built on these two fields.
-/

/-- `none` disables an action; `some state` may be an enabled stutter. -/
structure TransitionSystem where
  /-- The states of the model. -/
  State : Type
  /-- The actions that may be applied to a state. -/
  Action : Type
  /-- The states from which an execution may start. -/
  init : State -> Prop
  /-- Applies an action, returning `none` exactly when the action is disabled. -/
  step : State -> Action -> Option State

namespace TransitionSystem

/-- States connected by finitely many enabled steps, without fixing the actions. -/
inductive ReachableFrom (system : TransitionSystem) (start : system.State)
    : Set system.State where
  /-- Taking no steps reaches the starting state. -/
  | refl : ReachableFrom system start start
  /-- An enabled step preserves reachability. -/
  | step
    {state nextState : system.State}
    {action : system.Action}
    (reachable : ReachableFrom system start state)
    (transition : system.step state action = some nextState)
    : ReachableFrom system start nextState

/-- States reached from some initial state by finitely many enabled steps. -/
def Reachable (system : TransitionSystem) : Set system.State :=
  {state | exists initial, system.init initial /\ system.ReachableFrom initial state}

namespace Reachable

/-- An initial state is reachable without taking any steps. -/
theorem initial {system : TransitionSystem} {state : system.State}
    (initialized : system.init state) : system.Reachable state :=
  ⟨state, initialized, .refl⟩

/-- An enabled step from a reachable state reaches another reachable state. -/
theorem step {system : TransitionSystem} {state nextState : system.State}
    {action : system.Action} (reachable : system.Reachable state)
    (transition : system.step state action = some nextState)
    : system.Reachable nextState := by
  obtain ⟨initial, initialized, path⟩ := reachable
  exact ⟨initial, initialized, .step path transition⟩

end Reachable

end TransitionSystem

end CCF
