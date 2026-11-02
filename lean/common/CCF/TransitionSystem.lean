module

public import Std

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

/-- States reached from an initial state by finitely many enabled steps. -/
inductive Reachable (system : TransitionSystem) : system.State -> Prop where
  /-- An initial state is reachable without taking any steps. -/
  | initial {state : system.State} (initialized : system.init state)
    : Reachable system state
  /-- An enabled step preserves reachability. -/
  | step
    {state nextState : system.State}
    {action : system.Action}
    (reachable : Reachable system state)
    (transition : system.step state action = some nextState)
    : Reachable system nextState

end TransitionSystem

end CCF
