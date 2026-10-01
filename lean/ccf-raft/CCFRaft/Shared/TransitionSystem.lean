import Std

namespace CCFRaft.Shared

/-!
The minimal interface every model implements. `init` picks out the initial
states; `step` applies one action. Every other shared definition (traces,
reachability, the multi-node network) is built on these two fields.
-/

/-- `none` disables an action; `some state` may be an enabled stutter. -/
structure TransitionSystem (State Action : Type) where
  init : State -> Prop
  step : State -> Action -> Option State

namespace TransitionSystem

/-- States reached from an initial state by finitely many enabled steps. -/
inductive Reachable {State Action : Type} (system : TransitionSystem State Action)
    : State -> Prop where
  | initial {state : State} (initialized : system.init state) : Reachable system state
  | step
    {state nextState : State}
    {action : Action}
    (reachable : Reachable system state)
    (transition : system.step state action = some nextState)
    : Reachable system nextState

end TransitionSystem

end CCFRaft.Shared
