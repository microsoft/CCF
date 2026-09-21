import Std

namespace DisasterRecovery.Shared

/-- `none` disables an action; `some state` may be an enabled stutter. -/
structure TransitionSystem (State Action : Type) where
  init : State -> Prop
  step : State -> Action -> Option State

namespace TransitionSystem

inductive Reachable {State Action : Type}
    (system : TransitionSystem State Action) : State -> Prop where
  | initial
      {state : State}
      (initialized : system.init state) :
      Reachable system state
  | step
      {state nextState : State}
      {action : Action}
      (reachable : Reachable system state)
      (transition : system.step state action = some nextState) :
      Reachable system nextState

end TransitionSystem

end DisasterRecovery.Shared
