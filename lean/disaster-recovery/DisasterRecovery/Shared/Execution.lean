import DisasterRecovery.Shared.TransitionSystem

namespace DisasterRecovery.Shared.Execution

inductive Run {State Action : Type} (system : TransitionSystem State Action) :
    State -> List Action -> State -> Prop where
  | nil (state : State) : Run system state [] state
  | cons {before middle after : State} {action : Action} {actions : List Action}
      (step : system.step before action = some middle)
      (rest : Run system middle actions after) :
      Run system before (action :: actions) after

structure Transition (State Action : Type) where
  before : State
  action : Action
  after : State

inductive Trace {State Action : Type} (system : TransitionSystem State Action) :
    State -> List (Transition State Action) -> State -> Prop where
  | nil (state : State) : Trace system state [] state
  | cons {before middle after : State} {action : Action}
      {steps : List (Transition State Action)}
      (step : system.step before action = some middle)
      (rest : Trace system middle steps after) :
      Trace system before ({ before, action, after := middle } :: steps) after

namespace Trace

theorem append {system : TransitionSystem State Action} {before middle after}
    {first second : List (Transition State Action)}
    (left : Trace system before first middle) (right : Trace system middle second after) :
    Trace system before (first ++ second) after := by
  induction left with
  | nil => exact right
  | cons step rest ih => exact .cons step (ih right)

theorem reachable {system : TransitionSystem State Action} {before after steps}
    (trace : Trace system before steps after) (initial : system.Reachable before) :
    system.Reachable after := by
  induction trace with
  | nil => exact initial
  | cons step rest ih => exact ih (.step initial step)

theorem run {system : TransitionSystem State Action} {before after steps}
    (trace : Trace system before steps after) :
    Run system before (steps.map Transition.action) after := by
  induction trace with
  | nil => exact .nil _
  | cons step rest ih => exact .cons step ih

end Trace

end DisasterRecovery.Shared.Execution
