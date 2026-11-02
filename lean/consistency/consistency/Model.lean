module

public import consistency.Model.Transitions

@[expose] public section

namespace consistency.Model

/-- Empty history starting at view 2, with view 1 reserved as an empty branch. -/
def initialState : State :=
  { branches := List.replicate 2 [] }

/-- The multi-node service with forwarded reads and protocol actions only. -/
def transitionSystem : CCF.TransitionSystem where
  State := State
  Action := Action
  init state := state = initialState
  step := step

end consistency.Model
