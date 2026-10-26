module

public import consistency.Model.Transitions

@[expose] public section

namespace consistency.Model

/-- No view changes and no read-only operations. -/
def singleNode : Config := {}

/-- View changes and invalidation, without read-only operations. -/
def multiNode : Config := { multiNode := true }

/-- Single-node service with forwarded reads. -/
def singleNodeReads : Config := { reads := true }

/-- Multi-node service with forwarded reads. -/
def multiNodeReads : Config := { multiNode := true, reads := true }

/-- Empty history and one empty branch per initial view, including reserved views. -/
def initialState (config : Config) : State :=
  { branches := List.replicate config.firstBranch [] }

/-- The abstract global service, with protocol actions only. -/
def transitionSystem (config : Config) : CCF.TransitionSystem where
  State := State
  Action := Action
  init state := state = initialState config
  step := step config

end consistency.Model
