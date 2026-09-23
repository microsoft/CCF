-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

set_option autoImplicit false

namespace CCFRaft.Proofs.Abstract

/-- Guards and state updates shared by the model and its executable replayer. -/
structure ExecutableTransitionSystem where
  State : Type
  Action : Type
  initial : State
  Enabled : State -> Action -> Prop
  enabledDecidable : forall state action, Decidable (Enabled state action)
  next : State -> Action -> State

namespace ExecutableTransitionSystem

instance (system : ExecutableTransitionSystem)
    : forall state action, Decidable (system.Enabled state action) :=
  system.enabledDecidable

/-- Execute an action only when its canonical guard holds. -/
def applyAction
    (system : ExecutableTransitionSystem)
    (state : system.State)
    (action : system.Action)
    : Option system.State :=
  if system.Enabled state action then
    some (system.next state action)
  else
    none

/-- An enabled model action relates its input and output states. -/
def Step (system : ExecutableTransitionSystem) (before after : system.State) : Prop :=
  Exists
    fun action =>
      system.Enabled before action /\ after = system.next before action

/-- States obtainable from the initializer through enabled actions. -/
inductive Reachable (system : ExecutableTransitionSystem) : system.State -> Prop where
  | initial : Reachable system system.initial
  | step
    {state : system.State}
    (reachable : Reachable system state)
    {action : system.Action}
    (enabled : system.Enabled state action)
    : Reachable system (system.next state action)

end ExecutableTransitionSystem

end CCFRaft.Proofs.Abstract
