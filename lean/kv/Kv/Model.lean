-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import CCF.Execution
public import Kv.Model.Transitions

@[expose] public section

/-! Assembles the executable KV model as a transition system over trace records. -/

namespace Kv.Model

/-- The model starts from the empty world, and a record is enabled exactly when `step` accepts it. -/
def transitionSystem : CCF.TransitionSystem where
  State := World
  Action := Record
  init w := w = {}
  step w r := (step w r).toOption

end Kv.Model
