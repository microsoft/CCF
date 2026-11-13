-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import CCF.TransitionSystem
public import Kv.Model.Transitions

@[expose] public section

/-! Assembles the executable KV model over semantic inputs, independently of instrumentation. -/

namespace Kv.Model

/-- Empty live state; inputs compute outputs through `execute` and state through `step`. -/
abbrev transitionSystem : CCF.TransitionSystem where
  State := State
  Action := Action
  init w := w = {}
  step := step

end Kv.Model
