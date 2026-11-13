-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.TraceValidation.Transitions

@[expose] public section

namespace Kv.TraceValidation

/-- Typed trace validation, including instrumentation lifecycles and reported observations. -/
def transitionSystem : CCF.TransitionSystem where
  State := World
  Action := Record
  init w := w = {}
  step w r := (step w r).toOption

/-- Semantic inputs translated along the actual accepted typed replay. -/
def semanticInputs (w : World) : List Record → Except Failure (List Model.Action)
  | [] => .ok []
  | r :: rs => do
      let next ← step w r
      let rest ← semanticInputs next rs
      return actions w r.event ++ rest

end Kv.TraceValidation
