module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Lean.Data.Json

@[expose] public section

/-!
# M_tv actions

One action per trace event: the trace point reached and the event fields the
model consumes as input (see `Observe.inputFields`). The silent lock release is
`none : Option Action`. Each step also returns a `Label`: the values the model
computed at the trace point for the event's remaining non-state fields.
-/

namespace Consensus.TraceValidation.Exec

open Lean

structure Action where
  point : String
  inputs : List (String × Json)
deriving Inhabited

abbrev Label := List (String × Json)

end Consensus.TraceValidation.Exec
