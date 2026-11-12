-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Programs

@[expose] public section

/-! Human-reviewed trace projections, segment assumptions, and store invariants. -/

namespace Kv.Properties

open Kv.Model
      hiding Store Tx advance compactStore rollbackStore tryApply step transitionSystem
open Kv.TraceValidation

/-- The event neither creates, ends, nor rolls back store `sid`. -/
def SegmentEvent (sid : Nat) : Event → Prop
  | .storeCreate id | .storeEnd id | .rollback id _ _ _ => id ≠ sid
  | _ => True

/-- The attempt an event applies to store `sid`, if any. -/
def projectedApplication (w : World) (sid : Nat) : Event → List Tx
  | .apply id tid _ _ _ =>
      if id = sid then (txOf w id tid).toOption.toList else []
  | _ => []

/-- The attempts a record sequence applies to store `sid`, in order. -/
def projectApplications (w : World) (sid : Nat) : List Record → Except Failure (List Tx)
  | [] => .ok []
  | r :: rs => do
      let next ← step w r
      let rest ← projectApplications next sid rs
      return projectedApplication w sid r.event ++ rest

/-- The event neither creates nor ends attempt `tid`. -/
def AttemptEvent (tid : Nat) : Event → Prop
  | .txCreate _ id | .txEnd _ id => id ≠ tid
  | _ => True

end Kv.Properties
