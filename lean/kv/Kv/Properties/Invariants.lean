module

public import Kv.Properties.Programs

@[expose] public section

/-! Human-reviewed trace projections, segment assumptions, and store invariants. -/

namespace Kv.Properties

open Kv.Model

/-- The event neither creates, ends, nor rolls back store `sid`. -/
def SegmentEvent (sid : Nat) : Event → Prop
  | .storeCreate id | .storeEnd id | .rollback id _ _ _ => id ≠ sid
  | _ => True

/-- The attempt an event applies to store `sid`, if any. -/
def projectedApplication (w : World) (sid : Nat) : Event → List Tx
  | .apply id tid _ _ _ =>
      if id = sid then (txOf w id tid).toOption.toList else []
  | _ => []

/-- The head of `after` is that of `before`, or follows from it by applying the listed attempt. -/
inductive HeadEffect (before after : Store) : List Tx → Prop
  /-- The head data and version are unchanged. -/
  | stutter (data : after.head.data = before.head.data)
    (version : after.head.version = before.head.version)
    : HeadEffect before after []
  /-- One attempt is applied. -/
  | apply (tx : Tx) (one : tryApply before tx = some after) : HeadEffect before after [tx]

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

/-- Every cell was written at or before `version`. -/
def CellsBounded (db : Data) (version : Nat) : Prop :=
  ∀ key cell, find db key = some cell → cell.version ≤ version

end Kv.Properties
