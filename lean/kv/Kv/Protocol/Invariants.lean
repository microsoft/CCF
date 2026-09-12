-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Kv.Protocol.Programs

/-! Human-reviewed trace projections, segment assumptions, and store invariants. -/

namespace Kv

def SegmentEvent (sid : Nat) : Event → Prop
  | .storeCreate id | .storeEnd id | .rollback id _ _ _ => id ≠ sid
  | _ => True

def projectedApplication (w : World) (sid : Nat) : Event → List Tx
  | .apply id tid _ _ _ =>
    if id = sid then (txOf w id tid).toOption.toList else []
  | _ => []

inductive HeadEffect (before after : Store) : List Tx → Prop
  | stutter (data : after.head.data = before.head.data)
      (version : after.head.version = before.head.version) : HeadEffect before after []
  | apply (tx : Tx) (one : tryApply before tx = some after) : HeadEffect before after [tx]

def projectApplications (w : World) (sid : Nat) : List Record → Except Failure (List Tx)
  | [] => .ok []
  | r :: rs => do
    let next ← step w r
    let rest ← projectApplications next sid rs
    return projectedApplication w sid r.event ++ rest

def Reachable (w : World) : Prop := ∃ rs, replay {} rs = .ok w

def AttemptEvent (tid : Nat) : Event → Prop
  | .txCreate _ id | .txEnd _ id => id ≠ tid
  | _ => True

def CellsBounded (db : Data) (version : Nat) : Prop :=
  ∀ key cell, find db key = some cell → cell.version ≤ version

end Kv
