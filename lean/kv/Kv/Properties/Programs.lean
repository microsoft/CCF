-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Model

@[expose] public section

/-! Human-reviewed sequential reference semantics and branch-execution predicates. -/

namespace Kv.Properties

open Kv.Model

/-- Each key occurs at most once. -/
def Unique {K V : Type} (xs : Assoc K V) : Prop := (xs.map Prod.fst).Nodup

/-- Every cell was written at or before the supplied publication version. -/
def CellsBounded (db : Data) (version : Nat) : Prop :=
  ∀ key cell, find db key = some cell → cell.version ≤ version

/-- `History fs n`: `fs` lists frames from version `n` down to the empty frame at 0, each obtained from its predecessor by publishing some writes. -/
inductive History : List Frame → Nat → Prop
  /-- The empty initial history. -/
  | zero : History [{}] 0
  /-- Extends a history by one published frame. -/
  | succ (f : Frame) (n : Nat) (fs : List Frame) (version : f.version = n + 1)
    (effect : ∃ writes : Pending, f.data = publish (fs.head?.getD {}).data (n + 1) writes)
    (tail : History fs n)
    : History (f :: fs) (n + 1)

section Generic
variable {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]

/-- The reference transaction has no dependency tracking or OCC validation. -/
def serialStep (base : DB M K V) (ws : Writes M K V) (op : NormalOp M K V)
    : Option (Writes M K V) :=
  match op with
  | .read a observed =>
      if valueAt base ws a = observed then some ws else none
  | .previous a observed =>
      if previousAt base a = observed then some ws else none
  | .scan m observed =>
      if scanAt base ws m = observed then some ws else none
  | .write a value => some (set ws a value)

/-- Runs operations in order with `serialStep`. -/
def serialRun (base : DB M K V) (ws : Writes M K V)
    : List (NormalOp M K V) → Option (Writes M K V)
  | [] => some ws
  | op :: ops => (serialStep base ws op).bind fun next => serialRun base next ops

end Generic

/-- A branch of semantic applications, with compaction but no rollback. -/
inductive AppliedBranch : Model.Store → List Model.Tx → Model.Store → Prop
  /-- Empty application order. -/
  | nil (s) : AppliedBranch s [] s
  /-- One enabled semantic publication primitive. -/
  | cons (s middle final : Model.Store) (t : Model.Tx) (ts : List Model.Tx)
    (one : Model.tryApply s t = some middle)
    (rest : AppliedBranch middle ts final)
    : AppliedBranch s (t :: ts) final
  /-- Environment compaction between applications. -/
  | compact (s final : Model.Store) (v : Nat) (ts : List Model.Tx)
    (rest : AppliedBranch (Model.compactStore s v) ts final)
    : AppliedBranch s ts final

/-- Serial reference interpretation of semantic attempts in application order. -/
def serialTransactions (db : Model.Data) (version : Nat)
    : List Model.Tx → Option Model.Data
  | [] => some db
  | t :: ts =>
      (serialRun db [] t.normal.log).bind
        fun writes =>
          serialTransactions (Model.publish db (version + 1) writes) (version + 1) ts

end Kv.Properties
