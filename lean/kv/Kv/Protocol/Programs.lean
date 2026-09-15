-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Kv.Protocol.Model

/-! Human-reviewed sequential reference semantics and branch-execution predicates. -/

namespace Kv

section Generic
variable {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]

/-- The reference transaction has no dependency tracking or OCC validation. -/
def serialStep (base : DB M K V) (ws : Writes M K V)
    (op : NormalOp M K V) : Option (Writes M K V) :=
  match op with
  | .read a observed =>
    if valueAt base ws a = observed then some ws else none
  | .previous a observed =>
    if previousAt base a = observed then some ws else none
  | .scan m observed =>
    if scanAt base ws m = observed then some ws else none
  | .write a value => some (set ws a value)

def serialRun (base : DB M K V) (ws : Writes M K V) :
    List (NormalOp M K V) → Option (Writes M K V)
  | [] => some ws
  | op :: ops => (serialStep base ws op).bind fun next => serialRun base next ops

structure AppliedProgram (M K V : Type) where
  snapshot : DB M K V
  ops : List (NormalOp M K V)
  result : Normal M K V
  version : Nat

/-- OCC application mechanics on a branch. Rollback selects another branch;
replication return statuses deliberately do not occur here. -/
inductive BranchExecution : DB M K V → List (AppliedProgram M K V) → DB M K V → Prop
  | nil (db) : BranchExecution db [] db
  | apply (db tail : DB M K V) (p : AppliedProgram M K V) (ps)
      (executed : normalRun p.snapshot {} p.ops = some p.result)
      (validated : validates db p.result.deps = true)
      (rest : BranchExecution (publish db p.version p.result.writes) ps tail) :
      BranchExecution db (p :: ps) tail

def serialBranch (db : DB M K V) : List (AppliedProgram M K V) → Option (DB M K V)
  | [] => some db
  | p :: ps => (serialRun db [] p.ops).bind fun ws => serialBranch (publish db p.version ws) ps

end Generic

/-- A branch of actual executable applications, including no_replicate ones.
The sequence supplied to the reference interpreter is the recorded operation
program of each transaction, not a list of final-state observations. -/
inductive AppliedBranch : Store → List Tx → Store → Prop
  | nil (s) : AppliedBranch s [] s
  | cons (s middle final : Store) (t : Tx) (ts : List Tx)
      (one : tryApply s t = some middle)
      (rest : AppliedBranch middle ts final) : AppliedBranch s (t :: ts) final
  | compact (s final : Store) (v : Nat) (ts : List Tx)
      (rest : AppliedBranch (compactStore s v) ts final) : AppliedBranch s ts final

def serialTransactions (db : Data) (version : Nat) : List Tx → Option Data
  | [] => some db
  | t :: ts => (serialRun db [] t.normal.log).bind fun writes =>
      serialTransactions (publish db (version + 1) writes) (version + 1) ts

end Kv
