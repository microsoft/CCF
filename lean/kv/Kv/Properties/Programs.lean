module

public import Kv.Model

@[expose] public section

/-! Human-reviewed sequential reference semantics and branch-execution predicates. -/

namespace Kv.Properties

open Kv.Model

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

/-- A transaction program executed against a snapshot and applied at a version. -/
structure AppliedProgram (M K V : Type) where
  /-- The snapshot the program executed against. -/
  snapshot : DB M K V
  /-- The program's operations, with their observations. -/
  ops : List (NormalOp M K V)
  /-- The resulting normal view. -/
  result : Normal M K V
  /-- The version at which the writes were applied. -/
  version : Nat

/-- OCC application mechanics on a branch. Rollback selects another branch;
replication return statuses deliberately do not occur here. -/
inductive BranchExecution : DB M K V → List (AppliedProgram M K V) → DB M K V → Prop
  /-- No applications. -/
  | nil (db) : BranchExecution db [] db
  /-- Executes a program on its snapshot, validates it on the branch, and applies it. -/
  | apply (db tail : DB M K V) (p : AppliedProgram M K V) (ps)
    (executed : normalRun p.snapshot {} p.ops = some p.result)
    (validated : validates db p.result.deps = true)
    (rest : BranchExecution (publish db p.version p.result.writes) ps tail)
    : BranchExecution db (p :: ps) tail

/-- Runs each program serially against the branch state, applying its writes. -/
def serialBranch (db : DB M K V) : List (AppliedProgram M K V) → Option (DB M K V)
  | [] => some db
  | p :: ps =>
      (serialRun db [] p.ops).bind fun ws => serialBranch (publish db p.version ws) ps

end Generic

/-- A branch of actual executable applications, including no_replicate ones.
The sequence supplied to the reference interpreter is the recorded operation
program of each transaction, not a list of final-state observations. -/
inductive AppliedBranch : Store → List Tx → Store → Prop
  /-- No applications. -/
  | nil (s) : AppliedBranch s [] s
  /-- Applies one attempt with `tryApply`. -/
  | cons (s middle final : Store) (t : Tx) (ts : List Tx)
    (one : tryApply s t = some middle)
    (rest : AppliedBranch middle ts final)
    : AppliedBranch s (t :: ts) final
  /-- Compacts without applying anything. -/
  | compact (s final : Store) (v : Nat) (ts : List Tx)
    (rest : AppliedBranch (compactStore s v) ts final)
    : AppliedBranch s ts final

/-- Runs each attempt's recorded operation log serially, applying its writes at successive
versions. -/
def serialTransactions (db : Data) (version : Nat) : List Tx → Option Data
  | [] => some db
  | t :: ts =>
      (serialRun db [] t.normal.log).bind
        fun writes =>
          serialTransactions (publish db (version + 1) writes) (version + 1) ts

end Kv.Properties
