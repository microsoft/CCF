-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Semantics
public import Kv.TraceValidation.System

@[expose] public section

namespace Kv.Correspondence

open Kv.Model
      hiding Store Tx advance compactStore rollbackStore tryApply step transitionSystem
open Kv.TraceValidation Kv.Properties

/-- A branch of actual executable applications, including no_replicate ones.
The programs are each attempt's operation log, not final-state observations. -/
inductive AppliedBranch : Store → List Tx → Store → Prop
  /-- No applications. -/
  | nil (s) : AppliedBranch s [] s
  /-- Apply an attempt using the shared semantic publication primitive. -/
  | cons (s middle final : Store) (t : Tx) (ts : List Tx)
    (one : tryApply s t = some middle)
    (rest : AppliedBranch middle ts final)
    : AppliedBranch s (t :: ts) final
  /-- Compaction interleaving. -/
  | compact (s final : Store) (v : Nat) (ts : List Tx)
    (rest : AppliedBranch (compactStore s v) ts final)
    : AppliedBranch s ts final

/-- Runs each attempt's normal program serially, publishing at successive versions. -/
def serialTransactions (db : Data) (version : Nat) : List Tx → Option Data
  | [] => some db
  | t :: ts =>
      (serialRun db [] t.normal.log).bind
        fun writes =>
          serialTransactions (publish db (version + 1) writes) (version + 1) ts

end Kv.Correspondence
