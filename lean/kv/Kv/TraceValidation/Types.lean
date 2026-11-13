-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Model

@[expose] public section

namespace Kv.TraceValidation

open Kv.Model

/-- Schema 1 infers a store's omitted initial term at first capture or rollback. -/
structure Store extends Model.Store where
  /-- Whether the initial term has been established. -/
  termKnown : Bool := false
deriving Repr

instance : Inhabited Store := ⟨{}⟩

instance : Coe Store Model.Store := ⟨Store.toStore⟩

/-- Trace protocol state for a frozen iteration, not a KV reference or operation input. -/
structure Iteration where
  /-- Map whose entries were frozen. -/
  map : String
  /-- Trace-local iteration identifier. -/
  id : Nat
  /-- Entries whose callbacks have not run. -/
  remaining : Assoc String String
  /-- An entry awaits its callback result. -/
  awaitingContinue : Bool := false
  /-- A callback requested early termination. -/
  stopped : Bool := false
deriving Repr

/-- A semantic attempt decorated with the trace's callback protocol. -/
structure Tx extends Model.Tx where
  /-- Nested iterations, innermost first. -/
  iterations : List Iteration := []
  /-- Run-local iteration identities already used by each map. -/
  iterationIds : List (String × Nat) := []
deriving Repr

instance : Coe Tx Model.Tx := ⟨Tx.toTx⟩

/-- Schema 1 event inputs and reported observations. -/
inductive Event where
  /-- Schema declaration. -/
  | traceStart (schema : Nat)
  /-- Test case start. -/
  | caseBegin (name : String)
  /-- Test case completion. -/
  | caseEnd (name : String) (failed : Bool)
  /-- Nested test start. -/
  | subcaseBegin (name : String)
  /-- Nested test completion. -/
  | subcaseEnd (name : String)
  /-- Store incarnation start. -/
  | storeCreate (store : Nat)
  /-- Store incarnation end. -/
  | storeEnd (store : Nat)
  /-- Attempt start. -/
  | txCreate (store tx : Nat)
  /-- Attempt destruction. -/
  | txEnd (store tx : Nat)
  /-- Reported snapshot metadata. -/
  | snapshot (store tx version global term : Nat)
  /-- Reported local and global map revisions. -/
  | acquire (store tx : Nat) (map : String) (version global : Nat)
  /-- Reported lazy acquisition failure. -/
  | unavailable (store tx : Nat) (map : String)
  /-- Reported value. -/
  | get (store tx : Nat) (map key : String) (value : Option String) (global : Bool)
  /-- Reported presence. -/
  | has (store tx : Nat) (map key : String) (value : Bool) (global : Bool)
  /-- Reported previous-write version. -/
  | previous (store tx : Nat) (map key : String) (value : Option Nat)
  /-- Put input. -/
  | put (store tx : Nat) (map key value : String)
  /-- Removal input. -/
  | remove (store tx : Nat) (map key : String)
  /-- Clear input. -/
  | clear (store tx : Nat) (map : String)
  /-- Reported size. -/
  | size (store tx : Nat) (map : String) (value : Nat)
  /-- Reported ordered range. -/
  | range (store tx : Nat) (map : String) (lower upper : Option String)
    (entries : Assoc String String)
  /-- Frozen iteration start. -/
  | foreachBegin (store tx : Nat) (map : String) (iteration : Nat)
  /-- Reported frozen entry. -/
  | foreachEntry (store tx : Nat) (map : String) (iteration : Nat) (key value : String)
  /-- Callback decision. -/
  | foreachContinue (store tx : Nat) (map : String) (iteration : Nat) (value : Bool)
  /-- Iteration completion. -/
  | foreachEnd (store tx : Nat) (map : String) (iteration : Nat)
  /-- Commit invocation. -/
  | commitBegin (store tx : Nat)
  /-- Reported publication effects. -/
  | apply (store tx version term : Nat) (writes : Pending)
  /-- Reported environment outcome and assigned version. -/
  | commitResult (store tx : Nat) (result : Outcome) (version : Nat)
  /-- Reported compaction cut. -/
  | compact (store version requested : Nat)
  /-- Reported rollback cut and new term. -/
  | rollback (store version requested term : Nat)
  /-- Reported refusal to cross the global cut. -/
  | rollbackRejected (store requested term : Nat)
  /-- Explicit excluded mechanism. -/
  | unsupported (store : Option Nat) (operation : String)
  /-- Manifest completion and event count. -/
  | traceEnd (events : Nat)
deriving Repr

/-- One run-ordered trace record. -/
structure Record where
  /-- Run-wide sequence number. -/
  seq : Nat
  /-- Event with inputs and reports. -/
  event : Event
deriving Repr

/-- Trace outcome category. -/
inductive FailureKind where
  /-- Behavior forbidden by the model. -/
  | rejected
  /-- Malformed or incomplete instrumentation. -/
  | invalidTrace
  /-- Explicit excluded mechanism. -/
  | unsupported
deriving Repr, BEq, DecidableEq

/-- Trace failure and first diagnostic. -/
structure Failure where
  /-- Failure classification. -/
  kind : FailureKind
  /-- Diagnostic text. -/
  message : String
deriving Repr

/-- Replay state with semantic data and instrumentation bookkeeping. -/
structure World where
  /-- Live store incarnations. -/
  stores : Assoc Nat Store := []
  /-- Live attempts. -/
  txs : Assoc Nat Tx := []
  /-- Previously seen store IDs. -/
  seenStores : List Nat := []
  /-- Previously seen attempt IDs. -/
  seenTxs : List Nat := []
  /-- Open test case. -/
  currentCase : Option String := none
  /-- Nested test scopes. -/
  subcases : List String := []
  /-- Completed cases. -/
  cases : Nat := 0
  /-- Schema was declared. -/
  started : Bool := false
  /-- Manifest was closed. -/
  ended : Bool := false
  /-- Last accepted sequence number. -/
  lastSeq : Option Nat := none
  /-- Number of accepted records. -/
  count : Nat := 0
deriving Repr

/-- The reports agree with the computed local operation. -/
def observes {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (ws : Writes M K V)
    : NormalOp M K V → Bool
  | .read a v => decide (valueAt db ws a = v)
  | .previous a v => decide (previousAt db a = v)
  | .scan m vs => decide (scanAt db ws m = vs)
  | .write _ _ => true

end Kv.TraceValidation
