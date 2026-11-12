-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.TraceValidation.Types

@[expose] public section

namespace Kv.TraceValidation

open Kv.Model hiding Store Tx step transitionSystem

/-- Erases schema and callback-protocol decorations, retaining all semantic state. -/
def project (w : World) : Model.State :=
  {
    stores := w.stores.map fun (id, s) => (id, s.toStore)
    txs := w.txs.map fun (id, t) => (id, t.toTx)
  }

/-- Translates inputs, not reported outputs, into semantic model actions.
The omitted initial term is supplied as an environment input before the first snapshot.
Trace scopes and individual callback reports stutter; freezing entries is a semantic scan. -/
def actions (w : World) : Event → List Model.Action
  | .storeCreate sid => [.storeCreate sid 0]
  | .storeEnd sid => [.storeEnd sid]
  | .txCreate sid tid => [.txCreate sid tid]
  | .txEnd sid tid => [.txEnd sid tid]
  | .snapshot sid tid _ _ term =>
      (if (find w.stores sid).any (fun s => !s.termKnown) then
          [.setTerm sid term]
        else
          [])
      ++ [.snapshot sid tid]
  | .acquire sid tid m _ _ | .unavailable sid tid m => [.acquire sid tid m]
  | .get sid tid m k _ global => [.operation sid tid (.get m k global)]
  | .has sid tid m k _ global => [.operation sid tid (.has m k global)]
  | .previous sid tid m k _ => [.operation sid tid (.previous m k)]
  | .put sid tid m k value => [.operation sid tid (.write m k (some value))]
  | .remove sid tid m k => [.operation sid tid (.write m k none)]
  | .clear sid tid m => [.operation sid tid (.clear m)]
  | .size sid tid m _ => [.operation sid tid (.size m)]
  | .range sid tid m lower upper _ => [.operation sid tid (.range m lower upper)]
  | .foreachBegin sid tid m _ => [.operation sid tid (.scan m)]
  | .commitBegin sid tid => [.commitBegin sid tid]
  | .apply sid tid _ _ _ => [.apply sid tid]
  | .commitResult sid tid result _ => [.commitResult sid tid result]
  | .compact sid _ requested => [.compact sid requested]
  | .rollback sid _ requested term => [.rollback sid requested term]
  | .rollbackRejected sid requested term => [.rollback sid requested term]
  | _ => []

/-- Runs an event's semantic inputs, retaining the last computed output. -/
def executeActions (s : Model.State) : List Model.Action → Option (Model.State × Output)
  | [] => some (s, .unit)
  | a :: rest => do
      let (next, output) ← Model.execute s a
      if rest.isEmpty then some (next, output) else executeActions next rest

/-- Compares reported results with the model's computed output.
Publication echoes are order-insensitive; range results have semantic key order. -/
def reportedMatches : Event → Output → Bool
  | .snapshot _ _ version global term, .snapshot v g t =>
      decide (version = v ∧ global = g ∧ term = t)
  | .acquire _ _ _ version global, .acquired v g => decide (version = v ∧ global = g)
  | .unavailable _ _ _, .unavailable => true
  | .get _ _ _ _ value _, .value v => decide (value = v)
  | .has _ _ _ _ value _, .presence v => decide (value = v)
  | .previous _ _ _ _ value, .previous v => decide (value = v)
  | .size _ _ _ value, .size v => decide (value = v)
  | .range _ _ _ _ _ entries, .entries vs => decide (entries = vs)
  | .foreachBegin _ _ _ _, .entries _ => true
  | .apply _ _ version term writes, .applied v t ws =>
      decide (version = v ∧ term = t)
      && writes.length == ws.length
      && writes.all (fun (k, value) => find ws k == some value)
  | .commitResult _ _ outcome version, .committed result v =>
      decide (outcome = result ∧ version = v)
  | .compact _ version _, .compacted v => decide (version = v)
  | .rollback _ version _ _, .rolledBack v => decide (version = v)
  | .rollbackRejected _ _ _, .rollbackRejected => true
  | .snapshot .., _
  | .acquire .., _
  | .unavailable .., _
  | .get .., _
  | .has .., _
  | .previous .., _
  | .size .., _
  | .range .., _
  | .foreachBegin .., _
  | .apply .., _
  | .commitResult .., _
  | .compact .., _
  | .rollback .., _
  | .rollbackRejected .., _ => false
  | _, .unit => true
  | _, _ => false

end Kv.TraceValidation
