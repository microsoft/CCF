-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Model

@[expose] public section

namespace Kv.Proofs.SemanticHelpers

open Kv.Model

/-- A successful semantic bind exposes its successful input and continuation. -/
theorem option_bind_ok {α β : Type} {x : Option α} {f : α → Option β}
    {b : β} (h : x.bind f = some b)
    : ∃ a, x = some a ∧ f a = some b := by
  cases x with
  | none => cases h
  | some a => exact ⟨a, rfl, h⟩

/-- Semantic ownership lookup exposes its underlying live store and transaction. -/
theorem lookup_found {w : State} {sid tid : Nat} {s : Store} {t : Tx}
    (found : lookupTx w sid tid = some (s, t))
    : find w.stores sid = some s ∧ find w.txs tid = some t ∧ t.store = sid := by
  dsimp only [lookupTx] at found
  obtain ⟨actualStore, store, found⟩ := option_bind_ok found
  obtain ⟨actualTx, tx, found⟩ := option_bind_ok found
  split at found
  · cases found
    exact ⟨store, tx, beq_iff_eq.mp ‹(t.store == sid) = true›⟩
  · cases found

/-- Replacing an association-list value establishes exact lookup at its key. -/
theorem find_set_same {K V : Type} [DecidableEq K] (xs : Assoc K V) (k : K) (v : V)
    : find (set xs k v) k = some v := by
  simp [Model.set, find]

end Kv.Proofs.SemanticHelpers
