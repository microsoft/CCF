-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Semantics

@[expose] public section

namespace Kv.Proofs.Semantics

open Kv.Model

/-- An actual semantic apply computes its complete effects, version, and store update. -/
theorem semantic_apply_atomic
    : ∀ (w next : State) (sid tid version term : Nat) (writes : Pending),
        execute w (.apply sid tid) = some (next, .applied version term writes)
        → ∃ (s : Store) (t : Tx),
            lookupTx w sid tid = some (s, t)
            ∧ canApply s t = true
            ∧ writes = t.normal.writes
            ∧ version = s.head.version + 1
            ∧ term = s.term
            ∧ find next.stores sid = some (advance s writes)
            ∧ (advance s writes).head.data = publish s.head.data version writes := by
  intro w next sid tid version term writes accepted
  cases found : lookupTx w sid tid with
  | none => simp [execute, found] at accepted
  | some pair =>
      obtain ⟨s, t⟩ := pair
      simp only [execute, found] at accepted
      change
        (if t.phase != .committing || t.normal.writes.isEmpty then none
         else (tryApply s t).bind fun store =>
           some ({
             stores := set w.stores sid store
             txs := set w.txs tid { t with phase := .applied store.head.version }
           },
             Output.applied store.head.version s.term t.normal.writes))
          = some (next, .applied version term writes) at accepted
      split at accepted
      · cases accepted
      · cases applied : tryApply s t with
        | none => simp [applied] at accepted
        | some store =>
            have permitted : canApply s t = true := by
              unfold tryApply at applied
              split at applied
              · assumption
              · cases applied
            have storeEq : store = advance s t.normal.writes := by
              simpa [tryApply, permitted] using applied.symm
            subst store
            simp only [applied, Option.bind_some, Option.some.injEq, Prod.mk.injEq,
              Output.applied.injEq] at accepted
            obtain ⟨stateEq, versionEq, termEq, writesEq⟩ := accepted
            subst next version term writes
            exact ⟨s, t, rfl, permitted, rfl, rfl, rfl, by simp [Model.set, find], rfl⟩

/-- A semantic publication can affect multiple maps without any trace envelope. -/
theorem semantic_apply_atomic_witness
    : ∃ (w next : State) (sid tid version term : Nat) (writes : Pending),
        execute w (.apply sid tid) = some (next, .applied version term writes)
        ∧ ∃ a b : Addr String String,
            a.1 ≠ b.1 ∧ find writes a ≠ none ∧ find writes b ≠ none := by
  let writes : Pending := [(("a", "k"), some "x"), (("b", "k"), some "y")]
  let w : State := {
    stores := [(1, { term := 7 })]
    txs := [(1, { store := 1, phase := .committing, normal := { writes } })]
  }
  exact ⟨
    w,
    (step w (.apply 1 1)).getD {},
    1,
    1,
    1,
    7,
    writes,
    rfl,
    ("a", "k"),
    ("b", "k"),
    by decide +kernel,
    by decide +kernel,
    by decide +kernel
  ⟩

end Kv.Proofs.Semantics
