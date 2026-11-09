/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura, Jeremy Avigad, Minchao Wu, Mario Carneiro
-/
module

public import Mathlib.Data.Finset.Dedup
public import Mathlib.Data.Finset.Empty
public import Mathlib.Data.Multiset.FinsetOps

@[expose] public section
open Multiset Subtype Function
universe u
variable {α : Type*} {β : Type*}
namespace Finset
section Singleton
variable {s : Finset α} {a b : α}
/-- `{a} : Finset a` is the set `{a}` containing `a` and nothing else.

This differs from `insert a ∅` in that it does not require a `DecidableEq` instance for `α`.
-/
instance : Singleton α (Finset α) :=
  ⟨fun a => ⟨{a}, nodup_singleton a⟩⟩
@[simp]
theorem mem_singleton {a b : α} : b ∈ ({a} : Finset α) ↔ b = a := by
  show b ∈ [a] ↔ b = a
  simp
end Singleton
section Insert
variable [DecidableEq α] {s t : Finset α} {a b : α} {f : α → β}
/-- `insert a s` is the set `{a} ∪ s` containing `a` and the elements of `s`. -/
instance : Insert α (Finset α) :=
  ⟨fun a s => ⟨_, s.2.ndinsert a⟩⟩
@[simp]
theorem mem_insert : a ∈ insert b s ↔ a = b ∨ a ∈ s := by
  obtain ⟨⟨l⟩, _⟩ := s
  exact List.mem_insert_iff
end Insert
end Finset
