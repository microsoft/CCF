/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura, Jeremy Avigad, Minchao Wu, Mario Carneiro
-/
module

public import Mathlib.Data.Finset.Defs
public import Mathlib.Data.Multiset.FinsetOps

public section
open Multiset
universe u
variable {α : Type*}
namespace Finset
section Lattice
variable [DecidableEq α] {s s₁ s₂ t t₁ t₂ u v : Finset α} {a : α}
/-- `s ∪ t` is the set such that `a ∈ s ∪ t` iff `a ∈ s` or `a ∈ t`. -/
instance : Union (Finset α) :=
  ⟨fun s t => ⟨_, t.2.ndunion s.1⟩⟩
@[simp]
theorem mem_union : a ∈ s ∪ t ↔ a ∈ s ∨ a ∈ t := by
  obtain ⟨⟨l₁⟩, n₁⟩ := s
  obtain ⟨⟨l₂⟩, -⟩ := t
  show a ∈ List.union l₁ l₂ ↔ a ∈ l₁ ∨ a ∈ l₂
  clear n₁
  induction l₁ with
  | nil => simp [List.union]
  | cons b l ih => simp_all [List.union, or_assoc]
/-- `s ∩ t` is the set such that `a ∈ s ∩ t` iff `a ∈ s` and `a ∈ t`. -/
instance : Inter (Finset α) :=
  ⟨fun s t => ⟨_, s.2.ndinter t.1⟩⟩
@[simp]
theorem mem_inter {a : α} {s₁ s₂ : Finset α} : a ∈ s₁ ∩ s₂ ↔ a ∈ s₁ ∧ a ∈ s₂ := by
  obtain ⟨⟨l₁⟩, _⟩ := s₁
  obtain ⟨⟨l₂⟩, _⟩ := s₂
  show a ∈ l₁.filter (· ∈ l₂) ↔ a ∈ l₁ ∧ a ∈ l₂
  simp
@[simp] lemma inter_subset_left : s₁ ∩ s₂ ⊆ s₁ := fun _ h ↦ (mem_inter.1 h).1
@[simp] lemma inter_subset_right : s₁ ∩ s₂ ⊆ s₂ := fun _ h ↦ (mem_inter.1 h).2
end Lattice
end Finset
