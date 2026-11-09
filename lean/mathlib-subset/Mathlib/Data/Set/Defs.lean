/-
Copyright (c) 2016 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura
-/
module

public import Mathlib.Tactic.SetNotationForOrder

@[expose] public section
universe u
variable {α : Type u}
/-- A set is a collection of elements of some type `α`.

Although `Set` is defined as `α → Prop`, this is an implementation detail which should not be
relied on. Instead, `Set.ofPred` (also written `{x | p x}`) and membership of a set (`∈`) should be
used to convert between sets and predicates.
-/
@[use_set_notation_for_order]
def Set (α : Type u) := α → Prop
/-- Turn a predicate `p : α → Prop` into a set, also written as `{x | p x}` -/
@[implicit_reducible]
def Set.ofPred {α : Type u} (p : α → Prop) : Set α :=
  p
namespace Set
/-- Membership in a set -/
@[implicit_reducible]
protected def Mem (s : Set α) (a : α) : Prop :=
  s a
instance : Membership α (Set α) :=
  ⟨Set.Mem⟩
/-- The subset relation on sets. `s ⊆ t` means that all elements of `s` are elements of `t`.

Note that you should **not** use this definition directly, but instead write `s ⊆ t`. -/
protected def Subset (s₁ s₂ : Set α) :=
  ∀ ⦃a⦄, a ∈ s₁ → a ∈ s₂
/-- We introduce `≤` before `⊆` to help the unifier when applying lattice theorems
to subset hypotheses. -/
instance : LE (Set α) :=
  ⟨Set.Subset⟩
/-- The union of two sets `s` and `t` is the set of elements contained in either `s` or `t`.

Note that you should **not** use this definition directly, but instead write `s ∪ t`. -/
protected def union (s₁ s₂ : Set α) : Set α := Set.ofPred fun a => a ∈ s₁ ∨ a ∈ s₂
instance : Union (Set α) := ⟨Set.union⟩
/-- The intersection of two sets `s` and `t` is the set of elements contained in both `s` and `t`.

Note that you should **not** use this definition directly, but instead write `s ∩ t`. -/
protected def inter (s₁ s₂ : Set α) : Set α := Set.ofPred fun a => a ∈ s₁ ∧ a ∈ s₂
instance : Inter (Set α) := ⟨Set.inter⟩
end Set
