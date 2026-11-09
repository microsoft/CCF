/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura, Jeremy Avigad, Minchao Wu, Mario Carneiro
-/
module

public import Mathlib.Basic.SetLike.Basic
public import Mathlib.Data.Multiset.Defs

@[expose] public section
open Multiset Subtype Function
universe u
variable {α : Type*} {β : Type*}
/-- `Finset α` is the type of finite sets of elements of `α`. It is implemented
  as a multiset (a list up to permutation) which has no duplicate elements. -/

@[use_set_notation_for_order]
structure Finset (α : Type*) where
  /-- The underlying multiset -/
  val : Multiset α
  /-- `val` contains no duplicates -/
  nodup : Nodup val
namespace Finset
@[simp]
theorem val_inj {s t : Finset α} : s.1 = t.1 ↔ s = t :=
  ⟨fun h => by cases s; cases t; cases h; rfl, fun h => h ▸ rfl⟩
instance decidableEq [DecidableEq α] : DecidableEq (Finset α)
  | _, _ => decidable_of_iff _ val_inj
/-- Convert a finset to a set in the natural way. -/
instance : SetLike (Finset α) α where
  coe s := Set.ofPred fun a => a ∈ s.1
  coe_injective s₁ s₂ h := by
    rcases s₁ with ⟨v₁, n₁⟩
    rcases s₂ with ⟨v₂, n₂⟩
    induction v₁ using Quot.ind
    induction v₂ using Quot.ind
    congr 1
    exact Quot.sound ((List.perm_ext_iff_of_nodup n₁ n₂).2 fun a =>
      iff_of_eq (congrArg (fun t : Set α => a ∈ t) h))
@[simp]
theorem mem_val {a : α} {s : Finset α} : (a ∈ s.1) = (a ∈ s) := rfl
instance decidableMem [_h : DecidableEq α] (a : α) (s : Finset α) : Decidable (a ∈ s) :=
  Multiset.decidableMem _ _
instance : PartialOrder (Finset α) := .ofSetLike (Finset α)
section DecidablePiExists
variable {s : Finset α}
instance decidableDforallFinset {p : ∀ a ∈ s, Prop} [_hp : ∀ (a) (h : a ∈ s), Decidable (p a h)] :
    Decidable (∀ (a) (h : a ∈ s), p a h) :=
  Multiset.decidableDforallMultiset
instance instDecidableRelSubset [DecidableEq α] : DecidableRel (α := Finset α) (· ⊆ ·) :=
  fun _ _ ↦ decidableDforallFinset
instance decidableDExistsFinset {p : ∀ a ∈ s, Prop} [_hp : ∀ (a) (h : a ∈ s), Decidable (p a h)] :
    Decidable (∃ (a : _) (h : a ∈ s), p a h) :=
  Multiset.decidableDexistsMultiset
instance decidableExistsAndFinset {p : α → Prop} [_hp : ∀ (a), Decidable (p a)] :
    Decidable (∃ a ∈ s, p a) :=
  decidable_of_iff (∃ (a : _) (_ : a ∈ s), p a)
    ⟨fun ⟨a, h, hp⟩ => ⟨a, h, hp⟩, fun ⟨a, h, hp⟩ => ⟨a, h, hp⟩⟩
instance decidableExistsAndFinsetCoe {p : α → Prop} [DecidablePred p] :
    Decidable (∃ a ∈ (s : Set α), p a) := decidableExistsAndFinset
end DecidablePiExists
end Finset
