/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.Multiset.AddSub
public import Mathlib.Data.Set.Basic

@[expose] public section
universe v
open List Subtype Nat Function
variable {α : Type*} {β : Type v} {γ : Type*}
namespace Multiset
/-- `map f s` is the lift of the list `map` operation. The multiplicity
  of `b` in `map f s` is the number of `a ∈ s` (counting multiplicity)
  such that `f a = b`. -/
def map (f : α → β) (s : Multiset α) : Multiset β :=
  Quot.liftOn s (fun l : List α => (l.map f : Multiset β)) fun _l₁ _l₂ p => Quot.sound (p.map f)
section foldr
/-- `foldr f H b s` is the lift of the list operation `foldr f b l`,
  which folds `f` over the multiset. It is well defined when `f` is left-commutative,
  that is, `f a₁ (f a₂ b) = f a₂ (f a₁ b)`. -/
def foldr (f : α → β → β) [LeftCommutative f] (b : β) (s : Multiset α) : β :=
  Quot.liftOn s (fun l => List.foldr f b l) fun _l₁ _l₂ p => p.foldr_eq b
variable (f : α → β → β) [LeftCommutative f]
end foldr
end Multiset
