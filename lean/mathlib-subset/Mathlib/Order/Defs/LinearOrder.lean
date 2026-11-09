/-
Copyright (c) 2016 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura
-/
module

public import Mathlib.Order.Defs.PartialOrder
public import Mathlib.Tactic.SplitIfs

@[expose] public section
variable {α : Type*}
section LinearOrder
/-- This attempts to prove that a given instance of `compare` is equal to `compareOfLessAndEq` by
introducing the arguments and trying the following approaches in order:

1. seeing if `rfl` works
2. seeing if the `compare` at hand is nonetheless essentially `compareOfLessAndEq`, but, because of
   implicit arguments, requires us to unfold the defs and split the `if`s in the definition of
   `compareOfLessAndEq`
3. seeing if we can split by cases on the arguments, then see if the defs work themselves out
   (useful when `compare` is defined via a `match` statement, as it is for `Bool`)
-/
macro "compareOfLessAndEq_rfl" : tactic =>
  `(tactic| (intro a b; first | rfl |
    (simp only [compare, compareOfLessAndEq]; split_ifs <;> rfl) |
    (induction a <;> induction b <;> simp +decide only)))

/-- A linear order is reflexive, transitive, antisymmetric and total relation `≤`.
We assume that every linear ordered type has decidable `(≤)`, `(<)`, and `(=)`. -/
class LinearOrder (α : Type*) extends PartialOrder α, Min α, Max α, Ord α where
  /-- A linear order is total. -/
  protected le_total (a b : α) : a ≤ b ∨ b ≤ a
  /-- In a linearly ordered type, we assume the order relations are all decidable. -/
  toDecidableLE : DecidableLE α
  /-- In a linearly ordered type, we assume the order relations are all decidable. -/
  toDecidableEq : DecidableEq α := @decidableEqOfDecidableLE _ _ toDecidableLE
  /-- In a linearly ordered type, we assume the order relations are all decidable. -/
  toDecidableLT : DecidableLT α := @decidableLTOfDecidableLE _ _ toDecidableLE
  min := fun a b => if a ≤ b then a else b
  max := fun a b => if a ≤ b then b else a
  /-- The minimum function is equivalent to the one you get from `minOfLe`. -/
  protected min_def : ∀ a b, min a b = if a ≤ b then a else b := by intros; rfl
  /-- The minimum function is equivalent to the one you get from `maxOfLe`. -/
  protected max_def : ∀ a b, max a b = if a ≤ b then b else a := by intros; rfl
  compare a b := compareOfLessAndEq a b
  /-- Comparison via `compare` is equal to the canonical comparison given decidable `<` and `=`. -/
  compare_eq_compareOfLessAndEq : ∀ a b, compare a b = compareOfLessAndEq a b := by
    compareOfLessAndEq_rfl

variable [LinearOrder α] {a b c : α}

attribute [instance_reducible, instance 900] LinearOrder.toDecidableLT
attribute [instance_reducible, instance 900] LinearOrder.toDecidableLE
attribute [instance_reducible, instance 900] LinearOrder.toDecidableEq

lemma min_le_left (a b : α) : min a b ≤ a := by
  rw [LinearOrder.min_def]
  split
  · exact Preorder.le_refl a
  · exact (LinearOrder.le_total a b).resolve_left ‹_›

lemma le_max_left (a b : α) : a ≤ max a b := by
  rw [LinearOrder.max_def]
  split
  · assumption
  · exact Preorder.le_refl a

lemma min_le_right (a b : α) : min a b ≤ b := by
  rw [LinearOrder.min_def]
  split
  · assumption
  · exact Preorder.le_refl b

lemma le_max_right (a b : α) : b ≤ max a b := by
  rw [LinearOrder.max_def]
  split
  · exact Preorder.le_refl b
  · exact (LinearOrder.le_total a b).resolve_left ‹_›

lemma le_min (h₁ : c ≤ a) (h₂ : c ≤ b) : c ≤ min a b := by
  rw [LinearOrder.min_def]
  split <;> assumption

lemma max_le (h₁ : a ≤ c) (h₂ : b ≤ c) : max a b ≤ c := by
  rw [LinearOrder.max_def]
  split <;> assumption

lemma le_or_gt (a b : α) : a ≤ b ∨ b < a :=
  if h : a ≤ b then .inl h else .inr (lt_of_le_not_ge ((LinearOrder.le_total a b).resolve_left h) h)

end LinearOrder
