/-
Copyright (c) 2016 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura
-/
module

public import Mathlib.Init
@[expose] public section
variable {α : Type*}
section Preorder
/--
A preorder is a reflexive, transitive relation `≤`.
In a preorder, `a < b` means `a ≤ b ∧ ¬b ≤ a`, and `<` is defined this way by default.
You can override this definition to set a better def-eq.
-/
class Preorder (α : Type*) extends LE α, LT α where
  protected le_refl : ∀ a : α, a ≤ a
  protected le_trans : ∀ a b c : α, a ≤ b → b ≤ c → a ≤ c
  lt := fun a b => a ≤ b ∧ ¬b ≤ a
  protected lt_iff_le_not_ge : ∀ a b : α, a < b ↔ a ≤ b ∧ ¬b ≤ a := by intros; rfl
variable [Preorder α] {a b c : α}

@[refl] lemma le_refl : ∀ a : α, a ≤ a := Preorder.le_refl

lemma le_rfl : a ≤ a := le_refl a

lemma le_trans : a ≤ b → b ≤ c → a ≤ c := Preorder.le_trans _ _ _

lemma lt_iff_le_not_ge : a < b ↔ a ≤ b ∧ ¬b ≤ a := Preorder.lt_iff_le_not_ge _ _

lemma lt_of_le_not_ge (hab : a ≤ b) (hba : ¬ b ≤ a) : a < b := lt_iff_le_not_ge.2 ⟨hab, hba⟩

/-- `<` is decidable if `≤` is. -/
@[instance_reducible]
def decidableLTOfDecidableLE [DecidableLE α] : DecidableLT α :=
  fun _ _ => decidable_of_iff _ lt_iff_le_not_ge.symm

end Preorder
section PartialOrder
/-- A partial order is a reflexive, transitive, antisymmetric relation `≤`. -/
class PartialOrder (α : Type*) extends Preorder α where
  protected le_antisymm : ∀ a b : α, a ≤ b → b ≤ a → a = b
variable [PartialOrder α] {a b : α}

lemma le_antisymm : a ≤ b → b ≤ a → a = b := PartialOrder.le_antisymm _ _

/-- Equality is decidable if `≤` is. -/
def decidableEqOfDecidableLE [DecidableLE α] : DecidableEq α
  | a, b =>
    if hab : a ≤ b then
      if hba : b ≤ a then isTrue (le_antisymm hab hba) else isFalse fun heq => hba (heq ▸ le_refl _)
    else isFalse fun heq => hab (heq ▸ le_refl _)

end PartialOrder
