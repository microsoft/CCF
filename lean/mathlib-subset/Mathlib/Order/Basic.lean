/-
Copyright (c) 2014 Jeremy Avigad. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Jeremy Avigad, Mario Carneiro
-/
module

public import Mathlib.Logic.Function.Basic
public import Mathlib.Order.Defs.LinearOrder
public import Mathlib.Order.Defs.Prop
public import Mathlib.Order.Notation
public import Mathlib.Tactic.Spread

@[expose] public section

open Function

section Preorder

variable {α : Type*} [Preorder α] {a b c : α}

theorem LE.le.trans : a ≤ b → b ≤ c → a ≤ c := le_trans

theorem LT.lt.le : a < b → a ≤ b := fun h => (lt_iff_le_not_ge.1 h).1

theorem LE.le.trans_lt : a ≤ b → b < c → a < c := fun hab hbc =>
  lt_of_le_not_ge (le_trans hab (lt_iff_le_not_ge.1 hbc).1)
    fun hca => (lt_iff_le_not_ge.1 hbc).2 (le_trans hca hab)

theorem LT.lt.trans_le : a < b → b ≤ c → a < c := fun hab hbc =>
  lt_of_le_not_ge (le_trans (Preorder.lt_iff_le_not_ge _ _ |>.1 hab).1 hbc)
    fun hca => (Preorder.lt_iff_le_not_ge _ _ |>.1 hab).2 (le_trans hbc hca)

theorem LT.lt.trans : a < b → b < c → a < c := fun hab hbc => hab.trans_le hbc.le

theorem LT.lt.ne : a < b → a ≠ b := fun h e => (lt_iff_le_not_ge.1 h).2 (by subst e; exact le_refl a)

theorem LT.lt.ne' : b < a → a ≠ b := fun h e => (lt_iff_le_not_ge.1 h).2 (by subst e; exact le_refl a)

theorem Eq.le : a = b → a ≤ b := fun e => by subst e; exact le_refl a

theorem Eq.ge : a = b → b ≤ a := fun e => by subst e; exact le_refl a

end Preorder

variable {ι α β : Type*} {π : ι → Type*}

instance Pi.preorder [∀ i, Preorder (π i)] : Preorder (∀ i, π i) where
  __ := (inferInstance : LE (∀ i, π i))
  le_refl := fun a i ↦ le_refl (a i)
  le_trans := fun _ _ _ h₁ h₂ i ↦ le_trans (h₁ i) (h₂ i)

instance Pi.partialOrder [∀ i, PartialOrder (π i)] : PartialOrder (∀ i, π i) where
  __ := Pi.preorder
  le_antisymm := fun _ _ h1 h2 ↦ funext fun b ↦ le_antisymm (h1 b) (h2 b)

/-- Pull back a `Preorder` instance along an injective function.

See note [reducible non-instances]. -/
abbrev Function.Injective.preorder [Preorder β] [LE α] [LT α] (f : α → β)
    (le : ∀ {x y}, f x ≤ f y ↔ x ≤ y) (lt : ∀ {x y}, f x < f y ↔ x < y) :
    Preorder α where
  le_refl _ := le.1 <| le_refl _
  le_trans _ _ _ h₁ h₂ := le.1 <| le_trans (le.2 h₁) (le.2 h₂)
  lt_iff_le_not_ge _ _ := by
    rw [← le, ← le, ← lt, lt_iff_le_not_ge]

/-- Pull back a `PartialOrder` instance along an injective function.

See note [reducible non-instances]. -/
abbrev Function.Injective.partialOrder [PartialOrder β] [LE α] [LT α] (f : α → β)
    (hf : Function.Injective f)
    (le : ∀ {x y}, f x ≤ f y ↔ x ≤ y) (lt : ∀ {x y}, f x < f y ↔ x < y) :
    PartialOrder α where
  __ := Function.Injective.preorder f le lt
  le_antisymm _ _ h₁ h₂ := hf <| le_antisymm (le.2 h₁) (le.2 h₂)


/-- Transfer a `PartialOrder` on `β` to a `PartialOrder` on `α` using an injective
function `f : α → β`.

See also `Function.Injective.partialOrder` when only the proof fields need to be transferred.

See note [reducible non-instances]. -/
abbrev PartialOrder.lift [PartialOrder β] (f : α → β) (inj : Injective f) : PartialOrder α :=
  letI _instLE : LE α := ⟨fun a b ↦ f a ≤ f b⟩
  letI _instLT : LT α := ⟨fun a b ↦ f a < f b⟩
  Function.Injective.partialOrder f inj .rfl .rfl

section «Prop»

instance Prop.partialOrder : PartialOrder Prop where
  __ := Prop.le
  le_refl _ := id
  le_trans _ _ _ f g := g ∘ f
  le_antisymm _ _ Hab Hba := propext ⟨Hab, Hba⟩

end «Prop»
