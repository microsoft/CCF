/-
Copyright (c) 2017 Johannes Hölzl. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Johannes Hölzl
-/
module

public import Mathlib.Order.BoundedOrder.Basic
public import Mathlib.Order.Lattice
public import Mathlib.Order.TypeTags

@[expose] public section
variable {α β γ δ : Type*}

namespace WithTop

/-- Specialization of `Option.getD` to values in `WithTop α` that respects API boundaries. -/
def untopD (d : α) (x : WithTop α) : α :=
  recTopCoe d id x

@[simp]
theorem untopD_coe (d x : α) : untopD d (WithTop.some x) = x :=
  rfl

@[simp]
theorem coe_inj {a b : α} : (WithTop.some a : WithTop α) = WithTop.some b ↔ a = b :=
  Option.some_inj

end WithTop

section LE

variable [LE α]

/-- The order on `WithTop`. -/
protected inductive WithTop.LE : WithTop α → WithTop α → Prop
  | protected le_top (x : WithTop α) : WithTop.LE x ⊤
  | protected coe_le_coe {a b : α} : a ≤ b → WithTop.LE a b

/-- The order on `WithTop α`, defined by `x ≤ ⊤` and `a ≤ b → ↑a ≤ ↑b`.

Equivalently, `x ≤ y` can be defined as `∀ b : α, y = ↑b → ∃ a : α, x = ↑a ∧ a ≤ b`,
see `le_iff_forall`. The definition as an inductive predicate is preferred since it
cannot be accidentally unfolded too far. -/
instance (priority := 10) WithTop.instLE : LE (WithTop α) where le := WithTop.LE

lemma WithTop.le_def {x y : WithTop α} : x ≤ y ↔ y = ⊤ ∨ ∃ a b : α, a ≤ b ∧ x = a ∧ y = b := by
  dsimp [LE.le]
  grind [WithTop.LE, LE.le_top, LE.coe_le_coe]

end LE

section LT

variable [LT α]

/-- The order on `WithTop`. -/
protected inductive WithTop.LT [LT α] : WithTop α → WithTop α → Prop
  | protected lt_top (a : α) : WithTop.LT a ⊤
  | protected coe_lt_coe {a b : α} : a < b → WithTop.LT a b

/-- The order on `WithTop α`, defined by `↑a < ⊤` and `a < b → ↑a < ↑b`.

Equivalently, `x < y` can be defined as `∃ a : α, x = ↑a ∧ ∀ b : α, y = ↑b → a < b`,
see `le_if_forall`. The definition as an inductive predicate is preferred since it
cannot be accidentally unfolded too far. -/
instance (priority := 10) WithTop.instLT : LT (WithTop α) where lt := WithTop.LT

lemma WithTop.lt_def {x y : WithTop α} :
    x < y ↔ (∃ a : α, x = a) ∧ y = ⊤ ∨ ∃ a b : α, a < b ∧ x = a ∧ y = b := by
  dsimp [LT.lt]
  grind [WithTop.LT, LT.lt_top, LT.coe_lt_coe]

end LT

namespace WithTop

instance instOrderTop [LE α] : OrderTop (WithTop α) where
  le_top x := WithTop.LE.le_top x

instance instPreorder [Preorder α] : Preorder (WithTop α) where
  lt_iff_le_not_ge x y := by
    constructor
    · intro h
      cases h with
      | lt_top a => exact ⟨.le_top _, fun h' => nomatch h'⟩
      | coe_lt_coe hab =>
        refine ⟨.coe_le_coe (lt_iff_le_not_ge.1 hab).1, fun h' => ?_⟩
        cases h' with
        | coe_le_coe hba => exact (lt_iff_le_not_ge.1 hab).2 hba
    · intro ⟨h₁, h₂⟩
      cases h₁ with
      | le_top x =>
        cases x with
        | top => exact absurd (.le_top _) h₂
        | coe a => exact .lt_top a
      | coe_le_coe hab => exact .coe_lt_coe (lt_iff_le_not_ge.2 ⟨hab, fun hba => h₂ (.coe_le_coe hba)⟩)
  le_refl x := by
    cases x with
    | top => exact .le_top _
    | coe a => exact .coe_le_coe (le_refl a)
  le_trans x y z hxy hyz := by
    cases hyz with
    | le_top => exact .le_top _
    | coe_le_coe hbc =>
      cases hxy with
      | coe_le_coe hab => exact .coe_le_coe (le_trans hab hbc)

instance instPartialOrder [PartialOrder α] : PartialOrder (WithTop α) where
  le_antisymm x y hxy hyx := by
    cases hxy with
    | le_top =>
      cases hyx with
      | le_top => rfl
    | coe_le_coe hab =>
      cases hyx with
      | coe_le_coe hba => rw [le_antisymm hab hba]

instance semilatticeInf [SemilatticeInf α] : SemilatticeInf (WithTop α) where
  inf
    -- note this is `Option.merge`, but with the right defeq when unfolding
    | ⊤, ⊤ => ⊤
    | (a : α), ⊤ => a
    | ⊤, (b : α) => b
    | (a : α), (b : α) => ↑(a ⊓ b)
  inf_le_left x y := by
    cases x <;> cases y
    · exact .le_top _
    · exact .le_top _
    · exact .coe_le_coe (le_refl _)
    · exact .coe_le_coe (SemilatticeInf.inf_le_left _ _)
  inf_le_right x y := by
    cases x <;> cases y
    · exact .le_top _
    · exact .coe_le_coe (le_refl _)
    · exact .le_top _
    · exact .coe_le_coe (SemilatticeInf.inf_le_right _ _)
  le_inf x y z hxy hxz := by
    cases hxy with
    | le_top =>
      cases z
      · exact .le_top _
      · exact hxz
    | coe_le_coe hab =>
      cases hxz with
      | le_top => exact .coe_le_coe hab
      | coe_le_coe hac => exact .coe_le_coe (SemilatticeInf.le_inf _ _ _ hab hac)

instance decidableEq [DecidableEq α] : DecidableEq (WithTop α) :=
  inferInstanceAs <| DecidableEq (Option α)

end WithTop
