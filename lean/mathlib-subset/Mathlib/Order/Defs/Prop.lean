/-
Copyright (c) 2016 Johannes Hölzl. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Johannes Hölzl, Yury Kudryashov
-/
module

public import Mathlib.Init
public section
instance Pi.hasLe {ι : Type*} {π : ι → Type*} [∀ i, LE (π i)] : LE (∀ i, π i) where
  le x y := ∀ i, x i ≤ y i
/-- Propositions form a complete Boolean algebra, where the `≤` relation is given by implication. -/
instance Prop.le : LE Prop :=
  ⟨(· → ·)⟩
