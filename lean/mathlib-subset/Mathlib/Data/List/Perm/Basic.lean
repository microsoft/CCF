/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura, Jeremy Avigad, Mario Carneiro
-/
module

public import Batteries.Data.List.Basic
public import Mathlib.Logic.Function.Basic
public import Mathlib.Logic.OpClass
public import Mathlib.Order.Defs.Prop

public section
namespace List

variable {α β : Type*}

theorem Perm.foldr_eq {f : α → β → β} {l₁ l₂ : List α} [lcomm : LeftCommutative f] (p : l₁ ~ l₂) :
    ∀ b, foldr f b l₁ = foldr f b l₂ := by
  intro b
  induction p generalizing b with
  | nil => rfl
  | cons _ _ r => simp [r b]
  | swap x y l => exact lcomm.left_comm y x _
  | trans _ _ r₁ r₂ => exact Eq.trans (r₁ b) (r₂ b)

end List
