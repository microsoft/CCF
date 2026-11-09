/-
Copyright (c) 2014 Jeremy Avigad. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Jeremy Avigad, Leonardo de Moura
-/
module

public import Mathlib.Order.Lattice

public section
universe u v
variable {α : Type u} {β : Type v}
section
variable [LinearOrder α] {a b c d : α}
theorem max_choice (a b : α) : max a b = a ∨ max a b = b := by
  rw [LinearOrder.max_def]
  split
  · exact .inr rfl
  · exact .inl rfl
end
