/-
Copyright (c) 2016 Johannes Hölzl. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Johannes Hölzl, Mario Carneiro
-/
module

public import Mathlib.Order.Defs.Unbundled

@[expose] public section
universe u v

namespace Function

section Update

variable {α : Sort u} {β : α → Sort v} [DecidableEq α]

/-- Replacing the value of a function at a given point by a given value. -/
@[grind]
def update (f : ∀ a, β a) (a' : α) (v : β a') (a : α) : β a :=
  if h : a = a' then Eq.ndrec v h.symm else f a

@[simp]
theorem update_self (a : α) (v : β a) (f : ∀ a, β a) : update f a v a = v :=
  dite_eq_left rfl

@[simp]
theorem update_of_ne {a a' : α} (h : a ≠ a') (v : β a') (f : ∀ a, β a) : update f a' v a = f a :=
  dite_eq_right h

end Update

end Function
