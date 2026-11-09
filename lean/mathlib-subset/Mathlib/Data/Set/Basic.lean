/-
Copyright (c) 2014 Jeremy Avigad. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Jeremy Avigad, Leonardo de Moura
-/
module

public import Mathlib.Order.PropInstances

@[expose] public section
open Function
universe u v
namespace Set
variable {α : Type u} {s t : Set α}
instance instDistribLattice : DistribLattice (Set α) where
  __ : DistribLattice (α → Prop) := inferInstance
  le := (· ≤ ·)
  lt := fun s t => s ⊆ t ∧ ¬t ⊆ s
  sup := (· ∪ ·)
  inf := (· ∩ ·)
end Set
open Set
variable {α : Type*} {s : Set α}
