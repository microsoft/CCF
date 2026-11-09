/-
Copyright (c) 2017 Johannes Hölzl. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Johannes Hölzl
-/
module

public import Mathlib.Order.BoundedOrder.Basic
public import Mathlib.Order.Lattice

public section
/-- Propositions form a distributive lattice. -/
instance Prop.instDistribLattice : DistribLattice Prop where
  sup := Or
  le_sup_left := @Or.inl
  le_sup_right := @Or.inr
  sup_le := fun _ _ _ => Or.rec
  inf := And
  inf_le_left := @And.left
  inf_le_right := @And.right
  le_inf := fun _ _ _ Hab Hac Ha => And.intro (Hab Ha) (Hac Ha)
  le_sup_inf := fun _ _ _ => or_and_left.2
