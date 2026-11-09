/-
Copyright (c) 2017 Johannes Hölzl. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Johannes Hölzl
-/
module

public import Mathlib.Data.Nat.Basic
public import Mathlib.Order.Defs.Lattice
public import Mathlib.Order.RelClasses

@[expose] public section
universe u v w

instance (priority := 100) LinearOrder.toLattice {α : Type u} [LinearOrder α] : Lattice α where
  sup := max
  inf := min
  le_sup_left := le_max_left; le_sup_right := le_max_right; sup_le _ _ _ := max_le
  inf_le_left := min_le_left; inf_le_right := min_le_right; le_inf _ _ _ := le_min

instance (priority := 100) instDistribLatticeOfLinearOrder {α : Type u} [LinearOrder α] :
    DistribLattice α where
  le_sup_inf x b c := by
    show min (max x b) (max x c) ≤ max x (min b c)
    rw [LinearOrder.min_def b c]
    split
    · exact min_le_left _ _
    · exact min_le_right _ _

namespace Pi

variable {ι : Type*} {α' : ι → Type*}

instance instSemilatticeSup [∀ i, SemilatticeSup (α' i)] : SemilatticeSup (∀ i, α' i) where
  sup x y i := x i ⊔ y i
  le_sup_left _ _ _ := SemilatticeSup.le_sup_left _ _
  le_sup_right _ _ _ := SemilatticeSup.le_sup_right _ _
  sup_le _ _ _ ac bc i := SemilatticeSup.sup_le _ _ _ (ac i) (bc i)

instance instSemilatticeInf [∀ i, SemilatticeInf (α' i)] : SemilatticeInf (∀ i, α' i) where
  inf x y i := x i ⊓ y i
  inf_le_left _ _ _ := SemilatticeInf.inf_le_left _ _
  inf_le_right _ _ _ := SemilatticeInf.inf_le_right _ _
  le_inf _ _ _ ac bc i := SemilatticeInf.le_inf _ _ _ (ac i) (bc i)

instance instLattice [∀ i, Lattice (α' i)] : Lattice (∀ i, α' i) where

instance instDistribLattice [∀ i, DistribLattice (α' i)] : DistribLattice (∀ i, α' i) where
  le_sup_inf _ _ _ _ := DistribLattice.le_sup_inf _ _ _

end Pi
