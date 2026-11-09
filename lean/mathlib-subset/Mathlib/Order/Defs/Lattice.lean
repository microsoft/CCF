/-
Copyright (c) 2017 Johannes Hölzl. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Johannes Hölzl
-/
module

public import Mathlib.Order.Defs.PartialOrder
public import Mathlib.Order.Defs.Unbundled
public import Mathlib.Order.Notation

@[expose] public section
universe u v
variable {α : Type u} {β : Type v}
/-- A `SemilatticeSup` is a join-semilattice, that is, a partial order
  with a join (a.k.a. lub / least upper bound, sup / supremum) operation
  `⊔` which is the least element larger than both factors. -/
class SemilatticeSup (α : Type u) extends PartialOrder α where
  /-- The binary supremum, used to derive `Max α` -/
  sup : α → α → α
  /-- The supremum is an upper bound on the first argument -/
  protected le_sup_left : ∀ a b : α, a ≤ sup a b
  /-- The supremum is an upper bound on the second argument -/
  protected le_sup_right : ∀ a b : α, b ≤ sup a b
  /-- The supremum is the *least* upper bound -/
  protected sup_le : ∀ a b c : α, a ≤ c → b ≤ c → sup a b ≤ c
/-- A `SemilatticeInf` is a meet-semilattice, that is, a partial order
  with a meet (a.k.a. glb / greatest lower bound, inf / infimum) operation
  `⊓` which is the greatest element smaller than both factors. -/
class SemilatticeInf (α : Type u) extends PartialOrder α where
  /-- The binary infimum, used to derive `Min α` -/
  inf : α → α → α
  /-- The infimum is a lower bound on the first argument -/
  protected inf_le_left : ∀ a b : α, inf a b ≤ a
  /-- The infimum is a lower bound on the second argument -/
  protected inf_le_right : ∀ a b : α, inf a b ≤ b
  /-- The infimum is the *greatest* lower bound -/
  protected le_inf : ∀ a b c : α, a ≤ b → a ≤ c → a ≤ inf b c
instance SemilatticeSup.toMax [SemilatticeSup α] : Max α where max a b := SemilatticeSup.sup a b

instance SemilatticeInf.toMin [SemilatticeInf α] : Min α where min a b := SemilatticeInf.inf a b

section SemilatticeInf

variable [SemilatticeInf α] {a b c d : α}

theorem inf_comm (a b : α) : a ⊓ b = b ⊓ a :=
  le_antisymm (SemilatticeInf.le_inf _ _ _ (SemilatticeInf.inf_le_right _ _) (SemilatticeInf.inf_le_left _ _))
    (SemilatticeInf.le_inf _ _ _ (SemilatticeInf.inf_le_right _ _) (SemilatticeInf.inf_le_left _ _))

instance instCommutativeMin_mathlib : Std.Commutative (α := α) (· ⊓ ·) := ⟨inf_comm⟩

theorem inf_assoc (a b c : α) : a ⊓ b ⊓ c = a ⊓ (b ⊓ c) := by
  have h₁ : a ⊓ b ⊓ c ≤ a := le_trans (SemilatticeInf.inf_le_left _ _) (SemilatticeInf.inf_le_left _ _)
  have h₂ : a ⊓ b ⊓ c ≤ b := le_trans (SemilatticeInf.inf_le_left _ _) (SemilatticeInf.inf_le_right _ _)
  have h₃ : a ⊓ (b ⊓ c) ≤ b := le_trans (SemilatticeInf.inf_le_right _ _) (SemilatticeInf.inf_le_left _ _)
  have h₄ : a ⊓ (b ⊓ c) ≤ c := le_trans (SemilatticeInf.inf_le_right _ _) (SemilatticeInf.inf_le_right _ _)
  exact le_antisymm
    (SemilatticeInf.le_inf _ _ _ h₁ (SemilatticeInf.le_inf _ _ _ h₂ (SemilatticeInf.inf_le_right _ _)))
    (SemilatticeInf.le_inf _ _ _ (SemilatticeInf.le_inf _ _ _ (SemilatticeInf.inf_le_left _ _) h₃) h₄)

instance instAssociativeMin_mathlib : Std.Associative (α := α) (· ⊓ ·) := ⟨inf_assoc⟩

end SemilatticeInf

/-- A lattice is a join-semilattice which is also a meet-semilattice. -/
class Lattice (α : Type u) extends SemilatticeSup α, SemilatticeInf α
/-- A distributive lattice is a lattice that satisfies any of four
equivalent distributive properties (of `sup` over `inf` or `inf` over `sup`,
on the left or right).

The definition here chooses `le_sup_inf`: `(x ⊔ y) ⊓ (x ⊔ z) ≤ x ⊔ (y ⊓ z)`. To prove distributivity
from the dual law, use `DistribLattice.ofInfSupLe`.

A classic example of a distributive lattice
is the lattice of subsets of a set, and in fact this example is
generic in the sense that every distributive lattice is realizable
as a sublattice of a powerset lattice. -/
class DistribLattice (α) extends Lattice α where
  /-- The infimum distributes over the supremum -/
  protected le_sup_inf : ∀ x y z : α, (x ⊔ y) ⊓ (x ⊔ z) ≤ x ⊔ y ⊓ z
