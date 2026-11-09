/-
Copyright (c) 2014 Floris van Doorn (c) 2016 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Floris van Doorn, Leonardo de Moura, Jeremy Avigad, Mario Carneiro
-/
module

public import Mathlib.Data.Nat.Notation
public import Mathlib.Order.Defs.LinearOrder
public import Mathlib.Order.Defs.Unbundled

public section
open Function
namespace Nat
variable {a b c m n k : ℕ}
instance instLinearOrder : LinearOrder ℕ where
  le := Nat.le
  le_refl := @Nat.le_refl
  le_trans := @Nat.le_trans
  le_antisymm := @Nat.le_antisymm
  le_total := @Nat.le_total
  lt := Nat.lt
  lt_iff_le_not_ge := @Nat.lt_iff_le_and_not_ge
  toDecidableLT := inferInstance
  toDecidableLE := inferInstance
  toDecidableEq := inferInstance
instance : Preorder ℕ := inferInstance
end Nat
