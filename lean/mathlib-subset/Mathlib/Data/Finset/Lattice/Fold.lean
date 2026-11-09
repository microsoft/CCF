/-
Copyright (c) 2018 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.Finset.Card
public import Mathlib.Data.Finset.Fold
public import Mathlib.Order.WithBot

@[expose] public section
open Function Multiset
variable {F α β γ ι : Type*}
namespace Finset
section Inf
variable [SemilatticeInf α] [OrderTop α]
/-- Infimum of a finite set: `inf {a, b, c} f = f a ⊓ f b ⊓ f c` -/
def inf (s : Finset β) (f : β → α) : α :=
  s.fold (· ⊓ ·) ⊤ f
end Inf
end Finset
