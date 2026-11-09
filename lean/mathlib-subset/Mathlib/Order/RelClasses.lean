/-
Copyright (c) 2020 Jeremy Avigad. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Jeremy Avigad, Mario Carneiro, Yury Kudryashov
-/
module

public import Mathlib.Order.Basic

@[expose] public section
universe u v

variable {α : Type u}

instance instIsTransLe [Preorder α] : IsTrans α (· ≤ ·) :=
  ⟨@le_trans _ _⟩

instance LE.total [LinearOrder α] : @Std.Total α (· ≤ ·) :=
  ⟨LinearOrder.le_total⟩
