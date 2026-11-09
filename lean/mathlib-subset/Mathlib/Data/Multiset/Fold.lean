/-
Copyright (c) 2017 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.Multiset.Dedup

@[expose] public section
namespace Multiset
variable {α β : Type*}
section Fold
variable (op : α → α → α) [hc : Std.Commutative op] [ha : Std.Associative op]
/-- `fold op b s` folds a commutative associative operation `op` over
  the multiset `s`. -/
def fold : α → Multiset α → α :=
  foldr op
end Fold
end Multiset
