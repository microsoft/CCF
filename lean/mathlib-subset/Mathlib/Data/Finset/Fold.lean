/-
Copyright (c) 2017 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.Finset.Erase
public import Mathlib.Data.Finset.Filter
public import Mathlib.Data.Finset.SDiff
public import Mathlib.Data.Multiset.Fold

@[expose] public section
namespace Finset
open Multiset
variable {α β γ : Type*}
section Fold
variable (op : β → β → β) [hc : Std.Commutative op] [ha : Std.Associative op]
/-- `fold op b f s` folds the commutative associative operation `op` over the
  `f`-image of `s`, i.e. `fold (+) b f {1,2,3} = f 1 + f 2 + f 3 + b`. -/
def fold (b : β) (f : α → β) (s : Finset α) : β :=
  (s.1.map f).fold op b
variable {op} {f : α → β} {b : β} {s : Finset α} {a : α}
end Fold
end Finset
