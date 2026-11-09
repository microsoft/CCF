/-
Copyright (c) 2014 Parikshit Khanna. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Parikshit Khanna, Jeremy Avigad, Leonardo de Moura, Floris van Doorn, Mario Carneiro
-/
module

public import Batteries.Data.List.Basic
public import Mathlib.Data.Set.Defs

@[expose] public section
namespace List
open Nat
universe u v w x
variable {α β γ δ ε ζ : Type*}
/-- `dedup l` removes duplicates from `l` (taking only the last occurrence).
Defined as `pwFilter (≠)`.

See also `eraseDups` which keeps the first occurrence instead:
```
dedup [2, 0, 1, 0, 2, 0] = [1, 2, 0]
eraseDups [2, 0, 1, 0, 2, 0] = [2, 0, 1]
``` -/
def dedup [DecidableEq α] : List α → List α :=
  pwFilter (· ≠ ·)
end List
