/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura, Jeremy Avigad, Minchao Wu, Mario Carneiro
-/
module

public import Mathlib.Data.Finset.Defs
public import Mathlib.Data.Multiset.Dedup

@[expose] public section
open Multiset Function
universe u
variable {α : Type*} {β : Type*}
namespace Multiset
variable [DecidableEq α] {s t : Multiset α}
/-- `toFinset s` removes duplicates from the multiset `s` to produce a finset. -/
def toFinset (s : Multiset α) : Finset α :=
  ⟨_, nodup_dedup s⟩
end Multiset
namespace List
variable [DecidableEq α] {l l' : List α} {a : α} {s : Finset α}
/-- `toFinset l` removes duplicates from the list `l` to produce a finset. -/
def toFinset (l : List α) : Finset α :=
  Multiset.toFinset l
end List
