/-
Copyright (c) 2017 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.List.Dedup
public import Mathlib.Data.Multiset.Filter

@[expose] public section
namespace Multiset
open List
variable {α β : Type*} [DecidableEq α]
/-- `dedup s` removes duplicates from `s`, yielding a `nodup` multiset. -/
def dedup (s : Multiset α) : Multiset α :=
  Quot.liftOn s (fun l => (l.dedup : Multiset α)) fun _ _ p => Quot.sound p.dedup
@[simp]
theorem nodup_dedup (s : Multiset α) : Nodup (dedup s) :=
  Quot.ind (β := fun s => Nodup (dedup s)) List.nodup_dedup s
end Multiset
