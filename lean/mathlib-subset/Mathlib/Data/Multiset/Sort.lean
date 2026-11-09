/-
Copyright (c) 2017 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.List.Sort
public import Mathlib.Data.Multiset.Filter

@[expose] public section
variable {α β : Type*}
namespace Multiset
open List
section sort
/-- `sort s` constructs a sorted list from the multiset `s`.
  (Uses merge sort algorithm.) -/
def sort (s : Multiset α) (r : α → α → Prop := by exact fun a b => a ≤ b)
    [DecidableRel r] [IsTrans α r] [Std.Antisymm r] [Std.Total r] : List α :=
  Quot.liftOn s (mergeSort · (r · ·)) fun _ _ h =>
    ((mergeSort_perm _ _).trans <| h.trans (mergeSort_perm _ _).symm).eq_of_pairwise' (r := r)
      (pairwise_mergeSort' _ _) (pairwise_mergeSort' _ _)
end sort
end Multiset
