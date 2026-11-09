/-
Copyright (c) 2017 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.Finset.Max
public import Mathlib.Data.Multiset.Sort

@[expose] public section
namespace Finset
open Multiset Nat
variable {α β : Type*}
section sort
/-- `sort s` constructs a sorted list from the unordered set `s`.
  (Uses merge sort algorithm.) -/
def sort (s : Finset α) (r : α → α → Prop := by exact fun a b => a ≤ b)
    [DecidableRel r] [IsTrans α r] [Std.Antisymm r] [Std.Total r] : List α :=
  Multiset.sort s.1 r
section
variable {m : Multiset α} {s : Finset α}
variable (r : α → α → Prop) [DecidableRel r] [IsTrans α r] [Std.Antisymm r] [Std.Total r]
@[simp]
theorem mem_sort {a : α} : a ∈ sort s r ↔ a ∈ s := by
  obtain ⟨⟨l⟩, _⟩ := s
  exact List.mem_mergeSort
end
end sort
end Finset
