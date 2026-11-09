/-
Copyright (c) 2016 Jeremy Avigad. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Jeremy Avigad, Wrenna Robson
-/
module

public import Mathlib.Data.Nat.Notation
public import Mathlib.Data.List.Defs
public import Mathlib.Data.Set.Basic

public section
namespace List
section sort
variable {α β : Type*} (r : α → α → Prop) (s : β → β → Prop)
variable [DecidableRel r] [DecidableRel s]

local infixl:50 " ≼ " => r
local infixl:50 " ≼ " => s
section InsertionSort
/-- `orderedInsert a l` inserts `a` into `l` at such that
  `orderedInsert a l` is sorted if `l` is. -/
def orderedInsert (a : α) : List α → List α
  | [] => [a]
  | b :: l => if a ≼ b then a :: b :: l else b :: orderedInsert a l
/-- `insertionSort l` returns `l` sorted using the insertion sort algorithm. -/
def insertionSort : List α → List α := foldr (orderedInsert r) []
section Correctness
theorem perm_orderedInsert (a) : ∀ l : List α, orderedInsert r a l ~ a :: l
  | [] => Perm.refl _
  | b :: l => by
    by_cases h : a ≼ b
    · simp [orderedInsert, h]
    · simpa [orderedInsert, h] using ((perm_orderedInsert a l).cons b).trans (Perm.swap a b l)
theorem perm_insertionSort (l : List α) : insertionSort r l ~ l := by
  induction l with
  | nil => exact Perm.refl _
  | cons b l ih => exact (perm_orderedInsert r b _).trans (ih.cons b)
variable {r}
section TotalAndTransitive
variable [Std.Total r] [IsTrans α r]
theorem Pairwise.orderedInsert (a : α) : ∀ l, Pairwise r l → Pairwise r (orderedInsert r a l)
  | [], _ => pairwise_singleton _ a
  | b :: l, h => by
    unfold List.orderedInsert
    split
    · next h' =>
      refine pairwise_cons.2 ⟨fun c hc => ?_, h⟩
      rcases mem_cons.1 hc with hc | hc
      · exact hc ▸ h'
      · exact IsTrans.trans _ _ _ h' (rel_of_pairwise_cons h hc)
    · next h' =>
      refine pairwise_cons.2 ⟨fun c hc => ?_, Pairwise.orderedInsert a l h.of_cons⟩
      rcases mem_cons.1 ((perm_orderedInsert r a l).mem_iff.1 hc) with hc | hc
      · exact hc ▸ (Std.Total.total (r := r) b a).resolve_right h'
      · exact rel_of_pairwise_cons h hc
variable (r)
/-- The list `List.insertionSort r l` is `List.Pairwise` with respect to `r`. -/
theorem pairwise_insertionSort : ∀ l, Pairwise r (insertionSort r l)
  | [] => Pairwise.nil
  | a :: l => (pairwise_insertionSort l).orderedInsert a _
end TotalAndTransitive
end Correctness
end InsertionSort
section MergeSort
section Correctness
section Antisymm
variable {r : α → α → Prop} [Std.Antisymm r]
/-- Variant of `Perm.eq_of_pairwise` using relation typeclasses. -/
theorem Perm.eq_of_pairwise' {l₁ l₂ : List α} :
    Pairwise r l₁ → Pairwise r l₂ → (hl : l₁ ~ l₂) → l₁ = l₂ :=
  Perm.eq_of_pairwise fun a b _ _ => Std.Antisymm.antisymm a b
end Antisymm
section TotalAndTransitive
variable {r} [Std.Total r] [IsTrans α r]
variable (r)
/-- Variant of `pairwise_mergeSort` using relation typeclasses. -/
theorem pairwise_mergeSort' (l : List α) : Pairwise r (mergeSort l (r · ·)) :=
  (pairwise_mergeSort (le := (r · ·))
    (fun a b c h₁ h₂ => decide_eq_true (IsTrans.trans a b c (of_decide_eq_true h₁)
      (of_decide_eq_true h₂)))
    (fun a b => (Std.Total.total (r := r) a b).elim
      (fun h => by simp [decide_eq_true h]) (fun h => by simp [decide_eq_true h]))
    l).imp of_decide_eq_true
variable [Std.Antisymm r]
theorem mergeSort_eq_insertionSort (l : List α) :
    mergeSort l (r · ·) = insertionSort r l :=
  ((mergeSort_perm l _).trans (perm_insertionSort r l).symm).eq_of_pairwise'
    (pairwise_mergeSort' r l) (pairwise_insertionSort r l)
end TotalAndTransitive
end Correctness
end MergeSort
end sort
end List
