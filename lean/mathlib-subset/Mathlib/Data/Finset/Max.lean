/-
Copyright (c) 2018 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.Finset.Lattice.Fold

@[expose] public section
open Function Multiset
variable {α β ι : Type*}
namespace Finset
section MaxMin
variable [LinearOrder α]
/-- Let `s` be a finset in a linear order. Then `s.min` is the minimum of `s` if `s` is not empty,
and `⊤` otherwise. It belongs to `WithTop α`. If you want to get an element of `α`, see
`s.min'`. -/
protected def min (s : Finset α) : WithTop α :=
  inf s WithTop.some
private theorem foldr_inf_some (l : List α) :
    ((l.map WithTop.some).foldr (· ⊓ ·) ⊤ = ⊤ ∧ l = []) ∨
      ∃ a ∈ l, (l.map WithTop.some).foldr (· ⊓ ·) ⊤ = WithTop.some a := by
  induction l with
  | nil => exact .inl ⟨rfl, rfl⟩
  | cons b l ih =>
    refine .inr ?_
    rcases ih with ⟨h, _⟩ | ⟨y, hy, h⟩
    · exact ⟨b, List.mem_cons_self, by simp only [List.map_cons, List.foldr_cons, h]; rfl⟩
    · simp only [List.map_cons, List.foldr_cons, h]
      show ∃ a ∈ b :: l, WithTop.some (min b y) = WithTop.some a
      rw [LinearOrder.min_def]
      split
      · exact ⟨b, List.mem_cons_self, rfl⟩
      · exact ⟨y, List.mem_cons_of_mem _ hy, rfl⟩
theorem min_of_nonempty {s : Finset α} (h : s.Nonempty) : ∃ a : α, s.min = a := by
  obtain ⟨⟨l⟩, _⟩ := s
  obtain ⟨x, hx⟩ := h
  rcases foldr_inf_some l with ⟨_, rfl⟩ | ⟨a, _, h⟩
  · exact absurd hx List.not_mem_nil
  · exact ⟨a, h⟩
theorem mem_of_min {s : Finset α} : ∀ {a : α}, s.min = a → a ∈ s := by
  obtain ⟨⟨l⟩, _⟩ := s
  intro a (ha : (l.map WithTop.some).foldr (· ⊓ ·) ⊤ = WithTop.some a)
  rcases foldr_inf_some l with ⟨h, _⟩ | ⟨b, hb, h⟩
  · exact absurd (h.symm.trans ha) nofun
  · exact (Option.some.inj (h.symm.trans ha)) ▸ hb
end MaxMin
end Finset
