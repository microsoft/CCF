/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura, Jeremy Avigad, Minchao Wu, Mario Carneiro
-/
module

public import Mathlib.Data.Finset.Empty
public import Mathlib.Data.Multiset.Filter

@[expose] public section
open Multiset Subtype Function
universe u
variable {α : Type*} {β : Type*}
namespace Finset
section Filter
variable (p : α → Prop) [DecidablePred p] {s t : Finset α}
/-- `Finset.filter p s` is the set of elements of `s` that satisfy `p`.

For example, one can use `s.filter (· ∈ t)` to get the intersection of `s` with `t : Set α`
as a `Finset α` (when a `DecidablePred (· ∈ t)` instance is available). -/
def filter (s : Finset α) : Finset α :=
  ⟨_, s.2.filter p⟩
variable {p}
@[simp]
theorem mem_filter {s : Finset α} {a : α} : a ∈ s.filter p ↔ a ∈ s ∧ p a := by
  obtain ⟨⟨l⟩, _⟩ := s
  show a ∈ l.filter (fun x => decide (p x)) ↔ a ∈ l ∧ p a
  simp
end Finset.Filter

