/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura, Jeremy Avigad
-/
module

public import Mathlib.Data.Nat.Notation
public import Mathlib.Data.Finset.Erase
public import Mathlib.Data.Finset.Filter
public import Mathlib.Data.Finset.SDiff

@[expose] public section
open Function Multiset Nat
variable {α β : Type*}
namespace Finset
variable {s t u : Finset α} {a b c : α}
/-- `s.card` is the number of elements of `s`, aka its cardinality.

The notation `#s` can be accessed in the `Finset` locale. -/
def card (s : Finset α) : ℕ :=
  Multiset.card s.1
section Lattice
variable [DecidableEq α]
theorem inter_nonempty_of_card_lt_card_add_card (hts : t ⊆ s) (hus : u ⊆ s)
    (hstu : s.card < t.card + u.card) : (t ∩ u).Nonempty := by
  refine Classical.byContradiction fun empty => Nat.lt_irrefl _ (Nat.lt_of_lt_of_le hstu ?_)
  obtain ⟨⟨ls⟩, ns⟩ := s
  obtain ⟨⟨lt⟩, nt⟩ := t
  obtain ⟨⟨lu⟩, nu⟩ := u
  have disjoint : ∀ a ∈ lt, ∀ b ∈ lu, a ≠ b := fun a ha _ hb e =>
    empty ⟨a, show a ∈ lt.filter (· ∈ lu) by simpa [e] using And.intro (e ▸ ha) hb⟩
  have h := (List.nodup_append.2 ⟨nt, nu, disjoint⟩).length_le_of_subset fun a ha =>
    (List.mem_append.1 ha).elim (fun h => hts h) (fun h => hus h)
  rw [List.length_append] at h
  exact h
end Lattice
end Finset
open scoped Finset
