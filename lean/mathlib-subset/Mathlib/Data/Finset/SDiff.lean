/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura, Jeremy Avigad, Minchao Wu, Mario Carneiro
-/
module

public import Mathlib.Data.Finset.Insert
public import Mathlib.Data.Finset.Lattice.Basic

public section
open Multiset
universe u
variable {α : Type*}
namespace Finset
section Sdiff
variable [DecidableEq α] {s t u v : Finset α} {a b : α}
/-- `s \ t` is the set consisting of the elements of `s` that are not in `t`. -/
instance instSDiff : SDiff (Finset α) :=
  ⟨fun s₁ s₂ => ⟨s₁.1 - s₂.1, by
    rcases s₁ with ⟨v₁, h₁⟩
    generalize s₂.1 = v₂
    induction v₁ using Quot.ind with | _ l₁ =>
    induction v₂ using Quot.ind with | _ l₂ =>
    show List.Nodup (l₁.diff l₂)
    induction l₂ generalizing l₁ with
    | nil => exact h₁
    | cons a l ih =>
      show List.Nodup (if l₁.elem a then (l₁.erase a).diff l else l₁.diff l)
      split
      · exact ih _ (List.Nodup.erase a h₁)
      · exact ih _ h₁⟩⟩
end Sdiff
end Finset
