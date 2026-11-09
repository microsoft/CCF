/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura, Jeremy Avigad, Minchao Wu, Mario Carneiro
-/
module

public import Mathlib.Data.Finset.Defs
public import Mathlib.Data.Multiset.Filter

@[expose] public section
open Multiset
universe u
variable {α : Type*}
namespace Finset
section Erase
variable [DecidableEq α] {s t : Finset α} {a b : α}
/-- `erase s a` is the set `s - {a}`, that is, the elements of `s` which are
  not equal to `a`. -/
def erase (s : Finset α) (a : α) : Finset α :=
  ⟨_, s.2.erase a⟩
@[simp]
theorem mem_erase {a b : α} {s : Finset α} : a ∈ erase s b ↔ a ≠ b ∧ a ∈ s := by
  obtain ⟨⟨l⟩, nd⟩ := s
  exact List.Nodup.mem_erase_iff nd
end Erase
end Finset
