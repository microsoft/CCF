/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura, Jeremy Avigad, Minchao Wu, Mario Carneiro
-/
module

public import Mathlib.Data.Finset.Defs
public import Mathlib.Data.Multiset.ZeroCons

@[expose] public section
open Multiset Subtype
universe u
variable {α : Type*}
namespace Finset
/-- The property `s.Nonempty` expresses the fact that the finset `s` is not empty. It should be used
in theorem assumptions instead of `∃ x, x ∈ s` or `s ≠ ∅` as it gives access to a nice API thanks
to the dot notation. -/
protected def Nonempty (s : Finset α) : Prop := ∃ x : α, x ∈ s
instance decidableNonempty {s : Finset α} : Decidable s.Nonempty :=
  decidable_of_iff (∃ a ∈ s, true)
    ⟨fun ⟨a, h, _⟩ => ⟨a, h⟩, fun ⟨a, h⟩ => ⟨a, h, rfl⟩⟩
section Empty
variable {s : Finset α}
/-- The empty finset -/
protected def empty : Finset α :=
  ⟨0, nodup_zero⟩
instance : EmptyCollection (Finset α) :=
  ⟨Finset.empty⟩
end Empty
end Finset
