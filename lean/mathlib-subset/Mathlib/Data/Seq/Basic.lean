/-
Copyright (c) 2017 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.Seq.Defs

@[expose] public section

universe u v w

namespace Stream'

namespace Seq

variable {α : Type u} {β : Type v} {γ : Type w}

section Map

@[simp]
theorem map_get? (f : α → β) : ∀ s n, get? (map f s) n = (get? s n).map f
  | ⟨_, _⟩, _ => rfl

end Map

end Seq

end Stream'
