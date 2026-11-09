/-
Copyright (c) 2018 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro, Simon Hudon, Yury Kudryashov
-/
module

public import Mathlib.Order.Notation

@[expose] public section
variable {α : Type*}

/-- Attach `⊤` to a type. -/
def WithTop (α : Type*) := Option α

instance WithTop.instRepr [Repr α] : Repr (WithTop α) :=
  ⟨fun o _ =>
    match o with
    | none => "⊤"
    | some a => "↑" ++ repr a⟩

namespace WithTop

/-- The canonical map from `α` into `WithTop α` -/
@[coe, match_pattern]
def some : α → WithTop α :=
  Option.some

instance coe : Coe α (WithTop α) :=
  ⟨some⟩

instance top : Top (WithTop α) :=
  ⟨none⟩

/-- Recursor for `WithTop` using the preferred forms `⊤` and `↑a`. -/
@[elab_as_elim, induction_eliminator, cases_eliminator]
def recTopCoe {C : WithTop α → Sort*} (top : C ⊤) (coe : ∀ a : α, C a) : ∀ n : WithTop α, C n
  | ⊤ => top
  | (a : α) => coe a

end WithTop
