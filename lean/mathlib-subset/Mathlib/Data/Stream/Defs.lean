/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura
-/
module

public import Mathlib.Init
public import Mathlib.Data.Nat.Notation
@[expose] public section
universe u v w
variable {α : Type u} {β : Type v} {δ : Type w}
/-- A stream `Stream' α` is an infinite sequence of elements of `α`. -/
def Stream' (α : Type u) := ℕ → α
namespace Stream'
/-- Prepend an element to a stream. -/
def cons (a : α) (s : Stream' α) : Stream' α
  | 0 => a
  | n + 1 => s n

@[inherit_doc] scoped infixr:67 " :: " => cons
/-- Get the `n`-th element of a stream. -/
def get (s : Stream' α) (n : ℕ) : α := s n
/-- Proposition saying that at least one element of a stream satisfies a predicate. -/
def Any (p : α → Prop) (s : Stream' α) := ∃ n, p (get s n)
/-- `a ∈ s` means that `a = Stream'.get n s` for some `n`. -/
instance : Membership α (Stream' α) :=
  ⟨fun s a => Any (fun b => a = b) s⟩
/-- Apply a function `f` to all elements of a stream `s`. -/
def map (f : α → β) (s : Stream' α) : Stream' β := fun n => f (get s n)
/-- The constant stream: `Stream'.get n (Stream'.const a) = a`. -/
def const (a : α) : Stream' α := fun _ => a
end Stream'
