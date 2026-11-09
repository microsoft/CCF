/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Batteries.Data.List.Perm
public import Mathlib.Data.Multiset.ZeroCons

@[expose] public section
universe v
open List Nat
variable {α : Type*} {β : Type v}
namespace Multiset
section Erase
variable [DecidableEq α] {s t : Multiset α} {a b : α}
/-- `erase s a` is the multiset that subtracts 1 from the multiplicity of `a`. -/
def erase (s : Multiset α) (a : α) : Multiset α :=
  Quot.liftOn s (fun l => (l.erase a : Multiset α)) fun _l₁ _l₂ p => Quot.sound (p.erase a)
end Erase
section sub
variable [DecidableEq α] {s t u : Multiset α} {a : α}
/-- `s - t` is the multiset such that `count a (s - t) = count a s - count a t` for all `a`.
(note that it is truncated subtraction, so `count a (s - t) = 0` if `count a s ≤ count a t`). -/
protected def sub (s t : Multiset α) : Multiset α :=
  (Quotient.liftOn₂ s t fun l₁ l₂ => (l₁.diff l₂ : Multiset α)) fun _v₁ _v₂ _w₁ _w₂ p₁ p₂ =>
    Quot.sound <| p₁.diff p₂
instance : Sub (Multiset α) := ⟨.sub⟩
end sub
section Nodup
theorem Nodup.erase [DecidableEq α] (a : α) {l} : Nodup l → Nodup (l.erase a) :=
  Quot.inductionOn l fun _ => List.Nodup.erase a
@[simp]
theorem nodup_singleton : ∀ a : α, Nodup ({a} : Multiset α) :=
  fun _ => List.nodup_cons.2 ⟨List.not_mem_nil, List.nodup_nil⟩
end Nodup
end Multiset
