/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.Multiset.Defs
public import Mathlib.Order.BoundedOrder.Basic

@[expose] public section
universe v
open List Subtype Nat
variable {α : Type*} {β : Type v} {γ : Type*}
namespace Multiset
/-- `0 : Multiset α` is the empty set -/
protected def zero : Multiset α :=
  @nil α
instance : Zero (Multiset α) :=
  ⟨Multiset.zero⟩
/-- `cons a s` is the multiset which contains `s` plus one more instance of `a`. -/
def cons (a : α) (s : Multiset α) : Multiset α :=
  Quot.liftOn s (fun l => (a :: l : Multiset α)) fun _ _ p => Quot.sound (p.cons a)

@[inherit_doc Multiset.cons]
infixr:67 " ::ₘ " => Multiset.cons
instance : Singleton α (Multiset α) :=
  ⟨fun a => a ::ₘ 0⟩
section Nodup
variable {s : Multiset α} {a : α}
@[simp]
theorem nodup_zero : @Nodup α 0 :=
  Pairwise.nil
end Nodup
end Multiset
