/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro, Rudy Peterson
-/
module

public import Mathlib.Data.Multiset.MapFold

@[expose] public section
universe v
open List Subtype Nat Function
variable {α : Type*} {β : Type v} {γ : Type*}
namespace Multiset
section
variable (p : α → Prop) [DecidablePred p]
/-- `Filter p s` returns the elements in `s` (with the same multiplicities)
  which satisfy `p`, and removes the rest. -/
def filter (s : Multiset α) : Multiset α :=
  Quot.liftOn s (fun l => (List.filter p l : Multiset α)) fun _l₁ _l₂ h => Quot.sound <| h.filter p
end
theorem Nodup.filter (p : α → Prop) [DecidablePred p] {s} : Nodup s → Nodup (filter p s) :=
  Quot.inductionOn s fun _ => List.Pairwise.filter _
end Multiset
