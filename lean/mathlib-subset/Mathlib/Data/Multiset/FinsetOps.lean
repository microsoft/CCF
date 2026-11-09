/-
Copyright (c) 2017 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.Multiset.Dedup

@[expose] public section
namespace Multiset
open List
variable {α : Type*} [DecidableEq α] {s : Multiset α}
/-- `ndinsert a s` is the lift of the list `insert` operation. This operation
  does not respect multiplicities, unlike `cons`, but it is suitable as
  an insert operation on `Finset`. -/
def ndinsert (a : α) (s : Multiset α) : Multiset α :=
  Quot.liftOn s (fun l => (l.insert a : Multiset α)) fun _ _ p => Quot.sound (p.insert a)
/-- `ndunion s t` is the lift of the list `union` operation. This operation
  does not respect multiplicities, unlike `s ∪ t`, but it is suitable as
  a union operation on `Finset`. (`s ∪ t` would also work as a union operation
  on finset, but this is more efficient.) -/
def ndunion (s t : Multiset α) : Multiset α :=
  (Quotient.liftOn₂ s t fun l₁ l₂ => (l₁.union l₂ : Multiset α)) fun _ _ _ _ p₁ p₂ =>
    Quot.sound <| p₁.union p₂
/-- `ndinter s t` is the lift of the list `∩` operation. This operation
  does not respect multiplicities, unlike `s ∩ t`, but it is suitable as
  an intersection operation on `Finset`. (`s ∩ t` would also work as an intersection operation
  on finset, but this is more efficient.) -/
def ndinter (s t : Multiset α) : Multiset α :=
  filter (· ∈ t) s
theorem Nodup.ndinsert (a : α) : Nodup s → Nodup (ndinsert a s) :=
  Quot.inductionOn s fun l h => by
    show List.Nodup (l.insert a)
    unfold List.insert
    split
    · exact h
    · next hn => exact List.nodup_cons.2 ⟨by simpa using hn, h⟩
theorem Nodup.ndunion (s : Multiset α) {t : Multiset α} : Nodup t → Nodup (ndunion s t) :=
  Quotient.inductionOn₂ s t fun l₁ l₂ h => by
    show List.Nodup (List.foldr List.insert l₂ l₁)
    induction l₁ with
    | nil => exact h
    | cons x l ih => exact Nodup.ndinsert (s := ((List.foldr List.insert l₂ l : List α) : Multiset α)) x ih
theorem Nodup.ndinter {s : Multiset α} (t : Multiset α) : Nodup s → Nodup (ndinter s t) :=
  Nodup.filter _
end Multiset
