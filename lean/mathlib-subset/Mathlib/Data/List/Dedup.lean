/-
Copyright (c) 2018 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.List.Defs

public section

universe u

namespace List

variable {α β : Type*} [DecidableEq α]

theorem mem_dedup {a : α} {l : List α} : a ∈ dedup l ↔ a ∈ l := by
  induction l generalizing a with
  | nil => exact Iff.rfl
  | cons x l ih =>
    show a ∈ (if ∀ y ∈ dedup l, x ≠ y then x :: dedup l else dedup l) ↔ a ∈ x :: l
    split
    · rw [mem_cons, mem_cons, ih]
    · next h =>
      have hx : x ∈ l :=
        Classical.byContradiction fun hx => h fun y hy hxy => hx (hxy ▸ ih.1 hy)
      rw [ih, mem_cons]
      exact ⟨Or.inr, fun h' => h'.elim (fun e => e ▸ hx) id⟩

theorem nodup_dedup : ∀ l : List α, Nodup (dedup l)
  | [] => Pairwise.nil
  | x :: l => by
    show Pairwise (· ≠ ·) (if ∀ y ∈ dedup l, x ≠ y then x :: dedup l else dedup l)
    split
    · exact pairwise_cons.2 ⟨‹_›, nodup_dedup l⟩
    · exact nodup_dedup l

theorem Perm.dedup {l₁ l₂ : List α} (p : l₁ ~ l₂) : dedup l₁ ~ dedup l₂ :=
  (perm_ext_iff_of_nodup (nodup_dedup l₁) (nodup_dedup l₂)).2 fun _ => by
    rw [mem_dedup, mem_dedup]; exact p.mem_iff

end List
