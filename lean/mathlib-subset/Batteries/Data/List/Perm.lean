/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura, Jeremy Avigad, Mario Carneiro
-/
module

public import Batteries.Data.List.Basic

public section

open Nat

namespace List

theorem Perm.diff_right [BEq α] [LawfulBEq α] (t : List α) (h : l₁ ~ l₂) :
    l₁.diff t ~ l₂.diff t := by
  induction t generalizing l₁ l₂ h with simp only [List.diff]
  | nil => exact h
  | cons x t ih =>
    simp only [elem_eq_mem, decide_eq_true_eq, Perm.mem_iff h]
    split
    · exact ih (h.erase _)
    · exact ih h

theorem Perm.diff_left [BEq α] [LawfulBEq α] (l : List α) (h : t₁ ~ t₂) :
    l.diff t₁ = l.diff t₂ := by
  induction h generalizing l with try simp [List.diff]
  | cons x _ ih => apply ite_congr rfl <;> (intro; apply ih)
  | swap x y =>
    if h : x = y then
      simp [h]
    else
      simp [mem_erase_of_ne h, mem_erase_of_ne (Ne.symm h), erase_comm x y]
      split <;> simp
  | trans => simp only [*]

theorem Perm.diff [BEq α] [LawfulBEq α] {l₁ l₂ t₁ t₂ : List α} (hl : l₁ ~ l₂) (ht : t₁ ~ t₂) :
    l₁.diff t₁ ~ l₂.diff t₂ :=
  ht.diff_left l₂ ▸ hl.diff_right _

theorem Perm.union_right [BEq α] [LawfulBEq α] (t₁ : List α) (h : l₁ ~ l₂) :
    l₁ ∪ t₁ ~ l₂ ∪ t₁ := by
  induction h with
  | nil => exact .refl _
  | cons a _ ih => exact ih.insert a
  | swap => apply perm_insert_swap
  | trans _ _ ih_1 ih_2 => exact ih_1.trans ih_2

theorem Perm.union_left [BEq α] [LawfulBEq α] (l : List α) (h : t₁ ~ t₂) : l ∪ t₁ ~ l ∪ t₂ := by
  induction l with
  | nil => exact h
  | cons _ _ ih => exact Perm.insert _ ih

theorem Perm.union [BEq α] [LawfulBEq α] {l₁ l₂ t₁ t₂ : List α} (p₁ : l₁ ~ l₂) (p₂ : t₁ ~ t₂) :
    l₁ ∪ t₁ ~ l₂ ∪ t₂ :=
  (p₁.union_right t₁).trans (p₂.union_left l₂)

end List
