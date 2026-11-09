/-
Copyright (c) 2017 Mario Carneiro. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.Nat.Notation
public import Batteries.Data.List.Basic
public import Mathlib.Data.Nat.Basic
public import Mathlib.Data.Stream.Defs
public import Mathlib.Logic.Function.Basic
public import Mathlib.Order.TypeTags

@[expose] public section
namespace Stream'
universe u v w
/-- A stream `s : Option α` is a sequence if `s.get n = none` implies `s.get (n + 1) = none`.
-/
def IsSeq {α : Type u} (s : Stream' (Option α)) : Prop :=
  ∀ {n : ℕ}, s n = none → s (n + 1) = none
/-- `Seq α` is the type of possibly infinite lists (referred here as sequences).
  It is encoded as an infinite stream of options such that if `f n = none`, then
  `f m = none` for all `m ≥ n`. -/
def Seq (α : Type u) : Type u :=
  { f : Stream' (Option α) // f.IsSeq }
namespace Seq
variable {α : Type u} {β : Type v} {γ : Type w}
/-- Get the nth element of a sequence (if it exists) -/
def get? : Seq α → ℕ → Option α :=
  Subtype.val
theorem le_stable (s : Seq α) {m n} (h : m ≤ n) : s.get? m = none → s.get? n = none := by
  obtain ⟨f, al⟩ := s
  induction h with | refl => exact id | step _ IH => exact fun h2 ↦ al (IH h2)
/-- The empty sequence -/
def nil : Seq α :=
  ⟨Stream'.const none, fun {_} _ => rfl⟩
@[simp]
theorem get?_nil (n : ℕ) : (@nil α).get? n = none :=
  rfl
/-- Prepend an element to a sequence -/
def cons (a : α) (s : Seq α) : Seq α :=
  ⟨some a::s.1, by
    intro n h
    cases n with
    | zero => contradiction
    | succ n => exact s.2 h⟩
@[simp]
theorem get?_cons_zero (a : α) (s : Seq α) : (cons a s).get? 0 = some a :=
  rfl
@[simp]
theorem get?_cons_succ (a : α) (s : Seq α) (n : ℕ) : (cons a s).get? (n + 1) = s.get? n :=
  rfl
/-- member definition for `Seq` -/
protected def Mem (s : Seq α) (a : α) :=
  some a ∈ s.1
instance : Membership α (Seq α) :=
  ⟨Seq.Mem⟩
theorem get?_mem {s : Seq α} {n : ℕ} {x : α} (h : s.get? n = .some x) : x ∈ s := ⟨n, h.symm⟩
theorem mem_iff_exists_get? {s : Seq α} {x : α} : x ∈ s ↔ ∃ i, some x = s.get? i :=
  ⟨fun ⟨i, h⟩ => ⟨i, h⟩, fun ⟨i, h⟩ => ⟨i, h⟩⟩
/-- Embed a list as a sequence -/
@[coe]
def ofList (l : List α) : Seq α :=
  ⟨(l[·]?), fun {n} h => by
    rw [List.getElem?_eq_none_iff] at h ⊢
    exact Nat.le_succ_of_le h⟩
@[simp]
theorem ofList_get? (l : List α) (n : ℕ) : (ofList l).get? n = l[n]? :=
  rfl
/-- Embed an infinite stream as a sequence -/
@[coe]
def ofStream (s : Stream' α) : Seq α :=
  ⟨s.map some, fun {n} h => by contradiction⟩
/-- Map a function over a sequence. -/
def map (f : α → β) : Seq α → Seq β
  | ⟨s, al⟩ =>
    ⟨s.map (Option.map f), fun {n} => by
      dsimp [Stream'.map, Stream'.get]
      cases e : s n with
      | none => intro; rw [al e]; rfl
      | some _ => intro h; contradiction⟩
end Seq
end Stream'
