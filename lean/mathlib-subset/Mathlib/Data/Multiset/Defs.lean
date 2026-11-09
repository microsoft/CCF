/-
Copyright (c) 2015 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mario Carneiro
-/
module

public import Mathlib.Data.Nat.Notation
public import Mathlib.Data.List.Defs
public import Mathlib.Data.List.Perm.Basic
public import Mathlib.Data.Nat.Basic
public import Mathlib.Order.RelClasses

@[expose] public section
universe v
open List Subtype Nat
variable {α : Type*} {β : Type v}
/-- `Multiset α` is the quotient of `List α` by list permutation. The result
  is a type of finite sets with duplicates allowed. -/
def Multiset.{u} (α : Type u) : Type u :=
  Quotient (List.isSetoid α)
namespace Multiset
/-- The quotient map from `List α` to `Multiset α`. -/
@[coe]
def ofList : List α → Multiset α :=
  Quot.mk _

instance : Coe (List α) (Multiset α) :=
  ⟨ofList⟩
instance [DecidableEq α] (l₁ l₂ : List α) : Decidable (l₁ ≈ l₂) :=
  inferInstanceAs (Decidable (l₁ ~ l₂))
instance [DecidableEq α] (l₁ l₂ : List α) : Decidable ((isSetoid α).r l₁ l₂) :=
  inferInstanceAs (Decidable (l₁ ~ l₂))
instance decidableEq [DecidableEq α] : DecidableEq (Multiset α)
  | s₁, s₂ => Quotient.recOnSubsingleton₂ s₁ s₂ fun _ _ => decidable_of_iff' _ ⟨Quotient.exact, Quotient.sound⟩
section Mem
/-- `a ∈ s` means that `a` has nonzero multiplicity in `s`. -/
def Mem (s : Multiset α) (a : α) : Prop :=
  Quot.liftOn s (fun l => a ∈ l) fun l₁ l₂ (e : l₁ ~ l₂) => propext e.mem_iff
instance : Membership α (Multiset α) :=
  ⟨Mem⟩
instance decidableMem [DecidableEq α] (a : α) (s : Multiset α) : Decidable (a ∈ s) :=
  Quot.recOnSubsingleton s fun l ↦ inferInstanceAs (Decidable (a ∈ l))
end Mem
/-- The cardinality of a multiset is the sum of the multiplicities
  of all its elements, or simply the length of the underlying list. -/
def card : Multiset α → ℕ := Quot.lift length fun _l₁ _l₂ => Perm.length_eq
/-- Lift of the list `pmap` operation. Map a partial function `f` over a multiset
  `s` whose elements are all in the domain of `f`. -/
nonrec def pmap {p : α → Prop} (f : ∀ a, p a → β) (s : Multiset α) : (∀ a ∈ s, p a) → Multiset β :=
  Quot.recOn s (fun l H => ↑(pmap f l H)) fun l₁ l₂ (pp : l₁ ~ l₂) =>
    funext fun H₂ : ∀ a ∈ l₂, p a =>
      have H₁ : ∀ a ∈ l₁, p a := fun a h => H₂ a (pp.subset h)
      have : ∀ {s₂ e H}, @Eq.ndrec (Multiset α) l₁ (fun s => (∀ a ∈ s, p a) → Multiset β)
          (fun _ => ↑(pmap f l₁ H₁)) s₂ e H = ↑(pmap f l₁ H₁) := by
        intro s₂ e _; subst e; rfl
      this.trans <| Quot.sound <| pp.pmap f
/-- "Attach" a proof that `a ∈ s` to each element `a` in `s` to produce
  a multiset on `{x // x ∈ s}`. -/
def attach (s : Multiset α) : Multiset { x // x ∈ s } :=
  pmap Subtype.mk s fun _a => id

theorem mem_attach (s : Multiset α) : ∀ x, x ∈ s.attach :=
  Quot.inductionOn s fun _l => List.mem_attach _
section Decidable
variable {m : Multiset α}
/-- If `p` is a decidable predicate,
so is the predicate that all elements of a multiset satisfy `p`. -/
protected def decidableForallMultiset {p : α → Prop} [∀ a, Decidable (p a)] :
    Decidable (∀ a ∈ m, p a) :=
  Quotient.recOnSubsingleton m fun l => decidable_of_iff (∀ a ∈ l, p a) Iff.rfl
instance decidableDforallMultiset {p : ∀ a ∈ m, Prop} [_hp : ∀ (a) (h : a ∈ m), Decidable (p a h)] :
    Decidable (∀ (a) (h : a ∈ m), p a h) :=
  @decidable_of_iff _ _
    (Iff.intro (fun h a ha => h ⟨a, ha⟩ (mem_attach _ _)) fun h ⟨_a, _ha⟩ _ => h _ _)
    (@Multiset.decidableForallMultiset _ m.attach (fun a => p a.1 a.2) _)
/-- If `p` is a decidable predicate,
so is the existence of an element in a multiset satisfying `p`. -/
protected def decidableExistsMultiset {p : α → Prop} [DecidablePred p] : Decidable (∃ x ∈ m, p x) :=
  Quotient.recOnSubsingleton m fun l => decidable_of_iff (∃ a ∈ l, p a) Iff.rfl
instance decidableDexistsMultiset {p : ∀ a ∈ m, Prop} [_hp : ∀ (a) (h : a ∈ m), Decidable (p a h)] :
    Decidable (∃ (a : _) (h : a ∈ m), p a h) :=
  @decidable_of_iff _ _
    (Iff.intro (fun ⟨⟨a, ha₁⟩, _, ha₂⟩ => ⟨a, ha₁, ha₂⟩) fun ⟨a, ha₁, ha₂⟩ =>
      ⟨⟨a, ha₁⟩, mem_attach _ _, ha₂⟩)
    (@Multiset.decidableExistsMultiset { a // a ∈ m } m.attach (fun a => p a.1 a.2) _)
end Decidable
section Nodup
/-- `Nodup s` means that `s` has no duplicates, i.e. the multiplicity of
  any element is at most 1. -/
def Nodup (s : Multiset α) : Prop :=
  Quot.liftOn s List.Nodup fun _ _ p => propext p.nodup_iff
end Nodup
section SizeOf
/-- Defines a size for a multiset by referring to the size of the underlying list.

This has to be defined before the definition of `Finset`, otherwise its automatically generated
`SizeOf` instance will be wrong.
-/
protected noncomputable
def sizeOf [SizeOf α] (s : Multiset α) : ℕ :=
  (Quot.liftOn s SizeOf.sizeOf) fun _ _ => Perm.sizeOf_eq_sizeOf
noncomputable instance [SizeOf α] : SizeOf (Multiset α) :=
  ⟨Multiset.sizeOf⟩
end SizeOf
end Multiset
