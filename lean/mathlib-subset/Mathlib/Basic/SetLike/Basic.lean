/-
Copyright (c) 2021 Eric Wieser. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Eric Wieser
-/
module

public import Mathlib.Data.Set.Basic

@[expose] public section
/-- A class to indicate that there is a canonical injection between `A` and `Set B`.

This has the effect of giving terms of `A` elements of type `B` (through a `Membership`
instance) and a compatible coercion to `Type*` as a subtype.

Note: if `SetLike.coe` is a projection, implementers should create a simp lemma such as
```
@[simp] lemma mem_carrier {p : MySubobject X} : x ∈ p.carrier ↔ x ∈ (p : Set X) := Iff.rfl
```
to normalize terms.

If you declare an unbundled subclass of `SetLike`, for example:
```
class MulMemClass (S : Type*) (M : Type*) [Mul M] [SetLike S M] where
  ...
```
Then you should *not* repeat the `outParam` declaration so `SetLike` will supply the value instead.
This ensures your subclass will not have issues with synthesis of the `[Mul M]` parameter starting
before the value of `M` is known.
-/
class SetLike (A : Type*) (B : outParam Type*) where
  /-- The coercion from a term of a `SetLike` to its corresponding `Set`. -/
  protected coe : A → Set B
  /-- The coercion from a term of a `SetLike` to its corresponding `Set` is injective. -/
  coe_injective : Function.Injective coe
namespace SetLike
variable {A : Type*} {B : Type*} [i : SetLike A B]

instance : CoeTC A (Set B) where coe := SetLike.coe
instance (priority := 100) instMembership : Membership B A :=
  ⟨fun p x => x ∈ (p : Set B)⟩
end SetLike
section default
variable (A : Type*) {B : Type*}
/-- The order induced from a `Membership` instance by inclusion.

An order defined this way automatically makes available an instance of `IsConcreteLE`.
-/
@[reducible] def LE.ofMembership [Membership B A] : LE A where
  le H K := ∀ ⦃x⦄, x ∈ H → x ∈ K
/-- The preorder induced from a `Membership` instance by inclusion.

A preorder defined this way automatically makes available an instance of `IsConcreteLE`.
-/
@[reducible] def Preorder.ofMembership [Membership B A] : Preorder A where
  __ := LE.ofMembership A
  le_refl _ _ h := h
  le_trans _ _ _ h₁ h₂ _ h₃ := h₂ (h₁ h₃)
/-- The partial order induced from a `SetLike` instance by inclusion.
A partial order defined this way automatically makes available an instance of `IsConcreteLE`.
-/
@[reducible] def PartialOrder.ofSetLike [SetLike A B] : PartialOrder A where
  __ := Preorder.ofMembership A
  __ := PartialOrder.lift (SetLike.coe : A → Set B) SetLike.coe_injective
end default
