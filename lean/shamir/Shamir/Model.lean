/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Generated.CcfShamir
public import Shamir.Model.Field
public import Cslib.Crypto.Protocols.SecretSharing.Shamir
public import Mathlib.Algebra.BigOperators.Intervals

@[expose] public section

open Aeneas Aeneas.Std
open scoped BigOperators

namespace CCF.Shamir

instance inhabitedShare : Inhabited ccf_shamir.Share :=
  ⟨⟨0#u32, Array.repeat 10#usize 0#u32⟩⟩

/-- Interpret a machine integer modulo the sharing prime. -/
def field (x : U64) : F := x.val

/-- Evaluate the first `n` coefficients, in constant-coefficient-first order. -/
def polynomialPrefix (c : Slice U64) (n : Nat) (x : F) : F :=
  ∑ j ∈ Finset.range n, (c.val[j]!.val : F) * x ^ j

/-- The field coordinate of the share at index `i`. -/
def point (shares : Slice ccf_shamir.Share) (i : Nat) : F :=
  shares.val[i]!.x.val

/-- Multiply over the remaining share indices starting at `j`, omitting `i`. -/
def productFrom (shares : Slice ccf_shamir.Share) (i j : Nat) (f : Nat → F) : F :=
  ∏ k ∈ Finset.Ico j shares.val.length, if k = i then 1 else f k

/-- The Lagrange coefficient for share `i` evaluated at zero. -/
def weight (shares : Slice ccf_shamir.Share) (i : Nat) : F :=
  productFrom shares i 0 (point shares)
  / productFrom shares i 0 (fun j => point shares j - point shares i)

/-- Coordinates are distinct after reduction into the field. -/
def Distinct (shares : Slice ccf_shamir.Share) : Prop :=
  ∀ i j,
    i < shares.val.length
    → j < shares.val.length
    → i ≠ j
    → point shares i ≠ point shares j

/-- Interpret a share limb modulo the sharing prime. -/
def limbValue (shares : Slice ccf_shamir.Share) (limb i : Nat) : F :=
  shares.val[i]!.y.val[limb]!.val

/-- The mathematical interpolation result for one of the ten limbs. -/
def recoveredLimb (shares : Slice ccf_shamir.Share) (limb : Nat) : F :=
  ∑ i ∈ Finset.range shares.val.length, weight shares i * limbValue shares limb i

end CCF.Shamir
