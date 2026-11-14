-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Shamir.Properties.Encoding
public import Mathlib.Algebra.BigOperators.Intervals

/-!
# Proof-only definitions

Mathematical counterparts of the intermediate values computed by the extracted implementation.
They are used to state loop invariants and are not needed to read `Shamir.Properties`.
-/

@[expose] public section

open Aeneas Aeneas.Std
open scoped BigOperators
open Shamir.Model Shamir.Properties

namespace Shamir.Proofs

/-- Evaluate the first `n` coefficients, in constant-coefficient-first order. -/
def polynomialPrefix (c : Slice U64) (n : Nat) (x : F) : F :=
  ∑ j ∈ Finset.range n, (c.val[j]!.val : F) * x ^ j

/-- Multiply over the remaining share indices starting at `j`, omitting `i`. -/
def productFrom (shares : Slice ccf_shamir.Share) (i j : Nat) (f : Nat → F) : F :=
  ∏ k ∈ Finset.Ico j shares.val.length, if k = i then 1 else f k

/-- The Lagrange coefficient for share `i` evaluated at zero. -/
def weight (shares : Slice ccf_shamir.Share) (i : Nat) : F :=
  productFrom shares i 0 (point shares)
  / productFrom shares i 0 (fun j => point shares j - point shares i)

/-- The mathematical interpolation result for one of the ten limbs. -/
def recoveredLimb (shares : Slice ccf_shamir.Share) (limb : Nat) : F :=
  ∑ i ∈ Finset.range shares.val.length, weight shares i * limbValue shares limb i

end Shamir.Proofs
