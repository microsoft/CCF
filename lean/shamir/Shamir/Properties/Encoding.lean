-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Shamir.Model
public import Cslib.Crypto.Protocols.SecretSharing.Shamir

/-!
# Interpreting machine values in the sharing field

The definitions needed to read the claims in `Shamir.Properties`: how the machine integers, share
coordinates, share limbs and coefficient vectors of the extracted implementation are interpreted
as elements of the field, and as the objects of the CSLib specification.
-/

@[expose] public section

open Aeneas Aeneas.Std
open Cslib.Crypto.Protocols.SecretSharing.Shamir

namespace Shamir.Properties

open Model

/-- Interpret a machine integer modulo the sharing prime. -/
def field (x : U64) : F := x.val

/-- The field coordinate of the share at index `i`. -/
def point (shares : Slice ccf_shamir.Share) (i : Nat) : F :=
  shares.val[i]!.x.val

/-- Interpret one limb of the share at index `i` modulo the sharing prime. -/
def limbValue (shares : Slice ccf_shamir.Share) (limb i : Nat) : F :=
  shares.val[i]!.y.val[limb]!.val

/-- Coordinates are distinct after reduction into the field. -/
def Distinct (shares : Slice ccf_shamir.Share) : Prop :=
  ∀ i j,
    i < shares.val.length
    → j < shares.val.length
    → i ≠ j
    → point shares i ≠ point shares j

/-- A canonical coefficient vector represents CSLib's explicitly randomized polynomial. -/
def EncodesPolynomial {Party : Type} [Fintype Party]
    (params : Params F Party) (coeffs : Randomness params) (secret : F)
    (c : Slice U64)
    : Prop :=
  c.val.length = params.threshold + 1
  ∧ (∀ j, (hj : j < c.val.length) → c.val[j].val < prime)
  ∧ ∀ j,
      (hj : j < c.val.length)
      → field c.val[j]
        = (Polynomial.sharingPolynomial secret
            (Polynomial.tailPolynomial params.threshold coeffs)).coeff
            j

end Shamir.Properties
