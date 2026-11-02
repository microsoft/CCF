/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Shamir.Model

@[expose] public section

open Aeneas Aeneas.Std
open Cslib.Crypto.Protocols.SecretSharing.Shamir

namespace CCF.Shamir.Properties

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

end CCF.Shamir.Properties
