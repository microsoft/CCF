/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Shamir.Model

@[expose] public section

open Aeneas Aeneas.Std Result
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

/-- Extracted evaluation terminates and agrees with CSLib sharing under the encoding. -/
def SharingRefinement : Prop :=
  ∀ (Party : Type) [Fintype Party] (params : Params F Party)
    (coeffs : Randomness params) (secret : F) (c : Slice U64)
    (_ : EncodesPolynomial params coeffs secret c) (i : Party) (x : U32)
    (_ : (x.val : F) = params.point i),
    ccf_shamir.evaluate c x
    ⦃r
    =>
      ∃ y,
        r = core.result.Result.Ok y
        ∧ y.val < prime
        ∧ (y.val : F) = share params coeffs secret i⦄

/-- Extracted recovery terminates and refines CSLib reconstruction for all ten limbs. -/
def RecoveryRefinement : Prop :=
  ∀ (s : Slice ccf_shamir.Share) (w : Slice U64)
    (_ : s.val ≠ []) (_ : Distinct s) (_ : w.val.length = s.val.length),
    ccf_shamir.recover s w
    ⦃r w'
    =>
      ∃ out,
        r = core.result.Result.Ok out
        ∧ ∀ k,
            (hk : k < out.val.length)
            → (out.val[k].val : F)
              = Cslib.Crypto.Protocols.SecretSharing.Shamir.Polynomial.reconstruct
                  (fun i : Fin s.val.length => point s i.val)
                  (fun i => limbValue s k i.val)⦄

end CCF.Shamir.Properties
