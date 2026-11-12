-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Shamir.Properties.Encoding

import Shamir.Proofs.Outcome
import Shamir.Proofs.Refinement
import Shamir.Proofs.Witnesses

@[expose] public section

/-!
# Human-reviewed Shamir properties

Review these statements with the extracted implementation in `Generated/CcfShamir.lean`, the
field in `Shamir/Model/Field.lean`, and the interpretation of machine values in
`Shamir/Properties/Encoding.lean`. Each theorem links to its implementation in `Shamir/Proofs/`.
Each claim with premises has an adjacent witness that its premises can hold.

`f x ⦃r => P r⦄` is the Aeneas total-correctness triple: the extracted function `f` returns on
`x`, without panicking or diverging, and its result `r` satisfies `P`. A Rust `Result` returned by
`f` is part of `r`, so a triple also covers the inputs that the implementation rejects.
-/

open Aeneas Aeneas.Std Result
open Cslib.Crypto.Protocols.SecretSharing.Shamir

namespace Shamir.Properties

open Model

/-! ## Field arithmetic -/

/-- The branch-free reduction returns the canonical remainder of any 64-bit value. -/
theorem reduction_is_remainder
    : ∀ (x : U64), ccf_shamir.reduce x ⦃y => y.val = x.val % prime⦄ := by
  exact Proofs.reduce_spec

/-! ## Sharing -/

/-- Extracted share generation terminates and agrees with CSLib sharing under the encoding.

Filling one limb assigns coordinate `k + 1` to the share at index `k`, stores the canonical
polynomial value for that coordinate in the requested limb, and leaves every other limb of
every share unchanged. -/
theorem sharing_refines_cslib
    : ∀ (Party : Type) [Fintype Party] (params : Params F Party)
        (coeffs : Randomness params) (secret : F) (c : Slice U64)
        (_ : EncodesPolynomial params coeffs secret c)
        (limb : Usize) (_ : limb.val < 10)
        (s : Slice ccf_shamir.Share) (_ : s.val ≠ []) (_ : s.val.length < prime)
        (_ : c.val.length ≤ s.val.length),
        ccf_shamir.share_limb c limb s
        ⦃r s'
        =>
          r = core.result.Result.Ok ()
            ∧ s'.val.length = s.val.length
            ∧ ∀ k,
                k < s.val.length
                → s'.val[k]!.x.val = k + 1
                  ∧ s'.val[k]!.y.val[limb.val]!.val < prime
                  ∧ (∀ i : Party,
                      point s' k = params.point i
                      → limbValue s' limb.val k = share params coeffs secret i)
                  ∧ ∀ m, m ≠ limb.val → s'.val[k]!.y.val[m]! = s.val[k]!.y.val[m]!⦄ := by
  exact Proofs.sharing_refines_cslib

/-- Witness: the coefficients `123, 456` encode a two-of-three sharing polynomial, and can fill
a limb of three shares. -/
theorem sharing_refines_cslib_witness
    : ∃ (params : Params F (Fin 3)) (coeffs : Randomness params) (secret : F)
        (c : Slice U64) (limb : Usize) (s : Slice ccf_shamir.Share),
        EncodesPolynomial params coeffs secret c
        ∧ limb.val < 10
        ∧ s.val ≠ []
        ∧ s.val.length < prime
        ∧ c.val.length ≤ s.val.length := by
  exact Proofs.sharing_refines_cslib_witness

/-- Share generation returns for any inputs, succeeds exactly on valid arguments, and leaves the
shares unchanged when it reports an error.

Valid arguments are a limb index below ten, a nonempty share array shorter than the field
characteristic, and at least one but no more coefficients than shares, all canonical. -/
theorem sharing_succeeds_iff
    : ∀ (c : Slice U64) (limb : Usize) (s : Slice ccf_shamir.Share),
        ccf_shamir.share_limb c limb s
        ⦃r s'
        =>
          (r = core.result.Result.Ok ()
              ↔ limb.val < 10
                ∧ s.val ≠ []
                ∧ s.val.length < prime
                ∧ c.val ≠ []
                ∧ c.val.length ≤ s.val.length
                ∧ ∀ j, (hj : j < c.val.length) → c.val[j].val < prime)
            ∧ (r ≠ core.result.Result.Ok () → s' = s)⦄ := by
  exact Proofs.sharing_succeeds_iff

/-! ## Recovery -/

/-- Extracted recovery terminates and refines CSLib reconstruction for all ten limbs.

The secret is written in place into the caller's array, whatever its initial contents. -/
theorem recovery_refines_cslib
    : ∀ (s : Slice ccf_shamir.Share) (w : Slice U64) (secret : Array U32 10#usize)
        (_ : s.val ≠ []) (_ : Distinct s) (_ : w.val.length = s.val.length),
        ccf_shamir.recover s w secret
        ⦃r _w' out
        =>
          r = core.result.Result.Ok ()
            ∧ ∀ k,
                (hk : k < out.val.length)
                → out.val[k].val < prime
                  ∧ (out.val[k].val : F)
                    = Cslib.Crypto.Protocols.SecretSharing.Shamir.Polynomial.reconstruct
                        (fun i : Fin s.val.length => point s i.val)
                        (fun i => limbValue s k i.val)⦄ := by
  exact Proofs.recovery_refines_cslib

/-- Witness: two shares can have distinct coordinates, with a workspace entry each. -/
theorem recovery_refines_cslib_witness
    : ∃ (s : Slice ccf_shamir.Share) (w : Slice U64),
        s.val ≠ [] ∧ Distinct s ∧ w.val.length = s.val.length := by
  exact Proofs.recovery_refines_cslib_witness

/-- Recovery returns the secret of every limb from shares of low-degree sharing polynomials.

If, for each limb, the selected shares are values of a polynomial `secret + X * tail` of degree
below the number of selected shares, recovery writes the canonical representative of that
polynomial's constant term `secret` to the limb. -/
theorem recovery_returns_secret
    : ∀ (s : Slice ccf_shamir.Share) (w : Slice U64) (initial : Array U32 10#usize)
        (secret : Fin 10 → F) (tail : Fin 10 → _root_.Polynomial F)
        (_ : s.val ≠ []) (_ : Distinct s) (_ : w.val.length = s.val.length)
        (_
          : ∀ limb,
              (Polynomial.sharingPolynomial (secret limb) (tail limb)).degree
              < s.val.length)
        (_
          : ∀ (limb : Fin 10) i,
              i < s.val.length
              → limbValue s limb.val i
                = (Polynomial.sharingPolynomial (secret limb) (tail limb)).eval
                    (point s i)),
        ccf_shamir.recover s w initial
        ⦃r _w' out
        =>
          r = core.result.Result.Ok ()
            ∧ ∀ limb : Fin 10,
                out.val[limb.val]!.val < prime
                ∧ (out.val[limb.val]!.val : F) = secret limb⦄ := by
  exact Proofs.recovery_returns_secret

/-- Witness: two shares at distinct coordinates can lie on a line for every limb. -/
theorem recovery_returns_secret_witness
    : ∃ (s : Slice ccf_shamir.Share) (w : Slice U64) (secret : Fin 10 → F)
        (tail : Fin 10 → _root_.Polynomial F),
        s.val ≠ []
        ∧ Distinct s
        ∧ w.val.length = s.val.length
        ∧ (∀ limb,
            (Polynomial.sharingPolynomial (secret limb) (tail limb)).degree
            < s.val.length)
        ∧ ∀ (limb : Fin 10) i,
            i < s.val.length
            → limbValue s limb.val i
              = (Polynomial.sharingPolynomial (secret limb) (tail limb)).eval
                  (point s i) := by
  exact Proofs.recovery_returns_secret_witness

/-- Recovery returns for any inputs, and succeeds exactly on a nonempty selection of distinct
coordinates with a workspace entry per share.

Recovery shares are not authenticated, so this covers every input, including repeated,
noncanonical and zero coordinates. -/
theorem recovery_succeeds_iff
    : ∀ (s : Slice ccf_shamir.Share) (w : Slice U64) (secret : Array U32 10#usize),
        ccf_shamir.recover s w secret
        ⦃r _w' _out
        =>
          r = core.result.Result.Ok ()
            ↔ s.val ≠ [] ∧ w.val.length = s.val.length ∧ Distinct s⦄ := by
  exact Proofs.recovery_succeeds_iff

/-- Recovery that reports an error leaves the caller's secret untouched, for any inputs. -/
theorem recovery_error_preserves_secret
    : ∀ (s : Slice ccf_shamir.Share) (w : Slice U64) (secret : Array U32 10#usize)
        (r : core.result.Result Unit ccf_shamir.Error) (w' : Slice U64)
        (secret' : Array U32 10#usize),
        ccf_shamir.recover s w secret = ok (r, w', secret')
        → r ≠ core.result.Result.Ok ()
        → secret' = secret := by
  exact Proofs.recovery_error_preserves_secret

/-- Witness: recovery from two shares at the same coordinate returns an error. -/
theorem recovery_error_preserves_secret_witness
    : ∃ (s : Slice ccf_shamir.Share) (w : Slice U64) (secret : Array U32 10#usize)
        (r : core.result.Result Unit ccf_shamir.Error) (w' : Slice U64)
        (secret' : Array U32 10#usize),
        ccf_shamir.recover s w secret = ok (r, w', secret')
        ∧ r ≠ core.result.Result.Ok () := by
  exact Proofs.recovery_error_preserves_secret_witness

end Shamir.Properties
