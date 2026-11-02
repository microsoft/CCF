/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Shamir.Properties.Encoding
import Shamir.Proofs.CSLib

@[expose] public section

open Aeneas Aeneas.Std Result
open Cslib.Crypto.Protocols.SecretSharing.Shamir

namespace CCF.Shamir

/-- Extracted share generation terminates and agrees with CSLib sharing under the encoding.

Filling one limb assigns coordinate `k + 1` to the share at index `k`, stores the canonical
polynomial value for that coordinate in the requested limb, and leaves every other limb of
every share unchanged. -/
theorem sharing_refines_cslib :
  ∀ (Party : Type) [Fintype Party] (params : Params F Party)
    (coeffs : Randomness params) (secret : F) (c : Slice U64)
    (_ : Properties.EncodesPolynomial params coeffs secret c)
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
  exact Proofs.sharing_refinement

/-- Extracted recovery terminates and refines CSLib reconstruction for all ten limbs.

The secret is written in place into the caller's array, whatever its initial contents. -/
theorem recovery_refines_cslib :
  ∀ (s : Slice ccf_shamir.Share) (w : Slice U64) (secret : Array U32 10#usize)
    (_ : s.val ≠ []) (_ : Distinct s) (_ : w.val.length = s.val.length),
    ccf_shamir.recover s w secret
    ⦃r _w' out
    =>
      r = core.result.Result.Ok ()
        ∧ ∀ k,
            (hk : k < out.val.length)
            → (out.val[k].val : F)
              = Cslib.Crypto.Protocols.SecretSharing.Shamir.Polynomial.reconstruct
                  (fun i : Fin s.val.length => point s i.val)
                  (fun i => limbValue s k i.val)⦄ := by
  exact Proofs.recovery_refinement

/-- Recovery that reports an error leaves the caller's secret untouched, for any inputs. -/
theorem recovery_error_preserves_secret :
  ∀ (s : Slice ccf_shamir.Share) (w : Slice U64) (secret : Array U32 10#usize)
    (r : core.result.Result Unit ccf_shamir.Error) (w' : Slice U64)
    (secret' : Array U32 10#usize),
    ccf_shamir.recover s w secret = ok (r, w', secret')
    → r ≠ core.result.Result.Ok ()
    → secret' = secret := by
  exact Proofs.recover_error_preserves_secret

end CCF.Shamir
