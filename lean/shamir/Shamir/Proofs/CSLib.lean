/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Shamir.Proofs.Recovery
public import Shamir.Proofs.Sharing
public import Shamir.Properties

@[expose] public section

open Aeneas Aeneas.Std Result
open Cslib.Crypto.Protocols.SecretSharing.Shamir
open scoped BigOperators

namespace CCF.Shamir

private theorem constant_C (a : F) : Polynomial.constantCoeff (Polynomial.C a) = a := by
  simp

private theorem constant_X
    : Polynomial.constantCoeff (Polynomial.X : Polynomial F) = 0 := by simp

private theorem productFrom_fin (s : Slice ccf_shamir.Share)
    (i : Fin s.val.length) (f : Nat → F)
    : productFrom s i.val 0 f = ∏ j : Fin s.val.length, if j = i then 1 else f j.val := by
  unfold productFrom
  rw [← Finset.range_eq_Ico]
  simp only [Fin.ext_iff]
  exact (Fin.prod_univ_eq_prod_range (fun k => if k = i.val then 1 else f k) s.val.length).symm

private theorem basis_weight (s : Slice ccf_shamir.Share)
    [DecidableEq (Fin s.val.length)] (i : Fin s.val.length)
    : (Lagrange.basis Finset.univ (fun j : Fin s.val.length => point s j.val)
        i).constantCoeff
      = weight s i.val := by
  classical
  simp only [Lagrange.basis, map_prod, Lagrange.basisDivisor, map_mul,
    constant_C, constant_X, map_sub, zero_sub]
  unfold weight
  rw [productFrom_fin, productFrom_fin, ← Finset.prod_div_distrib]
  rw [← Finset.prod_erase_mul (a := i) (Finset.univ : Finset (Fin s.val.length)) _ (by simp)]
  simp only [↓reduceIte, one_div, inv_one, mul_one]
  apply Finset.prod_congr rfl
  intro j hj
  have hji : j ≠ i := (Finset.mem_erase.mp hj).1
  simp only [hji, ↓reduceIte]
  rw [div_eq_mul_inv, ← neg_sub (point s i.val) (point s j.val), inv_neg]
  ring

theorem recoveredLimb_eq_cslib (s : Slice ccf_shamir.Share) (limb : Nat)
    : recoveredLimb s limb
      = Cslib.Crypto.Protocols.SecretSharing.Shamir.Polynomial.reconstruct
          (fun i : Fin s.val.length => point s i.val)
          (fun i => limbValue s limb i.val) := by
  classical
  let : DecidableEq (Fin s.val.length) := fun a b => Classical.propDecidable (a = b)
  unfold Cslib.Crypto.Protocols.SecretSharing.Shamir.Polynomial.reconstruct
  rw [Lagrange.interpolate_apply]
  simp only [map_sum, map_mul, constant_C, basis_weight]
  unfold recoveredLimb
  rw [Fin.sum_univ_eq_sum_range (fun k => limbValue s limb k * weight s k) s.val.length]
  apply Finset.sum_congr rfl
  intro i hi
  ring

private theorem polynomialPrefix_eq_cslib
    {Party : Type} [Fintype Party] (params : Params F Party)
    (coeffs : Randomness params) (secret : F)
    (c : Slice U64) (hlen : c.val.length = params.threshold + 1)
    (hc
      : ∀ j,
          (hj : j < c.val.length)
          → field c.val[j]
            = (Polynomial.sharingPolynomial secret
                (Polynomial.tailPolynomial params.threshold coeffs)).coeff
                j)
    (x : F)
    : polynomialPrefix c c.val.length x
      = (Polynomial.sharingPolynomial secret
          (Polynomial.tailPolynomial params.threshold coeffs)).eval
          x := by
  let p := Polynomial.sharingPolynomial secret
    (Polynomial.tailPolynomial params.threshold coeffs)
  have hdeg : p.natDegree < c.val.length := by
    rw [hlen]
    exact Nat.lt_succ_of_le
      (Polynomial.natDegree_sharingPolynomial_le secret _
        (Polynomial.tailPolynomial_degree_lt params.threshold coeffs))
  rw [Polynomial.eval_eq_sum_range' hdeg]
  unfold polynomialPrefix
  apply Finset.sum_congr rfl
  intro j hj
  have hj' := Finset.mem_range.mp hj
  rw [getElem!_pos c.val j hj']
  rw [← hc j hj']
  rfl

theorem sharing_refinement : Properties.SharingRefinement := by
  intro Party _ params coeffs secret c hc limb hl s hne hlen hct
  have hcne : c.val ≠ [] := by
    intro heq
    have hlen := hc.1
    simp [heq] at hlen
  have hcanonical := hc.2.1
  step with share_limb_spec as ⟨r, s', hr, hlen', hpost⟩
  refine ⟨hr, hlen', ?_⟩
  intro k hk
  obtain ⟨⟨hx, hy, hyf⟩, hother⟩ := hpost k hk
  refine ⟨hx, hy, ?_, hother⟩
  intro i hi
  unfold point at hi
  rw [hx] at hi
  unfold limbValue
  rw [hyf, polynomialPrefix_eq_cslib params coeffs secret c hc.1 hc.2.2, hi]
  rfl

theorem recovery_refinement : Properties.RecoveryRefinement := by
  intro s w secret hne hs hw
  step with recover_spec as ⟨r, w', out, hr, hout⟩
  refine ⟨hr, ?_⟩
  intro k hk
  rw [hout k hk, recoveredLimb_eq_cslib]

theorem recoveredLimb_eq_secret (s : Slice ccf_shamir.Share) (limb : Nat)
    (secret : F) (tail : Polynomial F) (hs : Distinct s)
    (hdeg : (Polynomial.sharingPolynomial secret tail).degree < s.val.length)
    (hvalues
      : ∀ i : Fin s.val.length,
          limbValue s limb i.val
          = (Polynomial.sharingPolynomial secret tail).eval (point s i.val))
    : recoveredLimb s limb = secret := by
  have hinj : Function.Injective (fun i : Fin s.val.length => point s i.val) := by
    intro i j hij
    by_contra hne
    exact hs i.val j.val i.isLt j.isLt (by simpa only [Fin.ext_iff] using hne) hij
  rw [recoveredLimb_eq_cslib]
  simp_rw [hvalues]
  exact Polynomial.reconstruct_sharingPolynomial_eq_secret hinj (by simpa using hdeg)

end CCF.Shamir
