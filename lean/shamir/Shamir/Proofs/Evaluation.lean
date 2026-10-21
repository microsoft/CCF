/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Shamir.Proofs.Arithmetic

@[expose] public section

open Aeneas Aeneas.Std Result

namespace CCF.Shamir

@[step]
theorem evaluate_loop_spec (c : Slice U64) (x y : U64) (i : Usize)
    (hi : i.val ≤ c.val.length)
    (hc : ∀ j, (hj : j < c.val.length) → c.val[j].val < prime)
    (hx : x.val < prime) (hy : y.val < prime)
    : ccf_shamir.evaluate_loop c x y i
      ⦃r
      =>
        ∃ z,
          r = core.result.Result.Ok z
          ∧ z.val < prime
          ∧ (z.val : F) = polynomialPrefix c i.val (field x) + field y * field x ^ i.val
        ⦄ := by
  unfold ccf_shamir.evaluate_loop
  simp
  split
  · rename_i hpos
    step as ⟨i1, hi1⟩
    step as ⟨a, ha⟩
    have ha' : a.val < prime := by
      rw [ha]
      exact hc i1.val (by scalar_tac)
    have ha'' : ¬ 2147483647 ≤ a.val := Nat.not_le_of_lt ha'
    simp [ccf_shamir.PRIME, ha'']
    step as ⟨v, hv, hvf⟩
    step as ⟨w, hw, hwf⟩
    step as ⟨r, z, hr, hz, hzf⟩
    refine ⟨z, hr, hz, ?_⟩
    have hieq : i.val = i1.val + 1 := by scalar_tac
    rw [hzf, hieq]
    simp only [polynomialPrefix, Finset.sum_range_succ, pow_succ]
    rw [hwf, hvf]
    have hia : i1.val < c.val.length := by omega
    have hidx : c.val[i1.val]! = a := by
      rw [getElem!_pos c.val i1.val hia]
      exact ha.symm
    simp only [hidx, field]
    ring
  · have hi0 : i.val = 0 := by scalar_tac
    step with UScalar.cast_inBounds_spec as ⟨z, hz⟩
    refine ⟨z, rfl, ?_, ?_⟩
    · omega
    · simp [hi0, polynomialPrefix, field, hz]
termination_by i.val
decreasing_by scalar_decr_tac

@[step]
theorem evaluate_spec (c : Slice U64) (x : U32)
    (hne : c.val ≠ [])
    (hc : ∀ j, (hj : j < c.val.length) → c.val[j].val < prime)
    : ccf_shamir.evaluate c x
      ⦃r
      =>
        ∃ z,
          r = core.result.Result.Ok z
          ∧ z.val < prime
          ∧ (z.val : F) = polynomialPrefix c c.val.length (x.val : F)⦄ := by
  unfold ccf_shamir.evaluate
  step as ⟨b, hb⟩
  simp [hne] at hb
  simp only [hb, Bool.false_eq_true, ↓reduceIte]
  step as ⟨v, hv⟩
  step as ⟨w, hw⟩
  have hw' : w.val < prime := by rw [hw]; exact Nat.mod_lt _ (by decide)
  step as ⟨r, z, hr, hz, hzf⟩
  refine ⟨z, hr, hz, ?_⟩
  simpa [field, hw, hv] using hzf

end CCF.Shamir
