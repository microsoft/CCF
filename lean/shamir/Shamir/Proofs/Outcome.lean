-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Shamir.Proofs.Recovery
public import Shamir.Proofs.Sharing

/-!
# Outcome of recovery for arbitrary inputs

Recovery shares are not authenticated, so the extracted recovery must return for every input, and
must succeed only when the selected coordinates are distinct. These proofs do not assume
distinctness, unlike the functional specifications in `Shamir.Proofs.Interpolation`.
-/

@[expose] public section

open Aeneas Aeneas.Std Result
open scoped BigOperators
open Shamir.Model Shamir.Properties

namespace Shamir.Proofs

/-- The coordinates of the shares below index `i` differ from every other coordinate. -/
private def DistinctBelow (s : Slice ccf_shamir.Share) (i : Nat) : Prop :=
  ∀ k j, k < i → j < s.val.length → j ≠ k → point s j ≠ point s k

private theorem field_ne_zero (d : U64) (hd : d.val < prime) (hne : d ≠ 0#u64)
    : field d ≠ 0 := by
  intro h
  apply hne
  have hdvd : prime ∣ d.val := (ZMod.natCast_eq_zero_iff d.val prime).mp h
  have hzero : d.val = 0 := Nat.eq_zero_of_dvd_of_lt hdvd hd
  scalar_tac

private theorem factors_nonzero (s : Slice ccf_shamir.Share) (i : Nat)
    (h : productFrom s i 0 (fun k => point s k - point s i) ≠ 0)
    : ∀ j, j < s.val.length → j ≠ i → point s j ≠ point s i := by
  intro j hj hji heq
  apply h
  unfold productFrom
  apply Finset.prod_eq_zero (Finset.mem_Ico.mpr ⟨Nat.zero_le j, hj⟩)
  simp [hji, heq]

private theorem lagrange_loop_outcome (s : Slice ccf_shamir.Share) (w : Slice U64)
    (i : Usize) (hi : i.val ≤ s.val.length) (hw : w.val.length = s.val.length)
    (hbelow : DistinctBelow s i.val)
    : ccf_shamir.lagrange_loop0 s w i
      ⦃r _w'
      => r = core.result.Result.Ok () → Distinct s⦄ := by
  unfold ccf_shamir.lagrange_loop0
  simp
  split
  · rename_i hlt
    step as ⟨n, d, hn, hd, hnf, hdf⟩
    by_cases hdz : d = 0#u64
    · simp [hdz]
    · simp only [hdz, ↓reduceIte]
      have hdf' : field d ≠ 0 := field_ne_zero d hd hdz
      step as ⟨inv, hinv, hinvf⟩
      step as ⟨v, hv, hvf⟩
      step as ⟨w1, hw1⟩
      step as ⟨i1, hi1⟩
      have hw1len : w1.val.length = s.val.length := by simp [hw1, hw]
      have hproduct : productFrom s i.val 0 (fun k => point s k - point s i.val) ≠ 0 := by
        intro hzero
        apply hdf'
        rw [hdf, hzero]
        simp [field]
      have hnext : DistinctBelow s i1.val := by
        intro k j hk hj hjk
        by_cases hki : k = i.val
        · subst hki
          exact factors_nonzero s i.val hproduct j hj hjk
        · exact hbelow k j (by omega) hj hjk
      step with lagrange_loop_outcome as ⟨r, w', hr⟩
      exact hr (by assumption)
  · simp only [WP.spec_ok]
    intro _ a b ha hb hab
    exact hbelow b a (by omega) ha hab
termination_by s.val.length - i.val
decreasing_by scalar_decr_tac

/-- Weight computation returns for any inputs, and succeeds only on a nonempty selection of
distinct coordinates with a workspace entry per share. -/
theorem lagrange_outcome (s : Slice ccf_shamir.Share) (w : Slice U64)
    : ccf_shamir.lagrange s w
      ⦃r _w'
      =>
        r = core.result.Result.Ok ()
          → s.val ≠ [] ∧ w.val.length = s.val.length ∧ Distinct s⦄ := by
  unfold ccf_shamir.lagrange
  step as ⟨b, hb⟩
  by_cases hne : s.val = []
  · simp [hne] at hb
    simp [hb]
  · simp [hne] at hb
    simp only [hb, Bool.false_eq_true, ↓reduceIte]
    by_cases hw : w.val.length = s.val.length
    · simp [hw]
      step with lagrange_loop_outcome as ⟨r, w', hr⟩
      · intro k j hk
        simp at hk
      exact ⟨hne, hr (by assumption)⟩
    · have hlen : (w.len != s.len) = true := by
        simp only [bne_iff_ne, ne_eq]
        intro h
        apply hw
        simpa using congrArg (·.val) h
      simp [hlen]

/-- Recovery returns for any inputs, and succeeds exactly on a nonempty selection of distinct
coordinates with a workspace entry per share. -/
theorem recovery_succeeds_iff (s : Slice ccf_shamir.Share) (w : Slice U64)
    (secret : Array U32 10#usize)
    : ccf_shamir.recover s w secret
      ⦃r _w' _out
      =>
        r = core.result.Result.Ok ()
          ↔ s.val ≠ [] ∧ w.val.length = s.val.length ∧ Distinct s⦄ := by
  by_cases h : s.val ≠ [] ∧ w.val.length = s.val.length ∧ Distinct s
  · step with recover_spec as ⟨r, w', out, hr, _⟩
    simp [hr, h]
  · unfold ccf_shamir.recover
    step with lagrange_outcome as ⟨r, w1, hr⟩
    cases r with
    | Ok u => exact absurd (hr rfl) h
    | Err e =>
        simp [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, h]

private theorem evaluate_loop_outcome (c : Slice U64) (x y : U64) (i : Usize)
    (hi : i.val ≤ c.val.length) (hx : x.val < prime) (hy : y.val < prime)
    : ccf_shamir.evaluate_loop c x y i
      ⦃r
      =>
        (∃ z, r = core.result.Result.Ok z)
          → ∀ j, j < i.val → (hj : j < c.val.length) → c.val[j].val < prime⦄ := by
  unfold ccf_shamir.evaluate_loop
  simp
  split
  · rename_i hpos
    step as ⟨i1, hi1⟩
    step as ⟨a, ha⟩
    by_cases hbig : 2147483647 ≤ a.val
    · simp [ccf_shamir.PRIME, hbig]
    · simp [ccf_shamir.PRIME, hbig]
      have ha' : a.val < prime := by
        simp only [prime]
        omega
      step as ⟨v, hv, hvf⟩
      step as ⟨w, hw, hwf⟩
      step with evaluate_loop_outcome as ⟨r, hr⟩
      rename_i z hz j hj hjc
      by_cases hji : j = i1.val
      · subst hji
        rw [← ha]
        exact ha'
      · exact hr z hz j (by omega) hjc
  · step with UScalar.cast_inBounds_spec as ⟨z, hz⟩
    intro _ _ j hj
    omega
termination_by i.val
decreasing_by scalar_decr_tac

/-- Evaluation returns for any inputs, and succeeds only on canonical coefficients. -/
private theorem evaluate_outcome (c : Slice U64) (x : U32)
    : ccf_shamir.evaluate c x
      ⦃r
      =>
        (∃ z, r = core.result.Result.Ok z)
          → ∀ j, (hj : j < c.val.length) → c.val[j].val < prime⦄ := by
  unfold ccf_shamir.evaluate
  step as ⟨b, hb⟩
  by_cases hne : c.val = []
  · simp [hne] at hb
    simp [hb]
  · simp [hne] at hb
    simp only [hb, Bool.false_eq_true, ↓reduceIte]
    step as ⟨v, hv⟩
    step as ⟨w, hw⟩
    have hw' : w.val < prime := by rw [hw]; exact Nat.mod_lt _ (by decide)
    step with evaluate_loop_outcome as ⟨r, hr⟩
    rename_i z hz j hj
    exact hr z hz j (by simpa using hj) hj

/-- Share generation returns for any inputs, succeeds exactly on valid arguments, and leaves the
shares unchanged when it reports an error. -/
theorem sharing_succeeds_iff (c : Slice U64) (limb : Usize) (s : Slice ccf_shamir.Share)
    : ccf_shamir.share_limb c limb s
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
  by_cases h
      : limb.val < 10
        ∧ s.val ≠ []
        ∧ s.val.length < prime
        ∧ c.val ≠ []
        ∧ c.val.length ≤ s.val.length
        ∧ ∀ j, (hj : j < c.val.length) → c.val[j].val < prime
  · obtain ⟨hl, hne, hlen, hcne, hct, hc⟩ := h
    step with share_limb_spec as ⟨r, s', hr, _, _⟩
    simp [hr, hl, hne, hlen, hcne, hct]
    exact hc
  · have hprime : ccf_shamir.PRIME.val ≤ UScalar.max .Usize := by
      rw [UScalar.max_USize_eq]
      rcases Usize.bounds_eq with h | h <;> rw [h] <;>
        simp [ccf_shamir.PRIME, U32.max, U64.max, U32.numBits, U64.numBits]
    unfold ccf_shamir.share_limb
    simp only [ccf_shamir.LIMBS]
    split
    · simp [h]
    · rename_i hl
      step as ⟨b, hb⟩
      by_cases hne : s.val = []
      · simp [hne] at hb
        simp [hb, h]
      · simp [hne] at hb
        simp only [hb, Bool.false_eq_true, ↓reduceIte]
        step with UScalar.cast_inBounds_spec as ⟨p, hp⟩
        have hp' : p.val = prime := by rw [hp]; simp [ccf_shamir.PRIME, prime]
        split
        · simp [h]
        · rename_i hlen
          step as ⟨b1, hb1⟩
          by_cases hcne : c.val = []
          · simp [hcne] at hb1
            simp [hb1, h]
          · simp [hcne] at hb1
            simp only [hb1, Bool.false_eq_true, ↓reduceIte]
            split
            · simp [h]
            · rename_i hct
              have hnc : ¬ ∀ j, (hj : j < c.val.length) → c.val[j].val < prime := by
                intro hc
                apply h
                exact ⟨by scalar_tac, hne, by scalar_tac, hcne, by scalar_tac, hc⟩
              unfold ccf_shamir.share_limb_loop
              simp
              split
              · step as ⟨i2, hi2⟩
                have hi2b : i2.val ≤ UScalar.max .U32 := by
                  simp only [UScalar.max, UScalarTy.U32_numBits_eq]
                  omega
                step with UScalar.cast_inBounds_spec as ⟨x, hx⟩
                step with evaluate_outcome as ⟨r, hr⟩
                cases r with
                | Ok z => exact absurd (hr z rfl) hnc
                | Err e =>
                    simp [core.result.Result.Insts.CoreOpsTry.branch,
                      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, h]
              · rename_i hempty
                exfalso
                apply hne
                apply List.eq_nil_of_length_eq_zero
                omega

end Shamir.Proofs
