/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Shamir.Proofs.Inverse

@[expose] public section

open Aeneas Aeneas.Std Result
open scoped BigOperators

namespace CCF.Shamir

private theorem productFrom_step (s : Slice ccf_shamir.Share) (i j : Nat)
    (f : Nat → F) (hj : j < s.val.length)
    : productFrom s i j f = (if j = i then 1 else f j) * productFrom s i (j + 1) f := by
  exact Finset.prod_eq_prod_Ico_succ_bot hj _

@[step]
theorem products_spec (s : Slice ccf_shamir.Share) (i : Usize)
    (n d : U64) (j : Usize)
    (hi : i.val < s.val.length) (hj : j.val ≤ s.val.length)
    (hn : n.val < prime) (hd : d.val < prime)
    : ccf_shamir.lagrange_loop0_loop0 s i n d j
      ⦃a b
      =>
        a.val < prime
          ∧ b.val < prime
          ∧ field a = field n * productFrom s i.val j.val (point s)
          ∧ field b
            = field d * productFrom s i.val j.val (fun k => point s k - point s i.val)
        ⦄ := by
  unfold ccf_shamir.lagrange_loop0_loop0
  simp
  split
  · rename_i hlt
    split
    · rename_i heq
      step as ⟨j1, hj1⟩
      step as ⟨a, b, ha, hb, haf, hbf⟩
      refine ⟨ha, hb, ?_, ?_⟩
      · rw [productFrom_step s i.val j.val _ hlt]
        simp only [heq, ↓reduceIte, one_mul]
        simpa only [heq, hj1] using haf
      · rw [productFrom_step s i.val j.val _ hlt]
        simp only [heq, ↓reduceIte, one_mul]
        simpa only [heq, hj1] using hbf
    · rename_i hne
      step as ⟨sj, hsj⟩
      step as ⟨xj, hxj⟩
      step as ⟨rj, hrj⟩
      step as ⟨si, hsi⟩
      step as ⟨xi, hxi⟩
      step as ⟨ri, hri⟩
      have hrjb : rj.val < prime := by rw [hrj]; exact Nat.mod_lt _ (by decide)
      have hrib : ri.val < prime := by rw [hri]; exact Nat.mod_lt _ (by decide)
      step as ⟨n1, hn1, hnf⟩
      step as ⟨diff, hdiff, hdifff⟩
      step as ⟨d1, hd1, hdf⟩
      step as ⟨j1, hj1⟩
      step as ⟨a, b, ha, hb, haf, hbf⟩
      have hidxj : s.val[j.val]! = sj := by
        rw [getElem!_pos s.val j.val hlt]
        exact hsj.symm
      have hidxi : s.val[i.val]! = si := by
        rw [getElem!_pos s.val i.val hi]
        exact hsi.symm
      have hfj : field rj = point s j.val := by
        simp [field, point, hrj, hxj, hidxj]
      have hfi : field ri = point s i.val := by
        simp [field, point, hri, hxi, hidxi]
      refine ⟨ha, hb, ?_, ?_⟩
      · rw [haf, hnf, hfj, productFrom_step s i.val j.val _ hlt]
        simp only [Ne.symm hne, ↓reduceIte, hj1]
        ring
      · rw [hbf, hdf, hdifff, hfj, hfi, productFrom_step s i.val j.val _ hlt]
        simp only [Ne.symm hne, ↓reduceIte, hj1]
        ring
  · have hjeq : j.val = s.val.length := by omega
    simp [productFrom, hjeq, hn, hd]
termination_by s.val.length - j.val
decreasing_by all_goals scalar_decr_tac

private theorem denominator_nonzero (s : Slice ccf_shamir.Share) (i : Nat)
    (hi : i < s.val.length) (hs : Distinct s)
    : productFrom s i 0 (fun k => point s k - point s i) ≠ 0 := by
  apply Finset.prod_ne_zero_iff.mpr
  intro k hk
  split_ifs with heq
  · exact one_ne_zero
  · exact sub_ne_zero.mpr (hs k i (Finset.mem_Ico.mp hk).2 hi heq)

private def Ready (s : Slice ccf_shamir.Share) (w : Slice U64) (i : Nat) : Prop :=
  w.val.length = s.val.length
  ∧ ∀ k,
      k < i → (hk : k < w.val.length) → w.val[k].val < prime ∧ field w.val[k] = weight s k

@[step]
private theorem lagrange_loop_spec (s : Slice ccf_shamir.Share) (w : Slice U64)
    (i : Usize) (hi : i.val ≤ s.val.length) (hs : Distinct s)
    (hw : Ready s w i.val)
    : ccf_shamir.lagrange_loop0 s w i
      ⦃r w'
      =>
        r = core.result.Result.Ok () ∧ Ready s w' s.val.length⦄ := by
  unfold ccf_shamir.lagrange_loop0
  simp
  split
  · rename_i hlt
    step as ⟨n, d, hn, hd, hnf, hdf⟩
    have hdf' : field d ≠ 0 := by
      rw [hdf]
      simpa [field] using denominator_nonzero s i.val hlt hs
    have hdne : d ≠ 0#u64 := by
      intro h
      apply hdf'
      simp [field, h]
    simp only [hdne, ↓reduceIte]
    step as ⟨inv, hinv, hinvf⟩
    step as ⟨v, hv, hvf⟩
    have hvweight : field v = weight s i.val := by
      rw [hvf, hinvf, hnf, hdf]
      simp [weight, field, div_eq_mul_inv]
    step as ⟨w1, hw1⟩
    have hw1val : w1.val = w.val.set i.val v := by simp [hw1]
    have hw1len : w1.val.length = s.val.length := by simp [hw1val, hw.1]
    step as ⟨i1, hi1⟩
    have hready : Ready s w1 i1.val := by
      refine ⟨hw1len, ?_⟩
      intro k hk hkw
      by_cases hki : k = i.val
      · subst k
        simpa [hw1val, List.getElem_set_self] using And.intro hv hvweight
      · have hki' : k < i.val := by omega
        have old := hw.2 k hki' (by rw [hw.1]; omega)
        simpa [hw1val, List.getElem_set, hki, Ne.symm hki] using old
    step as ⟨r, w', hr, hready'⟩
    exact ⟨hr, hready'⟩
  · have heq : i.val = s.val.length := by omega
    simpa [heq] using hw
termination_by s.val.length - i.val
decreasing_by scalar_decr_tac

@[step]
theorem lagrange_spec (s : Slice ccf_shamir.Share) (w : Slice U64)
    (hne : s.val ≠ []) (hs : Distinct s) (hw : w.val.length = s.val.length)
    : ccf_shamir.lagrange s w
      ⦃r w'
      =>
        r = core.result.Result.Ok ()
          ∧ w'.val.length = s.val.length
          ∧ ∀ k,
              (hk : k < w'.val.length)
              → w'.val[k].val < prime ∧ field w'.val[k] = weight s k⦄ := by
  unfold ccf_shamir.lagrange
  step as ⟨b, hb⟩
  simp [hne] at hb
  simp [hb, hw]
  step as ⟨r, w', hr, hready⟩
  · exact ⟨hw, by simp⟩
  refine ⟨hr, hready.1, ?_⟩
  intro k hk
  exact hready.2 k (by simpa only [hready.1] using hk) hk

end CCF.Shamir
