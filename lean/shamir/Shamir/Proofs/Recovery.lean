/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Shamir.Proofs.Interpolation

@[expose] public section

open Aeneas Aeneas.Std Result
open scoped BigOperators

namespace CCF.Shamir

@[step]
private theorem recover_limb_loop_spec (s : Slice ccf_shamir.Share)
    (w : Slice U64) (limb : Usize) (y : U64) (i : Usize)
    (hl : limb.val < 10) (hi : i.val ≤ s.val.length)
    (hwl : w.val.length = s.val.length)
    (hw
      : ∀ k, (hk : k < w.val.length) → w.val[k].val < prime ∧ field w.val[k] = weight s k)
    (hy : y.val < prime)
    : ccf_shamir.recover_loop0_loop0 s w limb y i
      ⦃z
      =>
        z.val < prime
          ∧ field z
            = field y
              + ∑ k ∈ Finset.Ico i.val s.val.length, weight s k * limbValue s limb.val k
        ⦄ := by
  unfold ccf_shamir.recover_loop0_loop0
  simp
  split
  · rename_i hlt
    step as ⟨wi, hwi⟩
    step as ⟨si, hsi⟩
    step as ⟨v, hv⟩
    step as ⟨v64, hv64⟩
    step as ⟨r, hr⟩
    have hrb : r.val < prime := by rw [hr]; exact Nat.mod_lt _ (by decide)
    have hwib : wi.val < prime := by
      rw [hwi]
      exact (hw i.val (by omega)).1
    step as ⟨m, hm, hmf⟩
    step as ⟨y1, hy1, hy1f⟩
    step as ⟨i1, hi1⟩
    step as ⟨z, hz, hzf⟩
    have hidx : s.val[i.val]! = si := by
      rw [getElem!_pos s.val i.val hlt]
      exact hsi.symm
    have hval : field r = limbValue s limb.val i.val := by
      simp only [field, hr, hv64, ZMod.natCast_mod]
      simp only [limbValue, hidx]
      rw [getElem!_pos si.y.val limb.val (by simp; exact hl)]
      rw [hv]
    have hwif : field wi = weight s i.val := by
      rw [hwi]
      exact (hw i.val (by omega)).2
    refine ⟨hz, ?_⟩
    rw [hzf, hy1f, hmf, hval, hwif,
      Finset.sum_eq_sum_Ico_succ_bot hlt]
    simp only [hi1]
    ring
  · have heq : i.val = s.val.length := by omega
    simp [heq, hy]
termination_by s.val.length - i.val
decreasing_by scalar_decr_tac

@[step]
private theorem recover_limbs_loop_spec (s : Slice ccf_shamir.Share) (w : Slice U64)
    (secret : Array U32 10#usize) (limb : Usize)
    (hl : limb.val ≤ 10)
    (hwl : w.val.length = s.val.length)
    (hw
      : ∀ k, (hk : k < w.val.length) → w.val[k].val < prime ∧ field w.val[k] = weight s k)
    (hsecret
      : ∀ k,
          k < limb.val
          → (hk : k < secret.val.length) → (secret.val[k].val : F) = recoveredLimb s k)
    : ccf_shamir.recover_loop0 s w secret limb
      ⦃out
      =>
        ∀ k, (hk : k < out.val.length) → (out.val[k].val : F) = recoveredLimb s k⦄ := by
  unfold ccf_shamir.recover_loop0
  simp [ccf_shamir.LIMBS]
  split
  · rename_i hlt
    step as ⟨y, hy, hyf⟩
    step with UScalar.cast_inBounds_spec as ⟨v, hv⟩
    step as ⟨next, hnext⟩
    step as ⟨l1, hl1⟩
    have hnextval : next.val = secret.val.set limb.val v := by simp [hnext]
    have hnew : ∀ k, k < l1.val → (hk : k < next.val.length) →
        (next.val[k].val : F) = recoveredLimb s k := by
      intro k hk hkn
      by_cases heq : k = limb.val
      · subst k
        simp only [hnextval, List.getElem_set_self]
        have hf0 : field (0#u64) = 0 := rfl
        rw [hf0, zero_add, ← Finset.range_eq_Ico] at hyf
        simpa only [recoveredLimb, hv, field] using hyf
      · have hkl : k < limb.val := by omega
        have hold := hsecret k hkl (by simpa using hkn)
        simpa [hnextval, List.getElem_set, heq, Ne.symm heq] using hold
    step as ⟨out, hout⟩
    apply hout
  · have heq : limb.val = 10 := by omega
    simp only [WP.spec_ok]
    intro k hk
    exact hsecret k (by simpa [heq] using hk) (by simpa using hk)
termination_by 10 - limb.val
decreasing_by scalar_decr_tac

@[step]
theorem recover_spec (s : Slice ccf_shamir.Share) (w : Slice U64)
    (hne : s.val ≠ []) (hs : Distinct s) (hw : w.val.length = s.val.length)
    : ccf_shamir.recover s w
      ⦃r _w'
      =>
        ∃ out,
          r = core.result.Result.Ok out
          ∧ ∀ k, (hk : k < out.val.length) → (out.val[k].val : F) = recoveredLimb s k
        ⦄ := by
  unfold ccf_shamir.recover
  step as ⟨r, w1, hr, hwl, hw1⟩
  simp [hr, core.result.Result.Insts.CoreOpsTry.branch]
  step as ⟨out, hout⟩
  refine ⟨out, rfl, ?_⟩
  intro k hk
  exact hout k (by simpa using hk)

end CCF.Shamir
