/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Shamir.Proofs.Evaluation

@[expose] public section

open Aeneas Aeneas.Std Result

namespace CCF.Shamir

/-- The share at index `k` holds the polynomial value at coordinate `k + 1` in `limb`. -/
def FilledLimb (c : Slice U64) (limb : Nat) (s : Slice ccf_shamir.Share) (k : Nat)
    : Prop :=
  s.val[k]!.x.val = k + 1
  ∧ s.val[k]!.y.val[limb]!.val < prime
  ∧ (s.val[k]!.y.val[limb]!.val : F) = polynomialPrefix c c.val.length ((k + 1 : Nat) : F)

/-- Every limb other than `limb` of the share at index `k` is unchanged. -/
def OtherLimbsUnchanged (limb : Nat) (s s' : Slice ccf_shamir.Share) (k : Nat) : Prop :=
  ∀ m, m ≠ limb → s'.val[k]!.y.val[m]! = s.val[k]!.y.val[m]!

/-- The shares below index `i` are unchanged. -/
def PrefixUnchanged (s s' : Slice ccf_shamir.Share) (i : Nat) : Prop :=
  ∀ k, k < i → s'.val[k]! = s.val[k]!

private theorem getElem!_set_self_share (l : List ccf_shamir.Share) (i : Nat)
    (hi : i < l.length) (v : ccf_shamir.Share)
    : (l.set i v)[i]! = v := by
  rw [getElem!_pos (l.set i v) i (by simpa using hi)]
  exact List.getElem_set_self _

private theorem getElem!_set_ne_share (l : List ccf_shamir.Share) (i k : Nat)
    (hk : k < l.length) (hne : i ≠ k) (v : ccf_shamir.Share)
    : (l.set i v)[k]! = l[k]! := by
  rw [getElem!_pos (l.set i v) k (by simpa using hk), getElem!_pos l k hk]
  exact List.getElem_set_ne hne _

private theorem getElem!_set_ne_u32 (l : List U32) (i k : Nat) (hne : i ≠ k) (v : U32)
    : (l.set i v)[k]! = l[k]! := by
  by_cases hk : k < l.length
  · rw [getElem!_pos (l.set i v) k (by simpa using hk), getElem!_pos l k hk]
    exact List.getElem_set_ne hne _
  · rw [getElem!_neg (l.set i v) k (by simpa using hk), getElem!_neg l k hk]

@[step]
private theorem share_limb_loop_spec (c : Slice U64) (limb : Usize)
    (s : Slice ccf_shamir.Share) (i : Usize)
    (hl : limb.val < 10) (hlen : s.val.length < prime) (hi : i.val ≤ s.val.length)
    (hne : c.val ≠ [])
    (hc : ∀ j, (hj : j < c.val.length) → c.val[j].val < prime)
    : ccf_shamir.share_limb_loop c limb s i
      ⦃r s'
      =>
        r = core.result.Result.Ok ()
          ∧ s'.val.length = s.val.length
          ∧ PrefixUnchanged s s' i.val
          ∧ ∀ k,
              i.val ≤ k
              → k < s.val.length
              → FilledLimb c limb.val s' k ∧ OtherLimbsUnchanged limb.val s s' k
        ⦄ := by
  have hpv : prime = 2147483647 := rfl
  unfold ccf_shamir.share_limb_loop
  simp
  split
  · rename_i hlt
    step as ⟨i2, hi2⟩
    have hi2b : i2.val ≤ UScalar.max .U32 := by
      simp only [UScalar.max, UScalarTy.U32_numBits_eq]
      omega
    step with UScalar.cast_inBounds_spec as ⟨x, hx⟩
    step as ⟨r, y, hr, hy, hyf⟩
    simp only [hr, core.result.Result.Insts.CoreOpsTry.branch]
    step as ⟨sh, back, hsh, hback⟩
    simp only [hback]
    step as ⟨sh1, back1, hsh1, hback1⟩
    have hsh1v : sh1 = { sh with x := x } := by
      rw [hsh1]
      simp only [Slice.set_val_eq, List.getElem_set_self]
    step as ⟨a, ha⟩
    simp only [hback1]
    have hlen2
        : ((s.set i { sh with x := x }).set i { sh1 with y := a }).val.length
          = s.val.length := by
      simp [Slice.set_val_eq]
    have hlen2' : ((s.set i { sh with x := x }).set i { sh1 with y := a }).val.length < prime := by
      rw [hlen2]; exact hlen
    have hi2' : i2.val ≤ ((s.set i { sh with x := x }).set i { sh1 with y := a }).val.length := by
      rw [hlen2]; omega
    step as ⟨r', s', hr', hlen', hpre, hpost⟩
    unfold PrefixUnchanged at hpre
    have hs2
        : ∀ k,
            k < s.val.length
            → k ≠ i.val
            → ((s.set i { sh with x := x }).set i { sh1 with y := a }).val[k]! = s.val[k]! := by
      intro k hk hki
      simp only [Slice.set_val_eq]
      rw [getElem!_set_ne_share _ i.val k (by simpa using hk) (Ne.symm hki)]
      rw [getElem!_set_ne_share _ i.val k hk (Ne.symm hki)]
    have hs2i
        : ((s.set i { sh with x := x }).set i { sh1 with y := a }).val[i.val]!
          = { sh1 with y := a } := by
      simp only [Slice.set_val_eq]
      exact getElem!_set_self_share _ i.val (by simpa using hlt) _
    refine ⟨hr', by rw [hlen', hlen2], ?_, ?_⟩
    · intro k hk
      rw [hpre k (by omega)]
      exact hs2 k (by omega) (by omega)
    · intro k hik hk
      by_cases hki : k = i.val
      · subst hki
        unfold FilledLimb OtherLimbsUnchanged
        rw [hpre i.val (by omega), hs2i]
        have hyidx : (sh1.y.val.set limb.val y)[limb.val]! = y := by
          rw [getElem!_pos _ limb.val (by simpa using hl)]
          exact List.getElem_set_self _
        refine ⟨⟨?_, ?_, ?_⟩, ?_⟩
        · simp only [hsh1v]
          rw [hx, hi2]
        · simp only [ha, Array.set_val_eq, hyidx]
          exact hy
        · simp only [ha, Array.set_val_eq, hyidx]
          rw [hyf, hx, hi2]
        · intro m hm
          simp only [ha, Array.set_val_eq, hsh1v]
          rw [getElem!_set_ne_u32 _ limb.val m (Ne.symm hm)]
          rw [hsh, getElem!_pos s.val i.val hlt]
      · have hik' : i2.val ≤ k := by omega
        obtain ⟨hfilled, hother⟩ := hpost k hik' (by rw [hlen2]; exact hk)
        refine ⟨hfilled, ?_⟩
        unfold OtherLimbsUnchanged at hother ⊢
        intro m hm
        rw [hother m hm, hs2 k hk hki]
  · have heq : i.val = s.val.length := by omega
    simp only [WP.spec_ok]
    refine ⟨rfl, rfl, fun k _ => rfl, ?_⟩
    intro k hik hk
    omega
termination_by s.val.length - i.val
decreasing_by scalar_decr_tac

@[step]
theorem share_limb_spec (c : Slice U64) (limb : Usize) (s : Slice ccf_shamir.Share)
    (hl : limb.val < 10) (hne : s.val ≠ []) (hlen : s.val.length < prime)
    (hcne : c.val ≠ []) (hct : c.val.length ≤ s.val.length)
    (hc : ∀ j, (hj : j < c.val.length) → c.val[j].val < prime)
    : ccf_shamir.share_limb c limb s
      ⦃r s'
      =>
        r = core.result.Result.Ok ()
          ∧ s'.val.length = s.val.length
          ∧ ∀ k,
              k < s.val.length
              → FilledLimb c limb.val s' k ∧ OtherLimbsUnchanged limb.val s s' k
        ⦄ := by
  have hprime : ccf_shamir.PRIME.val ≤ UScalar.max .Usize := by
    rw [UScalar.max_USize_eq]
    rcases Usize.bounds_eq with h | h <;> rw [h] <;>
      simp [ccf_shamir.PRIME, U32.max, U64.max, U32.numBits, U64.numBits]
  unfold ccf_shamir.share_limb
  simp only [ccf_shamir.LIMBS]
  split
  · rename_i h
    exfalso
    scalar_tac
  · step as ⟨b, hb⟩
    simp [hne] at hb
    simp only [hb, Bool.false_eq_true, ↓reduceIte]
    step with UScalar.cast_inBounds_spec as ⟨p, hp⟩
    have hp' : p.val = prime := by rw [hp]; simp [ccf_shamir.PRIME, prime]
    split
    · rename_i h
      exfalso
      scalar_tac
    · step as ⟨b1, hb1⟩
      simp [hcne] at hb1
      simp only [hb1, Bool.false_eq_true, ↓reduceIte]
      split
      · rename_i h
        exfalso
        scalar_tac
      · step as ⟨r, s', hr, hlen', _, hpost⟩
        refine ⟨hr, hlen', ?_⟩
        intro k hk
        exact hpost k (Nat.zero_le k) hk

end CCF.Shamir
