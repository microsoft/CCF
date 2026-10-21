/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Shamir.Proofs.Arithmetic

@[expose] public section

open Aeneas Aeneas.Std Result

namespace CCF.Shamir

private theorem bit_zero (n : U64) : (n &&& 1#u64).val = n.val % 2 := by
  change (n.bv &&& (1 : BitVec 64)).toNat = n.bv.toNat % 2
  rw [BitVec.toNat_and]
  have hone : (1 : BitVec 64).toNat = 1 := by decide
  rw [hone]
  rw [Nat.and_comm, Nat.one_and_eq_mod_two]

@[step]
theorem inverse_loop_spec (x n y : U64) (hx : x.val < prime) (hy : y.val < prime)
    : ccf_shamir.inverse_loop x n y
      ⦃z
      =>
        z.val < prime ∧ field z = field y * field x ^ n.val⦄ := by
  unfold ccf_shamir.inverse_loop
  simp
  split
  · rename_i hn
    step as ⟨b, hb, _⟩
    have hb' : b.val = n.val % 2 := by rw [hb]; exact bit_zero n
    split
    · rename_i heven
      step as ⟨w, hw, hwf⟩
      step as ⟨k, hk, _⟩
      have hk' : k.val = n.val / 2 := by simpa [Nat.shiftRight_eq_div_pow] using hk
      step as ⟨z, hz, hzf⟩
      refine ⟨hz, ?_⟩
      have heq : n.val = 2 * k.val := by scalar_tac
      rw [hzf, hwf, heq, ← pow_two, ← pow_mul]
    · rename_i hodd
      step as ⟨v, hv, hvf⟩
      step as ⟨w, hw, hwf⟩
      step as ⟨k, hk, _⟩
      have hk' : k.val = n.val / 2 := by simpa [Nat.shiftRight_eq_div_pow] using hk
      step as ⟨z, hz, hzf⟩
      refine ⟨hz, ?_⟩
      have heq : n.val = 2 * k.val + 1 := by scalar_tac
      rw [hzf, hvf, hwf, heq, ← pow_two, ← pow_mul, pow_succ]
      ring
  · have hn0 : n.val = 0 := by scalar_tac
    simp [hn0, hy]
termination_by n.val
decreasing_by all_goals omega

@[step]
theorem inverse_spec (x : U64) (hx : x.val < prime) (hne : field x ≠ 0)
    : ccf_shamir.inverse x ⦃z => z.val < prime ∧ field z = (field x)⁻¹ ⦄ := by
  unfold ccf_shamir.inverse
  step as ⟨n, hn⟩
  · simp [ccf_shamir.PRIME]
  step as ⟨z, hz, hzf⟩
  refine ⟨hz, ?_⟩
  have hpow := ZMod.pow_card_sub_one_eq_one hne
  have hn' : n.val + 1 = prime - 1 := by
    norm_num [prime, ccf_shamir.PRIME] at hn ⊢
    omega
  have hmul : field x ^ n.val * field x = 1 := by
    rw [← pow_succ, hn']
    exact hpow
  have heq : field x ^ n.val = (field x)⁻¹ := by
    apply mul_right_cancel₀ hne
    rw [hmul, inv_mul_cancel₀ hne]
  have hf1 : field (1#u64) = 1 := by rfl
  rw [hf1, one_mul, heq] at hzf
  exact hzf

end CCF.Shamir
