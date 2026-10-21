/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Shamir.Model
public import Mathlib.Tactic.Linarith

@[expose] public section

open Aeneas Aeneas.Std Result

namespace CCF.Shamir

@[step]
theorem widen_spec (x : U32)
    : lift (core.convert.num.FromU64U32.from x) ⦃y => y.val = x.val⦄ := by
  change lift (UScalar.cast .U64 x) ⦃ y => y.val = x.val ⦄
  step with UScalar.cast_inBounds_spec as ⟨y, hy⟩
  exact hy

private theorem reduction_bounds (n : Nat) (hn : n < 18446744073709551616)
    : let d := n / 2147483648
      let a := n - d * prime
      let e := a / 2147483648
      let b := a - e * prime
      let f := (b + 1) / 2147483648
      d * prime ≤ n
      ∧ d * prime ≤ 18446744073709551615
      ∧ e * prime ≤ a
      ∧ e * prime ≤ 18446744073709551615
      ∧ b + 1 ≤ 18446744073709551615
      ∧ f * prime ≤ b
      ∧ f * prime ≤ 18446744073709551615
      ∧ b - f * prime < prime
      ∧ n = (b - f * prime) + (d + e + f) * prime := by
  dsimp [prime]
  omega

@[step]
theorem reduce_spec (x : U64) : ccf_shamir.reduce x ⦃y => y.val = x.val % prime⦄ := by
  have h := reduction_bounds x.val x.lt_succ_max
  dsimp at h
  have hmod :
      x.val % prime =
        (x.val - x.val / 2147483648 * prime) -
          (x.val - x.val / 2147483648 * prime) / 2147483648 * prime -
          (((x.val - x.val / 2147483648 * prime) -
            (x.val - x.val / 2147483648 * prime) / 2147483648 * prime + 1) /
            2147483648) * prime := by
    conv_lhs => rw [h.2.2.2.2.2.2.2.2]
    simp [Nat.add_mod, Nat.mod_eq_of_lt h.2.2.2.2.2.2.2.1]
  rcases h with ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8⟩
  clear h8
  simp only [prime] at *
  unfold ccf_shamir.reduce
  step as ⟨d, hd, _⟩
  have hd' : d.val = x.val / 2147483648 := by simpa [Nat.shiftRight_eq_div_pow] using hd
  step as ⟨a, ha⟩
  · simp [ccf_shamir.PRIME]
    scalar_tac
  step as ⟨b, hb⟩
  · simp [ccf_shamir.PRIME] at *
    scalar_tac
  step as ⟨e, he, _⟩
  have he' : e.val = b.val / 2147483648 := by simpa [Nat.shiftRight_eq_div_pow] using he
  step as ⟨f, hf⟩
  · simp [ccf_shamir.PRIME] at *
    scalar_tac
  step as ⟨g, hg⟩
  · simp [ccf_shamir.PRIME] at *
    scalar_tac
  step as ⟨k, hk⟩
  · simp [ccf_shamir.PRIME] at *
    scalar_tac
  step as ⟨l, hl, _⟩
  have hl' : l.val = k.val / 2147483648 := by simpa [Nat.shiftRight_eq_div_pow] using hl
  step as ⟨m, hm⟩
  · simp [ccf_shamir.PRIME] at *
    scalar_tac
  step as ⟨r, hr⟩
  · simp [ccf_shamir.PRIME] at *
    scalar_tac
  simp [ccf_shamir.PRIME] at *
  scalar_tac

@[step]
theorem mul_spec (x y : U64) (hx : x.val < prime) (hy : y.val < prime)
    : ccf_shamir.mul x y ⦃z => z.val < prime ∧ field z = field x * field y⦄ := by
  unfold ccf_shamir.mul
  step as ⟨v, hv⟩
  step as ⟨z, hz⟩
  simp only [field, hz, hv]
  constructor
  · exact Nat.mod_lt _ (by decide)
  · simp

@[step]
theorem add_spec (x y : U64) (hx : x.val < prime) (hy : y.val < prime)
    : ccf_shamir.add x y ⦃z => z.val < prime ∧ field z = field x + field y⦄ := by
  unfold ccf_shamir.add
  step as ⟨v, hv⟩
  step as ⟨z, hz⟩
  simp only [field, hz, hv]
  constructor
  · exact Nat.mod_lt _ (by decide)
  · simp

@[step]
theorem sub_spec (x y : U64) (hx : x.val < prime) (hy : y.val < prime)
    : ccf_shamir.sub x y ⦃z => z.val < prime ∧ field z = field x - field y⦄ := by
  unfold ccf_shamir.sub
  step as ⟨v, hv⟩
  · simp [ccf_shamir.PRIME, U64.max_eq]
    dsimp [prime] at hx
    omega
  step as ⟨w, hw⟩
  · simp [ccf_shamir.PRIME] at hv
    dsimp [prime] at hy
    omega
  step as ⟨z, hz⟩
  constructor
  · rw [hz]
    exact Nat.mod_lt _ (by decide)
  · simp only [field, hz]
    rw [ZMod.natCast_mod, hw, Nat.cast_sub (by
      simp [ccf_shamir.PRIME] at hv
      dsimp [prime] at hy
      omega)]
    simp [hv, ccf_shamir.PRIME, prime]

end CCF.Shamir
