-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Shamir.Proofs.Outcome
public import Shamir.Proofs.Refinement

/-!
# Non-vacuity witnesses

Concrete inputs satisfying the premises of the claims in `Shamir.Properties`: a two-of-three
sharing of the polynomial `123 + 456 X`, two shares of `5 + 3 X` at coordinates one and two, and a
selection that repeats a coordinate.
-/

@[expose] public section

open Aeneas Aeneas.Std Result
open Cslib.Crypto.Protocols.SecretSharing.Shamir
open Shamir.Model Shamir.Properties

namespace Shamir.Proofs

private theorem exists_ok_of_spec {α : Type} {m : Result α} {p : α → Prop}
    (h : WP.spec m p)
    : ∃ v, m = ok v ∧ p v := by
  cases hm : m with
  | ret v => exact ⟨v, rfl, by simpa [hm] using h⟩
  | vis i k => simp [hm] at h
  | div => simp [hm] at h

/-- A share at coordinate `x` whose ten limbs all hold `y`. -/
private def uniformShare (x y : U32) : ccf_shamir.Share :=
  ⟨x, Array.repeat 10#usize y⟩

/-- Shares of `5 + 3 X` at coordinates one and two. -/
private def lineShares : Slice ccf_shamir.Share :=
  Slice.from [uniformShare 1#u32 8#u32, uniformShare 2#u32 11#u32] (by scalar_tac)

/-- Two shares at the same coordinate. -/
private def repeatedShares : Slice ccf_shamir.Share :=
  Slice.from [uniformShare 1#u32 8#u32, uniformShare 1#u32 11#u32] (by scalar_tac)

/-- A workspace with one entry for each of two shares. -/
private def twoWeights : Slice U64 :=
  Slice.from [0#u64, 0#u64] (by scalar_tac)

private theorem lineShares_distinct : Distinct lineShares := by
  intro i j hi hj hij
  simp only [lineShares, Slice.from_val, List.length_cons, List.length_nil] at hi hj
  interval_cases i <;> interval_cases j <;> simp [point, lineShares, uniformShare] at hij ⊢
  all_goals decide

/-- Public parameters for a two-of-three sharing at coordinates one, two and three. -/
private def twoOfThree : Params F (Fin 3) where
  threshold := 1
  threshold_lt_card := by simp
  point := fun i => ((i.val + 1 : ℕ) : F)
  point_injective := by decide
  point_nonzero := by decide

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
  refine ⟨
    twoOfThree,
    fun _ => 456,
    123,
    Slice.from [123#u64, 456#u64] (by scalar_tac),
    0#usize,
    Slice.from (List.replicate 3 (uniformShare 0#u32 0#u32)) (by scalar_tac),
    ⟨?_, ?_, ?_⟩,
    by simp,
    by simp,
    by simp [prime],
    by simp
  ⟩
  · simp [twoOfThree]
  · intro j hj
    simp only [Slice.from_val, List.length_cons, List.length_nil] at hj
    interval_cases j <;> simp [prime]
  · intro j hj
    simp only [Slice.from_val, List.length_cons, List.length_nil] at hj
    interval_cases j
    · simp [field, Polynomial.sharingPolynomial]
    · have htail := Polynomial.tailPolynomial_coeff (F := F) 1 (fun _ => 456) 0
      simp [field, Polynomial.sharingPolynomial, twoOfThree]
      exact htail.symm

/-- Witness: two shares can have distinct coordinates, with a workspace entry each. -/
theorem recovery_refines_cslib_witness
    : ∃ (s : Slice ccf_shamir.Share) (w : Slice U64),
        s.val ≠ [] ∧ Distinct s ∧ w.val.length = s.val.length :=
  ⟨
    lineShares,
    twoWeights,
    by simp [lineShares],
    lineShares_distinct,
    by simp [lineShares, twoWeights]
  ⟩

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
  refine ⟨
    lineShares,
    twoWeights,
    fun _ => 5,
    fun _ => _root_.Polynomial.C 3,
    by simp [lineShares],
    lineShares_distinct,
    by simp [lineShares, twoWeights],
    ?_,
    ?_
  ⟩
  · intro limb
    have htail : (_root_.Polynomial.C (3 : F)).degree < (1 : ℕ) :=
      lt_of_le_of_lt _root_.Polynomial.degree_C_le (by decide)
    have hdeg := Polynomial.degree_sharingPolynomial_lt_succ (5 : F) _ htail
    simp only [lineShares, Slice.from_val, List.length_cons, List.length_nil]
    exact_mod_cast hdeg
  · intro limb i hi
    simp only [lineShares, Slice.from_val, List.length_cons, List.length_nil] at hi
    interval_cases i <;>
      simp [limbValue, point, lineShares, uniformShare]
    all_goals fin_cases limb <;> simp <;> decide

/-- Witness: recovery from two shares at the same coordinate returns an error. -/
theorem recovery_error_preserves_secret_witness
    : ∃ (s : Slice ccf_shamir.Share) (w : Slice U64) (secret : Array U32 10#usize)
        (r : core.result.Result Unit ccf_shamir.Error) (w' : Slice U64)
        (secret' : Array U32 10#usize),
        ccf_shamir.recover s w secret = ok (r, w', secret')
        ∧ r ≠ core.result.Result.Ok () := by
  obtain ⟨⟨r, w', secret'⟩, hok, hiff⟩ :=
    exists_ok_of_spec
      (recovery_succeeds_iff repeatedShares twoWeights (Array.repeat 10#usize 0#u32))
  refine ⟨repeatedShares, twoWeights, _, r, w', secret', hok, ?_⟩
  intro hr
  simp only [WP.uncurry'_pair] at hiff
  exact (hiff.mp hr).2.2 0 1 (by simp [repeatedShares]) (by simp [repeatedShares])
    (by decide) (by simp [point, repeatedShares, uniformShare])

end Shamir.Proofs
