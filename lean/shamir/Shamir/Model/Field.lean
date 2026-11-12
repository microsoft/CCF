-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Mathlib.NumberTheory.LucasLehmer

/-!
# The Shamir sharing field

The production implementation shares each limb over the integers modulo the Mersenne prime
`2^31 - 1`. This is also the field over which the CSLib specification is instantiated.
-/

@[expose] public section

namespace Shamir.Model

/-- The Mersenne prime used by the production implementation. -/
abbrev prime : Nat := 2147483647

/-- The common field for the extracted implementation and CSLib specification. -/
abbrev F := ZMod prime

/-- The modulus is prime, by the Lucas-Lehmer test, so `F` is a field. -/
instance : Fact (Nat.Prime prime) :=
  ⟨by
    change Nat.Prime (mersenne 31)
    exact lucas_lehmer_sufficiency 31 (by decide) (by norm_num)⟩

end Shamir.Model
