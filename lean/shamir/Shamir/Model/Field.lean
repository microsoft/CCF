/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Mathlib.NumberTheory.LucasLehmer

@[expose] public section

namespace CCF.Shamir

/-- The Mersenne prime used by the production implementation. -/
abbrev prime : Nat := 2147483647

/-- The common field for the extracted implementation and CSLib specification. -/
abbrev F := ZMod prime

instance : Fact (Nat.Prime prime) :=
  ⟨by
    change Nat.Prime (mersenne 31)
    exact lucas_lehmer_sufficiency 31 (by decide) (by norm_num)⟩

end CCF.Shamir
