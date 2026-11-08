module

@[expose] public section

/-!
# Order dot notation

Dot-notation aliases for core `Nat` order lemmas, covering the part of Mathlib's
`LE.le.trans`, `LT.lt.le`, `Eq.ge`, ... that the proofs use. They are stated for
`Nat` only, the one ordered type the proofs chain inequalities over.

As in Mathlib, `≤`, `<+:` and `<:+` are reflexive for the `rfl` tactic, which `rw` also
tries after rewriting.
-/

attribute [refl] Nat.le_refl List.prefix_refl List.suffix_refl

namespace LE.le

theorem trans {a b c : Nat} (h : a ≤ b) (h' : b ≤ c) : a ≤ c := Nat.le_trans h h'

theorem trans_lt {a b c : Nat} (h : a ≤ b) (h' : b < c) : a < c := Nat.lt_of_le_of_lt h h'

end LE.le

namespace LT.lt

theorem le {a b : Nat} (h : a < b) : a ≤ b := Nat.le_of_lt h

theorem trans {a b c : Nat} (h : a < b) (h' : b < c) : a < c := Nat.lt_trans h h'

theorem trans_le {a b c : Nat} (h : a < b) (h' : b ≤ c) : a < c := Nat.lt_of_lt_of_le h h'

theorem ne {a b : Nat} (h : a < b) : a ≠ b := Nat.ne_of_lt h

theorem ne' {a b : Nat} (h : a < b) : b ≠ a := Nat.ne_of_gt h

theorem not_le {a b : Nat} (h : a < b) : ¬b ≤ a := Nat.not_le_of_gt h

end LT.lt

namespace Eq

theorem le {a b : Nat} (h : a = b) : a ≤ b := Nat.le_of_eq h

theorem ge {a b : Nat} (h : a = b) : b ≤ a := Nat.le_of_eq h.symm

end Eq

namespace CCF

theorem max_choice (a b : Nat) : max a b = a ∨ max a b = b := by
  rw [Nat.max_def]
  split
  · exact Or.inr rfl
  · exact Or.inl rfl

theorem le_or_gt (a b : Nat) : a ≤ b ∨ b < a := (Nat.lt_or_ge b a).symm

end CCF
