module

public import CCF.WitnessedTheorem

public section

namespace CCF.Tests.WitnessedTheorem

/-- The README example. -/
theorem zero_add
    : CCF.WitnessedTheorem
        (requires := fun n : Nat => n = 0)

        (ensures := fun n => 0 + n = n)

        (witness_satisfies := fun n => n < 1) where

  proof := by
    intro n _
    exact Nat.zero_add n

  witness_proof := by exact ⟨0, rfl, by decide⟩

example : forall n : Nat, n = 0 -> 0 + n = n := zero_add.proof

example : exists n : Nat, n = 0 /\ n < 1 := zero_add.witness_proof

/-- Omitting the extra predicate requires only an applicable case. -/
theorem zero_add_without_extra
    : CCF.WitnessedTheorem
        (requires := fun _ : Nat => True)

        (ensures := fun n => 0 + n = n) where

  proof := by
    intro n _
    exact Nat.zero_add n

  witness_proof := by exact ⟨0, trivial, trivial⟩

example : exists _ : Nat, True := by
  obtain ⟨n, applicable, _⟩ := zero_add_without_extra.witness_proof
  exact ⟨n, applicable⟩

/-- A sigma type bundles dependent parameters without a separate case record. -/
theorem dependent_safety
    : CCF.WitnessedTheorem
        (Case := (size : Nat) × Fin (size + 1) × Fin (size + 1))

        (requires := fun ⟨size, left, _⟩ => left.val = size)

        (ensures :=
          fun ⟨size, left, right⟩ => left.val < size + 1 /\ right.val < size + 1)

        (witness_satisfies := fun ⟨size, left, right⟩ => size = 2 /\ left ≠ right) where

  proof := by
    intro ⟨_, left, right⟩ _
    exact ⟨left.isLt, right.isLt⟩

  witness_proof := by exact ⟨⟨2, ⟨2, by decide⟩, ⟨0, by decide⟩⟩, rfl, rfl, by decide⟩

-- The universal proof also covers cases that fail the extra witness predicate.
example : (0 : Nat) < 1 /\ (0 : Nat) < 1 :=
  dependent_safety.proof ⟨0, ⟨0, by decide⟩, ⟨0, by decide⟩⟩ rfl

example
    : exists c : (size : Nat) × Fin (size + 1) × Fin (size + 1),
        c.2.1.val = c.1 /\ (c.1 = 2 /\ c.2.1 ≠ c.2.2) :=
  dependent_safety.witness_proof

end CCF.Tests.WitnessedTheorem
