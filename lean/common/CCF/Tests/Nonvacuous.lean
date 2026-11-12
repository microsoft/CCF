-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

import CCF.Nonvacuous

/-!
# Checks of `nonvacuous%`

The statements `nonvacuous%` produces, as `#check` displays them, and its errors on
unsupported input.
-/

namespace CCF.Tests.Nonvacuous

theorem less : ∀ (n m : Nat), n < m → n ≠ m := fun _ _ less => Nat.ne_of_lt less

theorem less_witness : nonvacuous% less := ⟨0, 1, Nat.zero_lt_one⟩

/-- info: CCF.Tests.Nonvacuous.less_witness : ∃ n m, n < m -/
#guard_msgs in
#check less_witness

theorem less_zero_witness : nonvacuous% less /\ n = 0 := ⟨0, 1, Nat.zero_lt_one, rfl⟩

/-- info: CCF.Tests.Nonvacuous.less_zero_witness : ∃ n m, n < m ∧ n = 0 -/
#guard_msgs in
#check less_zero_witness

theorem less_each_witness : ∀ (n : Nat), n < 100 → nonvacuous% less n /\ m = n + 1 :=
  fun n _ => ⟨n + 1, Nat.lt_succ_self n, rfl⟩

/--
info: CCF.Tests.Nonvacuous.less_each_witness (n : Nat) : n < 100 → ∃ m, n < m ∧ m = n + 1
-/
#guard_msgs in
#check less_each_witness

theorem conjoined : ∀ (n m : Nat), (0 < n /\ n < m) → m < 5 → n ≠ m :=
  fun _ _ ⟨_, less⟩ _ => Nat.ne_of_lt less

theorem conjoined_witness : nonvacuous% conjoined /\ m = 2 :=
  ⟨1, 2, Nat.zero_lt_one, by decide, by decide, rfl⟩

/-- info: CCF.Tests.Nonvacuous.conjoined_witness : ∃ n m, 0 < n ∧ n < m ∧ m < 5 ∧ m = 2 -/
#guard_msgs in
#check conjoined_witness

theorem no_hypothesis : ∀ (n : Nat), 0 ≤ n := Nat.zero_le

/-- error: no_hypothesis has no hypothesis to witness -/
#guard_msgs (error) in
example : nonvacuous% no_hypothesis := trivial

theorem unused_variable : 0 < 1 → Empty → True → False := fun _ empty => nomatch empty

/-- error: unused_variable binds an unused variable of type Empty -/
#guard_msgs (error) in
example : nonvacuous% unused_variable := trivial

theorem late_variable : ∀ (n : Nat), 0 < n → ∀ (m : Nat), n < m → n ≠ m :=
  fun _ _ _ less => Nat.ne_of_lt less

/-- error: late_variable binds a variable after a hypothesis -/
#guard_msgs (error) in
example : nonvacuous% late_variable := trivial

/-- error: less has no variable for this argument -/
#guard_msgs (error) in
example : nonvacuous% less 0 1 Nat.zero_lt_one := trivial

theorem implicit : ∀ {n : Nat} (m : Nat), n < m → n ≠ m := fun _ less => Nat.ne_of_lt less

/-- error: implicit has no explicit variable for this argument -/
#guard_msgs (error) in
example : nonvacuous% implicit 0 := trivial

/-- error: less binds `m`, which would hide the outer `m` -/
#guard_msgs (error) in
example : ∀ (m : Nat), nonvacuous% less 0 /\ m = m := trivial

/-- error: expected a theorem, optionally followed by `/\ ..` -/
#guard_msgs (error) in
example : nonvacuous% 0 < 1 /\ less := trivial

end CCF.Tests.Nonvacuous
