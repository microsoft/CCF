-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

import CCF.Witnessed

/-!
# Checks of `witnessed%`

The statements `witnessed%` produces, as `#check` displays them, and its errors on
unsupported input.
-/

namespace CCF.Tests.Witnessed

theorem less : witnessed% forall (n m : Nat), { pre := n < m, post := n ≠ m } :=
  ⟨fun _ _ less => Nat.ne_of_lt less, 0, 1, Nat.zero_lt_one⟩

/-- info: CCF.Tests.Witnessed.less : Witnessed (∀ (n m : Nat), n < m → n ≠ m) (∃ n m, n < m) -/
#guard_msgs in
#check less

theorem less_zero
    : witnessed% forall (n m : Nat), { pre := n < m, post := n ≠ m, witness := n = 0 } :=
  ⟨fun _ _ less => Nat.ne_of_lt less, 0, 1, Nat.zero_lt_one, rfl⟩

/--
info: CCF.Tests.Witnessed.less_zero : Witnessed (∀ (n m : Nat), n < m → n ≠ m) (∃ n m, n < m ∧ n = 0)
-/
#guard_msgs in
#check less_zero

theorem conjoined
    : witnessed% forall (n m : Nat),
                  { pre := 0 < n /\ n < m /\ m < 5, post := n ≠ m, witness := m = 2 } :=
  ⟨fun _ _ ordered => Nat.ne_of_lt ordered.2.1, 1, 2, by decide⟩

/--
info: CCF.Tests.Witnessed.conjoined :
  Witnessed (∀ (n m : Nat), 0 < n ∧ n < m ∧ m < 5 → n ≠ m) (∃ n m, 0 < n ∧ n < m ∧ m < 5 ∧ m = 2)
-/
#guard_msgs in
#check conjoined

theorem less_each
    : forall (n : Nat),
        n < 100
        -> witnessed% forall (m : Nat),
                        { pre := n < m, post := n ≠ m, witness := m = n + 1 } :=
  fun n _ => ⟨fun _ less => Nat.ne_of_lt less, n + 1, Nat.lt_succ_self n, rfl⟩

/--
info: CCF.Tests.Witnessed.less_each (n : Nat) : n < 100 → Witnessed (∀ (m : Nat), n < m → n ≠ m) (∃ m, n < m ∧ m = n + 1)
-/
#guard_msgs in
#check less_each

theorem unbracketed : witnessed% forall n m : Nat, { post := n ≠ m, pre := n < m } :=
  ⟨fun _ _ less => Nat.ne_of_lt less, 0, 1, Nat.zero_lt_one⟩

/--
info: CCF.Tests.Witnessed.unbracketed : Witnessed (∀ (n m : Nat), n < m → n ≠ m) (∃ n m, n < m)
-/
#guard_msgs in
#check unbracketed

theorem dependent
    : witnessed% forall (n : Nat) (i : Fin n), { pre := i.val < 3, post := i.val < n } :=
  ⟨fun _ i _ => i.isLt, 1, 0, by decide⟩

/--
info: CCF.Tests.Witnessed.dependent : Witnessed (∀ (n : Nat) (i : Fin n), ↑i < 3 → ↑i < n) (∃ n i, ↑i < 3)
-/
#guard_msgs in
#check dependent

/-- error: expected `forall xs, spec` -/
#guard_msgs in
example : witnessed% 0 < 1 := trivial

/-- error: expected explicit binders, of the form `(x : T)` -/
#guard_msgs in
example : witnessed% forall {n : Nat}, { pre := 0 < n, post := 0 ≤ n } := trivial

/-- error: expected the fields of a `Witnessed.Spec`, in braces -/
#guard_msgs in
example (spec : Witnessed.Spec) : witnessed% forall (_ : Nat), spec := trivial

end CCF.Tests.Witnessed
