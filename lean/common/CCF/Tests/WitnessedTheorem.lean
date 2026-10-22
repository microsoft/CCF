module

public import CCF.WitnessedTheorem

open Lean Elab Command

namespace CCF.Tests.WitnessedTheorem.Private

/-- The example without an extra witness condition, under default private visibility. -/
witnessed_theorem zero_add
  for (n : Nat)
requires n = 0
ensures 0 + n = n
  proof :=
  by
    intro n _
    exact Nat.zero_add n
  witness_proof := by exact ⟨0, rfl⟩

example : ∃ n : Nat, n = 0 := zero_add_witness

run_cmd do
  for name in #[``zero_add, ``zero_add_witness] do
    unless (← findDeclarationRanges? name).isSome do
      throwError "Missing navigation for private declaration {name}"
    if (← getEnv).contains (privateToUserName name) then
      throwError "Expected default module-private declaration {name}"

end CCF.Tests.WitnessedTheorem.Private

public section

namespace CCF.Tests.WitnessedTheorem

/-- Grouped dependent parameters and the witness condition share the same scope. -/
witnessed_theorem dependent_safety
  for (size : Nat) (left right : Fin (size + 1))
requires left.val = size
ensures left.val < size + 1 ∧ right.val < size + 1
  witness_satisfies size = 2 ∧ left ≠ right
  proof :=
  by
    intro size left right _
    exact ⟨left.isLt, right.isLt⟩
  witness_proof := by exact ⟨2, ⟨2, by decide⟩, ⟨0, by decide⟩, rfl, rfl, by decide⟩

example
    : ∀ (size : Nat) (left right : Fin (size + 1)),
        left.val = size → left.val < size + 1 ∧ right.val < size + 1 :=
  dependent_safety

example
    : ∃ (size : Nat) (left right : Fin (size + 1)),
        left.val = size ∧ (size = 2 ∧ left ≠ right) :=
  dependent_safety_witness

/-- The README example, also used to inspect the formatter's layout. -/
witnessed_theorem zero_add
  for (n : Nat)
requires n = 0
ensures 0 + n = n
  witness_satisfies n < 1
  proof :=
  by
    intro n _
    exact Nat.zero_add n
  witness_proof := by exact ⟨0, rfl, by decide⟩

example : ∃ n : Nat, n = 0 ∧ n < 1 := zero_add_witness

-- Both ordinary declarations navigate to the same command and theorem name token.
run_cmd do
  let env ← getEnv
  for (safetyName, witnessName) in #[
      (``dependent_safety, ``dependent_safety_witness),
      (``zero_add, ``zero_add_witness)] do
    for name in #[safetyName, witnessName] do
      unless (env.find? name).any (fun info => info matches .thmInfo _) do
        throwError "Not an ordinary theorem: {name}"
      unless (← findDocString? env name).isSome do
        throwError "Missing documentation: {name}"
    let some a ← findDeclarationRanges? safetyName
      | throwError "Missing safety navigation"
    let some b ← findDeclarationRanges? witnessName
      | throwError "Missing witness navigation"
    unless a.range == b.range && a.selectionRange == b.selectionRange do
      throwError "Expected shared declaration and selection ranges"
    let fileMap ← getFileMap
    for selection in #[a.selectionRange, b.selectionRange] do
      let start := fileMap.ofPosition selection.pos
      let stop := fileMap.ofPosition selection.endPos
      unless start.extract fileMap.source stop == safetyName.getString! do
        throwError "Selection range does not select the theorem name token"

/-- error: `CCF.Tests.WitnessedTheorem.zero_add` has already been declared -/
#guard_msgs in
witnessed_theorem zero_add
  for (value : Nat)
requires value = 0
  ensures True
  proof := by intros; trivial
  witness_proof := by exact ⟨0, rfl⟩

/-- An existing witness name must prevent either declaration from being generated. -/
theorem fresh_safety_witness : True := True.intro

/-- error: `CCF.Tests.WitnessedTheorem.fresh_safety_witness` has already been declared -/
#guard_msgs in
witnessed_theorem fresh_safety
  for (value : Nat)
requires value = 0
  ensures True
  proof := by intros; trivial
  witness_proof := by exact ⟨0, rfl⟩

run_cmd do
  if (← getEnv).contains `CCF.Tests.WitnessedTheorem.fresh_safety then
    throwError "A witness name collision left a partial safety declaration"

/--
error: Type mismatch
  True.intro
has type
  True
but is expected to have type
  ∃ value, value = 0
-/
#guard_msgs in
run_cmd withoutModifyingEnv do
  elabCommand (← `(command|
    witnessed_theorem invalid_witness_safety
      for (value : Nat)
      requires value = 0
      ensures True
      proof := by intros; trivial
      witness_proof := True.intro))

/--
error: Type mismatch
  True.intro
has type
  True
but is expected to have type
  ∀ (value : Nat), value = 0 → False
-/
#guard_msgs in
run_cmd withoutModifyingEnv do
  elabCommand (← `(command|
    witnessed_theorem invalid_safety
      for (value : Nat)
      requires value = 0
      ensures False
      proof := True.intro
      witness_proof := by exact ⟨0, rfl⟩))

/-- error: witnessed_theorem requires a simple declaration name -/
#guard_msgs in
witnessed_theorem Nested.safety
  for (value : Nat)
requires value = 0
  ensures True
  proof := by intros; trivial
  witness_proof := by exact ⟨0, rfl⟩

/-- error: witnessed_theorem parameter types cannot contain placeholders -/
#guard_msgs in
witnessed_theorem inferred_domain
  for (value : _)
requires value = 0
ensures value + (0 : Int) = value
  proof := by intro value _; exact Int.add_zero value
  witness_proof := by exact ⟨0, rfl⟩

end CCF.Tests.WitnessedTheorem
