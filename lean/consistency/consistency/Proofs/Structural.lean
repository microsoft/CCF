module

public import consistency.Properties.History
public import CCF.Execution

import Mathlib.Tactic

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.Structural

open Model

def BranchExtension (before after : List (List Entry)) : Prop :=
  ∀ index ledger,
    at? before index = some ledger
    → ∃ extended, at? after index = some extended ∧ ledger <+: extended

theorem branches_refl (branches : List (List Entry))
    : BranchExtension branches branches := by
  intro index ledger found
  exact ⟨ledger, found, List.prefix_refl _⟩

theorem branches_modify (branches : List (List Entry)) (position : Nat) (entry : Entry)
    : BranchExtension branches (branches.modify position (· ++ [entry])) := by
  intro index ledger found
  have nonzero : index ≠ 0 := by
    rintro rfl
    simp [at?] at found
  have lookup : branches[index - 1]? = some ledger := by simpa [at?, nonzero] using found
  by_cases same : position = index - 1
  · refine ⟨ledger ++ [entry], ?_, by simp⟩
    simp [at?, nonzero, List.getElem?_modify, lookup, same]
  · refine ⟨ledger, ?_, List.prefix_refl _⟩
    simp [at?, nonzero, List.getElem?_modify, lookup, same]

theorem branches_append (branches extra : List (List Entry))
    : BranchExtension branches (branches ++ extra) := by
  intro index ledger found
  have nonzero : index ≠ 0 := by
    rintro rfl
    simp [at?] at found
  have lookup : branches[index - 1]? = some ledger := by simpa [at?, nonzero] using found
  refine ⟨ledger, ?_, List.prefix_refl _⟩
  simp [at?, nonzero, List.getElem?_append_left (List.getElem?_eq_some_iff.mp lookup).1,
    lookup]

theorem step_branches (before after : State) (action : Action)
    (transition : step before action = some after)
    : BranchExtension before.branches after.branches := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact branches_refl _)
      | (exact branches_modify _ _ _)
      | (exact branches_append _ _)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

end consistency.Proofs.Structural
