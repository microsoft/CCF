module

public import consistency.Properties.Predicates
public import CCF.Execution

import Mathlib.Tactic

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.Structural

open Model

theorem step_history_prefix (config : Config) (before after : State) (action : Action)
    (transition : step config before action = some after)
    : before.history <+: after.history := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem history_monotonic
    : forall (config : Config) (trace : CCF.Execution.Trace State),
        trace.Valid (transitionSystem config)
        -> forall (index : Nat) (before after : State),
            (trace.get? index = some before /\ trace.get? (index + 1) = some after)
            -> before.history <+: after.history := by
  intro config trace valid index before after ⟨current, next⟩
  obtain ⟨action, transition⟩ := valid.2 index before after current next
  exact step_history_prefix config before after action transition

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

theorem step_branches (config : Config) (before after : State) (action : Action)
    (transition : step config before action = some after)
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

theorem ledgers_monotonic
    : forall (config : Config) (trace : CCF.Execution.Trace State),
        trace.Valid (transitionSystem config)
        -> forall (index : Nat) (before after : State),
            (trace.get? index = some before /\ trace.get? (index + 1) = some after)
            -> forall (branch : Nat) (ledger : List Entry),
                at? before.branches branch = some ledger
                -> exists extended,
                    at? after.branches branch = some extended /\ ledger <+: extended := by
  intro config trace valid index before after ⟨current, next⟩
  obtain ⟨action, transition⟩ := valid.2 index before after current next
  exact step_branches config before after action transition

theorem step_no_invalid (config : Config) (single : config.multiNode = false)
    (before after : State) (action : Action)
    (empty : statusIDs before.history .invalid = [])
    (transition : step config before action = some after)
    : statusIDs after.history .invalid = [] := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (simp_all [appendEvent, appendEntry, statusIDs, Option.bind_eq_some_iff])
      | (solve | aesop)

theorem no_invalid_reachable (config : Config) (single : config.multiNode = false)
    {state : State} (reachable : (transitionSystem config).Reachable state)
    : statusIDs state.history .invalid = [] := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | @initial state initialized =>
      change state = initialState config at initialized
      subst state
      rfl
  | @step before after action _ transition ih =>
      exact step_no_invalid config single before after action ih transition

theorem invalid_not_observed
    : forall (config : Config) (trace : CCF.Execution.Trace State) (state : State),
        (config.multiNode = false
          /\ trace.Valid (transitionSystem config)
          /\ state ∈ trace)
        -> ∀ invalid ∈ Properties.responsesOf state.history .rw,
            ∀ observer ∈ Properties.responsesOf state.history .rw,
              invalid.1 ≠ observer.1
              -> invalid.2.txid ∈ statusIDs state.history .invalid
              -> invalid.2.tx ∉ observer.2.observed := by
  intro config trace state ⟨single, valid, member⟩ invalid _ observer _ _ invalidStatus
  have empty := no_invalid_reachable config single (valid.reachable member)
  simp [empty] at invalidStatus

end consistency.Proofs.Structural
