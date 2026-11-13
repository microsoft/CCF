-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.TraceValidation.System
public import CCF.Execution

@[expose] public section

namespace Kv.Proofs.Correspondence

open Kv.TraceValidation

private theorem bind_ok {α β : Type} {value : Except Failure α}
    {f : α → Except Failure β} {b : β} (h : value.bind f = .ok b)
    : ∃ a, value = .ok a ∧ f a = .ok b := by
  cases value with
  | error => cases h
  | ok a => exact ⟨a, rfl, h⟩

private theorem pure_ok {α : Type} {a b : α} (h : (pure a : Except Failure α) = .ok b)
    : a = b := by
  cases h
  rfl

private theorem expect_ok {condition : Bool} {message : String} {u : Unit}
    (h : expect condition message = .ok u)
    : condition = true := by
  cases condition
  · cases h
  · rfl

/-- Installing semantic state and erasing decorations is the identity. -/
theorem lift_projects (w : World) (semantic : Model.State)
    : project (liftState w semantic) = semantic := by
  cases semantic
  simp [project, liftState, List.map_map, Function.comp_def]

/-- An accepted event is a guarded, reported semantic execution followed by metadata lifting. -/
theorem event_checked {w next : World} {event : Event}
    (accepted : stepEvent w event = .ok next)
    : ∃ semantic output,
        guardEvent w event = .ok ()
        ∧ executeActions (project w) (actions w event) = some (semantic, output)
        ∧ reportedMatches event output = true
        ∧ next = liftState (metadata w event output) semantic := by
  obtain ⟨u, guarded, accepted⟩ := bind_ok accepted
  cases u
  dsimp only at accepted
  cases executed : executeActions (project w) (actions w event) with
  | none =>
      simp only [executed] at accepted
      obtain ⟨_, invalid, _⟩ := bind_ok accepted
      cases invalid
  | some pair =>
      obtain ⟨semantic, output⟩ := pair
      simp only [executed] at accepted
      obtain ⟨selected, selectedOk, accepted⟩ := bind_ok accepted
      cases pure_ok selectedOk
      obtain ⟨_, reported, accepted⟩ := bind_ok accepted
      exact ⟨semantic, output, guarded, rfl, expect_ok reported, (pure_ok accepted).symm⟩

/-- Sequence/count bookkeeping follows an accepted event without changing its semantic result. -/
theorem record_checked {w next : World} {r : Record} (accepted : step w r = .ok next)
    : ∃ eventNext,
        stepEvent w r.event = .ok eventNext
        ∧ next = { eventNext with lastSeq := some r.seq, count := w.count + 1 } := by
  obtain ⟨_, _, accepted⟩ := bind_ok accepted
  obtain ⟨_, _, accepted⟩ := bind_ok accepted
  obtain ⟨seq, event⟩ := r
  dsimp only at accepted ⊢
  split at accepted <;> try split at accepted
  all_goals first
    | obtain ⟨_, invalid, _⟩ := bind_ok accepted; cases invalid
    | obtain ⟨eventNext, eventAccepted, accepted⟩ := bind_ok accepted
      exact ⟨eventNext, eventAccepted, (pure_ok accepted).symm⟩

private theorem step_reports_checked {w next : World} {r : Record}
    (accepted : step w r = .ok next)
    : ∃ output,
        executeActions (project w) (actions w r.event) = some (project next, output)
        ∧ reportedMatches r.event output = true := by
  obtain ⟨eventNext, eventAccepted, equal⟩ := record_checked accepted
  obtain ⟨semantic, output, _, executed, reported, lifted⟩ := event_checked eventAccepted
  subst next eventNext
  refine ⟨output, ?_, reported⟩
  change executeActions (project w) (actions w r.event) =
    some (project (liftState (metadata w r.event output) semantic), output)
  rw [lift_projects]
  exact executed

private theorem step_checked {w next : World} {r : Record}
    (accepted : step w r = .ok next)
    : (executeActions (project w) (actions w r.event)).map Prod.fst
      = some (project next) := by
  obtain ⟨output, executed, _⟩ := step_reports_checked accepted
  simp only [executed, Option.map_some]

private theorem executeActions_run (s final : Model.State) (inputs : List Model.Action)
    (accepted : (executeActions s inputs).map Prod.fst = some final)
    : CCF.Execution.Run Model.transitionSystem s inputs final := by
  induction inputs generalizing s with
  | nil =>
      simp only [executeActions, Option.map_some, Option.some.injEq] at accepted
      subst final
      exact .nil _
  | cons a rest ih =>
      cases executed : Model.execute s a with
      | none => simp [executeActions, executed] at accepted
      | some pair =>
          obtain ⟨next, output⟩ := pair
          have transition : Model.transitionSystem.step s a = some next := by
            simp [Model.transitionSystem, Model.step, executed]
          cases rest with
          | nil =>
              simp [executeActions, executed] at accepted
              subst final
              exact .cons transition (.nil _)
          | cons b tail =>
              apply CCF.Execution.Run.cons transition
              apply ih next
              simpa [executeActions, executed] using accepted

/-- Every accepted record executes its translated semantic inputs; trace-only records stutter. -/
theorem step_projects
    : ∀ (w next : World) (r : Record),
        transitionSystem.step w r = some next
        → CCF.Execution.Run Model.transitionSystem (project w) (actions w r.event)
            (project next) := by
  intro w next r accepted
  have typed : step w r = .ok next := by
    cases typed : step w r with
    | error => simp [transitionSystem, typed, Except.toOption] at accepted
    | ok value =>
        have equal : value = next := by
          simpa [transitionSystem, typed, Except.toOption] using accepted
        exact congrArg Except.ok equal
  exact executeActions_run _ _ _ (step_checked typed)

/-- Accepted observations agree with the output actually computed by semantic execution. -/
theorem step_reports
    : ∀ (w next : World) (r : Record),
        transitionSystem.step w r = some next
        → ∃ output,
            executeActions (project w) (actions w r.event) = some (project next, output)
            ∧ reportedMatches r.event output = true := by
  intro w next r accepted
  have typed : step w r = .ok next := by
    cases typed : step w r with
    | error => simp [transitionSystem, typed, Except.toOption] at accepted
    | ok value =>
        have equal : value = next := by
          simpa [transitionSystem, typed, Except.toOption] using accepted
        exact congrArg Except.ok equal
  exact step_reports_checked typed

private theorem run_append {s middle final : Model.State} {left right : List Model.Action}
    (first : CCF.Execution.Run Model.transitionSystem s left middle)
    (second : CCF.Execution.Run Model.transitionSystem middle right final)
    : CCF.Execution.Run Model.transitionSystem s (left ++ right) final := by
  induction left generalizing s with
  | nil =>
      cases first using @CCF.Execution.Run.casesOn Model.transitionSystem
      exact second
  | cons a rest ih =>
      cases first using @CCF.Execution.Run.casesOn Model.transitionSystem with
      | cons one tail => exact .cons one (ih tail)

/-- Typed replay executes exactly the inputs translated along its own intermediate worlds. -/
theorem replay_projects
    : ∀ (w final : World) (records : List Record),
        replay w records = .ok final
        → ∃ inputs,
            semanticInputs w records = .ok inputs
            ∧ CCF.Execution.Run Model.transitionSystem (project w) inputs
                (project final) := by
  intro w final records accepted
  induction records generalizing w with
  | nil =>
      cases accepted
      exact ⟨[], rfl, .nil _⟩
  | cons r rs ih =>
      obtain ⟨next, one, rest⟩ := bind_ok accepted
      obtain ⟨inputs, translated, execution⟩ := ih next rest
      refine ⟨actions w r.event ++ inputs, ?_, ?_⟩
      · simp only [semanticInputs, one]
        change (semanticInputs next rs).bind
          (fun rest => .ok (actions w r.event ++ rest)) = _
        rw [translated]
        rfl
      · exact run_append (executeActions_run _ _ _ (step_checked one)) execution

private theorem run_reachable {s final : Model.State} {inputs : List Model.Action}
    (reachable : Model.transitionSystem.Reachable s)
    (execution : CCF.Execution.Run Model.transitionSystem s inputs final)
    : Model.transitionSystem.Reachable final := by
  induction inputs generalizing s with
  | nil =>
      cases execution using @CCF.Execution.Run.casesOn Model.transitionSystem
      exact reachable
  | cons a rest ih =>
      cases execution using @CCF.Execution.Run.casesOn Model.transitionSystem with
      | cons one tail => exact ih (.step reachable one) tail

/-- Every trace-reachable semantic projection is reachable by the KV model itself. -/
theorem reachable_projects
    : ∀ w : World,
        transitionSystem.Reachable w → Model.transitionSystem.Reachable (project w) := by
  intro w reachable
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | initial initialized =>
      cases initialized
      exact .initial rfl
  | step _ accepted ih => exact run_reachable ih (step_projects _ _ _ accepted)

end Kv.Proofs.Correspondence
