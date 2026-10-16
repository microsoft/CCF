module

public import Kv.Model

@[expose] public section

/-! Links the shared `CCF.Execution` vocabulary to the model's executable `step` and `replay`. -/

namespace Kv.Proofs.Execution

open Kv.Model

theorem step_iff_transition (w next : World) (r : Record)
    : transitionSystem.step w r = some next ↔ step w r = .ok next := by
  simp only [transitionSystem]
  cases step w r <;> simp [Except.toOption]

theorem replay_iff_run (w final : World) (rs : List Record)
    : CCF.Execution.Run transitionSystem w rs final ↔ replay w rs = .ok final := by
  induction rs generalizing w with
  | nil =>
      constructor
      · intro run
        cases run
        rfl
      · intro accepted
        cases accepted
        exact .nil _
  | cons r rs ih =>
      constructor
      · intro run
        cases run with
        | cons transition rest =>
            simp only [replay, (step_iff_transition _ _ _).mp transition, Except.bind]
            exact (ih _).mp rest
      · intro accepted
        simp only [replay] at accepted
        cases accepted' : step w r with
        | error failure => simp [accepted', Except.bind] at accepted
        | ok next =>
            simp only [accepted', Except.bind] at accepted
            exact .cons ((step_iff_transition _ _ _).mpr accepted') ((ih _).mpr accepted)

theorem run_snoc {start before after : World} {rs : List Record} {r : Record}
    (run : CCF.Execution.Run transitionSystem start rs before)
    (transition : transitionSystem.step before r = some after)
    : CCF.Execution.Run transitionSystem start (rs ++ [r]) after := by
  induction run with
  | nil => exact .cons transition (.nil _)
  | cons first _ ih => exact .cons first (ih transition)

theorem run_reachable {start final : World} {rs : List Record}
    (reachable : transitionSystem.Reachable start)
    (run : CCF.Execution.Run transitionSystem start rs final)
    : transitionSystem.Reachable final := by
  induction run with
  | nil => exact reachable
  | cons transition _ ih => exact ih (.step reachable transition)

theorem reachable_iff_replay (w : World)
    : transitionSystem.Reachable w ↔ ∃ rs, replay {} rs = .ok w := by
  constructor
  · intro reachable
    induction reachable with
    | initial initialized =>
        cases initialized
        exact ⟨[], rfl⟩
    | @step before after r _ transition ih =>
        obtain ⟨rs, accepted⟩ := ih
        exact ⟨rs ++ [r],
          (replay_iff_run _ _ _).mp (run_snoc ((replay_iff_run _ _ _).mpr accepted) transition)⟩
  · intro ⟨rs, accepted⟩
    exact run_reachable (.initial rfl) ((replay_iff_run {} w rs).mpr accepted)

end Kv.Proofs.Execution
