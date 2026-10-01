import DisasterRecovery.Shared.Execution
import Mathlib.Tactic

namespace DisasterRecovery.Proofs.Trace

open Shared

inductive Path (system : TransitionSystem State Action)
    : State -> List State -> State -> Prop where
  | nil (state) : Path system state [] state
  | cons {before middle after tail} {action}
    (step : system.step before action = some middle)
    (rest : Path system middle tail after)
    : Path system before (middle :: tail) after

lemma Path.reachable {system : TransitionSystem State Action} {before tail after}
    (path : Path system before tail after) (reachable : system.Reachable before)
    : system.Reachable after := by
  induction path with
  | nil => exact reachable
  | cons step _ ih => exact ih (.step reachable step)

lemma Path.run {system : TransitionSystem State Action} {before tail after}
    (path : Path system before tail after)
    : exists actions, Execution.Run system before actions after := by
  induction path with
  | nil => exact ⟨[], .nil _⟩
  | cons step _ ih =>
      obtain ⟨actions, rest⟩ := ih
      exact ⟨_, .cons step rest⟩

lemma Path.valid {system : TransitionSystem State Action} {before tail after}
    (path : Path system before tail after) (initialized : system.init before)
    : (Execution.Trace.mk (before :: tail)).Valid system := by
  refine ⟨⟨before, rfl, initialized⟩, ?_⟩
  clear initialized
  induction path with
  | nil =>
      intro i left right first second
      cases i <;> simp at second
  | cons step rest ih =>
      intro i left right first second
      cases i with
      | zero =>
          simp only [Nat.zero_add, List.getElem?_cons_zero, List.getElem?_cons_succ,
            Option.some.injEq] at first second
          subst left right
          exact ⟨_, step⟩
      | succ i => exact ih i left right first second

lemma valid_path {system : TransitionSystem State Action} {trace : Execution.Trace State}
    (valid : trace.Valid system)
    : exists before tail after,
        trace.states = before :: tail
        /\ system.init before
        /\ Path system before tail after := by
  obtain ⟨before, first, initialized⟩ := valid.1
  cases states : trace.states with
  | nil => simp [states] at first
  | cons head tail =>
      have equal : head = before := by simpa [states] using first
      subst head
      refine ⟨before, tail, ?_⟩
      have adjacent := valid.2
      rw [states] at adjacent
      have paths : forall (before : State) (tail : List State),
          (forall (i : Nat) left right, (before :: tail)[i]? = some left ->
            (before :: tail)[i + 1]? = some right ->
            exists action, system.step left action = some right) ->
          exists after, Path system before tail after := by
        intro before tail
        induction tail generalizing before with
        | nil => exact fun _ => ⟨before, .nil _⟩
        | cons middle tail ih =>
            intro linked
            obtain ⟨action, step⟩ := linked 0 before middle rfl rfl
            obtain ⟨after, rest⟩ := ih middle (fun i => linked (i + 1))
            exact ⟨after, .cons step rest⟩
      obtain ⟨after, path⟩ := paths before tail adjacent
      exact ⟨after, rfl, initialized, path⟩

lemma Path.suffix {system : TransitionSystem State Action} {before tail after}
    (path : Path system before tail after) {state : State}
    (member : state ∈ before :: tail)
    : exists rest, Path system state rest after := by
  induction path with
  | nil =>
      simp only [List.mem_singleton] at member
      subst state
      exact ⟨[], .nil _⟩
  | cons step rest ih =>
      rcases List.mem_cons.mp member with rfl | member
      · exact ⟨_, .cons step rest⟩
      · exact ih member

end DisasterRecovery.Proofs.Trace
