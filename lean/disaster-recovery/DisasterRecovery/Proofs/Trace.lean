module

public import CCF.Execution
public import Mathlib.Tactic

@[expose] public section

namespace DisasterRecovery.Proofs.Trace

open CCF

variable {State Action : Type}

/-- Enabled steps through the listed successor states, from a start state to a final state. -/
inductive Path (system : TransitionSystem State Action)
    : State -> List State -> State -> Prop where
  /-- An empty path starts and ends at the same state. -/
  | nil (state) : Path system state [] state
  /-- Prepend one enabled step and its successor to the remaining path. -/
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

lemma valid_path {system : TransitionSystem State Action} {trace : Execution.Trace State}
    (valid : trace.Valid system) (start count : Nat)
    : Path system (trace.states start)
        ((List.range count).map fun offset => trace.states (start + offset + 1))
        (trace.states (start + count)) := by
  induction count generalizing start with
  | zero => exact .nil _
  | succ count ih =>
      obtain ⟨action, step⟩ := valid.2 start
      have rest := ih (start + 1)
      rw [List.range_succ_eq_map, List.map_cons, List.map_map]
      refine .cons step ?_
      simpa only [Function.comp_def, Nat.add_assoc, Nat.add_comm 1, Nat.add_zero]
        using rest

/-- Every finite collection of trace indices lies below one bound. -/
lemma exists_bound {α : Type} {P : α -> Nat -> Prop} (items : List α)
    (indexed : forall item, item ∈ items -> exists index, P item index)
    : exists bound,
        forall item, item ∈ items -> exists index, index <= bound /\ P item index := by
  induction items with
  | nil => exact ⟨0, by simp⟩
  | cons head tail ih =>
      obtain ⟨headIndex, headHolds⟩ := indexed head (by simp)
      obtain ⟨bound, bounded⟩ := ih fun item member => indexed item (by simp [member])
      refine ⟨headIndex + bound, fun item member => ?_⟩
      rcases List.mem_cons.mp member with rfl | member
      · exact ⟨headIndex, by omega, headHolds⟩
      · obtain ⟨index, le, holds⟩ := bounded item member
        exact ⟨index, by omega, holds⟩

/-- An infinite trace that visits `states`, then `final` forever. -/
def lasso (states : List State) (final : State) : Execution.Trace State :=
  ⟨fun index => (states ++ [final]).getD index final⟩

lemma lasso_states_beyond {states : List State} {final : State} {index : Nat}
    (beyond : states.length <= index)
    : (lasso states final).states index = final := by
  simp only [lasso, List.getD_eq_getElem?_getD, List.getElem?_append_right beyond]
  cases same : index - states.length <;> simp

/-- Every lasso state is one of its listed states or its final state. -/
lemma lasso_states_mem (states : List State) (final : State) (index : Nat)
    : (lasso states final).states index ∈ states ++ [final] := by
  simp only [lasso, List.getD_eq_getElem?_getD]
  cases found : (states ++ [final])[index]? with
  | none =>
      simp
  | some state =>
      exact List.mem_iff_getElem?.mpr ⟨index, found⟩

/-- A lasso is valid when it starts initially, each listed step is enabled, and
`final` has an enabled action returning to itself. -/
lemma lasso_valid {system : TransitionSystem State Action} {states : List State}
    {final : State}
    (initialized : system.init ((states ++ [final]).getD 0 final))
    (adjacent
      : forall index : Fin ((states ++ [final]).length - 1),
          exists action,
            system.step ((states ++ [final])[index.val]'(by omega)) action
            = some ((states ++ [final])[index.val + 1]'(by omega)))
    (loop : exists action, system.step final action = some final)
    : (lasso states final).Valid system := by
  refine ⟨initialized, fun index => ?_⟩
  by_cases inside : index < states.length
  · obtain ⟨action, step⟩ := adjacent ⟨index, by simp; omega⟩
    refine ⟨action, ?_⟩
    simpa only [lasso, List.getD_eq_getElem?_getD,
      List.getElem?_eq_getElem (show index < (states ++ [final]).length by simp; omega),
      List.getElem?_eq_getElem (show index + 1 < (states ++ [final]).length by simp; omega),
      Option.getD_some] using step
  · rw [lasso_states_beyond (by omega), lasso_states_beyond (by omega)]
    exact loop

end DisasterRecovery.Proofs.Trace
