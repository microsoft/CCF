module

public import CCF.Execution
public import Mathlib.Tactic

@[expose] public section

namespace DisasterRecovery.Proofs.Trace

open CCF

variable {State Action : Type}

/-- Enabled steps through the listed successor states, from a start state to a final state. -/
inductive Path (system : TransitionSystem)
    : system.State -> List system.State -> system.State -> Prop where
  /-- An empty path starts and ends at the same state. -/
  | nil (state) : Path system state [] state
  /-- Prepend one enabled step and its successor to the remaining path. -/
  | cons {before middle after tail} {action}
    (step : system.step before action = some middle)
    (rest : Path system middle tail after)
    : Path system before (middle :: tail) after

lemma Path.reachable {system : TransitionSystem} {before tail after}
    (path : Path system before tail after) (reachable : system.Reachable before)
    : system.Reachable after := by
  induction path with
  | nil => exact reachable
  | cons step _ ih => exact ih (.step reachable step)

lemma Path.run {system : TransitionSystem} {before tail after}
    (path : Path system before tail after)
    : exists actions, Execution.Run system before actions after := by
  induction path with
  | nil => exact ⟨[], .nil _⟩
  | cons step _ ih =>
      obtain ⟨actions, rest⟩ := ih
      exact ⟨_, .cons step rest⟩

/-- Enabled steps connect a state of a valid trace to every later state of the trace. -/
lemma valid_path {system : TransitionSystem}
    {trace : Execution.Trace system.State system.Action}
    (valid : trace.Valid system) (start count : Nat) {before after : system.State}
    (first : trace.stateAt start = some before)
    (last : trace.stateAt (start + count) = some after)
    : exists tail, Path system before tail after := by
  induction count generalizing start before with
  | zero =>
      cases first.symm.trans last
      exact ⟨[], .nil _⟩
  | succ count ih =>
      cases next : trace.stateAt (start + 1) with
      | none =>
          simp [Execution.Trace.stateAt_le_stable
            (show start + 1 <= start + (count + 1) by omega) next] at last
      | some middle =>
          obtain ⟨action, step⟩ := valid.exists_action first next
          obtain ⟨tail, rest⟩ :=
            ih (start + 1) next (by rwa [show start + 1 + count = start + (count + 1) by omega])
          exact ⟨_, .cons step rest⟩

/-- The later of two trace positions is also a trace position. -/
lemma max_isSome {trace : Execution.Trace State Action} {first second : Nat}
    (firstIn : (trace.stateAt first).isSome) (secondIn : (trace.stateAt second).isSome)
    : (trace.stateAt (max first second)).isSome := by
  rcases le_total first second with le | le
  · rwa [max_eq_right le]
  · rwa [max_eq_left le]

/-- Finitely many trace positions all lie at or before one trace position after `start`. -/
lemma exists_bound {α : Type} {trace : Execution.Trace State Action} {P : α -> Nat -> Prop}
    {start : Nat} (startIn : (trace.stateAt start).isSome) (items : List α)
    (indexed
      : forall item,
          item ∈ items -> exists index, (trace.stateAt index).isSome /\ P item index)
    : exists bound,
        (trace.stateAt bound).isSome
        /\ start <= bound
        /\ forall item, item ∈ items -> exists index, index <= bound /\ P item index := by
  induction items with
  | nil => exact ⟨start, startIn, le_rfl, by simp⟩
  | cons head tail ih =>
      obtain ⟨headIndex, headIn, headHolds⟩ := indexed head (by simp)
      obtain ⟨bound, boundIn, startLe, bounded⟩ :=
        ih fun item member => indexed item (by simp [member])
      refine ⟨
        max headIndex bound,
        max_isSome headIn boundIn,
        startLe.trans (le_max_right _ _),
        fun item member => ?_
      ⟩
      rcases List.mem_cons.mp member with rfl | member
      · exact ⟨headIndex, le_max_left _ _, headHolds⟩
      · obtain ⟨index, le, holds⟩ := bounded item member
        exact ⟨index, le.trans (le_max_right _ _), holds⟩

end DisasterRecovery.Proofs.Trace
