module

public import CCF.TransitionSystem
public import Mathlib.Data.Seq.Defs

@[expose] public section

namespace CCF.Execution

/-!
Executions of a `TransitionSystem`. `Run` relates a start state, a finite
action list, and an end state. `Trace` is the finite or infinite state sequence
an execution passes through; properties quantify over every valid `Trace`.
Actions are not stored in a trace, so a step's action is existentially
quantified where needed.
-/

/-- `Run system start actions final`: executing `actions` from `start` reaches `final`. -/
inductive Run {State Action : Type} (system : TransitionSystem State Action)
    : State -> List Action -> State -> Prop where
  /-- An empty action list leaves the state unchanged. -/
  | nil (state : State) : Run system state [] state
  /-- Prepend one enabled action to the rest of an execution. -/
  | cons {before middle after : State} {action : Action} {actions : List Action}
    (step : system.step before action = some middle)
    (rest : Run system middle actions after)
    : Run system before (action :: actions) after

/-- The states an execution passes through, initial state first. Actions are not recorded.
A trace may be finite or infinite: `trace.get? i` is `none` past the end of a finite trace. -/
abbrev Trace (State : Type) := Stream'.Seq State

/-- The trace is nonempty, its first state is initial, and each later state
follows its predecessor by some enabled action. -/
def Trace.Valid {State Action : Type} (trace : Trace State)
    (system : TransitionSystem State Action)
    : Prop :=
  (exists initial, trace.get? 0 = some initial /\ system.init initial)
  /\ forall i before after,
      trace.get? i = some before
      -> trace.get? (i + 1) = some after
      -> exists action, system.step before action = some after

/-- Every state in a valid trace is reachable. -/
theorem Trace.Valid.reachable {State Action : Type}
    {system : TransitionSystem State Action}
    {trace : Trace State} (valid : trace.Valid system) {state : State}
    (member : state ∈ trace)
    : system.Reachable state := by
  obtain ⟨index, found⟩ := Stream'.Seq.mem_iff_exists_get?.mp member
  clear member
  induction index generalizing state with
  | zero =>
      obtain ⟨initial, first, initialized⟩ := valid.1
      rw [first] at found
      cases found
      exact .initial initialized
  | succ index ih =>
      cases previous : trace.get? index with
      | none => simp [trace.le_stable (Nat.le_succ index) previous] at found
      | some before =>
          obtain ⟨action, step⟩ := valid.2 index before state previous found.symm
          exact .step (ih previous.symm) step

/-- Valid traces cover exactly the reachable states. Every reachable state is the
last state of some valid finite trace. -/
theorem reachable_iff_trace {State Action : Type}
    {system : TransitionSystem State Action} {state : State}
    : system.Reachable state
      <-> exists trace : Trace State, trace.Valid system /\ state ∈ trace := by
  constructor
  · intro reachable
    suffices finite : exists states : List State,
        Trace.Valid (Stream'.Seq.ofList (states ++ [state])) system by
      obtain ⟨states, valid⟩ := finite
      exact ⟨_, valid, Stream'.Seq.get?_mem (n := states.length) (by simp [Stream'.Seq.ofList_get?])⟩
    induction reachable with
    | initial initialized =>
        refine ⟨[], ⟨_, rfl, initialized⟩, fun index before after _ next => ?_⟩
        simp at next
    | @step before after action _ step ih =>
        obtain ⟨states, valid⟩ := ih
        refine ⟨states ++ [before], ?_, ?_⟩
        · obtain ⟨initial, first, initialized⟩ := valid.1
          refine ⟨initial, ?_, initialized⟩
          simp only [Stream'.Seq.ofList_get?] at first ⊢
          rw [List.getElem?_append_left (by simp)]
          exact first
        · intro index pre post current next
          simp only [Stream'.Seq.ofList_get?] at current next
          by_cases inside : index + 1 < states.length + 1
          · rw [List.getElem?_append_left (by simp; omega)] at current next
            exact valid.2 index pre post (by simpa [Stream'.Seq.ofList_get?] using current)
              (by simpa [Stream'.Seq.ofList_get?] using next)
          · have length : index = states.length := by
              have := (List.getElem?_eq_some_iff.mp next).1
              simp at this
              omega
            subst length
            simp at current next
            subst current next
            exact ⟨action, step⟩
  · rintro ⟨trace, valid, member⟩
    exact valid.reachable member

end CCF.Execution
