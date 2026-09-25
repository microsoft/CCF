import CCFRaft.Shared.TransitionSystem

namespace CCFRaft.Shared.Execution

/-!
Finite executions of a `TransitionSystem`. `Run` relates a start state, an
action list, and an end state. `Trace` is the state list an execution passes
through; properties quantify over every valid `Trace`. Actions are not stored
in a trace, so a step's action is existentially quantified where needed.
-/

/-- `Run system start actions final`: executing `actions` from `start` reaches `final`. -/
inductive Run {State Action : Type} (system : TransitionSystem State Action)
    : State -> List Action -> State -> Prop where
  | nil (state : State) : Run system state [] state
  | cons {before middle after : State} {action : Action} {actions : List Action}
    (step : system.step before action = some middle)
    (rest : Run system middle actions after)
    : Run system before (action :: actions) after

/-- The states an execution passes through, initial state first. Actions are not recorded. -/
structure Trace (State : Type) where
  states : List State

/-- The trace is nonempty, its first state is initial, and each later state
follows its predecessor by some enabled action. -/
def Trace.Valid (trace : Trace State) (system : TransitionSystem State Action) : Prop :=
  (exists initial, trace.states[0]? = some initial /\ system.init initial)
  /\ forall i before after,
      trace.states[i]? = some before
      -> trace.states[i + 1]? = some after
      -> exists action, system.step before action = some after

/-- Every state in a valid trace is reachable. -/
theorem Trace.Valid.reachable {system : TransitionSystem State Action}
    {trace : Trace State} (valid : trace.Valid system) {state : State}
    (member : state ∈ trace.states)
    : system.Reachable state := by
  obtain ⟨i, found⟩ := List.mem_iff_getElem?.mp member
  have reaches : forall (i : Nat) current, trace.states[i]? = some current -> system.Reachable current := by
    intro i
    induction i with
    | zero =>
        intro current atZero
        obtain ⟨initial, first, initialized⟩ := valid.1
        cases first.symm.trans atZero
        exact .initial initialized
    | succ i ih =>
        intro current atNext
        have bound : i < trace.states.length := by
          obtain ⟨bound, _⟩ := List.getElem?_eq_some_iff.mp atNext
          omega
        have atPrevious : trace.states[i]? = some trace.states[i] := List.getElem?_eq_getElem bound
        obtain ⟨action, step⟩ := valid.2 i _ current atPrevious atNext
        exact .step (ih _ atPrevious) step
  exact reaches i state found

/-- Valid traces cover exactly the reachable states. -/
theorem reachable_iff_trace {system : TransitionSystem State Action} {state : State}
    : system.Reachable state
      <-> exists trace : Trace State, trace.Valid system /\ state ∈ trace.states := by
  constructor
  · intro reachable
    have witness : exists trace : Trace State, trace.Valid system /\
        trace.states.getLast? = some state := by
      induction reachable with
      | initial initialized =>
          refine ⟨⟨[_]⟩, ⟨⟨_, rfl, initialized⟩, ?_⟩, rfl⟩
          intro i before after first second
          cases i <;> simp at second
      | @step before after action _ step ih =>
          obtain ⟨⟨states⟩, valid, last⟩ := ih
          have nonempty : states ≠ [] := by intro empty; simp [empty] at last
          refine ⟨⟨states ++ [after]⟩, ⟨?_, ?_⟩, by simp⟩
          · obtain ⟨initial, first, initialized⟩ := valid.1
            refine ⟨initial, ?_, initialized⟩
            cases states with
            | nil => contradiction
            | cons head tail => exact first
          · intro i left right first second
            simp only [List.getElem?_append] at first second
            by_cases inside : i + 1 < states.length
            · exact valid.2 i left right (by simpa [show i < states.length by omega] using first)
                (by simpa [inside] using second)
            · have boundary : i + 1 = states.length := by
                by_cases same : i + 1 = states.length
                · exact same
                · simp [show ¬i + 1 < states.length by omega,
                    show i + 1 - states.length = (i - states.length) + 1 by omega] at second
              have atLast : states[i]? = some before := by
                rw [List.getLast?_eq_getElem?] at last
                simpa [show states.length - 1 = i by omega] using last
              have same : before = left := Option.some.inj
                (atLast.symm.trans (by simpa [show i < states.length by omega] using first))
              have rightEq : after = right := by simpa [inside, boundary] using second
              subst left right
              exact ⟨action, step⟩
    obtain ⟨trace, valid, last⟩ := witness
    rw [List.getLast?_eq_getElem?] at last
    exact ⟨trace, valid, List.mem_iff_getElem?.mpr ⟨_, last⟩⟩
  · rintro ⟨trace, valid, member⟩
    exact valid.reachable member

end CCFRaft.Shared.Execution
