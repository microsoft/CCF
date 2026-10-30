module

public import CCF.TransitionSystem
public import Mathlib.Data.Seq.Defs

@[expose] public section

namespace CCF.Execution

/-!
Executions of a `TransitionSystem`. `Run` relates a start state, a finite
action list, and an end state. `Trace` records the finite or infinite sequences
of states and actions, together with proofs that they form an execution.
-/

/-- `Run system start actions final`: executing `actions` from `start` reaches `final`. -/
inductive Run (system : TransitionSystem)
    : system.State -> List system.Action -> system.State -> Prop where
  /-- An empty action list leaves the state unchanged. -/
  | nil (state : system.State) : Run system state [] state
  /-- Prepend one enabled action to the rest of an execution. -/
  | cons {before middle after : system.State} {action : system.Action}
    {actions : List system.Action}
    (step : system.step before action = some middle)
    (rest : Run system middle actions after)
    : Run system before (action :: actions) after

/-- A nonempty execution, with one action for each pair of adjacent states.
Finite traces have one more state than action; infinite traces have both at every index. -/
structure Trace (system : TransitionSystem) where
  /-- The visited states, initial state first. -/
  states : Stream'.Seq system.State
  /-- Action `n` takes state `n` to state `n + 1`. -/
  actions : Stream'.Seq system.Action
  /-- The first state exists and is initial. -/
  valid_init : exists initial, states.get? 0 = some initial /\ system.init initial
  /-- Each recorded action executes the corresponding transition. -/
  valid_step
    : forall n before action,
        states.get? n = some before
        -> actions.get? n = some action
        -> system.step before action = states.get? (n + 1)
  /-- Actions exist exactly where a successor state exists. -/
  valid_domains : forall n, (actions.get? n).isSome <-> (states.get? (n + 1)).isSome

namespace Trace

/-- The state at an index, or `none` beyond a finite trace. -/
@[simp]
def stateAt {system : TransitionSystem} (trace : Trace system) (n : Nat)
    : Option system.State :=
  trace.states.get? n

/-- The action at an index, or `none` beyond a finite trace. -/
@[simp]
def actionAt {system : TransitionSystem} (trace : Trace system) (n : Nat)
    : Option system.Action :=
  trace.actions.get? n

instance {system : TransitionSystem} : Membership system.State (Trace system) :=
  ⟨fun trace state => state ∈ trace.states⟩

/-- State membership is membership in the recorded state sequence. -/
@[simp]
theorem mem_states {system : TransitionSystem} {trace : Trace system}
    {state : system.State}
    : state ∈ trace.states <-> state ∈ trace :=
  Iff.rfl

/-- A trace state is present at some index. -/
theorem mem_iff_exists_stateAt {system : TransitionSystem} {trace : Trace system}
    {state : system.State}
    : state ∈ trace <-> exists n, some state = trace.stateAt n :=
  Stream'.Seq.mem_iff_exists_get?

/-- A state found at an index belongs to the trace. -/
theorem stateAt_mem {system : TransitionSystem} {trace : Trace system}
    {n : Nat} {state : system.State} (found : trace.stateAt n = some state)
    : state ∈ trace :=
  Stream'.Seq.get?_mem found

/-- Adjacent states are connected by the action recorded at their shared step. -/
theorem step {system : TransitionSystem} (trace : Trace system) (n : Nat)
    (before after : system.State)
    (first : trace.stateAt n = some before) (next : trace.stateAt (n + 1) = some after)
    : exists action, system.step before action = some after := by
  have present : (trace.actions.get? n).isSome := (trace.valid_domains n).mpr
    (by change (trace.stateAt (n + 1)).isSome; rw [next]; rfl)
  obtain ⟨action, found⟩ := Option.isSome_iff_exists.mp present
  exact ⟨action, (trace.valid_step n before action first found).trans next⟩

/-- Every state in a trace is reachable. -/
theorem reachable {system : TransitionSystem} (trace : Trace system)
    {state : system.State} (member : state ∈ trace)
    : system.Reachable state := by
  obtain ⟨index, found⟩ := mem_iff_exists_stateAt.mp member
  clear member
  induction index generalizing state with
  | zero =>
      obtain ⟨initial, first, initialized⟩ := trace.valid_init
      change some state = trace.states.get? 0 at found
      rw [first] at found
      cases found
      exact .initial initialized
  | succ index ih =>
      cases previous : trace.stateAt index with
      | none =>
          simp [stateAt, trace.states.le_stable (Nat.le_succ index) previous] at found
      | some before =>
          obtain ⟨action, stepped⟩ := trace.step index before state previous found.symm
          exact .step (ih previous.symm) stepped

end Trace

/-- Valid traces cover exactly the reachable states. Every reachable state is the
last state of some valid finite trace. -/
theorem reachable_iff_trace {system : TransitionSystem} {state : system.State}
    : system.Reachable state <-> exists trace : Trace system, state ∈ trace := by
  constructor
  · intro reachable
    suffices finite : exists (states : List system.State) (actions : List system.Action),
        exists lengths : states.length = actions.length,
        (exists initial, (states ++ [state])[0]? = some initial /\ system.init initial)
        /\ forall i : Fin actions.length,
          system.step ((states ++ [state])[i.val]'(by simp; omega)) actions[i.val]
            = some ((states ++ [state])[i.val + 1]'(by simp; omega)) by
      obtain ⟨states, actions, lengths, initialized, steps⟩ := finite
      refine ⟨{
        states := Stream'.Seq.ofList (states ++ [state])
        actions := Stream'.Seq.ofList actions
        valid_init := by simpa only [Stream'.Seq.ofList_get?] using initialized
        valid_domains := by
          intro n
          simp only [Stream'.Seq.ofList_get?, isSome_getElem?, List.length_append,
            List.length_singleton]
          omega
        valid_step := by
          intro n before action first chosen
          simp only [Stream'.Seq.ofList_get?] at first chosen ⊢
          obtain ⟨_, beforeEq⟩ := List.getElem?_eq_some_iff.mp first
          obtain ⟨bound, actionEq⟩ := List.getElem?_eq_some_iff.mp chosen
          rw [← beforeEq, ← actionEq, steps ⟨n, bound⟩]
          symm
          exact List.getElem?_eq_getElem (by simp; omega)
      }, ?_⟩
      exact Trace.stateAt_mem (n := states.length) (by simp [Trace.stateAt])
    induction reachable with
    | initial initialized =>
        exact ⟨[], [], rfl, ⟨_, rfl, initialized⟩, fun i => Fin.elim0 i⟩
    | @step before after action _ step ih =>
        obtain ⟨states, actions, lengths, initialized, steps⟩ := ih
        refine ⟨states ++ [before], actions ++ [action], by simp [lengths], ?_, ?_⟩
        · obtain ⟨initial, first, initialized⟩ := initialized
          refine ⟨initial, ?_, initialized⟩
          rw [List.getElem?_append_left (by simp)]
          exact first
        · intro ⟨index, bounded⟩
          by_cases inside : index < actions.length
          · rw [List.getElem_append_left
                (as := states ++ [before]) (i := index) (by simp; omega),
              List.getElem_append_left
                (as := states ++ [before]) (i := index + 1) (by simp; omega),
              List.getElem_append_left inside]
            exact steps ⟨index, inside⟩
          · have last : index = actions.length := by simp at bounded; omega
            subst index
            simpa [lengths] using step
  · rintro ⟨trace, member⟩
    exact trace.reachable member

end CCF.Execution
