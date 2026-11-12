module

public import CCF.Execution

import Std.Tactic.BVDecide.Normalize.Prop

@[expose] public section

namespace CCF.Execution

/-!
Theorems about executions: trace states are connected by transitions and reachable,
and valid traces cover exactly the reachable states.
-/

namespace Trace

/-- The first state exists and is initial. -/
theorem valid_init {system : TransitionSystem} (trace : Trace system)
    : exists initial, trace.stateAt 0 = some initial /\ system.init initial :=
  ⟨trace.val.init, CCF.Seq.get?_cons_zero _ _, trace.property.1⟩

/-- Each recorded action executes the corresponding transition. -/
theorem valid_step {system : TransitionSystem} (trace : Trace system)
    (n : Nat) (before : system.State) (action : system.Action)
    (first : trace.stateAt n = some before) (chosen : trace.actionAt n = some action)
    : system.step before action = trace.stateAt (n + 1) :=
  trace.property.2 n before action first chosen

/-- Actions exist exactly where a successor state exists, by construction. -/
theorem valid_domains {system : TransitionSystem} (trace : Trace system) (n : Nat)
    : (trace.actions.get? n).isSome <-> (trace.states.get? (n + 1)).isSome := by
  simp [actions, states]

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
  CCF.Seq.mem_iff_exists_get?

/-- A state found at an index belongs to the trace. -/
theorem stateAt_mem {system : TransitionSystem} {trace : Trace system}
    {n : Nat} {state : system.State} (found : trace.stateAt n = some state)
    : state ∈ trace :=
  CCF.Seq.get?_mem found

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
      rw [first] at found
      cases found
      exact .initial initialized
  | succ index ih =>
      cases previous : trace.stateAt index with
      | none =>
          have absent := trace.states.le_stable (Nat.le_succ index) previous
          change trace.stateAt (index + 1) = none at absent
          rw [absent] at found
          cases found
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
    suffices finite : exists (initial : system.State) (steps : List (system.Action × system.State)),
        system.init initial
        /\ (initial :: steps.map Prod.snd)[steps.length]? = some state
        /\ forall i : Fin steps.length,
          system.step ((initial :: steps.map Prod.snd)[i.val]'(by simp; omega))
            steps[i.val].1 = some steps[i.val].2 by
      obtain ⟨initial, steps, initialized, last, enabled⟩ := finite
      have indexed (n : Nat)
          : (CCF.Seq.cons initial ((CCF.Seq.ofList steps).map Prod.snd)).get? n
              = (initial :: steps.map Prod.snd)[n]? := by
        cases n <;> simp
      refine ⟨⟨{
        init := initial
        steps := CCF.Seq.ofList steps
      }, initialized, ?_⟩, ?_⟩
      · intro n before action first chosen
        change (steps[n]?).map Prod.fst = some action at chosen
        obtain ⟨pair, present, actionEq⟩ := Option.map_eq_some_iff.mp chosen
        obtain ⟨bound, pairEq⟩ := List.getElem?_eq_some_iff.mp present
        have firstEq : (initial :: steps.map Prod.snd)[n]? = some before :=
          (indexed n).symm.trans first
        obtain ⟨_, beforeEq⟩ := List.getElem?_eq_some_iff.mp firstEq
        change system.step before action = (steps[n]?).map Prod.snd
        rw [present]
        simpa only [← beforeEq, ← actionEq, ← pairEq, Option.map_some] using enabled ⟨n, bound⟩
      · apply Trace.stateAt_mem (n := steps.length)
        exact (indexed steps.length).trans last
    induction reachable with
    | initial initialized =>
        exact ⟨_, [], initialized, rfl, fun i => Fin.elim0 i⟩
    | @step before after action _ step ih =>
        obtain ⟨initial, steps, initialized, last, enabled⟩ := ih
        refine ⟨initial, steps ++ [(action, after)], initialized, ?_, ?_⟩
        · simp [List.map_append]
        · intro ⟨index, bounded⟩
          simp only [List.map_append, List.map_cons, List.map_nil]
          simp only [← List.cons_append]
          by_cases inside : index < steps.length
          · rw [List.getElem_append_left
                (as := initial :: steps.map Prod.snd) (i := index) (by simp; omega),
              List.getElem_append_left inside]
            exact enabled ⟨index, inside⟩
          · have lastIndex : index = steps.length := by simp at bounded; omega
            subst index
            have beforeEq := (List.getElem?_eq_some_iff.mp last).2
            rw [List.getElem_append_left
              (as := initial :: steps.map Prod.snd) (i := steps.length) (by simp)]
            simpa [← beforeEq] using step
  · rintro ⟨trace, member⟩
    exact trace.reachable member

/-- The states of a finite recorded trace, indexed from its initial state. -/
theorem ofSteps_stateAt {system : TransitionSystem} {initial : system.State}
    {steps : List (system.Action × system.State)} {initialized : system.init initial}
    {valid : StepsFrom system initial steps} (n : Nat)
    : (ofSteps initial steps initialized valid).stateAt n
      = (initial :: steps.map Prod.snd)[n]? := by
  cases n <;>
    simp only [ofSteps, Trace.stateAt, Trace.states,
      CCF.Seq.get?_cons_zero, CCF.Seq.get?_cons_succ, CCF.Seq.map_get?,
      CCF.Seq.ofList_get?, List.getElem?_cons_zero, List.getElem?_cons_succ,
      List.getElem?_map]

/-- The actions of a finite recorded trace. -/
theorem ofSteps_actionAt {system : TransitionSystem} {initial : system.State}
    {steps : List (system.Action × system.State)} {initialized : system.init initial}
    {valid : StepsFrom system initial steps} (n : Nat)
    : (ofSteps initial steps initialized valid).actionAt n
      = (steps.map Prod.fst)[n]? := by
  simp only [ofSteps, Trace.actionAt, Trace.actions,
    CCF.Seq.map_get?, CCF.Seq.ofList_get?, List.getElem?_map]

/-- Membership in a finite recorded trace is membership in its list of states. -/
theorem mem_ofSteps {system : TransitionSystem} {initial : system.State}
    {steps : List (system.Action × system.State)} {initialized : system.init initial}
    {valid : StepsFrom system initial steps} {state : system.State}
    : state ∈ ofSteps initial steps initialized valid
      <-> state ∈ initial :: steps.map Prod.snd := by
  rw [Trace.mem_iff_exists_stateAt]
  simp only [ofSteps_stateAt]
  constructor
  · rintro ⟨n, found⟩
    exact List.mem_of_getElem? found.symm
  · intro member
    obtain ⟨n, bound, rfl⟩ := List.getElem_of_mem member
    exact ⟨n, (List.getElem?_eq_getElem bound).symm⟩

/-- Append an enabled transition at the end of a valid list of recorded steps. -/
theorem steps_snoc {system : TransitionSystem} (start before after : system.State)
    (steps : List (system.Action × system.State)) (action : system.Action)
    (valid : StepsFrom system start steps)
    (last : (start :: steps.map Prod.snd)[steps.length]? = some before)
    (enabled : system.step before action = some after)
    : StepsFrom system start (steps ++ [(action, after)]) := by
  induction steps generalizing start with
  | nil =>
      simp only [List.map_nil, List.length_nil, List.getElem?_cons_zero,
        Option.some.injEq] at last
      subst start
      exact ⟨enabled, trivial⟩
  | cons pair rest ih =>
      obtain ⟨first, valid⟩ := valid
      refine ⟨first, ih pair.2 valid ?_⟩
      simpa using last

/-- Every state reached along the stem belongs to the resulting lasso trace. -/
theorem lasso_mem {system : TransitionSystem} {start final state : system.State}
    {stem cycle : List (system.State -> system.Action)}
    (initialized : system.init start)
    (stemRun : run system start stem = some final)
    (cycleRun : run system final cycle = some final) (nonempty : cycle ≠ []) {index : Nat}
    (bounded : index <= stem.length)
    (reached : run system start (stem.take index) = some state)
    : state ∈ lassoTrace initialized stemRun cycleRun nonempty := by
  apply Trace.stateAt_mem (n := index)
  have position
      : (lassoTrace initialized stemRun cycleRun nonempty).stateAt index
          = some (lasso system start stem cycle index) := by
    cases index <;> rfl
  rw [position, Option.some.injEq]
  by_cases inStem : index < stem.length
  · simp only [lasso, ite_eq_left inStem, reached, Option.getD_some]
  · have last : index = stem.length := by omega
    subst last
    rw [List.take_length, stemRun] at reached
    simp only [Option.some.injEq] at reached
    subst reached
    simp only [lasso, Nat.lt_irrefl, ite_false, stemRun, Option.getD_some,
      Nat.sub_self, Nat.zero_mod, List.take_zero, run]

end CCF.Execution
