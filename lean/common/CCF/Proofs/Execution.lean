module

public import CCF.Execution
public import CCF.Proofs.Seq

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

/-- Each recorded action leads from the previous state to the state paired with it. -/
def StepsFrom (system : TransitionSystem)
    : system.State -> List (system.Action × system.State) -> Prop
  | _, [] => True
  | before, (action, after) :: rest =>
      system.step before action = some after /\ StepsFrom system after rest

/-- Indexed transitions in a valid list of recorded steps. -/
theorem stepsFrom_getElem? {system : TransitionSystem}
    : forall (initial : system.State) (steps : List (system.Action × system.State)),
        StepsFrom system initial steps
        -> forall (n : Nat) (before : system.State) (action : system.Action),
            (initial :: steps.map Prod.snd)[n]? = some before
            -> (steps.map Prod.fst)[n]? = some action
            -> system.step before action = (steps.map Prod.snd)[n]?
  | _, [], _, _, _, _, _, chosen => by simp at chosen
  | _, (_, _) :: _, ⟨step, _⟩, 0, _, _, first, chosen => by
      simp only [List.map_cons, List.getElem?_cons_zero, Option.some.injEq] at first chosen ⊢
      subst first chosen
      exact step
  | _, (_, after) :: rest, ⟨_, valid⟩, n + 1, before, action, first, chosen => by
      simp only [List.map_cons, List.getElem?_cons_succ] at first chosen ⊢
      exact stepsFrom_getElem? after rest valid n before action first chosen

/-- The finite trace that starts at `initial` and records `steps`. -/
def ofSteps {system : TransitionSystem} (initial : system.State)
    (steps : List (system.Action × system.State)) (initialized : system.init initial)
    (valid : StepsFrom system initial steps)
    : Trace system :=
  ⟨
    { init := initial, steps := CCF.Seq.ofList steps },
    initialized,
    by
      intro n before action first chosen
      simp only [CCF.Seq.map_get?, CCF.Seq.ofList_get?] at chosen ⊢
      rw [← List.getElem?_map] at chosen ⊢
      refine stepsFrom_getElem? initial steps valid n before action ?_ chosen
      cases n <;>
        simpa only [CCF.Seq.get?_cons_zero, CCF.Seq.get?_cons_succ,
          CCF.Seq.map_get?, CCF.Seq.ofList_get?, List.getElem?_cons_zero,
          List.getElem?_cons_succ, List.getElem?_map] using first
  ⟩

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

/-- The final state of choosing each action from the current state, when every
chosen action is enabled. -/
def run (system : TransitionSystem) (start : system.State)
    : List (system.State -> system.Action) -> Option system.State
  | [] => some start
  | choose :: rest =>
      (system.step start (choose start)).bind fun next => run system next rest

/-- Each prefix of a finished run finishes, and its next choice is enabled. -/
theorem run_take_step {system : TransitionSystem} {start final : system.State}
    {choices : List (system.State -> system.Action)}
    (finished : run system start choices = some final) {index : Nat}
    (bounded : index < choices.length)
    : exists before after,
        run system start (choices.take index) = some before
        /\ run system start (choices.take (index + 1)) = some after
        /\ system.step before (choices[index] before) = some after := by
  induction choices generalizing start index with
  | nil => simp at bounded
  | cons choose rest ih =>
      simp only [run, Option.bind_eq_some_iff] at finished
      obtain ⟨next, stepped, finished⟩ := finished
      cases index with
      | zero =>
          refine ⟨start, next, rfl, ?_, stepped⟩
          simp only [List.take_succ_cons, List.take_zero, run, stepped, Option.bind_some]
      | succ index =>
          obtain ⟨before, after, first, second, enabled⟩ :=
            ih finished (by simpa using bounded)
          exact ⟨
            before,
            after,
            by
              simpa only [List.take_succ_cons, run, stepped, Option.bind_some]
                using first,
            by
              simpa only [List.take_succ_cons, run, stepped, Option.bind_some]
                using second,
            by simpa using enabled
          ⟩

/--
The states of running `stem` from `start` and then repeating `cycle` forever.
The default `start` is never used when the runs finish.
-/
def lasso (system : TransitionSystem) (start : system.State)
    (stem cycle : List (system.State -> system.Action)) (index : Nat)
    : system.State :=
  if index < stem.length then
    (run system start (stem.take index)).getD start
  else
    (run system ((run system start stem).getD start)
      (cycle.take ((index - stem.length) % cycle.length))).getD
      start

/-- The action chosen at each position of a lasso. -/
def lassoAction (system : TransitionSystem) (start : system.State)
    (stem cycle : List (system.State -> system.Action)) (nonempty : cycle ≠ [])
    (index : Nat)
    : system.Action :=
  if inStem : index < stem.length then
    stem[index] (lasso system start stem cycle index)
  else
    (cycle[(index - stem.length) % cycle.length
      ]'(Nat.mod_lt _ (List.length_pos_iff.mpr nonempty)))
      (lasso system start stem cycle index)

/-- A finished stem followed by a nonempty cycle back to its final state records
the chosen action at every step of a valid infinite trace. -/
def lassoTrace {system : TransitionSystem} {start final : system.State}
    {stem cycle : List (system.State -> system.Action)} (initialized : system.init start)
    (stemRun : run system start stem = some final)
    (cycleRun : run system final cycle = some final) (nonempty : cycle ≠ [])
    : Trace system := by
  have positive : 0 < cycle.length := List.length_pos_iff.mpr nonempty
  have tail : forall index, stem.length <= index
      -> lasso system start stem cycle index
          = (run system final (cycle.take ((index - stem.length) % cycle.length))).getD
              start := by
    intro index le
    simp only [lasso, ite_eq_right (Nat.not_lt.mpr le), stemRun, Option.getD_some]
  refine ⟨{
    init := lasso system start stem cycle 0
    steps := CCF.Seq.ofStream fun index =>
      (lassoAction system start stem cycle nonempty index,
        lasso system start stem cycle (index + 1))
  }, ?_, ?_⟩
  · show system.init (lasso system start stem cycle 0)
    by_cases empty : stem = []
    · subst empty
      simp only [run, Option.some.injEq] at stemRun
      subst stemRun
      simpa only [tail 0 (Nat.zero_le _), List.length_nil, Nat.sub_self, Nat.zero_mod,
        List.take_zero, run, Option.getD_some] using initialized
    · simpa only [lasso, ite_eq_left (List.length_pos_iff.mpr empty),
        List.take_zero, run, Option.getD_some] using initialized
  intro index before action atBefore chosen
  have atBefore : lasso system start stem cycle index = before := by
    cases index <;> exact Option.some.inj atBefore
  change some (lassoAction system start stem cycle nonempty index) = some action at chosen
  cases atBefore
  cases chosen
  show system.step (lasso system start stem cycle index)
      (lassoAction system start stem cycle nonempty index)
      = some (lasso system start stem cycle (index + 1))
  by_cases inStem : index < stem.length
  · obtain ⟨before, after, first, second, enabled⟩ := run_take_step stemRun inStem
    have now : lasso system start stem cycle index = before := by
      simp only [lasso, ite_eq_left inStem, first, Option.getD_some]
    have next : lasso system start stem cycle (index + 1) = after := by
      by_cases more : index + 1 < stem.length
      · simp only [lasso, ite_eq_left more, second, Option.getD_some]
      · have last : index + 1 = stem.length := by omega
        rw [tail _ (by omega), last, Nat.sub_self, Nat.zero_mod]
        rw [last, List.take_length, stemRun] at second
        simp only [Option.some.injEq] at second
        subst second
        simp only [List.take_zero, run, Option.getD_some]
    simpa only [lassoAction, dite_eq_left inStem, now, next] using enabled
  · have offset : (index + 1 - stem.length) % cycle.length
        = ((index - stem.length) % cycle.length + 1) % cycle.length := by
      rw [show index + 1 - stem.length = index - stem.length + 1 by omega, Nat.mod_add_mod]
    have within := Nat.mod_lt (index - stem.length) positive
    obtain ⟨before, after, first, second, enabled⟩ := run_take_step cycleRun within
    simp only [lassoAction, dite_eq_right inStem]
    rw [tail _ (by omega), tail _ (by omega), offset, first]
    by_cases more : (index - stem.length) % cycle.length + 1 < cycle.length
    · rw [Nat.mod_eq_of_lt more, second]
      exact enabled
    · have last : (index - stem.length) % cycle.length + 1 = cycle.length := by omega
      rw [last, Nat.mod_self, List.take_zero]
      rw [last, List.take_length, cycleRun] at second
      simp only [Option.some.injEq] at second
      subst second
      exact enabled

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
