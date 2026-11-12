module

public import CCF.TransitionSystem
public import CCF.Seq

@[expose] public section

namespace CCF.Execution

/-!
Executions of a `TransitionSystem`. `Run` relates a start state, a finite
action list, and an end state. `Trace` records an initial state and a finite or
infinite sequence of actions paired with their successor states, with a validity proof.
Theorems about executions are in `CCF.Proofs.Execution`.
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

/-- An initial state and recorded actions paired with their successor states. -/
structure TraceImpl (system : TransitionSystem) where
  /-- The initial state. -/
  init : system.State
  /-- Each action is paired with the state it reaches. -/
  steps : CCF.Seq (system.Action × system.State)

/-- The initial state is allowed and each recorded action reaches its paired state. -/
def TraceImpl.Valid {system : TransitionSystem} (trace : TraceImpl system) : Prop :=
  system.init trace.init
  /\ forall n before action,
      (CCF.Seq.cons trace.init (trace.steps.map Prod.snd)).get? n = some before
      -> (trace.steps.map Prod.fst).get? n = some action
      -> system.step before action = (trace.steps.map Prod.snd).get? n

/-- A nonempty, valid finite or infinite execution. -/
abbrev Trace (system : TransitionSystem) :=
  {trace : TraceImpl system // trace.Valid}

namespace Trace

/-- The visited states, initial state first. -/
def states {system : TransitionSystem} (trace : Trace system) : CCF.Seq system.State :=
  CCF.Seq.cons trace.val.init (trace.val.steps.map Prod.snd)

/-- The actions recorded by the execution. -/
def actions {system : TransitionSystem} (trace : Trace system) : CCF.Seq system.Action :=
  trace.val.steps.map Prod.fst

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

end Trace

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

end CCF.Execution
