module

public import CCF.TransitionSystem
public import Mathlib.Data.Seq.Defs

import Mathlib.Data.Seq.Basic
import Std.Tactic.BVDecide.Normalize.Prop

@[expose] public section

namespace CCF.Execution

/-!
Executions of a `TransitionSystem`. `Run` relates a start state, a finite
action list, and an end state. `Trace` records an initial state and a finite or
infinite sequence of actions paired with their successor states, with a validity proof.
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

/-- Hiding a finite run's actions gives endpoint reachability, and conversely. -/
theorem reachableFrom_iff_run {system : TransitionSystem} {start final : system.State}
    : system.ReachableFrom start final <-> exists actions, Run system start actions final := by
  constructor
  · intro path
    suffices append : forall {before middle after : system.State}
        {actions : List system.Action} {action : system.Action},
        Run system before actions middle -> system.step middle action = some after
        -> Run system before (actions ++ [action]) after by
      induction path with
      | refl => exact ⟨[], .nil _⟩
      | step _ transition ih =>
          obtain ⟨actions, run⟩ := ih
          exact ⟨actions ++ [_], append run transition⟩
    intro before middle after actions action run transition
    induction run with
    | nil => exact .cons transition (.nil _)
    | cons first _ ih => exact .cons first (ih transition)
  · rintro ⟨actions, run⟩
    suffices extend : forall {before after : system.State} {actions : List system.Action},
        Run system before actions after -> system.ReachableFrom start before
        -> system.ReachableFrom start after from extend run .refl
    intro before after actions run path
    induction run with
    | nil => exact path
    | cons first _ ih => exact ih (.step path first)

/-- An initial state and recorded actions paired with their successor states. -/
structure TraceImpl (system : TransitionSystem) where
  /-- The initial state. -/
  init : system.State
  /-- Each action is paired with the state it reaches. -/
  steps : Stream'.Seq (system.Action × system.State)

/-- The initial state is allowed and each recorded action reaches its paired state. -/
def TraceImpl.Valid {system : TransitionSystem} (trace : TraceImpl system) : Prop :=
  system.init trace.init
  /\ forall n before action,
      (Stream'.Seq.cons trace.init (trace.steps.map Prod.snd)).get? n = some before
      -> (trace.steps.map Prod.fst).get? n = some action
      -> system.step before action = (trace.steps.map Prod.snd).get? n

/-- A nonempty, valid finite or infinite execution. -/
abbrev Trace (system : TransitionSystem) :=
  {trace : TraceImpl system // trace.Valid}

namespace Trace

/-- The visited states, initial state first. -/
def states {system : TransitionSystem} (trace : Trace system)
    : Stream'.Seq system.State :=
  Stream'.Seq.cons trace.val.init (trace.val.steps.map Prod.snd)

/-- The actions recorded by the execution. -/
def actions {system : TransitionSystem} (trace : Trace system)
    : Stream'.Seq system.Action :=
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

/-- The first state exists and is initial. -/
theorem valid_init {system : TransitionSystem} (trace : Trace system)
    : exists initial, trace.stateAt 0 = some initial /\ system.init initial :=
  ⟨trace.val.init, Stream'.Seq.get?_cons_zero _ _, trace.property.1⟩

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
          : (Stream'.Seq.cons initial ((Stream'.Seq.ofList steps).map Prod.snd)).get? n
              = (initial :: steps.map Prod.snd)[n]? := by
        cases n <;> simp
      refine ⟨⟨{
        init := initial
        steps := Stream'.Seq.ofList steps
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
    obtain ⟨start, initialized, path⟩ := reachable
    induction path with
    | refl =>
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

/-- A state visited by an executable prefix of a finite action list, including its start. -/
def Visits (system : TransitionSystem) (start : system.State)
    (actions : List system.Action) (state : system.State) : Prop :=
  exists preceding following,
    actions = preceding ++ following /\ Run system start preceding state

/-- A particular transition within a finite run, with executable prefixes and suffixes. -/
def Executes (system : TransitionSystem) (start : system.State)
    (actions : List system.Action) (final before : system.State)
    (action : system.Action) (after : system.State) : Prop :=
  exists preceding following,
    actions = preceding ++ action :: following
    /\ Run system start preceding before
    /\ system.step before action = some after
    /\ Run system after following final

end CCF.Execution
