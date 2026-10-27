module

public import CCF.TransitionSystem
public import Mathlib.Data.Seq.Defs

@[expose] public section

namespace CCF.Execution

/-!
Executions of a `TransitionSystem`. `Run` relates a start state, a finite
action list, and an end state. `Trace` is an initial state followed by the
finite or infinite sequence of steps an execution takes, each recording its
before-state, action and after-state; properties quantify over every valid
`Trace`.
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

/-- Append one enabled action to the end of an execution. -/
theorem Run.snoc {system : TransitionSystem} {start middle final : system.State}
    {actions : List system.Action} {action : system.Action}
    (run : Run system start actions middle)
    (step : system.step middle action = some final)
    : Run system start (actions ++ [action]) final := by
  induction run with
  | nil => exact .cons step (.nil _)
  | cons first _ ih => exact .cons first (ih step)

/-- One recorded transition: the state an action is applied to, the action, and
the state it produces. -/
structure Step (State Action : Type) where
  /-- The state the action is applied to. -/
  before : State
  /-- The recorded action. -/
  action : Action
  /-- The state the action produces. -/
  after : State

/-- An initial state and the finite or infinite sequence of steps taken from it.
`steps.get? i` is `none` past the end of a finite trace. The steps form one
path: the first starts at `initial`, and each starts where its predecessor ended. -/
structure Trace (State Action : Type) where
  /-- The state before any step. -/
  initial : State
  /-- The steps taken, in execution order. -/
  steps : Stream'.Seq (Step State Action)
  /-- The first step starts at the initial state. -/
  first : forall step, steps.get? 0 = some step -> step.before = initial
  /-- Each step starts where its predecessor ended. -/
  linked
    : forall index previous next,
        steps.get? index = some previous
        -> steps.get? (index + 1) = some next
        -> previous.after = next.before

namespace Trace

variable {State Action : Type}

/-- The step at `index`, or `none` past the end of a finite trace. -/
def stepAt (trace : Trace State Action) (index : Nat) : Option (Step State Action) :=
  trace.steps.get? index

/-- The state after `index` steps: the initial state at zero, then each step's
after-state. `none` past the end of a finite trace. -/
def stateAt (trace : Trace State Action) : Nat -> Option State
  | 0 => some trace.initial
  | index + 1 => (trace.stepAt index).map Step.after

/-- A trace contains every state it passes through, including the initial state. -/
instance : Membership State (Trace State Action) where
  mem trace state := exists index, trace.stateAt index = some state

/-- The trace starts in an initial state, and every step is an enabled transition. -/
def Valid (system : TransitionSystem) (trace : Trace system.State system.Action) : Prop :=
  system.init trace.initial
  /\ forall index step,
      trace.stepAt index = some step
      -> system.step step.before step.action = some step.after

@[simp]
theorem stateAt_zero (trace : Trace State Action)
    : trace.stateAt 0 = some trace.initial :=
  rfl

@[simp]
theorem stateAt_succ (trace : Trace State Action) (index : Nat)
    : trace.stateAt (index + 1) = (trace.stepAt index).map Step.after :=
  rfl

theorem mem_iff {trace : Trace State Action} {state : State}
    : state ∈ trace <-> exists index, trace.stateAt index = some state :=
  Iff.rfl

theorem mem_of_stateAt {trace : Trace State Action} {index : Nat} {state : State}
    (found : trace.stateAt index = some state)
    : state ∈ trace :=
  ⟨index, found⟩

/-- The initial state is in every trace. -/
theorem initial_mem (trace : Trace State Action) : trace.initial ∈ trace :=
  ⟨0, rfl⟩

/-- A step starts at the state reached before it. -/
theorem stateAt_of_stepAt {trace : Trace State Action} {index : Nat}
    {step : Step State Action} (found : trace.stepAt index = some step)
    : trace.stateAt index = some step.before := by
  cases index with
  | zero => exact congrArg some (trace.first step found).symm
  | succ index =>
      obtain ⟨previous, earlier⟩ := trace.steps.ge_stable (Nat.le_succ index) found
      have joined := trace.linked index previous step earlier found
      simp only [stateAt_succ, stepAt, earlier, Option.map_some, joined]

/-- A step ends at the next state. -/
theorem stateAt_succ_of_stepAt {trace : Trace State Action} {index : Nat}
    {step : Step State Action} (found : trace.stepAt index = some step)
    : trace.stateAt (index + 1) = some step.after := by
  simp [found]

/-- A state after the initial one is the after-state of the preceding step. -/
theorem stateAt_succ_eq_some {trace : Trace State Action} {index : Nat} {state : State}
    : trace.stateAt (index + 1) = some state
      <-> exists step, trace.stepAt index = some step /\ step.after = state := by
  simp

/-- Consecutive states are joined by the step between them. -/
theorem exists_stepAt {trace : Trace State Action} {index : Nat} {before after : State}
    (current : trace.stateAt index = some before)
    (next : trace.stateAt (index + 1) = some after)
    : exists action, trace.stepAt index = some { before, action, after } := by
  obtain ⟨⟨stepBefore, action, stepAfter⟩, found, rfl⟩ := stateAt_succ_eq_some.mp next
  have same := (stateAt_of_stepAt found).symm.trans current
  simp only [Option.some.injEq] at same
  subst same
  exact ⟨action, found⟩

/-- Every position before a state of the trace also holds a state. -/
theorem stateAt_ge_stable {trace : Trace State Action} {index later : Nat} {state : State}
    (le : index <= later) (found : trace.stateAt later = some state)
    : exists earlier, trace.stateAt index = some earlier := by
  cases index with
  | zero => exact ⟨_, rfl⟩
  | succ index =>
      obtain ⟨later, rfl⟩ : exists previous, later = previous + 1 := ⟨later - 1, by omega⟩
      obtain ⟨step, found, _⟩ := stateAt_succ_eq_some.mp found
      obtain ⟨previous, earlier⟩ := trace.steps.ge_stable (by omega : index <= later) found
      exact ⟨previous.after, stateAt_succ_of_stepAt earlier⟩

/-- A trace that has ended stays ended. -/
theorem stateAt_le_stable {trace : Trace State Action} {index later : Nat}
    (le : index <= later) (missing : trace.stateAt index = none)
    : trace.stateAt later = none := by
  cases later with
  | zero => cases Nat.le_zero.mp le; simp at missing
  | succ later =>
      cases found : trace.stateAt (later + 1) with
      | none => rfl
      | some state =>
          obtain ⟨_, present⟩ := stateAt_ge_stable le found
          simp [present] at missing

/-- A state that is not the last is followed by a step. -/
theorem stepAt_of_stateAt_lt {trace : Trace State Action} {index later : Nat}
    {state : State} (lt : index < later) (found : trace.stateAt later = some state)
    : exists step, trace.stepAt index = some step := by
  obtain ⟨_, next⟩ := stateAt_ge_stable lt found
  obtain ⟨step, found, _⟩ := stateAt_succ_eq_some.mp next
  exact ⟨step, found⟩

/-- Induction over the states of a trace from `start`. -/
protected theorem induction (trace : Trace State Action) {start : Nat}
    {motive : Nat -> State -> Prop}
    (base : forall state, trace.stateAt start = some state -> motive start state)
    (next
      : forall index step,
          start <= index
          -> trace.stepAt index = some step
          -> motive index step.before
          -> motive (index + 1) step.after)
    : forall index state,
        start <= index -> trace.stateAt index = some state -> motive index state := by
  intro index state le found
  induction index, le using Nat.le_induction generalizing state with
  | base => exact base state found
  | succ index le held =>
      obtain ⟨step, stepped, rfl⟩ := stateAt_succ_eq_some.mp found
      exact next index step le stepped (held step.before (stateAt_of_stepAt stepped))

/-- A relation that every step preserves holds between any two states in order. -/
theorem chain (trace : Trace State Action) {relation : State -> State -> Prop}
    (refl : forall state, relation state state)
    (trans : forall a b c, relation a b -> relation b c -> relation a c)
    (next
      : forall index step,
          trace.stepAt index = some step -> relation step.before step.after)
    {earlier later : Nat} (le : earlier <= later) {source target : State}
    (sourceFound : trace.stateAt earlier = some source)
    (targetFound : trace.stateAt later = some target)
    : relation source target :=
  trace.induction (start := earlier) (motive := fun _ state => relation source state)
    (fun state found => by
      rw [sourceFound, Option.some.injEq] at found
      exact found ▸ refl source)
    (fun index step _ stepped held => trans _ _ _ held (next index step stepped))
    later target le targetFound

section Valid

variable {system : TransitionSystem} {trace : Trace system.State system.Action}

/-- A valid trace starts in an initial state. -/
theorem Valid.init (valid : trace.Valid system) : system.init trace.initial :=
  valid.1

/-- Every step of a valid trace is an enabled transition. -/
theorem Valid.enabled (valid : trace.Valid system) {index : Nat}
    {step : Step system.State system.Action} (found : trace.stepAt index = some step)
    : system.step step.before step.action = some step.after :=
  valid.2 index step found

/-- Consecutive states of a valid trace are joined by an enabled action. -/
theorem Valid.exists_action (valid : trace.Valid system) {index : Nat}
    {before after : system.State}
    (current : trace.stateAt index = some before)
    (next : trace.stateAt (index + 1) = some after)
    : exists action, system.step before action = some after := by
  obtain ⟨action, found⟩ := exists_stepAt current next
  exact ⟨action, valid.enabled found⟩

/-- Every state of a valid trace, by position, is reachable. -/
theorem Valid.reachable_stateAt (valid : trace.Valid system) {index : Nat}
    {state : system.State} (found : trace.stateAt index = some state)
    : system.Reachable state := by
  induction index generalizing state with
  | zero =>
      cases Option.some.inj found
      exact .initial valid.init
  | succ index ih =>
      obtain ⟨step, stepped, rfl⟩ := stateAt_succ_eq_some.mp found
      exact .step (ih (stateAt_of_stepAt stepped)) (valid.enabled stepped)

/-- Every state in a valid trace is reachable. -/
theorem Valid.reachable (valid : trace.Valid system) {state : system.State}
    (member : state ∈ trace)
    : system.Reachable state := by
  obtain ⟨_, found⟩ := member
  exact valid.reachable_stateAt found

end Valid

/-- The infinite trace through `states`, taking `actions index` from
`states index` to `states (index + 1)`. -/
def ofStream (states : Stream' State) (actions : Stream' Action)
    : Trace State Action where
  initial := states 0
  steps :=
    Stream'.Seq.ofStream
      fun index =>
        { before := states index, action := actions index, after := states (index + 1) }
  first _ found := by cases Option.some.inj found; rfl
  linked _ _ _ previous next := by
    cases Option.some.inj previous
    cases Option.some.inj next
    rfl

@[simp]
theorem ofStream_stepAt (states : Stream' State) (actions : Stream' Action) (index : Nat)
    : (ofStream states actions).stepAt index
      = some
          {
            before := states index, action := actions index, after := states (index + 1)
          } :=
  rfl

@[simp]
theorem ofStream_stateAt (states : Stream' State) (actions : Stream' Action) (index : Nat)
    : (ofStream states actions).stateAt index = some (states index) := by
  cases index <;> rfl

/-- The steps of executing `actions` from `before`, ending before the first
disabled action. -/
def runSteps (system : TransitionSystem)
    : system.State -> List system.Action -> List (Step system.State system.Action)
  | _, [] => []
  | before, action :: actions =>
      match system.step before action with
      | none => []
      | some after => { before, action, after } :: runSteps system after actions

theorem runSteps_first {system : TransitionSystem} {before : system.State}
    {actions : List system.Action} {step : Step system.State system.Action}
    (found : (runSteps system before actions)[0]? = some step)
    : step.before = before := by
  cases actions with
  | nil => simp [runSteps] at found
  | cons action actions =>
      cases stepped : system.step before action with
      | none => simp [runSteps, stepped] at found
      | some after =>
          simp only [runSteps, stepped, List.getElem?_cons_zero, Option.some.injEq] at found
          subst found
          rfl

theorem runSteps_linked {system : TransitionSystem} {before : system.State}
    {actions : List system.Action} {index : Nat}
    {previous next : Step system.State system.Action}
    (current : (runSteps system before actions)[index]? = some previous)
    (following : (runSteps system before actions)[index + 1]? = some next)
    : previous.after = next.before := by
  induction actions generalizing before index with
  | nil => simp [runSteps] at current
  | cons action actions ih =>
      cases stepped : system.step before action with
      | none => simp [runSteps, stepped] at current
      | some after =>
          simp only [runSteps, stepped] at current following
          cases index with
          | zero =>
              simp only [List.getElem?_cons_zero, Option.some.injEq] at current
              subst current
              simp only [List.getElem?_cons_succ] at following
              exact (runSteps_first following).symm
          | succ index =>
              simp only [List.getElem?_cons_succ] at current following
              exact ih current following

theorem runSteps_enabled {system : TransitionSystem} {before : system.State}
    {actions : List system.Action} {step : Step system.State system.Action}
    (member : step ∈ runSteps system before actions)
    : system.step step.before step.action = some step.after := by
  induction actions generalizing before with
  | nil => simp [runSteps] at member
  | cons action actions ih =>
      cases stepped : system.step before action with
      | none => simp [runSteps, stepped] at member
      | some after =>
          simp only [runSteps, stepped] at member
          rcases List.mem_cons.mp member with rfl | member
          · exact stepped
          · exact ih member

/-- The finite trace of executing `actions` from `initial`. A disabled action
ends the trace before it. -/
def run (system : TransitionSystem) (initial : system.State)
    (actions : List system.Action)
    : Trace system.State system.Action where
  initial
  steps := Stream'.Seq.ofList (runSteps system initial actions)
  first _ found := by
    rw [Stream'.Seq.ofList_get?] at found
    exact runSteps_first found
  linked _ _ _ current following := by
    rw [Stream'.Seq.ofList_get?] at current following
    exact runSteps_linked current following

/-- Every step of an executed trace is enabled, so it is valid from an initial state. -/
theorem run_valid {system : TransitionSystem} {initial : system.State}
    {actions : List system.Action} (initialized : system.init initial)
    : (run system initial actions).Valid system := by
  refine ⟨initialized, fun index step found => ?_⟩
  simp only [stepAt, run, Stream'.Seq.ofList_get?] at found
  exact runSteps_enabled (List.mem_of_getElem? found)

/-- Executing an enabled action first shifts every later state by one position. -/
theorem run_cons_stateAt_succ {system : TransitionSystem} {before middle : system.State}
    {action : system.Action} {actions : List system.Action}
    (stepped : system.step before action = some middle) (index : Nat)
    : (run system before (action :: actions)).stateAt (index + 1)
      = (run system middle actions).stateAt index := by
  cases index <;>
    simp [stepAt, run, runSteps, stepped, Stream'.Seq.ofList_get?]

/-- An execution's final state is the state after all of its actions. -/
theorem run_stateAt_length {system : TransitionSystem} {start final : system.State}
    {actions : List system.Action} (execution : Run system start actions final)
    : (run system start actions).stateAt actions.length = some final := by
  induction execution with
  | nil => rfl
  | cons stepped _ ih =>
      rw [List.length_cons, run_cons_stateAt_succ stepped]
      exact ih

end Trace

/-- Valid traces cover exactly the reachable states. Every reachable state is the
last state of some valid finite trace. -/
theorem reachable_iff_trace {system : TransitionSystem} {state : system.State}
    : system.Reachable state
      <-> exists trace : Trace system.State system.Action,
            trace.Valid system /\ state ∈ trace := by
  constructor
  · intro reachable
    suffices execution : exists initial actions,
        system.init initial /\ Run system initial actions state by
      obtain ⟨initial, actions, initialized, execution⟩ := execution
      exact ⟨_, Trace.run_valid initialized,
        Trace.mem_of_stateAt (Trace.run_stateAt_length execution)⟩
    induction reachable with
    | initial initialized => exact ⟨_, [], initialized, .nil _⟩
    | step _ stepped ih =>
        obtain ⟨initial, actions, initialized, execution⟩ := ih
        exact ⟨initial, actions ++ [_], initialized, execution.snoc stepped⟩
  · rintro ⟨trace, valid, member⟩
    exact valid.reachable member

end CCF.Execution
