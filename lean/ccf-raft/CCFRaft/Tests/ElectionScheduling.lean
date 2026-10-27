module

import CCFRaft.Proofs.Liveness.Timers

/-!
Regression checks for `ElectionScheduling minimum jitter` on one eligible
node. `minimum = some m` bounds each reset's draw to `[m, 2 * m]`; `none` drops
only that bound, still fixing deadlines between resets and forbidding early
timeouts. `jitter = none` still requires an overdue eligible node to time out
eventually, and `some j` caps the clock's overshoot past a deadline.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Tests.ElectionScheduling

open CCFRaft.Model.Node
open CCFRaft.Liveness

/-- A protocol state, clock, live set and election deadlines. -/
structure TimerWorld where
  state : Model.State
  clock : Real
  alive : Finset NodeID
  deadlines : NodeID -> Real

instance : HasProtocol TimerWorld Model.State := ⟨TimerWorld.state⟩
instance : HasTime TimerWorld := ⟨TimerWorld.clock⟩
instance : HasLive TimerWorld := ⟨TimerWorld.alive⟩
instance : HasTimers TimerWorld := ⟨TimerWorld.deadlines⟩

@[simp]
theorem proto_eq (world : TimerWorld) : HasProtocol.proto world = world.state := rfl

@[simp] theorem time_eq (world : TimerWorld) : HasTime.time world = world.clock := rfl
@[simp] theorem live_eq (world : TimerWorld) : HasLive.live world = world.alive := rfl

@[simp]
theorem deadline_eq (world : TimerWorld) : HasTimers.deadline world = world.deadlines :=
  rfl

abbrev Step := CCF.Execution.Step TimerWorld Liveness.Event

/-- Node 1 follows a signed configuration, so it may start an election. -/
def follower : NodeState :=
  {
    Model.initialNodeState {0, 1, 2} 1 with
      log :=
        [
          { term := 2, content := .transaction 0 { configuration := some {0, 1, 2} } },
          { term := 2, content := .signature }
        ]
      commitIndex := 2
  }

theorem follower_eligible : canStartElection follower 1 := by decide

/-- Only node 1 is live and holds `follower`; it has deadline `due`, every other
node has deadline zero. -/
def world (clock due : Real) : TimerWorld :=
  {
    state := { nodes := [(1, follower)] }
    clock
    alive := {1}
    deadlines := fun node => if node = 1 then due else 0
  }

theorem follower_found (clock due : Real)
    : CCF.MultiNodeTransitionSystem.nodeState (world clock due).state 1 = some follower :=
  rfl

/-- Node 1 is due exactly when its deadline has passed. -/
theorem due_iff (clock due : Real) (node : NodeID)
    : TimeoutDue (world clock due) node <-> node = 1 /\ due <= clock := by
  constructor
  · rintro ⟨live, passed, -⟩
    simp only [live_eq, world, Finset.mem_singleton] at live
    subst live
    simpa [world] using passed
  · rintro ⟨rfl, passed⟩
    exact ⟨by simp [world], by simpa [world] using passed, follower, follower_found clock due,
      follower_eligible⟩

/-- A recording of `step` alone. -/
def single (step : Step) : Trace TimerWorld Liveness.Event where
  initial := step.before
  steps := Stream'.Seq.ofList [step]
  first _ found := by
    simp only [Stream'.Seq.ofList_get?, List.getElem?_cons_zero, Option.some.injEq] at found
    rw [found]
  linked _ _ _ _ following := by simp at following

theorem single_stepAt {step found : Step} {index : Nat}
    (stepped : (single step).stepAt index = some found)
    : index = 0 /\ found = step := by
  cases index with
  | zero =>
      simp only [single, Trace.stepAt, Stream'.Seq.ofList_get?] at stepped
      simp_all
  | succ index => simp [single, Trace.stepAt] at stepped

theorem single_stepAt_zero (step : Step) : (single step).stepAt 0 = some step := by
  simp [single, Trace.stepAt]

/-- Node 1 times out at time zero with deadline `due`, then draws `drawn`. -/
def timeout (due drawn : Real) : Step :=
  {
    before := world 0 due, action := .local 1 (.timeout .election), after := world 0 drawn
  }

theorem timeout_resets (due drawn : Real) (node : NodeID)
    : ElectionReset (timeout due drawn) node <-> node = 1 := by
  simp [ElectionReset, timeout, eq_comm]

/-- The timeout step's validity for every node, given the draw clause for node 1. -/
theorem timeout_valid {minimum : Option Real} {due drawn : Real}
    (early : due <= 0)
    (drawOk
      : match minimum with
        | none => True
        | some minimum => 0 + minimum <= drawn /\ drawn <= 0 + 2 * minimum)
    : ElectionTimeouts (single (timeout due drawn)) minimum := by
  refine ⟨fun {index step} stepped node => ?_⟩
  obtain ⟨rfl, rfl⟩ := single_stepAt stepped
  by_cases one : node = 1
  · subst one
    refine ⟨fun _ => ?_, fun quiet => absurd ((timeout_resets due drawn 1).2 rfl) quiet,
      fun _ => by simpa [timeout, world] using early⟩
    cases minimum with
    | none => trivial
    | some minimum => simpa [timeout, world] using drawOk
  · refine ⟨fun reset => absurd ((timeout_resets due drawn node).1 reset) one,
      fun _ => by simp [timeout, world, one], fun fires => ?_⟩
    simp only [timeout, Event.local.injEq] at fires
    exact absurd fires.1.symm one

/-- `some 1` accepts exactly a timeout at or after its deadline that draws within
`[1, 2]` of the reset. -/
theorem timeout_some_iff (due drawn : Real)
    : ElectionTimeouts (single (timeout due drawn)) (some 1)
      <-> due <= 0 /\ 1 <= drawn /\ drawn <= 2 := by
  constructor
  · intro valid
    obtain ⟨draw, -, early⟩ := valid.next (single_stepAt_zero (timeout due drawn)) 1
    have drawn' := draw ((timeout_resets due drawn 1).2 rfl)
    have early' := early rfl
    simp only [timeout, world, deadline_eq, time_eq, ite_true] at drawn' early'
    exact ⟨early', by linarith [drawn'.1], by linarith [drawn'.2]⟩
  · rintro ⟨early, low, high⟩
    exact timeout_valid early ⟨by linarith, by linarith⟩

/-- `none` accepts any draw, but still rejects a timeout before its deadline. -/
theorem timeout_none_iff (due drawn : Real)
    : ElectionTimeouts (single (timeout due drawn)) none <-> due <= 0 := by
  constructor
  · intro valid
    have early := (valid.next (single_stepAt_zero (timeout due drawn)) 1).2.2 rfl
    simpa [timeout, world] using early
  · intro early
    exact timeout_valid early trivial

/-- An idle step moving node 1's deadline from `due` to `moved`. -/
def drift (due moved : Real) : Step :=
  { before := world 0 due, action := .idle, after := world 0 moved }

/-- Even with `minimum = none`, a deadline changes only on a reset. -/
theorem drift_none_iff (due moved : Real)
    : ElectionTimeouts (single (drift due moved)) none <-> moved = due := by
  constructor
  · intro valid
    have kept := (valid.next (single_stepAt_zero (drift due moved)) 1).2.1
      (by simp [ElectionReset, drift])
    simpa [drift, world] using kept
  · rintro rfl
    refine ⟨fun {index step} stepped node => ?_⟩
    obtain ⟨rfl, rfl⟩ := single_stepAt stepped
    exact ⟨fun _ => trivial, fun _ => rfl, fun fires => by simp [drift] at fires⟩

/-- An idle step advancing the clock from zero to `clock`, before node 1's
deadline of one. -/
def advance (clock : Real) : Step :=
  { before := world 0 1, action := .idle, after := world clock 1 }

/-- `some jitter` lets the clock pass a pending deadline by at most `jitter`. -/
theorem advance_overshoot_iff (clock jitter : Real)
    : NoOvershoot (some jitter) (advance clock) 1 <-> clock <= 1 + jitter := by
  constructor
  · intro bounded
    have := bounded (by simp [advance, world])
      ⟨follower, follower_found 0 1, follower_eligible⟩ (by simp [advance, world])
    simpa [advance, world] using this
  · intro bound _ _ _
    simpa [advance, world] using bound

/-- A recording that stops at time zero, with node 1's deadline at `due`. -/
def stopped (due : Real) : Trace TimerWorld Liveness.Event where
  initial := world 0 due
  steps := Stream'.Seq.nil
  first _ found := by simp at found
  linked _ _ _ current := by simp at current

theorem stopped_stepAt (due : Real) (index : Nat)
    : (stopped due).stepAt index = none := by
  simp [stopped, Trace.stepAt]

/-- Even with `jitter = none`, a recording cannot stop while an eligible node is
overdue; it may stop before the deadline. -/
theorem stopped_iff (due : Real)
    : ElectionScheduling (stopped due) none none <-> 0 < due := by
  constructor
  · intro scheduled
    by_contra late
    have due' := (due_iff 0 due 1).2 ⟨rfl, not_lt.1 late⟩
    obtain ⟨later, point, -, found, -, resolved⟩ := scheduled.firing 1 0 _ rfl due'
    cases later with
    | zero =>
        simp only [Trace.stateAt, stopped, Option.some.injEq] at found
        subst found
        rcases resolved with notDue | ⟨step, stepped, -⟩
        · exact notDue due'
        · simp [stopped_stepAt] at stepped
    | succ later => simp [Trace.stateAt, stopped_stepAt] at found
  · intro early
    refine ⟨⟨fun {index step} stepped => by simp [stopped_stepAt] at stepped⟩, ?_,
      fun index step node stepped => by simp [stopped_stepAt] at stepped⟩
    intro node index point found due'
    cases index with
    | zero =>
        simp only [Trace.stateAt, stopped, Option.some.injEq] at found
        subst found
        have := ((due_iff 0 due node).1 due').2
        linarith
    | succ index => simp [Trace.stateAt, stopped_stepAt] at found

/-- With zero jitter, a node that fires as soon as it is due, then draws a
deadline in range, meets the whole contract. -/
theorem timeout_scheduled
    : ElectionScheduling (single (timeout 0 1)) (some 1) (some 0) := by
  refine ⟨(timeout_some_iff 0 1).2 ⟨le_rfl, le_rfl, by norm_num⟩, ?_, ?_⟩
  · intro node index point found due'
    match index with
    | 0 =>
        simp only [Trace.stateAt, single, timeout, Option.some.injEq] at found
        subst found
        obtain ⟨rfl, -⟩ := (due_iff 0 0 node).1 due'
        exact ⟨
          0,
          world 0 0,
          le_rfl,
          rfl,
          by simp [Deadline],
          Or.inr ⟨timeout 0 1, single_stepAt_zero _, rfl⟩
        ⟩
    | 1 =>
        simp only [Trace.stateAt, single_stepAt_zero, Option.map_some, timeout,
          Option.some.injEq] at found
        subst found
        have := ((due_iff 0 1 node).1 due').2
        norm_num at this
    | index + 2 =>
        simp [Trace.stateAt, single, Trace.stepAt] at found
  · intro index step node stepped
    obtain ⟨rfl, rfl⟩ := single_stepAt stepped
    intro _ _ before
    simp [timeout, world] at before

/-- Spacing is derived from timeouts and the timing model, not assumed separately. -/
example {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasTimers W]
    {trace : Trace W Liveness.Event} {minimum jitter : Option Real}
    (scheduled : ElectionScheduling trace minimum jitter)
    (timing : Satisfies trace timingModel)
    : ElectionSpacing trace minimum :=
  scheduled.spacing timing

end CCFRaft.Tests.ElectionScheduling
