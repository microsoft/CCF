module

import CCFRaft.Properties.Liveness.Model.Scheduling
import Mathlib.Tactic.Linarith

/-!
Regression checks for `CheckQuorumScheduling window` with node 0 the
primary of configuration `{0, 1}`. It may step down only once `window` has
passed both since it became primary and since node 1 last responded. A check
with no recorded reset before it is always permitted. Appending a configuration
that adds node 2 resets node 2's acknowledgement age, but not node 1's.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Tests.CheckQuorumScheduling

open CCFRaft.Model.Node
open CCFRaft.Liveness

/-- A protocol state and clock. -/
structure ClockWorld where
  state : Model.State
  clock : Real

instance : HasProtocol ClockWorld Model.State := ⟨ClockWorld.state⟩
instance : HasTime ClockWorld := ⟨ClockWorld.clock⟩
instance : HasLive ClockWorld := ⟨fun _ => {0, 1}⟩

@[simp]
theorem proto_eq (world : ClockWorld) : HasProtocol.proto world = world.state := rfl

@[simp] theorem time_eq (world : ClockWorld) : HasTime.time world = world.clock := rfl

abbrev Step := CCF.Execution.Step ClockWorld Liveness.Event

/-- The only configuration. -/
def pair : Configuration := { index := 1, nodes := {0, 1} }

/-- Node 0 follows the committed configuration `pair`. -/
def follower : NodeState :=
  {
    Model.initialNodeState {0, 1} 0 with
      role := .follower
      log :=
        [
          { term := 2, content := .transaction 0 { configuration := some {0, 1} } },
          { term := 2, content := .signature }
        ]
      commitIndex := 2
  }

def primary : NodeState := { follower with role := .primary, primaryKnown := true }

theorem primary_active : primary.activeConfigurations = [pair] := by decide

/-- Node 0 alone, holding `node`, at time `clock`. -/
def world (node : NodeState) (clock : Real) : ClockWorld :=
  { state := { nodes := [(0, node)] }, clock }

theorem follower_not_primary (clock : Real)
    : Not (IsPrimary (world follower clock) 0) := by
  rintro ⟨state, found, role⟩
  cases found
  exact absurd role (by decide)

theorem primary_primary (clock : Real) : IsPrimary (world primary clock) 0 :=
  ⟨primary, rfl, rfl⟩

/-- Node 0 becomes primary at time zero. -/
def elect : Step :=
  {
    before := world follower 0,
    action := .local 0 (.timeout .election),
    after := world primary 0
  }

/-- The primary receives node 1's AppendEntries response at time `clock`. -/
def ack (clock : Real) : Step :=
  {
    before := world primary clock
    action :=
      .deliver
        {
          id := 0
          envelope :=
            {
              source := 1
              target := 0
              payload :=
                .appendEntriesResponse { term := 2, success := true, lastLogIndex := 2 }
            }
          sentAt := 0
        }
    after := world primary clock
  }

/-- The primary steps down on a quorum check at time `clock`. -/
def check (clock : Real) : Step :=
  {
    before := world primary clock
    action := .local 0 (.timeout .checkQuorum)
    after := world follower clock
  }

theorem elect_resets : AckReset elect 0 1 :=
  .inr (.inl ⟨follower_not_primary 0, primary_primary 0⟩)

theorem ack_resets (clock : Real) : AckReset (ack clock) 0 1 :=
  .inl ⟨primary_primary clock, _, _, rfl, rfl, rfl, rfl⟩

/-- The primary after appending configuration `{0, 1, 2}`. -/
def grown : NodeState :=
  {
    primary with
      log :=
        primary.log
        ++ [{ term := 2, content := .transaction 1 { configuration := some {0, 1, 2} } }]
  }

/-- The primary appends configuration `{0, 1, 2}` at time `clock`. -/
def grow (clock : Real) : Step :=
  {
    before := world primary clock
    action := .local 0 (.append [.transaction 1 { configuration := some {0, 1, 2} }])
    after := world grown clock
  }

/-- Starting to track node 2 zeroes its acknowledgement age. -/
theorem grow_resets (clock : Real) : AckReset (grow clock) 0 2 :=
  .inr (.inr ⟨primary, grown, rfl, rfl, rfl, rfl, by decide, by decide⟩)

/-- Node 1 was already tracked, so its acknowledgement age is unchanged. -/
theorem grow_keeps (clock : Real) : Not (AckReset (grow clock) 0 1) := by
  rintro (⟨-, _, _, action, -⟩ | ⟨primary', -⟩ | ⟨before, -, found, -, -, -, untracked, -⟩)
  · cases action
  · exact primary' (primary_primary clock)
  · cases found
    exact untracked (by decide)

/-- Time passes from `earlier` to `later` while node 0 stays primary. -/
def tick (earlier later : Real) : Step :=
  { before := world primary earlier, action := .idle, after := world primary later }

/-- Idling changes nothing node 0 tracks. -/
theorem tick_quiet (earlier later : Real) : Not (AckReset (tick earlier later) 0 1) := by
  rintro (⟨-, _, _, action, -⟩ | ⟨primary', -⟩ | ⟨before, after, found, -, found', -, untracked, tracked⟩)
  · cases action
  · exact primary' (primary_primary earlier)
  · cases found
    cases found'
    exact untracked tracked

/-- Each step starts where its predecessor ended, the first at `before`. -/
def Linked : ClockWorld -> List Step -> Prop
  | _, [] => True
  | before, step :: steps => step.before = before /\ Linked step.after steps

theorem Linked.first {before : ClockWorld} {steps : List Step} {step : Step}
    (chained : Linked before steps) (found : steps[0]? = some step)
    : step.before = before := by
  cases steps with
  | nil => simp at found
  | cons head tail =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at found
      subst found
      exact chained.1

theorem Linked.next {before : ClockWorld} {steps : List Step} {index : Nat}
    {previous next : Step} (chained : Linked before steps)
    (current : steps[index]? = some previous) (following : steps[index + 1]? = some next)
    : previous.after = next.before := by
  induction steps generalizing before index with
  | nil => simp at current
  | cons head tail ih =>
      cases index with
      | zero =>
          simp only [List.getElem?_cons_zero, Option.some.injEq] at current
          subst current
          simp only [List.getElem?_cons_succ] at following
          exact (chained.2.first following).symm
      | succ index =>
          simp only [List.getElem?_cons_succ] at current following
          exact ih chained.2 current following

/-- The recording of `steps` from `initial`. -/
def run (initial : ClockWorld) (steps : List Step) (chained : Linked initial steps)
    : Trace ClockWorld Liveness.Event where
  initial
  steps := Stream'.Seq.ofList steps
  first _ found := by
    rw [Stream'.Seq.ofList_get?] at found
    exact chained.first found
  linked _ _ _ current following := by
    rw [Stream'.Seq.ofList_get?] at current following
    exact chained.next current following

@[simp]
theorem run_stepAt (initial : ClockWorld) (steps : List Step)
    (chained : Linked initial steps) (index : Nat)
    : (run initial steps chained).stepAt index = steps[index]? := by
  simp [run, Trace.stepAt]

theorem lone_linked (now : Real) : Linked (world primary now) [check now] := by
  simp [Linked, check]

/-- A primary checks quorum at `now`, with nothing before. -/
def lone (now : Real) : Trace ClockWorld Liveness.Event :=
  run (world primary now) [check now] (lone_linked now)

theorem fresh_linked (now : Real)
    : Linked (world follower 0) [elect, tick 0 now, check now] := by
  simp [Linked, elect, tick, check]

/-- Node 0 is elected at time zero and checks quorum at `now`. -/
def fresh (now : Real) : Trace ClockWorld Liveness.Event :=
  run (world follower 0) [elect, tick 0 now, check now] (fresh_linked now)

theorem acked_linked (responded now : Real)
    : Linked (world follower 0)
        [elect, tick 0 responded, ack responded, tick responded now, check now] := by
  simp [Linked, elect, tick, ack, check]

/-- As `fresh`, with node 1 responding at `responded` in between. -/
def acked (responded now : Real) : Trace ClockWorld Liveness.Event :=
  run (world follower 0)
    [elect, tick 0 responded, ack responded, tick responded now, check now]
    (acked_linked responded now)

/-- Node 0 counts a majority of `pair` exactly when it counts both nodes. -/
theorem majority_iff (responders : Finset NodeID)
    : hasConfigurationMajority responders pair <-> 0 ∈ responders /\ 1 ∈ responders := by
  have size : ({0, 1} : Finset NodeID).card = 2 := by decide
  unfold hasConfigurationMajority pair
  constructor
  · intro big
    by_contra missing
    have small : (responders ∩ {0, 1}).card <= 1 := by
      rcases not_and_or.mp missing with absent | absent
      · calc (responders ∩ {0, 1}).card <= ({1} : Finset NodeID).card := by
              apply Finset.card_le_card
              intro node mem
              simp only [Finset.mem_inter, Finset.mem_insert, Finset.mem_singleton] at mem ⊢
              rcases mem with ⟨inside, rfl | rfl⟩
              · exact absurd inside absent
              · rfl
          _ = 1 := Finset.card_singleton 1
      · calc (responders ∩ {0, 1}).card <= ({0} : Finset NodeID).card := by
              apply Finset.card_le_card
              intro node mem
              simp only [Finset.mem_inter, Finset.mem_insert, Finset.mem_singleton] at mem ⊢
              rcases mem with ⟨inside, rfl | rfl⟩
              · rfl
              · exact absurd inside absent
          _ = 1 := Finset.card_singleton 0
    simp only [size] at big
    omega
  · rintro ⟨zero, one⟩
    have whole : responders ∩ {0, 1} = {0, 1} := by
      ext node
      simp only [Finset.mem_inter, Finset.mem_insert, Finset.mem_singleton]
      constructor
      · exact And.right
      · rintro (rfl | rfl)
        · exact ⟨zero, .inl rfl⟩
        · exact ⟨one, .inr rfl⟩
    rw [whole, size]
    norm_num

/-- Some step before `index` resets node 0's acknowledgement age for node 1 less
than `window` before `now`. -/
def Heard (trace : Trace ClockWorld Liveness.Event) (index : Nat) (window now : Real)
    : Prop :=
  exists earlier reset,
    earlier < index
    /\ trace.stepAt earlier = some reset
    /\ AckReset reset 0 1
    /\ now < reset.before.clock + window

/-- The clause for a check at `index` and time `now` holds exactly when node 1
has not been heard from recently. -/
theorem lost_iff (trace : Trace ClockWorld Liveness.Event) (index : Nat)
    (window now : Real)
    : (exists state,
        CCF.MultiNodeTransitionSystem.nodeState (HasProtocol.proto (check now).before) 0
          = some state
        /\ exists configuration,
            configuration ∈ state.activeConfigurations
            /\ Not
                (exists responders,
                  hasConfigurationMajority responders configuration
                  /\ forall peer,
                      peer ∈ responders
                      -> peer = 0
                          \/ AckedAfter trace index 0 peer
                              (HasTime.time (check now).before - window)))
      <-> Not (Heard trace index window now) := by
  constructor
  · rintro ⟨state, found, configuration, mem, lost⟩ heard
    cases found
    rw [primary_active, List.mem_singleton] at mem
    subst mem
    refine lost ⟨{0, 1}, (majority_iff _).2 (by simp), fun peer inside => ?_⟩
    simp only [Finset.mem_insert, Finset.mem_singleton] at inside
    rcases inside with rfl | rfl
    · exact .inl rfl
    · obtain ⟨earlier, reset, before, stepped, resets, recent⟩ := heard
      exact .inr ⟨earlier, reset, before, stepped, resets, by
        simp only [check, world, time_eq] at recent ⊢
        linarith⟩
  · intro quiet
    refine ⟨primary, rfl, pair, by simp [primary_active], ?_⟩
    rintro ⟨responders, majority, counted⟩
    rcases counted 1 ((majority_iff responders).1 majority).2 with self | heard
    · exact absurd self (by decide)
    · obtain ⟨earlier, reset, before, stepped, resets, recent⟩ := heard
      exact quiet ⟨earlier, reset, before, stepped, resets, by
        simp only [check, world, time_eq] at recent ⊢
        linarith⟩

/-- A check with nothing recorded before it is always permitted. -/
theorem unrecorded (window now : Real) : CheckQuorumScheduling (lone now) window := by
  intro index step leader stepped action
  match index with
  | 0 =>
      simp only [lone, run_stepAt, List.getElem?_cons_zero, Option.some.injEq] at stepped
      subst stepped
      simp only [check, Event.local.injEq, and_true] at action
      subst action
      exact (lost_iff _ 0 window now).2 fun ⟨_, _, before, _⟩ => by omega
  | _ + 1 => simp [lone] at stepped

/-- A new primary may not step down within `window` of becoming primary. -/
theorem grace_iff (window now : Real)
    : CheckQuorumScheduling (fresh now) window <-> window <= now := by
  have heard : Heard (fresh now) 2 window now <-> now < window := by
    constructor
    · rintro ⟨earlier, reset, before, stepped, resets, recent⟩
      match earlier, before with
      | 0, _ =>
          simp only [fresh, run_stepAt, List.getElem?_cons_zero, Option.some.injEq] at stepped
          subst stepped
          simpa [elect, world] using recent
      | 1, _ =>
          simp only [fresh, run_stepAt, List.getElem?_cons_succ, List.getElem?_cons_zero,
            Option.some.injEq] at stepped
          subst stepped
          exact absurd resets (tick_quiet 0 now)
    · intro recent
      exact ⟨0, elect, by omega, rfl, elect_resets, by simpa [elect, world] using recent⟩
  constructor
  · intro scheduled
    have := (lost_iff _ 2 window now).1 (scheduled 2 (check now) 0 rfl rfl)
    rw [heard] at this
    exact not_lt.1 this
  · intro late index step leader stepped action
    match index with
    | 0 =>
        simp only [fresh, run_stepAt, List.getElem?_cons_zero, Option.some.injEq] at stepped
        subst stepped
        simp [elect] at action
    | 1 =>
        simp only [fresh, run_stepAt, List.getElem?_cons_succ, List.getElem?_cons_zero,
          Option.some.injEq] at stepped
        subst stepped
        simp [tick] at action
    | 2 =>
        simp only [fresh, run_stepAt, List.getElem?_cons_succ, List.getElem?_cons_zero,
          Option.some.injEq] at stepped
        subst stepped
        simp only [check, Event.local.injEq, and_true] at action
        subst action
        exact (lost_iff _ 2 window now).2 (by rw [heard]; exact not_lt.2 late)
    | _ + 3 => simp [fresh] at stepped

/-- After a response from node 1 at time `responded`, the primary may step down
only `window` later. -/
theorem ack_iff (window responded now : Real) (after : 0 <= responded)
    : CheckQuorumScheduling (acked responded now) window
      <-> responded + window <= now := by
  have heard
      : Heard (acked responded now) 4 window now
        <-> now < responded + window := by
    constructor
    · rintro ⟨earlier, reset, before, stepped, resets, recent⟩
      match earlier, before with
      | 0, _ =>
          simp only [acked, run_stepAt, List.getElem?_cons_zero, Option.some.injEq] at stepped
          subst stepped
          simp only [elect, world] at recent
          linarith
      | 1, _ =>
          simp only [acked, run_stepAt, List.getElem?_cons_succ, List.getElem?_cons_zero,
            Option.some.injEq] at stepped
          subst stepped
          exact absurd resets (tick_quiet 0 responded)
      | 2, _ =>
          simp only [acked, run_stepAt, List.getElem?_cons_succ, List.getElem?_cons_zero,
            Option.some.injEq] at stepped
          subst stepped
          simpa [ack, world] using recent
      | 3, _ =>
          simp only [acked, run_stepAt, List.getElem?_cons_succ, List.getElem?_cons_zero,
            Option.some.injEq] at stepped
          subst stepped
          exact absurd resets (tick_quiet responded now)
    · intro recent
      exact ⟨2, ack responded, by omega, rfl, ack_resets responded,
        by simpa [ack, world] using recent⟩
  constructor
  · intro scheduled
    have := (lost_iff _ 4 window now).1 (scheduled 4 (check now) 0 rfl rfl)
    rw [heard] at this
    exact not_lt.1 this
  · intro late index step leader stepped action
    match index with
    | 0 =>
        simp only [acked, run_stepAt, List.getElem?_cons_zero, Option.some.injEq] at stepped
        subst stepped
        simp [elect] at action
    | 1 | 3 =>
        simp only [acked, run_stepAt, List.getElem?_cons_succ, List.getElem?_cons_zero,
          Option.some.injEq] at stepped
        subst stepped
        simp [tick] at action
    | 2 =>
        simp only [acked, run_stepAt, List.getElem?_cons_succ, List.getElem?_cons_zero,
          Option.some.injEq] at stepped
        subst stepped
        simp [ack] at action
    | 4 =>
        simp only [acked, run_stepAt, List.getElem?_cons_succ, List.getElem?_cons_zero,
          Option.some.injEq] at stepped
        subst stepped
        simp only [check, Event.local.injEq, and_true] at action
        subst action
        exact (lost_iff _ 4 window now).2 (by rw [heard]; exact not_lt.2 late)
    | _ + 5 => simp [acked] at stepped

end CCFRaft.Tests.CheckQuorumScheduling
