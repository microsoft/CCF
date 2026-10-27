module

public import CCFRaft.Proofs.Leadership.Settles
public import CCFRaft.Proofs.Leadership.Init
public import CCFRaft.Proofs.Duel.ElectedNet
public import CCFRaft.Proofs.Liveness.Timers

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The good period of a minimal start

From `start` no node crashes, no packet is dropped, nobody nominates a successor
and no configuration is appended, so every listed node live at `start` stays live
and the listed nodes form a good period of any length. Election deadlines at least
half an election timeout past `start` stay so, since each reset draws at least
that far past a later time.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasTimers (deadline)

section Timers

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasTimers W]
  {trace : Trace W Liveness.Event} {minimum : Real}
  (timing : Satisfies trace timingModel) (timers : ElectionTimeouts trace (some minimum))
  {start : Nat} {first : W} (firstFound : trace.stateAt start = some first)
  {node : NodeID} (initial : time first + minimum <= deadline first node)

include timing timers firstFound initial

/-- A deadline at least `minimum` past the start time stays so. -/
theorem deadline_floor {index : Nat} {point : W} (afterStart : start <= index)
    (found : trace.stateAt index = some point)
    : time first + minimum <= deadline point node :=
  trace.induction
    (start := start)
    (motive := fun _ point => time first + minimum <= deadline point node)
    (fun point found => by
      rw [firstFound, Option.some.injEq] at found
      exact found ▸ initial)
    (fun _ step afterStart stepped held => by
      by_cases resets : ElectionReset step node
      · have elapsed :=
          time_mono timing afterStart firstFound (Trace.stateAt_of_stepAt stepped)
        have drawn := (((timers.next stepped) node).1 resets).1
        linarith
      · rw [((timers.next stepped) node).2.1 resets]
        exact held)
    index point afterStart found

/-- Such a node times out only at least `minimum` past the start time. -/
theorem timeout_late {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (afterStart : start <= index) (stepped : trace.stepAt index = some step)
    (fires : step.action = .local node (.timeout .election))
    : time first + minimum <= time step.before := by
  have floor :=
    deadline_floor timing timers firstFound initial afterStart
      (Trace.stateAt_of_stepAt stepped)
  have passed := ((timers.next stepped) node).2.2 fires
  linarith

end Timers

section Good

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {nodes : List NodeID} {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)
  {start : Nat}
  (noCrash
    : forall index step node,
        start <= index
        -> trace.stepAt index = some step
        -> Not (step.action = .crash node))

include admissible noCrash

/-- With no crash from `start`, a node live at `start` stays live. -/
theorem live_from {first : W} (firstFound : trace.stateAt start = some first)
    {node : NodeID} (alive : node ∈ live first) {index : Nat} {point : W}
    (afterStart : start <= index) (found : trace.stateAt index = some point)
    : node ∈ live point :=
  trace.induction
    (start := start)
    (motive := fun _ point => node ∈ live point)
    (fun point found => by
      rw [firstFound, Option.some.injEq] at found
      exact found ▸ alive)
    (fun later step afterStart stepped held => by
      by_contra gone
      exact noCrash later step node afterStart stepped (admissible.crashes stepped held gone))
    index point afterStart found

omit noCrash in
/-- A delivered envelope comes from one of the system's nodes. -/
theorem delivered_source {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {envelope : Model.Envelope}
    (delivered : step.action.delivered = some envelope)
    : envelope.source ∈ nodes := by
  obtain ⟨packet, actionEq, rfl⟩
      : exists packet, step.action = .deliver packet /\ packet.envelope = envelope := by
    cases h : step.action <;> simp_all [Liveness.Event.delivered]
  have selected : step.action.action = some (.deliver packet.envelope) := by
    rw [actionEq]
    rfl
  have reachable := admissible.reachable_before stepped
  obtain ⟨sender, member, _⟩ :=
    Duel.Elected.network_terms reachable _
      (Concrete.step_deliver (admissible.step stepped selected)).1
  rw [← Leadership.keys_eq reachable]
  exact List.mem_map.mpr ⟨_, member, rfl⟩

/-- From a start where every listed node is live, with no crash, drop, nomination
or configuration change from `start` onward, the listed nodes form a good period
of any length. -/
theorem minimal_good {first : W} (firstFound : trace.stateAt start = some first)
    (alive : forall node, node ∈ nodes -> node ∈ live first)
    (noDrop
      : forall index step packet,
          start <= index
          -> trace.stepAt index = some step
          -> Not (step.action = .drop packet))
    (noNominate
      : forall index step node,
          start <= index
          -> trace.stepAt index = some step
          -> Not (step.action = .local node .nominateSuccessor))
    (plain
      : forall index step node entries entry,
          start <= index
          -> trace.stepAt index = some step
          -> step.action = .local node (.append entries)
          -> entry ∈ entries
          -> entry.metadata.configuration = none)
    (duration : Real)
    : Leadership.GoodBase trace start duration nodes.toFinset where
  participantsLive _ _ _ within found member :=
    live_from admissible noCrash firstFound (alive _ (List.mem_toFinset.mp member))
      within.1 found
  noReconfiguration index step node entries within stepped appended entry :=
    plain index step node entries entry within.1 stepped appended
  noNominations index step node within stepped :=
    noNominate index step node within.1 stepped
  lossless index step packet within stepped dropped _ :=
    noDrop index step packet within.1 stepped dropped
  isolated _ _ _ _ stepped delivered _ :=
    List.mem_toFinset.mpr (delivered_source admissible stepped delivered)

end Good

end CCFRaft.Proofs.Liveness
