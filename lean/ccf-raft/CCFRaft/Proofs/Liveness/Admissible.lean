module

public import CCFRaft.Proofs.Liveness.Trace
public import CCFRaft.Properties.Liveness.Assumptions

@[expose] public section

/-!
# Admissible executions

The executions the liveness theorems quantify over: traces satisfying the
protocol, timing, crash and delivery models. Each fact here is read off one
step, or carried along the trace by induction.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Liveness

open Model.Node
open HasProtocol (proto)

variable {W A : Type} [HasProtocol W Model.State]

/-- A node's protocol state at a recorded index; `none` past the end of a finite
recording, or when the node has no state. -/
def nodeAt (trace : Trace W A) (index : Nat) (node : NodeID) : Option NodeState :=
  (trace.stateAt index).bind
    fun point =>
      CCF.MultiNodeTransitionSystem.nodeState (proto point) node

theorem nodeAt_of_stateAt {trace : Trace W A} {index : Nat} {point : W}
    (found : trace.stateAt index = some point) (node : NodeID)
    : nodeAt trace index node
      = CCF.MultiNodeTransitionSystem.nodeState (proto point) node := by
  simp [nodeAt, found]

theorem nodeAt_eq_some {trace : Trace W A} {index : Nat} {node : NodeID}
    {state : NodeState}
    : nodeAt trace index node = some state
      <-> exists point,
            trace.stateAt index = some point
            /\ CCF.MultiNodeTransitionSystem.nodeState (proto point) node
                = some state := by
  simp [nodeAt, Option.bind_eq_some_iff]

/-- A node's state after a recorded step. -/
theorem nodeAt_succ {trace : Trace W A} {index : Nat} {step : CCF.Execution.Step W A}
    (stepped : trace.stepAt index = some step) (node : NodeID)
    : nodeAt trace (index + 1) node
      = CCF.MultiNodeTransitionSystem.nodeState (proto step.after) node :=
  nodeAt_of_stateAt (Trace.stateAt_succ_of_stepAt stepped) node

/-- A node's state before a recorded step. -/
theorem nodeAt_before {trace : Trace W A} {index : Nat} {step : CCF.Execution.Step W A}
    (stepped : trace.stepAt index = some step) (node : NodeID)
    : nodeAt trace index node
      = CCF.MultiNodeTransitionSystem.nodeState (proto step.before) node :=
  nodeAt_of_stateAt (Trace.stateAt_of_stepAt stepped) node

end CCFRaft.Liveness

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- The recorded executions of `Model.transitionSystem config nodes` that the liveness
theorems consider. -/
structure Admissible (config : Finset NodeID) (nodes : List NodeID)
    (trace : Trace W Liveness.Event)
    : Prop where
  protocol : Satisfies trace (protocolModel config nodes)
  timing : Satisfies trace timingModel
  crash : Satisfies trace crashModel
  delivery : Satisfies trace (deliveryModel config nodes)

namespace Admissible

variable {config : Finset NodeID} {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible config nodes trace)

include admissible

/-- A recorded protocol action is an enabled step of the system. -/
theorem step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    {action : Model.Action} (stepped : trace.stepAt index = some step)
    (selected : step.action.action = some action)
    : (Model.transitionSystem config nodes).step (proto step.before) action
      = some (proto step.after) := by
  have next := admissible.protocol.next stepped
  simp only [protocolModel, selected] at next
  exact next

/-- Environment-only events leave the protocol state unchanged. -/
theorem stutter {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) (selected : step.action.action = none)
    : proto step.after = proto step.before := by
  have next := admissible.protocol.next stepped
  simp only [protocolModel, selected] at next
  exact next

/-- Environment events do not introduce new protocol states. -/
theorem reachable {index : Nat} {point : W} (found : trace.stateAt index = some point)
    : (Model.transitionSystem config nodes).Reachable (proto point) :=
  admissible.protocol.invariant
    (invariant :=
      fun point => (Model.transitionSystem config nodes).Reachable (proto point))
    (fun _ init => .initial init)
    (fun step next held => by
      cases selected : step.action.action with
      | none =>
          simp only [protocolModel, selected] at next
          rw [next]
          exact held
      | some action =>
          simp only [protocolModel, selected] at next
          exact .step held next)
    found

theorem reachable_before {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    : (Model.transitionSystem config nodes).Reachable (proto step.before) :=
  admissible.reachable (Trace.stateAt_of_stepAt stepped)

/-- Time never runs backwards along the recording. -/
theorem time_le {earlier later : Nat} (le : earlier <= later) {first last : W}
    (firstFound : trace.stateAt earlier = some first)
    (lastFound : trace.stateAt later = some last)
    : time first <= time last :=
  trace.chain (relation := fun first last => time first <= time last)
    (fun _ => le_rfl) (fun _ _ _ => le_trans)
    (fun _ _ stepped => (admissible.timing.next stepped).1) le firstFound lastFound

/-- The actor of a recorded step is live before it. -/
theorem actor_live {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    {node : NodeID} (stepped : trace.stepAt index = some step)
    (actor : step.action.actor = some node)
    : node ∈ live step.before := by
  have next := admissible.crash.next stepped
  simp only [crashModel, crashSystem, actor] at next
  by_contra absent
  simp [absent] at next

/-- A step only removes live nodes, by crashing them. -/
theorem live_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    : live step.after ⊆ live step.before := by
  have next := admissible.crash.next stepped
  obtain ⟨before, event, after⟩ := step
  simp only [crashModel, crashSystem] at next
  cases event with
  | crash node =>
      simp only [Liveness.Event.actor] at next
      split_ifs at next with present
      · simp only [Option.some.injEq] at next
        rw [← next]
        exact Finset.erase_subset _ _
  | _ =>
      simp only [Liveness.Event.actor, Liveness.Event.liveAfter] at next
      first
      | (split_ifs at next with present; simp_all)
      | simp_all

/-- Only a crash of a live node removes it from the live set. -/
theorem crashes {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {node : NodeID}
    (before : node ∈ live step.before) (after : Not (node ∈ live step.after))
    : step.action = .crash node := by
  have next := admissible.crash.next stepped
  obtain ⟨before', event, after'⟩ := step
  simp only [crashModel, crashSystem] at next
  cases event with
  | crash crashed =>
      simp only [Liveness.Event.actor] at next
      split_ifs at next with present
      simp only [Option.some.injEq] at next
      simp only [← next, Finset.mem_erase, not_and_or, not_not] at after
      rcases after with same | absent
      · exact congrArg Liveness.Event.crash same.symm
      · exact absurd before absent
  | _ =>
      simp only [Liveness.Event.actor, Liveness.Event.liveAfter] at next
      first
      | (split_ifs at next with present; simp_all)
      | simp_all

/-- Crash-stop: a node live at a recorded state was live at every earlier one. -/
theorem live_anti {earlier later : Nat} (le : earlier <= later) {first last : W}
    (firstFound : trace.stateAt earlier = some first)
    (lastFound : trace.stateAt later = some last)
    : live last ⊆ live first :=
  trace.chain (relation := fun first last => live last ⊆ live first)
    (fun _ => Finset.Subset.refl _) (fun _ _ _ first second => second.trans first)
    (fun _ _ stepped => admissible.live_step stepped) le firstFound lastFound

end Admissible

end CCFRaft.Proofs.Liveness

namespace CCFRaft.Liveness.StableLeader

open Model.Node
open HasProtocol (proto)
open HasLive (live)

variable {W : Type} [HasProtocol W Model.State] [HasLive W]
  {trace : Trace W Liveness.Event}
  {start : Nat} {leader : NodeID} {term : Nat}
  (stable : StableLeader trace start leader term)

include stable

/-- The primary at a recorded state from `start`. -/
theorem leads {index : Nat} {point : W} (le : start <= index)
    (found : trace.stateAt index = some point)
    : Membership.mem (live point) leader
      /\ exists state,
          CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
          /\ state.role = .primary
          /\ state.currentTerm = term
          /\ Not (state.isRetiredCommitted leader) := by
  obtain ⟨point', state, found', alive, nodeFound, primary, current, notRetired⟩ :=
    stable.2 index point le found
  rw [found, Option.some.injEq] at found'
  subst found'
  exact ⟨alive, state, nodeFound, primary, current, notRetired⟩

/-- The primary has a state at every recorded index from `start`. -/
theorem found {index : Nat} {point : W} (le : start <= index)
    (found : trace.stateAt index = some point)
    : exists state, nodeAt trace index leader = some state := by
  obtain ⟨_, state, nodeFound, _⟩ := stable.leads le found
  exact ⟨state, by rw [nodeAt_of_stateAt found, nodeFound]⟩

/-- The primary's state from `start` is primary in `term`, and not retired. -/
theorem state {index : Nat} {state : NodeState} (le : start <= index)
    (found : nodeAt trace index leader = some state)
    : state.role = .primary
      /\ state.currentTerm = term
      /\ Not (state.isRetiredCommitted leader) := by
  obtain ⟨point, pointFound, nodeFound⟩ := nodeAt_eq_some.mp found
  obtain ⟨_, state', nodeFound', primary, current, notRetired⟩ := stable.leads le pointFound
  rw [nodeFound, Option.some.injEq] at nodeFound'
  subst nodeFound'
  exact ⟨primary, current, notRetired⟩

theorem primary {index : Nat} {state : NodeState} (le : start <= index)
    (found : nodeAt trace index leader = some state)
    : state.role = .primary :=
  (stable.state le found).1

theorem current {index : Nat} {state : NodeState} (le : start <= index)
    (found : nodeAt trace index leader = some state)
    : state.currentTerm = term :=
  (stable.state le found).2.1

theorem notRetired {index : Nat} {state : NodeState} (le : start <= index)
    (found : nodeAt trace index leader = some state)
    : Not (state.isRetiredCommitted leader) :=
  (stable.state le found).2.2

end CCFRaft.Liveness.StableLeader
