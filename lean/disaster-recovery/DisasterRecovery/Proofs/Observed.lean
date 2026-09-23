import DisasterRecovery.Proofs.Lifting

namespace DisasterRecovery.Proofs.Observed

open Execution.Local
open Execution.Global hiding Config
open Predicates

def OpeningThresholds (config : Model.Config) (state : State) : Prop :=
  forall entry,
    entry ∈ state.system.nodes
    -> forall kind,
        entry.2.openKind = some kind
        -> (if kind = .quorum then voteQuorum config.protocol else 1) <= entry.2.votes.length

lemma step_preserves_opening_threshold (config : Config) (state : NodeState)
    (event : Event)
    (threshold
      : forall kind,
          state.openKind = some kind
          -> (if kind = .quorum then voteQuorum config else 1) <= state.votes.length)
    : forall kind,
        (step config state event).state.openKind = some kind
        -> (if kind = .quorum then voteQuorum config else 1)
            <= (step config state event).state.votes.length := by
  intro kind
  specialize threshold kind
  have grows (source : Location) :
      state.votes.length <= (insertVote source state.votes).length := by
    unfold insertVote
    split <;> simp
  cases kind <;> by_cases empty : state.votes = [] <;>
    cases event <;> try cases_type DisasterRecovery.Model.Local.Validation
  all_goals
    simp [step, Execution.Local.transitionSystem, rejectionReason, rejected, advance,
      advanceTimeoutLane, guard, failure]
  all_goals
    repeat' first
      | split
      | simp_all [validTimeout, ← List.length_eq_zero_iff]
      | exact fun chosen => Nat.le_trans (threshold chosen) (grows _)
      | omega
      | tauto

lemma systemStep_preserves_opening_thresholds
    (config : Model.Config) (before after : SystemState)
    (target : Location) (event : Event) (output : StepOutput)
    (threshold
      : forall entry,
          entry ∈ before.nodes
          -> forall kind,
              entry.2.openKind = some kind
              -> (if kind = .quorum then voteQuorum config.protocol else 1) <= entry.2.votes.length)
    (trans : systemStep config.protocol before target event = some (after, output))
    : forall entry,
        entry ∈ after.nodes
        -> forall kind,
            entry.2.openKind = some kind
            -> (if kind = .quorum then voteQuorum config.protocol else 1)
                <= entry.2.votes.length := by
  simp [systemStep, Option.bind_eq_some_iff] at trans
  rcases trans with ⟨state, found, rfl, rfl⟩
  rcases found with ⟨key, selectedFound⟩
  have selectedMember := List.mem_of_find?_eq_some selectedFound
  intro entry membership
  simp only [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, member, entryEq⟩
  split at entryEq
  · subst entry
    exact step_preserves_opening_threshold config.protocol state event
      (threshold (key, state) selectedMember)
  · subst entry
    exact threshold previous member

lemma next_preserves_opening_thresholds (config : Model.Config) (before after : State)
    (action : Action) (threshold : OpeningThresholds config before)
    (trans : next config before action = some after)
    : OpeningThresholds config after := by
  cases action with
  | retry source =>
      simp [next, guard, failure, Option.bind_eq_some_iff] at trans
      rcases trans with ⟨_, state, _, _, rfl⟩
      exact threshold
  | deliver envelope =>
      simp [next, guard, failure, Option.bind_eq_some_iff] at trans
      rcases trans with ⟨_, _, system, output, systemStep, rfl⟩
      simpa [OpeningThresholds]
        using systemStep_preserves_opening_thresholds config before.system system
          envelope.target (eventFor envelope) output threshold systemStep
  | timeout target =>
      simp [next, guard, failure, Option.bind_eq_some_iff] at trans
      rcases trans with ⟨_, system, output, systemStep, _, rfl⟩
      simpa [OpeningThresholds]
        using systemStep_preserves_opening_thresholds config before.system system
          target .timeout output threshold systemStep

lemma reachable_opening_thresholds {config : Model.Config} {state : State}
    (reachable : Reachable config state)
    : OpeningThresholds config state := by
  induction reachable with
  | initial initialized =>
      rcases initialized with ⟨active, _, _, _, rfl⟩
      simp [OpeningThresholds, initial, initialSystem, initialNode]
  | step reachable trans ih =>
      exact next_preserves_opening_thresholds config _ _ _ ih trans

lemma reachable_quorum_thresholds {config : Model.Config} {state : State}
    (reachable : Reachable config state)
    (entry : Location × NodeState) (member : entry ∈ state.system.nodes)
    (quorum : entry.2.openKind = some .quorum)
    : voteQuorum config.protocol <= entry.2.votes.length := by
  simpa using reachable_opening_thresholds reachable entry member .quorum quorum

lemma reachable_opening_has_vote {config : Model.Config} {state : State}
    (reachable : Reachable config state)
    (entry : Location × NodeState) (member : entry ∈ state.system.nodes)
    (opened : entry.2.openKind.isSome = true)
    : exists voter, voter ∈ entry.2.votes := by
  cases selected : entry.2.openKind with
  | none => simp [selected] at opened
  | some kind =>
      have threshold := reachable_opening_thresholds reachable entry member kind selected
      cases votes : entry.2.votes with
      | nil => cases kind <;> simp [votes, voteQuorum] at threshold
      | cons voter rest => exact ⟨voter, by simp⟩

lemma notification_opening_state {config : Model.Config} {trace : Properties.GlobalTrace}
    {index : Nat} {node : Location} {kind : OpenKind}
    (notification : Properties.Trace.NotificationAt config trace index node (.opening kind))
    : exists after current,
        after ∈ trace.states /\ (node, current) ∈ after.nodes /\ current.openKind = some kind := by
  obtain ⟨before, after, action, nodeBefore, nodeAfter, execute, outputs,
    _, atAfter, _, _, _, foundAfter, enabled, run, notified⟩ := notification
  simp [Model.protocol, Option.bind_eq_some_iff] at enabled
  obtain ⟨recovered, _, enabled⟩ := enabled
  have erased := Lifting.step_erases config.protocol recovered nodeBefore (source := node)
    (Properties.Trace.event action) { state := nodeAfter, effects := outputs.notifications }
    (by simp [enabled, run, Lifting.capture])
  have stateEq := congrArg Lifting.Result.state erased
  have notifications := congrArg Lifting.Result.effects erased
  change (step config.protocol nodeBefore (Properties.Trace.event action)).state = nodeAfter at stateEq
  change
    (step config.protocol nodeBefore (Properties.Trace.event action)).effects.filterMap
      Effect.diagnostic = outputs.notifications at notifications
  have recorded : .opening kind ∈
      (step config.protocol nodeBefore (Properties.Trace.event action)).effects := by
    rw [← notifications] at notified
    obtain ⟨effect, member, diagnostic⟩ := List.mem_filterMap.mp notified
    cases effect <;> simp_all [Effect.diagnostic]
  have opened := (Quorum.opening_effect_state config.protocol nodeBefore
    (Properties.Trace.event action) kind recorded).2
  rw [stateEq] at opened
  refine ⟨after, nodeAfter, List.mem_iff_getElem?.mpr ⟨_, atAfter⟩, ?_, opened⟩
  obtain ⟨entry, found, value⟩ := Option.map_eq_some_iff.mp foundAfter
  have key := beq_iff_eq.mp
    (List.find?_some (p := fun entry : Location × NodeState => entry.1 == node) found)
  have same : entry = (node, nodeAfter) := Prod.ext key value
  rw [← same]
  exact List.mem_of_find?_eq_some found

lemma current_quorum_unique_of_thresholds {config : Model.Config} {state : State}
    (reachable : Reachable config state)
    (first second : Location × NodeState)
    (firstMember : first ∈ state.system.nodes)
    (secondMember : second ∈ state.system.nodes)
    (firstQuorum : voteQuorum config.protocol <= first.2.votes.length)
    (secondQuorum : voteQuorum config.protocol <= second.2.votes.length)
    : first.1 = second.1 := by
  have wf := Invariants.reachable_well_formed reachable
  have invariant := Quorum.reachable_quorum_invariant reachable
  have configured (entry : Location × NodeState) (member : entry ∈ state.system.nodes)
      (voter : Location) (vote : voter ∈ entry.2.votes) :
      voter ∈ config.protocol.expectedLocations := by
    obtain ⟨sent, sentMember, source, _, _⟩ := invariant.votesSent entry member voter vote
    exact wf.activeConfigured voter
      (by simpa [source] using wf.sentSourceActive sent sentMember)
  obtain ⟨voter, firstVote, secondVote⟩ :=
    Quorum.quorum_lists_intersect config.protocol.expectedLocations
      first.2.votes second.2.votes
      (invariant.votesNodup first firstMember)
      (invariant.votesNodup second secondMember)
      (configured first firstMember)
      (configured second secondMember)
      firstQuorum secondQuorum
  exact invariant.sentVotesFunctional voter first.1 second.1
    (invariant.votesSent first firstMember voter firstVote)
    (invariant.votesSent second secondMember voter secondVote)

lemma current_quorum_unique {config : Model.Config} {state : State}
    (reachable : Reachable config state)
    (first second : Location × NodeState)
    (firstMember : first ∈ state.system.nodes)
    (secondMember : second ∈ state.system.nodes)
    (firstQuorum : first.2.openKind = some .quorum)
    (secondQuorum : second.2.openKind = some .quorum)
    : first.1 = second.1 :=
  current_quorum_unique_of_thresholds reachable first second firstMember secondMember
    (reachable_quorum_thresholds reachable first firstMember firstQuorum)
    (reachable_quorum_thresholds reachable second secondMember secondQuorum)

end DisasterRecovery.Proofs.Observed
