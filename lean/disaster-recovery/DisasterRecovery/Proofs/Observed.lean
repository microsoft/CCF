import DisasterRecovery.Proofs.Lifting

namespace DisasterRecovery.Proofs.Observed

open Execution.Local
open Execution.Global hiding Config
open Predicates

def QuorumThresholds (config : Model.Config) (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    entry.2.openKind = some .quorum ->
      voteQuorum config.protocol <= entry.2.votes.length

lemma step_preserves_quorum_threshold (config : Config) (state : NodeState)
    (event : Event)
    (threshold : state.openKind = some .quorum ->
      voteQuorum config <= state.votes.length) :
    (step config state event).state.openKind = some .quorum ->
      voteQuorum config <= (step config state event).state.votes.length := by
  have grows (source : Location) :
      state.votes.length <= (insertVote source state.votes).length := by
    unfold insertVote
    split <;> simp
  cases event <;> try cases_type DisasterRecovery.Model.Local.Validation
  all_goals
    simp [step, Execution.Local.transitionSystem, rejectionReason, rejected, advance,
      advanceTimeoutLane, guard, failure]
  all_goals
    repeat first
      | split
      | simp_all [validTimeout]
      | exact fun chosen => Nat.le_trans (threshold chosen) (grows _)
      | tauto
      | omega

lemma systemStep_preserves_quorum_thresholds
    (config : Model.Config) (before after : SystemState)
    (target : Location) (event : Event) (output : StepOutput)
    (threshold : forall entry, entry ∈ before.nodes ->
      entry.2.openKind = some .quorum ->
        voteQuorum config.protocol <= entry.2.votes.length)
    (trans : systemStep config.protocol before target event = some (after, output)) :
    forall entry, entry ∈ after.nodes ->
      entry.2.openKind = some .quorum ->
        voteQuorum config.protocol <= entry.2.votes.length := by
  simp [systemStep, Option.bind_eq_some_iff] at trans
  rcases trans with ⟨state, found, rfl, rfl⟩
  rcases found with ⟨key, selectedFound⟩
  have selectedMember := List.mem_of_find?_eq_some selectedFound
  intro entry membership
  simp only [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, member, entryEq⟩
  split at entryEq
  · subst entry
    exact step_preserves_quorum_threshold config.protocol state event
      (threshold (key, state) selectedMember)
  · subst entry
    exact threshold previous member

lemma next_preserves_quorum_thresholds (config : Model.Config) (before after : State)
    (action : Action) (threshold : QuorumThresholds config before)
    (trans : next config before action = some after) :
    QuorumThresholds config after := by
  cases action with
  | retry source =>
      simp [next, guard, failure, Option.bind_eq_some_iff] at trans
      rcases trans with ⟨_, state, _, _, rfl⟩
      exact threshold
  | deliver envelope =>
      simp [next, guard, failure, Option.bind_eq_some_iff] at trans
      rcases trans with ⟨_, _, system, output, systemStep, rfl⟩
      simpa [QuorumThresholds] using
        systemStep_preserves_quorum_thresholds config before.system system
          envelope.target (eventFor envelope) output threshold systemStep
  | timeout target =>
      simp [next, guard, failure, Option.bind_eq_some_iff] at trans
      rcases trans with ⟨_, system, output, systemStep, _, rfl⟩
      simpa [QuorumThresholds] using
        systemStep_preserves_quorum_thresholds config before.system system
          target .timeout output threshold systemStep

lemma reachable_quorum_thresholds {config : Model.Config} {state : State}
    (reachable : Reachable config state) :
    QuorumThresholds config state := by
  induction reachable with
  | initial initialized =>
      rcases initialized with ⟨active, _, _, _, rfl⟩
      simp [QuorumThresholds, initial, initialSystem, initialNode]
  | step reachable trans ih =>
      exact next_preserves_quorum_thresholds config _ _ _ ih trans

lemma current_quorum_unique {config : Model.Config} {state : State}
    (reachable : Reachable config state)
    (first second : Location × NodeState)
    (firstMember : first ∈ state.system.nodes)
    (secondMember : second ∈ state.system.nodes)
    (firstQuorum : first.2.openKind = some .quorum)
    (secondQuorum : second.2.openKind = some .quorum) :
    first.1 = second.1 := by
  have wf := Invariants.reachable_well_formed reachable
  have invariant := Quorum.reachable_quorum_invariant reachable
  have threshold := reachable_quorum_thresholds reachable
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
      (threshold first firstMember firstQuorum)
      (threshold second secondMember secondQuorum)
  exact invariant.sentVotesFunctional voter first.1 second.1
    (invariant.votesSent first firstMember voter firstVote)
    (invariant.votesSent second secondMember voter secondVote)

end DisasterRecovery.Proofs.Observed
