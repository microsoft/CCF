import DisasterRecovery.Model
import DisasterRecovery.Protocol.Model
import Mathlib.Logic.Relation

namespace DisasterRecovery.Protocol.Refinement

def projectPhase (state : NodeState) : DisasterRecovery.Phase :=
  match state.phase with
  | .gossiping => .vote
  | .voting => .openJoin
  | .opening | .open =>
      match state.openKind with
      | some .failover => .open true
      | _ => .open false
  | .joining => .join

inductive LegacyAtomic :
    DisasterRecovery.Phase -> DisasterRecovery.Phase -> Prop where
  | gossipToVoting : LegacyAtomic .vote .openJoin
  | quorumOpen : LegacyAtomic .openJoin (.open false)
  | failoverOpen : LegacyAtomic .openJoin (.open true)
  | gossipToJoin : LegacyAtomic .vote .join
  | votingToJoin : LegacyAtomic .openJoin .join

abbrev LegacyWeakStep :=
  Relation.ReflTransGen LegacyAtomic

def embeddedTxID
    (config : Config)
    (source : Location)
    (txid : TxID) : Prop :=
  txid.view = 0 /\ config.expectedLocations[txid.seqno]? = some source

structure LegacyDataAssumptions
    (config : Config)
    (event : Event)
    (after : NodeState) : Prop where
  /-- Recorded for a future data refinement; phase simulation does not assume it. -/
  oddNodeCount :
    exists half, config.expectedLocations.length = 2 * half + 1
  acceptedExpectedInput :
    match event with
    | .receiveGossip source txid validation =>
        validation = .accepted /\
          expectedSource config source = true /\
          embeddedTxID config source txid
    | .receiveVote source validation =>
        validation = .accepted /\ expectedSource config source = true
    | .receiveIAmOpen source validation =>
        validation = .accepted /\ expectedSource config source = true
    | .timeout | .retry => True
  quorumOnly :
    after.openKind != some .failover

structure CompatibilityStep
    (config : Config)
    (before : NodeState)
    (event : Event)
    (after : NodeState) : Prop where
  canonical :
    after = (step config before event).state

private theorem advance_simulates
    (config : Config)
    (state : NodeState)
    (timeout : Bool)
    (output : StepOutput)
    (advanced : advance config state timeout = some output) :
    LegacyWeakStep (projectPhase state) (projectPhase output.state) := by
  cases timeout <;> cases phase : state.phase <;>
    simp [advance, phase] at advanced <;>
    repeat' split at advanced <;>
    simp_all [projectPhase, advanceTimeoutLane, advanceTimeoutState]
  all_goals subst output
  all_goals simp_all [projectPhase, advanceTimeoutLane]
  all_goals
    first
    | (split <;> simp_all)
    | skip
  all_goals
    first
    | exact .refl
    | exact .single .gossipToVoting
    | exact .single .quorumOpen
    | exact .single .failoverOpen

private theorem receive_gossip_simulates
    (config : Config)
    (before : NodeState)
    (source : Location)
    (txid : TxID)
    (validation : Validation) :
    LegacyWeakStep
      (projectPhase before)
      (projectPhase
        (step config before (.receiveGossip source txid validation)).state) := by
  cases validation with
  | rejected =>
      simp [step, rejected]
      exact .refl
  | accepted =>
      by_cases frozen : before.chosen != none
      case pos =>
        simp [step, frozen, rejected]
        exact .refl
      case neg =>
        let received := {
          before with gossips := insertGossip source txid before.gossips }
        have same : projectPhase received = projectPhase before := by
          simp [received, projectPhase]
        cases advanced : advance config received false with
        | none =>
            simp [step, frozen, received, advanced, rejected]
            exact .refl
        | some output =>
            simp [step, frozen, received, advanced]
            have simulation :=
              advance_simulates config received false output advanced
            rw [same] at simulation
            exact simulation

private theorem receive_vote_simulates
    (config : Config)
    (before : NodeState)
    (source : Location)
    (validation : Validation) :
    LegacyWeakStep
      (projectPhase before)
      (projectPhase
        (step config before (.receiveVote source validation)).state) := by
  cases validation with
  | rejected =>
      simp [step, rejected]
      exact .refl
  | accepted =>
      let received := { before with votes := insertVote source before.votes }
      have same : projectPhase received = projectPhase before := by
        simp [received, projectPhase]
      cases advanced : advance config received false with
      | none =>
          simp [step, received, advanced, rejected]
          exact .refl
      | some output =>
          simp [step, received, advanced]
          have simulation :=
            advance_simulates config received false output advanced
          rw [same] at simulation
          exact simulation

private theorem receive_iamopen_simulates
    (config : Config)
    (before : NodeState)
    (source : Location)
    (validation : Validation) :
    LegacyWeakStep
      (projectPhase before)
      (projectPhase
        (step config before (.receiveIAmOpen source validation)).state) := by
  cases validation with
  | rejected =>
      simp [step, rejected]
      exact .refl
  | accepted =>
      cases phase : before.phase <;>
        simp [step, phase, advance, rejected, projectPhase,
          advanceTimeoutLane]
      all_goals
        first
        | exact .single .gossipToJoin
        | exact .single .votingToJoin
        | exact .refl

theorem canonical_step_simulates
    (config : Config)
    (before : NodeState)
    (event : Event) :
    LegacyWeakStep
      (projectPhase before)
      (projectPhase (step config before event).state) := by
  cases event with
  | receiveGossip source txid validation =>
      exact receive_gossip_simulates config before source txid validation
  | receiveVote source validation =>
      exact receive_vote_simulates config before source validation
  | receiveIAmOpen source validation =>
      exact receive_iamopen_simulates config before source validation
  | timeout =>
      cases advanced : advance config before true with
      | none =>
          simp [step, advanced, rejected]
          exact .refl
      | some output =>
          simp [step, advanced]
          exact advance_simulates config before true output advanced
  | retry =>
      exact .refl

theorem compatibility_step_simulates
    {config : Config}
    {before after : NodeState}
    {event : Event}
    (compatible : CompatibilityStep config before event after) :
    LegacyWeakStep (projectPhase before) (projectPhase after) := by
  rw [compatible.canonical]
  exact canonical_step_simulates config before event

def retryCompatibility
    (config : Config)
    (state : NodeState) :
    CompatibilityStep config state .retry state := {
  canonical := rfl
}

def voteQuorumCompatibility
    (config : Config)
    (before : NodeState)
    (source : Location) :
    CompatibilityStep config before
      (.receiveVote source .accepted)
      (step config before (.receiveVote source .accepted)).state := {
  canonical := rfl
}

theorem quorum_phase_step_is_weak
    (before after : NodeState)
    (beforePhase : before.phase = .voting)
    (afterPhase : after.phase = .opening)
    (kind : after.openKind = some .quorum) :
    LegacyWeakStep (projectPhase before) (projectPhase after) := by
  simp [projectPhase, beforePhase, afterPhase, kind]
  exact .single .quorumOpen

theorem opening_to_open_is_stuttering
    (before after : NodeState)
    (beforePhase : before.phase = .opening)
    (afterPhase : after.phase = .open)
    (kind : after.openKind = before.openKind) :
    LegacyWeakStep (projectPhase before) (projectPhase after) := by
  simp [projectPhase, beforePhase, afterPhase, kind]
  exact .refl

inductive CompatibilityTrace
    (config : Config) :
    NodeState ->
    List Event ->
    NodeState ->
    Prop where
  | nil (state) : CompatibilityTrace config state [] state
  | cons
      (first middle last event rest)
      (head : CompatibilityStep config first event middle)
      (tail : CompatibilityTrace config middle rest last) :
      CompatibilityTrace config first (event :: rest) last

theorem compatibility_trace_simulates
    {config : Config}
    {first last : NodeState}
    {events : List Event}
    (compatible : CompatibilityTrace config first events last) :
    LegacyWeakStep (projectPhase first) (projectPhase last) := by
  induction compatible with
  | nil state => exact .refl
  | cons first middle last event rest head tail induction =>
      exact Relation.ReflTransGen.trans
        (compatibility_step_simulates head) induction

theorem initial_phase_correspondence :
    projectPhase (initialNode "node0") = DisasterRecovery.Phase.vote := by
  rfl

theorem three_node_initial_correspondence :
    let config : Config := {
      instanceId := "compat"
      expectedLocations := ["0", "1", "2"]
    }
    ((initialSystem config).nodes.map
        (fun entry => projectPhase entry.2) ==
      (DisasterRecovery.initialState 3).actors.toList.map
        (fun actor => actor.nextStep)) = true := by
  rfl

theorem odd_quorum_matches_legacy
    (nodes half : Nat)
    (odd : nodes = 2 * half + 1) :
    nodes / 2 + 1 = (nodes + 1) / 2 := by
  subst nodes
  simp [Nat.add_div]

theorem even_quorum_exceeds_legacy_by_one
    (nodes half : Nat)
    (even : nodes = 2 * half) :
    nodes / 2 + 1 = (nodes + 1) / 2 + 1 := by
  subst nodes
  simp [Nat.add_div]

def canonicalReachedOpen (state : NodeState) : Prop :=
  state.phase = .opening \/ state.phase = .open

def projectedReachedOpen (state : NodeState) : Prop :=
  match projectPhase state with
  | .open _ => True
  | _ => False

theorem reached_open_is_preserved
    (state : NodeState) :
    canonicalReachedOpen state <-> projectedReachedOpen state := by
  cases phase : state.phase <;>
    cases kind : state.openKind <;>
    simp [canonicalReachedOpen, projectedReachedOpen, projectPhase, phase, kind]
  all_goals
    rename_i value
    cases value <;>
      simp

theorem quorum_kind_projects_to_non_timeout_open
    (state : NodeState)
    (phase : state.phase = .opening \/ state.phase = .open)
    (kind : state.openKind = some .quorum) :
    projectPhase state = .open false := by
  cases phase with
  | inl opening =>
      cases state
      simp_all [projectPhase]
  | inr opened =>
      cases state
      simp_all [projectPhase]

theorem single_node_full_initial_models_differ :
    projectPhase (initialNode "0") !=
      (DisasterRecovery.initialState 1).actors[0]!.nextStep := by
  decide

end DisasterRecovery.Protocol.Refinement