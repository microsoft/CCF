import DisasterRecovery.Protocol.Invariants
import Mathlib.Tactic

namespace DisasterRecovery.Protocol.Global

def SentVote (state : State) (voter target : Location) : Prop :=
  exists envelope,
    envelope ∈ state.sent /\
      envelope.source = voter /\
      envelope.target = target /\
      envelope.payload = .vote

def NodeVotesNodup (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    entry.2.votes.Nodup

def NodeVotesSent (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    forall voter, voter ∈ entry.2.votes ->
      SentVote state voter entry.1

def SentVotesFunctional (state : State) : Prop :=
  forall voter first second,
    SentVote state voter first ->
    SentVote state voter second ->
    first = second

def SentVoteStable (state : State) : Prop :=
  forall envelope, envelope ∈ state.sent ->
    envelope.payload = .vote ->
    forall entry, entry ∈ state.system.nodes ->
      entry.1 = envelope.source ->
      entry.2.phase ≠ .gossiping /\
        (entry.2.phase = .voting ->
          entry.2.chosen = some envelope.target)

def NodeVotingSelection (state : NodeState) : Prop :=
  exists target txid,
    state.chosen = some target /\
      maximumGossip state.gossips = some (target, txid)

def VotingSelectionsValid (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    entry.2.phase = .voting ->
      NodeVotingSelection entry.2

def SentVotesSelected (state : State) : Prop :=
  forall envelope, envelope ∈ state.sent ->
    envelope.payload = .vote ->
      NodeVotingSelection envelope.sourceState

structure Opening.Valid
    (config : Config)
    (globalState : State)
    (opening : Opening) : Prop where
  location : opening.state.location = opening.node
  phase : opening.state.phase = .opening
  kind : opening.state.openKind = some opening.kind
  votesNodup : opening.state.votes.Nodup
  quorum :
    opening.kind = .quorum ->
      voteQuorum config.protocol <= opening.state.votes.length
  votesSent :
    forall voter, voter ∈ opening.state.votes ->
      SentVote globalState voter opening.node

def OpeningsValid (config : Config) (state : State) : Prop :=
  forall opening, opening ∈ state.openings ->
    opening.Valid config state

structure QuorumInvariant (config : Config) (state : State) : Prop where
  votesNodup : NodeVotesNodup state
  votesSent : NodeVotesSent state
  sentVoteStable : SentVoteStable state
  sentVotesFunctional : SentVotesFunctional state
  votingSelections : VotingSelectionsValid state
  sentVotesSelected : SentVotesSelected state
  openingsValid : OpeningsValid config state

theorem insertVote_nodup
    (source : Location)
    {votes : List Location}
    (nodup : votes.Nodup) :
    (insertVote source votes).Nodup := by
  unfold insertVote
  split
  · exact nodup
  · rename_i absent
    apply (List.mergeSort_perm _ _).symm.nodup
    rw [List.nodup_cons]
    exact
      ⟨fun member => absent (List.contains_iff_mem.mpr member), nodup⟩

theorem mem_insertVote
    {member source : Location}
    {votes : List Location}
    (membership : member ∈ insertVote source votes) :
    member ∈ votes \/ member = source := by
  unfold insertVote at membership
  split at membership
  · exact Or.inl membership
  · have unsorted :=
      (List.mergeSort_perm _ _).mem_iff.mp membership
    rw [List.mem_cons] at unsorted
    exact unsorted.symm

theorem step_preserves_votes_nodup
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (nodup : state.votes.Nodup) :
    (step config state event).state.votes.Nodup := by
  cases event <;>
    simp [step, rejected, advance, advanceTimeoutLane]
  all_goals
    repeat first | split | simp_all [insertVote_nodup]

def acceptedVoteSource : Event -> Option Location
  | .receiveVote source .accepted => some source
  | _ => none

theorem step_votes_shape
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event) :
    (step config state event).state.votes = state.votes \/
      exists source,
        acceptedVoteSource event = some source /\
          (step config state event).state.votes =
            insertVote source state.votes := by
  cases event
  all_goals try cases_type Validation
  all_goals
    simp [acceptedVoteSource, step, rejected, advance, advanceTimeoutLane]
  all_goals repeat first | split | simp_all

theorem step_vote_origin
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (voter : Location)
    (membership : voter ∈ (step config state event).state.votes) :
    voter ∈ state.votes \/
      acceptedVoteSource event = some voter := by
  rcases step_votes_shape config state event with
    unchanged | ⟨source, sourceEq, changed⟩
  · rw [unchanged] at membership
    exact Or.inl membership
  · rw [changed] at membership
    rcases mem_insertVote membership with old | added
    · exact Or.inl old
    · subst source
      exact Or.inr sourceEq

theorem step_preserves_non_gossiping
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (pastGossip : state.phase ≠ .gossiping) :
    (step config state event).state.phase ≠ .gossiping := by
  cases event <;>
    simp [step, rejected, advance, advanceTimeoutLane]
  all_goals repeat first | split | simp_all

theorem voting_step_preserves_choice
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (pastGossip : state.phase ≠ .gossiping)
    (stillVoting : (step config state event).state.phase = .voting) :
    state.phase = .voting /\
      (step config state event).state.chosen = state.chosen := by
  cases event <;>
    simp [step, rejected, advance, advanceTimeoutLane] at stillVoting ⊢
  all_goals repeat first | split at stillVoting | split | simp_all

theorem step_preserves_voting_selection
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (before :
      state.phase = .voting ->
        NodeVotingSelection state)
    (voting : (step config state event).state.phase = .voting) :
    NodeVotingSelection (step config state event).state := by
  cases event
  all_goals try cases_type Validation
  all_goals
    simp [NodeVotingSelection, step, rejected, advance,
      advanceTimeoutLane, validTimeout] at before voting ⊢
  all_goals
    repeat first | split at voting | split | simp_all | aesop

theorem retry_vote_state
    {config : Config}
    {envelope : Envelope}
    (valid : envelope.Valid config)
    (vote : envelope.payload = .vote) :
    envelope.sourceState.phase = .voting /\
      envelope.sourceState.chosen = some envelope.target := by
  rcases valid_envelope_effect valid with
    ⟨effect, member, created⟩
  cases effect with
  | sendGossip target =>
      cases found : recoveredTxID config envelope.source with
      | none =>
          simp [messageForEffect, found] at created
      | some txid =>
          simp [messageForEffect, found] at created
          rw [←created] at vote
          contradiction
  | sendVote target =>
      simp [messageForEffect] at created
      rw [←created] at vote ⊢
      cases phase : envelope.sourceState.phase <;>
        simp [step, phase] at member
      next =>
        cases chosen : envelope.sourceState.chosen <;>
          simp_all
  | sendIAmOpen target =>
      simp [messageForEffect] at created
      rw [←created] at vote
      contradiction
  | opening kind =>
      simp [messageForEffect] at created
  | restart chosen =>
      simp [messageForEffect] at created
  | completed =>
      simp [messageForEffect] at created
  | rejected reason =>
      simp [messageForEffect] at created

theorem opening_effect_state
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (kind : OpenKind)
    (opening : .opening kind ∈ (step config state event).effects) :
    (step config state event).state.phase = .opening /\
      (step config state event).state.openKind = some kind := by
  cases event
  all_goals try cases_type Validation
  all_goals
    simp [step, rejected, advance, advanceTimeoutLane, validTimeout]
      at opening ⊢
  all_goals
    repeat first | split at opening | split | simp_all | aesop

theorem quorum_effect_has_threshold
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (opening :
      .opening .quorum ∈ (step config state event).effects) :
    voteQuorum config <=
      (step config state event).state.votes.length := by
  cases event
  all_goals try cases_type Validation
  all_goals
    simp [step, rejected, advance, advanceTimeoutLane, validTimeout]
      at opening ⊢
  all_goals
    repeat first | split at opening | split | simp_all | aesop

theorem sentVote_mono
    {before after : State}
    {voter target : Location}
    (sent : forall envelope, envelope ∈ before.sent ->
      envelope ∈ after.sent)
    (vote : SentVote before voter target) :
    SentVote after voter target := by
  rcases vote with
    ⟨envelope, membership, source, destination, payload⟩
  exact
    ⟨envelope, sent envelope membership, source, destination, payload⟩

theorem opening_valid_of_sent_eq
    {config : Config}
    {before after : State}
    {opening : Opening}
    (sentEq : after.sent = before.sent)
    (valid : opening.Valid config before) :
    opening.Valid config after := by
  rcases valid with
    ⟨location, phase, kind, nodup, quorum, votesSent⟩
  constructor
  · exact location
  · exact phase
  · exact kind
  · exact nodup
  · exact quorum
  · intro voter membership
    apply sentVote_mono
    · intro envelope sent
      rw [sentEq]
      exact sent
    · exact votesSent voter membership

theorem opening_valid_mono
    {config : Config}
    {before after : State}
    {opening : Opening}
    (sent :
      forall envelope, envelope ∈ before.sent ->
        envelope ∈ after.sent)
    (valid : opening.Valid config before) :
    opening.Valid config after := by
  rcases valid with
    ⟨location, phase, kind, nodup, quorum, votesSent⟩
  constructor
  · exact location
  · exact phase
  · exact kind
  · exact nodup
  · exact quorum
  · intro voter membership
    exact sentVote_mono sent (votesSent voter membership)

theorem recordEffect_preserves_openings_valid
    {config : Config}
    {node : Location}
    {nodeState : NodeState}
    {state : State}
    {effect : Effect}
    (valid : OpeningsValid config state)
    (newValid :
      forall kind,
        effect = .opening kind ->
          Opening.Valid config state
            { node, kind, state := nodeState }) :
    OpeningsValid config
      (recordEffect node nodeState state effect) := by
  intro opening membership
  cases effect with
  | opening kind =>
      simp [recordEffect] at membership
      rcases membership with rfl | old
      · apply opening_valid_of_sent_eq
          (before := state)
          (after := recordEffect node nodeState state (.opening kind))
          rfl
        exact newValid kind rfl
      · apply opening_valid_of_sent_eq
          (before := state)
          (after := recordEffect node nodeState state (.opening kind))
          rfl
        exact valid opening old
  | sendGossip target =>
      exact valid opening membership
  | sendVote target =>
      exact valid opening membership
  | sendIAmOpen target =>
      exact valid opening membership
  | restart target =>
      apply opening_valid_of_sent_eq
        (before := state)
        (after := recordEffect node nodeState state (.restart target))
        rfl
      exact valid opening membership
  | completed =>
      apply opening_valid_of_sent_eq
        (before := state)
        (after := recordEffect node nodeState state .completed)
        rfl
      exact valid opening membership
  | rejected reason =>
      exact valid opening membership

theorem recordEffects_preserves_openings_valid
    {config : Config}
    {node : Location}
    {nodeState : NodeState}
    {state : State}
    {effects : List Effect}
    (valid : OpeningsValid config state)
    (newValid :
      forall kind,
        .opening kind ∈ effects ->
          Opening.Valid config state
            { node, kind, state := nodeState }) :
    OpeningsValid config
      (recordEffects node nodeState effects state) := by
  induction effects generalizing state with
  | nil => exact valid
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      apply ih
      · apply recordEffect_preserves_openings_valid valid
        intro kind effectEq
        subst effect
        exact newValid kind (by simp)
      · intro kind membership
        apply opening_valid_of_sent_eq
          (before := state)
          (after := recordEffect node nodeState state effect)
          (by cases effect <;> rfl)
        exact newValid kind (by simp [membership])

theorem eventFor_vote_source
    {envelope : Envelope}
    {voter : Location}
    (source :
      acceptedVoteSource (eventFor envelope) = some voter) :
    envelope.payload = .vote /\
      envelope.source = voter := by
  cases payload : envelope.payload <;>
    simp_all [eventFor, acceptedVoteSource]

theorem systemStep_preserves_votes_nodup
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (nodup :
      forall entry, entry ∈ before.nodes ->
        entry.2.votes.Nodup)
    (transition :
      systemStep config before target event = some (after, output)) :
    forall entry, entry ∈ after.nodes ->
      entry.2.votes.Nodup := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, stateEq, _⟩
  rw [←stateEq]
  intro entry membership
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · apply step_preserves_votes_nodup
    exact nodup (key, node) (List.mem_of_find?_eq_some found)
  · exact nodup previous previousMember

theorem systemStep_preserves_voting_selections
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (valid :
      forall entry, entry ∈ before.nodes ->
        entry.2.phase = .voting ->
          NodeVotingSelection entry.2)
    (transition :
      systemStep config before target event = some (after, output)) :
    forall entry, entry ∈ after.nodes ->
      entry.2.phase = .voting ->
        NodeVotingSelection entry.2 := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, outputEq⟩
  rw [←systemEq]
  intro entry membership voting
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · rename_i atTarget
    apply step_preserves_voting_selection config node event
    · exact valid (key, node)
        (List.mem_of_find?_eq_some found)
    · simpa [atTarget, outputEq] using voting
  · rename_i notTarget
    exact valid previous previousMember
      (by simpa [notTarget] using voting)

theorem systemStep_output_location
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (locations :
      forall entry, entry ∈ before.nodes ->
        entry.2.location = entry.1)
    (transition :
      systemStep config before target event = some (after, output)) :
    output.state.location = target := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, _, outputEq⟩
  calc
    output.state.location =
        node.location := by
          rw [←outputEq]
          exact step_preserves_location config node event
    _ = key :=
      locations (key, node) (List.mem_of_find?_eq_some found)
    _ = target :=
      beq_iff_eq.mp
        (List.find?_some
          (p := fun entry : Prod Location NodeState =>
            entry.1 == target) found)

theorem systemStep_output_mem
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (transition :
      systemStep config before target event = some (after, output)) :
    (target, output.state) ∈ after.nodes := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, outputEq⟩
  rw [←systemEq, replaceNode, List.mem_map]
  refine ⟨(key, node), List.mem_of_find?_eq_some found, ?_⟩
  have keyEq : key = target :=
    beq_iff_eq.mp
      (List.find?_some
        (p := fun entry : Prod Location NodeState =>
          entry.1 == target) found)
  simp [keyEq, outputEq]

theorem systemStep_opening_effect_state
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    {kind : OpenKind}
    (transition :
      systemStep config before target event = some (after, output))
    (opening : .opening kind ∈ output.effects) :
    output.state.phase = .opening /\
      output.state.openKind = some kind := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, _, _, outputEq⟩
  rw [←outputEq] at opening ⊢
  exact opening_effect_state config node event kind opening

theorem systemStep_quorum_effect_has_threshold
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (transition :
      systemStep config before target event = some (after, output))
    (opening : .opening .quorum ∈ output.effects) :
    voteQuorum config <= output.state.votes.length := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, _, _, outputEq⟩
  rw [←outputEq] at opening ⊢
  exact quorum_effect_has_threshold config node event opening

theorem initial_node_votes_nodup
    (config : Config)
    (active : List Location) :
    NodeVotesNodup (initial config active) := by
  simp [NodeVotesNodup, Global.initial, initialSystem, initialNode]

theorem initial_node_votes_sent
    (config : Config)
    (active : List Location) :
    NodeVotesSent (initial config active) := by
  simp [NodeVotesSent, Global.initial, initialSystem, initialNode]

theorem initial_sent_votes_functional
    (config : Config)
    (active : List Location) :
    SentVotesFunctional (initial config active) := by
  simp [SentVotesFunctional, SentVote, Global.initial]

theorem initial_sent_vote_stable
    (config : Config)
    (active : List Location) :
    SentVoteStable (initial config active) := by
  simp [SentVoteStable, Global.initial]

theorem initial_voting_selections
    (config : Config)
    (active : List Location) :
    VotingSelectionsValid (initial config active) := by
  simp [VotingSelectionsValid, Global.initial, initialSystem, initialNode]

theorem initial_sent_votes_selected
    (config : Config)
    (active : List Location) :
    SentVotesSelected (initial config active) := by
  simp [SentVotesSelected, Global.initial]

theorem initial_openings_valid
    (config : Config)
    (active : List Location) :
    OpeningsValid config (initial config active) := by
  simp [OpeningsValid, Global.initial]

theorem systemStep_preserves_node_votes_sent
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    {beforeState afterState : State}
    (beforeSystem : beforeState.system = before)
    (votesSent : NodeVotesSent beforeState)
    (carry :
      forall voter destination,
        SentVote beforeState voter destination ->
          SentVote afterState voter destination)
    (introduced :
      forall voter,
        acceptedVoteSource event = some voter ->
          SentVote afterState voter target)
    (transition :
      systemStep config before target event = some (after, output)) :
    forall entry, entry ∈ after.nodes ->
      forall voter, voter ∈ entry.2.votes ->
        SentVote afterState voter entry.1 := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, outputEq⟩
  rw [←systemEq]
  intro entry membership voter vote
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · rename_i atTarget
    have targetEq : previous.1 = target :=
      beq_iff_eq.mp atTarget
    rcases step_vote_origin config node event voter
      (by simpa [outputEq, atTarget] using vote) with
      old | added
    · have keyEq : key = target :=
        beq_iff_eq.mp
          (List.find?_some
            (p := fun entry : Prod Location NodeState =>
              entry.1 == target) found)
      apply carry
      rw [←keyEq]
      exact votesSent (key, node)
        (by
          rw [beforeSystem]
          exact List.mem_of_find?_eq_some found)
        voter old
    · exact introduced voter added
  · rename_i notTarget
    apply carry
    exact votesSent previous
      (by
        rw [beforeSystem]
        exact previousMember)
      voter (by simpa [notTarget] using vote)

theorem eq_of_key_eq
    {α : Type}
    {nodes : List (Prod Location α)}
    (nodup : (nodes.map Prod.fst).Nodup)
    {first second : Prod Location α}
    (firstMember : first ∈ nodes)
    (secondMember : second ∈ nodes)
    (keyEq : first.1 = second.1) :
    first = second := by
  induction nodes generalizing first second with
  | nil => simp at firstMember
  | cons head tail ih =>
      rw [List.map_cons, List.nodup_cons] at nodup
      rcases nodup with ⟨headFresh, tailNodup⟩
      rw [List.mem_cons] at firstMember secondMember
      rcases firstMember with rfl | firstTail
      · rcases secondMember with rfl | secondTail
        · rfl
        · exfalso
          apply headFresh
          rw [List.mem_map]
          exact ⟨second, secondTail, keyEq.symm⟩
      · rcases secondMember with rfl | secondTail
        · exfalso
          apply headFresh
          rw [List.mem_map]
          exact ⟨first, firstTail, keyEq⟩
        · exact ih tailNodup firstTail secondTail keyEq

theorem systemStep_preserves_vote_stability
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    {envelope : Envelope}
    (stable :
      forall entry, entry ∈ before.nodes ->
        entry.1 = envelope.source ->
        entry.2.phase ≠ .gossiping /\
          (entry.2.phase = .voting ->
            entry.2.chosen = some envelope.target))
    (transition :
      systemStep config before target event = some (after, output)) :
    forall entry, entry ∈ after.nodes ->
      entry.1 = envelope.source ->
      entry.2.phase ≠ .gossiping /\
        (entry.2.phase = .voting ->
          entry.2.chosen = some envelope.target) := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, outputEq⟩
  rw [←systemEq]
  intro entry membership sourceEq
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · rename_i atTarget
    have targetEq : previous.1 = target :=
      beq_iff_eq.mp atTarget
    have targetSource : target = envelope.source := by
      simpa [atTarget] using sourceEq
    have keyEq : key = target :=
      beq_iff_eq.mp
        (List.find?_some
          (p := fun entry : Prod Location NodeState =>
            entry.1 == target) found)
    have beforeStable :=
      stable (key, node) (List.mem_of_find?_eq_some found)
        (keyEq.trans targetSource)
    constructor
    · exact step_preserves_non_gossiping config node event
        beforeStable.1
    · intro voting
      rcases voting_step_preserves_choice config node event
        beforeStable.1 voting with ⟨beforeVoting, chosenEq⟩
      rw [chosenEq]
      exact beforeStable.2 beforeVoting
  · rename_i notTarget
    exact stable previous previousMember
      (by simpa [notTarget] using sourceEq)

theorem next_preserves_node_votes_nodup
    {config : Config}
    {before after : State}
    {action : Action}
    (nodup : NodeVotesNodup before)
    (transition : next config before action = some after) :
    NodeVotesNodup after := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, rfl⟩
      exact nodup
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, _, system, output, systemStep, rfl⟩
      intro entry membership
      rw [recordEffects_system] at membership
      exact systemStep_preserves_votes_nodup nodup systemStep
        entry membership
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, system, output, systemStep, _, rfl⟩
      intro entry membership
      rw [recordEffects_system] at membership
      exact systemStep_preserves_votes_nodup nodup systemStep
        entry membership

theorem next_preserves_voting_selections
    {config : Config}
    {before after : State}
    {action : Action}
    (valid : VotingSelectionsValid before)
    (transition : next config before action = some after) :
    VotingSelectionsValid after := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, rfl⟩
      exact valid
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, _, system, output, systemStep, rfl⟩
      intro entry membership voting
      rw [recordEffects_system] at membership
      exact systemStep_preserves_voting_selections valid systemStep
        entry membership voting
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, system, output, systemStep, _, rfl⟩
      intro entry membership voting
      rw [recordEffects_system] at membership
      exact systemStep_preserves_voting_selections valid systemStep
        entry membership voting

theorem retry_preserves_sent_votes_selected
    {config : Config}
    {before after : State}
    {source : Location}
    (wellFormed : WellFormed config before)
    (votingSelections : VotingSelectionsValid before)
    (selected : SentVotesSelected before)
    (transition : next config before (.retry source) = some after) :
    SentVotesSelected after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, sourceState, found, _, stateEq⟩
  have sourceLocation : sourceState.location = source :=
    nodeState_location wellFormed.nodeLocations found
  rw [←stateEq]
  intro envelope membership payload
  rw [List.mem_append] at membership
  rcases membership with old | added
  · exact selected envelope old payload
  · have valid : envelope.Valid config :=
      retryMessages_valid config source sourceState sourceLocation
        envelope added
    have voteState := retry_vote_state valid payload
    have identity := retryMessages_source added
    rw [identity.2] at voteState
    rw [nodeState, Option.map_eq_some_iff] at found
    rcases found with ⟨entry, findEq, stateEq⟩
    have sourceSelection :=
      votingSelections entry (List.mem_of_find?_eq_some findEq)
        (by simpa [stateEq] using voteState.1)
    simpa [identity.2, stateEq] using sourceSelection

theorem deliver_preserves_sent_votes_selected
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (selected : SentVotesSelected before)
    (transition : next config before (.deliver envelope) = some after) :
    SentVotesSelected after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, _, system, output, _, stateEq⟩
  rw [←stateEq]
  intro vote membership payload
  rw [recordEffects_sent] at membership
  exact selected vote membership payload

theorem timeout_preserves_sent_votes_selected
    {config : Config}
    {before after : State}
    {target : Location}
    (selected : SentVotesSelected before)
    (transition : next config before (.timeout target) = some after) :
    SentVotesSelected after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, system, output, _, _, stateEq⟩
  rw [←stateEq]
  intro vote membership payload
  rw [recordEffects_sent] at membership
  exact selected vote membership payload

theorem retry_preserves_node_votes_sent
    {config : Config}
    {before after : State}
    {source : Location}
    (votesSent : NodeVotesSent before)
    (transition : next config before (.retry source) = some after) :
    NodeVotesSent after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with ⟨_, sourceState, _, _, rfl⟩
  intro entry membership voter vote
  apply sentVote_mono (before := before)
  · intro envelope sent
    exact List.mem_append_left _ sent
  · exact votesSent entry membership voter vote

theorem deliver_preserves_node_votes_sent
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config before)
    (votesSent : NodeVotesSent before)
    (transition : next config before (.deliver envelope) = some after) :
    NodeVotesSent after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨inNetwork, _, system, output, systemStep, stateEq⟩
  rw [←stateEq]
  intro entry membership voter vote
  rw [recordEffects_system] at membership
  let afterState :=
    recordEffects envelope.target output.state output.effects
      {
        before with
        system
        network := removeOne envelope before.network
      }
  have carry :
      forall oldVoter oldTarget,
        SentVote before oldVoter oldTarget ->
          SentVote afterState oldVoter oldTarget := by
    intro oldVoter oldTarget oldVote
    apply sentVote_mono (before := before) (after := afterState)
    · intro sent sentMember
      simpa [afterState] using sentMember
    · exact oldVote
  have introducedVote :
      forall newVoter,
        acceptedVoteSource (eventFor envelope) = some newVoter ->
          SentVote afterState newVoter envelope.target := by
    intro newVoter introduced
    rcases eventFor_vote_source introduced with
      ⟨payload, source⟩
    subst newVoter
    refine ⟨envelope, ?_, rfl, rfl, payload⟩
    simp [afterState]
    exact wellFormed.networkSent envelope
      inNetwork
  exact systemStep_preserves_node_votes_sent
    (before := before.system)
    (after := system)
    (beforeState := before)
    (afterState := afterState)
    rfl votesSent carry introducedVote systemStep
    entry membership voter vote

theorem timeout_preserves_node_votes_sent
    {config : Config}
    {before after : State}
    {target : Location}
    (votesSent : NodeVotesSent before)
    (transition : next config before (.timeout target) = some after) :
    NodeVotesSent after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, system, output, systemStep, _, stateEq⟩
  rw [←stateEq]
  intro entry membership voter vote
  rw [recordEffects_system] at membership
  let afterState :=
    recordEffects target output.state output.effects
      { before with system }
  have carry :
      forall oldVoter oldTarget,
        SentVote before oldVoter oldTarget ->
          SentVote afterState oldVoter oldTarget := by
    intro oldVoter oldTarget oldVote
    apply sentVote_mono (before := before) (after := afterState)
    · intro sent sentMember
      simpa [afterState] using sentMember
    · exact oldVote
  have introducedVote :
      forall newVoter,
        acceptedVoteSource Event.timeout = some newVoter ->
          SentVote afterState newVoter target := by
    intro newVoter introduced
    simp [acceptedVoteSource] at introduced
  exact systemStep_preserves_node_votes_sent
    (before := before.system)
    (after := system)
    (beforeState := before)
    (afterState := afterState)
    rfl votesSent carry introducedVote systemStep
    entry membership voter vote

theorem retry_preserves_openings_valid
    {config : Config}
    {before after : State}
    {source : Location}
    (valid : OpeningsValid config before)
    (transition : next config before (.retry source) = some after) :
    OpeningsValid config after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with ⟨_, sourceState, _, _, stateEq⟩
  rw [←stateEq]
  intro opening membership
  apply opening_valid_mono
  · intro envelope sent
    exact List.mem_append_left _ sent
  · exact valid opening membership

theorem deliver_preserves_openings_valid
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config before)
    (votesNodup : NodeVotesNodup before)
    (votesSent : NodeVotesSent before)
    (valid : OpeningsValid config before)
    (transition : next config before (.deliver envelope) = some after) :
    OpeningsValid config after := by
  have afterNodup :=
    next_preserves_node_votes_nodup votesNodup transition
  have afterVotesSent :=
    deliver_preserves_node_votes_sent wellFormed votesSent transition
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, _, system, output, systemStep, stateEq⟩
  rw [←stateEq] at afterNodup afterVotesSent ⊢
  let delivered : State := {
    before with
    system
    network := removeOne envelope before.network
  }
  apply recordEffects_preserves_openings_valid
  · intro opening membership
    apply opening_valid_of_sent_eq
      (before := before) (after := delivered) rfl
    exact valid opening membership
  · intro kind openingEffect
    have effectState :=
      systemStep_opening_effect_state systemStep openingEffect
    constructor
    · exact systemStep_output_location
        wellFormed.nodeLocations systemStep
    · exact effectState.1
    · exact effectState.2
    · apply afterNodup (envelope.target, output.state)
      rw [recordEffects_system]
      exact systemStep_output_mem systemStep
    · intro quorumKind
      have kindEq : kind = .quorum := by simpa using quorumKind
      rw [kindEq] at openingEffect
      simpa using
        systemStep_quorum_effect_has_threshold systemStep openingEffect
    · intro voter vote
      have sent :=
        afterVotesSent (envelope.target, output.state)
          (by
            rw [recordEffects_system]
            exact systemStep_output_mem systemStep)
          voter vote
      simpa [SentVote, delivered] using sent

theorem timeout_preserves_openings_valid
    {config : Config}
    {before after : State}
    {target : Location}
    (wellFormed : WellFormed config before)
    (votesNodup : NodeVotesNodup before)
    (votesSent : NodeVotesSent before)
    (valid : OpeningsValid config before)
    (transition : next config before (.timeout target) = some after) :
    OpeningsValid config after := by
  have afterNodup :=
    next_preserves_node_votes_nodup votesNodup transition
  have afterVotesSent :=
    timeout_preserves_node_votes_sent votesSent transition
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, system, output, systemStep, _, stateEq⟩
  rw [←stateEq] at afterNodup afterVotesSent ⊢
  let timedOut : State := { before with system }
  apply recordEffects_preserves_openings_valid
  · intro opening membership
    apply opening_valid_of_sent_eq
      (before := before) (after := timedOut) rfl
    exact valid opening membership
  · intro kind openingEffect
    have effectState :=
      systemStep_opening_effect_state systemStep openingEffect
    constructor
    · exact systemStep_output_location
        wellFormed.nodeLocations systemStep
    · exact effectState.1
    · exact effectState.2
    · apply afterNodup (target, output.state)
      rw [recordEffects_system]
      exact systemStep_output_mem systemStep
    · intro quorumKind
      have kindEq : kind = .quorum := by simpa using quorumKind
      rw [kindEq] at openingEffect
      simpa using
        systemStep_quorum_effect_has_threshold systemStep openingEffect
    · intro voter vote
      have sent :=
        afterVotesSent (target, output.state)
          (by
            rw [recordEffects_system]
            exact systemStep_output_mem systemStep)
          voter vote
      simpa [SentVote, timedOut] using sent

theorem retry_preserves_sent_vote_stable
    {config : Config}
    {before after : State}
    {source : Location}
    (wellFormed : WellFormed config before)
    (stable : SentVoteStable before)
    (transition : next config before (.retry source) = some after) :
    SentVoteStable after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, sourceState, found, _, stateEq⟩
  have sourceLocation : sourceState.location = source :=
    nodeState_location wellFormed.nodeLocations found
  rw [←stateEq]
  intro envelope membership payload entry entryMember keyEq
  rw [List.mem_append] at membership
  rcases membership with old | added
  · exact stable envelope old payload entry entryMember keyEq
  · have valid : envelope.Valid config :=
      retryMessages_valid config source sourceState sourceLocation
        envelope added
    have voteState := retry_vote_state valid payload
    rcases retryMessages_source added with
      ⟨sourceEq, stateEq⟩
    rw [nodeState, Option.map_eq_some_iff] at found
    rcases found with ⟨foundEntry, findEq, foundStateEq⟩
    have foundMember : foundEntry ∈ before.system.nodes :=
      List.mem_of_find?_eq_some findEq
    have foundKey : foundEntry.1 = source :=
      beq_iff_eq.mp
        (List.find?_some
          (p := fun entry : Prod Location NodeState =>
            entry.1 == source) findEq)
    have sameEntry : entry = foundEntry :=
      eq_of_key_eq wellFormed.nodeKeysNodup entryMember foundMember
        ((keyEq.trans sourceEq).trans foundKey.symm)
    subst entry
    rw [foundStateEq, ←stateEq]
    exact ⟨by simp [voteState.1], fun _ => voteState.2⟩

theorem deliver_preserves_sent_vote_stable
    {config : Config}
    {before after : State}
    {delivered : Envelope}
    (stable : SentVoteStable before)
    (transition : next config before (.deliver delivered) = some after) :
    SentVoteStable after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, _, system, output, systemStep, stateEq⟩
  rw [←stateEq]
  intro envelope membership payload entry entryMember keyEq
  rw [recordEffects_sent] at membership
  rw [recordEffects_system] at entryMember
  exact systemStep_preserves_vote_stability
    (fun previous previousMember source =>
      stable envelope membership payload previous previousMember source)
    systemStep entry entryMember keyEq

theorem timeout_preserves_sent_vote_stable
    {config : Config}
    {before after : State}
    {target : Location}
    (stable : SentVoteStable before)
    (transition : next config before (.timeout target) = some after) :
    SentVoteStable after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, system, output, systemStep, _, stateEq⟩
  rw [←stateEq]
  intro envelope membership payload entry entryMember keyEq
  rw [recordEffects_sent] at membership
  rw [recordEffects_system] at entryMember
  exact systemStep_preserves_vote_stability
    (fun previous previousMember source =>
      stable envelope membership payload previous previousMember source)
    systemStep entry entryMember keyEq

theorem sentVote_stable_at_node
    {state : State}
    {voter target : Location}
    {current : NodeState}
    (stable : SentVoteStable state)
    (vote : SentVote state voter target)
    (found : nodeState state voter = some current) :
    current.phase ≠ .gossiping /\
      (current.phase = .voting ->
        current.chosen = some target) := by
  rcases vote with
    ⟨envelope, sent, sourceEq, targetEq, payload⟩
  rw [nodeState, Option.map_eq_some_iff] at found
  rcases found with ⟨entry, findEq, stateEq⟩
  have entryMember : entry ∈ state.system.nodes :=
    List.mem_of_find?_eq_some findEq
  have entryKey : entry.1 = voter :=
    beq_iff_eq.mp
      (List.find?_some
        (p := fun entry : Prod Location NodeState =>
          entry.1 == voter) findEq)
  have result :=
    stable envelope sent payload entry entryMember
      (entryKey.trans sourceEq.symm)
  rw [stateEq] at result
  simpa [targetEq] using result

theorem retry_preserves_sent_votes_functional
    {config : Config}
    {before after : State}
    {source : Location}
    (wellFormed : WellFormed config before)
    (functional : SentVotesFunctional before)
    (stable : SentVoteStable before)
    (transition : next config before (.retry source) = some after) :
    SentVotesFunctional after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, sourceState, found, _, stateEq⟩
  have sourceLocation : sourceState.location = source :=
    nodeState_location wellFormed.nodeLocations found
  rw [←stateEq]
  have classify :
      forall voter target,
        SentVote
            {
              before with
              network := before.network ++
                retryMessages config source sourceState
              sent := before.sent ++
                retryMessages config source sourceState
            }
            voter target ->
          SentVote before voter target \/
            (voter = source /\
              sourceState.phase = .voting /\
              sourceState.chosen = some target) := by
    intro voter target vote
    rcases vote with
      ⟨envelope, membership, sourceEq, targetEq, payload⟩
    rw [List.mem_append] at membership
    rcases membership with old | added
    · exact Or.inl
        ⟨envelope, old, sourceEq, targetEq, payload⟩
    · have valid : envelope.Valid config :=
        retryMessages_valid config source sourceState sourceLocation
          envelope added
      have voteState := retry_vote_state valid payload
      have retryIdentity := retryMessages_source added
      rw [retryIdentity.2] at voteState
      exact Or.inr
        ⟨sourceEq.symm.trans retryIdentity.1,
          voteState.1,
          by simpa [targetEq] using voteState.2⟩
  intro voter first second firstVote secondVote
  rcases classify voter first firstVote with
    firstOld | ⟨firstSource, firstPhase, firstChoice⟩
  · rcases classify voter second secondVote with
      secondOld | ⟨secondSource, secondPhase, secondChoice⟩
    · exact functional voter first second firstOld secondOld
    · have oldState :=
        sentVote_stable_at_node stable firstOld
          (by simpa [secondSource] using found)
      have oldChoice := oldState.2 secondPhase
      rw [oldChoice] at secondChoice
      exact Option.some.inj secondChoice
  · rcases classify voter second secondVote with
      secondOld | ⟨secondSource, secondPhase, secondChoice⟩
    · have oldState :=
        sentVote_stable_at_node stable secondOld
          (by simpa [firstSource] using found)
      have oldChoice := oldState.2 firstPhase
      rw [oldChoice] at firstChoice
      exact (Option.some.inj firstChoice).symm
    · rw [firstChoice] at secondChoice
      exact Option.some.inj secondChoice

theorem deliver_preserves_sent_votes_functional
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (functional : SentVotesFunctional before)
    (transition : next config before (.deliver envelope) = some after) :
    SentVotesFunctional after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, _, system, output, _, stateEq⟩
  rw [←stateEq]
  intro voter first second firstVote secondVote
  apply functional voter first second
  · simpa [SentVote] using firstVote
  · simpa [SentVote] using secondVote

theorem timeout_preserves_sent_votes_functional
    {config : Config}
    {before after : State}
    {target : Location}
    (functional : SentVotesFunctional before)
    (transition : next config before (.timeout target) = some after) :
    SentVotesFunctional after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, system, output, _, _, stateEq⟩
  rw [←stateEq]
  intro voter first second firstVote secondVote
  apply functional voter first second
  · simpa [SentVote] using firstVote
  · simpa [SentVote] using secondVote

theorem initial_quorum_invariant
    (config : Config)
    (active : List Location) :
    QuorumInvariant config (initial config active) := {
  votesNodup := initial_node_votes_nodup config active
  votesSent := initial_node_votes_sent config active
  sentVoteStable := initial_sent_vote_stable config active
  sentVotesFunctional := initial_sent_votes_functional config active
  votingSelections := initial_voting_selections config active
  sentVotesSelected := initial_sent_votes_selected config active
  openingsValid := initial_openings_valid config active
}

theorem next_preserves_quorum_invariant
    {config : Config}
    {before after : State}
    {action : Action}
    (wellFormed : WellFormed config before)
    (invariant : QuorumInvariant config before)
    (transition : next config before action = some after) :
    QuorumInvariant config after := by
  cases action with
  | retry source =>
      constructor
      · exact next_preserves_node_votes_nodup
          invariant.votesNodup transition
      · exact retry_preserves_node_votes_sent
          invariant.votesSent transition
      · exact retry_preserves_sent_vote_stable
          wellFormed invariant.sentVoteStable transition
      · exact retry_preserves_sent_votes_functional
          wellFormed invariant.sentVotesFunctional
            invariant.sentVoteStable transition
      · exact next_preserves_voting_selections
          invariant.votingSelections transition
      · exact retry_preserves_sent_votes_selected
          wellFormed invariant.votingSelections
            invariant.sentVotesSelected transition
      · exact retry_preserves_openings_valid
          invariant.openingsValid transition
  | deliver envelope =>
      constructor
      · exact next_preserves_node_votes_nodup
          invariant.votesNodup transition
      · exact deliver_preserves_node_votes_sent
          wellFormed invariant.votesSent transition
      · exact deliver_preserves_sent_vote_stable
          invariant.sentVoteStable transition
      · exact deliver_preserves_sent_votes_functional
          invariant.sentVotesFunctional transition
      · exact next_preserves_voting_selections
          invariant.votingSelections transition
      · exact deliver_preserves_sent_votes_selected
          invariant.sentVotesSelected transition
      · exact deliver_preserves_openings_valid
          wellFormed invariant.votesNodup invariant.votesSent
            invariant.openingsValid transition
  | timeout target =>
      constructor
      · exact next_preserves_node_votes_nodup
          invariant.votesNodup transition
      · exact timeout_preserves_node_votes_sent
          invariant.votesSent transition
      · exact timeout_preserves_sent_vote_stable
          invariant.sentVoteStable transition
      · exact timeout_preserves_sent_votes_functional
          invariant.sentVotesFunctional transition
      · exact next_preserves_voting_selections
          invariant.votingSelections transition
      · exact timeout_preserves_sent_votes_selected
          invariant.sentVotesSelected transition
      · exact timeout_preserves_openings_valid
          wellFormed invariant.votesNodup invariant.votesSent
            invariant.openingsValid transition

theorem reachable_quorum_invariant
    {config : Config}
    {state : State}
    (reachable : Reachable config state) :
    QuorumInvariant config state := by
  induction reachable with
  | initial active valid nodup configured =>
      exact initial_quorum_invariant config active
  | step reachable transition invariant =>
      exact next_preserves_quorum_invariant
        (reachable_well_formed reachable) invariant transition

theorem quorum_lists_intersect
    {α : Type}
    [DecidableEq α]
    (expected first second : List α)
    (firstNodup : first.Nodup)
    (secondNodup : second.Nodup)
    (firstSubset :
      forall value, value ∈ first -> value ∈ expected)
    (secondSubset :
      forall value, value ∈ second -> value ∈ expected)
    (firstQuorum :
      expected.length / 2 + 1 <= first.length)
    (secondQuorum :
      expected.length / 2 + 1 <= second.length) :
    exists value, value ∈ first /\ value ∈ second := by
  by_contra noShared
  push_neg at noShared
  have disjoint : Disjoint first.toFinset second.toFinset :=
    Finset.disjoint_left.mpr (by
      intro value firstMember secondMember
      exact noShared value
        (List.mem_toFinset.mp firstMember)
        (List.mem_toFinset.mp secondMember))
  have unionSubset :
      first.toFinset ∪ second.toFinset ⊆ expected.toFinset := by
    intro value membership
    rw [Finset.mem_union] at membership
    rw [List.mem_toFinset]
    exact membership.elim
      (fun member =>
        firstSubset value (List.mem_toFinset.mp member))
      (fun member =>
        secondSubset value (List.mem_toFinset.mp member))
  have unionCard := Finset.card_le_card unionSubset
  rw [Finset.card_union_of_disjoint disjoint,
    List.toFinset_card_of_nodup firstNodup,
    List.toFinset_card_of_nodup secondNodup] at unionCard
  have expectedCard := List.toFinset_card_le expected
  omega

def QuorumOpened (state : State) (node : Location) : Prop :=
  exists opening,
    opening ∈ state.openings /\
      opening.node = node /\
      opening.kind = .quorum

theorem opening_vote_configured
    {config : Config}
    {state : State}
    {opening : Opening}
    (wellFormed : WellFormed config state)
    (valid : opening.Valid config state)
    {voter : Location}
    (vote : voter ∈ opening.state.votes) :
    voter ∈ config.protocol.expectedLocations := by
  rcases valid.votesSent voter vote with
    ⟨envelope, sent, sourceEq, _, _⟩
  apply wellFormed.activeConfigured voter
  simpa [sourceEq] using
    wellFormed.sentSourceActive envelope sent

theorem quorum_opener_unique
    {config : Config}
    {state : State}
    {first second : Location}
    (reachable : Reachable config state)
    (firstOpened : QuorumOpened state first)
    (secondOpened : QuorumOpened state second) :
    first = second := by
  have wellFormed := reachable_well_formed reachable
  have invariant := reachable_quorum_invariant reachable
  rcases firstOpened with
    ⟨firstOpening, firstMember, firstNode, firstKind⟩
  rcases secondOpened with
    ⟨secondOpening, secondMember, secondNode, secondKind⟩
  have firstValid :=
    invariant.openingsValid firstOpening firstMember
  have secondValid :=
    invariant.openingsValid secondOpening secondMember
  rcases quorum_lists_intersect
      config.protocol.expectedLocations
      firstOpening.state.votes
      secondOpening.state.votes
      firstValid.votesNodup
      secondValid.votesNodup
      (fun voter vote =>
        opening_vote_configured wellFormed firstValid vote)
      (fun voter vote =>
        opening_vote_configured wellFormed secondValid vote)
      (by
        simpa [voteQuorum] using firstValid.quorum firstKind)
      (by
        simpa [voteQuorum] using secondValid.quorum secondKind) with
    ⟨voter, firstVote, secondVote⟩
  have targetEq :=
    invariant.sentVotesFunctional voter
      firstOpening.node secondOpening.node
      (firstValid.votesSent voter firstVote)
      (secondValid.votesSent voter secondVote)
  exact firstNode.symm.trans (targetEq.trans secondNode)

end DisasterRecovery.Protocol.Global
