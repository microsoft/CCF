import DisasterRecovery.Protocol.Committed
import DisasterRecovery.Protocol.Temporal
import Mathlib.Tactic

namespace DisasterRecovery.Protocol.Global

structure Execution (config : Config) where
  states : Nat -> State
  actions : Nat -> Action
  step_succ : forall n,
    next config (states n) (actions n) = some (states (n + 1))

def HasPhase (state : State) (node : Location) (phase : Phase) : Prop :=
  exists nodeState,
    Global.nodeState state node = some nodeState /\
      nodeState.phase = phase

def HasGossip (state : State) (node : Location) : Prop :=
  exists nodeState,
    Global.nodeState state node = some nodeState /\
      nodeState.gossips ≠ []

def HasVote (state : State) (node : Location) : Prop :=
  exists nodeState,
    Global.nodeState state node = some nodeState /\
      nodeState.votes ≠ []

def LaneAdvanced (state : State) (node : Location) : Prop :=
  exists nodeState,
    Global.nodeState state node = some nodeState /\
      nodeState.timeoutState ≠ .gossiping

theorem hasPhase_unique
    {state : State}
    {node : Location}
    {first second : Phase}
    (firstPhase : HasPhase state node first)
    (secondPhase : HasPhase state node second) :
    first = second := by
  rcases firstPhase with ⟨firstState, firstFound, firstEq⟩
  rcases secondPhase with ⟨secondState, secondFound, secondEq⟩
  rw [firstFound] at secondFound
  injection secondFound with stateEq
  subst secondState
  exact firstEq.symm.trans secondEq

def Terminal (state : State) (node : Location) : Prop :=
  node ∈ state.restarts \/ node ∈ state.completed

def CompletedOpen (state : State) (node : Location) : Prop :=
  node ∈ state.completed

def AnnouncementsLive (state : State) : Prop :=
  forall envelope, envelope ∈ state.sent ->
    envelope.payload = .iAmOpen ->
      HasPhase state envelope.source .opening \/
        CompletedOpen state envelope.source

def SentAnnouncementTo (state : State) (target : Location) : Prop :=
  exists envelope,
    envelope ∈ state.sent /\
      envelope.target = target /\
      envelope.payload = .iAmOpen

def JoiningAnnouncements (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    entry.2.phase = .joining ->
      SentAnnouncementTo state entry.1

def OpenCompleted (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    entry.2.phase = .open ->
      CompletedOpen state entry.1

def AdvancedNodesActive (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    entry.2.phase ≠ .gossiping ->
      entry.1 ∈ state.active

def OpenerWitness (state : State) : Prop :=
  exists node,
    HasPhase state node .opening \/
      CompletedOpen state node

def OnlyOpenerCompletesFrom
    {config : Config}
    (execution : Execution config)
    (start : Nat)
    (opener : Location) : Prop :=
  forall n node,
    start <= n ->
    CompletedOpen (execution.states n) node ->
      node = opener

def QuorumOnlyCompletions
    {config : Config}
    (execution : Execution config) : Prop :=
  forall n node,
    CompletedOpen (execution.states n) node ->
      QuorumOpened (execution.states n) node

def SentAnnouncement
    (state : State)
    (source target : Location) : Prop :=
  exists envelope,
    envelope ∈ state.sent /\
      envelope.source = source /\
      envelope.target = target /\
      envelope.payload = .iAmOpen

def BroadcastBeforeCompletion
    {config : Config}
    (execution : Execution config) : Prop :=
  forall n opener,
    CompletedOpen (execution.states n) opener ->
    forall target, target ∈ (execution.states n).active ->
      target ≠ opener ->
      SentAnnouncement (execution.states n) opener target

def AnnouncementsResolved (state : State) : Prop :=
  forall envelope, envelope ∈ state.sent ->
    envelope.payload = .iAmOpen ->
      envelope ∈ state.network \/
        Terminal state envelope.target \/
        HasPhase state envelope.target .opening

def Enabled (config : Config) (state : State) (action : Action) : Prop :=
  exists nextState, next config state action = some nextState

def LaneValid (state : NodeState) : Prop :=
  (state.phase = .gossiping ->
    state.timeoutState = .gossiping) /\
  (state.phase = .voting ->
    state.timeoutState = .gossiping \/
      state.timeoutState = .voting) /\
  (state.phase = .opening ->
    state.timeoutState = .gossiping \/
      state.timeoutState = .voting \/
      state.timeoutState = .opening) /\
  (state.phase = .gossiping ->
    state.chosen = none)

def NodeLanesValid (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    LaneValid entry.2

theorem step_preserves_lane
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (valid : LaneValid state) :
    LaneValid (step config state event).state := by
  cases event
  all_goals try cases_type Validation
  all_goals
    simp [LaneValid, step, rejected, advance, advanceTimeoutLane,
      advanceTimeoutState, validTimeout] at valid ⊢
  all_goals repeat first | split | simp_all | aesop

theorem step_preserves_advanced_lane
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (advanced : state.timeoutState ≠ .gossiping) :
    (step config state event).state.timeoutState ≠ .gossiping := by
  cases event
  all_goals try cases_type Validation
  all_goals
    simp [step, rejected, advance, validTimeout, advanceTimeoutLane,
      advanceTimeoutState] at advanced ⊢
  all_goals repeat first | split | simp_all

theorem systemStep_preserves_lanes
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (valid :
      forall entry, entry ∈ before.nodes ->
        LaneValid entry.2)
    (transition :
      systemStep config before target event = some (after, output)) :
    forall entry, entry ∈ after.nodes ->
      LaneValid entry.2 := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, outputEq⟩
  rw [←systemEq]
  intro entry membership
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · apply step_preserves_lane config node event
    exact valid (key, node) (List.mem_of_find?_eq_some found)
  · exact valid previous previousMember

theorem initial_lanes_valid
    (config : Config)
    (active : List Location) :
    NodeLanesValid (initial config active) := by
  simp [NodeLanesValid, LaneValid, Global.initial, initialSystem,
    initialNode]

theorem next_preserves_lanes
    {config : Config}
    {before after : State}
    {action : Action}
    (valid : NodeLanesValid before)
    (transition : next config before action = some after) :
    NodeLanesValid after := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, rfl⟩
      exact valid
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, _, system, output, systemStep, rfl⟩
      intro entry membership
      rw [recordEffects_system] at membership
      exact systemStep_preserves_lanes valid systemStep
        entry membership
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, system, output, systemStep, _, rfl⟩
      intro entry membership
      rw [recordEffects_system] at membership
      exact systemStep_preserves_lanes valid systemStep
        entry membership

theorem reachable_lanes_valid
    {config : Config}
    {state : State}
    (reachable : Reachable config state) :
    NodeLanesValid state := by
  induction reachable with
  | initial active valid nodup configured =>
      exact initial_lanes_valid config active
  | step reachable transition valid =>
      exact next_preserves_lanes valid transition

theorem nodeState_eq_of_mem
    {state : State}
    {node : Location}
    {foundState : NodeState}
    (keysNodup : (state.system.nodes.map Prod.fst).Nodup)
    (membership : (node, foundState) ∈ state.system.nodes) :
    Global.nodeState state node = some foundState := by
  unfold Global.nodeState
  cases found :
      state.system.nodes.find? fun entry => entry.1 == node with
  | none =>
      rw [List.find?_eq_none] at found
      exact False.elim
        (found (node, foundState) membership (by simp))
  | some entry =>
      have foundMember : entry ∈ state.system.nodes :=
        List.mem_of_find?_eq_some found
      have foundKey : entry.1 = node :=
        beq_iff_eq.mp
          (List.find?_some
            (p := fun entry : Prod Location NodeState =>
              entry.1 == node) found)
      have same : entry = (node, foundState) :=
        eq_of_key_eq keysNodup foundMember membership foundKey
      simp [same]

theorem node_property_of_nodeState
    {state : State}
    {node : Location}
    {foundState : NodeState}
    {predicate : NodeState -> Prop}
    (property :
      forall entry, entry ∈ state.system.nodes ->
        predicate entry.2)
    (found : Global.nodeState state node = some foundState) :
    predicate foundState := by
  rw [Global.nodeState, Option.map_eq_some_iff] at found
  rcases found with ⟨entry, findEq, stateEq⟩
  rw [←stateEq]
  exact property entry (List.mem_of_find?_eq_some findEq)

theorem deliver_target_state
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config before)
    (transition : next config before (.deliver envelope) = some after) :
    exists output,
      Global.nodeState after envelope.target = some output.state /\
        systemStep config.protocol before.system envelope.target
          (eventFor envelope) = some (after.system, output) := by
  have afterWellFormed :=
    next_preserves_well_formed wellFormed transition
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, _, system, output, systemStep, stateEq⟩
  rw [←stateEq] at afterWellFormed ⊢
  refine ⟨output, ?_, ?_⟩
  · apply nodeState_eq_of_mem afterWellFormed.nodeKeysNodup
    rw [recordEffects_system]
    exact systemStep_output_mem systemStep
  · simpa using systemStep

theorem timeout_target_state
    {config : Config}
    {before after : State}
    {target : Location}
    (wellFormed : WellFormed config before)
    (transition : next config before (.timeout target) = some after) :
    exists output,
      Global.nodeState after target = some output.state /\
        output.accepted = true /\
        systemStep config.protocol before.system target .timeout =
          some (after.system, output) := by
  have afterWellFormed :=
    next_preserves_well_formed wellFormed transition
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, system, output, systemStep, accepted, stateEq⟩
  rw [←stateEq] at afterWellFormed ⊢
  refine ⟨output, ?_, accepted, ?_⟩
  · apply nodeState_eq_of_mem afterWellFormed.nodeKeysNodup
    rw [recordEffects_system]
    exact systemStep_output_mem systemStep
  · simpa using systemStep

theorem systemStep_output_eq
    {config : Protocol.Config}
    {global : State}
    {after : SystemState}
    {target : Location}
    {event : Event}
    {state : NodeState}
    {output : StepOutput}
    (found : Global.nodeState global target = some state)
    (transition :
      systemStep config global.system target event = some (after, output)) :
    output = step config state event := by
  change
    (do
      let node <- Global.nodeState global target
      let result := step config node event
      pure ({
        nodes := replaceNode target result.state global.system.nodes
      }, result)) = some (after, output) at transition
  rw [found] at transition
  simp at transition
  exact transition.2.symm

theorem completed_effect_recorded
    {node : Location}
    {nodeState : NodeState}
    {effects : List Effect}
    {state : State}
    (completed : .completed ∈ effects) :
    node ∈ (recordEffects node nodeState effects state).completed := by
  induction effects generalizing state with
  | nil => simp at completed
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      rw [List.mem_cons] at completed
      rcases completed with rfl | inTail
      · apply mem_completed_recordEffects
        simp [recordEffect]
      · exact ih inTail

theorem restart_effect_recorded
    {node chosen : Location}
    {nodeState : NodeState}
    {effects : List Effect}
    {state : State}
    (restart : .restart chosen ∈ effects) :
    node ∈ (recordEffects node nodeState effects state).restarts := by
  induction effects generalizing state with
  | nil => simp at restart
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      rw [List.mem_cons] at restart
      rcases restart with rfl | inTail
      · apply mem_restarts_recordEffects
        simp [recordEffect]
      · exact ih inTail

theorem mem_removeOne_or_eq
    [BEq α]
    [LawfulBEq α]
    {member removed : α}
    {values : List α}
    (membership : member ∈ values) :
    member ∈ removeOne removed values \/ member = removed := by
  induction values with
  | nil => simp at membership
  | cons head tail ih =>
      rw [List.mem_cons] at membership
      rcases membership with rfl | inTail
      · by_cases equal : member = removed
        · exact Or.inr equal
        · exact Or.inl (by simp [removeOne, equal])
      · simp only [removeOne]
        split
        · exact Or.inl inTail
        · rcases ih inTail with still | equal
          · exact Or.inl (by simp [still])
          · exact Or.inr equal

structure Fair
    {config : Config}
    (execution : Execution config) : Prop where
  retry :
    forall start node phase,
      node ∈ (execution.states start).active ->
      HasPhase (execution.states start) node phase ->
      (phase = .gossiping \/ phase = .voting \/ phase = .opening) ->
      Enabled config (execution.states start) (.retry node) ->
      EventuallyFrom start (fun n =>
        Not (HasPhase (execution.states n) node phase) \/
          execution.actions n = .retry node)
  delivery :
    forall start envelope,
      envelope ∈ (execution.states start).network ->
      EventuallyFrom start (fun n =>
        execution.actions n = .deliver envelope)
  timeout :
    forall start node phase,
      node ∈ (execution.states start).active ->
      HasPhase (execution.states start) node phase ->
      (phase = .gossiping \/ phase = .voting \/ phase = .opening) ->
      Enabled config (execution.states start) (.timeout node) ->
      EventuallyFrom start (fun n =>
        Not (HasPhase (execution.states n) node phase) \/
          execution.actions n = .timeout node)
  openingTimeout :
    forall start node,
      node ∈ (execution.states start).active ->
      HasPhase (execution.states start) node .opening ->
      Enabled config (execution.states start) (.timeout node) ->
      EventuallyFrom start (fun n =>
        CompletedOpen (execution.states n) node \/
          (HasPhase (execution.states n) node .opening /\
            execution.actions n = .timeout node))

theorem execution_reachable
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0)) :
    forall n, Reachable config (execution.states n) := by
  intro n
  induction n with
  | zero => exact initial
  | succ n reachable =>
      exact Reachable.step reachable (execution.step_succ n)

theorem execution_active_eq
    {config : Config}
    (execution : Execution config) :
    forall n, (execution.states n).active = (execution.states 0).active := by
  intro n
  induction n with
  | zero => rfl
  | succ n activeEq =>
      exact (next_active_eq (execution.step_succ n)).trans activeEq

theorem active_at
    {config : Config}
    (execution : Execution config)
    {node : Location}
    (active : node ∈ (execution.states 0).active) :
    forall n, node ∈ (execution.states n).active := by
  intro n
  rw [execution_active_eq execution n]
  exact active

theorem recovered_for_configured
    {config : Config}
    (valid : config.Valid)
    {node : Location}
    (configured : node ∈ config.protocol.expectedLocations) :
    exists txid, recoveredTxID config node = some txid := by
  rw [←valid.2.2] at configured
  rcases List.mem_map.mp configured with
    ⟨entry, membership, keyEq⟩
  rcases entry with ⟨location, txid⟩
  simp at keyEq
  subst location
  refine ⟨txid, ?_⟩
  apply recoveredTxID_of_mem valid
  exact membership

theorem active_nodeState
    {config : Config}
    {state : State}
    (wellFormed : WellFormed config state)
    {node : Location}
    (active : node ∈ state.active) :
    exists nodeState,
      Global.nodeState state node = some nodeState := by
  have configured := wellFormed.activeConfigured node active
  rw [←wellFormed.nodeKeys] at configured
  rcases List.mem_map.mp configured with
    ⟨entry, membership, keyEq⟩
  refine ⟨entry.2, ?_⟩
  apply nodeState_eq_of_mem wellFormed.nodeKeysNodup
  rcases entry with ⟨location, nodeState⟩
  simp at keyEq
  subst location
  exact membership

theorem retryMessages_self_gossip
    {config : Config}
    {node : Location}
    {state : NodeState}
    {txid : TxID}
    (phase : state.phase = .gossiping)
    (configured : node ∈ config.protocol.expectedLocations)
    (recovered : recoveredTxID config node = some txid) :
    {
      source := node
      target := node
      payload := Payload.gossip txid
      sourceState := state
    } ∈ retryMessages config node state := by
  rw [retryMessages, List.mem_filterMap]
  refine ⟨.sendGossip node, ?_, ?_⟩
  · simpa [step, phase] using configured
  · simp [messageForEffect, recovered]

theorem retryMessages_vote
    {config : Config}
    {node target : Location}
    {state : NodeState}
    (phase : state.phase = .voting)
    (chosen : state.chosen = some target) :
    {
      source := node
      target
      payload := Payload.vote
      sourceState := state
    } ∈ retryMessages config node state := by
  rw [retryMessages, List.mem_filterMap]
  refine ⟨.sendVote target, ?_, rfl⟩
  simp [step, phase, chosen]

theorem retry_iamopen_state
    {config : Config}
    {envelope : Envelope}
    (valid : envelope.Valid config)
    (announcement : envelope.payload = .iAmOpen) :
    envelope.sourceState.phase = .opening := by
  rcases valid_envelope_effect valid with
    ⟨effect, member, created⟩
  cases effect with
  | sendGossip target =>
      cases found : recoveredTxID config envelope.source with
      | none => simp [messageForEffect, found] at created
      | some txid =>
          simp [messageForEffect, found] at created
          rw [←created] at announcement
          contradiction
  | sendVote target =>
      simp [messageForEffect] at created
      rw [←created] at announcement
      contradiction
  | sendIAmOpen target =>
      simp [messageForEffect] at created
      rw [←created] at announcement ⊢
      cases phase : envelope.sourceState.phase
      case opening => rfl
      case voting =>
          cases chosen : envelope.sourceState.chosen <;>
            simp [step, phase, chosen] at member
      all_goals simp [step, phase] at member
  | opening kind => simp [messageForEffect] at created
  | restart chosen => simp [messageForEffect] at created
  | completed => simp [messageForEffect] at created
  | rejected reason => simp [messageForEffect] at created

def acceptedIAmOpenSource : Event -> Option Location
  | .receiveIAmOpen source .accepted => some source
  | _ => none

theorem step_joining_origin
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (joining : (step config state event).state.phase = .joining) :
    state.phase = .joining \/
      exists source, acceptedIAmOpenSource event = some source := by
  cases event
  all_goals try cases_type Validation
  all_goals
    simp [acceptedIAmOpenSource, step, rejected, advance,
      advanceTimeoutLane] at joining ⊢
  all_goals
    repeat first | split at joining | split | simp_all | aesop

theorem step_open_origin
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (opened : (step config state event).state.phase = .open) :
    state.phase = .open \/
      .completed ∈ (step config state event).effects := by
  cases event
  all_goals try cases_type Validation
  all_goals
    simp [step, rejected, advance, advanceTimeoutLane, validTimeout]
      at opened ⊢
  all_goals
    repeat first | split at opened | split | simp_all | aesop

theorem iamopen_delivery_outcome
    (config : Protocol.Config)
    (state : NodeState)
    (source : Location) :
    let output := step config state (.receiveIAmOpen source .accepted)
    output.state.phase = .opening \/
      output.state.phase = .open \/
      exists chosen, .restart chosen ∈ output.effects := by
  cases phase : state.phase <;>
    simp [step, phase, rejected, advance, advanceTimeoutLane]

theorem iamopen_open_predecessor
    (config : Protocol.Config)
    (state : NodeState)
    (source : Location)
    (opened :
      (step config state (.receiveIAmOpen source .accepted)).state.phase =
        .open) :
    state.phase = .open := by
  cases phase : state.phase <;>
    simp [step, phase, rejected, advance, advanceTimeoutLane] at opened
  rfl

theorem eventFor_iamopen_source
    {envelope : Envelope}
    {source : Location}
    (accepted :
      acceptedIAmOpenSource (eventFor envelope) = some source) :
    envelope.payload = .iAmOpen /\
      envelope.source = source := by
  cases payload : envelope.payload <;>
    simp_all [eventFor, acceptedIAmOpenSource]

theorem retry_gossip_enabled
    {config : Config}
    {state : State}
    {node : Location}
    (valid : config.Valid)
    (wellFormed : WellFormed config state)
    (active : node ∈ state.active)
    (phase : HasPhase state node .gossiping) :
    Enabled config state (.retry node) := by
  rcases phase with ⟨nodeState, found, gossiping⟩
  have configured := wellFormed.activeConfigured node active
  rcases recovered_for_configured valid configured with
    ⟨txid, recovered⟩
  have message :=
    retryMessages_self_gossip gossiping configured recovered
  have messagesNonempty :
      retryMessages config node nodeState ≠ [] := by
    intro empty
    rw [empty] at message
    simp at message
  refine ⟨{
    state with
    network := state.network ++ retryMessages config node nodeState
    sent := state.sent ++ retryMessages config node nodeState
  }, ?_⟩
  simp [next, active, found, messagesNonempty]

theorem retry_voting_enabled
    {config : Config}
    {state : State}
    {node target : Location}
    {nodeState : NodeState}
    (active : node ∈ state.active)
    (found : Global.nodeState state node = some nodeState)
    (phase : nodeState.phase = .voting)
    (chosen : nodeState.chosen = some target) :
    Enabled config state (.retry node) := by
  have message := retryMessages_vote (config := config)
    (node := node) phase chosen
  have messagesNonempty :
      retryMessages config node nodeState ≠ [] := by
    intro empty
    rw [empty] at message
    simp at message
  refine ⟨{
    state with
    network := state.network ++ retryMessages config node nodeState
    sent := state.sent ++ retryMessages config node nodeState
  }, ?_⟩
  simp [next, active, found, messagesNonempty]

theorem delivery_enabled
    {config : Config}
    {state : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config state)
    (network : envelope ∈ state.network)
    (targetActive : envelope.target ∈ state.active) :
    Enabled config state (.deliver envelope) := by
  rcases active_nodeState wellFormed targetActive with
    ⟨targetState, found⟩
  let output := step config.protocol targetState (eventFor envelope)
  let system : SystemState := {
    nodes := replaceNode envelope.target output.state state.system.nodes
  }
  let delivered : State := {
    state with
    system
    network := removeOne envelope state.network
  }
  have stepResult :
      systemStep config.protocol state.system envelope.target
        (eventFor envelope) = some (system, output) := by
    change
      (do
        let node <- Global.nodeState state envelope.target
        let result := step config.protocol node (eventFor envelope)
        pure ({
          nodes :=
            replaceNode envelope.target result.state state.system.nodes
        }, result)) = some (system, output)
    rw [found]
    rfl
  refine
    ⟨recordEffects envelope.target output.state output.effects delivered, ?_⟩
  simp [next, network, targetActive, stepResult, output, system,
    delivered]

theorem timeout_enabled_of_accepted
    {config : Config}
    {state : State}
    {node : Location}
    {nodeState : NodeState}
    (active : node ∈ state.active)
    (found : Global.nodeState state node = some nodeState)
    (accepted : (step config.protocol nodeState .timeout).accepted = true) :
    Enabled config state (.timeout node) := by
  let output := step config.protocol nodeState .timeout
  let system : SystemState := {
    nodes := replaceNode node output.state state.system.nodes
  }
  have stepResult :
      systemStep config.protocol state.system node .timeout =
        some (system, output) := by
    change
      (do
        let current <- Global.nodeState state node
        let result := step config.protocol current .timeout
        pure ({
          nodes := replaceNode node result.state state.system.nodes
        }, result)) = some (system, output)
    rw [found]
    rfl
  refine
    ⟨recordEffects node output.state output.effects
      { state with system }, ?_⟩
  simp [next, active, stepResult, accepted, output, system]

theorem retry_gossip_enqueued
    {config : Config}
    {before after : State}
    {node : Location}
    (valid : config.Valid)
    (wellFormed : WellFormed config before)
    (phase : HasPhase before node .gossiping)
    (transition : next config before (.retry node) = some after) :
    exists envelope,
      envelope ∈ after.network /\
        envelope.source = node /\
          envelope.target = node /\
          exists txid, envelope.payload = .gossip txid := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨active, sourceState, found, _, stateEq⟩
  rcases phase with ⟨phaseState, foundPhase, gossiping⟩
  have configured :=
    wellFormed.activeConfigured node active
  rcases recovered_for_configured valid configured with
    ⟨txid, recovered⟩
  rw [found] at foundPhase
  injection foundPhase with stateEq'
  subst phaseState
  let envelope : Envelope := {
    source := node
    target := node
    payload := .gossip txid
    sourceState
  }
  have message : envelope ∈ retryMessages config node sourceState :=
    retryMessages_self_gossip gossiping configured recovered
  rw [←stateEq]
  exact
    ⟨envelope, List.mem_append_right _ message, rfl, rfl, txid, rfl⟩

theorem retry_vote_enqueued
    {config : Config}
    {before after : State}
    {node target : Location}
    {nodeState : NodeState}
    (found : Global.nodeState before node = some nodeState)
    (phase : nodeState.phase = .voting)
    (chosen : nodeState.chosen = some target)
    (transition : next config before (.retry node) = some after) :
    exists envelope,
      envelope ∈ after.network /\
        envelope.source = node /\
        envelope.target = target /\
        envelope.payload = .vote := by
  have message := retryMessages_vote (config := config)
    (node := node) phase chosen
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, actualState, actualFound, _, stateEq⟩
  rw [found] at actualFound
  injection actualFound with actualEq
  subst actualState
  let envelope : Envelope := {
    source := node
    target
    payload := .vote
    sourceState := nodeState
  }
  rw [←stateEq]
  exact
    ⟨envelope, List.mem_append_right _ message, rfl, rfl, rfl⟩

theorem insertGossip_nonempty
    (source : Location)
    (txid : TxID)
    (gossips : List (Prod Location TxID)) :
    insertGossip source txid gossips ≠ [] := by
  unfold insertGossip
  split
  · rename_i present
    intro empty
    subst gossips
    simp at present
  · intro empty
    have lengths :=
      (List.mergeSort_perm ((source, txid) :: gossips)
        (fun left right => left.1 <= right.1)).length_eq
    rw [empty] at lengths
    simp at lengths

theorem maximumGossip_some
    {gossips : List (Prod Location TxID)}
    (nonempty : gossips ≠ []) :
    exists selected, maximumGossip gossips = some selected := by
  cases gossips with
  | nil => contradiction
  | cons head tail =>
      exact ⟨tail.foldl selectMaximum head, rfl⟩

theorem gossip_receive_progress
    (config : Protocol.Config)
    (state : NodeState)
    (source : Location)
    (txid : TxID)
    (valid : LaneValid state)
    (phase : state.phase = .gossiping) :
    let output :=
      step config state (.receiveGossip source txid .accepted)
    output.state.phase ≠ .gossiping \/
      output.state.gossips ≠ [] := by
  have chosen := valid.2.2.2 phase
  have nonempty := insertGossip_nonempty source txid state.gossips
  obtain ⟨selected, maximum⟩ := maximumGossip_some nonempty
  simp [step, phase, chosen, rejected, advance, advanceTimeoutLane,
    validTimeout]
  repeat first | split | simp_all

theorem gossip_timeout_progress
    (config : Protocol.Config)
    (state : NodeState)
    (valid : LaneValid state)
    (phase : state.phase = .gossiping)
    (accepted : (step config state .timeout).accepted = true) :
    (step config state .timeout).state.phase = .voting := by
  have lane := valid.1 phase
  simp [step, phase, lane, rejected, advance, advanceTimeoutLane,
    validTimeout] at accepted ⊢
  repeat first | split at accepted | split | simp_all

theorem gossip_timeout_enabled_local
    (config : Protocol.Config)
    (state : NodeState)
    (valid : LaneValid state)
    (phase : state.phase = .gossiping)
    (nonempty : state.gossips ≠ []) :
    (step config state .timeout).accepted = true := by
  have lane := valid.1 phase
  obtain ⟨selected, maximum⟩ := maximumGossip_some nonempty
  simp [step, phase, lane, advance, validTimeout, advanceTimeoutLane,
    maximum]

theorem gossip_timeout_enabled
    {config : Config}
    {state : State}
    {node : Location}
    (active : node ∈ state.active)
    (lanes : NodeLanesValid state)
    (phase : HasPhase state node .gossiping)
    (gossip : HasGossip state node) :
    Enabled config state (.timeout node) := by
  rcases phase with ⟨phaseState, foundPhase, gossiping⟩
  rcases gossip with ⟨gossipState, foundGossip, nonempty⟩
  rw [foundPhase] at foundGossip
  injection foundGossip with stateEq
  subst gossipState
  have lane := node_property_of_nodeState lanes foundPhase
  apply timeout_enabled_of_accepted active foundPhase
  exact gossip_timeout_enabled_local config.protocol phaseState lane
    gossiping nonempty

def openingDistance : Phase -> Nat
  | .gossiping => 3
  | .voting => 2
  | .opening => 1
  | .joining | .open => 0

theorem opening_timeout_local
    (config : Protocol.Config)
    (state : NodeState)
    (valid : LaneValid state)
    (phase : state.phase = .opening) :
    let output := step config state .timeout
    (output.effects = [.completed] /\ output.state.phase = .open) \/
      (output.state.phase = .opening /\
        openingDistance output.state.timeoutState <
          openingDistance state.timeoutState) := by
  rcases valid.2.2.1 phase with lane | lane | lane
  · simp [step, phase, lane, advance, validTimeout, advanceTimeoutLane,
      advanceTimeoutState, openingDistance]
  · simp [step, phase, lane, advance, validTimeout, advanceTimeoutLane,
      advanceTimeoutState, openingDistance]
  · simp [step, phase, lane, advance, validTimeout, advanceTimeoutLane,
      advanceTimeoutState, openingDistance]

theorem opening_step_distance_le
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (valid : LaneValid state)
    (phase : state.phase = .opening)
    (after : (step config state event).state.phase = .opening) :
    openingDistance (step config state event).state.timeoutState <=
      openingDistance state.timeoutState := by
  cases event with
  | receiveGossip source txid validation =>
      cases validation <;>
        simp [step, phase, rejected, advance, validTimeout,
          advanceTimeoutLane]
      repeat first | split | simp_all
  | receiveVote source validation =>
      cases validation <;>
        simp [step, phase, rejected, advance, validTimeout,
          advanceTimeoutLane]
  | receiveIAmOpen source validation =>
      cases validation <;> simp [step, phase, rejected]
  | timeout =>
      rcases opening_timeout_local config state valid phase with
        done | progress
      · rw [done.2] at after
        contradiction
      · exact Nat.le_of_lt progress.2
  | retry => simp [step]

theorem opening_step_or_completed
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (phase : state.phase = .opening) :
    (step config state event).state.phase = .opening \/
      ((step config state event).state.phase = .open /\
        .completed ∈ (step config state event).effects) := by
  cases event with
  | receiveGossip source txid validation =>
      cases validation <;>
        simp [step, phase, rejected, advance, validTimeout,
          advanceTimeoutLane]
      repeat first | split | simp_all
  | receiveVote source validation =>
      cases validation <;>
        simp [step, phase, rejected, advance, validTimeout,
          advanceTimeoutLane]
  | receiveIAmOpen source validation =>
      cases validation <;> simp [step, phase, rejected]
  | timeout =>
      simp [step, phase, rejected, advance, validTimeout,
        advanceTimeoutLane]
      split <;> simp_all
  | retry => simp [step, phase]

theorem opening_non_timeout
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (phase : state.phase = .opening)
    (notTimeout : event ≠ .timeout) :
    (step config state event).state.phase = .opening /\
      (step config state event).state.timeoutState =
        state.timeoutState := by
  cases event with
  | receiveGossip source txid validation =>
      cases validation <;>
        simp [step, phase, rejected, advance, validTimeout,
          advanceTimeoutLane]
      repeat first | split | simp_all
  | receiveVote source validation =>
      cases validation <;>
        simp [step, phase, rejected, advance, validTimeout,
          advanceTimeoutLane]
  | receiveIAmOpen source validation =>
      cases validation <;> simp [step, phase, rejected]
  | timeout => contradiction
  | retry => exact ⟨phase, rfl⟩

theorem opening_timeout_enabled
    {config : Config}
    {state : State}
    {node : Location}
    (active : node ∈ state.active)
    (phase : HasPhase state node .opening) :
    Enabled config state (.timeout node) := by
  rcases phase with ⟨nodeState, found, opening⟩
  apply timeout_enabled_of_accepted active found
  simp [step, opening, advance, rejected]
  repeat first | split | simp_all

theorem timeout_opening_step
    {config : Config}
    {before after : State}
    {node : Location}
    {beforeState : NodeState}
    (wellFormed : WellFormed config before)
    (lanes : NodeLanesValid before)
    (foundBefore :
      Global.nodeState before node = some beforeState)
    (opening : beforeState.phase = .opening)
    (transition : next config before (.timeout node) = some after) :
    CompletedOpen after node \/
      (exists nextState : NodeState,
        Global.nodeState after node = some nextState /\
          nextState.phase = .opening /\
          openingDistance nextState.timeoutState <
            openingDistance beforeState.timeoutState) := by
  have lane : LaneValid beforeState := by
    apply node_property_of_nodeState (predicate := LaneValid)
    · exact lanes
    · exact foundBefore
  have timeoutResult :
      ((step config.protocol beforeState .timeout).effects =
          [.completed] /\
        (step config.protocol beforeState .timeout).state.phase = .open) \/
      ((step config.protocol beforeState .timeout).state.phase =
          .opening /\
        openingDistance
            (step config.protocol beforeState .timeout).state.timeoutState <
          openingDistance beforeState.timeoutState) :=
    opening_timeout_local config.protocol beforeState lane opening
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, system, output, systemStep, _, stateEq⟩
  have outputEq := systemStep_output_eq foundBefore systemStep
  rw [←outputEq] at timeoutResult
  rw [←stateEq]
  rcases timeoutResult with completed | progress
  · exact Or.inl (by
      rcases completed with ⟨effects, _⟩
      rw [effects]
      simp [CompletedOpen, recordEffects, recordEffect])
  · exact Or.inr
      ⟨output.state,
        (by
          apply nodeState_eq_of_mem
          · rw [recordEffects_system,
              systemStep_node_keys_eq systemStep]
            exact wellFormed.nodeKeysNodup
          · rw [recordEffects_system]
            exact systemStep_output_mem systemStep),
        progress.1,
        by simpa using progress.2⟩

theorem next_opening_progress
    {config : Config}
    {before after : State}
    {node : Location}
    {beforeState : NodeState}
    (wellFormed : WellFormed config before)
    (lanes : NodeLanesValid before)
    (foundBefore :
      Global.nodeState before node = some beforeState)
    (opening : beforeState.phase = .opening)
    (transition : next config before action = some after) :
    CompletedOpen after node \/
      (exists afterState : NodeState,
        Global.nodeState after node = some afterState /\
          afterState.phase = .opening /\
          openingDistance afterState.timeoutState <=
            openingDistance beforeState.timeoutState) := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, sourceState, _, _, stateEq⟩
      rw [←stateEq]
      exact Or.inr
        ⟨beforeState, foundBefore, opening, Nat.le_refl _⟩
  | deliver envelope =>
      by_cases target : node = envelope.target
      · subst node
        rcases deliver_target_state wellFormed transition with
          ⟨output, foundAfter, systemStep⟩
        have outputEq :=
          systemStep_output_eq foundBefore systemStep
        have preserved :=
          opening_non_timeout config.protocol beforeState
            (eventFor envelope) opening
              (by
                cases payloadEq : envelope.payload <;>
                  simp [eventFor, payloadEq])
        rw [←outputEq] at preserved
        exact Or.inr
          ⟨output.state, foundAfter, preserved.1,
            by rw [preserved.2]⟩
      · have unchanged := deliver_other_node_eq target transition
        rw [foundBefore] at unchanged
        exact Or.inr
          ⟨beforeState, by simp [unchanged], opening, Nat.le_refl _⟩
  | timeout target =>
      by_cases same : node = target
      · subst node
        rcases timeout_opening_step wellFormed lanes foundBefore
            opening transition with
          completed | ⟨nextState, foundAfter, nextOpening, distance⟩
        · exact Or.inl completed
        · exact Or.inr
            ⟨nextState, foundAfter, nextOpening,
              Nat.le_of_lt distance⟩
      · have unchanged := timeout_other_node_eq same transition
        rw [foundBefore] at unchanged
        exact Or.inr
          ⟨beforeState, by simp [unchanged], opening, Nat.le_refl _⟩

theorem insertVote_nonempty
    (source : Location)
    (votes : List Location) :
    insertVote source votes ≠ [] := by
  unfold insertVote
  split
  · rename_i present
    intro empty
    subst votes
    simp at present
  · intro empty
    have lengths :=
      (List.mergeSort_perm (source :: votes)
        (fun left right => left <= right)).length_eq
    rw [empty] at lengths
    simp at lengths

theorem step_preserves_nonempty_votes
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event)
    (nonempty : state.votes ≠ []) :
    (step config state event).state.votes ≠ [] := by
  rcases step_votes_shape config state event with
    unchanged | ⟨source, _, changed⟩
  · rw [unchanged]
    exact nonempty
  · rw [changed]
    exact insertVote_nonempty source state.votes

theorem next_preserves_hasVote
    {config : Config}
    {before after : State}
    {action : Action}
    {node : Location}
    (wellFormed : WellFormed config before)
    (vote : HasVote before node)
    (transition : next config before action = some after) :
    HasVote after node := by
  rcases vote with ⟨beforeState, foundBefore, nonempty⟩
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, stateEq⟩
      rw [←stateEq]
      exact ⟨beforeState, foundBefore, nonempty⟩
  | deliver envelope =>
      by_cases target : node = envelope.target
      · subst node
        rcases deliver_target_state wellFormed transition with
          ⟨output, foundAfter, systemStep⟩
        have outputEq :=
          systemStep_output_eq foundBefore systemStep
        exact
          ⟨output.state, foundAfter,
            by
              rw [outputEq]
              exact step_preserves_nonempty_votes
                config.protocol beforeState (eventFor envelope) nonempty⟩
      · have unchanged := deliver_other_node_eq target transition
        rw [foundBefore] at unchanged
        exact ⟨beforeState, by simp [unchanged], nonempty⟩
  | timeout target =>
      by_cases same : node = target
      · subst node
        rcases timeout_target_state wellFormed transition with
          ⟨output, foundAfter, _, systemStep⟩
        have outputEq :=
          systemStep_output_eq foundBefore systemStep
        exact
          ⟨output.state, foundAfter,
            by
              rw [outputEq]
              exact step_preserves_nonempty_votes
                config.protocol beforeState .timeout nonempty⟩
      · have unchanged := timeout_other_node_eq same transition
        rw [foundBefore] at unchanged
        exact ⟨beforeState, by simp [unchanged], nonempty⟩

theorem hasVote_mono
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    {start finish : Nat}
    {node : Location}
    (order : start <= finish)
    (vote : HasVote (execution.states start) node) :
    HasVote (execution.states finish) node := by
  induction finish, order using Nat.le_induction with
  | base => exact vote
  | succ finish order vote =>
      exact next_preserves_hasVote
        (reachable_well_formed
          (execution_reachable execution initial finish))
        vote (execution.step_succ finish)

theorem next_preserves_advanced_lane
    {config : Config}
    {before after : State}
    {action : Action}
    {node : Location}
    (wellFormed : WellFormed config before)
    (advanced : LaneAdvanced before node)
    (transition : next config before action = some after) :
    LaneAdvanced after node := by
  rcases advanced with ⟨beforeState, foundBefore, lane⟩
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, stateEq⟩
      rw [←stateEq]
      exact ⟨beforeState, foundBefore, lane⟩
  | deliver envelope =>
      by_cases target : node = envelope.target
      · subst node
        rcases deliver_target_state wellFormed transition with
          ⟨output, foundAfter, systemStep⟩
        have outputEq :=
          systemStep_output_eq foundBefore systemStep
        exact
          ⟨output.state, foundAfter,
            by
              rw [outputEq]
              exact step_preserves_advanced_lane
                config.protocol beforeState (eventFor envelope) lane⟩
      · have unchanged := deliver_other_node_eq target transition
        rw [foundBefore] at unchanged
        exact ⟨beforeState, by simp [unchanged], lane⟩
  | timeout target =>
      by_cases same : node = target
      · subst node
        rcases timeout_target_state wellFormed transition with
          ⟨output, foundAfter, _, systemStep⟩
        have outputEq :=
          systemStep_output_eq foundBefore systemStep
        exact
          ⟨output.state, foundAfter,
            by
              rw [outputEq]
              exact step_preserves_advanced_lane
                config.protocol beforeState .timeout lane⟩
      · have unchanged := timeout_other_node_eq same transition
        rw [foundBefore] at unchanged
        exact ⟨beforeState, by simp [unchanged], lane⟩

theorem advanced_lane_mono
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    {start finish : Nat}
    {node : Location}
    (order : start <= finish)
    (advanced : LaneAdvanced (execution.states start) node) :
    LaneAdvanced (execution.states finish) node := by
  induction finish, order using Nat.le_induction with
  | base => exact advanced
  | succ finish order advanced =>
      exact next_preserves_advanced_lane
        (reachable_well_formed
          (execution_reachable execution initial finish))
        advanced (execution.step_succ finish)

theorem opening_progress_between
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    {start finish : Nat}
    {node : Location}
    {startState : NodeState}
    (order : start <= finish)
    (foundStart :
      Global.nodeState (execution.states start) node = some startState)
    (openingStart : startState.phase = .opening)
    (notCompleted :
      Not (CompletedOpen (execution.states finish) node)) :
    exists finishState : NodeState,
      Global.nodeState (execution.states finish) node = some finishState /\
        finishState.phase = .opening /\
        openingDistance finishState.timeoutState <=
          openingDistance startState.timeoutState := by
  induction finish, order using Nat.le_induction with
  | base =>
      exact
        ⟨startState, foundStart, openingStart, Nat.le_refl _⟩
  | succ finish order ih =>
      have notCompletedBefore :
          Not (CompletedOpen (execution.states finish) node) := by
        intro completed
        exact notCompleted
          (next_completed_monotonic
            (execution.step_succ finish) node completed)
      rcases ih notCompletedBefore with
        ⟨beforeState, foundBefore, openingBefore, distanceBefore⟩
      rcases next_opening_progress
          (reachable_well_formed
            (execution_reachable execution initial finish))
          (reachable_lanes_valid
            (execution_reachable execution initial finish))
          foundBefore openingBefore (execution.step_succ finish) with
        completed |
          ⟨afterState, foundAfter, openingAfter, distanceAfter⟩
      · contradiction
      · exact
          ⟨afterState, foundAfter, openingAfter,
            Nat.le_trans distanceAfter distanceBefore⟩

theorem deliver_gossip_progress
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config before)
    (lanes : NodeLanesValid before)
    (payload : exists txid, envelope.payload = .gossip txid)
    (phase : HasPhase before envelope.target .gossiping)
    (transition : next config before (.deliver envelope) = some after) :
    Not (HasPhase after envelope.target .gossiping) \/
      HasGossip after envelope.target := by
  rcases phase with ⟨beforeState, foundBefore, gossiping⟩
  rcases payload with ⟨txid, payload⟩
  rcases deliver_target_state wellFormed transition with
    ⟨output, foundAfter, systemStep⟩
  have outputEq :=
    systemStep_output_eq foundBefore systemStep
  have lane :=
    node_property_of_nodeState lanes foundBefore
  simp [eventFor, payload] at outputEq
  have progress :=
    gossip_receive_progress config.protocol beforeState
      envelope.source txid lane gossiping
  rw [←outputEq] at progress
  rcases progress with left | right
  · exact Or.inl (by
      intro stillGossiping
      rcases stillGossiping with ⟨state, found, phase⟩
      rw [foundAfter] at found
      injection found with stateEq
      subst state
      exact left phase)
  · exact Or.inr ⟨output.state, foundAfter, right⟩

theorem timeout_gossip_progress
    {config : Config}
    {before after : State}
    {node : Location}
    (wellFormed : WellFormed config before)
    (lanes : NodeLanesValid before)
    (phase : HasPhase before node .gossiping)
    (transition : next config before (.timeout node) = some after) :
    HasPhase after node .voting := by
  rcases phase with ⟨beforeState, foundBefore, gossiping⟩
  rcases timeout_target_state wellFormed transition with
    ⟨output, foundAfter, accepted, systemStep⟩
  have outputEq :=
    systemStep_output_eq foundBefore systemStep
  have lane :=
    node_property_of_nodeState lanes foundBefore
  have voting :=
    gossip_timeout_progress config.protocol beforeState lane
      gossiping (by simpa [outputEq] using accepted)
  exact
    ⟨output.state, foundAfter, by simpa [outputEq] using voting⟩

theorem vote_receive_progress
    (config : Protocol.Config)
    (state : NodeState)
    (source : Location)
    (phase : state.phase = .voting) :
    let output := step config state (.receiveVote source .accepted)
    output.state.phase ≠ .voting \/ output.state.votes ≠ [] := by
  have nonempty := insertVote_nonempty source state.votes
  simp [step, phase, rejected, advance, validTimeout,
    advanceTimeoutLane]
  repeat first | split | simp_all

theorem voting_timeout_local
    (config : Protocol.Config)
    (state : NodeState)
    (valid : LaneValid state)
    (phase : state.phase = .voting)
    (nonempty : state.votes ≠ []) :
    let output := step config state .timeout
    output.state.phase = .opening \/
      (output.state.phase = .voting /\
        output.state.timeoutState = .voting) := by
  rcases valid.2.1 phase with lane | lane
  · simp [step, phase, lane, rejected, advance, validTimeout,
      advanceTimeoutLane, advanceTimeoutState]
    repeat first | split | simp_all
  · simp [step, phase, lane, nonempty, rejected, advance, validTimeout,
      advanceTimeoutLane, advanceTimeoutState]

theorem aligned_voting_timeout_opens
    (config : Protocol.Config)
    (state : NodeState)
    (phase : state.phase = .voting)
    (lane : state.timeoutState = .voting)
    (nonempty : state.votes ≠ []) :
    (step config state .timeout).state.phase = .opening := by
  simp [step, phase, lane, nonempty, rejected, advance, validTimeout,
    advanceTimeoutLane]

theorem deliver_vote_progress
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config before)
    (payload : envelope.payload = .vote)
    (phase : HasPhase before envelope.target .voting)
    (transition : next config before (.deliver envelope) = some after) :
    Not (HasPhase after envelope.target .voting) \/
      HasVote after envelope.target := by
  rcases phase with ⟨beforeState, foundBefore, voting⟩
  rcases deliver_target_state wellFormed transition with
    ⟨output, foundAfter, systemStep⟩
  have outputEq :=
    systemStep_output_eq foundBefore systemStep
  simp [eventFor, payload] at outputEq
  have progress :=
    vote_receive_progress config.protocol beforeState
      envelope.source voting
  rw [←outputEq] at progress
  rcases progress with left | right
  · exact Or.inl (by
      intro stillVoting
      rcases stillVoting with ⟨state, found, phase⟩
      rw [foundAfter] at found
      injection found with stateEq
      subst state
      exact left phase)
  · exact Or.inr ⟨output.state, foundAfter, right⟩

theorem deliver_iamopen_resolves
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config before)
    (openCompleted : OpenCompleted before)
    (payload : envelope.payload = .iAmOpen)
    (transition : next config before (.deliver envelope) = some after) :
    Terminal after envelope.target \/
      HasPhase after envelope.target .opening := by
  have details := transition
  simp [next, Option.bind_eq_some_iff] at details
  rcases details with
    ⟨_, targetActive, system, output, systemStep, stateEq⟩
  rcases active_nodeState wellFormed targetActive with
    ⟨beforeState, foundBefore⟩
  have outputEq := systemStep_output_eq foundBefore systemStep
  simp [eventFor, payload] at outputEq
  have outcome :=
    iamopen_delivery_outcome config.protocol beforeState envelope.source
  rw [←outputEq] at outcome
  rw [←stateEq]
  rcases outcome with opening | opened | ⟨chosen, restarted⟩
  · exact Or.inr
      ⟨output.state,
        by
          apply nodeState_eq_of_mem
          · rw [recordEffects_system,
              systemStep_node_keys_eq systemStep]
            exact wellFormed.nodeKeysNodup
          · rw [recordEffects_system]
            exact systemStep_output_mem systemStep,
        opening⟩
  · have beforeOpen :=
      iamopen_open_predecessor config.protocol beforeState
        envelope.source (by simpa [outputEq] using opened)
    have completedBefore : CompletedOpen before envelope.target := by
      rw [Global.nodeState, Option.map_eq_some_iff] at foundBefore
      rcases foundBefore with ⟨entry, findEq, stateEq⟩
      have keyEq : entry.1 = envelope.target :=
        beq_iff_eq.mp
          (List.find?_some
            (p := fun entry : Prod Location NodeState =>
              entry.1 == envelope.target) findEq)
      rw [←keyEq]
      apply openCompleted entry (List.mem_of_find?_eq_some findEq)
      simpa [stateEq] using beforeOpen
    exact Or.inl (Or.inr
      (mem_completed_recordEffects completedBefore))
  · exact Or.inl (Or.inl
      (restart_effect_recorded restarted))

theorem voting_timeout_enabled
    {config : Config}
    {state : State}
    {node : Location}
    (active : node ∈ state.active)
    (phase : HasPhase state node .voting) :
    Enabled config state (.timeout node) := by
  rcases phase with ⟨nodeState, found, voting⟩
  apply timeout_enabled_of_accepted active found
  simp [step, voting, advance, rejected]
  repeat first | split | simp_all

theorem timeout_voting_step
    {config : Config}
    {before after : State}
    {node : Location}
    (wellFormed : WellFormed config before)
    (lanes : NodeLanesValid before)
    (phase : HasPhase before node .voting)
    (vote : HasVote before node)
    (transition : next config before (.timeout node) = some after) :
    HasPhase after node .opening \/
      (exists nextState : NodeState,
        Global.nodeState after node = some nextState /\
          nextState.phase = .voting /\
          nextState.timeoutState = .voting /\
          nextState.votes ≠ []) := by
  rcases phase with ⟨beforeState, foundBefore, voting⟩
  rcases vote with ⟨voteState, foundVote, nonempty⟩
  rw [foundBefore] at foundVote
  injection foundVote with stateEq
  subst voteState
  have lane : LaneValid beforeState := by
    apply node_property_of_nodeState (predicate := LaneValid)
    · exact lanes
    · exact foundBefore
  rcases timeout_target_state wellFormed transition with
    ⟨output, foundAfter, _, systemStep⟩
  have outputEq := systemStep_output_eq foundBefore systemStep
  have progress :=
    voting_timeout_local config.protocol beforeState lane voting nonempty
  rw [←outputEq] at progress
  rcases progress with opening | waiting
  · exact Or.inl ⟨output.state, foundAfter, opening⟩
  · exact Or.inr
      ⟨output.state, foundAfter, waiting.1, waiting.2,
        by
          rw [outputEq]
          exact step_preserves_nonempty_votes
            config.protocol beforeState .timeout nonempty⟩

theorem aligned_timeout_voting_opens
    {config : Config}
    {before after : State}
    {node : Location}
    {nodeState : NodeState}
    (wellFormed : WellFormed config before)
    (found : Global.nodeState before node = some nodeState)
    (phase : nodeState.phase = .voting)
    (lane : nodeState.timeoutState = .voting)
    (nonempty : nodeState.votes ≠ [])
    (transition : next config before (.timeout node) = some after) :
    HasPhase after node .opening := by
  rcases timeout_target_state wellFormed transition with
    ⟨output, foundAfter, _, systemStep⟩
  have outputEq := systemStep_output_eq found systemStep
  exact
    ⟨output.state, foundAfter,
      by
        rw [outputEq]
        exact aligned_voting_timeout_opens config.protocol nodeState
          phase lane nonempty⟩

theorem fair_gossip_progress
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    {start : Nat}
    {node : Location}
    (active : node ∈ (execution.states start).active)
    (phase : HasPhase (execution.states start) node .gossiping) :
    EventuallyFrom start (fun n =>
      Not (HasPhase (execution.states n) node .gossiping)) := by
  have reachable (n : Nat) :=
    execution_reachable execution initial n
  have configValid := reachable_config_valid (reachable start)
  have retryEnabled :=
    retry_gossip_enabled configValid
      (reachable_well_formed (reachable start)) active phase
  rcases fair.retry start node .gossiping active phase
      (Or.inl rfl) retryEnabled with
    ⟨retryAt, startRetry, leftGossip | retryAction⟩
  · exact ⟨retryAt, startRetry, leftGossip⟩
  · by_cases retryPhase :
      HasPhase (execution.states retryAt) node .gossiping
    · have retryStep :
          next config (execution.states retryAt) (.retry node) =
            some (execution.states (retryAt + 1)) := by
        simpa [retryAction] using execution.step_succ retryAt
      rcases retry_gossip_enqueued configValid
          (reachable_well_formed (reachable retryAt))
          retryPhase retryStep with
        ⟨envelope, pending, sourceEq, targetEq, txid, payload⟩
      rcases fair.delivery (retryAt + 1) envelope pending with
        ⟨deliverAt, retryDeliver, deliverAction⟩
      by_cases deliverPhase :
          HasPhase (execution.states deliverAt) node .gossiping
      · have deliverStep :
            next config (execution.states deliverAt)
                (.deliver envelope) =
              some (execution.states (deliverAt + 1)) := by
          simpa [deliverAction] using execution.step_succ deliverAt
        have delivered :=
          deliver_gossip_progress
            (reachable_well_formed (reachable deliverAt))
            (reachable_lanes_valid (reachable deliverAt))
            ⟨txid, payload⟩
            (by simpa [targetEq] using deliverPhase)
            deliverStep
        rcases delivered with leftAfter | hasGossip
        · exact
            ⟨deliverAt + 1, by omega, by simpa [targetEq] using leftAfter⟩
        · by_cases afterPhase :
            HasPhase (execution.states (deliverAt + 1)) node .gossiping
          · have timeoutEnabled :=
              gossip_timeout_enabled
                (config := config)
                (by
                  rw [execution_active_eq execution (deliverAt + 1)]
                  rw [execution_active_eq execution start] at active
                  exact active)
                (reachable_lanes_valid (reachable (deliverAt + 1)))
                afterPhase
                (by simpa [targetEq] using hasGossip)
            rcases fair.timeout (deliverAt + 1) node .gossiping
                (by
                  rw [execution_active_eq execution (deliverAt + 1)]
                  rw [execution_active_eq execution start] at active
                  exact active)
                afterPhase (Or.inl rfl) timeoutEnabled with
              ⟨timeoutAt, deliverTimeout, leftBeforeTimeout | timeoutAction⟩
            · exact ⟨timeoutAt, by omega, leftBeforeTimeout⟩
            · by_cases timeoutPhase :
                HasPhase (execution.states timeoutAt) node .gossiping
              · have timeoutStep :
                    next config (execution.states timeoutAt)
                        (.timeout node) =
                      some (execution.states (timeoutAt + 1)) := by
                  simpa [timeoutAction] using
                    execution.step_succ timeoutAt
                have voting :=
                  timeout_gossip_progress
                    (reachable_well_formed (reachable timeoutAt))
                    (reachable_lanes_valid (reachable timeoutAt))
                    timeoutPhase timeoutStep
                refine ⟨timeoutAt + 1, by omega, ?_⟩
                intro impossible
                have phases := hasPhase_unique voting impossible
                contradiction
              · exact ⟨timeoutAt, by omega, timeoutPhase⟩
          · exact ⟨deliverAt + 1, by omega, afterPhase⟩
      · exact ⟨deliverAt, by omega, deliverPhase⟩
    · exact ⟨retryAt, startRetry, retryPhase⟩

theorem next_gossiping_predecessor
    {config : Config}
    {before after : State}
    {action : Action}
    {node : Location}
    (wellFormed : WellFormed config before)
    (transition : next config before action = some after)
    (afterGossip : HasPhase after node .gossiping) :
    HasPhase before node .gossiping := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, stateEq⟩
      rw [←stateEq] at afterGossip
      exact afterGossip
  | deliver envelope =>
      by_cases target : node = envelope.target
      · subst node
        have details := transition
        simp [next, Option.bind_eq_some_iff] at details
        have targetActive := details.2.1
        rcases active_nodeState wellFormed targetActive with
          ⟨beforeState, foundBefore⟩
        rcases deliver_target_state wellFormed transition with
          ⟨output, foundAfter, systemStep⟩
        rcases afterGossip with ⟨afterState, found, phase⟩
        rw [foundAfter] at found
        injection found with stateEq
        subst afterState
        have outputEq :=
          systemStep_output_eq foundBefore systemStep
        have beforePhase : beforeState.phase = .gossiping := by
          by_contra notGossip
          have notAfter :=
            step_preserves_non_gossiping config.protocol beforeState
              (eventFor envelope) notGossip
          rw [←outputEq] at notAfter
          exact notAfter phase
        exact ⟨beforeState, foundBefore, beforePhase⟩
      · rcases afterGossip with ⟨afterState, foundAfter, phase⟩
        have unchanged :=
          deliver_other_node_eq target transition
        rw [foundAfter] at unchanged
        cases foundBefore :
            Global.nodeState before node with
        | none => simp [foundBefore] at unchanged
        | some beforeState =>
            rw [foundBefore] at unchanged
            injection unchanged with stateEq
            subst beforeState
            exact ⟨afterState, foundBefore, phase⟩
  | timeout target =>
      by_cases same : node = target
      · subst node
        have details := transition
        simp [next, Option.bind_eq_some_iff] at details
        have targetActive := details.1
        rcases active_nodeState wellFormed targetActive with
          ⟨beforeState, foundBefore⟩
        rcases timeout_target_state wellFormed transition with
          ⟨output, foundAfter, _, systemStep⟩
        rcases afterGossip with ⟨afterState, found, phase⟩
        rw [foundAfter] at found
        injection found with stateEq
        subst afterState
        have outputEq :=
          systemStep_output_eq foundBefore systemStep
        have beforePhase : beforeState.phase = .gossiping := by
          by_contra notGossip
          have notAfter :=
            step_preserves_non_gossiping config.protocol beforeState
              .timeout notGossip
          rw [←outputEq] at notAfter
          exact notAfter phase
        exact ⟨beforeState, foundBefore, beforePhase⟩
      · rcases afterGossip with ⟨afterState, foundAfter, phase⟩
        have unchanged :=
          timeout_other_node_eq same transition
        rw [foundAfter] at unchanged
        cases foundBefore :
            Global.nodeState before node with
        | none => simp [foundBefore] at unchanged
        | some beforeState =>
            rw [foundBefore] at unchanged
            injection unchanged with stateEq
            subst beforeState
            exact ⟨afterState, foundBefore, phase⟩

theorem not_gossiping_mono
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    {start finish : Nat}
    {node : Location}
    (order : start <= finish)
    (notGossip :
      Not (HasPhase (execution.states start) node .gossiping)) :
    Not (HasPhase (execution.states finish) node .gossiping) := by
  induction finish, order using Nat.le_induction with
  | base => exact notGossip
  | succ finish order notGossip =>
      intro gossip
      exact notGossip
        (next_gossiping_predecessor
          (reachable_well_formed
            (execution_reachable execution initial finish))
          (execution.step_succ finish) gossip)

theorem eventually_list
    {predicate : Nat -> Location -> Prop}
    {start : Nat}
    (nodes : List Location)
    (eventual :
      forall node, node ∈ nodes ->
        EventuallyFrom start (fun n => predicate n node))
    (monotonic :
      forall node first second,
        first <= second ->
        predicate first node ->
        predicate second node) :
    EventuallyFrom start (fun n =>
      forall node, node ∈ nodes -> predicate n node) := by
  revert eventual
  induction nodes with
  | nil =>
      intro eventual
      exact ⟨start, Nat.le_refl start, by simp⟩
  | cons head tail ih =>
      intro eventual
      rcases eventual head (by simp) with
        ⟨headAt, startHead, headHolds⟩
      rcases ih
          (fun node membership => eventual node (by simp [membership])) with
        ⟨tailAt, startTail, tailHolds⟩
      refine
        ⟨max headAt tailAt, by omega, ?_⟩
      intro node membership
      rw [List.mem_cons] at membership
      rcases membership with rfl | inTail
      · exact monotonic _ headAt (max headAt tailAt)
          (Nat.le_max_left _ _) headHolds
      · exact monotonic node tailAt (max headAt tailAt)
          (Nat.le_max_right _ _) (tailHolds node inTail)

theorem fair_all_leave_gossip
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    (start : Nat) :
    EventuallyFrom start (fun n =>
      forall node, node ∈ (execution.states start).active ->
        Not (HasPhase (execution.states n) node .gossiping)) := by
  apply eventually_list (execution.states start).active
  · intro node active
    by_cases phase :
        HasPhase (execution.states start) node .gossiping
    · exact fair_gossip_progress execution initial fair active phase
    · exact ⟨start, Nat.le_refl start, phase⟩
  · intro node first second order notGossip
    exact not_gossiping_mono execution initial order notGossip

theorem terminal_mono_step
    {config : Config}
    {before after : State}
    {action : Action}
    {node : Location}
    (transition : next config before action = some after)
    (terminal : Terminal before node) :
    Terminal after node := by
  rcases terminal with restarted | completed
  · exact Or.inl (next_restarts_monotonic transition node restarted)
  · exact Or.inr (next_completed_monotonic transition node completed)

theorem terminal_mono
    {config : Config}
    (execution : Execution config)
    {start finish : Nat}
    {node : Location}
    (order : start <= finish)
    (terminal : Terminal (execution.states start) node) :
    Terminal (execution.states finish) node := by
  induction finish, order using Nat.le_induction with
  | base => exact terminal
  | succ finish order terminal =>
      exact terminal_mono_step (execution.step_succ finish) terminal

theorem completed_mono
    {config : Config}
    (execution : Execution config)
    {start finish : Nat}
    {node : Location}
    (order : start <= finish)
    (completed : CompletedOpen (execution.states start) node) :
    CompletedOpen (execution.states finish) node := by
  induction finish, order using Nat.le_induction with
  | base => exact completed
  | succ finish order completed =>
      exact next_completed_monotonic
        (execution.step_succ finish) node completed

theorem quorumOpened_mono
    {config : Config}
    (execution : Execution config)
    {start finish : Nat}
    {node : Location}
    (order : start <= finish)
    (opened : QuorumOpened (execution.states start) node) :
    QuorumOpened (execution.states finish) node := by
  induction finish, order using Nat.le_induction with
  | base => exact opened
  | succ finish order opened =>
      rcases opened with
        ⟨opening, membership, openingNode, kind⟩
      exact
        ⟨opening,
          next_openings_monotonic
            (execution.step_succ finish) opening membership,
          openingNode,
          kind⟩

theorem fair_opening_completes
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    {start : Nat}
    {node : Location}
    (active : node ∈ (execution.states start).active)
    (phase : HasPhase (execution.states start) node .opening) :
    EventuallyFrom start (fun n =>
      CompletedOpen (execution.states n) node) := by
  rcases phase with ⟨startState, foundStart, openingStart⟩
  have auxiliary :
      forall distance start state,
        openingDistance state.timeoutState = distance ->
        node ∈ (execution.states start).active ->
        Global.nodeState (execution.states start) node = some state ->
        state.phase = .opening ->
        EventuallyFrom start (fun n =>
          CompletedOpen (execution.states n) node) := by
    intro distance
    induction distance using Nat.strong_induction_on with
    | h distance ih =>
        intro start state distanceEq active found opening
        have enabled :=
          opening_timeout_enabled (config := config)
            active ⟨state, found, opening⟩
        rcases fair.openingTimeout start node active
            ⟨state, found, opening⟩ enabled with
          ⟨timeoutAt, startTimeout,
            completed | ⟨stillOpening, timeoutAction⟩⟩
        · exact ⟨timeoutAt, startTimeout, completed⟩
        · by_cases completedBefore :
            CompletedOpen (execution.states timeoutAt) node
          · exact ⟨timeoutAt, startTimeout, completedBefore⟩
          · rcases opening_progress_between execution initial startTimeout
                found opening completedBefore with
              ⟨timeoutState, foundTimeout, openingTimeout,
                distanceTimeout⟩
            have timeoutStep :
                next config (execution.states timeoutAt)
                    (.timeout node) =
                  some (execution.states (timeoutAt + 1)) := by
              simpa [timeoutAction] using execution.step_succ timeoutAt
            rcases timeout_opening_step
                (reachable_well_formed
                  (execution_reachable execution initial timeoutAt))
                (reachable_lanes_valid
                  (execution_reachable execution initial timeoutAt))
                foundTimeout openingTimeout timeoutStep with
              completedAfter |
                ⟨nextState, foundNext, openingNext, distanceNext⟩
            · exact ⟨timeoutAt + 1, by omega, completedAfter⟩
            · have nextLess : openingDistance nextState.timeoutState <
                  distance := by
                rw [←distanceEq]
                exact Nat.lt_of_lt_of_le distanceNext distanceTimeout
              rcases ih (openingDistance nextState.timeoutState)
                  nextLess (timeoutAt + 1) nextState rfl
                  (by
                    rw [execution_active_eq execution (timeoutAt + 1)]
                    rw [execution_active_eq execution start] at active
                    exact active)
                  foundNext openingNext with
                ⟨completedAt, nextCompleted, completed⟩
              exact ⟨completedAt, by omega, completed⟩
  exact auxiliary (openingDistance startState.timeoutState)
    start startState rfl active foundStart openingStart

theorem initial_announcements_live
    (config : Config)
    (active : List Location) :
    AnnouncementsLive (initial config active) := by
  simp [AnnouncementsLive, Global.initial]

theorem next_preserves_announcements_live
    {config : Config}
    {before after : State}
    {action : Action}
    (wellFormed : WellFormed config before)
    (lanes : NodeLanesValid before)
    (live : AnnouncementsLive before)
    (transition : next config before action = some after) :
    AnnouncementsLive after := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, sourceState, found, _, stateEq⟩
      have sourceLocation :=
        nodeState_location wellFormed.nodeLocations found
      rw [←stateEq]
      intro envelope membership payload
      rw [List.mem_append] at membership
      rcases membership with old | added
      · exact live envelope old payload
      · have valid : envelope.Valid config :=
          retryMessages_valid config source sourceState sourceLocation
            envelope added
        have opening := retry_iamopen_state valid payload
        have identity := retryMessages_source added
        rw [identity.2] at opening
        exact Or.inl
          ⟨sourceState,
            by simpa [identity.1] using found,
            opening⟩
  | deliver delivered =>
      intro envelope membership payload
      have details := transition
      simp [next, Option.bind_eq_some_iff] at details
      rcases details with
        ⟨_, _, system, output, systemStep, stateEq⟩
      rw [←stateEq, recordEffects_sent] at membership
      rcases live envelope membership payload with
        opening | completed
      · rcases opening with ⟨sourceState, found, phase⟩
        rcases next_opening_progress wellFormed lanes found phase
            transition with
          completed | ⟨afterState, foundAfter, phaseAfter, _⟩
        · exact Or.inr completed
        · exact Or.inl ⟨afterState, foundAfter, phaseAfter⟩
      · exact Or.inr
          (next_completed_monotonic transition envelope.source completed)
  | timeout target =>
      intro envelope membership payload
      have details := transition
      simp [next, Option.bind_eq_some_iff] at details
      rcases details with
        ⟨_, system, output, systemStep, _, stateEq⟩
      rw [←stateEq, recordEffects_sent] at membership
      rcases live envelope membership payload with
        opening | completed
      · rcases opening with ⟨sourceState, found, phase⟩
        rcases next_opening_progress wellFormed lanes found phase
            transition with
          completed | ⟨afterState, foundAfter, phaseAfter, _⟩
        · exact Or.inr completed
        · exact Or.inl ⟨afterState, foundAfter, phaseAfter⟩
      · exact Or.inr
          (next_completed_monotonic transition envelope.source completed)

theorem reachable_announcements_live
    {config : Config}
    {state : State}
    (reachable : Reachable config state) :
    AnnouncementsLive state := by
  induction reachable with
  | initial active valid nodup configured =>
      exact initial_announcements_live config active
  | step reachable transition live =>
      exact next_preserves_announcements_live
        (reachable_well_formed reachable)
        (reachable_lanes_valid reachable)
        live transition

theorem initial_announcements_resolved
    (config : Config)
    (active : List Location) :
    AnnouncementsResolved (initial config active) := by
  simp [AnnouncementsResolved, Global.initial]

theorem next_preserves_announcements_resolved
    {config : Config}
    {before after : State}
    {action : Action}
    (wellFormed : WellFormed config before)
    (lanes : NodeLanesValid before)
    (openCompleted : OpenCompleted before)
    (resolved : AnnouncementsResolved before)
    (transition : next config before action = some after) :
    AnnouncementsResolved after := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, sourceState, _, _, stateEq⟩
      rw [←stateEq]
      intro envelope membership payload
      rw [List.mem_append] at membership
      rcases membership with old | added
      · rcases resolved envelope old payload with
          pending | terminal | opening
        · exact Or.inl (List.mem_append_left _ pending)
        · exact Or.inr (Or.inl terminal)
        · exact Or.inr (Or.inr opening)
      · exact Or.inl (List.mem_append_right _ added)
  | deliver delivered =>
      intro envelope membership payload
      have details := transition
      simp [next, Option.bind_eq_some_iff] at details
      rcases details with
        ⟨_, _, system, output, systemStep, stateEq⟩
      rw [←stateEq, recordEffects_sent] at membership
      rcases resolved envelope membership payload with
        pending | terminal | opening
      · rcases mem_removeOne_or_eq pending with remains | equal
        · exact Or.inl (by
            rw [←stateEq, recordEffects_network]
            exact remains)
        · subst envelope
          rcases deliver_iamopen_resolves wellFormed openCompleted payload
              transition with
            terminal | opening
          · exact Or.inr (Or.inl terminal)
          · exact Or.inr (Or.inr opening)
      · exact Or.inr (Or.inl
          (terminal_mono_step transition terminal))
      · rcases opening with ⟨sourceState, found, phase⟩
        rcases next_opening_progress wellFormed lanes found phase
            transition with
          completed | ⟨afterState, foundAfter, phaseAfter, _⟩
        · exact Or.inr (Or.inl (Or.inr completed))
        · exact Or.inr (Or.inr
            ⟨afterState, foundAfter, phaseAfter⟩)
  | timeout target =>
      intro envelope membership payload
      have details := transition
      simp [next, Option.bind_eq_some_iff] at details
      rcases details with
        ⟨_, system, output, systemStep, _, stateEq⟩
      rw [←stateEq, recordEffects_sent] at membership
      rcases resolved envelope membership payload with
        pending | terminal | opening
      · exact Or.inl (by
          rw [←stateEq, recordEffects_network]
          exact pending)
      · exact Or.inr (Or.inl
          (terminal_mono_step transition terminal))
      · rcases opening with ⟨sourceState, found, phase⟩
        rcases next_opening_progress wellFormed lanes found phase
            transition with
          completed | ⟨afterState, foundAfter, phaseAfter, _⟩
        · exact Or.inr (Or.inl (Or.inr completed))
        · exact Or.inr (Or.inr
            ⟨afterState, foundAfter, phaseAfter⟩)

theorem systemStep_preserves_joining_announcements
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    {beforeState afterState : State}
    (beforeSystem : beforeState.system = before)
    (valid : JoiningAnnouncements beforeState)
    (carry :
      forall destination,
        SentAnnouncementTo beforeState destination ->
          SentAnnouncementTo afterState destination)
    (introduced :
      (exists source, acceptedIAmOpenSource event = some source) ->
        SentAnnouncementTo afterState target)
    (transition :
      systemStep config before target event = some (after, output)) :
    forall entry, entry ∈ after.nodes ->
      entry.2.phase = .joining ->
        SentAnnouncementTo afterState entry.1 := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, outputEq⟩
  rw [←systemEq]
  intro entry membership joining
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · rename_i atTarget
    rcases step_joining_origin config node event
        (by simpa [atTarget, outputEq] using joining) with
      old | received
    · have keyEq : key = target :=
        beq_iff_eq.mp
          (List.find?_some
            (p := fun entry : Prod Location NodeState =>
              entry.1 == target) found)
      rw [←keyEq]
      apply carry
      apply valid (key, node)
      · rw [beforeSystem]
        exact List.mem_of_find?_eq_some found
      · exact old
    · exact introduced received
  · rename_i notTarget
    apply carry
    apply valid previous
    · rw [beforeSystem]
      exact previousMember
    · simpa [notTarget] using joining

theorem initial_joining_announcements
    (config : Config)
    (active : List Location) :
    JoiningAnnouncements (initial config active) := by
  simp [JoiningAnnouncements, Global.initial, initialSystem, initialNode]

theorem next_preserves_joining_announcements
    {config : Config}
    {before after : State}
    {action : Action}
    (wellFormed : WellFormed config before)
    (valid : JoiningAnnouncements before)
    (transition : next config before action = some after) :
    JoiningAnnouncements after := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, sourceState, _, _, stateEq⟩
      rw [←stateEq]
      intro entry membership joining
      rcases valid entry membership joining with
        ⟨envelope, sent, target, payload⟩
      exact
        ⟨envelope, List.mem_append_left _ sent, target, payload⟩
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨inNetwork, _, system, output, systemStep, stateEq⟩
      rw [←stateEq]
      intro entry membership joining
      rw [recordEffects_system] at membership
      let afterState :=
        recordEffects envelope.target output.state output.effects
          {
            before with
            system
            network := removeOne envelope before.network
          }
      have carry :
          forall destination,
            SentAnnouncementTo before destination ->
              SentAnnouncementTo afterState destination := by
        intro destination announcement
        rcases announcement with
          ⟨sentEnvelope, sent, target, payload⟩
        exact
          ⟨sentEnvelope, by simpa [afterState] using sent,
            target, payload⟩
      have introduced :
          (exists source,
            acceptedIAmOpenSource (eventFor envelope) = some source) ->
            SentAnnouncementTo afterState envelope.target := by
        rintro ⟨source, accepted⟩
        rcases eventFor_iamopen_source accepted with
          ⟨payload, _⟩
        exact
          ⟨envelope,
            by
              simp [afterState]
              exact wellFormed.networkSent envelope inNetwork,
            rfl, payload⟩
      exact systemStep_preserves_joining_announcements
        (before := before.system)
        (after := system)
        (beforeState := before)
        (afterState := afterState)
        rfl valid carry introduced systemStep
        entry membership joining
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, system, output, systemStep, _, stateEq⟩
      rw [←stateEq]
      intro entry membership joining
      rw [recordEffects_system] at membership
      let afterState :=
        recordEffects target output.state output.effects
          { before with system }
      have carry :
          forall destination,
            SentAnnouncementTo before destination ->
              SentAnnouncementTo afterState destination := by
        intro destination announcement
        rcases announcement with
          ⟨sentEnvelope, sent, target, payload⟩
        exact
          ⟨sentEnvelope, by simpa [afterState] using sent,
            target, payload⟩
      have introduced :
          (exists source,
            acceptedIAmOpenSource Event.timeout = some source) ->
            SentAnnouncementTo afterState target := by
        rintro ⟨source, accepted⟩
        simp [acceptedIAmOpenSource] at accepted
      exact systemStep_preserves_joining_announcements
        (before := before.system)
        (after := system)
        (beforeState := before)
        (afterState := afterState)
        rfl valid carry introduced systemStep
        entry membership joining

theorem reachable_joining_announcements
    {config : Config}
    {state : State}
    (reachable : Reachable config state) :
    JoiningAnnouncements state := by
  induction reachable with
  | initial active valid nodup configured =>
      exact initial_joining_announcements config active
  | step reachable transition valid =>
      exact next_preserves_joining_announcements
        (reachable_well_formed reachable) valid transition

theorem systemStep_preserves_open_completed
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    {beforeState afterState : State}
    (beforeSystem : beforeState.system = before)
    (valid : OpenCompleted beforeState)
    (carry :
      forall node,
        CompletedOpen beforeState node ->
          CompletedOpen afterState node)
    (introduced :
      .completed ∈ output.effects ->
        CompletedOpen afterState target)
    (transition :
      systemStep config before target event = some (after, output)) :
    forall entry, entry ∈ after.nodes ->
      entry.2.phase = .open ->
        CompletedOpen afterState entry.1 := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, outputEq⟩
  rw [←systemEq]
  intro entry membership opened
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · rename_i atTarget
    rcases step_open_origin config node event
        (by simpa [atTarget, outputEq] using opened) with
      old | completed
    · have keyEq : key = target :=
        beq_iff_eq.mp
          (List.find?_some
            (p := fun entry : Prod Location NodeState =>
              entry.1 == target) found)
      rw [←keyEq]
      apply carry
      apply valid (key, node)
      · rw [beforeSystem]
        exact List.mem_of_find?_eq_some found
      · exact old
    · rw [outputEq] at completed
      exact introduced completed
  · rename_i notTarget
    apply carry
    apply valid previous
    · rw [beforeSystem]
      exact previousMember
    · simpa [notTarget] using opened

theorem initial_open_completed
    (config : Config)
    (active : List Location) :
    OpenCompleted (initial config active) := by
  simp [OpenCompleted, Global.initial, initialSystem, initialNode]

theorem next_preserves_open_completed
    {config : Config}
    {before after : State}
    {action : Action}
    (valid : OpenCompleted before)
    (transition : next config before action = some after) :
    OpenCompleted after := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, sourceState, _, _, stateEq⟩
      rw [←stateEq]
      exact valid
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, _, system, output, systemStep, stateEq⟩
      rw [←stateEq]
      intro entry membership opened
      rw [recordEffects_system] at membership
      let afterState :=
        recordEffects envelope.target output.state output.effects
          {
            before with
            system
            network := removeOne envelope before.network
          }
      have carry :
          forall node,
            CompletedOpen before node ->
              CompletedOpen afterState node := by
        intro node completed
        apply mem_completed_recordEffects
        exact completed
      have introduced :
          .completed ∈ output.effects ->
            CompletedOpen afterState envelope.target := by
        intro completed
        exact completed_effect_recorded completed
      exact systemStep_preserves_open_completed
        (before := before.system)
        (after := system)
        (beforeState := before)
        (afterState := afterState)
        rfl valid carry introduced systemStep entry membership opened
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, system, output, systemStep, _, stateEq⟩
      rw [←stateEq]
      intro entry membership opened
      rw [recordEffects_system] at membership
      let afterState :=
        recordEffects target output.state output.effects
          { before with system }
      have carry :
          forall node,
            CompletedOpen before node ->
              CompletedOpen afterState node := by
        intro node completed
        apply mem_completed_recordEffects
        exact completed
      have introduced :
          .completed ∈ output.effects ->
            CompletedOpen afterState target := by
        intro completed
        exact completed_effect_recorded completed
      exact systemStep_preserves_open_completed
        (before := before.system)
        (after := system)
        (beforeState := before)
        (afterState := afterState)
        rfl valid carry introduced systemStep entry membership opened

theorem reachable_open_completed
    {config : Config}
    {state : State}
    (reachable : Reachable config state) :
    OpenCompleted state := by
  induction reachable with
  | initial active valid nodup configured =>
      exact initial_open_completed config active
  | step reachable transition valid =>
      exact next_preserves_open_completed valid transition

theorem reachable_announcements_resolved
    {config : Config}
    {state : State}
    (reachable : Reachable config state) :
    AnnouncementsResolved state := by
  induction reachable with
  | initial active valid nodup configured =>
      exact initial_announcements_resolved config active
  | step reachable transition resolved =>
      exact next_preserves_announcements_resolved
        (reachable_well_formed reachable)
        (reachable_lanes_valid reachable)
        (reachable_open_completed reachable)
        resolved transition

theorem open_node_completed
    {state : State}
    {node : Location}
    {nodeState : NodeState}
    (valid : OpenCompleted state)
    (found : Global.nodeState state node = some nodeState)
    (opened : nodeState.phase = .open) :
    CompletedOpen state node := by
  rw [Global.nodeState, Option.map_eq_some_iff] at found
  rcases found with ⟨entry, findEq, stateEq⟩
  have keyEq : entry.1 = node :=
    beq_iff_eq.mp
      (List.find?_some
        (p := fun entry : Prod Location NodeState =>
          entry.1 == node) findEq)
  rw [←keyEq]
  apply valid entry (List.mem_of_find?_eq_some findEq)
  simpa [stateEq] using opened

theorem joining_node_announcement
    {state : State}
    {node : Location}
    {nodeState : NodeState}
    (valid : JoiningAnnouncements state)
    (found : Global.nodeState state node = some nodeState)
    (joining : nodeState.phase = .joining) :
    SentAnnouncementTo state node := by
  rw [Global.nodeState, Option.map_eq_some_iff] at found
  rcases found with ⟨entry, findEq, stateEq⟩
  have keyEq : entry.1 = node :=
    beq_iff_eq.mp
      (List.find?_some
        (p := fun entry : Prod Location NodeState =>
          entry.1 == node) findEq)
  rw [←keyEq]
  apply valid entry (List.mem_of_find?_eq_some findEq)
  simpa [stateEq] using joining

theorem openerWitness_of_later_phase
    {config : Config}
    {state : State}
    {node : Location}
    (reachable : Reachable config state)
    (active : node ∈ state.active)
    (notGossip : Not (HasPhase state node .gossiping))
    (notVoting : Not (HasPhase state node .voting)) :
    OpenerWitness state := by
  rcases active_nodeState (reachable_well_formed reachable) active with
    ⟨nodeState, found⟩
  cases phase : nodeState.phase with
  | gossiping =>
      exact False.elim
        (notGossip ⟨nodeState, found, phase⟩)
  | voting =>
      exact False.elim
        (notVoting ⟨nodeState, found, phase⟩)
  | opening =>
      exact ⟨node, Or.inl ⟨nodeState, found, phase⟩⟩
  | joining =>
      rcases joining_node_announcement
          (reachable_joining_announcements reachable)
          found phase with
        ⟨envelope, sent, target, payload⟩
      rcases reachable_announcements_live reachable
          envelope sent payload with
        opening | completed
      · exact ⟨envelope.source, Or.inl opening⟩
      · exact ⟨envelope.source, Or.inr completed⟩
  | «open» =>
      exact
        ⟨node, Or.inr
          (open_node_completed
            (reachable_open_completed reachable) found phase)⟩

theorem openerWitness_after_leave_voting
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    {start later : Nat}
    {node : Location}
    (order : start <= later)
    (allPastGossip :
      forall activeNode,
        activeNode ∈ (execution.states start).active ->
          Not (HasPhase (execution.states start)
            activeNode .gossiping))
    (active : node ∈ (execution.states later).active)
    (notVoting :
      Not (HasPhase (execution.states later) node .voting)) :
    OpenerWitness (execution.states later) := by
  have activeStart : node ∈ (execution.states start).active := by
    rw [execution_active_eq execution later] at active
    rw [execution_active_eq execution start]
    exact active
  have notGossip :=
    not_gossiping_mono execution initial order
      (allPastGossip node activeStart)
  exact openerWitness_of_later_phase
    (execution_reachable execution initial later)
    active notGossip notVoting

theorem systemStep_preserves_advanced_active
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    {active : List Location}
    (valid :
      forall entry, entry ∈ before.nodes ->
        entry.2.phase ≠ .gossiping ->
          entry.1 ∈ active)
    (targetActive : target ∈ active)
    (transition :
      systemStep config before target event = some (after, output)) :
    forall entry, entry ∈ after.nodes ->
      entry.2.phase ≠ .gossiping ->
        entry.1 ∈ active := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, outputEq⟩
  rw [←systemEq]
  intro entry membership advanced
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · exact targetActive
  · rename_i notTarget
    exact valid previous previousMember
      (by simpa [notTarget] using advanced)

theorem initial_advanced_active
    (config : Config)
    (active : List Location) :
    AdvancedNodesActive (initial config active) := by
  simp [AdvancedNodesActive, Global.initial, initialSystem, initialNode]

theorem next_preserves_advanced_active
    {config : Config}
    {before after : State}
    {action : Action}
    (valid : AdvancedNodesActive before)
    (transition : next config before action = some after) :
    AdvancedNodesActive after := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, sourceState, _, _, stateEq⟩
      rw [←stateEq]
      exact valid
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, targetActive, system, output, systemStep, stateEq⟩
      rw [←stateEq]
      intro entry membership advanced
      rw [recordEffects_system] at membership
      simpa using
        systemStep_preserves_advanced_active
          valid targetActive systemStep entry membership advanced
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨targetActive, system, output, systemStep, _, stateEq⟩
      rw [←stateEq]
      intro entry membership advanced
      rw [recordEffects_system] at membership
      simpa using
        systemStep_preserves_advanced_active
          valid targetActive systemStep entry membership advanced

theorem reachable_advanced_active
    {config : Config}
    {state : State}
    (reachable : Reachable config state) :
    AdvancedNodesActive state := by
  induction reachable with
  | initial active valid nodup configured =>
      exact initial_advanced_active config active
  | step reachable transition valid =>
      exact next_preserves_advanced_active valid transition

theorem hasPhase_active
    {config : Config}
    {state : State}
    {node : Location}
    {phase : Phase}
    (reachable : Reachable config state)
    (hasPhase : HasPhase state node phase)
    (advancedPhase : phase ≠ .gossiping) :
    node ∈ state.active := by
  rcases hasPhase with ⟨nodeState, found, phaseEq⟩
  rw [Global.nodeState, Option.map_eq_some_iff] at found
  rcases found with ⟨entry, findEq, stateEq⟩
  have keyEq : entry.1 = node :=
    beq_iff_eq.mp
      (List.find?_some
        (p := fun entry : Prod Location NodeState =>
          entry.1 == node) findEq)
  rw [←keyEq]
  apply reachable_advanced_active reachable entry
    (List.mem_of_find?_eq_some findEq)
  rw [stateEq, phaseEq]
  exact advancedPhase

theorem fair_opener_witness
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    {start : Nat}
    (activeNonempty : (execution.states start).active ≠ [])
    (allPastGossip :
      forall node, node ∈ (execution.states start).active ->
        Not (HasPhase (execution.states start) node .gossiping)) :
    EventuallyFrom start (fun n =>
      OpenerWitness (execution.states n)) := by
  obtain ⟨voter, voterActive⟩ :=
    List.exists_mem_of_ne_nil _ activeNonempty
  by_cases voting :
      HasPhase (execution.states start) voter .voting
  · rcases voting with ⟨voterState, foundVoter, voterVoting⟩
    have selectionProperty :=
      node_property_of_nodeState
        (predicate := fun state =>
          state.phase = .voting -> NodeVotingSelection state)
        (reachable_quorum_invariant
          (execution_reachable execution initial start)).votingSelections
        foundVoter
    rcases selectionProperty voterVoting with
      ⟨target, txid, chosen, maximum⟩
    have retryEnabled :=
      retry_voting_enabled (config := config)
        voterActive foundVoter voterVoting chosen
    rcases fair.retry start voter .voting voterActive
        ⟨voterState, foundVoter, voterVoting⟩
        (Or.inr (Or.inl rfl)) retryEnabled with
      ⟨retryAt, startRetry, leftVoting | retryAction⟩
    · exact
        ⟨retryAt, startRetry,
          openerWitness_after_leave_voting execution initial
            startRetry allPastGossip
            (by
              rw [execution_active_eq execution retryAt]
              rw [execution_active_eq execution start] at voterActive
              exact voterActive)
            leftVoting⟩
    · by_cases retryVoting :
          HasPhase (execution.states retryAt) voter .voting
      · rcases retryVoting with
          ⟨retryState, foundRetry, votingRetry⟩
        have retrySelectionProperty :=
          node_property_of_nodeState
            (predicate := fun state =>
              state.phase = .voting -> NodeVotingSelection state)
            (reachable_quorum_invariant
              (execution_reachable execution initial retryAt)).votingSelections
            foundRetry
        rcases retrySelectionProperty votingRetry with
          ⟨retryTarget, retryTxID, retryChosen, retryMaximum⟩
        have retryStep :
            next config (execution.states retryAt) (.retry voter) =
              some (execution.states (retryAt + 1)) := by
          simpa [retryAction] using execution.step_succ retryAt
        rcases retry_vote_enqueued foundRetry votingRetry retryChosen
            retryStep with
          ⟨voteEnvelope, pending, voteSource, voteTarget, votePayload⟩
        rcases fair.delivery (retryAt + 1) voteEnvelope pending with
          ⟨deliverAt, retryDeliver, deliverAction⟩
        have deliverStep :
            next config (execution.states deliverAt)
                (.deliver voteEnvelope) =
              some (execution.states (deliverAt + 1)) := by
          simpa [deliverAction] using execution.step_succ deliverAt
        have deliverDetails := deliverStep
        simp [next, Option.bind_eq_some_iff] at deliverDetails
        have targetActive : voteEnvelope.target ∈
            (execution.states deliverAt).active :=
          deliverDetails.2.1
        by_cases targetVoting :
            HasPhase (execution.states deliverAt)
              voteEnvelope.target .voting
        · rcases deliver_vote_progress
              (reachable_well_formed
                (execution_reachable execution initial deliverAt))
              votePayload targetVoting deliverStep with
            leftAfter | hasVote
          · have activeAfter : voteEnvelope.target ∈
                (execution.states (deliverAt + 1)).active := by
              rw [execution_active_eq execution (deliverAt + 1)]
              rw [execution_active_eq execution deliverAt] at targetActive
              exact targetActive
            exact
              ⟨deliverAt + 1, by omega,
                openerWitness_after_leave_voting execution initial
                  (by omega) allPastGossip activeAfter leftAfter⟩
          · by_cases votingAfter :
                HasPhase (execution.states (deliverAt + 1))
                  voteEnvelope.target .voting
            · have activeAfter : voteEnvelope.target ∈
                  (execution.states (deliverAt + 1)).active := by
                rw [execution_active_eq execution (deliverAt + 1)]
                rw [execution_active_eq execution deliverAt] at targetActive
                exact targetActive
              have timeoutEnabled :=
                voting_timeout_enabled (config := config)
                  activeAfter votingAfter
              rcases fair.timeout (deliverAt + 1)
                  voteEnvelope.target .voting activeAfter votingAfter
                  (Or.inr (Or.inl rfl)) timeoutEnabled with
                ⟨timeoutAt, deliverTimeout,
                  leftBeforeTimeout | timeoutAction⟩
              · exact
                  ⟨timeoutAt, by omega,
                    openerWitness_after_leave_voting execution initial
                      (by omega) allPastGossip
                      (by
                        rw [execution_active_eq execution timeoutAt]
                        rw [execution_active_eq execution
                          (deliverAt + 1)] at activeAfter
                        exact activeAfter)
                      leftBeforeTimeout⟩
              · by_cases votingAtTimeout :
                    HasPhase (execution.states timeoutAt)
                      voteEnvelope.target .voting
                · have voteAtTimeout :=
                    hasVote_mono execution initial deliverTimeout hasVote
                  have timeoutStep :
                      next config (execution.states timeoutAt)
                          (.timeout voteEnvelope.target) =
                        some (execution.states (timeoutAt + 1)) := by
                    simpa [timeoutAction] using
                      execution.step_succ timeoutAt
                  rcases timeout_voting_step
                      (reachable_well_formed
                        (execution_reachable execution initial timeoutAt))
                      (reachable_lanes_valid
                        (execution_reachable execution initial timeoutAt))
                      votingAtTimeout voteAtTimeout timeoutStep with
                    opened |
                      ⟨waitingState, foundWaiting, waitingPhase,
                        waitingLane, waitingVotes⟩
                  · exact
                      ⟨timeoutAt + 1, by omega,
                        ⟨voteEnvelope.target, Or.inl opened⟩⟩
                  · have activeWaiting : voteEnvelope.target ∈
                        (execution.states (timeoutAt + 1)).active := by
                      rw [execution_active_eq execution (timeoutAt + 1)]
                      rw [execution_active_eq execution
                        (deliverAt + 1)] at activeAfter
                      exact activeAfter
                    have secondEnabled :=
                      voting_timeout_enabled (config := config)
                        activeWaiting
                        ⟨waitingState, foundWaiting, waitingPhase⟩
                    rcases fair.timeout (timeoutAt + 1)
                        voteEnvelope.target .voting activeWaiting
                        ⟨waitingState, foundWaiting, waitingPhase⟩
                        (Or.inr (Or.inl rfl)) secondEnabled with
                      ⟨secondAt, firstSecond,
                        leftBeforeSecond | secondAction⟩
                    · exact
                        ⟨secondAt, by omega,
                          openerWitness_after_leave_voting execution initial
                            (by omega) allPastGossip
                            (by
                              rw [execution_active_eq execution secondAt]
                              rw [execution_active_eq execution
                                (timeoutAt + 1)] at activeWaiting
                              exact activeWaiting)
                            leftBeforeSecond⟩
                    · by_cases votingAtSecond :
                          HasPhase (execution.states secondAt)
                            voteEnvelope.target .voting
                      · rcases votingAtSecond with
                          ⟨secondState, foundSecond, secondPhase⟩
                        have votesSecond :=
                          hasVote_mono execution initial firstSecond
                            ⟨waitingState, foundWaiting, waitingVotes⟩
                        rcases votesSecond with
                          ⟨voteState, foundVotes, secondVotes⟩
                        rw [foundSecond] at foundVotes
                        injection foundVotes with voteStateEq
                        subst voteState
                        have advancedSecond :=
                          advanced_lane_mono execution initial firstSecond
                            ⟨waitingState, foundWaiting, by simp [waitingLane]⟩
                        rcases advancedSecond with
                          ⟨laneState, foundLane, advanced⟩
                        rw [foundSecond] at foundLane
                        injection foundLane with laneStateEq
                        subst laneState
                        have laneValid : LaneValid secondState := by
                          apply node_property_of_nodeState
                            (predicate := LaneValid)
                          · exact reachable_lanes_valid
                              (execution_reachable execution initial secondAt)
                          · exact foundSecond
                        have secondLane : secondState.timeoutState =
                            .voting := by
                          rcases laneValid.2.1 secondPhase with
                            gossipLane | votingLane
                          · contradiction
                          · exact votingLane
                        have secondStep :
                            next config (execution.states secondAt)
                                (.timeout voteEnvelope.target) =
                              some (execution.states (secondAt + 1)) := by
                          simpa [secondAction] using
                            execution.step_succ secondAt
                        have opened :=
                          aligned_timeout_voting_opens
                            (reachable_well_formed
                              (execution_reachable execution initial secondAt))
                            foundSecond secondPhase secondLane secondVotes
                            secondStep
                        exact
                          ⟨secondAt + 1, by omega,
                            ⟨voteEnvelope.target, Or.inl opened⟩⟩
                      · exact
                          ⟨secondAt, by omega,
                            openerWitness_after_leave_voting execution initial
                              (by omega) allPastGossip
                              (by
                                rw [execution_active_eq execution secondAt]
                                rw [execution_active_eq execution
                                  (timeoutAt + 1)] at activeWaiting
                                exact activeWaiting)
                              votingAtSecond⟩
                · exact
                    ⟨timeoutAt, by omega,
                      openerWitness_after_leave_voting execution initial
                        (by omega) allPastGossip
                        (by
                          rw [execution_active_eq execution timeoutAt]
                          rw [execution_active_eq execution
                            (deliverAt + 1)] at activeAfter
                          exact activeAfter)
                        votingAtTimeout⟩
            · exact
                ⟨deliverAt + 1, by omega,
                  openerWitness_after_leave_voting execution initial
                    (by omega) allPastGossip
                    (by
                      rw [execution_active_eq execution (deliverAt + 1)]
                      rw [execution_active_eq execution deliverAt]
                        at targetActive
                      exact targetActive)
                    votingAfter⟩
        · exact
            ⟨deliverAt, by omega,
              openerWitness_after_leave_voting execution initial
                (by omega) allPastGossip targetActive targetVoting⟩
      · exact
          ⟨retryAt, startRetry,
            openerWitness_after_leave_voting execution initial
              startRetry allPastGossip
              (by
                rw [execution_active_eq execution retryAt]
                rw [execution_active_eq execution start] at voterActive
                exact voterActive)
              retryVoting⟩
  · exact
      ⟨start, Nat.le_refl start,
        openerWitness_after_leave_voting execution initial
          (Nat.le_refl start) allPastGossip voterActive voting⟩

theorem openerWitness_eventually_completes
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    {start : Nat}
    (witness : OpenerWitness (execution.states start)) :
    EventuallyFrom start (fun n =>
      exists node, CompletedOpen (execution.states n) node) := by
  rcases witness with ⟨node, opening | completed⟩
  · have active :=
      hasPhase_active (execution_reachable execution initial start)
        opening (by simp)
    rcases fair_opening_completes execution initial fair active opening with
      ⟨completedAt, order, completed⟩
    exact ⟨completedAt, order, node, completed⟩
  · exact ⟨start, Nat.le_refl start, node, completed⟩

theorem fair_some_opener_completes
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    (activeNonempty : (execution.states 0).active ≠ []) :
    EventuallyFrom 0 (fun n =>
      exists node, CompletedOpen (execution.states n) node) := by
  rcases fair_all_leave_gossip execution initial fair 0 with
    ⟨pastGossipAt, _, allPastGossip⟩
  have nonemptyAt :
      (execution.states pastGossipAt).active ≠ [] := by
    rw [execution_active_eq execution pastGossipAt]
    exact activeNonempty
  have allPastAt :
      forall node, node ∈ (execution.states pastGossipAt).active ->
        Not (HasPhase (execution.states pastGossipAt)
          node .gossiping) := by
    intro node active
    rw [execution_active_eq execution pastGossipAt] at active
    exact allPastGossip node active
  rcases fair_opener_witness execution initial fair nonemptyAt
      allPastAt with
    ⟨witnessAt, pastWitness, witness⟩
  rcases openerWitness_eventually_completes execution initial fair
      witness with
    ⟨completedAt, witnessCompleted, completed⟩
  exact ⟨completedAt, by omega, completed⟩

theorem fair_target_terminal_after_completion
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    (broadcast : BroadcastBeforeCompletion execution)
    {start : Nat}
    {opener target : Location}
    (completed : CompletedOpen (execution.states start) opener)
    (active : target ∈ (execution.states start).active) :
    EventuallyFrom start (fun n =>
      Terminal (execution.states n) target) := by
  by_cases same : target = opener
  · subst target
    exact ⟨start, Nat.le_refl start, Or.inr completed⟩
  · rcases broadcast start opener completed target active same with
      ⟨envelope, sent, sourceEq, targetEq, payload⟩
    rcases reachable_announcements_resolved
        (execution_reachable execution initial start)
        envelope sent payload with
      pending | terminal | opening
    · rcases fair.delivery start envelope pending with
        ⟨deliverAt, startDelivery, deliverAction⟩
      have deliverStep :
          next config (execution.states deliverAt) (.deliver envelope) =
            some (execution.states (deliverAt + 1)) := by
        simpa [deliverAction] using execution.step_succ deliverAt
      rcases deliver_iamopen_resolves
          (reachable_well_formed
            (execution_reachable execution initial deliverAt))
          (reachable_open_completed
            (execution_reachable execution initial deliverAt))
          payload deliverStep with
        terminal | targetOpening
      · exact
          ⟨deliverAt + 1, by omega, by simpa [targetEq] using terminal⟩
      · have openingActive :=
          hasPhase_active
            (execution_reachable execution initial (deliverAt + 1))
            targetOpening (by simp)
        rcases fair_opening_completes execution initial fair
            openingActive targetOpening with
          ⟨completedAt, deliveryCompleted, targetCompleted⟩
        exact
          ⟨completedAt, by omega,
            by simpa [targetEq] using (Or.inr targetCompleted)⟩
    · exact
        ⟨start, Nat.le_refl start, by simpa [targetEq] using terminal⟩
    · have openingActive :=
        hasPhase_active
          (execution_reachable execution initial start)
          opening (by simp)
      rcases fair_opening_completes execution initial fair
          openingActive opening with
        ⟨completedAt, startCompleted, targetCompleted⟩
      exact
        ⟨completedAt, startCompleted,
          by simpa [targetEq] using (Or.inr targetCompleted)⟩

theorem fair_all_terminal_after_completion
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    (broadcast : BroadcastBeforeCompletion execution)
    {start : Nat}
    {opener : Location}
    (completed : CompletedOpen (execution.states start) opener) :
    EventuallyFrom start (fun n =>
      forall node, node ∈ (execution.states start).active ->
        Terminal (execution.states n) node) := by
  apply eventually_list (execution.states start).active
  · intro node active
    exact fair_target_terminal_after_completion
      execution initial fair broadcast completed active
  · intro node first second order terminal
    exact terminal_mono execution order terminal

theorem global_progress
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    (broadcast : BroadcastBeforeCompletion execution)
    (activeNonempty : (execution.states 0).active ≠ []) :
    EventuallyFrom 0 (fun n =>
      exists node, CompletedOpen (execution.states n) node) /\
    EventuallyFrom 0 (fun n =>
      forall node, node ∈ (execution.states 0).active ->
        Terminal (execution.states n) node) := by
  have completed :=
    fair_some_opener_completes execution initial fair activeNonempty
  constructor
  · exact completed
  · rcases completed with
      ⟨completedAt, _, opener, openerCompleted⟩
    rcases fair_all_terminal_after_completion execution initial fair
        broadcast openerCompleted with
      ⟨terminalAt, completedTerminal, allTerminal⟩
    refine ⟨terminalAt, by omega, ?_⟩
    intro node active
    apply allTerminal node
    rw [execution_active_eq execution completedAt]
    exact active

theorem single_completion_path_joins_others
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    (broadcast : BroadcastBeforeCompletion execution)
    {start : Nat}
    {opener : Location}
    (completed : CompletedOpen (execution.states start) opener)
    (onlyOpener : OnlyOpenerCompletesFrom execution start opener) :
    EventuallyFrom start (fun n =>
      forall node, node ∈ (execution.states start).active ->
        node = opener \/ node ∈ (execution.states n).restarts) := by
  apply eventually_list (execution.states start).active
  · intro node active
    by_cases same : node = opener
    · exact ⟨start, Nat.le_refl start, Or.inl same⟩
    · rcases fair_target_terminal_after_completion
          execution initial fair broadcast completed active with
        ⟨terminalAt, startTerminal, terminal⟩
      rcases terminal with restarted | targetCompleted
      · exact ⟨terminalAt, startTerminal, Or.inr restarted⟩
      · exact False.elim
          (same
            (onlyOpener terminalAt node startTerminal targetCompleted))
  · intro node first second order joined
    rcases joined with same | restarted
    · exact Or.inl same
    · exact Or.inr
        (by
          induction second, order using Nat.le_induction with
          | base => exact restarted
          | succ second order restarted =>
              exact next_restarts_monotonic
                (execution.step_succ second) node restarted)

theorem quorum_path_progress
    {config : Config}
    (execution : Execution config)
    (initial : Reachable config (execution.states 0))
    (fair : Fair execution)
    (broadcast : BroadcastBeforeCompletion execution)
    {start : Nat}
    {opener : Location}
    (opened : QuorumOpened (execution.states start) opener)
    (completed : CompletedOpen (execution.states start) opener)
    (quorumOnly : QuorumOnlyCompletions execution) :
    QuorumOpened (execution.states start) opener /\
      CompletedOpen (execution.states start) opener /\
      EventuallyFrom start (fun n =>
        forall node, node ∈ (execution.states start).active ->
          node = opener \/ node ∈ (execution.states n).restarts) := by
  have onlyOpener :
      OnlyOpenerCompletesFrom execution start opener := by
    intro n node startN nodeCompleted
    exact quorum_opener_unique
      (execution_reachable execution initial n)
      (quorumOnly n node nodeCompleted)
      (quorumOpened_mono execution startN opened)
  exact
    ⟨opened, completed,
      single_completion_path_joins_others
        execution initial fair broadcast completed onlyOpener⟩

end DisasterRecovery.Protocol.Global
