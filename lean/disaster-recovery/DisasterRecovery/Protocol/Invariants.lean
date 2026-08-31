import DisasterRecovery.Protocol.Global
import Mathlib.Tactic

namespace DisasterRecovery.Protocol.Global

structure HistoriesActive (state : State) : Prop where
  openings :
    forall opening, opening ∈ state.openings ->
      opening.node ∈ state.active
  restarts :
    forall node, node ∈ state.restarts ->
      node ∈ state.active
  completed :
    forall node, node ∈ state.completed ->
      node ∈ state.active

structure WellFormed (config : Config) (state : State) : Prop where
  nodeKeys :
    state.system.nodes.map Prod.fst =
      config.protocol.expectedLocations
  nodeLocations :
    forall entry, entry ∈ state.system.nodes ->
      entry.2.location = entry.1
  activeNodup : state.active.Nodup
  activeConfigured :
    forall node, node ∈ state.active ->
      node ∈ config.protocol.expectedLocations
  sentValid :
    forall envelope, envelope ∈ state.sent ->
      envelope.Valid config
  sentSourceActive :
    forall envelope, envelope ∈ state.sent ->
      envelope.source ∈ state.active
  networkSent :
    forall envelope, envelope ∈ state.network ->
      envelope ∈ state.sent
  historiesActive : HistoriesActive state

theorem messageForEffect_source
    {config : Config}
    {source : Location}
    {sourceState : NodeState}
    {effect : Effect}
    {envelope : Envelope}
    (created :
      messageForEffect config source sourceState effect = some envelope) :
    envelope.source = source /\
      envelope.sourceState = sourceState := by
  cases effect with
  | sendGossip target =>
      cases found : recoveredTxID config source with
      | none =>
          simp [messageForEffect, found] at created
      | some txid =>
          simp [messageForEffect, found] at created
          rw [←created]
          exact ⟨rfl, rfl⟩
  | sendVote target =>
      simp [messageForEffect] at created
      rw [←created]
      exact ⟨rfl, rfl⟩
  | sendIAmOpen target =>
      simp [messageForEffect] at created
      rw [←created]
      exact ⟨rfl, rfl⟩
  | opening kind =>
      simp_all [messageForEffect]
  | restart chosen =>
      simp_all [messageForEffect]
  | completed =>
      simp_all [messageForEffect]
  | rejected reason =>
      simp_all [messageForEffect]

theorem retryMessages_source
    {config : Config}
    {source : Location}
    {sourceState : NodeState}
    {envelope : Envelope}
    (created :
      envelope ∈ retryMessages config source sourceState) :
    envelope.source = source /\
      envelope.sourceState = sourceState := by
  rw [retryMessages, List.mem_filterMap] at created
  rcases created with ⟨effect, _, produced⟩
  exact messageForEffect_source produced

theorem retryMessages_valid
    (config : Config)
    (source : Location)
    (sourceState : NodeState)
    (sourceLocation : sourceState.location = source) :
    forall envelope,
      envelope ∈ retryMessages config source sourceState ->
      envelope.Valid config := by
  intro envelope created
  rcases retryMessages_source created with
    ⟨sourceEq, stateEq⟩
  constructor
  · rw [stateEq, sourceEq]
    exact sourceLocation
  · rw [sourceEq, stateEq]
    exact created

theorem valid_envelope_effect
    {config : Config}
    {envelope : Envelope}
    (valid : envelope.Valid config) :
    exists effect,
      effect ∈
        (step config.protocol envelope.sourceState .retry).effects /\
      messageForEffect config envelope.source
        envelope.sourceState effect = some envelope := by
  rcases valid with ⟨_, created⟩
  rw [retryMessages, List.mem_filterMap] at created
  exact created

theorem valid_gossip_uses_recovered_txid
    {config : Config}
    {envelope : Envelope}
    {txid : TxID}
    (valid : envelope.Valid config)
    (gossip : envelope.payload = .gossip txid) :
    recoveredTxID config envelope.source = some txid := by
  rcases valid_envelope_effect valid with
    ⟨effect, _, created⟩
  cases effect with
  | sendGossip target =>
      cases found : recoveredTxID config envelope.source with
      | none =>
          simp [messageForEffect, found] at created
      | some recovered =>
          simp [messageForEffect, found] at created
          rw [←created] at gossip
          injection gossip with same
          subst recovered
          rfl
  | sendVote target =>
      simp [messageForEffect] at created
      rw [←created] at gossip
      contradiction
  | sendIAmOpen target =>
      simp [messageForEffect] at created
      rw [←created] at gossip
      contradiction
  | opening kind =>
      simp [messageForEffect] at created
  | restart chosen =>
      simp [messageForEffect] at created
  | completed =>
      simp [messageForEffect] at created
  | rejected reason =>
      simp [messageForEffect] at created

theorem step_preserves_location
    (config : Protocol.Config)
    (state : NodeState)
    (event : Event) :
    (step config state event).state.location = state.location := by
  cases event <;>
    simp [step, rejected, advance, advanceTimeoutLane]
  all_goals repeat first | split | simp_all

theorem nodeState_location
    {state : State}
    {node : Location}
    {foundState : NodeState}
    (locations :
      forall entry, entry ∈ state.system.nodes ->
        entry.2.location = entry.1)
    (found : nodeState state node = some foundState) :
    foundState.location = node := by
  rw [nodeState, Option.map_eq_some_iff] at found
  rcases found with ⟨entry, findEq, stateEq⟩
  have membership : entry ∈ state.system.nodes :=
    List.mem_of_find?_eq_some findEq
  have condition : (entry.1 == node) = true :=
    List.find?_some
      (p := fun entry : Prod Location NodeState =>
        entry.1 == node) findEq
  have keyEq : entry.1 = node := beq_iff_eq.mp condition
  rw [←stateEq, locations entry membership, keyEq]

theorem initial_well_formed
    (config : Config)
    (active : List Location)
    (activeNodup : active.Nodup)
    (activeConfigured :
      forall node, node ∈ active ->
        node ∈ config.protocol.expectedLocations) :
    WellFormed config (initial config active) := by
  constructor
  · simp [Global.initial, initialSystem, Function.comp_def]
  · simp [Global.initial, initialSystem, initialNode]
  · exact activeNodup
  · exact activeConfigured
  · simp [Global.initial]
  · simp [Global.initial]
  · simp [Global.initial]
  · constructor <;> simp [Global.initial]

@[simp]
theorem recordEffects_active
    (node : Location)
    (effects : List Effect)
    (state : State) :
    (recordEffects node effects state).active = state.active := by
  induction effects generalizing state with
  | nil => rfl
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      change
        (recordEffects node tail (recordEffect node state effect)).active =
          state.active
      rw [ih]
      cases effect <;> rfl

@[simp]
theorem recordEffects_system
    (node : Location)
    (effects : List Effect)
    (state : State) :
    (recordEffects node effects state).system = state.system := by
  induction effects generalizing state with
  | nil => rfl
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      change
        (recordEffects node tail (recordEffect node state effect)).system =
          state.system
      rw [ih]
      cases effect <;> rfl

@[simp]
theorem recordEffects_network
    (node : Location)
    (effects : List Effect)
    (state : State) :
    (recordEffects node effects state).network = state.network := by
  induction effects generalizing state with
  | nil => rfl
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      change
        (recordEffects node tail (recordEffect node state effect)).network =
          state.network
      rw [ih]
      cases effect <;> rfl

@[simp]
theorem recordEffects_sent
    (node : Location)
    (effects : List Effect)
    (state : State) :
    (recordEffects node effects state).sent = state.sent := by
  induction effects generalizing state with
  | nil => rfl
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      change
        (recordEffects node tail (recordEffect node state effect)).sent =
          state.sent
      rw [ih]
      cases effect <;> rfl

theorem recordEffect_preserves_histories_active
    {node : Location}
    {state : State}
    {effect : Effect}
    (wellFormed : HistoriesActive state)
    (nodeActive : node ∈ state.active) :
    HistoriesActive (recordEffect node state effect) := by
  rcases wellFormed with ⟨openings, restarts, completed⟩
  cases effect <;>
    constructor <;>
    simp_all [recordEffect]

theorem recordEffects_preserves_histories_active
    {node : Location}
    {effects : List Effect}
    {state : State}
    (wellFormed : HistoriesActive state)
    (nodeActive : node ∈ state.active) :
    HistoriesActive (recordEffects node effects state) := by
  induction effects generalizing state with
  | nil => exact wellFormed
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      apply ih
      · exact recordEffect_preserves_histories_active wellFormed nodeActive
      · cases effect <;> simpa [recordEffect] using nodeActive

theorem mem_of_mem_removeOne
    [BEq α]
    (value member : α)
    (values : List α) :
    member ∈ removeOne value values ->
      member ∈ values := by
  induction values with
  | nil => simp [removeOne]
  | cons head tail ih =>
      simp only [removeOne]
      split
      · exact List.mem_cons_of_mem head
      · intro membership
        rw [List.mem_cons] at membership ⊢
        exact membership.imp_right ih

theorem mem_openings_recordEffect
    {node : Location}
    {state : State}
    {effect : Effect}
    {opening : Opening}
    (membership : opening ∈ state.openings) :
    opening ∈ (recordEffect node state effect).openings := by
  cases effect <;> simp_all [recordEffect]

theorem mem_restarts_recordEffect
    {node : Location}
    {state : State}
    {effect : Effect}
    {restart : Location}
    (membership : restart ∈ state.restarts) :
    restart ∈ (recordEffect node state effect).restarts := by
  cases effect <;> simp_all [recordEffect]

theorem mem_completed_recordEffect
    {node : Location}
    {state : State}
    {effect : Effect}
    {completed : Location}
    (membership : completed ∈ state.completed) :
    completed ∈ (recordEffect node state effect).completed := by
  cases effect <;> simp_all [recordEffect]

theorem mem_openings_recordEffects
    {node : Location}
    {state : State}
    {effects : List Effect}
    {opening : Opening}
    (membership : opening ∈ state.openings) :
    opening ∈ (recordEffects node effects state).openings := by
  induction effects generalizing state with
  | nil => exact membership
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      exact ih (mem_openings_recordEffect membership)

theorem mem_restarts_recordEffects
    {node : Location}
    {state : State}
    {effects : List Effect}
    {restart : Location}
    (membership : restart ∈ state.restarts) :
    restart ∈ (recordEffects node effects state).restarts := by
  induction effects generalizing state with
  | nil => exact membership
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      exact ih (mem_restarts_recordEffect membership)

theorem mem_completed_recordEffects
    {node : Location}
    {state : State}
    {effects : List Effect}
    {completed : Location}
    (membership : completed ∈ state.completed) :
    completed ∈ (recordEffects node effects state).completed := by
  induction effects generalizing state with
  | nil => exact membership
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      exact ih (mem_completed_recordEffect membership)

theorem replaceNode_keys
    (target : Location)
    (nextState : NodeState)
    (nodes : List (Prod Location NodeState)) :
    (replaceNode target nextState nodes).map Prod.fst =
      nodes.map Prod.fst := by
  induction nodes with
  | nil => rfl
  | cons entry tail ih =>
      simp only [replaceNode, List.map_cons]
      split
      ·
        rename_i condition
        have same : entry.1 = target := beq_iff_eq.mp condition
        simp only [List.cons.injEq]
        constructor
        · exact same.symm
        · simpa [replaceNode] using ih
      ·
        simp only [List.cons.injEq, true_and]
        simpa [replaceNode] using ih

theorem replaceNode_locations
    (target : Location)
    (nextState : NodeState)
    (nodes : List (Prod Location NodeState))
    (locations :
      forall entry, entry ∈ nodes ->
        entry.2.location = entry.1)
    (nextLocation : nextState.location = target) :
    forall entry, entry ∈ replaceNode target nextState nodes ->
      entry.2.location = entry.1 := by
  intro entry membership
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · exact nextLocation
  · exact locations previous previousMember

theorem findNode_replaceNode_ne
    (target other : Location)
    (nextState : NodeState)
    (nodes : List (Prod Location NodeState))
    (different : other ≠ target) :
    ((replaceNode target nextState nodes).find?
      fun entry => entry.1 == other).map Prod.snd =
        (nodes.find? fun entry => entry.1 == other).map Prod.snd := by
  let replace : Prod Location NodeState -> Prod Location NodeState :=
    fun entry =>
      if entry.1 == target then (target, nextState) else entry
  change
    Option.map Prod.snd
      (List.find? (fun entry => entry.1 == other)
        (nodes.map replace)) =
      Option.map Prod.snd
        (List.find? (fun entry => entry.1 == other) nodes)
  rw [List.find?_map]
  have predicate :
      ((fun entry : Prod Location NodeState => entry.1 == other) ∘
        replace) =
        (fun entry => entry.1 == other) := by
    funext entry
    by_cases atTarget : entry.1 = target
    · simp [replace, atTarget]
    · simp [replace, atTarget]
  rw [predicate]
  cases found :
      List.find? (fun entry : Prod Location NodeState =>
        entry.1 == other) nodes with
  | none => simp
  | some entry =>
      have condition :
          (entry.1 == other) = true :=
        List.find?_some
          (p := fun entry : Prod Location NodeState =>
            entry.1 == other) found
      have entryOther : entry.1 = other :=
        beq_iff_eq.mp condition
      have notTarget : entry.1 ≠ target := by
        simpa [entryOther] using different
      simp [replace, notTarget]

theorem systemStep_node_keys_eq
    {config : Protocol.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (transition :
      systemStep config before target event = some (after, output)) :
    after.nodes.map Prod.fst = before.nodes.map Prod.fst := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with ⟨node, _, stateEq, _⟩
  rw [←stateEq]
  exact replaceNode_keys target
    (step config node event).state before.nodes

theorem systemStep_preserves_node_locations
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
    forall entry, entry ∈ after.nodes ->
      entry.2.location = entry.1 := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, stateEq, _⟩
  rw [←stateEq]
  apply replaceNode_locations
  · exact locations
  · calc
      (step config node event).state.location =
          node.location := step_preserves_location config node event
      _ = key :=
        locations (key, node) (List.mem_of_find?_eq_some found)
      _ = target :=
        beq_iff_eq.mp
          (List.find?_some
            (p := fun entry : Prod Location NodeState =>
              entry.1 == target) found)

theorem systemStep_other_node_eq
    {config : Protocol.Config}
    {before after : SystemState}
    {target other : Location}
    {event : Event}
    {output : StepOutput}
    (different : other ≠ target)
    (transition :
      systemStep config before target event = some (after, output)) :
    (after.nodes.find? fun entry => entry.1 == other).map Prod.snd =
      (before.nodes.find? fun entry => entry.1 == other).map Prod.snd := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with ⟨node, _, stateEq, _⟩
  rw [←stateEq]
  exact findNode_replaceNode_ne target other
    (step config node event).state before.nodes different

theorem next_active_eq
    {config : Config}
    {before after : State}
    {action : Action}
    (transition : next config before action = some after) :
    after.active = before.active := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, rfl⟩
      rfl
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, _, system, output, _, rfl⟩
      exact recordEffects_active envelope.target output.effects _
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, system, output, _, _, rfl⟩
      exact recordEffects_active target output.effects _

theorem next_node_keys_eq
    {config : Config}
    {before after : State}
    {action : Action}
    (transition : next config before action = some after) :
    after.system.nodes.map Prod.fst =
      before.system.nodes.map Prod.fst := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, rfl⟩
      rfl
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, _, system, output, systemStep, rfl⟩
      simpa using systemStep_node_keys_eq systemStep
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, system, output, systemStep, _, rfl⟩
      simpa using systemStep_node_keys_eq systemStep

theorem retry_system_eq
    {config : Config}
    {before after : State}
    {source : Location}
    (transition : next config before (.retry source) = some after) :
    after.system = before.system := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with ⟨_, sourceState, _, _, rfl⟩
  rfl

theorem deliver_network_eq
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (transition : next config before (.deliver envelope) = some after) :
    after.network = removeOne envelope before.network := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, _, system, output, _, rfl⟩
  exact recordEffects_network envelope.target output.effects _

theorem timeout_network_eq
    {config : Config}
    {before after : State}
    {target : Location}
    (transition : next config before (.timeout target) = some after) :
    after.network = before.network := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, system, output, _, _, rfl⟩
  exact recordEffects_network target output.effects _

theorem deliver_other_node_eq
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    {other : Location}
    (different : other ≠ envelope.target)
    (transition : next config before (.deliver envelope) = some after) :
    nodeState after other = nodeState before other := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, _, system, output, systemStep, stateEq⟩
  rw [←stateEq]
  simp only [nodeState, recordEffects_system]
  exact systemStep_other_node_eq different systemStep

theorem timeout_other_node_eq
    {config : Config}
    {before after : State}
    {target other : Location}
    (different : other ≠ target)
    (transition : next config before (.timeout target) = some after) :
    nodeState after other = nodeState before other := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, system, output, systemStep, _, stateEq⟩
  rw [←stateEq]
  simp only [nodeState, recordEffects_system]
  exact systemStep_other_node_eq different systemStep

theorem next_sent_extends
    {config : Config}
    {before after : State}
    {action : Action}
    (transition : next config before action = some after) :
    exists added, after.sent = before.sent ++ added := by
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, rfl⟩
      exact ⟨retryMessages config source sourceState, rfl⟩
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, _, system, output, _, rfl⟩
      refine ⟨[], ?_⟩
      simp
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, system, output, _, _, rfl⟩
      refine ⟨[], ?_⟩
      simp

theorem next_openings_monotonic
    {config : Config}
    {before after : State}
    {action : Action}
    (transition : next config before action = some after) :
    forall opening, opening ∈ before.openings ->
      opening ∈ after.openings := by
  intro opening membership
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, rfl⟩
      exact membership
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, _, system, output, _, rfl⟩
      exact mem_openings_recordEffects membership
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, system, output, _, _, rfl⟩
      exact mem_openings_recordEffects membership

theorem next_restarts_monotonic
    {config : Config}
    {before after : State}
    {action : Action}
    (transition : next config before action = some after) :
    forall restart, restart ∈ before.restarts ->
      restart ∈ after.restarts := by
  intro restart membership
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, rfl⟩
      exact membership
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, _, system, output, _, rfl⟩
      exact mem_restarts_recordEffects membership
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, system, output, _, _, rfl⟩
      exact mem_restarts_recordEffects membership

theorem next_completed_monotonic
    {config : Config}
    {before after : State}
    {action : Action}
    (transition : next config before action = some after) :
    forall completed, completed ∈ before.completed ->
      completed ∈ after.completed := by
  intro completed membership
  cases action with
  | retry source =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with ⟨_, sourceState, _, _, rfl⟩
      exact membership
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, _, system, output, _, rfl⟩
      exact mem_completed_recordEffects membership
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      rcases transition with
        ⟨_, system, output, _, _, rfl⟩
      exact mem_completed_recordEffects membership

theorem retry_preserves_well_formed
    {config : Config}
    {before after : State}
    {source : Location}
    (wellFormed : WellFormed config before)
    (transition : next config before (.retry source) = some after) :
    WellFormed config after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨sourceActive, sourceState, found, _, stateEq⟩
  have sourceLocation : sourceState.location = source :=
    nodeState_location wellFormed.nodeLocations found
  rw [←stateEq]
  constructor
  · exact wellFormed.nodeKeys
  · exact wellFormed.nodeLocations
  · exact wellFormed.activeNodup
  · exact wellFormed.activeConfigured
  · intro envelope membership
    rw [List.mem_append] at membership
    rcases membership with membership | membership
    · exact wellFormed.sentValid envelope membership
    · exact retryMessages_valid config source sourceState
        sourceLocation envelope membership
  · intro envelope membership
    rw [List.mem_append] at membership
    rcases membership with membership | membership
    · exact wellFormed.sentSourceActive envelope membership
    · rw [(retryMessages_source membership).1]
      exact sourceActive
  · intro envelope membership
    rw [List.mem_append] at membership ⊢
    rcases membership with membership | membership
    · exact Or.inl (wellFormed.networkSent envelope membership)
    · exact Or.inr membership
  · constructor
    · exact wellFormed.historiesActive.openings
    · exact wellFormed.historiesActive.restarts
    · exact wellFormed.historiesActive.completed

theorem deliver_preserves_well_formed
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config before)
    (transition : next config before (.deliver envelope) = some after) :
    WellFormed config after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨_, targetActive, system, output, systemStep, stateEq⟩
  rw [←stateEq]
  constructor
  · rw [recordEffects_system]
    exact (systemStep_node_keys_eq systemStep).trans
      wellFormed.nodeKeys
  · rw [recordEffects_system]
    exact systemStep_preserves_node_locations
      wellFormed.nodeLocations systemStep
  · simpa using wellFormed.activeNodup
  · simpa using wellFormed.activeConfigured
  · intro sent membership
    rw [recordEffects_sent] at membership
    exact wellFormed.sentValid sent membership
  · intro sent membership
    rw [recordEffects_sent] at membership
    rw [recordEffects_active]
    exact wellFormed.sentSourceActive sent membership
  · intro pending membership
    rw [recordEffects_network] at membership
    rw [recordEffects_sent]
    exact wellFormed.networkSent pending
      (mem_of_mem_removeOne envelope pending before.network membership)
  · apply recordEffects_preserves_histories_active
    · constructor
      · exact wellFormed.historiesActive.openings
      · exact wellFormed.historiesActive.restarts
      · exact wellFormed.historiesActive.completed
    · exact targetActive

theorem timeout_preserves_well_formed
    {config : Config}
    {before after : State}
    {target : Location}
    (wellFormed : WellFormed config before)
    (transition : next config before (.timeout target) = some after) :
    WellFormed config after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨targetActive, system, output, systemStep, _, stateEq⟩
  rw [←stateEq]
  constructor
  · rw [recordEffects_system]
    exact (systemStep_node_keys_eq systemStep).trans
      wellFormed.nodeKeys
  · rw [recordEffects_system]
    exact systemStep_preserves_node_locations
      wellFormed.nodeLocations systemStep
  · simpa using wellFormed.activeNodup
  · simpa using wellFormed.activeConfigured
  · intro sent membership
    rw [recordEffects_sent] at membership
    exact wellFormed.sentValid sent membership
  · intro sent membership
    rw [recordEffects_sent] at membership
    rw [recordEffects_active]
    exact wellFormed.sentSourceActive sent membership
  · intro pending membership
    rw [recordEffects_network] at membership
    rw [recordEffects_sent]
    exact wellFormed.networkSent pending membership
  · apply recordEffects_preserves_histories_active
    · constructor
      · exact wellFormed.historiesActive.openings
      · exact wellFormed.historiesActive.restarts
      · exact wellFormed.historiesActive.completed
    · exact targetActive

theorem next_preserves_well_formed
    {config : Config}
    {before after : State}
    {action : Action}
    (wellFormed : WellFormed config before)
    (transition : next config before action = some after) :
    WellFormed config after := by
  cases action with
  | retry source =>
      exact retry_preserves_well_formed wellFormed transition
  | deliver envelope =>
      exact deliver_preserves_well_formed wellFormed transition
  | timeout target =>
      exact timeout_preserves_well_formed wellFormed transition

theorem reachable_well_formed
    {config : Config}
    {state : State}
    (reachable : Reachable config state) :
    WellFormed config state := by
  induction reachable with
  | initial active nodup configured =>
      exact initial_well_formed config active nodup configured
  | step reachable transition wellFormed =>
      exact next_preserves_well_formed wellFormed transition

end DisasterRecovery.Protocol.Global
