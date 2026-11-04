module

public import DisasterRecovery.Proofs.Predicates
public import Mathlib.Tactic.CasesM

@[expose] public section

/-!
Machine-checked proof implementations. Review the system-level statements in
`DisasterRecovery.Properties` and ghost predicates in `DisasterRecovery.Proofs.Predicates`.
-/

namespace DisasterRecovery.Proofs.Invariants

open Execution
open Execution.Local hiding Config
open Execution.Global Predicates

lemma recovered_configured
    {config : Config}
    {node : Location}
    (keys : config.recovered.map Prod.fst = config.protocol.expectedLocations)
    (found : recoveredTxID config node ≠ none)
    : node ∈ config.protocol.expectedLocations := by
  obtain ⟨txid, found⟩ := Option.ne_none_iff_exists.mp found
  obtain ⟨entry, selected, _⟩ := Option.map_eq_some_iff.mp found.symm
  have member := List.mem_of_find?_eq_some selected
  have key : entry.1 = node :=
    beq_iff_eq.mp
      (List.find?_some (p := fun entry : Location × TxID => entry.1 == node) selected)
  rw [←keys, ←key]
  exact List.mem_map_of_mem member

lemma messageForEffect_source
    {config : Config}
    {source : Location}
    {sourceState : NodeState}
    {effect : Effect}
    {envelope : Envelope}
    (created : messageForEffect config source sourceState effect = some envelope)
    : envelope.source = source /\ envelope.sourceState = sourceState := by
  cases effect with
  | sendGossip target =>
      simp only [messageForEffect, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq] at created
      obtain ⟨_, _, rfl⟩ := created
      exact ⟨rfl, rfl⟩
  | sendVote target | sendIAmOpen target =>
      cases created
      exact ⟨rfl, rfl⟩
  | opening _ | restart _ | completed | rejected _ => cases created

lemma retryMessages_source
    {config : Config}
    {source : Location}
    {sourceState : NodeState}
    {envelope : Envelope}
    (created : envelope ∈ retryMessages config source sourceState)
    : envelope.source = source /\ envelope.sourceState = sourceState := by
  rw [retryMessages, List.mem_filterMap] at created
  rcases created with ⟨effect, _, produced⟩
  exact messageForEffect_source produced

lemma retryMessages_valid
    (config : Config)
    (source : Location)
    (sourceState : NodeState)
    (sourceLocation : sourceState.location = source)
    : forall envelope,
        envelope ∈ retryMessages config source sourceState -> envelope.Valid config := by
  intro envelope created
  rcases retryMessages_source created with
    ⟨sourceEq, stateEq⟩
  constructor
  · rw [stateEq, sourceEq]
    exact sourceLocation
  · rw [sourceEq, stateEq]
    exact created

lemma valid_envelope_effect
    {config : Config}
    {envelope : Envelope}
    (valid : envelope.Valid config)
    : exists effect,
        effect ∈ (step config.protocol envelope.sourceState .retry).effects
        /\ messageForEffect config envelope.source envelope.sourceState effect
            = some envelope := by
  rcases valid with ⟨_, created⟩
  rw [retryMessages, List.mem_filterMap] at created
  exact created

lemma valid_gossip_uses_recovered_txid
    {config : Config}
    {envelope : Envelope}
    {txid : TxID}
    (valid : envelope.Valid config)
    (gossip : envelope.payload = .gossip txid)
    : recoveredTxID config envelope.source = some txid := by
  rcases valid_envelope_effect valid with
    ⟨effect, _, created⟩
  cases effect with
  | sendGossip target =>
      simp only [messageForEffect, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq] at created
      obtain ⟨recovered, found, created⟩ := created
      rw [← created] at gossip
      cases gossip
      exact found
  | sendVote target | sendIAmOpen target =>
      rw [← Option.some.inj created] at gossip
      cases gossip
  | opening _ | restart _ | completed | rejected _ => cases created

private lemma lane_location (state : NodeState) (timeout : Bool)
    : (advanceTimeoutLane state timeout).location = state.location := by
  cases timeout <;> rfl

private lemma advance_location {config : Execution.Local.Config} {state : NodeState}
    {timeout : Bool} {output : StepOutput}
    (advanced : advance config state timeout = some output)
    : output.state.location = state.location := by
  unfold advance at advanced
  cases phase : state.phase <;> simp only [phase] at advanced
  · split at advanced
    · split at advanced
      · cases advanced
      · cases advanced
        exact lane_location _ timeout
    · cases advanced
      exact lane_location _ timeout
  · split at advanced
    · split at advanced <;> cases advanced
      · rfl
      · exact lane_location _ timeout
    · cases advanced
      exact lane_location _ timeout
  · split at advanced <;> cases advanced <;> exact lane_location _ timeout
  · split at advanced <;> cases advanced
    exact lane_location _ timeout
  · cases advanced
    exact lane_location _ timeout

lemma step_preserves_location
    (config : Execution.Local.Config)
    (state : NodeState)
    (event : Event)
    : (step config state event).state.location = state.location := by
  suffices stepped :
    forall output,
      (Execution.Local.transitionSystem config state.location).step { state } event
        = some output
      -> output.state.location = state.location by
    unfold step
    cases found
          : (Execution.Local.transitionSystem config state.location).step
              { state } event with
    | none => rfl
    | some output => exact stepped output found
  intro output stepped
  cases event with
  | receiveGossip source txid validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · exact (advance_location stepped :)
        · cases stepped
      · cases stepped
  | receiveVote source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · exact (advance_location stepped :)
      · cases stepped
  | receiveIAmOpen source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · exact advance_location (config := config) (timeout := false)
            (state := { state with phase := .joining, chosen := some source }) stepped
        · cases stepped
      · cases stepped
  | timeout => exact advance_location stepped
  | retry =>
      cases stepped
      rfl

lemma nodeState_location
    {state : State}
    {node : Location}
    {foundState : NodeState}
    (locations : forall entry, entry ∈ state.system.nodes -> entry.2.location = entry.1)
    (found : nodeState state node = some foundState)
    : foundState.location = node := by
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

lemma initial_well_formed
    (config : Config)
    (nodes : List Location)
    (valid : config.Valid)
    (nodesNodup : nodes.Nodup)
    (covered : forall node, node ∈ config.protocol.expectedLocations -> node ∈ nodes)
    : WellFormed config (initial config nodes) := by
  constructor
  · simpa [Execution.Global.initial, Function.comp_def] using covered
  · simpa [Execution.Global.initial, Function.comp_def] using nodesNodup
  · simp [Execution.Global.initial, initialNode]
  · exact valid.2.2
  · simp [Execution.Global.initial]
  · simp [Execution.Global.initial]
  · simp [Execution.Global.initial]
  · constructor <;> simp [Execution.Global.initial]

@[simp]
lemma recordEffects_system
    (node : Location)
    (nodeState : NodeState)
    (effects : List Effect)
    (state : State)
    : (recordEffects node nodeState effects state).system = state.system := by
  induction effects generalizing state with
  | nil => rfl
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      change (recordEffects node nodeState tail
                (recordEffect node nodeState state effect)).system
      = state.system
      rw [ih]
      cases effect <;> rfl

@[simp]
lemma recordEffects_network
    (node : Location)
    (nodeState : NodeState)
    (effects : List Effect)
    (state : State)
    : (recordEffects node nodeState effects state).network = state.network := by
  induction effects generalizing state with
  | nil => rfl
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      change (recordEffects node nodeState tail
                (recordEffect node nodeState state effect)).network
      = state.network
      rw [ih]
      cases effect <;> rfl

@[simp]
lemma recordEffects_sent
    (node : Location)
    (nodeState : NodeState)
    (effects : List Effect)
    (state : State)
    : (recordEffects node nodeState effects state).sent = state.sent := by
  induction effects generalizing state with
  | nil => rfl
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      change (recordEffects node nodeState tail
                (recordEffect node nodeState state effect)).sent
      = state.sent
      rw [ih]
      cases effect <;> rfl

lemma recordEffect_preserves_histories_configured
    {config : Config}
    {node : Location}
    {nodeState : NodeState}
    {state : State}
    {effect : Effect}
    (wellFormed : HistoriesConfigured config state)
    (nodeConfigured : node ∈ config.protocol.expectedLocations)
    : HistoriesConfigured config (recordEffect node nodeState state effect) := by
  rcases wellFormed with ⟨openings, restarts, completed⟩
  cases effect with
  | opening kind =>
      refine ⟨fun opening member => ?_, restarts, completed⟩
      rcases List.mem_cons.mp member with rfl | old
      · exact nodeConfigured
      · exact openings opening old
  | restart chosen =>
      refine ⟨openings, fun restarted member => ?_, completed⟩
      rcases List.mem_cons.mp member with rfl | old
      · exact nodeConfigured
      · exact restarts restarted old
  | completed =>
      refine ⟨openings, restarts, fun finished member => ?_⟩
      rcases List.mem_cons.mp member with rfl | old
      · exact nodeConfigured
      · exact completed finished old
  | sendGossip | sendVote | sendIAmOpen | rejected =>
      exact ⟨openings, restarts, completed⟩

lemma recordEffects_preserves_histories_configured
    {config : Config}
    {node : Location}
    {nodeState : NodeState}
    {effects : List Effect}
    {state : State}
    (wellFormed : HistoriesConfigured config state)
    (nodeConfigured : node ∈ config.protocol.expectedLocations)
    : HistoriesConfigured config (recordEffects node nodeState effects state) := by
  induction effects generalizing state with
  | nil => exact wellFormed
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      apply ih
      exact recordEffect_preserves_histories_configured wellFormed nodeConfigured

lemma mem_of_mem_removeOne {α : Type _} [BEq α] (value member : α) (values : List α)
    : member ∈ removeOne value values -> member ∈ values := by
  induction values with
  | nil => simp [removeOne]
  | cons head tail ih =>
      simp only [removeOne]
      split
      · exact List.mem_cons_of_mem head
      · intro membership
        rw [List.mem_cons] at membership ⊢
        exact membership.imp_right ih

lemma mem_openings_recordEffect
    {node : Location}
    {nodeState : NodeState}
    {state : State}
    {effect : Effect}
    {opening : Opening}
    (membership : opening ∈ state.openings)
    : opening ∈ (recordEffect node nodeState state effect).openings := by
  cases effect <;> first | exact List.mem_cons_of_mem _ membership | exact membership

lemma mem_restarts_recordEffect
    {node : Location}
    {nodeState : NodeState}
    {state : State}
    {effect : Effect}
    {restart : Location}
    (membership : restart ∈ state.restarts)
    : restart ∈ (recordEffect node nodeState state effect).restarts := by
  cases effect <;> first | exact List.mem_cons_of_mem _ membership | exact membership

lemma mem_completed_recordEffect
    {node : Location}
    {nodeState : NodeState}
    {state : State}
    {effect : Effect}
    {completed : Location}
    (membership : completed ∈ state.completed)
    : completed ∈ (recordEffect node nodeState state effect).completed := by
  cases effect <;> first | exact List.mem_cons_of_mem _ membership | exact membership

lemma mem_openings_recordEffects
    {node : Location}
    {nodeState : NodeState}
    {state : State}
    {effects : List Effect}
    {opening : Opening}
    (membership : opening ∈ state.openings)
    : opening ∈ (recordEffects node nodeState effects state).openings := by
  induction effects generalizing state with
  | nil => exact membership
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      exact ih (mem_openings_recordEffect membership)

lemma mem_restarts_recordEffects
    {node : Location}
    {nodeState : NodeState}
    {state : State}
    {effects : List Effect}
    {restart : Location}
    (membership : restart ∈ state.restarts)
    : restart ∈ (recordEffects node nodeState effects state).restarts := by
  induction effects generalizing state with
  | nil => exact membership
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      exact ih (mem_restarts_recordEffect membership)

lemma mem_completed_recordEffects
    {node : Location}
    {nodeState : NodeState}
    {state : State}
    {effects : List Effect}
    {completed : Location}
    (membership : completed ∈ state.completed)
    : completed ∈ (recordEffects node nodeState effects state).completed := by
  induction effects generalizing state with
  | nil => exact membership
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      exact ih (mem_completed_recordEffect membership)

lemma replaceNode_keys
    (target : Location)
    (nextState : NodeState)
    (nodes : List (Prod Location NodeState))
    : (replaceNode target nextState nodes).map Prod.fst = nodes.map Prod.fst := by
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

lemma replaceNode_locations
    (target : Location)
    (nextState : NodeState)
    (nodes : List (Prod Location NodeState))
    (locations : forall entry, entry ∈ nodes -> entry.2.location = entry.1)
    (nextLocation : nextState.location = target)
    : forall entry,
        entry ∈ replaceNode target nextState nodes -> entry.2.location = entry.1 := by
  intro entry membership
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · exact nextLocation
  · exact locations previous previousMember

lemma findNode_replaceNode_ne
    (target other : Location)
    (nextState : NodeState)
    (nodes : List (Prod Location NodeState))
    (different : other ≠ target)
    : ((replaceNode target nextState nodes).find? fun entry => entry.1 == other).map
        Prod.snd
      = (nodes.find? fun entry => entry.1 == other).map Prod.snd := by
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
  cases found
        : List.find?
            (fun entry : Prod Location NodeState =>
              entry.1 == other)
            nodes with
  | none => simp
  | some entry =>
      have condition :
          (entry.1 == other) = true :=
        List.find?_some
          (p := fun entry : Prod Location NodeState =>
            entry.1 == other) found
      have entryOther : entry.1 = other :=
        beq_iff_eq.mp condition
      have notTarget : entry.1 ≠ target := by simpa [entryOther] using different
      simp [replace, notTarget]

lemma systemStep_node_keys_eq
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (transition : systemStep config before target event = some (after, output))
    : after.nodes.map Prod.fst = before.nodes.map Prod.fst := by
  simp only [systemStep, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.map_eq_some_iff,
    Option.pure_def, Option.some.injEq, Prod.mk.injEq] at transition
  rcases transition with ⟨node, _, stateEq, _⟩
  rw [←stateEq]
  exact replaceNode_keys target
    (step config node event).state before.nodes

lemma systemStep_preserves_node_locations
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (locations : forall entry, entry ∈ before.nodes -> entry.2.location = entry.1)
    (transition : systemStep config before target event = some (after, output))
    : forall entry, entry ∈ after.nodes -> entry.2.location = entry.1 := by
  simp only [systemStep, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.map_eq_some_iff,
    Option.pure_def, Option.some.injEq, Prod.mk.injEq] at transition
  rcases transition with
    ⟨_, ⟨⟨key, node⟩, found, rfl⟩, stateEq, _⟩
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

lemma systemStep_other_node_eq
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target other : Location}
    {event : Event}
    {output : StepOutput}
    (different : other ≠ target)
    (transition : systemStep config before target event = some (after, output))
    : (after.nodes.find? fun entry => entry.1 == other).map Prod.snd
      = (before.nodes.find? fun entry => entry.1 == other).map Prod.snd := by
  simp only [systemStep, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.map_eq_some_iff,
    Option.pure_def, Option.some.injEq, Prod.mk.injEq] at transition
  rcases transition with ⟨node, _, stateEq, _⟩
  rw [←stateEq]
  exact findNode_replaceNode_ne target other
    (step config node event).state before.nodes different

private lemma retry_cases
    {config : Config}
    {before after : State}
    {source : Location}
    (transition : next config before (.retry source) = some after)
    : (recoveredTxID config source).isSome = true
      /\ exists sourceState,
          nodeState before source = some sourceState
          /\ {
                  before with
                    network := before.network ++ retryMessages config source sourceState
                    sent := before.sent ++ retryMessages config source sourceState
                }
              = after := by
  simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
    Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
    and_true] at transition
  obtain ⟨recovered, sourceState, found, _, rfl⟩ := transition
  exact ⟨recovered, sourceState, found, rfl⟩

private lemma deliver_cases
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (transition : next config before (.deliver envelope) = some after)
    : envelope ∈ before.network
      /\ (recoveredTxID config envelope.target).isSome = true
      /\ exists system output,
          systemStep config.protocol before.system envelope.target (eventFor envelope)
            = some (system, output)
          /\ recordEffects envelope.target output.state output.effects
                { before with system, network := removeOne envelope before.network }
              = after := by
  simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
    Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some,
    List.contains_iff_mem, exists_const, and_true] at transition
  obtain ⟨pending, recovered, ⟨system, output⟩, stepped, rfl⟩ := transition
  exact ⟨pending, recovered, system, output, stepped, rfl⟩

private lemma timeout_cases
    {config : Config}
    {before after : State}
    {target : Location}
    (transition : next config before (.timeout target) = some after)
    : (recoveredTxID config target).isSome = true
      /\ exists system output,
          systemStep config.protocol before.system target .timeout = some (system, output)
          /\ output.accepted = true
          /\ recordEffects target output.state output.effects { before with system }
              = after := by
  simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
    Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
    and_true] at transition
  obtain ⟨recovered, ⟨system, output⟩, stepped, accepted, rfl⟩ := transition
  exact ⟨recovered, system, output, stepped, accepted, rfl⟩

lemma next_node_keys_eq
    {config : Config}
    {before after : State}
    {action : Action}
    (transition : next config before action = some after)
    : after.system.nodes.map Prod.fst = before.system.nodes.map Prod.fst := by
  cases action with
  | retry source =>
      obtain ⟨_, sourceState, _, rfl⟩ := retry_cases transition
      rfl
  | deliver envelope =>
      obtain ⟨_, _, system, output, systemStep, rfl⟩ := deliver_cases transition
      simpa using systemStep_node_keys_eq systemStep
  | timeout target =>
      obtain ⟨_, system, output, systemStep, _, rfl⟩ := timeout_cases transition
      simpa using systemStep_node_keys_eq systemStep

lemma retry_system_eq
    {config : Config}
    {before after : State}
    {source : Location}
    (transition : next config before (.retry source) = some after)
    : after.system = before.system := by
  obtain ⟨_, sourceState, _, rfl⟩ := retry_cases transition
  rfl

lemma deliver_network_eq
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (transition : next config before (.deliver envelope) = some after)
    : after.network = removeOne envelope before.network := by
  obtain ⟨_, _, system, output, _, rfl⟩ := deliver_cases transition
  simp

lemma timeout_network_eq
    {config : Config}
    {before after : State}
    {target : Location}
    (transition : next config before (.timeout target) = some after)
    : after.network = before.network := by
  obtain ⟨_, system, output, _, _, rfl⟩ := timeout_cases transition
  simp

lemma deliver_other_node_eq
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    {other : Location}
    (different : other ≠ envelope.target)
    (transition : next config before (.deliver envelope) = some after)
    : nodeState after other = nodeState before other := by
  obtain ⟨_, _, system, output, systemStep, stateEq⟩ := deliver_cases transition
  rw [←stateEq]
  simp only [nodeState, recordEffects_system]
  exact systemStep_other_node_eq different systemStep

lemma timeout_other_node_eq
    {config : Config}
    {before after : State}
    {target other : Location}
    (different : other ≠ target)
    (transition : next config before (.timeout target) = some after)
    : nodeState after other = nodeState before other := by
  obtain ⟨_, system, output, systemStep, _, stateEq⟩ := timeout_cases transition
  rw [←stateEq]
  simp only [nodeState, recordEffects_system]
  exact systemStep_other_node_eq different systemStep

lemma next_sent_extends
    {config : Config}
    {before after : State}
    {action : Action}
    (transition : next config before action = some after)
    : exists added, after.sent = before.sent ++ added := by
  cases action with
  | retry source =>
      obtain ⟨_, sourceState, _, rfl⟩ := retry_cases transition
      exact ⟨retryMessages config source sourceState, rfl⟩
  | deliver envelope =>
      obtain ⟨_, _, system, output, _, rfl⟩ := deliver_cases transition
      refine ⟨[], ?_⟩
      simp
  | timeout target =>
      obtain ⟨_, system, output, _, _, rfl⟩ := timeout_cases transition
      refine ⟨[], ?_⟩
      simp

lemma next_openings_monotonic
    {config : Config}
    {before after : State}
    {action : Action}
    (transition : next config before action = some after)
    : forall opening, opening ∈ before.openings -> opening ∈ after.openings := by
  intro opening membership
  cases action with
  | retry source =>
      obtain ⟨_, sourceState, _, rfl⟩ := retry_cases transition
      exact membership
  | deliver envelope =>
      obtain ⟨_, _, system, output, _, rfl⟩ := deliver_cases transition
      apply mem_openings_recordEffects
      simpa using membership
  | timeout target =>
      obtain ⟨_, system, output, _, _, rfl⟩ := timeout_cases transition
      apply mem_openings_recordEffects
      simpa using membership

lemma next_restarts_monotonic
    {config : Config}
    {before after : State}
    {action : Action}
    (transition : next config before action = some after)
    : forall restart, restart ∈ before.restarts -> restart ∈ after.restarts := by
  intro restart membership
  cases action with
  | retry source =>
      obtain ⟨_, sourceState, _, rfl⟩ := retry_cases transition
      exact membership
  | deliver envelope =>
      obtain ⟨_, _, system, output, _, rfl⟩ := deliver_cases transition
      apply mem_restarts_recordEffects
      simpa using membership
  | timeout target =>
      obtain ⟨_, system, output, _, _, rfl⟩ := timeout_cases transition
      apply mem_restarts_recordEffects
      simpa using membership

lemma next_completed_monotonic
    {config : Config}
    {before after : State}
    {action : Action}
    (transition : next config before action = some after)
    : forall completed, completed ∈ before.completed -> completed ∈ after.completed := by
  intro completed membership
  cases action with
  | retry source =>
      obtain ⟨_, sourceState, _, rfl⟩ := retry_cases transition
      exact membership
  | deliver envelope =>
      obtain ⟨_, _, system, output, _, rfl⟩ := deliver_cases transition
      apply mem_completed_recordEffects
      simpa using membership
  | timeout target =>
      obtain ⟨_, system, output, _, _, rfl⟩ := timeout_cases transition
      apply mem_completed_recordEffects
      simpa using membership

lemma retry_preserves_well_formed
    {config : Config}
    {before after : State}
    {source : Location}
    (wellFormed : WellFormed config before)
    (transition : next config before (.retry source) = some after)
    : WellFormed config after := by
  obtain ⟨sourceRecovered, sourceState, found, stateEq⟩ := retry_cases transition
  have sourceLocation : sourceState.location = source :=
    nodeState_location wellFormed.nodeLocations found
  rw [←stateEq]
  constructor
  · exact wellFormed.nodeKeys
  · exact wellFormed.nodeKeysNodup
  · exact wellFormed.nodeLocations
  · exact wellFormed.recoveredKeys
  · intro envelope membership
    rw [List.mem_append] at membership
    rcases membership with membership | membership
    · exact wellFormed.sentValid envelope membership
    · exact retryMessages_valid config source sourceState
        sourceLocation envelope membership
  · intro envelope membership
    rw [List.mem_append] at membership
    rcases membership with membership | membership
    · exact wellFormed.sentSourceConfigured envelope membership
    · rw [(retryMessages_source membership).1]
      exact recovered_configured wellFormed.recoveredKeys
        (Option.isSome_iff_ne_none.mp sourceRecovered)
  · intro envelope membership
    rw [List.mem_append] at membership ⊢
    rcases membership with membership | membership
    · exact Or.inl (wellFormed.networkSent envelope membership)
    · exact Or.inr membership
  · constructor
    · exact wellFormed.historiesConfigured.openings
    · exact wellFormed.historiesConfigured.restarts
    · exact wellFormed.historiesConfigured.completed

lemma deliver_preserves_well_formed
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config before)
    (transition : next config before (.deliver envelope) = some after)
    : WellFormed config after := by
  obtain ⟨_, targetRecovered, system, output, systemStep, stateEq⟩ := deliver_cases transition
  rw [←stateEq]
  constructor
  · simp only [recordEffects_system]
    rw [systemStep_node_keys_eq systemStep]
    exact wellFormed.nodeKeys
  · rw [recordEffects_system, systemStep_node_keys_eq systemStep]
    exact wellFormed.nodeKeysNodup
  · simp only [recordEffects_system]
    exact systemStep_preserves_node_locations
      wellFormed.nodeLocations systemStep
  · simpa using wellFormed.recoveredKeys
  · intro sent membership
    rw [recordEffects_sent] at membership
    exact wellFormed.sentValid sent membership
  · intro sent membership
    rw [recordEffects_sent] at membership
    exact wellFormed.sentSourceConfigured sent membership
  · intro pending membership
    rw [recordEffects_network] at membership
    rw [recordEffects_sent]
    exact wellFormed.networkSent pending
      (mem_of_mem_removeOne envelope pending before.network membership)
  · apply recordEffects_preserves_histories_configured
    · constructor
      · simpa using wellFormed.historiesConfigured.openings
      · simpa using wellFormed.historiesConfigured.restarts
      · simpa using wellFormed.historiesConfigured.completed
    · exact recovered_configured wellFormed.recoveredKeys
        (Option.isSome_iff_ne_none.mp targetRecovered)

lemma timeout_preserves_well_formed
    {config : Config}
    {before after : State}
    {target : Location}
    (wellFormed : WellFormed config before)
    (transition : next config before (.timeout target) = some after)
    : WellFormed config after := by
  obtain ⟨targetRecovered, system, output, systemStep, _, stateEq⟩ := timeout_cases transition
  rw [←stateEq]
  constructor
  · simp only [recordEffects_system]
    rw [systemStep_node_keys_eq systemStep]
    exact wellFormed.nodeKeys
  · rw [recordEffects_system, systemStep_node_keys_eq systemStep]
    exact wellFormed.nodeKeysNodup
  · simp only [recordEffects_system]
    exact systemStep_preserves_node_locations
      wellFormed.nodeLocations systemStep
  · simpa using wellFormed.recoveredKeys
  · intro sent membership
    rw [recordEffects_sent] at membership
    exact wellFormed.sentValid sent membership
  · intro sent membership
    rw [recordEffects_sent] at membership
    exact wellFormed.sentSourceConfigured sent membership
  · intro pending membership
    rw [recordEffects_network] at membership
    rw [recordEffects_sent]
    exact wellFormed.networkSent pending membership
  · apply recordEffects_preserves_histories_configured
    · constructor
      · simpa using wellFormed.historiesConfigured.openings
      · simpa using wellFormed.historiesConfigured.restarts
      · simpa using wellFormed.historiesConfigured.completed
    · exact recovered_configured wellFormed.recoveredKeys
        (Option.isSome_iff_ne_none.mp targetRecovered)

lemma next_preserves_well_formed
    {config : Config}
    {before after : State}
    {action : Action}
    (wellFormed : WellFormed config before)
    (transition : next config before action = some after)
    : WellFormed config after := by
  cases action with
  | retry source =>
      exact retry_preserves_well_formed wellFormed transition
  | deliver envelope =>
      exact deliver_preserves_well_formed wellFormed transition
  | timeout target =>
      exact timeout_preserves_well_formed wellFormed transition

lemma reachable_well_formed
    {config : Config}
    {state : State}
    (reachable : Reachable config state)
    : WellFormed config state := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | initial initialized =>
      rcases initialized with
        ⟨valid, nodes, nodesNodup, covered, rfl⟩
      exact initial_well_formed config nodes valid nodesNodup covered
  | step _ transition wellFormed =>
      exact next_preserves_well_formed wellFormed transition

lemma reachable_config_valid
    {config : Config}
    {state : State}
    (reachable : Reachable config state)
    : config.Valid := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | initial initialized =>
      rcases initialized with ⟨valid, _⟩
      exact valid
  | step _ _ valid => exact valid

end DisasterRecovery.Proofs.Invariants
