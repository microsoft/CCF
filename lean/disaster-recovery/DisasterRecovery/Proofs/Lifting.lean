module

public import DisasterRecovery.Proofs.Quorum
public import DisasterRecovery.Proofs.Local
public import DisasterRecovery.Properties.Utils
public import CCF.Execution

@[expose] public section

namespace DisasterRecovery.Proofs.Lifting

open CCF
open DisasterRecovery.Model.Local
open Execution.Local (messages)
open DisasterRecovery.Proofs.Local
attribute [local simp] StateT.run

/-- Local state and notifications retained when comparing decorated and model steps. -/
structure Result where
  /-- The local state produced by the step. -/
  state : NodeState
  /-- Host-visible notifications produced by the step. -/
  effects : List Notification := []

/-- Retains the local state and notifications of an executable model step. -/
def capture (run : NodeState × Outputs Location Message Notification) : Result :=
  { state := run.1, effects := run.2.notifications }

/-- Removes a decorated envelope's proof-only sender snapshot. -/
def eraseEnvelope (envelope : Execution.Global.Envelope) : Model.Envelope :=
  { source := envelope.source, target := envelope.target, payload := envelope.payload }

/-- Removes send snapshots and histories to recover the executable network state. -/
def erase (state : Execution.Global.State) : Model.State :=
  { nodes := state.system.nodes, network := state.network.map eraseEnvelope }

/-- Translates a decorated action into its executable model counterpart. -/
def eraseAction : Execution.Global.Action -> Model.Action
  | .retry source => .local source .retry
  | .timeout target => .local target .timeout
  | .deliver envelope => .deliver (eraseEnvelope envelope)

/-- Retains a decorated local step's state and notifications, ignoring send effects. -/
def eraseOutput (output : Execution.Local.StepOutput) : Result :=
  {
    state := output.state,
    effects := output.effects.filterMap Execution.Local.Effect.diagnostic
  }

/-- A model run reconstructed from an instrumented step for sender `source`. -/
private def toRun (source : Location) (recovered : TxID)
    (output : Execution.Local.StepOutput)
    : NodeState × Outputs Location Message Notification :=
  (
    output.state,
    {
      outgoing := messages source recovered output.effects,
      notifications := output.effects.filterMap Execution.Local.Effect.diagnostic
    }
  )

private lemma effect_guard {S : Type} (c : Prop) [Decidable c] (s : S)
    : (guard c : StateT S Option Unit) s
      = (guard c : Option Unit).map fun _ => ((), s) := by
  unfold guard
  split
  · rfl
  · exact effect_failure s

private lemma option_guard (c : Prop) [Decidable c]
    : (guard c : Option Unit) = if c then some () else none := by
  unfold guard
  rfl

private lemma messages_cons (source : Location) (recovered : TxID)
    (effect : Execution.Local.Effect) (effects : List Execution.Local.Effect)
    : messages source recovered (effect :: effects)
      = messages source recovered [effect] ++ messages source recovered effects := by
  cases effect <;> rfl

private lemma messages_map (source : Location) (recovered : TxID)
    (send : Location -> Execution.Local.Effect) (message : Message)
    (sends
      : forall target,
          messages source recovered [send target]
          = [{ source, target, payload := message }])
    (targets : List Location)
    : messages source recovered (targets.map send)
      = targets.map fun target => { source, target, payload := message } := by
  induction targets with
  | nil => rfl
  | cons head tail ih => rw [List.map_cons, messages_cons, sends, ih]; rfl

private lemma send_all_run (source : Location) (recovered : TxID) (message : Message)
    (send : Location -> Execution.Local.Effect)
    (sends
      : forall target,
          messages source recovered [send target]
          = [{ source, target, payload := message }])
    (targets : List Location) (accumulated : Outputs Location Message Notification)
    : (forIn targets PUnit.unit
          fun target (_ : PUnit) => do
            modify
              fun (outputs : Outputs Location Message Notification) =>
                {
                  outputs with
                    outgoing :=
                      outputs.outgoing ++ [{ source, target, payload := message }]
                }
            pure (ForInStep.yield PUnit.unit)
        : Effect Location Message Notification PUnit)
        accumulated
      = some
          (
            PUnit.unit,
            {
              accumulated with
                outgoing :=
                  accumulated.outgoing ++ messages source recovered (targets.map send)
            }
          ) := by
  rw [messages_map source recovered send message sends]
  induction targets generalizing accumulated with
  | nil => simp
  | cons head tail ih =>
      simp only [List.forIn_cons, effect_bind, effect_modify, Option.bind_some, effect_pure, ih,
        List.map_cons, List.append_assoc, List.singleton_append]

/-- The executable and instrumented phase advances agree, case by case, by computation. -/
private lemma advance_run (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState) (timeout : Bool)
    : advance (Capabilities.record source) config state timeout {}
      = (Execution.Local.advance config state timeout).map (toRun source recovered) := by
  rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
  unfold advance Execution.Local.advance
  cases phase <;> dsimp only
  case gossiping =>
    split
    · cases maximumGossip gossips
      · exact effect_failure _
      · rfl
    · rfl
  case joining =>
    cases chosen
    · exact effect_failure _
    · rfl
  all_goals repeat' split
  all_goals rfl

/-- Every instrumented advance is accepted and emits only notifications. -/
private lemma advance_output (config : Config) (state : NodeState) (timeout : Bool)
    (output : Execution.Local.StepOutput)
    (h : Execution.Local.advance config state timeout = some output)
    (source : Location) (recovered : TxID)
    : output.accepted = true /\ messages source recovered output.effects = [] := by
  revert h
  rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
  unfold Execution.Local.advance
  cases phase <;> dsimp only
  case gossiping =>
    split
    · cases maximumGossip gossips
      · nofun
      · rintro ⟨⟩
        exact ⟨rfl, rfl⟩
    · rintro ⟨⟩
      exact ⟨rfl, rfl⟩
  case joining =>
    cases chosen
    · nofun
    · rintro ⟨⟩
      exact ⟨rfl, rfl⟩
  all_goals repeat' split
  all_goals rintro ⟨⟩
  all_goals exact ⟨rfl, rfl⟩

private lemma advance_messages (config : Config) (state : NodeState) (timeout : Bool)
    (source : Location) (recovered : TxID) (fallback : Execution.Local.StepOutput)
    (empty : messages source recovered fallback.effects = [])
    : messages source recovered
        ((Execution.Local.advance config state timeout).getD fallback).effects
      = [] := by
  cases h : Execution.Local.advance config state timeout with
  | none => exact empty
  | some output => exact (advance_output config state timeout output h source recovered).2

private lemma orElse_rejected (source : Location) (recovered : TxID)
    (result : Option Execution.Local.StepOutput) (state : NodeState) (reason : String)
    : (result.map (toRun source recovered)
        <|> rejected (Capabilities.record source) state reason {})
      = some
          (toRun source recovered
            (result.getD (Execution.Local.rejected state reason))) := by
  cases result <;> rfl

/-- Receive events never disable the executable step; they match the instrumented step. -/
private lemma receive_run (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState) (event : Event) (notRetry : event ≠ .retry)
    (notTimeout : event ≠ .timeout)
    : (step (Capabilities.record source) config recovered state event).run {}
      = some (toRun source recovered (Execution.Local.step config state event)) := by
  rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
  unfold StateT.run
  cases event with
  | retry | timeout => contradiction
  | receiveGossip sender txid validation =>
      cases validation
      · cases chosen
        · simp (config := { decide := true }) only [step, reduceIte, effect_alternative,
            advance_run _ source recovered]
          rw [orElse_rejected]
          rfl
        · rfl
      · rfl
  | receiveVote sender validation =>
      cases validation
      · simp only [step, effect_alternative, advance_run _ source recovered]
        rw [orElse_rejected]
        rfl
      · rfl
  | receiveIAmOpen sender validation =>
      cases validation
      · cases phase
        case opening | «open» => rfl
        all_goals
          simp only [step, effect_alternative, advance_run _ source recovered]
          rw [orElse_rejected]
          rfl
      · rfl

private lemma timeout_run (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState)
    : (step (Capabilities.record source) config recovered state .timeout).run {}
      = (Execution.Local.advance config state true).map (toRun source recovered) :=
  advance_run config source recovered state true

private lemma diagnostics_map (send : Location -> Execution.Local.Effect)
    (sends : forall target, (send target).diagnostic = none) (targets : List Location)
    : (targets.map send).filterMap Execution.Local.Effect.diagnostic = [] := by
  induction targets with
  | nil => rfl
  | cons head tail ih => rw [List.map_cons, List.filterMap_cons, sends, ih]

private lemma retry_diagnostics (config : Config) (state : NodeState)
    : (Execution.Local.step config state .retry).effects.filterMap
        Execution.Local.Effect.diagnostic
      = [] := by
  rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
  cases phase
  case voting =>
    cases chosen
    · exact diagnostics_map _ (fun _ => rfl) _
    · exact diagnostics_map _ (fun _ => rfl) _
  case gossiping | opening => exact diagnostics_map _ (fun _ => rfl) _
  all_goals rfl

lemma advance_erases (config : Config) (source : Location) (state : NodeState)
    (timeout : Bool)
    : (Execution.Local.advance config state timeout).map eraseOutput
      = ((advance (Capabilities.record source) config state timeout).run {}).map
          capture := by
  unfold StateT.run
  rw [advance_run config source default, Option.map_map]
  rfl

lemma advance_accepted (config : Config) (state : NodeState) (timeout : Bool)
    (output : Execution.Local.StepOutput)
    (h : Execution.Local.advance config state timeout = some output)
    : output.accepted = true :=
  (advance_output config state timeout output h "" default).1

lemma retry_recorded (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState)
    : (step (Capabilities.record source) config recovered state .retry).run {}
      = (do
          let outgoing :=
            messages source recovered (Execution.Local.step config state .retry).effects
          guard (!outgoing.isEmpty)
          pure (state, { outgoing, notifications := [] })) := by
  rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
  rcases config with ⟨instanceId, targets⟩
  cases phase
  case gossiping =>
    cases targets <;>
      simp only [StateT.run, step, effect_bind, effect_guard, Capabilities.record,
        show (Phase.gossiping == Phase.voting) = false from rfl, Bool.false_eq_true, reduceIte,
        Option.bind_some, effect_pure,
        send_all_run source recovered (.gossip recovered) .sendGossip (fun _ => rfl)]
    all_goals rfl
  case voting =>
    cases chosen <;> cases targets <;>
      simp only [StateT.run, step, effect_bind, effect_guard, Capabilities.record,
        beq_self_eq_true, reduceIte, Option.bind_some, effect_pure,
        send_all_run source recovered (.gossip recovered) .sendGossip (fun _ => rfl)]
    all_goals rfl
  case opening =>
    simp only [StateT.run, step, effect_bind, effect_guard, Capabilities.record,
      Option.bind_some, effect_pure,
      send_all_run source recovered .iAmOpen .sendIAmOpen (fun _ => rfl),
      Execution.Local.step, Option.pure_def, Option.getD, option_guard, List.isEmpty_map,
      messages_map source recovered .sendIAmOpen .iAmOpen (fun _ => rfl)]
    split <;> rfl
  all_goals exact effect_failure (A := NodeState) _

lemma step_erases (config : Config) (recovered : TxID) (state : NodeState) (event : Event)
    {source : Location}
    (output : Result)
    (h
      : ((step (Capabilities.record source) config recovered state event).run {}).map
          capture
        = some output)
    : eraseOutput (Execution.Local.step config state event) = output := by
  cases event
  case retry =>
    rw [retry_recorded] at h
    generalize messages source recovered _ = outgoing at h
    cases outgoing <;> cases h
    show ({ state, effects := _ } : Result) = { state }
    rw [retry_diagnostics]
  case timeout =>
    rw [timeout_run _ _ recovered] at h
    cases advanced : Execution.Local.advance config state true <;>
      rw [advanced] at h <;> cases h
    show eraseOutput ((Execution.Local.advance config state true).getD _) = _
    rw [advanced]
    rfl
  all_goals
    rw [receive_run config source recovered state _ ?_ ?_] at h
    · cases h
      rfl
    all_goals nofun

lemma timeout_accepted (config : Config) (recovered : TxID) (state : NodeState)
    (output : Result) {source : Location}
    (h
      : ((step (Capabilities.record source) config recovered state .timeout).run {}).map
          capture
        = some output)
    : (Execution.Local.step config state .timeout).accepted = true := by
  rw [timeout_run _ _ recovered] at h
  cases advanced : Execution.Local.advance config state true <;>
    rw [advanced] at h <;> cases h
  show ((Execution.Local.advance config state true).getD _).accepted = true
  rw [advanced]
  exact advance_accepted config state true _ advanced

/-- Erasing snapshots can merge envelopes. Select before removing, using projected equality. -/
lemma first_matching_envelope
    (envelopes : List Execution.Global.Envelope) (envelope : Model.Envelope)
    (present : envelope ∈ envelopes.map eraseEnvelope)
    : exists decorated,
        decorated ∈ envelopes
        /\ eraseEnvelope decorated = envelope
        /\ (Execution.Global.removeOne decorated envelopes).map eraseEnvelope
            = MultiNodeTransitionSystem.removeOne envelope (envelopes.map eraseEnvelope)
        /\ envelopes.find? (fun candidate => eraseEnvelope candidate == envelope)
            = some decorated := by
  induction envelopes with
  | nil => simp at present
  | cons head tail ih =>
      by_cases first : eraseEnvelope head = envelope
      · refine ⟨head, by simp, first, ?_, ?_⟩
        · simp [Execution.Global.removeOne, MultiNodeTransitionSystem.removeOne, first]
        · simp [first]
      · have member : envelope ∈ tail.map eraseEnvelope := by
          rcases List.mem_cons.mp present with same | member
          · exact False.elim (first same.symm)
          · exact member
        rcases ih member with ⟨decorated, member, projected, removed, selected⟩
        have different : head ≠ decorated := by
          intro same
          exact first (same ▸ projected)
        refine ⟨decorated, by simp [member], projected, ?_, ?_⟩
        · simp [Execution.Global.removeOne, MultiNodeTransitionSystem.removeOne, first,
            different, removed]
        · simp [first, selected]

lemma transition_messages_empty (config : Config) (state : NodeState)
    (event : Event) (source : Location) (recovered : TxID)
    (notRetry : event ≠ .retry)
    : messages source recovered (Execution.Local.step config state event).effects
      = [] := by
  rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
  cases event with
  | retry => contradiction
  | timeout =>
      refine advance_messages config _ true source recovered _ ?_
      rfl
  | receiveGossip _ _ validation =>
      cases validation
      · cases chosen
        · refine advance_messages config _ false source recovered _ ?_
          rfl
        · rfl
      · rfl
  | receiveVote _ validation =>
      cases validation
      · refine advance_messages config _ false source recovered _ ?_
        rfl
      · rfl
  | receiveIAmOpen sender validation =>
      cases validation
      · cases phase
        case opening | «open» => rfl
        all_goals
          refine advance_messages config
            { location, phase := .joining, timeoutState, gossips, votes, chosen := some sender,
              openKind, restartRequested := restart }
            false source recovered _ ?_
          rfl
      · rfl

lemma retry_messages_erases (config : Model.Config) (source : Location)
    (state : NodeState) (recovered : TxID)
    (found : Model.recoveredTxID config source = some recovered)
    : (Execution.Global.retryMessages config source state).map eraseEnvelope
      = messages source recovered
          (Execution.Local.step config.protocol state .retry).effects := by
  unfold Execution.Global.retryMessages
  have found' : Execution.Global.recoveredTxID config source = some recovered := found
  generalize (Execution.Local.step config.protocol state .retry).effects = effects
  induction effects with
  | nil => rfl
  | cons effect tail ih =>
      rw [List.filterMap_cons, messages_cons, ← ih]
      cases effect
      case sendGossip target =>
        simp only [Execution.Global.messageForEffect, found']
        rfl
      all_goals rfl

lemma local_step_run (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState) (event : Event)
    : (step (Capabilities.record source) config recovered state event).run {}
      = (do
          let output <- ((step (Capabilities.record source)
                            config recovered state event).run
                          {}).map
                          capture
          let outgoing :=
            messages source recovered (Execution.Local.step config state event).effects
          match event with
          | .retry => guard (!outgoing.isEmpty)
          | _ => pure ()
          pure (output.state, { outgoing, notifications := output.effects })) := by
  cases event
  case retry =>
    rw [retry_recorded]
    generalize messages source recovered _ = outgoing
    cases outgoing <;> rfl
  case timeout =>
    rw [timeout_run _ _ recovered,
      transition_messages_empty config state .timeout source recovered nofun]
    cases advanced : Execution.Local.advance config state true with
    | none => rfl
    | some output =>
        simp only [Option.map_some, toRun,
          (advance_output _ _ _ output advanced source recovered).2]
        rfl
  all_goals
    rw [receive_run config source recovered state _ ?_ ?_]
    · rfl
    all_goals nofun

private lemma protocol_run (config : Model.Config) (node : Location) (state : NodeState)
    (event : Event)
    : ((Model.protocol config).step (Capabilities.record node) node state event).run {}
      = (Model.recoveredTxID config node).bind
          fun recovered =>
            (step (Capabilities.record node) config.protocol recovered state event).run
              {} := by
  simp only [Model.protocol, StateT.run, effect_bind, effect_lift]
  cases Model.recoveredTxID config node <;> rfl

lemma scheduled_step_some (config : Model.Config) (before after : Model.State)
    (node : Location) (event : Event)
    (h
      : (do
          let current <- MultiNodeTransitionSystem.nodeState before node
          let (next, effects) <- ((Model.protocol config).step (Capabilities.record node)
                                    node current event).run
                                  {}
          pure
            {
              before with
                nodes :=
                  before.nodes.map
                    fun entry => if entry.1 == node then (node, next) else entry
                network := before.network ++ effects.outgoing
            })
        = some after)
    : exists state output recovered,
        MultiNodeTransitionSystem.nodeState before node = some state
        /\ ((step (Capabilities.record node) config.protocol recovered state event).run
              {}).map
              capture
            = some output
        /\ Model.recoveredTxID config node = some recovered
        /\ (event = .retry
            -> messages node recovered
                  (Execution.Local.step config.protocol state event).effects
                ≠ [])
        /\ after
            = {
              before with
                nodes :=
                  before.nodes.map
                    fun entry => if entry.1 == node then (node, output.state) else entry
                network :=
                  before.network
                  ++ messages node recovered
                      (Execution.Local.step config.protocol state event).effects
            } := by
  obtain ⟨state, found, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨⟨next, sent⟩, run, h⟩ := Option.bind_eq_some_iff.mp h
  cases h
  rw [protocol_run] at run
  obtain ⟨recovered, recoveredFound, run⟩ := Option.bind_eq_some_iff.mp run
  rw [local_step_run] at run
  obtain ⟨output, localEnabled, rest⟩ := Option.bind_eq_some_iff.mp run
  refine ⟨state, output, recovered, found, localEnabled, recoveredFound, ?_⟩
  cases event
  case retry =>
    generalize messages node recovered _ = outgoing at rest ⊢
    cases outgoing
    · cases rest
    · cases rest
      exact ⟨fun _ => nofun, rfl⟩
  all_goals
    cases rest
    exact ⟨nofun, rfl⟩

lemma replace_found
    (nodes : List (Location × NodeState)) (node : Location) (state : NodeState)
    (nodup : (nodes.map Prod.fst).Nodup)
    (found : (nodes.find? fun entry => entry.1 == node).map Prod.snd = some state)
    : (nodes.map fun entry => if entry.1 == node then (node, state) else entry)
      = nodes := by
  rcases Option.map_eq_some_iff.mp found with ⟨entry, selected, value⟩
  have member := List.mem_of_find?_eq_some selected
  have key : entry.1 = node := beq_iff_eq.mp
    (List.find?_some (p := fun entry : Location × NodeState => entry.1 == node) selected)
  conv_rhs => rw [← List.map_id nodes]
  apply List.map_congr_left
  intro other membership
  split
  · rename_i same
    have eq : other = entry :=
      Quorum.eq_of_key_eq nodup membership member
        ((beq_iff_eq.mp same).trans key.symm)
    subst other
    exact Prod.ext key.symm value.symm
  · rfl

@[simp]
lemma erase_recordEffects (node : Location) (state : NodeState)
    (effects : List Execution.Local.Effect) (before : Execution.Global.State)
    : erase (Execution.Global.recordEffects node state effects before)
      = erase before := by
  simp [erase]

lemma systemStep_of_result (config : Model.Config)
    (before : Execution.Global.State) (node : Location) (event : Event)
    (recovered : TxID) (state : NodeState) (output : Result)
    {source : Location}
    (found : Execution.Global.nodeState before node = some state)
    (trans
      : ((step (Capabilities.record source) config.protocol recovered state event).run
          {}).map
          capture
        = some output)
    : Execution.Local.systemStep config.protocol before.system node event
      = some
          (
            {
              nodes :=
                before.system.nodes.map
                  fun entry =>
                    if entry.1 == node then (node, output.state) else entry
            },
            Execution.Local.step config.protocol state event
          ) := by
  have states := congrArg Result.state (step_erases config.protocol recovered state event output trans)
  change (Execution.Local.step config.protocol state event).state = output.state at states
  unfold Execution.Global.nodeState at found
  simp [Execution.Local.systemStep, found, states,
    Execution.Local.replaceNode]

lemma step_lifts (config : Model.Config)
    (before : Execution.Global.State) (action : Model.Action) (after : Model.State)
    (nodup : (before.system.nodes.map Prod.fst).Nodup)
    (h : (Model.transitionSystem config).step (erase before) action = some after)
    : exists decoratedAction decoratedAfter,
        eraseAction decoratedAction = action
        /\ Execution.Global.next config before decoratedAction = some decoratedAfter
        /\ erase decoratedAfter = after := by
  cases action with
  | «local» node input =>
      cases input with
      | retry =>
          rcases scheduled_step_some config (erase before) after node .retry h with
            ⟨state, output, recovered, found, trans, recoveredFound, nonempty, result⟩
          have projectedOutput := step_erases config.protocol recovered state .retry output trans
          have outputState : output.state = state :=
            (congrArg Result.state projectedOutput).symm
          have projectedMessages := retry_messages_erases config node state recovered recoveredFound
          have hasMessages
              : (Execution.Global.retryMessages config node state).isEmpty = false := by
            cases empty : Execution.Global.retryMessages config node state
            · rw [empty] at projectedMessages
              exact absurd projectedMessages.symm (nonempty rfl)
            · rfl
          refine ⟨.retry node, {
            before with
            network := before.network ++ Execution.Global.retryMessages config node state
            sent := before.sent ++ Execution.Global.retryMessages config node state
          }, rfl, ?_, ?_⟩
          · have ghostFound : Execution.Global.nodeState before node = some state := found
            have ghostRecovered : Execution.Global.recoveredTxID config node = some recovered :=
              recoveredFound
            simp only [Execution.Global.next, ghostRecovered, ghostFound, Option.bind_eq_bind,
              Option.bind_some, hasMessages]
            rfl
          · rw [result, outputState]
            have unchanged := replace_found before.system.nodes node state nodup found
            simp only [erase, unchanged, List.map_append, projectedMessages]
      | timeout =>
          rcases scheduled_step_some config (erase before) after node .timeout h with
            ⟨state, output, recovered, found, trans, recoveredFound, _, result⟩
          have system := systemStep_of_result config before node .timeout recovered state output found trans
          have accepted := timeout_accepted config.protocol recovered state output trans
          have noMessages := transition_messages_empty config.protocol state .timeout node recovered
            (by intro impossible; cases impossible)
          have ghostRecovered : Execution.Global.recoveredTxID config node = some recovered :=
            recoveredFound
          refine ⟨.timeout node,
            Execution.Global.recordEffects node
              (Execution.Local.step config.protocol state .timeout).state
              (Execution.Local.step config.protocol state .timeout).effects
              { before with system := {
                nodes := before.system.nodes.map fun entry =>
                  if entry.1 == node then (node, output.state) else entry } },
            rfl, ?_, ?_⟩
          · simp only [Execution.Global.next, ghostRecovered, system, Option.bind_eq_bind,
              Option.bind_some, accepted]
            rfl
          · rw [erase_recordEffects, result, noMessages]
            simp [erase]
  | deliver envelope =>
      dsimp only [Model.transitionSystem, MultiNodeTransitionSystem.lift,
        MultiNodeTransitionSystem.next] at h
      cases contains : (erase before).network.contains envelope <;> rw [contains] at h
      · cases h
      have membership : envelope ∈ (erase before).network := List.elem_iff.mp contains
      rcases first_matching_envelope before.network envelope membership with
        ⟨decorated, member, projected, removed, _⟩
      rcases scheduled_step_some config
          { erase before with network := MultiNodeTransitionSystem.removeOne envelope (erase before).network }
          after envelope.target (Model.receive envelope.source envelope.payload) h with
        ⟨state, output, recovered, found, trans, recoveredFound, _, result⟩
      have eventEq : Execution.Global.eventFor decorated =
          Model.receive envelope.source envelope.payload := by
        rw [← projected]
        cases decorated.payload <;> rfl
      have targetEq : decorated.target = envelope.target := congrArg CCF.Envelope.target projected
      have ghostFound : Execution.Global.nodeState before decorated.target = some state := by
        rw [targetEq]
        exact found
      have ghostTrans :
          ((step (Capabilities.record envelope.target)
            config.protocol recovered state (Execution.Global.eventFor decorated)).run {}).map capture =
          some output := by
        rw [eventEq]
        exact trans
      have system := systemStep_of_result config before decorated.target
        (Execution.Global.eventFor decorated) recovered state output ghostFound ghostTrans
      have noMessages := transition_messages_empty config.protocol state
        (Model.receive envelope.source envelope.payload) envelope.target recovered
        (by cases envelope.payload <;> nofun)
      refine ⟨
        .deliver decorated,
        Execution.Global.recordEffects decorated.target
          (Execution.Local.step config.protocol state
            (Execution.Global.eventFor decorated)).state
          (Execution.Local.step config.protocol state
            (Execution.Global.eventFor decorated)).effects
          {
            before with
              system :=
                {
                  nodes :=
                    before.system.nodes.map
                      fun entry =>
                        if entry.1 == decorated.target then
                          (decorated.target, output.state)
                        else
                          entry
                }
              network := Execution.Global.removeOne decorated before.network
          },
        congrArg MultiNodeTransitionSystem.Action.deliver projected,
        ?_,
        ?_
      ⟩
      · have ghostRecovered : Execution.Global.recoveredTxID config decorated.target =
            some recovered := by rw [targetEq]; exact recoveredFound
        simp only [Execution.Global.next, List.elem_eq_true_of_mem member, ghostRecovered,
          system, Option.bind_eq_bind, Option.bind_some]
        rfl
      · rw [erase_recordEffects, result, noMessages]
        simp [erase, removed, targetEq]

lemma empty_retry_disabled (config : Model.Config) (before : Execution.Global.State)
    (source : Location) (state : NodeState)
    (found : Execution.Global.nodeState before source = some state)
    (empty : Execution.Global.retryMessages config source state = [])
    : Execution.Global.next config before (.retry source) = none
      /\ (Model.transitionSystem config).step (erase before) (.local source .retry)
          = none := by
  constructor
  · simp [Execution.Global.next, found, empty, guard, failure]
  · cases actual
          : (Model.transitionSystem config).step (erase before)
              (.local source .retry) with
    | none => rfl
    | some after =>
        obtain ⟨current, _, recovered, selected, _, recoveredFound, nonempty, _⟩ :=
          scheduled_step_some config (erase before) after source .retry actual
        change Execution.Global.nodeState before source = some current at selected
        rw [found] at selected
        cases selected
        have projected := retry_messages_erases config source state recovered recoveredFound
        rw [empty] at projected
        exact False.elim (nonempty rfl (by simpa using projected.symm))

theorem model_initial_lifts (config : Model.Config) (state : Model.State)
    (initialized : (Model.transitionSystem config).init state)
    : exists decorated,
        (Execution.Global.transitionSystem config).init decorated
        /\ erase decorated = state := by
  rcases initialized with
    ⟨valid, covered, nodesNodup, network, nodes⟩
  have initialNodes :
      (state.nodes.map Prod.fst).map (fun node => (node, initialNode node)) =
        state.nodes := by
    rw [List.map_map]
    conv_rhs => rw [← List.map_id state.nodes]
    apply List.map_congr_left
    intro entry member
    have initialized := nodes entry member
    change entry.2 = initialNode entry.1 at initialized
    exact Prod.ext rfl initialized.symm
  refine ⟨Execution.Global.initial config (state.nodes.map Prod.fst),
    ⟨valid, _, nodesNodup, covered, rfl⟩, ?_⟩
  rcases state with ⟨nodes, network⟩
  simp_all [erase, Execution.Global.initial]

theorem model_reachable_lifts {config : Model.Config} {state : Model.State}
    (reachable : (Model.transitionSystem config).Reachable state)
    : exists decorated,
        Execution.Global.Reachable config decorated /\ erase decorated = state := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (Model.transitionSystem config) with
  | initial initialized =>
      obtain ⟨decorated, init, projected⟩ := model_initial_lifts config _ initialized
      exact ⟨decorated, .initial init, projected⟩
  | @step before after action _ transition ih =>
      obtain ⟨decorated, ghostReachable, projected⟩ := ih
      obtain ⟨ghostAction, ghostAfter, _, ghostStep, erased⟩ :=
        step_lifts config decorated action after
          (Invariants.reachable_well_formed ghostReachable).nodeKeysNodup
          (by simpa only [projected] using transition)
      exact ⟨ghostAfter, .step ghostReachable ghostStep, erased⟩

theorem model_step_lifts {config : Model.Config} {before after : Model.State}
    {action : Model.Action}
    (reachable : (Model.transitionSystem config).Reachable before)
    (transition : (Model.transitionSystem config).step before action = some after)
    : exists decoratedBefore decoratedAction decoratedAfter,
        Execution.Global.Reachable config decoratedBefore
        /\ erase decoratedBefore = before
        /\ eraseAction decoratedAction = action
        /\ Execution.Global.next config decoratedBefore decoratedAction
            = some decoratedAfter
        /\ erase decoratedAfter = after := by
  obtain ⟨decoratedBefore, ghostReachable, linked⟩ := model_reachable_lifts reachable
  obtain ⟨decoratedAction, decoratedAfter, projectedAction, ghostStep, projectedAfter⟩ :=
    step_lifts config decoratedBefore action after
      (Invariants.reachable_well_formed ghostReachable).nodeKeysNodup
      (by simpa only [linked] using transition)
  exact ⟨decoratedBefore, decoratedAction, decoratedAfter,
    ghostReachable, linked, projectedAction, ghostStep, projectedAfter⟩

open CCF.Execution (Run)

lemma execution_lifts {config : Model.Config}
    {before after : Model.State} {actions : List Model.Action}
    (run : Run (Model.transitionSystem config) before actions after)
    (decorated : Execution.Global.State)
    (reachable : Execution.Global.Reachable config decorated)
    (linked : erase decorated = before)
    : exists ghostActions ghostAfter,
        Run (Execution.Global.transitionSystem config) decorated ghostActions ghostAfter
        /\ ghostActions.map eraseAction = actions
        /\ erase ghostAfter = after := by
  induction run using @Run.rec (Model.transitionSystem config) generalizing decorated with
  | nil state =>
      exact ⟨[], decorated, .nil (system := Execution.Global.transitionSystem config) decorated,
        rfl, linked⟩
  | @cons before middle after action actions step _ ih =>
      obtain ⟨ghostAction, ghostMiddle, erasedAction, ghostStep, erasedMiddle⟩ :=
        step_lifts config decorated action middle
          (Invariants.reachable_well_formed reachable).nodeKeysNodup
          (by simpa only [linked] using step)
      obtain ⟨ghostActions, ghostAfter, ghostRun, erasedActions, erasedAfter⟩ :=
        ih ghostMiddle (.step reachable ghostStep) erasedMiddle
      exact ⟨
        ghostAction :: ghostActions,
        ghostAfter,
        .cons ghostStep ghostRun,
        by simp [erasedAction, erasedActions],
        erasedAfter
      ⟩

theorem model_execution_lifts {config : Model.Config}
    {before after : Model.State} {actions : List Model.Action}
    (reachable : (Model.transitionSystem config).Reachable before)
    (run : Run (Model.transitionSystem config) before actions after)
    : exists decoratedBefore decoratedActions decoratedAfter,
        Execution.Global.Reachable config decoratedBefore
        /\ erase decoratedBefore = before
        /\ Run (Execution.Global.transitionSystem config)
            decoratedBefore decoratedActions decoratedAfter
        /\ decoratedActions.map eraseAction = actions
        /\ erase decoratedAfter = after := by
  obtain ⟨decoratedBefore, ghostReachable, linked⟩ := model_reachable_lifts reachable
  obtain ⟨decoratedActions, decoratedAfter, ghostRun, projectedActions, projectedAfter⟩ :=
    execution_lifts run decoratedBefore ghostReachable linked
  exact ⟨decoratedBefore, decoratedActions, decoratedAfter,
    ghostReachable, linked, ghostRun, projectedActions, projectedAfter⟩

end DisasterRecovery.Proofs.Lifting
