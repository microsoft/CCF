import DisasterRecovery.Proofs.Quorum
import DisasterRecovery.Proofs.Local
import DisasterRecovery.Properties.Utils
import DisasterRecovery.Shared.Execution

namespace DisasterRecovery.Proofs.Lifting

open Shared
open DisasterRecovery.Model.Local
open Execution.Local (messages)

structure Result where
  state : NodeState
  effects : List Notification := []

def capture (run : NodeState × Outputs Location Message Notification) : Result :=
  { state := run.1, effects := run.2.notifications }

private lemma send_messages_run {Node Message Notification : Type}
    (source : Node) (targets : List Node) (message : Message)
    (accumulated : Outputs Node Message Notification) :
    (List.foldlM (m := Shared.Effect Node Message Notification)
      (fun (_ : PUnit) target => modify fun outputs =>
        { outputs with outgoing := outputs.outgoing ++ [{ source, target, payload := message }] })
        PUnit.unit targets).run accumulated =
      (PUnit.unit, { accumulated with
        outgoing := accumulated.outgoing ++ targets.map (fun target => { source, target, payload := message }) }) := by
  induction targets generalizing accumulated with
  | nil => simp only [List.foldlM_nil, List.map_nil, List.append_nil]; rfl
  | cons head tail ih =>
      change (List.foldlM (m := Shared.Effect Node Message Notification)
        (fun (_ : PUnit) target => modify fun outputs =>
          { outputs with outgoing := outputs.outgoing ++ [{ source, target, payload := message }] })
          PUnit.unit tail).run
          { accumulated with
            outgoing := accumulated.outgoing ++ [{ source, target := head, payload := message }] } = _
      rw [ih]
      simp

lemma step_recording_appends (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState) (event : Event)
    (execute : Shared.Effect Location Message Notification NodeState)
    (pending : Outputs Location Message Notification)
    (enabled : step (Capabilities.record source) config recovered state event = some execute) :
    execute.run pending = ((execute.run {}).1, {
      outgoing := pending.outgoing ++ (execute.run {}).2.outgoing
      notifications := pending.notifications ++ (execute.run {}).2.notifications
    }) := by
  cases event <;> try cases_type Validation
  all_goals simp [step, advance, rejected, guard, failure] at enabled
  all_goals
    repeat' first
      | split at enabled
      | contradiction
      | (simp_all only [Option.some.injEq, Option.bind_some])
      | subst execute
  all_goals try simp [Capabilities.record, send_messages_run]
  all_goals try dsimp [pure, Functor.map]
  all_goals simp

def eraseEnvelope (envelope : Execution.Global.Envelope) : Model.Envelope :=
  { source := envelope.source, target := envelope.target, payload := envelope.payload }

def erase (state : Execution.Global.State) : Model.State :=
  { nodes := state.system.nodes, active := state.active,
    network := state.network.map eraseEnvelope }

def eraseAction : Execution.Global.Action -> Model.Action
  | .retry source => .local source .retry
  | .timeout target => .local target .timeout
  | .deliver envelope => .deliver (eraseEnvelope envelope)

def eraseOutput (output : Execution.Local.StepOutput) : Result :=
  { state := output.state, effects := output.effects.filterMap Execution.Local.Effect.diagnostic }

lemma advance_erases (config : Config) (source : Location) (state : NodeState) (timeout : Bool) :
    (Execution.Local.advance config state timeout).map eraseOutput =
      (advance (Capabilities.record source) config state timeout).map
        (fun execute => capture (execute.run {})) := by
  cases phase : state.phase <;> simp [Execution.Local.advance, advance, phase]
  all_goals repeat first
    | rfl
    | exact ⟨rfl, rfl⟩
    | simp_all [eraseOutput, Execution.Local.Effect.diagnostic, capture, Capabilities.record]
    | split

lemma advance_accepted (config : Config) (state : NodeState) (timeout : Bool)
    (output : Execution.Local.StepOutput)
    (h : Execution.Local.advance config state timeout = some output) :
    output.accepted = true := by
  simp [Execution.Local.advance] at h
  repeat first | split at h | simp_all | subst output

lemma step_erases (config : Config) (recovered : TxID) (state : NodeState) (event : Event)
    {source : Location}
    (output : Result)
    (h : (step (Capabilities.record source) config recovered state event).map
      (fun execute => capture (execute.run {})) = some output) :
    eraseOutput (Execution.Local.step config state event) = output := by
  cases event <;> try cases_type Validation
  case retry =>
    cases phase : state.phase <;> cases chosen : state.chosen <;>
      simp [step, phase, chosen, guard] at h
    all_goals try split at h
    all_goals try simp_all only [Option.bind_some, Option.bind_none, Option.some.injEq]
    all_goals try contradiction
    all_goals
      simp [send_messages_run, capture, Capabilities.record] at h
    all_goals change ({ state } : Result) = output at h
    all_goals
      simpa [Execution.Local.step, Execution.Local.transitionSystem,
        eraseOutput, phase, chosen, List.filterMap_cons, List.filterMap_map, Function.comp_def,
        Execution.Local.Effect.diagnostic] using h
  all_goals cases phase : state.phase
  all_goals
    simp [step, Execution.Local.step, Execution.Local.transitionSystem,
      Execution.Local.rejectionReason, Execution.Local.rejected, rejected,
      advance, Execution.Local.advance, phase, validTimeout, guard, failure] at h ⊢
  all_goals
    repeat first
      | exact h
      | (simp_all [eraseOutput, Execution.Local.Effect.diagnostic, capture, Capabilities.record])
      | split at h
      | split
      | (simp [advance, Execution.Local.advance] at h ⊢)
  all_goals first | omega | aesop (add safe (by omega))

lemma timeout_accepted (config : Config) (recovered : TxID) (state : NodeState) (output : Result)
    {source : Location}
    (h : (step (Capabilities.record source) config recovered state .timeout).map
      (fun execute => capture (execute.run {})) = some output) :
    (Execution.Local.step config state .timeout).accepted = true := by
  have h' := advance_erases config source state true
  change (advance (Capabilities.record source) config state true).map
    (fun execute => capture (execute.run {})) = some output at h
  rw [h] at h'
  cases ha : Execution.Local.advance config state true with
  | none => simp [ha] at h'
  | some result =>
      simpa [Execution.Local.step, Execution.Local.transitionSystem, ha] using
        advance_accepted config state true result ha

/-- Erasing snapshots can merge envelopes. Select before removing, using projected equality. -/
lemma first_matching_envelope
    (envelopes : List Execution.Global.Envelope) (envelope : Model.Envelope)
    (present : envelope ∈ envelopes.map eraseEnvelope) :
    exists decorated,
      decorated ∈ envelopes /\
      eraseEnvelope decorated = envelope /\
      (Execution.Global.removeOne decorated envelopes).map eraseEnvelope =
        MultiNodeTransitionSystem.removeOne envelope (envelopes.map eraseEnvelope) /\
      envelopes.find? (fun candidate => eraseEnvelope candidate == envelope) =
        some decorated := by
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
    (notRetry : event ≠ .retry) :
    messages source recovered (Execution.Local.step config state event).effects = [] := by
  cases event <;> try cases_type Validation
  all_goals simp [Execution.Local.step, Execution.Local.transitionSystem,
    Execution.Local.rejected, Execution.Local.advance, guard, failure]
  all_goals repeat first | split | simp_all [messages]

lemma retry_messages_erases (config : Model.Config) (source : Location)
    (state : NodeState) (recovered : TxID)
    (found : Model.recoveredTxID config source = some recovered) :
    (Execution.Global.retryMessages config source state).map eraseEnvelope =
      messages source recovered (Execution.Local.step config.protocol state .retry).effects := by
  unfold Execution.Global.retryMessages
  have found' : Execution.Global.recoveredTxID config source = some recovered := found
  generalize (Execution.Local.step config.protocol state .retry).effects = effects
  induction effects with
  | nil => rfl
  | cons effect tail ih =>
      cases effect <;>
        simp [messages, List.filterMap_cons, Execution.Global.messageForEffect,
          found', eraseEnvelope] at ih ⊢ <;> exact ih

lemma retry_result (config : Config) (source : Location) (recovered : TxID) (state : NodeState)
    (host : Capabilities Location Message Notification) (pending : Outputs Location Message Notification) :
    (step host config recovered state .retry).map (fun execute => (execute.run pending).1) = (do
      guard (!(messages source recovered (Execution.Local.step config state .retry).effects).isEmpty)
      pure state) := by
  cases phase : state.phase <;> cases chosen : state.chosen <;>
    simp [step, phase, chosen, Execution.Local.step, Execution.Local.transitionSystem,
      messages, List.filterMap_map, guard, failure]
  all_goals try split
  all_goals try simp_all
  all_goals rfl

lemma local_step_run (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState) (event : Event) :
    (step (Capabilities.record source)
      config recovered state event).map (fun execute => execute.run {}) = (do
      let output <- (step (Capabilities.record source)
        config recovered state event).map (fun execute => capture (execute.run {}))
      let outgoing := messages source recovered (Execution.Local.step config state event).effects
      match event with
      | .retry => guard (!outgoing.isEmpty)
      | _ => pure ()
      pure (output.state, { outgoing, notifications := output.effects })) := by
  cases event with
  | retry =>
      cases phase : state.phase <;> cases chosen : state.chosen <;>
        simp [step, phase, Execution.Local.step, Execution.Local.transitionSystem,
          chosen, messages, List.filterMap_map, guard, failure]
      all_goals try split
      all_goals simp_all [send_messages_run, pure, capture, Capabilities.record]
      all_goals rfl
  | receiveGossip sender txid validation =>
      rw [transition_messages_empty config state _ source recovered (by intro h; cases h)]
      simp [step, advance, rejected, bind, pure]
      repeat first | split | rfl
  | receiveVote sender validation =>
      rw [transition_messages_empty config state _ source recovered (by intro h; cases h)]
      simp [step, advance, rejected, bind, pure]
      repeat first | split | rfl
  | receiveIAmOpen sender validation =>
      rw [transition_messages_empty config state _ source recovered (by intro h; cases h)]
      simp [step, advance, rejected, bind, pure]
      repeat first | split | rfl
  | timeout =>
      rw [transition_messages_empty config state _ source recovered (by intro h; cases h)]
      simp [step, advance, bind, pure]
      repeat first | split | rfl

lemma retry_recorded (config : Config) (source : Location) (recovered : TxID) (state : NodeState) :
    (step (Capabilities.record source) config recovered state .retry).map
      (fun execute => execute.run {}) = (do
        let outgoing := messages source recovered (Execution.Local.step config state .retry).effects
        guard (!outgoing.isEmpty)
        pure (state, { outgoing, notifications := [] })) := by
  cases phase : state.phase <;> cases chosen : state.chosen <;>
    simp [step, phase, chosen, Execution.Local.step, Execution.Local.transitionSystem,
      messages, List.filterMap_map, guard, failure]
  all_goals try split
  all_goals simp_all [Capabilities.record, send_messages_run]
  all_goals rfl

lemma scheduled_step_some (config : Model.Config) (before after : Model.State)
    (node : Location) (event : Event)
    (h : (do
      guard (before.active.contains node)
      let current <- MultiNodeTransitionSystem.nodeState before node
      let execute <- (Model.protocol config).step (Capabilities.record node) node current event
      let (next, effects) := execute.run {}
      pure {
        before with
        nodes := before.nodes.map fun entry => if entry.1 == node then (node, next) else entry
        network := before.network ++ effects.outgoing
      }) = some after) :
    exists state output recovered,
      node ∈ before.active /\
      MultiNodeTransitionSystem.nodeState before node = some state /\
      (step (Capabilities.record node)
        config.protocol recovered state event).map (fun execute => capture (execute.run {})) = some output /\
      Model.recoveredTxID config node = some recovered /\
      (event = .retry -> messages node recovered (Execution.Local.step config.protocol state event).effects ≠ []) /\
      after = {
        before with
        nodes := before.nodes.map fun entry => if entry.1 == node then (node, output.state) else entry
        network := before.network ++ messages node recovered
          (Execution.Local.step config.protocol state event).effects
      } := by
  simp [Model.protocol, Option.bind_assoc, Option.bind_eq_some_iff, guard, failure] at h
  rcases h with ⟨active, state, found, recovered, recoveredFound, execute, enabled, result⟩
  obtain ⟨next, sent, executed⟩ :
      exists next sent, execute.run {} = (next, sent) := ⟨_, _, rfl⟩
  simp only [executed] at result
  have run : (step (Capabilities.record node)
      config.protocol recovered state event).map (fun execute => execute.run {}) = some (execute.run {}) := by
    simp [enabled]
  simp [local_step_run, executed, Option.bind_eq_some_iff, guard, failure] at run
  rcases run with ⟨localExecute, localEnabled, rest⟩
  refine ⟨state, capture (localExecute.run {}), recovered, active, found,
    by simp [localEnabled], recoveredFound, ?_⟩
  cases event <;> simp_all
  all_goals try split at rest
  all_goals try simp_all
  all_goals have values := Prod.mk.inj rest
  all_goals simp_all [capture]
  all_goals have outgoing := congrArg Outputs.outgoing values
  all_goals simp_all

lemma replace_found
    (nodes : List (Location × NodeState)) (node : Location) (state : NodeState)
    (nodup : (nodes.map Prod.fst).Nodup)
    (found : (nodes.find? fun entry => entry.1 == node).map Prod.snd = some state) :
    (nodes.map fun entry => if entry.1 == node then (node, state) else entry) = nodes := by
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
    (effects : List Execution.Local.Effect) (before : Execution.Global.State) :
    erase (Execution.Global.recordEffects node state effects before) = erase before := by
  simp [erase]

lemma systemStep_of_result (config : Model.Config)
    (before : Execution.Global.State) (node : Location) (event : Event)
    (recovered : TxID) (state : NodeState) (output : Result)
    {source : Location}
    (found : Execution.Global.nodeState before node = some state)
    (trans : (step (Capabilities.record source) config.protocol recovered state event).map
      (fun execute => capture (execute.run {})) = some output) :
    Execution.Local.systemStep config.protocol before.system node event =
      some (
        { nodes := before.system.nodes.map fun entry =>
          if entry.1 == node then (node, output.state) else entry },
        Execution.Local.step config.protocol state event) := by
  have states := congrArg Result.state (step_erases config.protocol recovered state event output trans)
  change (Execution.Local.step config.protocol state event).state = output.state at states
  unfold Execution.Global.nodeState at found
  simp [Execution.Local.systemStep, found, states,
    Execution.Local.replaceNode]

lemma step_lifts (config : Model.Config)
    (before : Execution.Global.State) (action : Model.Action) (after : Model.State)
    (nodup : (before.system.nodes.map Prod.fst).Nodup)
    (h : (Model.transitionSystem config).step (erase before) action = some after) :
    exists decoratedAction decoratedAfter,
      eraseAction decoratedAction = action /\
      Execution.Global.next config before decoratedAction = some decoratedAfter /\
      erase decoratedAfter = after := by
  cases action with
  | «local» node input =>
      cases input with
      | retry =>
          rcases scheduled_step_some config (erase before) after node .retry h with
            ⟨state, output, recovered, active, found, trans, recoveredFound, nonempty, result⟩
          have projectedOutput := step_erases config.protocol recovered state .retry output trans
          have outputState : output.state = state :=
            (congrArg Result.state projectedOutput).symm
          have projectedMessages := retry_messages_erases config node state recovered recoveredFound
          have hasMessages : Execution.Global.retryMessages config node state ≠ [] := by
            intro empty
            rw [empty] at projectedMessages
            have emptyOutput : messages node recovered
                (Execution.Local.step config.protocol state .retry).effects = [] := by
              simpa using projectedMessages.symm
            exact nonempty rfl emptyOutput
          refine ⟨.retry node, {
            before with
            network := before.network ++ Execution.Global.retryMessages config node state
            sent := before.sent ++ Execution.Global.retryMessages config node state
          }, rfl, ?_, ?_⟩
          · have ghostFound : Execution.Global.nodeState before node = some state := found
            simp [Execution.Global.next, guard, failure, hasMessages, ghostFound,
              show node ∈ before.active from active]
          · rw [result, outputState]
            have unchanged := replace_found before.system.nodes node state nodup found
            simp only [erase, unchanged, List.map_append, projectedMessages]
      | timeout =>
          rcases scheduled_step_some config (erase before) after node .timeout h with
            ⟨state, output, recovered, active, found, trans, _, _, result⟩
          have system := systemStep_of_result config before node .timeout recovered state output found trans
          have accepted := timeout_accepted config.protocol recovered state output trans
          have noMessages := transition_messages_empty config.protocol state .timeout node recovered
            (by intro impossible; cases impossible)
          refine ⟨.timeout node,
            Execution.Global.recordEffects node
              (Execution.Local.step config.protocol state .timeout).state
              (Execution.Local.step config.protocol state .timeout).effects
              { before with system := {
                nodes := before.system.nodes.map fun entry =>
                  if entry.1 == node then (node, output.state) else entry } },
            rfl, ?_, ?_⟩
          · simp [Execution.Global.next, system, accepted, guard, failure,
              show node ∈ before.active from active]
          · rw [erase_recordEffects, result, noMessages]
            simp [erase]
  | deliver envelope =>
      have membership : envelope ∈ (erase before).network := by
        by_contra absent
        simp [Model.transitionSystem, MultiNodeTransitionSystem.lift, MultiNodeTransitionSystem.next, guard, failure, absent] at h
      rcases first_matching_envelope before.network envelope membership with
        ⟨decorated, member, projected, removed, _⟩
      rcases scheduled_step_some config
          { erase before with network := MultiNodeTransitionSystem.removeOne envelope (erase before).network }
          after envelope.target (Model.GlobalHelper.receive envelope.source envelope.payload)
          (by
            simp [Model.transitionSystem, MultiNodeTransitionSystem.lift, MultiNodeTransitionSystem.next,
              membership, guard, failure, MultiNodeTransitionSystem.nodeState] at h ⊢
            exact h) with
        ⟨state, output, recovered, active, found, trans, _, _, result⟩
      have eventEq : Execution.Global.eventFor decorated =
          Model.GlobalHelper.receive envelope.source envelope.payload := by
        rw [← projected]
        cases decorated.payload <;> rfl
      have targetEq : decorated.target = envelope.target := congrArg Shared.Envelope.target projected
      have ghostFound : Execution.Global.nodeState before decorated.target = some state := by
        simpa [MultiNodeTransitionSystem.nodeState, Execution.Global.nodeState,
          erase, targetEq] using found
      have ghostTrans :
          (step (Capabilities.record envelope.target)
            config.protocol recovered state (Execution.Global.eventFor decorated)).map
              (fun execute => capture (execute.run {})) =
          some output := by simpa [eventEq] using trans
      have system := systemStep_of_result config before decorated.target
        (Execution.Global.eventFor decorated) recovered state output ghostFound ghostTrans
      have noMessages := transition_messages_empty config.protocol state
        (Model.GlobalHelper.receive envelope.source envelope.payload) envelope.target recovered
        (by cases envelope.payload <;> simp [Model.GlobalHelper.receive])
      refine ⟨.deliver decorated,
        Execution.Global.recordEffects decorated.target
          (Execution.Local.step config.protocol state (Execution.Global.eventFor decorated)).state
          (Execution.Local.step config.protocol state (Execution.Global.eventFor decorated)).effects
          { before with
            system := { nodes := before.system.nodes.map fun entry =>
              if entry.1 == decorated.target then (decorated.target, output.state) else entry }
            network := Execution.Global.removeOne decorated before.network },
        ?_, ?_, ?_⟩
      · simp [eraseAction, projected]
      · simp [Execution.Global.next, member, system, guard,
          show decorated.target ∈ before.active from targetEq ▸ active]
      · rw [erase_recordEffects, result, noMessages]
        simp [erase, removed, targetEq]

lemma empty_retry_disabled (config : Model.Config) (before : Execution.Global.State)
    (source : Location) (state : NodeState)
    (found : Execution.Global.nodeState before source = some state)
    (empty : Execution.Global.retryMessages config source state = []) :
    Execution.Global.next config before (.retry source) = none /\
    (Model.transitionSystem config).step (erase before) (.local source .retry) = none := by
  constructor
  · simp [Execution.Global.next, found, empty, guard, failure]
  · cases actual : (Model.transitionSystem config).step (erase before) (.local source .retry) with
    | none => rfl
    | some after =>
        obtain ⟨current, _, recovered, _, selected, _, recoveredFound, nonempty, _⟩ :=
          scheduled_step_some config (erase before) after source .retry actual
        change Execution.Global.nodeState before source = some current at selected
        rw [found] at selected
        cases selected
        have projected := retry_messages_erases config source state recovered recoveredFound
        rw [empty] at projected
        exact False.elim (nonempty rfl (by simpa using projected.symm))

theorem model_initial_lifts (config : Model.Config) (state : Model.State)
    (initialized : (Model.transitionSystem config).init state) :
    exists decorated,
      (Execution.Global.transitionSystem config).init decorated /\
      erase decorated = state := by
  rcases initialized with
    ⟨valid, _, keys, activeNodup, configured, network, nodes⟩
  have initialNodes :
      config.protocol.expectedLocations.map (fun node => (node, initialNode node)) =
        state.nodes := by
    rw [← keys, List.map_map]
    conv_rhs => rw [← List.map_id state.nodes]
    apply List.map_congr_left
    intro entry member
    have initialized := nodes entry member
    change entry.2 = initialNode entry.1 at initialized
    exact Prod.ext rfl initialized.symm
  refine ⟨Execution.Global.initial config state.active,
    ⟨state.active, valid, activeNodup, configured, rfl⟩, ?_⟩
  cases state
  simp_all [erase, Execution.Global.initial, Execution.Local.initialSystem]

theorem model_reachable_lifts {config : Model.Config} {state : Model.State}
    (reachable : (Model.transitionSystem config).Reachable state) :
    exists decorated,
      Execution.Global.Reachable config decorated /\
      erase decorated = state := by
  induction reachable with
  | initial initialized =>
      obtain ⟨decorated, init, projected⟩ := model_initial_lifts config _ initialized
      exact ⟨decorated, .initial init, projected⟩
  | @step before after action reachable transition ih =>
      obtain ⟨decorated, ghostReachable, projected⟩ := ih
      obtain ⟨ghostAction, ghostAfter, _, ghostStep, erased⟩ :=
        step_lifts config decorated action after
          (Invariants.reachable_well_formed ghostReachable).nodeKeysNodup
          (by simpa only [projected] using transition)
      exact ⟨ghostAfter, .step ghostReachable ghostStep, erased⟩

theorem model_step_lifts {config : Model.Config} {before after : Model.State}
    {action : Model.Action}
    (reachable : (Model.transitionSystem config).Reachable before)
    (transition : (Model.transitionSystem config).step before action = some after) :
    exists decoratedBefore decoratedAction decoratedAfter,
      Execution.Global.Reachable config decoratedBefore /\
      erase decoratedBefore = before /\
      eraseAction decoratedAction = action /\
      Execution.Global.next config decoratedBefore decoratedAction = some decoratedAfter /\
      erase decoratedAfter = after := by
  obtain ⟨decoratedBefore, ghostReachable, linked⟩ := model_reachable_lifts reachable
  obtain ⟨decoratedAction, decoratedAfter, projectedAction, ghostStep, projectedAfter⟩ :=
    step_lifts config decoratedBefore action after
      (Invariants.reachable_well_formed ghostReachable).nodeKeysNodup
      (by simpa only [linked] using transition)
  exact ⟨decoratedBefore, decoratedAction, decoratedAfter,
    ghostReachable, linked, projectedAction, ghostStep, projectedAfter⟩

open Shared.Execution (Run)

lemma execution_lifts {config : Model.Config}
    {before after : Model.State} {actions : List Model.Action}
    (run : Run (Model.transitionSystem config) before actions after)
    (decorated : Execution.Global.State)
    (reachable : Execution.Global.Reachable config decorated)
    (linked : erase decorated = before) :
    exists ghostActions ghostAfter,
      Run (Execution.Global.transitionSystem config) decorated ghostActions ghostAfter /\
      ghostActions.map eraseAction = actions /\
      erase ghostAfter = after := by
  induction run generalizing decorated with
  | nil state => exact ⟨[], decorated, .nil decorated, rfl, linked⟩
  | @cons before middle after action actions step rest ih =>
      obtain ⟨ghostAction, ghostMiddle, erasedAction, ghostStep, erasedMiddle⟩ :=
        step_lifts config decorated action middle
          (Invariants.reachable_well_formed reachable).nodeKeysNodup
          (by simpa only [linked] using step)
      obtain ⟨ghostActions, ghostAfter, ghostRun, erasedActions, erasedAfter⟩ :=
        ih ghostMiddle (.step reachable ghostStep) erasedMiddle
      exact ⟨ghostAction :: ghostActions, ghostAfter, .cons ghostStep ghostRun,
        by simp [erasedAction, erasedActions], erasedAfter⟩

theorem model_execution_lifts {config : Model.Config}
    {before after : Model.State} {actions : List Model.Action}
    (reachable : (Model.transitionSystem config).Reachable before)
    (run : Run (Model.transitionSystem config) before actions after) :
    exists decoratedBefore decoratedActions decoratedAfter,
      Execution.Global.Reachable config decoratedBefore /\
      erase decoratedBefore = before /\
      Run (Execution.Global.transitionSystem config)
        decoratedBefore decoratedActions decoratedAfter /\
      decoratedActions.map eraseAction = actions /\
      erase decoratedAfter = after := by
  obtain ⟨decoratedBefore, ghostReachable, linked⟩ := model_reachable_lifts reachable
  obtain ⟨decoratedActions, decoratedAfter, ghostRun, projectedActions, projectedAfter⟩ :=
    execution_lifts run decoratedBefore ghostReachable linked
  exact ⟨decoratedBefore, decoratedActions, decoratedAfter,
    ghostReachable, linked, ghostRun, projectedActions, projectedAfter⟩

end DisasterRecovery.Proofs.Lifting
