import DisasterRecovery.Proofs.Quorum
import DisasterRecovery.Shared.Execution

namespace DisasterRecovery.Proofs.Lifting

open Shared
open DisasterRecovery.Model.Local
open Execution.Local (messages)

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

lemma advance_erases (config : Config) (state : NodeState) (timeout : Bool) :
    (Execution.Local.advance config state timeout).map eraseOutput =
      advance config state timeout := by
  simp [Execution.Local.advance, advance]
  repeat first | split | simp_all [eraseOutput, Execution.Local.Effect.diagnostic]

lemma advance_accepted (config : Config) (state : NodeState) (timeout : Bool)
    (output : Execution.Local.StepOutput)
    (h : Execution.Local.advance config state timeout = some output) :
    output.accepted = true := by
  simp [Execution.Local.advance] at h
  repeat first | split at h | simp_all | subst output

lemma transition_erases (config : Config) (state : NodeState) (event : Event)
    (output : Result)
    (h : transition config state event = some output) :
    eraseOutput (Execution.Local.step config state event) = output := by
  cases event <;> try cases_type Validation
  case retry =>
    cases phase : state.phase <;> cases chosen : state.chosen <;>
      simpa [transition, Execution.Local.step, Execution.Local.transitionSystem,
        eraseOutput, phase, chosen, List.filterMap_cons, List.filterMap_map, Function.comp_def,
        Execution.Local.Effect.diagnostic] using h
  all_goals
    simp [transition, Execution.Local.step, Execution.Local.transitionSystem,
      Execution.Local.rejectionReason, Execution.Local.rejected, rejected,
      guard, failure] at h ⊢
  all_goals
    repeat first
      | split at h
      | split
      | (simp_all [eraseOutput, Execution.Local.Effect.diagnostic])
      | (rw [← advance_erases] at h; cases ha : Execution.Local.advance _ _ _ <;>
          simp_all [eraseOutput, Execution.Local.Effect.diagnostic])

lemma timeout_accepted (config : Config) (state : NodeState) (output : Result)
    (h : transition config state .timeout = some output) :
    (Execution.Local.step config state .timeout).accepted = true := by
  have h' := advance_erases config state true
  rw [show advance config state true = some output from h] at h'
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
        Global.removeOne envelope (envelopes.map eraseEnvelope) /\
      envelopes.find? (fun candidate => eraseEnvelope candidate == envelope) =
        some decorated := by
  induction envelopes with
  | nil => simp at present
  | cons head tail ih =>
      by_cases first : eraseEnvelope head = envelope
      · refine ⟨head, by simp, first, ?_, ?_⟩
        · simp [Execution.Global.removeOne, Global.removeOne, first]
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
        · simp [Execution.Global.removeOne, Global.removeOne, first,
            different, removed]
        · simp [first, selected]

lemma transition_messages_empty (config : Config) (state : NodeState)
    (event : Event) (recovered : TxID)
    (notRetry : event ≠ .retry) :
    messages recovered (Execution.Local.step config state event).effects = [] := by
  cases event <;> try cases_type Validation
  all_goals simp [Execution.Local.step, Execution.Local.transitionSystem,
    Execution.Local.rejected, Execution.Local.advance, guard, failure]
  all_goals repeat first | split | simp_all [messages]

lemma retry_messages_erases (config : Model.Config) (source : Location)
    (state : NodeState) (recovered : TxID)
    (found : Model.recoveredTxID config source = some recovered) :
    (Execution.Global.retryMessages config source state).map eraseEnvelope =
      (messages recovered (Execution.Local.step config.protocol state .retry).effects).map
        (fun (target, payload) =>
          ({ source, target, payload } : Model.Envelope)) := by
  unfold Execution.Global.retryMessages
  have found' : Execution.Global.recoveredTxID config source = some recovered := found
  generalize (Execution.Local.step config.protocol state .retry).effects = effects
  induction effects with
  | nil => rfl
  | cons effect tail ih =>
      cases effect <;>
        simp [messages, List.filterMap_cons, Execution.Global.messageForEffect,
          found', eraseEnvelope] at ih ⊢ <;> exact ih

private lemma send_messages_run {Node Message : Type}
    (targets : List Node) (message : Message) (accumulated : List (Node × Message)) :
    (List.foldlM (m := Shared.Effect Node Message)
      (fun (_ : PUnit) target => modify (· ++ [(target, message)])) PUnit.unit targets).run accumulated =
      (PUnit.unit, accumulated ++ targets.map (fun target => (target, message))) := by
  induction targets generalizing accumulated with
  | nil => simp only [List.foldlM_nil, List.map_nil, List.append_nil]; rfl
  | cons head tail ih =>
      change (List.foldlM (m := Shared.Effect Node Message)
        (fun (_ : PUnit) target => modify (· ++ [(target, message)])) PUnit.unit tail).run
          (accumulated ++ [(head, message)]) = _
      rw [ih]
      simp

lemma local_step_run (config : Config) (recovered : TxID)
    (state : NodeState) (event : Event) :
    (step { send := fun message target => modify (· ++ [(target, message)]) }
      config recovered state event).map (fun execute => execute.run []) = (do
      let output <- transition config state event
      let outgoing := messages recovered (Execution.Local.step config state event).effects
      match event with
      | .retry => guard (!outgoing.isEmpty)
      | _ => pure ()
      pure (output.state, outgoing)) := by
  cases event with
  | retry =>
      cases phase : state.phase <;> cases chosen : state.chosen <;>
        simp [step, phase, transition, Execution.Local.step, Execution.Local.transitionSystem,
          chosen, messages, List.filterMap_map, guard, failure]
      all_goals try split
      all_goals simp_all [send_messages_run, pure]
      all_goals rfl
  | receiveGossip source txid validation =>
      rw [transition_messages_empty config state _ recovered (by intro h; cases h)]
      simp [step, bind, pure]; rfl
  | receiveVote source validation =>
      rw [transition_messages_empty config state _ recovered (by intro h; cases h)]
      simp [step, bind, pure]; rfl
  | receiveIAmOpen source validation =>
      rw [transition_messages_empty config state _ recovered (by intro h; cases h)]
      simp [step, bind, pure]; rfl
  | timeout =>
      rw [transition_messages_empty config state _ recovered (by intro h; cases h)]
      simp [step, bind, pure]; rfl

lemma model_step_run (config : Model.Config) (node : Location)
    (state : NodeState) (event : Event) :
    Global.runStep (Model.protocol config) node state event = (do
      let recovered <- Model.recoveredTxID config node
      let output <- transition config.protocol state event
      let outgoing := messages recovered (Execution.Local.step config.protocol state event).effects
      match event with
      | .retry => guard (!outgoing.isEmpty)
      | _ => pure ()
      pure (output.state, outgoing)) := by
  cases recovered : Model.recoveredTxID config node with
  | none => simp [Global.runStep, Model.protocol, recovered]
  | some txid =>
      simp only [Global.runStep, Model.protocol, recovered, bind, Option.bind_some, pure]
      calc
        _ = (step { send := fun message target => modify (· ++ [(target, message)]) }
            config.protocol txid state event).map (fun execute => execute.run []) := by
          cases step { send := fun message target => modify (· ++ [(target, message)]) }
              config.protocol txid state event <;> rfl
        _ = _ := local_step_run config.protocol txid state event

lemma runLocal_some (config : Model.Config) (before after : Model.State)
    (node : Location) (event : Event)
    (h : Global.runLocal (Model.protocol config) before node event = some after) :
    exists state output recovered,
      node ∈ before.active /\
      Model.nodeState before node = some state /\
      transition config.protocol state event = some output /\
      Model.recoveredTxID config node = some recovered /\
      (event = .retry -> messages recovered (Execution.Local.step config.protocol state event).effects ≠ []) /\
      after = {
        before with
        nodes := Global.replaceNode node output.state before.nodes
        network := before.network ++ (messages recovered
          (Execution.Local.step config.protocol state event).effects).map
          (fun (target, payload) => { source := node, target, payload })
      } := by
  simp [Global.runLocal, model_step_run,
    Option.bind_eq_some_iff, guard, failure] at h
  rcases h with ⟨active, state, found, next, sent,
    ⟨recovered, recoveredFound, output, trans, rest⟩, result⟩
  refine ⟨state, output, recovered, active, found, trans, recoveredFound, ?_⟩
  cases event <;> simp_all
  split at rest <;> simp_all

lemma replace_found
    (nodes : List (Location × NodeState)) (node : Location) (state : NodeState)
    (nodup : (nodes.map Prod.fst).Nodup)
    (found : (nodes.find? fun entry => entry.1 == node).map Prod.snd = some state) :
    Global.replaceNode node state nodes = nodes := by
  rcases Option.map_eq_some_iff.mp found with ⟨entry, selected, value⟩
  have member := List.mem_of_find?_eq_some selected
  have key : entry.1 = node := beq_iff_eq.mp
    (List.find?_some (p := fun entry : Location × NodeState => entry.1 == node) selected)
  unfold Global.replaceNode
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

lemma systemStep_of_transition (config : Model.Config)
    (before : Execution.Global.State) (node : Location) (event : Event)
    (state : NodeState) (output : Result)
    (found : Execution.Global.nodeState before node = some state)
    (trans : transition config.protocol state event = some output) :
    Execution.Local.systemStep config.protocol before.system node event =
      some (
        { nodes := Global.replaceNode node output.state before.system.nodes },
        Execution.Local.step config.protocol state event) := by
  have states := congrArg Result.state (transition_erases config.protocol state event output trans)
  change (Execution.Local.step config.protocol state event).state = output.state at states
  unfold Execution.Global.nodeState at found
  simp [Execution.Local.systemStep, found, states,
    Execution.Local.replaceNode, Global.replaceNode]

lemma step_lifts (config : Model.Config)
    (before : Execution.Global.State) (action : Model.Action) (after : Model.State)
    (nodup : (before.system.nodes.map Prod.fst).Nodup)
    (h : Model.next config (erase before) action = some after) :
    exists decoratedAction decoratedAfter,
      eraseAction decoratedAction = action /\
      Execution.Global.next config before decoratedAction = some decoratedAfter /\
      erase decoratedAfter = after := by
  cases action with
  | «local» node input =>
      cases input with
      | retry =>
          rcases runLocal_some config (erase before) after node .retry h with
            ⟨state, output, recovered, active, found, trans, recoveredFound, nonempty, result⟩
          have projectedOutput := transition_erases config.protocol state .retry output trans
          have outputState : output.state = state :=
            (congrArg Result.state projectedOutput).symm
          have projectedMessages := retry_messages_erases config node state recovered recoveredFound
          have hasMessages : Execution.Global.retryMessages config node state ≠ [] := by
            intro empty
            rw [empty] at projectedMessages
            have emptyOutput : messages recovered
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
            simp [erase, unchanged, List.map_append, projectedMessages]
      | timeout =>
          rcases runLocal_some config (erase before) after node .timeout h with
            ⟨state, output, recovered, active, found, trans, _, _, result⟩
          have system := systemStep_of_transition config before node .timeout state output found trans
          have accepted := timeout_accepted config.protocol state output trans
          have noMessages := transition_messages_empty config.protocol state .timeout recovered
            (by intro impossible; cases impossible)
          refine ⟨.timeout node,
            Execution.Global.recordEffects node
              (Execution.Local.step config.protocol state .timeout).state
              (Execution.Local.step config.protocol state .timeout).effects
              { before with system := {
                nodes := Global.replaceNode node output.state before.system.nodes } },
            rfl, ?_, ?_⟩
          · simp [Execution.Global.next, system, accepted, guard, failure,
              show node ∈ before.active from active]
          · rw [erase_recordEffects, result, noMessages]
            simp [erase]
  | deliver envelope =>
      change (do
        guard ((erase before).network.contains envelope)
        Global.runLocal (Model.protocol config)
          { erase before with network := Global.removeOne envelope (erase before).network }
          envelope.target (receive envelope.source envelope.payload)) = some after at h
      simp [guard, failure, Option.bind_eq_some_iff] at h
      rcases h with ⟨membership, localStep⟩
      rcases first_matching_envelope before.network envelope membership with
        ⟨decorated, member, projected, removed, _⟩
      rcases runLocal_some config _ after envelope.target
          (receive envelope.source envelope.payload) localStep with
        ⟨state, output, recovered, active, found, trans, _, _, result⟩
      have eventEq : Execution.Global.eventFor decorated =
          receive envelope.source envelope.payload := by
        rw [← projected]
        cases decorated.payload <;> rfl
      have targetEq : decorated.target = envelope.target := congrArg Global.Envelope.target projected
      have ghostFound : Execution.Global.nodeState before decorated.target = some state := by
        simpa [Model.nodeState, Global.nodeState, Execution.Global.nodeState,
          erase, targetEq] using found
      have ghostTrans : transition config.protocol state (Execution.Global.eventFor decorated) =
          some output := by simpa [eventEq] using trans
      have system := systemStep_of_transition config before decorated.target
        (Execution.Global.eventFor decorated) state output ghostFound ghostTrans
      have noMessages := transition_messages_empty config.protocol state
        (receive envelope.source envelope.payload) recovered
        (by cases envelope.payload <;> simp [receive])
      refine ⟨.deliver decorated,
        Execution.Global.recordEffects decorated.target
          (Execution.Local.step config.protocol state (Execution.Global.eventFor decorated)).state
          (Execution.Local.step config.protocol state (Execution.Global.eventFor decorated)).effects
          { before with
            system := { nodes := Global.replaceNode decorated.target output.state before.system.nodes }
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
    Model.next config (erase before) (.local source .retry) = none := by
  constructor
  · simp [Execution.Global.next, found, empty, guard, failure]
  · cases actual : Model.next config (erase before) (.local source .retry) with
    | none => rfl
    | some after =>
        obtain ⟨current, _, recovered, _, selected, _, recoveredFound, nonempty, _⟩ :=
          runLocal_some config (erase before) after source .retry actual
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
    (reachable : Model.Reachable config state) :
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
          (by simpa only [projected, Model.next] using transition)
      exact ⟨ghostAfter, .step ghostReachable ghostStep, erased⟩

theorem model_step_lifts {config : Model.Config} {before after : Model.State}
    {action : Model.Action}
    (reachable : Model.Reachable config before)
    (transition : Model.next config before action = some after) :
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
          (by simpa only [linked, Model.next] using step)
      obtain ⟨ghostActions, ghostAfter, ghostRun, erasedActions, erasedAfter⟩ :=
        ih ghostMiddle (.step reachable ghostStep) erasedMiddle
      exact ⟨ghostAction :: ghostActions, ghostAfter, .cons ghostStep ghostRun,
        by simp [erasedAction, erasedActions], erasedAfter⟩

theorem model_execution_lifts {config : Model.Config}
    {before after : Model.State} {actions : List Model.Action}
    (reachable : Model.Reachable config before)
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
