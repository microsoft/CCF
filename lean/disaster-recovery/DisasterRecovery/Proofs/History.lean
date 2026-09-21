import DisasterRecovery.Properties.History
import DisasterRecovery.Proofs.Lifting
import DisasterRecovery.Proofs.Committed

namespace DisasterRecovery.Proofs.History

open Shared
open Model.Local
open Properties.History
open Lifting
open Execution.Local (messages)

inductive Decoration (config : Model.Config) :
    Execution.Global.State -> List Transition -> Execution.Global.State -> Prop where
  | nil (state) : Decoration config state [] state
  | cons {before middle after} {action} {steps}
      (step : Execution.Global.next config before action = some middle)
      (rest : Decoration config middle steps after) :
      Decoration config before
        ({ before := erase before, action := eraseAction action, after := erase middle } :: steps)
        after

lemma trace_lifts {config : Model.Config} {before after : Model.State} {steps}
    (trace : Shared.Execution.Trace (Model.transitionSystem config) before steps after)
    (ghost : Execution.Global.State)
    (reachable : Execution.Global.Reachable config ghost)
    (linked : erase ghost = before) :
    exists final, Decoration config ghost steps final /\
      Execution.Global.Reachable config final /\ erase final = after := by
  induction trace generalizing ghost with
  | nil => exact ⟨ghost, .nil ghost, reachable, linked⟩
  | @cons before middle after action steps step rest ih =>
      obtain ⟨ghostAction, ghostMiddle, actionEq, ghostStep, middleEq⟩ :=
        step_lifts config ghost action middle
          (Invariants.reachable_well_formed reachable).nodeKeysNodup
          (by simpa only [linked, Model.next] using step)
      obtain ⟨final, decorated, reachableFinal, finalEq⟩ :=
        ih ghostMiddle (.step reachable ghostStep) middleEq
      refine ⟨final, ?_, reachableFinal, finalEq⟩
      simpa only [linked, actionEq, middleEq] using Decoration.cons ghostStep decorated

lemma history_lifts {config : Model.Config} {state : Model.State}
    (history : Properties.History.History config state) :
    exists initial final,
      (Execution.Global.transitionSystem config).init initial /\
      Decoration config initial history.steps final /\
      Execution.Global.Reachable config final /\ erase final = state := by
  obtain ⟨initial, initialized, linked⟩ := model_initial_lifts config _ history.initialized
  obtain ⟨final, decorated, reachable, finalEq⟩ :=
    trace_lifts history.valid initial (.initial initialized) linked
  exact ⟨initial, final, initialized, decorated, reachable, finalEq⟩

lemma retry_run_messages (config : Model.Config) (source : Location) (state : NodeState)
    (after : NodeState) (outgoing : List (Location × Message))
    (run : Global.runStep (Model.protocol config) source state .retry = some (after, outgoing)) :
    exists recovered,
      Model.recoveredTxID config source = some recovered /\
      outgoing = messages recovered (Execution.Local.step config.protocol state .retry).effects := by
  simp [model_step_run,
    Option.bind_eq_some_iff, guard, failure] at run
  rcases run with ⟨recovered, found, output, _, rest⟩
  exact ⟨recovered, found, rest.2.2.symm⟩

lemma sentAt_retry_iff {config : Model.Config} {before after : Execution.Global.State}
    {source : Location} {state : NodeState}
    (step : Execution.Global.next config before (.retry source) = some after)
    (valid : config.Valid)
    (wf : Predicates.WellFormed config before)
    (found : Execution.Global.nodeState before source = some state)
    (envelope : Execution.Global.Envelope) :
    SentAt config { before := erase before, action := .local source .retry, after := erase after }
        envelope.sourceState (eraseEnvelope envelope) <->
      envelope ∈ Execution.Global.retryMessages config source state := by
  have recoveredExists : exists recovered, Model.recoveredTxID config source = some recovered := by
    have active : source ∈ before.active := by
      simp [Execution.Global.next, guard, failure, Option.bind_eq_some_iff] at step
      exact step.1
    have configured := wf.activeConfigured source active
    rw [← valid.2.2, List.mem_map] at configured
    obtain ⟨entry, member, key⟩ := configured
    exact ⟨entry.2, Committed.recoveredTxID_of_mem valid (by simpa [← key] using member)⟩
  obtain ⟨recovered, recoveredFound⟩ := recoveredExists
  have projection := retry_messages_erases config source state recovered recoveredFound
  have nonempty : Execution.Global.retryMessages config source state ≠ [] := by
    simp [Execution.Global.next, guard, failure, Option.bind_eq_some_iff, found] at step
    exact step.2.1
  have outgoingNonempty :
      messages recovered (Execution.Local.step config.protocol state .retry).effects ≠ [] := by
    intro empty
    rw [empty] at projection
    exact nonempty (by simpa using projection)
  constructor
  · rintro ⟨action, selected, next, outgoing, run, member⟩
    have sourceEq : source = envelope.source := by simpa [eraseEnvelope] using action
    have stateEq : state = envelope.sourceState := by
      change Execution.Global.nodeState before envelope.source = some envelope.sourceState at selected
      rw [← sourceEq, found] at selected
      exact Option.some.inj selected
    obtain ⟨actual, foundActual, messagesEq⟩ := retry_run_messages config _ _ _ _ run
    change Model.recoveredTxID config envelope.source = some actual at foundActual
    rw [← sourceEq, recoveredFound] at foundActual
    cases foundActual
    rw [messagesEq, ← stateEq] at member
    have mapped : eraseEnvelope envelope ∈
        (Execution.Global.retryMessages config source state).map eraseEnvelope := by
      rw [projection, List.mem_map]
      exact ⟨(envelope.target, envelope.payload), member, by simp [eraseEnvelope, sourceEq]⟩
    obtain ⟨sent, sentMember, same⟩ := List.mem_map.mp mapped
    have snapshot := (Invariants.retryMessages_source sentMember).2
    have eq : sent = envelope := by
      cases sent
      cases envelope
      simp_all [eraseEnvelope]
    simpa [eq] using sentMember
  · intro member
    obtain ⟨sourceEq, stateEq⟩ := Invariants.retryMessages_source member
    refine ⟨by simp [eraseEnvelope, sourceEq], ?_, state,
      messages recovered (Execution.Local.step config.protocol state .retry).effects, ?_, ?_⟩
    · simpa [eraseEnvelope, sourceEq, stateEq, Model.nodeState, Global.nodeState,
        erase, Execution.Global.nodeState] using found
    · have result : transition config.protocol state .retry = some { state } := rfl
      simp [eraseEnvelope, sourceEq, stateEq, model_step_run,
        recoveredFound, result, guard, failure, outgoingNonempty]
    · have mapped : eraseEnvelope envelope ∈
          (Execution.Global.retryMessages config source state).map eraseEnvelope :=
        List.mem_map.mpr ⟨envelope, member, rfl⟩
      rw [projection, List.mem_map] at mapped
      obtain ⟨pair, present, eq⟩ := mapped
      have pairEq : pair = (envelope.target, envelope.payload) := by
        cases pair
        simp_all [eraseEnvelope]
      simpa [pairEq, eraseEnvelope] using present

lemma next_sent_iff {config : Model.Config} {before after : Execution.Global.State}
    {action : Execution.Global.Action}
    (reachable : Execution.Global.Reachable config before)
    (step : Execution.Global.next config before action = some after)
    (envelope : Execution.Global.Envelope) :
    envelope ∈ after.sent <->
      envelope ∈ before.sent \/
      SentAt config { before := erase before, action := eraseAction action, after := erase after }
        envelope.sourceState (eraseEnvelope envelope) := by
  cases action with
  | retry source =>
      have shape := step
      simp [Execution.Global.next, guard, failure, Option.bind_eq_some_iff] at shape
      obtain ⟨_, state, found, _, rfl⟩ := shape
      simp only [eraseAction]
      rw [sentAt_retry_iff step (Invariants.reachable_config_valid reachable)
        (Invariants.reachable_well_formed reachable) found envelope, List.mem_append]
  | deliver delivered =>
      simp [Execution.Global.next, guard, failure, Option.bind_eq_some_iff] at step
      obtain ⟨_, _, system, output, _, rfl⟩ := step
      simp [SentAt, eraseAction]
  | timeout target =>
      simp [Execution.Global.next, guard, failure, Option.bind_eq_some_iff] at step
      obtain ⟨_, system, output, _, _, rfl⟩ := step
      simp [SentAt, eraseAction]

lemma decoration_sent {config : Model.Config} {before after : Execution.Global.State} {steps}
    (decorated : Decoration config before steps after)
    (reachable : Execution.Global.Reachable config before)
    (envelope : Execution.Global.Envelope) :
    envelope ∈ after.sent <->
      envelope ∈ before.sent \/
      exists edge, edge ∈ steps /\ SentAt config edge envelope.sourceState (eraseEnvelope envelope) := by
  induction decorated with
  | nil => simp
  | cons step rest ih =>
      rw [ih (.step reachable step), next_sent_iff reachable step]
      simp only [List.mem_cons, or_and_right, exists_or, exists_eq_left]
      tauto

lemma decoration_active {config : Model.Config} {before after : Execution.Global.State} {steps}
    (decorated : Decoration config before steps after) :
    after.active = before.active := by
  induction decorated with
  | nil => rfl
  | cons step rest ih => exact ih.trans (Invariants.next_active_eq step)

lemma next_actor_active {config : Model.Config} {before after : Execution.Global.State}
    {action : Execution.Global.Action}
    (step : Execution.Global.next config before action = some after) :
    actor (eraseAction action) ∈ before.active := by
  cases action <;>
    simp [Execution.Global.next, guard, failure, Option.bind_eq_some_iff] at step
  · exact step.1
  · exact step.2.1
  · exact step.1

lemma decoration_actors {config : Model.Config} {before after : Execution.Global.State} {steps}
    (decorated : Decoration config before steps after) :
    forall edge, edge ∈ steps -> actor edge.action ∈ after.active := by
  induction decorated with
  | nil => simp
  | cons step rest ih =>
      intro edge member
      rcases List.mem_cons.mp member with rfl | member
      · rw [decoration_active rest, Invariants.next_active_eq step]
        exact next_actor_active step
      · exact ih edge member

lemma opening_recorded (node : Location) (state : NodeState) (effects : List Execution.Local.Effect)
    (before : Execution.Global.State) (kind : OpenKind)
    (member : .opening kind ∈ effects) :
    ({ node, kind, state } : Execution.Global.Opening) ∈
      (Execution.Global.recordEffects node state effects before).openings := by
  induction effects generalizing before with
  | nil => simp at member
  | cons effect tail ih =>
      change _ ∈ (Execution.Global.recordEffects node state tail
        (Execution.Global.recordEffect node state before effect)).openings
      rcases List.mem_cons.mp member with rfl | member
      · apply Invariants.mem_openings_recordEffects
        simp [Execution.Global.recordEffect]
      · exact ih _ member

lemma next_opening_recorded {config : Model.Config} {before after : Execution.Global.State}
    {action : Execution.Global.Action} {output : Result} {kind : OpenKind}
    (step : Execution.Global.next config before action = some after)
    (observed : OutputAt config
      { before := erase before, action := eraseAction action, after := erase after } output)
    (member : .opening kind ∈ output.effects) :
    ({ node := actor (eraseAction action), kind, state := output.state } : Execution.Global.Opening)
      ∈ after.openings := by
  obtain ⟨state, found, trans⟩ := observed
  cases action with
  | retry source =>
      simp [event, eraseAction, transition] at trans
      subst output
      simp at member
  | timeout target =>
      change Execution.Global.nodeState before target = some state at found
      change transition config.protocol state .timeout = some output at trans
      have system := systemStep_of_transition config before target .timeout state output found trans
      have projected := transition_erases config.protocol state .timeout output trans
      simp [Execution.Global.next, system, guard, failure, Option.bind_eq_some_iff] at step
      obtain ⟨_, _, rfl⟩ := step
      have effects := congrArg Result.effects projected
      have states := congrArg Result.state projected
      change (Execution.Local.step config.protocol state .timeout).effects.filterMap
        Execution.Local.Effect.diagnostic = output.effects at effects
      change (Execution.Local.step config.protocol state .timeout).state = output.state at states
      rw [← states]
      apply opening_recorded
      rw [← effects, List.mem_filterMap] at member
      obtain ⟨effect, present, diagnostic⟩ := member
      cases effect <;> simp_all [Execution.Local.Effect.diagnostic]
  | deliver envelope =>
      change Execution.Global.nodeState before envelope.target = some state at found
      change transition config.protocol state (Execution.Global.eventFor envelope) = some output at trans
      have system := systemStep_of_transition config before envelope.target
        (Execution.Global.eventFor envelope) state output found trans
      have projected := transition_erases config.protocol state (Execution.Global.eventFor envelope) output trans
      simp [Execution.Global.next, system, guard, failure, Option.bind_eq_some_iff] at step
      obtain ⟨_, _, rfl⟩ := step
      have effects := congrArg Result.effects projected
      have states := congrArg Result.state projected
      change (Execution.Local.step config.protocol state (Execution.Global.eventFor envelope)).effects.filterMap
        Execution.Local.Effect.diagnostic =
        output.effects at effects
      change (Execution.Local.step config.protocol state (Execution.Global.eventFor envelope)).state =
        output.state at states
      rw [← states]
      apply opening_recorded
      rw [← effects, List.mem_filterMap] at member
      obtain ⟨effect, present, diagnostic⟩ := member
      cases effect <;> simp_all [Execution.Local.Effect.diagnostic]

lemma decoration_openings {config : Model.Config} {before after : Execution.Global.State} {steps}
    (decorated : Decoration config before steps after) :
    forall edge, edge ∈ steps ->
      forall output, OutputAt config edge output ->
        forall kind, .opening kind ∈ output.effects ->
          ({ node := actor edge.action, kind, state := output.state } : Execution.Global.Opening)
            ∈ after.openings := by
  have carry {start finish : Execution.Global.State} {steps}
      (run : Decoration config start steps finish)
      (opening : Execution.Global.Opening) :
      opening ∈ start.openings -> opening ∈ finish.openings := by
    induction run with
    | nil => exact id
    | cons step rest ih => exact fun member => ih (Invariants.next_openings_monotonic step _ member)
  induction decorated with
  | nil => simp
  | cons step rest ih =>
      intro edge member output observed kind effect
      rcases List.mem_cons.mp member with rfl | member
      · exact carry rest _ (next_opening_recorded step observed effect)
      · exact ih edge member output observed kind effect

structure Correspondence {config : Model.Config} {state : Model.State}
    (history : Properties.History.History config state) (ghost : Execution.Global.State) : Prop where
  reachable : Execution.Global.Reachable config ghost
  projection : erase ghost = state
  sent :
    forall envelope, envelope ∈ ghost.sent <->
      Sent history envelope.sourceState (eraseEnvelope envelope)
  openings :
    forall edge, edge ∈ history.steps ->
      forall output, OutputAt config edge output ->
        forall kind, .opening kind ∈ output.effects ->
          ({ node := actor edge.action, kind, state := output.state } : Execution.Global.Opening)
            ∈ ghost.openings
  actors :
    forall edge, edge ∈ history.steps -> actor edge.action ∈ state.active

theorem history_correspondence {config : Model.Config} {state : Model.State}
    (history : Properties.History.History config state) :
    exists ghost, Correspondence history ghost := by
  obtain ⟨initial, final, initialized, decorated, reachable, linked⟩ := history_lifts history
  have initialReachable : Execution.Global.Reachable config initial := .initial initialized
  have empty : initial.sent = [] := by
    obtain ⟨active, _, _, _, rfl⟩ := initialized
    rfl
  refine ⟨final, reachable, linked, ?_, decoration_openings decorated, ?_⟩
  · intro envelope
    simpa [empty, Sent] using decoration_sent decorated initialReachable envelope
  · simpa only [← linked, erase] using decoration_actors decorated

lemma sentVote_iff {config : Model.Config} {state : Model.State}
    {history : Properties.History.History config state} {ghost : Execution.Global.State}
    (linked : Correspondence history ghost) (voter target : Location) :
    Predicates.SentVote ghost voter target <-> SentVote history voter target := by
  constructor
  · rintro ⟨envelope, member, source, destination, payload⟩
    refine ⟨envelope.sourceState, ?_⟩
    simpa [eraseEnvelope, source, destination, payload] using (linked.sent envelope).mp member
  · rintro ⟨sourceState, sent⟩
    exact ⟨{ source := voter, target, payload := .vote, sourceState },
      (linked.sent _).mpr sent, rfl, rfl, rfl⟩

theorem history_well_formed {config : Model.Config} {state : Model.State}
    (history : Properties.History.History config state) :
    Properties.History.WellFormed history := by
  obtain ⟨ghost, linked⟩ := history_correspondence history
  have wf := Invariants.reachable_well_formed linked.reachable
  constructor
  · intro sourceState envelope sent
    have member := (linked.sent {
      source := envelope.source, target := envelope.target,
      payload := envelope.payload, sourceState }).mpr sent
    exact (wf.sentValid _ member).1
  · intro sourceState envelope sent
    have member := (linked.sent {
      source := envelope.source, target := envelope.target,
      payload := envelope.payload, sourceState }).mpr sent
    simpa only [← linked.projection, erase] using wf.sentSourceActive _ member
  · intro envelope pending
    rw [← linked.projection] at pending
    obtain ⟨sent, sentPending, rfl⟩ := List.mem_map.mp pending
    exact ⟨sent.sourceState, (linked.sent sent).mp (wf.networkSent sent sentPending)⟩
  · exact linked.actors

theorem history_quorum_invariant {config : Model.Config} {state : Model.State}
    (history : Properties.History.History config state) :
    Properties.History.QuorumInvariant history := by
  obtain ⟨ghost, linked⟩ := history_correspondence history
  have invariant := Quorum.reachable_quorum_invariant linked.reachable
  have nodes : state.nodes = ghost.system.nodes := congrArg Global.State.nodes linked.projection.symm
  constructor
  · intro entry member voter vote
    exact (sentVote_iff linked voter entry.1).mp
      (invariant.votesSent entry (by simpa only [nodes] using member) voter vote)
  · intro voter first second firstVote secondVote
    exact invariant.sentVotesFunctional voter first second
      ((sentVote_iff linked voter first).mpr firstVote)
      ((sentVote_iff linked voter second).mpr secondVote)
  · intro sourceState voter target sent entry member key
    have sentMember := (linked.sent
      { source := voter, target, payload := .vote, sourceState }).mpr sent
    exact invariant.sentVoteStable _ sentMember rfl entry
      (by simpa only [nodes] using member) key
  · intro entry member voting
    exact invariant.votingSelections entry (by simpa only [nodes] using member) voting
  · intro sourceState voter target sent
    have sentMember := (linked.sent
      { source := voter, target, payload := .vote, sourceState }).mpr sent
    exact invariant.sentVotesSelected _ sentMember rfl
  · intro edge member output observed kind effect
    have valid := invariant.openingsValid _ (linked.openings edge member output observed kind effect)
    exact {
      location := valid.location
      phase := valid.phase
      openKind := valid.kind
      votesNodup := valid.votesNodup
      quorum := valid.quorum
      votesSent := fun voter member =>
        (sentVote_iff linked voter (actor edge.action)).mp (valid.votesSent voter member)
    }

end DisasterRecovery.Proofs.History
