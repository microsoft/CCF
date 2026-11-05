module

public import DisasterRecovery.Properties.Utils
public import DisasterRecovery.Proofs.History
public import DisasterRecovery.Proofs.Observed
public import DisasterRecovery.Proofs.Committed

@[expose] public section

namespace DisasterRecovery.Proofs.Gossip

open Execution
open Execution.Local hiding Config
open Execution.Global
open Invariants Quorum

/-- Gossip and votes grow monotonically, and choosing a node freezes its gossip. -/
structure Evolves (before after : NodeState) : Prop where
  /-- Previously accepted gossips remain present. -/
  gossips : before.gossips ⊆ after.gossips
  /-- Previously accepted votes remain present. -/
  votes : before.votes ⊆ after.votes
  /-- Once chosen, a node retains a choice and cannot change its gossips. -/
  frozen
    : before.chosen.isSome = true
      -> after.chosen.isSome = true /\ after.gossips = before.gossips

lemma evolves_refl (state : NodeState) : Evolves state state :=
  ⟨fun _ h => h, fun _ h => h, fun h => ⟨h, rfl⟩⟩

lemma evolves_trans {first second third : NodeState}
    (left : Evolves first second) (right : Evolves second third)
    : Evolves first third :=
  ⟨
    fun _ h => right.gossips (left.gossips h),
    fun _ h => right.votes (left.votes h),
    fun chosen => by
      obtain ⟨chosen', same⟩ := left.frozen chosen
      obtain ⟨chosen'', same'⟩ := right.frozen chosen'
      exact ⟨chosen'', same'.trans same⟩
  ⟩

lemma insertGossip_extends (source : Location) (txid : TxID)
    (gossips : List (Location × TxID))
    : gossips ⊆ insertGossip source txid gossips := by
  intro entry member
  unfold insertGossip
  split
  · exact member
  · exact (List.mergeSort_perm _ _).mem_iff.mpr (List.mem_cons_of_mem _ member)

lemma insertVote_extends (source : Location) (votes : List Location)
    : votes ⊆ insertVote source votes := by
  intro voter member
  unfold insertVote
  split
  · exact member
  · exact (List.mergeSort_perm _ _).mem_iff.mpr (List.mem_cons_of_mem _ member)

private abbrev Frame (before after : NodeState) : Prop :=
  after.gossips = before.gossips
  /\ after.votes = before.votes
  /\ (before.chosen.isSome = true -> after.chosen.isSome = true)

private lemma frame_lane {before after : NodeState} (timeout : Bool)
    (frame : Frame before after)
    : Frame before (advanceTimeoutLane after timeout) := by
  cases timeout <;> exact frame

private lemma advance_frame {config : Execution.Local.Config} {state : NodeState}
    {timeout : Bool} {output : StepOutput}
    (advanced : advance config state timeout = some output)
    : Frame state output.state := by
  unfold advance at advanced
  cases phase : state.phase <;> simp only [phase] at advanced
  · split at advanced
    · split at advanced
      · cases advanced
      · cases advanced
        exact frame_lane timeout ⟨rfl, rfl, fun _ => rfl⟩
    · cases advanced
      exact frame_lane timeout ⟨rfl, rfl, id⟩
  · split at advanced
    · split at advanced <;> cases advanced
      · exact ⟨rfl, rfl, id⟩
      · exact frame_lane timeout ⟨rfl, rfl, id⟩
    · cases advanced
      exact frame_lane timeout ⟨rfl, rfl, id⟩
  · split at advanced <;> cases advanced <;> exact frame_lane timeout ⟨rfl, rfl, id⟩
  · split at advanced <;> cases advanced
    exact frame_lane timeout ⟨rfl, rfl, id⟩
  · cases advanced
    exact frame_lane timeout ⟨rfl, rfl, id⟩

private lemma evolves_of_advance {config : Execution.Local.Config}
    {state received : NodeState} {timeout : Bool} {output : StepOutput}
    (advanced : advance config received timeout = some output)
    (gossips : state.gossips ⊆ received.gossips) (votes : state.votes ⊆ received.votes)
    (frozen
      : state.chosen.isSome = true
        -> received.chosen.isSome = true /\ received.gossips = state.gossips)
    : Evolves state output.state := by
  obtain ⟨sameGossips, sameVotes, keepsChoice⟩ := advance_frame advanced
  refine ⟨sameGossips ▸ gossips, sameVotes ▸ votes, fun chosen => ?_⟩
  obtain ⟨chosen', same⟩ := frozen chosen
  exact ⟨keepsChoice chosen', sameGossips.trans same⟩

lemma step_evolves (config : Execution.Local.Config) (state : NodeState) (event : Event)
    : Evolves state (step config state event).state := by
  suffices stepped :
    forall output,
      (Execution.Local.transitionSystem config state.location).step { state } event
        = some output
      -> Evolves state output.state by
    unfold step
    cases found
          : (Execution.Local.transitionSystem config state.location).step
              { state } event with
    | none => exact evolves_refl state
    | some output => exact stepped output found
  intro output stepped
  cases event with
  | receiveGossip source txid validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · rename_i unchosen
          refine evolves_of_advance stepped (insertGossip_extends _ _ _) (fun _ h => h)
            fun chosen => ?_
          rw [unchosen] at chosen
          cases chosen
        · cases stepped
      · cases stepped
  | receiveVote source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · exact evolves_of_advance stepped (fun _ h => h) (insertVote_extends _ _)
          fun chosen => ⟨chosen, rfl⟩
      · cases stepped
  | receiveIAmOpen source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · exact evolves_of_advance (config := config) (timeout := false)
            (received := { state with phase := .joining, chosen := some source })
            stepped (fun _ h => h) (fun _ h => h) fun _ => ⟨rfl, rfl⟩
        · cases stepped
      · cases stepped
  | timeout =>
      exact evolves_of_advance stepped (fun _ h => h) (fun _ h => h) fun chosen => ⟨chosen, rfl⟩
  | retry =>
      cases stepped
      exact evolves_refl state

/-- Every node's accepted gossip comes from the configured recovered ledger tips. -/
def Genuine (config : Config) (nodes : List (Location × NodeState)) : Prop :=
  forall entry, entry ∈ nodes -> entry.2.gossips ⊆ config.recovered

/-- An accepted gossip event carries its source's configured recovered ledger tip. -/
def EventGenuine (config : Config) : Event -> Prop
  | .receiveGossip source txid .accepted => (source, txid) ∈ config.recovered
  | _ => True

lemma insertGossip_genuine {config : Config} {state : NodeState} {source : Location}
    {txid : TxID} (prior : state.gossips ⊆ config.recovered)
    (incoming : (source, txid) ∈ config.recovered)
    : insertGossip source txid state.gossips ⊆ config.recovered := by
  intro entry member
  unfold insertGossip at member
  split at member
  · exact prior member
  · have original := (List.mergeSort_perm _ _).mem_iff.mp member
    rcases List.mem_cons.mp original with rfl | old
    · exact incoming
    · exact prior old

lemma step_genuine (config : Config) (state : NodeState) (event : Event)
    (prior : state.gossips ⊆ config.recovered) (incoming : EventGenuine config event)
    : (step config.protocol state event).state.gossips ⊆ config.recovered := by
  suffices stepped :
    forall output,
      (Execution.Local.transitionSystem config.protocol state.location).step { state }
          event
        = some output
      -> output.state.gossips ⊆ config.recovered by
    unfold step
    cases found
          : (Execution.Local.transitionSystem config.protocol state.location).step
              { state } event with
    | none => exact prior
    | some output => exact stepped output found
  intro output stepped
  cases event with
  | receiveGossip source txid validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · rename_i accepted _
          subst accepted
          rw [(advance_frame stepped).1]
          exact insertGossip_genuine prior incoming
        · cases stepped
      · cases stepped
  | receiveVote source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · rw [(advance_frame stepped).1]
        exact prior
      · cases stepped
  | receiveIAmOpen source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · rw [(advance_frame (config := config.protocol) (timeout := false)
            (state := { state with phase := .joining, chosen := some source }) stepped).1]
          exact prior
        · cases stepped
      · cases stepped
  | timeout =>
      rw [(advance_frame stepped).1]
      exact prior
  | retry =>
      cases stepped
      exact prior

lemma lookup_member {state : State} {node : Location} {current : NodeState}
    (found : nodeState state node = some current)
    : (node, current) ∈ state.system.nodes := by
  obtain ⟨entry, found, same⟩ := Option.map_eq_some_iff.mp found
  have key := beq_iff_eq.mp
    (List.find?_some found :)
  have entryEq : entry = (node, current) := Prod.ext key same
  rw [← entryEq]
  exact List.mem_of_find?_eq_some found

lemma systemStep_evolves {config : Execution.Local.Config} {before after : SystemState}
    {target : Location} {event : Event} {output : StepOutput}
    (nodup : (before.nodes.map Prod.fst).Nodup)
    (transition : systemStep config before target event = some (after, output))
    {node : Location} {current : NodeState} (member : (node, current) ∈ before.nodes)
    : exists next, (node, next) ∈ after.nodes /\ Evolves current next := by
  simp only [systemStep, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.map_eq_some_iff,
    Option.pure_def, Option.some.injEq, Prod.mk.injEq] at transition
  obtain ⟨_, ⟨⟨key, foundState⟩, found, rfl⟩, rfl, _⟩ := transition
  have foundMember := List.mem_of_find?_eq_some found
  have keyEq : key = target := beq_iff_eq.mp
    (List.find?_some found :)
  by_cases same : node = target
  · have equal := eq_of_key_eq nodup member foundMember (same.trans keyEq.symm)
    have stateEq := congrArg Prod.snd equal
    change current = foundState at stateEq
    subst foundState
    refine ⟨(step config current event).state, ?_, step_evolves config current event⟩
    exact List.mem_map.mpr ⟨(node, current), member, by simp [same]⟩
  · refine ⟨current, ?_, evolves_refl current⟩
    exact List.mem_map.mpr ⟨(node, current), member, by simp [same]⟩

lemma systemStep_genuine {config : Config} {before after : SystemState}
    {target : Location} {event : Event} {output : StepOutput}
    (prior : Genuine config before.nodes) (incoming : EventGenuine config event)
    (transition : systemStep config.protocol before target event = some (after, output))
    : Genuine config after.nodes := by
  simp only [systemStep, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.map_eq_some_iff,
    Option.pure_def, Option.some.injEq, Prod.mk.injEq] at transition
  obtain ⟨_, ⟨⟨key, current⟩, found, rfl⟩, rfl, _⟩ := transition
  intro entry member
  obtain ⟨previous, present, rfl⟩ := List.mem_map.mp member
  split
  · exact step_genuine config current event
      (prior (key, current) (List.mem_of_find?_eq_some found)) incoming
  · exact prior previous present

lemma next_evolves {config : Config} {before after : State} {action : Action}
    (wf : Predicates.WellFormed config before)
    (transition : next config before action = some after) {node : Location}
    {current : NodeState} (member : (node, current) ∈ before.system.nodes)
    : exists updated,
        (node, updated) ∈ after.system.nodes /\ Evolves current updated := by
  cases action with
  | retry source =>
      rw [retry_system_eq transition]
      exact ⟨current, member, evolves_refl current⟩
  | deliver envelope =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some,
        List.contains_iff_mem, exists_const, and_true] at transition
      obtain ⟨_, _, ⟨system, output⟩, updated, rfl⟩ := transition
      simpa only [recordEffects_system] using systemStep_evolves wf.nodeKeysNodup updated member
  | timeout target =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
        and_true] at transition
      obtain ⟨_, ⟨system, output⟩, updated, _, rfl⟩ := transition
      simpa only [recordEffects_system] using systemStep_evolves wf.nodeKeysNodup updated member

lemma next_genuine {config : Config} {before after : State} {action : Action}
    (wf : Predicates.WellFormed config before)
    (prior : Genuine config before.system.nodes)
    (transition : next config before action = some after)
    : Genuine config after.system.nodes := by
  cases action with
  | retry source =>
      simpa only [retry_system_eq transition] using prior
  | deliver envelope =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some,
        List.contains_iff_mem, exists_const, and_true] at transition
      obtain ⟨pending, _, ⟨system, output⟩, updated, rfl⟩ := transition
      have incoming : EventGenuine config (eventFor envelope) := by
        cases payload : envelope.payload with
        | vote | iAmOpen =>
            unfold eventFor
            rw [payload]
            trivial
        | gossip txid =>
            unfold eventFor
            rw [payload]
            show (envelope.source, txid) ∈ config.recovered
            have recovered := valid_gossip_uses_recovered_txid
              (wf.sentValid _ (wf.networkSent _ pending)) payload
            obtain ⟨entry, found, value⟩ := Option.map_eq_some_iff.mp recovered
            have key := beq_iff_eq.mp
              (List.find?_some found :)
            have entryEq : entry = (envelope.source, txid) := Prod.ext key value
            rw [← entryEq]
            exact List.mem_of_find?_eq_some found
      simpa only [recordEffects_system] using systemStep_genuine prior incoming updated
  | timeout target =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
        and_true] at transition
      obtain ⟨_, ⟨system, output⟩, updated, _, rfl⟩ := transition
      simpa only [recordEffects_system]
        using systemStep_genuine prior (by trivial) updated

/-- Every sent vote's snapshot still matches its sender's frozen gossip. -/
def FrozenVotes (state : State) : Prop :=
  forall envelope,
    envelope ∈ state.sent
    -> envelope.payload = .vote
    -> exists current,
        (envelope.source, current) ∈ state.system.nodes
        /\ current.chosen.isSome = true
        /\ current.gossips = envelope.sourceState.gossips

lemma next_frozen {config : Config} {before after : State} {action : Action}
    (wf : Predicates.WellFormed config before)
    (prior : FrozenVotes before)
    (transition : next config before action = some after)
    : FrozenVotes after := by
  have carry : forall envelope, envelope ∈ before.sent -> envelope.payload = .vote ->
      exists current, (envelope.source, current) ∈ after.system.nodes /\
        current.chosen.isSome = true /\ current.gossips = envelope.sourceState.gossips := by
    intro envelope sent vote
    obtain ⟨current, present, chosen, same⟩ := prior envelope sent vote
    obtain ⟨updated, present', evolves⟩ := next_evolves wf transition present
    obtain ⟨chosen', same'⟩ := evolves.frozen chosen
    exact ⟨updated, present', chosen', same'.trans same⟩
  cases action with
  | retry source =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
        and_true] at transition
      obtain ⟨_, current, found, _, rfl⟩ := transition
      intro envelope sent vote
      rcases List.mem_append.mp sent with old | fresh
      · exact carry envelope old vote
      · have snapshot := retryMessages_source fresh
        have present := lookup_member found
        have location := nodeState_location wf.nodeLocations found
        have selected := (retry_vote_state (retryMessages_valid config source current location _ fresh) vote).2
        refine ⟨current, ?_, ?_, snapshot.2.symm ▸ rfl⟩
        · simpa only [snapshot.1] using present
        · rw [← snapshot.2, selected]
          rfl
  | deliver envelope =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some,
        List.contains_iff_mem, exists_const, and_true] at transition
      obtain ⟨_, _, ⟨system, output⟩, _, rfl⟩ := transition
      simpa only [FrozenVotes, recordEffects_sent] using carry
  | timeout target =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
        and_true] at transition
      obtain ⟨_, ⟨system, output⟩, _, _, rfl⟩ := transition
      simpa only [FrozenVotes, recordEffects_sent] using carry

lemma reachable_gossip_invariant {config : Config} {state : State}
    (reachable : Reachable config state)
    : Genuine config state.system.nodes /\ FrozenVotes state := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | initial initialized =>
      obtain ⟨_, nodes, _, _, rfl⟩ := initialized
      constructor
      · intro entry member
        obtain ⟨node, _, rfl⟩ := List.mem_map.mp member
        exact List.nil_subset _
      · intro envelope sent
        cases sent
  | step reachable transition ih =>
      have wf := reachable_well_formed reachable
      exact ⟨next_genuine wf ih.1 transition, next_frozen wf ih.2 transition⟩

lemma model_step_evolves {config : Model.Config} {before after : Model.State}
    {action : Model.Action} (reachable : (Model.transitionSystem config).Reachable before)
    (transition : (Model.transitionSystem config).step before action = some after)
    {node : Location} {current : NodeState} (member : (node, current) ∈ before.nodes)
    : exists updated, (node, updated) ∈ after.nodes /\ Evolves current updated := by
  obtain ⟨ghostBefore, ghostAction, ghostAfter, reachable', projected, _, step, projected'⟩ :=
    Lifting.model_step_lifts reachable transition
  have original : (node, current) ∈ ghostBefore.system.nodes := by
    simpa only [← projected, Lifting.erase] using member
  simpa only [← projected', Lifting.erase]
    using next_evolves (reachable_well_formed reachable') step original

lemma steps_evolve {config : Model.Config} {before after : Model.State} {steps}
    (run : Trace.Path (Model.transitionSystem config) before steps after)
    (reachable : (Model.transitionSystem config).Reachable before)
    {node : Location} {current : NodeState} (member : (node, current) ∈ before.nodes)
    : exists updated, (node, updated) ∈ after.nodes /\ Evolves current updated := by
  induction run
    using @Trace.Path.rec (Model.transitionSystem config) generalizing current with
  | nil => exact ⟨current, member, evolves_refl current⟩
  | cons transition _ ih =>
      obtain ⟨middle, present, evolves⟩ := model_step_evolves reachable transition member
      obtain ⟨updated, present', evolves'⟩ := ih (.step reachable transition) present
      exact ⟨updated, present', evolves_trans evolves evolves'⟩

lemma trace_node_final {config : Model.Config} {trace : Properties.GlobalTrace config}
    {bound : Nat} {ghost : State}
    (linked : History.Correspondence config trace bound ghost) {i : Nat}
    {state : Model.State} (le : i <= bound) (found : trace.stateAt i = some state)
    {node : Location} {current : NodeState} (present : (node, current) ∈ state.nodes)
    : exists final, (node, final) ∈ ghost.system.nodes /\ Evolves current final := by
  obtain ⟨suffix, run⟩ := linked.suffix i state le found
  exact steps_evolve run (trace.reachable (CCF.Execution.Trace.stateAt_mem found)) present

lemma quorum_notification_final_votes {config : Model.Config}
    {trace : Properties.GlobalTrace config} {bound : Nat} {ghost : State}
    (linked : History.Correspondence config trace bound ghost) {index : Nat}
    (le : index + 1 <= bound) {node : Location}
    (notification
      : Properties.Trace.NotificationAt config trace index node (.opening .quorum))
    : exists final,
        (node, final) ∈ ghost.system.nodes
        /\ voteQuorum config.protocol <= final.votes.length := by
  obtain ⟨after, current, inTrace, present, opened⟩ :=
    Observed.notification_opening_state notification
  obtain ⟨atOpening, openingReachable, projected⟩ :=
    Lifting.model_reachable_lifts (trace.reachable (CCF.Execution.Trace.stateAt_mem inTrace))
  have openingPresent : (node, current) ∈ atOpening.system.nodes := by
    simpa only [← projected, Lifting.erase] using present
  have nodup := (reachable_quorum_invariant openingReachable).votesNodup _ openingPresent
  have threshold := Observed.reachable_quorum_thresholds openingReachable _ openingPresent opened
  obtain ⟨final, finalMember, evolves⟩ := trace_node_final linked le inTrace present
  have subset : current.votes.toFinset ⊆ final.votes.toFinset := by
    intro voter member
    exact List.mem_toFinset.mpr (evolves.votes (List.mem_toFinset.mp member))
  have count := Finset.card_le_card subset
  rw [List.toFinset_card_of_nodup nodup] at count
  exact ⟨final, finalMember, threshold.trans (count.trans (List.toFinset_card_le _))⟩

/-- `node` has accepted gossip from itself in a trace state up to `bound`. -/
def OwnGossipBy {config : Model.Config} (trace : Properties.GlobalTrace config)
    (bound : Nat) (node : Location)
    : Prop :=
  exists i state,
    i <= bound
    /\ trace.stateAt i = some state
    /\ exists nodeState txid,
        (node, nodeState) ∈ state.nodes /\ (node, txid) ∈ nodeState.gossips

lemma sent_vote_preserves_own {config : Config} {trace : Properties.GlobalTrace config}
    {bound : Nat} {ghost : State}
    (linked : History.Correspondence config trace bound ghost) {envelope : Envelope}
    (sent : envelope ∈ ghost.sent) (vote : envelope.payload = .vote)
    (own : OwnGossipBy trace bound envelope.source)
    : exists sourceTx targetTx,
        Model.recoveredTxID config envelope.source = some sourceTx
        /\ Model.recoveredTxID config envelope.target = some targetTx
        /\ Predicates.TxID.EarlierThan sourceTx targetTx := by
  have wf := reachable_well_formed linked.reachable
  obtain ⟨genuine, frozen⟩ := reachable_gossip_invariant linked.reachable
  obtain ⟨current, present, _, same⟩ := frozen envelope sent vote
  obtain ⟨i, witness, le, found, original, txid, originalPresent, ownGossip⟩ := own
  obtain ⟨final, finalMember, evolves⟩ := trace_node_final linked le found originalPresent
  have states : final = current :=
    congrArg Prod.snd (eq_of_key_eq wf.nodeKeysNodup finalMember present rfl)
  have ownCurrent : (envelope.source, txid) ∈ current.gossips := by
    simpa only [states] using evolves.gossips ownGossip
  have ownSnapshot : (envelope.source, txid) ∈ envelope.sourceState.gossips := same ▸ ownCurrent
  obtain ⟨selected, maximum, choice, greatest⟩ :=
    (reachable_quorum_invariant linked.reachable).sentVotesSelected envelope sent vote
  have selectedEq : selected = envelope.target :=
    Option.some.inj (choice.symm.trans (retry_vote_state (wf.sentValid envelope sent) vote).2)
  rw [selectedEq] at greatest
  have maximumCurrent : (envelope.target, maximum) ∈ current.gossips := by
    rw [same]
    exact Committed.maximumGossip_mem greatest
  have configValid := reachable_config_valid linked.reachable
  exact ⟨txid, maximum,
    Committed.recoveredTxID_of_mem configValid (genuine _ present ownCurrent),
    Committed.recoveredTxID_of_mem configValid (genuine _ present maximumCurrent),
    Committed.maximumGossip_upper_bound greatest ownSnapshot⟩

lemma quorum_open_preserves_commit
    : forall (config : Model.Config) (trace : Properties.GlobalTrace config)
              (openedState : Model.State),
      forall (opener : Model.Local.Location) (openerState : Model.Local.NodeState),
        (openedState ∈ trace
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind = some .quorum
          /\ (forall voter,
                voter ∈ openerState.votes -> Properties.ReceivedOwnGossip trace voter))
        -> exists openerTxID,
            Model.recoveredTxID config opener = some openerTxID
            /\ Properties.UpToDateWithQuorum config openerTxID := by
  rintro config trace state opener current ⟨inTrace, present, opened, own⟩
  obtain ⟨openIndex, found⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp inTrace
  obtain ⟨bound, boundIn, openLe, bounded⟩ :=
    Trace.exists_bound (P := fun voter i => exists witness, trace.stateAt i = some witness
        /\ exists nodeState txid,
            (voter, nodeState) ∈ witness.nodes /\ (voter, txid) ∈ nodeState.gossips)
      (Option.isSome_iff_exists.mpr ⟨_, found.symm⟩) current.votes fun voter voted => by
        obtain ⟨witness, member, rest⟩ := own voter voted
        obtain ⟨i, atI⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp member
        exact ⟨i, Option.isSome_iff_exists.mpr ⟨_, atI.symm⟩, witness, atI.symm, rest⟩
  have own : forall voter, voter ∈ current.votes -> OwnGossipBy trace bound voter :=
    fun voter voted => by
      obtain ⟨i, le, witness, atI, rest⟩ := bounded voter voted
      exact ⟨i, witness, le, atI, rest⟩
  obtain ⟨ghost, linked⟩ := History.history_correspondence trace boundIn
  have invariant := reachable_quorum_invariant linked.reachable
  have stateReachable := trace.reachable inTrace
  obtain ⟨atOpening, openingReachable, projected⟩ := Lifting.model_reachable_lifts stateReachable
  have openingPresent : (opener, current) ∈ atOpening.system.nodes := by
    simpa only [← projected, Lifting.erase] using present
  have nodup := (reachable_quorum_invariant openingReachable).votesNodup _ openingPresent
  have threshold := Observed.reachable_quorum_thresholds openingReachable _ openingPresent opened
  obtain ⟨final, finalMember, evolves⟩ :=
    trace_node_final linked openLe found.symm present
  have votesSent : forall voter, voter ∈ current.votes -> Predicates.SentVote ghost voter opener :=
    fun voter member => invariant.votesSent _ finalMember voter (evolves.votes member)
  have anyVote : exists voter, voter ∈ current.votes := by
    cases votes : current.votes with
    | nil => simp [votes, voteQuorum] at threshold
    | cons voter rest => exact ⟨voter, by simp⟩
  obtain ⟨voter, voted⟩ := anyVote
  obtain ⟨envelope, sent, source, target, vote⟩ := votesSent voter voted
  obtain ⟨_, targetTx, _, targetRecovered, _⟩ :=
    sent_vote_preserves_own linked sent vote (by simpa only [source] using own voter voted)
  rw [target] at targetRecovered
  refine ⟨targetTx, targetRecovered, ?_⟩
  apply Committed.up_to_date_with_quorum_of_voters nodup threshold
  intro voter voted
  obtain ⟨envelope, sent, source, target, vote⟩ := votesSent voter voted
  obtain ⟨sourceTx, candidateTx, sourceRecovered, candidateRecovered, earlier⟩ :=
    sent_vote_preserves_own linked sent vote (by simpa only [source] using own voter voted)
  rw [source] at sourceRecovered
  rw [target] at candidateRecovered
  have same := Option.some.inj (candidateRecovered.symm.trans targetRecovered)
  exact ⟨sourceTx, sourceRecovered, same ▸ earlier⟩

lemma sent_vote_full_gossip {config : Config} {trace : Properties.GlobalTrace config}
    {bound : Nat} {ghost : State}
    (linked : History.Correspondence config trace bound ghost) {i : Nat}
    {gossiped : Model.State} (le : i <= bound) (inTrace : trace.stateAt i = some gossiped)
    (full
      : forall node nodeState,
          node ∈ config.protocol.expectedLocations
          -> (node, nodeState) ∈ gossiped.nodes
          -> forall gossip, gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
    {envelope : Envelope} (sent : envelope ∈ ghost.sent) (vote : envelope.payload = .vote)
    : forall gossip,
        gossip ∈ envelope.sourceState.gossips <-> gossip ∈ config.recovered := by
  have wf := reachable_well_formed linked.reachable
  obtain ⟨genuine, frozen⟩ := reachable_gossip_invariant linked.reachable
  obtain ⟨current, present, _, same⟩ := frozen envelope sent vote
  obtain ⟨atGossip, gossipReachable, projected⟩ :=
    Lifting.model_reachable_lifts (trace.reachable (CCF.Execution.Trace.stateAt_mem inTrace))
  have configured := wf.sentSourceConfigured envelope sent
  have sourceKey : envelope.source ∈ atGossip.system.nodes.map Prod.fst := by
    exact (reachable_well_formed gossipReachable).nodeKeys _ configured
  obtain ⟨entry, entryMember, key⟩ := List.mem_map.mp sourceKey
  have originalPresent : (envelope.source, entry.2) ∈ gossiped.nodes := by
    simpa only [← projected, Lifting.erase, ← key] using entryMember
  obtain ⟨final, finalMember, evolves⟩ :=
    trace_node_final linked le inTrace originalPresent
  have states : final = current :=
    congrArg Prod.snd (eq_of_key_eq wf.nodeKeysNodup finalMember present rfl)
  intro gossip
  constructor
  · intro member
    exact genuine _ present (same.symm ▸ member)
  · intro member
    have original := (full envelope.source entry.2 configured originalPresent gossip).mpr member
    have finalGossip := evolves.gossips original
    simpa only [states, same] using finalGossip

lemma full_gossip_preserves_commit
    : forall (config : Model.Config) (trace : Properties.GlobalTrace config)
              (gossipedState openedState : Model.State),
      forall (opener : Model.Local.Location) (openerState : Model.Local.NodeState),
        (gossipedState ∈ trace
          /\ (forall node nodeState,
                node ∈ config.protocol.expectedLocations
                -> (node, nodeState) ∈ gossipedState.nodes
                -> forall gossip,
                    gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
          /\ openedState ∈ trace
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind.isSome = true)
        -> exists openerTxID,
            Model.recoveredTxID config opener = some openerTxID
            /\ Properties.UpToDateWithQuorum config openerTxID := by
  rintro config trace gossiped opened opener current
    ⟨gossipedMember, full, openedMember, present, opening⟩
  obtain ⟨gossipIndex, gossipFound⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp gossipedMember
  obtain ⟨openIndex, openFound⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp openedMember
  obtain ⟨ghost, linked⟩ := History.history_correspondence trace
    (Trace.max_isSome (Option.isSome_iff_exists.mpr ⟨_, gossipFound.symm⟩)
      (Option.isSome_iff_exists.mpr ⟨_, openFound.symm⟩))
  obtain ⟨atOpening, openingReachable, projected⟩ :=
    Lifting.model_reachable_lifts (trace.reachable openedMember)
  have openingPresent : (opener, current) ∈ atOpening.system.nodes := by
    simpa only [← projected, Lifting.erase] using present
  obtain ⟨voter, voted⟩ :=
    Observed.reachable_opening_has_vote openingReachable _ openingPresent opening
  obtain ⟨final, finalMember, evolves⟩ :=
    trace_node_final linked (le_max_right _ _) openFound.symm present
  have invariant := reachable_quorum_invariant linked.reachable
  obtain ⟨envelope, sent, _, target, vote⟩ :=
    invariant.votesSent _ finalMember voter (evolves.votes voted)
  have complete :=
    sent_vote_full_gossip linked (le_max_left _ _) gossipFound.symm full sent vote
  obtain ⟨selected, txid, choice, maximum⟩ := invariant.sentVotesSelected envelope sent vote
  have wf := reachable_well_formed linked.reachable
  have selectedEq : selected = envelope.target :=
    Option.some.inj (choice.symm.trans (retry_vote_state (wf.sentValid envelope sent) vote).2)
  rw [selectedEq, target] at maximum
  have configValid := reachable_config_valid linked.reachable
  refine ⟨txid, Committed.recoveredTxID_of_mem configValid
    ((complete _).mp (Committed.maximumGossip_mem maximum)), ?_⟩
  apply Committed.up_to_date_with_quorum_of_all configValid
  intro entry member
  exact Committed.maximumGossip_upper_bound maximum ((complete entry).mpr member)

end DisasterRecovery.Proofs.Gossip
