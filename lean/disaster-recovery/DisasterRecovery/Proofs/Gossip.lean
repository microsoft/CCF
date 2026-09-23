import DisasterRecovery.Properties
import DisasterRecovery.Proofs.History
import DisasterRecovery.Proofs.Observed
import DisasterRecovery.Proofs.Committed

namespace DisasterRecovery.Proofs.Gossip

open Execution
open Execution.Local hiding Config
open Execution.Global
open Invariants Quorum

attribute [local simp] Execution.Local.transitionSystem rejectionReason guard failure

structure Evolves (before after : NodeState) : Prop where
  gossips : before.gossips ⊆ after.gossips
  votes : before.votes ⊆ after.votes
  frozen : before.chosen.isSome = true ->
    after.chosen.isSome = true /\ after.gossips = before.gossips

lemma evolves_refl (state : NodeState) : Evolves state state :=
  ⟨fun _ h => h, fun _ h => h, fun h => ⟨h, rfl⟩⟩

lemma evolves_trans {first second third : NodeState}
    (left : Evolves first second) (right : Evolves second third) : Evolves first third :=
  ⟨fun _ h => right.gossips (left.gossips h),
    fun _ h => right.votes (left.votes h), fun chosen => by
      obtain ⟨chosen', same⟩ := left.frozen chosen
      obtain ⟨chosen'', same'⟩ := right.frozen chosen'
      exact ⟨chosen'', same'.trans same⟩⟩

lemma insertGossip_extends (source : Location) (txid : TxID) (gossips : List (Location × TxID)) :
    gossips ⊆ insertGossip source txid gossips := by
  intro entry member
  unfold insertGossip
  split
  · exact member
  · exact (List.mergeSort_perm _ _).mem_iff.mpr (List.mem_cons_of_mem _ member)

lemma insertVote_extends (source : Location) (votes : List Location) :
    votes ⊆ insertVote source votes := by
  intro voter member
  unfold insertVote
  split
  · exact member
  · exact (List.mergeSort_perm _ _).mem_iff.mpr (List.mem_cons_of_mem _ member)

lemma step_evolves (config : Execution.Local.Config) (state : NodeState) (event : Event) :
    Evolves state (step config state event).state := by
  cases event <;> try cases_type Model.Local.Validation
  all_goals simp [step, rejected, advance, advanceTimeoutLane]
  all_goals repeat' first | split | apply evolves_refl
  all_goals constructor
  all_goals first
    | exact fun _ h => h
    | exact insertGossip_extends _ _ _
    | exact insertVote_extends _ _
    | simp_all

def Genuine (config : Config) (nodes : List (Location × NodeState)) : Prop :=
  forall entry, entry ∈ nodes -> entry.2.gossips ⊆ config.recovered

def EventGenuine (config : Config) : Event -> Prop
  | .receiveGossip source txid .accepted => (source, txid) ∈ config.recovered
  | _ => True

lemma insertGossip_genuine {config : Config} {state : NodeState} {source : Location} {txid : TxID}
    (prior : state.gossips ⊆ config.recovered) (incoming : (source, txid) ∈ config.recovered) :
    insertGossip source txid state.gossips ⊆ config.recovered := by
  intro entry member
  unfold insertGossip at member
  split at member
  · exact prior member
  · have original := (List.mergeSort_perm _ _).mem_iff.mp member
    rcases List.mem_cons.mp original with rfl | old
    · exact incoming
    · exact prior old

lemma step_genuine (config : Config) (state : NodeState) (event : Event)
    (prior : state.gossips ⊆ config.recovered) (incoming : EventGenuine config event) :
    (step config.protocol state event).state.gossips ⊆ config.recovered := by
  cases event <;> try cases_type Model.Local.Validation
  all_goals simp [step, rejected, advance, advanceTimeoutLane]
  all_goals repeat' first | split | exact prior
  all_goals exact insertGossip_genuine prior incoming

lemma lookup_member {state : State} {node : Location} {current : NodeState}
    (found : nodeState state node = some current) : (node, current) ∈ state.system.nodes := by
  obtain ⟨entry, found, same⟩ := Option.map_eq_some_iff.mp found
  have key := beq_iff_eq.mp
    (List.find?_some (p := fun entry : Location × NodeState => entry.1 == node) found)
  have entryEq : entry = (node, current) := Prod.ext key same
  rw [← entryEq]
  exact List.mem_of_find?_eq_some found

lemma systemStep_evolves {config : Execution.Local.Config} {before after : SystemState}
    {target : Location} {event : Event} {output : StepOutput}
    (nodup : (before.nodes.map Prod.fst).Nodup)
    (transition : systemStep config before target event = some (after, output))
    {node : Location} {current : NodeState} (member : (node, current) ∈ before.nodes) :
    exists next, (node, next) ∈ after.nodes /\ Evolves current next := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  obtain ⟨foundState, ⟨key, found⟩, rfl, _⟩ := transition
  have foundMember := List.mem_of_find?_eq_some found
  have keyEq : key = target := beq_iff_eq.mp
    (List.find?_some (p := fun entry : Location × NodeState => entry.1 == target) found)
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
    (transition : systemStep config.protocol before target event = some (after, output)) :
    Genuine config after.nodes := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  obtain ⟨current, ⟨key, found⟩, rfl, _⟩ := transition
  intro entry member
  obtain ⟨previous, present, rfl⟩ := List.mem_map.mp member
  split
  · exact step_genuine config current event
      (prior (key, current) (List.mem_of_find?_eq_some found)) incoming
  · exact prior previous present

lemma next_evolves {config : Config} {before after : State} {action : Action}
    (wf : Predicates.WellFormed config before)
    (transition : next config before action = some after)
    {node : Location} {current : NodeState} (member : (node, current) ∈ before.system.nodes) :
    exists updated, (node, updated) ∈ after.system.nodes /\ Evolves current updated := by
  cases action with
  | retry source =>
      rw [retry_system_eq transition]
      exact ⟨current, member, evolves_refl current⟩
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      obtain ⟨_, _, system, output, updated, rfl⟩ := transition
      simpa only [recordEffects_system] using systemStep_evolves wf.nodeKeysNodup updated member
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      obtain ⟨_, system, output, updated, _, rfl⟩ := transition
      simpa only [recordEffects_system] using systemStep_evolves wf.nodeKeysNodup updated member

lemma next_genuine {config : Config} {before after : State} {action : Action}
    (wf : Predicates.WellFormed config before)
    (prior : Genuine config before.system.nodes)
    (transition : next config before action = some after) : Genuine config after.system.nodes := by
  cases action with
  | retry source =>
      simpa only [retry_system_eq transition] using prior
  | deliver envelope =>
      simp [next, Option.bind_eq_some_iff] at transition
      obtain ⟨pending, _, system, output, updated, rfl⟩ := transition
      have incoming : EventGenuine config (eventFor envelope) := by
        cases payload : envelope.payload <;> simp [eventFor, payload, EventGenuine]
        case gossip txid =>
          have recovered := valid_gossip_uses_recovered_txid
            (wf.sentValid _ (wf.networkSent _ pending)) payload
          obtain ⟨entry, found, value⟩ := Option.map_eq_some_iff.mp recovered
          have key := beq_iff_eq.mp
            (List.find?_some (p := fun entry : Location × TxID => entry.1 == envelope.source) found)
          have entryEq : entry = (envelope.source, txid) := Prod.ext key value
          rw [← entryEq]
          exact List.mem_of_find?_eq_some found
      simpa only [recordEffects_system] using systemStep_genuine prior incoming updated
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      obtain ⟨_, system, output, updated, _, rfl⟩ := transition
      simpa only [recordEffects_system] using systemStep_genuine prior (by trivial) updated

def FrozenVotes (state : State) : Prop :=
  forall envelope, envelope ∈ state.sent -> envelope.payload = .vote ->
    exists current, (envelope.source, current) ∈ state.system.nodes /\
      current.chosen.isSome = true /\ current.gossips = envelope.sourceState.gossips

lemma next_frozen {config : Config} {before after : State} {action : Action}
    (wf : Predicates.WellFormed config before)
    (prior : FrozenVotes before)
    (transition : next config before action = some after) : FrozenVotes after := by
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
      simp [next, Option.bind_eq_some_iff] at transition
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
      simp [next, Option.bind_eq_some_iff] at transition
      obtain ⟨_, _, system, output, _, rfl⟩ := transition
      simpa only [FrozenVotes, recordEffects_sent] using carry
  | timeout target =>
      simp [next, Option.bind_eq_some_iff] at transition
      obtain ⟨_, system, output, _, _, rfl⟩ := transition
      simpa only [FrozenVotes, recordEffects_sent] using carry

lemma reachable_gossip_invariant {config : Config} {state : State}
    (reachable : Reachable config state) :
    Genuine config state.system.nodes /\ FrozenVotes state := by
  induction reachable with
  | initial initialized =>
      obtain ⟨active, _, _, _, rfl⟩ := initialized
      constructor
      · simp [Genuine, initial, initialSystem, initialNode]
      · simp [FrozenVotes, initial]
  | step reachable transition ih =>
      have wf := reachable_well_formed reachable
      exact ⟨next_genuine wf ih.1 transition, next_frozen wf ih.2 transition⟩

lemma model_step_evolves {config : Model.Config} {before after : Model.State} {action : Model.Action}
    (reachable : (Model.transitionSystem config).Reachable before)
    (transition : (Model.transitionSystem config).step before action = some after)
    {node : Location} {current : NodeState} (member : (node, current) ∈ before.nodes) :
    exists updated, (node, updated) ∈ after.nodes /\ Evolves current updated := by
  obtain ⟨ghostBefore, ghostAction, ghostAfter, reachable', projected, _, step, projected'⟩ :=
    Lifting.model_step_lifts reachable transition
  have original : (node, current) ∈ ghostBefore.system.nodes := by
    simpa only [← projected, Lifting.erase] using member
  simpa only [← projected', Lifting.erase] using
    next_evolves (reachable_well_formed reachable') step original

lemma steps_evolve {config : Model.Config} {before after : Model.State} {steps}
    (run : Trace.Path (Model.transitionSystem config) before steps after)
    (reachable : (Model.transitionSystem config).Reachable before)
    {node : Location} {current : NodeState} (member : (node, current) ∈ before.nodes) :
    exists updated, (node, updated) ∈ after.nodes /\ Evolves current updated := by
  induction run generalizing current with
  | nil => exact ⟨current, member, evolves_refl current⟩
  | cons transition rest ih =>
      obtain ⟨middle, present, evolves⟩ := model_step_evolves reachable transition member
      obtain ⟨updated, present', evolves'⟩ := ih (.step reachable transition) present
      exact ⟨updated, present', evolves_trans evolves evolves'⟩

lemma trace_node_final {config : Model.Config} {trace : Properties.GlobalTrace}
    (valid : trace.Valid (Model.transitionSystem config))
    {ghost : State} (linked : History.Correspondence config trace ghost)
    {state : Model.State} (member : state ∈ trace.states)
    {node : Location} {current : NodeState} (present : (node, current) ∈ state.nodes) :
    exists final, (node, final) ∈ ghost.system.nodes /\ Evolves current final := by
  obtain ⟨suffix, run⟩ := linked.suffix state member
  exact steps_evolve run (valid.reachable member) present

lemma sent_vote_preserves_own {config : Config} {trace : Properties.GlobalTrace} {ghost : State}
    (valid : trace.Valid (Model.transitionSystem config))
    (linked : History.Correspondence config trace ghost)
    {envelope : Envelope} (sent : envelope ∈ ghost.sent) (vote : envelope.payload = .vote)
    (own : Properties.ReceivedOwnGossip trace envelope.source) :
    exists sourceTx targetTx,
      Model.recoveredTxID config envelope.source = some sourceTx /\
      Model.recoveredTxID config envelope.target = some targetTx /\
      Predicates.TxID.EarlierThan sourceTx targetTx := by
  have wf := reachable_well_formed linked.reachable
  obtain ⟨genuine, frozen⟩ := reachable_gossip_invariant linked.reachable
  obtain ⟨current, present, _, same⟩ := frozen envelope sent vote
  obtain ⟨witness, inTrace, original, txid, originalPresent, ownGossip⟩ := own
  obtain ⟨final, finalMember, evolves⟩ := trace_node_final valid linked inTrace originalPresent
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

lemma quorum_open_preserves_commit : Properties.QuorumOpenPreservesCommit := by
  intro config trace valid state inTrace opener current present opened own committed committable
  obtain ⟨_, _, ghost, _, _, _, linked⟩ := History.history_correspondence trace valid
  have wf := reachable_well_formed linked.reachable
  have invariant := reachable_quorum_invariant linked.reachable
  have configValid := reachable_config_valid linked.reachable
  have stateReachable := valid.reachable inTrace
  obtain ⟨atOpening, openingReachable, projected⟩ := Lifting.model_reachable_lifts stateReachable
  have openingPresent : (opener, current) ∈ atOpening.system.nodes := by
    simpa only [← projected, Lifting.erase] using present
  have nodup := (reachable_quorum_invariant openingReachable).votesNodup _ openingPresent
  have threshold := Observed.reachable_quorum_thresholds openingReachable _ openingPresent opened
  obtain ⟨final, finalMember, evolves⟩ := trace_node_final valid linked inTrace present
  have votesSent : forall voter, voter ∈ current.votes -> Predicates.SentVote ghost voter opener :=
    fun voter member => invariant.votesSent _ finalMember voter (evolves.votes member)
  let durable := config.recovered.filter fun entry =>
    decide (committed.view < entry.2.view \/
      (committed.view = entry.2.view /\ committed.seqno <= entry.2.seqno))
  have keysNodup : (config.recovered.map Prod.fst).Nodup := by
    rw [configValid.2.2]
    exact configValid.2.1
  have durableNodup : (durable.map Prod.fst).Nodup :=
    keysNodup.sublist ((List.filter_sublist : durable.Sublist config.recovered).map Prod.fst)
  have durableConfigured : forall voter, voter ∈ durable.map Prod.fst ->
      voter ∈ config.protocol.expectedLocations := by
    intro voter member
    rw [← configValid.2.2]
    exact List.mem_map.mpr (by
      obtain ⟨entry, member, key⟩ := List.mem_map.mp member
      exact ⟨entry, (List.mem_filter.mp member).1, key⟩)
  obtain ⟨voter, voted, durableVote⟩ := quorum_lists_intersect
    config.protocol.expectedLocations current.votes (durable.map Prod.fst) nodup durableNodup
    (by
      intro voter member
      obtain ⟨envelope, sent, source, _, _⟩ := votesSent voter member
      exact wf.activeConfigured voter (source ▸ wf.sentSourceActive envelope sent))
    durableConfigured threshold (by
      rw [List.length_map]
      exact committable)
  obtain ⟨envelope, sent, source, target, vote⟩ := votesSent voter voted
  obtain ⟨sourceTx, targetTx, sourceRecovered, targetRecovered, sourceTarget⟩ :=
    sent_vote_preserves_own valid linked sent vote (by simpa only [source] using own voter voted)
  obtain ⟨entry, durableMember, key⟩ := List.mem_map.mp durableVote
  obtain ⟨recoveredMember, committedEntry⟩ := List.mem_filter.mp durableMember
  have entryRecovered := Committed.recoveredTxID_of_mem configValid
    (show (entry.1, entry.2) ∈ config.recovered from recoveredMember)
  change Model.recoveredTxID config entry.1 = some entry.2 at entryRecovered
  rw [key] at entryRecovered
  rw [source] at sourceRecovered
  have sameTx : entry.2 = sourceTx := Option.some.inj (entryRecovered.symm.trans sourceRecovered)
  refine ⟨targetTx, by simpa only [target] using targetRecovered, ?_⟩
  apply Committed.prefix_trans (second := sourceTx) _ sourceTarget
  simpa only [Predicates.TxID.EarlierThan, decide_eq_true_eq, sameTx] using committedEntry

end DisasterRecovery.Proofs.Gossip
