module

public import Consensus.Model
public import Consensus.Properties.Config
public import CCF.Execution

import all Init.Control.State

@[expose] public section

/-!
Executions for arbitrary nonempty initial memberships. Function-valued node
tables make updates independent of the membership's size and node identifiers.
The primary signs the bootstrap configuration, exchanges genuine replication
requests and acknowledgements with every peer, and commits the signature.
-/

namespace Consensus.Proofs.GenericWitnesses

open CCF CCF.MultiNodeTransitionSystem
open Model.Node

abbrev Config := Properties.ValidConfig

def ids (config : Config) : List NodeID := config.val.sort (· <= ·)

def table (config : Config) (states : NodeID -> NodeState) :=
  (ids config).map fun node => (node, states node)

def At (config : Config) (states : NodeID -> NodeState) : Prop :=
  exists network,
    (Model.transitionSystem config (ids config)).Reachable
      { nodes := table config states, network }

lemma lookup_table (config : Config) (states : NodeID -> NodeState) (node : NodeID)
    (member : node ∈ config.val) (network : List Model.Envelope)
    : nodeState { nodes := table config states, network } node = some (states node) := by
  simp only [nodeState, table, List.find?_map]
  have find_eq (xs : List NodeID) (present : node ∈ xs) :
      xs.find? (fun n => n == node) = some node := by
    induction xs with
    | nil => simp at present
    | cons head tail ih =>
        by_cases same : head = node
        · simp [same]
        · simp only [List.mem_cons] at present
          simp [List.find?, beq_eq_false_iff_ne.mpr same,
            ih (present.resolve_left (Ne.symm same))]
  simp [Function.comp_def, find_eq (ids config) (by simpa [ids] using member)]

lemma table_member (config : Config) (states : NodeID -> NodeState) (node : NodeID)
    (member : node ∈ config.val)
    : (node, states node) ∈ table config states := by
  exact List.mem_map.mpr ⟨node, by simpa [ids] using member, rfl⟩

lemma at_initial (config : Config) : At config (Model.initialNodeState config) := by
  refine ⟨[], .initial ⟨config.property, ?_, ?_, rfl, ?_⟩⟩
  · simp [table, Function.comp_def]
  · simp [table, ids, Function.comp_def]
  · intro entry member
    obtain ⟨node, _, rfl⟩ := List.mem_map.mp member
    rfl

@[local simp]
lemma effect_bind {S A B : Type} (a : StateT S Option A)
    (f : A -> StateT S Option B) (s : S)
    : (a >>= f) s = (a s).bind (fun (a, s) => f a s) :=
  rfl

@[local simp]
lemma effect_lift {S A : Type} (a : Option A) (s : S)
    : (liftM a : StateT S Option A) s = a.map (fun a => (a, s)) := by
  cases a <;> rfl

lemma local_next (config : Config) (states : NodeID -> NodeState)
    (network : List Model.Envelope) (node : NodeID) (member : node ∈ config.val)
    (input : Input) (after : NodeState) (outputs : Outputs NodeID Message Notification)
    (run
      : (step (Capabilities.record node) node (states node) (.internal input)).run {}
        = some (after, outputs))
    : (Model.transitionSystem config (ids config)).step
        { nodes := table config states, network } (.local node input)
      = some
          {
            nodes := table config (Function.update states node after)
            network := network ++ outputs.outgoing
          } := by
  simp [MultiNodeTransitionSystem.next, Model.protocol,
    lookup_table config states node member, run]
  simp only [table, List.map_map]
  apply List.map_congr_left
  intro a _
  by_cases same : a = node <;> simp [same, Function.update]

lemma delivery_next (config : Config) (states : NodeID -> NodeState)
    (network : List Model.Envelope) (envelope : Model.Envelope)
    (member : envelope.target ∈ config.val) (queued : envelope ∈ network)
    (after : NodeState) (outputs : Outputs NodeID Message Notification)
    (run
      : (step (Capabilities.record envelope.target) envelope.target
          (states envelope.target) (.receive envelope.source envelope.payload)).run
          {}
        = some (after, outputs))
    : (Model.transitionSystem config (ids config)).step
        { nodes := table config states, network } (.deliver envelope)
      = some
          {
            nodes := table config (Function.update states envelope.target after)
            network := removeOne envelope network ++ outputs.outgoing
          } := by
  simp [MultiNodeTransitionSystem.next, Model.protocol, queued,
    lookup_table config states envelope.target member, run]
  simp only [table, List.map_map]
  apply List.map_congr_left
  intro a _
  by_cases same : a = envelope.target <;> simp [same, Function.update]

lemma at_local {config : Config} {states : NodeID -> NodeState}
    (reachable : At config states) (node : NodeID) (member : node ∈ config.val)
    (input : Input) (after : NodeState) (outputs : Outputs NodeID Message Notification)
    (run
      : (step (Capabilities.record node) node (states node) (.internal input)).run {}
        = some (after, outputs))
    : At config (Function.update states node after) := by
  obtain ⟨network, reachable⟩ := reachable
  exact ⟨_, .step reachable (local_next config states network node member input after outputs run)⟩

def bootstrapLog (config : Config) : List Entry :=
  [
    {
      term := Model.BOOTSTRAP_TERM,
      content := .transaction 0 { configuration := some config.val }
    },
    { term := Model.BOOTSTRAP_TERM, content := .signature }
  ]

def committed (config : Config) (primary : NodeID) (peers : Finset NodeID) : Nat :=
  if config.val.card < (insert primary peers ∩ config.val).card * 2 then 2 else 0

def leader (config : Config) (primary : NodeID) (peers : Finset NodeID) : NodeState :=
  {
    role := .primary
    currentTerm := Model.BOOTSTRAP_TERM
    log := bootstrapLog config
    commitIndex := committed config primary peers
    sentIndex := fun node => if node ∈ peers then 2 else 0
    matchIndex := fun node => if node ∈ peers then 2 else 0
    isNewFollower := false
    votedFor := none
    primaryKnown := true
    votesGranted := ∅
  }

def follower (config : Config) (commit : Nat) : NodeState :=
  {
    role := .follower
    currentTerm := Model.BOOTSTRAP_TERM
    log := bootstrapLog config
    commitIndex := commit
    sentIndex := fun _ => 0
    matchIndex := fun _ => 0
    isNewFollower := false
    votedFor := none
    primaryKnown := true
    votesGranted := ∅
  }

lemma bootstrap_active (config : Config) (commit : Nat)
    : activeConfigurations (bootstrapLog config) commit
      = [{ index := 1, nodes := config.val }] := by
  by_cases h : 1 <= commit <;>
    simp [activeConfigurations, configurationHistory, bootstrapLog, EntryContent.metadata, h]

lemma bootstrap_members (config : Config) (commit : Nat)
    : configurationMembers (activeConfigurations (bootstrapLog config) commit)
      = config.val := by
  simp [bootstrap_active, configurationMembers]

lemma bootstrap_frontier (config : Config)
    : maxCommittableIndex (bootstrapLog config) = 2 := by
  simp [maxCommittableIndex, bootstrapLog, List.range_succ, isSignatureAt, entryAt?,
    EntryContent.isSignature]

lemma bootstrap_retired (config : Config) (node : NodeID) (state : NodeState)
    (log : state.log = bootstrapLog config)
    : Not (state.isRetiredCommitted node) := by
  simp [NodeState.isRetiredCommitted, NodeState.retirement, retirementIndexInLog,
    configurationHistory, log, bootstrapLog, EntryContent.metadata]

lemma bootstrap_completed (config : Config) (state : NodeState)
    (log : state.log = bootstrapLog config)
    : state.retirementCompletedNodes = ∅ := by
  unfold NodeState.retirementCompletedNodes NodeState.committedLog
  rw [log]
  cases state.commitIndex with
  | zero =>
      simp [configurationHistory, configurationMembers, latestConfigurationMembers,
        retiredCommittedNodes]
  | succ index =>
      cases index with
      | zero =>
          simp [bootstrapLog, configurationHistory, configurationMembers,
            latestConfigurationMembers, retiredCommittedNodes, EntryContent.metadata]
      | succ index =>
          simp [bootstrapLog, configurationHistory, configurationMembers,
            latestConfigurationMembers, retiredCommittedNodes, EntryContent.metadata]

lemma bootstrap_peers (config : Config) (state : NodeState) (self : NodeID)
    (log : state.log = bootstrapLog config)
    : eligiblePeers state self = config.val.erase self := by
  simp [eligiblePeers, NodeState.activeMembers, NodeState.activeConfigurations, log,
    bootstrap_members, bootstrap_completed config state log]

lemma bootstrap_record (config : Config) (state : NodeState) (node commit : Nat)
    (log : state.log = bootstrapLog config) (retired : state.retiredCommittedIndex = none)
    : state.recordCommit node commit = { state with commitIndex := commit } := by
  unfold NodeState.recordCommit
  simp only [retired, Option.isSome_none, Option.orElse_none]
  have noConfirmation :
      firstLogIndexAfter ((bootstrapLog config).take commit) 0
        (fun content => decide (node ∈ content.metadata.retirementConfirmations)) = none := by
    cases commit with
    | zero => rfl
    | succ index =>
        cases index with
        | zero =>
            simp [bootstrapLog, firstLogIndexAfter, EntryContent.metadata]
        | succ index =>
            simp [bootstrapLog, firstLogIndexAfter, EntryContent.metadata]
  rw [log, noConfirmation]
  simp [NodeState.isRetiredCommitted, NodeState.retirement, retirementIndexInLog,
    configurationHistory, bootstrapLog, EntryContent.metadata]

lemma full_commit (config : Config) (primary : NodeID) (member : primary ∈ config.val)
    : committed config primary (config.val.erase primary) = 2 := by
  have positive := Finset.card_pos.mpr config.property
  simp [committed, Finset.insert_erase member, show config.val.card < config.val.card * 2 by omega]

lemma committed_values (config : Config) (primary : NodeID) (peers : Finset NodeID)
    : committed config primary peers = 0 \/ committed config primary peers = 2 := by
  unfold committed
  split <;> simp

lemma committed_mono (config : Config) (primary : NodeID) {before after : Finset NodeID}
    (subset : before ⊆ after)
    : committed config primary before <= committed config primary after := by
  have support : insert primary before ∩ config.val ⊆ insert primary after ∩ config.val :=
    Finset.inter_subset_inter (Finset.insert_subset_insert _ subset) (Finset.Subset.refl _)
  have cards := Finset.card_le_card support
  unfold committed
  split_ifs <;> omega

lemma replicated (config : Config) (primary : NodeID) (peers : Finset NodeID)
    : config.val.filter
        (fun node => node = primary \/ (if node ∈ peers then 2 else 0) >= 2)
      = insert primary peers ∩ config.val := by
  ext node
  by_cases member : node ∈ peers <;> simp [member]
  tauto

lemma bootstrap_highest (config : Config) (primary : NodeID) (peers : Finset NodeID)
    (state : NodeState) (log : state.log = bootstrapLog config)
    (term : state.currentTerm = Model.BOOTSTRAP_TERM)
    (matched : state.matchIndex = fun node => if node ∈ peers then 2 else 0)
    : highestCommittableIndex state primary
      = if state.commitIndex < 2
            /\ config.val.card < (insert primary peers ∩ config.val).card * 2 then
          2
        else
          0 := by
  simp only [highestCommittableIndex, NodeState.activeMembers, NodeState.activeConfigurations,
    log, bootstrap_active, configurationMembers, List.foldl_cons, List.foldl_nil,
    Finset.empty_union, matched]
  simp [bootstrapLog, List.range_succ, isSignatureAt, entryAt?, EntryContent.isSignature,
    termAt, term, Model.BOOTSTRAP_TERM, hasQuorum, hasConfigurationMajority, replicated]

lemma advance_bootstrap (config : Config) (primary : NodeID) (peers : Finset NodeID)
    (state : NodeState) (log : state.log = bootstrapLog config)
    (term : state.currentTerm = Model.BOOTSTRAP_TERM)
    (matched : state.matchIndex = fun node => if node ∈ peers then 2 else 0)
    (retired : state.retiredCommittedIndex = none)
    (values : state.commitIndex = 0 \/ state.commitIndex = 2)
    (bounded : state.commitIndex <= committed config primary peers)
    : (advanceCommit (Capabilities.record primary) state primary).run {}
      = some ({ state with commitIndex := committed config primary peers }, {}) := by
  rw [advanceCommit, bootstrap_highest config primary peers state log term matched]
  obtain zero | two := values
  · rw [zero]
    unfold committed at bounded ⊢
    split_ifs <;>
      simp_all [bootstrap_record config state primary, bootstrap_retired config primary]
    cases state
    simp_all
  · rw [two]
    have final : committed config primary peers = 2 := by
      obtain h | h := committed_values config primary peers <;> omega
    rw [final]
    simp only [Nat.lt_irrefl, false_and, ite_false, Nat.zero_le, ite_true,
      StateT.run, pure, StateT.pure]
    cases state
    simp_all

def primary (config : Config) : NodeID := config.val.min' config.property

lemma primary_mem (config : Config) : primary config ∈ config.val :=
  Finset.min'_mem _ _

lemma primary_min (config : Config)
    : config.val.min = (primary config : WithTop NodeID) :=
  (Finset.coe_min' config.property).symm

lemma initial_primary (config : Config)
    : Model.initialNodeState config (primary config)
      = {
        role := .primary
        currentTerm := Model.BOOTSTRAP_TERM
        log :=
          [{
            term := Model.BOOTSTRAP_TERM,
            content := .transaction 0 { configuration := some config.val }
          }]
        commitIndex := 0
        sentIndex := fun _ => 0
        matchIndex := fun _ => 0
        isNewFollower := false
        votedFor := none
        primaryKnown := true
        votesGranted := ∅
      } := by
  simp [Model.initialNodeState, primary_min, primary_mem]

lemma initial_follower (config : Config) (node : NodeID) (member : node ∈ config.val)
    (different : node ≠ primary config)
    : Model.initialNodeState config node
      = {
        role := .follower
        currentTerm := Model.BOOTSTRAP_TERM
        log := []
        commitIndex := 0
        sentIndex := fun _ => 0
        matchIndex := fun _ => 0
        isNewFollower := false
        votedFor := none
        primaryKnown := false
        votesGranted := ∅
      } := by
  simp [Model.initialNodeState, primary_min, member, Ne.symm different]

lemma sign_bootstrap (config : Config)
    : (step (Capabilities.record (primary config)) (primary config)
        (Model.initialNodeState config (primary config))
        (.internal (.append [{ content := .signature }]))).run
        {}
      = some (leader config (primary config) ∅, {}) := by
  let state := { (Model.initialNodeState config (primary config)) with log := bootstrapLog config }
  have advanced := advance_bootstrap config (primary config) ∅ state rfl
    (by simp [state, initial_primary])
    (by simp [state, initial_primary])
    (by simp [state, initial_primary])
    (Or.inl rfl) (Nat.zero_le _)
  simpa [step, act, appendBatch, appendEntry, initial_primary, EntryContent.isSignature,
    EntryContent.metadata, StateT.run, pure, StateT.pure, state, leader, bootstrapLog,
    NodeState.isRetiredCommitted, NodeState.retirement, retirementIndexInLog,
    configurationHistory]
    using advanced

lemma at_signed (config : Config)
    : At config
        (Function.update (Model.initialNodeState config) (primary config)
          (leader config (primary config) ∅)) :=
  at_local (at_initial config) (primary config) (primary_mem config)
    (.append [{ content := .signature }]) _ {} (sign_bootstrap config)

def replicationRequest (config : Config) (primary : NodeID) (peers : Finset NodeID)
    (target : NodeID)
    : Model.Envelope :=
  {
    source := primary
    target
    payload :=
      .appendEntriesRequest
        {
          term := Model.BOOTSTRAP_TERM
          prevLogIndex := 0
          prevLogTerm := 0
          entries := bootstrapLog config
          primaryCommit := committed config primary peers
        }
  }

def replicationResponse (source target : NodeID) : Model.Envelope :=
  {
    source
    target
    payload :=
      .appendEntriesResponse
        {
          term := Model.BOOTSTRAP_TERM
          success := true
          lastLogIndex := 2
        }
  }

lemma send_bootstrap (config : Config) (primary target : NodeID) (peers : Finset NodeID)
    (member : target ∈ config.val) (different : target ≠ primary) (fresh : target ∉ peers)
    : (step (Capabilities.record primary) primary (leader config primary peers)
        (.internal (.sendEntries target 2))).run
        {}
      = some
          (
            {
              (leader config primary peers) with
                sentIndex :=
                  Function.update (leader config primary peers).sentIndex target 2
            },
            { outgoing := [replicationRequest config primary peers target] }
          ) := by
  have eligible := bootstrap_peers config (leader config primary peers) primary rfl
  have safe := bootstrap_retired config primary (leader config primary peers) rfl
  simp only [step, act, sendEntries, eligible, safe]
  simp [member, different, fresh, leader,
    makeAppendEntriesRequest, messageEntries, bootstrapLog, termAt, entryAt?,
    Capabilities.record, StateT.run, replicationRequest]
  rfl

lemma receive_bootstrap (config : Config) (target : NodeID) (member : target ∈ config.val)
    (different : target ≠ primary config) (peers : Finset NodeID)
    : (step (Capabilities.record target) target (Model.initialNodeState config target)
        (.receive (primary config)
          (replicationRequest config (primary config) peers target).payload)).run
        {}
      = some
          (
            follower config (committed config (primary config) peers),
            { outgoing := [replicationResponse target (primary config)] }
          ) := by
  obtain h | h := committed_values config (primary config) peers <;>
    simp [step, receive, replicationRequest, observeTerm, updateTerm, Message.term,
      Model.BOOTSTRAP_TERM, initial_follower config target
      member different, handleAppendEntriesRequest, appendEntryMatchesLog, firstTermConflictIndex,
      handleAppendEntiresFromPrimary, termAt, entryAt?, bootstrapLog, maxCommittableIndexUpTo,
      maxCommittableIndex, List.range_succ, isSignatureAt, EntryContent.isSignature,
      NodeState.recordCommit, NodeState.isRetiredCommitted, NodeState.retirement,
      retirementIndexInLog, firstLogIndexAfter, configurationHistory, EntryContent.metadata,
      Capabilities.record, StateT.run, follower, replicationResponse, h] <;> rfl

lemma update_indicator (peers : Finset NodeID) (target : NodeID)
    : Function.update (fun node => if node ∈ peers then 2 else 0) target 2
      = fun node => if node ∈ insert target peers then 2 else 0 := by
  funext node
  by_cases same : node = target <;> simp [same, Function.update]

lemma acknowledge_bootstrap (config : Config) (primary target : NodeID)
    (peers : Finset NodeID) (member : target ∈ config.val) (different : target ≠ primary)
    : (step (Capabilities.record primary) primary
        {
          (leader config primary peers) with
            sentIndex := Function.update (leader config primary peers).sentIndex target 2
        }
        (.receive target (replicationResponse target primary).payload)).run
        {}
      = some (leader config primary (insert target peers), {}) := by
  let state := { (leader config primary (insert target peers)) with
    commitIndex := committed config primary peers }
  have advanced := advance_bootstrap config primary (insert target peers) state rfl rfl rfl rfl
    (committed_values config primary peers)
    (committed_mono config primary (Finset.subset_insert target peers))
  have eligible := bootstrap_peers config
    { (leader config primary peers) with
      sentIndex := Function.update (leader config primary peers).sentIndex target 2 } primary rfl
  simp only [step, receive, eligible]
  have maxed : max (if target ∈ peers then 2 else 0) 2 = 2 := by
    split_ifs <;> decide
  simpa [replicationResponse, different, member, observeTerm, updateTerm,
    handleAppendEntriesResponse, leader, maxed, update_indicator, state, StateT.run]
    using advanced

lemma at_replicate {config : Config} {states : NodeID -> NodeState}
    (reachable : At config states) (peers : Finset NodeID) (target : NodeID)
    (member : target ∈ config.val) (different : target ≠ primary config)
    (fresh : target ∉ peers)
    (leading : states (primary config) = leader config (primary config) peers)
    (initial : states target = Model.initialNodeState config target)
    : At config
        (Function.update
          (Function.update states target
            (follower config (committed config (primary config) peers)))
          (primary config) (leader config (primary config) (insert target peers))) := by
  obtain ⟨network, reachable⟩ := reachable
  let sent := { (leader config (primary config) peers) with
    sentIndex := Function.update (leader config (primary config) peers).sentIndex target 2 }
  let first := Function.update states (primary config) sent
  let request := replicationRequest config (primary config) peers target
  let response := replicationResponse target (primary config)
  let second := Function.update first target (follower config (committed config (primary config) peers))
  have sentStep := local_next config states network (primary config) (primary_mem config)
    (.sendEntries target 2) sent { outgoing := [request] }
    (by simpa [leading] using send_bootstrap config (primary config) target peers member different fresh)
  have requestStep := delivery_next config first (network ++ [request]) request member
    (by simp) _ { outgoing := [response] }
    (by simpa [first, request, response, replicationRequest, replicationResponse,
      Function.update, different, initial] using receive_bootstrap config target member different peers)
  have responseStep :=
    delivery_next config second (removeOne request (network ++ [request]) ++ [response])
      response (primary_mem config) (by simp) _ {}
      (by
        simpa [second, first, request, response, replicationRequest, replicationResponse,
          Function.update, Ne.symm different, sent]
          using acknowledge_bootstrap config (primary config) target peers member
            different)
  have reached := TransitionSystem.Reachable.step
    (TransitionSystem.Reachable.step (TransitionSystem.Reachable.step reachable sentStep) requestStep)
    responseStep
  have same :
      Function.update second (primary config) (leader config (primary config) (insert target peers)) =
      Function.update
        (Function.update states target (follower config (committed config (primary config) peers)))
        (primary config) (leader config (primary config) (insert target peers)) := by
    funext node
    by_cases atPrimary : node = primary config <;>
      by_cases atTarget : node = target <;>
        simp_all [second, first, Function.update]
  change (Model.transitionSystem config (ids config)).Reachable
    { nodes := table config (Function.update second (primary config)
        (leader config (primary config) (insert target peers))), network := _ } at reached
  rw [same] at reached
  exact ⟨_, reached⟩

lemma replicate_set (config : Config) (targets : Finset NodeID)
    (subset : targets ⊆ config.val.erase (primary config))
    : exists states : NodeID -> NodeState,
        At config states
        /\ states (primary config) = leader config (primary config) targets
        /\ (forall node,
              node ∈ targets
              -> exists commit,
                  states node = follower config commit /\ (commit = 0 \/ commit = 2))
        /\ (forall node,
              node ∉ insert (primary config) targets
              -> states node = Model.initialNodeState config node) := by
  induction targets using Finset.induction_on with
  | empty =>
      refine ⟨_, at_signed config, ?_, ?_, ?_⟩
      · simp
      · simp
      · intro node absent
        exact Function.update_of_ne (by simpa using absent) _ _
  | @insert target targets fresh ih =>
      have member := Finset.mem_erase.mp (subset (Finset.mem_insert_self target targets))
      have smaller : targets ⊆ config.val.erase (primary config) :=
        fun node hn => subset (Finset.mem_insert_of_mem hn)
      obtain ⟨states, reachable, leading, copied, untouched⟩ := ih smaller
      let next := Function.update
        (Function.update states target (follower config (committed config (primary config) targets)))
        (primary config) (leader config (primary config) (insert target targets))
      refine ⟨
        next,
        at_replicate reachable targets target member.2 member.1 fresh leading
          (untouched target (by simp [member.1, fresh])),
        ?_,
        ?_,
        ?_
      ⟩
      · simp [next]
      · intro node present
        by_cases same : node = target
        · subst node
          exact ⟨_, by simp [next, Function.update, member.1],
            committed_values config (primary config) targets⟩
        · have old := (Finset.mem_insert.mp present).resolve_left same
          obtain ⟨commit, stored, values⟩ := copied node old
          have different := (Finset.mem_erase.mp (smaller old)).1
          exact ⟨commit, by simpa [next, Function.update, same, different] using stored, values⟩
      · intro node absent
        have different : node ≠ primary config := by
          intro same
          subst node
          simp at absent
        have other : node ≠ target := by
          intro same
          subst node
          simp at absent
        have old : node ∉ insert (primary config) targets := by
          simpa [Finset.mem_insert, different, other] using absent
        simpa [next, Function.update, different, other] using untouched node old

lemma primary_nominates (node : NodeID) (state : NodeState)
    (leading : state.role = .primary)
    : exists outputs,
        (step (Capabilities.record node) node state (.internal .nominateSuccessor)).run {}
        = some (state, outputs) := by
  cases successor : findSuccessor state node with
  | none =>
      exact ⟨{}, by simp [step, act, nominateSuccessor, leading, successor]⟩
  | some target =>
      refine ⟨{ outgoing := [
        { source := node, target, payload := .proposeRequestVoteRequest state.currentTerm }
      ] }, ?_⟩
      simp [step, act, nominateSuccessor, leading, successor, Capabilities.record]

lemma reachable_trace_of_tail {system : TransitionSystem} {state : system.State}
    (reachable : system.Reachable state) (states : Nat -> system.State)
    (actions : Nat -> system.Action) (first : states 0 = state)
    (enabled : forall n, system.step (states n) (actions n) = some (states (n + 1)))
    (index : Nat)
    : exists trace : Execution.Trace system, states index ∈ trace := by
  induction reachable generalizing states actions index with
  | initial initialized =>
      let trace : Execution.Trace system := ⟨{
        init := states 0
        steps := Stream'.Seq.ofStream fun n => (actions n, states (n + 1))
      }, by
        refine ⟨first.symm ▸ initialized, ?_⟩
        intro n before action located chosen
        have beforeEq : states n = before := by
          cases n <;> exact Option.some.inj located
        have actionEq : actions n = action := Option.some.inj chosen
        subst before
        subst action
        exact enabled n⟩
      exact ⟨trace, Execution.Trace.stateAt_mem (n := index) (by cases index <;> rfl)⟩
  | @step before after action reachable stepped ih =>
      let extended : Nat -> system.State
        | 0 => before
        | n + 1 => states n
      let choices : Nat -> system.Action
        | 0 => action
        | n + 1 => actions n
      have valid
          : forall n, system.step (extended n) (choices n) = some (extended (n + 1)) := by
        intro n
        cases n with
        | zero => simpa [extended, choices, first] using stepped
        | succ n => exact enabled n
      exact ih extended choices rfl valid (index + 1)

/-- Continue forever by nominating successors, leaving their packets undelivered. -/
lemma at_trace {config : Config} {states : NodeID -> NodeState}
    (reachable : At config states) (node : NodeID) (member : node ∈ config.val)
    (leading : (states node).role = .primary)
    : exists (trace
              : Execution.Trace (Model.transitionSystem config (ids config))) (network
                                                                                : List
                                                                                    Model.Envelope),
        { nodes := table config states, network } ∈ trace := by
  obtain ⟨network, reachable⟩ := reachable
  obtain ⟨outputs, run⟩ := primary_nominates node (states node) leading
  let continuation : Nat -> Model.State := fun n => {
    nodes := table config states
    network := network ++ (List.range n).flatMap (fun _ => outputs.outgoing)
  }
  have enabled : forall n,
      (Model.transitionSystem config (ids config)).step
        (continuation n) (.local node .nominateSuccessor) = some (continuation (n + 1)) := by
    intro n
    simpa [continuation, List.range_succ, List.append_assoc]
      using local_next config states
        (network ++ (List.range n).flatMap (fun _ => outputs.outgoing)) node member
        .nominateSuccessor (states node) outputs run
  obtain ⟨trace, present⟩ := reachable_trace_of_tail reachable continuation
    (fun _ => .local node .nominateSuccessor) (by simp [continuation]) enabled 0
  exact ⟨trace, network, by simpa [continuation] using present⟩

end Consensus.Proofs.GenericWitnesses
