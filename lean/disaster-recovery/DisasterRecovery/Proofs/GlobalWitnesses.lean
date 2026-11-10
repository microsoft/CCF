module

public import DisasterRecovery.Proofs.Evaluation

import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.GlobalWitnesses

/-!
Construct executions for arbitrary recovery configurations. Gossip is delivered on
demand: the source retries, appending its genuine broadcast, before its envelope
is delivered. This works throughout gossip collection because voting nodes still
broadcast their recovered ledger. All nodes therefore obtain the same collection
and choice before any votes are delivered.
-/

open CCF Model.Local
open Evaluation

private abbrev table (config : Properties.ValidConfig) (states : Location → NodeState) :=
  config.val.protocol.expectedLocations.map fun node => (node, states node)

private def initial (config : Properties.ValidConfig) : Model.State :=
  { nodes := table config initialNode }

private lemma initialized (config : Properties.ValidConfig)
    : (Model.transitionSystem config).init (initial config) := by
  refine ⟨config.property, ?_, ?_, rfl, ?_⟩
  · simp [initial, table, Function.comp_def]
  · simpa [initial, table, Function.comp_def] using config.property.2.1
  · intro entry member
    obtain ⟨node, _, rfl⟩ := List.mem_map.mp member
    rfl

private def At (config : Properties.ValidConfig) (states : Location → NodeState) : Prop :=
  ∃ network,
    (Model.transitionSystem config).Reachable { nodes := table config states, network }

private lemma at_initial (config : Properties.ValidConfig) : At config initialNode :=
  ⟨[], .initial (initialized config)⟩

private lemma lookup_table (config : Properties.ValidConfig)
    (states : Location → NodeState) (node : Location)
    (member : node ∈ config.val.protocol.expectedLocations)
    (network : List Model.Envelope)
    : MultiNodeTransitionSystem.nodeState { nodes := table config states, network } node
      = some (states node) := by
  simp only [MultiNodeTransitionSystem.nodeState, table, List.find?_map]
  have find_eq (xs : List Location) (present : node ∈ xs) :
      xs.find? (fun n => n == node) = some node := by
    induction xs with
    | nil => simp at present
    | cons head tail ih =>
        by_cases same : head = node
        · simp [same]
        · simp only [List.mem_cons] at present
          simp [List.find?, beq_eq_false_iff_ne.mpr same,
            ih (present.resolve_left (Ne.symm same))]
  simp [Function.comp_def, find_eq _ member]

private lemma update_table (config : Properties.ValidConfig)
    (states : Location → NodeState) (node : Location) (after : NodeState)
    : (table config states).map
        (fun entry => if entry.1 == node then (node, after) else entry)
      = table config (Function.update states node after) := by
  simp only [table, List.map_map]
  apply List.map_congr_left
  intro n _
  by_cases same : n = node <;> simp [same, Function.update]

@[local simp]
private lemma effect_bind {S A B : Type} (a : StateT S Option A)
    (f : A → StateT S Option B) (s : S)
    : (a >>= f) s = (a s).bind (fun (a, s) => f a s) :=
  rfl

@[local simp]
private lemma effect_lift {S A : Type} (a : Option A) (s : S)
    : (liftM a : StateT S Option A) s = a.map (fun a => (a, s)) := by
  cases a <;> rfl

@[local simp]
private lemma effect_orElse {S A : Type} (a : StateT S Option A)
    (b : Unit → StateT S Option A) (s : S)
    : (StateT.orElse a b) s = (a s <|> b () s) :=
  rfl

private lemma recovered_exists (config : Properties.ValidConfig) (node : Location)
    (member : node ∈ config.val.protocol.expectedLocations)
    : ∃ txid, Model.recoveredTxID config node = some txid := by
  have existsEntry : ∃ entry ∈ config.val.recovered, entry.1 = node := by
    simpa [← config.property.2.2] using member
  obtain ⟨entry, present, key⟩ := existsEntry
  have found : (config.val.recovered.find? (fun e => e.1 == node)).isSome := by
    simp only [List.isSome_find?]
    exact List.any_eq_true.mpr ⟨entry, present, by simp [key]⟩
  obtain ⟨entry, found⟩ := Option.isSome_iff_exists.mp found
  exact ⟨entry.2, by simp [Model.recoveredTxID, found]⟩

private lemma protocol_run (config : Properties.ValidConfig) (node : Location)
    (txid : TxID) (before after : NodeState) (event : Event)
    (outputs : Outputs Location Message Notification)
    (recovered : Model.recoveredTxID config node = some txid)
    (run
      : (step (Capabilities.record node) config.val.protocol txid before event).run {}
        = some (after, outputs))
    : ((Model.protocol config).step (Capabilities.record node) node before event).run {}
      = some (after, outputs) := by
  simpa [Model.protocol, StateT.run, recovered] using run

private lemma local_next (config : Properties.ValidConfig) (states : Location → NodeState)
    (network : List Model.Envelope) (node : Location)
    (member : node ∈ config.val.protocol.expectedLocations) (input : Model.Input)
    (after : NodeState) (outputs : Outputs Location Message Notification)
    (run
      : ((Model.protocol config).step (Capabilities.record node) node
          (states node) ((Model.protocol config).internal input)).run
          {}
        = some (after, outputs))
    : (Model.transitionSystem config).step { nodes := table config states, network }
        (.local node input)
      = some
          {
            nodes := table config (Function.update states node after)
            network := network ++ outputs.outgoing
          } := by
  simp [MultiNodeTransitionSystem.next, lookup_table config states node member,
    run]
  intro a _
  by_cases same : a = node <;> simp [same, Function.update]

private lemma delivery_next (config : Properties.ValidConfig)
    (states : Location → NodeState) (network : List Model.Envelope)
    (envelope : Model.Envelope)
    (member : envelope.target ∈ config.val.protocol.expectedLocations)
    (queued : envelope ∈ network) (after : NodeState)
    (outputs : Outputs Location Message Notification)
    (run
      : ((Model.protocol config).step (Capabilities.record envelope.target)
          envelope.target (states envelope.target)
          ((Model.protocol config).receive envelope.source envelope.payload)).run
          {}
        = some (after, outputs))
    : (Model.transitionSystem config).step { nodes := table config states, network }
        (.deliver envelope)
      = some
          {
            nodes := table config (Function.update states envelope.target after)
            network :=
              MultiNodeTransitionSystem.removeOne envelope network ++ outputs.outgoing
          } := by
  simp [MultiNodeTransitionSystem.next, queued,
    lookup_table config states envelope.target member, run]
  intro a _
  by_cases same : a = envelope.target <;> simp [same, Function.update]

private lemma at_local {config : Properties.ValidConfig} {states : Location → NodeState}
    (reachable : At config states) (node : Location)
    (member : node ∈ config.val.protocol.expectedLocations) (input : Model.Input)
    (after : NodeState) (outputs : Outputs Location Message Notification)
    (run
      : ((Model.protocol config).step (Capabilities.record node) node
          (states node) ((Model.protocol config).internal input)).run
          {}
        = some (after, outputs))
    : At config (Function.update states node after) := by
  obtain ⟨network, reachable⟩ := reachable
  exact ⟨_, .step reachable (local_next config states network node member input
    after outputs run)⟩

private lemma broadcast_run (source : Location) (message : Message)
    (targets : List Location) (outputs : Outputs Location Message Notification)
    : (targets.foldlM
          (fun (_ : Unit) target => (Capabilities.record source).send message target) ()
        : Effect Location Message Notification Unit).run
        outputs
      = some
          (
            (),
            {
              outputs with
                outgoing :=
                  (outputs.outgoing
                    ++ targets.map (fun target => { source, target, payload := message }))
            }
          ) := by
  induction targets generalizing outputs with
  | nil => simp
  | cons target targets ih =>
      change (targets.foldlM
        (fun (_ : Unit) target => (Capabilities.record source).send message target) () :
        Effect Location Message Notification Unit).run
          { outputs with outgoing := outputs.outgoing ++ [{ source, target, payload := message }] } = _
      simpa [List.append_assoc] using ih
        { outputs with outgoing := outputs.outgoing ++ [{ source, target, payload := message }] }

private lemma nonempty (config : Properties.ValidConfig)
    : config.val.protocol.expectedLocations ≠ [] := by
  have valid := config.property.1
  simp only [Config.isValid, Bool.and_eq_true] at valid
  intro empty
  simp [empty] at valid

private lemma retry_run (config : Properties.ValidConfig) (source : Location)
    (txid : TxID) (state : NodeState)
    (phase : state.phase = .gossiping ∨ state.phase = .voting)
    (chosen : state.phase = .voting → state.chosen.isSome = true)
    : ∃ outputs,
        (step (Capabilities.record source) config.val.protocol txid state .retry).run {}
          = some (state, outputs)
        ∧ (∀ target ∈ config.val.protocol.expectedLocations,
            { source, target, payload := Message.gossip txid } ∈ outputs.outgoing)
        ∧ (∀ target,
            state.phase = .voting
            → state.chosen = some target
            → { source, target, payload := Message.vote } ∈ outputs.outgoing) := by
  rcases phase with phase | phase
  · refine ⟨{ outgoing := (config.val.protocol.expectedLocations.map
        (fun target => { source, target, payload := Message.gossip txid })) }, ?_, ?_, ?_⟩
    · simp [step, phase, nonempty config]
      exact ⟨(), by simpa using (broadcast_run source (.gossip txid)
        config.val.protocol.expectedLocations {})⟩
    · intro target member
      exact List.mem_map.mpr ⟨target, member, rfl⟩
    · intro _ other
      simp [phase] at other
  · obtain ⟨target, selected⟩ := Option.isSome_iff_exists.mp (chosen phase)
    refine ⟨{ outgoing := (
        { source, target, payload := Message.vote } ::
          config.val.protocol.expectedLocations.map
            (fun target => { source, target, payload := Message.gossip txid })) },
      ?_, ?_, ?_⟩
    · simp [step, phase, selected]
      change ((config.val.protocol.expectedLocations.foldlM
        (fun (_ : Unit) target => (Capabilities.record source).send (.gossip txid) target)
          () : Effect Location Message Notification Unit).run
            { outgoing := [{ source, target, payload := Message.vote }] }).map
          (fun (_, outputs) => (state, outputs)) = _
      rw [broadcast_run]
      rfl
    · intro target member
      exact List.mem_cons_of_mem _ (List.mem_map.mpr ⟨target, member, rfl⟩)
    · intro other _ eq
      simp_all

private lemma send_deliver {config : Properties.ValidConfig}
    {states : Location → NodeState} (reachable : At config states)
    (source target : Location) (payload : Message)
    (sourceMember : source ∈ config.val.protocol.expectedLocations)
    (targetMember : target ∈ config.val.protocol.expectedLocations)
    (sent : Outputs Location Message Notification)
    (retry
      : ((Model.protocol config).step (Capabilities.record source) source
          (states source) .retry).run
          {}
        = some (states source, sent))
    (emitted : { source, target, payload } ∈ sent.outgoing) (after : NodeState)
    (received : Outputs Location Message Notification)
    (receive
      : ((Model.protocol config).step (Capabilities.record target) target
          (states target) (Model.receive source payload)).run
          {}
        = some (after, received))
    : At config (Function.update states target after) := by
  obtain ⟨network, reachable⟩ := reachable
  have same : Function.update states source (states source) = states := by
    simp
  have retryStep := local_next config states network source sourceMember .retry
    (states source) sent retry
  rw [same] at retryStep
  have queued : ({ source, target, payload } : Model.Envelope) ∈ network ++ sent.outgoing :=
    List.mem_append_right _ emitted
  exact ⟨_, .step (.step reachable retryStep)
    (delivery_next config states _ { source, target, payload } targetMember queued
      after received receive)⟩

private def collect : List (Location × TxID) → List (Location × TxID)
  | [] => []
  | entry :: rest => insertGossip entry.1 entry.2 (collect rest)

private lemma collect_perm (entries : List (Location × TxID))
    (distinct : (entries.map Prod.fst).Nodup)
    : (collect entries).Perm entries := by
  induction entries with
  | nil => exact .nil
  | cons entry rest ih =>
      simp only [List.map_cons, List.nodup_cons] at distinct
      have perm := ih distinct.2
      have absent : ¬ (collect rest).any (fun e => e.1 == entry.1) = true := by
        intro present
        obtain ⟨e, member, same⟩ := List.any_eq_true.mp present
        have key : e.1 = entry.1 := by simpa using same
        exact distinct.1 (List.mem_map.mpr ⟨e, perm.mem_iff.mp member, key⟩)
      simp only [collect, insertGossip, absent]
      exact (List.mergeSort_perm _ _).trans (List.Perm.cons _ perm)

private lemma maximum_member {entries : List (Location × TxID)}
    {entry : Location × TxID} (selected : maximumGossip entries = some entry)
    : entry ∈ entries := by
  cases entries with
  | nil => simp [maximumGossip] at selected
  | cons head tail =>
      simp only [maximumGossip, Option.some.injEq] at selected
      rw [← selected]
      have fold_member (rest : List (Location × TxID)) (start : Location × TxID) :
          rest.foldl selectMaximum start ∈ start :: rest := by
        induction rest generalizing start with
        | nil => simp
        | cons next rest ih =>
            have member := ih (selectMaximum start next)
            simp only [List.foldl_cons]
            rcases List.mem_cons.mp member with same | member
            · rw [same]
              unfold selectMaximum
              split <;> simp
            · exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ member)
      exact fold_member tail head

private lemma maximum_exists (entries : List (Location × TxID)) (nonempty : entries ≠ [])
    : ∃ entry, maximumGossip entries = some entry := by
  cases entries with
  | nil => contradiction
  | cons head tail => exact ⟨_, rfl⟩

private def gathered (config : Properties.ValidConfig) (node : Location)
    (entries : List (Location × TxID))
    : NodeState :=
  {
    location := node
    gossips := collect entries
    phase :=
      if config.val.protocol.expectedLocations.length ≤ entries.length then
        .voting
      else
        .gossiping
    chosen :=
      if config.val.protocol.expectedLocations.length ≤ entries.length then
        (maximumGossip (collect entries)).map Prod.fst
      else
        none
  }

private lemma gathered_empty (config : Properties.ValidConfig) (node : Location)
    : gathered config node [] = initialNode node := by
  have positive : 0 < config.val.protocol.expectedLocations.length :=
    List.length_pos_iff.mpr (nonempty config)
  simp [gathered, collect, initialNode, Nat.not_le.mpr positive]

private def Active (config : Properties.ValidConfig) (states : Location → NodeState)
    : Prop :=
  ∀ node ∈ config.val.protocol.expectedLocations,
    ((states node).phase = .gossiping ∨ (states node).phase = .voting)
    ∧ ((states node).phase = .voting → (states node).chosen.isSome = true)

private lemma gathered_active (config : Properties.ValidConfig) (node : Location)
    (entries : List (Location × TxID))
    (distinct : (entries.map Prod.fst).Nodup)
    : ((gathered config node entries).phase = .gossiping
        ∨ (gathered config node entries).phase = .voting)
      ∧ ((gathered config node entries).phase = .voting
          → (gathered config node entries).chosen.isSome = true) := by
  by_cases full : config.val.protocol.expectedLocations.length ≤ entries.length
  · have positive : 0 < config.val.protocol.expectedLocations.length :=
      List.length_pos_iff.mpr (nonempty config)
    have populated : collect entries ≠ [] := by
      have := (collect_perm entries distinct).length_eq
      intro empty
      simp [empty] at this
      omega
    obtain ⟨entry, selected⟩ := maximum_exists (collect entries) populated
    simp [gathered, full, selected]
  · simp [gathered, full]

private lemma active_update {config : Properties.ValidConfig}
    {states : Location → NodeState} (active : Active config states) (node : Location)
    (after : NodeState)
    (next
      : (after.phase = .gossiping ∨ after.phase = .voting)
        ∧ (after.phase = .voting → after.chosen.isSome = true))
    : Active config (Function.update states node after) := by
  intro other member
  by_cases same : other = node
  · simpa [same] using next
  · simpa [Function.update, same] using active other member

private lemma recovered_of_mem (config : Properties.ValidConfig)
    (entry : Location × TxID) (member : entry ∈ config.val.recovered)
    : Model.recoveredTxID config entry.1 = some entry.2 := by
  have distinct : (config.val.recovered.map Prod.fst).Nodup := by
    rw [config.property.2.2]
    exact config.property.2.1
  have lookup (entries : List (Location × TxID))
      (distinct : (entries.map Prod.fst).Nodup) (member : entry ∈ entries) :
      (entries.find? (fun e => e.1 == entry.1)).map Prod.snd = some entry.2 := by
    induction entries with
    | nil => simp at member
    | cons head rest ih =>
        simp only [List.mem_cons] at member
        rcases member with same | member
        · subst head
          simp
        · simp only [List.map_cons, List.nodup_cons] at distinct
          have different : head.1 ≠ entry.1 := by
            intro same
            exact distinct.1 (List.mem_map.mpr ⟨entry, member, same.symm⟩)
          simp [List.find?, beq_eq_false_iff_ne.mpr different, ih distinct.2 member]
  exact lookup _ distinct member

private lemma gossip_gathered_run (config : Properties.ValidConfig) (node : Location)
    (recovered : TxID) (entry : Location × TxID)
    (rest : List (Location × TxID))
    (distinct : ((entry :: rest).map Prod.fst).Nodup)
    (bound : (entry :: rest).length ≤ config.val.protocol.expectedLocations.length)
    : (step (Capabilities.record node) config.val.protocol recovered
        (gathered config node rest) (.receiveGossip entry.1 entry.2 .accepted)).run
        {}
      = some (gathered config node (entry :: rest), {}) := by
  have smaller : ¬config.val.protocol.expectedLocations.length ≤ rest.length := by
    simp at bound
    omega
  have length : (collect (entry :: rest)).length = (entry :: rest).length :=
    (collect_perm _ distinct).length_eq
  have ins : insertGossip entry.1 entry.2 (collect rest) = collect (entry :: rest) := rfl
  by_cases full : config.val.protocol.expectedLocations.length ≤ (entry :: rest).length
  · have populated : collect (entry :: rest) ≠ [] := by
      have positive := List.length_pos_iff.mpr (nonempty config)
      intro empty
      rw [empty, List.length_nil] at length
      omega
    obtain ⟨winner, selected⟩ := maximum_exists (collect (entry :: rest)) populated
    simp only [List.length_cons] at full length
    simp [step, gathered, smaller, advance, validTimeout,
      advanceTimeoutLane, ins, full, length, selected]
    rfl
  · simp only [List.length_cons] at full length
    simp [step, gathered, smaller, advance, validTimeout,
      advanceTimeoutLane, ins, full, length]
    rfl

private lemma fill_node (config : Properties.ValidConfig) (target : Location)
    (targetMember : target ∈ config.val.protocol.expectedLocations)
    (entries : List (Location × TxID))
    (distinct : (entries.map Prod.fst).Nodup)
    (subset : ∀ entry ∈ entries, entry ∈ config.val.recovered)
    (bound : entries.length ≤ config.val.protocol.expectedLocations.length)
    (states : Location → NodeState)
    (reachable : At config states) (active : Active config states)
    (empty : states target = initialNode target)
    : At config (Function.update states target (gathered config target entries)) := by
  induction entries with
  | nil =>
      simpa [gathered_empty, ← empty] using reachable
  | cons entry rest ih =>
      have distinctRest : (rest.map Prod.fst).Nodup := (List.nodup_cons.mp distinct).2
      have subsetRest : ∀ e ∈ rest, e ∈ config.val.recovered :=
        fun e member => subset e (List.mem_cons_of_mem _ member)
      have boundRest : rest.length ≤ config.val.protocol.expectedLocations.length := by
        simp at bound
        omega
      have reachableRest := ih distinctRest subsetRest boundRest
      let before := Function.update states target (gathered config target rest)
      have activeRest : Active config before :=
        active_update active target _ (gathered_active config target rest distinctRest)
      have sourceMember : entry.1 ∈ config.val.protocol.expectedLocations := by
        rw [← config.property.2.2]
        exact List.mem_map.mpr ⟨entry, subset entry (by simp), rfl⟩
      have recovered := recovered_of_mem config entry (subset entry (by simp))
      obtain ⟨sent, retry, emitted, _⟩ := retry_run config entry.1 entry.2
        (before entry.1) (activeRest entry.1 sourceMember).1
        (activeRest entry.1 sourceMember).2
      obtain ⟨targetTxID, targetRecovered⟩ := recovered_exists config target targetMember
      have receive := protocol_run config target targetTxID
        (gathered config target rest) (gathered config target (entry :: rest))
        (.receiveGossip entry.1 entry.2 .accepted) {} targetRecovered
        (gossip_gathered_run config target targetTxID entry rest distinct bound)
      have next := send_deliver reachableRest entry.1 target (.gossip entry.2)
        sourceMember targetMember sent
        (protocol_run config entry.1 entry.2 (before entry.1) (before entry.1) .retry
          sent recovered retry)
        (emitted target targetMember) (gathered config target (entry :: rest)) {}
        (by simpa [before, Model.protocol, Model.receive] using receive)
      simpa [before] using next

private lemma fill_nodes (config : Properties.ValidConfig) (targets : List Location)
    (distinct : targets.Nodup)
    (subset : ∀ target ∈ targets, target ∈ config.val.protocol.expectedLocations)
    (states : Location → NodeState) (reachable : At config states)
    (active : Active config states)
    (empty : ∀ target ∈ targets, states target = initialNode target)
    : ∃ finalStates,
        At config finalStates
        ∧ Active config finalStates
        ∧ (∀ target ∈ targets,
            finalStates target = gathered config target config.val.recovered)
        ∧ (∀ target, target ∉ targets → finalStates target = states target) := by
  induction targets generalizing states with
  | nil => exact ⟨states, reachable, active, by simp, by simp⟩
  | cons target rest ih =>
      obtain ⟨notMember, distinctRest⟩ := List.nodup_cons.mp distinct
      have targetMember := subset target (by simp)
      have recoveredDistinct : (config.val.recovered.map Prod.fst).Nodup := by
        rw [config.property.2.2]
        exact config.property.2.1
      have bound
          : config.val.recovered.length ≤ config.val.protocol.expectedLocations.length := by
        have := congrArg List.length config.property.2.2
        simp only [List.length_map] at this
        omega
      let next := Function.update states target (gathered config target config.val.recovered)
      have nextReachable : At config next :=
        fill_node config target targetMember config.val.recovered recoveredDistinct
          (fun _ member => member) bound states reachable active (empty target (by simp))
      have nextActive : Active config next :=
        active_update active target _ (gathered_active config target _ recoveredDistinct)
      obtain ⟨finalStates, finalReachable, finalActive, filled, unchanged⟩ :=
        ih distinctRest (fun n mem => subset n (by simp [mem])) next nextReachable nextActive
          (by
            intro other member
            have different : other ≠ target := by
              intro same
              subst other
              contradiction
            simpa [next, Function.update, different] using empty other (by simp [member]))
      refine ⟨finalStates, finalReachable, finalActive, ?_, ?_⟩
      · intro other member
        rcases List.mem_cons.mp member with same | member
        · subst other
          rw [unchanged target notMember]
          simp [next]
        · exact filled other member
      · intro other absent
        have different : other ≠ target := by
          intro same
          subst other
          simp at absent
        rw [unchanged other (fun member => absent (by simp [member]))]
        simp [next, different]

private lemma full_gossip_reachable (config : Properties.ValidConfig)
    : At config (fun node => gathered config node config.val.recovered) := by
  obtain ⟨states, reachable, _, filled, _⟩ :=
    fill_nodes config config.val.protocol.expectedLocations config.property.2.1
      (fun _ member => member) initialNode (at_initial config)
      (by intro node _; simp [initialNode])
      (by simp)
  obtain ⟨network, reachable⟩ := reachable
  refine ⟨network, ?_⟩
  have same : table config states =
      table config (fun node => gathered config node config.val.recovered) := by
    apply List.map_congr_left
    intro node member
    rw [filled node member]
  simpa only [same] using reachable

private def selected (config : Properties.ValidConfig) (winner node : Location)
    : NodeState :=
  {
    location := node,
    phase := .voting,
    chosen := some winner,
    gossips := collect config.val.recovered
  }

private lemma full_choice (config : Properties.ValidConfig)
    : ∃ winner ∈ config.val.protocol.expectedLocations,
        (∀ node, gathered config node config.val.recovered = selected config winner node)
        ∧ At config (selected config winner) := by
  have distinct : (config.val.recovered.map Prod.fst).Nodup := by
    rw [config.property.2.2]
    exact config.property.2.1
  have length : config.val.recovered.length = config.val.protocol.expectedLocations.length := by
    simpa using congrArg List.length config.property.2.2
  have populated : collect config.val.recovered ≠ [] := by
    intro empty
    have := (collect_perm config.val.recovered distinct).length_eq
    simp [empty, length] at this
    exact nonempty config (List.length_eq_zero_iff.mp this.symm)
  obtain ⟨entry, chosen⟩ := maximum_exists (collect config.val.recovered) populated
  have member : entry.1 ∈ config.val.protocol.expectedLocations := by
    rw [← config.property.2.2]
    exact List.mem_map.mpr ⟨entry,
      (collect_perm config.val.recovered distinct).mem_iff.mp (maximum_member chosen), rfl⟩
  have same (node : Location) :
      gathered config node config.val.recovered = selected config entry.1 node := by
    simp [gathered, selected, length, chosen]
  refine ⟨entry.1, member, same, ?_⟩
  have eq : (fun node => gathered config node config.val.recovered) =
      selected config entry.1 := funext same
  rw [← eq]
  exact full_gossip_reachable config

private def ballots : List Location → List Location
  | [] => []
  | source :: rest => insertVote source (ballots rest)

private lemma ballots_perm (sources : List Location) (distinct : sources.Nodup)
    : (ballots sources).Perm sources := by
  induction sources with
  | nil => exact .nil
  | cons source rest ih =>
      obtain ⟨absent, distinct⟩ := List.nodup_cons.mp distinct
      have perm := ih distinct
      have missing : source ∉ ballots rest :=
        fun member => absent (perm.mem_iff.mp member)
      simp only [ballots, insertVote, List.contains_eq_mem, missing]
      exact (List.mergeSort_perm _ _).trans (List.Perm.cons _ perm)

private def voted (config : Properties.ValidConfig) (winner : Location)
    (sources : List Location)
    : NodeState :=
  {
    selected config winner winner with
      votes := ballots sources
      phase :=
        if voteQuorum config.val.protocol ≤ sources.length then .opening else .voting
      openKind :=
        if voteQuorum config.val.protocol ≤ sources.length then some .quorum else none
  }

private lemma voted_nil (config : Properties.ValidConfig) (winner : Location)
    : voted config winner [] = selected config winner winner := by
  simp [voted, ballots, voteQuorum, selected]

private lemma voted_active (config : Properties.ValidConfig) (winner : Location)
    (sources : List Location) (small : sources.length < voteQuorum config.val.protocol)
    : ((voted config winner sources).phase = .gossiping
        ∨ (voted config winner sources).phase = .voting)
      ∧ ((voted config winner sources).phase = .voting
          → (voted config winner sources).chosen.isSome = true) := by
  simp [voted, selected, Nat.not_le.mpr small]

private lemma vote_run (config : Properties.ValidConfig) (winner source : Location)
    (recovered : TxID) (rest : List Location) (distinct : (source :: rest).Nodup)
    (bound : (source :: rest).length ≤ voteQuorum config.val.protocol)
    : (step (Capabilities.record winner) config.val.protocol recovered
        (voted config winner rest) (.receiveVote source .accepted)).run
        {}
      = some
          (
            voted config winner (source :: rest),
            {
              notifications :=
                if voteQuorum config.val.protocol ≤ (source :: rest).length then
                  [.opening .quorum]
                else
                  []
            }
          ) := by
  have smaller : ¬voteQuorum config.val.protocol ≤ rest.length := by
    simp at bound
    omega
  have length := (ballots_perm (source :: rest) distinct).length_eq
  have ins : insertVote source (ballots rest) = ballots (source :: rest) := rfl
  by_cases full : voteQuorum config.val.protocol ≤ (source :: rest).length
  · simp only [List.length_cons] at full length
    simp [step, voted, selected, smaller, ins, advance, validTimeout,
      full, length, advanceTimeoutLane, Capabilities.record]
    rfl
  · simp only [List.length_cons] at full length
    simp [step, voted, selected, smaller, ins, advance, validTimeout,
      full, length, advanceTimeoutLane]
    rfl

private lemma collect_votes (config : Properties.ValidConfig) (winner : Location)
    (winnerMember : winner ∈ config.val.protocol.expectedLocations)
    (reachable : At config (selected config winner))
    (sources : List Location) (distinct : sources.Nodup)
    (subset : ∀ source ∈ sources, source ∈ config.val.protocol.expectedLocations)
    (bound : sources.length ≤ voteQuorum config.val.protocol)
    : At config
        (Function.update (selected config winner) winner
          (voted config winner sources)) := by
  induction sources with
  | nil => simpa [voted_nil] using reachable
  | cons source rest ih =>
      obtain ⟨_, distinctRest⟩ := List.nodup_cons.mp distinct
      have boundRest : rest.length ≤ voteQuorum config.val.protocol := by
        simp at bound
        omega
      have small : rest.length < voteQuorum config.val.protocol := by
        simp at bound
        omega
      have reachableRest := ih distinctRest
        (fun source member => subset source (List.mem_cons_of_mem _ member)) boundRest
      let before :=
        Function.update (selected config winner) winner (voted config winner rest)
      have active : Active config before :=
        active_update (by intro node _; simp [selected]) winner _
          (voted_active config winner rest small)
      have sourceMember := subset source (by simp)
      obtain ⟨sourceTxID, sourceRecovered⟩ := recovered_exists config source sourceMember
      obtain ⟨targetTxID, targetRecovered⟩ := recovered_exists config winner winnerMember
      obtain ⟨sent, retry, _, emitted⟩ := retry_run config source sourceTxID
        (before source) (active source sourceMember).1 (active source sourceMember).2
      have chosen : (before source).chosen = some winner := by
        by_cases same : source = winner <;> simp [before, same, voted, selected]
      have phase : (before source).phase = .voting := by
        by_cases same : source = winner <;>
          simp [before, same, voted, selected, Nat.not_le.mpr small]
      have receive := protocol_run config winner targetTxID
        (voted config winner rest) (voted config winner (source :: rest))
        (.receiveVote source .accepted) _ targetRecovered
        (vote_run config winner source targetTxID rest distinct bound)
      have next :=
        send_deliver reachableRest source winner .vote sourceMember winnerMember sent
          (protocol_run config source sourceTxID (before source) (before source) .retry
            sent sourceRecovered retry)
          (emitted winner phase chosen) (voted config winner (source :: rest)) _
          (by simpa [before, Model.protocol, Model.receive] using receive)
      simpa [before] using next

private lemma quorum_bound (config : Properties.ValidConfig)
    : voteQuorum config.val.protocol ≤ config.val.protocol.expectedLocations.length := by
  have positive := List.length_pos_iff.mpr (nonempty config)
  unfold voteQuorum
  omega

private lemma recovered_distinct (config : Properties.ValidConfig)
    : (config.val.recovered.map Prod.fst).Nodup := by
  rw [config.property.2.2]
  exact config.property.2.1

/-- A full gossip exchange followed by a quorum of genuine votes reaches a quorum opener. -/
lemma quorum_open_preserves_commit_witness
    : ∀ config : Properties.ValidConfig,
        ∃ (trace : Properties.GlobalTrace config) (openedState : Model.State),
        ∃ (opener : Location) (openerState : NodeState),
          openedState ∈ trace
          ∧ (opener, openerState) ∈ openedState.nodes
          ∧ openerState.openKind = some .quorum
          ∧ (∀ voter,
              voter ∈ openerState.votes → Properties.ReceivedOwnGossip trace voter) := by
  intro config
  obtain ⟨winner, winnerMember, _, reachable⟩ := full_choice config
  let voters := config.val.protocol.expectedLocations.take (voteQuorum config.val.protocol)
  have distinct : voters.Nodup := config.property.2.1.take
  have subset : ∀ voter ∈ voters, voter ∈ config.val.protocol.expectedLocations :=
    fun _ member => List.mem_of_mem_take member
  have length : voters.length = voteQuorum config.val.protocol := by
    simp [voters, Nat.min_eq_left (quorum_bound config)]
  let states := Function.update (selected config winner) winner (voted config winner voters)
  obtain ⟨network, reachable⟩ := collect_votes config winner winnerMember reachable
    voters distinct subset (by omega)
  let globalState : Model.State := { nodes := table config states, network }
  obtain ⟨trace, member⟩ := Execution.reachable_iff_trace.mp reachable
  refine ⟨trace, globalState, winner, voted config winner voters, member, ?_, ?_, ?_⟩
  · exact List.mem_map.mpr ⟨winner, winnerMember, by simp [states]⟩
  · simp [voted, length]
  · intro voter voterMember
    have expected : voter ∈ config.val.protocol.expectedLocations :=
      subset voter ((ballots_perm voters distinct).mem_iff.mp voterMember)
    have own : ∃ txid, (voter, txid) ∈ config.val.recovered := by
      have key : voter ∈ config.val.recovered.map Prod.fst := by
        rw [config.property.2.2]
        exact expected
      obtain ⟨entry, present, key⟩ := List.mem_map.mp key
      exact ⟨entry.2, by simpa [← key] using present⟩
    obtain ⟨txid, own⟩ := own
    refine ⟨globalState, member, states voter, txid,
      List.mem_map.mpr ⟨voter, expected, rfl⟩, ?_⟩
    have gossips : (states voter).gossips = collect config.val.recovered := by
      by_cases same : voter = winner <;> simp [states, same, voted, selected]
    rw [gossips]
    exact (collect_perm config.val.recovered (recovered_distinct config)).mem_iff.mpr own

private def failoverReady (config : Properties.ValidConfig) (winner : Location)
    : NodeState :=
  { voted config winner [winner] with timeoutState := .voting }

private def failedOver (config : Properties.ValidConfig) (winner : Location)
    : NodeState :=
  {
    voted config winner [winner] with
      phase := .opening, timeoutState := .opening, openKind := some .failover
  }

private lemma failover_reachable (config : Properties.ValidConfig)
    (multiple : 2 ≤ config.val.protocol.expectedLocations.length)
    (winner : Location) (winnerMember : winner ∈ config.val.protocol.expectedLocations)
    (reachable : At config (selected config winner))
    : At config
        (Function.update (selected config winner) winner (failedOver config winner)) := by
  have quorum : 2 ≤ voteQuorum config.val.protocol := by
    unfold voteQuorum
    omega
  have votedReachable := collect_votes config winner winnerMember reachable [winner]
    (by simp) (by
      intro node member
      simp only [List.mem_singleton] at member
      simpa [member] using winnerMember)
    (by simp; omega)
  obtain ⟨txid, recovered⟩ := recovered_exists config winner winnerMember
  have first :
      (step (Capabilities.record winner) config.val.protocol txid
        (voted config winner [winner]) .timeout).run {} =
        some (failoverReady config winner, {}) := by
    simp [step, advance, voted, selected, ballots, insertVote, validTimeout,
      failoverReady, advanceTimeoutLane, advanceTimeoutState,
      show ¬voteQuorum config.val.protocol ≤ 1 by omega]
  have next :=
    at_local votedReachable winner winnerMember .timeout
      (failoverReady config winner) {}
      (by
        simpa [Model.protocol]
          using protocol_run config winner txid _ _ .timeout {} recovered first)
  have second :
      (step (Capabilities.record winner) config.val.protocol txid
        (failoverReady config winner) .timeout).run {} =
        some (failedOver config winner, { notifications := [.opening .failover] }) := by
    simp [step, advance, voted, selected, ballots, insertVote, validTimeout,
      failoverReady, failedOver, advanceTimeoutLane, advanceTimeoutState,
      Capabilities.record, show ¬voteQuorum config.val.protocol ≤ 1 by omega]
  have final :=
    at_local next winner winnerMember .timeout (failedOver config winner)
      { notifications := [.opening .failover] }
      (by
        simpa [Model.protocol]
          using protocol_run config winner txid _ _ .timeout _ recovered second)
  simpa using final

/-- With at least two locations, one genuine vote and two timeouts reach failover. -/
lemma full_gossip_preserves_commit_witness
    : ∀ config : Properties.ValidConfig,
        2 ≤ config.val.protocol.expectedLocations.length
        → ∃ (trace : Properties.GlobalTrace config)
            (gossipedState openedState : Model.State),
          ∃ (opener : Location) (openerState : NodeState),
            gossipedState ∈ trace
            ∧ (∀ node nodeState,
                node ∈ config.val.protocol.expectedLocations
                → (node, nodeState) ∈ gossipedState.nodes
                → ∀ gossip, gossip ∈ nodeState.gossips ↔ gossip ∈ config.val.recovered)
            ∧ openedState ∈ trace
            ∧ (opener, openerState) ∈ openedState.nodes
            ∧ openerState.openKind = some .failover := by
  intro config multiple
  obtain ⟨winner, winnerMember, _, reachable⟩ := full_choice config
  obtain ⟨network, reachable⟩ :=
    failover_reachable config multiple winner winnerMember reachable
  let states := Function.update (selected config winner) winner (failedOver config winner)
  let globalState : Model.State := { nodes := table config states, network }
  obtain ⟨trace, member⟩ := Execution.reachable_iff_trace.mp reachable
  refine ⟨trace, globalState, globalState, winner, failedOver config winner,
    member, ?_, member, ?_, rfl⟩
  · intro node nodeState _ present gossip
    obtain ⟨key, _, pair⟩ := List.mem_map.mp present
    have keyEq : key = node := congrArg Prod.fst pair
    have stateEq : states node = nodeState := by simpa [keyEq] using congrArg Prod.snd pair
    rw [← stateEq]
    have gossips : (states node).gossips = collect config.val.recovered := by
      by_cases same : node = winner <;>
        simp [states, same, failedOver, voted, selected]
    rw [gossips]
    exact (collect_perm config.val.recovered (recovered_distinct config)).mem_iff
  · exact List.mem_map.mpr ⟨winner, winnerMember, by simp [states]⟩

private lemma steps_snoc {system : TransitionSystem} (start before after : system.State)
    (steps : List (system.Action × system.State)) (action : system.Action)
    (valid : StepsFrom system start steps)
    (last : (start :: steps.map Prod.snd)[steps.length]? = some before)
    (enabled : system.step before action = some after)
    : StepsFrom system start (steps ++ [(action, after)]) := by
  induction steps generalizing start with
  | nil =>
      simp only [List.map_nil, List.length_nil, List.getElem?_cons_zero,
        Option.some.injEq] at last
      subst start
      exact ⟨enabled, trivial⟩
  | cons pair rest ih =>
      obtain ⟨first, valid⟩ := valid
      refine ⟨first, ih pair.2 valid ?_⟩
      simpa using last

private lemma snoc_before {α β : Type} (start before after : β)
    (steps : List (α × β)) (action : α)
    (last : (start :: steps.map Prod.snd)[steps.length]? = some before)
    : (start :: (steps ++ [(action, after)]).map Prod.snd)[steps.length]?
      = some before := by
  simp only [List.map_append, List.map_cons, List.map_nil]
  change ((start :: steps.map Prod.snd) ++ [after])[steps.length]? = some before
  rw [List.getElem?_append]
  simpa using last

private lemma snoc_after {α β : Type} (start after : β)
    (steps : List (α × β)) (action : α)
    : (start :: (steps ++ [(action, after)]).map Prod.snd)[steps.length + 1]?
      = some after := by
  simp only [List.map_append, List.map_cons, List.map_nil]
  change ((start :: steps.map Prod.snd) ++ [after])[steps.length + 1]? = some after
  rw [List.getElem?_append]
  simp

private lemma reachable_finite {system : TransitionSystem} {state : system.State}
    (reachable : system.Reachable state)
    : ∃ (start : system.State) (steps : List (system.Action × system.State)),
        system.init start
        ∧ StepsFrom system start steps
        ∧ (start :: steps.map Prod.snd)[steps.length]? = some state := by
  induction reachable with
  | initial initialized => exact ⟨_, [], initialized, trivial, rfl⟩
  | @step before after action _ enabled ih =>
      obtain ⟨start, steps, initialized, valid, last⟩ := ih
      refine ⟨start, steps ++ [(action, after)], initialized,
        steps_snoc start before after steps action valid last enabled, ?_⟩
      simp

private lemma notification_exists (config : Properties.ValidConfig)
    (states : Location → NodeState) (network : List Model.Envelope)
    (reachable
      : (Model.transitionSystem config).Reachable
          { nodes := table config states, network })
    (envelope : Model.Envelope)
    (member : envelope.target ∈ config.val.protocol.expectedLocations)
    (queued : envelope ∈ network)
    (after : NodeState) (outputs : Outputs Location Message Notification)
    (run
      : ((Model.protocol config).step (Capabilities.record envelope.target)
          envelope.target (states envelope.target)
          (Model.receive envelope.source envelope.payload)).run
          {}
        = some (after, outputs))
    (notified : Notification.opening .quorum ∈ outputs.notifications)
    : ∃ (trace : Properties.GlobalTrace config) (index : Nat) (opener : Location),
        Properties.Trace.NotificationAt config trace index opener (.opening .quorum) := by
  let beforeGlobal : Model.State := { nodes := table config states, network }
  let nextStates := Function.update states envelope.target after
  let afterGlobal : Model.State := {
    nodes := table config nextStates
    network := MultiNodeTransitionSystem.removeOne envelope network ++ outputs.outgoing }
  have enabled : (Model.transitionSystem config).step beforeGlobal (.deliver envelope)
      = some afterGlobal :=
    delivery_next config states network envelope member queued after outputs run
  obtain ⟨start, steps, initialized, valid, last⟩ := reachable_finite reachable
  let trace := ofSteps start (steps ++ [(.deliver envelope, afterGlobal)]) initialized
    (steps_snoc start beforeGlobal afterGlobal steps (.deliver envelope) valid last enabled)
  refine ⟨trace, steps.length, envelope.target, beforeGlobal, afterGlobal,
    .deliver envelope, states envelope.target, after, outputs, ?_, ?_, ?_, rfl, ?_, ?_,
    run, notified⟩
  · rw [ofSteps_stateAt]
    exact snoc_before start beforeGlobal afterGlobal steps (.deliver envelope) last
  · rw [ofSteps_stateAt]
    exact snoc_after start afterGlobal steps (.deliver envelope)
  · rw [ofSteps_actionAt]
    simp [List.map_append]
  · exact lookup_table config states envelope.target member network
  · simpa [nextStates]
      using lookup_table config nextStates envelope.target member afterGlobal.network

/-- The final vote of a quorum emits an opening notification in a valid finite trace. -/
lemma quorum_opener_unique_witness
    : ∀ config : Properties.ValidConfig,
        ∃ (trace : Properties.GlobalTrace config) (index : Nat) (opener : Location),
          Properties.Trace.NotificationAt config trace index opener
            (.opening .quorum) := by
  intro config
  obtain ⟨winner, winnerMember, _, reachable⟩ := full_choice config
  let voters := config.val.protocol.expectedLocations.take (voteQuorum config.val.protocol)
  have distinct : voters.Nodup := config.property.2.1.take
  have subset : ∀ voter ∈ voters, voter ∈ config.val.protocol.expectedLocations :=
    fun _ member => List.mem_of_mem_take member
  have length : voters.length = voteQuorum config.val.protocol := by
    simp [voters, Nat.min_eq_left (quorum_bound config)]
  have populated : voters ≠ [] := by
    intro empty
    simp [empty, voteQuorum] at length
  obtain ⟨source, rest, eq⟩ := List.exists_cons_of_ne_nil populated
  have distinct' : (source :: rest).Nodup := by simpa [eq] using distinct
  have restSmall : rest.length < voteQuorum config.val.protocol := by
    simp [eq] at length
    omega
  have sourceMember : source ∈ config.val.protocol.expectedLocations :=
    subset source (by simp [eq])
  have reachableRest := collect_votes config winner winnerMember reachable rest
    (List.nodup_cons.mp distinct').2
    (fun voter member => subset voter (by simp [eq, member])) (by omega)
  let states := Function.update (selected config winner) winner (voted config winner rest)
  have active : Active config states :=
    active_update (by intro node _; simp [selected]) winner _
      (voted_active config winner rest restSmall)
  obtain ⟨sourceTxID, sourceRecovered⟩ := recovered_exists config source sourceMember
  obtain ⟨targetTxID, targetRecovered⟩ := recovered_exists config winner winnerMember
  obtain ⟨sent, retry, _, emitted⟩ := retry_run config source sourceTxID
    (states source) (active source sourceMember).1 (active source sourceMember).2
  have chosen : (states source).chosen = some winner := by
    by_cases same : source = winner <;> simp [states, same, voted, selected]
  have phase : (states source).phase = .voting := by
    by_cases same : source = winner <;>
      simp [states, same, voted, selected, Nat.not_le.mpr restSmall]
  obtain ⟨network, reachableRest⟩ := reachableRest
  have sentStep := local_next config states network source sourceMember .retry
    (states source) sent
    (protocol_run config source sourceTxID (states source) (states source) .retry
      sent sourceRecovered retry)
  simp only [Function.update_eq_self] at sentStep
  have reachableSent : (Model.transitionSystem config).Reachable
      { nodes := table config states, network := network ++ sent.outgoing } :=
    .step (action := .local source .retry) reachableRest sentStep
  have full : voteQuorum config.val.protocol ≤ (source :: rest).length := by
    rw [← eq, length]
  have receive := protocol_run config winner targetTxID
    (voted config winner rest) (voted config winner (source :: rest))
    (.receiveVote source .accepted) _ targetRecovered
    (vote_run config winner source targetTxID rest distinct' (by rw [← eq, length]))
  exact notification_exists config states
    (network ++ sent.outgoing)
    reachableSent { source, target := winner, payload := .vote } winnerMember
    (List.mem_append_right _ (emitted winner phase chosen))
    (voted config winner (source :: rest))
    _
    (by simpa [states, Model.receive] using receive)
    (by
      simp only [List.length_cons] at full
      simp [full])

end DisasterRecovery.Proofs.GlobalWitnesses
