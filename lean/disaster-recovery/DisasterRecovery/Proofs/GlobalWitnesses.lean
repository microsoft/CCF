module

public import DisasterRecovery.Proofs.Serial

import CCF.Proofs.Function
import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.GlobalWitnesses

/-!
Construct executions for arbitrary recovery configurations. Gossip is delivered on
demand: the source retries, appending its genuine broadcast, before its envelope
is delivered. This works throughout gossip collection because voting nodes still
broadcast their recovered ledger. All nodes therefore obtain the same collection
and choice before any votes are delivered. Each accepted handler is executed as a
run followed immediately by committing that pending attempt.
-/

open CCF CCF.Execution
open Model.Local (
  Location TxID Message Notification Event Operation voteQuorum maximumGossip
    selectMaximum
  )
open Atomic (Clean)

private abbrev table (config : Properties.ValidConfig)
    (states : Location → Model.Local.NodeState) :=
  config.val.protocol.expectedLocations.map fun node => (node, states node)

private def initial (config : Properties.ValidConfig) : Model.State :=
  { nodes := table config Model.Local.initialNode }

private theorem initialized (config : Properties.ValidConfig)
    : (Model.transitionSystem config).init (initial config) := by
  refine ⟨config.property, ?_, ?_, rfl, ?_⟩
  · simp [initial, table, Function.comp_def]
  · simpa [initial, table, Function.comp_def] using config.property.2.1
  · intro entry member
    obtain ⟨node, _, rfl⟩ := List.mem_map.mp member
    rfl

private def At (config : Properties.ValidConfig) (states : Location → Atomic.NodeState)
    : Prop :=
  ∃ (concrete : Location → Model.Local.NodeState) (network : List Model.Envelope),
    (∀ node ∈ config.val.protocol.expectedLocations, Clean (concrete node) (states node))
    ∧ (Model.transitionSystem config).Reachable
        { nodes := table config concrete, network }

private theorem at_initial (config : Properties.ValidConfig)
    : At config Atomic.initialNode :=
  ⟨
    Model.Local.initialNode,
    [],
    fun node _ => Atomic.clean_initial node,
    .initial (initialized config)
  ⟩

private theorem lookup_table (config : Properties.ValidConfig)
    (states : Location → Model.Local.NodeState) (node : Location)
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

@[local simp]
private theorem effect_bind {S A B : Type} (a : StateT S Option A)
    (f : A → StateT S Option B) (s : S)
    : (a >>= f) s = (a s).bind (fun (a, s) => f a s) :=
  rfl

@[local simp]
private theorem effect_lift {S A : Type} (a : Option A) (s : S)
    : (liftM a : StateT S Option A) s = a.map (fun a => (a, s)) := by
  cases a <;> rfl

@[local simp]
private theorem effect_orElse {S A : Type} (a : StateT S Option A)
    (b : Unit → StateT S Option A) (s : S)
    : (StateT.orElse a b) s = (a s <|> b () s) :=
  rfl

private theorem recovered_exists (config : Properties.ValidConfig) (node : Location)
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

private theorem protocol_perform (config : Properties.ValidConfig) (node : Location)
    (txid : TxID) (before after : Model.Local.NodeState) (op : Operation)
    (outputs : Outputs Location Message Notification)
    (recovered : Model.recoveredTxID config node = some txid)
    (run
      : (Model.Local.perform (Capabilities.record node) config.val.protocol txid before
          op).run
          {}
        = some (after, outputs))
    : ((Model.protocol config).step (Capabilities.record node) node before op).run {}
      = some (after, outputs) := by
  simpa [Model.protocol, StateT.run, recovered] using run

private theorem local_next (config : Properties.ValidConfig)
    (states : Location → Model.Local.NodeState) (network : List Model.Envelope)
    (node : Location) (member : node ∈ config.val.protocol.expectedLocations)
    (input : Model.Input) (after : Model.Local.NodeState)
    (outputs : Outputs Location Message Notification)
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

private theorem delivery_next (config : Properties.ValidConfig)
    (states : Location → Model.Local.NodeState) (network : List Model.Envelope)
    (envelope : Model.Envelope)
    (member : envelope.target ∈ config.val.protocol.expectedLocations)
    (queued : envelope ∈ network) (after : Model.Local.NodeState)
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
  simp [MultiNodeTransitionSystem.next, guard, queued,
    lookup_table config states envelope.target member, run]
  intro a _
  by_cases same : a = envelope.target <;> simp [same, Function.update]

private theorem clean_update {config : Properties.ValidConfig}
    {concrete : Location → Model.Local.NodeState} {states : Location → Atomic.NodeState}
    (clean
      : ∀ node ∈ config.val.protocol.expectedLocations,
          Clean (concrete node) (states node))
    (node : Location) (last : Model.Local.NodeState) (after : Atomic.NodeState)
    (next : Clean last after)
    : ∀ other ∈ config.val.protocol.expectedLocations,
        Clean (Function.update concrete node last other)
          (Function.update states node after other) := by
  intro other member
  by_cases same : other = node
  · subst other
    simpa using next
  · simpa [Function.update, same] using clean other member

private theorem at_timeout {config : Properties.ValidConfig}
    {states : Location → Atomic.NodeState}
    (reachable : At config states) (node : Location)
    (member : node ∈ config.val.protocol.expectedLocations) (txid : TxID)
    (recovered : Model.recoveredTxID config node = some txid)
    (after : Atomic.NodeState) (outputs : Outputs Location Message Notification)
    (accepted : ∀ reason, outputs.notifications ≠ [.rejected reason])
    (atomic
      : (Atomic.step (Capabilities.record node) config.val.protocol txid
          (states node) .timeout).run
          {}
        = some (after, outputs))
    : At config (Function.update states node after) := by
  obtain ⟨concrete, network, clean, reachable⟩ := reachable
  obtain ⟨mid, last, early, runEq, _, commitEq, cleanLast⟩ :=
    Atomic.run_commit config.val.protocol node txid (concrete node) (states node) after
      (clean node member) .timeout (by decide) outputs accepted atomic
  have step1 := local_next config concrete network node member .timeout mid early
    (protocol_perform config node txid (concrete node) mid (.run .timeout) early recovered runEq)
  have step2 :=
    local_next config (Function.update concrete node mid)
      (network ++ early.outgoing) node member (.commit 0) last outputs
      (by
        simpa [Model.protocol]
          using protocol_perform config node txid mid last (.commit 0) outputs recovered
            commitEq)
  have collapsed : Function.update (Function.update concrete node mid) node last =
      Function.update concrete node last := by
    funext other
    by_cases same : other = node <;> simp [Function.update, same]
  rw [collapsed] at step2
  exact ⟨
    Function.update concrete node last,
    _,
    clean_update clean node last after cleanLast,
    .step (.step reachable step1) step2
  ⟩

private theorem broadcast_run (source : Location) (message : Message)
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

private theorem nonempty (config : Properties.ValidConfig)
    : config.val.protocol.expectedLocations ≠ [] := by
  have valid := config.property.1
  simp only [Model.Local.Config.isValid, Bool.and_eq_true] at valid
  intro empty
  simp [empty] at valid

private theorem retry_run (config : Properties.ValidConfig) (source : Location)
    (txid : TxID) (state : Atomic.NodeState)
    (phase : state.phase = .gossiping ∨ state.phase = .voting)
    (chosen : state.phase = .voting → state.chosen.isSome = true)
    : ∃ outputs,
        (Atomic.step (Capabilities.record source) config.val.protocol txid state
            .retry).run
            {}
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
    · simp [Atomic.step, phase, nonempty config, guard]
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
    · simp [Atomic.step, phase, selected]
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

private theorem receive_ne_retry (source : Location) (payload : Message)
    : Model.receive source payload ≠ .retry := by
  cases payload <;> simp [Model.receive]

private theorem send_deliver {config : Properties.ValidConfig}
    {states : Location → Atomic.NodeState} (reachable : At config states)
    (source target : Location) (payload : Message)
    (sourceMember : source ∈ config.val.protocol.expectedLocations)
    (targetMember : target ∈ config.val.protocol.expectedLocations)
    (sourceTxID targetTxID : TxID)
    (sourceRecovered : Model.recoveredTxID config source = some sourceTxID)
    (targetRecovered : Model.recoveredTxID config target = some targetTxID)
    (sent : Outputs Location Message Notification)
    (retry
      : (Atomic.step (Capabilities.record source) config.val.protocol sourceTxID
          (states source) .retry).run
          {}
        = some (states source, sent))
    (emitted : { source, target, payload } ∈ sent.outgoing) (after : Atomic.NodeState)
    (received : Outputs Location Message Notification)
    (accepted : ∀ reason, received.notifications ≠ [.rejected reason])
    (receive
      : (Atomic.step (Capabilities.record target) config.val.protocol targetTxID
          (states target) (Model.receive source payload)).run
          {}
        = some (after, received))
    : At config (Function.update states target after) := by
  obtain ⟨concrete, network, clean, reachable⟩ := reachable
  have retryReal :
      (Model.Local.perform (Capabilities.record source) config.val.protocol sourceTxID
        (concrete source) .retry).run {} = some (concrete source, sent) := by
    rw [Atomic.retry_agrees config.val.protocol source sourceTxID (concrete source)
      (states source) (clean source sourceMember).represented (clean source sourceMember).location,
      retry]
    rfl
  have same : Function.update concrete source (concrete source) = concrete := by
    simp
  have retryStep := local_next config concrete network source sourceMember .retry
    (concrete source) sent
    (protocol_perform config source sourceTxID (concrete source) (concrete source) .retry
      sent sourceRecovered retryReal)
  rw [same] at retryStep
  have queued : ({ source, target, payload } : Model.Envelope) ∈ network ++ sent.outgoing :=
    List.mem_append_right _ emitted
  obtain ⟨mid, last, early, runEq, _, commitEq, cleanLast⟩ :=
    Atomic.run_commit config.val.protocol target targetTxID (concrete target) (states target)
      after (clean target targetMember) (Model.receive source payload)
      (receive_ne_retry source payload) received accepted receive
  have deliverStep := delivery_next config concrete (network ++ sent.outgoing)
    { source, target, payload } targetMember queued mid early
    (protocol_perform config target targetTxID (concrete target) mid
      (.run (Model.receive source payload)) early targetRecovered runEq)
  have commitStep :=
    local_next config (Function.update concrete target mid)
      (MultiNodeTransitionSystem.removeOne { source, target, payload }
          (network ++ sent.outgoing)
        ++ early.outgoing)
      target targetMember (.commit 0) last received
      (by
        simpa [Model.protocol]
          using protocol_perform config target targetTxID mid last (.commit 0) received
            targetRecovered commitEq)
  have collapsed : Function.update (Function.update concrete target mid) target last =
      Function.update concrete target last := by
    funext other
    by_cases same : other = target <;> simp [Function.update, same]
  rw [collapsed] at commitStep
  exact ⟨Function.update concrete target last, _,
    clean_update clean target last after cleanLast,
    .step (.step (.step reachable retryStep) deliverStep) commitStep⟩

private def collect : List (Location × TxID) → List (Location × TxID)
  | [] => []
  | entry :: rest => Atomic.insertGossip entry.1 entry.2 (collect rest)

private theorem collect_perm (entries : List (Location × TxID))
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
      simp only [collect, Atomic.insertGossip, absent, Bool.false_eq_true, ↓reduceIte]
      exact List.Perm.cons _ perm

private theorem maximum_member {entries : List (Location × TxID)}
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

private theorem maximum_exists (entries : List (Location × TxID))
    (nonempty : entries ≠ [])
    : ∃ entry, maximumGossip entries = some entry := by
  cases entries with
  | nil => contradiction
  | cons head tail => exact ⟨_, rfl⟩

private def gathered (config : Properties.ValidConfig) (node : Location)
    (entries : List (Location × TxID))
    : Atomic.NodeState :=
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

private theorem gathered_empty (config : Properties.ValidConfig) (node : Location)
    : gathered config node [] = Atomic.initialNode node := by
  have positive : 0 < config.val.protocol.expectedLocations.length :=
    List.length_pos_iff.mpr (nonempty config)
  simp [gathered, collect, Atomic.initialNode, Nat.not_le.mpr positive]

private def Active (config : Properties.ValidConfig)
    (states : Location → Atomic.NodeState)
    : Prop :=
  ∀ node ∈ config.val.protocol.expectedLocations,
    ((states node).phase = .gossiping ∨ (states node).phase = .voting)
    ∧ ((states node).phase = .voting → (states node).chosen.isSome = true)

private theorem gathered_active (config : Properties.ValidConfig) (node : Location)
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

private theorem active_update {config : Properties.ValidConfig}
    {states : Location → Atomic.NodeState} (active : Active config states)
    (node : Location) (after : Atomic.NodeState)
    (next
      : (after.phase = .gossiping ∨ after.phase = .voting)
        ∧ (after.phase = .voting → after.chosen.isSome = true))
    : Active config (Function.update states node after) := by
  intro other member
  by_cases same : other = node
  · simpa [same] using next
  · simpa [Function.update, same] using active other member

private theorem recovered_of_mem (config : Properties.ValidConfig)
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

private theorem gossip_gathered_run (config : Properties.ValidConfig) (node : Location)
    (recovered : TxID) (entry : Location × TxID)
    (rest : List (Location × TxID))
    (distinct : ((entry :: rest).map Prod.fst).Nodup)
    (bound : (entry :: rest).length ≤ config.val.protocol.expectedLocations.length)
    : (Atomic.step (Capabilities.record node) config.val.protocol recovered
        (gathered config node rest) (.receiveGossip entry.1 entry.2 .accepted)).run
        {}
      = some (gathered config node (entry :: rest), {}) := by
  have smaller : ¬config.val.protocol.expectedLocations.length ≤ rest.length := by
    simp at bound
    omega
  have length : (collect (entry :: rest)).length = (entry :: rest).length :=
    (collect_perm _ distinct).length_eq
  have ins : Atomic.insertGossip entry.1 entry.2 (collect rest) = collect (entry :: rest) := rfl
  by_cases full : config.val.protocol.expectedLocations.length ≤ (entry :: rest).length
  · have populated : collect (entry :: rest) ≠ [] := by
      have positive := List.length_pos_iff.mpr (nonempty config)
      intro empty
      rw [empty, List.length_nil] at length
      omega
    obtain ⟨winner, selected⟩ := maximum_exists (collect (entry :: rest)) populated
    simp only [List.length_cons] at full length
    simp [Atomic.step, gathered, smaller, Atomic.advance, Atomic.validTimeout,
      Atomic.advanceTimeoutLane, ins, full, length, selected]
    rfl
  · simp only [List.length_cons] at full length
    simp [Atomic.step, gathered, smaller, Atomic.advance, Atomic.validTimeout,
      Atomic.advanceTimeoutLane, ins, full, length]
    rfl

private theorem fill_node (config : Properties.ValidConfig) (target : Location)
    (targetMember : target ∈ config.val.protocol.expectedLocations)
    (entries : List (Location × TxID))
    (distinct : (entries.map Prod.fst).Nodup)
    (subset : ∀ entry ∈ entries, entry ∈ config.val.recovered)
    (bound : entries.length ≤ config.val.protocol.expectedLocations.length)
    (states : Location → Atomic.NodeState)
    (reachable : At config states) (active : Active config states)
    (empty : states target = Atomic.initialNode target)
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
      have receive := gossip_gathered_run config target targetTxID entry rest distinct bound
      have next := send_deliver reachableRest entry.1 target (.gossip entry.2)
        sourceMember targetMember entry.2 targetTxID recovered targetRecovered sent retry
        (emitted target targetMember) (gathered config target (entry :: rest)) {}
        (by intro _; simp)
        (by simpa [before, Model.receive] using receive)
      simpa [before] using next

private theorem fill_nodes (config : Properties.ValidConfig) (targets : List Location)
    (distinct : targets.Nodup)
    (subset : ∀ target ∈ targets, target ∈ config.val.protocol.expectedLocations)
    (states : Location → Atomic.NodeState) (reachable : At config states)
    (active : Active config states)
    (empty : ∀ target ∈ targets, states target = Atomic.initialNode target)
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

private theorem full_gossip_reachable (config : Properties.ValidConfig)
    : At config (fun node => gathered config node config.val.recovered) := by
  obtain ⟨states, reachable, _, filled, _⟩ :=
    fill_nodes config config.val.protocol.expectedLocations config.property.2.1
      (fun _ member => member) Atomic.initialNode (at_initial config)
      (by intro node _; simp [Atomic.initialNode])
      (by simp)
  obtain ⟨concrete, network, clean, reachable⟩ := reachable
  refine ⟨concrete, network, ?_, reachable⟩
  intro node member
  simpa [filled node member] using clean node member

private def selected (config : Properties.ValidConfig) (winner node : Location)
    : Atomic.NodeState :=
  {
    location := node,
    phase := .voting,
    chosen := some winner,
    gossips := collect config.val.recovered
  }

private theorem full_choice (config : Properties.ValidConfig)
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
  | source :: rest => Atomic.insertVote source (ballots rest)

private theorem ballots_perm (sources : List Location) (distinct : sources.Nodup)
    : (ballots sources).Perm sources := by
  induction sources with
  | nil => exact .nil
  | cons source rest ih =>
      obtain ⟨absent, distinct⟩ := List.nodup_cons.mp distinct
      have perm := ih distinct
      have missing : source ∉ ballots rest :=
        fun member => absent (perm.mem_iff.mp member)
      simp only [ballots, Atomic.insertVote, List.erase_of_not_mem missing]
      exact List.Perm.cons _ perm

private def voted (config : Properties.ValidConfig) (winner : Location)
    (sources : List Location)
    : Atomic.NodeState :=
  {
    selected config winner winner with
      votes := ballots sources
      phase :=
        if voteQuorum config.val.protocol ≤ sources.length then .opening else .voting
      openKind :=
        if voteQuorum config.val.protocol ≤ sources.length then some .quorum else none
  }

private theorem voted_nil (config : Properties.ValidConfig) (winner : Location)
    : voted config winner [] = selected config winner winner := by
  simp [voted, ballots, voteQuorum, selected]

private theorem voted_active (config : Properties.ValidConfig) (winner : Location)
    (sources : List Location) (small : sources.length < voteQuorum config.val.protocol)
    : ((voted config winner sources).phase = .gossiping
        ∨ (voted config winner sources).phase = .voting)
      ∧ ((voted config winner sources).phase = .voting
          → (voted config winner sources).chosen.isSome = true) := by
  simp [voted, selected, Nat.not_le.mpr small]

private theorem vote_run (config : Properties.ValidConfig) (winner source : Location)
    (recovered : TxID) (rest : List Location) (distinct : (source :: rest).Nodup)
    (bound : (source :: rest).length ≤ voteQuorum config.val.protocol)
    : (Atomic.step (Capabilities.record winner) config.val.protocol recovered
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
  have ins : Atomic.insertVote source (ballots rest) = ballots (source :: rest) := rfl
  by_cases full : voteQuorum config.val.protocol ≤ (source :: rest).length
  · simp only [List.length_cons] at full length
    simp [Atomic.step, voted, selected, smaller, ins, Atomic.advance, Atomic.validTimeout,
      full, length, Atomic.advanceTimeoutLane, Capabilities.record]
    rfl
  · simp only [List.length_cons] at full length
    simp [Atomic.step, voted, selected, smaller, ins, Atomic.advance, Atomic.validTimeout,
      full, length, Atomic.advanceTimeoutLane]
    rfl

private theorem collect_votes (config : Properties.ValidConfig) (winner : Location)
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
      have receive := vote_run config winner source targetTxID rest distinct bound
      let voteOut : Outputs Location Message Notification := {
        notifications :=
          if voteQuorum config.val.protocol ≤ (source :: rest).length then
            [.opening .quorum]
          else
            []
      }
      have next :=
        send_deliver reachableRest source winner .vote sourceMember winnerMember
          sourceTxID targetTxID sourceRecovered targetRecovered sent retry
          (emitted winner phase chosen) (voted config winner (source :: rest)) voteOut
          (by intro _; dsimp [voteOut]; split <;> simp)
          (by simpa [before, Model.receive, voteOut] using receive)
      simpa [before] using next

private theorem quorum_bound (config : Properties.ValidConfig)
    : voteQuorum config.val.protocol ≤ config.val.protocol.expectedLocations.length := by
  have positive := List.length_pos_iff.mpr (nonempty config)
  unfold voteQuorum
  omega

private theorem recovered_distinct (config : Properties.ValidConfig)
    : (config.val.recovered.map Prod.fst).Nodup := by
  rw [config.property.2.2]
  exact config.property.2.1

/-- A full gossip exchange followed by a quorum of genuine votes reaches a quorum opener. -/
theorem quorum_open_preserves_commit_witness
    : ∀ config : Properties.ValidConfig,
        ∃ (behaviour : Properties.Behaviour config) (openedState : Model.State),
        ∃ (opener : Location) (openerState : Model.Local.NodeState),
          openedState ∈ behaviour
          ∧ (opener, openerState) ∈ openedState.nodes
          ∧ openerState.openKind = some .quorum
          ∧ (∀ voter,
              voter ∈ openerState.votes
              → Properties.ReceivedOwnGossip behaviour voter) := by
  intro config
  obtain ⟨winner, winnerMember, _, reachable⟩ := full_choice config
  let voters := config.val.protocol.expectedLocations.take (voteQuorum config.val.protocol)
  have distinct : voters.Nodup := config.property.2.1.take
  have subset : ∀ voter ∈ voters, voter ∈ config.val.protocol.expectedLocations :=
    fun _ member => List.mem_of_mem_take member
  have length : voters.length = voteQuorum config.val.protocol := by
    simp [voters, Nat.min_eq_left (quorum_bound config)]
  let states := Function.update (selected config winner) winner (voted config winner voters)
  obtain ⟨concrete, network, clean, reachable⟩ :=
    collect_votes config winner winnerMember reachable voters distinct subset (by omega)
  let globalState : Model.State := { nodes := table config concrete, network }
  obtain ⟨behaviour, member⟩ := Execution.reachable_iff_behaviour.mp reachable
  have winnerProj := (clean winner winnerMember).represented.project
    (clean winner winnerMember).location
  have winnerKind : (concrete winner).openKind = (voted config winner voters).openKind := by
    have := congrArg Atomic.NodeState.openKind winnerProj
    simpa [states, Atomic.project] using this
  have winnerVotes : (concrete winner).votes = (voted config winner voters).votes := by
    have := congrArg Atomic.NodeState.votes winnerProj
    simpa [states, Atomic.project] using this
  refine ⟨behaviour, globalState, winner, concrete winner, member, ?_, ?_, ?_⟩
  · exact List.mem_map.mpr ⟨winner, winnerMember, rfl⟩
  · rw [winnerKind]
    simp [voted, length]
  · intro voter voterMember
    rw [winnerVotes] at voterMember
    have expected : voter ∈ config.val.protocol.expectedLocations :=
      subset voter ((ballots_perm voters distinct).mem_iff.mp voterMember)
    have own : ∃ txid, (voter, txid) ∈ config.val.recovered := by
      have key : voter ∈ config.val.recovered.map Prod.fst := by
        rw [config.property.2.2]
        exact expected
      obtain ⟨entry, present, key⟩ := List.mem_map.mp key
      exact ⟨entry.2, by simpa [← key] using present⟩
    obtain ⟨txid, own⟩ := own
    refine ⟨globalState, member, concrete voter, txid,
      List.mem_map.mpr ⟨voter, expected, rfl⟩, ?_⟩
    have voterGossips : (concrete voter).gossips = collect config.val.recovered := by
      have h := congrArg Atomic.NodeState.gossips
        ((clean voter expected).represented.project (clean voter expected).location)
      have atom : (states voter).gossips = collect config.val.recovered := by
        by_cases same : voter = winner <;> simp [states, same, voted, selected]
      exact h.trans atom
    rw [voterGossips]
    exact (collect_perm config.val.recovered (recovered_distinct config)).mem_iff.mpr own

private def failoverReady (config : Properties.ValidConfig) (winner : Location)
    : Atomic.NodeState :=
  { voted config winner [winner] with timeoutState := .voting }

private def failedOver (config : Properties.ValidConfig) (winner : Location)
    : Atomic.NodeState :=
  {
    voted config winner [winner] with
      phase := .opening, timeoutState := .opening, openKind := some .failover
  }

private theorem failover_reachable (config : Properties.ValidConfig)
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
      (Atomic.step (Capabilities.record winner) config.val.protocol txid
        (voted config winner [winner]) .timeout).run {} =
        some (failoverReady config winner, {}) := by
    simp [Atomic.step, Atomic.advance, voted, selected, ballots, Atomic.insertVote,
      Atomic.validTimeout, failoverReady, Atomic.advanceTimeoutLane,
      Atomic.advanceTimeoutState, show ¬voteQuorum config.val.protocol ≤ 1 by omega]
  have next :=
    at_timeout votedReachable winner winnerMember txid recovered
      (failoverReady config winner) {} (by intro _; simp)
      (by simpa using first)
  have second :
      (Atomic.step (Capabilities.record winner) config.val.protocol txid
        (failoverReady config winner) .timeout).run {} =
        some (failedOver config winner, { notifications := [.opening .failover] }) := by
    simp [Atomic.step, Atomic.advance, voted, selected, ballots, Atomic.insertVote,
      Atomic.validTimeout, failoverReady, failedOver, Atomic.advanceTimeoutLane,
      Atomic.advanceTimeoutState, Capabilities.record,
      show ¬voteQuorum config.val.protocol ≤ 1 by omega]
  have final :=
    at_timeout next winner winnerMember txid recovered (failedOver config winner)
      { notifications := [.opening .failover] } (by intro _; simp)
      (by simpa using second)
  simpa using final

/-- With at least two locations, one genuine vote and two timeouts reach failover. -/
theorem full_gossip_preserves_commit_witness
    : ∀ config : Properties.ValidConfig,
        2 ≤ config.val.protocol.expectedLocations.length
        → ∃ (behaviour : Properties.Behaviour config)
            (gossipedState openedState : Model.State),
          ∃ (opener : Location) (openerState : Model.Local.NodeState),
            gossipedState ∈ behaviour
            ∧ (∀ node nodeState,
                node ∈ config.val.protocol.expectedLocations
                → (node, nodeState) ∈ gossipedState.nodes
                → ∀ gossip, gossip ∈ nodeState.gossips ↔ gossip ∈ config.val.recovered)
            ∧ openedState ∈ behaviour
            ∧ (opener, openerState) ∈ openedState.nodes
            ∧ openerState.openKind = some .failover := by
  intro config multiple
  obtain ⟨winner, winnerMember, _, reachable⟩ := full_choice config
  obtain ⟨concrete, network, clean, reachable⟩ :=
    failover_reachable config multiple winner winnerMember reachable
  let states := Function.update (selected config winner) winner (failedOver config winner)
  let globalState : Model.State := { nodes := table config concrete, network }
  obtain ⟨behaviour, member⟩ := Execution.reachable_iff_behaviour.mp reachable
  have winnerKind : (concrete winner).openKind = some .failover := by
    have := congrArg Atomic.NodeState.openKind
      ((clean winner winnerMember).represented.project (clean winner winnerMember).location)
    simpa [states, failedOver, Atomic.project] using this
  refine ⟨behaviour, globalState, globalState, winner, concrete winner,
    member, ?_, member, ?_, winnerKind⟩
  · intro node nodeState expected present gossip
    obtain ⟨key, _, pair⟩ := List.mem_map.mp present
    have keyEq : key = node := congrArg Prod.fst pair
    have stateEq : concrete node = nodeState := by
      simpa [keyEq] using congrArg Prod.snd pair
    rw [← stateEq]
    have nodeGossips : (concrete node).gossips = collect config.val.recovered := by
      have h := congrArg Atomic.NodeState.gossips
        ((clean node expected).represented.project (clean node expected).location)
      have atom : (states node).gossips = collect config.val.recovered := by
        by_cases same : node = winner <;>
          simp [states, same, failedOver, voted, selected]
      exact h.trans atom
    rw [nodeGossips]
    exact (collect_perm config.val.recovered (recovered_distinct config)).mem_iff
  · exact List.mem_map.mpr ⟨winner, winnerMember, rfl⟩

private theorem snoc_before {α β : Type} (start before after : β)
    (steps : List (α × β)) (action : α)
    (last : (start :: steps.map Prod.snd)[steps.length]? = some before)
    : (start :: (steps ++ [(action, after)]).map Prod.snd)[steps.length]?
      = some before := by
  simp only [List.map_append, List.map_cons, List.map_nil]
  change ((start :: steps.map Prod.snd) ++ [after])[steps.length]? = some before
  rw [List.getElem?_append]
  simpa using last

private theorem snoc_after {α β : Type} (start after : β)
    (steps : List (α × β)) (action : α)
    : (start :: (steps ++ [(action, after)]).map Prod.snd)[steps.length + 1]?
      = some after := by
  simp only [List.map_append, List.map_cons, List.map_nil]
  change ((start :: steps.map Prod.snd) ++ [after])[steps.length + 1]? = some after
  rw [List.getElem?_append]
  simp

private theorem reachable_finite {system : TransitionSystem} {state : system.State}
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

private theorem commit_notification_exists (config : Properties.ValidConfig)
    (concrete : Location → Model.Local.NodeState) (network : List Model.Envelope)
    (reachable
      : (Model.transitionSystem config).Reachable
          { nodes := table config concrete, network })
    (node : Location) (member : node ∈ config.val.protocol.expectedLocations)
    (after : Model.Local.NodeState) (outputs : Outputs Location Message Notification)
    (commit
      : ((Model.protocol config).step (Capabilities.record node) node
          (concrete node) (.commit 0)).run
          {}
        = some (after, outputs))
    (notif : Notification) (notified : notif ∈ outputs.notifications)
    : ∃ (behaviour : Properties.Behaviour config) (index : Nat) (actor : Location),
        Properties.Behaviour.NotificationAt config behaviour index actor notif := by
  let beforeGlobal : Model.State := { nodes := table config concrete, network }
  let nextConcrete := Function.update concrete node after
  let afterGlobal : Model.State := {
    nodes := table config nextConcrete
    network := network ++ outputs.outgoing }
  have enabled : (Model.transitionSystem config).step beforeGlobal (.local node (.commit 0))
      = some afterGlobal :=
    local_next config concrete network node member (.commit 0) after outputs commit
  obtain ⟨start, steps, initialized, valid, last⟩ := reachable_finite reachable
  let behaviour := ofSteps start (steps ++ [(.local node (.commit 0), afterGlobal)]) initialized
    (steps_snoc start beforeGlobal afterGlobal steps (.local node (.commit 0)) valid last enabled)
  refine ⟨behaviour, steps.length, node, beforeGlobal, afterGlobal,
    .local node (.commit 0), concrete node, after, outputs, ?_, ?_, ?_, rfl, ?_, ?_,
    commit, notified⟩
  · rw [ofSteps_stateAt]
    exact snoc_before start beforeGlobal afterGlobal steps (.local node (.commit 0)) last
  · rw [ofSteps_stateAt]
    exact snoc_after start afterGlobal steps (.local node (.commit 0))
  · rw [ofSteps_actionAt]
    simp [List.map_append]
  · exact lookup_table config concrete node member network
  · simpa [nextConcrete]
      using lookup_table config nextConcrete node member afterGlobal.network

/-- The final vote of a quorum emits an opening notification in a valid finite behaviour. -/
theorem quorum_opener_unique_witness
    : ∀ config : Properties.ValidConfig,
        ∃ (behaviour : Properties.Behaviour config) (index : Nat) (opener : Location),
          Properties.Behaviour.NotificationAt config behaviour index opener
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
  obtain ⟨concrete, network, clean, reachableRest⟩ := reachableRest
  have retryReal :
      (Model.Local.perform (Capabilities.record source) config.val.protocol sourceTxID
        (concrete source) .retry).run {} = some (concrete source, sent) := by
    rw [Atomic.retry_agrees config.val.protocol source sourceTxID (concrete source)
      (states source) (clean source sourceMember).represented (clean source sourceMember).location,
      retry]
    rfl
  have sentStep := local_next config concrete network source sourceMember .retry
    (concrete source) sent
    (protocol_perform config source sourceTxID (concrete source) (concrete source) .retry
      sent sourceRecovered retryReal)
  simp only [Function.update_eq_self] at sentStep
  have reachableSent : (Model.transitionSystem config).Reachable
      { nodes := table config concrete, network := network ++ sent.outgoing } :=
    .step (action := .local source .retry) reachableRest sentStep
  have full : voteQuorum config.val.protocol ≤ (source :: rest).length := by
    rw [← eq, length]
    exact Nat.le_refl _
  have receive := vote_run config winner source targetTxID rest distinct'
    (by rw [← eq, length]; exact Nat.le_refl _)
  let voteOut : Outputs Location Message Notification := {
    notifications :=
      if voteQuorum config.val.protocol ≤ (source :: rest).length then
        [.opening .quorum]
      else
        []
  }
  obtain ⟨mid, last, early, runEq, _, commitEq, _⟩ :=
    Atomic.run_commit config.val.protocol winner targetTxID (concrete winner) (states winner)
      (voted config winner (source :: rest)) (clean winner winnerMember)
      (Model.receive source .vote) (receive_ne_retry source .vote) voteOut
      (by intro _; dsimp [voteOut]; split <;> simp)
      (by simpa [states, Model.receive, voteOut] using receive)
  have deliverStep := delivery_next config concrete (network ++ sent.outgoing)
    { source, target := winner, payload := .vote } winnerMember
    (List.mem_append_right _ (emitted winner phase chosen)) mid early
    (protocol_perform config winner targetTxID (concrete winner) mid
      (.run (Model.receive source .vote)) early targetRecovered runEq)
  have reachableDelivered : (Model.transitionSystem config).Reachable
      {
        nodes := table config (Function.update concrete winner mid)
        network := MultiNodeTransitionSystem.removeOne
          { source, target := winner, payload := .vote }
          (network ++ sent.outgoing) ++ early.outgoing
      } :=
    .step (action := .deliver { source, target := winner, payload := .vote })
      reachableSent deliverStep
  exact commit_notification_exists config
    (Function.update concrete winner mid)
    _ reachableDelivered winner winnerMember last voteOut
    (by
      simpa [Model.protocol]
        using protocol_perform config winner targetTxID mid last (.commit 0) voteOut
          targetRecovered commitEq)
    (.opening .quorum)
    (by
      simp [voteOut]
      exact full)

/-- A failover opener can announce itself to another configured node, which commits the restart. -/
theorem restart_excludes_opening_witness (config : Properties.ValidConfig)
    (multiple : 2 ≤ config.val.protocol.expectedLocations.length)
    : ∃ (behaviour : Properties.Behaviour config) (index : Nat) (node chosen : Location),
        Properties.Behaviour.NotificationAt config behaviour index node
          (.restart chosen) := by
  obtain ⟨winner, member, _, ready⟩ := full_choice config
  let peers := config.val.protocol.expectedLocations.filter (· != winner)
  have distinct := config.property.2.1
  have nonemptyPeers : peers ≠ [] := by
    intro empty
    have sub : config.val.protocol.expectedLocations ⊆ [winner] := by
      intro node mem
      by_cases same : node = winner
      · simp [same]
      · have has : node ∈ peers := List.mem_filter.mpr ⟨mem, by simpa using same⟩
        simp [empty] at has
    have bound := distinct.length_le_of_subset sub
    simp at bound
    omega
  obtain ⟨peer, peerMem⟩ := List.exists_mem_of_ne_nil _ nonemptyPeers
  obtain ⟨configured, different⟩ := List.mem_filter.mp peerMem
  have ne : peer ≠ winner := by simpa using different
  let states := Function.update (selected config winner) winner (failedOver config winner)
  obtain ⟨concrete, network, clean, reachable⟩ :=
    failover_reachable config multiple winner member ready
  let sent : Outputs Location Message Notification :=
    { outgoing := peers.map fun target => { source := winner, target, payload := .iAmOpen } }
  obtain ⟨tx, recovered⟩ := recovered_exists config winner member
  have retry :
      (Atomic.step (Capabilities.record winner) config.val.protocol tx (states winner) .retry).run {}
        = some (states winner, sent) := by
    have ph : (states winner).phase = .opening := by simp [states, failedOver]
    have location : (states winner).location = winner := by
      simp [states, failedOver, voted, selected]
    simp only [Atomic.step, ph, location]
    change (do
      guard (!peers.isEmpty)
      for target in peers do
        (Capabilities.record winner).send .iAmOpen target
      pure (states winner) : Effect Location Message Notification Atomic.NodeState).run {} = _
    simp [guard, nonemptyPeers, broadcast_run, sent]
  have retryReal :
      (Model.Local.perform (Capabilities.record winner) config.val.protocol tx
        (concrete winner) .retry).run {} = some (concrete winner, sent) := by
    rw [Atomic.retry_agrees config.val.protocol winner tx (concrete winner) (states winner)
      (clean winner member).represented (clean winner member).location, retry]
    rfl
  have sentStep := local_next config concrete network winner member .retry
    (concrete winner) sent
    (protocol_perform config winner tx (concrete winner) (concrete winner) .retry
      sent recovered retryReal)
  simp only [Function.update_eq_self] at sentStep
  have sentReach : (Model.transitionSystem config).Reachable
      { nodes := table config concrete, network := network ++ sent.outgoing } :=
    .step (action := .local winner .retry) reachable sentStep
  obtain ⟨peerTx, peerRecovered⟩ := recovered_exists config peer configured
  let before := selected config winner peer
  let after : Atomic.NodeState := { before with phase := .joining, chosen := some winner }
  let restartOut : Outputs Location Message Notification :=
    { notifications := [.restart winner] }
  have body :
      (Atomic.step (Capabilities.record peer) config.val.protocol peerTx before
        (.receiveIAmOpen winner .accepted)).run {} = some (after, restartOut) := by
    rfl
  obtain ⟨mid, last, early, runEq, _, commitEq, _⟩ :=
    Atomic.run_commit config.val.protocol peer peerTx (concrete peer) (states peer) after
      (clean peer configured) (Model.receive winner .iAmOpen)
      (receive_ne_retry winner .iAmOpen) restartOut (by intro _; simp [restartOut])
      (by simpa [states, ne, before, Model.receive] using body)
  have deliverStep := delivery_next config concrete (network ++ sent.outgoing)
    { source := winner, target := peer, payload := .iAmOpen } configured
    (List.mem_append_right _ (List.mem_map.mpr ⟨peer, peerMem, rfl⟩)) mid early
    (protocol_perform config peer peerTx (concrete peer) mid
      (.run (Model.receive winner .iAmOpen)) early peerRecovered runEq)
  have deliverReach : (Model.transitionSystem config).Reachable
      {
        nodes := table config (Function.update concrete peer mid)
        network := MultiNodeTransitionSystem.removeOne
          { source := winner, target := peer, payload := .iAmOpen }
          (network ++ sent.outgoing) ++ early.outgoing
      } :=
    .step (action := .deliver { source := winner, target := peer, payload := .iAmOpen })
      sentReach deliverStep
  obtain ⟨behaviour, index, node, restart⟩ :=
    commit_notification_exists config (Function.update concrete peer mid) _
      deliverReach peer configured last restartOut
      (by
        simpa [Model.protocol] using
          protocol_perform config peer peerTx mid last (.commit 0) restartOut
            peerRecovered commitEq)
      (.restart winner) (by simp [restartOut])
  exact ⟨behaviour, index, node, winner, restart⟩

end DisasterRecovery.Proofs.GlobalWitnesses
