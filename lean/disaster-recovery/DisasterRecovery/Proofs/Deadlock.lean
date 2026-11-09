module

public import DisasterRecovery.Model

import all Init.Control.State
import Aesop
import Mathlib.Tactic.Lemma

@[expose] public section

set_option linter.unusedSimpArgs false

namespace DisasterRecovery.Proofs.Deadlock

open CCF Model Model.Local

private def Ready (state : NodeState) : Prop :=
  state.phase = .joining -> state.chosen ≠ none

@[local simp]
private theorem effect_bind {S A B : Type} (a : StateT S Option A)
    (f : A -> StateT S Option B) (s : S)
    : (a >>= f) s = (a s).bind (fun (a, s) => f a s) :=
  rfl

@[local simp]
private theorem effect_pure {S A : Type} (a : A) (s : S)
    : (pure a : StateT S Option A) s = some (a, s) :=
  rfl

@[local simp]
private theorem effect_failure {S A : Type} (s : S)
    : (failure : StateT S Option A) s = none :=
  rfl

@[local simp]
private theorem effect_modify {S : Type} (f : S -> S) (s : S)
    : (modify f : StateT S Option Unit) s = some ((), f s) :=
  rfl

@[local simp]
private theorem effect_map {S A B : Type} (f : A -> B) (a : StateT S Option A) (s : S)
    : (f <$> a) s = (a s).map (fun (a, s) => (f a, s)) := by
  change ((a s).bind fun (a, s) => some (f a, s)) = _
  cases a s <;> rfl

@[local simp]
private theorem effect_orElse {S A : Type} (a : StateT S Option A)
    (b : Unit -> StateT S Option A) (s : S)
    : (StateT.orElse a b) s = (a s <|> b () s) :=
  rfl

private theorem advance_ready (config : Local.Config) (state : NodeState)
    (source : Location) (timeout : Bool) (outputs : Outputs Location Message Notification)
    (ready : Ready state)
    : forall after effects,
        (advance (Capabilities.record source) config state timeout).run outputs
          = some (after, effects)
        -> Ready after := by
  intro after effects transition
  cases phase : state.phase <;> cases timeout <;>
    simp [advance, phase, validTimeout, advanceTimeoutLane, StateT.run, Capabilities.record]
      at transition
  all_goals
    repeat first
      | simp_all [Ready, Capabilities.record]
      | split at transition
  all_goals
    cases gossip : maximumGossip state.gossips <;> cases chosen : state.chosen <;>
      simp_all [Ready, Capabilities.record] <;> aesop

private theorem advance_or_reject_ready (config : Local.Config)
    (state fallback : NodeState) (source : Location) (reason : String)
    (ready : Ready state) (fallbackReady : Ready fallback) (after : NodeState)
    (effects : Outputs Location Message Notification)
    (transition
      : ((advance (Capabilities.record source) config state false
          <|> rejected (Capabilities.record source) fallback reason).run
          {})
        = some (after, effects))
    : Ready after := by
  change (StateT.orElse
    (advance (Capabilities.record source) config state false)
    (fun _ => rejected (Capabilities.record source) fallback reason)) {} = _ at transition
  rw [effect_orElse] at transition
  change ((advance (Capabilities.record source) config state false).run {} <|> _) = _
    at transition
  cases run : (advance (Capabilities.record source) config state false).run {} with
  | none =>
      rw [run] at transition
      simp [rejected, Capabilities.record] at transition
      obtain ⟨rfl, _⟩ := transition
      exact fallbackReady
  | some result =>
      rw [run] at transition
      have same : result = (after, effects) := by
        simpa using transition
      exact advance_ready config state source false {} ready after effects (same ▸ run)

private theorem step_ready (config : Local.Config) (state : NodeState)
    (source : Location) (recovered : TxID) (event : Event)
    (ready : Ready state)
    : forall after effects,
        (Local.step (Capabilities.record source) config recovered state event).run {}
          = some (after, effects)
        -> Ready after := by
  intro after effects transition
  cases event with
  | timeout =>
      exact advance_ready config state source true {} ready after effects transition
  | retry =>
      cases phase : state.phase <;>
        simp [Local.step, phase, StateT.run, Option.bind_eq_some_iff,
          Option.map_eq_some_iff] at transition
      all_goals first
        | solve | aesop
        | cases chosen : state.chosen <;>
            simp_all [Option.bind_eq_some_iff, Option.map_eq_some_iff, Capabilities.record]
            <;> aesop
  | receiveGossip sender txid validation =>
      cases validation <;> simp only [Local.step] at transition
      · split at transition
        · simp [rejected, Capabilities.record] at transition
          aesop
        · exact advance_or_reject_ready config _ state source _ (by simpa [Ready] using ready)
            ready after effects transition
      · simp [rejected, Capabilities.record] at transition
        aesop
  | receiveVote sender validation =>
      cases validation <;> simp only [Local.step] at transition
      · exact advance_or_reject_ready config _ state source _ (by simpa [Ready] using ready)
          ready after effects transition
      · simp [rejected, Capabilities.record] at transition
        aesop
  | receiveIAmOpen sender validation =>
      cases validation <;> simp only [Local.step] at transition
      · cases phase : state.phase <;> simp only [phase] at transition
        all_goals first
          | exact advance_or_reject_ready config _ state source _ (by simp [Ready])
              ready after effects transition
          | simp [rejected, Capabilities.record] at transition; aesop
      · simp [rejected, Capabilities.record] at transition
        aesop

@[local simp]
private theorem effect_lift {S A : Type} (a : Option A) (s : S)
    : (liftM a : StateT S Option A) s = a.map (fun a => (a, s)) := by
  cases a <;> rfl

private def WellFormed (config : Model.Config) (state : Model.State) : Prop :=
  config.Valid
  /\ (forall node,
        node ∈ config.protocol.expectedLocations -> node ∈ state.nodes.map Prod.fst)
  /\ (forall entry, entry ∈ state.nodes -> Ready entry.2)

private theorem reachable_wellFormed (config : Model.Config) (state : Model.State)
    (reachable : (transitionSystem config).Reachable state)
    : WellFormed config state := by
  induction reachable using @TransitionSystem.Reachable.rec (transitionSystem config) with
  | initial initialized =>
      refine ⟨initialized.1, initialized.2.1, ?_⟩
      intro entry member
      have initializedNode := initialized.2.2.2.2 entry member
      rw [show entry.2 = initialNode entry.1 from initializedNode]
      simp [Ready, initialNode]
  | @step before after action _reachable transition ih =>
      have preserve (target : Location) (event : Event) (pending : List Model.Envelope)
          (transition :
            (do
              let localState <- MultiNodeTransitionSystem.nodeState before target
              let (updated, effects) <-
                ((protocol config).step (Capabilities.record target) target localState event).run {}
              pure {
                nodes := before.nodes.map
                  (fun entry => if entry.1 == target then (target, updated) else entry)
                network := pending ++ effects.outgoing
              }) = some after) : WellFormed config after := by
        obtain ⟨localState, found, transition⟩ := Option.bind_eq_some_iff.mp transition
        obtain ⟨⟨updated, effects⟩, ran, transition⟩ := Option.bind_eq_some_iff.mp transition
        cases Option.some.inj transition
        have member : (target, localState) ∈ before.nodes := by
          obtain ⟨entry, selected, same⟩ := Option.map_eq_some_iff.mp found
          have present := List.mem_of_find?_eq_some selected
          have key := List.find?_some selected
          have equal : entry = (target, localState) := by
            exact Prod.ext (by simpa using key) same
          exact equal ▸ present
        have localReady := ih.2.2 _ member
        have updatedReady : Ready updated := by
          simp only [protocol, StateT.run, effect_bind, effect_lift,
            Option.bind_eq_some_iff, Option.map_eq_some_iff] at ran
          obtain ⟨_, ⟨recovered, _, rfl⟩, ran⟩ := ran
          exact step_ready config.protocol localState target recovered event localReady
            updated effects ran
        refine ⟨ih.1, ?_, ?_⟩
        · intro node expected
          have keys :
              (before.nodes.map
                (fun entry => if entry.1 == target then (target, updated) else entry)).map
                  Prod.fst = before.nodes.map Prod.fst := by
            simp only [List.map_map]
            apply List.map_congr_left
            intro entry _
            simp only [Function.comp_apply]
            split <;> simp_all
          rw [keys]
          exact ih.2.1 node expected
        · intro entry member
          obtain ⟨old, present, rfl⟩ := List.mem_map.mp member
          split
          · exact updatedReady
          · exact ih.2.2 old present
      change MultiNodeTransitionSystem.next (protocol config) before action = some after
        at transition
      cases action with
      | «local» node input =>
          exact preserve node ((protocol config).internal input) before.network transition
      | deliver envelope =>
          simp only [MultiNodeTransitionSystem.next] at transition
          obtain ⟨_, _, transition⟩ := Option.bind_eq_some_iff.mp transition
          exact preserve envelope.target ((protocol config).receive envelope.source envelope.payload)
            (MultiNodeTransitionSystem.removeOne envelope before.network) transition

@[local simp]
private theorem send_run (source target : Location) (message : Message)
    (outputs : Outputs Location Message Notification)
    : (Capabilities.record source).send message target outputs
      = some
          (
            (),
            {
              outputs with
                outgoing :=
                  outputs.outgoing ++ [{ source, target, payload := message }]
            }
          ) :=
  rfl

private theorem send_all (source : Location) (message : Message) (targets : List Location)
    (outputs : Outputs Location Message Notification)
    : (targets.foldlM
        (fun (_ : PUnit) target => (Capabilities.record source).send message target)
        PUnit.unit)
        outputs
      = some
          (
            PUnit.unit,
            {
              outputs with
                outgoing :=
                  outputs.outgoing
                  ++ targets.map (fun target => { source, target, payload := message })
            }
          ) := by
  induction targets generalizing outputs with
  | nil => simp
  | cons head tail ih =>
      simp only [List.foldlM_cons, effect_bind, send_run,
        Option.bind_some, ih, List.map_cons, List.append_assoc, List.singleton_append]

@[local simp]
private theorem effect_guard {S : Type} (p : Prop) [Decidable p] (s : S)
    : (guard p : StateT S Option Unit) s = if p then some ((), s) else none := by
  unfold guard
  split <;> rfl

private theorem local_enabled (config : Model.Config) (state : NodeState)
    (source : Location) (recovered : TxID)
    (nonempty : config.protocol.expectedLocations ≠ []) (ready : Ready state)
    : exists input after effects,
        (Local.step (Capabilities.record source) config.protocol recovered state
          ((protocol config).internal input)).run
          {}
        = some (after, effects) := by
  cases phase : state.phase with
  | gossiping =>
      refine ⟨.retry, ?_⟩
      simp [protocol, Local.step, phase, nonempty, StateT.run, send_all]
  | voting =>
      refine ⟨.retry, ?_⟩
      cases chosen : state.chosen <;>
        simp [protocol, Local.step, phase, chosen, nonempty, StateT.run, send_all]
  | joining =>
      refine ⟨.timeout, ?_⟩
      cases chosen : state.chosen with
      | none => exact False.elim (ready phase chosen)
      | some target =>
          simp [protocol, Local.step, advance, phase, chosen, StateT.run,
            Capabilities.record]
  | opening =>
      refine ⟨.timeout, ?_⟩
      cases lane : state.timeoutState <;>
        simp [protocol, Local.step, advance, phase, lane, validTimeout, StateT.run,
          Capabilities.record]
  | «open» =>
      refine ⟨.timeout, ?_⟩
      simp [protocol, Local.step, advance, phase, StateT.run]

private theorem lookup_exists {Value : Type} (entries : List (Location × Value))
    (node : Location) (member : node ∈ entries.map Prod.fst)
    : exists entry, entries.find? (fun entry => entry.1 == node) = some entry := by
  apply Option.isSome_iff_exists.mp
  rw [List.find?_isSome]
  obtain ⟨entry, present, key⟩ := List.mem_map.mp member
  exact ⟨entry, present, by simpa using key⟩

theorem deadlock_free (config : Model.Config)
    : (transitionSystem config).DeadlockFree := by
  intro state reachable
  have wellFormed := reachable_wellFormed config state reachable
  have nonempty : config.protocol.expectedLocations ≠ [] := by
    intro empty
    have valid := wellFormed.1.1
    simp [Local.Config.isValid, empty] at valid
  obtain ⟨node, expected⟩ := List.exists_mem_of_ne_nil _ nonempty
  obtain ⟨entry, found⟩ := lookup_exists state.nodes node (wellFormed.2.1 node expected)
  have ready := wellFormed.2.2 entry (List.mem_of_find?_eq_some found)
  have recoveredMember : node ∈ config.recovered.map Prod.fst := by
    rw [wellFormed.1.2.2]
    exact expected
  obtain ⟨ledger, recovered⟩ := lookup_exists config.recovered node recoveredMember
  obtain ⟨input, after, effects, enabled⟩ :=
    local_enabled config entry.2 node ledger.2 nonempty ready
  refine ⟨
    .local node input,
    {
      nodes :=
        state.nodes.map (fun entry => if entry.1 == node then (node, after) else entry)
      network := state.network ++ effects.outgoing
    },
    ?_
  ⟩
  change MultiNodeTransitionSystem.next (protocol config) state (.local node input) = _
  simp [MultiNodeTransitionSystem.next, MultiNodeTransitionSystem.nodeState, found,
    protocol, recoveredTxID, recovered, StateT.run] at enabled ⊢
  rw [enabled]
  rfl

lemma deadlock_free_witness
    : exists (config : Model.Config) (state : Model.State),
        (transitionSystem config).Reachable state := by
  refine ⟨{
    protocol := { instanceId := "recovery", expectedLocations := ["a"] }
    recovered := [("a", { view := 1, seqno := 1 })]
  }, { nodes := [("a", initialNode "a")] }, .initial ?_⟩
  simp [transitionSystem, MultiNodeTransitionSystem.lift, protocol, Model.Config.Valid,
    Local.Config.isValid]
  decide

end DisasterRecovery.Proofs.Deadlock
