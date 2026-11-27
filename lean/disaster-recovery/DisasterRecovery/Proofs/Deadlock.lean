module

public import DisasterRecovery.Properties.Utils

import DisasterRecovery.Proofs.Evaluation
import all Init.Control.State

@[expose] public section

set_option linter.unusedSimpArgs false

namespace DisasterRecovery.Proofs.Deadlock

open CCF Model Model.Local

@[local simp]
private theorem effect_bind {S A B : Type} (a : StateT S Option A)
    (f : A -> StateT S Option B) (s : S)
    : (a >>= f) s = (a s).bind (fun (a, s) => f a s) :=
  rfl

@[local simp]
private theorem effect_lift {S A : Type} (a : Option A) (s : S)
    : (liftM a : StateT S Option A) s = a.map (fun a => (a, s)) := by
  cases a <;> rfl

private def WellFormed (config : Model.Config) (state : Model.State) : Prop :=
  config.Valid
  /\ (forall node,
        node ∈ config.protocol.expectedLocations -> node ∈ state.nodes.map Prod.fst)

private theorem reachable_wellFormed (config : Model.Config) (state : Model.State)
    (reachable : (transitionSystem config).Reachable state)
    : WellFormed config state := by
  induction reachable using @TransitionSystem.Reachable.rec (transitionSystem config) with
  | initial initialized =>
      exact ⟨initialized.1, initialized.2.1⟩
  | @step before after action _reachable transition ih =>
      have preserve (target : Location) (event : Operation) (pending : List Model.Envelope)
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
        obtain ⟨localState, _, transition⟩ := Option.bind_eq_some_iff.mp transition
        obtain ⟨⟨updated, effects⟩, _, transition⟩ := Option.bind_eq_some_iff.mp transition
        cases Option.some.inj transition
        refine ⟨ih.1, ?_⟩
        intro node expected
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
        exact ih.2 node expected
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
  obtain ⟨entry, found⟩ := lookup_exists state.nodes node (wellFormed.2 node expected)
  have recoveredMember : node ∈ config.recovered.map Prod.fst := by
    rw [wellFormed.1.2.2]
    exact expected
  obtain ⟨ledger, recovered⟩ := lookup_exists config.recovered node recoveredMember
  obtain ⟨after, effects, enabled⟩ := Evaluation.timeout_enabled node config.protocol ledger.2 entry.2
  refine ⟨
    .local node .timeout,
    {
      nodes :=
        state.nodes.map (fun entry => if entry.1 == node then (node, after) else entry)
      network := state.network ++ effects.outgoing
    },
    ?_
  ⟩
  change MultiNodeTransitionSystem.next (protocol config) state (.local node .timeout) = _
  simp [MultiNodeTransitionSystem.next, MultiNodeTransitionSystem.nodeState, found,
    protocol, recoveredTxID, recovered, StateT.run] at enabled ⊢
  rw [enabled]
  rfl

theorem deadlock_free_witness
    : forall (config : Properties.ValidConfig),
        exists (state : Model.State), (transitionSystem config).Reachable state := by
  intro config
  refine ⟨{
    nodes := config.val.protocol.expectedLocations.map fun node => (node, initialNode node)
  }, .initial ?_⟩
  refine ⟨config.property, ?_, ?_, rfl, ?_⟩
  · simp [Function.comp_def]
  · simpa [Function.comp_def] using config.property.2.1
  · intro entry member
    obtain ⟨node, _, rfl⟩ := List.mem_map.mp member
    rfl

end DisasterRecovery.Proofs.Deadlock
