module

public import Consensus.Model

import Mathlib.Tactic.Lemma
import all Init.Control.State

@[expose] public section

namespace Consensus.Proofs.Deadlock

open CCF CCF.MultiNodeTransitionSystem Model.Node

private theorem reachable_nodes_nonempty (config : Finset NodeID) (nodes : List NodeID)
    (state : Model.State)
    (reachable : (Model.transitionSystem config nodes).Reachable state)
    : state.nodes ≠ [] := by
  induction reachable
    using @TransitionSystem.Reachable.rec (Model.transitionSystem config nodes) with
  | initial initialized =>
      intro empty
      have keys := initialized.2.1
      rw [empty] at keys
      exact initialized.2.2.2 keys.symm
  | @step before after action _reachable transition ih =>
      have preserve (target : NodeID) (event : Event) (pending : List Model.Envelope)
          (transition :
            (do
              let localState <- nodeState before target
              let (updated, effects) <-
                ((Model.protocol config).step (Capabilities.record target) target localState event).run {}
              pure {
                nodes := before.nodes.map
                  (fun entry => if entry.1 == target then (target, updated) else entry)
                network := pending ++ effects.outgoing
              }) = some after) : after.nodes ≠ [] := by
        obtain ⟨_, _, transition⟩ := Option.bind_eq_some_iff.mp transition
        obtain ⟨⟨_, _⟩, _, transition⟩ := Option.bind_eq_some_iff.mp transition
        cases Option.some.inj transition
        simpa using ih
      change next (Model.protocol config) before action = some after at transition
      cases action with
      | «local» node input =>
          exact preserve node (.internal input) before.network transition
      | deliver envelope =>
          simp only [next] at transition
          obtain ⟨_, _, transition⟩ := Option.bind_eq_some_iff.mp transition
          exact preserve envelope.target (.receive envelope.source envelope.payload)
            (removeOne envelope before.network) transition

theorem deadlock_free (config : Finset NodeID) (nodes : List NodeID)
    : (Model.transitionSystem config nodes).DeadlockFree := by
  intro state reachable
  have nonempty := reachable_nodes_nonempty config nodes state reachable
  cases members : state.nodes with
  | nil => exact False.elim (nonempty members)
  | cons entry rest =>
      have idle : (pure entry.2 : NodeEffect NodeState) {} = some (entry.2, {}) := rfl
      refine ⟨.local entry.1 .tick, {
        nodes := state.nodes.map
          (fun candidate => if candidate.1 == entry.1 then (entry.1, entry.2) else candidate)
        network := state.network
      }, ?_⟩
      simp [next, nodeState, members, Model.protocol, Model.Node.step, act,
        StateT.run, idle]

lemma deadlock_free_witness
    : exists (config : Finset NodeID) (nodes : List NodeID) (state : Model.State),
        (Model.transitionSystem config nodes).Reachable state := by
  refine ⟨{0}, [0], { nodes := [(0, Model.initialNodeState {0} 0)] }, .initial ?_⟩
  simp [Model.protocol]

end Consensus.Proofs.Deadlock
