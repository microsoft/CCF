module

public import Consensus.Model

import Mathlib.Tactic.Lemma
import all Init.Control.State

@[expose] public section

namespace Consensus.Proofs.Deadlock

open CCF CCF.MultiNodeTransitionSystem Model.Node

theorem initial_deadlock_free (node : NodeID) (nodes : List NodeID) (state : Model.State)
    (declared : node ∈ nodes)
    (initialized : (Model.transitionSystem {node} nodes).init state)
    : exists action nextState,
        (Model.transitionSystem {node} nodes).step state action = some nextState := by
  have listed : node ∈ state.nodes.map Prod.fst := initialized.2.1.symm ▸ declared
  obtain ⟨entry, member, keyEq⟩ := List.mem_map.mp listed
  have foundSome :
      (state.nodes.find? fun entry => entry.1 == node).isSome = true :=
    List.find?_isSome.mpr ⟨entry, member, by simp [keyEq]⟩
  obtain ⟨entry, located⟩ := Option.isSome_iff_exists.mp foundSome
  have keyEq : entry.1 = node := by simpa using List.find?_some located
  have localEq : entry.2 = Model.initialNodeState {node} node := by
    simpa [Model.protocol, keyEq]
      using initialized.2.2.2.2 entry (List.mem_of_find?_eq_some located)
  have found : nodeState state node = some (Model.initialNodeState {node} node) := by
    simp [nodeState, located, localEq]
  have primary : (Model.initialNodeState {node} node).role = .primary := by
    simp [Model.initialNodeState]
  have enabled :
      exists effects,
        (Model.Node.step (Capabilities.record node) node
          (Model.initialNodeState {node} node) (.internal .nominateSuccessor)).run {}
          = some (Model.initialNodeState {node} node, effects) := by
    cases successor : findSuccessor (Model.initialNodeState {node} node) node with
    | none =>
        refine ⟨{}, ?_⟩
        simp only [Model.Node.step, act, nominateSuccessor, primary,
          successor, guard, ite_true]
        rfl
    | some peer =>
        refine ⟨{ outgoing := [{
          source := node
          target := peer
          payload := .proposeRequestVoteRequest (Model.initialNodeState {node} node).currentTerm
        }] }, ?_⟩
        simp only [Model.Node.step, act, nominateSuccessor, primary,
          successor, guard, ite_true]
        rfl
  obtain ⟨effects, enabled⟩ := enabled
  refine ⟨.local node .nominateSuccessor, {
    nodes := state.nodes.map fun entry =>
      if entry.1 == node then (node, Model.initialNodeState {node} node) else entry
    network := state.network ++ effects.outgoing
  }, ?_⟩
  simp [next, Model.protocol, found, enabled]

lemma initial_deadlock_free_witness
    : exists (node : NodeID) (nodes : List NodeID) (state : Model.State),
        node ∈ nodes /\ (Model.transitionSystem {node} nodes).init state := by
  refine ⟨0, [0], { nodes := [(0, Model.initialNodeState {0} 0)] }, by simp, ?_⟩
  simp [Model.protocol]

end Consensus.Proofs.Deadlock
