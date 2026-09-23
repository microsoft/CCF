-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model
import Mathlib.Tactic

set_option autoImplicit false
set_option linter.unusedSectionVars false

/-!
Unfolds one step of `Model.transitionSystem` into the acting node's local
step, its new state, and its sends.
-/

namespace CCFRaft.Proofs.Concrete

open Shared Shared.MultiNodeTransitionSystem
open Model.Local (NodeState Bootstrap)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

/-- Replace the state of `node` in a node table. -/
def replaceNode (nodes : List (Node × NodeState Node TxId)) (node : Node)
    (value : NodeState Node TxId)
    : List (Node × NodeState Node TxId) :=
  nodes.map fun entry => if entry.1 == node then (node, value) else entry

theorem step_local
    {nodes : List Node} {before after : Model.State Node TxId}
    {node : Node} {input : Model.Local.Input Node TxId}
    (stepped
      : (Model.transitionSystem nodes).step before (.local node input) = some after)
    : exists state execute,
        nodeState before node = some state
        /\ Model.Local.act (Capabilities.record node) node state input = some execute
        /\ after
            = {
              before with
                nodes := replaceNode before.nodes node (execute.run {}).1
                network := before.network ++ (execute.run {}).2.outgoing
            } := by
  simp only [Model.transitionSystem, lift, next, Model.protocol] at stepped
  simp at stepped
  simp only [Option.bind_eq_some_iff] at stepped
  obtain ⟨_, _, state, found, execute, acted, result⟩ := stepped
  refine ⟨state, execute, found, acted, ?_⟩
  rcases run : StateT.run execute {} with ⟨value, outputs⟩
  rw [run] at result
  simp only [Option.some.injEq] at result
  subst result
  simp [replaceNode]

theorem step_deliver
    {nodes : List Node} {before after : Model.State Node TxId}
    {envelope : Model.Envelope Node TxId}
    (stepped
      : (Model.transitionSystem nodes).step before (.deliver envelope) = some after)
    : envelope ∈ before.network
      /\ exists state execute,
          nodeState before envelope.target = some state
          /\ Model.Local.receive (Capabilities.record envelope.target) envelope.target
                envelope.source state envelope.payload
              = some execute
          /\ after
              = {
                before with
                  nodes := replaceNode before.nodes envelope.target (execute.run {}).1
                  network :=
                    removeOne envelope before.network ++ (execute.run {}).2.outgoing
              } := by
  simp only [Model.transitionSystem, lift, next, Model.protocol] at stepped
  simp at stepped
  simp only [Option.bind_eq_some_iff] at stepped
  obtain ⟨_, queued, _, _, state, found, execute, acted, result⟩ := stepped
  refine ⟨?_, state, execute, found, acted, ?_⟩
  · by_contra absent
    simp [guard, absent] at queued
  · rcases run : StateT.run execute {} with ⟨value, outputs⟩
    rw [run] at result
    simp only [Option.some.injEq] at result
    subst result
    simp [replaceNode]

theorem mem_replaceNode {nodes : List (Node × NodeState Node TxId)} {node member : Node}
    {value state : NodeState Node TxId}
    (found : (member, state) ∈ replaceNode nodes node value)
    : (member = node /\ state = value)
      \/ (Not (member = node) /\ (member, state) ∈ nodes) := by
  simp only [replaceNode, List.mem_map] at found
  obtain ⟨⟨key, old⟩, listed, same⟩ := found
  by_cases here : key = node
  · simp only [here, beq_self_eq_true, ite_true, Prod.mk.injEq] at same
    exact Or.inl ⟨same.1.symm, same.2.symm⟩
  · have different : (key == node) = false := by simpa using here
    simp only [different, Bool.false_eq_true, ite_false, Prod.mk.injEq] at same
    obtain ⟨rfl, rfl⟩ := same
    exact Or.inr ⟨here, listed⟩

theorem replaceNode_keys (nodes : List (Node × NodeState Node TxId)) (node : Node)
    (value : NodeState Node TxId)
    : (replaceNode nodes node value).map Prod.fst = nodes.map Prod.fst := by
  simp only [replaceNode, List.map_map]
  congr 1
  funext entry
  by_cases here : entry.1 = node <;> simp [here]

theorem mem_of_nodeState {concrete : Model.State Node TxId} {node : Node}
    {state : NodeState Node TxId} (found : nodeState concrete node = some state)
    : (node, state) ∈ concrete.nodes := by
  simp only [nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, value⟩, located, rfl⟩ := found
  have same : key = node := by simpa using List.find?_some located
  subst same
  exact List.mem_of_find?_eq_some located

theorem observeTerm_log (state : NodeState Node TxId)
    (message : Model.Local.Message Node TxId)
    : (Model.Local.observeTerm state message).log = state.log := by
  unfold Model.Local.observeTerm Model.Local.updateTerm
  split <;> (try split) <;> (try split) <;> rfl

theorem observeTerm_commitIndex (state : NodeState Node TxId)
    (message : Model.Local.Message Node TxId)
    : (Model.Local.observeTerm state message).commitIndex = state.commitIndex := by
  unfold Model.Local.observeTerm Model.Local.updateTerm
  split <;> (try split) <;> (try split) <;> rfl

theorem updateTerm_bounded (state : NodeState Node TxId) (term : Nat)
    : term <= (Model.Local.updateTerm state term).currentTerm := by
  unfold Model.Local.updateTerm
  split_ifs with newer
  · exact Nat.le_refl _
  · omega

theorem handleAppendEntriesResponse_log (state : NodeState Node TxId) (source : Node)
    (response : Model.Local.AppendEntriesResponse)
    : (Model.Local.handleAppendEntriesResponse state source response).log = state.log
      /\ (Model.Local.handleAppendEntriesResponse state source response).commitIndex
          = state.commitIndex := by
  unfold Model.Local.handleAppendEntriesResponse
  split_ifs <;> exact ⟨rfl, rfl⟩

theorem handleRequestVoteRequest_log (state : NodeState Node TxId) (source : Node)
    (request : Model.Local.RequestVoteRequest)
    : (Model.Local.handleRequestVoteRequest state source request).1.log = state.log
      /\ (Model.Local.handleRequestVoteRequest state source request).1.commitIndex
          = state.commitIndex := by
  unfold Model.Local.handleRequestVoteRequest
  dsimp only
  split_ifs <;> exact ⟨rfl, rfl⟩

theorem handleRequestVoteResponse_log (state : NodeState Node TxId) (source : Node)
    (response : Model.Local.RequestVoteResponse)
    : (Model.Local.handleRequestVoteResponse state source response).log = state.log
      /\ (Model.Local.handleRequestVoteResponse state source response).commitIndex
          = state.commitIndex := by
  unfold Model.Local.handleRequestVoteResponse
  split_ifs <;> exact ⟨rfl, rfl⟩

theorem handleRequestPreVoteResponse_log (state : NodeState Node TxId) (source : Node)
    (response : Model.Local.RequestVoteResponse)
    : (Model.Local.handleRequestPreVoteResponse state source response).log = state.log
      /\ (Model.Local.handleRequestPreVoteResponse state source response).commitIndex
          = state.commitIndex := by
  unfold Model.Local.handleRequestPreVoteResponse
  split_ifs <;> exact ⟨rfl, rfl⟩

theorem handleProposeVoteRequest_log (state : NodeState Node TxId) (self : Node)
    (term : Nat)
    : (Model.Local.handleProposeVoteRequest state self term).log = state.log
      /\ (Model.Local.handleProposeVoteRequest state self term).commitIndex
          = state.commitIndex := by
  unfold Model.Local.handleProposeVoteRequest
  split_ifs <;> exact ⟨rfl, rfl⟩

theorem guard_holds {p : Prop} [Decidable p] {done : Unit}
    (holds : (if p then pure () else failure : Option Unit) = some done)
    : p := by
  by_contra absent
  simp [absent] at holds

end CCFRaft.Proofs.Concrete
