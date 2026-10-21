module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model
public import CCFRaft.Proofs.Config
public import Mathlib.Tactic

import all Init.Control.State

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Unfolds one step of `Model.transitionSystem` into the acting node's local
step, its new state, and its sends.
-/

namespace CCFRaft.Proofs.Concrete

open CCFRaft.Proofs.Config

open CCF CCF.MultiNodeTransitionSystem
open Model.Node

/-- Replace the state of `node` in a node table. -/
def replaceNode (nodes : List (NodeID × NodeState)) (node : NodeID) (value : NodeState)
    : List (NodeID × NodeState) :=
  nodes.map fun entry => if entry.1 == node then (node, value) else entry

section Steps

variable [Config.InitialConfiguration]

theorem step_local
    {nodes : List NodeID} {before after : Model.State}
    {node : NodeID} {input : Model.Node.Input}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before
          (.local node input)
        = some after)
    : exists state next outputs,
        nodeState before node = some state
        /\ (Model.Node.act (Capabilities.record node) node state input).run {}
            = some (next, outputs)
        /\ after
            = {
              before with
                nodes := replaceNode before.nodes node next
                network := before.network ++ outputs.outgoing
            } := by
  simp only [Model.transitionSystem, lift, next, Model.protocol] at stepped
  simp [Model.Node.step, Option.bind_eq_some_iff] at stepped
  obtain ⟨state, found, next, outputs, ran, rfl⟩ := stepped
  refine ⟨state, next, outputs, found, ?_, by simp [replaceNode]⟩
  exact ran

theorem step_deliver
    {nodes : List NodeID} {before after : Model.State}
    {envelope : Model.Envelope}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before
          (.deliver envelope)
        = some after)
    : envelope ∈ before.network
      /\ exists state next outputs,
          nodeState before envelope.target = some state
          /\ (Model.Node.receive (Capabilities.record envelope.target)
                envelope.target envelope.source state
                envelope.payload).run
                {}
              = some (next, outputs)
          /\ after
              = {
                before with
                  nodes := replaceNode before.nodes envelope.target next
                  network := removeOne envelope before.network ++ outputs.outgoing
              } := by
  simp only [Model.transitionSystem, lift, next, Model.protocol] at stepped
  simp [Model.Node.step, Option.bind_eq_some_iff] at stepped
  obtain ⟨queued, state, found, next, outputs, ran, rfl⟩ := stepped
  exact ⟨queued, state, next, outputs, found, ran, by simp [replaceNode]⟩

end Steps

theorem mem_replaceNode {nodes : List (NodeID × NodeState)} {node member : NodeID}
    {value state : NodeState}
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

theorem replaceNode_keys (nodes : List (NodeID × NodeState)) (node : NodeID)
    (value : NodeState)
    : (replaceNode nodes node value).map Prod.fst = nodes.map Prod.fst := by
  simp only [replaceNode, List.map_map]
  congr 1
  funext entry
  by_cases here : entry.1 = node <;> simp [here]

theorem mem_of_nodeState {concrete : Model.State} {node : NodeID}
    {state : NodeState} (found : nodeState concrete node = some state)
    : (node, state) ∈ concrete.nodes := by
  simp only [nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, value⟩, located, rfl⟩ := found
  have same : key = node := by simpa using List.find?_some located
  subst same
  exact List.mem_of_find?_eq_some located

theorem observeTerm_log (state : NodeState) (message : Model.Node.Message)
    : (Model.Node.observeTerm state message).log = state.log := by
  unfold Model.Node.observeTerm Model.Node.updateTerm
  split <;> (try split) <;> (try split) <;> rfl

theorem observeTerm_commitIndex (state : NodeState) (message : Model.Node.Message)
    : (Model.Node.observeTerm state message).commitIndex = state.commitIndex := by
  unfold Model.Node.observeTerm Model.Node.updateTerm
  split <;> (try split) <;> (try split) <;> rfl

theorem updateTerm_bounded (state : NodeState) (term : Nat)
    : term <= (Model.Node.updateTerm state term).currentTerm := by
  unfold Model.Node.updateTerm
  split_ifs with newer
  · exact Nat.le_refl _
  · omega

theorem handleRequestVoteRequest_log (state : NodeState) (source : NodeID)
    (request : Model.Node.RequestVoteRequest)
    {self : NodeID} {after : NodeState}
    {outputs : Outputs NodeID (Model.Node.Message) Model.Node.Notification}
    (ran
      : (Model.Node.handleRequestVoteRequest (Capabilities.record self)
          state source request).run
          {}
        = some (after, outputs))
    : after.log = state.log /\ after.commitIndex = state.commitIndex := by
  let grant : Bool := decide (request.term = state.currentTerm
    /\ Model.Node.voteLogUpToDate state request /\ !state.primaryKnown
    /\ (state.votedFor = none \/ state.votedFor = some source))
  change some ((if grant then { state with votedFor := some source } else state), _) =
    some (after, outputs) at ran
  split at ran <;> grind

@[simp]
theorem run_failure {σ α : Type} (s : σ) : (failure : StateT σ Option α).run s = none :=
  Option.eq_none_iff_forall_ne_some.mpr fun _ ran => nomatch ran

@[simp]
theorem run_guard {σ : Type} (p : Prop) [Decidable p] (s : σ)
    : (guard p : StateT σ Option Unit).run s = if p then some ((), s) else none := by
  unfold guard
  split <;> rfl

@[simp]
theorem ite_some_none_bind {α β : Type} (p : Prop) [Decidable p] (a : α)
    (f : α -> Option β)
    : (if p then some a else none).bind f = if p then f a else none := by
  split <;> rfl

@[simp]
theorem ite_none_some_bind {α β : Type} (p : Prop) [Decidable p] (a : α)
    (f : α -> Option β)
    : (if p then none else some a).bind f = if p then none else f a := by
  split <;> rfl

theorem guard_holds {p : Prop} [Decidable p] {done : Unit}
    (holds : (if p then pure () else failure : Option Unit) = some done)
    : p := by
  by_contra absent
  simp [absent] at holds

end CCFRaft.Proofs.Concrete
