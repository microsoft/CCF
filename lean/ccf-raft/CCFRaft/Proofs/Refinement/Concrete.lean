-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model
import Mathlib.Tactic

set_option autoImplicit false

/-!
Unfolds one step of `Model.transitionSystem` into the acting node's local
step, its new state, and its sends.
-/

namespace CCFRaft.Proofs.Refinement

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

end CCFRaft.Proofs.Refinement
