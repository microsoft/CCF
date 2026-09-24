-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Direct.Framework

set_option autoImplicit false
set_option linter.unusedSectionVars false

namespace CCFRaft.Proofs.Invariant

open Shared.MultiNodeTransitionSystem Concrete
open Model.Local (Bootstrap NodeState initialNodeState)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

/-- Total lookup; identities absent from the node table retain their initial state. -/
def nodeOf (state : Model.State Node TxId) (node : Node) : NodeState Node TxId :=
  (nodeState state node).getD (initialNodeState node)

theorem nodeOf_of_lookup {state : Model.State Node TxId} {node : Node}
    {value : NodeState Node TxId} (found : nodeState state node = some value)
    : nodeOf state node = value := by
  simp [nodeOf, found]

theorem nodeOf_of_mem {state : Model.State Node TxId} {node : Node}
    {value : NodeState Node TxId} (distinct : (state.nodes.map Prod.fst).Nodup)
    (found : (node, value) ∈ state.nodes)
    : nodeOf state node = value :=
  nodeOf_of_lookup (Direct.nodeState_of_mem distinct found)

theorem lookup_replaceNode_other (state : Model.State Node TxId)
    (node member : Node) (value : NodeState Node TxId) (different : member ≠ node)
    : nodeState { state with nodes := replaceNode state.nodes node value } member
      = nodeState state member := by
  simp only [nodeState, replaceNode]
  induction state.nodes with
  | nil => rfl
  | cons head tail ih =>
      rcases head with ⟨key, old⟩
      by_cases here : key = node
      · subst key
        simpa [different, Ne.symm different] using ih
      · by_cases queried : key = member
        · simp [queried, different]
        · simpa [here, queried] using ih

@[simp]
theorem nodeOf_replaceNode_other (state : Model.State Node TxId)
    (node member : Node) (value : NodeState Node TxId) (different : member ≠ node)
    : nodeOf { state with nodes := replaceNode state.nodes node value } member
      = nodeOf state member := by
  simp [nodeOf, lookup_replaceNode_other state node member value different]

theorem nodeOf_replaceNode_same {state : Model.State Node TxId}
    {node : Node} {old : NodeState Node TxId}
    (distinct : (state.nodes.map Prod.fst).Nodup)
    (found : nodeState state node = some old) (value : NodeState Node TxId)
    : nodeOf { state with nodes := replaceNode state.nodes node value } node
      = value := by
  apply nodeOf_of_mem
  · simpa [replaceNode_keys] using distinct
  · exact List.mem_map.mpr ⟨(node, old), mem_of_nodeState found, by simp⟩

theorem lookup_replaceNode_present (state : Model.State Node TxId)
    (node : Node) (value : NodeState Node TxId)
    (present : node ∈ state.nodes.map Prod.fst)
    : nodeState { state with nodes := replaceNode state.nodes node value } node
      = some value := by
  simp only [nodeState, replaceNode]
  generalize state.nodes = entries at present ⊢
  induction entries with
  | nil => simp at present
  | cons head tail ih =>
      rcases head with ⟨key, old⟩
      by_cases here : key = node
      · simp [here]
      · have later : node ∈ tail.map Prod.fst := by
          simpa [here, Ne.symm here] using present
        simpa [here] using ih later

/-- Concrete replacement has the usual lookup law when the key is present. -/
@[simp]
theorem nodeOf_replaceNode (state : Model.State Node TxId)
    (node member : Node) (value : NodeState Node TxId)
    (present : node ∈ state.nodes.map Prod.fst)
    : nodeOf { state with nodes := replaceNode state.nodes node value } member
      = if member = node then value else nodeOf state member := by
  by_cases here : member = node
  · subst member
    simp [nodeOf, lookup_replaceNode_present state node value present]
  · simp [nodeOf_replaceNode_other state node member value here, here]

@[simp]
theorem nodeOf_network (state : Model.State Node TxId)
    (network : List (Model.Envelope Node TxId)) (node : Node)
    : nodeOf { state with network } node = nodeOf state node :=
  rfl

theorem nodeOf_initial {nodes : List Node} {state : Model.State Node TxId}
    (initialized : (Model.transitionSystem nodes).init state) (node : Node)
    : nodeOf state node = initialNodeState node := by
  cases found : nodeState state node with
  | none => simp [nodeOf, found]
  | some value =>
      rw [nodeOf_of_lookup found]
      exact initialized.2.2.2.2.2 (node, value) (mem_of_nodeState found)

omit [Bootstrap Node] in
theorem removeOne_eq_list_erase (envelope : Model.Envelope Node TxId)
    (network : List (Model.Envelope Node TxId))
    : removeOne envelope network = network.erase envelope := by
  induction network with
  | nil => rfl
  | cons head tail ih =>
      simp only [removeOne, List.erase_cons]
      split <;> simp_all

end CCFRaft.Proofs.Invariant
