-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Receive
import CCFRaft.Proofs.Invariant.Preservation.Initial

/-!
# The invariant on reachable concrete states

Each step runs `Model.Node.act` or `Model.Node.receive`, replaces one node-table entry,
and updates the envelope list. The joined set is proof-only; configuration
changes extend it without changing the concrete state representation.
-/

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Proofs.Config

open Shared Shared.MultiNodeTransitionSystem Concrete
open Model.Node (InitialConfig)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node]
  [LinearOrder Node] [Inhabited TxId]

theorem initial_inv {nodes : List Node} {state : Model.State Node TxId}
    (initialized : (Model.transitionSystem (inferInstance) nodes).init state)
    : Inv state := by
  refine ⟨INITIAL_CONFIGURATION, ?_⟩
  exact {
    safety :=
      initialSystemInductiveInvariant state (nodeOf_initial initialized)
        initialized.2.2.2.2.1
    distinct := initialized.2.1 ▸ initialized.1
    initialJoined := Finset.Subset.refl _
    unjoined := fun node _ => nodeOf_initial initialized node
    endpoints := by simp [initialized.2.2.2.2.1]
  }

theorem step_inv {nodes : List Node} {before after : Model.State Node TxId}
    {action : Model.Action Node TxId} (invariant : Inv before)
    (stepped
      : (Model.transitionSystem (inferInstance) nodes).step before action = some after)
    : Inv after := by
  obtain ⟨joined, invariant⟩ := invariant
  cases action with
  | «local» node input =>
      obtain ⟨local_, next, outputs, found, acted, rfl⟩ := step_local stepped
      have present : node ∈ before.nodes.map Prod.fst :=
        List.mem_map.mpr ⟨(node, local_), mem_of_nodeState found, rfl⟩
      exact act_preserves invariant present (by rwa [nodeOf_of_lookup found])
  | deliver envelope =>
      obtain ⟨queued, local_, next, outputs, found, received, rfl⟩ := step_deliver stepped
      have present : envelope.target ∈ before.nodes.map Prod.fst :=
        List.mem_map.mpr ⟨(envelope.target, local_), mem_of_nodeState found, rfl⟩
      exact ⟨
        joined,
        receive_preserves invariant present queued (by rwa [nodeOf_of_lookup found])
      ⟩

theorem reachable_inv {nodes : List Node} {c : Model.State Node TxId}
    (reachable
      : (Model.transitionSystem (inferInstance) (TxId := TxId) nodes).Reachable c)
    : Inv c := by
  induction reachable with
  | initial initialized => exact initial_inv initialized
  | step _ stepped invariant => exact step_inv invariant stepped

end CCFRaft.Proofs.Invariant
