-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Receive
import CCFRaft.Proofs.Invariant.Preservation.Initial

set_option autoImplicit false

/-!
# The invariant on reachable network states

Each concrete step runs either `Local.act` or `Local.receive`. The view of
its result is the node replacement and queue update proved in `Internal`
and `Receive`. The joined set is ghost state; configuration changes extend it.
-/

namespace CCFRaft.Proofs.Invariant

open Shared Shared.MultiNodeTransitionSystem Concrete
open Model.Local (Bootstrap INITIAL_CONFIGURATION)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

theorem initial_inv {nodes : List Node} {state : Model.State Node TxId}
    (initialized : (Model.transitionSystem nodes).init state)
    : Inv state := by
  refine ⟨INITIAL_CONFIGURATION, ?_⟩
  rw [view_initial initialized]
  exact ⟨initialSystemInductiveInvariant, Finset.Subset.refl _, fun _ _ => rfl, by simp⟩

theorem step_inv {nodes : List Node} {before after : Model.State Node TxId}
    {action : Model.Action Node TxId} (invariant : Inv before)
    (distinct : (before.nodes.map Prod.fst).Nodup)
    (stepped : (Model.transitionSystem nodes).step before action = some after)
    : Inv after := by
  obtain ⟨joined, invariant⟩ := invariant
  cases action with
  | «local» node input =>
      obtain ⟨local_, execute, found, acted, rfl⟩ := step_local stepped
      have here := view_node (joined := joined) found
      obtain ⟨joined', preserved⟩ := act_preserves invariant (by rwa [here])
      refine ⟨joined', ?_⟩
      rw [view_replaceNode (joined := joined) distinct found]
      have network :
          messagesAt (before.network ++ (execute.run {}).2.outgoing)
          = fun destination =>
              (view before joined).network destination
              ++ messagesAt (execute.run {}).2.outgoing destination :=
        funext fun destination => messagesAt_append _ _ destination
      rw [network]
      exact preserved
  | deliver envelope =>
      obtain ⟨queued, local_, execute, found, received, rfl⟩ := step_deliver stepped
      have here := view_node (joined := joined) found
      have preserved := receive_preserves invariant (mem_view_network queued) (by rwa [here])
      refine ⟨joined, ?_⟩
      rw [view_replaceNode (joined := joined) distinct found]
      have network :
          messagesAt (removeOne envelope before.network ++ (execute.run {}).2.outgoing)
          = fun destination =>
              updateQueue (view before joined).network envelope.target
                  (((view before joined).network envelope.target).erase (toMessage envelope))
                  destination
              ++ messagesAt (execute.run {}).2.outgoing destination := by
        funext destination
        rw [messagesAt_append, messagesAt_erase_eq]
        rfl
      rw [network]
      exact preserved

theorem reachable_inv {nodes : List Node} {c : Model.State Node TxId}
    (reachable : (Model.transitionSystem (TxId := TxId) nodes).Reachable c)
    : Inv c := by
  induction reachable with
  | initial initialized => exact initial_inv initialized
  | @step before after action reachable stepped invariant =>
      exact step_inv invariant (Direct.keys_nodup reachable) stepped

end CCFRaft.Proofs.Invariant
