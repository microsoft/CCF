-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Protocol.Safety
import Mathlib

set_option autoImplicit false

namespace CCFRaft.Proofs.Support

open Protocol Protocol.Model

/-- Projection used only to compare handler results independently of retirement metadata. -/
def protocolNodeState {Node TxId : Type} (node : NodeState Node TxId) :
    NodeState Node TxId :=
  { node with
    membershipState := .active
    retirementIndex := none
    retirementCommittableIndex := none
    retiredCommittedIndex := none }

lemma reachableInvariant
    (system : ExecutableTransitionSystem)
    {Invariant : system.State -> Prop}
    (initial : Invariant system.initial)
    (preserved : forall state action,
      Invariant state -> system.Enabled state action ->
        Invariant (system.next state action))
    {state : system.State}
    (reachable : system.Reachable state) :
    Invariant state := by
  induction reachable with
  | initial => exact initial
  | step reachable enabled invariant =>
      exact preserved _ _ invariant enabled

end CCFRaft.Proofs.Support
