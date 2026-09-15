-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.ReconfigurationPreservation

set_option autoImplicit false

/-!
Review these statements with their definitions in `CCFRaft.Protocol`.
The supporting invariant and preservation proofs are implementation details
under `CCFRaft.Proofs`, not premises of the public safety statements.
-/

namespace CCFRaft.Properties

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]
variable [Protocol.Model.Bootstrap Node]

theorem reachable_committed_logs_prefix
    {state : Protocol.Model.State Node TxId}
    (reachable : Protocol.Model.Reachable state) :
    Protocol.Safety.CommittedLogsPrefix state :=
  Proofs.ReconfigurationPreservation.reachableCommittedLogsPrefix reachable

theorem reachable_committed_frontier_is_signature
    {state : Protocol.Model.State Node TxId}
    (reachable : Protocol.Model.Reachable state) :
    Protocol.Safety.CommittedFrontierIsSignature state :=
  Proofs.ReconfigurationPreservation.reachableCommittedFrontierIsSignature reachable

theorem reachable_election_safety
    {state : Protocol.Model.State Node TxId}
    (reachable : Protocol.Model.Reachable state) :
    Protocol.Safety.ElectionSafety state :=
  Proofs.ReconfigurationPreservation.reachableElectionSafety reachable

theorem reachable_consensus_safety
    {state : Protocol.Model.State Node TxId}
    (reachable : Protocol.Model.Reachable state) :
    Protocol.Safety.ConsensusSafety state :=
  Proofs.ReconfigurationPreservation.reachableConsensusSafety reachable

end CCFRaft.Properties
