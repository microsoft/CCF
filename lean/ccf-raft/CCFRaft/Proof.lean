-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Properties
import CCFRaft.Proofs.CommittedLogs
import CCFRaft.Proofs.Direct.CommitFrontier
import CCFRaft.Proofs.Model
import CCFRaft.Proofs.Witnesses

namespace CCFRaft.Proof

theorem election_safety : Properties.ElectionSafety :=
  Proofs.Model.election_safety

theorem committed_logs_prefix : Properties.CommittedLogsPrefix :=
  Proofs.CommittedLogs.committed_logs_prefix

theorem committed_frontier_is_signature : Properties.CommittedFrontierIsSignature :=
  Proofs.Direct.committed_frontier_is_signature

theorem election_safety_witness : Properties.ElectionSafetyWitness :=
  Proofs.Witnesses.election_safety_witness

theorem committed_logs_prefix_witness : Properties.CommittedLogsPrefixWitness :=
  Proofs.Witnesses.committed_logs_prefix_witness

theorem committed_frontier_is_signature_witness
    : Properties.CommittedFrontierIsSignatureWitness :=
  Proofs.Witnesses.committed_frontier_is_signature_witness

end CCFRaft.Proof
