module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Properties
public import CCFRaft.Proofs.CommittedLogs
public import CCFRaft.Proofs.Direct.AppendOnly
public import CCFRaft.Proofs.Direct.CommitFrontier
public import CCFRaft.Proofs.Election
public import CCFRaft.Proofs.Witnesses

@[expose] public section

namespace CCFRaft.Proof

theorem election_safety : Properties.ElectionSafety :=
  Proofs.Election.election_safety

theorem committed_logs_prefix : Properties.CommittedLogsPrefix :=
  Proofs.CommittedLogs.committed_logs_prefix

theorem committed_frontier_is_signature : Properties.CommittedFrontierIsSignature :=
  Proofs.Direct.committed_frontier_is_signature

theorem single_node_committed_log_monotonic
    : Properties.SingleNodeCommittedLogMonotonic :=
  Proofs.Direct.single_node_committed_log_monotonic

theorem election_safety_witness : Properties.ElectionSafetyWitness :=
  Proofs.Witnesses.election_safety_witness

theorem committed_logs_prefix_witness : Properties.CommittedLogsPrefixWitness :=
  Proofs.Witnesses.committed_logs_prefix_witness

theorem committed_frontier_is_signature_witness
    : Properties.CommittedFrontierIsSignatureWitness :=
  Proofs.Witnesses.committed_frontier_is_signature_witness

theorem single_node_committed_log_monotonic_witness
    : Properties.SingleNodeCommittedLogMonotonicWitness :=
  Proofs.Witnesses.single_node_committed_log_monotonic_witness

end CCFRaft.Proof
