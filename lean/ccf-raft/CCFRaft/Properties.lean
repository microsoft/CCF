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

/-- No enabled step from a reachable state rolls back or rewrites committed entries. -/
theorem reachable_committed_log_append_only
    {state : Protocol.Model.State Node TxId}
    (reachable : Protocol.Model.Reachable state) :
    Protocol.Safety.CommittedLogAppendOnly state :=
  Proofs.ReconfigurationPreservation.reachableCommittedLogAppendOnly reachable

/-- The committed prefix survives any finite execution from a reachable state. -/
theorem run_actions_committed_log_prefix
    {start final : Protocol.Model.State Node TxId}
    {actions : List (Protocol.Model.Action Node TxId)}
    (reachable : Protocol.Model.Reachable start)
    (ran : Protocol.Model.runActions start actions = some final) :
    forall node,
      (start.nodes node).committedLog <+: (final.nodes node).committedLog := by
  induction actions generalizing start with
  | nil =>
      simp only [Protocol.Model.runActions, Option.some.injEq] at ran
      subst final
      intro node
      exact Proofs.HandlerProofs.prefixRefl _
  | cons action actions inductionHypothesis =>
      unfold Protocol.Model.runActions Protocol.ExecutableTransitionSystem.applyAction at ran
      split at ran
      · rename_i enabled
        have tail := inductionHypothesis
          (Proofs.ModelProofs.Reachable.step reachable enabled) ran
        intro node
        exact (reachable_committed_log_append_only reachable action enabled node).trans (tail node)
      · simp at ran

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
